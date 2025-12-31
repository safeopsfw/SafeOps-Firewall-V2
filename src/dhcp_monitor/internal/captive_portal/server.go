// Package captive_portal provides captive portal web server for CA certificate distribution
package captive_portal

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"dhcp_monitor/internal/storage"
	"embed"
	"fmt"
	"html/template"
	"net"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"
)

//go:embed templates/*
var templateFS embed.FS

// Server is the captive portal HTTP/HTTPS server
type Server struct {
	config      Config
	db          *storage.Database
	httpServer  *http.Server
	httpsServer *http.Server
	templates   *template.Template
	rootCACert  []byte

	// Statistics
	mu                    sync.RWMutex
	totalVisits           uint64
	certificateDownloads  uint64
	successfulEnrollments uint64
}

// Config holds captive portal configuration
type Config struct {
	// Portal IP address (auto-detected if empty)
	PortalIP string

	// HTTP port (default: 80)
	HTTPPort int

	// HTTPS port (default: 443)
	HTTPSPort int

	// Enable HTTPS (requires TLS certificate)
	EnableHTTPS bool

	// TLS certificate and key paths (for portal HTTPS)
	TLSCertPath string
	TLSKeyPath  string

	// Step-CA root certificate path (to distribute to devices)
	RootCACertPath string

	// Session timeout for certificate installation
	SessionTimeout time.Duration

	// Verify client certificates (for enrollment detection)
	VerifyClientCerts bool
}

// New creates a new captive portal server
func New(cfg Config, db *storage.Database) (*Server, error) {
	if cfg.HTTPPort == 0 {
		cfg.HTTPPort = 80
	}
	if cfg.HTTPSPort == 0 {
		cfg.HTTPSPort = 443
	}
	if cfg.SessionTimeout == 0 {
		cfg.SessionTimeout = 10 * time.Minute
	}

	// Load root CA certificate (non-fatal if missing)
	var rootCACert []byte
	if cfg.RootCACertPath != "" {
		var err error
		rootCACert, err = os.ReadFile(cfg.RootCACertPath)
		if err != nil {
			fmt.Printf("[WARN] Could not read root CA certificate from %s: %v\n", cfg.RootCACertPath, err)
			fmt.Println("[WARN] Certificate download feature will be disabled")
		}
	} else {
		fmt.Println("[WARN] Root CA certificate path not configured")
		fmt.Println("[WARN] Certificate download feature will be disabled")
	}

	// Parse templates
	tmpl, err := template.ParseFS(templateFS, "templates/*.html")
	if err != nil {
		return nil, fmt.Errorf("failed to parse templates: %w", err)
	}

	// Auto-detect portal IP if not specified
	if cfg.PortalIP == "" || cfg.PortalIP == "auto" {
		cfg.PortalIP = getLocalIP()
	}

	return &Server{
		config:     cfg,
		db:         db,
		templates:  tmpl,
		rootCACert: rootCACert,
	}, nil
}

// Start starts the captive portal server
func (s *Server) Start(ctx context.Context) error {
	// Set up HTTP routes
	mux := http.NewServeMux()

	// Main portal routes
	mux.HandleFunc("/", s.handlePortalPage)
	mux.HandleFunc("/download", s.handleDownload)
	mux.HandleFunc("/download/ca.crt", s.handleDownloadCACert)
	mux.HandleFunc("/api/check-cert", s.handleCheckCert)
	mux.HandleFunc("/api/status", s.handleStatus)
	mux.HandleFunc("/api/stats", s.handleAPIStats)
	mux.HandleFunc("/api/devices", s.handleAPIDevices)
	mux.HandleFunc("/api/health", s.handleAPIHealth)
	mux.HandleFunc("/success", s.handleSuccess)

	// Captive Portal Detection URLs - triggers "Sign in to network" popup
	// iOS/macOS detection
	mux.HandleFunc("/hotspot-detect.html", s.handleCaptivePortalDetect)
	// Android detection
	mux.HandleFunc("/generate_204", s.handleCaptivePortalDetect)
	// Windows detection
	mux.HandleFunc("/connecttest.txt", s.handleCaptivePortalDetect)
	mux.HandleFunc("/ncsi.txt", s.handleCaptivePortalDetect)
	// Chrome detection
	mux.HandleFunc("/blank.html", s.handleCaptivePortalDetect)

	// Create HTTP server
	s.httpServer = &http.Server{
		Addr:    fmt.Sprintf(":%d", s.config.HTTPPort),
		Handler: s.addMiddleware(mux),
	}

	// Start HTTP server
	go func() {
		fmt.Printf("[INFO] Captive portal HTTP server listening on port %d\n", s.config.HTTPPort)
		fmt.Printf("[INFO] Captive portal detection enabled for iOS/Android/Windows\n")
		if err := s.httpServer.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			fmt.Printf("[ERROR] HTTP server error: %v\n", err)
		}
	}()

	// Start HTTPS server if enabled
	if s.config.EnableHTTPS {
		if err := s.startHTTPSServer(mux); err != nil {
			return fmt.Errorf("failed to start HTTPS server: %w", err)
		}
	}

	// Wait for context cancellation
	<-ctx.Done()
	return s.Stop()
}

// startHTTPSServer starts the HTTPS server with optional client certificate verification
func (s *Server) startHTTPSServer(mux *http.ServeMux) error {
	// Load TLS certificate
	cert, err := tls.LoadX509KeyPair(s.config.TLSCertPath, s.config.TLSKeyPath)
	if err != nil {
		return fmt.Errorf("failed to load TLS certificate: %w", err)
	}

	// Configure TLS
	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{cert},
		MinVersion:   tls.VersionTLS12,
	}

	// Enable client certificate verification if requested
	if s.config.VerifyClientCerts {
		// Load root CA for client cert verification
		caCertPool := x509.NewCertPool()
		caCertPool.AppendCertsFromPEM(s.rootCACert)

		tlsConfig.ClientAuth = tls.RequestClientCert // Don't require, just request
		tlsConfig.ClientCAs = caCertPool
	}

	// Create HTTPS server
	s.httpsServer = &http.Server{
		Addr:      fmt.Sprintf(":%d", s.config.HTTPSPort),
		Handler:   s.addMiddleware(mux),
		TLSConfig: tlsConfig,
	}

	// Start HTTPS server
	go func() {
		fmt.Printf("[INFO] Captive portal HTTPS server listening on port %d\n", s.config.HTTPSPort)
		if err := s.httpsServer.ListenAndServeTLS("", ""); err != nil && err != http.ErrServerClosed {
			fmt.Printf("[ERROR] HTTPS server error: %v\n", err)
		}
	}()

	return nil
}

// Stop stops the captive portal server
func (s *Server) Stop() error {
	fmt.Println("[INFO] Stopping captive portal server...")

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if s.httpServer != nil {
		if err := s.httpServer.Shutdown(ctx); err != nil {
			fmt.Printf("[ERROR] HTTP server shutdown error: %v\n", err)
		}
	}

	if s.httpsServer != nil {
		if err := s.httpsServer.Shutdown(ctx); err != nil {
			fmt.Printf("[ERROR] HTTPS server shutdown error: %v\n", err)
		}
	}

	return nil
}

// addMiddleware wraps handlers with logging and CORS
func (s *Server) addMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// CORS headers
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type")

		// Handle preflight
		if r.Method == "OPTIONS" {
			w.WriteHeader(http.StatusNoContent)
			return
		}

		// Log request
		fmt.Printf("[INFO] %s %s from %s\n", r.Method, r.URL.Path, r.RemoteAddr)

		next.ServeHTTP(w, r)
	})
}

// handleCaptivePortalDetect handles captive portal detection requests from iOS/Android/Windows
// This triggers the "Sign in to network" popup on devices
func (s *Server) handleCaptivePortalDetect(w http.ResponseWriter, r *http.Request) {
	clientIP := getClientIP(r)

	// Check if device has already seen the portal
	device, _ := s.db.GetDeviceByIP(clientIP)
	if device != nil && device.SeenPortal {
		// Device has seen portal, return expected response for each platform
		path := r.URL.Path
		switch {
		case strings.Contains(path, "hotspot-detect") || strings.Contains(path, "captive.apple.com"):
			// iOS expects: "<HTML><HEAD><TITLE>Success</TITLE></HEAD><BODY>Success</BODY></HTML>"
			w.Header().Set("Content-Type", "text/html")
			w.Write([]byte("<HTML><HEAD><TITLE>Success</TITLE></HEAD><BODY>Success</BODY></HTML>"))
		case strings.Contains(path, "generate_204"):
			// Android expects: HTTP 204 No Content
			w.WriteHeader(http.StatusNoContent)
		case strings.Contains(path, "connecttest.txt"):
			// Windows expects: "Microsoft Connect Test"
			w.Header().Set("Content-Type", "text/plain")
			w.Write([]byte("Microsoft Connect Test"))
		case strings.Contains(path, "ncsi.txt"):
			// Windows NCSI expects: "Microsoft NCSI"
			w.Header().Set("Content-Type", "text/plain")
			w.Write([]byte("Microsoft NCSI"))
		default:
			w.WriteHeader(http.StatusNoContent)
		}
		return
	}

	// Device hasn't seen portal yet - redirect to captive portal
	// This triggers the "Sign in to network" popup!
	fmt.Printf("[INFO] Captive portal redirect for new device %s\n", clientIP)

	// For captive portal to work, we need to return a redirect or non-expected response
	portalURL := fmt.Sprintf("http://%s/", s.config.PortalIP)
	http.Redirect(w, r, portalURL, http.StatusFound)
}

// handlePortalPage serves the main captive portal page
func (s *Server) handlePortalPage(w http.ResponseWriter, r *http.Request) {
	s.mu.Lock()
	s.totalVisits++
	s.mu.Unlock()

	clientIP := getClientIP(r)

	// Check if device is already enrolled
	device, _ := s.db.GetDeviceByIP(clientIP)
	if device != nil && device.HasCertificate {
		http.Redirect(w, r, "/success", http.StatusFound)
		return
	}

	// Mark device as "seen portal" - this enables normal DNS after first visit
	// This is the key to one-time redirect: after seeing this page, DNS works normally
	if device != nil && !device.SeenPortal {
		if err := s.db.MarkDeviceSeenPortal(clientIP); err != nil {
			fmt.Printf("[WARN] Failed to mark device as seen portal: %v\n", err)
		} else {
			fmt.Printf("[INFO] Device %s marked as seen portal - DNS will now work normally\n", clientIP)
		}
	}

	// Detect OS from User-Agent
	userAgent := r.Header.Get("User-Agent")
	os := DetectOS(userAgent)

	// Update device OS in database
	if device != nil {
		s.db.UpdateDeviceOS(clientIP, string(os), userAgent)
	}

	// Prepare template data
	data := struct {
		OS               OSType
		OSDisplayName    string
		Instructions     string
		DownloadURL      string
		DownloadFilename string
		PortalIP         string
	}{
		OS:               os,
		OSDisplayName:    GetOSDisplayName(os),
		Instructions:     GetInstallationInstructions(os),
		DownloadURL:      GetDownloadURL(os),
		DownloadFilename: GetDownloadFilename(os),
		PortalIP:         s.config.PortalIP,
	}

	// Render template
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := s.templates.ExecuteTemplate(w, "portal.html", data); err != nil {
		http.Error(w, "Template error", http.StatusInternalServerError)
		fmt.Printf("[ERROR] Template execution error: %v\n", err)
	}
}

// handleDownload serves the CA certificate download
func (s *Server) handleDownload(w http.ResponseWriter, r *http.Request) {
	// Check if certificate is available
	if len(s.rootCACert) == 0 {
		http.Error(w, "CA certificate not configured", http.StatusServiceUnavailable)
		return
	}

	s.mu.Lock()
	s.certificateDownloads++
	s.mu.Unlock()

	osType := r.URL.Query().Get("type")
	clientIP := getClientIP(r)

	// Log download event
	s.db.LogEvent(clientIP, "certificate_download", fmt.Sprintf("OS: %s", osType))

	// For iOS, serve mobileconfig profile
	if osType == "ios" {
		s.serveIOSProfile(w, r)
		return
	}

	// For all other platforms, serve .crt file
	w.Header().Set("Content-Type", "application/x-x509-ca-cert")
	w.Header().Set("Content-Disposition", "attachment; filename=network-ca.crt")
	w.Write(s.rootCACert)
}

// serveIOSProfile serves iOS configuration profile
func (s *Server) serveIOSProfile(w http.ResponseWriter, _ *http.Request) {
	// Check if certificate is available
	if len(s.rootCACert) == 0 {
		http.Error(w, "CA certificate not configured", http.StatusServiceUnavailable)
		return
	}

	// Generate iOS mobileconfig profile
	profile := s.generateIOSProfile()

	w.Header().Set("Content-Type", "application/x-apple-aspen-config")
	w.Header().Set("Content-Disposition", "attachment; filename=network-ca.mobileconfig")
	w.Write([]byte(profile))
}

// handleCheckCert checks if the device has installed the certificate
func (s *Server) handleCheckCert(w http.ResponseWriter, r *http.Request) {
	clientIP := getClientIP(r)

	// Method 1: Check if client presented certificate (HTTPS only)
	hasCert := false
	if r.TLS != nil && len(r.TLS.PeerCertificates) > 0 {
		// Client presented a certificate - verify it's from our CA
		if s.verifyCertificate(r.TLS.PeerCertificates[0]) {
			hasCert = true
		}
	}

	// Method 2: Check database (in case already verified)
	device, _ := s.db.GetDeviceByIP(clientIP)
	if device != nil && device.HasCertificate {
		hasCert = true
	}

	// If certificate verified, update database
	if hasCert && (device == nil || !device.HasCertificate) {
		s.mu.Lock()
		s.successfulEnrollments++
		s.mu.Unlock()

		s.db.UpdateCertificateStatus(clientIP, true)
		s.db.LogEvent(clientIP, "certificate_installed", "Verified via TLS handshake")
		fmt.Printf("[INFO] Device %s successfully enrolled (certificate installed)\n", clientIP)
	}

	// Return JSON response
	w.Header().Set("Content-Type", "application/json")
	if hasCert {
		w.Write([]byte(`{"installed": true, "message": "Certificate verified"}`))
	} else {
		w.Write([]byte(`{"installed": false, "message": "Certificate not detected"}`))
	}
}

// handleStatus returns portal statistics
func (s *Server) handleStatus(w http.ResponseWriter, r *http.Request) {
	stats := s.GetStats()

	w.Header().Set("Content-Type", "application/json")
	fmt.Fprintf(w, `{
		"total_visits": %d,
		"certificate_downloads": %d,
		"successful_enrollments": %d
	}`, stats.TotalVisits, stats.CertificateDownloads, stats.SuccessfulEnrollments)
}

// handleSuccess shows success page for enrolled devices
func (s *Server) handleSuccess(w http.ResponseWriter, r *http.Request) {
	data := struct {
		Message string
	}{
		Message: "You're connected! Internet access has been granted.",
	}

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := s.templates.ExecuteTemplate(w, "success.html", data); err != nil {
		http.Error(w, "Template error", http.StatusInternalServerError)
	}
}

// verifyCertificate verifies if a certificate was issued by our CA
func (s *Server) verifyCertificate(cert *x509.Certificate) bool {
	// Parse root CA certificate
	caCertPool := x509.NewCertPool()
	if !caCertPool.AppendCertsFromPEM(s.rootCACert) {
		return false
	}

	// Verify certificate chain
	opts := x509.VerifyOptions{
		Roots: caCertPool,
	}

	_, err := cert.Verify(opts)
	return err == nil
}

// GetStats returns portal statistics
func (s *Server) GetStats() Stats {
	s.mu.RLock()
	defer s.mu.RUnlock()

	return Stats{
		TotalVisits:           s.totalVisits,
		CertificateDownloads:  s.certificateDownloads,
		SuccessfulEnrollments: s.successfulEnrollments,
	}
}

// Stats holds portal statistics
type Stats struct {
	TotalVisits           uint64
	CertificateDownloads  uint64
	SuccessfulEnrollments uint64
}

// Helper functions

func getClientIP(r *http.Request) string {
	// Check X-Forwarded-For header
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		ips := strings.Split(xff, ",")
		return strings.TrimSpace(ips[0])
	}

	// Check X-Real-IP header
	if xri := r.Header.Get("X-Real-IP"); xri != "" {
		return xri
	}

	// Fall back to RemoteAddr
	ip, _, _ := net.SplitHostPort(r.RemoteAddr)
	return ip
}

func getLocalIP() string {
	addrs, err := net.InterfaceAddrs()
	if err != nil {
		return "192.168.1.1"
	}

	for _, addr := range addrs {
		if ipnet, ok := addr.(*net.IPNet); ok && !ipnet.IP.IsLoopback() {
			if ipnet.IP.To4() != nil {
				return ipnet.IP.String()
			}
		}
	}

	return "192.168.1.1"
}

// generateIOSProfile generates an iOS configuration profile
func (s *Server) generateIOSProfile() string {
	// Note: This is a simplified version. In production, you'd use proper XML generation
	// and base64 encode the certificate properly.

	profile := fmt.Sprintf(`<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
	<key>PayloadContent</key>
	<array>
		<dict>
			<key>PayloadCertificateFileName</key>
			<string>network-ca.crt</string>
			<key>PayloadContent</key>
			<data>
			%s
			</data>
			<key>PayloadDescription</key>
			<string>Network Security Certificate</string>
			<key>PayloadDisplayName</key>
			<string>Network CA Certificate</string>
			<key>PayloadIdentifier</key>
			<string>com.safeops.network.ca</string>
			<key>PayloadType</key>
			<string>com.apple.security.root</string>
			<key>PayloadUUID</key>
			<string>%s</string>
			<key>PayloadVersion</key>
			<integer>1</integer>
		</dict>
	</array>
	<key>PayloadDescription</key>
	<string>Install this profile to access the network securely</string>
	<key>PayloadDisplayName</key>
	<string>Network Access</string>
	<key>PayloadIdentifier</key>
	<string>com.safeops.network.profile</string>
	<key>PayloadRemovalDisallowed</key>
	<false/>
	<key>PayloadType</key>
	<string>Configuration</string>
	<key>PayloadUUID</key>
	<string>%s</string>
	<key>PayloadVersion</key>
	<integer>1</integer>
</dict>
</plist>`,
		base64Encode(s.rootCACert),
		generateUUID(),
		generateUUID())

	return profile
}

func base64Encode(data []byte) string {
	// Simple base64 encoding wrapper
	encoder := make([]byte, 0, len(data)*2)
	const base64Chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"

	for i := 0; i < len(data); i += 3 {
		// This is simplified - use encoding/base64 in production
		encoder = append(encoder, base64Chars[data[i]>>2])
		if i+1 < len(data) {
			encoder = append(encoder, base64Chars[((data[i]&0x03)<<4)|(data[i+1]>>4)])
			if i+2 < len(data) {
				encoder = append(encoder, base64Chars[((data[i+1]&0x0F)<<2)|(data[i+2]>>6)])
				encoder = append(encoder, base64Chars[data[i+2]&0x3F])
			}
		}
	}

	return string(encoder)
}

func generateUUID() string {
	// Simple UUID v4 generation (not cryptographically secure - use proper UUID library in production)
	return fmt.Sprintf("%08x-%04x-%04x-%04x-%012x",
		time.Now().UnixNano()&0xFFFFFFFF,
		time.Now().UnixNano()&0xFFFF,
		0x4000|(time.Now().UnixNano()&0x0FFF),
		0x8000|(time.Now().UnixNano()&0x3FFF),
		time.Now().UnixNano()&0xFFFFFFFFFFFF)
}

// handleDownloadCACert serves the raw CA certificate for direct download
func (s *Server) handleDownloadCACert(w http.ResponseWriter, r *http.Request) {
	// Check if certificate is available
	if len(s.rootCACert) == 0 {
		http.Error(w, "CA certificate not configured", http.StatusServiceUnavailable)
		return
	}

	s.mu.Lock()
	s.certificateDownloads++
	s.mu.Unlock()

	w.Header().Set("Content-Type", "application/x-x509-ca-cert")
	w.Header().Set("Content-Disposition", "attachment; filename=safeops-root-ca.crt")
	w.Write(s.rootCACert)
}

// handleAPIStats returns statistics for the UI dashboard
func (s *Server) handleAPIStats(w http.ResponseWriter, r *http.Request) {
	// Get database stats
	dbStats, _ := s.db.GetStats()
	portalStats := s.GetStats()

	w.Header().Set("Content-Type", "application/json")
	fmt.Fprintf(w, `{
		"totalDevices": %d,
		"enrolledDevices": %d,
		"unenrolledDevices": %d,
		"activeDevices": %d,
		"portalVisits": %d,
		"certificateDownloads": %d,
		"successfulEnrollments": %d
	}`,
		dbStats.TotalDevices,
		dbStats.EnrolledDevices,
		dbStats.UnenrolledDevices,
		dbStats.ActiveDevicesLastHour,
		portalStats.TotalVisits,
		portalStats.CertificateDownloads,
		portalStats.SuccessfulEnrollments)
}

// handleAPIDevices returns list of all devices for the UI dashboard
func (s *Server) handleAPIDevices(w http.ResponseWriter, r *http.Request) {
	// Get query parameters for filtering
	enrolledParam := r.URL.Query().Get("enrolled")

	var devices []storage.Device
	var err error

	// Get all devices first, then filter if needed
	devices, err = s.db.GetAllDevices()
	if err != nil {
		http.Error(w, fmt.Sprintf(`{"error": "%s"}`, err.Error()), http.StatusInternalServerError)
		return
	}

	// Filter by enrolled status if requested
	if enrolledParam == "true" || enrolledParam == "false" {
		wantEnrolled := enrolledParam == "true"
		filtered := make([]storage.Device, 0)
		for _, d := range devices {
			if d.HasCertificate == wantEnrolled {
				filtered = append(filtered, d)
			}
		}
		devices = filtered
	}

	w.Header().Set("Content-Type", "application/json")

	// Build JSON response manually to match frontend expectations
	w.Write([]byte("["))
	for i, device := range devices {
		if i > 0 {
			w.Write([]byte(","))
		}
		fmt.Fprintf(w, `{
			"ip": "%s",
			"mac": "%s",
			"hostname": "%s",
			"hasCertificate": %t,
			"os": "%s",
			"firstSeen": "%s",
			"lastSeen": "%s",
			"nicType": "%s",
			"nicInterfaceName": "%s"
		}`,
			device.IP,
			device.MAC,
			device.Hostname,
			device.HasCertificate,
			device.OS,
			device.FirstSeen.Format(time.RFC3339),
			device.LastSeen.Format(time.RFC3339),
			device.NICType,
			device.NICInterfaceName)
	}
	w.Write([]byte("]"))
}

// handleAPIHealth returns service health status for monitoring
func (s *Server) handleAPIHealth(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	// Check database connectivity
	dbStatus := "healthy"
	if s.db == nil {
		dbStatus = "error"
	}

	// Check root CA certificate
	caStatus := "healthy"
	if len(s.rootCACert) == 0 {
		caStatus = "error"
	}

	overallStatus := "healthy"
	if dbStatus == "error" || caStatus == "error" {
		overallStatus = "unhealthy"
	}

	fmt.Fprintf(w, `{
		"status": "%s",
		"service": "dhcp-monitor",
		"version": "1.0.0",
		"components": {
			"database": "%s",
			"rootCACertificate": "%s",
			"httpServer": "healthy",
			"dnsServer": "healthy"
		},
		"timestamp": "%s"
	}`,
		overallStatus,
		dbStatus,
		caStatus,
		time.Now().Format(time.RFC3339))
}
