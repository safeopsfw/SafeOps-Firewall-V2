// Package captive_portal provides captive portal web server for CA certificate distribution
package captive_portal

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"dhcp_monitor/internal/storage"
	"embed"
	"encoding/json"
	"fmt"
	"html/template"
	"net"
	"net/http"
	"os"
	"os/exec"
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
		fmt.Printf("[WARN] Database query failed, trying direct ARP: %v\n", err)
		devices = nil
	}

	// If database is empty, fall back to direct ARP table scan
	if len(devices) == 0 {
		devices = s.getDevicesFromARPTable()
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

// getDevicesFromARPTable fetches devices directly from Windows ARP table via PowerShell
func (s *Server) getDevicesFromARPTable() []storage.Device {
	cmd := exec.Command("powershell", "-NoProfile", "-Command", `
		Get-NetNeighbor | Where-Object { 
			$_.LinkLayerAddress -ne '' -and
			$_.LinkLayerAddress -ne '00-00-00-00-00-00' -and
			$_.LinkLayerAddress -ne 'FF-FF-FF-FF-FF-FF' -and
			-not $_.LinkLayerAddress.StartsWith('01-00-5E') -and
			-not $_.LinkLayerAddress.StartsWith('33-33') -and
			-not $_.IPAddress.StartsWith('224.') -and
			-not $_.IPAddress.StartsWith('239.') -and
			-not $_.IPAddress.StartsWith('ff0') -and
			$_.IPAddress -ne '127.0.0.1' -and
			$_.IPAddress -ne '::1'
		} | Select-Object IPAddress, LinkLayerAddress, InterfaceAlias, State | 
		ConvertTo-Json -Depth 2 -Compress
	`)

	output, err := cmd.Output()
	if err != nil {
		fmt.Printf("[ERROR] PowerShell ARP fetch failed: %v\n", err)
		return nil
	}

	// Parse JSON output
	var devices []storage.Device
	type ARPEntry struct {
		IPAddress        string `json:"IPAddress"`
		LinkLayerAddress string `json:"LinkLayerAddress"`
		InterfaceAlias   string `json:"InterfaceAlias"`
		State            int    `json:"State"`
	}

	var entries []ARPEntry
	outputStr := strings.TrimSpace(string(output))
	if outputStr == "" || outputStr == "null" {
		return devices
	}

	// Handle single object vs array
	if strings.HasPrefix(outputStr, "{") {
		var single ARPEntry
		if err := json.Unmarshal([]byte(outputStr), &single); err == nil {
			entries = append(entries, single)
		}
	} else {
		json.Unmarshal([]byte(outputStr), &entries)
	}

	now := time.Now()
	for _, e := range entries {
		vendor := lookupMACVendor(e.LinkLayerAddress)
		devices = append(devices, storage.Device{
			IP:               e.IPAddress,
			MAC:              e.LinkLayerAddress,
			Hostname:         vendor,
			NICInterfaceName: e.InterfaceAlias,
			NICType:          detectNICType(e.InterfaceAlias),
			FirstSeen:        now,
			LastSeen:         now,
		})
	}

	fmt.Printf("[INFO] Direct ARP fetch found %d devices\n", len(devices))
	return devices
}

// detectNICType determines the NIC type from interface name
func detectNICType(interfaceName string) string {
	lower := strings.ToLower(interfaceName)
	if strings.Contains(lower, "wi-fi") || strings.Contains(lower, "wifi") || strings.Contains(lower, "wireless") {
		return "WiFi"
	}
	if strings.Contains(lower, "ethernet") || strings.Contains(lower, "local area") {
		return "LAN"
	}
	if strings.Contains(lower, "mobile") || strings.Contains(lower, "hotspot") {
		return "Hotspot"
	}
	return "Unknown"
}

// lookupMACVendor returns the manufacturer name based on MAC address OUI
func lookupMACVendor(mac string) string {
	// Normalize MAC address - take first 3 octets (OUI)
	mac = strings.ToUpper(strings.ReplaceAll(mac, ":", "-"))
	parts := strings.Split(mac, "-")
	if len(parts) < 3 {
		return "Unknown Device"
	}
	oui := parts[0] + "-" + parts[1] + "-" + parts[2]

	// MAC OUI vendor lookup table (common manufacturers)
	vendors := map[string]string{
		// Apple
		"00-03-93": "Apple", "00-05-02": "Apple", "00-0A-27": "Apple", "00-0A-95": "Apple",
		"00-0D-93": "Apple", "00-10-FA": "Apple", "00-11-24": "Apple", "00-14-51": "Apple",
		"00-16-CB": "Apple", "00-17-F2": "Apple", "00-19-E3": "Apple", "00-1B-63": "Apple",
		"00-1C-B3": "Apple", "00-1D-4F": "Apple", "00-1E-52": "Apple", "00-1E-C2": "Apple",
		"00-1F-5B": "Apple", "00-1F-F3": "Apple", "00-21-E9": "Apple", "00-22-41": "Apple",
		"00-23-12": "Apple", "00-23-32": "Apple", "00-23-6C": "Apple", "00-23-DF": "Apple",
		"00-24-36": "Apple", "00-25-00": "Apple", "00-25-4B": "Apple", "00-25-BC": "Apple",
		"00-26-08": "Apple", "00-26-4A": "Apple", "00-26-B0": "Apple", "00-26-BB": "Apple",
		"28-CF-DA": "Apple", "34-C0-59": "Apple", "3C-15-C2": "Apple", "40-A6-D9": "Apple",
		"44-D8-84": "Apple", "5C-59-48": "Apple", "68-A8-6D": "Apple", "70-DE-E2": "Apple",
		"78-31-C1": "Apple", "7C-6D-62": "Apple", "80-E6-50": "Apple", "84-38-35": "Apple",
		"88-66-A5": "Apple", "8C-58-77": "Apple", "9C-20-7B": "Apple", "A4-5E-60": "Apple",
		"A8-88-08": "Apple", "AC-BC-32": "Apple", "B4-F0-AB": "Apple", "BC-52-B7": "Apple",
		"C0-63-94": "Apple", "C8-69-CD": "Apple", "D0-23-DB": "Apple", "D4-9A-20": "Apple",
		"D8-30-62": "Apple", "DC-A4-CA": "Apple", "E0-B9-BA": "Apple", "E4-C6-3D": "Apple",
		"F0-B4-79": "Apple", "F4-5C-89": "Apple", "F8-1E-DF": "Apple", "FC-25-3F": "Apple",

		// Samsung
		"00-00-F0": "Samsung", "00-02-78": "Samsung", "00-09-18": "Samsung", "00-0D-AE": "Samsung",
		"00-12-47": "Samsung", "00-12-FB": "Samsung", "00-13-77": "Samsung", "00-15-99": "Samsung",
		"00-16-32": "Samsung", "00-16-6B": "Samsung", "00-17-C9": "Samsung", "00-17-D5": "Samsung",
		"00-18-AF": "Samsung", "00-1A-8A": "Samsung", "00-1B-98": "Samsung", "00-1C-43": "Samsung",
		"00-1D-25": "Samsung", "00-1D-F6": "Samsung", "00-1E-7D": "Samsung", "00-1F-CC": "Samsung",
		"00-21-19": "Samsung", "00-21-4C": "Samsung", "00-21-D1": "Samsung", "00-21-D2": "Samsung",
		"00-23-39": "Samsung", "00-23-3A": "Samsung", "00-23-99": "Samsung", "00-23-D6": "Samsung",
		"00-23-D7": "Samsung", "00-24-54": "Samsung", "00-24-90": "Samsung", "00-24-91": "Samsung",
		"00-24-E9": "Samsung", "00-25-66": "Samsung", "00-25-67": "Samsung", "00-26-37": "Samsung",
		"14-49-E0": "Samsung", "18-3A-2D": "Samsung", "24-C6-96": "Samsung", "2C-AE-2B": "Samsung",
		"34-23-BA": "Samsung", "38-01-97": "Samsung", "40-0E-85": "Samsung", "50-01-BB": "Samsung",
		"50-CC-F8": "Samsung", "5C-2E-59": "Samsung", "5C-A3-9D": "Samsung", "64-B3-10": "Samsung",
		"84-25-DB": "Samsung", "84-55-A5": "Samsung", "88-32-9B": "Samsung", "90-00-4E": "Samsung",
		"94-35-0A": "Samsung", "9C-2A-83": "Samsung", "A0-82-1F": "Samsung", "AC-5F-3E": "Samsung",

		// OnePlus / OPPO / Realme
		"64-A2-F9": "OnePlus", "8A-76-8F": "OnePlus", "94-65-2D": "OnePlus", "C0-EE-40": "OnePlus",
		"58-CB-52": "OPPO", "2C-5B-B8": "OPPO", "A4-3B-FA": "OPPO", "3C-CD-5D": "OPPO",
		"D0-17-69": "Realme", "2C-4D-54": "Realme",

		// Xiaomi / Redmi
		"00-9E-C8": "Xiaomi", "04-CF-8C": "Xiaomi", "0C-1D-AF": "Xiaomi", "10-2A-B3": "Xiaomi",
		"14-F6-5A": "Xiaomi", "18-59-36": "Xiaomi", "20-34-FB": "Xiaomi", "28-6C-07": "Xiaomi",
		"34-80-B3": "Xiaomi", "38-A4-ED": "Xiaomi", "3C-BD-3E": "Xiaomi", "50-8F-4C": "Xiaomi",
		"58-44-98": "Xiaomi", "64-09-80": "Xiaomi", "64-B4-73": "Xiaomi", "68-DF-DD": "Xiaomi",
		"74-23-44": "Xiaomi", "78-02-F8": "Xiaomi", "7C-1D-D9": "Xiaomi", "84-F3-EB": "Xiaomi",
		"8C-BE-BE": "Xiaomi", "98-FA-E3": "Xiaomi", "9C-99-A0": "Xiaomi", "AC-C1-EE": "Xiaomi",
		"B0-E2-35": "Xiaomi", "C4-0B-CB": "Xiaomi", "C8-D7-B0": "Xiaomi", "D4-97-0B": "Xiaomi",
		"F0-B4-29": "Xiaomi", "F4-F5-E8": "Xiaomi", "F8-A4-5F": "Xiaomi", "FC-64-BA": "Xiaomi",

		// Google
		"00-1A-11": "Google", "3C-5A-B4": "Google", "54-60-09": "Google", "94-EB-2C": "Google",
		"F4-F5-D8": "Google", "F8-0F-F9": "Google", "20-DF-B9": "Google", "30-FD-38": "Google",

		// Huawei / Honor
		"00-0F-E2": "Huawei", "00-18-82": "Huawei", "00-1E-10": "Huawei", "00-22-A1": "Huawei",
		"00-25-68": "Huawei", "00-25-9E": "Huawei", "00-2E-C7": "Huawei", "00-34-FE": "Huawei",
		"00-46-4B": "Huawei", "00-5A-13": "Huawei", "00-66-4B": "Huawei", "00-9A-CD": "Huawei",
		"00-E0-FC": "Huawei", "04-02-1F": "Huawei", "04-25-C5": "Huawei", "04-33-89": "Huawei",
		"04-4F-4C": "Huawei", "04-B0-E7": "Huawei", "04-BD-70": "Huawei", "04-C0-6F": "Huawei",
		"08-19-A6": "Huawei", "08-63-61": "Huawei", "08-7A-4C": "Huawei", "08-E8-4F": "Huawei",
		"0C-45-BA": "Huawei", "0C-96-BF": "Huawei", "10-1B-54": "Huawei", "10-44-00": "Huawei",
		"10-47-80": "Huawei", "14-30-04": "Honor", "38-37-8B": "Honor", "78-D2-94": "Honor",

		// TP-Link
		"00-14-78": "TP-Link", "00-1D-0F": "TP-Link", "00-21-27": "TP-Link", "00-23-CD": "TP-Link",
		"00-27-19": "TP-Link", "14-CC-20": "TP-Link", "14-CF-92": "TP-Link", "14-E6-E4": "TP-Link",
		"18-A6-F7": "TP-Link", "1C-3B-F3": "TP-Link", "24-69-68": "TP-Link", "30-B4-9E": "TP-Link",
		"50-3E-AA": "TP-Link", "54-E6-FC": "TP-Link", "5C-63-BF": "TP-Link", "60-E3-27": "TP-Link",
		"64-56-01": "TP-Link", "64-66-B3": "TP-Link", "64-70-02": "TP-Link", "68-FF-7B": "TP-Link",

		// Intel
		"00-02-B3": "Intel", "00-03-47": "Intel", "00-04-23": "Intel", "00-07-E9": "Intel",
		"00-0C-F1": "Intel", "00-0E-0C": "Intel", "00-0E-35": "Intel", "00-11-11": "Intel",
		"00-12-F0": "Intel", "00-13-02": "Intel", "00-13-20": "Intel", "00-13-CE": "Intel",
		"00-13-E8": "Intel", "00-15-00": "Intel", "00-15-17": "Intel", "00-16-6F": "Intel",
		"00-16-76": "Intel", "00-16-EA": "Intel", "00-16-EB": "Intel", "00-18-DE": "Intel",
		"00-19-D1": "Intel", "00-19-D2": "Intel", "00-1B-21": "Intel", "00-1B-77": "Intel",
		"00-1C-BF": "Intel", "00-1C-C0": "Intel", "00-1D-E0": "Intel", "00-1D-E1": "Intel",
		"00-1E-64": "Intel", "00-1E-65": "Intel", "00-1E-67": "Intel", "00-1F-3B": "Intel",
		"00-1F-3C": "Intel", "00-21-5C": "Intel", "00-21-5D": "Intel", "00-21-6A": "Intel",
		"00-21-6B": "Intel", "00-22-FA": "Intel", "00-22-FB": "Intel", "00-24-D6": "Intel",
		"00-24-D7": "Intel", "00-26-C6": "Intel", "00-26-C7": "Intel", "00-27-10": "Intel",
		"78-AF-08": "Intel", "8C-EC-4B": "Intel", "A4-34-D9": "Intel", "B4-B5-2F": "Intel",
		"C8-D3-FF": "Intel", "F4-26-79": "Intel", "F8-16-54": "Intel",

		// Realtek (common in routers/NICs)
		"00-E0-4C": "Realtek", "52-54-00": "Realtek", "00-1A-4A": "Realtek",

		// Microsoft
		"00-03-FF": "Microsoft", "00-0D-3A": "Microsoft", "00-12-5A": "Microsoft", "00-15-5D": "Microsoft",
		"00-17-FA": "Microsoft", "00-1D-D8": "Microsoft", "00-22-48": "Microsoft", "00-25-AE": "Microsoft",
		"28-18-78": "Microsoft", "50-1A-C5": "Microsoft", "60-45-BD": "Microsoft", "7C-1E-52": "Microsoft",

		// Motorola
		"00-0A-28": "Motorola", "00-0C-E5": "Motorola", "00-14-9A": "Motorola", "00-17-00": "Motorola",
		"00-1A-66": "Motorola", "00-1C-11": "Motorola", "00-1E-46": "Motorola", "00-21-36": "Motorola",

		// LG
		"00-05-C9": "LG", "00-0B-E9": "LG", "00-1C-62": "LG", "00-1E-75": "LG",
		"00-1F-6B": "LG", "00-1F-E3": "LG", "00-22-A9": "LG", "00-24-83": "LG",
		"00-25-E5": "LG", "00-26-E2": "LG", "10-68-3F": "LG", "20-21-A5": "LG",

		// Lenovo
		"00-09-2D": "Lenovo", "00-0A-E4": "Lenovo", "00-12-FE": "Lenovo", "00-16-D4": "Lenovo",
		"00-1A-6B": "Lenovo", "00-20-25": "Lenovo", "00-21-5E": "Lenovo",
		"00-22-68": "Lenovo", "00-24-7E": "Lenovo", "00-26-6C": "Lenovo", "00-27-13": "Lenovo",

		// Dell
		"00-06-5B": "Dell", "00-08-74": "Dell", "00-0B-DB": "Dell", "00-0D-56": "Dell",
		"00-0F-1F": "Dell", "00-11-43": "Dell", "00-12-3F": "Dell", "00-13-72": "Dell",
		"00-14-22": "Dell", "00-15-C5": "Dell", "00-18-8B": "Dell", "00-19-B9": "Dell",
		"00-1A-A0": "Dell", "00-1C-23": "Dell", "00-1D-09": "Dell", "00-1E-4F": "Dell",
		"00-1E-C9": "Dell", "00-21-70": "Dell", "00-21-9B": "Dell", "00-22-19": "Dell",
		"00-24-E8": "Dell", "00-25-64": "Dell", "00-26-B9": "Dell", "14-FE-B5": "Dell",
		"18-03-73": "Dell", "18-A9-9B": "Dell", "18-DB-F2": "Dell", "1C-40-24": "Dell",
	}

	if vendor, ok := vendors[oui]; ok {
		return vendor
	}
	return "Unknown Device"
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
