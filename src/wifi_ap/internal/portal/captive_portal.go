// Package portal provides captive portal functionality for WiFi AP.
// This includes CA certificate distribution for network clients.
package portal

import (
	"context"
	"fmt"
	"html/template"
	"log"
	"net"
	"net/http"
	"sync"
	"time"
)

// ============================================================================
// Configuration
// ============================================================================

// CaptivePortalConfig holds captive portal configuration.
type CaptivePortalConfig struct {
	ListenAddress      string        // Listen address (e.g., ":80", ":8080")
	CertManagerBaseURL string        // Certificate Manager base URL for CA distribution
	PortalTitle        string        // Portal page title
	Organization       string        // Organization name
	WelcomeMessage     string        // Welcome message
	RedirectDelay      time.Duration // Auto-redirect delay (0 to disable)
	EnableCARedirect   bool          // Auto-redirect to CA download page
	TrustedNetworks    []string      // Networks that bypass captive portal
}

// DefaultCaptivePortalConfig returns default configuration.
func DefaultCaptivePortalConfig() *CaptivePortalConfig {
	return &CaptivePortalConfig{
		ListenAddress:      ":80",
		CertManagerBaseURL: "http://192.168.1.1",
		PortalTitle:        "SafeOps WiFi Network",
		Organization:       "SafeOps",
		WelcomeMessage:     "Welcome to the SafeOps secure network.",
		RedirectDelay:      0,
		EnableCARedirect:   true,
		TrustedNetworks: []string{
			"192.168.1.0/24",
		},
	}
}

// ============================================================================
// Captive Portal Server
// ============================================================================

// CaptivePortal implements a basic captive portal with CA distribution.
type CaptivePortal struct {
	config     *CaptivePortalConfig
	server     *http.Server
	templates  *template.Template
	mu         sync.RWMutex
	running    bool
	connTrack  map[string]time.Time // Track client connections
	connTrackMu sync.RWMutex
}

// NewCaptivePortal creates a new captive portal instance.
func NewCaptivePortal(config *CaptivePortalConfig) (*CaptivePortal, error) {
	if config == nil {
		config = DefaultCaptivePortalConfig()
	}

	portal := &CaptivePortal{
		config:    config,
		connTrack: make(map[string]time.Time),
	}

	// Parse templates
	if err := portal.loadTemplates(); err != nil {
		return nil, fmt.Errorf("failed to load templates: %w", err)
	}

	// Create HTTP server
	mux := http.NewServeMux()
	portal.registerRoutes(mux)

	portal.server = &http.Server{
		Addr:         config.ListenAddress,
		Handler:      portal.loggingMiddleware(mux),
		ReadTimeout:  15 * time.Second,
		WriteTimeout: 30 * time.Second,
		IdleTimeout:  60 * time.Second,
	}

	return portal, nil
}

// ============================================================================
// Server Lifecycle
// ============================================================================

// Start starts the captive portal server.
func (p *CaptivePortal) Start() error {
	p.mu.Lock()
	if p.running {
		p.mu.Unlock()
		return fmt.Errorf("captive portal already running")
	}
	p.running = true
	p.mu.Unlock()

	log.Printf("[Portal] Starting captive portal on %s", p.config.ListenAddress)
	log.Printf("[Portal] Certificate Manager URL: %s", p.config.CertManagerBaseURL)

	go func() {
		if err := p.server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Printf("[Portal] Server error: %v", err)
		}
	}()

	return nil
}

// Stop gracefully stops the captive portal server.
func (p *CaptivePortal) Stop() error {
	p.mu.Lock()
	if !p.running {
		p.mu.Unlock()
		return fmt.Errorf("captive portal not running")
	}
	p.running = false
	p.mu.Unlock()

	log.Printf("[Portal] Stopping captive portal")

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	return p.server.Shutdown(ctx)
}

// IsRunning returns whether the portal is running.
func (p *CaptivePortal) IsRunning() bool {
	p.mu.RLock()
	defer p.mu.RUnlock()
	return p.running
}

// ============================================================================
// Route Registration
// ============================================================================

func (p *CaptivePortal) registerRoutes(mux *http.ServeMux) {
	// Main portal page
	mux.HandleFunc("/", p.handleIndex)
	mux.HandleFunc("/index.html", p.handleIndex)

	// CA certificate distribution page
	mux.HandleFunc("/setup-ca", p.handleCASetup)
	mux.HandleFunc("/setup", p.handleCASetup)
	mux.HandleFunc("/ca", p.handleCASetup)

	// Direct download endpoints (redirect to Certificate Manager)
	mux.HandleFunc("/download/ca.crt", p.handleCADownload)
	mux.HandleFunc("/download/install.sh", p.handleScriptDownload("install-ca.sh"))
	mux.HandleFunc("/download/install.ps1", p.handleScriptDownload("install-ca.ps1"))
	mux.HandleFunc("/download/install-mac.sh", p.handleScriptDownload("install-ca-mac.sh"))

	// Mobile configuration
	mux.HandleFunc("/download/ca.mobileconfig", p.handleMobileConfigDownload)

	// Status and health
	mux.HandleFunc("/health", p.handleHealth)
	mux.HandleFunc("/status", p.handleStatus)

	// Captive portal detection endpoints (for iOS, Android, Windows)
	mux.HandleFunc("/generate_204", p.handleCaptiveDetection)
	mux.HandleFunc("/hotspot-detect.html", p.handleCaptiveDetection)
	mux.HandleFunc("/ncsi.txt", p.handleCaptiveDetection)
	mux.HandleFunc("/connecttest.txt", p.handleCaptiveDetection)

	// Register Android-specific routes
	p.registerAndroidRoutes(mux)
}

// ============================================================================
// Handlers
// ============================================================================

// handleIndex serves the main captive portal page.
func (p *CaptivePortal) handleIndex(w http.ResponseWriter, r *http.Request) {
	clientIP := p.getClientIP(r)
	p.trackConnection(clientIP)

	// If auto-redirect to CA setup is enabled
	if p.config.EnableCARedirect && r.URL.Path == "/" {
		http.Redirect(w, r, "/setup-ca", http.StatusTemporaryRedirect)
		return
	}

	data := map[string]interface{}{
		"Title":          p.config.PortalTitle,
		"Organization":   p.config.Organization,
		"Message":        p.config.WelcomeMessage,
		"CASetupURL":     "/setup-ca",
		"CertManagerURL": p.config.CertManagerBaseURL,
	}

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := p.templates.ExecuteTemplate(w, "index.html", data); err != nil {
		log.Printf("[Portal] Template error: %v", err)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
	}
}

// handleCASetup serves the CA certificate setup page.
func (p *CaptivePortal) handleCASetup(w http.ResponseWriter, r *http.Request) {
	clientIP := p.getClientIP(r)
	userAgent := r.UserAgent()
	osType := p.detectOS(userAgent)

	data := map[string]interface{}{
		"Title":             p.config.PortalTitle + " - CA Setup",
		"Organization":      p.config.Organization,
		"CertManagerURL":    p.config.CertManagerBaseURL,
		"OSType":            osType,
		"ClientIP":          clientIP,
		"CACertURL":         p.config.CertManagerBaseURL + "/ca.crt",
		"CADerURL":          p.config.CertManagerBaseURL + "/ca.der",
		"InstallScriptURL":  p.getInstallScriptURL(osType),
		"MobileConfigURL":   p.config.CertManagerBaseURL + "/ca.mobileconfig",
		"TrustGuideURL":     p.config.CertManagerBaseURL + "/trust-guide.html",
		"QRCodeURL":         p.config.CertManagerBaseURL + "/ca-qr-code.png",
		"ShowWindowsSteps":  osType == "Windows",
		"ShowMacSteps":      osType == "macOS",
		"ShowLinuxSteps":    osType == "Linux",
		"ShowiOSSteps":      osType == "iOS",
		"ShowAndroidSteps":  osType == "Android",
	}

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := p.templates.ExecuteTemplate(w, "ca_setup.html", data); err != nil {
		log.Printf("[Portal] Template error: %v", err)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
	}
}

// handleCADownload redirects to Certificate Manager CA download.
func (p *CaptivePortal) handleCADownload(w http.ResponseWriter, r *http.Request) {
	downloadURL := p.config.CertManagerBaseURL + "/ca.crt"
	http.Redirect(w, r, downloadURL, http.StatusTemporaryRedirect)
}

// handleScriptDownload returns a handler that redirects to a specific install script.
func (p *CaptivePortal) handleScriptDownload(scriptName string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		scriptURL := p.config.CertManagerBaseURL + "/" + scriptName
		http.Redirect(w, r, scriptURL, http.StatusTemporaryRedirect)
	}
}

// handleMobileConfigDownload redirects to Certificate Manager mobile config.
func (p *CaptivePortal) handleMobileConfigDownload(w http.ResponseWriter, r *http.Request) {
	configURL := p.config.CertManagerBaseURL + "/ca.mobileconfig"
	http.Redirect(w, r, configURL, http.StatusTemporaryRedirect)
}

// handleCaptiveDetection handles OS captive portal detection requests.
func (p *CaptivePortal) handleCaptiveDetection(w http.ResponseWriter, r *http.Request) {
	// Return non-200 status to indicate captive portal presence
	// This triggers the OS to open the captive portal browser

	w.Header().Set("Content-Type", "text/html")
	w.WriteHeader(http.StatusFound)

	// Redirect to CA setup page
	redirectURL := fmt.Sprintf("http://%s/setup-ca", r.Host)
	w.Header().Set("Location", redirectURL)

	fmt.Fprintf(w, `<html><head><meta http-equiv="refresh" content="0; url=%s"></head></html>`, redirectURL)
}

// handleHealth returns portal health status.
func (p *CaptivePortal) handleHealth(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	fmt.Fprintf(w, `{"status":"healthy","running":%v}`, p.IsRunning())
}

// handleStatus returns portal statistics.
func (p *CaptivePortal) handleStatus(w http.ResponseWriter, r *http.Request) {
	p.connTrackMu.RLock()
	connCount := len(p.connTrack)
	p.connTrackMu.RUnlock()

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	fmt.Fprintf(w, `{"status":"running","connected_clients":%d}`, connCount)
}

// ============================================================================
// Helper Functions
// ============================================================================

func (p *CaptivePortal) getClientIP(r *http.Request) string {
	// Check X-Forwarded-For
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		return xff
	}

	// Check X-Real-IP
	if xri := r.Header.Get("X-Real-IP"); xri != "" {
		return xri
	}

	// Parse RemoteAddr
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

func (p *CaptivePortal) detectOS(userAgent string) string {
	ua := userAgent

	if contains(ua, "Windows") {
		return "Windows"
	}
	if contains(ua, "Macintosh") || contains(ua, "Mac OS X") {
		return "macOS"
	}
	if contains(ua, "iPhone") || contains(ua, "iPad") {
		return "iOS"
	}
	if contains(ua, "Android") {
		return "Android"
	}
	if contains(ua, "Linux") {
		return "Linux"
	}

	return "Unknown"
}

func (p *CaptivePortal) getInstallScriptURL(osType string) string {
	baseURL := p.config.CertManagerBaseURL

	switch osType {
	case "Windows":
		return baseURL + "/install-ca.ps1"
	case "macOS":
		return baseURL + "/install-ca-mac.sh"
	case "Linux":
		return baseURL + "/install-ca.sh"
	default:
		return baseURL + "/install-ca.sh"
	}
}

func (p *CaptivePortal) trackConnection(clientIP string) {
	p.connTrackMu.Lock()
	defer p.connTrackMu.Unlock()
	p.connTrack[clientIP] = time.Now()
}

func contains(s, substr string) bool {
	return len(s) >= len(substr) && (s == substr || len(s) > len(substr) &&
		(s[:len(substr)] == substr || s[len(s)-len(substr):] == substr ||
		len(s) > len(substr)+1 && findSubstring(s, substr)))
}

func findSubstring(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}

// ============================================================================
// Middleware
// ============================================================================

func (p *CaptivePortal) loggingMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		clientIP := p.getClientIP(r)

		next.ServeHTTP(w, r)

		duration := time.Since(start)
		log.Printf("[Portal] %s | %s %s | %v", clientIP, r.Method, r.URL.Path, duration)
	})
}

// ============================================================================
// Template Loading
// ============================================================================

func (p *CaptivePortal) loadTemplates() error {
	tmpl := template.New("")

	// Index template
	tmpl, err := tmpl.New("index.html").Parse(indexTemplate)
	if err != nil {
		return err
	}

	// CA Setup template
	tmpl, err = tmpl.New("ca_setup.html").Parse(caSetupTemplate)
	if err != nil {
		return err
	}

	// Android-specific templates
	tmpl, err = tmpl.New("android_setup.html").Parse(androidSetupTemplate)
	if err != nil {
		return err
	}

	tmpl, err = tmpl.New("android_verify.html").Parse(androidVerifyTemplate)
	if err != nil {
		return err
	}

	p.templates = tmpl
	return nil
}
