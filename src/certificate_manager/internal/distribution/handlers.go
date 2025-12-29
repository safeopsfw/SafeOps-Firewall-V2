package distribution

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"
)

// ============================================================================
// Handler Configuration
// ============================================================================

// HandlersConfig contains configuration for HTTP handlers.
type HandlersConfig struct {
	CACertPath     string        // Path to root CA certificate PEM file
	CADerPath      string        // Path to root CA certificate DER file (optional)
	CRLPath        string        // Path to Certificate Revocation List
	BaseURL        string        // Base URL for scripts and profiles
	CacheMaxAge    time.Duration // Cache-Control max-age
	Organization   string        // Organization name
	CACommonName   string        // CA common name
	SupportEmail   string        // Support email
	EnableTracking bool          // Enable download tracking
}

// Handlers manages HTTP request handlers for certificate distribution.
type Handlers struct {
	config        *HandlersConfig
	tracker       *DownloadTracker
	qrGenerator   *QRCodeGenerator
	cachedDER     []byte
	cachedPEM     []byte
	cachedPEMETag string
	cachedDERETag string
	fingerprint   string
}

// ============================================================================
// Constructor
// ============================================================================

// NewHandlers creates a new handlers instance.
func NewHandlers(config *HandlersConfig) *Handlers {
	if config == nil {
		config = DefaultHandlersConfig()
	}

	h := &Handlers{
		config:      config,
		qrGenerator: NewQRCodeGenerator(config.BaseURL, DefaultQRCodeConfig()),
	}

	if config.EnableTracking {
		h.tracker = NewDownloadTracker(DefaultDownloadTrackerConfig())
		h.tracker.Start()
	}

	// Pre-load and cache certificate
	h.loadCertificate()

	return h
}

// DefaultHandlersConfig returns default configuration.
func DefaultHandlersConfig() *HandlersConfig {
	return &HandlersConfig{
		CACertPath:     "/etc/safeops/ca/root-cert.pem",
		BaseURL:        "http://192.168.1.1",
		CacheMaxAge:    24 * time.Hour,
		Organization:   "SafeOps",
		CACommonName:   "SafeOps Root CA",
		EnableTracking: true,
	}
}

// Stop stops the handlers and cleans up resources.
func (h *Handlers) Stop() {
	if h.tracker != nil {
		h.tracker.Stop()
	}
}

// ============================================================================
// Certificate Loading
// ============================================================================

// loadCertificate loads and caches the CA certificate.
func (h *Handlers) loadCertificate() error {
	// Load PEM
	pemData, err := os.ReadFile(h.config.CACertPath)
	if err != nil {
		return fmt.Errorf("failed to read CA certificate: %w", err)
	}
	h.cachedPEM = pemData
	h.cachedPEMETag = h.calculateETag(pemData)

	// Convert to DER
	derData, err := PEMToDER(pemData)
	if err != nil {
		return fmt.Errorf("failed to convert to DER: %w", err)
	}
	h.cachedDER = derData
	h.cachedDERETag = h.calculateETag(derData)

	// Calculate fingerprint
	h.fingerprint, _ = GetFingerprintFromBytes(pemData, FormatPEM)

	return nil
}

// calculateETag generates an ETag from data.
func (h *Handlers) calculateETag(data []byte) string {
	hash := sha256.Sum256(data)
	return fmt.Sprintf(`"%s"`, hex.EncodeToString(hash[:8]))
}

// ReloadCertificate reloads the CA certificate from disk.
func (h *Handlers) ReloadCertificate() error {
	return h.loadCertificate()
}

// ============================================================================
// Certificate Handlers
// ============================================================================

// HandleCACertPEM handles GET /ca.crt - serves CA certificate in PEM format.
func (h *Handlers) HandleCACertPEM(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		h.methodNotAllowed(w, r)
		return
	}

	// Check if certificate is loaded
	if len(h.cachedPEM) == 0 {
		if err := h.loadCertificate(); err != nil {
			h.internalError(w, r, "Certificate not available")
			return
		}
	}

	// Check conditional request
	if h.handleConditionalRequest(w, r, h.cachedPEMETag) {
		return
	}

	// Set headers
	w.Header().Set("Content-Type", "application/x-x509-ca-cert")
	w.Header().Set("Content-Disposition", `attachment; filename="safeops-root-ca.crt"`)
	w.Header().Set("Content-Length", strconv.Itoa(len(h.cachedPEM)))
	w.Header().Set("Cache-Control", fmt.Sprintf("public, max-age=%d", int(h.config.CacheMaxAge.Seconds())))
	w.Header().Set("ETag", h.cachedPEMETag)
	w.Header().Set("X-Content-Type-Options", "nosniff")

	// Track download
	h.trackDownload(r, "ca.crt", "PEM", len(h.cachedPEM))

	// Write response
	if r.Method == http.MethodGet {
		w.WriteHeader(http.StatusOK)
		w.Write(h.cachedPEM)
	} else {
		w.WriteHeader(http.StatusOK)
	}
}

// HandleCACertDER handles GET /ca.der - serves CA certificate in DER format.
func (h *Handlers) HandleCACertDER(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		h.methodNotAllowed(w, r)
		return
	}

	// Check if certificate is loaded
	if len(h.cachedDER) == 0 {
		if err := h.loadCertificate(); err != nil {
			h.internalError(w, r, "Certificate not available")
			return
		}
	}

	// Check conditional request
	if h.handleConditionalRequest(w, r, h.cachedDERETag) {
		return
	}

	// Set headers
	w.Header().Set("Content-Type", "application/pkix-cert")
	w.Header().Set("Content-Disposition", `attachment; filename="safeops-root-ca.der"`)
	w.Header().Set("Content-Length", strconv.Itoa(len(h.cachedDER)))
	w.Header().Set("Cache-Control", fmt.Sprintf("public, max-age=%d", int(h.config.CacheMaxAge.Seconds())))
	w.Header().Set("ETag", h.cachedDERETag)
	w.Header().Set("X-Content-Type-Options", "nosniff")

	// Track download
	h.trackDownload(r, "ca.der", "DER", len(h.cachedDER))

	// Write response
	if r.Method == http.MethodGet {
		w.WriteHeader(http.StatusOK)
		w.Write(h.cachedDER)
	} else {
		w.WriteHeader(http.StatusOK)
	}
}

// ============================================================================
// Script Handlers
// ============================================================================

// HandleInstallScriptLinux handles GET /install-ca.sh - Linux/macOS bash script.
func (h *Handlers) HandleInstallScriptLinux(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		h.methodNotAllowed(w, r)
		return
	}

	config := NewScriptConfig(h.config.BaseURL).
		WithOrganization(h.config.Organization).
		WithCertificateName(h.config.CACommonName).
		WithFingerprint(h.fingerprint)

	script, err := GenerateLinuxScript(config)
	if err != nil {
		h.internalError(w, r, "Failed to generate script")
		return
	}

	w.Header().Set("Content-Type", "application/x-sh")
	w.Header().Set("Content-Disposition", `attachment; filename="install-ca.sh"`)
	w.Header().Set("Content-Length", strconv.Itoa(len(script)))
	w.Header().Set("Cache-Control", "no-cache")

	h.trackDownload(r, "install-ca.sh", "Script", len(script))

	w.WriteHeader(http.StatusOK)
	io.WriteString(w, script)
}

// HandleInstallScriptWindows handles GET /install-ca.ps1 - Windows PowerShell script.
func (h *Handlers) HandleInstallScriptWindows(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		h.methodNotAllowed(w, r)
		return
	}

	config := NewScriptConfig(h.config.BaseURL).
		WithOrganization(h.config.Organization).
		WithCertificateName(h.config.CACommonName).
		WithFingerprint(h.fingerprint)

	script, err := GenerateWindowsScript(config)
	if err != nil {
		h.internalError(w, r, "Failed to generate script")
		return
	}

	w.Header().Set("Content-Type", "application/x-powershell")
	w.Header().Set("Content-Disposition", `attachment; filename="install-ca.ps1"`)
	w.Header().Set("Content-Length", strconv.Itoa(len(script)))
	w.Header().Set("Cache-Control", "no-cache")

	h.trackDownload(r, "install-ca.ps1", "Script", len(script))

	w.WriteHeader(http.StatusOK)
	io.WriteString(w, script)
}

// HandleInstallScriptMac handles GET /install-ca-mac.sh - macOS script.
func (h *Handlers) HandleInstallScriptMac(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		h.methodNotAllowed(w, r)
		return
	}

	config := NewScriptConfig(h.config.BaseURL).
		WithOrganization(h.config.Organization).
		WithCertificateName(h.config.CACommonName).
		WithFingerprint(h.fingerprint)

	script, err := GenerateMacScript(config)
	if err != nil {
		h.internalError(w, r, "Failed to generate script")
		return
	}

	w.Header().Set("Content-Type", "application/x-sh")
	w.Header().Set("Content-Disposition", `attachment; filename="install-ca-mac.sh"`)
	w.Header().Set("Content-Length", strconv.Itoa(len(script)))
	w.Header().Set("Cache-Control", "no-cache")

	h.trackDownload(r, "install-ca-mac.sh", "Script", len(script))

	w.WriteHeader(http.StatusOK)
	io.WriteString(w, script)
}

// HandleInstallScriptFirefox handles GET /install-ca-firefox.sh - Firefox script.
func (h *Handlers) HandleInstallScriptFirefox(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		h.methodNotAllowed(w, r)
		return
	}

	config := NewScriptConfig(h.config.BaseURL).
		WithOrganization(h.config.Organization).
		WithCertificateName(h.config.CACommonName).
		WithFingerprint(h.fingerprint)

	script, err := GenerateFirefoxScript(config)
	if err != nil {
		h.internalError(w, r, "Failed to generate script")
		return
	}

	w.Header().Set("Content-Type", "application/x-sh")
	w.Header().Set("Content-Disposition", `attachment; filename="install-ca-firefox.sh"`)
	w.Header().Set("Content-Length", strconv.Itoa(len(script)))
	w.Header().Set("Cache-Control", "no-cache")

	h.trackDownload(r, "install-ca-firefox.sh", "Script", len(script))

	w.WriteHeader(http.StatusOK)
	io.WriteString(w, script)
}

// ============================================================================
// Mobile Profile Handlers
// ============================================================================

// HandleMobileConfig handles GET /ca.mobileconfig - iOS configuration profile.
func (h *Handlers) HandleMobileConfig(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		h.methodNotAllowed(w, r)
		return
	}

	if len(h.cachedPEM) == 0 {
		if err := h.loadCertificate(); err != nil {
			h.internalError(w, r, "Certificate not available")
			return
		}
	}

	config := NewMobileProfileConfig(h.config.BaseURL).
		WithOrganization(h.config.Organization).
		WithDisplayName(h.config.CACommonName)

	profile, _, err := GenerateiOSProfile(h.cachedPEM, config)
	if err != nil {
		h.internalError(w, r, "Failed to generate mobile config")
		return
	}

	w.Header().Set("Content-Type", "application/x-apple-aspen-config")
	w.Header().Set("Content-Disposition", `attachment; filename="SafeOps-CA.mobileconfig"`)
	w.Header().Set("Content-Length", strconv.Itoa(len(profile)))
	w.Header().Set("Cache-Control", "no-cache")

	h.trackDownload(r, "ca.mobileconfig", "MobileConfig", len(profile))

	w.WriteHeader(http.StatusOK)
	w.Write(profile)
}

// HandleAndroidCert handles GET /ca-android.crt - Android certificate.
func (h *Handlers) HandleAndroidCert(w http.ResponseWriter, r *http.Request) {
	// Android prefers DER format
	h.HandleCACertDER(w, r)
}

// ============================================================================
// QR Code Handlers
// ============================================================================

// HandleQRCodeGeneric handles GET /ca-qr-code.png - generic QR code.
func (h *Handlers) HandleQRCodeGeneric(w http.ResponseWriter, r *http.Request) {
	h.serveQRCode(w, r, QRCodeTypeGeneric, "ca-qr-code.png")
}

// HandleQRCodeiOS handles GET /ca-qr-ios.png - iOS QR code.
func (h *Handlers) HandleQRCodeiOS(w http.ResponseWriter, r *http.Request) {
	h.serveQRCode(w, r, QRCodeTypeiOS, "ca-qr-ios.png")
}

// HandleQRCodeAndroid handles GET /ca-qr-android.png - Android QR code.
func (h *Handlers) HandleQRCodeAndroid(w http.ResponseWriter, r *http.Request) {
	h.serveQRCode(w, r, QRCodeTypeAndroid, "ca-qr-android.png")
}

// HandleQRCodeGuide handles GET /ca-qr-guide.png - trust guide QR code.
func (h *Handlers) HandleQRCodeGuide(w http.ResponseWriter, r *http.Request) {
	h.serveQRCode(w, r, QRCodeTypeTrustGuide, "ca-qr-guide.png")
}

// serveQRCode generates and serves a QR code.
func (h *Handlers) serveQRCode(w http.ResponseWriter, r *http.Request, qrType QRCodeType, filename string) {
	if r.Method != http.MethodGet {
		h.methodNotAllowed(w, r)
		return
	}

	// Parse size parameter
	size := 256
	if sizeParam := r.URL.Query().Get("size"); sizeParam != "" {
		if parsedSize, err := strconv.Atoi(sizeParam); err == nil && parsedSize >= 64 && parsedSize <= 1024 {
			size = parsedSize
		}
	}

	qrData, err := h.qrGenerator.GenerateQRCodeForTypeWithSize(qrType, size)
	if err != nil {
		h.internalError(w, r, "Failed to generate QR code")
		return
	}

	w.Header().Set("Content-Type", "image/png")
	w.Header().Set("Content-Disposition", fmt.Sprintf(`inline; filename="%s"`, filename))
	w.Header().Set("Content-Length", strconv.Itoa(len(qrData)))
	w.Header().Set("Cache-Control", "public, max-age=3600")

	h.trackDownload(r, filename, "QRCode", len(qrData))

	w.WriteHeader(http.StatusOK)
	w.Write(qrData)
}

// ============================================================================
// Trust Guide Handler
// ============================================================================

// HandleTrustGuide handles GET /trust-guide.html - trust instructions page.
func (h *Handlers) HandleTrustGuide(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		h.methodNotAllowed(w, r)
		return
	}

	config := NewTrustInstructionsConfig(h.config.BaseURL).
		WithOrganization(h.config.Organization).
		WithCAName(h.config.CACommonName).
		WithTitle("How to Install SafeOps Root CA").
		WithQRCodes(true)

	if h.config.SupportEmail != "" {
		config.WithSupportEmail(h.config.SupportEmail)
	}

	html, err := GenerateTrustGuide(config, h.fingerprint)
	if err != nil {
		h.internalError(w, r, "Failed to generate trust guide")
		return
	}

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Content-Length", strconv.Itoa(len(html)))
	w.Header().Set("Cache-Control", "no-cache")

	h.trackDownload(r, "trust-guide.html", "Page", len(html))

	w.WriteHeader(http.StatusOK)
	w.Write(html)
}

// HandleIndex handles GET / - redirects to trust guide.
func (h *Handlers) HandleIndex(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		h.notFound(w, r)
		return
	}
	h.HandleTrustGuide(w, r)
}

// ============================================================================
// CRL Handler
// ============================================================================

// HandleCRL handles GET /crl.pem - Certificate Revocation List.
func (h *Handlers) HandleCRL(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		h.methodNotAllowed(w, r)
		return
	}

	if h.config.CRLPath == "" {
		h.notFound(w, r)
		return
	}

	crlData, err := os.ReadFile(h.config.CRLPath)
	if err != nil {
		if os.IsNotExist(err) {
			h.notFound(w, r)
		} else {
			h.internalError(w, r, "Failed to read CRL")
		}
		return
	}

	etag := h.calculateETag(crlData)
	if h.handleConditionalRequest(w, r, etag) {
		return
	}

	w.Header().Set("Content-Type", "application/pkix-crl")
	w.Header().Set("Content-Disposition", `attachment; filename="safeops.crl"`)
	w.Header().Set("Content-Length", strconv.Itoa(len(crlData)))
	w.Header().Set("Cache-Control", "max-age=86400, must-revalidate")
	w.Header().Set("ETag", etag)

	h.trackDownload(r, "crl.pem", "CRL", len(crlData))

	w.WriteHeader(http.StatusOK)
	w.Write(crlData)
}

// ============================================================================
// Health Check Handler
// ============================================================================

// HealthResponse represents the health check response.
type HealthResponse struct {
	Status      string    `json:"status"`
	CAValid     bool      `json:"ca_valid"`
	Timestamp   time.Time `json:"timestamp"`
	Version     string    `json:"version,omitempty"`
	Fingerprint string    `json:"fingerprint,omitempty"`
}

// HandleHealth handles GET /health - health check endpoint.
func (h *Handlers) HandleHealth(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		h.methodNotAllowed(w, r)
		return
	}

	response := HealthResponse{
		Status:      "healthy",
		CAValid:     len(h.cachedPEM) > 0,
		Timestamp:   time.Now(),
		Version:     "1.0.0",
		Fingerprint: h.fingerprint,
	}

	// Check if CA certificate is available
	if !response.CAValid {
		response.Status = "degraded"
		w.WriteHeader(http.StatusServiceUnavailable)
	} else {
		w.WriteHeader(http.StatusOK)
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}

// ============================================================================
// Metrics Handler
// ============================================================================

// HandleMetrics handles GET /metrics - Prometheus metrics.
func (h *Handlers) HandleMetrics(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		h.methodNotAllowed(w, r)
		return
	}

	// Get tracker metrics
	var metrics *DownloadMetrics
	if h.tracker != nil {
		metrics = h.tracker.GetMetrics()
	}

	w.Header().Set("Content-Type", "text/plain; version=0.0.4")
	w.WriteHeader(http.StatusOK)

	// Write Prometheus-format metrics
	if metrics != nil {
		fmt.Fprintf(w, "# HELP safeops_ca_downloads_total Total CA certificate downloads\n")
		fmt.Fprintf(w, "# TYPE safeops_ca_downloads_total counter\n")
		fmt.Fprintf(w, "safeops_ca_downloads_total %d\n\n", metrics.TotalDownloads)

		fmt.Fprintf(w, "# HELP safeops_ca_downloads_success Successful downloads\n")
		fmt.Fprintf(w, "# TYPE safeops_ca_downloads_success counter\n")
		fmt.Fprintf(w, "safeops_ca_downloads_success %d\n\n", metrics.SuccessfulDownloads)

		fmt.Fprintf(w, "# HELP safeops_ca_unique_devices Unique device IPs\n")
		fmt.Fprintf(w, "# TYPE safeops_ca_unique_devices gauge\n")
		fmt.Fprintf(w, "safeops_ca_unique_devices %d\n\n", metrics.UniqueIPs)

		fmt.Fprintf(w, "# HELP safeops_ca_downloads_per_hour Downloads per hour\n")
		fmt.Fprintf(w, "# TYPE safeops_ca_downloads_per_hour gauge\n")
		fmt.Fprintf(w, "safeops_ca_downloads_per_hour %.2f\n\n", metrics.DownloadsPerHour)

		for format, count := range metrics.ByFormat {
			fmt.Fprintf(w, "safeops_ca_downloads_by_format{format=\"%s\"} %d\n", format, count)
		}
		fmt.Fprintln(w)

		for platform, count := range metrics.ByPlatform {
			fmt.Fprintf(w, "safeops_ca_downloads_by_platform{platform=\"%s\"} %d\n", platform, count)
		}
	}
}

// ============================================================================
// Helper Functions
// ============================================================================

// handleConditionalRequest handles ETag-based conditional requests.
func (h *Handlers) handleConditionalRequest(w http.ResponseWriter, r *http.Request, etag string) bool {
	ifNoneMatch := r.Header.Get("If-None-Match")
	if ifNoneMatch != "" && ifNoneMatch == etag {
		w.WriteHeader(http.StatusNotModified)
		return true
	}
	return false
}

// trackDownload logs a download event.
func (h *Handlers) trackDownload(r *http.Request, resource string, format string, size int) {
	if h.tracker == nil {
		return
	}

	ip := h.getClientIP(r)
	h.tracker.TrackDownloadSimple(ip, resource, format, r.UserAgent(), http.StatusOK, int64(size))
}

// getClientIP extracts the client IP from the request.
func (h *Handlers) getClientIP(r *http.Request) string {
	// Check X-Forwarded-For header
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		parts := strings.Split(xff, ",")
		return strings.TrimSpace(parts[0])
	}

	// Check X-Real-IP header
	if xri := r.Header.Get("X-Real-IP"); xri != "" {
		return xri
	}

	// Fall back to RemoteAddr
	ip := r.RemoteAddr
	if colonIdx := strings.LastIndex(ip, ":"); colonIdx != -1 {
		// Check if it's IPv6
		if strings.Count(ip, ":") > 1 {
			// IPv6 - handle [ip]:port format
			if strings.HasPrefix(ip, "[") {
				if bracketIdx := strings.Index(ip, "]"); bracketIdx != -1 {
					ip = ip[1:bracketIdx]
				}
			}
		} else {
			ip = ip[:colonIdx]
		}
	}
	return ip
}

// ============================================================================
// Error Handlers
// ============================================================================

// notFound returns a 404 Not Found response.
func (h *Handlers) notFound(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/plain")
	w.WriteHeader(http.StatusNotFound)
	fmt.Fprintf(w, "404 Not Found: %s", r.URL.Path)
}

// methodNotAllowed returns a 405 Method Not Allowed response.
func (h *Handlers) methodNotAllowed(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Allow", "GET, HEAD")
	w.WriteHeader(http.StatusMethodNotAllowed)
	fmt.Fprintf(w, "405 Method Not Allowed: %s", r.Method)
}

// internalError returns a 500 Internal Server Error response.
func (h *Handlers) internalError(w http.ResponseWriter, _ *http.Request, message string) {
	w.Header().Set("Content-Type", "text/plain")
	w.WriteHeader(http.StatusInternalServerError)
	fmt.Fprintf(w, "500 Internal Server Error: %s", message)
}

// ============================================================================
// Route Registration
// ============================================================================

// RegisterRoutes registers all handlers to an HTTP mux.
func (h *Handlers) RegisterRoutes(mux *http.ServeMux) {
	// Certificate endpoints
	mux.HandleFunc("/ca.crt", h.HandleCACertPEM)
	mux.HandleFunc("/ca.pem", h.HandleCACertPEM)
	mux.HandleFunc("/ca.der", h.HandleCACertDER)
	mux.HandleFunc("/ca.cer", h.HandleCACertDER)

	// Script endpoints
	mux.HandleFunc("/install-ca.sh", h.HandleInstallScriptLinux)
	mux.HandleFunc("/install-ca.ps1", h.HandleInstallScriptWindows)
	mux.HandleFunc("/install-ca-mac.sh", h.HandleInstallScriptMac)
	mux.HandleFunc("/install-ca-firefox.sh", h.HandleInstallScriptFirefox)

	// Mobile profile endpoints
	mux.HandleFunc("/ca.mobileconfig", h.HandleMobileConfig)
	mux.HandleFunc("/ca-android.crt", h.HandleAndroidCert)

	// QR code endpoints
	mux.HandleFunc("/ca-qr-code.png", h.HandleQRCodeGeneric)
	mux.HandleFunc("/ca-qr-ios.png", h.HandleQRCodeiOS)
	mux.HandleFunc("/ca-qr-android.png", h.HandleQRCodeAndroid)
	mux.HandleFunc("/ca-qr-guide.png", h.HandleQRCodeGuide)

	// Trust guide endpoints
	mux.HandleFunc("/trust-guide", h.HandleTrustGuide)
	mux.HandleFunc("/trust-guide.html", h.HandleTrustGuide)
	mux.HandleFunc("/help", h.HandleTrustGuide)

	// CRL endpoint
	mux.HandleFunc("/crl.pem", h.HandleCRL)
	mux.HandleFunc("/crl", h.HandleCRL)

	// Utility endpoints
	mux.HandleFunc("/health", h.HandleHealth)
	mux.HandleFunc("/healthz", h.HandleHealth)
	mux.HandleFunc("/metrics", h.HandleMetrics)

	// Index
	mux.HandleFunc("/", h.HandleIndex)
}

// GetTracker returns the download tracker instance.
func (h *Handlers) GetTracker() *DownloadTracker {
	return h.tracker
}

// GetFingerprint returns the CA certificate fingerprint.
func (h *Handlers) GetFingerprint() string {
	return h.fingerprint
}

// ServeFile serves a static file from the filesystem.
func (h *Handlers) ServeFile(w http.ResponseWriter, r *http.Request, filepath string) {
	data, err := os.ReadFile(filepath)
	if err != nil {
		if os.IsNotExist(err) {
			h.notFound(w, r)
		} else {
			h.internalError(w, r, "Failed to read file")
		}
		return
	}

	// Detect content type
	contentType := http.DetectContentType(data)
	w.Header().Set("Content-Type", contentType)
	w.Header().Set("Content-Length", strconv.Itoa(len(data)))
	w.WriteHeader(http.StatusOK)
	w.Write(data)
}
