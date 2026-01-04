// ============================================================================
// SafeOps Captive Portal - HTTP Handlers
// ============================================================================
// File: D:\SafeOpsFV2\src\captive_portal\internal\server\handlers.go
// Purpose: HTTP request handlers for all portal endpoints
//
// Endpoints:
//   GET  /                    - Welcome page (renders template)
//   GET  /success             - Success page
//   GET  /error               - Error page
//   GET  /api/download-ca/:format - Download CA certificate
//   GET  /api/verify-trust    - Check if device is trusted
//   POST /api/mark-trusted    - Mark device as trusted
//   GET  /health              - Health check endpoint
//   GET  /static/*            - Static files (CSS, JS)
//
// Author: SafeOps Phase 3A
// Date: 2026-01-03
// ============================================================================

package server

import (
	"context"
	"encoding/json"
	"fmt"
	"html/template"
	"log"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"captive_portal/internal/config"
	"captive_portal/internal/database"
	"captive_portal/internal/stepca"
)

// ============================================================================
// Handler Dependencies
// ============================================================================

// Handlers holds all HTTP handler dependencies
type Handlers struct {
	config       *config.Config
	templates    *template.Template
	dhcpClient   *database.DHCPClient
	stepcaClient *stepca.StepCAClient
	osStats      *OSStats
}

// NewHandlers creates a new Handlers instance
func NewHandlers(cfg *config.Config, dhcp *database.DHCPClient, stepCA *stepca.StepCAClient) (*Handlers, error) {
	// Load templates
	tmplPath := filepath.Join(cfg.Templates.Path, "*.html")
	templates, err := template.ParseGlob(tmplPath)
	if err != nil {
		return nil, fmt.Errorf("failed to parse templates: %w", err)
	}

	return &Handlers{
		config:       cfg,
		templates:    templates,
		dhcpClient:   dhcp,
		stepcaClient: stepCA,
		osStats:      NewOSStats(),
	}, nil
}

// ============================================================================
// Template Data Structures
// ============================================================================

// PageData is the base data structure for all pages
type PageData struct {
	PortalConfig PortalConfigData `json:"portal_config"`
	DeviceInfo   *DeviceInfoData  `json:"device_info,omitempty"`
	DetectedOS   string           `json:"detected_os"`
	CAInfo       *CAInfoData      `json:"ca_info,omitempty"`
	Error        *ErrorData       `json:"error,omitempty"`
}

// PortalConfigData contains portal configuration for templates
type PortalConfigData struct {
	Title             string `json:"title"`
	WelcomeMessage    string `json:"welcome_message"`
	CACertName        string `json:"ca_cert_name"`
	AutoVerifyEnabled bool   `json:"auto_verify_enabled"`
}

// DeviceInfoData contains device information for templates
type DeviceInfoData struct {
	CurrentIP   string `json:"current_ip"`
	MACAddress  string `json:"mac_address"`
	Vendor      string `json:"vendor"`
	TrustStatus string `json:"trust_status"`
	DeviceType  string `json:"device_type"`
}

// CAInfoData contains certificate information
type CAInfoData struct {
	Subject     string `json:"subject"`
	Fingerprint string `json:"fingerprint"`
	ExpiresAt   string `json:"expires_at"`
}

// ErrorData contains error information for error page
type ErrorData struct {
	Code    string `json:"code"`
	Title   string `json:"title"`
	Message string `json:"message"`
	Details string `json:"details,omitempty"`
}

// ============================================================================
// Helper Functions
// ============================================================================

// getClientIP extracts the real client IP from the request
func getClientIP(r *http.Request) string {
	// Check X-Forwarded-For header first (for reverse proxies)
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		// Take the first IP in the chain
		if idx := strings.Index(xff, ","); idx != -1 {
			return strings.TrimSpace(xff[:idx])
		}
		return strings.TrimSpace(xff)
	}

	// Check X-Real-IP header
	if xri := r.Header.Get("X-Real-IP"); xri != "" {
		return xri
	}

	// Fall back to RemoteAddr
	ip, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return ip
}

// buildPageData creates the base page data for templates
func (h *Handlers) buildPageData(r *http.Request) PageData {
	return PageData{
		PortalConfig: PortalConfigData{
			Title:             h.config.Portal.Title,
			WelcomeMessage:    h.config.Portal.WelcomeMessage,
			CACertName:        h.config.Portal.CACertName,
			AutoVerifyEnabled: h.config.Portal.AutoVerifyEnabled,
		},
		DetectedOS: DetectOSFromRequest(r),
	}
}

// renderTemplate renders a template with error handling
func (h *Handlers) renderTemplate(w http.ResponseWriter, name string, data interface{}) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")

	if err := h.templates.ExecuteTemplate(w, name, data); err != nil {
		log.Printf("[Handlers] Template render error: %v", err)
		http.Error(w, "Internal server error", http.StatusInternalServerError)
	}
}

// sendJSON sends a JSON response
func sendJSON(w http.ResponseWriter, status int, data interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)

	if err := json.NewEncoder(w).Encode(data); err != nil {
		log.Printf("[Handlers] JSON encode error: %v", err)
	}
}

// ============================================================================
// Page Handlers
// ============================================================================

// HandleWelcome serves the main welcome/landing page
func (h *Handlers) HandleWelcome(w http.ResponseWriter, r *http.Request) {
	log.Printf("[Handlers] Welcome page request from %s", getClientIP(r))

	// Track OS statistics
	osInfo := GetOSInfoFromRequest(r)
	h.osStats.Record(osInfo)

	// Build page data
	data := h.buildPageData(r)

	// Try to get device info from DHCP Monitor
	if h.dhcpClient != nil {
		ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
		defer cancel()

		clientIP := getClientIP(r)
		device, err := h.dhcpClient.GetDeviceByIP(ctx, clientIP)
		if err == nil && device != nil {
			data.DeviceInfo = &DeviceInfoData{
				CurrentIP:   device.CurrentIP,
				MACAddress:  device.MACAddress,
				Vendor:      device.Vendor,
				TrustStatus: device.TrustStatus,
				DeviceType:  device.DeviceType,
			}
		} else {
			// Device not found, use IP from request
			data.DeviceInfo = &DeviceInfoData{
				CurrentIP:   clientIP,
				TrustStatus: "UNTRUSTED",
			}
		}
	}

	h.renderTemplate(w, "welcome.html", data)
}

// HandleSuccess serves the success page
func (h *Handlers) HandleSuccess(w http.ResponseWriter, r *http.Request) {
	log.Printf("[Handlers] Success page request from %s", getClientIP(r))

	data := h.buildPageData(r)

	// Get device info to show trusted status
	if h.dhcpClient != nil {
		ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
		defer cancel()

		clientIP := getClientIP(r)
		device, err := h.dhcpClient.GetDeviceByIP(ctx, clientIP)
		if err == nil && device != nil {
			data.DeviceInfo = &DeviceInfoData{
				CurrentIP:   device.CurrentIP,
				TrustStatus: device.TrustStatus,
			}
		}
	}

	h.renderTemplate(w, "success.html", data)
}

// HandleError serves the error page
func (h *Handlers) HandleError(w http.ResponseWriter, r *http.Request) {
	data := h.buildPageData(r)

	// Get error details from query params
	data.Error = &ErrorData{
		Code:    r.URL.Query().Get("code"),
		Title:   r.URL.Query().Get("title"),
		Message: r.URL.Query().Get("message"),
	}

	if data.Error.Title == "" {
		data.Error.Title = "Error"
	}
	if data.Error.Message == "" {
		data.Error.Message = "An unexpected error occurred."
	}

	h.renderTemplate(w, "error.html", data)
}

// ============================================================================
// API Handlers
// ============================================================================

// HandleDownloadCA handles certificate download requests
func (h *Handlers) HandleDownloadCA(w http.ResponseWriter, r *http.Request) {
	// Extract format from path: /api/download-ca/{format}
	format := strings.TrimPrefix(r.URL.Path, "/api/download-ca/")
	if format == "" || format == r.URL.Path {
		format = "pem" // Default to PEM
	}

	log.Printf("[Handlers] Certificate download request: format=%s, client=%s", format, getClientIP(r))

	// Try to read Root CA from TLS Proxy's generated file first
	rootCAPath := "D:/SafeOpsFV2/src/tls_proxy/certs/safeops-root-ca.crt"
	certData, err := os.ReadFile(rootCAPath)

	if err != nil {
		log.Printf("[Handlers] Failed to read root CA from %s: %v", rootCAPath, err)

		// Fallback to Step-CA client if available
		if h.stepcaClient != nil {
			ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
			defer cancel()

			certData, _, err = h.stepcaClient.GetCertificateInFormat(ctx, format)
			if err != nil {
				log.Printf("[Handlers] Certificate fetch error: %v", err)
			}
		}

		// If still no cert data, return error
		if certData == nil || len(certData) == 0 {
			log.Printf("[Handlers] No certificate available - TLS Proxy not running and Step-CA unavailable")
			sendJSON(w, http.StatusInternalServerError, map[string]string{
				"error": "Failed to fetch certificate - ensure TLS Proxy is running first",
			})
			return
		}
	}

	// Determine MIME type based on format
	mimeType := "application/x-pem-file"
	if format == "der" {
		mimeType = "application/x-x509-ca-cert"
	} else if format == "p12" || format == "pkcs12" {
		mimeType = "application/x-pkcs12"
	}

	// Set headers for download
	filename := fmt.Sprintf("SafeOps_Root_CA%s", GetFileExtension(format))
	w.Header().Set("Content-Type", mimeType)
	w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=\"%s\"", filename))
	w.Header().Set("Content-Length", fmt.Sprintf("%d", len(certData)))
	w.Header().Set("Cache-Control", "no-cache, no-store, must-revalidate")

	// Phase 3B: Mark that device has downloaded CA cert (only if dhcpClient available)
	if h.dhcpClient != nil {
		go func() {
			bgCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()

			clientIP := getClientIP(r)
			if err := h.dhcpClient.MarkCACertInstalled(bgCtx, clientIP); err != nil {
				log.Printf("[Handlers] Failed to mark CA cert installed for %s: %v", clientIP, err)
			} else {
				log.Printf("[Handlers] ✅ Marked CA cert installed for %s", clientIP)
			}
		}()
	}

	w.Write(certData)
}

// HandleVerifyTrust checks if a device is trusted
func (h *Handlers) HandleVerifyTrust(w http.ResponseWriter, r *http.Request) {
	clientIP := getClientIP(r)
	log.Printf("[Handlers] Trust verification request from %s", clientIP)

	response := map[string]interface{}{
		"trusted": false,
		"ip":      clientIP,
	}

	if h.dhcpClient != nil {
		ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
		defer cancel()

		device, err := h.dhcpClient.GetDeviceByIP(ctx, clientIP)
		if err == nil && device != nil {
			response["trusted"] = device.TrustStatus == database.TrustStatusTrusted
			response["device"] = map[string]interface{}{
				"mac_address":  device.MACAddress,
				"trust_status": device.TrustStatus,
				"vendor":       device.Vendor,
			}
		}
	}

	sendJSON(w, http.StatusOK, response)
}

// HandleMarkTrusted marks a device as trusted
func (h *Handlers) HandleMarkTrusted(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		sendJSON(w, http.StatusMethodNotAllowed, map[string]string{
			"error": "Method not allowed",
		})
		return
	}

	clientIP := getClientIP(r)
	log.Printf("[Handlers] Mark trusted request from %s", clientIP)

	if h.dhcpClient == nil {
		sendJSON(w, http.StatusServiceUnavailable, map[string]string{
			"success": "false",
			"error":   "DHCP Monitor not available",
		})
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()

	// First, get the device by IP to get the device ID
	device, err := h.dhcpClient.GetDeviceByIP(ctx, clientIP)
	if err != nil {
		log.Printf("[Handlers] Device lookup error: %v", err)
		sendJSON(w, http.StatusNotFound, map[string]string{
			"success": "false",
			"error":   "Device not found",
		})
		return
	}

	// Mark as trusted
	updatedDevice, err := h.dhcpClient.MarkDeviceTrusted(ctx, device.DeviceID)
	if err != nil {
		log.Printf("[Handlers] Mark trusted error: %v", err)
		sendJSON(w, http.StatusInternalServerError, map[string]string{
			"success": "false",
			"error":   "Failed to mark device as trusted",
		})
		return
	}

	sendJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"device": map[string]interface{}{
			"mac_address":  updatedDevice.MACAddress,
			"trust_status": updatedDevice.TrustStatus,
		},
	})
}

// ============================================================================
// Health Check Handler
// ============================================================================

// HandleHealth returns service health status
func (h *Handlers) HandleHealth(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()

	health := map[string]interface{}{
		"status":    "ok",
		"timestamp": time.Now().Format(time.RFC3339),
		"services":  map[string]string{},
	}

	services := health["services"].(map[string]string)

	// Check Step-CA
	if h.stepcaClient != nil {
		if err := h.stepcaClient.HealthCheck(ctx); err != nil {
			services["step_ca"] = "unhealthy: " + err.Error()
			health["status"] = "degraded"
		} else {
			services["step_ca"] = "healthy"
		}
	} else {
		services["step_ca"] = "not configured"
	}

	// Check DHCP Monitor
	if h.dhcpClient != nil {
		if err := h.dhcpClient.HealthCheck(ctx); err != nil {
			services["dhcp_monitor"] = "unhealthy: " + err.Error()
			health["status"] = "degraded"
		} else {
			services["dhcp_monitor"] = "healthy"
		}
	} else {
		services["dhcp_monitor"] = "not configured"
	}

	// Add stats
	health["stats"] = map[string]interface{}{
		"os_detections": h.osStats,
	}

	sendJSON(w, http.StatusOK, health)
}

// ============================================================================
// Static File Handler Factory
// ============================================================================

// StaticFileHandler returns a handler for static files
func (h *Handlers) StaticFileHandler() http.Handler {
	cssDir := http.Dir(h.config.Static.CSSPath)
	jsDir := http.Dir(h.config.Static.JSPath)

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		path := strings.TrimPrefix(r.URL.Path, "/static/")

		if strings.HasPrefix(path, "css/") {
			path = strings.TrimPrefix(path, "css/")
			http.FileServer(cssDir).ServeHTTP(w, r)
		} else if strings.HasPrefix(path, "js/") {
			path = strings.TrimPrefix(path, "js/")
			http.FileServer(jsDir).ServeHTTP(w, r)
		} else {
			http.NotFound(w, r)
		}
	})
}
