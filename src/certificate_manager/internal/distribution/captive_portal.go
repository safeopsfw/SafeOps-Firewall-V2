// Package distribution provides captive portal for automatic CA installation.
// Forces all connected devices to install CA certificate before internet access.
package distribution

import (
	"fmt"
	"log"
	"net/http"
	"strings"
	"sync"
)

// ============================================================================
// Captive Portal HTTP Interceptor
// ============================================================================

// CaptivePortal intercepts HTTP requests and forces CA installation.
type CaptivePortal struct {
	mu              sync.RWMutex
	installedDevices map[string]bool // MAC address -> installed status
	baseURL         string
	enabled         bool
}

// NewCaptivePortal creates a new captive portal.
func NewCaptivePortal(baseURL string) *CaptivePortal {
	return &CaptivePortal{
		installedDevices: make(map[string]bool),
		baseURL:          baseURL,
		enabled:          true,
	}
}

// ============================================================================
// HTTP Middleware - Intercept All Requests
// ============================================================================

// InterceptHTTP is middleware that intercepts HTTP requests.
// It redirects to CA installation page if certificate not installed.
func (cp *CaptivePortal) InterceptHTTP(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Skip if captive portal disabled
		if !cp.enabled {
			next.ServeHTTP(w, r)
			return
		}

		// Skip API endpoints and installation pages
		if cp.isExcludedPath(r.URL.Path) {
			next.ServeHTTP(w, r)
			return
		}

		// Get client IP and detect OS
		clientIP := getClientIP(r)
		osType := detectOSFromUserAgent(r.UserAgent())

		log.Printf("[CAPTIVE] Request from %s (%s): %s", clientIP, osType, r.URL.Path)

		// Check if CA already installed
		if cp.isCAInstalled(clientIP) {
			log.Printf("[CAPTIVE] CA already installed for %s - allowing through", clientIP)
			next.ServeHTTP(w, r)
			return
		}

		// Redirect to OS-specific installation page
		cp.redirectToInstall(w, r, osType, clientIP)
	})
}

// ============================================================================
// Redirection Logic
// ============================================================================

func (cp *CaptivePortal) redirectToInstall(w http.ResponseWriter, r *http.Request, osType, clientIP string) {
	var installURL string

	switch osType {
	case "Android":
		installURL = fmt.Sprintf("%s/android?auto=1", cp.baseURL)
	case "iOS":
		installURL = fmt.Sprintf("%s/ios?auto=1", cp.baseURL)
	case "Windows":
		installURL = fmt.Sprintf("%s/windows?auto=1", cp.baseURL)
	case "Linux":
		installURL = fmt.Sprintf("%s/linux?auto=1", cp.baseURL)
	case "macOS":
		installURL = fmt.Sprintf("%s/macos?auto=1", cp.baseURL)
	default:
		installURL = fmt.Sprintf("%s/install?auto=1", cp.baseURL)
	}

	log.Printf("[CAPTIVE] Redirecting %s (%s) to: %s", clientIP, osType, installURL)

	// Send 302 redirect
	http.Redirect(w, r, installURL, http.StatusFound)
}

// ============================================================================
// CA Installation Status Tracking
// ============================================================================

// MarkAsInstalled marks a device as having CA installed.
func (cp *CaptivePortal) MarkAsInstalled(ipOrMAC string) {
	cp.mu.Lock()
	defer cp.mu.Unlock()
	cp.installedDevices[ipOrMAC] = true
	log.Printf("[CAPTIVE] Marked %s as CA installed", ipOrMAC)
}

// isCAInstalled checks if CA is installed on device.
func (cp *CaptivePortal) isCAInstalled(clientIP string) bool {
	cp.mu.RLock()
	defer cp.mu.RUnlock()
	return cp.installedDevices[clientIP]
}

// ============================================================================
// Path Exclusions
// ============================================================================

func (cp *CaptivePortal) isExcludedPath(path string) bool {
	excluded := []string{
		"/ca.crt",
		"/ca.der",
		"/install-ca",
		"/android",
		"/ios",
		"/windows",
		"/linux",
		"/macos",
		"/install",
		"/api/report",
		"/api/status",
		"/health",
		"/metrics",
	}

	for _, prefix := range excluded {
		if strings.HasPrefix(path, prefix) {
			return true
		}
	}

	return false
}

// ============================================================================
// OS Detection from User-Agent
// ============================================================================

func detectOSFromUserAgent(ua string) string {
	ua = strings.ToLower(ua)

	if strings.Contains(ua, "android") {
		return "Android"
	}
	if strings.Contains(ua, "iphone") || strings.Contains(ua, "ipad") {
		return "iOS"
	}
	if strings.Contains(ua, "windows") {
		return "Windows"
	}
	if strings.Contains(ua, "macintosh") || strings.Contains(ua, "mac os x") {
		return "macOS"
	}
	if strings.Contains(ua, "linux") {
		return "Linux"
	}

	return "Unknown"
}

// ============================================================================
// Client IP Extraction (uses function from http_server.go)
// ============================================================================

// getClientIP is provided by http_server.go

// ============================================================================
// Enable/Disable Captive Portal
// ============================================================================

// Enable enables the captive portal.
func (cp *CaptivePortal) Enable() {
	cp.mu.Lock()
	defer cp.mu.Unlock()
	cp.enabled = true
	log.Println("[CAPTIVE] Captive portal ENABLED")
}

// Disable disables the captive portal.
func (cp *CaptivePortal) Disable() {
	cp.mu.Lock()
	defer cp.mu.Unlock()
	cp.enabled = false
	log.Println("[CAPTIVE] Captive portal DISABLED")
}

// IsEnabled returns whether captive portal is enabled.
func (cp *CaptivePortal) IsEnabled() bool {
	cp.mu.RLock()
	defer cp.mu.RUnlock()
	return cp.enabled
}
