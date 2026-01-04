// ============================================================================
// SafeOps TLS Proxy - Captive Portal Detection
// ============================================================================
// File: D:\SafeOpsFV2\src\tls_proxy\internal\packet\captive_detector.go
// Purpose: Detect and intercept captive portal detection requests from devices
//
// How Captive Portal Detection Works:
//   When a device connects to WiFi, it automatically sends HTTP requests to
//   known URLs to check if there's a captive portal (like hotel WiFi login).
//
//   - iOS/macOS: http://captive.apple.com/hotspot-detect.html
//   - Android: http://connectivitycheck.gstatic.com/generate_204
//   - Windows: http://www.msftconnecttest.com/connecttest.txt
//   - Firefox: http://detectportal.firefox.com/success.txt
//   - Linux: http://network-test.debian.org/nm
//
//   If the response is unexpected (e.g., HTTP 302 redirect instead of 200),
//   the device assumes there's a captive portal and auto-opens a popup.
//
// Our Strategy:
//   For UNTRUSTED devices, we intercept these requests and return a 302
//   redirect to our captive portal. This triggers the device to auto-open
//   a popup showing our CA certificate download page.
//
// Author: SafeOps Phase 3A
// Date: 2026-01-04
// ============================================================================

package packet

import (
	"strings"
)

// CaptivePortalDetectionURL represents a known captive portal check URL
type CaptivePortalDetectionURL struct {
	Host           string // Domain to match (e.g., "captive.apple.com")
	Path           string // Expected path (e.g., "/hotspot-detect.html")
	Platform       string // Platform that uses this (iOS, Android, Windows, etc.)
	ExpectedStatus int    // Expected HTTP status code (200, 204)
}

// KnownCaptivePortalURLs is the list of all known captive portal detection URLs
var KnownCaptivePortalURLs = []CaptivePortalDetectionURL{
	// Apple (iOS, macOS, watchOS, tvOS)
	{
		Host:           "captive.apple.com",
		Path:           "/hotspot-detect.html",
		Platform:       "iOS/macOS",
		ExpectedStatus: 200, // Returns "Success" in HTML
	},

	// Google/Android
	{
		Host:           "connectivitycheck.gstatic.com",
		Path:           "/generate_204",
		Platform:       "Android",
		ExpectedStatus: 204, // Returns HTTP 204 No Content
	},
	{
		Host:           "clients3.google.com",
		Path:           "/generate_204",
		Platform:       "Android",
		ExpectedStatus: 204,
	},

	// Microsoft Windows
	{
		Host:           "www.msftconnecttest.com",
		Path:           "/connecttest.txt",
		Platform:       "Windows",
		ExpectedStatus: 200, // Returns "Microsoft Connect Test"
	},
	{
		Host:           "www.msftncsi.com",
		Path:           "/ncsi.txt",
		Platform:       "Windows",
		ExpectedStatus: 200, // Returns "Microsoft NCSI"
	},

	// Firefox
	{
		Host:           "detectportal.firefox.com",
		Path:           "/success.txt",
		Platform:       "Firefox",
		ExpectedStatus: 200, // Returns "success"
	},

	// Linux (NetworkManager, GNOME)
	{
		Host:           "network-test.debian.org",
		Path:           "/nm",
		Platform:       "Linux/Debian",
		ExpectedStatus: 204,
	},
	{
		Host:           "nmcheck.gnome.org",
		Path:           "/check_network_status.txt",
		Platform:       "Linux/GNOME",
		ExpectedStatus: 200,
	},

	// Ubuntu
	{
		Host:           "connectivity-check.ubuntu.com",
		Path:           "/",
		Platform:       "Ubuntu",
		ExpectedStatus: 204,
	},
}

// IsCaptivePortalCheck checks if the HTTP request is a captive portal detection
// request from a device
func IsCaptivePortalCheck(host, path string) bool {
	// Normalize to lowercase for comparison
	host = strings.ToLower(strings.TrimSpace(host))
	path = strings.ToLower(strings.TrimSpace(path))

	// Remove port if present (e.g., "captive.apple.com:80" → "captive.apple.com")
	if colonIdx := strings.Index(host, ":"); colonIdx != -1 {
		host = host[:colonIdx]
	}

	// Check against known captive portal URLs
	for _, portalURL := range KnownCaptivePortalURLs {
		portalHost := strings.ToLower(portalURL.Host)

		// Exact host match
		if host == portalHost {
			// If path is specified, check it too
			if portalURL.Path != "" {
				if path == portalURL.Path || strings.HasPrefix(path, portalURL.Path) {
					return true
				}
			} else {
				// No specific path requirement, host match is enough
				return true
			}
		}

		// Subdomain match (e.g., "www.captive.apple.com")
		if strings.HasSuffix(host, "."+portalHost) {
			return true
		}
	}

	return false
}

// GetPlatformFromCaptiveURL determines which platform is checking for captive portal
func GetPlatformFromCaptiveURL(host string) string {
	host = strings.ToLower(strings.TrimSpace(host))

	for _, portalURL := range KnownCaptivePortalURLs {
		if strings.Contains(host, strings.ToLower(portalURL.Host)) {
			return portalURL.Platform
		}
	}

	return "Unknown"
}

// ShouldInterceptCaptivePortalCheck determines if we should intercept this request
// based on device trust status
//
// Returns true if:
//   - This is a captive portal detection request
//   - Device is UNTRUSTED (hasn't installed CA cert)
//   - Portal hasn't been shown yet (for ALLOW_ONCE policy)
func ShouldInterceptCaptivePortalCheck(host, path, trustStatus string, portalShown bool, policyMode string) bool {
	// Not a captive portal check → don't intercept
	if !IsCaptivePortalCheck(host, path) {
		return false
	}

	// TRUSTED device → forward normally (no interception)
	if trustStatus == "TRUSTED" {
		return false
	}

	// BLOCKED device → always intercept (no internet)
	if trustStatus == "BLOCKED" {
		return true
	}

	// UNTRUSTED device → check policy
	switch policyMode {
	case "STRICT":
		// Always intercept untrusted devices
		return true

	case "PERMISSIVE":
		// Never intercept (allow internet without portal)
		return false

	case "ALLOW_ONCE":
		// Intercept only if portal hasn't been shown yet
		return !portalShown

	default:
		// Unknown policy → fail safe (intercept)
		return true
	}
}
