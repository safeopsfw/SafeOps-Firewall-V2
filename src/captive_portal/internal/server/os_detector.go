// ============================================================================
// SafeOps Captive Portal - OS Detector
// ============================================================================
// File: D:\SafeOpsFV2\src\captive_portal\internal\server\os_detector.go
// Purpose: Detect client operating system from User-Agent header
//
// Used to:
//   - Pre-select the correct platform tab in the welcome page
//   - Provide correct certificate format for download
//   - Log client platform statistics
//
// Author: SafeOps Phase 3A
// Date: 2026-01-03
// ============================================================================

package server

import (
	"net/http"
	"regexp"
	"strings"
)

// ============================================================================
// OS Type Constants
// ============================================================================

const (
	// OSiOS - Apple iPhone, iPad, iPod
	OSiOS = "ios"

	// OSAndroid - Android phones and tablets
	OSAndroid = "android"

	// OSWindows - Microsoft Windows
	OSWindows = "windows"

	// OSmacOS - Apple macOS
	OSmacOS = "macos"

	// OSLinux - Linux distributions
	OSLinux = "linux"

	// OSChromeOS - Google ChromeOS
	OSChromeOS = "chromeos"

	// OSUnknown - Undetected OS
	OSUnknown = "unknown"
)

// ============================================================================
// OS Detection Patterns
// ============================================================================

// osPatterns maps OS identifiers to their regex patterns
// Patterns are checked in order - more specific patterns first
var osPatterns = []struct {
	OS      string
	Pattern *regexp.Regexp
}{
	// iOS - Check before macOS since iPad can report as Mac
	{OSiOS, regexp.MustCompile(`(?i)(iphone|ipad|ipod)`)},

	// Android - Check before Linux since Android includes Linux in UA
	{OSAndroid, regexp.MustCompile(`(?i)android`)},

	// ChromeOS - Check before Linux
	{OSChromeOS, regexp.MustCompile(`(?i)cros`)},

	// macOS - Various patterns for Mac
	{OSmacOS, regexp.MustCompile(`(?i)(macintosh|mac os x|mac_powerpc)`)},

	// Windows
	{OSWindows, regexp.MustCompile(`(?i)(windows|win32|win64)`)},

	// Linux - General Linux (but not Android)
	{OSLinux, regexp.MustCompile(`(?i)linux`)},
}

// ============================================================================
// OS Information Structure
// ============================================================================

// OSInfo contains detected operating system information
type OSInfo struct {
	// OS is the detected operating system (ios, android, windows, macos, linux, unknown)
	OS string `json:"os"`

	// Name is the human-readable OS name
	Name string `json:"name"`

	// IsMobile indicates if the device is mobile
	IsMobile bool `json:"is_mobile"`

	// Browser is the detected browser (chrome, firefox, safari, edge, unknown)
	Browser string `json:"browser"`

	// BrowserVersion is the browser version string
	BrowserVersion string `json:"browser_version"`

	// RawUserAgent is the original User-Agent string
	RawUserAgent string `json:"raw_user_agent"`

	// PreferredCertFormat is the recommended certificate format
	PreferredCertFormat string `json:"preferred_cert_format"`
}

// ============================================================================
// OS Detection Functions
// ============================================================================

// DetectOS detects the operating system from a User-Agent string
func DetectOS(userAgent string) string {
	if userAgent == "" {
		return OSUnknown
	}

	for _, pattern := range osPatterns {
		if pattern.Pattern.MatchString(userAgent) {
			return pattern.OS
		}
	}

	return OSUnknown
}

// DetectOSFromRequest extracts and detects OS from HTTP request
func DetectOSFromRequest(r *http.Request) string {
	userAgent := r.Header.Get("User-Agent")
	return DetectOS(userAgent)
}

// GetOSInfo returns detailed OS information from User-Agent
func GetOSInfo(userAgent string) *OSInfo {
	info := &OSInfo{
		OS:           DetectOS(userAgent),
		RawUserAgent: userAgent,
	}

	// Set human-readable name
	info.Name = GetOSName(info.OS)

	// Detect if mobile
	info.IsMobile = isMobileOS(info.OS) || isMobileUA(userAgent)

	// Detect browser
	info.Browser, info.BrowserVersion = detectBrowser(userAgent)

	// Set preferred certificate format based on OS
	info.PreferredCertFormat = GetPreferredCertFormat(info.OS)

	return info
}

// GetOSInfoFromRequest gets OS info from HTTP request
func GetOSInfoFromRequest(r *http.Request) *OSInfo {
	userAgent := r.Header.Get("User-Agent")
	return GetOSInfo(userAgent)
}

// ============================================================================
// Helper Functions
// ============================================================================

// GetOSName returns human-readable name for an OS identifier
func GetOSName(os string) string {
	names := map[string]string{
		OSiOS:      "iOS",
		OSAndroid:  "Android",
		OSWindows:  "Windows",
		OSmacOS:    "macOS",
		OSLinux:    "Linux",
		OSChromeOS: "ChromeOS",
		OSUnknown:  "Unknown",
	}

	if name, ok := names[os]; ok {
		return name
	}
	return "Unknown"
}

// GetPreferredCertFormat returns the preferred certificate format for an OS
func GetPreferredCertFormat(os string) string {
	formats := map[string]string{
		OSiOS:      "p12", // PKCS#12 for iOS
		OSAndroid:  "pem", // PEM for Android
		OSWindows:  "der", // DER for Windows (native)
		OSmacOS:    "pem", // PEM for macOS
		OSLinux:    "pem", // PEM for Linux
		OSChromeOS: "pem", // PEM for ChromeOS
		OSUnknown:  "pem", // PEM as fallback
	}

	if format, ok := formats[os]; ok {
		return format
	}
	return "pem"
}

// GetMIMEType returns the MIME type for a certificate format
func GetMIMEType(format string) string {
	mimeTypes := map[string]string{
		"pem": "application/x-pem-file",
		"crt": "application/x-x509-ca-cert",
		"cer": "application/x-x509-ca-cert",
		"der": "application/x-x509-ca-cert",
		"p12": "application/x-pkcs12",
		"pfx": "application/x-pkcs12",
	}

	if mime, ok := mimeTypes[format]; ok {
		return mime
	}
	return "application/octet-stream"
}

// GetFileExtension returns the preferred file extension for a format
func GetFileExtension(format string) string {
	extensions := map[string]string{
		"pem": ".crt",
		"crt": ".crt",
		"cer": ".cer",
		"der": ".der",
		"p12": ".p12",
		"pfx": ".pfx",
	}

	if ext, ok := extensions[format]; ok {
		return ext
	}
	return ".crt"
}

// isMobileOS checks if an OS identifier is typically a mobile OS
func isMobileOS(os string) bool {
	return os == OSiOS || os == OSAndroid
}

// isMobileUA checks User-Agent for mobile indicators
func isMobileUA(userAgent string) bool {
	mobilePatterns := []string{
		"mobile", "android", "iphone", "ipad", "ipod",
		"blackberry", "windows phone", "opera mini",
		"silk", "kindle",
	}

	lowerUA := strings.ToLower(userAgent)
	for _, pattern := range mobilePatterns {
		if strings.Contains(lowerUA, pattern) {
			return true
		}
	}
	return false
}

// detectBrowser detects the browser from User-Agent
func detectBrowser(userAgent string) (browser, version string) {
	if userAgent == "" {
		return "unknown", ""
	}

	lowerUA := strings.ToLower(userAgent)

	// Browser patterns with version extraction
	browsers := []struct {
		name    string
		pattern *regexp.Regexp
	}{
		{"edge", regexp.MustCompile(`(?i)edg[ea]?/(\d+[\d.]*)`)},
		{"chrome", regexp.MustCompile(`(?i)chrome/(\d+[\d.]*)`)},
		{"firefox", regexp.MustCompile(`(?i)firefox/(\d+[\d.]*)`)},
		{"safari", regexp.MustCompile(`(?i)version/(\d+[\d.]*).+safari`)},
		{"opera", regexp.MustCompile(`(?i)(?:opera|opr)/(\d+[\d.]*)`)},
		{"ie", regexp.MustCompile(`(?i)(?:msie\s|trident/.+rv:)(\d+[\d.]*)`)},
	}

	for _, b := range browsers {
		if matches := b.pattern.FindStringSubmatch(userAgent); len(matches) > 1 {
			return b.name, matches[1]
		}
	}

	// Check for generic patterns
	if strings.Contains(lowerUA, "safari") && !strings.Contains(lowerUA, "chrome") {
		return "safari", ""
	}

	return "unknown", ""
}

// ============================================================================
// Statistics and Logging
// ============================================================================

// OSStats tracks OS detection statistics
type OSStats struct {
	Total     int64            `json:"total"`
	ByOS      map[string]int64 `json:"by_os"`
	ByBrowser map[string]int64 `json:"by_browser"`
	Mobile    int64            `json:"mobile"`
	Desktop   int64            `json:"desktop"`
}

// NewOSStats creates a new OS stats tracker
func NewOSStats() *OSStats {
	return &OSStats{
		ByOS:      make(map[string]int64),
		ByBrowser: make(map[string]int64),
	}
}

// Record adds an OS info record to the stats
func (s *OSStats) Record(info *OSInfo) {
	s.Total++
	s.ByOS[info.OS]++
	s.ByBrowser[info.Browser]++

	if info.IsMobile {
		s.Mobile++
	} else {
		s.Desktop++
	}
}
