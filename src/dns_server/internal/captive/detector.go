// Package captive implements captive portal redirect for CA certificate enrollment.
package captive

import (
	"context"
	"log"
	"net"
	"strings"
	"sync"
	"time"
)

// ============================================================================
// Enrollment Status
// ============================================================================

// EnrollmentStatus represents device enrollment state
type EnrollmentStatus int

const (
	StatusUnknown     EnrollmentStatus = 0 // Device not seen before
	StatusNotEnrolled EnrollmentStatus = 1 // Device seen, CA not installed
	StatusEnrolled    EnrollmentStatus = 2 // Device has CA installed
	StatusPending     EnrollmentStatus = 3 // Enrollment in progress
)

func (s EnrollmentStatus) String() string {
	switch s {
	case StatusUnknown:
		return "Unknown"
	case StatusNotEnrolled:
		return "NotEnrolled"
	case StatusEnrolled:
		return "Enrolled"
	case StatusPending:
		return "Pending"
	default:
		return "Invalid"
	}
}

// ============================================================================
// Device Enrollment
// ============================================================================

// DeviceEnrollment tracks enrollment status for a single device
type DeviceEnrollment struct {
	IPAddress  string
	MACAddress string
	Status     EnrollmentStatus
	FirstSeen  time.Time
	LastSeen   time.Time
	EnrolledAt *time.Time
	UserAgent  string
	OSType     string
}

// ============================================================================
// Enrollment Detector
// ============================================================================

// EnrollmentDetector checks if devices have the CA certificate installed
type EnrollmentDetector struct {
	cache    map[string]*DeviceEnrollment
	cacheMu  sync.RWMutex
	cacheTTL time.Duration

	portalIP   net.IP
	portalPort int
	enabled    bool

	// Excluded domains that should never be redirected
	excludedDomains []string

	// Stop channel for cleanup goroutine
	stopCh chan struct{}
}

// NewEnrollmentDetector creates a new enrollment detector
func NewEnrollmentDetector(portalIP string, portalPort int, cacheTTL time.Duration) *EnrollmentDetector {
	if cacheTTL == 0 {
		cacheTTL = 5 * time.Minute
	}

	d := &EnrollmentDetector{
		cache:      make(map[string]*DeviceEnrollment),
		cacheTTL:   cacheTTL,
		portalIP:   net.ParseIP(portalIP),
		portalPort: portalPort,
		enabled:    true,
		excludedDomains: []string{
			"localhost",
			"*.local",
			"*.internal",
			"*.lan",
			"*.safeops.local",
		},
		stopCh: make(chan struct{}),
	}

	// Start background cleanup
	go d.cleanupExpiredCache()

	return d
}

// ============================================================================
// Core Detection Methods
// ============================================================================

// IsDeviceEnrolled checks if a device has the CA certificate installed
func (d *EnrollmentDetector) IsDeviceEnrolled(ctx context.Context, ipAddress string) bool {
	if !d.enabled {
		return true // If disabled, treat all as enrolled
	}

	// Check cache first (fast path)
	d.cacheMu.RLock()
	if entry, ok := d.cache[ipAddress]; ok {
		if time.Since(entry.LastSeen) < d.cacheTTL {
			isEnrolled := entry.Status == StatusEnrolled
			d.cacheMu.RUnlock()
			return isEnrolled
		}
	}
	d.cacheMu.RUnlock()

	// Default to not enrolled for new devices
	d.MarkDeviceSeen(ipAddress, "")
	return false
}

// ShouldRedirect determines if DNS query should be redirected to portal
func (d *EnrollmentDetector) ShouldRedirect(ctx context.Context, clientIP net.IP, domain string) bool {
	if !d.enabled {
		return false
	}

	// Don't redirect excluded domains
	if d.isExcludedDomain(domain) {
		return false
	}

	// Check if device is enrolled
	return !d.IsDeviceEnrolled(ctx, clientIP.String())
}

// GetRedirectIP returns the captive portal IP address
func (d *EnrollmentDetector) GetRedirectIP() net.IP {
	return d.portalIP
}

// ============================================================================
// Captive Portal Detection
// ============================================================================

// Captive portal detection domains by OS
var captivePortalDomains = map[string]string{
	"www.msftconnecttest.com":       "Windows",
	"msftncsi.com":                  "Windows",
	"connectivitycheck.gstatic.com": "Android",
	"clients3.google.com":           "Android",
	"captive.apple.com":             "iOS",
	"www.apple.com":                 "macOS",
	"detectportal.firefox.com":      "Linux",
	"networkcheck.kde.org":          "Linux",
	"nmcheck.gnome.org":             "Linux",
}

// IsCaptivePortalCheck detects if query is a captive portal detection request
func (d *EnrollmentDetector) IsCaptivePortalCheck(queryName string) (bool, string) {
	queryName = strings.ToLower(strings.TrimSuffix(queryName, "."))

	for domain, osType := range captivePortalDomains {
		if queryName == domain || strings.HasSuffix(queryName, "."+domain) {
			return true, osType
		}
	}

	return false, ""
}

// ============================================================================
// Device Management
// ============================================================================

// MarkDeviceEnrolled marks a device as having the CA installed
func (d *EnrollmentDetector) MarkDeviceEnrolled(ipAddress, macAddress, osType string) {
	d.cacheMu.Lock()
	defer d.cacheMu.Unlock()

	now := time.Now()
	if entry, ok := d.cache[ipAddress]; ok {
		entry.Status = StatusEnrolled
		entry.EnrolledAt = &now
		entry.MACAddress = macAddress
		entry.OSType = osType
		entry.LastSeen = now
	} else {
		d.cache[ipAddress] = &DeviceEnrollment{
			IPAddress:  ipAddress,
			MACAddress: macAddress,
			Status:     StatusEnrolled,
			FirstSeen:  now,
			LastSeen:   now,
			EnrolledAt: &now,
			OSType:     osType,
		}
	}

	log.Printf("Device enrolled: %s (OS: %s)", ipAddress, osType)
}

// MarkDeviceSeen records a device making a DNS query
func (d *EnrollmentDetector) MarkDeviceSeen(ipAddress, userAgent string) {
	d.cacheMu.Lock()
	defer d.cacheMu.Unlock()

	now := time.Now()
	if entry, ok := d.cache[ipAddress]; ok {
		entry.LastSeen = now
		if userAgent != "" {
			entry.UserAgent = userAgent
			entry.OSType = detectOSFromUserAgent(userAgent)
		}
	} else {
		osType := ""
		if userAgent != "" {
			osType = detectOSFromUserAgent(userAgent)
		}
		d.cache[ipAddress] = &DeviceEnrollment{
			IPAddress: ipAddress,
			Status:    StatusNotEnrolled,
			FirstSeen: now,
			LastSeen:  now,
			UserAgent: userAgent,
			OSType:    osType,
		}
	}
}

// GetDeviceEnrollment returns enrollment info for a device
func (d *EnrollmentDetector) GetDeviceEnrollment(ipAddress string) *DeviceEnrollment {
	d.cacheMu.RLock()
	defer d.cacheMu.RUnlock()

	if entry, ok := d.cache[ipAddress]; ok {
		// Return copy to prevent race conditions
		copy := *entry
		return &copy
	}
	return nil
}

// ListPendingDevices returns all devices awaiting enrollment
func (d *EnrollmentDetector) ListPendingDevices() []*DeviceEnrollment {
	d.cacheMu.RLock()
	defer d.cacheMu.RUnlock()

	var pending []*DeviceEnrollment
	for _, entry := range d.cache {
		if entry.Status != StatusEnrolled {
			copy := *entry
			pending = append(pending, &copy)
		}
	}
	return pending
}

// ============================================================================
// Statistics
// ============================================================================

// EnrollmentStats contains enrollment statistics
type EnrollmentStats struct {
	TotalDevicesSeen int
	DevicesEnrolled  int
	DevicesPending   int
}

// GetEnrollmentStats returns enrollment statistics
func (d *EnrollmentDetector) GetEnrollmentStats() EnrollmentStats {
	d.cacheMu.RLock()
	defer d.cacheMu.RUnlock()

	stats := EnrollmentStats{}
	for _, entry := range d.cache {
		stats.TotalDevicesSeen++
		if entry.Status == StatusEnrolled {
			stats.DevicesEnrolled++
		} else {
			stats.DevicesPending++
		}
	}
	return stats
}

// ============================================================================
// Helper Methods
// ============================================================================

func (d *EnrollmentDetector) isExcludedDomain(domain string) bool {
	domain = strings.ToLower(strings.TrimSuffix(domain, "."))

	for _, excluded := range d.excludedDomains {
		if strings.HasPrefix(excluded, "*.") {
			suffix := excluded[1:] // Remove *
			if strings.HasSuffix(domain, suffix) {
				return true
			}
		} else if domain == excluded {
			return true
		}
	}
	return false
}

func (d *EnrollmentDetector) cleanupExpiredCache() {
	ticker := time.NewTicker(10 * time.Minute)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			d.doCleanup()
		case <-d.stopCh:
			return
		}
	}
}

func (d *EnrollmentDetector) doCleanup() {
	d.cacheMu.Lock()
	defer d.cacheMu.Unlock()

	maxAge := d.cacheTTL * 2
	cutoff := time.Now().Add(-maxAge)

	for ip, entry := range d.cache {
		// Don't remove enrolled devices
		if entry.Status == StatusEnrolled {
			continue
		}
		if entry.LastSeen.Before(cutoff) {
			delete(d.cache, ip)
		}
	}
}

// Stop stops the background cleanup goroutine
func (d *EnrollmentDetector) Stop() {
	close(d.stopCh)
}

// SetEnabled enables or disables captive redirect
func (d *EnrollmentDetector) SetEnabled(enabled bool) {
	d.enabled = enabled
}

// ============================================================================
// OS Detection
// ============================================================================

func detectOSFromUserAgent(userAgent string) string {
	ua := strings.ToLower(userAgent)

	switch {
	case strings.Contains(ua, "windows"):
		return "Windows"
	case strings.Contains(ua, "iphone") || strings.Contains(ua, "ipad"):
		return "iOS"
	case strings.Contains(ua, "mac os") || strings.Contains(ua, "macintosh"):
		return "macOS"
	case strings.Contains(ua, "android"):
		return "Android"
	case strings.Contains(ua, "linux"):
		return "Linux"
	default:
		return "Unknown"
	}
}
