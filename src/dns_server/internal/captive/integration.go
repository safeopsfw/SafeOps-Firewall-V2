// Package captive provides the main integration for captive portal functionality.
package captive

import (
	"context"
	"database/sql"
	"log"
	"net"
	"time"

	"safeops/dns_server/internal/protocol"
)

// ============================================================================
// Captive Portal Manager
// ============================================================================

// Manager coordinates all captive portal components
type Manager struct {
	detector   *EnrollmentDetector
	redirector *Redirector
	tracker    *DeviceTracker

	portalIP   string
	portalPort int
	portalURL  string
	enabled    bool
}

// Config holds captive portal configuration
type Config struct {
	Enabled         bool
	PortalIP        string
	PortalPort      int
	PortalURL       string
	CacheTTL        time.Duration
	RedirectTTL     uint32
	ExcludedDomains []string
}

// NewManager creates a new captive portal manager
func NewManager(cfg *Config, db *sql.DB) *Manager {
	m := &Manager{
		portalIP:   cfg.PortalIP,
		portalPort: cfg.PortalPort,
		portalURL:  cfg.PortalURL,
		enabled:    cfg.Enabled,
	}

	// Initialize detector
	m.detector = NewEnrollmentDetector(cfg.PortalIP, cfg.PortalPort, cfg.CacheTTL)

	// Initialize redirector
	m.redirector = NewRedirector(cfg.PortalIP, cfg.RedirectTTL)

	// Initialize tracker (requires database)
	if db != nil {
		m.tracker = NewDeviceTracker(db)
	}

	log.Printf("Captive portal manager initialized (enabled: %v, portal: %s:%d)",
		cfg.Enabled, cfg.PortalIP, cfg.PortalPort)

	return m
}

// ============================================================================
// DNS Query Processing Integration
// ============================================================================

// ProcessQuery handles a DNS query with captive portal logic
// Returns: response message if redirect needed, nil if normal processing
func (m *Manager) ProcessQuery(ctx context.Context, query *protocol.Message, clientIP net.IP) *protocol.Message {
	if !m.enabled || len(query.Questions) == 0 {
		return nil // Normal processing
	}

	domain := query.Questions[0].Name

	// Check for captive portal detection URLs
	if isCaptive, osType := m.detector.IsCaptivePortalCheck(domain); isCaptive {
		log.Printf("Captive check from %s (OS: %s): %s", clientIP, osType, domain)
		// For captive detection, always redirect to trigger portal popup
		if m.detector.ShouldRedirect(ctx, clientIP, domain) {
			return m.redirector.CreateCaptiveCheckResponse(query, osType)
		}
	}

	// Check if device needs redirect
	if m.detector.ShouldRedirect(ctx, clientIP, domain) {
		log.Printf("Redirecting %s to portal: %s", clientIP, domain)
		return m.redirector.CreateRedirectResponse(query)
	}

	return nil // Normal processing
}

// ShouldRedirect checks if a query should be redirected
func (m *Manager) ShouldRedirect(ctx context.Context, clientIP net.IP, domain string) bool {
	if !m.enabled {
		return false
	}
	return m.detector.ShouldRedirect(ctx, clientIP, domain)
}

// GetRedirectIP returns the portal IP for redirects
func (m *Manager) GetRedirectIP() net.IP {
	if m.detector == nil {
		return nil
	}
	return m.detector.GetRedirectIP()
}

// ============================================================================
// Enrollment Callbacks
// ============================================================================

// OnDeviceEnrolled is called when a device installs the CA
func (m *Manager) OnDeviceEnrolled(ctx context.Context, ipAddress, macAddress, osType, installMethod, certFingerprint string) error {
	// Update in-memory cache
	m.detector.MarkDeviceEnrolled(ipAddress, macAddress, osType)

	// Persist to database
	if m.tracker != nil {
		deviceID := generateDeviceID(ipAddress, macAddress)
		return m.tracker.MarkDeviceEnrolled(ctx, deviceID, installMethod, certFingerprint)
	}

	return nil
}

// OnDeviceSeen is called when a new device makes a DNS query
func (m *Manager) OnDeviceSeen(ctx context.Context, ipAddress, macAddress, osType, userAgent string) {
	// Update in-memory cache
	m.detector.MarkDeviceSeen(ipAddress, userAgent)

	// Record in database
	if m.tracker != nil {
		deviceID := generateDeviceID(ipAddress, macAddress)
		if err := m.tracker.RecordDeviceSeen(ctx, deviceID, ipAddress, macAddress, osType, userAgent); err != nil {
			log.Printf("Failed to record device: %v", err)
		}
	}
}

// ============================================================================
// Status & Statistics
// ============================================================================

// GetStats returns enrollment statistics
func (m *Manager) GetStats(ctx context.Context) (*TrackerStats, error) {
	if m.tracker != nil {
		return m.tracker.GetEnrollmentStats(ctx)
	}

	// Fall back to in-memory stats
	stats := m.detector.GetEnrollmentStats()
	return &TrackerStats{
		TotalDevices:    stats.TotalDevicesSeen,
		EnrolledDevices: stats.DevicesEnrolled,
		PendingDevices:  stats.DevicesPending,
	}, nil
}

// ListPendingDevices returns devices awaiting enrollment
func (m *Manager) ListPendingDevices(ctx context.Context) ([]*TrackedDevice, error) {
	if m.tracker != nil {
		return m.tracker.ListPendingDevices(ctx)
	}

	// Fall back to in-memory list
	pending := m.detector.ListPendingDevices()
	var devices []*TrackedDevice
	for _, d := range pending {
		devices = append(devices, &TrackedDevice{
			DeviceID:   d.IPAddress,
			IPAddress:  d.IPAddress,
			MACAddress: d.MACAddress,
			OSType:     d.OSType,
			UserAgent:  d.UserAgent,
			FirstSeen:  d.FirstSeen,
			LastSeen:   d.LastSeen,
		})
	}
	return devices, nil
}

// IsEnabled returns whether captive portal is enabled
func (m *Manager) IsEnabled() bool {
	return m.enabled
}

// SetEnabled enables or disables captive portal
func (m *Manager) SetEnabled(enabled bool) {
	m.enabled = enabled
	m.detector.SetEnabled(enabled)
}

// GetPortalURL returns the captive portal URL
func (m *Manager) GetPortalURL() string {
	return m.portalURL
}

// ============================================================================
// Lifecycle
// ============================================================================

// Stop cleanly shuts down the captive portal manager
func (m *Manager) Stop() {
	if m.detector != nil {
		m.detector.Stop()
	}
	log.Printf("Captive portal manager stopped")
}

// ============================================================================
// Helper Functions
// ============================================================================

func generateDeviceID(ipAddress, macAddress string) string {
	if macAddress != "" {
		return macAddress
	}
	return ipAddress
}

// DefaultConfig returns default captive portal configuration
func DefaultConfig() *Config {
	return &Config{
		Enabled:     true,
		PortalIP:    "192.168.1.1",
		PortalPort:  80,
		PortalURL:   "http://192.168.1.1/install",
		CacheTTL:    5 * time.Minute,
		RedirectTTL: 60,
	}
}
