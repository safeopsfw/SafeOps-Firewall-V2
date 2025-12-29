// Package types defines core data structures for the Certificate Manager service.
// This file contains device tracking types for monitoring CA certificate installation status.
// These types support the internal CA distribution feature for SafeOps network devices.
package types

import (
	"net"
	"time"
)

// ============================================================================
// Section 1: Device Identification Types
// ============================================================================

// DeviceStatus represents a network device's CA installation status
type DeviceStatus struct {
	DeviceID        string      `json:"device_id"`        // Unique device identifier (hash of IP+MAC)
	IPAddress       net.IP      `json:"ip_address"`       // Device IP address
	MACAddress      string      `json:"mac_address"`      // Device MAC address
	Hostname        string      `json:"hostname"`         // Device hostname (if resolved)
	CAInstalled     bool        `json:"ca_installed"`     // Root CA trust status
	LastSeen        time.Time   `json:"last_seen"`        // Last detection timestamp
	FirstSeen       time.Time   `json:"first_seen"`       // First detection timestamp
	DetectionMethod string      `json:"detection_method"` // How installation was detected
	UserAgent       string      `json:"user_agent"`       // Browser/OS user agent string
	OSType          string      `json:"os_type"`          // Detected operating system
	TrustStatus     TrustStatus `json:"trust_status"`     // Detailed trust status
}

// TrustStatus represents the CA trust verification status
type TrustStatus string

const (
	TrustStatusUnknown   TrustStatus = "unknown"   // Not yet verified
	TrustStatusTrusted   TrustStatus = "trusted"   // CA is trusted
	TrustStatusUntrusted TrustStatus = "untrusted" // CA not trusted
	TrustStatusPending   TrustStatus = "pending"   // Verification in progress
	TrustStatusError     TrustStatus = "error"     // Verification failed
)

func (ts TrustStatus) String() string { return string(ts) }

// DeviceInfo contains basic device identification for lookups
type DeviceInfo struct {
	IPAddress  net.IP `json:"ip_address"`
	MACAddress string `json:"mac_address"`
	Hostname   string `json:"hostname,omitempty"`
}

// GenerateDeviceID creates a unique device identifier from IP and MAC
func GenerateDeviceID(ip net.IP, mac string) string {
	// Simple concatenation for ID generation
	// In production, this would use a hash function
	return ip.String() + "-" + mac
}

// ============================================================================
// Section 2: Download Tracking Types
// ============================================================================

// DownloadRecord tracks CA certificate download events
type DownloadRecord struct {
	ID           int64          `json:"id"`                      // Primary key
	DeviceID     string         `json:"device_id"`               // Device identifier
	IPAddress    net.IP         `json:"ip_address"`              // Download source IP
	DownloadTime time.Time      `json:"download_time"`           // Download timestamp
	Format       CertFormat     `json:"format"`                  // Certificate format requested
	UserAgent    string         `json:"user_agent"`              // HTTP User-Agent header
	Referer      string         `json:"referer"`                 // HTTP Referer header
	Source       DownloadSource `json:"source"`                  // Download trigger source
	Success      bool           `json:"success"`                 // Download completed successfully
	BytesSent    int64          `json:"bytes_sent"`              // Bytes transferred
	ErrorMessage string         `json:"error_message,omitempty"` // Error if failed
}

// CertFormat represents certificate file formats
type CertFormat string

const (
	CertFormatPEM    CertFormat = "pem"    // PEM format (.pem, .crt)
	CertFormatDER    CertFormat = "der"    // DER format (.der, .cer)
	CertFormatP7B    CertFormat = "p7b"    // PKCS#7 format
	CertFormatPKCS12 CertFormat = "pkcs12" // PKCS#12 format (.p12, .pfx)
)

func (cf CertFormat) String() string { return string(cf) }

// Extension returns the file extension for this format
func (cf CertFormat) Extension() string {
	switch cf {
	case CertFormatPEM:
		return ".pem"
	case CertFormatDER:
		return ".der"
	case CertFormatP7B:
		return ".p7b"
	case CertFormatPKCS12:
		return ".p12"
	default:
		return ""
	}
}

// ContentType returns the MIME type for this format
func (cf CertFormat) ContentType() string {
	switch cf {
	case CertFormatPEM:
		return "application/x-pem-file"
	case CertFormatDER:
		return "application/x-x509-ca-cert"
	case CertFormatP7B:
		return "application/x-pkcs7-certificates"
	case CertFormatPKCS12:
		return "application/x-pkcs12"
	default:
		return "application/octet-stream"
	}
}

// DownloadSource indicates how the download was triggered
type DownloadSource string

const (
	DownloadSourceHTTP   DownloadSource = "http"    // Direct HTTP download
	DownloadSourceDHCP   DownloadSource = "dhcp"    // DHCP Option 224 URL
	DownloadSourceScript DownloadSource = "script"  // Installation script
	DownloadSourceAPI    DownloadSource = "api"     // API request
	DownloadSourceQRCode DownloadSource = "qr_code" // QR code scan
	DownloadSourceMobile DownloadSource = "mobile"  // Mobile config profile
)

func (ds DownloadSource) String() string { return string(ds) }

// ============================================================================
// Section 3: Installation Detection Types
// ============================================================================

// InstallationDetection records CA trust verification attempts
type InstallationDetection struct {
	ID                  int64           `json:"id"`                      // Primary key
	DeviceID            string          `json:"device_id"`               // Device identifier
	DetectionTimestamp  time.Time       `json:"detection_timestamp"`     // Test timestamp
	DetectionMethod     DetectionMethod `json:"detection_method"`        // How trust was verified
	TLSHandshakeSuccess bool            `json:"tls_handshake_success"`   // TLS test succeeded
	CertificateAccepted bool            `json:"certificate_accepted"`    // Device trusts our CA
	TLSVersion          string          `json:"tls_version"`             // Negotiated TLS version
	CipherSuite         string          `json:"cipher_suite"`            // Negotiated cipher suite
	SNI                 string          `json:"sni"`                     // Server Name Indication
	ErrorMessage        string          `json:"error_message,omitempty"` // Error if detection failed
	ConfidenceScore     float64         `json:"confidence_score"`        // 0.0 to 1.0 confidence
}

// DetectionMethod indicates how CA trust was verified
type DetectionMethod string

const (
	DetectionTLSHandshake DetectionMethod = "tls_handshake" // TLS connection test
	DetectionHTTPProbe    DetectionMethod = "http_probe"    // HTTP request through proxy
	DetectionBrowserTest  DetectionMethod = "browser_test"  // Browser-based verification
	DetectionAPICallback  DetectionMethod = "api_callback"  // Client API callback
	DetectionPassive      DetectionMethod = "passive"       // Passive traffic observation
)

func (dm DetectionMethod) String() string { return string(dm) }

// ============================================================================
// Section 4: Device Statistics Types
// ============================================================================

// DeviceStats contains aggregate device tracking statistics
type DeviceStats struct {
	TotalDevices      int64     `json:"total_devices"`      // Total unique devices seen
	TrustedDevices    int64     `json:"trusted_devices"`    // Devices with CA installed
	UntrustedDevices  int64     `json:"untrusted_devices"`  // Devices without CA
	PendingDevices    int64     `json:"pending_devices"`    // Pending verification
	TotalDownloads    int64     `json:"total_downloads"`    // Total CA downloads
	UniqueDownloaders int64     `json:"unique_downloaders"` // Unique devices downloaded
	LastUpdated       time.Time `json:"last_updated"`       // Stats timestamp
}

// TrustPercentage returns the percentage of trusted devices
func (ds *DeviceStats) TrustPercentage() float64 {
	if ds.TotalDevices == 0 {
		return 0
	}
	return float64(ds.TrustedDevices) / float64(ds.TotalDevices) * 100
}

// DevicesByOS contains device counts by operating system
type DevicesByOS struct {
	Windows  int64 `json:"windows"`
	MacOS    int64 `json:"macos"`
	Linux    int64 `json:"linux"`
	IOS      int64 `json:"ios"`
	Android  int64 `json:"android"`
	ChromeOS int64 `json:"chromeos"`
	Other    int64 `json:"other"`
}

// ============================================================================
// Section 5: Installation Script Types
// ============================================================================

// InstallScript represents a platform-specific installation script
type InstallScript struct {
	Platform     Platform  `json:"platform"`      // Target platform
	ScriptType   string    `json:"script_type"`   // powershell, bash, etc.
	Content      string    `json:"content"`       // Script content
	DownloadURL  string    `json:"download_url"`  // URL to download script
	Checksum     string    `json:"checksum"`      // SHA-256 checksum
	Version      string    `json:"version"`       // Script version
	LastModified time.Time `json:"last_modified"` // Last update timestamp
}

// Platform represents target operating system platforms
type Platform string

const (
	PlatformWindows  Platform = "windows"
	PlatformMacOS    Platform = "macos"
	PlatformLinux    Platform = "linux"
	PlatformiOS      Platform = "ios"
	PlatformAndroid  Platform = "android"
	PlatformChromeOS Platform = "chromeos"
)

func (p Platform) String() string { return string(p) }

// ScriptExtension returns the script file extension for this platform
func (p Platform) ScriptExtension() string {
	switch p {
	case PlatformWindows:
		return ".ps1"
	case PlatformMacOS, PlatformLinux:
		return ".sh"
	default:
		return ""
	}
}

// ============================================================================
// Section 6: Mobile Profile Types
// ============================================================================

// MobileProfile represents a mobile configuration profile
type MobileProfile struct {
	ID           string    `json:"id"`           // Profile UUID
	Platform     Platform  `json:"platform"`     // ios or android
	ProfileData  []byte    `json:"-"`            // Raw profile data (never serialize)
	DownloadURL  string    `json:"download_url"` // URL to download profile
	DisplayName  string    `json:"display_name"` // User-visible name
	Description  string    `json:"description"`  // Profile description
	Organization string    `json:"organization"` // Organization name
	Identifier   string    `json:"identifier"`   // Reverse-DNS identifier
	Version      string    `json:"version"`      // Profile version
	CreatedAt    time.Time `json:"created_at"`   // Creation timestamp
	ExpiresAt    time.Time `json:"expires_at"`   // Profile expiration
}

// ============================================================================
// Section 7: QR Code Types
// ============================================================================

// QRCodeRequest for generating QR codes
type QRCodeRequest struct {
	Content string `json:"content"` // URL or data to encode
	Size    int    `json:"size"`    // QR code size in pixels
	Format  string `json:"format"`  // png, svg
	Label   string `json:"label"`   // Optional label text
}

// QRCodeResponse contains generated QR code data
type QRCodeResponse struct {
	ImageData   []byte `json:"image_data,omitempty"` // Raw image bytes
	ImageBase64 string `json:"image_base64"`         // Base64 encoded image
	ContentType string `json:"content_type"`         // MIME type
	Width       int    `json:"width"`                // Image width
	Height      int    `json:"height"`               // Image height
}

// ============================================================================
// Section 8: Device Query and Filtering Types
// ============================================================================

// DeviceQuery specifies parameters for querying devices
type DeviceQuery struct {
	IPAddress      net.IP       `json:"ip_address,omitempty"`       // Filter by IP address
	MACAddress     string       `json:"mac_address,omitempty"`      // Filter by MAC address
	Hostname       string       `json:"hostname,omitempty"`         // Filter by hostname (partial match)
	CAInstalled    *bool        `json:"ca_installed,omitempty"`     // nil = all, true = installed, false = not
	TrustStatus    *TrustStatus `json:"trust_status,omitempty"`     // Filter by trust status
	OSType         string       `json:"os_type,omitempty"`          // Filter by operating system
	LastSeenAfter  *time.Time   `json:"last_seen_after,omitempty"`  // Seen after this time
	LastSeenBefore *time.Time   `json:"last_seen_before,omitempty"` // Seen before this time
	Limit          int          `json:"limit,omitempty"`            // Maximum results (default: 50)
	Offset         int          `json:"offset,omitempty"`           // Pagination offset
	SortBy         string       `json:"sort_by,omitempty"`          // Field to sort by
	SortDesc       bool         `json:"sort_desc,omitempty"`        // Sort descending
}

// DefaultLimit returns the effective limit (default 50, max 1000)
func (dq *DeviceQuery) DefaultLimit() int {
	if dq.Limit <= 0 {
		return 50
	}
	if dq.Limit > 1000 {
		return 1000
	}
	return dq.Limit
}

// IsEmpty returns true if no filters are set
func (dq *DeviceQuery) IsEmpty() bool {
	return dq.IPAddress == nil &&
		dq.MACAddress == "" &&
		dq.Hostname == "" &&
		dq.CAInstalled == nil &&
		dq.TrustStatus == nil &&
		dq.OSType == "" &&
		dq.LastSeenAfter == nil &&
		dq.LastSeenBefore == nil
}

// DeviceListResult contains query results with pagination info
type DeviceListResult struct {
	Devices           []*DeviceStatus `json:"devices"`             // List of matching devices
	TotalCount        int64           `json:"total_count"`         // Total matching devices
	InstalledCount    int64           `json:"installed_count"`     // Devices with CA installed
	NotInstalledCount int64           `json:"not_installed_count"` // Devices without CA
	Limit             int             `json:"limit"`               // Page size used
	Offset            int             `json:"offset"`              // Current offset
	HasMore           bool            `json:"has_more"`            // More results available
}

// NextOffset returns the offset for the next page
func (dlr *DeviceListResult) NextOffset() int {
	return dlr.Offset + dlr.Limit
}

// PageCount returns the total number of pages
func (dlr *DeviceListResult) PageCount() int {
	if dlr.Limit <= 0 {
		return 1
	}
	pages := int(dlr.TotalCount) / dlr.Limit
	if int(dlr.TotalCount)%dlr.Limit > 0 {
		pages++
	}
	return pages
}

// CurrentPage returns the current page number (1-indexed)
func (dlr *DeviceListResult) CurrentPage() int {
	if dlr.Limit <= 0 {
		return 1
	}
	return (dlr.Offset / dlr.Limit) + 1
}

// ============================================================================
// Section 9: Extended Device Statistics Types
// ============================================================================

// DeviceStatistics provides comprehensive CA installation metrics
type DeviceStatistics struct {
	// Basic counts
	TotalDevices     int64   `json:"total_devices"`      // Total unique devices tracked
	DevicesWithCA    int64   `json:"devices_with_ca"`    // Devices with CA installed
	DevicesWithoutCA int64   `json:"devices_without_ca"` // Devices without CA installed
	InstallationRate float64 `json:"installation_rate"`  // Percentage installed (0.0-100.0)

	// Time-based metrics
	DownloadsLast24Hours        int64 `json:"downloads_last_24_hours"`         // Downloads in last 24 hours
	DownloadsLast7Days          int64 `json:"downloads_last_7_days"`           // Downloads in last 7 days
	DownloadsLast30Days         int64 `json:"downloads_last_30_days"`          // Downloads in last 30 days
	NewInstallationsLast24Hours int64 `json:"new_installations_last_24_hours"` // New installations in 24h
	NewInstallationsLast7Days   int64 `json:"new_installations_last_7_days"`   // New installations in 7 days
	NewDevicesLast24Hours       int64 `json:"new_devices_last_24_hours"`       // New devices seen in 24h
	NewDevicesLast7Days         int64 `json:"new_devices_last_7_days"`         // New devices seen in 7 days

	// Breakdown by status
	ByTrustStatus map[TrustStatus]int64 `json:"by_trust_status"` // Count per trust status
	ByOS          *DevicesByOS          `json:"by_os"`           // Count per operating system

	// Download format breakdown
	DownloadsByFormat map[CertFormat]int64     `json:"downloads_by_format"` // Downloads per format
	DownloadsBySource map[DownloadSource]int64 `json:"downloads_by_source"` // Downloads per source

	// Metadata
	Timestamp   time.Time `json:"timestamp"`    // When statistics were calculated
	PeriodStart time.Time `json:"period_start"` // Statistics period start
	PeriodEnd   time.Time `json:"period_end"`   // Statistics period end
}

// NewDeviceStatistics creates a DeviceStatistics with initialized maps
func NewDeviceStatistics() *DeviceStatistics {
	return &DeviceStatistics{
		ByTrustStatus:     make(map[TrustStatus]int64),
		ByOS:              &DevicesByOS{},
		DownloadsByFormat: make(map[CertFormat]int64),
		DownloadsBySource: make(map[DownloadSource]int64),
		Timestamp:         time.Now(),
	}
}

// CalculateInstallationRate computes the installation rate from counts
func (ds *DeviceStatistics) CalculateInstallationRate() {
	if ds.TotalDevices == 0 {
		ds.InstallationRate = 0
		return
	}
	ds.InstallationRate = float64(ds.DevicesWithCA) / float64(ds.TotalDevices) * 100
}

// ============================================================================
// Section 10: Validation and Helper Methods
// ============================================================================

// IsValidMACAddress validates MAC address format (AA:BB:CC:DD:EE:FF)
func IsValidMACAddress(mac string) bool {
	_, err := net.ParseMAC(mac)
	return err == nil
}

// NormalizeMACAddress converts MAC address to uppercase with colons
func NormalizeMACAddress(mac string) (string, error) {
	hw, err := net.ParseMAC(mac)
	if err != nil {
		return "", err
	}
	return hw.String(), nil
}

// DeviceStatusFromInfo creates a new DeviceStatus from basic info
func DeviceStatusFromInfo(info DeviceInfo) *DeviceStatus {
	deviceID := GenerateDeviceID(info.IPAddress, info.MACAddress)
	now := time.Now()
	return &DeviceStatus{
		DeviceID:    deviceID,
		IPAddress:   info.IPAddress,
		MACAddress:  info.MACAddress,
		Hostname:    info.Hostname,
		CAInstalled: false,
		LastSeen:    now,
		FirstSeen:   now,
		TrustStatus: TrustStatusUnknown,
	}
}

// UpdateLastSeen updates the LastSeen timestamp
func (ds *DeviceStatus) UpdateLastSeen() {
	ds.LastSeen = time.Now()
}

// MarkAsTrusted marks the device as having the CA installed
func (ds *DeviceStatus) MarkAsTrusted(method DetectionMethod) {
	ds.CAInstalled = true
	ds.TrustStatus = TrustStatusTrusted
	ds.DetectionMethod = string(method)
	ds.LastSeen = time.Now()
}

// MarkAsUntrusted marks the device as not having the CA installed
func (ds *DeviceStatus) MarkAsUntrusted(method DetectionMethod) {
	ds.CAInstalled = false
	ds.TrustStatus = TrustStatusUntrusted
	ds.DetectionMethod = string(method)
	ds.LastSeen = time.Now()
}

// IsStale returns true if the device hasn't been seen in the specified duration
func (ds *DeviceStatus) IsStale(staleDuration time.Duration) bool {
	return time.Since(ds.LastSeen) > staleDuration
}

// DurationSinceLastSeen returns how long since the device was last seen
func (ds *DeviceStatus) DurationSinceLastSeen() time.Duration {
	return time.Since(ds.LastSeen)
}

// ToInfo extracts basic DeviceInfo from DeviceStatus
func (ds *DeviceStatus) ToInfo() DeviceInfo {
	return DeviceInfo{
		IPAddress:  ds.IPAddress,
		MACAddress: ds.MACAddress,
		Hostname:   ds.Hostname,
	}
}
