// Package database provides PostgreSQL database models and operations
// for the DHCP Monitor service.
package database

import (
	"database/sql"
	"net"
	"time"

	pb "dhcp_monitor/proto/gen"

	"github.com/google/uuid"
)

// TrustStatus represents device security classification
type TrustStatus string

const (
	TrustStatusUntrusted TrustStatus = "UNTRUSTED"
	TrustStatusTrusted   TrustStatus = "TRUSTED"
	TrustStatusBlocked   TrustStatus = "BLOCKED"
)

// DeviceStatus represents device connection state
type DeviceStatus string

const (
	DeviceStatusActive  DeviceStatus = "ACTIVE"
	DeviceStatusOffline DeviceStatus = "OFFLINE"
	DeviceStatusExpired DeviceStatus = "EXPIRED"
)

// DetectionMethod represents how the device was discovered
type DetectionMethod string

const (
	DetectionMethodIPHelper  DetectionMethod = "IP_HELPER_API"
	DetectionMethodDHCPEvent DetectionMethod = "DHCP_EVENT_LOG"
	DetectionMethodARPTable  DetectionMethod = "ARP_TABLE"
	DetectionMethodManual    DetectionMethod = "MANUAL"
)

// LeaseState represents DHCP lease lifecycle state
type LeaseState string

const (
	LeaseStateActive   LeaseState = "ACTIVE"
	LeaseStateExpired  LeaseState = "EXPIRED"
	LeaseStateReleased LeaseState = "RELEASED"
	LeaseStateRenewed  LeaseState = "RENEWED"
)

// ChangeReason represents why an IP address changed
type ChangeReason string

const (
	ChangeReasonIPCallback   ChangeReason = "IP_CHANGE_CALLBACK"
	ChangeReasonDHCPRenew    ChangeReason = "DHCP_RENEW"
	ChangeReasonNICSwitch    ChangeReason = "NIC_SWITCH"
	ChangeReasonReconnect    ChangeReason = "RECONNECT"
	ChangeReasonManual       ChangeReason = "MANUAL"
	ChangeReasonARPDetection ChangeReason = "ARP_DETECTION"
)

// =============================================================================
// DEVICE MODEL
// =============================================================================

// Device represents a network device in the database
type Device struct {
	DeviceID        uuid.UUID       `db:"device_id" json:"device_id"`
	MACAddress      string          `db:"mac_address" json:"mac_address"`
	CurrentIP       net.IP          `db:"current_ip" json:"current_ip"`
	PreviousIP      sql.NullString  `db:"previous_ip" json:"previous_ip,omitempty"`
	Hostname        sql.NullString  `db:"hostname" json:"hostname,omitempty"`
	DeviceType      string          `db:"device_type" json:"device_type"`
	Vendor          sql.NullString  `db:"vendor" json:"vendor,omitempty"`
	TrustStatus     TrustStatus     `db:"trust_status" json:"trust_status"`
	InterfaceName   string          `db:"interface_name" json:"interface_name"`
	InterfaceIndex  int32           `db:"interface_index" json:"interface_index"`
	InterfaceGUID   sql.NullString  `db:"interface_guid" json:"interface_guid,omitempty"`
	Status          DeviceStatus    `db:"status" json:"status"`
	IsOnline        bool            `db:"is_online" json:"is_online"`
	DetectionMethod DetectionMethod `db:"detection_method" json:"detection_method"`
	FirstSeen       time.Time       `db:"first_seen" json:"first_seen"`
	LastSeen        time.Time       `db:"last_seen" json:"last_seen"`
	CreatedAt       time.Time       `db:"created_at" json:"created_at"`
	UpdatedAt       time.Time       `db:"updated_at" json:"updated_at"`
	Notes           sql.NullString  `db:"notes" json:"notes,omitempty"`
	// Phase 3A: Portal tracking for ALLOW_ONCE policy
	PortalShown   bool         `db:"portal_shown" json:"portal_shown"`
	PortalShownAt sql.NullTime `db:"portal_shown_at" json:"portal_shown_at,omitempty"`
	// Phase 3B: CA certificate tracking
	CACertInstalled   bool         `db:"ca_cert_installed" json:"ca_cert_installed"`
	CACertInstalledAt sql.NullTime `db:"ca_cert_installed_at" json:"ca_cert_installed_at,omitempty"`
	// Device Fingerprint Fields
	NetBIOSName      sql.NullString `db:"netbios_name" json:"netbios_name,omitempty"`
	NetBIOSDomain    sql.NullString `db:"netbios_domain" json:"netbios_domain,omitempty"`
	ResolvedHostname sql.NullString `db:"resolved_hostname" json:"resolved_hostname,omitempty"`
	OSType           sql.NullString `db:"os_type" json:"os_type,omitempty"`
	OSVersion        sql.NullString `db:"os_version" json:"os_version,omitempty"`
	OSFingerprint    sql.NullString `db:"os_fingerprint" json:"os_fingerprint,omitempty"`
	InitialTTL       sql.NullInt32  `db:"initial_ttl" json:"initial_ttl,omitempty"`
	DHCPVendorClass  sql.NullString `db:"dhcp_vendor_class" json:"dhcp_vendor_class,omitempty"`
	DeviceClass      sql.NullString `db:"device_class" json:"device_class,omitempty"`
	Manufacturer     sql.NullString `db:"manufacturer" json:"manufacturer,omitempty"`
	FingerprintedAt  sql.NullTime   `db:"fingerprinted_at" json:"fingerprinted_at,omitempty"`
}

// ToProto converts Device to protobuf message
func (d *Device) ToProto() *pb.Device {
	portalShownAt := ""
	if d.PortalShownAt.Valid {
		portalShownAt = d.PortalShownAt.Time.Format(time.RFC3339)
	}
	caCertInstalledAt := ""
	if d.CACertInstalledAt.Valid {
		caCertInstalledAt = d.CACertInstalledAt.Time.Format(time.RFC3339)
	}
	return &pb.Device{
		DeviceId:          d.DeviceID.String(),
		MacAddress:        d.MACAddress,
		CurrentIp:         d.CurrentIP.String(),
		Hostname:          d.Hostname.String,
		DeviceType:        d.DeviceType,
		Vendor:            d.Vendor.String,
		TrustStatus:       string(d.TrustStatus),
		InterfaceName:     d.InterfaceName,
		InterfaceIndex:    d.InterfaceIndex,
		Status:            string(d.Status),
		DetectionMethod:   string(d.DetectionMethod),
		FirstSeen:         d.FirstSeen.Format(time.RFC3339),
		LastSeen:          d.LastSeen.Format(time.RFC3339),
		IsOnline:          d.IsOnline,
		PortalShown:       d.PortalShown,
		PortalShownAt:     portalShownAt,
		CaCertInstalled:   d.CACertInstalled,
		CaCertInstalledAt: caCertInstalledAt,
	}
}

// DeviceFromProto converts protobuf message to Device
func DeviceFromProto(pb *pb.Device) (*Device, error) {
	deviceID, err := uuid.Parse(pb.DeviceId)
	if err != nil {
		deviceID = uuid.New()
	}

	return &Device{
		DeviceID:        deviceID,
		MACAddress:      pb.MacAddress,
		CurrentIP:       net.ParseIP(pb.CurrentIp),
		Hostname:        sql.NullString{String: pb.Hostname, Valid: pb.Hostname != ""},
		DeviceType:      pb.DeviceType,
		Vendor:          sql.NullString{String: pb.Vendor, Valid: pb.Vendor != ""},
		TrustStatus:     TrustStatus(pb.TrustStatus),
		InterfaceName:   pb.InterfaceName,
		InterfaceIndex:  pb.InterfaceIndex,
		Status:          DeviceStatus(pb.Status),
		IsOnline:        pb.IsOnline,
		DetectionMethod: DetectionMethod(pb.DetectionMethod),
	}, nil
}

// IsExpired checks if device should be marked offline based on LastSeen
func (d *Device) IsExpired(timeout time.Duration) bool {
	return time.Since(d.LastSeen) > timeout
}

// =============================================================================
// DHCP LEASE MODEL
// =============================================================================

// DHCPLease represents a DHCP lease record
type DHCPLease struct {
	LeaseID       uuid.UUID    `db:"lease_id" json:"lease_id"`
	DeviceID      uuid.UUID    `db:"device_id" json:"device_id"`
	IPAddress     net.IP       `db:"ip_address" json:"ip_address"`
	InterfaceName string       `db:"interface_name" json:"interface_name"`
	LeaseStart    time.Time    `db:"lease_start" json:"lease_start"`
	LeaseEnd      sql.NullTime `db:"lease_end" json:"lease_end,omitempty"`
	LeaseState    LeaseState   `db:"lease_state" json:"lease_state"`
	LeaseRenewals int          `db:"lease_renewals" json:"lease_renewals"`
	CreatedAt     time.Time    `db:"created_at" json:"created_at"`
}

// IsActive checks if lease is currently active
func (l *DHCPLease) IsActive() bool {
	if l.LeaseState != LeaseStateActive {
		return false
	}
	if l.LeaseEnd.Valid && time.Now().After(l.LeaseEnd.Time) {
		return false
	}
	return true
}

// TimeRemaining calculates time until lease expiration
func (l *DHCPLease) TimeRemaining() time.Duration {
	if !l.LeaseEnd.Valid {
		return time.Duration(0) // Infinite lease
	}
	remaining := time.Until(l.LeaseEnd.Time)
	if remaining < 0 {
		return 0
	}
	return remaining
}

// =============================================================================
// IP HISTORY MODEL
// =============================================================================

// IPHistory represents an IP address change record
type IPHistory struct {
	HistoryID      uuid.UUID      `db:"history_id" json:"history_id"`
	DeviceID       uuid.UUID      `db:"device_id" json:"device_id"`
	IPAddress      net.IP         `db:"ip_address" json:"ip_address"`
	PreviousIP     sql.NullString `db:"previous_ip" json:"previous_ip,omitempty"`
	InterfaceName  string         `db:"interface_name" json:"interface_name"`
	InterfaceIndex int32          `db:"interface_index" json:"interface_index"`
	ChangeReason   ChangeReason   `db:"change_reason" json:"change_reason"`
	AssignedAt     time.Time      `db:"assigned_at" json:"assigned_at"`
	ReleasedAt     sql.NullTime   `db:"released_at" json:"released_at,omitempty"`
	CreatedAt      time.Time      `db:"created_at" json:"created_at"`
}

// =============================================================================
// DEVICE STATS MODEL
// =============================================================================

// DeviceStats represents aggregate device statistics
type DeviceStats struct {
	TotalDevices     int32 `json:"total_devices"`
	ActiveDevices    int32 `json:"active_devices"`
	TrustedDevices   int32 `json:"trusted_devices"`
	UntrustedDevices int32 `json:"untrusted_devices"`
	BlockedDevices   int32 `json:"blocked_devices"`
	OfflineDevices   int32 `json:"offline_devices"`
	OnlineDevices    int32 `json:"online_devices"`
}

// ToProto converts DeviceStats to protobuf message
func (s *DeviceStats) ToProto() *pb.DeviceStats {
	return &pb.DeviceStats{
		TotalDevices:     s.TotalDevices,
		ActiveDevices:    s.ActiveDevices,
		TrustedDevices:   s.TrustedDevices,
		UntrustedDevices: s.UntrustedDevices,
		BlockedDevices:   s.BlockedDevices,
		OfflineDevices:   s.OfflineDevices,
		OnlineDevices:    s.OnlineDevices,
	}
}

// =============================================================================
// DEVICE FILTER MODEL
// =============================================================================

// DeviceFilter represents filtering criteria for device queries
type DeviceFilter struct {
	TrustStatus   string `json:"trust_status,omitempty"`
	DeviceType    string `json:"device_type,omitempty"`
	Status        string `json:"status,omitempty"`
	InterfaceName string `json:"interface_name,omitempty"`
	OnlineOnly    bool   `json:"online_only,omitempty"`
	Limit         int32  `json:"limit,omitempty"`
	Offset        int32  `json:"offset,omitempty"`
}

// DeviceFilterFromProto converts ListDevicesRequest to DeviceFilter
func DeviceFilterFromProto(req *pb.ListDevicesRequest) *DeviceFilter {
	return &DeviceFilter{
		TrustStatus:   req.FilterByTrust,
		DeviceType:    req.FilterByType,
		Status:        req.FilterByStatus,
		InterfaceName: req.InterfaceName,
		OnlineOnly:    req.OnlineOnly,
		Limit:         req.Limit,
		Offset:        req.Offset,
	}
}
