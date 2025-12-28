// Package models defines core DHCP data structures.
// This file implements the Lease structure for IP address assignment tracking.
package models

import (
	"bytes"
	"crypto/rand"
	"database/sql/driver"
	"errors"
	"fmt"
	"net"
	"time"
)

// ============================================================================
// LeaseState Enumeration
// ============================================================================

// LeaseState represents the current state of a DHCP lease
type LeaseState int

const (
	// LeaseStateUnknown is the zero value (invalid)
	LeaseStateUnknown LeaseState = iota
	// LeaseStateActive - Lease is currently valid and in use
	LeaseStateActive
	// LeaseStateExpired - Lease time exceeded, IP available for reassignment
	LeaseStateExpired
	// LeaseStateReleased - Client explicitly released IP via DHCPRELEASE
	LeaseStateReleased
	// LeaseStateAbandoned - IP conflict detected, address marked unsafe
	LeaseStateAbandoned
	// LeaseStateReserved - IP temporarily held during OFFER phase
	LeaseStateReserved
)

// LeaseState string representations
var leaseStateStrings = map[LeaseState]string{
	LeaseStateUnknown:   "UNKNOWN",
	LeaseStateActive:    "ACTIVE",
	LeaseStateExpired:   "EXPIRED",
	LeaseStateReleased:  "RELEASED",
	LeaseStateAbandoned: "ABANDONED",
	LeaseStateReserved:  "RESERVED",
}

var leaseStateFromString = map[string]LeaseState{
	"UNKNOWN":   LeaseStateUnknown,
	"ACTIVE":    LeaseStateActive,
	"EXPIRED":   LeaseStateExpired,
	"RELEASED":  LeaseStateReleased,
	"ABANDONED": LeaseStateAbandoned,
	"RESERVED":  LeaseStateReserved,
}

// String returns the string representation of the lease state
func (s LeaseState) String() string {
	if str, ok := leaseStateStrings[s]; ok {
		return str
	}
	return "UNKNOWN"
}

// Value implements driver.Valuer for database serialization
func (s LeaseState) Value() (driver.Value, error) {
	return s.String(), nil
}

// Scan implements sql.Scanner for database deserialization
func (s *LeaseState) Scan(value interface{}) error {
	if value == nil {
		*s = LeaseStateUnknown
		return nil
	}

	str, ok := value.(string)
	if !ok {
		if b, ok := value.([]byte); ok {
			str = string(b)
		} else {
			return errors.New("cannot scan non-string value into LeaseState")
		}
	}

	if state, ok := leaseStateFromString[str]; ok {
		*s = state
		return nil
	}

	*s = LeaseStateUnknown
	return nil
}

// ============================================================================
// Lease Structure
// ============================================================================

// Lease represents a DHCP IP address assignment to a client device.
// It contains all metadata for lifecycle management, renewal tracking,
// expiration handling, and audit logging.
type Lease struct {
	// Identification Fields
	LeaseID    string           `json:"lease_id" db:"lease_id"`
	PoolID     string           `json:"pool_id" db:"pool_id"`
	MACAddress net.HardwareAddr `json:"mac_address" db:"mac_address"`
	IPAddress  net.IP           `json:"ip_address" db:"ip_address"`

	// Timing Fields
	LeaseStart  time.Time `json:"lease_start" db:"lease_start"`
	LeaseEnd    time.Time `json:"lease_end" db:"lease_end"`
	T1Time      time.Time `json:"t1_time" db:"-"` // Renewal time (50%)
	T2Time      time.Time `json:"t2_time" db:"-"` // Rebinding time (87.5%)
	LastRenewal time.Time `json:"last_renewal" db:"last_renewal"`

	// Client Information
	Hostname         string `json:"hostname" db:"hostname"`
	ClientIdentifier []byte `json:"client_identifier" db:"client_identifier"`
	VendorClassID    string `json:"vendor_class_id" db:"vendor_class"`
	UserClass        string `json:"user_class" db:"user_class"`

	// State Tracking
	State             LeaseState `json:"state" db:"state"`
	RenewalCount      uint32     `json:"renewal_count" db:"renewal_count"`
	ConflictDetected  bool       `json:"conflict_detected" db:"-"`
	ConflictTimestamp time.Time  `json:"conflict_timestamp" db:"-"`

	// Metadata
	CreatedAt time.Time `json:"created_at" db:"created_at"`
	UpdatedAt time.Time `json:"updated_at" db:"updated_at"`
	Notes     string    `json:"notes" db:"-"`
}

// ============================================================================
// Lease Constructor Functions
// ============================================================================

// T1 and T2 ratios per RFC 2131
const (
	T1RenewalRatio   = 0.5   // 50% of lease duration
	T2RebindingRatio = 0.875 // 87.5% of lease duration
)

// generateUUID creates a random UUID v4 string using crypto/rand
func generateUUID() string {
	b := make([]byte, 16)
	_, _ = rand.Read(b)
	// Set version (4) and variant bits
	b[6] = (b[6] & 0x0f) | 0x40
	b[8] = (b[8] & 0x3f) | 0x80
	return fmt.Sprintf("%08x-%04x-%04x-%04x-%012x",
		b[0:4], b[4:6], b[6:8], b[8:10], b[10:16])
}

// NewLease creates a new active lease with the specified duration.
// Automatically generates LeaseID and calculates T1/T2 times.
func NewLease(poolID string, mac net.HardwareAddr, ip net.IP, duration time.Duration) *Lease {
	now := time.Now()
	leaseEnd := now.Add(duration)

	return &Lease{
		LeaseID:      generateUUID(),
		PoolID:       poolID,
		MACAddress:   mac,
		IPAddress:    ip,
		LeaseStart:   now,
		LeaseEnd:     leaseEnd,
		T1Time:       now.Add(time.Duration(float64(duration) * T1RenewalRatio)),
		T2Time:       now.Add(time.Duration(float64(duration) * T2RebindingRatio)),
		State:        LeaseStateActive,
		RenewalCount: 0,
		CreatedAt:    now,
		UpdatedAt:    now,
	}
}

// NewReservedLease creates a lease in Reserved state during OFFER phase.
// Uses a short TTL (typically 2 minutes) before reverting to available.
func NewReservedLease(poolID string, mac net.HardwareAddr, ip net.IP, holdDuration time.Duration) *Lease {
	now := time.Now()

	return &Lease{
		LeaseID:    generateUUID(),
		PoolID:     poolID,
		MACAddress: mac,
		IPAddress:  ip,
		LeaseStart: now,
		LeaseEnd:   now.Add(holdDuration),
		State:      LeaseStateReserved,
		CreatedAt:  now,
		UpdatedAt:  now,
	}
}

// ============================================================================
// Lease Lifecycle Methods
// ============================================================================

// Renew extends the lease by the specified duration.
// Returns error if lease is not in Active state.
func (l *Lease) Renew(duration time.Duration) error {
	if l.State != LeaseStateActive {
		return fmt.Errorf("cannot renew lease in %s state", l.State)
	}

	now := time.Now()
	l.LeaseEnd = now.Add(duration)
	l.T1Time = now.Add(time.Duration(float64(duration) * T1RenewalRatio))
	l.T2Time = now.Add(time.Duration(float64(duration) * T2RebindingRatio))
	l.LastRenewal = now
	l.RenewalCount++
	l.UpdatedAt = now

	return nil
}

// Release transitions the lease to Released state.
// Returns error if already released or expired.
func (l *Lease) Release() error {
	if l.State == LeaseStateReleased {
		return errors.New("lease already released")
	}
	if l.State == LeaseStateExpired {
		return errors.New("lease already expired")
	}

	l.State = LeaseStateReleased
	l.LeaseEnd = time.Now()
	l.UpdatedAt = time.Now()

	return nil
}

// Expire marks the lease as expired.
// Called by background cleanup goroutine.
func (l *Lease) Expire() {
	l.State = LeaseStateExpired
	l.UpdatedAt = time.Now()
}

// Abandon marks the IP as abandoned due to conflict.
// Sets ConflictDetected flag and stores reason in Notes.
func (l *Lease) Abandon(reason string) {
	l.State = LeaseStateAbandoned
	l.ConflictDetected = true
	l.ConflictTimestamp = time.Now()
	l.Notes = reason
	l.UpdatedAt = time.Now()
}

// Activate transitions a reserved lease to active state.
// Used when DHCPREQUEST is received after DHCPOFFER.
func (l *Lease) Activate(duration time.Duration) error {
	if l.State != LeaseStateReserved {
		return fmt.Errorf("cannot activate lease in %s state", l.State)
	}

	now := time.Now()
	l.State = LeaseStateActive
	l.LeaseStart = now
	l.LeaseEnd = now.Add(duration)
	l.T1Time = now.Add(time.Duration(float64(duration) * T1RenewalRatio))
	l.T2Time = now.Add(time.Duration(float64(duration) * T2RebindingRatio))
	l.UpdatedAt = now

	return nil
}

// ============================================================================
// Validation Methods
// ============================================================================

// IsValid checks lease data integrity.
// Returns nil if valid, error describing violation.
func (l *Lease) IsValid() error {
	if l.LeaseID == "" {
		return errors.New("LeaseID is required")
	}

	if len(l.MACAddress) != 6 {
		return fmt.Errorf("MACAddress must be 6 bytes, got %d", len(l.MACAddress))
	}

	if l.IPAddress == nil || l.IPAddress.To4() == nil {
		return errors.New("IPAddress must be valid IPv4")
	}

	if !l.LeaseEnd.After(l.LeaseStart) {
		return errors.New("LeaseEnd must be after LeaseStart")
	}

	// T1 and T2 validation only for active leases
	if l.State == LeaseStateActive {
		if !l.T1Time.Before(l.T2Time) {
			return errors.New("T1Time must be before T2Time")
		}
		if !l.T2Time.Before(l.LeaseEnd) {
			return errors.New("T2Time must be before LeaseEnd")
		}
	}

	return nil
}

// IsExpired returns true if the lease has exceeded its end time.
func (l *Lease) IsExpired() bool {
	return time.Now().After(l.LeaseEnd)
}

// IsActive returns true if the lease is in Active state and not expired.
func (l *Lease) IsActive() bool {
	return l.State == LeaseStateActive && !l.IsExpired()
}

// NeedsRenewal returns true if T1 timer has passed but lease is still active.
func (l *Lease) NeedsRenewal() bool {
	return l.IsActive() && time.Now().After(l.T1Time)
}

// NeedsRebinding returns true if T2 timer has passed but lease is still active.
func (l *Lease) NeedsRebinding() bool {
	return l.IsActive() && time.Now().After(l.T2Time)
}

// TimeRemaining returns the duration until lease expiration.
func (l *Lease) TimeRemaining() time.Duration {
	remaining := time.Until(l.LeaseEnd)
	if remaining < 0 {
		return 0
	}
	return remaining
}

// ============================================================================
// Comparison Methods
// ============================================================================

// Equals returns true if the lease IDs match.
func (l *Lease) Equals(other *Lease) bool {
	if other == nil {
		return false
	}
	return l.LeaseID == other.LeaseID
}

// IsSameClient returns true if the MAC address matches.
func (l *Lease) IsSameClient(mac net.HardwareAddr) bool {
	return bytes.Equal(l.MACAddress, mac)
}

// IsSameIP returns true if the IP address matches.
func (l *Lease) IsSameIP(ip net.IP) bool {
	return l.IPAddress.Equal(ip)
}

// ============================================================================
// String Representation
// ============================================================================

// String returns a human-readable lease description.
func (l *Lease) String() string {
	return fmt.Sprintf("Lease[IP=%s MAC=%s Hostname=%s State=%s Expires=%s]",
		l.IPAddress.String(),
		l.MACAddress.String(),
		l.Hostname,
		l.State.String(),
		l.LeaseEnd.Format(time.RFC3339),
	)
}

// ShortString returns a brief lease description for logging.
func (l *Lease) ShortString() string {
	return fmt.Sprintf("%s→%s (%s)", l.MACAddress, l.IPAddress, l.State)
}
