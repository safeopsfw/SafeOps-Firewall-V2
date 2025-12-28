// Package pool provides DHCP IP pool management.
// This file implements static IP address reservation management.
package pool

import (
	"errors"
	"fmt"
	"net"
	"regexp"
	"strings"
	"sync"
	"time"
)

// ============================================================================
// Reservation Data Structures
// ============================================================================

// Reservation represents a static IP address reservation.
type Reservation struct {
	MAC         net.HardwareAddr `json:"mac"`
	IP          net.IP           `json:"ip"`
	Hostname    string           `json:"hostname,omitempty"`
	PoolID      string           `json:"pool_id"`
	Description string           `json:"description,omitempty"`
	CreatedAt   time.Time        `json:"created_at"`
	LastSeen    time.Time        `json:"last_seen,omitempty"`
	ExpiresAt   *time.Time       `json:"expires_at,omitempty"`
	Active      bool             `json:"active"`
}

// ReservationRegistry manages all reservations with multiple indices.
type ReservationRegistry struct {
	mu sync.RWMutex

	// Storage
	reservations map[string]*Reservation // Keyed by normalized MAC

	// Indices for O(1) lookups
	byIP       map[string]*Reservation // Keyed by IP string
	byHostname map[string]*Reservation // Keyed by lowercase hostname
}

// ReservationStatistics holds registry metrics.
type ReservationStatistics struct {
	Total   int            `json:"total"`
	Active  int            `json:"active"`
	ByPool  map[string]int `json:"by_pool"`
	Expired int            `json:"expired"`
	Unused  int            `json:"unused"`
}

// ============================================================================
// Reservation Creation Functions
// ============================================================================

// NewReservation creates a new static IP reservation.
func NewReservation(macStr string, ip net.IP, poolID, hostname string) (*Reservation, error) {
	// Parse and validate MAC
	mac, err := net.ParseMAC(macStr)
	if err != nil {
		return nil, fmt.Errorf("invalid MAC address: %w", err)
	}

	// Validate IP
	ip4 := ip.To4()
	if ip4 == nil {
		return nil, errors.New("IP must be valid IPv4")
	}

	// Validate hostname if provided
	if hostname != "" {
		if err := ValidateHostname(hostname); err != nil {
			return nil, err
		}
	}

	return &Reservation{
		MAC:       mac,
		IP:        ip4,
		Hostname:  hostname,
		PoolID:    poolID,
		CreatedAt: time.Now(),
		Active:    true,
	}, nil
}

// NewTemporaryReservation creates a reservation with expiration.
func NewTemporaryReservation(macStr string, ip net.IP, poolID string, duration time.Duration) (*Reservation, error) {
	res, err := NewReservation(macStr, ip, poolID, "")
	if err != nil {
		return nil, err
	}

	expires := time.Now().Add(duration)
	res.ExpiresAt = &expires
	return res, nil
}

// ============================================================================
// Registry Creation
// ============================================================================

// NewReservationRegistry creates an empty reservation registry.
func NewReservationRegistry() *ReservationRegistry {
	return &ReservationRegistry{
		reservations: make(map[string]*Reservation),
		byIP:         make(map[string]*Reservation),
		byHostname:   make(map[string]*Reservation),
	}
}

// ============================================================================
// Registry Operations
// ============================================================================

// Add adds a reservation to the registry.
func (r *ReservationRegistry) Add(res *Reservation) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	macKey := normalizeMACKey(res.MAC)
	ipKey := res.IP.String()

	// Check for MAC conflict
	if existing, ok := r.reservations[macKey]; ok {
		if !existing.IP.Equal(res.IP) {
			return fmt.Errorf("MAC %s already reserved for different IP %s", res.MAC, existing.IP)
		}
	}

	// Check for IP conflict
	if existing, ok := r.byIP[ipKey]; ok {
		if normalizeMACKey(existing.MAC) != macKey {
			return fmt.Errorf("IP %s already reserved for different MAC %s", res.IP, existing.MAC)
		}
	}

	// Add to all indices
	r.reservations[macKey] = res
	r.byIP[ipKey] = res
	if res.Hostname != "" {
		r.byHostname[strings.ToLower(res.Hostname)] = res
	}

	return nil
}

// Remove removes a reservation by MAC address.
func (r *ReservationRegistry) Remove(mac net.HardwareAddr) (*Reservation, error) {
	r.mu.Lock()
	defer r.mu.Unlock()

	macKey := normalizeMACKey(mac)
	res, ok := r.reservations[macKey]
	if !ok {
		return nil, ErrReservationNotFound
	}

	// Remove from all indices
	delete(r.reservations, macKey)
	delete(r.byIP, res.IP.String())
	if res.Hostname != "" {
		delete(r.byHostname, strings.ToLower(res.Hostname))
	}

	return res, nil
}

// Update updates an existing reservation.
func (r *ReservationRegistry) Update(mac net.HardwareAddr, ip net.IP, hostname string) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	macKey := normalizeMACKey(mac)
	res, ok := r.reservations[macKey]
	if !ok {
		return ErrReservationNotFound
	}

	oldIPKey := res.IP.String()
	newIPKey := ip.String()

	// Check IP conflict if changing IP
	if oldIPKey != newIPKey {
		if existing, ok := r.byIP[newIPKey]; ok {
			if normalizeMACKey(existing.MAC) != macKey {
				return fmt.Errorf("IP %s already reserved for MAC %s", ip, existing.MAC)
			}
		}
		// Update IP index
		delete(r.byIP, oldIPKey)
		r.byIP[newIPKey] = res
		res.IP = ip.To4()
	}

	// Update hostname index if changing
	if res.Hostname != hostname {
		if res.Hostname != "" {
			delete(r.byHostname, strings.ToLower(res.Hostname))
		}
		if hostname != "" {
			if err := ValidateHostname(hostname); err != nil {
				return err
			}
			r.byHostname[strings.ToLower(hostname)] = res
		}
		res.Hostname = hostname
	}

	return nil
}

// ============================================================================
// Lookup Functions
// ============================================================================

// FindByMAC searches for reservation by MAC address (O(1)).
func (r *ReservationRegistry) FindByMAC(mac net.HardwareAddr) *Reservation {
	r.mu.RLock()
	defer r.mu.RUnlock()

	return r.reservations[normalizeMACKey(mac)]
}

// FindByIP searches for reservation by IP address (O(1)).
func (r *ReservationRegistry) FindByIP(ip net.IP) *Reservation {
	r.mu.RLock()
	defer r.mu.RUnlock()

	return r.byIP[ip.String()]
}

// FindByHostname searches for reservation by hostname (case-insensitive).
func (r *ReservationRegistry) FindByHostname(hostname string) *Reservation {
	r.mu.RLock()
	defer r.mu.RUnlock()

	return r.byHostname[strings.ToLower(hostname)]
}

// FindByPool returns all reservations for a specific pool.
func (r *ReservationRegistry) FindByPool(poolID string) []*Reservation {
	r.mu.RLock()
	defer r.mu.RUnlock()

	results := make([]*Reservation, 0)
	for _, res := range r.reservations {
		if res.PoolID == poolID {
			results = append(results, res)
		}
	}
	return results
}

// GetAll returns all reservations.
func (r *ReservationRegistry) GetAll() []*Reservation {
	r.mu.RLock()
	defer r.mu.RUnlock()

	results := make([]*Reservation, 0, len(r.reservations))
	for _, res := range r.reservations {
		results = append(results, res)
	}
	return results
}

// GetActive returns all active, non-expired reservations.
func (r *ReservationRegistry) GetActive() []*Reservation {
	r.mu.RLock()
	defer r.mu.RUnlock()

	now := time.Now()
	results := make([]*Reservation, 0)
	for _, res := range r.reservations {
		if res.Active && !res.IsExpired(now) {
			results = append(results, res)
		}
	}
	return results
}

// ============================================================================
// Reservation Priority Functions
// ============================================================================

// GetReservedIPForMAC returns the IP reserved for a MAC (if any).
func (r *ReservationRegistry) GetReservedIPForMAC(mac net.HardwareAddr) net.IP {
	res := r.FindByMAC(mac)
	if res == nil || !res.Active {
		return nil
	}
	if res.IsExpired(time.Now()) {
		return nil
	}
	return res.IP
}

// IsIPReserved checks if an IP has any reservation.
func (r *ReservationRegistry) IsIPReserved(ip net.IP) bool {
	return r.FindByIP(ip) != nil
}

// IsIPReservedForOtherMAC checks if IP is reserved for a different MAC.
func (r *ReservationRegistry) IsIPReservedForOtherMAC(ip net.IP, mac net.HardwareAddr) bool {
	res := r.FindByIP(ip)
	if res == nil {
		return false
	}
	return normalizeMACKey(res.MAC) != normalizeMACKey(mac)
}

// ClaimReservation marks reservation as used and updates last seen.
func (r *ReservationRegistry) ClaimReservation(mac net.HardwareAddr, ip net.IP) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	res := r.reservations[normalizeMACKey(mac)]
	if res == nil {
		return ErrReservationNotFound
	}

	if !res.IP.Equal(ip) {
		return fmt.Errorf("reservation IP %s doesn't match claimed IP %s", res.IP, ip)
	}

	res.LastSeen = time.Now()
	return nil
}

// ============================================================================
// Enable/Disable
// ============================================================================

// Enable activates a reservation.
func (r *ReservationRegistry) Enable(mac net.HardwareAddr) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	res := r.reservations[normalizeMACKey(mac)]
	if res == nil {
		return ErrReservationNotFound
	}

	res.Active = true
	return nil
}

// Disable deactivates a reservation.
func (r *ReservationRegistry) Disable(mac net.HardwareAddr) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	res := r.reservations[normalizeMACKey(mac)]
	if res == nil {
		return ErrReservationNotFound
	}

	res.Active = false
	return nil
}

// ============================================================================
// Expiration Handling
// ============================================================================

// IsExpired checks if reservation has passed expiration time.
func (r *Reservation) IsExpired(now time.Time) bool {
	if r.ExpiresAt == nil {
		return false
	}
	return now.After(*r.ExpiresAt)
}

// ProcessExpirations removes all expired reservations.
func (r *ReservationRegistry) ProcessExpirations() []*Reservation {
	r.mu.Lock()
	defer r.mu.Unlock()

	now := time.Now()
	expired := make([]*Reservation, 0)

	for macKey, res := range r.reservations {
		if res.IsExpired(now) {
			expired = append(expired, res)
			delete(r.reservations, macKey)
			delete(r.byIP, res.IP.String())
			if res.Hostname != "" {
				delete(r.byHostname, strings.ToLower(res.Hostname))
			}
		}
	}

	return expired
}

// GetExpiring returns reservations expiring within duration.
func (r *ReservationRegistry) GetExpiring(within time.Duration) []*Reservation {
	r.mu.RLock()
	defer r.mu.RUnlock()

	cutoff := time.Now().Add(within)
	results := make([]*Reservation, 0)

	for _, res := range r.reservations {
		if res.ExpiresAt != nil && res.ExpiresAt.Before(cutoff) {
			results = append(results, res)
		}
	}

	return results
}

// ============================================================================
// Statistics
// ============================================================================

// GetStatistics returns registry statistics.
func (r *ReservationRegistry) GetStatistics() ReservationStatistics {
	r.mu.RLock()
	defer r.mu.RUnlock()

	now := time.Now()
	stats := ReservationStatistics{
		Total:  len(r.reservations),
		ByPool: make(map[string]int),
	}

	unusedThreshold := time.Now().Add(-30 * 24 * time.Hour)

	for _, res := range r.reservations {
		if res.Active && !res.IsExpired(now) {
			stats.Active++
		}
		if res.IsExpired(now) {
			stats.Expired++
		}
		if res.LastSeen.Before(unusedThreshold) {
			stats.Unused++
		}
		stats.ByPool[res.PoolID]++
	}

	return stats
}

// Count returns total number of reservations.
func (r *ReservationRegistry) Count() int {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return len(r.reservations)
}

// ============================================================================
// Validation Functions
// ============================================================================

// Hostname regex: RFC 952/1123 compliant
var hostnameRegex = regexp.MustCompile(`^[a-zA-Z][a-zA-Z0-9\-]{0,62}$`)

// ValidateHostname validates hostname format.
func ValidateHostname(hostname string) error {
	if len(hostname) > 63 {
		return errors.New("hostname exceeds 63 characters")
	}

	if !hostnameRegex.MatchString(hostname) {
		return errors.New("hostname must start with letter, contain only alphanumeric and hyphens")
	}

	if strings.HasSuffix(hostname, "-") {
		return errors.New("hostname cannot end with hyphen")
	}

	return nil
}

// ============================================================================
// Helper Functions
// ============================================================================

// normalizeMACKey converts MAC to lowercase colon-separated string.
func normalizeMACKey(mac net.HardwareAddr) string {
	return strings.ToLower(mac.String())
}

// String returns reservation description.
func (r *Reservation) String() string {
	return fmt.Sprintf("Reservation[MAC=%s IP=%s Hostname=%s Pool=%s Active=%v]",
		r.MAC, r.IP, r.Hostname, r.PoolID, r.Active)
}

// ============================================================================
// Errors
// ============================================================================

var (
	// ErrReservationNotFound is returned when reservation doesn't exist
	ErrReservationNotFound = errors.New("reservation not found")

	// ErrReservationConflict is returned when reservation conflicts exist
	ErrReservationConflict = errors.New("reservation conflict")

	// ErrInvalidMAC is returned for malformed MAC addresses
	ErrInvalidMAC = errors.New("invalid MAC address")

	// ErrInvalidHostname is returned for malformed hostnames
	ErrInvalidHostname = errors.New("invalid hostname")
)
