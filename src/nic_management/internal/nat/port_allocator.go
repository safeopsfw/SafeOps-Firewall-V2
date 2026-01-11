// Package nat provides NAT/NAPT translation functionality for the NIC Management service.
package nat

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"sync"
	"time"
)

// =============================================================================
// Error Types
// =============================================================================

var (
	// ErrPortAlreadyReserved indicates the port is already reserved.
	ErrPortAlreadyReserved = errors.New("port already reserved")
	// ErrPortNotFound indicates the reservation was not found.
	ErrPortNotFound = errors.New("port reservation not found")
	// ErrInvalidPortRange indicates invalid port range parameters.
	ErrInvalidPortRange = errors.New("invalid port range")
	// ErrPortInUse indicates the port is currently in use.
	ErrPortInUse = errors.New("port currently in use")
	// ErrDatabaseSync indicates a database synchronization failure.
	ErrDatabaseSync = errors.New("database synchronization failed")
	// ErrInvalidReservation indicates invalid reservation parameters.
	ErrInvalidReservation = errors.New("invalid reservation parameters")
)

// =============================================================================
// Port Reservation
// =============================================================================

// PortReservation represents a static port forwarding rule.
type PortReservation struct {
	// ExternalPort is the external (WAN) port.
	ExternalPort uint16 `json:"external_port"`
	// InternalIP is the internal (LAN) IP address.
	InternalIP string `json:"internal_ip"`
	// InternalPort is the internal (LAN) port.
	InternalPort uint16 `json:"internal_port"`
	// Protocol is the protocol ("TCP", "UDP", or "BOTH").
	Protocol string `json:"protocol"`
	// WANInterface is the WAN interface name (or "any").
	WANInterface string `json:"wan_interface"`
	// Description is a human-readable description.
	Description string `json:"description"`
	// Enabled indicates whether the reservation is active.
	Enabled bool `json:"enabled"`
	// CreatedAt is the creation timestamp.
	CreatedAt time.Time `json:"created_at"`
	// UpdatedAt is the last update timestamp.
	UpdatedAt time.Time `json:"updated_at"`
}

// =============================================================================
// Port Allocator Configuration
// =============================================================================

// PortAllocatorConfig contains configuration for the port allocator.
type PortAllocatorConfig struct {
	// PortRangeStart is the start of the dynamic port range.
	PortRangeStart uint16 `json:"port_range_start"`
	// PortRangeEnd is the end of the dynamic port range.
	PortRangeEnd uint16 `json:"port_range_end"`
	// EnablePortPreservation tries to preserve client ports.
	EnablePortPreservation bool `json:"enable_port_preservation"`
	// ReservedPorts are excluded from dynamic allocation.
	ReservedPorts []uint16 `json:"reserved_ports"`
	// EnablePersistence enables database persistence.
	EnablePersistence bool `json:"enable_persistence"`
}

// DefaultPortAllocatorConfig returns the default configuration.
func DefaultPortAllocatorConfig() *PortAllocatorConfig {
	return &PortAllocatorConfig{
		PortRangeStart:         10000,
		PortRangeEnd:           65535,
		EnablePortPreservation: false,
		ReservedPorts:          []uint16{22, 80, 443, 8080},
		EnablePersistence:      true,
	}
}

// =============================================================================
// Port Allocation Statistics
// =============================================================================

// PortAllocationStats contains port allocation statistics.
type PortAllocationStats struct {
	// TotalPortsInRange is the total ports in dynamic range.
	TotalPortsInRange uint32 `json:"total_ports_in_range"`
	// AllocatedPorts is the currently allocated dynamic ports.
	AllocatedPorts uint32 `json:"allocated_ports"`
	// StaticReservations is the count of static reservations.
	StaticReservations uint32 `json:"static_reservations"`
	// AvailablePorts is the ports available for allocation.
	AvailablePorts uint32 `json:"available_ports"`
	// UtilizationPercent is the port pool utilization (0-100).
	UtilizationPercent float64 `json:"utilization_percent"`
}

// =============================================================================
// Database Interface
// =============================================================================

// PortAllocatorDB defines the database interface for port allocator persistence.
type PortAllocatorDB interface {
	// LoadStaticReservations loads all static reservations from database.
	LoadStaticReservations(ctx context.Context) ([]*PortReservation, error)
	// SaveStaticReservation saves a static reservation to database.
	SaveStaticReservation(ctx context.Context, reservation *PortReservation) error
	// DeleteStaticReservation deletes a static reservation from database.
	DeleteStaticReservation(ctx context.Context, externalPort uint16, protocol string) error
	// UpdateStaticReservation updates a static reservation in database.
	UpdateStaticReservation(ctx context.Context, reservation *PortReservation) error
	// SyncStaticReservations syncs all reservations to database.
	SyncStaticReservations(ctx context.Context, reservations []*PortReservation) error
}

// =============================================================================
// No-Op Database (for testing/standalone mode)
// =============================================================================

// noOpDB is a no-op database implementation.
type noOpDB struct{}

func (n *noOpDB) LoadStaticReservations(ctx context.Context) ([]*PortReservation, error) {
	return nil, nil
}

func (n *noOpDB) SaveStaticReservation(ctx context.Context, reservation *PortReservation) error {
	return nil
}

func (n *noOpDB) DeleteStaticReservation(ctx context.Context, externalPort uint16, protocol string) error {
	return nil
}

func (n *noOpDB) UpdateStaticReservation(ctx context.Context, reservation *PortReservation) error {
	return nil
}

func (n *noOpDB) SyncStaticReservations(ctx context.Context, reservations []*PortReservation) error {
	return nil
}

// =============================================================================
// Port Allocator
// =============================================================================

// PortAllocator manages port allocation for NAT.
type PortAllocator struct {
	// Database client for persistence.
	db PortAllocatorDB
	// Configuration.
	config *PortAllocatorConfig
	// Read-write mutex for thread safety.
	mu sync.RWMutex
	// Static port reservations (keyed by "port:protocol").
	staticReservations map[string]*PortReservation
	// Port range start.
	portRangeStart uint16
	// Port range end.
	portRangeEnd uint16
	// Reserved ports set.
	reservedPorts map[uint16]bool
}

// NewPortAllocator creates a new port allocator.
func NewPortAllocator(db PortAllocatorDB, config *PortAllocatorConfig) (*PortAllocator, error) {
	if config == nil {
		config = DefaultPortAllocatorConfig()
	}

	if err := validatePortRange(config.PortRangeStart, config.PortRangeEnd); err != nil {
		return nil, err
	}

	if db == nil {
		db = &noOpDB{}
	}

	// Build reserved ports set.
	reservedPorts := make(map[uint16]bool)
	for _, port := range config.ReservedPorts {
		reservedPorts[port] = true
	}

	pa := &PortAllocator{
		db:                 db,
		config:             config,
		staticReservations: make(map[string]*PortReservation),
		portRangeStart:     config.PortRangeStart,
		portRangeEnd:       config.PortRangeEnd,
		reservedPorts:      reservedPorts,
	}

	return pa, nil
}

// Initialize loads state from database.
func (pa *PortAllocator) Initialize(ctx context.Context) error {
	if pa.config.EnablePersistence {
		return pa.loadStaticReservationsFromDB(ctx)
	}
	return nil
}

// =============================================================================
// Static Reservation Management
// =============================================================================

// reservationKey creates a map key for a reservation.
func reservationKey(port uint16, protocol string) string {
	return fmt.Sprintf("%d:%s", port, protocol)
}

// AddStaticReservation adds a static port forwarding rule.
func (pa *PortAllocator) AddStaticReservation(ctx context.Context, reservation *PortReservation) error {
	if err := pa.validateReservation(reservation); err != nil {
		return err
	}

	pa.mu.Lock()
	defer pa.mu.Unlock()

	// Check for conflicts.
	if err := pa.checkPortConflict(reservation); err != nil {
		return err
	}

	// Set timestamps.
	now := time.Now()
	reservation.CreatedAt = now
	reservation.UpdatedAt = now

	// Add to map.
	key := reservationKey(reservation.ExternalPort, reservation.Protocol)
	pa.staticReservations[key] = reservation

	// If protocol is BOTH, also add for the other protocol.
	if reservation.Protocol == "BOTH" {
		tcpKey := reservationKey(reservation.ExternalPort, "TCP")
		udpKey := reservationKey(reservation.ExternalPort, "UDP")
		pa.staticReservations[tcpKey] = reservation
		pa.staticReservations[udpKey] = reservation
	}

	// Persist to database.
	if pa.config.EnablePersistence {
		if err := pa.db.SaveStaticReservation(ctx, reservation); err != nil {
			// Rollback in-memory changes.
			delete(pa.staticReservations, key)
			return fmt.Errorf("%w: %v", ErrDatabaseSync, err)
		}
	}

	return nil
}

// RemoveStaticReservation removes a static port forwarding rule.
func (pa *PortAllocator) RemoveStaticReservation(ctx context.Context, externalPort uint16, protocol string) error {
	pa.mu.Lock()
	defer pa.mu.Unlock()

	key := reservationKey(externalPort, protocol)
	reservation, exists := pa.staticReservations[key]
	if !exists {
		return ErrPortNotFound
	}

	// Remove from map.
	delete(pa.staticReservations, key)

	// If protocol was BOTH, also remove the other keys.
	if reservation.Protocol == "BOTH" {
		delete(pa.staticReservations, reservationKey(externalPort, "TCP"))
		delete(pa.staticReservations, reservationKey(externalPort, "UDP"))
	}

	// Delete from database.
	if pa.config.EnablePersistence {
		if err := pa.db.DeleteStaticReservation(ctx, externalPort, protocol); err != nil {
			// Re-add to map on failure.
			pa.staticReservations[key] = reservation
			return fmt.Errorf("%w: %v", ErrDatabaseSync, err)
		}
	}

	return nil
}

// UpdateStaticReservation updates an existing static port forwarding rule.
func (pa *PortAllocator) UpdateStaticReservation(ctx context.Context, externalPort uint16, protocol string, updates *PortReservation) error {
	pa.mu.Lock()
	defer pa.mu.Unlock()

	key := reservationKey(externalPort, protocol)
	existing, exists := pa.staticReservations[key]
	if !exists {
		return ErrPortNotFound
	}

	// Update fields.
	if updates.InternalIP != "" {
		existing.InternalIP = updates.InternalIP
	}
	if updates.InternalPort != 0 {
		existing.InternalPort = updates.InternalPort
	}
	if updates.Description != "" {
		existing.Description = updates.Description
	}
	if updates.WANInterface != "" {
		existing.WANInterface = updates.WANInterface
	}
	existing.Enabled = updates.Enabled
	existing.UpdatedAt = time.Now()

	// Update in database.
	if pa.config.EnablePersistence {
		if err := pa.db.UpdateStaticReservation(ctx, existing); err != nil {
			return fmt.Errorf("%w: %v", ErrDatabaseSync, err)
		}
	}

	return nil
}

// ListStaticReservations returns all static port forwarding rules.
func (pa *PortAllocator) ListStaticReservations(ctx context.Context) ([]*PortReservation, error) {
	pa.mu.RLock()
	defer pa.mu.RUnlock()

	// Use a map to deduplicate (BOTH creates multiple keys).
	seen := make(map[string]bool)
	result := make([]*PortReservation, 0, len(pa.staticReservations))

	for _, reservation := range pa.staticReservations {
		key := reservationKey(reservation.ExternalPort, reservation.Protocol)
		if !seen[key] {
			seen[key] = true
			result = append(result, reservation)
		}
	}

	return result, nil
}

// GetStaticReservation gets a specific static reservation.
func (pa *PortAllocator) GetStaticReservation(externalPort uint16, protocol string) (*PortReservation, error) {
	pa.mu.RLock()
	defer pa.mu.RUnlock()

	key := reservationKey(externalPort, protocol)
	reservation, exists := pa.staticReservations[key]
	if !exists {
		return nil, ErrPortNotFound
	}

	return reservation, nil
}

// =============================================================================
// Port Range Configuration
// =============================================================================

// UpdatePortRange updates the dynamic port allocation range.
func (pa *PortAllocator) UpdatePortRange(ctx context.Context, start, end uint16) error {
	if err := validatePortRange(start, end); err != nil {
		return err
	}

	pa.mu.Lock()
	defer pa.mu.Unlock()

	pa.portRangeStart = start
	pa.portRangeEnd = end
	pa.config.PortRangeStart = start
	pa.config.PortRangeEnd = end

	return nil
}

// GetPortRange returns the current port allocation range.
func (pa *PortAllocator) GetPortRange() (uint16, uint16) {
	pa.mu.RLock()
	defer pa.mu.RUnlock()
	return pa.portRangeStart, pa.portRangeEnd
}

// =============================================================================
// Port Availability
// =============================================================================

// IsPortAvailable checks if a port is available for static reservation.
func (pa *PortAllocator) IsPortAvailable(port uint16, protocol string) bool {
	pa.mu.RLock()
	defer pa.mu.RUnlock()

	// Check reserved ports.
	if pa.reservedPorts[port] {
		return false
	}

	// Check static reservations.
	key := reservationKey(port, protocol)
	if _, exists := pa.staticReservations[key]; exists {
		return false
	}

	// Check BOTH protocol.
	bothKey := reservationKey(port, "BOTH")
	if _, exists := pa.staticReservations[bothKey]; exists {
		return false
	}

	return true
}

// =============================================================================
// Reserved Ports Management
// =============================================================================

// AddReservedPort adds a port to the reserved list.
func (pa *PortAllocator) AddReservedPort(port uint16) {
	pa.mu.Lock()
	defer pa.mu.Unlock()
	pa.reservedPorts[port] = true
	pa.config.ReservedPorts = append(pa.config.ReservedPorts, port)
}

// RemoveReservedPort removes a port from the reserved list.
func (pa *PortAllocator) RemoveReservedPort(port uint16) {
	pa.mu.Lock()
	defer pa.mu.Unlock()
	delete(pa.reservedPorts, port)

	// Remove from config slice.
	newPorts := make([]uint16, 0, len(pa.config.ReservedPorts))
	for _, p := range pa.config.ReservedPorts {
		if p != port {
			newPorts = append(newPorts, p)
		}
	}
	pa.config.ReservedPorts = newPorts
}

// GetReservedPorts returns a copy of the reserved ports list.
func (pa *PortAllocator) GetReservedPorts() []uint16 {
	pa.mu.RLock()
	defer pa.mu.RUnlock()

	result := make([]uint16, 0, len(pa.reservedPorts))
	for port := range pa.reservedPorts {
		result = append(result, port)
	}
	return result
}

// =============================================================================
// Database Persistence
// =============================================================================

// loadStaticReservationsFromDB loads static reservations from database.
func (pa *PortAllocator) loadStaticReservationsFromDB(ctx context.Context) error {
	reservations, err := pa.db.LoadStaticReservations(ctx)
	if err != nil {
		return fmt.Errorf("failed to load static reservations: %w", err)
	}

	pa.mu.Lock()
	defer pa.mu.Unlock()

	for _, reservation := range reservations {
		key := reservationKey(reservation.ExternalPort, reservation.Protocol)
		pa.staticReservations[key] = reservation

		if reservation.Protocol == "BOTH" {
			pa.staticReservations[reservationKey(reservation.ExternalPort, "TCP")] = reservation
			pa.staticReservations[reservationKey(reservation.ExternalPort, "UDP")] = reservation
		}
	}

	return nil
}

// SyncToDatabase synchronizes in-memory state to database.
func (pa *PortAllocator) SyncToDatabase(ctx context.Context) error {
	if !pa.config.EnablePersistence {
		return nil
	}

	reservations, err := pa.ListStaticReservations(ctx)
	if err != nil {
		return err
	}

	if err := pa.db.SyncStaticReservations(ctx, reservations); err != nil {
		return fmt.Errorf("%w: %v", ErrDatabaseSync, err)
	}

	return nil
}

// =============================================================================
// Statistics
// =============================================================================

// GetPortAllocationStats returns port allocation statistics.
func (pa *PortAllocator) GetPortAllocationStats(ctx context.Context) (*PortAllocationStats, error) {
	pa.mu.RLock()
	defer pa.mu.RUnlock()

	totalPorts := uint32(pa.portRangeEnd - pa.portRangeStart + 1)
	staticCount := uint32(len(pa.staticReservations))

	// TODO: Get allocated ports count from Rust via FFI.
	allocatedPorts := uint32(0)

	availablePorts := totalPorts - allocatedPorts - staticCount
	utilization := float64(allocatedPorts+staticCount) / float64(totalPorts) * 100.0

	return &PortAllocationStats{
		TotalPortsInRange:  totalPorts,
		AllocatedPorts:     allocatedPorts,
		StaticReservations: staticCount,
		AvailablePorts:     availablePorts,
		UtilizationPercent: utilization,
	}, nil
}

// =============================================================================
// Validation
// =============================================================================

// validateReservation validates a port reservation.
func (pa *PortAllocator) validateReservation(reservation *PortReservation) error {
	if reservation == nil {
		return ErrInvalidReservation
	}

	// Validate external port (uint16 range is 0-65535).
	if reservation.ExternalPort == 0 {
		return fmt.Errorf("%w: invalid external port", ErrInvalidReservation)
	}

	// Validate internal IP.
	if ip := net.ParseIP(reservation.InternalIP); ip == nil {
		return fmt.Errorf("%w: invalid internal IP", ErrInvalidReservation)
	}

	// Validate internal port (uint16 range is 0-65535).
	if reservation.InternalPort == 0 {
		return fmt.Errorf("%w: invalid internal port", ErrInvalidReservation)
	}

	// Validate protocol.
	switch reservation.Protocol {
	case "TCP", "UDP", "BOTH":
		// Valid.
	default:
		return fmt.Errorf("%w: invalid protocol (must be TCP, UDP, or BOTH)", ErrInvalidReservation)
	}

	return nil
}

// validatePortRange validates a port range.
func validatePortRange(start, end uint16) error {
	if start >= end {
		return fmt.Errorf("%w: start must be less than end", ErrInvalidPortRange)
	}

	rangeSize := end - start + 1
	if rangeSize < 1000 {
		return fmt.Errorf("%w: range must be at least 1000 ports", ErrInvalidPortRange)
	}

	return nil
}

// checkPortConflict checks for port conflicts.
func (pa *PortAllocator) checkPortConflict(reservation *PortReservation) error {
	key := reservationKey(reservation.ExternalPort, reservation.Protocol)

	// Check direct conflict.
	if _, exists := pa.staticReservations[key]; exists {
		return ErrPortAlreadyReserved
	}

	// Check BOTH protocol conflict.
	if reservation.Protocol == "BOTH" {
		tcpKey := reservationKey(reservation.ExternalPort, "TCP")
		udpKey := reservationKey(reservation.ExternalPort, "UDP")
		if _, exists := pa.staticReservations[tcpKey]; exists {
			return ErrPortAlreadyReserved
		}
		if _, exists := pa.staticReservations[udpKey]; exists {
			return ErrPortAlreadyReserved
		}
	} else {
		// Check if BOTH is already reserved.
		bothKey := reservationKey(reservation.ExternalPort, "BOTH")
		if _, exists := pa.staticReservations[bothKey]; exists {
			return ErrPortAlreadyReserved
		}
	}

	// Check reserved ports.
	if pa.reservedPorts[reservation.ExternalPort] {
		return ErrPortAlreadyReserved
	}

	return nil
}

// =============================================================================
// Export/Import
// =============================================================================

// ExportStaticReservations exports reservations to JSON.
func (pa *PortAllocator) ExportStaticReservations(ctx context.Context) ([]byte, error) {
	reservations, err := pa.ListStaticReservations(ctx)
	if err != nil {
		return nil, err
	}

	return json.MarshalIndent(reservations, "", "  ")
}

// ImportStaticReservations imports reservations from JSON.
func (pa *PortAllocator) ImportStaticReservations(ctx context.Context, data []byte) error {
	var reservations []*PortReservation
	if err := json.Unmarshal(data, &reservations); err != nil {
		return fmt.Errorf("failed to parse JSON: %w", err)
	}

	// Validate all reservations first.
	for _, r := range reservations {
		if err := pa.validateReservation(r); err != nil {
			return err
		}
	}

	pa.mu.Lock()
	defer pa.mu.Unlock()

	// Clear existing reservations.
	pa.staticReservations = make(map[string]*PortReservation)

	// Add all reservations.
	for _, r := range reservations {
		key := reservationKey(r.ExternalPort, r.Protocol)
		pa.staticReservations[key] = r

		if r.Protocol == "BOTH" {
			pa.staticReservations[reservationKey(r.ExternalPort, "TCP")] = r
			pa.staticReservations[reservationKey(r.ExternalPort, "UDP")] = r
		}
	}

	// Sync to database.
	if pa.config.EnablePersistence {
		if err := pa.db.SyncStaticReservations(ctx, reservations); err != nil {
			return fmt.Errorf("%w: %v", ErrDatabaseSync, err)
		}
	}

	return nil
}

// =============================================================================
// Cleanup
// =============================================================================

// CleanupDisabledReservations removes disabled reservations.
func (pa *PortAllocator) CleanupDisabledReservations(ctx context.Context) (int, error) {
	pa.mu.Lock()
	defer pa.mu.Unlock()

	var toRemove []string
	for key, reservation := range pa.staticReservations {
		if !reservation.Enabled {
			toRemove = append(toRemove, key)
		}
	}

	for _, key := range toRemove {
		reservation := pa.staticReservations[key]
		delete(pa.staticReservations, key)

		if pa.config.EnablePersistence {
			_ = pa.db.DeleteStaticReservation(ctx, reservation.ExternalPort, reservation.Protocol)
		}
	}

	return len(toRemove), nil
}

// GetConfig returns the current configuration.
func (pa *PortAllocator) GetConfig() *PortAllocatorConfig {
	pa.mu.RLock()
	defer pa.mu.RUnlock()
	return pa.config
}
