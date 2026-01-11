// Package nat provides NAT/NAPT translation functionality for the NIC Management service.
package nat

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"time"
)

// =============================================================================
// Error Types
// =============================================================================

var (
	// ErrMappingNotFound indicates the mapping was not found.
	ErrMappingNotFound = errors.New("mapping not found")
	// ErrMappingExists indicates the mapping already exists.
	ErrMappingExists = errors.New("mapping already exists")
	// ErrDatabaseError indicates a database operation failed.
	ErrDatabaseError = errors.New("database operation failed")
	// ErrSyncFailed indicates sync from Rust failed.
	ErrSyncFailed = errors.New("sync from Rust failed")
)

// =============================================================================
// Mapping Structure
// =============================================================================

// Mapping represents a NAT mapping database model.
type Mapping struct {
	// MappingID is the unique mapping identifier (UUID).
	MappingID string `json:"mapping_id"`
	// InternalIP is the internal (LAN) IP address.
	InternalIP string `json:"internal_ip"`
	// InternalPort is the internal (LAN) port.
	InternalPort int `json:"internal_port"`
	// ExternalIP is the external (WAN) IP address.
	ExternalIP string `json:"external_ip"`
	// ExternalPort is the external (WAN) port.
	ExternalPort int `json:"external_port"`
	// Protocol is the protocol ("TCP", "UDP", "ICMP").
	Protocol string `json:"protocol"`
	// WANInterface is the WAN interface name.
	WANInterface string `json:"wan_interface"`
	// ConnectionID is the associated connection tracking ID.
	ConnectionID string `json:"connection_id,omitempty"`
	// CreatedAt is the mapping creation time.
	CreatedAt time.Time `json:"created_at"`
	// ExpiresAt is the mapping expiration time.
	ExpiresAt time.Time `json:"expires_at"`
	// LastUsed is the last packet timestamp.
	LastUsed time.Time `json:"last_used"`
	// BytesTransferred is the total bytes through mapping.
	BytesTransferred int64 `json:"bytes_transferred"`
	// IsStatic indicates static port forwarding vs dynamic.
	IsStatic bool `json:"is_static"`
}

// =============================================================================
// Mapping Filters
// =============================================================================

// MappingFilters contains query filters for NAT mappings.
type MappingFilters struct {
	// Protocol filters by protocol.
	Protocol string
	// WANInterface filters by WAN interface name.
	WANInterface string
	// InternalIP filters by internal IP address.
	InternalIP string
	// OnlyStatic returns only static mappings.
	OnlyStatic bool
	// OnlyDynamic returns only dynamic mappings.
	OnlyDynamic bool
	// OnlyActive returns only non-expired mappings.
	OnlyActive bool
}

// =============================================================================
// Mapping Statistics
// =============================================================================

// MappingStatistics contains NAT mapping statistics.
type MappingStatistics struct {
	// TotalMappings is the total mappings in database.
	TotalMappings int `json:"total_mappings"`
	// ActiveMappings is the non-expired mappings.
	ActiveMappings int `json:"active_mappings"`
	// ExpiredMappings is the expired mappings pending cleanup.
	ExpiredMappings int `json:"expired_mappings"`
	// TCPMappings is the TCP protocol count.
	TCPMappings int `json:"tcp_mappings"`
	// UDPMappings is the UDP protocol count.
	UDPMappings int `json:"udp_mappings"`
	// ICMPMappings is the ICMP protocol count.
	ICMPMappings int `json:"icmp_mappings"`
	// StaticMappings is the static port forwarding count.
	StaticMappings int `json:"static_mappings"`
	// DynamicMappings is the dynamic NAT count.
	DynamicMappings int `json:"dynamic_mappings"`
	// TotalBytesTransferred is the aggregate bytes.
	TotalBytesTransferred int64 `json:"total_bytes_transferred"`
}

// =============================================================================
// Pagination
// =============================================================================

// Pagination contains pagination parameters.
type Pagination struct {
	// Limit is the maximum rows to return.
	Limit int
	// Offset is the number of rows to skip.
	Offset int
}

// =============================================================================
// Mapping Table Configuration
// =============================================================================

// MappingTableConfig contains configuration for the mapping table.
type MappingTableConfig struct {
	// EnablePersistence enables database persistence.
	EnablePersistence bool `json:"enable_persistence"`
	// SyncInterval is how often to sync from Rust to database.
	SyncInterval time.Duration `json:"sync_interval"`
	// CleanupInterval is how often to cleanup expired mappings.
	CleanupInterval time.Duration `json:"cleanup_interval"`
	// MaxMappings is the maximum mappings to store.
	MaxMappings int `json:"max_mappings"`
	// EnableQueryOptimization creates database indexes.
	EnableQueryOptimization bool `json:"enable_query_optimization"`
}

// DefaultMappingTableConfig returns the default configuration.
func DefaultMappingTableConfig() *MappingTableConfig {
	return &MappingTableConfig{
		EnablePersistence:       true,
		SyncInterval:            10 * time.Second,
		CleanupInterval:         60 * time.Second,
		MaxMappings:             100000,
		EnableQueryOptimization: true,
	}
}

// =============================================================================
// Database Interface
// =============================================================================

// MappingTableDB defines the database interface for mapping table persistence.
type MappingTableDB interface {
	// InsertMapping inserts a mapping into the database.
	InsertMapping(ctx context.Context, mapping *Mapping) error
	// UpdateMapping updates a mapping in the database.
	UpdateMapping(ctx context.Context, mapping *Mapping) error
	// DeleteMapping deletes a mapping from the database.
	DeleteMapping(ctx context.Context, mappingID string) error
	// GetMappingByID retrieves a mapping by ID.
	GetMappingByID(ctx context.Context, mappingID string) (*Mapping, error)
	// ListMappings lists mappings with filters.
	ListMappings(ctx context.Context, filters *MappingFilters, pagination *Pagination) ([]*Mapping, error)
	// CountMappings counts mappings matching filters.
	CountMappings(ctx context.Context, filters *MappingFilters) (int, error)
	// DeleteExpiredMappings deletes expired mappings.
	DeleteExpiredMappings(ctx context.Context) (int, error)
	// DeleteMappingsByInterface deletes mappings for an interface.
	DeleteMappingsByInterface(ctx context.Context, wanInterface string) (int, error)
	// GetStatistics retrieves mapping statistics.
	GetStatistics(ctx context.Context) (*MappingStatistics, error)
	// LoadActiveMappings loads all active mappings.
	LoadActiveMappings(ctx context.Context) ([]*Mapping, error)
	// CreateIndexes creates database indexes.
	CreateIndexes(ctx context.Context) error
}

// =============================================================================
// No-Op Database (for testing/standalone mode)
// =============================================================================

type noOpMappingDB struct {
	mappings map[string]*Mapping
	mu       sync.RWMutex
}

func newNoOpMappingDB() *noOpMappingDB {
	return &noOpMappingDB{
		mappings: make(map[string]*Mapping),
	}
}

func (n *noOpMappingDB) InsertMapping(ctx context.Context, mapping *Mapping) error {
	n.mu.Lock()
	defer n.mu.Unlock()
	n.mappings[mapping.MappingID] = mapping
	return nil
}

func (n *noOpMappingDB) UpdateMapping(ctx context.Context, mapping *Mapping) error {
	n.mu.Lock()
	defer n.mu.Unlock()
	if _, exists := n.mappings[mapping.MappingID]; !exists {
		return ErrMappingNotFound
	}
	n.mappings[mapping.MappingID] = mapping
	return nil
}

func (n *noOpMappingDB) DeleteMapping(ctx context.Context, mappingID string) error {
	n.mu.Lock()
	defer n.mu.Unlock()
	delete(n.mappings, mappingID)
	return nil
}

func (n *noOpMappingDB) GetMappingByID(ctx context.Context, mappingID string) (*Mapping, error) {
	n.mu.RLock()
	defer n.mu.RUnlock()
	m, exists := n.mappings[mappingID]
	if !exists {
		return nil, ErrMappingNotFound
	}
	return m, nil
}

func (n *noOpMappingDB) ListMappings(ctx context.Context, filters *MappingFilters, pagination *Pagination) ([]*Mapping, error) {
	n.mu.RLock()
	defer n.mu.RUnlock()
	result := make([]*Mapping, 0, len(n.mappings))
	for _, m := range n.mappings {
		if n.matchesFilters(m, filters) {
			result = append(result, m)
		}
	}
	return result, nil
}

func (n *noOpMappingDB) matchesFilters(m *Mapping, filters *MappingFilters) bool {
	if filters == nil {
		return true
	}
	if filters.Protocol != "" && m.Protocol != filters.Protocol {
		return false
	}
	if filters.WANInterface != "" && m.WANInterface != filters.WANInterface {
		return false
	}
	if filters.InternalIP != "" && m.InternalIP != filters.InternalIP {
		return false
	}
	if filters.OnlyStatic && !m.IsStatic {
		return false
	}
	if filters.OnlyDynamic && m.IsStatic {
		return false
	}
	if filters.OnlyActive && time.Now().After(m.ExpiresAt) {
		return false
	}
	return true
}

func (n *noOpMappingDB) CountMappings(ctx context.Context, filters *MappingFilters) (int, error) {
	mappings, err := n.ListMappings(ctx, filters, nil)
	if err != nil {
		return 0, err
	}
	return len(mappings), nil
}

func (n *noOpMappingDB) DeleteExpiredMappings(ctx context.Context) (int, error) {
	n.mu.Lock()
	defer n.mu.Unlock()
	now := time.Now()
	count := 0
	for id, m := range n.mappings {
		if !m.IsStatic && now.After(m.ExpiresAt) {
			delete(n.mappings, id)
			count++
		}
	}
	return count, nil
}

func (n *noOpMappingDB) DeleteMappingsByInterface(ctx context.Context, wanInterface string) (int, error) {
	n.mu.Lock()
	defer n.mu.Unlock()
	count := 0
	for id, m := range n.mappings {
		if m.WANInterface == wanInterface {
			delete(n.mappings, id)
			count++
		}
	}
	return count, nil
}

func (n *noOpMappingDB) GetStatistics(ctx context.Context) (*MappingStatistics, error) {
	n.mu.RLock()
	defer n.mu.RUnlock()
	stats := &MappingStatistics{}
	now := time.Now()
	for _, m := range n.mappings {
		stats.TotalMappings++
		stats.TotalBytesTransferred += m.BytesTransferred
		if now.Before(m.ExpiresAt) {
			stats.ActiveMappings++
		} else {
			stats.ExpiredMappings++
		}
		switch m.Protocol {
		case "TCP":
			stats.TCPMappings++
		case "UDP":
			stats.UDPMappings++
		case "ICMP":
			stats.ICMPMappings++
		}
		if m.IsStatic {
			stats.StaticMappings++
		} else {
			stats.DynamicMappings++
		}
	}
	return stats, nil
}

func (n *noOpMappingDB) LoadActiveMappings(ctx context.Context) ([]*Mapping, error) {
	return n.ListMappings(ctx, &MappingFilters{OnlyActive: true}, nil)
}

func (n *noOpMappingDB) CreateIndexes(ctx context.Context) error {
	return nil
}

// =============================================================================
// Mapping Table Manager
// =============================================================================

// MappingTable manages NAT mapping table persistence.
type MappingTable struct {
	// Database client.
	db MappingTableDB
	// Configuration.
	config *MappingTableConfig
	// Sync/cleanup control.
	stopChan  chan struct{}
	wg        sync.WaitGroup
	running   bool
	runningMu sync.Mutex
}

// NewMappingTable creates a new mapping table manager.
func NewMappingTable(db MappingTableDB, config *MappingTableConfig) (*MappingTable, error) {
	if config == nil {
		config = DefaultMappingTableConfig()
	}

	if db == nil {
		db = newNoOpMappingDB()
	}

	return &MappingTable{
		db:       db,
		config:   config,
		stopChan: make(chan struct{}),
	}, nil
}

// =============================================================================
// Lifecycle Management
// =============================================================================

// Start starts background sync and cleanup tasks.
func (mt *MappingTable) Start(ctx context.Context) error {
	mt.runningMu.Lock()
	defer mt.runningMu.Unlock()

	if mt.running {
		return nil
	}

	// Create indexes if enabled.
	if mt.config.EnableQueryOptimization {
		if err := mt.db.CreateIndexes(ctx); err != nil {
			// Log but don't fail - indexes are optimization only.
			_ = err
		}
	}

	// Start sync goroutine.
	mt.wg.Add(1)
	go mt.syncLoop()

	// Start cleanup goroutine.
	mt.wg.Add(1)
	go mt.cleanupLoop()

	mt.running = true
	return nil
}

// Stop stops background tasks.
func (mt *MappingTable) Stop() error {
	mt.runningMu.Lock()
	if !mt.running {
		mt.runningMu.Unlock()
		return nil
	}
	mt.running = false
	mt.runningMu.Unlock()

	// Signal goroutines to stop.
	close(mt.stopChan)

	// Wait for goroutines to exit.
	mt.wg.Wait()

	// Perform final sync.
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	_ = mt.syncMappingsFromRust(ctx)

	return nil
}

// syncLoop runs the periodic sync task.
func (mt *MappingTable) syncLoop() {
	defer mt.wg.Done()

	ticker := time.NewTicker(mt.config.SyncInterval)
	defer ticker.Stop()

	for {
		select {
		case <-mt.stopChan:
			return
		case <-ticker.C:
			ctx, cancel := context.WithTimeout(context.Background(), mt.config.SyncInterval)
			_ = mt.syncMappingsFromRust(ctx)
			cancel()
		}
	}
}

// cleanupLoop runs the periodic cleanup task.
func (mt *MappingTable) cleanupLoop() {
	defer mt.wg.Done()

	ticker := time.NewTicker(mt.config.CleanupInterval)
	defer ticker.Stop()

	for {
		select {
		case <-mt.stopChan:
			return
		case <-ticker.C:
			ctx, cancel := context.WithTimeout(context.Background(), mt.config.CleanupInterval)
			_, _ = mt.cleanupExpiredMappings(ctx)
			cancel()
		}
	}
}

// =============================================================================
// Sync Operations
// =============================================================================

// syncMappingsFromRust syncs mappings from Rust NAT translator to database.
func (mt *MappingTable) syncMappingsFromRust(ctx context.Context) error {
	_ = ctx // Will be used for FFI calls.
	if !mt.config.EnablePersistence {
		return nil
	}

	// TODO: Call Rust FFI rust_get_nat_mappings() to get active mappings.
	// For now, this is a stub that would be implemented with actual FFI calls.
	//
	// mappings := getRustNATMappings()
	// for _, m := range mappings {
	//     goMapping := convertRustMappingToGo(m)
	//     existing, err := mt.db.GetMappingByID(ctx, goMapping.MappingID)
	//     if err == ErrMappingNotFound {
	//         mt.db.InsertMapping(ctx, goMapping)
	//     } else {
	//         mt.db.UpdateMapping(ctx, goMapping)
	//     }
	// }

	return nil
}

// cleanupExpiredMappings removes expired mappings from database.
func (mt *MappingTable) cleanupExpiredMappings(ctx context.Context) (int, error) {
	if !mt.config.EnablePersistence {
		return 0, nil
	}

	return mt.db.DeleteExpiredMappings(ctx)
}

// =============================================================================
// CRUD Operations
// =============================================================================

// InsertMapping adds a new NAT mapping to database.
func (mt *MappingTable) InsertMapping(ctx context.Context, mapping *Mapping) error {
	if mapping == nil {
		return fmt.Errorf("%w: nil mapping", ErrDatabaseError)
	}
	return mt.db.InsertMapping(ctx, mapping)
}

// UpdateMapping updates an existing NAT mapping.
func (mt *MappingTable) UpdateMapping(ctx context.Context, mappingID string, updates *Mapping) error {
	updates.MappingID = mappingID
	return mt.db.UpdateMapping(ctx, updates)
}

// DeleteMapping removes a NAT mapping.
func (mt *MappingTable) DeleteMapping(ctx context.Context, mappingID string) error {
	return mt.db.DeleteMapping(ctx, mappingID)
}

// GetMappingByID retrieves a single mapping by ID.
func (mt *MappingTable) GetMappingByID(ctx context.Context, mappingID string) (*Mapping, error) {
	return mt.db.GetMappingByID(ctx, mappingID)
}

// =============================================================================
// Query Operations
// =============================================================================

// ListMappings queries mappings with filters and pagination.
func (mt *MappingTable) ListMappings(ctx context.Context, filters *MappingFilters, pagination *Pagination) ([]*Mapping, error) {
	return mt.db.ListMappings(ctx, filters, pagination)
}

// CountMappings returns count of mappings matching filters.
func (mt *MappingTable) CountMappings(ctx context.Context, filters *MappingFilters) (int, error) {
	return mt.db.CountMappings(ctx, filters)
}

// GetMappingsByInternalIP retrieves all mappings for a specific internal IP.
func (mt *MappingTable) GetMappingsByInternalIP(ctx context.Context, internalIP string) ([]*Mapping, error) {
	filters := &MappingFilters{
		InternalIP: internalIP,
		OnlyActive: true,
	}
	return mt.db.ListMappings(ctx, filters, nil)
}

// GetMappingByExternalPort retrieves mapping by external endpoint.
func (mt *MappingTable) GetMappingByExternalPort(ctx context.Context, externalIP string, externalPort int, protocol string) (*Mapping, error) {
	filters := &MappingFilters{
		Protocol:   protocol,
		OnlyActive: true,
	}
	mappings, err := mt.db.ListMappings(ctx, filters, nil)
	if err != nil {
		return nil, err
	}

	for _, m := range mappings {
		if m.ExternalIP == externalIP && m.ExternalPort == externalPort {
			return m, nil
		}
	}

	return nil, ErrMappingNotFound
}

// =============================================================================
// Restoration
// =============================================================================

// RestoreMappingsToRust restores mappings from database to Rust NAT translator.
func (mt *MappingTable) RestoreMappingsToRust(ctx context.Context) error {
	if !mt.config.EnablePersistence {
		return nil
	}

	mappings, err := mt.db.LoadActiveMappings(ctx)
	if err != nil {
		return fmt.Errorf("failed to load active mappings: %w", err)
	}

	// TODO: Call Rust FFI to restore each mapping.
	// for _, m := range mappings {
	//     rustMapping := convertGoMappingToRust(m)
	//     rust_restore_nat_mapping(rustMapping)
	// }

	_ = mappings // Placeholder to avoid unused variable.
	return nil
}

// =============================================================================
// Statistics
// =============================================================================

// GetMappingStatistics retrieves NAT mapping statistics.
func (mt *MappingTable) GetMappingStatistics(ctx context.Context) (*MappingStatistics, error) {
	return mt.db.GetStatistics(ctx)
}

// =============================================================================
// Bulk Operations
// =============================================================================

// DeleteExpiredMappings manually triggers cleanup of expired mappings.
func (mt *MappingTable) DeleteExpiredMappings(ctx context.Context) (int, error) {
	return mt.db.DeleteExpiredMappings(ctx)
}

// DeleteMappingsByInterface removes all mappings for a WAN interface.
func (mt *MappingTable) DeleteMappingsByInterface(ctx context.Context, wanInterface string) (int, error) {
	return mt.db.DeleteMappingsByInterface(ctx, wanInterface)
}

// =============================================================================
// Helper Functions
// =============================================================================

// ProtocolNumberToString converts protocol number to string.
func ProtocolNumberToString(protocol uint8) string {
	switch protocol {
	case 6:
		return "TCP"
	case 17:
		return "UDP"
	case 1:
		return "ICMP"
	default:
		return fmt.Sprintf("UNKNOWN(%d)", protocol)
	}
}

// ProtocolStringToNumber converts protocol string to number.
func ProtocolStringToNumber(protocol string) uint8 {
	switch protocol {
	case "TCP":
		return 6
	case "UDP":
		return 17
	case "ICMP":
		return 1
	default:
		return 0
	}
}

// NewMapping creates a new Mapping with default values.
func NewMapping(internalIP string, internalPort int, externalIP string, externalPort int, protocol string) *Mapping {
	now := time.Now()
	return &Mapping{
		MappingID:        fmt.Sprintf("%d-%s-%d", externalPort, protocol, now.UnixNano()),
		InternalIP:       internalIP,
		InternalPort:     internalPort,
		ExternalIP:       externalIP,
		ExternalPort:     externalPort,
		Protocol:         protocol,
		CreatedAt:        now,
		LastUsed:         now,
		ExpiresAt:        now.Add(5 * time.Minute),
		BytesTransferred: 0,
		IsStatic:         false,
	}
}

// GetConfig returns the current configuration.
func (mt *MappingTable) GetConfig() *MappingTableConfig {
	return mt.config
}

// IsRunning returns whether background tasks are running.
func (mt *MappingTable) IsRunning() bool {
	mt.runningMu.Lock()
	defer mt.runningMu.Unlock()
	return mt.running
}
