// Package pool provides DHCP IP pool management.
// This file implements the central coordinator for all pool operations.
package pool

import (
	"context"
	"errors"
	"fmt"
	"net"
	"sync"
	"time"
)

// ============================================================================
// Pool Manager Data Structures
// ============================================================================

// PoolManager coordinates all DHCP pool operations.
type PoolManager struct {
	mu sync.RWMutex

	pools        map[string]*Pool     // Pools indexed by name
	bySubnet     map[string]*Pool     // Pools indexed by subnet CIDR
	reservations *ReservationRegistry // Global reservation registry

	// Settings
	defaultPoolName     string
	exhaustionThreshold float64

	// State
	running bool
	ctx     context.Context
	cancel  context.CancelFunc
}

// Pool represents a complete DHCP pool configuration.
type Pool struct {
	Name        string     `json:"name"`
	Description string     `json:"description,omitempty"`
	Subnet      *Subnet    `json:"subnet"`
	Ranges      []*IPRange `json:"ranges"`
	Enabled     bool       `json:"enabled"`
	VLANID      uint16     `json:"vlan_id,omitempty"`

	// Network configuration
	Gateway    net.IP   `json:"gateway,omitempty"`
	DNSServers []net.IP `json:"dns_servers,omitempty"`
	DomainName string   `json:"domain_name,omitempty"`
	NTPServers []net.IP `json:"ntp_servers,omitempty"`

	// Lease times
	DefaultLeaseTime time.Duration `json:"default_lease_time"`
	MinLeaseTime     time.Duration `json:"min_lease_time"`
	MaxLeaseTime     time.Duration `json:"max_lease_time"`

	// Timestamps
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
}

// PoolStatistics holds pool utilization metrics.
type PoolStatistics struct {
	TotalIPs         uint32  `json:"total_ips"`
	AllocatedIPs     uint32  `json:"allocated_ips"`
	AvailableIPs     uint32  `json:"available_ips"`
	ReservedIPs      uint32  `json:"reserved_ips"`
	Utilization      float64 `json:"utilization_percent"`
	RangeCount       int     `json:"range_count"`
	ReservationCount int     `json:"reservation_count"`
}

// GlobalStatistics holds aggregated metrics across all pools.
type GlobalStatistics struct {
	TotalPools       int                        `json:"total_pools"`
	EnabledPools     int                        `json:"enabled_pools"`
	TotalIPs         uint32                     `json:"total_ips"`
	AllocatedIPs     uint32                     `json:"allocated_ips"`
	AvailableIPs     uint32                     `json:"available_ips"`
	Utilization      float64                    `json:"overall_utilization"`
	PoolsNearExhaust []string                   `json:"pools_near_exhaustion"`
	ByPool           map[string]*PoolStatistics `json:"by_pool"`
}

// ============================================================================
// Pool Manager Initialization
// ============================================================================

// NewPoolManager creates a new pool manager.
func NewPoolManager() *PoolManager {
	ctx, cancel := context.WithCancel(context.Background())

	return &PoolManager{
		pools:               make(map[string]*Pool),
		bySubnet:            make(map[string]*Pool),
		reservations:        NewReservationRegistry(),
		exhaustionThreshold: 90.0,
		ctx:                 ctx,
		cancel:              cancel,
	}
}

// Start starts background maintenance tasks.
func (m *PoolManager) Start() {
	m.mu.Lock()
	if m.running {
		m.mu.Unlock()
		return
	}
	m.running = true
	m.mu.Unlock()

	// Background tasks
	go m.maintenanceLoop()
}

// Stop stops the pool manager.
func (m *PoolManager) Stop() {
	m.mu.Lock()
	defer m.mu.Unlock()

	if !m.running {
		return
	}
	m.running = false
	m.cancel()
}

// maintenanceLoop runs periodic maintenance.
func (m *PoolManager) maintenanceLoop() {
	ticker := time.NewTicker(5 * time.Minute)
	defer ticker.Stop()

	for {
		select {
		case <-m.ctx.Done():
			return
		case <-ticker.C:
			m.reservations.ProcessExpirations()
		}
	}
}

// ============================================================================
// Pool Registration and Management
// ============================================================================

// AddPool adds a new pool to the manager.
func (m *PoolManager) AddPool(pool *Pool) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if pool == nil {
		return errors.New("pool cannot be nil")
	}

	if pool.Name == "" {
		return errors.New("pool name is required")
	}

	// Check for duplicate name
	if _, exists := m.pools[pool.Name]; exists {
		return fmt.Errorf("pool %s already exists", pool.Name)
	}

	// Check for subnet overlap
	if pool.Subnet != nil {
		subnetKey := pool.Subnet.ToCIDRString()
		if existing, exists := m.bySubnet[subnetKey]; exists {
			return fmt.Errorf("subnet %s already used by pool %s", subnetKey, existing.Name)
		}

		// Check for overlapping subnets
		for _, existing := range m.pools {
			if existing.Subnet != nil && pool.Subnet.Overlaps(existing.Subnet) {
				return fmt.Errorf("subnet overlaps with pool %s", existing.Name)
			}
		}
	}

	// Set defaults
	if pool.DefaultLeaseTime == 0 {
		pool.DefaultLeaseTime = 24 * time.Hour
	}
	if pool.MinLeaseTime == 0 {
		pool.MinLeaseTime = 5 * time.Minute
	}
	if pool.MaxLeaseTime == 0 {
		pool.MaxLeaseTime = 7 * 24 * time.Hour
	}

	pool.CreatedAt = time.Now()
	pool.UpdatedAt = time.Now()

	// Add to indices
	m.pools[pool.Name] = pool
	if pool.Subnet != nil {
		m.bySubnet[pool.Subnet.ToCIDRString()] = pool
	}

	// Set as default if first pool
	if m.defaultPoolName == "" {
		m.defaultPoolName = pool.Name
	}

	return nil
}

// RemovePool removes a pool by name.
func (m *PoolManager) RemovePool(name string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	pool, exists := m.pools[name]
	if !exists {
		return ErrPoolNotFound
	}

	// Remove from indices
	delete(m.pools, name)
	if pool.Subnet != nil {
		delete(m.bySubnet, pool.Subnet.ToCIDRString())
	}

	// Remove pool's reservations
	for _, res := range m.reservations.FindByPool(name) {
		m.reservations.Remove(res.MAC)
	}

	// Update default pool if needed
	if m.defaultPoolName == name {
		m.defaultPoolName = ""
		for n := range m.pools {
			m.defaultPoolName = n
			break
		}
	}

	return nil
}

// GetPool retrieves a pool by name.
func (m *PoolManager) GetPool(name string) (*Pool, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	pool, exists := m.pools[name]
	if !exists {
		return nil, ErrPoolNotFound
	}
	return pool, nil
}

// GetAllPools returns all pools.
func (m *PoolManager) GetAllPools() []*Pool {
	m.mu.RLock()
	defer m.mu.RUnlock()

	pools := make([]*Pool, 0, len(m.pools))
	for _, p := range m.pools {
		pools = append(pools, p)
	}
	return pools
}

// EnablePool activates a pool.
func (m *PoolManager) EnablePool(name string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	pool, exists := m.pools[name]
	if !exists {
		return ErrPoolNotFound
	}
	pool.Enabled = true
	pool.UpdatedAt = time.Now()
	return nil
}

// DisablePool deactivates a pool.
func (m *PoolManager) DisablePool(name string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	pool, exists := m.pools[name]
	if !exists {
		return ErrPoolNotFound
	}
	pool.Enabled = false
	pool.UpdatedAt = time.Now()
	return nil
}

// SetDefaultPool sets the default pool.
func (m *PoolManager) SetDefaultPool(name string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if _, exists := m.pools[name]; !exists {
		return ErrPoolNotFound
	}
	m.defaultPoolName = name
	return nil
}

// ============================================================================
// Pool Selection Logic
// ============================================================================

// SelectPoolByIP finds the pool containing an IP address.
func (m *PoolManager) SelectPoolByIP(ip net.IP) *Pool {
	m.mu.RLock()
	defer m.mu.RUnlock()

	for _, pool := range m.pools {
		if !pool.Enabled {
			continue
		}
		if pool.Subnet != nil && pool.Subnet.ContainsIP(ip) {
			return pool
		}
	}
	return nil
}

// SelectPoolByRelay finds pool based on relay agent (giaddr).
func (m *PoolManager) SelectPoolByRelay(giaddr net.IP) *Pool {
	return m.SelectPoolByIP(giaddr)
}

// SelectPoolByVLAN finds pool by VLAN ID.
func (m *PoolManager) SelectPoolByVLAN(vlanID uint16) *Pool {
	m.mu.RLock()
	defer m.mu.RUnlock()

	for _, pool := range m.pools {
		if pool.Enabled && pool.VLANID == vlanID {
			return pool
		}
	}
	return nil
}

// GetDefaultPool returns the default pool.
func (m *PoolManager) GetDefaultPool() *Pool {
	m.mu.RLock()
	defer m.mu.RUnlock()

	if m.defaultPoolName == "" {
		return nil
	}
	return m.pools[m.defaultPoolName]
}

// ============================================================================
// IP Allocation Coordination
// ============================================================================

// AllocateIP allocates an IP from a pool for a MAC address.
func (m *PoolManager) AllocateIP(poolName string, mac net.HardwareAddr, preferredIP net.IP) (net.IP, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	pool, exists := m.pools[poolName]
	if !exists {
		return nil, ErrPoolNotFound
	}

	if !pool.Enabled {
		return nil, ErrPoolDisabled
	}

	// Check for static reservation first
	if reservedIP := m.reservations.GetReservedIPForMAC(mac); reservedIP != nil {
		m.reservations.ClaimReservation(mac, reservedIP)
		return reservedIP, nil
	}

	// Try preferred IP if provided and available
	if len(preferredIP) > 0 {
		ip := preferredIP.To4()
		if ip != nil {
			for _, r := range pool.Ranges {
				if r.ContainsIP(ip) && !r.IsAllocated(ip) && !m.reservations.IsIPReserved(ip) {
					if err := r.MarkAllocated(ip); err == nil {
						return ip, nil
					}
				}
			}
		}
	}

	// Find next available IP from ranges
	for _, r := range pool.Ranges {
		if !r.Enabled {
			continue
		}

		ip, err := r.ReserveNextIP()
		if err == nil {
			// Verify not reserved for someone else
			if !m.reservations.IsIPReserved(ip) {
				return ip, nil
			}
			// IP was reserved, return it and continue
			r.MarkAvailable(ip)
		}
	}

	return nil, ErrPoolExhausted
}

// ReleaseIP returns an IP to the available pool.
func (m *PoolManager) ReleaseIP(poolName string, ip net.IP) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	pool, exists := m.pools[poolName]
	if !exists {
		return ErrPoolNotFound
	}

	// Don't release reserved IPs
	if m.reservations.IsIPReserved(ip) {
		return nil // Reserved IPs stay marked
	}

	for _, r := range pool.Ranges {
		if r.ContainsIP(ip) {
			return r.MarkAvailable(ip)
		}
	}

	return ErrIPNotInRange
}

// ============================================================================
// Range Management
// ============================================================================

// AddRangeToPool adds an IP range to a pool.
func (m *PoolManager) AddRangeToPool(poolName string, r *IPRange) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	pool, exists := m.pools[poolName]
	if !exists {
		return ErrPoolNotFound
	}

	// Validate range is within subnet
	if pool.Subnet != nil {
		if !pool.Subnet.ContainsIP(r.StartIP) || !pool.Subnet.ContainsIP(r.EndIP) {
			return errors.New("range not within pool subnet")
		}
	}

	// Check for overlap with existing ranges
	for _, existing := range pool.Ranges {
		overlap, _, _ := DetectRangeOverlap(r.StartIP, r.EndIP, existing.StartIP, existing.EndIP)
		if overlap {
			return errors.New("range overlaps with existing range")
		}
	}

	r.Subnet = pool.Subnet
	pool.Ranges = append(pool.Ranges, r)
	pool.UpdatedAt = time.Now()

	return nil
}

// RemoveRangeFromPool removes a range by index.
func (m *PoolManager) RemoveRangeFromPool(poolName string, rangeIndex int) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	pool, exists := m.pools[poolName]
	if !exists {
		return ErrPoolNotFound
	}

	if rangeIndex < 0 || rangeIndex >= len(pool.Ranges) {
		return errors.New("range index out of bounds")
	}

	pool.Ranges = append(pool.Ranges[:rangeIndex], pool.Ranges[rangeIndex+1:]...)
	pool.UpdatedAt = time.Now()

	return nil
}

// ============================================================================
// Reservation Management
// ============================================================================

// AddReservation adds a static reservation.
func (m *PoolManager) AddReservation(poolName string, res *Reservation) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	pool, exists := m.pools[poolName]
	if !exists {
		return ErrPoolNotFound
	}

	// Validate IP is within pool
	ipInPool := false
	for _, r := range pool.Ranges {
		if r.ContainsIP(res.IP) {
			ipInPool = true
			break
		}
	}
	if !ipInPool && pool.Subnet != nil {
		ipInPool = pool.Subnet.ContainsIP(res.IP)
	}
	if !ipInPool {
		return errors.New("reservation IP not within pool")
	}

	res.PoolID = poolName
	if err := m.reservations.Add(res); err != nil {
		return err
	}

	// Mark IP as allocated in range
	for _, r := range pool.Ranges {
		if r.ContainsIP(res.IP) {
			r.AddExclusion(res.IP)
			break
		}
	}

	return nil
}

// RemoveReservation removes a reservation by MAC.
func (m *PoolManager) RemoveReservation(mac net.HardwareAddr) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	res, err := m.reservations.Remove(mac)
	if err != nil {
		return err
	}

	// Remove exclusion from range
	if pool, exists := m.pools[res.PoolID]; exists {
		for _, r := range pool.Ranges {
			if r.ContainsIP(res.IP) {
				r.RemoveExclusion(res.IP)
				break
			}
		}
	}

	return nil
}

// GetReservation gets a reservation by MAC.
func (m *PoolManager) GetReservation(mac net.HardwareAddr) *Reservation {
	return m.reservations.FindByMAC(mac)
}

// GetReservationsForPool returns all reservations for a pool.
func (m *PoolManager) GetReservationsForPool(poolName string) []*Reservation {
	return m.reservations.FindByPool(poolName)
}

// ============================================================================
// Pool Options
// ============================================================================

// SetGateway sets the default gateway for a pool.
func (m *PoolManager) SetGateway(poolName string, gateway net.IP) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	pool, exists := m.pools[poolName]
	if !exists {
		return ErrPoolNotFound
	}

	pool.Gateway = gateway.To4()
	pool.UpdatedAt = time.Now()
	return nil
}

// SetDNSServers sets DNS servers for a pool.
func (m *PoolManager) SetDNSServers(poolName string, servers []net.IP) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	pool, exists := m.pools[poolName]
	if !exists {
		return ErrPoolNotFound
	}

	pool.DNSServers = servers
	pool.UpdatedAt = time.Now()
	return nil
}

// ============================================================================
// Statistics
// ============================================================================

// GetPoolStatistics returns statistics for a specific pool.
func (m *PoolManager) GetPoolStatistics(poolName string) (*PoolStatistics, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	pool, exists := m.pools[poolName]
	if !exists {
		return nil, ErrPoolNotFound
	}

	return m.calculatePoolStats(pool), nil
}

func (m *PoolManager) calculatePoolStats(pool *Pool) *PoolStatistics {
	stats := &PoolStatistics{
		RangeCount:       len(pool.Ranges),
		ReservationCount: len(m.reservations.FindByPool(pool.Name)),
	}

	for _, r := range pool.Ranges {
		rs := r.GetStatistics()
		stats.TotalIPs += rs.TotalIPs
		stats.AllocatedIPs += rs.AllocatedIPs
		stats.AvailableIPs += rs.AvailableIPs
		stats.ReservedIPs += rs.ExcludedIPs
	}

	if stats.TotalIPs > 0 {
		stats.Utilization = float64(stats.AllocatedIPs) / float64(stats.TotalIPs) * 100
	}

	return stats
}

// GetGlobalStatistics returns aggregated statistics.
func (m *PoolManager) GetGlobalStatistics() *GlobalStatistics {
	m.mu.RLock()
	defer m.mu.RUnlock()

	stats := &GlobalStatistics{
		TotalPools:       len(m.pools),
		PoolsNearExhaust: make([]string, 0),
		ByPool:           make(map[string]*PoolStatistics),
	}

	for name, pool := range m.pools {
		if pool.Enabled {
			stats.EnabledPools++
		}

		ps := m.calculatePoolStats(pool)
		stats.ByPool[name] = ps
		stats.TotalIPs += ps.TotalIPs
		stats.AllocatedIPs += ps.AllocatedIPs
		stats.AvailableIPs += ps.AvailableIPs

		if ps.Utilization >= m.exhaustionThreshold {
			stats.PoolsNearExhaust = append(stats.PoolsNearExhaust, name)
		}
	}

	if stats.TotalIPs > 0 {
		stats.Utilization = float64(stats.AllocatedIPs) / float64(stats.TotalIPs) * 100
	}

	return stats
}

// GetPoolsNearExhaustion returns pools exceeding threshold.
func (m *PoolManager) GetPoolsNearExhaustion(threshold float64) []string {
	m.mu.RLock()
	defer m.mu.RUnlock()

	result := make([]string, 0)
	for name, pool := range m.pools {
		ps := m.calculatePoolStats(pool)
		if ps.Utilization >= threshold {
			result = append(result, name)
		}
	}
	return result
}

// ============================================================================
// Errors
// ============================================================================

var (
	// ErrPoolNotFound is returned when pool doesn't exist
	ErrPoolNotFound = errors.New("pool not found")

	// ErrPoolDisabled is returned when pool is disabled
	ErrPoolDisabled = errors.New("pool is disabled")
)
