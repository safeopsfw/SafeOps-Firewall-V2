// Package lease_manager handles DHCP lease lifecycle operations.
// This file implements the core IP address allocation engine.
package lease_manager

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"hash/fnv"
	"net"
	"sync"
	"time"
)

// ============================================================================
// Allocation Algorithm Types
// ============================================================================

// AllocationAlgorithm specifies the IP selection strategy.
type AllocationAlgorithm int

const (
	AlgorithmSequential AllocationAlgorithm = iota
	AlgorithmRandom
	AlgorithmHash
	AlgorithmLRU
	AlgorithmRoundRobin
)

// ============================================================================
// Pool Types (Local definitions for allocator)
// ============================================================================

// AllocPool represents an IP address pool for allocation.
type AllocPool struct {
	Name             string
	SubnetCIDR       string
	Subnet           *net.IPNet
	Ranges           []*AllocRange
	Gateway          net.IP
	DNSServers       []net.IP
	DefaultLeaseTime time.Duration
	Enabled          bool
}

// AllocRange represents an IP range within a pool.
type AllocRange struct {
	StartIP   net.IP
	EndIP     net.IP
	Enabled   bool
	allocated map[string]bool // IP string -> allocated
	mu        sync.RWMutex
}

// AllocRangeStats holds range statistics.
type AllocRangeStats struct {
	TotalIPs     uint32
	AllocatedIPs uint32
	AvailableIPs uint32
}

// ContainsIP checks if IP is within range.
func (r *AllocRange) ContainsIP(ip net.IP) bool {
	ipVal := ipToUint32Alloc(ip)
	startVal := ipToUint32Alloc(r.StartIP)
	endVal := ipToUint32Alloc(r.EndIP)
	return ipVal >= startVal && ipVal <= endVal
}

// IsAllocated checks if IP is allocated.
func (r *AllocRange) IsAllocated(ip net.IP) bool {
	r.mu.RLock()
	defer r.mu.RUnlock()
	if r.allocated == nil {
		return false
	}
	return r.allocated[ip.String()]
}

// MarkAllocated marks an IP as allocated.
func (r *AllocRange) MarkAllocated(ip net.IP) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.allocated == nil {
		r.allocated = make(map[string]bool)
	}
	r.allocated[ip.String()] = true
	return nil
}

// MarkAvailable marks an IP as available.
func (r *AllocRange) MarkAvailable(ip net.IP) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.allocated != nil {
		delete(r.allocated, ip.String())
	}
}

// ReserveNextIP reserves the next available IP.
func (r *AllocRange) ReserveNextIP() (net.IP, error) {
	r.mu.Lock()
	defer r.mu.Unlock()

	if r.allocated == nil {
		r.allocated = make(map[string]bool)
	}

	startVal := ipToUint32Alloc(r.StartIP)
	endVal := ipToUint32Alloc(r.EndIP)

	for i := startVal; i <= endVal; i++ {
		ip := uint32ToIPAlloc(i)
		ipStr := ip.String()
		if !r.allocated[ipStr] {
			r.allocated[ipStr] = true
			return ip, nil
		}
	}

	return nil, ErrRangeExhausted
}

// GetStatistics returns range statistics.
func (r *AllocRange) GetStatistics() AllocRangeStats {
	r.mu.RLock()
	defer r.mu.RUnlock()

	startVal := ipToUint32Alloc(r.StartIP)
	endVal := ipToUint32Alloc(r.EndIP)
	total := endVal - startVal + 1

	allocated := uint32(0)
	if r.allocated != nil {
		allocated = uint32(len(r.allocated))
	}

	return AllocRangeStats{
		TotalIPs:     total,
		AllocatedIPs: allocated,
		AvailableIPs: total - allocated,
	}
}

// ============================================================================
// Pool Manager Interface
// ============================================================================

// PoolManagerInterface defines pool management operations.
type PoolManagerInterface interface {
	GetPool(name string) (*AllocPool, error)
	GetDefaultPool() *AllocPool
	GetAllPools() []*AllocPool
	SelectPoolByRelay(relayIP net.IP) *AllocPool
	SelectPoolByVLAN(vlanID uint16) *AllocPool
	SelectPoolByIP(ip net.IP) *AllocPool
	GetReservation(mac net.HardwareAddr) *Reservation
	ReleaseIP(poolName string, ip net.IP) error
}

// Reservation represents a static IP reservation.
type Reservation struct {
	MAC      net.HardwareAddr
	IP       net.IP
	Hostname string
}

// ============================================================================
// Allocation Request/Response
// ============================================================================

// AllocationRequest contains information for IP allocation.
type AllocationRequest struct {
	MAC          net.HardwareAddr
	RequestedIP  net.IP
	ClientID     string
	Hostname     string
	VendorClass  string
	RelayAgentIP net.IP
	VLANID       uint16
	PoolName     string
}

// AllocationResult contains the allocation outcome.
type AllocationResult struct {
	IP            net.IP
	Pool          *AllocPool
	Gateway       net.IP
	DNSServers    []net.IP
	LeaseTime     time.Duration
	IsReservation bool
	AllocatedAt   time.Time
}

// ============================================================================
// Allocator Configuration
// ============================================================================

// AllocatorConfig holds allocation settings.
type AllocatorConfig struct {
	Algorithm          AllocationAlgorithm
	EnableReservations bool
	PreferSameClient   bool
	AllocationTimeout  time.Duration
	MaxLeasesPerClient int
	EnablePoolOverflow bool
	RetryCount         int
	ConflictCheckMode  string // "sync" or "async"
}

// DefaultAllocatorConfig returns sensible defaults.
func DefaultAllocatorConfig() *AllocatorConfig {
	return &AllocatorConfig{
		Algorithm:          AlgorithmSequential,
		EnableReservations: true,
		PreferSameClient:   true,
		AllocationTimeout:  5 * time.Second,
		MaxLeasesPerClient: 1,
		EnablePoolOverflow: true,
		RetryCount:         3,
		ConflictCheckMode:  "sync",
	}
}

// ============================================================================
// IP Address Allocator
// ============================================================================

// Allocator manages IP address allocation from pools.
type Allocator struct {
	mu     sync.RWMutex
	config *AllocatorConfig

	// Pool management
	poolManager PoolManagerInterface

	// Conflict detection
	conflictDetector *ConflictDetector

	// Recent allocations per client for reuse
	clientHistory map[string]net.IP

	// Round-robin state
	lastAllocated map[string]uint32 // Pool name -> last allocated IP offset

	// Statistics
	stats AllocatorStats
}

// AllocatorStats tracks allocation metrics.
type AllocatorStats struct {
	TotalRequests     int64
	SuccessfulAllocs  int64
	FailedAllocs      int64
	ConflictsDetected int64
	ReservationsUsed  int64
	PoolOverflows     int64
}

// ============================================================================
// Allocator Creation
// ============================================================================

// NewAllocator creates a new IP address allocator.
func NewAllocator(poolMgr PoolManagerInterface, conflictDetector *ConflictDetector, config *AllocatorConfig) *Allocator {
	if config == nil {
		config = DefaultAllocatorConfig()
	}

	return &Allocator{
		config:           config,
		poolManager:      poolMgr,
		conflictDetector: conflictDetector,
		clientHistory:    make(map[string]net.IP),
		lastAllocated:    make(map[string]uint32),
	}
}

// ============================================================================
// Main Allocation Entry Point
// ============================================================================

// Allocate allocates an IP address for a client request.
func (a *Allocator) Allocate(ctx context.Context, req *AllocationRequest) (*AllocationResult, error) {
	ctx, cancel := context.WithTimeout(ctx, a.config.AllocationTimeout)
	defer cancel()

	a.mu.Lock()
	a.stats.TotalRequests++
	a.mu.Unlock()

	// Step 1: Select appropriate pool
	selectedPool := a.selectPool(req)
	if selectedPool == nil {
		a.recordFailure()
		return nil, ErrNoPoolAvailable
	}

	// Step 2: Check for static reservation
	if a.config.EnableReservations && a.poolManager != nil {
		if result := a.checkReservation(ctx, req, selectedPool); result != nil {
			a.recordSuccess()
			a.stats.ReservationsUsed++
			return result, nil
		}
	}

	// Step 3: Try requested IP if provided
	if len(req.RequestedIP) > 0 {
		if result, err := a.tryRequestedIP(ctx, req, selectedPool); err == nil {
			a.recordSuccess()
			return result, nil
		}
	}

	// Step 4: Check for same-client reuse
	if a.config.PreferSameClient {
		if result := a.tryClientReuse(ctx, req, selectedPool); result != nil {
			a.recordSuccess()
			return result, nil
		}
	}

	// Step 5: Allocate from pool using algorithm
	for attempt := 0; attempt < a.config.RetryCount; attempt++ {
		result, err := a.allocateFromPool(ctx, req, selectedPool)
		if err == nil {
			a.recordSuccess()
			return result, nil
		}

		if errors.Is(err, ErrConflictDetected) {
			a.stats.ConflictsDetected++
			continue // Retry with different IP
		}

		// Non-retryable error
		break
	}

	// Step 6: Try overflow to other pools
	if a.config.EnablePoolOverflow && a.poolManager != nil {
		if result := a.tryPoolOverflow(ctx, req, selectedPool.Name); result != nil {
			a.stats.PoolOverflows++
			a.recordSuccess()
			return result, nil
		}
	}

	a.recordFailure()
	return nil, ErrPoolExhausted
}

// ============================================================================
// Pool Selection
// ============================================================================

func (a *Allocator) selectPool(req *AllocationRequest) *AllocPool {
	if a.poolManager == nil {
		return nil
	}

	// Priority 1: Explicit pool name
	if req.PoolName != "" {
		if p, err := a.poolManager.GetPool(req.PoolName); err == nil {
			return p
		}
	}

	// Priority 2: Relay agent IP (giaddr)
	if len(req.RelayAgentIP) > 0 {
		if p := a.poolManager.SelectPoolByRelay(req.RelayAgentIP); p != nil {
			return p
		}
	}

	// Priority 3: VLAN ID
	if req.VLANID > 0 {
		if p := a.poolManager.SelectPoolByVLAN(req.VLANID); p != nil {
			return p
		}
	}

	// Priority 4: Requested IP subnet
	if req.RequestedIP != nil {
		if p := a.poolManager.SelectPoolByIP(req.RequestedIP); p != nil {
			return p
		}
	}

	// Fallback: Default pool
	return a.poolManager.GetDefaultPool()
}

// ============================================================================
// Static Reservation Handling
// ============================================================================

func (a *Allocator) checkReservation(ctx context.Context, req *AllocationRequest, p *AllocPool) *AllocationResult {
	if a.poolManager == nil {
		return nil
	}

	reservedIP := a.poolManager.GetReservation(req.MAC)
	if reservedIP == nil {
		return nil
	}

	// Verify reserved IP is in the selected pool
	if p.Subnet != nil && !p.Subnet.Contains(reservedIP.IP) {
		return nil
	}

	// Check for conflicts (even reserved IPs may have conflicts)
	if a.conflictDetector != nil {
		result, _ := a.conflictDetector.CheckConflict(ctx, reservedIP.IP)
		if result != nil && result.HasConflict {
			// Log conflict but still use reservation
			// The reserved device should win
		}
	}

	return &AllocationResult{
		IP:            reservedIP.IP,
		Pool:          p,
		Gateway:       p.Gateway,
		DNSServers:    p.DNSServers,
		LeaseTime:     p.DefaultLeaseTime,
		IsReservation: true,
		AllocatedAt:   time.Now(),
	}
}

// ============================================================================
// Requested IP Handling
// ============================================================================

func (a *Allocator) tryRequestedIP(ctx context.Context, req *AllocationRequest, p *AllocPool) (*AllocationResult, error) {
	ip := req.RequestedIP.To4()
	if ip == nil {
		return nil, errors.New("invalid IPv4 address")
	}

	// Verify IP is in pool
	inPool := false
	for _, r := range p.Ranges {
		if r.ContainsIP(ip) {
			inPool = true
			break
		}
	}
	if !inPool {
		return nil, ErrIPOutsidePool
	}

	// Check if IP is reserved for someone else
	if a.poolManager != nil && a.poolManager.GetReservation(req.MAC) != nil {
		// Client has a different reservation
		return nil, errors.New("client has different reservation")
	}

	// Check if IP is already allocated
	for _, r := range p.Ranges {
		if r.ContainsIP(ip) && r.IsAllocated(ip) {
			return nil, ErrIPAlreadyAllocated
		}
	}

	// Perform conflict detection
	if a.conflictDetector != nil {
		result, _ := a.conflictDetector.CheckConflict(ctx, ip)
		if result != nil && result.HasConflict {
			return nil, ErrConflictDetected
		}
	}

	// Mark as allocated
	for _, r := range p.Ranges {
		if r.ContainsIP(ip) {
			if err := r.MarkAllocated(ip); err != nil {
				return nil, err
			}
			break
		}
	}

	// Track for client reuse
	a.mu.Lock()
	a.clientHistory[req.MAC.String()] = ip
	a.mu.Unlock()

	return &AllocationResult{
		IP:          ip,
		Pool:        p,
		Gateway:     p.Gateway,
		DNSServers:  p.DNSServers,
		LeaseTime:   p.DefaultLeaseTime,
		AllocatedAt: time.Now(),
	}, nil
}

// ============================================================================
// Client Reuse
// ============================================================================

func (a *Allocator) tryClientReuse(ctx context.Context, req *AllocationRequest, p *AllocPool) *AllocationResult {
	a.mu.RLock()
	previousIP, exists := a.clientHistory[req.MAC.String()]
	a.mu.RUnlock()

	if !exists || previousIP == nil {
		return nil
	}

	// Try to reallocate same IP
	fakeReq := &AllocationRequest{
		MAC:         req.MAC,
		RequestedIP: previousIP,
	}

	result, err := a.tryRequestedIP(ctx, fakeReq, p)
	if err != nil {
		return nil
	}

	return result
}

// ============================================================================
// Pool Allocation with Algorithm
// ============================================================================

func (a *Allocator) allocateFromPool(ctx context.Context, req *AllocationRequest, p *AllocPool) (*AllocationResult, error) {
	var ip net.IP
	var err error

	switch a.config.Algorithm {
	case AlgorithmSequential:
		ip, err = a.allocateSequential(p)
	case AlgorithmRandom:
		ip, err = a.allocateRandom(p)
	case AlgorithmHash:
		ip, err = a.allocateHash(p, req.MAC)
	case AlgorithmLRU:
		ip, err = a.allocateLRU(p)
	case AlgorithmRoundRobin:
		ip, err = a.allocateRoundRobin(p)
	default:
		ip, err = a.allocateSequential(p)
	}

	if err != nil {
		return nil, err
	}

	// Conflict detection
	if a.conflictDetector != nil {
		result, _ := a.conflictDetector.CheckConflict(ctx, ip)
		if result != nil && result.HasConflict {
			// Release the IP back
			for _, r := range p.Ranges {
				if r.ContainsIP(ip) {
					r.MarkAvailable(ip)
					break
				}
			}
			return nil, ErrConflictDetected
		}
	}

	// Track for client reuse
	a.mu.Lock()
	a.clientHistory[req.MAC.String()] = ip
	a.mu.Unlock()

	return &AllocationResult{
		IP:          ip,
		Pool:        p,
		Gateway:     p.Gateway,
		DNSServers:  p.DNSServers,
		LeaseTime:   p.DefaultLeaseTime,
		AllocatedAt: time.Now(),
	}, nil
}

// ============================================================================
// Allocation Algorithms
// ============================================================================

func (a *Allocator) allocateSequential(p *AllocPool) (net.IP, error) {
	for _, r := range p.Ranges {
		if !r.Enabled {
			continue
		}
		ip, err := r.ReserveNextIP()
		if err == nil {
			return ip, nil
		}
	}
	return nil, ErrPoolExhausted
}

func (a *Allocator) allocateRandom(p *AllocPool) (net.IP, error) {
	for _, r := range p.Ranges {
		if !r.Enabled {
			continue
		}

		stats := r.GetStatistics()
		if stats.AvailableIPs == 0 {
			continue
		}

		// Try random selection with limited attempts
		for attempt := 0; attempt < 10; attempt++ {
			offset := randomUint32() % stats.TotalIPs
			ip := uint32ToIPAlloc(ipToUint32Alloc(r.StartIP) + offset)

			if r.ContainsIP(ip) && !r.IsAllocated(ip) {
				if err := r.MarkAllocated(ip); err == nil {
					return ip, nil
				}
			}
		}
	}
	return nil, ErrPoolExhausted
}

func (a *Allocator) allocateHash(p *AllocPool, mac net.HardwareAddr) (net.IP, error) {
	h := fnv.New32a()
	h.Write(mac)
	hash := h.Sum32()

	for _, r := range p.Ranges {
		if !r.Enabled {
			continue
		}

		stats := r.GetStatistics()
		if stats.AvailableIPs == 0 {
			continue
		}

		// Use hash to select starting point, then scan for available
		startOffset := hash % stats.TotalIPs
		for i := uint32(0); i < stats.TotalIPs; i++ {
			offset := (startOffset + i) % stats.TotalIPs
			ip := uint32ToIPAlloc(ipToUint32Alloc(r.StartIP) + offset)

			if r.ContainsIP(ip) && !r.IsAllocated(ip) {
				if err := r.MarkAllocated(ip); err == nil {
					return ip, nil
				}
			}
		}
	}
	return nil, ErrPoolExhausted
}

func (a *Allocator) allocateLRU(p *AllocPool) (net.IP, error) {
	// LRU requires tracking last-used times
	// Default to sequential for now
	return a.allocateSequential(p)
}

func (a *Allocator) allocateRoundRobin(p *AllocPool) (net.IP, error) {
	a.mu.Lock()
	lastOffset := a.lastAllocated[p.Name]
	a.mu.Unlock()

	for _, r := range p.Ranges {
		if !r.Enabled {
			continue
		}

		stats := r.GetStatistics()
		if stats.AvailableIPs == 0 {
			continue
		}

		// Start from last allocated position
		for i := uint32(0); i < stats.TotalIPs; i++ {
			offset := (lastOffset + i + 1) % stats.TotalIPs
			ip := uint32ToIPAlloc(ipToUint32Alloc(r.StartIP) + offset)

			if r.ContainsIP(ip) && !r.IsAllocated(ip) {
				if err := r.MarkAllocated(ip); err == nil {
					a.mu.Lock()
					a.lastAllocated[p.Name] = offset
					a.mu.Unlock()
					return ip, nil
				}
			}
		}
	}
	return nil, ErrPoolExhausted
}

// ============================================================================
// Pool Overflow
// ============================================================================

func (a *Allocator) tryPoolOverflow(ctx context.Context, req *AllocationRequest, excludePool string) *AllocationResult {
	if a.poolManager == nil {
		return nil
	}

	pools := a.poolManager.GetAllPools()

	for _, p := range pools {
		if p.Name == excludePool || !p.Enabled {
			continue
		}

		result, err := a.allocateFromPool(ctx, req, p)
		if err == nil {
			return result
		}
	}

	return nil
}

// ============================================================================
// Release IP
// ============================================================================

// Release returns an IP to the available pool.
func (a *Allocator) Release(poolName string, ip net.IP) error {
	if a.poolManager == nil {
		return errors.New("pool manager not set")
	}
	return a.poolManager.ReleaseIP(poolName, ip)
}

// RemoveClientHistory removes client allocation history.
func (a *Allocator) RemoveClientHistory(mac net.HardwareAddr) {
	a.mu.Lock()
	defer a.mu.Unlock()
	delete(a.clientHistory, mac.String())
}

// ============================================================================
// Statistics
// ============================================================================

func (a *Allocator) recordSuccess() {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.stats.SuccessfulAllocs++
}

func (a *Allocator) recordFailure() {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.stats.FailedAllocs++
}

// GetStats returns allocator statistics.
func (a *Allocator) GetStats() AllocatorStats {
	a.mu.RLock()
	defer a.mu.RUnlock()
	return a.stats
}

// ============================================================================
// Helper Functions
// ============================================================================

func ipToUint32Alloc(ip net.IP) uint32 {
	ip4 := ip.To4()
	if ip4 == nil {
		return 0
	}
	return binary.BigEndian.Uint32(ip4)
}

func uint32ToIPAlloc(val uint32) net.IP {
	ip := make(net.IP, 4)
	binary.BigEndian.PutUint32(ip, val)
	return ip
}

func randomUint32() uint32 {
	var b [4]byte
	rand.Read(b[:])
	return binary.BigEndian.Uint32(b[:])
}

// ============================================================================
// Errors
// ============================================================================

var (
	// ErrNoPoolAvailable is returned when no suitable pool found
	ErrNoPoolAvailable = errors.New("no pool available for allocation")

	// ErrPoolExhausted is returned when pool has no available IPs
	ErrPoolExhausted = errors.New("pool exhausted - no available IP addresses")

	// ErrIPOutsidePool is returned when requested IP not in pool
	ErrIPOutsidePool = errors.New("requested IP is outside pool range")

	// ErrIPAlreadyAllocated is returned when IP is already in use
	ErrIPAlreadyAllocated = errors.New("IP address is already allocated")

	// ErrRangeExhausted is returned when range has no available IPs
	ErrRangeExhausted = errors.New("range exhausted")
)
