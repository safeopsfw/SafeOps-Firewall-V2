// Package pool provides DHCP IP pool management.
// This file implements IP address range management with allocation tracking.
package pool

import (
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"math/big"
	"net"
	"sync"
	"time"
)

// ============================================================================
// Range Data Structures
// ============================================================================

// IPRange represents an IP address range with allocation tracking.
type IPRange struct {
	mu sync.RWMutex

	StartIP net.IP  `json:"start_ip"`
	EndIP   net.IP  `json:"end_ip"`
	Subnet  *Subnet `json:"-"`
	Name    string  `json:"name"`
	Enabled bool    `json:"enabled"`

	// Allocation tracking
	bitmap         []byte          // Bit per IP: 0=available, 1=allocated
	totalIPs       uint32          // Total IPs in range
	allocatedCount uint32          // Currently allocated IPs
	exclusions     map[uint32]bool // IPs that cannot be allocated

	// Statistics
	peakUtilization float64
	peakTime        time.Time
	lastAllocation  uint32 // Position of last allocation for sequential
}

// RangeStatistics holds range utilization metrics.
type RangeStatistics struct {
	TotalIPs        uint32    `json:"total_ips"`
	AllocatedIPs    uint32    `json:"allocated_ips"`
	AvailableIPs    uint32    `json:"available_ips"`
	ExcludedIPs     uint32    `json:"excluded_ips"`
	Utilization     float64   `json:"utilization_percent"`
	PeakUtilization float64   `json:"peak_utilization"`
	PeakTime        time.Time `json:"peak_time"`
}

// ============================================================================
// Range Creation Functions
// ============================================================================

// NewIPRange creates a new IP range with allocation tracking.
func NewIPRange(startIP, endIP net.IP, subnet *Subnet) (*IPRange, error) {
	start4 := startIP.To4()
	end4 := endIP.To4()

	if start4 == nil || end4 == nil {
		return nil, errors.New("both start and end must be valid IPv4 addresses")
	}

	startVal := ipToUint32Local(start4)
	endVal := ipToUint32Local(end4)

	if startVal > endVal {
		return nil, fmt.Errorf("start IP %s must be <= end IP %s", startIP, endIP)
	}

	// Validate IPs are within subnet if provided
	if subnet != nil {
		if !subnet.ContainsIP(start4) {
			return nil, fmt.Errorf("start IP %s not within subnet", startIP)
		}
		if !subnet.ContainsIP(end4) {
			return nil, fmt.Errorf("end IP %s not within subnet", endIP)
		}
	}

	totalIPs := endVal - startVal + 1

	r := &IPRange{
		StartIP:    start4,
		EndIP:      end4,
		Subnet:     subnet,
		Enabled:    true,
		totalIPs:   totalIPs,
		exclusions: make(map[uint32]bool),
	}

	// Initialize bitmap
	r.initBitmap()

	return r, nil
}

// NewRangeFromString parses "192.168.1.10-192.168.1.100" format.
func NewRangeFromString(rangeStr string, subnet *Subnet) (*IPRange, error) {
	var startStr, endStr string
	n, err := fmt.Sscanf(rangeStr, "%s-%s", &startStr, &endStr)
	if err != nil || n != 2 {
		return nil, fmt.Errorf("invalid range format: %s", rangeStr)
	}

	startIP := net.ParseIP(startStr)
	endIP := net.ParseIP(endStr)

	if startIP == nil || endIP == nil {
		return nil, fmt.Errorf("invalid IP in range: %s", rangeStr)
	}

	return NewIPRange(startIP, endIP, subnet)
}

// NewRangeFromCIDR creates range covering all usable IPs in CIDR.
func NewRangeFromCIDR(cidr string) (*IPRange, error) {
	subnet, err := NewSubnetFromCIDR(cidr)
	if err != nil {
		return nil, err
	}

	return NewIPRange(subnet.FirstUsable, subnet.LastUsable, subnet)
}

// NewRangeWithExclusions creates range with excluded IPs.
func NewRangeWithExclusions(startIP, endIP net.IP, subnet *Subnet, exclusions []net.IP) (*IPRange, error) {
	r, err := NewIPRange(startIP, endIP, subnet)
	if err != nil {
		return nil, err
	}

	for _, ip := range exclusions {
		r.AddExclusion(ip)
	}

	return r, nil
}

// ============================================================================
// Allocation Bitmap Management
// ============================================================================

// initBitmap creates the allocation bitmap.
func (r *IPRange) initBitmap() {
	// Bits needed = totalIPs, bytes needed = (totalIPs + 7) / 8
	bitmapSize := (r.totalIPs + 7) / 8
	r.bitmap = make([]byte, bitmapSize)
}

// ipToOffset converts IP to offset in range (0-based).
func (r *IPRange) ipToOffset(ip net.IP) (uint32, error) {
	ip4 := ip.To4()
	if ip4 == nil {
		return 0, errors.New("invalid IPv4 address")
	}

	ipVal := ipToUint32Local(ip4)
	startVal := ipToUint32Local(r.StartIP)
	endVal := ipToUint32Local(r.EndIP)

	if ipVal < startVal || ipVal > endVal {
		return 0, errors.New("IP not in range")
	}

	return ipVal - startVal, nil
}

// offsetToIP converts offset back to IP.
func (r *IPRange) offsetToIP(offset uint32) net.IP {
	startVal := ipToUint32Local(r.StartIP)
	return uint32ToIPLocal(startVal + offset)
}

// getBit returns the bit value at offset.
func (r *IPRange) getBit(offset uint32) bool {
	if offset >= r.totalIPs {
		return true // Out of range = allocated
	}
	byteIndex := offset / 8
	bitIndex := offset % 8
	return (r.bitmap[byteIndex] & (1 << bitIndex)) != 0
}

// setBit sets the bit value at offset.
func (r *IPRange) setBit(offset uint32, value bool) {
	if offset >= r.totalIPs {
		return
	}
	byteIndex := offset / 8
	bitIndex := offset % 8
	if value {
		r.bitmap[byteIndex] |= (1 << bitIndex)
	} else {
		r.bitmap[byteIndex] &^= (1 << bitIndex)
	}
}

// MarkAllocated marks an IP as allocated.
func (r *IPRange) MarkAllocated(ip net.IP) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	offset, err := r.ipToOffset(ip)
	if err != nil {
		return err
	}

	if !r.getBit(offset) {
		r.setBit(offset, true)
		r.allocatedCount++
		r.updatePeak()
	}

	return nil
}

// MarkAvailable marks an IP as available.
func (r *IPRange) MarkAvailable(ip net.IP) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	offset, err := r.ipToOffset(ip)
	if err != nil {
		return err
	}

	// Don't mark excluded IPs as available
	if r.exclusions[offset] {
		return errors.New("cannot mark excluded IP as available")
	}

	if r.getBit(offset) {
		r.setBit(offset, false)
		if r.allocatedCount > 0 {
			r.allocatedCount--
		}
	}

	return nil
}

// IsAllocated checks if an IP is allocated.
func (r *IPRange) IsAllocated(ip net.IP) bool {
	r.mu.RLock()
	defer r.mu.RUnlock()

	offset, err := r.ipToOffset(ip)
	if err != nil {
		return true // Error = treat as allocated
	}

	return r.getBit(offset)
}

// ============================================================================
// IP Address Selection Functions
// ============================================================================

// FindNextAvailableIP finds the first available IP sequentially.
func (r *IPRange) FindNextAvailableIP() (net.IP, error) {
	r.mu.Lock()
	defer r.mu.Unlock()

	// Start from last allocation position
	start := r.lastAllocation

	// First pass: from lastAllocation to end
	for i := start; i < r.totalIPs; i++ {
		if !r.getBit(i) && !r.exclusions[i] {
			r.lastAllocation = i
			return r.offsetToIP(i), nil
		}
	}

	// Second pass: from beginning to lastAllocation
	for i := uint32(0); i < start; i++ {
		if !r.getBit(i) && !r.exclusions[i] {
			r.lastAllocation = i
			return r.offsetToIP(i), nil
		}
	}

	return nil, ErrPoolExhausted
}

// FindRandomAvailableIP selects a random available IP.
func (r *IPRange) FindRandomAvailableIP() (net.IP, error) {
	r.mu.Lock()
	defer r.mu.Unlock()

	available := r.getAvailableCountLocked()
	if available == 0 {
		return nil, ErrPoolExhausted
	}

	// Generate random index among available IPs
	nBig, err := rand.Int(rand.Reader, big.NewInt(int64(available)))
	if err != nil {
		// Fallback to sequential
		return r.findNextLocked()
	}

	targetIndex := uint32(nBig.Int64())

	// Find the nth available IP
	count := uint32(0)
	for i := uint32(0); i < r.totalIPs; i++ {
		if !r.getBit(i) && !r.exclusions[i] {
			if count == targetIndex {
				return r.offsetToIP(i), nil
			}
			count++
		}
	}

	return nil, ErrPoolExhausted
}

// findNextLocked finds next available (must hold lock).
func (r *IPRange) findNextLocked() (net.IP, error) {
	for i := uint32(0); i < r.totalIPs; i++ {
		if !r.getBit(i) && !r.exclusions[i] {
			return r.offsetToIP(i), nil
		}
	}
	return nil, ErrPoolExhausted
}

// FindAvailableIPNear finds an available IP near the preferred address.
func (r *IPRange) FindAvailableIPNear(preferredIP net.IP) (net.IP, error) {
	r.mu.Lock()
	defer r.mu.Unlock()

	offset, err := r.ipToOffset(preferredIP)
	if err != nil {
		return r.findNextLocked()
	}

	// Check preferred first
	if !r.getBit(offset) && !r.exclusions[offset] {
		return preferredIP, nil
	}

	// Search nearby (expanding radius)
	for radius := uint32(1); radius < r.totalIPs; radius++ {
		// Check below
		if offset >= radius {
			below := offset - radius
			if !r.getBit(below) && !r.exclusions[below] {
				return r.offsetToIP(below), nil
			}
		}

		// Check above
		above := offset + radius
		if above < r.totalIPs {
			if !r.getBit(above) && !r.exclusions[above] {
				return r.offsetToIP(above), nil
			}
		}
	}

	return nil, ErrPoolExhausted
}

// ReserveNextIP atomically finds and marks next available IP.
func (r *IPRange) ReserveNextIP() (net.IP, error) {
	r.mu.Lock()
	defer r.mu.Unlock()

	for i := r.lastAllocation; i < r.totalIPs; i++ {
		if !r.getBit(i) && !r.exclusions[i] {
			r.setBit(i, true)
			r.allocatedCount++
			r.lastAllocation = i
			r.updatePeak()
			return r.offsetToIP(i), nil
		}
	}

	for i := uint32(0); i < r.lastAllocation; i++ {
		if !r.getBit(i) && !r.exclusions[i] {
			r.setBit(i, true)
			r.allocatedCount++
			r.lastAllocation = i
			r.updatePeak()
			return r.offsetToIP(i), nil
		}
	}

	return nil, ErrPoolExhausted
}

// ============================================================================
// Range Utilization Tracking
// ============================================================================

// GetStatistics returns current range statistics.
func (r *IPRange) GetStatistics() RangeStatistics {
	r.mu.RLock()
	defer r.mu.RUnlock()

	excluded := uint32(len(r.exclusions))
	available := r.totalIPs - r.allocatedCount - excluded

	utilization := float64(0)
	if r.totalIPs > excluded {
		utilization = float64(r.allocatedCount) / float64(r.totalIPs-excluded) * 100
	}

	return RangeStatistics{
		TotalIPs:        r.totalIPs,
		AllocatedIPs:    r.allocatedCount,
		AvailableIPs:    available,
		ExcludedIPs:     excluded,
		Utilization:     utilization,
		PeakUtilization: r.peakUtilization,
		PeakTime:        r.peakTime,
	}
}

// GetUtilizationPercent returns current utilization percentage.
func (r *IPRange) GetUtilizationPercent() float64 {
	return r.GetStatistics().Utilization
}

// IsNearlyExhausted checks if utilization exceeds threshold.
func (r *IPRange) IsNearlyExhausted(threshold float64) bool {
	return r.GetUtilizationPercent() >= threshold
}

// GetAvailableCount returns number of available IPs.
func (r *IPRange) GetAvailableCount() uint32 {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.getAvailableCountLocked()
}

func (r *IPRange) getAvailableCountLocked() uint32 {
	excluded := uint32(len(r.exclusions))
	return r.totalIPs - r.allocatedCount - excluded
}

// GetAllocatedCount returns number of allocated IPs.
func (r *IPRange) GetAllocatedCount() uint32 {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.allocatedCount
}

// GetTotalCount returns total IPs in range.
func (r *IPRange) GetTotalCount() uint32 {
	return r.totalIPs
}

func (r *IPRange) updatePeak() {
	utilization := float64(r.allocatedCount) / float64(r.totalIPs) * 100
	if utilization > r.peakUtilization {
		r.peakUtilization = utilization
		r.peakTime = time.Now()
	}
}

// ============================================================================
// Exclusion Management
// ============================================================================

// AddExclusion adds an IP to the exclusion list.
func (r *IPRange) AddExclusion(ip net.IP) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	offset, err := r.ipToOffset(ip)
	if err != nil {
		return err
	}

	r.exclusions[offset] = true
	r.setBit(offset, true) // Mark as allocated in bitmap
	return nil
}

// RemoveExclusion removes an IP from the exclusion list.
func (r *IPRange) RemoveExclusion(ip net.IP) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	offset, err := r.ipToOffset(ip)
	if err != nil {
		return err
	}

	delete(r.exclusions, offset)
	r.setBit(offset, false) // Mark as available
	return nil
}

// IsExcluded checks if an IP is excluded.
func (r *IPRange) IsExcluded(ip net.IP) bool {
	r.mu.RLock()
	defer r.mu.RUnlock()

	offset, err := r.ipToOffset(ip)
	if err != nil {
		return false
	}

	return r.exclusions[offset]
}

// GetExclusionList returns all excluded IPs.
func (r *IPRange) GetExclusionList() []net.IP {
	r.mu.RLock()
	defer r.mu.RUnlock()

	ips := make([]net.IP, 0, len(r.exclusions))
	for offset := range r.exclusions {
		ips = append(ips, r.offsetToIP(offset))
	}
	return ips
}

// ============================================================================
// Range Validation
// ============================================================================

// ContainsIP checks if IP is within this range.
func (r *IPRange) ContainsIP(ip net.IP) bool {
	_, err := r.ipToOffset(ip)
	return err == nil
}

// GetIPAtOffset returns IP at specific offset from range start.
func (r *IPRange) GetIPAtOffset(offset uint32) (net.IP, error) {
	if offset >= r.totalIPs {
		return nil, errors.New("offset out of range")
	}
	return r.offsetToIP(offset), nil
}

// ============================================================================
// Bitmap Serialization
// ============================================================================

// SerializeBitmap returns the bitmap as bytes for storage.
func (r *IPRange) SerializeBitmap() []byte {
	r.mu.RLock()
	defer r.mu.RUnlock()

	result := make([]byte, len(r.bitmap))
	copy(result, r.bitmap)
	return result
}

// DeserializeBitmap restores bitmap from bytes.
func (r *IPRange) DeserializeBitmap(data []byte) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	expectedSize := (r.totalIPs + 7) / 8
	if uint32(len(data)) != expectedSize {
		return fmt.Errorf("bitmap size mismatch: expected %d, got %d", expectedSize, len(data))
	}

	r.bitmap = make([]byte, len(data))
	copy(r.bitmap, data)

	// Recalculate allocation count
	r.allocatedCount = 0
	for i := uint32(0); i < r.totalIPs; i++ {
		if r.getBit(i) {
			r.allocatedCount++
		}
	}

	return nil
}

// ============================================================================
// String Representation
// ============================================================================

// String returns range as "start-end" format.
func (r *IPRange) String() string {
	return fmt.Sprintf("%s-%s", r.StartIP, r.EndIP)
}

// ============================================================================
// Helper Functions
// ============================================================================

func ipToUint32Local(ip net.IP) uint32 {
	if ip == nil {
		return 0
	}
	ip4 := ip.To4()
	if ip4 == nil {
		return 0
	}
	return binary.BigEndian.Uint32(ip4)
}

func uint32ToIPLocal(val uint32) net.IP {
	ip := make(net.IP, 4)
	binary.BigEndian.PutUint32(ip, val)
	return ip
}

// ============================================================================
// Errors
// ============================================================================

var (
	// ErrPoolExhausted is returned when no IPs are available
	ErrPoolExhausted = errors.New("pool exhausted: no available IP addresses")

	// ErrIPNotInRange is returned when IP is outside range
	ErrIPNotInRange = errors.New("IP address not in range")

	// ErrIPExcluded is returned when trying to allocate excluded IP
	ErrIPExcluded = errors.New("IP address is excluded from allocation")
)
