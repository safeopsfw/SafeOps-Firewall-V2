// Package models defines core DHCP data structures.
// This file implements the Pool structure for IP address pool configuration.
package models

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"time"
)

// ============================================================================
// Default Lease Time Constants
// ============================================================================

const (
	DefaultPoolLeaseTime = 24 * time.Hour
	MinPoolLeaseTime     = 1 * time.Hour
	MaxPoolLeaseTime     = 7 * 24 * time.Hour
)

// ============================================================================
// Pool Structure
// ============================================================================

// Pool represents an IP address pool configuration for a network segment.
// Each pool defines a subnet, assignable IP range, and DHCP options.
type Pool struct {
	// Identification
	PoolID      string `json:"pool_id" db:"pool_id"`
	Name        string `json:"name" db:"name"`
	Description string `json:"description" db:"-"`

	// Network Configuration
	Subnet     *net.IPNet `json:"subnet" db:"subnet"`
	RangeStart net.IP     `json:"range_start" db:"range_start"`
	RangeEnd   net.IP     `json:"range_end" db:"range_end"`
	Gateway    net.IP     `json:"gateway" db:"gateway"`

	// Lease Settings
	LeaseTime     time.Duration `json:"lease_time" db:"lease_time"`
	MinLeaseTime  time.Duration `json:"min_lease_time" db:"-"`
	MaxLeaseTime  time.Duration `json:"max_lease_time" db:"-"`
	RenewalTime   time.Duration `json:"renewal_time" db:"-"`   // T1
	RebindingTime time.Duration `json:"rebinding_time" db:"-"` // T2

	// Network Services
	DNSServers []net.IP `json:"dns_servers" db:"dns_servers"`
	NTPServers []net.IP `json:"ntp_servers" db:"ntp_servers"`
	DomainName string   `json:"domain_name" db:"domain_name"`

	// Operational Settings
	Interface            string `json:"interface" db:"interface"`
	Enabled              bool   `json:"enabled" db:"enabled"`
	ConflictCheckEnabled bool   `json:"conflict_check_enabled" db:"-"`

	// Statistics (runtime, not persisted)
	TotalIPs     uint32 `json:"total_ips" db:"-"`
	AllocatedIPs uint32 `json:"allocated_ips" db:"-"`
	ReservedIPs  uint32 `json:"reserved_ips" db:"-"`

	// Metadata
	CreatedAt time.Time `json:"created_at" db:"created_at"`
	UpdatedAt time.Time `json:"updated_at" db:"updated_at"`
}

// ============================================================================
// Pool Constructor Functions
// ============================================================================

// NewPool creates a new pool with the specified subnet and range.
// Returns error if the range is invalid or not within subnet.
func NewPool(poolID, name string, subnet *net.IPNet, rangeStart, rangeEnd net.IP) (*Pool, error) {
	pool := &Pool{
		PoolID:               poolID,
		Name:                 name,
		Subnet:               subnet,
		RangeStart:           rangeStart.To4(),
		RangeEnd:             rangeEnd.To4(),
		LeaseTime:            DefaultPoolLeaseTime,
		MinLeaseTime:         MinPoolLeaseTime,
		MaxLeaseTime:         MaxPoolLeaseTime,
		Enabled:              true,
		ConflictCheckEnabled: true,
		CreatedAt:            time.Now(),
		UpdatedAt:            time.Now(),
	}

	// Calculate T1 and T2
	pool.RenewalTime = time.Duration(float64(pool.LeaseTime) * 0.5)
	pool.RebindingTime = time.Duration(float64(pool.LeaseTime) * 0.875)

	// Calculate total IPs
	pool.TotalIPs = pool.CalculateTotalIPs()

	// Validate
	if err := pool.Validate(); err != nil {
		return nil, err
	}

	return pool, nil
}

// NewPoolFromCIDR creates a pool by parsing a CIDR string.
func NewPoolFromCIDR(poolID, name, cidr string, rangeStart, rangeEnd string) (*Pool, error) {
	_, subnet, err := net.ParseCIDR(cidr)
	if err != nil {
		return nil, fmt.Errorf("invalid CIDR: %w", err)
	}

	start := net.ParseIP(rangeStart)
	if start == nil {
		return nil, fmt.Errorf("invalid range start IP: %s", rangeStart)
	}

	end := net.ParseIP(rangeEnd)
	if end == nil {
		return nil, fmt.Errorf("invalid range end IP: %s", rangeEnd)
	}

	return NewPool(poolID, name, subnet, start, end)
}

// ============================================================================
// Subnet Calculation Methods
// ============================================================================

// NetworkAddress returns the network address (first IP in CIDR).
func (p *Pool) NetworkAddress() net.IP {
	if p.Subnet == nil {
		return nil
	}
	return p.Subnet.IP.Mask(p.Subnet.Mask)
}

// BroadcastAddress returns the broadcast address (last IP in CIDR).
func (p *Pool) BroadcastAddress() net.IP {
	if p.Subnet == nil {
		return nil
	}

	ip := p.Subnet.IP.To4()
	mask := p.Subnet.Mask

	broadcast := make(net.IP, 4)
	for i := 0; i < 4; i++ {
		broadcast[i] = ip[i] | ^mask[i]
	}
	return broadcast
}

// SubnetMask returns the subnet mask.
func (p *Pool) SubnetMask() net.IPMask {
	if p.Subnet == nil {
		return nil
	}
	return p.Subnet.Mask
}

// SubnetMaskIP returns the subnet mask as an IP address.
func (p *Pool) SubnetMaskIP() net.IP {
	mask := p.SubnetMask()
	if mask == nil {
		return nil
	}
	return net.IP(mask)
}

// CalculateTotalIPs returns the number of IPs between RangeStart and RangeEnd.
func (p *Pool) CalculateTotalIPs() uint32 {
	if p.RangeStart == nil || p.RangeEnd == nil {
		return 0
	}

	start := ipToUint32(p.RangeStart.To4())
	end := ipToUint32(p.RangeEnd.To4())

	if end < start {
		return 0
	}

	return end - start + 1
}

// ============================================================================
// IP Range Validation Methods
// ============================================================================

// Validate checks pool configuration integrity.
// Returns nil if valid, error describing violation.
func (p *Pool) Validate() error {
	if p.PoolID == "" {
		return errors.New("PoolID is required")
	}

	if p.Subnet == nil {
		return errors.New("Subnet is required")
	}

	if p.RangeStart == nil {
		return errors.New("RangeStart is required")
	}

	if p.RangeEnd == nil {
		return errors.New("RangeEnd is required")
	}

	// Check RangeStart is within Subnet
	if !p.Subnet.Contains(p.RangeStart) {
		return fmt.Errorf("RangeStart %s is not within Subnet %s", p.RangeStart, p.Subnet)
	}

	// Check RangeEnd is within Subnet
	if !p.Subnet.Contains(p.RangeEnd) {
		return fmt.Errorf("RangeEnd %s is not within Subnet %s", p.RangeEnd, p.Subnet)
	}

	// Check RangeStart <= RangeEnd
	start := ipToUint32(p.RangeStart.To4())
	end := ipToUint32(p.RangeEnd.To4())
	if start > end {
		return fmt.Errorf("RangeStart %s must be <= RangeEnd %s", p.RangeStart, p.RangeEnd)
	}

	// Check Gateway is within Subnet (if set)
	if p.Gateway != nil && !p.Gateway.IsUnspecified() {
		if !p.Subnet.Contains(p.Gateway) {
			return fmt.Errorf("Gateway %s is not within Subnet %s", p.Gateway, p.Subnet)
		}

		// Gateway should not be in assignable range
		if p.Contains(p.Gateway) {
			return fmt.Errorf("Gateway %s should not be in assignable range", p.Gateway)
		}
	}

	// Check lease time constraints
	if p.LeaseTime < p.MinLeaseTime {
		return fmt.Errorf("LeaseTime %v must be >= MinLeaseTime %v", p.LeaseTime, p.MinLeaseTime)
	}

	if p.LeaseTime > p.MaxLeaseTime {
		return fmt.Errorf("LeaseTime %v must be <= MaxLeaseTime %v", p.LeaseTime, p.MaxLeaseTime)
	}

	return nil
}

// Contains returns true if IP is within RangeStart to RangeEnd (inclusive).
func (p *Pool) Contains(ip net.IP) bool {
	if ip == nil || p.RangeStart == nil || p.RangeEnd == nil {
		return false
	}

	ip4 := ip.To4()
	if ip4 == nil {
		return false
	}

	ipVal := ipToUint32(ip4)
	start := ipToUint32(p.RangeStart.To4())
	end := ipToUint32(p.RangeEnd.To4())

	return ipVal >= start && ipVal <= end
}

// IsInSubnet returns true if IP is within the Subnet CIDR.
func (p *Pool) IsInSubnet(ip net.IP) bool {
	if p.Subnet == nil || ip == nil {
		return false
	}
	return p.Subnet.Contains(ip)
}

// IsReservedIP returns true if IP is network address, broadcast, gateway, or DNS server.
// These IPs cannot be assigned to clients.
func (p *Pool) IsReservedIP(ip net.IP) bool {
	if ip == nil {
		return true
	}

	ip4 := ip.To4()
	if ip4 == nil {
		return true
	}

	// Network address
	if ip4.Equal(p.NetworkAddress()) {
		return true
	}

	// Broadcast address
	if ip4.Equal(p.BroadcastAddress()) {
		return true
	}

	// Gateway
	if p.Gateway != nil && ip4.Equal(p.Gateway.To4()) {
		return true
	}

	// DNS servers
	for _, dns := range p.DNSServers {
		if dns != nil && ip4.Equal(dns.To4()) {
			return true
		}
	}

	return false
}

// ============================================================================
// IP Iterator Methods
// ============================================================================

// NextIP returns the IP address incremented by 1.
func NextIP(ip net.IP) net.IP {
	ip4 := ip.To4()
	if ip4 == nil {
		return nil
	}

	val := ipToUint32(ip4)
	val++
	return uint32ToIP(val)
}

// PrevIP returns the IP address decremented by 1.
func PrevIP(ip net.IP) net.IP {
	ip4 := ip.To4()
	if ip4 == nil {
		return nil
	}

	val := ipToUint32(ip4)
	if val == 0 {
		return nil
	}
	val--
	return uint32ToIP(val)
}

// GetIPRange returns a channel that yields all assignable IPs in range.
// Excludes reserved IPs (network, broadcast, gateway, DNS).
func (p *Pool) GetIPRange() <-chan net.IP {
	ch := make(chan net.IP)

	go func() {
		defer close(ch)

		start := ipToUint32(p.RangeStart.To4())
		end := ipToUint32(p.RangeEnd.To4())

		for i := start; i <= end; i++ {
			ip := uint32ToIP(i)
			if !p.IsReservedIP(ip) {
				ch <- ip
			}
		}
	}()

	return ch
}

// GetIPList returns a slice of all assignable IPs in range.
// Excludes reserved IPs (network, broadcast, gateway, DNS).
func (p *Pool) GetIPList() []net.IP {
	var ips []net.IP

	start := ipToUint32(p.RangeStart.To4())
	end := ipToUint32(p.RangeEnd.To4())

	for i := start; i <= end; i++ {
		ip := uint32ToIP(i)
		if !p.IsReservedIP(ip) {
			ips = append(ips, ip)
		}
	}

	return ips
}

// ============================================================================
// Utilization Calculation Methods
// ============================================================================

// UtilizationPercent returns the pool usage percentage (0.0 to 100.0).
func (p *Pool) UtilizationPercent() float64 {
	if p.TotalIPs == 0 {
		return 0.0
	}
	return float64(p.AllocatedIPs) / float64(p.TotalIPs) * 100.0
}

// AvailableIPs returns the number of unallocated IPs.
func (p *Pool) AvailableIPs() uint32 {
	used := p.AllocatedIPs + p.ReservedIPs
	if used >= p.TotalIPs {
		return 0
	}
	return p.TotalIPs - used
}

// IsExhausted returns true if no more IPs are available.
func (p *Pool) IsExhausted() bool {
	return p.AvailableIPs() == 0
}

// NeedsExpansion returns true if utilization exceeds the threshold.
// threshold should be between 0.0 and 1.0 (e.g., 0.85 for 85%)
func (p *Pool) NeedsExpansion(threshold float64) bool {
	return p.UtilizationPercent() > threshold*100.0
}

// ============================================================================
// String Representation
// ============================================================================

// String returns a human-readable pool description.
func (p *Pool) String() string {
	subnet := "nil"
	if p.Subnet != nil {
		subnet = p.Subnet.String()
	}

	enabled := "disabled"
	if p.Enabled {
		enabled = "enabled"
	}

	return fmt.Sprintf("Pool[Name=%s Subnet=%s Range=%s-%s Utilization=%.1f%% %s]",
		p.Name,
		subnet,
		p.RangeStart,
		p.RangeEnd,
		p.UtilizationPercent(),
		enabled,
	)
}

// ShortString returns a brief pool description.
func (p *Pool) ShortString() string {
	return fmt.Sprintf("%s (%s)", p.Name, p.PoolID)
}

// ============================================================================
// Helper Functions
// ============================================================================

// ipToUint32 converts an IPv4 address to uint32.
func ipToUint32(ip net.IP) uint32 {
	if ip == nil {
		return 0
	}
	ip4 := ip.To4()
	if ip4 == nil {
		return 0
	}
	return binary.BigEndian.Uint32(ip4)
}

// uint32ToIP converts a uint32 to IPv4 address.
func uint32ToIP(val uint32) net.IP {
	ip := make(net.IP, 4)
	binary.BigEndian.PutUint32(ip, val)
	return ip
}
