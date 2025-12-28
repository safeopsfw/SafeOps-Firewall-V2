// Package types provides NAT (Network Address Translation) and NAPT (Network
// Address Port Translation) type definitions including mapping structures,
// port allocation tracking, session lifecycle management, and configuration.
// These types are critical for sharing WAN IP addresses across multiple LAN clients.
package types

import (
	"fmt"
	"time"
)

// =============================================================================
// NAT Mapping Types
// =============================================================================

// NATMappingType represents the type of NAT mapping.
type NATMappingType string

const (
	// NATMappingTypeDynamic is an automatically created mapping.
	NATMappingTypeDynamic NATMappingType = "DYNAMIC"
	// NATMappingTypeStatic is a manually configured port forward.
	NATMappingTypeStatic NATMappingType = "STATIC"
	// NATMappingTypeSymmetric is a symmetric NAT mapping.
	NATMappingTypeSymmetric NATMappingType = "SYMMETRIC"
	// NATMappingTypeFullCone is a full cone NAT mapping.
	NATMappingTypeFullCone NATMappingType = "FULL_CONE"
)

// NATMapping represents a single NAT translation entry (internal ↔ external).
type NATMapping struct {
	// Identity
	MappingID string `json:"mapping_id" yaml:"mapping_id" db:"mapping_id"`

	// Internal (LAN) address
	InternalIP   string `json:"internal_ip" yaml:"internal_ip" db:"internal_ip"`
	InternalPort int    `json:"internal_port" yaml:"internal_port" db:"internal_port"`

	// External (WAN) address
	ExternalIP   string `json:"external_ip" yaml:"external_ip" db:"external_ip"`
	ExternalPort int    `json:"external_port" yaml:"external_port" db:"external_port"`

	// Protocol
	Protocol Protocol `json:"protocol" yaml:"protocol" db:"protocol"`

	// Interface binding
	WANInterfaceID    string `json:"wan_interface_id,omitempty" yaml:"wan_interface_id,omitempty" db:"wan_interface_id"`
	WANInterfaceName  string `json:"wan_interface" yaml:"wan_interface" db:"wan_interface_name"`
	WANInterfaceAlias string `json:"wan_interface_alias,omitempty" yaml:"wan_interface_alias,omitempty"`

	// Connection tracking reference
	ConnectionID string `json:"connection_id,omitempty" yaml:"connection_id,omitempty" db:"connection_id"`

	// Type and flags
	MappingType NATMappingType `json:"mapping_type,omitempty" yaml:"mapping_type,omitempty"`
	IsStatic    bool           `json:"is_static" yaml:"is_static" db:"is_static"`

	// Traffic counters
	BytesSent       uint64 `json:"bytes_sent" yaml:"bytes_sent" db:"bytes_sent"`
	BytesReceived   uint64 `json:"bytes_received" yaml:"bytes_received" db:"bytes_received"`
	PacketsSent     uint64 `json:"packets_sent" yaml:"packets_sent" db:"packets_sent"`
	PacketsReceived uint64 `json:"packets_received" yaml:"packets_received" db:"packets_received"`

	// Timestamps
	CreatedAt time.Time `json:"created_at" yaml:"created_at" db:"created_at"`
	ExpiresAt time.Time `json:"expires_at" yaml:"expires_at" db:"expires_at"`
	LastUsed  time.Time `json:"last_used" yaml:"last_used" db:"last_used"`

	// Metadata
	Description string `json:"description,omitempty" yaml:"description,omitempty" db:"description"`
}

// InternalAddress returns the formatted internal address:port.
func (m *NATMapping) InternalAddress() string {
	return fmt.Sprintf("%s:%d", m.InternalIP, m.InternalPort)
}

// ExternalAddress returns the formatted external address:port.
func (m *NATMapping) ExternalAddress() string {
	return fmt.Sprintf("%s:%d", m.ExternalIP, m.ExternalPort)
}

// Key returns a unique key for this mapping (external side).
func (m *NATMapping) Key() string {
	return fmt.Sprintf("%s:%d/%s", m.ExternalIP, m.ExternalPort, m.Protocol)
}

// ReverseKey returns a unique key for reverse lookup (internal side).
func (m *NATMapping) ReverseKey() string {
	return fmt.Sprintf("%s:%d/%s", m.InternalIP, m.InternalPort, m.Protocol)
}

// IsExpired returns true if the mapping has expired.
func (m *NATMapping) IsExpired() bool {
	if m.IsStatic {
		return false // Static mappings never expire
	}
	return time.Now().After(m.ExpiresAt)
}

// TotalBytes returns total bytes transferred through this mapping.
func (m *NATMapping) TotalBytes() uint64 {
	return m.BytesSent + m.BytesReceived
}

// TotalPackets returns total packets transferred through this mapping.
func (m *NATMapping) TotalPackets() uint64 {
	return m.PacketsSent + m.PacketsReceived
}

// Lifetime returns how long this mapping has existed.
func (m *NATMapping) Lifetime() time.Duration {
	return time.Since(m.CreatedAt)
}

// IdleTime returns time since last use.
func (m *NATMapping) IdleTime() time.Duration {
	return time.Since(m.LastUsed)
}

// Touch updates the last used timestamp and optionally extends expiration.
func (m *NATMapping) Touch(extendBy time.Duration) {
	m.LastUsed = time.Now()
	if !m.IsStatic && extendBy > 0 {
		m.ExpiresAt = m.LastUsed.Add(extendBy)
	}
}

// UpdateCounters updates traffic counters.
func (m *NATMapping) UpdateCounters(bytesSent, bytesRecv uint64, packetsSent, packetsRecv uint64) {
	m.BytesSent += bytesSent
	m.BytesReceived += bytesRecv
	m.PacketsSent += packetsSent
	m.PacketsReceived += packetsRecv
	m.LastUsed = time.Now()
}

// String returns a human-readable representation.
func (m *NATMapping) String() string {
	mappingType := "dynamic"
	if m.IsStatic {
		mappingType = "static"
	}
	return fmt.Sprintf("[%s] %s ↔ %s (%s/%s)",
		mappingType, m.InternalAddress(), m.ExternalAddress(), m.Protocol, m.WANInterfaceName)
}

// =============================================================================
// Port Allocation Types
// =============================================================================

// PortAllocationConfig defines the port pool configuration.
type PortAllocationConfig struct {
	// Port range
	PortRangeStart int `json:"port_range_start" yaml:"port_range_start"`
	PortRangeEnd   int `json:"port_range_end" yaml:"port_range_end"`

	// Pool limits
	PoolSize       int `json:"pool_size" yaml:"pool_size"`               // Max concurrent allocations
	MaxPerHost     int `json:"max_per_host" yaml:"max_per_host"`         // Max allocations per internal IP
	MaxPerProtocol int `json:"max_per_protocol" yaml:"max_per_protocol"` // Max per protocol

	// Reuse policy
	ReuseDelay time.Duration `json:"reuse_delay" yaml:"reuse_delay"` // Delay before reusing freed port

	// Reserved ports (not to be allocated)
	ReservedPorts []int `json:"reserved_ports,omitempty" yaml:"reserved_ports,omitempty"`
}

// AvailablePorts returns the total available port count.
func (c *PortAllocationConfig) AvailablePorts() int {
	return c.PortRangeEnd - c.PortRangeStart + 1 - len(c.ReservedPorts)
}

// IsInRange checks if a port is within the allocation range.
func (c *PortAllocationConfig) IsInRange(port int) bool {
	return port >= c.PortRangeStart && port <= c.PortRangeEnd
}

// IsReserved checks if a port is reserved.
func (c *PortAllocationConfig) IsReserved(port int) bool {
	for _, reserved := range c.ReservedPorts {
		if port == reserved {
			return true
		}
	}
	return false
}

// PortAllocation represents an allocated port from the pool.
type PortAllocation struct {
	// Port details
	Port     int      `json:"port" yaml:"port"`
	Protocol Protocol `json:"protocol" yaml:"protocol"`

	// Allocation info
	AllocatedTo  string    `json:"allocated_to" yaml:"allocated_to"`                       // Internal IP
	AllocatedFor string    `json:"allocated_for,omitempty" yaml:"allocated_for,omitempty"` // Destination
	AllocatedAt  time.Time `json:"allocated_at" yaml:"allocated_at"`

	// State
	InUse    bool      `json:"in_use" yaml:"in_use"`
	LastUsed time.Time `json:"last_used,omitempty" yaml:"last_used,omitempty"`
	FreedAt  time.Time `json:"freed_at,omitempty" yaml:"freed_at,omitempty"`

	// Reference
	MappingID string `json:"mapping_id,omitempty" yaml:"mapping_id,omitempty"`
}

// Key returns a unique key for this allocation.
func (a *PortAllocation) Key() string {
	return fmt.Sprintf("%d/%s", a.Port, a.Protocol)
}

// CanReuse checks if the port can be reused after the reuse delay.
func (a *PortAllocation) CanReuse(reuseDelay time.Duration) bool {
	if a.InUse {
		return false
	}
	if a.FreedAt.IsZero() {
		return true
	}
	return time.Since(a.FreedAt) >= reuseDelay
}

// PortPoolStatus represents the current state of the port allocation pool.
type PortPoolStatus struct {
	Protocol       Protocol  `json:"protocol"`
	TotalPorts     int       `json:"total_ports"`
	AllocatedPorts int       `json:"allocated_ports"`
	AvailablePorts int       `json:"available_ports"`
	ReservedPorts  int       `json:"reserved_ports"`
	UtilizationPct float64   `json:"utilization_percent"`
	PeakUsage      int       `json:"peak_usage"`
	PeakUsageAt    time.Time `json:"peak_usage_at,omitempty"`
}

// =============================================================================
// NAT Session Types
// =============================================================================

// NATSessionConfig defines session timeout configuration.
type NATSessionConfig struct {
	// Protocol-specific timeouts
	TCPEstablishedTimeout time.Duration `json:"tcp_established_timeout" yaml:"tcp_established_timeout"`
	TCPTransitoryTimeout  time.Duration `json:"tcp_transitory_timeout" yaml:"tcp_transitory_timeout"`
	TCPSynSentTimeout     time.Duration `json:"tcp_syn_sent_timeout" yaml:"tcp_syn_sent_timeout"`
	TCPSynRecvTimeout     time.Duration `json:"tcp_syn_recv_timeout" yaml:"tcp_syn_recv_timeout"`
	TCPFinWaitTimeout     time.Duration `json:"tcp_fin_wait_timeout" yaml:"tcp_fin_wait_timeout"`
	TCPCloseWaitTimeout   time.Duration `json:"tcp_close_wait_timeout" yaml:"tcp_close_wait_timeout"`
	TCPTimeWaitTimeout    time.Duration `json:"tcp_time_wait_timeout" yaml:"tcp_time_wait_timeout"`

	UDPTimeout       time.Duration `json:"udp_timeout" yaml:"udp_timeout"`
	UDPStreamTimeout time.Duration `json:"udp_stream_timeout" yaml:"udp_stream_timeout"`

	ICMPTimeout time.Duration `json:"icmp_timeout" yaml:"icmp_timeout"`

	GenericTimeout time.Duration `json:"generic_timeout" yaml:"generic_timeout"`
}

// DefaultNATSessionConfig returns default timeout configuration.
func DefaultNATSessionConfig() *NATSessionConfig {
	return &NATSessionConfig{
		TCPEstablishedTimeout: 7200 * time.Second, // 2 hours
		TCPTransitoryTimeout:  120 * time.Second,  // 2 minutes
		TCPSynSentTimeout:     120 * time.Second,
		TCPSynRecvTimeout:     60 * time.Second,
		TCPFinWaitTimeout:     120 * time.Second,
		TCPCloseWaitTimeout:   60 * time.Second,
		TCPTimeWaitTimeout:    120 * time.Second,
		UDPTimeout:            180 * time.Second, // 3 minutes
		UDPStreamTimeout:      180 * time.Second,
		ICMPTimeout:           30 * time.Second,
		GenericTimeout:        600 * time.Second, // 10 minutes
	}
}

// GetTimeout returns the appropriate timeout for a protocol and state.
func (c *NATSessionConfig) GetTimeout(protocol Protocol, state ConnectionState) time.Duration {
	switch protocol {
	case ProtocolTCP:
		switch state {
		case ConnectionStateESTABLISHED:
			return c.TCPEstablishedTimeout
		case ConnectionStateSYN_SENT:
			return c.TCPSynSentTimeout
		case ConnectionStateSYN_RECV:
			return c.TCPSynRecvTimeout
		case ConnectionStateFIN_WAIT:
			return c.TCPFinWaitTimeout
		case ConnectionStateTIME_WAIT:
			return c.TCPTimeWaitTimeout
		default:
			return c.TCPTransitoryTimeout
		}
	case ProtocolUDP:
		return c.UDPTimeout
	case ProtocolICMP:
		return c.ICMPTimeout
	default:
		return c.GenericTimeout
	}
}

// NATSession represents an active NAT session with state tracking.
type NATSession struct {
	// Identity
	SessionID string `json:"session_id" yaml:"session_id"`

	// Associated mapping
	MappingID string      `json:"mapping_id" yaml:"mapping_id"`
	Mapping   *NATMapping `json:"mapping,omitempty" yaml:"mapping,omitempty"`

	// Session state
	State         ConnectionState `json:"state" yaml:"state"`
	PreviousState ConnectionState `json:"previous_state,omitempty" yaml:"previous_state,omitempty"`

	// Traffic counters
	PacketCount   uint64  `json:"packet_count" yaml:"packet_count"`
	ByteCount     uint64  `json:"byte_count" yaml:"byte_count"`
	PacketRatePPS float64 `json:"packet_rate_pps,omitempty" yaml:"packet_rate_pps,omitempty"`

	// Timing
	CreatedAt    time.Time     `json:"created_at" yaml:"created_at"`
	LastActivity time.Time     `json:"last_activity" yaml:"last_activity"`
	ExpiresAt    time.Time     `json:"expires_at" yaml:"expires_at"`
	Timeout      time.Duration `json:"timeout" yaml:"timeout"`

	// Metadata
	ApplicationProtocol string `json:"application_protocol,omitempty" yaml:"application_protocol,omitempty"` // HTTP, DNS, etc.
	Mark                int    `json:"mark,omitempty" yaml:"mark,omitempty"`
}

// IsExpired returns true if the session has expired.
func (s *NATSession) IsExpired() bool {
	return time.Now().After(s.ExpiresAt)
}

// TimeRemaining returns time until expiration.
func (s *NATSession) TimeRemaining() time.Duration {
	remaining := time.Until(s.ExpiresAt)
	if remaining < 0 {
		return 0
	}
	return remaining
}

// IdleTime returns time since last activity.
func (s *NATSession) IdleTime() time.Duration {
	return time.Since(s.LastActivity)
}

// Touch updates activity and extends timeout.
func (s *NATSession) Touch(timeout time.Duration) {
	s.LastActivity = time.Now()
	s.Timeout = timeout
	s.ExpiresAt = s.LastActivity.Add(timeout)
}

// SetState updates the session state and expiration.
func (s *NATSession) SetState(state ConnectionState, timeout time.Duration) {
	s.PreviousState = s.State
	s.State = state
	s.Touch(timeout)
}

// =============================================================================
// NAT Statistics Types
// =============================================================================

// NATStatistics provides comprehensive NAT engine statistics.
type NATStatistics struct {
	// Mapping counts
	ActiveMappings       int64  `json:"active_mappings"`
	StaticMappings       int64  `json:"static_mappings"`
	DynamicMappings      int64  `json:"dynamic_mappings"`
	TotalMappingsCreated uint64 `json:"total_mappings_created"`
	MappingsExpired      uint64 `json:"mappings_expired"`
	MappingsDeleted      uint64 `json:"mappings_deleted"`

	// Per-protocol counts
	TCPMappings   int64 `json:"tcp_mappings"`
	UDPMappings   int64 `json:"udp_mappings"`
	ICMPMappings  int64 `json:"icmp_mappings"`
	OtherMappings int64 `json:"other_mappings"`

	// Port pool status
	PortPoolTotal       int     `json:"port_pool_total"`
	PortPoolUsed        int     `json:"port_pool_used"`
	PortPoolAvailable   int     `json:"port_pool_available"`
	PortPoolUtilization float64 `json:"port_pool_utilization"` // 0-100%

	// Rates
	MappingsPerSecond     float64 `json:"mappings_per_second"`
	MappingsExpiredPerSec float64 `json:"mappings_expired_per_sec"`
	TranslationsPerSecond float64 `json:"translations_per_second"`

	// Traffic
	TotalBytesSent     uint64 `json:"total_bytes_sent"`
	TotalBytesReceived uint64 `json:"total_bytes_received"`
	TotalPacketsSent   uint64 `json:"total_packets_sent"`
	TotalPacketsRecv   uint64 `json:"total_packets_received"`

	// Errors
	AllocationFailures uint64 `json:"allocation_failures"`
	TranslationErrors  uint64 `json:"translation_errors"`
	ExpiredHits        uint64 `json:"expired_hits"` // Lookups on expired mappings

	// Performance
	AverageAllocationTimeUs  float64 `json:"avg_allocation_time_us"`
	AverageTranslationTimeNs float64 `json:"avg_translation_time_ns"`
	LookupCacheHitRate       float64 `json:"lookup_cache_hit_rate"` // 0-100%

	// Peak values
	PeakMappings   int64     `json:"peak_mappings"`
	PeakMappingsAt time.Time `json:"peak_mappings_at,omitempty"`

	// Timestamp
	CollectedAt time.Time `json:"collected_at"`
}

// UtilizationWarning returns true if port pool utilization is high.
func (s *NATStatistics) UtilizationWarning(threshold float64) bool {
	return s.PortPoolUtilization >= threshold
}

// =============================================================================
// Static NAT Types (Port Forwarding)
// =============================================================================

// StaticNATRule represents a static port forwarding rule.
type StaticNATRule struct {
	// Identity
	RuleID string `json:"rule_id" yaml:"rule_id" db:"rule_id"`
	Name   string `json:"name" yaml:"name" db:"name"`
	Alias  string `json:"alias,omitempty" yaml:"alias,omitempty" db:"alias"`

	// External (WAN) side
	ExternalIP      string `json:"external_ip,omitempty" yaml:"external_ip,omitempty"` // Empty = use WAN IP
	ExternalPort    int    `json:"external_port" yaml:"external_port" db:"external_port"`
	ExternalPortEnd int    `json:"external_port_end,omitempty" yaml:"external_port_end,omitempty"` // For port ranges

	// Internal (LAN) side
	InternalIP   string `json:"internal_ip" yaml:"internal_ip" db:"internal_ip"`
	InternalPort int    `json:"internal_port" yaml:"internal_port" db:"internal_port"`

	// Protocol
	Protocol Protocol `json:"protocol" yaml:"protocol" db:"protocol"`

	// Interface binding
	WANInterface      string `json:"wan_interface" yaml:"wan_interface" db:"wan_interface"` // Interface name or "any"
	WANInterfaceAlias string `json:"wan_interface_alias,omitempty" yaml:"wan_interface_alias,omitempty"`

	// State
	Enabled bool `json:"enabled" yaml:"enabled" db:"enabled"`

	// Traffic counters
	ActiveConnections int64  `json:"active_connections,omitempty" yaml:"active_connections,omitempty"`
	TotalConnections  uint64 `json:"total_connections,omitempty" yaml:"total_connections,omitempty"`
	BytesTransferred  uint64 `json:"bytes_transferred,omitempty" yaml:"bytes_transferred,omitempty"`

	// Timestamps
	LastConnectionTime *time.Time `json:"last_connection_time,omitempty" yaml:"last_connection_time,omitempty"`
	CreatedAt          time.Time  `json:"created_at,omitempty" yaml:"created_at,omitempty" db:"created_at"`
	UpdatedAt          time.Time  `json:"updated_at,omitempty" yaml:"updated_at,omitempty" db:"updated_at"`

	// Metadata
	Description string `json:"description,omitempty" yaml:"description,omitempty" db:"description"`
}

// Key returns a unique key for this rule.
func (r *StaticNATRule) Key() string {
	return fmt.Sprintf("%s:%d/%s/%s", r.WANInterface, r.ExternalPort, r.Protocol, r.InternalIP)
}

// IsPortRange returns true if this rule forwards a range of ports.
func (r *StaticNATRule) IsPortRange() bool {
	return r.ExternalPortEnd > 0 && r.ExternalPortEnd > r.ExternalPort
}

// PortCount returns the number of ports in this rule.
func (r *StaticNATRule) PortCount() int {
	if r.IsPortRange() {
		return r.ExternalPortEnd - r.ExternalPort + 1
	}
	return 1
}

// String returns a human-readable representation.
func (r *StaticNATRule) String() string {
	portStr := fmt.Sprintf("%d", r.ExternalPort)
	if r.IsPortRange() {
		portStr = fmt.Sprintf("%d-%d", r.ExternalPort, r.ExternalPortEnd)
	}
	return fmt.Sprintf("[%s] %s:%s/%s → %s:%d (%s)",
		r.Name, r.WANInterface, portStr, r.Protocol, r.InternalIP, r.InternalPort,
		func() string {
			if r.Enabled {
				return "enabled"
			} else {
				return "disabled"
			}
		}())
}

// =============================================================================
// NAT Table Types
// =============================================================================

// NATTableStats represents NAT table statistics.
type NATTableStats struct {
	TableName      string    `json:"table_name"`
	EntryCount     int64     `json:"entry_count"`
	MaxEntries     int64     `json:"max_entries"`
	UtilizationPct float64   `json:"utilization_percent"`
	LastCleanupAt  time.Time `json:"last_cleanup_at"`
	EntriesRemoved uint64    `json:"entries_removed_last_cleanup"`
}

// NATMappingFilter defines filter criteria for querying NAT mappings.
type NATMappingFilter struct {
	Protocol            Protocol `json:"protocol,omitempty"`
	WANInterface        string   `json:"wan_interface,omitempty"`
	InternalIP          string   `json:"internal_ip,omitempty"`
	ExternalIP          string   `json:"external_ip,omitempty"`
	StaticOnly          bool     `json:"static_only,omitempty"`
	DynamicOnly         bool     `json:"dynamic_only,omitempty"`
	ActiveOnly          bool     `json:"active_only,omitempty"` // Not expired
	MinBytesTransferred uint64   `json:"min_bytes_transferred,omitempty"`
}

// =============================================================================
// UPnP/NAT-PMP Types
// =============================================================================

// UPnPConfig represents UPnP/NAT-PMP configuration.
type UPnPConfig struct {
	Enabled          bool          `json:"enabled" yaml:"enabled"`
	AllowFromSubnets []string      `json:"allow_from_subnets" yaml:"allow_from_subnets"`
	DenyFromSubnets  []string      `json:"deny_from_subnets" yaml:"deny_from_subnets"`
	MaxPortForwards  int           `json:"max_port_forwards" yaml:"max_port_forwards"`
	LeaseTime        time.Duration `json:"lease_time" yaml:"lease_time"`
	AllowedPorts     []int         `json:"allowed_ports,omitempty" yaml:"allowed_ports,omitempty"`
	DeniedPorts      []int         `json:"denied_ports,omitempty" yaml:"denied_ports,omitempty"`
	SecureMode       bool          `json:"secure_mode" yaml:"secure_mode"` // Require same source IP
}

// UPnPMapping represents a mapping created via UPnP/NAT-PMP.
type UPnPMapping struct {
	MappingID    string    `json:"mapping_id"`
	Protocol     Protocol  `json:"protocol"`
	ExternalPort int       `json:"external_port"`
	InternalIP   string    `json:"internal_ip"`
	InternalPort int       `json:"internal_port"`
	Description  string    `json:"description"`
	RequestedBy  string    `json:"requested_by"` // Client that requested
	CreatedAt    time.Time `json:"created_at"`
	ExpiresAt    time.Time `json:"expires_at"`
	Renewed      int       `json:"renewed"` // Number of times renewed
}

// IsExpired returns true if the UPnP mapping has expired.
func (m *UPnPMapping) IsExpired() bool {
	return time.Now().After(m.ExpiresAt)
}
