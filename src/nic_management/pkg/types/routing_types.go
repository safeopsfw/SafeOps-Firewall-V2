// Package types provides routing-related type definitions including routing table
// entries, connection tracking structures, load balancing configurations, failover
// policies, and WAN health monitoring data. These types are central to the
// multi-WAN routing engine and packet forwarding logic.
package types

import (
	"fmt"
	"net"
	"time"
)

// =============================================================================
// Routing Table Types
// =============================================================================

// RouteType represents the source/type of a routing entry.
type RouteType string

const (
	// RouteTypeStatic is a manually configured static route.
	RouteTypeStatic RouteType = "STATIC"
	// RouteTypeDHCP is a route learned from DHCP.
	RouteTypeDHCP RouteType = "DHCP"
	// RouteTypeConnected is a directly connected network.
	RouteTypeConnected RouteType = "CONNECTED"
	// RouteTypeKernel is a kernel-managed route.
	RouteTypeKernel RouteType = "KERNEL"
	// RouteTypePolicy is a policy-based route.
	RouteTypePolicy RouteType = "POLICY"
)

// Route represents a single routing table entry.
type Route struct {
	// Route identity
	ID string `json:"id,omitempty" yaml:"id,omitempty" db:"route_id"`

	// Destination network
	Destination string `json:"destination" yaml:"destination" db:"destination"`
	Netmask     string `json:"netmask" yaml:"netmask" db:"netmask"`
	CIDR        string `json:"cidr,omitempty" yaml:"cidr,omitempty"` // Combined destination/prefix

	// Next hop
	Gateway       string `json:"gateway" yaml:"gateway" db:"gateway"`
	InterfaceID   string `json:"interface_id,omitempty" yaml:"interface_id,omitempty" db:"interface_id"`
	InterfaceName string `json:"interface_name" yaml:"interface_name" db:"interface_name"`

	// Route properties
	Metric    int       `json:"metric" yaml:"metric" db:"metric"`
	Type      RouteType `json:"type,omitempty" yaml:"type,omitempty" db:"route_type"`
	IsDefault bool      `json:"is_default" yaml:"is_default" db:"is_default"`
	IsEnabled bool      `json:"is_enabled" yaml:"is_enabled" db:"is_enabled"`

	// Scope and flags
	Scope    string `json:"scope,omitempty" yaml:"scope,omitempty"`       // link, host, global
	Protocol string `json:"protocol,omitempty" yaml:"protocol,omitempty"` // static, dhcp, kernel

	// Metadata
	Description string    `json:"description,omitempty" yaml:"description,omitempty" db:"description"`
	CreatedAt   time.Time `json:"created_at,omitempty" yaml:"created_at,omitempty" db:"created_at"`
	UpdatedAt   time.Time `json:"updated_at,omitempty" yaml:"updated_at,omitempty" db:"updated_at"`
	CreatedBy   string    `json:"created_by,omitempty" yaml:"created_by,omitempty" db:"created_by"`
}

// IsValid checks if the route has valid destination and gateway.
func (r *Route) IsValid() bool {
	// Check destination
	if r.Destination == "" {
		return false
	}
	_, _, err := net.ParseCIDR(r.Destination + "/" + r.NetmaskToCIDR())
	if err != nil && net.ParseIP(r.Destination) == nil {
		return false
	}
	return true
}

// NetmaskToCIDR converts netmask to CIDR prefix length.
func (r *Route) NetmaskToCIDR() string {
	if r.Netmask == "" {
		return "32"
	}
	ip := net.ParseIP(r.Netmask)
	if ip == nil {
		return "32"
	}
	mask := net.IPMask(ip.To4())
	ones, _ := mask.Size()
	return fmt.Sprintf("%d", ones)
}

// String returns a human-readable route description.
func (r *Route) String() string {
	if r.IsDefault {
		return fmt.Sprintf("default via %s dev %s metric %d", r.Gateway, r.InterfaceName, r.Metric)
	}
	return fmt.Sprintf("%s/%s via %s dev %s metric %d", r.Destination, r.Netmask, r.Gateway, r.InterfaceName, r.Metric)
}

// RoutingTable represents the complete routing table.
type RoutingTable struct {
	Routes         []Route   `json:"routes"`
	DefaultGateway string    `json:"default_gateway,omitempty"`
	DefaultWAN     string    `json:"default_wan,omitempty"`
	TotalRoutes    int       `json:"total_routes"`
	LastUpdated    time.Time `json:"last_updated"`
}

// FindDefaultRoute returns the default route if present.
func (rt *RoutingTable) FindDefaultRoute() *Route {
	for i := range rt.Routes {
		if rt.Routes[i].IsDefault {
			return &rt.Routes[i]
		}
	}
	return nil
}

// =============================================================================
// Connection Tracking Types
// =============================================================================

// ConnectionState represents the lifecycle state of a tracked connection.
type ConnectionState string

const (
	// ConnectionStateNEW indicates a new connection.
	ConnectionStateNEW ConnectionState = "NEW"
	// ConnectionStateESTABLISHED indicates an established connection.
	ConnectionStateESTABLISHED ConnectionState = "ESTABLISHED"
	// ConnectionStateRELATED indicates a connection related to an existing one.
	ConnectionStateRELATED ConnectionState = "RELATED"
	// ConnectionStateINVALID indicates an invalid connection.
	ConnectionStateINVALID ConnectionState = "INVALID"
	// ConnectionStateCLOSING indicates a connection being closed.
	ConnectionStateCLOSING ConnectionState = "CLOSING"
	// ConnectionStateCLOSED indicates a closed connection.
	ConnectionStateCLOSED ConnectionState = "CLOSED"
	// ConnectionStateTIME_WAIT indicates TCP TIME_WAIT state.
	ConnectionStateTIME_WAIT ConnectionState = "TIME_WAIT"
	// ConnectionStateSYN_SENT indicates TCP SYN sent.
	ConnectionStateSYN_SENT ConnectionState = "SYN_SENT"
	// ConnectionStateSYN_RECV indicates TCP SYN received.
	ConnectionStateSYN_RECV ConnectionState = "SYN_RECV"
	// ConnectionStateFIN_WAIT indicates TCP FIN_WAIT state.
	ConnectionStateFIN_WAIT ConnectionState = "FIN_WAIT"
)

// IsActive returns true if the connection is active (not closed/invalid).
func (s ConnectionState) IsActive() bool {
	return s == ConnectionStateNEW || s == ConnectionStateESTABLISHED || s == ConnectionStateRELATED
}

// String returns the string representation.
func (s ConnectionState) String() string {
	return string(s)
}

// Connection represents a tracked network connection (5-tuple + state).
type Connection struct {
	// Identity
	ConnectionID string `json:"connection_id" yaml:"connection_id" db:"connection_id"`

	// 5-tuple
	SrcIP    string   `json:"src_ip" yaml:"src_ip" db:"src_ip"`
	SrcPort  int      `json:"src_port" yaml:"src_port" db:"src_port"`
	DstIP    string   `json:"dst_ip" yaml:"dst_ip" db:"dst_ip"`
	DstPort  int      `json:"dst_port" yaml:"dst_port" db:"dst_port"`
	Protocol Protocol `json:"protocol" yaml:"protocol" db:"protocol"`

	// State
	State ConnectionState `json:"state" yaml:"state" db:"state"`

	// Interface binding
	WANInterfaceID   string `json:"wan_interface_id,omitempty" yaml:"wan_interface_id,omitempty" db:"wan_interface_id"`
	WANInterfaceName string `json:"wan_interface" yaml:"wan_interface" db:"wan_interface_name"`
	LANInterfaceID   string `json:"lan_interface_id,omitempty" yaml:"lan_interface_id,omitempty" db:"lan_interface_id"`
	LANInterfaceName string `json:"lan_interface,omitempty" yaml:"lan_interface,omitempty" db:"lan_interface_name"`

	// NAT information
	IsNAT        bool   `json:"is_nat" yaml:"is_nat" db:"is_nat"`
	NATMappingID string `json:"nat_mapping_id,omitempty" yaml:"nat_mapping_id,omitempty" db:"nat_mapping_id"`

	// Traffic counters
	BytesSent       uint64 `json:"bytes_sent" yaml:"bytes_sent" db:"bytes_sent"`
	BytesReceived   uint64 `json:"bytes_received" yaml:"bytes_received" db:"bytes_received"`
	PacketsSent     uint64 `json:"packets_sent" yaml:"packets_sent" db:"packets_sent"`
	PacketsReceived uint64 `json:"packets_received" yaml:"packets_received" db:"packets_received"`

	// Timestamps
	CreatedAt time.Time  `json:"created_at" yaml:"created_at" db:"created_at"`
	LastSeen  time.Time  `json:"last_seen" yaml:"last_seen" db:"last_seen"`
	ExpiresAt *time.Time `json:"expires_at,omitempty" yaml:"expires_at,omitempty" db:"expires_at"`

	// Metadata
	Mark int    `json:"mark,omitempty" yaml:"mark,omitempty" db:"mark"`
	Zone string `json:"zone,omitempty" yaml:"zone,omitempty" db:"zone"`
}

// FiveTuple returns the connection's 5-tuple as a string key.
func (c *Connection) FiveTuple() string {
	return fmt.Sprintf("%s:%d->%s:%d/%s", c.SrcIP, c.SrcPort, c.DstIP, c.DstPort, c.Protocol)
}

// IsExpired returns true if the connection has expired.
func (c *Connection) IsExpired() bool {
	if c.ExpiresAt == nil {
		return false
	}
	return time.Now().After(*c.ExpiresAt)
}

// TotalBytes returns the total bytes transferred.
func (c *Connection) TotalBytes() uint64 {
	return c.BytesSent + c.BytesReceived
}

// Duration returns the connection duration.
func (c *Connection) Duration() time.Duration {
	return c.LastSeen.Sub(c.CreatedAt)
}

// ConnectionTrackingStats provides aggregated connection tracking statistics.
type ConnectionTrackingStats struct {
	TotalConnections      int            `json:"total_connections"`
	ActiveConnections     int            `json:"active_connections"`
	MaxConnections        int            `json:"max_connections"`
	ConnectionsByState    map[string]int `json:"connections_by_state"`
	ConnectionsByProto    map[string]int `json:"connections_by_protocol"`
	NewConnectionsRate    float64        `json:"new_connections_rate"`    // per second
	ClosedConnectionsRate float64        `json:"closed_connections_rate"` // per second
	AverageLifetime       time.Duration  `json:"average_lifetime"`
	CollectedAt           time.Time      `json:"collected_at"`
}

// =============================================================================
// Load Balancing Types
// =============================================================================

// LoadBalancingMode represents the load balancing algorithm.
type LoadBalancingMode string

const (
	// LoadBalancingDisabled means no load balancing, use primary only.
	LoadBalancingDisabled LoadBalancingMode = "DISABLED"
	// LoadBalancingRoundRobin distributes connections round-robin.
	LoadBalancingRoundRobin LoadBalancingMode = "ROUND_ROBIN"
	// LoadBalancingWeighted distributes based on configured weights.
	LoadBalancingWeighted LoadBalancingMode = "WEIGHTED"
	// LoadBalancingLeastConnections routes to WAN with fewest connections.
	LoadBalancingLeastConnections LoadBalancingMode = "LEAST_CONNECTIONS"
	// LoadBalancingHashBased uses hash of IP/port for consistent routing.
	LoadBalancingHashBased LoadBalancingMode = "HASH_BASED"
	// LoadBalancingBandwidthBased routes based on available bandwidth.
	LoadBalancingBandwidthBased LoadBalancingMode = "BANDWIDTH_BASED"
	// LoadBalancingFailoverOnly uses backup only when primary fails.
	LoadBalancingFailoverOnly LoadBalancingMode = "FAILOVER_ONLY"
)

// IsValid returns true if the mode is valid.
func (m LoadBalancingMode) IsValid() bool {
	switch m {
	case LoadBalancingDisabled, LoadBalancingRoundRobin, LoadBalancingWeighted,
		LoadBalancingLeastConnections, LoadBalancingHashBased,
		LoadBalancingBandwidthBased, LoadBalancingFailoverOnly:
		return true
	default:
		return false
	}
}

// String returns the string representation.
func (m LoadBalancingMode) String() string {
	return string(m)
}

// HashAlgorithm represents the hashing algorithm for hash-based load balancing.
type HashAlgorithm string

const (
	HashAlgorithmSrcIP   HashAlgorithm = "SRC_IP"
	HashAlgorithmDstIP   HashAlgorithm = "DST_IP"
	HashAlgorithm5Tuple  HashAlgorithm = "5TUPLE"
	HashAlgorithmSrcPort HashAlgorithm = "SRC_PORT"
)

// WANWeight represents weight configuration for weighted load balancing.
type WANWeight struct {
	InterfaceID    string `json:"interface_id,omitempty" yaml:"interface_id,omitempty" db:"wan_interface_id"`
	InterfaceName  string `json:"interface_name" yaml:"interface_name" db:"interface_name"`
	InterfaceAlias string `json:"interface_alias,omitempty" yaml:"interface_alias,omitempty"`
	Weight         int    `json:"weight" yaml:"weight" db:"weight"` // 1-100
	IsActive       bool   `json:"is_active" yaml:"is_active" db:"is_active"`
}

// IsValid checks if the weight is within valid range.
func (w *WANWeight) IsValid() bool {
	return w.Weight >= 1 && w.Weight <= 100
}

// WANPriority represents failover priority configuration.
type WANPriority struct {
	InterfaceID    string `json:"interface_id,omitempty" yaml:"interface_id,omitempty"`
	InterfaceName  string `json:"interface_name" yaml:"interface_name"`
	InterfaceAlias string `json:"interface_alias,omitempty" yaml:"interface_alias,omitempty"`
	Priority       int    `json:"priority" yaml:"priority"` // Lower = higher priority
	IsPrimary      bool   `json:"is_primary" yaml:"is_primary"`
}

// LoadBalancerConfig represents the complete load balancer configuration.
type LoadBalancerConfig struct {
	Mode                LoadBalancingMode `json:"mode" yaml:"mode" db:"mode"`
	WANWeights          []WANWeight       `json:"wan_weights,omitempty" yaml:"wan_weights,omitempty"`
	WANPriorities       []WANPriority     `json:"wan_priorities,omitempty" yaml:"wan_priorities,omitempty"`
	SessionAffinity     bool              `json:"session_affinity" yaml:"session_affinity"`
	SessionAffinityMode string            `json:"session_affinity_mode,omitempty" yaml:"session_affinity_mode,omitempty"` // src_ip, 5tuple
	HashAlgorithm       HashAlgorithm     `json:"hash_algorithm,omitempty" yaml:"hash_algorithm,omitempty"`
	RebalanceInterval   time.Duration     `json:"rebalance_interval,omitempty" yaml:"rebalance_interval,omitempty"`
	UpdatedAt           time.Time         `json:"updated_at,omitempty" yaml:"updated_at,omitempty"`
}

// =============================================================================
// WAN Health Monitoring Types
// =============================================================================

// WANHealthState represents the health state of a WAN interface.
type WANHealthState string

const (
	// WANHealthUnknown indicates health cannot be determined.
	WANHealthUnknown WANHealthState = "UNKNOWN"
	// WANHealthHealthy indicates the WAN is fully operational.
	WANHealthHealthy WANHealthState = "HEALTHY"
	// WANHealthDegraded indicates reduced performance but functional.
	WANHealthDegraded WANHealthState = "DEGRADED"
	// WANHealthFailing indicates health checks are failing.
	WANHealthFailing WANHealthState = "FAILING"
	// WANHealthDown indicates the WAN is not operational.
	WANHealthDown WANHealthState = "DOWN"
	// WANHealthRecovering indicates the WAN is recovering from failure.
	WANHealthRecovering WANHealthState = "RECOVERING"
)

// IsOperational returns true if the WAN can route traffic.
func (s WANHealthState) IsOperational() bool {
	return s == WANHealthHealthy || s == WANHealthDegraded || s == WANHealthRecovering
}

// SeverityLevel returns a numeric severity (0=healthy, higher=worse).
func (s WANHealthState) SeverityLevel() int {
	switch s {
	case WANHealthHealthy:
		return 0
	case WANHealthRecovering:
		return 1
	case WANHealthDegraded:
		return 2
	case WANHealthFailing:
		return 3
	case WANHealthDown:
		return 4
	default:
		return 5
	}
}

// String returns the string representation.
func (s WANHealthState) String() string {
	return string(s)
}

// WANHealth represents health metrics for a WAN interface.
type WANHealth struct {
	// Identity
	InterfaceID    string `json:"interface_id,omitempty" yaml:"interface_id,omitempty" db:"wan_interface_id"`
	InterfaceName  string `json:"interface_name" yaml:"interface_name" db:"interface_name"`
	InterfaceAlias string `json:"interface_alias,omitempty" yaml:"interface_alias,omitempty"`

	// Current state
	State WANHealthState `json:"state" yaml:"state" db:"state"`

	// Latency metrics
	LatencyMs    float64 `json:"latency_ms" yaml:"latency_ms" db:"latency_ms"`
	LatencyAvgMs float64 `json:"latency_avg_ms,omitempty" yaml:"latency_avg_ms,omitempty"`
	LatencyMinMs float64 `json:"latency_min_ms,omitempty" yaml:"latency_min_ms,omitempty"`
	LatencyMaxMs float64 `json:"latency_max_ms,omitempty" yaml:"latency_max_ms,omitempty"`
	JitterMs     float64 `json:"jitter_ms,omitempty" yaml:"jitter_ms,omitempty" db:"jitter_ms"`

	// Loss metrics
	PacketLossPercent float64 `json:"packet_loss_percent" yaml:"packet_loss_percent" db:"packet_loss_percent"`

	// Uptime
	UptimePercent  float64       `json:"uptime_percent" yaml:"uptime_percent"`
	UptimeDuration time.Duration `json:"uptime_duration,omitempty" yaml:"uptime_duration,omitempty"`

	// Health check counters
	ConsecutiveFailures  int `json:"consecutive_failures" yaml:"consecutive_failures" db:"consecutive_failures"`
	ConsecutiveSuccesses int `json:"consecutive_successes" yaml:"consecutive_successes" db:"consecutive_successes"`

	// Bandwidth (optional, from speed tests)
	BandwidthUpMbps   float64 `json:"bandwidth_up_mbps,omitempty" yaml:"bandwidth_up_mbps,omitempty"`
	BandwidthDownMbps float64 `json:"bandwidth_down_mbps,omitempty" yaml:"bandwidth_down_mbps,omitempty"`

	// Health check configuration
	HealthCheckTarget   string        `json:"health_check_target,omitempty" yaml:"health_check_target,omitempty"`
	HealthCheckInterval time.Duration `json:"health_check_interval,omitempty" yaml:"health_check_interval,omitempty"`

	// Status flags
	IsActive  bool `json:"is_active" yaml:"is_active"`
	IsPrimary bool `json:"is_primary" yaml:"is_primary"`

	// Timestamps
	LastCheckTime  time.Time `json:"last_check_time" yaml:"last_check_time" db:"checked_at"`
	StateChangedAt time.Time `json:"state_changed_at,omitempty" yaml:"state_changed_at,omitempty"`

	// Trend indicator
	Trend string `json:"trend,omitempty" yaml:"trend,omitempty"` // STABLE, IMPROVING, DEGRADING
}

// ShouldFailover returns true if the health state warrants failover.
func (h *WANHealth) ShouldFailover(failureThreshold int) bool {
	return h.State == WANHealthDown || h.ConsecutiveFailures >= failureThreshold
}

// ShouldRecover returns true if the WAN has recovered sufficiently.
func (h *WANHealth) ShouldRecover(recoveryThreshold int) bool {
	return h.State == WANHealthRecovering && h.ConsecutiveSuccesses >= recoveryThreshold
}

// WANHealthHistory represents a historical health record.
type WANHealthHistory struct {
	ID                string         `json:"id" db:"health_id"`
	WANInterfaceID    string         `json:"wan_interface_id" db:"wan_interface_id"`
	State             WANHealthState `json:"state" db:"state"`
	LatencyMs         float64        `json:"latency_ms" db:"latency_ms"`
	JitterMs          float64        `json:"jitter_ms" db:"jitter_ms"`
	PacketLossPercent float64        `json:"packet_loss_percent" db:"packet_loss_percent"`
	BandwidthUpMbps   float64        `json:"bandwidth_up_mbps" db:"bandwidth_up_mbps"`
	BandwidthDownMbps float64        `json:"bandwidth_down_mbps" db:"bandwidth_down_mbps"`
	CheckedAt         time.Time      `json:"checked_at" db:"checked_at"`
}

// =============================================================================
// Failover Types
// =============================================================================

// FailoverReason represents the reason for a failover event.
type FailoverReason string

const (
	// FailoverReasonManual indicates manual administrator action.
	FailoverReasonManual FailoverReason = "MANUAL"
	// FailoverReasonHealthCheckFailed indicates health check failures.
	FailoverReasonHealthCheckFailed FailoverReason = "HEALTH_CHECK_FAILED"
	// FailoverReasonGatewayUnreachable indicates gateway unreachable.
	FailoverReasonGatewayUnreachable FailoverReason = "GATEWAY_UNREACHABLE"
	// FailoverReasonHighPacketLoss indicates high packet loss.
	FailoverReasonHighPacketLoss FailoverReason = "HIGH_PACKET_LOSS"
	// FailoverReasonHighLatency indicates high latency.
	FailoverReasonHighLatency FailoverReason = "HIGH_LATENCY"
	// FailoverReasonInterfaceDown indicates interface went down.
	FailoverReasonInterfaceDown FailoverReason = "INTERFACE_DOWN"
	// FailoverReasonDNSFailure indicates DNS resolution failure.
	FailoverReasonDNSFailure FailoverReason = "DNS_FAILURE"
	// FailoverReasonScheduled indicates scheduled maintenance.
	FailoverReasonScheduled FailoverReason = "SCHEDULED"
	// FailoverReasonAdministrative indicates administrative action.
	FailoverReasonAdministrative FailoverReason = "ADMINISTRATIVE"
	// FailoverReasonRecovery indicates returning to primary after recovery.
	FailoverReasonRecovery FailoverReason = "RECOVERY"
)

// String returns the string representation.
func (r FailoverReason) String() string {
	return string(r)
}

// FailoverTrigger represents who/what triggered the failover.
type FailoverTrigger string

const (
	FailoverTriggerAutomatic FailoverTrigger = "automatic"
	FailoverTriggerManual    FailoverTrigger = "manual"
	FailoverTriggerScheduled FailoverTrigger = "scheduled"
	FailoverTriggerAPI       FailoverTrigger = "api"
)

// FailoverEvent represents a failover event record.
type FailoverEvent struct {
	// Identity
	EventID string `json:"event_id" yaml:"event_id" db:"event_id"`

	// WAN interfaces
	FromWANID    string `json:"from_wan_id,omitempty" yaml:"from_wan_id,omitempty" db:"from_wan_id"`
	FromWAN      string `json:"from_wan" yaml:"from_wan" db:"from_wan_name"`
	FromWANAlias string `json:"from_wan_alias,omitempty" yaml:"from_wan_alias,omitempty"`
	ToWANID      string `json:"to_wan_id,omitempty" yaml:"to_wan_id,omitempty" db:"to_wan_id"`
	ToWAN        string `json:"to_wan" yaml:"to_wan" db:"to_wan_name"`
	ToWANAlias   string `json:"to_wan_alias,omitempty" yaml:"to_wan_alias,omitempty"`

	// Reason and trigger
	Reason      FailoverReason  `json:"reason" yaml:"reason" db:"reason"`
	TriggeredBy FailoverTrigger `json:"triggered_by" yaml:"triggered_by" db:"triggered_by"`

	// Timestamps
	TriggeredAt time.Time  `json:"triggered_at" yaml:"triggered_at" db:"triggered_at"`
	CompletedAt *time.Time `json:"completed_at,omitempty" yaml:"completed_at,omitempty" db:"completed_at"`

	// Duration and impact
	DurationSeconds     int   `json:"duration_seconds,omitempty" yaml:"duration_seconds,omitempty" db:"duration_seconds"`
	RecoveryTimeMs      int   `json:"recovery_time_ms,omitempty" yaml:"recovery_time_ms,omitempty" db:"recovery_time_ms"`
	AffectedConnections int64 `json:"affected_connections" yaml:"affected_connections" db:"affected_connections"`
	MigratedConnections int64 `json:"migrated_connections,omitempty" yaml:"migrated_connections,omitempty" db:"migrated_connections"`
	DroppedConnections  int64 `json:"dropped_connections,omitempty" yaml:"dropped_connections,omitempty" db:"dropped_connections"`

	// Outcome
	Success      bool   `json:"success" yaml:"success" db:"success"`
	ErrorMessage string `json:"error_message,omitempty" yaml:"error_message,omitempty" db:"error_message"`
	Notes        string `json:"notes,omitempty" yaml:"notes,omitempty" db:"notes"`
}

// Duration returns the failover duration.
func (e *FailoverEvent) Duration() time.Duration {
	if e.CompletedAt == nil {
		return time.Since(e.TriggeredAt)
	}
	return e.CompletedAt.Sub(e.TriggeredAt)
}

// FailoverState represents the current failover state machine state.
type FailoverState string

const (
	// FailoverStatePrimaryActive means primary WAN is active.
	FailoverStatePrimaryActive FailoverState = "PRIMARY_ACTIVE"
	// FailoverStateFailover means system is in failover to backup.
	FailoverStateFailover FailoverState = "FAILOVER"
	// FailoverStateRecovering means primary is recovering.
	FailoverStateRecovering FailoverState = "RECOVERING"
	// FailoverStateManualOverride means manual override is active.
	FailoverStateManualOverride FailoverState = "MANUAL_OVERRIDE"
)

// =============================================================================
// Load Balancer Statistics
// =============================================================================

// WANStats represents traffic statistics for a WAN interface.
type WANStats struct {
	// Identity
	InterfaceID    string `json:"interface_id,omitempty" yaml:"interface_id,omitempty"`
	InterfaceName  string `json:"interface_name" yaml:"interface_name"`
	InterfaceAlias string `json:"interface_alias,omitempty" yaml:"interface_alias,omitempty"`

	// Weight and distribution
	ConfiguredWeight        int     `json:"configured_weight,omitempty" yaml:"configured_weight,omitempty"`
	TargetTrafficPercentage float64 `json:"target_traffic_percentage,omitempty" yaml:"target_traffic_percentage,omitempty"`
	ActualTrafficPercentage float64 `json:"actual_traffic_percentage" yaml:"actual_traffic_percentage"`

	// Connection counts
	ActiveConnections int64 `json:"active_connections" yaml:"active_connections"`
	TotalConnections  int64 `json:"total_connections,omitempty" yaml:"total_connections,omitempty"`

	// Traffic volume
	TotalBytesSent     uint64 `json:"total_bytes_sent" yaml:"total_bytes_sent"`
	TotalBytesReceived uint64 `json:"total_bytes_received" yaml:"total_bytes_received"`

	// Throughput
	CurrentThroughputMbps float64 `json:"current_throughput_mbps,omitempty" yaml:"current_throughput_mbps,omitempty"`
	MaxThroughputMbps     float64 `json:"max_throughput_mbps,omitempty" yaml:"max_throughput_mbps,omitempty"`
	SaturationPercent     float64 `json:"saturation_percent,omitempty" yaml:"saturation_percent,omitempty"`

	// Latency
	AverageLatencyMs float64 `json:"average_latency_ms,omitempty" yaml:"average_latency_ms,omitempty"`

	// Timestamp
	CollectedAt time.Time `json:"collected_at,omitempty" yaml:"collected_at,omitempty"`
}

// TotalBytes returns total bytes transferred.
func (s *WANStats) TotalBytes() uint64 {
	return s.TotalBytesSent + s.TotalBytesReceived
}

// LoadBalancerStats represents aggregated load balancer statistics.
type LoadBalancerStats struct {
	CurrentMode           LoadBalancingMode `json:"current_mode"`
	WANStats              []WANStats        `json:"wan_stats"`
	TotalConnections      int64             `json:"total_connections"`
	TotalBytesTransferred uint64            `json:"total_bytes_transferred"`
	StatsSince            time.Time         `json:"stats_since"`
	CollectedAt           time.Time         `json:"collected_at"`
}

// =============================================================================
// Session Affinity Types
// =============================================================================

// SessionAffinity represents session-to-WAN affinity binding.
type SessionAffinity struct {
	Key             string    `json:"key"` // Hash key (e.g., src IP)
	WANInterface    string    `json:"wan_interface"`
	CreatedAt       time.Time `json:"created_at"`
	LastUsed        time.Time `json:"last_used"`
	ExpiresAt       time.Time `json:"expires_at"`
	ConnectionCount int       `json:"connection_count"`
}
