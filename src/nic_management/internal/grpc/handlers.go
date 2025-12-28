// Package grpc provides gRPC server and handlers for the NIC Management service.
package grpc

import (
	"context"
	"errors"
	"fmt"
	"net"
	"sync"
	"time"

	"safeops/nic_management/internal/configuration"
	"safeops/nic_management/internal/discovery"
	"safeops/nic_management/internal/failover"
	"safeops/nic_management/internal/integration"
	"safeops/nic_management/internal/performance"
)

// =============================================================================
// Handler Error Types
// =============================================================================

var (
	// ErrInterfaceNotFound indicates interface not found.
	ErrInterfaceNotFound = errors.New("interface not found")
	// ErrInvalidIPAddress indicates invalid IP address format.
	ErrInvalidIPAddress = errors.New("invalid IP address format")
	// ErrInvalidNetmask indicates invalid netmask.
	ErrInvalidNetmask = errors.New("invalid netmask")
	// ErrFailoverTargetDown indicates failover target is down.
	ErrFailoverTargetDown = errors.New("failover target interface is down")
	// ErrServiceUnavailable indicates service is unavailable.
	ErrServiceUnavailable = errors.New("service unavailable")
	// ErrPermissionDenied indicates permission denied.
	ErrPermissionDenied = errors.New("permission denied")
)

// =============================================================================
// Interface Type Filter Constants
// =============================================================================

// InterfaceTypeFilter for filtering interfaces.
type InterfaceTypeFilter string

const (
	InterfaceFilterAll          InterfaceTypeFilter = "ALL"
	InterfaceFilterWANOnly      InterfaceTypeFilter = "WAN_ONLY"
	InterfaceFilterLANOnly      InterfaceTypeFilter = "LAN_ONLY"
	InterfaceFilterPhysicalOnly InterfaceTypeFilter = "PHYSICAL_ONLY"
	InterfaceFilterVirtualOnly  InterfaceTypeFilter = "VIRTUAL_ONLY"
)

// =============================================================================
// Time Range Constants
// =============================================================================

// TimeRange for historical stats queries.
type TimeRange string

const (
	TimeRangeLastMinute TimeRange = "LAST_MINUTE"
	TimeRangeLastHour   TimeRange = "LAST_HOUR"
	TimeRangeLastDay    TimeRange = "LAST_DAY"
)

// =============================================================================
// Request Structures
// =============================================================================

// ListInterfacesRequest contains parameters for listing interfaces.
type ListInterfacesRequest struct {
	InterfaceType   InterfaceTypeFilter `json:"interface_type"`
	IncludeDisabled bool                `json:"include_disabled"`
}

// GetStatsRequest contains parameters for getting interface stats.
type GetStatsRequest struct {
	InterfaceID string    `json:"interface_id"`
	TimeRange   TimeRange `json:"time_range,omitempty"`
}

// ConfigureInterfaceRequest contains interface configuration parameters.
type ConfigureInterfaceRequest struct {
	InterfaceID string   `json:"interface_id"`
	IPAddress   string   `json:"ip_address,omitempty"`
	Netmask     string   `json:"netmask,omitempty"`
	Gateway     string   `json:"gateway,omitempty"`
	DNSServers  []string `json:"dns_servers,omitempty"`
	MTU         int      `json:"mtu,omitempty"`
	DHCPEnabled bool     `json:"dhcp_enabled"`
}

// GetNATMappingsRequest contains NAT query parameters.
type GetNATMappingsRequest struct {
	WANInterface string `json:"wan_interface,omitempty"`
	Protocol     string `json:"protocol,omitempty"`
	PageSize     int    `json:"page_size"`
	PageToken    string `json:"page_token,omitempty"`
}

// TriggerFailoverRequest contains failover parameters.
type TriggerFailoverRequest struct {
	TargetWAN string `json:"target_wan"`
	Reason    string `json:"reason"`
	Force     bool   `json:"force"`
}

// UnblockIPSRequest contains unblock parameters.
type UnblockIPSRequest struct {
	SourceIP string `json:"source_ip"`
	Reason   string `json:"reason"`
}

// =============================================================================
// Response Structures
// =============================================================================

// InterfaceInfo contains interface details.
type InterfaceInfo struct {
	ID         string `json:"id"`
	Name       string `json:"name"`
	Type       string `json:"type"` // WAN or LAN
	Role       string `json:"role"` // PRIMARY, BACKUP, NONE
	MACAddress string `json:"mac_address"`
	IPAddress  string `json:"ip_address"`
	Netmask    string `json:"netmask"`
	Gateway    string `json:"gateway,omitempty"`
	Status     string `json:"status"` // UP or DOWN
	LinkSpeed  int64  `json:"link_speed"`
	Duplex     string `json:"duplex"`
	IsPhysical bool   `json:"is_physical"`
	MTU        int    `json:"mtu"`
}

// InterfaceList contains a list of interfaces.
type InterfaceList struct {
	Interfaces []*InterfaceInfo `json:"interfaces"`
	Count      int              `json:"count"`
}

// InterfaceStats contains interface statistics.
type InterfaceStats struct {
	InterfaceID         string    `json:"interface_id"`
	RxBytes             uint64    `json:"rx_bytes"`
	TxBytes             uint64    `json:"tx_bytes"`
	RxPackets           uint64    `json:"rx_packets"`
	TxPackets           uint64    `json:"tx_packets"`
	RxErrors            uint64    `json:"rx_errors"`
	TxErrors            uint64    `json:"tx_errors"`
	RxDrops             uint64    `json:"rx_drops"`
	TxDrops             uint64    `json:"tx_drops"`
	Collisions          uint64    `json:"collisions"`
	CurrentThroughputRx float64   `json:"current_throughput_rx"`
	CurrentThroughputTx float64   `json:"current_throughput_tx"`
	AvgPacketRate       float64   `json:"avg_packet_rate"`
	Timestamp           time.Time `json:"timestamp"`
}

// ConfigureResponse contains configuration result.
type ConfigureResponse struct {
	Success       bool                   `json:"success"`
	InterfaceID   string                 `json:"interface_id"`
	AppliedConfig map[string]interface{} `json:"applied_config"`
	Message       string                 `json:"message,omitempty"`
}

// NATMapping contains NAT translation info.
type NATMapping struct {
	LanIP            string    `json:"lan_ip"`
	LanPort          uint16    `json:"lan_port"`
	WanIP            string    `json:"wan_ip"`
	WanPort          uint16    `json:"wan_port"`
	Protocol         string    `json:"protocol"`
	ExternalIP       string    `json:"external_ip"`
	ExternalPort     uint16    `json:"external_port"`
	State            string    `json:"state"`
	CreatedAt        time.Time `json:"created_at"`
	LastActivity     time.Time `json:"last_activity"`
	BytesTransferred uint64    `json:"bytes_transferred"`
}

// NATMappingList contains paginated NAT mappings.
type NATMappingList struct {
	Mappings      []*NATMapping `json:"mappings"`
	Count         int           `json:"count"`
	NextPageToken string        `json:"next_page_token,omitempty"`
}

// FailoverResponse contains failover result.
type FailoverResponse struct {
	Success          bool   `json:"success"`
	AffectedSessions int    `json:"affected_sessions"`
	NewActiveWAN     string `json:"new_active_wan"`
	ExecutionTimeMs  int64  `json:"execution_time_ms"`
	Message          string `json:"message,omitempty"`
}

// WANHealth contains WAN interface health info.
type WANHealth struct {
	InterfaceID         string        `json:"interface_id"`
	Status              string        `json:"status"` // UP, DOWN, DEGRADED
	LatencyMs           float64       `json:"latency_ms"`
	PacketLossPercent   float64       `json:"packet_loss_percent"`
	LastHealthCheck     time.Time     `json:"last_health_check"`
	ConsecutiveFailures int           `json:"consecutive_failures"`
	Uptime              time.Duration `json:"uptime"`
}

// WANHealthResponse contains health for all WANs.
type WANHealthResponse struct {
	WANInterfaces []*WANHealth `json:"wan_interfaces"`
	Count         int          `json:"count"`
}

// UnblockResponse contains unblock result.
type UnblockResponse struct {
	Success bool   `json:"success"`
	Message string `json:"message,omitempty"`
}

// =============================================================================
// Handlers Configuration
// =============================================================================

// HandlersConfig contains handler configuration.
type HandlersConfig struct {
	MaxNATMappingsPerPage int  `json:"max_nat_mappings_per_page"`
	EnableManualFailover  bool `json:"enable_manual_failover"`
	RequireAdminForConfig bool `json:"require_admin_for_config"`
}

// DefaultHandlersConfig returns the default configuration.
func DefaultHandlersConfig() *HandlersConfig {
	return &HandlersConfig{
		MaxNATMappingsPerPage: 1000,
		EnableManualFailover:  true,
		RequireAdminForConfig: true,
	}
}

// =============================================================================
// Handlers
// =============================================================================

// Handlers manages unary RPC handlers.
type Handlers struct {
	// Dependencies.
	discoveryMonitor  *discovery.Monitor
	metricsAggregator *performance.MetricsAggregator
	failoverHandler   *failover.FailoverHandler
	configManager     *configuration.InterfaceConfigurator
	firewallHooks     *integration.FirewallHooks
	idsHooks          *integration.IDSHooks
	loggerHooks       *integration.LoggerHooks

	// Configuration.
	config *HandlersConfig

	// Mutex for thread safety.
	mu sync.RWMutex
}

// NewHandlers creates a new handlers instance.
func NewHandlers(
	discoveryMonitor *discovery.Monitor,
	metricsAggregator *performance.MetricsAggregator,
	failoverHandler *failover.FailoverHandler,
	configManager *configuration.InterfaceConfigurator,
	firewallHooks *integration.FirewallHooks,
	idsHooks *integration.IDSHooks,
	loggerHooks *integration.LoggerHooks,
	config *HandlersConfig,
) *Handlers {
	if config == nil {
		config = DefaultHandlersConfig()
	}

	return &Handlers{
		discoveryMonitor:  discoveryMonitor,
		metricsAggregator: metricsAggregator,
		failoverHandler:   failoverHandler,
		configManager:     configManager,
		firewallHooks:     firewallHooks,
		idsHooks:          idsHooks,
		loggerHooks:       loggerHooks,
		config:            config,
	}
}

// =============================================================================
// Interface Listing
// =============================================================================

// ListNetworkInterfaces returns all detected network interfaces.
func (h *Handlers) ListNetworkInterfaces(ctx context.Context, request *ListInterfacesRequest) (*InterfaceList, error) {
	_ = ctx // Used in production for deadline checking.

	if h.discoveryMonitor == nil {
		return nil, ErrServiceUnavailable
	}

	// Get current interface state from monitor.
	interfaceStates := h.discoveryMonitor.GetCurrentState()

	result := &InterfaceList{
		Interfaces: make([]*InterfaceInfo, 0, len(interfaceStates)),
	}

	for name, state := range interfaceStates {
		// Skip disabled unless requested.
		if !request.IncludeDisabled && state.OperStatus == "DOWN" {
			continue
		}

		// Get IP address.
		ipAddr := ""
		if len(state.IPAddresses) > 0 {
			ipAddr = state.IPAddresses[0]
		}

		info := &InterfaceInfo{
			ID:         name,
			Name:       state.InterfaceName,
			MACAddress: state.MACAddress,
			IPAddress:  ipAddr,
			Status:     state.OperStatus,
			LinkSpeed:  int64(state.SpeedMbps),
			IsPhysical: true, // Would be determined by classifier.
		}
		result.Interfaces = append(result.Interfaces, info)
	}

	result.Count = len(result.Interfaces)
	return result, nil
}

// =============================================================================
// Interface Statistics
// =============================================================================

// GetInterfaceStats retrieves statistics for a specific interface.
func (h *Handlers) GetInterfaceStats(ctx context.Context, request *GetStatsRequest) (*InterfaceStats, error) {
	_ = ctx // Used in production for deadline checking.

	if request.InterfaceID == "" {
		return nil, ErrInterfaceNotFound
	}

	// Validate interface exists.
	if h.discoveryMonitor != nil {
		states := h.discoveryMonitor.GetCurrentState()
		found := false
		for name := range states {
			if name == request.InterfaceID {
				found = true
				break
			}
		}
		if !found {
			return nil, ErrInterfaceNotFound
		}
	}

	stats := &InterfaceStats{
		InterfaceID: request.InterfaceID,
		Timestamp:   time.Now(),
	}

	// Get metrics from aggregator.
	if h.metricsAggregator != nil {
		metrics, err := h.metricsAggregator.GetAggregatedSnapshot(request.InterfaceID)
		if err == nil && metrics != nil {
			stats.CurrentThroughputRx = metrics.Throughput.RxMbps
			stats.CurrentThroughputTx = metrics.Throughput.TxMbps
			stats.AvgPacketRate = float64(metrics.PacketRate.TotalPacketsPerSec)
			stats.Timestamp = metrics.Timestamp
		}
	}

	return stats, nil
}

// =============================================================================
// Interface Configuration
// =============================================================================

// ConfigureInterface configures an interface's IP settings.
func (h *Handlers) ConfigureInterface(ctx context.Context, request *ConfigureInterfaceRequest) (*ConfigureResponse, error) {
	if request.InterfaceID == "" {
		return nil, ErrInterfaceNotFound
	}

	// Validate IP address if provided.
	if request.IPAddress != "" {
		if ip := net.ParseIP(request.IPAddress); ip == nil {
			return nil, ErrInvalidIPAddress
		}
	}

	// Validate netmask if provided.
	if request.Netmask != "" {
		if ip := net.ParseIP(request.Netmask); ip == nil {
			return nil, ErrInvalidNetmask
		}
	}

	// Validate gateway if provided.
	if request.Gateway != "" {
		if ip := net.ParseIP(request.Gateway); ip == nil {
			return nil, fmt.Errorf("invalid gateway address")
		}
	}

	// Validate DNS servers.
	for _, dns := range request.DNSServers {
		if ip := net.ParseIP(dns); ip == nil {
			return nil, fmt.Errorf("invalid DNS server address: %s", dns)
		}
	}

	// Apply configuration.
	if h.configManager != nil {
		ipv4Config := &configuration.IPv4Configuration{
			Address:     net.ParseIP(request.IPAddress),
			Netmask:     net.IPMask(net.ParseIP(request.Netmask).To4()),
			Gateway:     net.ParseIP(request.Gateway),
			DHCPEnabled: request.DHCPEnabled,
		}

		config := &configuration.InterfaceConfig{
			InterfaceName: request.InterfaceID,
			IPv4Config:    ipv4Config,
			MTU:           request.MTU,
			State:         configuration.InterfaceStateUp,
			ConfigMethod:  configuration.ConfigMethodStatic,
		}

		if request.DHCPEnabled {
			config.ConfigMethod = configuration.ConfigMethodDHCP
		}

		err := h.configManager.ConfigureInterface(ctx, config)
		if err != nil {
			return &ConfigureResponse{
				Success:     false,
				InterfaceID: request.InterfaceID,
				Message:     err.Error(),
			}, nil
		}
	}

	return &ConfigureResponse{
		Success:     true,
		InterfaceID: request.InterfaceID,
		AppliedConfig: map[string]interface{}{
			"ip_address":   request.IPAddress,
			"netmask":      request.Netmask,
			"gateway":      request.Gateway,
			"dns_servers":  request.DNSServers,
			"mtu":          request.MTU,
			"dhcp_enabled": request.DHCPEnabled,
		},
		Message: "Configuration applied successfully",
	}, nil
}

// =============================================================================
// NAT Mappings
// =============================================================================

// GetNATMappings retrieves active NAT mappings.
func (h *Handlers) GetNATMappings(ctx context.Context, request *GetNATMappingsRequest) (*NATMappingList, error) {
	_ = ctx // Used in production for deadline checking.

	// Set defaults.
	if request.PageSize <= 0 {
		request.PageSize = 100
	}
	if request.PageSize > h.config.MaxNATMappingsPerPage {
		request.PageSize = h.config.MaxNATMappingsPerPage
	}

	// In production, would query NAT mapping table:
	// mappings := h.natMappingTable.GetActiveMappings(filters, pagination)

	// Stub: Return empty list.
	return &NATMappingList{
		Mappings: make([]*NATMapping, 0),
		Count:    0,
	}, nil
}

// =============================================================================
// WAN Failover
// =============================================================================

// TriggerFailover manually triggers a WAN failover.
func (h *Handlers) TriggerFailover(ctx context.Context, request *TriggerFailoverRequest) (*FailoverResponse, error) {
	if !h.config.EnableManualFailover {
		return nil, ErrPermissionDenied
	}

	if request.TargetWAN == "" {
		return nil, fmt.Errorf("target WAN interface required")
	}

	startTime := time.Now()

	// Validate target WAN exists and is UP (unless force).
	if h.discoveryMonitor != nil && !request.Force {
		states := h.discoveryMonitor.GetCurrentState()
		state, exists := states[request.TargetWAN]
		if !exists {
			return nil, ErrInterfaceNotFound
		}
		if state.OperStatus != "UP" {
			return nil, ErrFailoverTargetDown
		}
	}

	// Trigger failover.
	var affectedSessions int
	if h.failoverHandler != nil {
		// Get the current active WAN as primary.
		primaryWAN := "" // Would be determined from routing state.
		result, err := h.failoverHandler.ExecuteFailover(ctx, primaryWAN, request.TargetWAN, request.Reason)
		if err != nil {
			return &FailoverResponse{
				Success: false,
				Message: err.Error(),
			}, nil
		}
		affectedSessions = result.FlowsReassigned
	}

	executionTime := time.Since(startTime).Milliseconds()

	return &FailoverResponse{
		Success:          true,
		AffectedSessions: affectedSessions,
		NewActiveWAN:     request.TargetWAN,
		ExecutionTimeMs:  executionTime,
		Message:          fmt.Sprintf("Manual failover to %s completed", request.TargetWAN),
	}, nil
}

// =============================================================================
// WAN Health Status
// =============================================================================

// GetWANHealthStatus retrieves health status for all WAN interfaces.
func (h *Handlers) GetWANHealthStatus(ctx context.Context) (*WANHealthResponse, error) {
	_ = ctx // Used in production for deadline checking.

	response := &WANHealthResponse{
		WANInterfaces: make([]*WANHealth, 0),
	}

	// Get WAN interfaces from discovery.
	if h.discoveryMonitor != nil {
		states := h.discoveryMonitor.GetCurrentState()
		for name, state := range states {
			health := &WANHealth{
				InterfaceID:     name,
				Status:          state.OperStatus,
				LastHealthCheck: time.Now(),
			}

			// Note: WAN health metrics would be populated from health checker.
			// For now, return basic status from interface state.

			response.WANInterfaces = append(response.WANInterfaces, health)
		}
	}

	response.Count = len(response.WANInterfaces)
	return response, nil
}

// =============================================================================
// Integration Stats
// =============================================================================

// GetQoSStats retrieves QoS enforcement statistics.
func (h *Handlers) GetQoSStats(ctx context.Context) (map[string]interface{}, error) {
	_ = ctx // Used in production for deadline checking.

	// QoS hooks not implemented yet, return stub.
	return map[string]interface{}{
		"enabled":            false,
		"packets_classified": 0,
		"dscp_marked":        0,
	}, nil
}

// GetFirewallStats retrieves firewall enforcement statistics.
func (h *Handlers) GetFirewallStats(ctx context.Context) (*integration.FirewallStats, error) {
	_ = ctx // Used in production for deadline checking.

	if h.firewallHooks == nil || !h.firewallHooks.IsEnabled() {
		return nil, ErrServiceUnavailable
	}

	return h.firewallHooks.GetFirewallStats(), nil
}

// GetIDSStats retrieves IDS/IPS enforcement statistics.
func (h *Handlers) GetIDSStats(ctx context.Context) (*integration.IDSStats, error) {
	_ = ctx // Used in production for deadline checking.

	if h.idsHooks == nil || !h.idsHooks.IsEnabled() {
		return nil, ErrServiceUnavailable
	}

	return h.idsHooks.GetIDSStats(), nil
}

// =============================================================================
// IPS Management
// =============================================================================

// UnblockIPSSource removes an IP from the IPS blocklist.
func (h *Handlers) UnblockIPSSource(ctx context.Context, request *UnblockIPSRequest) (*UnblockResponse, error) {
	_ = ctx // Used in production for deadline checking.

	if request.SourceIP == "" {
		return nil, fmt.Errorf("source IP required")
	}

	// Validate IP format.
	ip := net.ParseIP(request.SourceIP)
	if ip == nil {
		return nil, ErrInvalidIPAddress
	}

	if h.idsHooks == nil {
		return nil, ErrServiceUnavailable
	}

	err := h.idsHooks.UnblockSource(ip)
	if err != nil {
		return &UnblockResponse{
			Success: false,
			Message: err.Error(),
		}, nil
	}

	// Log the unblock action.
	if h.loggerHooks != nil {
		h.loggerHooks.LogInterfaceStateChange(
			request.SourceIP,
			integration.InterfaceEventUp, // Reusing for unblock event.
			"BLOCKED",
			"UNBLOCKED",
			map[string]interface{}{
				"reason": request.Reason,
				"action": "manual_unblock",
			},
		)
	}

	return &UnblockResponse{
		Success: true,
		Message: fmt.Sprintf("IP %s unblocked from IPS blocklist", request.SourceIP),
	}, nil
}

// =============================================================================
// Logger Stats
// =============================================================================

// GetLoggerStats retrieves logger integration statistics.
func (h *Handlers) GetLoggerStats(ctx context.Context) (*integration.LoggerStats, error) {
	_ = ctx // Used in production for deadline checking.

	if h.loggerHooks == nil {
		return nil, ErrServiceUnavailable
	}

	return h.loggerHooks.GetLoggerStats(), nil
}

// =============================================================================
// Health Check
// =============================================================================

// HealthCheck verifies handlers are operational.
func (h *Handlers) HealthCheck() error {
	// Check core dependencies.
	if h.discoveryMonitor == nil {
		return errors.New("discovery monitor not available")
	}
	return nil
}

// GetConfig returns the current configuration.
func (h *Handlers) GetConfig() *HandlersConfig {
	return h.config
}
