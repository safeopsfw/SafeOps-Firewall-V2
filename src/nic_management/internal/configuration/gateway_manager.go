// Package configuration provides network interface configuration management
// for the NIC Management service.
package configuration

import (
	"context"
	"errors"
	"fmt"
	"net"
	"sync"
	"sync/atomic"
	"time"
)

// =============================================================================
// Gateway Error Types
// =============================================================================

var (
	// ErrInterfaceNotWAN indicates interface is not classified as WAN type.
	ErrInterfaceNotWAN = errors.New("interface is not WAN type")
	// ErrRouteAddFailed indicates unable to add route to routing table.
	ErrRouteAddFailed = errors.New("route add failed")
	// ErrRouteDeleteFailed indicates unable to remove route from routing table.
	ErrRouteDeleteFailed = errors.New("route delete failed")
	// ErrMultipleGatewaysNotAllowed indicates secondary gateway not permitted.
	ErrMultipleGatewaysNotAllowed = errors.New("multiple gateways not allowed")
	// ErrInvalidMetricValue indicates route metric outside valid range.
	ErrInvalidMetricValue = errors.New("invalid metric value")
	// ErrGatewayNotConfigured indicates no default gateway configured.
	ErrGatewayNotConfigured = errors.New("gateway not configured")
	// ErrGatewayAlreadyActive indicates gateway is already the active one.
	ErrGatewayAlreadyActive = errors.New("gateway already active")
)

// =============================================================================
// Gateway Source Enumeration
// =============================================================================

// GatewaySource represents how gateway configuration was established.
type GatewaySource int

const (
	// GatewaySourceStatic indicates manually configured static gateway.
	GatewaySourceStatic GatewaySource = iota
	// GatewaySourceDHCP indicates gateway received from DHCP server.
	GatewaySourceDHCP
	// GatewaySourceFailover indicates gateway configured by failover manager.
	GatewaySourceFailover
	// GatewaySourceAdmin indicates gateway set by administrator via API.
	GatewaySourceAdmin
	// GatewaySourceAuto indicates automatically detected from interface.
	GatewaySourceAuto
)

// String returns the string representation of the gateway source.
func (s GatewaySource) String() string {
	switch s {
	case GatewaySourceStatic:
		return "STATIC"
	case GatewaySourceDHCP:
		return "DHCP"
	case GatewaySourceFailover:
		return "FAILOVER"
	case GatewaySourceAdmin:
		return "ADMIN"
	case GatewaySourceAuto:
		return "AUTO"
	default:
		return "UNKNOWN"
	}
}

// =============================================================================
// Gateway Configuration Structure
// =============================================================================

// GatewayConfiguration contains complete gateway configuration for an interface.
type GatewayConfiguration struct {
	// InterfaceName is the interface serving as gateway.
	InterfaceName string `json:"interface_name"`
	// GatewayIP is the gateway IP address.
	GatewayIP net.IP `json:"gateway_ip"`
	// Metric is the route metric (priority, lower = higher priority).
	Metric int `json:"metric"`
	// IsDefault indicates whether this is the default route.
	IsDefault bool `json:"is_default"`
	// IPVersion is the IP version (4 or 6).
	IPVersion int `json:"ip_version"`
	// ConfiguredAt is when gateway was configured.
	ConfiguredAt time.Time `json:"configured_at,omitempty"`
	// Source indicates how gateway was configured.
	Source GatewaySource `json:"source"`
	// IsActive indicates whether currently active in routing table.
	IsActive bool `json:"is_active"`
	// LastValidated is when gateway was last validated reachable.
	LastValidated time.Time `json:"last_validated,omitempty"`
}

// =============================================================================
// Gateway Change Event Structure
// =============================================================================

// GatewayChangeEvent records a gateway configuration change.
type GatewayChangeEvent struct {
	// EventID is the unique event identifier.
	EventID string `json:"event_id"`
	// Timestamp is when change occurred.
	Timestamp time.Time `json:"timestamp"`
	// OldGateway is the previous gateway.
	OldGateway *GatewayConfiguration `json:"old_gateway,omitempty"`
	// NewGateway is the new gateway.
	NewGateway *GatewayConfiguration `json:"new_gateway,omitempty"`
	// ChangeReason is why changed.
	ChangeReason string `json:"change_reason"`
	// TriggeredBy indicates who/what triggered the change.
	TriggeredBy string `json:"triggered_by"`
	// Success indicates whether change completed successfully.
	Success bool `json:"success"`
	// ErrorMessage contains error details if failed.
	ErrorMessage string `json:"error_message,omitempty"`
}

// =============================================================================
// Gateway Manager Configuration
// =============================================================================

// GatewayConfig contains configuration for gateway management behavior.
type GatewayConfig struct {
	// ValidateGatewayReachability pings gateway before activation (default: true).
	ValidateGatewayReachability bool `json:"validate_gateway_reachability"`
	// GatewayPingTimeout is max time for gateway ping validation (default: 5s).
	GatewayPingTimeout time.Duration `json:"gateway_ping_timeout"`
	// GatewayPingCount is number of ping packets to send (default: 3).
	GatewayPingCount int `json:"gateway_ping_count"`
	// AllowMultipleGateways permits multiple default routes (default: false).
	AllowMultipleGateways bool `json:"allow_multiple_gateways"`
	// DefaultMetric is the default route metric value (default: 100).
	DefaultMetric int `json:"default_metric"`
	// WANGatewayMetricOffset is metric increment for additional WAN gateways (default: 10).
	WANGatewayMetricOffset int `json:"wan_gateway_metric_offset"`
	// EnableAutomaticFailover auto-switches gateway on WAN failure (default: true).
	EnableAutomaticFailover bool `json:"enable_automatic_failover"`
	// FailoverDelay is wait before switching to backup gateway (default: 0s).
	FailoverDelay time.Duration `json:"failover_delay"`
	// EnablePersistence saves gateway config to database (default: true).
	EnablePersistence bool `json:"enable_persistence"`
	// RestoreOnStartup restores persisted gateway on start (default: true).
	RestoreOnStartup bool `json:"restore_on_startup"`
	// SyncWithRoutingEngine coordinates with routing engine (default: true).
	SyncWithRoutingEngine bool `json:"sync_with_routing_engine"`
}

// DefaultGatewayConfig returns the default gateway manager configuration.
func DefaultGatewayConfig() *GatewayConfig {
	return &GatewayConfig{
		ValidateGatewayReachability: true,
		GatewayPingTimeout:          5 * time.Second,
		GatewayPingCount:            3,
		AllowMultipleGateways:       false,
		DefaultMetric:               100,
		WANGatewayMetricOffset:      10,
		EnableAutomaticFailover:     true,
		FailoverDelay:               0,
		EnablePersistence:           true,
		RestoreOnStartup:            true,
		SyncWithRoutingEngine:       true,
	}
}

// =============================================================================
// WAN Selector Interface
// =============================================================================

// WANSelectorInterface defines WAN selector operations needed by gateway manager.
type WANSelectorInterface interface {
	// WANExists checks if a WAN interface exists.
	WANExists(wanID string) bool
	// GetWANGateway returns the gateway IP for a WAN.
	GetWANGateway(wanID string) (net.IP, error)
	// IsWANInterface checks if interface is classified as WAN.
	IsWANInterface(interfaceName string) bool
}

// GatewayDBInterface defines database operations for gateway persistence.
type GatewayDBInterface interface {
	// LoadGatewayConfiguration loads persisted gateway configuration.
	LoadGatewayConfiguration(ctx context.Context) (*GatewayConfiguration, error)
	// SaveGatewayConfiguration saves gateway configuration.
	SaveGatewayConfiguration(ctx context.Context, config *GatewayConfiguration) error
	// SaveGatewayChangeEvent saves a gateway change event.
	SaveGatewayChangeEvent(ctx context.Context, event *GatewayChangeEvent) error
}

// =============================================================================
// No-Op Implementations
// =============================================================================

type noOpWANSelectorGateway struct{}

func (n *noOpWANSelectorGateway) WANExists(wanID string) bool {
	return true
}

func (n *noOpWANSelectorGateway) GetWANGateway(wanID string) (net.IP, error) {
	return net.ParseIP("192.168.1.1"), nil
}

func (n *noOpWANSelectorGateway) IsWANInterface(interfaceName string) bool {
	return true
}

type noOpGatewayDB struct{}

func (n *noOpGatewayDB) LoadGatewayConfiguration(ctx context.Context) (*GatewayConfiguration, error) {
	return nil, nil
}

func (n *noOpGatewayDB) SaveGatewayConfiguration(ctx context.Context, config *GatewayConfiguration) error {
	return nil
}

func (n *noOpGatewayDB) SaveGatewayChangeEvent(ctx context.Context, event *GatewayChangeEvent) error {
	return nil
}

// =============================================================================
// Gateway Manager
// =============================================================================

// GatewayManager manages default gateway configuration.
type GatewayManager struct {
	// Dependencies.
	wanSelector WANSelectorInterface
	db          GatewayDBInterface

	// Configuration.
	config *GatewayConfig

	// State.
	activeGateway    *GatewayConfiguration
	secondaryGateway *GatewayConfiguration
	mu               sync.RWMutex

	// History.
	gatewayHistory   []*GatewayChangeEvent
	gatewayHistoryMu sync.RWMutex

	// Platform.
	platform Platform

	// Statistics.
	gatewayChanges         uint64
	validationSuccesses    uint64
	validationFailures     uint64
	failoverGatewayChanges uint64
	recoveryGatewayChanges uint64

	// Control.
	stopChan  chan struct{}
	running   bool
	runningMu sync.Mutex
}

// NewGatewayManager creates a new gateway manager.
func NewGatewayManager(
	wanSelector WANSelectorInterface,
	db GatewayDBInterface,
	config *GatewayConfig,
) *GatewayManager {
	if config == nil {
		config = DefaultGatewayConfig()
	}

	if wanSelector == nil {
		wanSelector = &noOpWANSelectorGateway{}
	}

	if db == nil {
		db = &noOpGatewayDB{}
	}

	return &GatewayManager{
		wanSelector:    wanSelector,
		db:             db,
		config:         config,
		gatewayHistory: make([]*GatewayChangeEvent, 0, 500),
		platform:       DetectPlatform(),
		stopChan:       make(chan struct{}),
	}
}

// =============================================================================
// Lifecycle Management
// =============================================================================

// Start initializes the gateway manager.
func (gm *GatewayManager) Start(ctx context.Context) error {
	gm.runningMu.Lock()
	defer gm.runningMu.Unlock()

	if gm.running {
		return nil
	}

	// Validate platform support.
	if gm.platform == PlatformUnknown {
		return ErrPlatformUnsupported
	}

	// Load persisted gateway configuration if enabled.
	if gm.config.RestoreOnStartup {
		persistedConfig, err := gm.db.LoadGatewayConfiguration(ctx)
		if err == nil && persistedConfig != nil {
			// Validate interface still exists.
			if gm.wanSelector.WANExists(persistedConfig.InterfaceName) {
				// Restore gateway.
				_ = gm.SetDefaultGateway(ctx, persistedConfig)
			}
		}
	}

	// Detect current gateway if none restored.
	gm.mu.RLock()
	hasGateway := gm.activeGateway != nil
	gm.mu.RUnlock()

	if !hasGateway {
		currentGateway, err := gm.getCurrentGatewayFromOS()
		if err == nil && currentGateway != nil {
			gm.mu.Lock()
			gm.activeGateway = currentGateway
			gm.mu.Unlock()
		}
	}

	gm.running = true
	return nil
}

// Stop shuts down the gateway manager.
func (gm *GatewayManager) Stop() error {
	gm.runningMu.Lock()
	if !gm.running {
		gm.runningMu.Unlock()
		return nil
	}
	gm.running = false
	gm.runningMu.Unlock()

	close(gm.stopChan)

	// Persist current gateway configuration.
	if gm.config.EnablePersistence {
		gm.mu.RLock()
		gateway := gm.activeGateway
		gm.mu.RUnlock()

		if gateway != nil {
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			_ = gm.db.SaveGatewayConfiguration(ctx, gateway)
		}
	}

	return nil
}

// =============================================================================
// Gateway Configuration
// =============================================================================

// SetDefaultGateway configures default route for internet egress.
func (gm *GatewayManager) SetDefaultGateway(ctx context.Context, config *GatewayConfiguration) error {
	if config == nil {
		return errors.New("gateway configuration cannot be nil")
	}

	if config.GatewayIP == nil {
		return errors.New("gateway IP cannot be nil")
	}

	if config.InterfaceName == "" {
		return errors.New("interface name cannot be empty")
	}

	// Validate interface is WAN type.
	if !gm.wanSelector.IsWANInterface(config.InterfaceName) {
		return fmt.Errorf("%w: %s", ErrInterfaceNotWAN, config.InterfaceName)
	}

	// Set defaults.
	if config.Metric == 0 {
		config.Metric = gm.config.DefaultMetric
	}
	if config.IPVersion == 0 {
		if config.GatewayIP.To4() != nil {
			config.IPVersion = 4
		} else {
			config.IPVersion = 6
		}
	}

	atomic.AddUint64(&gm.gatewayChanges, 1)

	// Step 1: Validate gateway reachability.
	if gm.config.ValidateGatewayReachability {
		if err := gm.validateGatewayReachability(config.GatewayIP); err != nil {
			atomic.AddUint64(&gm.validationFailures, 1)
			return fmt.Errorf("%w: %v", ErrGatewayUnreachable, err)
		}
		atomic.AddUint64(&gm.validationSuccesses, 1)
		config.LastValidated = time.Now()
	}

	// Step 2: Backup current gateway and remove if not allowing multiple.
	gm.mu.Lock()
	oldGateway := gm.activeGateway
	gm.mu.Unlock()

	if !gm.config.AllowMultipleGateways && oldGateway != nil {
		if err := gm.removeDefaultGateway(); err != nil {
			// Log but continue - may be already removed.
			_ = err
		}
	}

	// Step 3: Add new default gateway.
	var err error
	switch gm.platform {
	case PlatformLinux:
		err = gm.setDefaultGatewayLinux(config)
	case PlatformWindows:
		err = gm.setDefaultGatewayWindows(config)
	default:
		err = ErrPlatformUnsupported
	}

	if err != nil {
		// Rollback if we removed old gateway.
		if oldGateway != nil && !gm.config.AllowMultipleGateways {
			switch gm.platform {
			case PlatformLinux:
				_ = gm.setDefaultGatewayLinux(oldGateway)
			case PlatformWindows:
				_ = gm.setDefaultGatewayWindows(oldGateway)
			}
		}
		gm.recordEvent(oldGateway, config, "SET_GATEWAY", "system", false, err.Error())
		return fmt.Errorf("%w: %v", ErrRouteAddFailed, err)
	}

	// Step 4: Update state.
	gm.mu.Lock()
	config.IsActive = true
	config.ConfiguredAt = time.Now()
	config.IsDefault = true
	gm.activeGateway = config
	gm.mu.Unlock()

	// Step 5: Persist configuration.
	if gm.config.EnablePersistence {
		_ = gm.db.SaveGatewayConfiguration(ctx, config)
	}

	// Step 6: Record event.
	gm.recordEvent(oldGateway, config, "SET_GATEWAY", "system", true, "")

	return nil
}

func (gm *GatewayManager) setDefaultGatewayLinux(config *GatewayConfiguration) error {
	_ = config // Will be used in production implementation.

	// In production, this would use github.com/vishvananda/netlink:
	//
	// link, err := netlink.LinkByName(config.InterfaceName)
	// if err != nil {
	//     return err
	// }
	//
	// route := &netlink.Route{
	//     Dst:       nil, // default route (0.0.0.0/0)
	//     Gw:        config.GatewayIP,
	//     LinkIndex: link.Attrs().Index,
	//     Priority:  config.Metric,
	//     Scope:     netlink.SCOPE_UNIVERSE,
	//     Protocol:  netlink.RTPROT_STATIC,
	// }
	//
	// return netlink.RouteAdd(route)

	// For stub: Simulate successful route add.
	return nil
}

func (gm *GatewayManager) setDefaultGatewayWindows(config *GatewayConfiguration) error {
	_ = config // Will be used in production implementation.

	// In production, this would execute netsh commands:
	//
	// var cmd string
	// if config.IPVersion == 4 {
	//     cmd = fmt.Sprintf("netsh interface ipv4 add route 0.0.0.0/0 \"%s\" %s metric=%d",
	//         config.InterfaceName, config.GatewayIP.String(), config.Metric)
	// } else {
	//     cmd = fmt.Sprintf("netsh interface ipv6 add route ::/0 \"%s\" %s metric=%d",
	//         config.InterfaceName, config.GatewayIP.String(), config.Metric)
	// }
	//
	// return exec.Command("cmd", "/c", cmd).Run()

	// For stub: Simulate successful route add.
	return nil
}

// RemoveDefaultGateway removes default route from routing table.
func (gm *GatewayManager) RemoveDefaultGateway(ctx context.Context) error {
	gm.mu.RLock()
	gateway := gm.activeGateway
	gm.mu.RUnlock()

	if gateway == nil {
		return nil // No gateway to remove.
	}

	if err := gm.removeDefaultGateway(); err != nil {
		return err
	}

	gm.mu.Lock()
	oldGateway := gm.activeGateway
	gm.activeGateway = nil
	gm.mu.Unlock()

	gm.recordEvent(oldGateway, nil, "REMOVE_GATEWAY", "system", true, "")

	return nil
}

// removeDefaultGateway is the internal route removal function.
func (gm *GatewayManager) removeDefaultGateway() error {
	switch gm.platform {
	case PlatformLinux:
		return gm.removeDefaultGatewayLinux()
	case PlatformWindows:
		return gm.removeDefaultGatewayWindows()
	default:
		return ErrPlatformUnsupported
	}
}

// removeDefaultGatewayLinux removes default route on Linux.
func (gm *GatewayManager) removeDefaultGatewayLinux() error {
	// In production:
	//
	// routes, err := netlink.RouteList(nil, netlink.FAMILY_V4)
	// if err != nil {
	//     return err
	// }
	//
	// for _, route := range routes {
	//     if route.Dst == nil { // default route
	//         if err := netlink.RouteDel(&route); err != nil {
	//             return err
	//         }
	//     }
	// }

	return nil
}

// removeDefaultGatewayWindows removes default route on Windows.
func (gm *GatewayManager) removeDefaultGatewayWindows() error {
	// In production:
	//
	// exec.Command("netsh", "interface", "ipv4", "delete", "route",
	//     "0.0.0.0/0", gm.activeGateway.InterfaceName).Run()

	return nil
}

// =============================================================================
// Gateway Validation
// =============================================================================

// validateGatewayReachability checks if gateway IP is reachable.
func (gm *GatewayManager) validateGatewayReachability(gatewayIP net.IP) error {
	// In production, this would use ICMP ping:
	//
	// pinger, err := ping.NewPinger(gatewayIP.String())
	// if err != nil {
	//     return err
	// }
	//
	// pinger.Count = gm.config.GatewayPingCount
	// pinger.Timeout = gm.config.GatewayPingTimeout
	// pinger.SetPrivileged(true)
	//
	// err = pinger.Run()
	// if err != nil {
	//     return err
	// }
	//
	// stats := pinger.Statistics()
	// if stats.PacketsRecv == 0 {
	//     return ErrGatewayUnreachable
	// }

	// For stub: Assume gateway is reachable.
	_ = gatewayIP
	return nil
}

// =============================================================================
// Current Gateway Detection
// =============================================================================

// getCurrentGatewayFromOS queries OS for active default route.
func (gm *GatewayManager) getCurrentGatewayFromOS() (*GatewayConfiguration, error) {
	switch gm.platform {
	case PlatformLinux:
		return gm.getCurrentGatewayLinux()
	case PlatformWindows:
		return gm.getCurrentGatewayWindows()
	default:
		return nil, ErrPlatformUnsupported
	}
}

// getCurrentGatewayLinux gets current gateway on Linux.
func (gm *GatewayManager) getCurrentGatewayLinux() (*GatewayConfiguration, error) {
	// In production:
	//
	// routes, err := netlink.RouteList(nil, netlink.FAMILY_V4)
	// if err != nil {
	//     return nil, err
	// }
	//
	// var defaultRoute *netlink.Route
	// for _, route := range routes {
	//     if route.Dst == nil { // default route
	//         if defaultRoute == nil || route.Priority < defaultRoute.Priority {
	//             r := route
	//             defaultRoute = &r
	//         }
	//     }
	// }
	//
	// if defaultRoute == nil {
	//     return nil, nil
	// }
	//
	// link, _ := netlink.LinkByIndex(defaultRoute.LinkIndex)
	// return &GatewayConfiguration{
	//     InterfaceName: link.Attrs().Name,
	//     GatewayIP:     defaultRoute.Gw,
	//     Metric:        defaultRoute.Priority,
	//     IsDefault:     true,
	//     IPVersion:     4,
	//     IsActive:      true,
	//     Source:        GatewaySourceAuto,
	// }, nil

	return nil, nil
}

// getCurrentGatewayWindows gets current gateway on Windows.
func (gm *GatewayManager) getCurrentGatewayWindows() (*GatewayConfiguration, error) {
	// In production:
	//
	// output, err := exec.Command("route", "print").Output()
	// if err != nil {
	//     return nil, err
	// }
	//
	// // Parse output for default route (0.0.0.0)
	// // Extract gateway IP, interface, metric

	return nil, nil
}

// =============================================================================
// Failover Integration
// =============================================================================

// OnFailover handles failover event to backup WAN.
func (gm *GatewayManager) OnFailover(ctx context.Context, primaryWAN, backupWAN string) error {
	// Get backup WAN gateway IP.
	gatewayIP, err := gm.wanSelector.GetWANGateway(backupWAN)
	if err != nil {
		return err
	}

	atomic.AddUint64(&gm.failoverGatewayChanges, 1)

	config := &GatewayConfiguration{
		InterfaceName: backupWAN,
		GatewayIP:     gatewayIP,
		Metric:        gm.config.DefaultMetric,
		IsDefault:     true,
		IPVersion:     4,
		Source:        GatewaySourceFailover,
	}

	// Apply failover delay if configured.
	if gm.config.FailoverDelay > 0 {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(gm.config.FailoverDelay):
		}
	}

	err = gm.SetDefaultGateway(ctx, config)
	if err != nil {
		return err
	}

	// Record failover-specific event.
	gm.recordEvent(nil, config, "FAILOVER", "failover_manager", true, "")

	return nil
}

// OnRecovery handles recovery event to primary WAN.
func (gm *GatewayManager) OnRecovery(ctx context.Context, primaryWAN, backupWAN string) error {
	// Get primary WAN gateway IP.
	gatewayIP, err := gm.wanSelector.GetWANGateway(primaryWAN)
	if err != nil {
		return err
	}

	atomic.AddUint64(&gm.recoveryGatewayChanges, 1)

	config := &GatewayConfiguration{
		InterfaceName: primaryWAN,
		GatewayIP:     gatewayIP,
		Metric:        gm.config.DefaultMetric,
		IsDefault:     true,
		IPVersion:     4,
		Source:        GatewaySourceFailover,
	}

	err = gm.SetDefaultGateway(ctx, config)
	if err != nil {
		return err
	}

	// Record recovery-specific event.
	gm.recordEvent(nil, config, "WAN_RECOVERY", "recovery_manager", true, "")

	return nil
}

// =============================================================================
// Metric Management
// =============================================================================

// SetGatewayMetric changes route priority without changing gateway.
func (gm *GatewayManager) SetGatewayMetric(ctx context.Context, interfaceName string, metric int) error {
	if metric < 1 || metric > 9999 {
		return fmt.Errorf("%w: must be 1-9999, got %d", ErrInvalidMetricValue, metric)
	}

	gm.mu.RLock()
	gateway := gm.activeGateway
	gm.mu.RUnlock()

	if gateway == nil || gateway.InterfaceName != interfaceName {
		return ErrGatewayNotConfigured
	}

	// Remove and re-add with new metric.
	if err := gm.removeDefaultGateway(); err != nil {
		return err
	}

	gateway.Metric = metric
	return gm.SetDefaultGateway(ctx, gateway)
}

// =============================================================================
// Secondary Gateway
// =============================================================================

// AddSecondaryGateway adds additional default route with higher metric.
func (gm *GatewayManager) AddSecondaryGateway(ctx context.Context, config *GatewayConfiguration) error {
	if !gm.config.AllowMultipleGateways {
		return ErrMultipleGatewaysNotAllowed
	}

	gm.mu.RLock()
	activeGateway := gm.activeGateway
	gm.mu.RUnlock()

	if activeGateway != nil && config.Metric <= activeGateway.Metric {
		return fmt.Errorf("%w: secondary gateway metric must be higher than primary (%d)",
			ErrInvalidMetricValue, activeGateway.Metric)
	}

	// Add route without removing existing.
	var err error
	switch gm.platform {
	case PlatformLinux:
		err = gm.setDefaultGatewayLinux(config)
	case PlatformWindows:
		err = gm.setDefaultGatewayWindows(config)
	default:
		err = ErrPlatformUnsupported
	}

	if err != nil {
		return err
	}

	gm.mu.Lock()
	config.IsActive = true
	config.ConfiguredAt = time.Now()
	gm.secondaryGateway = config
	gm.mu.Unlock()

	gm.recordEvent(nil, config, "ADD_SECONDARY_GATEWAY", "system", true, "")

	return nil
}

// RemoveSecondaryGateway removes the secondary default route.
func (gm *GatewayManager) RemoveSecondaryGateway(ctx context.Context) error {
	gm.mu.Lock()
	secondary := gm.secondaryGateway
	gm.secondaryGateway = nil
	gm.mu.Unlock()

	if secondary == nil {
		return nil
	}

	// Remove the secondary route.
	// In production, would use netlink or netsh to delete specific route.

	gm.recordEvent(secondary, nil, "REMOVE_SECONDARY_GATEWAY", "system", true, "")

	return nil
}

// =============================================================================
// Query Methods
// =============================================================================

// GetDefaultGateway retrieves currently active gateway configuration.
func (gm *GatewayManager) GetDefaultGateway() *GatewayConfiguration {
	gm.mu.RLock()
	defer gm.mu.RUnlock()

	if gm.activeGateway == nil {
		return nil
	}

	// Return copy.
	copy := *gm.activeGateway
	return &copy
}

// GetSecondaryGateway retrieves secondary gateway configuration.
func (gm *GatewayManager) GetSecondaryGateway() *GatewayConfiguration {
	gm.mu.RLock()
	defer gm.mu.RUnlock()

	if gm.secondaryGateway == nil {
		return nil
	}

	copy := *gm.secondaryGateway
	return &copy
}

// GetGatewayHistory retrieves historical gateway change events.
func (gm *GatewayManager) GetGatewayHistory(limit int) []*GatewayChangeEvent {
	gm.gatewayHistoryMu.RLock()
	defer gm.gatewayHistoryMu.RUnlock()

	if len(gm.gatewayHistory) == 0 {
		return nil
	}

	start := 0
	if len(gm.gatewayHistory) > limit {
		start = len(gm.gatewayHistory) - limit
	}

	result := make([]*GatewayChangeEvent, len(gm.gatewayHistory)-start)
	for i, event := range gm.gatewayHistory[start:] {
		eventCopy := *event
		result[i] = &eventCopy
	}

	// Reverse for most recent first.
	for i, j := 0, len(result)-1; i < j; i, j = i+1, j-1 {
		result[i], result[j] = result[j], result[i]
	}

	return result
}

// =============================================================================
// Event Recording
// =============================================================================

// recordEvent creates and stores a gateway change event.
func (gm *GatewayManager) recordEvent(oldGateway, newGateway *GatewayConfiguration, reason, triggeredBy string, success bool, errorMsg string) {
	event := &GatewayChangeEvent{
		EventID:      generateConfigUUID(),
		Timestamp:    time.Now(),
		OldGateway:   oldGateway,
		NewGateway:   newGateway,
		ChangeReason: reason,
		TriggeredBy:  triggeredBy,
		Success:      success,
		ErrorMessage: errorMsg,
	}

	gm.gatewayHistoryMu.Lock()
	gm.gatewayHistory = append(gm.gatewayHistory, event)
	if len(gm.gatewayHistory) > 500 {
		gm.gatewayHistory = gm.gatewayHistory[len(gm.gatewayHistory)-500:]
	}
	gm.gatewayHistoryMu.Unlock()

	// Persist event.
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_ = gm.db.SaveGatewayChangeEvent(ctx, event)
}

// =============================================================================
// Health Check
// =============================================================================

// HealthCheck verifies the manager is operational.
func (gm *GatewayManager) HealthCheck() error {
	if gm.platform == PlatformUnknown {
		return ErrPlatformUnsupported
	}

	gm.runningMu.Lock()
	running := gm.running
	gm.runningMu.Unlock()

	if !running {
		return errors.New("gateway manager not running")
	}

	// Check active gateway is reachable.
	gm.mu.RLock()
	gateway := gm.activeGateway
	gm.mu.RUnlock()

	if gateway != nil && gm.config.ValidateGatewayReachability {
		if err := gm.validateGatewayReachability(gateway.GatewayIP); err != nil {
			return fmt.Errorf("active gateway unreachable: %w", err)
		}
	}

	// Check routing table consistency.
	osGateway, err := gm.getCurrentGatewayFromOS()
	if err == nil && gateway != nil && osGateway != nil {
		if !gateway.GatewayIP.Equal(osGateway.GatewayIP) {
			return errors.New("gateway state mismatch with routing table")
		}
	}

	return nil
}

// =============================================================================
// Statistics
// =============================================================================

// GetStatistics returns gateway management statistics.
func (gm *GatewayManager) GetStatistics() map[string]uint64 {
	return map[string]uint64{
		"gateway_changes":          atomic.LoadUint64(&gm.gatewayChanges),
		"validation_successes":     atomic.LoadUint64(&gm.validationSuccesses),
		"validation_failures":      atomic.LoadUint64(&gm.validationFailures),
		"failover_gateway_changes": atomic.LoadUint64(&gm.failoverGatewayChanges),
		"recovery_gateway_changes": atomic.LoadUint64(&gm.recoveryGatewayChanges),
	}
}

// GetConfig returns the current configuration.
func (gm *GatewayManager) GetConfig() *GatewayConfig {
	return gm.config
}

// GetPlatform returns the detected platform.
func (gm *GatewayManager) GetPlatform() Platform {
	return gm.platform
}
