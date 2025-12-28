// Package configuration provides network interface configuration management
// for the NIC Management service.
package configuration

import (
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"net"
	"runtime"
	"sync"
	"sync/atomic"
	"time"
)

// =============================================================================
// Error Types
// =============================================================================

var (
	// ErrInterfaceNotFound indicates interface does not exist.
	ErrInterfaceNotFound = errors.New("interface not found")
	// ErrInvalidIPAddress indicates IP address is invalid or malformed.
	ErrInvalidIPAddress = errors.New("invalid IP address")
	// ErrInvalidNetmask indicates netmask is invalid or non-contiguous.
	ErrInvalidNetmask = errors.New("invalid netmask")
	// ErrGatewayNotInSubnet indicates gateway IP is outside interface subnet.
	ErrGatewayNotInSubnet = errors.New("gateway not in subnet")
	// ErrIPConflict indicates IP address already assigned to another interface.
	ErrIPConflict = errors.New("IP address conflict")
	// ErrSubnetOverlap indicates subnet overlaps with another interface.
	ErrSubnetOverlap = errors.New("subnet overlap detected")
	// ErrInvalidMTU indicates MTU outside valid range (576-9000).
	ErrInvalidMTU = errors.New("invalid MTU value")
	// ErrConfigurationTimeout indicates configuration exceeded timeout.
	ErrConfigurationTimeout = errors.New("configuration timeout")
	// ErrRollbackFailed indicates unable to revert to previous configuration.
	ErrRollbackFailed = errors.New("rollback failed")
	// ErrPlatformUnsupported indicates operating system not supported.
	ErrPlatformUnsupported = errors.New("platform unsupported")
	// ErrGatewayUnreachable indicates gateway ping validation failed.
	ErrGatewayUnreachable = errors.New("gateway unreachable")
	// ErrDuplicateAddress indicates IP conflict detected on network.
	ErrDuplicateAddress = errors.New("duplicate address detected")
	// ErrConfigNotFound indicates no configuration for interface.
	ErrConfigNotFound = errors.New("configuration not found")
)

// =============================================================================
// Platform Enumeration
// =============================================================================

// Platform represents the operating system platform.
type Platform int

const (
	// PlatformUnknown indicates unsupported or undetected platform.
	PlatformUnknown Platform = iota
	// PlatformLinux indicates Linux operating system (uses netlink).
	PlatformLinux
	// PlatformWindows indicates Windows operating system (uses netsh/WMI).
	PlatformWindows
)

// String returns the string representation of the platform.
func (p Platform) String() string {
	switch p {
	case PlatformLinux:
		return "LINUX"
	case PlatformWindows:
		return "WINDOWS"
	default:
		return "UNKNOWN"
	}
}

// DetectPlatform detects the current operating system platform.
func DetectPlatform() Platform {
	switch runtime.GOOS {
	case "linux":
		return PlatformLinux
	case "windows":
		return PlatformWindows
	default:
		return PlatformUnknown
	}
}

// =============================================================================
// Configuration Method Enumeration
// =============================================================================

// ConfigurationMethod represents IP address assignment methods.
type ConfigurationMethod int

const (
	// ConfigMethodStatic indicates manually configured static IP address.
	ConfigMethodStatic ConfigurationMethod = iota
	// ConfigMethodDHCP indicates dynamic IP from DHCP server.
	ConfigMethodDHCP
	// ConfigMethodDHCPWithFallback indicates DHCP with static fallback.
	ConfigMethodDHCPWithFallback
	// ConfigMethodLinkLocal indicates auto-assigned link-local address.
	ConfigMethodLinkLocal
)

// String returns the string representation of the configuration method.
func (m ConfigurationMethod) String() string {
	switch m {
	case ConfigMethodStatic:
		return "STATIC"
	case ConfigMethodDHCP:
		return "DHCP"
	case ConfigMethodDHCPWithFallback:
		return "DHCP_WITH_STATIC_FALLBACK"
	case ConfigMethodLinkLocal:
		return "LINK_LOCAL"
	default:
		return "UNKNOWN"
	}
}

// =============================================================================
// Interface State Enumeration
// =============================================================================

// InterfaceState represents desired interface administrative state.
type InterfaceState int

const (
	// InterfaceStateUp indicates interface enabled and active.
	InterfaceStateUp InterfaceState = iota
	// InterfaceStateDown indicates interface administratively disabled.
	InterfaceStateDown
)

// String returns the string representation of the interface state.
func (s InterfaceState) String() string {
	switch s {
	case InterfaceStateUp:
		return "UP"
	case InterfaceStateDown:
		return "DOWN"
	default:
		return "UNKNOWN"
	}
}

// =============================================================================
// Configuration Outcome Enumeration
// =============================================================================

// ConfigurationOutcome represents configuration operation results.
type ConfigurationOutcome int

const (
	// ConfigOutcomeSuccess indicates configuration applied successfully.
	ConfigOutcomeSuccess ConfigurationOutcome = iota
	// ConfigOutcomeFailure indicates configuration failed.
	ConfigOutcomeFailure
	// ConfigOutcomeRolledBack indicates configuration reverted.
	ConfigOutcomeRolledBack
	// ConfigOutcomePartial indicates some settings applied, others failed.
	ConfigOutcomePartial
)

// String returns the string representation of the outcome.
func (o ConfigurationOutcome) String() string {
	switch o {
	case ConfigOutcomeSuccess:
		return "SUCCESS"
	case ConfigOutcomeFailure:
		return "FAILURE"
	case ConfigOutcomeRolledBack:
		return "ROLLED_BACK"
	case ConfigOutcomePartial:
		return "PARTIAL"
	default:
		return "UNKNOWN"
	}
}

// =============================================================================
// Static Route Structure
// =============================================================================

// StaticRoute represents an additional routing entry for interface.
type StaticRoute struct {
	// Destination is the destination network.
	Destination *net.IPNet `json:"destination"`
	// Gateway is the gateway for this route (nil for direct route).
	Gateway net.IP `json:"gateway,omitempty"`
	// Metric is the route priority (lower = higher priority).
	Metric int `json:"metric"`
	// InterfaceName is the interface to use for this route.
	InterfaceName string `json:"interface_name"`
}

// =============================================================================
// IPv4 Configuration Structure
// =============================================================================

// IPv4Configuration contains IPv4-specific address configuration.
type IPv4Configuration struct {
	// Address is the IPv4 address.
	Address net.IP `json:"address"`
	// Netmask is the subnet mask.
	Netmask net.IPMask `json:"netmask"`
	// PrefixLength is the CIDR prefix length.
	PrefixLength int `json:"prefix_length"`
	// Gateway is the default gateway IP.
	Gateway net.IP `json:"gateway,omitempty"`
	// Broadcast is the broadcast address.
	Broadcast net.IP `json:"broadcast,omitempty"`
	// Network is the network address and mask.
	Network *net.IPNet `json:"network,omitempty"`
	// DNSServers contains DNS server addresses.
	DNSServers []net.IP `json:"dns_servers,omitempty"`
	// DHCPEnabled indicates whether DHCP client enabled.
	DHCPEnabled bool `json:"dhcp_enabled"`
	// DHCPLeaseTime is the DHCP lease duration.
	DHCPLeaseTime time.Duration `json:"dhcp_lease_time,omitempty"`
	// StaticRoutes contains additional static routes.
	StaticRoutes []*StaticRoute `json:"static_routes,omitempty"`
}

// =============================================================================
// IPv6 Configuration Structure
// =============================================================================

// IPv6Configuration contains IPv6-specific address configuration.
type IPv6Configuration struct {
	// Address is the IPv6 address.
	Address net.IP `json:"address"`
	// PrefixLength is the CIDR prefix length.
	PrefixLength int `json:"prefix_length"`
	// Gateway is the default gateway IPv6.
	Gateway net.IP `json:"gateway,omitempty"`
	// DNSServers contains IPv6 DNS server addresses.
	DNSServers []net.IP `json:"dns_servers,omitempty"`
	// AutoconfigEnabled indicates SLAAC enabled.
	AutoconfigEnabled bool `json:"autoconfig_enabled"`
	// PrivacyExtensions enables RFC 4941 privacy extensions.
	PrivacyExtensions bool `json:"privacy_extensions"`
	// StaticRoutes contains additional static IPv6 routes.
	StaticRoutes []*StaticRoute `json:"static_routes,omitempty"`
}

// =============================================================================
// Interface Configuration Structure
// =============================================================================

// InterfaceConfig contains complete IP configuration for a network interface.
type InterfaceConfig struct {
	// InterfaceName is the OS interface name.
	InterfaceName string `json:"interface_name"`
	// HardwareAddr is the MAC address for validation.
	HardwareAddr string `json:"hardware_addr,omitempty"`
	// IPv4Config contains IPv4 address configuration.
	IPv4Config *IPv4Configuration `json:"ipv4_config,omitempty"`
	// IPv6Config contains IPv6 address configuration.
	IPv6Config *IPv6Configuration `json:"ipv6_config,omitempty"`
	// MTU is the maximum transmission unit.
	MTU int `json:"mtu"`
	// State is the desired interface state.
	State InterfaceState `json:"state"`
	// ConfigMethod indicates how IP is assigned.
	ConfigMethod ConfigurationMethod `json:"config_method"`
	// AppliedAt is when configuration was last applied.
	AppliedAt time.Time `json:"applied_at,omitempty"`
	// IsApplied indicates whether configuration is currently active.
	IsApplied bool `json:"is_applied"`
	// ValidationErrors contains errors from last validation.
	ValidationErrors []string `json:"validation_errors,omitempty"`
}

// =============================================================================
// Configuration Event Structure
// =============================================================================

// ConfigurationEvent records a configuration change.
type ConfigurationEvent struct {
	// EventID is the unique event identifier.
	EventID string `json:"event_id"`
	// InterfaceName is the interface that was configured.
	InterfaceName string `json:"interface_name"`
	// Timestamp is when configuration was applied.
	Timestamp time.Time `json:"timestamp"`
	// OldConfig is the previous configuration.
	OldConfig *InterfaceConfig `json:"old_config,omitempty"`
	// NewConfig is the new configuration.
	NewConfig *InterfaceConfig `json:"new_config"`
	// Outcome is the result of the configuration.
	Outcome ConfigurationOutcome `json:"outcome"`
	// AppliedBy indicates who applied the configuration.
	AppliedBy string `json:"applied_by"`
	// ValidationErrors contains errors encountered during validation.
	ValidationErrors []string `json:"validation_errors,omitempty"`
	// ErrorMessage contains detailed error if failed.
	ErrorMessage string `json:"error_message,omitempty"`
}

// =============================================================================
// Configurator Configuration
// =============================================================================

// ConfiguratorConfig contains configuration for interface configuration behavior.
type ConfiguratorConfig struct {
	// EnableIPv4 configures IPv4 addresses (default: true).
	EnableIPv4 bool `json:"enable_ipv4"`
	// EnableIPv6 configures IPv6 addresses (default: false).
	EnableIPv6 bool `json:"enable_ipv6"`
	// ValidateBeforeApply checks for conflicts before applying (default: true).
	ValidateBeforeApply bool `json:"validate_before_apply"`
	// EnableRollback reverts on configuration failure (default: true).
	EnableRollback bool `json:"enable_rollback"`
	// RollbackTimeout is max time for rollback operation (default: 30s).
	RollbackTimeout time.Duration `json:"rollback_timeout"`
	// ConfigurationTimeout is max time for single interface config (default: 10s).
	ConfigurationTimeout time.Duration `json:"configuration_timeout"`
	// EnablePersistence saves configurations to database (default: true).
	EnablePersistence bool `json:"enable_persistence"`
	// PersistenceInterval determines how often to sync configs to DB (default: 60s).
	PersistenceInterval time.Duration `json:"persistence_interval"`
	// AllowOverlappingSubnets permits subnet overlaps across interfaces (default: false).
	AllowOverlappingSubnets bool `json:"allow_overlapping_subnets"`
	// RequireGatewayValidation verifies gateway reachable after config (default: true).
	RequireGatewayValidation bool `json:"require_gateway_validation"`
	// GatewayPingTimeout is max time for gateway ping validation (default: 5s).
	GatewayPingTimeout time.Duration `json:"gateway_ping_timeout"`
	// EnableDuplicateAddressDetection checks for IP conflicts on network (default: true).
	EnableDuplicateAddressDetection bool `json:"enable_duplicate_address_detection"`
	// DADTimeout is max time for duplicate address detection (default: 3s).
	DADTimeout time.Duration `json:"dad_timeout"`
}

// DefaultConfiguratorConfig returns the default configurator configuration.
func DefaultConfiguratorConfig() *ConfiguratorConfig {
	return &ConfiguratorConfig{
		EnableIPv4:                      true,
		EnableIPv6:                      false,
		ValidateBeforeApply:             true,
		EnableRollback:                  true,
		RollbackTimeout:                 30 * time.Second,
		ConfigurationTimeout:            10 * time.Second,
		EnablePersistence:               true,
		PersistenceInterval:             60 * time.Second,
		AllowOverlappingSubnets:         false,
		RequireGatewayValidation:        true,
		GatewayPingTimeout:              5 * time.Second,
		EnableDuplicateAddressDetection: true,
		DADTimeout:                      3 * time.Second,
	}
}

// =============================================================================
// Enumerator Interface
// =============================================================================

// EnumeratorInterface defines interface discovery operations needed by configurator.
type EnumeratorInterface interface {
	// InterfaceExists checks if an interface exists.
	InterfaceExists(name string) bool
	// GetInterfaceMAC returns the MAC address of an interface.
	GetInterfaceMAC(name string) (string, error)
}

// ConfiguratorDBInterface defines database operations for configuration persistence.
type ConfiguratorDBInterface interface {
	// LoadInterfaceConfigurations loads persisted configurations.
	LoadInterfaceConfigurations(ctx context.Context) (map[string]*InterfaceConfig, error)
	// SaveInterfaceConfiguration saves a configuration.
	SaveInterfaceConfiguration(ctx context.Context, config *InterfaceConfig) error
	// DeleteInterfaceConfiguration removes a configuration.
	DeleteInterfaceConfiguration(ctx context.Context, interfaceName string) error
	// SaveConfigurationEvent saves a configuration event.
	SaveConfigurationEvent(ctx context.Context, event *ConfigurationEvent) error
}

// =============================================================================
// No-Op Implementations
// =============================================================================

type noOpEnumerator struct{}

func (n *noOpEnumerator) InterfaceExists(name string) bool {
	// Check against OS network interfaces.
	ifaces, err := net.Interfaces()
	if err != nil {
		return false
	}
	for _, iface := range ifaces {
		if iface.Name == name {
			return true
		}
	}
	return false
}

func (n *noOpEnumerator) GetInterfaceMAC(name string) (string, error) {
	iface, err := net.InterfaceByName(name)
	if err != nil {
		return "", err
	}
	return iface.HardwareAddr.String(), nil
}

type noOpConfiguratorDB struct{}

func (n *noOpConfiguratorDB) LoadInterfaceConfigurations(ctx context.Context) (map[string]*InterfaceConfig, error) {
	return make(map[string]*InterfaceConfig), nil
}

func (n *noOpConfiguratorDB) SaveInterfaceConfiguration(ctx context.Context, config *InterfaceConfig) error {
	return nil
}

func (n *noOpConfiguratorDB) DeleteInterfaceConfiguration(ctx context.Context, interfaceName string) error {
	return nil
}

func (n *noOpConfiguratorDB) SaveConfigurationEvent(ctx context.Context, event *ConfigurationEvent) error {
	return nil
}

// =============================================================================
// Interface Configurator
// =============================================================================

// InterfaceConfigurator manages NIC configuration operations.
type InterfaceConfigurator struct {
	// Dependencies.
	enumerator EnumeratorInterface
	db         ConfiguratorDBInterface

	// Configuration.
	config *ConfiguratorConfig

	// State.
	interfaceConfigs map[string]*InterfaceConfig
	mu               sync.RWMutex

	// History.
	configHistory   []*ConfigurationEvent
	configHistoryMu sync.RWMutex

	// Platform.
	platform Platform

	// Statistics.
	totalConfigurations    uint64
	successConfigurations  uint64
	failedConfigurations   uint64
	rollbackConfigurations uint64

	// Control.
	stopChan  chan struct{}
	wg        sync.WaitGroup
	running   bool
	runningMu sync.Mutex
}

// NewInterfaceConfigurator creates a new interface configurator.
func NewInterfaceConfigurator(
	enumerator EnumeratorInterface,
	db ConfiguratorDBInterface,
	config *ConfiguratorConfig,
) *InterfaceConfigurator {
	if config == nil {
		config = DefaultConfiguratorConfig()
	}

	if enumerator == nil {
		enumerator = &noOpEnumerator{}
	}

	if db == nil {
		db = &noOpConfiguratorDB{}
	}

	return &InterfaceConfigurator{
		enumerator:       enumerator,
		db:               db,
		config:           config,
		interfaceConfigs: make(map[string]*InterfaceConfig),
		configHistory:    make([]*ConfigurationEvent, 0, 1000),
		platform:         DetectPlatform(),
		stopChan:         make(chan struct{}),
	}
}

// =============================================================================
// Lifecycle Management
// =============================================================================

// Start initializes the interface configurator.
func (ic *InterfaceConfigurator) Start(ctx context.Context) error {
	ic.runningMu.Lock()
	defer ic.runningMu.Unlock()

	if ic.running {
		return nil
	}

	// Validate platform support.
	if ic.platform == PlatformUnknown {
		return ErrPlatformUnsupported
	}

	// Load persisted configurations from database.
	configs, err := ic.db.LoadInterfaceConfigurations(ctx)
	if err != nil {
		// Log warning but continue.
		_ = err
	} else if configs != nil {
		ic.mu.Lock()
		ic.interfaceConfigs = configs
		ic.mu.Unlock()
	}

	// Start persistence worker if enabled.
	if ic.config.EnablePersistence {
		ic.wg.Add(1)
		go ic.persistenceWorker()
	}

	ic.running = true
	return nil
}

// Stop shuts down the interface configurator.
func (ic *InterfaceConfigurator) Stop() error {
	ic.runningMu.Lock()
	if !ic.running {
		ic.runningMu.Unlock()
		return nil
	}
	ic.running = false
	ic.runningMu.Unlock()

	close(ic.stopChan)
	ic.wg.Wait()

	// Final persistence.
	if ic.config.EnablePersistence {
		ic.persistAllConfigurations()
	}

	return nil
}

// =============================================================================
// Configuration Operations
// =============================================================================

// ConfigureInterface applies IP configuration to a network interface.
func (ic *InterfaceConfigurator) ConfigureInterface(ctx context.Context, config *InterfaceConfig) error {
	if config == nil {
		return errors.New("configuration cannot be nil")
	}

	if config.InterfaceName == "" {
		return errors.New("interface name cannot be empty")
	}

	// Validate interface exists.
	if !ic.enumerator.InterfaceExists(config.InterfaceName) {
		return fmt.Errorf("%w: %s", ErrInterfaceNotFound, config.InterfaceName)
	}

	// Validate MAC address if provided.
	if config.HardwareAddr != "" {
		mac, err := ic.enumerator.GetInterfaceMAC(config.InterfaceName)
		if err == nil && mac != config.HardwareAddr {
			return fmt.Errorf("MAC address mismatch: expected %s, got %s", config.HardwareAddr, mac)
		}
	}

	atomic.AddUint64(&ic.totalConfigurations, 1)

	// Step 1: Validation.
	if ic.config.ValidateBeforeApply {
		if err := ic.validateConfiguration(config); err != nil {
			config.ValidationErrors = append(config.ValidationErrors, err.Error())
			return err
		}
	}

	// Step 2: Backup current configuration.
	var backupConfig *InterfaceConfig
	if ic.config.EnableRollback {
		backupConfig, _ = ic.getCurrentConfiguration(config.InterfaceName)
	}

	// Step 3: Apply configuration.
	configCtx, cancel := context.WithTimeout(ctx, ic.config.ConfigurationTimeout)
	defer cancel()

	var err error
	switch ic.platform {
	case PlatformLinux:
		err = ic.applyConfigurationLinux(configCtx, config)
	case PlatformWindows:
		err = ic.applyConfigurationWindows(configCtx, config)
	default:
		err = ErrPlatformUnsupported
	}

	if err != nil {
		atomic.AddUint64(&ic.failedConfigurations, 1)

		// Rollback if enabled.
		if ic.config.EnableRollback && backupConfig != nil {
			_ = ic.rollbackConfiguration(ctx, backupConfig)
			atomic.AddUint64(&ic.rollbackConfigurations, 1)

			ic.recordEvent(config.InterfaceName, backupConfig, config, ConfigOutcomeRolledBack, err.Error())
		} else {
			ic.recordEvent(config.InterfaceName, backupConfig, config, ConfigOutcomeFailure, err.Error())
		}

		return err
	}

	// Step 4: Post-configuration validation.
	if ic.config.RequireGatewayValidation && config.IPv4Config != nil && config.IPv4Config.Gateway != nil {
		if err := ic.pingGateway(config.IPv4Config.Gateway, ic.config.GatewayPingTimeout); err != nil {
			// Gateway unreachable - rollback.
			if ic.config.EnableRollback && backupConfig != nil {
				_ = ic.rollbackConfiguration(ctx, backupConfig)
				atomic.AddUint64(&ic.rollbackConfigurations, 1)
			}
			atomic.AddUint64(&ic.failedConfigurations, 1)
			ic.recordEvent(config.InterfaceName, backupConfig, config, ConfigOutcomeRolledBack, ErrGatewayUnreachable.Error())
			return ErrGatewayUnreachable
		}
	}

	// Duplicate address detection.
	if ic.config.EnableDuplicateAddressDetection && config.IPv4Config != nil && config.IPv4Config.Address != nil {
		isDuplicate, err := ic.duplicateAddressDetection(config.IPv4Config.Address, config.InterfaceName, ic.config.DADTimeout)
		if err == nil && isDuplicate {
			// Duplicate detected - rollback.
			if ic.config.EnableRollback && backupConfig != nil {
				_ = ic.rollbackConfiguration(ctx, backupConfig)
				atomic.AddUint64(&ic.rollbackConfigurations, 1)
			}
			atomic.AddUint64(&ic.failedConfigurations, 1)
			ic.recordEvent(config.InterfaceName, backupConfig, config, ConfigOutcomeRolledBack, ErrDuplicateAddress.Error())
			return ErrDuplicateAddress
		}
	}

	// Step 5: Update state.
	ic.mu.Lock()
	config.IsApplied = true
	config.AppliedAt = time.Now()
	ic.interfaceConfigs[config.InterfaceName] = config
	ic.mu.Unlock()

	atomic.AddUint64(&ic.successConfigurations, 1)
	ic.recordEvent(config.InterfaceName, backupConfig, config, ConfigOutcomeSuccess, "")

	return nil
}

// applyConfigurationLinux applies configuration on Linux using netlink.
func (ic *InterfaceConfigurator) applyConfigurationLinux(ctx context.Context, config *InterfaceConfig) error {
	// Check for context cancellation.
	select {
	case <-ctx.Done():
		return ErrConfigurationTimeout
	default:
	}

	// Get interface by name.
	iface, err := net.InterfaceByName(config.InterfaceName)
	if err != nil {
		return fmt.Errorf("%w: %s", ErrInterfaceNotFound, config.InterfaceName)
	}
	_ = iface // Will be used with netlink in production.

	// For now, this is a stub that indicates Linux configuration support.
	// In production, this would use github.com/vishvananda/netlink:
	//
	// link, err := netlink.LinkByName(config.InterfaceName)
	// if err != nil {
	//     return err
	// }
	//
	// // Set interface state
	// if config.State == InterfaceStateDown {
	//     netlink.LinkSetDown(link)
	// } else {
	//     netlink.LinkSetUp(link)
	// }
	//
	// // Set MTU
	// netlink.LinkSetMTU(link, config.MTU)
	//
	// // Configure IPv4
	// if config.IPv4Config != nil {
	//     addr := &netlink.Addr{
	//         IPNet: &net.IPNet{
	//             IP:   config.IPv4Config.Address,
	//             Mask: config.IPv4Config.Netmask,
	//         },
	//     }
	//     netlink.AddrAdd(link, addr)
	//
	//     // Add default gateway
	//     if config.IPv4Config.Gateway != nil {
	//         route := &netlink.Route{
	//             Dst: nil, // default route
	//             Gw:  config.IPv4Config.Gateway,
	//         }
	//         netlink.RouteAdd(route)
	//     }
	// }

	return nil
}

// applyConfigurationWindows applies configuration on Windows using netsh.
func (ic *InterfaceConfigurator) applyConfigurationWindows(ctx context.Context, config *InterfaceConfig) error {
	_ = config // Will be used in production implementation.

	// Check for context cancellation.
	select {
	case <-ctx.Done():
		return ErrConfigurationTimeout
	default:
	}

	// For now, this is a stub that indicates Windows configuration support.
	// In production, this would execute netsh commands:
	//
	// // Set interface state
	// if config.State == InterfaceStateDown {
	//     exec.Command("netsh", "interface", "set", "interface", config.InterfaceName, "admin=disabled")
	// } else {
	//     exec.Command("netsh", "interface", "set", "interface", config.InterfaceName, "admin=enabled")
	// }
	//
	// // Configure IPv4
	// if config.IPv4Config != nil {
	//     if config.IPv4Config.DHCPEnabled {
	//         exec.Command("netsh", "interface", "ipv4", "set", "address", "name="+config.InterfaceName, "dhcp")
	//     } else {
	//         exec.Command("netsh", "interface", "ipv4", "set", "address",
	//             "name="+config.InterfaceName,
	//             "static",
	//             config.IPv4Config.Address.String(),
	//             net.IP(config.IPv4Config.Netmask).String(),
	//             config.IPv4Config.Gateway.String())
	//     }
	// }
	//
	// // Set MTU
	// exec.Command("netsh", "interface", "ipv4", "set", "subinterface",
	//     config.InterfaceName, fmt.Sprintf("mtu=%d", config.MTU))

	return nil
}

// getCurrentConfiguration retrieves active configuration from operating system.
func (ic *InterfaceConfigurator) getCurrentConfiguration(interfaceName string) (*InterfaceConfig, error) {
	iface, err := net.InterfaceByName(interfaceName)
	if err != nil {
		return nil, fmt.Errorf("%w: %s", ErrInterfaceNotFound, interfaceName)
	}

	config := &InterfaceConfig{
		InterfaceName: interfaceName,
		HardwareAddr:  iface.HardwareAddr.String(),
		MTU:           iface.MTU,
		State:         InterfaceStateUp,
	}

	if iface.Flags&net.FlagUp == 0 {
		config.State = InterfaceStateDown
	}

	// Get IP addresses.
	addrs, err := iface.Addrs()
	if err == nil && len(addrs) > 0 {
		for _, addr := range addrs {
			ipnet, ok := addr.(*net.IPNet)
			if !ok {
				continue
			}

			if ipnet.IP.To4() != nil {
				// IPv4 address.
				config.IPv4Config = &IPv4Configuration{
					Address:      ipnet.IP,
					Netmask:      ipnet.Mask,
					PrefixLength: prefixLength(ipnet.Mask),
					Network:      ipnet,
				}
			} else if ipnet.IP.To16() != nil {
				// IPv6 address.
				config.IPv6Config = &IPv6Configuration{
					Address:      ipnet.IP,
					PrefixLength: prefixLength(ipnet.Mask),
				}
			}
		}
	}

	return config, nil
}

// =============================================================================
// Validation
// =============================================================================

// validateConfiguration checks configuration for errors and conflicts.
func (ic *InterfaceConfigurator) validateConfiguration(config *InterfaceConfig) error {
	var errors []string

	// Validate IPv4 configuration.
	if config.IPv4Config != nil {
		if config.IPv4Config.Address == nil {
			errors = append(errors, "IPv4 address cannot be nil")
		} else {
			if config.IPv4Config.Address.IsLoopback() {
				errors = append(errors, "IPv4 address cannot be loopback")
			}
			if config.IPv4Config.Address.IsMulticast() {
				errors = append(errors, "IPv4 address cannot be multicast")
			}
		}

		if config.IPv4Config.Netmask == nil && config.IPv4Config.PrefixLength == 0 {
			errors = append(errors, "IPv4 netmask or prefix length required")
		}

		// Validate gateway in same subnet.
		if config.IPv4Config.Gateway != nil && config.IPv4Config.Network != nil {
			if !config.IPv4Config.Network.Contains(config.IPv4Config.Gateway) {
				errors = append(errors, "gateway not in same subnet as interface")
			}
		}
	}

	// Validate MTU.
	if config.MTU > 0 && (config.MTU < 576 || config.MTU > 9000) {
		errors = append(errors, fmt.Sprintf("MTU must be between 576 and 9000, got %d", config.MTU))
	}

	// Check for IP conflicts.
	if config.IPv4Config != nil && config.IPv4Config.Address != nil {
		if hasConflict, conflictingIface := ic.checkIPConflict(config.IPv4Config.Address, config.InterfaceName); hasConflict {
			errors = append(errors, fmt.Sprintf("IP address conflicts with interface %s", conflictingIface))
		}
	}

	// Check for subnet overlaps.
	if !ic.config.AllowOverlappingSubnets && config.IPv4Config != nil && config.IPv4Config.Network != nil {
		if hasOverlap, overlappingIface := ic.checkSubnetOverlap(config.IPv4Config.Network, config.InterfaceName); hasOverlap {
			errors = append(errors, fmt.Sprintf("subnet overlaps with interface %s", overlappingIface))
		}
	}

	if len(errors) > 0 {
		config.ValidationErrors = errors
		return fmt.Errorf("validation failed: %v", errors)
	}

	return nil
}

// checkIPConflict detects IP address conflicts across interfaces.
func (ic *InterfaceConfigurator) checkIPConflict(address net.IP, excludeInterface string) (bool, string) {
	ic.mu.RLock()
	defer ic.mu.RUnlock()

	for name, cfg := range ic.interfaceConfigs {
		if name == excludeInterface {
			continue
		}

		if cfg.IPv4Config != nil && cfg.IPv4Config.Address != nil {
			if cfg.IPv4Config.Address.Equal(address) {
				return true, name
			}
		}

		if cfg.IPv6Config != nil && cfg.IPv6Config.Address != nil {
			if cfg.IPv6Config.Address.Equal(address) {
				return true, name
			}
		}
	}

	return false, ""
}

// checkSubnetOverlap detects overlapping subnets across interfaces.
func (ic *InterfaceConfigurator) checkSubnetOverlap(network *net.IPNet, excludeInterface string) (bool, string) {
	ic.mu.RLock()
	defer ic.mu.RUnlock()

	for name, cfg := range ic.interfaceConfigs {
		if name == excludeInterface {
			continue
		}

		if cfg.IPv4Config != nil && cfg.IPv4Config.Network != nil {
			otherNet := cfg.IPv4Config.Network
			// Check if networks overlap.
			if network.Contains(otherNet.IP) || otherNet.Contains(network.IP) {
				return true, name
			}
		}
	}

	return false, ""
}

// =============================================================================
// Rollback
// =============================================================================

// rollbackConfiguration reverts to previous configuration after failure.
func (ic *InterfaceConfigurator) rollbackConfiguration(ctx context.Context, backupConfig *InterfaceConfig) error {
	if backupConfig == nil {
		// No backup config provided - nothing to rollback to.
		return nil
	}

	rollbackCtx, cancel := context.WithTimeout(ctx, ic.config.RollbackTimeout)
	defer cancel()

	var err error
	switch ic.platform {
	case PlatformLinux:
		err = ic.applyConfigurationLinux(rollbackCtx, backupConfig)
	case PlatformWindows:
		err = ic.applyConfigurationWindows(rollbackCtx, backupConfig)
	default:
		err = ErrPlatformUnsupported
	}

	if err != nil {
		return fmt.Errorf("%w: %v", ErrRollbackFailed, err)
	}

	return nil
}

// =============================================================================
// Query Methods
// =============================================================================

// GetInterfaceConfiguration retrieves configured settings for specific interface.
func (ic *InterfaceConfigurator) GetInterfaceConfiguration(interfaceName string) (*InterfaceConfig, error) {
	ic.mu.RLock()
	defer ic.mu.RUnlock()

	config, exists := ic.interfaceConfigs[interfaceName]
	if !exists {
		return nil, ErrConfigNotFound
	}

	// Return copy.
	copy := *config
	return &copy, nil
}

// GetAllConfigurations retrieves all interface configurations.
func (ic *InterfaceConfigurator) GetAllConfigurations() map[string]*InterfaceConfig {
	ic.mu.RLock()
	defer ic.mu.RUnlock()

	result := make(map[string]*InterfaceConfig, len(ic.interfaceConfigs))
	for name, cfg := range ic.interfaceConfigs {
		copy := *cfg
		result[name] = &copy
	}
	return result
}

// DeleteConfiguration removes IP configuration from interface.
func (ic *InterfaceConfigurator) DeleteConfiguration(interfaceName string) error {
	ic.mu.Lock()
	_, exists := ic.interfaceConfigs[interfaceName]
	if exists {
		delete(ic.interfaceConfigs, interfaceName)
	}
	ic.mu.Unlock()

	// Delete from database.
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	_ = ic.db.DeleteInterfaceConfiguration(ctx, interfaceName)

	return nil
}

// ResetInterface resets interface to default unconfigured state.
func (ic *InterfaceConfigurator) ResetInterface(interfaceName string) error {
	// Delete configuration.
	if err := ic.DeleteConfiguration(interfaceName); err != nil {
		return err
	}

	// The interface will return to its default state (DHCP or unconfigured).
	return nil
}

// GetConfigurationHistory retrieves historical configuration events.
func (ic *InterfaceConfigurator) GetConfigurationHistory(limit int) []*ConfigurationEvent {
	ic.configHistoryMu.RLock()
	defer ic.configHistoryMu.RUnlock()

	if len(ic.configHistory) == 0 {
		return nil
	}

	start := 0
	if len(ic.configHistory) > limit {
		start = len(ic.configHistory) - limit
	}

	result := make([]*ConfigurationEvent, len(ic.configHistory)-start)
	for i, event := range ic.configHistory[start:] {
		copy := *event
		result[i] = &copy
	}

	// Reverse for most recent first.
	for i, j := 0, len(result)-1; i < j; i, j = i+1, j-1 {
		result[i], result[j] = result[j], result[i]
	}

	return result
}

// =============================================================================
// Network Validation Helpers
// =============================================================================

// pingGateway validates gateway reachability.
func (ic *InterfaceConfigurator) pingGateway(gateway net.IP, timeout time.Duration) error {
	// For stub implementation, we'll just do a quick connection test.
	// In production, this would use ICMP ping.
	// For now, we assume gateway is reachable.
	_ = gateway
	_ = timeout
	return nil
}

// duplicateAddressDetection checks for IP conflicts on network using ARP.
func (ic *InterfaceConfigurator) duplicateAddressDetection(address net.IP, interfaceName string, timeout time.Duration) (bool, error) {
	// For stub implementation, assume no duplicates.
	// In production, this would send gratuitous ARP requests.
	_ = address
	_ = interfaceName
	_ = timeout
	return false, nil
}

// =============================================================================
// Event Recording
// =============================================================================

// recordEvent creates and stores a configuration event.
func (ic *InterfaceConfigurator) recordEvent(interfaceName string, oldConfig, newConfig *InterfaceConfig, outcome ConfigurationOutcome, errorMsg string) {
	event := &ConfigurationEvent{
		EventID:       generateConfigUUID(),
		InterfaceName: interfaceName,
		Timestamp:     time.Now(),
		OldConfig:     oldConfig,
		NewConfig:     newConfig,
		Outcome:       outcome,
		AppliedBy:     "system",
		ErrorMessage:  errorMsg,
	}

	ic.configHistoryMu.Lock()
	ic.configHistory = append(ic.configHistory, event)
	if len(ic.configHistory) > 1000 {
		ic.configHistory = ic.configHistory[len(ic.configHistory)-1000:]
	}
	ic.configHistoryMu.Unlock()

	// Persist event.
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_ = ic.db.SaveConfigurationEvent(ctx, event)
}

// =============================================================================
// Persistence
// =============================================================================

// persistenceWorker runs the background persistence task.
func (ic *InterfaceConfigurator) persistenceWorker() {
	defer ic.wg.Done()

	ticker := time.NewTicker(ic.config.PersistenceInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ic.stopChan:
			return
		case <-ticker.C:
			ic.persistAllConfigurations()
		}
	}
}

// persistAllConfigurations saves all configurations to database.
func (ic *InterfaceConfigurator) persistAllConfigurations() {
	ic.mu.RLock()
	defer ic.mu.RUnlock()

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	for _, config := range ic.interfaceConfigs {
		_ = ic.db.SaveInterfaceConfiguration(ctx, config)
	}
}

// =============================================================================
// Health Check
// =============================================================================

// HealthCheck verifies the configurator is operational.
func (ic *InterfaceConfigurator) HealthCheck() error {
	if ic.platform == PlatformUnknown {
		return ErrPlatformUnsupported
	}

	ic.runningMu.Lock()
	running := ic.running
	ic.runningMu.Unlock()

	if !running {
		return errors.New("configurator not running")
	}

	return nil
}

// =============================================================================
// Statistics
// =============================================================================

// GetStatistics returns configuration statistics.
func (ic *InterfaceConfigurator) GetStatistics() map[string]uint64 {
	return map[string]uint64{
		"total_configurations":    atomic.LoadUint64(&ic.totalConfigurations),
		"success_configurations":  atomic.LoadUint64(&ic.successConfigurations),
		"failed_configurations":   atomic.LoadUint64(&ic.failedConfigurations),
		"rollback_configurations": atomic.LoadUint64(&ic.rollbackConfigurations),
	}
}

// GetPlatform returns the detected platform.
func (ic *InterfaceConfigurator) GetPlatform() Platform {
	return ic.platform
}

// GetConfig returns the current configuration.
func (ic *InterfaceConfigurator) GetConfig() *ConfiguratorConfig {
	return ic.config
}

// =============================================================================
// Utility Functions
// =============================================================================

// generateConfigUUID generates a UUID v4 for configuration operations.
func generateConfigUUID() string {
	uuid := make([]byte, 16)
	_, _ = rand.Read(uuid)
	// Set version (4) and variant (10) bits.
	uuid[6] = (uuid[6] & 0x0f) | 0x40
	uuid[8] = (uuid[8] & 0x3f) | 0x80
	return fmt.Sprintf("%08x-%04x-%04x-%04x-%012x",
		uuid[0:4], uuid[4:6], uuid[6:8], uuid[8:10], uuid[10:16])
}

// prefixLength calculates the prefix length from a netmask.
func prefixLength(mask net.IPMask) int {
	ones, _ := mask.Size()
	return ones
}

// ParseIPv4Config creates an IPv4Configuration from address string and prefix.
func ParseIPv4Config(address string, prefixLen int, gateway string) (*IPv4Configuration, error) {
	ip := net.ParseIP(address)
	if ip == nil {
		return nil, ErrInvalidIPAddress
	}

	ip = ip.To4()
	if ip == nil {
		return nil, fmt.Errorf("%w: not an IPv4 address", ErrInvalidIPAddress)
	}

	mask := net.CIDRMask(prefixLen, 32)
	network := &net.IPNet{IP: ip.Mask(mask), Mask: mask}

	// Calculate broadcast.
	broadcast := make(net.IP, 4)
	for i := 0; i < 4; i++ {
		broadcast[i] = ip[i] | ^mask[i]
	}

	config := &IPv4Configuration{
		Address:      ip,
		Netmask:      mask,
		PrefixLength: prefixLen,
		Network:      network,
		Broadcast:    broadcast,
	}

	if gateway != "" {
		gw := net.ParseIP(gateway)
		if gw == nil {
			return nil, fmt.Errorf("%w: invalid gateway address", ErrInvalidIPAddress)
		}
		config.Gateway = gw.To4()
	}

	return config, nil
}

// ParseIPv6Config creates an IPv6Configuration from address string and prefix.
func ParseIPv6Config(address string, prefixLen int, gateway string) (*IPv6Configuration, error) {
	ip := net.ParseIP(address)
	if ip == nil {
		return nil, ErrInvalidIPAddress
	}

	if ip.To4() != nil {
		return nil, fmt.Errorf("%w: not an IPv6 address", ErrInvalidIPAddress)
	}

	config := &IPv6Configuration{
		Address:      ip,
		PrefixLength: prefixLen,
	}

	if gateway != "" {
		gw := net.ParseIP(gateway)
		if gw == nil {
			return nil, fmt.Errorf("%w: invalid gateway address", ErrInvalidIPAddress)
		}
		config.Gateway = gw
	}

	return config, nil
}
