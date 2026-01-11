// Package configuration provides network interface configuration management
// for the NIC Management service.
package configuration

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// =============================================================================
// MTU Error Types
// =============================================================================

var (
	// ErrMTUOutOfRange indicates MTU value outside valid range.
	ErrMTUOutOfRange = errors.New("MTU value out of range")
	// ErrMTUExceedsHardwareLimit indicates MTU larger than hardware supports.
	ErrMTUExceedsHardwareLimit = errors.New("MTU exceeds hardware limit")
	// ErrMTUValidationFailed indicates MTU ping test failed.
	ErrMTUValidationFailed = errors.New("MTU validation failed")
	// ErrFragmentationDetected indicates packet fragmentation observed.
	ErrFragmentationDetected = errors.New("fragmentation detected")
	// ErrJumboFramesNotSupported indicates hardware does not support jumbo frames.
	ErrJumboFramesNotSupported = errors.New("jumbo frames not supported")
	// ErrJumboFramesDisabled indicates jumbo frames are disabled in configuration.
	ErrJumboFramesDisabled = errors.New("jumbo frames disabled")
	// ErrMTUInterfaceNotFound indicates interface not found for MTU configuration.
	ErrMTUInterfaceNotFound = errors.New("interface not found for MTU")
)

// =============================================================================
// MTU Source Enumeration
// =============================================================================

// MTUSource represents how MTU configuration was established.
type MTUSource int

const (
	// MTUSourceStatic indicates manually configured static MTU.
	MTUSourceStatic MTUSource = iota
	// MTUSourceAutoDetected indicates automatically detected from interface.
	MTUSourceAutoDetected
	// MTUSourcePMTUD indicates determined via Path MTU Discovery.
	MTUSourcePMTUD
	// MTUSourceAdmin indicates set by administrator via API.
	MTUSourceAdmin
	// MTUSourceAdjusted indicates automatically adjusted for PPPoE/VPN.
	MTUSourceAdjusted
)

// String returns the string representation of the MTU source.
func (s MTUSource) String() string {
	switch s {
	case MTUSourceStatic:
		return "STATIC"
	case MTUSourceAutoDetected:
		return "AUTO_DETECTED"
	case MTUSourcePMTUD:
		return "PMTUD"
	case MTUSourceAdmin:
		return "ADMIN"
	case MTUSourceAdjusted:
		return "ADJUSTED"
	default:
		return "UNKNOWN"
	}
}

// =============================================================================
// Interface MTU Configuration Structure
// =============================================================================

// InterfaceMTUConfig contains MTU settings for a specific network interface.
type InterfaceMTUConfig struct {
	// InterfaceName is the interface with this MTU.
	InterfaceName string `json:"interface_name"`
	// MTU is the maximum transmission unit (bytes).
	MTU int `json:"mtu"`
	// OriginalMTU is the MTU before any adjustments (for rollback).
	OriginalMTU int `json:"original_mtu"`
	// MaxSupportedMTU is the hardware maximum from interface capabilities.
	MaxSupportedMTU int `json:"max_supported_mtu"`
	// Source indicates how MTU was configured.
	Source MTUSource `json:"source"`
	// InterfaceType is the interface type (ethernet, pppoe, vpn, loopback).
	InterfaceType string `json:"interface_type"`
	// ConfiguredAt is when MTU was configured.
	ConfiguredAt time.Time `json:"configured_at,omitempty"`
	// LastValidated is when MTU was last validated working.
	LastValidated time.Time `json:"last_validated,omitempty"`
	// IsActive indicates whether MTU is currently applied.
	IsActive bool `json:"is_active"`
	// FragmentationDetected indicates whether fragmentation observed.
	FragmentationDetected bool `json:"fragmentation_detected"`
}

// =============================================================================
// MTU Change Event Structure
// =============================================================================

// MTUChangeEvent records an MTU configuration change.
type MTUChangeEvent struct {
	// EventID is the unique event identifier.
	EventID string `json:"event_id"`
	// Timestamp is when change occurred.
	Timestamp time.Time `json:"timestamp"`
	// InterfaceName is the interface affected.
	InterfaceName string `json:"interface_name"`
	// OldMTU is the previous MTU value.
	OldMTU int `json:"old_mtu"`
	// NewMTU is the new MTU value.
	NewMTU int `json:"new_mtu"`
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
// MTU Manager Configuration
// =============================================================================

// MTUConfig contains configuration for MTU management behavior.
type MTUConfig struct {
	// DefaultMTU is the default MTU for Ethernet interfaces (default: 1500).
	DefaultMTU int `json:"default_mtu"`
	// MinMTU is the minimum allowed MTU value (default: 576).
	MinMTU int `json:"min_mtu"`
	// MaxMTU is the maximum allowed MTU value (default: 9000).
	MaxMTU int `json:"max_mtu"`
	// EnablePathMTUDiscovery performs PMTUD on WAN interfaces (default: true).
	EnablePathMTUDiscovery bool `json:"enable_path_mtu_discovery"`
	// PMTUDTimeout is max time for path MTU discovery (default: 10s).
	PMTUDTimeout time.Duration `json:"pmtud_timeout"`
	// PMTUDTarget is the target host for PMTUD (default: "8.8.8.8").
	PMTUDTarget string `json:"pmtud_target"`
	// AutoAdjustForPPPoE reduces MTU for PPPoE connections (default: true).
	AutoAdjustForPPPoE bool `json:"auto_adjust_for_pppoe"`
	// PPPoEMTU is the MTU for PPPoE interfaces (default: 1492).
	PPPoEMTU int `json:"pppoe_mtu"`
	// AutoAdjustForVPN reduces MTU for VPN tunnels (default: true).
	AutoAdjustForVPN bool `json:"auto_adjust_for_vpn"`
	// VPNMTUOverhead is additional overhead for VPN encapsulation (default: 50).
	VPNMTUOverhead int `json:"vpn_mtu_overhead"`
	// EnableJumboFrames allows MTU > 1500 on LAN (default: false).
	EnableJumboFrames bool `json:"enable_jumbo_frames"`
	// EnablePersistence saves MTU config to database (default: true).
	EnablePersistence bool `json:"enable_persistence"`
	// RestoreOnStartup restores persisted MTU on start (default: true).
	RestoreOnStartup bool `json:"restore_on_startup"`
	// ValidateMTUBeforeApply tests MTU with ICMP ping (default: true).
	ValidateMTUBeforeApply bool `json:"validate_mtu_before_apply"`
}

// DefaultMTUConfig returns the default MTU manager configuration.
func DefaultMTUConfig() *MTUConfig {
	return &MTUConfig{
		DefaultMTU:             1500,
		MinMTU:                 576,
		MaxMTU:                 9000,
		EnablePathMTUDiscovery: true,
		PMTUDTimeout:           10 * time.Second,
		PMTUDTarget:            "8.8.8.8",
		AutoAdjustForPPPoE:     true,
		PPPoEMTU:               1492,
		AutoAdjustForVPN:       true,
		VPNMTUOverhead:         50,
		EnableJumboFrames:      false,
		EnablePersistence:      true,
		RestoreOnStartup:       true,
		ValidateMTUBeforeApply: true,
	}
}

// =============================================================================
// Enumerator Interface for MTU
// =============================================================================

// MTUEnumeratorInterface defines interface discovery operations needed by MTU manager.
type MTUEnumeratorInterface interface {
	// InterfaceExists checks if an interface exists.
	InterfaceExists(interfaceName string) bool
	// GetInterfaceType returns the interface type.
	GetInterfaceType(interfaceName string) string
	// GetMaxSupportedMTU returns the hardware maximum MTU.
	GetMaxSupportedMTU(interfaceName string) int
}

// MTUDBInterface defines database operations for MTU persistence.
type MTUDBInterface interface {
	// LoadMTUConfigurations loads persisted MTU configurations.
	LoadMTUConfigurations(ctx context.Context) (map[string]*InterfaceMTUConfig, error)
	// SaveMTUConfiguration saves an MTU configuration.
	SaveMTUConfiguration(ctx context.Context, config *InterfaceMTUConfig) error
	// DeleteMTUConfiguration removes an MTU configuration.
	DeleteMTUConfiguration(ctx context.Context, interfaceName string) error
	// SaveMTUChangeEvent saves an MTU change event.
	SaveMTUChangeEvent(ctx context.Context, event *MTUChangeEvent) error
}

// =============================================================================
// No-Op Implementations
// =============================================================================

type noOpMTUEnumerator struct{}

func (n *noOpMTUEnumerator) InterfaceExists(interfaceName string) bool {
	_, err := net.InterfaceByName(interfaceName)
	return err == nil
}

func (n *noOpMTUEnumerator) GetInterfaceType(interfaceName string) string {
	name := strings.ToLower(interfaceName)
	if strings.HasPrefix(name, "ppp") {
		return "pppoe"
	}
	if strings.HasPrefix(name, "tun") || strings.HasPrefix(name, "tap") || strings.HasPrefix(name, "wg") {
		return "vpn"
	}
	if strings.HasPrefix(name, "lo") {
		return "loopback"
	}
	return "ethernet"
}

func (n *noOpMTUEnumerator) GetMaxSupportedMTU(interfaceName string) int {
	// Default hardware limit for most interfaces.
	return 9000
}

type noOpMTUDB struct{}

func (n *noOpMTUDB) LoadMTUConfigurations(ctx context.Context) (map[string]*InterfaceMTUConfig, error) {
	return make(map[string]*InterfaceMTUConfig), nil
}

func (n *noOpMTUDB) SaveMTUConfiguration(ctx context.Context, config *InterfaceMTUConfig) error {
	return nil
}

func (n *noOpMTUDB) DeleteMTUConfiguration(ctx context.Context, interfaceName string) error {
	return nil
}

func (n *noOpMTUDB) SaveMTUChangeEvent(ctx context.Context, event *MTUChangeEvent) error {
	return nil
}

// =============================================================================
// MTU Manager
// =============================================================================

// MTUManager manages MTU configuration.
type MTUManager struct {
	// Dependencies.
	enumerator MTUEnumeratorInterface
	db         MTUDBInterface

	// Configuration.
	config *MTUConfig

	// State.
	interfaceMTU map[string]*InterfaceMTUConfig
	mu           sync.RWMutex

	// History.
	mtuHistory   []*MTUChangeEvent
	mtuHistoryMu sync.RWMutex

	// Platform.
	platform Platform

	// Statistics.
	mtuConfigChanges      uint64
	mtuValidationSuccess  uint64
	mtuValidationFailures uint64
	pmtudAttempts         uint64
	fragmentationEvents   uint64

	// Control.
	stopChan  chan struct{}
	running   bool
	runningMu sync.Mutex
}

// NewMTUManager creates a new MTU manager.
func NewMTUManager(
	enumerator MTUEnumeratorInterface,
	db MTUDBInterface,
	config *MTUConfig,
) *MTUManager {
	if config == nil {
		config = DefaultMTUConfig()
	}

	if enumerator == nil {
		enumerator = &noOpMTUEnumerator{}
	}

	if db == nil {
		db = &noOpMTUDB{}
	}

	return &MTUManager{
		enumerator:   enumerator,
		db:           db,
		config:       config,
		interfaceMTU: make(map[string]*InterfaceMTUConfig),
		mtuHistory:   make([]*MTUChangeEvent, 0, 500),
		platform:     DetectPlatform(),
		stopChan:     make(chan struct{}),
	}
}

// =============================================================================
// Lifecycle Management
// =============================================================================

// Start initializes the MTU manager.
func (mm *MTUManager) Start(ctx context.Context) error {
	mm.runningMu.Lock()
	defer mm.runningMu.Unlock()

	if mm.running {
		return nil
	}

	// Validate platform support.
	if mm.platform == PlatformUnknown {
		return ErrPlatformUnsupported
	}

	// Load persisted MTU configurations if enabled.
	if mm.config.RestoreOnStartup {
		configs, err := mm.db.LoadMTUConfigurations(ctx)
		if err == nil && configs != nil {
			mm.mu.Lock()
			for name, cfg := range configs {
				if mm.enumerator.InterfaceExists(name) {
					mm.interfaceMTU[name] = cfg
				}
			}
			mm.mu.Unlock()
		}
	}

	// Auto-detect MTU for system interfaces.
	ifaces, err := net.Interfaces()
	if err == nil {
		for _, iface := range ifaces {
			mm.mu.RLock()
			_, hasConfig := mm.interfaceMTU[iface.Name]
			mm.mu.RUnlock()

			if !hasConfig && iface.MTU > 0 {
				cfg := &InterfaceMTUConfig{
					InterfaceName:   iface.Name,
					MTU:             iface.MTU,
					OriginalMTU:     iface.MTU,
					MaxSupportedMTU: mm.enumerator.GetMaxSupportedMTU(iface.Name),
					Source:          MTUSourceAutoDetected,
					InterfaceType:   mm.enumerator.GetInterfaceType(iface.Name),
					ConfiguredAt:    time.Now(),
					IsActive:        true,
				}

				mm.mu.Lock()
				mm.interfaceMTU[iface.Name] = cfg
				mm.mu.Unlock()
			}
		}
	}

	mm.running = true
	return nil
}

// Stop shuts down the MTU manager.
func (mm *MTUManager) Stop() error {
	mm.runningMu.Lock()
	if !mm.running {
		mm.runningMu.Unlock()
		return nil
	}
	mm.running = false
	mm.runningMu.Unlock()

	close(mm.stopChan)

	// Persist all MTU configurations.
	if mm.config.EnablePersistence {
		mm.mu.RLock()
		configs := make(map[string]*InterfaceMTUConfig, len(mm.interfaceMTU))
		for name, cfg := range mm.interfaceMTU {
			configs[name] = cfg
		}
		mm.mu.RUnlock()

		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()

		for _, cfg := range configs {
			_ = mm.db.SaveMTUConfiguration(ctx, cfg)
		}
	}

	return nil
}

// =============================================================================
// MTU Configuration
// =============================================================================

// SetInterfaceMTU configures MTU for specific network interface.
func (mm *MTUManager) SetInterfaceMTU(ctx context.Context, config *InterfaceMTUConfig) error {
	if config == nil {
		return errors.New("MTU configuration cannot be nil")
	}

	if config.InterfaceName == "" {
		return errors.New("interface name cannot be empty")
	}

	// Validate MTU range.
	if config.MTU < mm.config.MinMTU || config.MTU > mm.config.MaxMTU {
		return fmt.Errorf("%w: must be between %d and %d, got %d",
			ErrMTUOutOfRange, mm.config.MinMTU, mm.config.MaxMTU, config.MTU)
	}

	// Validate interface exists.
	if !mm.enumerator.InterfaceExists(config.InterfaceName) {
		return fmt.Errorf("%w: %s", ErrMTUInterfaceNotFound, config.InterfaceName)
	}

	// Validate against hardware limits.
	maxSupported := mm.enumerator.GetMaxSupportedMTU(config.InterfaceName)
	if config.MTU > maxSupported {
		return fmt.Errorf("%w: hardware maximum is %d", ErrMTUExceedsHardwareLimit, maxSupported)
	}
	config.MaxSupportedMTU = maxSupported

	atomic.AddUint64(&mm.mtuConfigChanges, 1)

	// Validate MTU with ping if enabled.
	if mm.config.ValidateMTUBeforeApply {
		if err := mm.validateMTUWithPing(config.InterfaceName, config.MTU); err != nil {
			atomic.AddUint64(&mm.mtuValidationFailures, 1)
			return fmt.Errorf("%w: %v", ErrMTUValidationFailed, err)
		}
		atomic.AddUint64(&mm.mtuValidationSuccess, 1)
		config.LastValidated = time.Now()
	}

	// Backup current MTU.
	currentMTU, err := mm.getCurrentMTU(config.InterfaceName)
	if err == nil {
		config.OriginalMTU = currentMTU
	}

	// Get old config for event.
	mm.mu.RLock()
	oldConfig := mm.interfaceMTU[config.InterfaceName]
	mm.mu.RUnlock()

	var oldMTU int
	if oldConfig != nil {
		oldMTU = oldConfig.MTU
	}

	// Apply MTU to interface.
	switch mm.platform {
	case PlatformLinux:
		err = mm.setInterfaceMTULinux(config)
	case PlatformWindows:
		err = mm.setInterfaceMTUWindows(config)
	default:
		err = ErrPlatformUnsupported
	}

	if err != nil {
		mm.recordEvent(config.InterfaceName, oldMTU, config.MTU, "SET_MTU", "system", false, err.Error())
		return err
	}

	// Update state.
	mm.mu.Lock()
	config.IsActive = true
	config.ConfiguredAt = time.Now()
	config.InterfaceType = mm.enumerator.GetInterfaceType(config.InterfaceName)
	mm.interfaceMTU[config.InterfaceName] = config
	mm.mu.Unlock()

	// Record event.
	mm.recordEvent(config.InterfaceName, oldMTU, config.MTU, "SET_MTU", "system", true, "")

	// Persist configuration.
	if mm.config.EnablePersistence {
		_ = mm.db.SaveMTUConfiguration(ctx, config)
	}

	return nil
}

// setInterfaceMTULinux sets MTU on Linux.
func (mm *MTUManager) setInterfaceMTULinux(config *InterfaceMTUConfig) error {
	_ = config // Will be used in production implementation.

	// In production, this would use github.com/vishvananda/netlink:
	//
	// link, err := netlink.LinkByName(config.InterfaceName)
	// if err != nil {
	//     return err
	// }
	//
	// err = netlink.LinkSetMTU(link, config.MTU)
	// if err != nil {
	//     return err
	// }
	//
	// // Verify MTU propagated.
	// content, _ := os.ReadFile(fmt.Sprintf("/sys/class/net/%s/mtu", config.InterfaceName))
	// actualMTU, _ := strconv.Atoi(strings.TrimSpace(string(content)))
	// if actualMTU != config.MTU {
	//     return fmt.Errorf("MTU verification failed: expected %d, got %d", config.MTU, actualMTU)
	// }

	return nil
}

// setInterfaceMTUWindows sets MTU on Windows.
func (mm *MTUManager) setInterfaceMTUWindows(config *InterfaceMTUConfig) error {
	_ = config // Will be used in production implementation.

	// In production, this would use netsh:
	//
	// cmd := exec.Command("netsh", "interface", "ipv4", "set", "subinterface",
	//     config.InterfaceName,
	//     fmt.Sprintf("mtu=%d", config.MTU),
	//     "store=persistent")
	// err := cmd.Run()
	// if err != nil {
	//     return err
	// }
	//
	// // For IPv6:
	// exec.Command("netsh", "interface", "ipv6", "set", "subinterface",
	//     config.InterfaceName,
	//     fmt.Sprintf("mtu=%d", config.MTU),
	//     "store=persistent").Run()

	return nil
}

// =============================================================================
// MTU Queries
// =============================================================================

// getCurrentMTU retrieves active MTU from operating system.
func (mm *MTUManager) getCurrentMTU(interfaceName string) (int, error) {
	switch mm.platform {
	case PlatformLinux:
		return mm.getCurrentMTULinux(interfaceName)
	case PlatformWindows:
		return mm.getCurrentMTUWindows(interfaceName)
	default:
		return 0, ErrPlatformUnsupported
	}
}

// getCurrentMTULinux gets current MTU on Linux.
func (mm *MTUManager) getCurrentMTULinux(interfaceName string) (int, error) {
	iface, err := net.InterfaceByName(interfaceName)
	if err != nil {
		return 0, err
	}
	return iface.MTU, nil
}

// getCurrentMTUWindows gets current MTU on Windows.
func (mm *MTUManager) getCurrentMTUWindows(interfaceName string) (int, error) {
	iface, err := net.InterfaceByName(interfaceName)
	if err != nil {
		return 0, err
	}
	return iface.MTU, nil
}

// =============================================================================
// MTU Validation
// =============================================================================

// validateMTUWithPing tests MTU value by sending ICMP packet with Don't Fragment flag.
func (mm *MTUManager) validateMTUWithPing(interfaceName string, mtu int) error {
	_ = interfaceName
	_ = mtu

	// In production, this would:
	//
	// 1. Create raw ICMP socket
	// conn, err := icmp.ListenPacket("ip4:icmp", "0.0.0.0")
	// if err != nil {
	//     return err
	// }
	// defer conn.Close()
	//
	// 2. Create ICMP Echo Request
	// msg := icmp.Message{
	//     Type: ipv4.ICMPTypeEcho,
	//     Code: 0,
	//     Body: &icmp.Echo{
	//         ID:   os.Getpid() & 0xffff,
	//         Seq:  1,
	//         Data: make([]byte, mtu - 20 - 8), // MTU - IP header - ICMP header
	//     },
	// }
	// msgBytes, _ := msg.Marshal(nil)
	//
	// 3. Send to target with DF flag
	// dst, _ := net.ResolveIPAddr("ip4", mm.config.PMTUDTarget)
	// conn.WriteTo(msgBytes, dst)
	//
	// 4. Wait for response or "Fragmentation Needed" error
	// conn.SetReadDeadline(time.Now().Add(mm.config.PMTUDTimeout))
	// response := make([]byte, 1500)
	// n, _, err := conn.ReadFrom(response)
	// if err != nil {
	//     return ErrMTUValidationFailed
	// }
	//
	// 5. Parse response - check for "Fragmentation Needed" ICMP error
	// resp, _ := icmp.ParseMessage(1, response[:n])
	// if resp.Type == ipv4.ICMPTypeDestinationUnreachable {
	//     return ErrMTUValidationFailed
	// }

	// Stub: Assume MTU validation passes.
	return nil
}

// =============================================================================
// Path MTU Discovery
// =============================================================================

// DiscoverPathMTU performs Path MTU Discovery for WAN interface.
func (mm *MTUManager) DiscoverPathMTU(ctx context.Context, interfaceName string) (int, error) {
	if !mm.config.EnablePathMTUDiscovery {
		return mm.config.DefaultMTU, nil
	}

	atomic.AddUint64(&mm.pmtudAttempts, 1)

	// Binary search for optimal MTU.
	minMTU := mm.config.MinMTU
	maxMTU := mm.config.DefaultMTU
	discoveredMTU := minMTU

	for minMTU <= maxMTU {
		select {
		case <-ctx.Done():
			return discoveredMTU, ctx.Err()
		default:
		}

		midpoint := (minMTU + maxMTU) / 2

		err := mm.validateMTUWithPing(interfaceName, midpoint)
		if err == nil {
			// MTU works, try larger.
			discoveredMTU = midpoint
			minMTU = midpoint + 1
		} else {
			// MTU too large, try smaller.
			maxMTU = midpoint - 1
		}
	}

	return discoveredMTU, nil
}

// =============================================================================
// Automatic MTU Adjustment
// =============================================================================

// AutoAdjustForPPPoE reduces MTU for PPPoE connections.
func (mm *MTUManager) AutoAdjustForPPPoE(ctx context.Context, interfaceName string) error {
	if !mm.config.AutoAdjustForPPPoE {
		return nil
	}

	ifaceType := mm.enumerator.GetInterfaceType(interfaceName)
	if ifaceType != "pppoe" {
		return nil
	}

	config := &InterfaceMTUConfig{
		InterfaceName: interfaceName,
		MTU:           mm.config.PPPoEMTU,
		Source:        MTUSourceAdjusted,
		InterfaceType: "pppoe",
	}

	return mm.SetInterfaceMTU(ctx, config)
}

// AutoAdjustForVPN reduces MTU for VPN tunnel interfaces.
func (mm *MTUManager) AutoAdjustForVPN(ctx context.Context, interfaceName string) error {
	if !mm.config.AutoAdjustForVPN {
		return nil
	}

	ifaceType := mm.enumerator.GetInterfaceType(interfaceName)
	if ifaceType != "vpn" {
		return nil
	}

	// Calculate VPN MTU.
	baseMTU := mm.config.DefaultMTU
	vpnMTU := baseMTU - mm.config.VPNMTUOverhead

	config := &InterfaceMTUConfig{
		InterfaceName: interfaceName,
		MTU:           vpnMTU,
		Source:        MTUSourceAdjusted,
		InterfaceType: "vpn",
	}

	return mm.SetInterfaceMTU(ctx, config)
}

// =============================================================================
// Query Methods
// =============================================================================

// GetInterfaceMTU retrieves MTU configuration for specific interface.
func (mm *MTUManager) GetInterfaceMTU(interfaceName string) (*InterfaceMTUConfig, error) {
	mm.mu.RLock()
	defer mm.mu.RUnlock()

	config, exists := mm.interfaceMTU[interfaceName]
	if !exists {
		return nil, ErrMTUInterfaceNotFound
	}

	// Return copy.
	copy := *config
	return &copy, nil
}

// GetAllMTUConfigurations retrieves all interface MTU configurations.
func (mm *MTUManager) GetAllMTUConfigurations() map[string]*InterfaceMTUConfig {
	mm.mu.RLock()
	defer mm.mu.RUnlock()

	result := make(map[string]*InterfaceMTUConfig, len(mm.interfaceMTU))
	for name, cfg := range mm.interfaceMTU {
		copy := *cfg
		result[name] = &copy
	}
	return result
}

// ResetInterfaceMTU restores interface to original MTU.
func (mm *MTUManager) ResetInterfaceMTU(ctx context.Context, interfaceName string) error {
	mm.mu.RLock()
	config := mm.interfaceMTU[interfaceName]
	mm.mu.RUnlock()

	if config == nil {
		return ErrMTUInterfaceNotFound
	}

	if config.OriginalMTU == 0 {
		config.OriginalMTU = mm.config.DefaultMTU
	}

	resetConfig := &InterfaceMTUConfig{
		InterfaceName: interfaceName,
		MTU:           config.OriginalMTU,
		Source:        MTUSourceAdmin,
		InterfaceType: config.InterfaceType,
	}

	return mm.SetInterfaceMTU(ctx, resetConfig)
}

// =============================================================================
// Jumbo Frames
// =============================================================================

// EnableJumboFrames configures interface for jumbo frames (MTU > 1500).
func (mm *MTUManager) EnableJumboFrames(ctx context.Context, interfaceName string, mtu int) error {
	if !mm.config.EnableJumboFrames {
		return ErrJumboFramesDisabled
	}

	if mtu <= 1500 {
		return fmt.Errorf("%w: MTU must be > 1500 for jumbo frames", ErrMTUOutOfRange)
	}

	if mtu > mm.config.MaxMTU {
		return fmt.Errorf("%w: maximum is %d", ErrMTUOutOfRange, mm.config.MaxMTU)
	}

	// Check hardware support.
	maxSupported := mm.enumerator.GetMaxSupportedMTU(interfaceName)
	if maxSupported < mtu {
		return fmt.Errorf("%w: hardware maximum is %d", ErrJumboFramesNotSupported, maxSupported)
	}

	config := &InterfaceMTUConfig{
		InterfaceName:   interfaceName,
		MTU:             mtu,
		MaxSupportedMTU: maxSupported,
		Source:          MTUSourceAdmin,
		InterfaceType:   mm.enumerator.GetInterfaceType(interfaceName),
	}

	return mm.SetInterfaceMTU(ctx, config)
}

// DisableJumboFrames resets interface to standard MTU.
func (mm *MTUManager) DisableJumboFrames(ctx context.Context, interfaceName string) error {
	config := &InterfaceMTUConfig{
		InterfaceName: interfaceName,
		MTU:           mm.config.DefaultMTU,
		Source:        MTUSourceAdmin,
		InterfaceType: mm.enumerator.GetInterfaceType(interfaceName),
	}

	return mm.SetInterfaceMTU(ctx, config)
}

// =============================================================================
// Fragmentation Detection
// =============================================================================

// DetectFragmentation monitors interface for packet fragmentation events.
func (mm *MTUManager) DetectFragmentation(interfaceName string) (bool, error) {
	mm.mu.RLock()
	config := mm.interfaceMTU[interfaceName]
	mm.mu.RUnlock()

	if config == nil {
		return false, ErrMTUInterfaceNotFound
	}

	// In production, this would:
	//
	// Linux: Read /proc/net/snmp for IP fragmentation counters:
	// content, _ := os.ReadFile("/proc/net/snmp")
	// Parse Ip: ... FragCreates FragFails ...
	//
	// Windows: Query performance counters for fragmented packets
	//
	// Compare current count with previous reading to detect new fragmentation.

	// Stub: No fragmentation detected.
	fragmentationDetected := false

	if fragmentationDetected {
		atomic.AddUint64(&mm.fragmentationEvents, 1)

		mm.mu.Lock()
		config.FragmentationDetected = true
		mm.mu.Unlock()
	}

	return fragmentationDetected, nil
}

// GetMTUHistory retrieves historical MTU change events.
func (mm *MTUManager) GetMTUHistory(limit int) []*MTUChangeEvent {
	mm.mtuHistoryMu.RLock()
	defer mm.mtuHistoryMu.RUnlock()

	if len(mm.mtuHistory) == 0 {
		return nil
	}

	start := 0
	if len(mm.mtuHistory) > limit {
		start = len(mm.mtuHistory) - limit
	}

	result := make([]*MTUChangeEvent, len(mm.mtuHistory)-start)
	for i, event := range mm.mtuHistory[start:] {
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

// recordEvent creates and stores an MTU change event.
func (mm *MTUManager) recordEvent(interfaceName string, oldMTU, newMTU int, reason, triggeredBy string, success bool, errorMsg string) {
	event := &MTUChangeEvent{
		EventID:       generateConfigUUID(),
		Timestamp:     time.Now(),
		InterfaceName: interfaceName,
		OldMTU:        oldMTU,
		NewMTU:        newMTU,
		ChangeReason:  reason,
		TriggeredBy:   triggeredBy,
		Success:       success,
		ErrorMessage:  errorMsg,
	}

	mm.mtuHistoryMu.Lock()
	mm.mtuHistory = append(mm.mtuHistory, event)
	if len(mm.mtuHistory) > 500 {
		mm.mtuHistory = mm.mtuHistory[len(mm.mtuHistory)-500:]
	}
	mm.mtuHistoryMu.Unlock()

	// Persist event.
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_ = mm.db.SaveMTUChangeEvent(ctx, event)
}

// =============================================================================
// Health Check
// =============================================================================

// HealthCheck verifies the manager is operational.
func (mm *MTUManager) HealthCheck() error {
	if mm.platform == PlatformUnknown {
		return ErrPlatformUnsupported
	}

	mm.runningMu.Lock()
	running := mm.running
	mm.runningMu.Unlock()

	if !running {
		return errors.New("MTU manager not running")
	}

	// Check all configured MTUs are within valid range.
	mm.mu.RLock()
	defer mm.mu.RUnlock()

	for name, cfg := range mm.interfaceMTU {
		if cfg.MTU < mm.config.MinMTU || cfg.MTU > mm.config.MaxMTU {
			return fmt.Errorf("interface %s has invalid MTU %d", name, cfg.MTU)
		}

		if cfg.FragmentationDetected {
			return fmt.Errorf("fragmentation detected on interface %s", name)
		}
	}

	return nil
}

// =============================================================================
// Statistics
// =============================================================================

// GetStatistics returns MTU management statistics.
func (mm *MTUManager) GetStatistics() map[string]uint64 {
	return map[string]uint64{
		"mtu_config_changes":      atomic.LoadUint64(&mm.mtuConfigChanges),
		"mtu_validation_success":  atomic.LoadUint64(&mm.mtuValidationSuccess),
		"mtu_validation_failures": atomic.LoadUint64(&mm.mtuValidationFailures),
		"pmtud_attempts":          atomic.LoadUint64(&mm.pmtudAttempts),
		"fragmentation_events":    atomic.LoadUint64(&mm.fragmentationEvents),
	}
}

// GetConfig returns the current configuration.
func (mm *MTUManager) GetConfig() *MTUConfig {
	return mm.config
}

// GetPlatform returns the detected platform.
func (mm *MTUManager) GetPlatform() Platform {
	return mm.platform
}
