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
// DNS Error Types
// =============================================================================

var (
	// ErrDNSServerUnreachable indicates DNS server validation query failed.
	ErrDNSServerUnreachable = errors.New("DNS server unreachable")
	// ErrMaxDNSServersExceeded indicates too many DNS servers configured.
	ErrMaxDNSServersExceeded = errors.New("maximum DNS servers exceeded")
	// ErrNoDNSServersConfigured indicates no DNS servers available.
	ErrNoDNSServersConfigured = errors.New("no DNS servers configured")
	// ErrDNSConfigFileFailed indicates unable to write DNS configuration.
	ErrDNSConfigFileFailed = errors.New("DNS configuration file update failed")
	// ErrInvalidDNSServer indicates DNS server IP address invalid.
	ErrInvalidDNSServer = errors.New("invalid DNS server")
	// ErrDNSServerNotFound indicates DNS server not in interface configuration.
	ErrDNSServerNotFound = errors.New("DNS server not found")
	// ErrDNSInterfaceNotFound indicates interface not found for DNS configuration.
	ErrDNSInterfaceNotFound = errors.New("interface not found for DNS")
)

// =============================================================================
// DNS Source Enumeration
// =============================================================================

// DNSSource represents how DNS configuration was established.
type DNSSource int

const (
	// DNSSourceStatic indicates manually configured static DNS servers.
	DNSSourceStatic DNSSource = iota
	// DNSSourceDHCP indicates DNS servers received from DHCP server.
	DNSSourceDHCP
	// DNSSourceFailover indicates DNS servers configured by failover manager.
	DNSSourceFailover
	// DNSSourceAdmin indicates DNS servers set by administrator via API.
	DNSSourceAdmin
	// DNSSourceAuto indicates automatically detected from interface.
	DNSSourceAuto
)

// String returns the string representation of the DNS source.
func (s DNSSource) String() string {
	switch s {
	case DNSSourceStatic:
		return "STATIC"
	case DNSSourceDHCP:
		return "DHCP"
	case DNSSourceFailover:
		return "FAILOVER"
	case DNSSourceAdmin:
		return "ADMIN"
	case DNSSourceAuto:
		return "AUTO"
	default:
		return "UNKNOWN"
	}
}

// =============================================================================
// Interface DNS Configuration Structure
// =============================================================================

// InterfaceDNSConfig contains DNS settings for a specific network interface.
type InterfaceDNSConfig struct {
	// InterfaceName is the interface with these DNS servers.
	InterfaceName string `json:"interface_name"`
	// DNSServers contains DNS server addresses.
	DNSServers []net.IP `json:"dns_servers"`
	// SearchDomains contains DNS search domains for this interface.
	SearchDomains []string `json:"search_domains,omitempty"`
	// Source indicates how DNS servers were configured.
	Source DNSSource `json:"source"`
	// ConfiguredAt is when DNS servers were configured.
	ConfiguredAt time.Time `json:"configured_at,omitempty"`
	// LastValidated is when DNS servers were last validated.
	LastValidated time.Time `json:"last_validated,omitempty"`
	// IsActive indicates whether these DNS servers are currently in use.
	IsActive bool `json:"is_active"`
}

// =============================================================================
// System DNS Configuration Structure
// =============================================================================

// SystemDNSConfig contains system-wide DNS resolver configuration.
type SystemDNSConfig struct {
	// PrimaryDNS is the primary DNS server.
	PrimaryDNS net.IP `json:"primary_dns,omitempty"`
	// SecondaryDNS is the secondary DNS server.
	SecondaryDNS net.IP `json:"secondary_dns,omitempty"`
	// TertiaryDNS is the tertiary DNS server (optional).
	TertiaryDNS net.IP `json:"tertiary_dns,omitempty"`
	// SearchDomains contains DNS search domains.
	SearchDomains []string `json:"search_domains,omitempty"`
	// Options contains resolver options.
	Options []string `json:"options,omitempty"`
	// ConfiguredAt is when system DNS was configured.
	ConfiguredAt time.Time `json:"configured_at,omitempty"`
	// SourceInterface is the interface providing these DNS servers.
	SourceInterface string `json:"source_interface,omitempty"`
}

// =============================================================================
// DNS Change Event Structure
// =============================================================================

// DNSChangeEvent records a DNS configuration change.
type DNSChangeEvent struct {
	// EventID is the unique event identifier.
	EventID string `json:"event_id"`
	// Timestamp is when change occurred.
	Timestamp time.Time `json:"timestamp"`
	// InterfaceName is the interface affected (empty for system-wide).
	InterfaceName string `json:"interface_name,omitempty"`
	// OldDNSServers contains the previous DNS servers.
	OldDNSServers []net.IP `json:"old_dns_servers,omitempty"`
	// NewDNSServers contains the new DNS servers.
	NewDNSServers []net.IP `json:"new_dns_servers,omitempty"`
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
// DNS Manager Configuration
// =============================================================================

// DNSConfig contains configuration for DNS management behavior.
type DNSConfig struct {
	// ValidateDNSServers queries DNS servers before activation (default: true).
	ValidateDNSServers bool `json:"validate_dns_servers"`
	// DNSValidationTimeout is max time for DNS query validation (default: 3s).
	DNSValidationTimeout time.Duration `json:"dns_validation_timeout"`
	// DNSValidationQuery is the hostname to query for validation (default: "google.com").
	DNSValidationQuery string `json:"dns_validation_query"`
	// MaxDNSServersPerInterface is maximum nameservers per interface (default: 3).
	MaxDNSServersPerInterface int `json:"max_dns_servers_per_interface"`
	// EnableSystemDNS configures system-wide DNS (default: true).
	EnableSystemDNS bool `json:"enable_system_dns"`
	// PreferIPv4DNS prioritizes IPv4 DNS servers over IPv6 (default: true).
	PreferIPv4DNS bool `json:"prefer_ipv4_dns"`
	// DNSSearchDomains contains DNS search domains.
	DNSSearchDomains []string `json:"dns_search_domains,omitempty"`
	// DNSOptions contains resolver options.
	DNSOptions []string `json:"dns_options,omitempty"`
	// EnablePersistence saves DNS config to database (default: true).
	EnablePersistence bool `json:"enable_persistence"`
	// RestoreOnStartup restores persisted DNS on start (default: true).
	RestoreOnStartup bool `json:"restore_on_startup"`
	// SyncWithDHCP coordinates with DHCP-provided DNS servers (default: true).
	SyncWithDHCP bool `json:"sync_with_dhcp"`
	// FallbackDNSServers contains DNS servers to use if all configured fail.
	FallbackDNSServers []net.IP `json:"fallback_dns_servers,omitempty"`
}

// DefaultDNSConfig returns the default DNS manager configuration.
func DefaultDNSConfig() *DNSConfig {
	return &DNSConfig{
		ValidateDNSServers:        true,
		DNSValidationTimeout:      3 * time.Second,
		DNSValidationQuery:        "google.com",
		MaxDNSServersPerInterface: 3,
		EnableSystemDNS:           true,
		PreferIPv4DNS:             true,
		DNSSearchDomains:          []string{},
		DNSOptions:                []string{},
		EnablePersistence:         true,
		RestoreOnStartup:          true,
		SyncWithDHCP:              true,
		FallbackDNSServers: []net.IP{
			net.ParseIP("8.8.8.8"),
			net.ParseIP("1.1.1.1"),
		},
	}
}

// =============================================================================
// WAN Selector Interface for DNS
// =============================================================================

// WANSelectorDNSInterface defines WAN selector operations needed by DNS manager.
type WANSelectorDNSInterface interface {
	// WANExists checks if a WAN interface exists.
	WANExists(wanID string) bool
	// GetActiveWAN returns the currently active WAN interface.
	GetActiveWAN() string
	// InterfaceExists checks if an interface exists.
	InterfaceExists(interfaceName string) bool
}

// DNSDBInterface defines database operations for DNS persistence.
type DNSDBInterface interface {
	// LoadDNSConfigurations loads persisted DNS configurations.
	LoadDNSConfigurations(ctx context.Context) (map[string]*InterfaceDNSConfig, error)
	// SaveDNSConfiguration saves a DNS configuration.
	SaveDNSConfiguration(ctx context.Context, config *InterfaceDNSConfig) error
	// DeleteDNSConfiguration removes a DNS configuration.
	DeleteDNSConfiguration(ctx context.Context, interfaceName string) error
	// SaveDNSChangeEvent saves a DNS change event.
	SaveDNSChangeEvent(ctx context.Context, event *DNSChangeEvent) error
}

// =============================================================================
// No-Op Implementations
// =============================================================================

type noOpWANSelectorDNS struct{}

func (n *noOpWANSelectorDNS) WANExists(wanID string) bool {
	return true
}

func (n *noOpWANSelectorDNS) GetActiveWAN() string {
	return "wan0"
}

func (n *noOpWANSelectorDNS) InterfaceExists(interfaceName string) bool {
	_, err := net.InterfaceByName(interfaceName)
	return err == nil
}

type noOpDNSDB struct{}

func (n *noOpDNSDB) LoadDNSConfigurations(ctx context.Context) (map[string]*InterfaceDNSConfig, error) {
	return make(map[string]*InterfaceDNSConfig), nil
}

func (n *noOpDNSDB) SaveDNSConfiguration(ctx context.Context, config *InterfaceDNSConfig) error {
	return nil
}

func (n *noOpDNSDB) DeleteDNSConfiguration(ctx context.Context, interfaceName string) error {
	return nil
}

func (n *noOpDNSDB) SaveDNSChangeEvent(ctx context.Context, event *DNSChangeEvent) error {
	return nil
}

// =============================================================================
// DNS Manager
// =============================================================================

// DNSManager manages DNS server configuration.
type DNSManager struct {
	// Dependencies.
	wanSelector WANSelectorDNSInterface
	db          DNSDBInterface

	// Configuration.
	config *DNSConfig

	// State.
	interfaceDNS map[string]*InterfaceDNSConfig
	systemDNS    *SystemDNSConfig
	mu           sync.RWMutex

	// History.
	dnsHistory   []*DNSChangeEvent
	dnsHistoryMu sync.RWMutex

	// Platform.
	platform Platform

	// Statistics.
	dnsConfigChanges      uint64
	dnsValidationSuccess  uint64
	dnsValidationFailures uint64
	systemDNSUpdates      uint64

	// Control.
	stopChan  chan struct{}
	running   bool
	runningMu sync.Mutex
}

// NewDNSManager creates a new DNS manager.
func NewDNSManager(
	wanSelector WANSelectorDNSInterface,
	db DNSDBInterface,
	config *DNSConfig,
) *DNSManager {
	if config == nil {
		config = DefaultDNSConfig()
	}

	if wanSelector == nil {
		wanSelector = &noOpWANSelectorDNS{}
	}

	if db == nil {
		db = &noOpDNSDB{}
	}

	// Initialize system DNS with fallback servers.
	systemDNS := &SystemDNSConfig{
		SearchDomains: config.DNSSearchDomains,
		Options:       config.DNSOptions,
	}
	if len(config.FallbackDNSServers) > 0 {
		systemDNS.PrimaryDNS = config.FallbackDNSServers[0]
	}
	if len(config.FallbackDNSServers) > 1 {
		systemDNS.SecondaryDNS = config.FallbackDNSServers[1]
	}

	return &DNSManager{
		wanSelector:  wanSelector,
		db:           db,
		config:       config,
		interfaceDNS: make(map[string]*InterfaceDNSConfig),
		systemDNS:    systemDNS,
		dnsHistory:   make([]*DNSChangeEvent, 0, 500),
		platform:     DetectPlatform(),
		stopChan:     make(chan struct{}),
	}
}

// =============================================================================
// Lifecycle Management
// =============================================================================

// Start initializes the DNS manager.
func (dm *DNSManager) Start(ctx context.Context) error {
	dm.runningMu.Lock()
	defer dm.runningMu.Unlock()

	if dm.running {
		return nil
	}

	// Validate platform support.
	if dm.platform == PlatformUnknown {
		return ErrPlatformUnsupported
	}

	// Load persisted DNS configurations if enabled.
	if dm.config.RestoreOnStartup {
		configs, err := dm.db.LoadDNSConfigurations(ctx)
		if err == nil && configs != nil {
			dm.mu.Lock()
			for name, cfg := range configs {
				if dm.wanSelector.InterfaceExists(name) {
					dm.interfaceDNS[name] = cfg
				}
			}
			dm.mu.Unlock()
		}
	}

	// Detect current system DNS if none configured.
	dm.mu.RLock()
	hasPrimaryDNS := dm.systemDNS.PrimaryDNS != nil
	dm.mu.RUnlock()

	if !hasPrimaryDNS {
		currentDNS, err := dm.getCurrentDNSFromOS()
		if err == nil && currentDNS != nil {
			dm.mu.Lock()
			dm.systemDNS = currentDNS
			dm.mu.Unlock()
		}
	}

	// Apply fallback DNS if still no DNS configured.
	dm.mu.RLock()
	stillNoDNS := dm.systemDNS.PrimaryDNS == nil
	dm.mu.RUnlock()

	if stillNoDNS && len(dm.config.FallbackDNSServers) > 0 {
		dm.mu.Lock()
		dm.systemDNS.PrimaryDNS = dm.config.FallbackDNSServers[0]
		if len(dm.config.FallbackDNSServers) > 1 {
			dm.systemDNS.SecondaryDNS = dm.config.FallbackDNSServers[1]
		}
		dm.mu.Unlock()
	}

	dm.running = true
	return nil
}

// Stop shuts down the DNS manager.
func (dm *DNSManager) Stop() error {
	dm.runningMu.Lock()
	if !dm.running {
		dm.runningMu.Unlock()
		return nil
	}
	dm.running = false
	dm.runningMu.Unlock()

	close(dm.stopChan)

	// Persist all DNS configurations.
	if dm.config.EnablePersistence {
		dm.mu.RLock()
		configs := make(map[string]*InterfaceDNSConfig, len(dm.interfaceDNS))
		for name, cfg := range dm.interfaceDNS {
			configs[name] = cfg
		}
		dm.mu.RUnlock()

		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()

		for _, cfg := range configs {
			_ = dm.db.SaveDNSConfiguration(ctx, cfg)
		}
	}

	return nil
}

// =============================================================================
// Interface DNS Configuration
// =============================================================================

// SetInterfaceDNS configures DNS servers for specific network interface.
func (dm *DNSManager) SetInterfaceDNS(ctx context.Context, config *InterfaceDNSConfig) error {
	if config == nil {
		return errors.New("DNS configuration cannot be nil")
	}

	if config.InterfaceName == "" {
		return errors.New("interface name cannot be empty")
	}

	if len(config.DNSServers) == 0 {
		return ErrNoDNSServersConfigured
	}

	if len(config.DNSServers) > dm.config.MaxDNSServersPerInterface {
		return fmt.Errorf("%w: maximum %d, got %d",
			ErrMaxDNSServersExceeded, dm.config.MaxDNSServersPerInterface, len(config.DNSServers))
	}

	// Validate interface exists.
	if !dm.wanSelector.InterfaceExists(config.InterfaceName) {
		return fmt.Errorf("%w: %s", ErrDNSInterfaceNotFound, config.InterfaceName)
	}

	atomic.AddUint64(&dm.dnsConfigChanges, 1)

	// Step 1: Validate DNS servers if enabled.
	if dm.config.ValidateDNSServers {
		validatedCount := 0
		for _, dns := range config.DNSServers {
			if err := dm.validateDNSServer(dns); err == nil {
				validatedCount++
				atomic.AddUint64(&dm.dnsValidationSuccess, 1)
			} else {
				atomic.AddUint64(&dm.dnsValidationFailures, 1)
			}
		}

		if validatedCount == 0 {
			return fmt.Errorf("%w: all DNS servers failed validation", ErrDNSServerUnreachable)
		}

		config.LastValidated = time.Now()
	}

	// Step 2: Update interface DNS map.
	dm.mu.Lock()
	oldConfig := dm.interfaceDNS[config.InterfaceName]
	config.IsActive = true
	config.ConfiguredAt = time.Now()
	dm.interfaceDNS[config.InterfaceName] = config
	dm.mu.Unlock()

	// Extract old DNS servers for event.
	var oldDNSServers []net.IP
	if oldConfig != nil {
		oldDNSServers = oldConfig.DNSServers
	}

	// Step 3: Update system DNS if enabled.
	if dm.config.EnableSystemDNS {
		_ = dm.updateSystemDNS()
	}

	// Step 4: Record event.
	dm.recordEvent(config.InterfaceName, oldDNSServers, config.DNSServers, "INTERFACE_CONFIG", "system", true, "")

	// Step 5: Persist configuration.
	if dm.config.EnablePersistence {
		_ = dm.db.SaveDNSConfiguration(ctx, config)
	}

	return nil
}

// updateSystemDNS propagates DNS servers to operating system resolver.
func (dm *DNSManager) updateSystemDNS() error {
	// Select DNS servers for system configuration.
	activeWAN := dm.wanSelector.GetActiveWAN()

	dm.mu.RLock()
	wanDNS := dm.interfaceDNS[activeWAN]
	dm.mu.RUnlock()

	var dnsServers []net.IP
	if wanDNS != nil && len(wanDNS.DNSServers) > 0 {
		dnsServers = wanDNS.DNSServers
	} else {
		dnsServers = dm.config.FallbackDNSServers
	}

	if len(dnsServers) == 0 {
		return ErrNoDNSServersConfigured
	}

	// Create new system DNS config.
	newSystemDNS := &SystemDNSConfig{
		SearchDomains:   dm.config.DNSSearchDomains,
		Options:         dm.config.DNSOptions,
		ConfiguredAt:    time.Now(),
		SourceInterface: activeWAN,
	}

	if len(dnsServers) > 0 {
		newSystemDNS.PrimaryDNS = dnsServers[0]
	}
	if len(dnsServers) > 1 {
		newSystemDNS.SecondaryDNS = dnsServers[1]
	}
	if len(dnsServers) > 2 {
		newSystemDNS.TertiaryDNS = dnsServers[2]
	}

	// Apply to OS.
	var err error
	switch dm.platform {
	case PlatformLinux:
		err = dm.updateSystemDNSLinux(newSystemDNS)
	case PlatformWindows:
		err = dm.updateSystemDNSWindows(newSystemDNS)
	default:
		err = ErrPlatformUnsupported
	}

	if err != nil {
		return err
	}

	atomic.AddUint64(&dm.systemDNSUpdates, 1)

	// Update state.
	dm.mu.Lock()
	dm.systemDNS = newSystemDNS
	dm.mu.Unlock()

	return nil
}

// updateSystemDNSLinux updates system DNS on Linux.
func (dm *DNSManager) updateSystemDNSLinux(config *SystemDNSConfig) error {
	_ = config // Will be used in production implementation.

	// In production, this would:
	//
	// 1. Backup /etc/resolv.conf
	// err := os.Rename("/etc/resolv.conf", "/etc/resolv.conf.backup")
	//
	// 2. Build new resolv.conf content
	// var content strings.Builder
	// content.WriteString("# Generated by NIC Management Service\n")
	// if config.PrimaryDNS != nil {
	//     content.WriteString(fmt.Sprintf("nameserver %s\n", config.PrimaryDNS))
	// }
	// if config.SecondaryDNS != nil {
	//     content.WriteString(fmt.Sprintf("nameserver %s\n", config.SecondaryDNS))
	// }
	// if config.TertiaryDNS != nil {
	//     content.WriteString(fmt.Sprintf("nameserver %s\n", config.TertiaryDNS))
	// }
	// if len(config.SearchDomains) > 0 {
	//     content.WriteString(fmt.Sprintf("search %s\n", strings.Join(config.SearchDomains, " ")))
	// }
	// if len(config.Options) > 0 {
	//     content.WriteString(fmt.Sprintf("options %s\n", strings.Join(config.Options, " ")))
	// }
	//
	// 3. Write to /etc/resolv.conf
	// err = os.WriteFile("/etc/resolv.conf", []byte(content.String()), 0644)
	//
	// 4. Check for systemd-resolved and use resolvectl
	// if isSystemdResolved() {
	//     exec.Command("resolvectl", "dns", config.SourceInterface,
	//         config.PrimaryDNS.String(), config.SecondaryDNS.String()).Run()
	// }

	return nil
}

// updateSystemDNSWindows updates system DNS on Windows.
func (dm *DNSManager) updateSystemDNSWindows(config *SystemDNSConfig) error {
	_ = config // Will be used in production implementation.

	// In production, this would:
	//
	// 1. Set primary DNS via netsh
	// exec.Command("netsh", "interface", "ipv4", "set", "dnsservers",
	//     fmt.Sprintf("name=\"%s\"", config.SourceInterface),
	//     "static", config.PrimaryDNS.String(), "primary").Run()
	//
	// 2. Add secondary DNS
	// exec.Command("netsh", "interface", "ipv4", "add", "dnsservers",
	//     fmt.Sprintf("name=\"%s\"", config.SourceInterface),
	//     config.SecondaryDNS.String(), "index=2").Run()
	//
	// 3. Add tertiary DNS if configured
	// if config.TertiaryDNS != nil {
	//     exec.Command("netsh", "interface", "ipv4", "add", "dnsservers",
	//         fmt.Sprintf("name=\"%s\"", config.SourceInterface),
	//         config.TertiaryDNS.String(), "index=3").Run()
	// }
	//
	// 4. Set search suffix via registry
	// key, _ := registry.OpenKey(registry.LOCAL_MACHINE,
	//     `SYSTEM\CurrentControlSet\Services\Tcpip\Parameters`, registry.SET_VALUE)
	// key.SetStringValue("SearchList", strings.Join(config.SearchDomains, ","))
	//
	// 5. Flush DNS cache
	// exec.Command("ipconfig", "/flushdns").Run()

	return nil
}

// =============================================================================
// DNS Validation
// =============================================================================

// validateDNSServer checks if DNS server is responsive.
func (dm *DNSManager) validateDNSServer(dnsIP net.IP) error {
	if dnsIP == nil {
		return ErrInvalidDNSServer
	}

	// In production, this would use github.com/miekg/dns:
	//
	// client := &dns.Client{
	//     Timeout: dm.config.DNSValidationTimeout,
	// }
	//
	// msg := new(dns.Msg)
	// msg.SetQuestion(dns.Fqdn(dm.config.DNSValidationQuery), dns.TypeA)
	//
	// resp, _, err := client.Exchange(msg, net.JoinHostPort(dnsIP.String(), "53"))
	// if err != nil {
	//     return fmt.Errorf("%w: %v", ErrDNSServerUnreachable, err)
	// }
	//
	// if resp.Rcode != dns.RcodeSuccess {
	//     return fmt.Errorf("%w: DNS query returned error code %d", ErrDNSServerUnreachable, resp.Rcode)
	// }

	// Stub: Assume DNS server is reachable.
	return nil
}

// =============================================================================
// Current DNS Detection
// =============================================================================

// getCurrentDNSFromOS queries operating system for active DNS servers.
func (dm *DNSManager) getCurrentDNSFromOS() (*SystemDNSConfig, error) {
	switch dm.platform {
	case PlatformLinux:
		return dm.getCurrentDNSLinux()
	case PlatformWindows:
		return dm.getCurrentDNSWindows()
	default:
		return nil, ErrPlatformUnsupported
	}
}

// getCurrentDNSLinux gets current DNS on Linux.
func (dm *DNSManager) getCurrentDNSLinux() (*SystemDNSConfig, error) {
	// In production:
	//
	// content, err := os.ReadFile("/etc/resolv.conf")
	// if err != nil {
	//     return nil, err
	// }
	//
	// config := &SystemDNSConfig{}
	// lines := strings.Split(string(content), "\n")
	// var dnsServers []net.IP
	//
	// for _, line := range lines {
	//     line = strings.TrimSpace(line)
	//     if strings.HasPrefix(line, "nameserver ") {
	//         ip := net.ParseIP(strings.TrimPrefix(line, "nameserver "))
	//         if ip != nil {
	//             dnsServers = append(dnsServers, ip)
	//         }
	//     } else if strings.HasPrefix(line, "search ") {
	//         config.SearchDomains = strings.Fields(strings.TrimPrefix(line, "search "))
	//     } else if strings.HasPrefix(line, "options ") {
	//         config.Options = strings.Fields(strings.TrimPrefix(line, "options "))
	//     }
	// }
	//
	// if len(dnsServers) > 0 { config.PrimaryDNS = dnsServers[0] }
	// if len(dnsServers) > 1 { config.SecondaryDNS = dnsServers[1] }
	// if len(dnsServers) > 2 { config.TertiaryDNS = dnsServers[2] }

	return nil, nil
}

// getCurrentDNSWindows gets current DNS on Windows.
func (dm *DNSManager) getCurrentDNSWindows() (*SystemDNSConfig, error) {
	// In production:
	//
	// output, err := exec.Command("netsh", "interface", "ipv4", "show", "dnsservers").Output()
	// if err != nil {
	//     return nil, err
	// }
	//
	// Parse output for DNS server addresses...

	return nil, nil
}

// =============================================================================
// Failover Integration
// =============================================================================

// OnFailover handles failover event to backup WAN.
func (dm *DNSManager) OnFailover(ctx context.Context, primaryWAN, backupWAN string) error {
	// Get backup WAN DNS servers.
	dm.mu.RLock()
	backupDNS := dm.interfaceDNS[backupWAN]
	dm.mu.RUnlock()

	var dnsServers []net.IP
	if backupDNS != nil && len(backupDNS.DNSServers) > 0 {
		dnsServers = backupDNS.DNSServers
	} else {
		dnsServers = dm.config.FallbackDNSServers
	}

	// Extract old DNS for event.
	dm.mu.RLock()
	var oldDNS []net.IP
	if dm.systemDNS.PrimaryDNS != nil {
		oldDNS = append(oldDNS, dm.systemDNS.PrimaryDNS)
	}
	if dm.systemDNS.SecondaryDNS != nil {
		oldDNS = append(oldDNS, dm.systemDNS.SecondaryDNS)
	}
	dm.mu.RUnlock()

	// Update system DNS.
	if err := dm.updateSystemDNS(); err != nil {
		dm.recordEvent("", oldDNS, dnsServers, "FAILOVER", "failover_manager", false, err.Error())
		return err
	}

	dm.recordEvent("", oldDNS, dnsServers, "FAILOVER", "failover_manager", true, "")

	return nil
}

// OnRecovery handles recovery event to primary WAN.
func (dm *DNSManager) OnRecovery(ctx context.Context, primaryWAN, backupWAN string) error {
	// Get primary WAN DNS servers.
	dm.mu.RLock()
	primaryDNS := dm.interfaceDNS[primaryWAN]
	dm.mu.RUnlock()

	var dnsServers []net.IP
	if primaryDNS != nil && len(primaryDNS.DNSServers) > 0 {
		dnsServers = primaryDNS.DNSServers
	} else {
		dnsServers = dm.config.FallbackDNSServers
	}

	// Extract old DNS for event.
	dm.mu.RLock()
	var oldDNS []net.IP
	if dm.systemDNS.PrimaryDNS != nil {
		oldDNS = append(oldDNS, dm.systemDNS.PrimaryDNS)
	}
	if dm.systemDNS.SecondaryDNS != nil {
		oldDNS = append(oldDNS, dm.systemDNS.SecondaryDNS)
	}
	dm.mu.RUnlock()

	// Update system DNS.
	if err := dm.updateSystemDNS(); err != nil {
		dm.recordEvent("", oldDNS, dnsServers, "WAN_RECOVERY", "recovery_manager", false, err.Error())
		return err
	}

	dm.recordEvent("", oldDNS, dnsServers, "WAN_RECOVERY", "recovery_manager", true, "")

	return nil
}

// OnDHCPLease handles DHCP lease event with DNS servers.
func (dm *DNSManager) OnDHCPLease(ctx context.Context, interfaceName string, dnsServers []net.IP) error {
	if len(dnsServers) == 0 {
		return nil
	}

	config := &InterfaceDNSConfig{
		InterfaceName: interfaceName,
		DNSServers:    dnsServers,
		Source:        DNSSourceDHCP,
	}

	return dm.SetInterfaceDNS(ctx, config)
}

// =============================================================================
// DNS Server Management
// =============================================================================

// AddDNSServer adds DNS server to interface configuration.
func (dm *DNSManager) AddDNSServer(ctx context.Context, interfaceName string, dnsIP net.IP) error {
	if dnsIP == nil {
		return ErrInvalidDNSServer
	}

	dm.mu.RLock()
	config := dm.interfaceDNS[interfaceName]
	dm.mu.RUnlock()

	if config == nil {
		config = &InterfaceDNSConfig{
			InterfaceName: interfaceName,
			DNSServers:    []net.IP{dnsIP},
			Source:        DNSSourceAdmin,
		}
	} else {
		if len(config.DNSServers) >= dm.config.MaxDNSServersPerInterface {
			return ErrMaxDNSServersExceeded
		}

		// Check if already exists.
		for _, dns := range config.DNSServers {
			if dns.Equal(dnsIP) {
				return nil // Already exists.
			}
		}

		config.DNSServers = append(config.DNSServers, dnsIP)
	}

	return dm.SetInterfaceDNS(ctx, config)
}

// RemoveDNSServer removes DNS server from interface configuration.
func (dm *DNSManager) RemoveDNSServer(ctx context.Context, interfaceName string, dnsIP net.IP) error {
	if dnsIP == nil {
		return ErrInvalidDNSServer
	}

	dm.mu.RLock()
	config := dm.interfaceDNS[interfaceName]
	dm.mu.RUnlock()

	if config == nil {
		return ErrDNSInterfaceNotFound
	}

	// Find and remove the DNS server.
	found := false
	newServers := make([]net.IP, 0, len(config.DNSServers))
	for _, dns := range config.DNSServers {
		if dns.Equal(dnsIP) {
			found = true
			continue
		}
		newServers = append(newServers, dns)
	}

	if !found {
		return ErrDNSServerNotFound
	}

	if len(newServers) == 0 {
		// Remove entire config.
		dm.mu.Lock()
		delete(dm.interfaceDNS, interfaceName)
		dm.mu.Unlock()

		_ = dm.db.DeleteDNSConfiguration(ctx, interfaceName)
		return dm.updateSystemDNS()
	}

	config.DNSServers = newServers
	return dm.SetInterfaceDNS(ctx, config)
}

// SetSearchDomains configures DNS search domains.
func (dm *DNSManager) SetSearchDomains(domains []string) error {
	dm.config.DNSSearchDomains = domains

	dm.mu.Lock()
	dm.systemDNS.SearchDomains = domains
	dm.mu.Unlock()

	return dm.updateSystemDNS()
}

// =============================================================================
// Query Methods
// =============================================================================

// GetInterfaceDNS retrieves DNS configuration for specific interface.
func (dm *DNSManager) GetInterfaceDNS(interfaceName string) (*InterfaceDNSConfig, error) {
	dm.mu.RLock()
	defer dm.mu.RUnlock()

	config, exists := dm.interfaceDNS[interfaceName]
	if !exists {
		return nil, ErrDNSInterfaceNotFound
	}

	// Return copy.
	copy := *config
	return &copy, nil
}

// GetAllInterfaceDNS retrieves all interface DNS configurations.
func (dm *DNSManager) GetAllInterfaceDNS() map[string]*InterfaceDNSConfig {
	dm.mu.RLock()
	defer dm.mu.RUnlock()

	result := make(map[string]*InterfaceDNSConfig, len(dm.interfaceDNS))
	for name, cfg := range dm.interfaceDNS {
		copy := *cfg
		result[name] = &copy
	}
	return result
}

// GetSystemDNS retrieves system-wide DNS configuration.
func (dm *DNSManager) GetSystemDNS() *SystemDNSConfig {
	dm.mu.RLock()
	defer dm.mu.RUnlock()

	if dm.systemDNS == nil {
		return nil
	}

	copy := *dm.systemDNS
	return &copy
}

// GetDNSHistory retrieves historical DNS change events.
func (dm *DNSManager) GetDNSHistory(limit int) []*DNSChangeEvent {
	dm.dnsHistoryMu.RLock()
	defer dm.dnsHistoryMu.RUnlock()

	if len(dm.dnsHistory) == 0 {
		return nil
	}

	start := 0
	if len(dm.dnsHistory) > limit {
		start = len(dm.dnsHistory) - limit
	}

	result := make([]*DNSChangeEvent, len(dm.dnsHistory)-start)
	for i, event := range dm.dnsHistory[start:] {
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

// recordEvent creates and stores a DNS change event.
func (dm *DNSManager) recordEvent(interfaceName string, oldDNS, newDNS []net.IP, reason, triggeredBy string, success bool, errorMsg string) {
	event := &DNSChangeEvent{
		EventID:       generateConfigUUID(),
		Timestamp:     time.Now(),
		InterfaceName: interfaceName,
		OldDNSServers: oldDNS,
		NewDNSServers: newDNS,
		ChangeReason:  reason,
		TriggeredBy:   triggeredBy,
		Success:       success,
		ErrorMessage:  errorMsg,
	}

	dm.dnsHistoryMu.Lock()
	dm.dnsHistory = append(dm.dnsHistory, event)
	if len(dm.dnsHistory) > 500 {
		dm.dnsHistory = dm.dnsHistory[len(dm.dnsHistory)-500:]
	}
	dm.dnsHistoryMu.Unlock()

	// Persist event.
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_ = dm.db.SaveDNSChangeEvent(ctx, event)
}

// =============================================================================
// Health Check
// =============================================================================

// HealthCheck verifies the manager is operational.
func (dm *DNSManager) HealthCheck() error {
	if dm.platform == PlatformUnknown {
		return ErrPlatformUnsupported
	}

	dm.runningMu.Lock()
	running := dm.running
	dm.runningMu.Unlock()

	if !running {
		return errors.New("DNS manager not running")
	}

	// Check system DNS is configured.
	dm.mu.RLock()
	primaryDNS := dm.systemDNS.PrimaryDNS
	dm.mu.RUnlock()

	if primaryDNS == nil {
		return ErrNoDNSServersConfigured
	}

	// Validate primary DNS server is reachable.
	if dm.config.ValidateDNSServers {
		if err := dm.validateDNSServer(primaryDNS); err != nil {
			return fmt.Errorf("primary DNS server unreachable: %w", err)
		}
	}

	return nil
}

// =============================================================================
// Statistics
// =============================================================================

// GetStatistics returns DNS management statistics.
func (dm *DNSManager) GetStatistics() map[string]uint64 {
	return map[string]uint64{
		"dns_config_changes":      atomic.LoadUint64(&dm.dnsConfigChanges),
		"dns_validation_success":  atomic.LoadUint64(&dm.dnsValidationSuccess),
		"dns_validation_failures": atomic.LoadUint64(&dm.dnsValidationFailures),
		"system_dns_updates":      atomic.LoadUint64(&dm.systemDNSUpdates),
	}
}

// GetConfig returns the current configuration.
func (dm *DNSManager) GetConfig() *DNSConfig {
	return dm.config
}

// GetPlatform returns the detected platform.
func (dm *DNSManager) GetPlatform() Platform {
	return dm.platform
}

// =============================================================================
// Utility Functions
// =============================================================================

// FormatDNSServers formats DNS servers as a comma-separated string.
func FormatDNSServers(servers []net.IP) string {
	strs := make([]string, len(servers))
	for i, ip := range servers {
		strs[i] = ip.String()
	}
	return strings.Join(strs, ", ")
}

// ParseDNSServers parses a comma-separated string of DNS servers.
func ParseDNSServers(input string) ([]net.IP, error) {
	if input == "" {
		return nil, nil
	}

	parts := strings.Split(input, ",")
	servers := make([]net.IP, 0, len(parts))

	for _, part := range parts {
		ip := net.ParseIP(strings.TrimSpace(part))
		if ip == nil {
			return nil, fmt.Errorf("%w: %s", ErrInvalidDNSServer, part)
		}
		servers = append(servers, ip)
	}

	return servers, nil
}
