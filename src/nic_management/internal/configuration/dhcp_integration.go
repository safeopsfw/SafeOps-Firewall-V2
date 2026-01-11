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
// DHCP Error Types
// =============================================================================

var (
	// ErrDHCPServerUnreachable indicates cannot connect to DHCP server.
	ErrDHCPServerUnreachable = errors.New("DHCP server unreachable")
	// ErrDHCPTimeout indicates DHCP operation exceeded timeout.
	ErrDHCPTimeout = errors.New("DHCP timeout")
	// ErrNoOffer indicates no DHCP OFFER received.
	ErrNoOffer = errors.New("no DHCP offer received")
	// ErrDHCPNak indicates DHCP server sent negative acknowledgment.
	ErrDHCPNak = errors.New("DHCP NAK received")
	// ErrLeaseNotFound indicates no active lease for interface.
	ErrLeaseNotFound = errors.New("DHCP lease not found")
	// ErrLeaseExpired indicates lease expired and must be re-acquired.
	ErrLeaseExpired = errors.New("DHCP lease expired")
	// ErrPoolSyncFailed indicates unable to sync address pools.
	ErrPoolSyncFailed = errors.New("DHCP pool sync failed")
	// ErrReservationFailed indicates unable to register static reservation.
	ErrReservationFailed = errors.New("DHCP reservation failed")
	// ErrDHCPClientDisabled indicates DHCP client is disabled.
	ErrDHCPClientDisabled = errors.New("DHCP client disabled")
)

// =============================================================================
// Lease State Enumeration
// =============================================================================

// LeaseState represents DHCP lease lifecycle states.
type LeaseState int

const (
	// LeaseStateRequesting indicates sending DHCP DISCOVER/REQUEST.
	LeaseStateRequesting LeaseState = iota
	// LeaseStateBound indicates lease active and valid.
	LeaseStateBound
	// LeaseStateRenewing indicates attempting lease renewal.
	LeaseStateRenewing
	// LeaseStateRebinding indicates renewal failed, trying rebind.
	LeaseStateRebinding
	// LeaseStateExpired indicates lease expired, must re-acquire.
	LeaseStateExpired
	// LeaseStateReleased indicates lease manually released.
	LeaseStateReleased
)

// String returns the string representation of the lease state.
func (s LeaseState) String() string {
	switch s {
	case LeaseStateRequesting:
		return "REQUESTING"
	case LeaseStateBound:
		return "BOUND"
	case LeaseStateRenewing:
		return "RENEWING"
	case LeaseStateRebinding:
		return "REBINDING"
	case LeaseStateExpired:
		return "EXPIRED"
	case LeaseStateReleased:
		return "RELEASED"
	default:
		return "UNKNOWN"
	}
}

// =============================================================================
// DHCP Lease Structure
// =============================================================================

// DHCPLease represents an active DHCP lease for an interface.
type DHCPLease struct {
	// InterfaceName is the interface with this lease.
	InterfaceName string `json:"interface_name"`
	// MACAddress is the interface MAC address.
	MACAddress string `json:"mac_address"`
	// AssignedIP is the leased IP address.
	AssignedIP net.IP `json:"assigned_ip"`
	// SubnetMask is the lease subnet mask.
	SubnetMask net.IPMask `json:"subnet_mask"`
	// Gateway is the gateway from DHCP offer.
	Gateway net.IP `json:"gateway,omitempty"`
	// DNSServers contains DNS servers from DHCP offer.
	DNSServers []net.IP `json:"dns_servers,omitempty"`
	// LeaseTime is the lease duration.
	LeaseTime time.Duration `json:"lease_time"`
	// AcquiredAt is when lease was obtained.
	AcquiredAt time.Time `json:"acquired_at"`
	// ExpiresAt is when lease expires.
	ExpiresAt time.Time `json:"expires_at"`
	// RenewAt is when to renew lease (50% of lifetime).
	RenewAt time.Time `json:"renew_at"`
	// DHCPServerIP is the DHCP server that issued lease.
	DHCPServerIP net.IP `json:"dhcp_server_ip,omitempty"`
	// LeaseState is the current lease state.
	LeaseState LeaseState `json:"lease_state"`
}

// IsExpired checks if the lease has expired.
func (l *DHCPLease) IsExpired() bool {
	return time.Now().After(l.ExpiresAt)
}

// NeedsRenewal checks if the lease should be renewed.
func (l *DHCPLease) NeedsRenewal() bool {
	return time.Now().After(l.RenewAt) && !l.IsExpired()
}

// TimeToExpiry returns the time remaining until expiration.
func (l *DHCPLease) TimeToExpiry() time.Duration {
	return time.Until(l.ExpiresAt)
}

// =============================================================================
// Static Reservation Structure
// =============================================================================

// StaticReservation represents a permanent IP assignment coordinated with DHCP server.
type StaticReservation struct {
	// MACAddress is the interface MAC address.
	MACAddress string `json:"mac_address"`
	// ReservedIP is the statically assigned IP.
	ReservedIP net.IP `json:"reserved_ip"`
	// InterfaceName is the interface with this reservation.
	InterfaceName string `json:"interface_name"`
	// Hostname is the hostname for this reservation.
	Hostname string `json:"hostname,omitempty"`
	// RegisteredWithDHCP indicates whether DHCP server knows about this.
	RegisteredWithDHCP bool `json:"registered_with_dhcp"`
	// CreatedAt is when reservation was created.
	CreatedAt time.Time `json:"created_at"`
}

// =============================================================================
// DHCP Pool Status
// =============================================================================

// DHCPPoolStatus represents the status of a DHCP address pool.
type DHCPPoolStatus struct {
	// PoolID is the pool identifier.
	PoolID string `json:"pool_id"`
	// Network is the pool network.
	Network *net.IPNet `json:"network"`
	// Gateway is the pool gateway.
	Gateway net.IP `json:"gateway,omitempty"`
	// TotalAddresses is the total addresses in pool.
	TotalAddresses int `json:"total_addresses"`
	// AvailableAddresses is the available addresses.
	AvailableAddresses int `json:"available_addresses"`
	// LeasedAddresses is the currently leased addresses.
	LeasedAddresses int `json:"leased_addresses"`
	// ReservedAddresses is the reserved addresses.
	ReservedAddresses int `json:"reserved_addresses"`
	// ExcludedAddresses is the excluded addresses.
	ExcludedAddresses int `json:"excluded_addresses"`
	// IsSynced indicates if pool is synced with DHCP server.
	IsSynced bool `json:"is_synced"`
	// LastSyncTime is when pool was last synced.
	LastSyncTime time.Time `json:"last_sync_time,omitempty"`
}

// =============================================================================
// DHCP Integrator Configuration
// =============================================================================

// DHCPIntegratorConfig contains configuration for DHCP integration.
type DHCPIntegratorConfig struct {
	// DHCPServerAddress is the DHCP server gRPC endpoint.
	DHCPServerAddress string `json:"dhcp_server_address"`
	// DHCPServerTimeout is max time for DHCP server RPC calls (default: 5s).
	DHCPServerTimeout time.Duration `json:"dhcp_server_timeout"`
	// EnableDHCPClient enables DHCP client for WAN interfaces (default: true).
	EnableDHCPClient bool `json:"enable_dhcp_client"`
	// DHCPClientTimeout is max time for DHCP discover/request (default: 10s).
	DHCPClientTimeout time.Duration `json:"dhcp_client_timeout"`
	// LeaseRenewalInterval determines how often to check lease expiration (default: 60s).
	LeaseRenewalInterval time.Duration `json:"lease_renewal_interval"`
	// LeaseRenewalThreshold is when to renew (fraction of lease time, default: 0.5).
	LeaseRenewalThreshold float64 `json:"lease_renewal_threshold"`
	// EnableStaticReservations registers static IPs with DHCP server (default: true).
	EnableStaticReservations bool `json:"enable_static_reservations"`
	// SyncPoolsOnStartup syncs interface subnets to DHCP pools on start (default: true).
	SyncPoolsOnStartup bool `json:"sync_pools_on_startup"`
	// AutoExcludeStaticIPs adds static IPs to DHCP exclusion lists (default: true).
	AutoExcludeStaticIPs bool `json:"auto_exclude_static_ips"`
	// RetryAttempts is max retries for failed DHCP operations (default: 3).
	RetryAttempts int `json:"retry_attempts"`
	// RetryBackoff is delay between retry attempts (default: 5s).
	RetryBackoff time.Duration `json:"retry_backoff"`
}

// DefaultDHCPIntegratorConfig returns the default DHCP integrator configuration.
func DefaultDHCPIntegratorConfig() *DHCPIntegratorConfig {
	return &DHCPIntegratorConfig{
		DHCPServerAddress:        "localhost:50051",
		DHCPServerTimeout:        5 * time.Second,
		EnableDHCPClient:         true,
		DHCPClientTimeout:        10 * time.Second,
		LeaseRenewalInterval:     60 * time.Second,
		LeaseRenewalThreshold:    0.5,
		EnableStaticReservations: true,
		SyncPoolsOnStartup:       true,
		AutoExcludeStaticIPs:     true,
		RetryAttempts:            3,
		RetryBackoff:             5 * time.Second,
	}
}

// =============================================================================
// DHCP Server Client Interface
// =============================================================================

// DHCPServerClientInterface defines the DHCP server gRPC operations.
type DHCPServerClientInterface interface {
	// CreateOrUpdatePool creates or updates a DHCP address pool.
	CreateOrUpdatePool(ctx context.Context, poolID string, network *net.IPNet, gateway net.IP, dnsServers []net.IP, leaseTime time.Duration) error
	// DeletePool removes a DHCP address pool.
	DeletePool(ctx context.Context, poolID string) error
	// AddReservation adds a static IP reservation.
	AddReservation(ctx context.Context, macAddr string, ip net.IP, hostname string) error
	// RemoveReservation removes a static IP reservation.
	RemoveReservation(ctx context.Context, macAddr string) error
	// AddExclusion adds an IP to the exclusion list.
	AddExclusion(ctx context.Context, poolID string, ip net.IP) error
	// RemoveExclusion removes an IP from the exclusion list.
	RemoveExclusion(ctx context.Context, poolID string, ip net.IP) error
	// GetPoolStatus returns the status of a DHCP pool.
	GetPoolStatus(ctx context.Context, poolID string) (*DHCPPoolStatus, error)
	// GetServerStatus returns the DHCP server status.
	GetServerStatus(ctx context.Context) (bool, error)
	// Close closes the client connection.
	Close() error
}

// =============================================================================
// No-Op DHCP Server Client
// =============================================================================

type noOpDHCPServerClient struct{}

func (n *noOpDHCPServerClient) CreateOrUpdatePool(ctx context.Context, poolID string, network *net.IPNet, gateway net.IP, dnsServers []net.IP, leaseTime time.Duration) error {
	return nil
}

func (n *noOpDHCPServerClient) DeletePool(ctx context.Context, poolID string) error {
	return nil
}

func (n *noOpDHCPServerClient) AddReservation(ctx context.Context, macAddr string, ip net.IP, hostname string) error {
	return nil
}

func (n *noOpDHCPServerClient) RemoveReservation(ctx context.Context, macAddr string) error {
	return nil
}

func (n *noOpDHCPServerClient) AddExclusion(ctx context.Context, poolID string, ip net.IP) error {
	return nil
}

func (n *noOpDHCPServerClient) RemoveExclusion(ctx context.Context, poolID string, ip net.IP) error {
	return nil
}

func (n *noOpDHCPServerClient) GetPoolStatus(ctx context.Context, poolID string) (*DHCPPoolStatus, error) {
	return &DHCPPoolStatus{PoolID: poolID, IsSynced: true}, nil
}

func (n *noOpDHCPServerClient) GetServerStatus(ctx context.Context) (bool, error) {
	return true, nil
}

func (n *noOpDHCPServerClient) Close() error {
	return nil
}

// =============================================================================
// DHCP Integrator
// =============================================================================

// DHCPIntegrator manages DHCP server integration.
type DHCPIntegrator struct {
	// Dependencies.
	interfaceConfig *InterfaceConfigurator
	dhcpClient      DHCPServerClientInterface

	// Configuration.
	config *DHCPIntegratorConfig

	// State.
	dhcpLeases         map[string]*DHCPLease
	staticReservations map[string]*StaticReservation
	poolStatus         map[string]*DHCPPoolStatus
	mu                 sync.RWMutex

	// Statistics.
	leaseAcquisitions    uint64
	leaseRenewals        uint64
	leaseReleases        uint64
	leaseExpirations     uint64
	poolSyncs            uint64
	reservationRegisters uint64

	// Control.
	stopChan  chan struct{}
	wg        sync.WaitGroup
	running   bool
	runningMu sync.Mutex
}

// NewDHCPIntegrator creates a new DHCP integrator.
func NewDHCPIntegrator(
	interfaceConfig *InterfaceConfigurator,
	dhcpClient DHCPServerClientInterface,
	config *DHCPIntegratorConfig,
) *DHCPIntegrator {
	if config == nil {
		config = DefaultDHCPIntegratorConfig()
	}

	if dhcpClient == nil {
		dhcpClient = &noOpDHCPServerClient{}
	}

	return &DHCPIntegrator{
		interfaceConfig:    interfaceConfig,
		dhcpClient:         dhcpClient,
		config:             config,
		dhcpLeases:         make(map[string]*DHCPLease),
		staticReservations: make(map[string]*StaticReservation),
		poolStatus:         make(map[string]*DHCPPoolStatus),
		stopChan:           make(chan struct{}),
	}
}

// =============================================================================
// Lifecycle Management
// =============================================================================

// Start initializes the DHCP integrator.
func (di *DHCPIntegrator) Start(ctx context.Context) error {
	di.runningMu.Lock()
	defer di.runningMu.Unlock()

	if di.running {
		return nil
	}

	// Verify DHCP server connection.
	serverUp, err := di.dhcpClient.GetServerStatus(ctx)
	if err != nil {
		// Log warning but continue - server may come up later.
		_ = err
	} else if !serverUp {
		// Server not ready, but continue.
		_ = serverUp
	}

	// Sync address pools on startup if enabled.
	if di.config.SyncPoolsOnStartup {
		_ = di.syncAddressPoolsWithDHCPServer(ctx)
	}

	// Register static reservations if enabled.
	if di.config.EnableStaticReservations {
		_ = di.registerStaticReservations(ctx)
	}

	// Auto-exclude static IPs if enabled.
	if di.config.AutoExcludeStaticIPs {
		_ = di.excludeStaticIPsFromDHCP(ctx)
	}

	// Start lease renewal monitor if DHCP client enabled.
	if di.config.EnableDHCPClient {
		di.wg.Add(1)
		go di.leaseRenewalLoop()
	}

	di.running = true
	return nil
}

// Stop shuts down the DHCP integrator.
func (di *DHCPIntegrator) Stop() error {
	di.runningMu.Lock()
	if !di.running {
		di.runningMu.Unlock()
		return nil
	}
	di.running = false
	di.runningMu.Unlock()

	close(di.stopChan)
	di.wg.Wait()

	// Release all active leases.
	di.mu.RLock()
	interfaces := make([]string, 0, len(di.dhcpLeases))
	for ifaceName := range di.dhcpLeases {
		interfaces = append(interfaces, ifaceName)
	}
	di.mu.RUnlock()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	for _, ifaceName := range interfaces {
		_ = di.ReleaseDHCPLease(ctx, ifaceName)
	}

	// Close DHCP server connection.
	_ = di.dhcpClient.Close()

	return nil
}

// =============================================================================
// DHCP Lease Acquisition
// =============================================================================

// AcquireDHCPLease obtains an IP address from DHCP server for interface.
func (di *DHCPIntegrator) AcquireDHCPLease(ctx context.Context, interfaceName string) (*DHCPLease, error) {
	if !di.config.EnableDHCPClient {
		return nil, ErrDHCPClientDisabled
	}

	// Check if lease already exists.
	di.mu.RLock()
	existingLease, exists := di.dhcpLeases[interfaceName]
	di.mu.RUnlock()

	if exists && !existingLease.IsExpired() {
		return existingLease, nil
	}

	atomic.AddUint64(&di.leaseAcquisitions, 1)

	// Get interface MAC address.
	var macAddr string
	if di.interfaceConfig != nil {
		iface, err := net.InterfaceByName(interfaceName)
		if err != nil {
			return nil, fmt.Errorf("%w: %s", ErrInterfaceNotFound, interfaceName)
		}
		macAddr = iface.HardwareAddr.String()
	}

	// Create lease in requesting state.
	lease := &DHCPLease{
		InterfaceName: interfaceName,
		MACAddress:    macAddr,
		LeaseState:    LeaseStateRequesting,
	}

	// Perform DHCP DISCOVER/REQUEST.
	// In production, this would use github.com/insomniacslk/dhcp/dhcpv4/nclient4
	// with retry logic:
	//
	// var lastErr error
	// for attempt := 0; attempt < di.config.RetryAttempts; attempt++ {
	//     if attempt > 0 {
	//         select {
	//         case <-ctx.Done():
	//             return nil, ErrDHCPTimeout
	//         case <-time.After(di.config.RetryBackoff):
	//         }
	//     }
	//
	//     client, err := nclient4.New(interfaceName)
	//     if err != nil {
	//         lastErr = err
	//         continue
	//     }
	//     defer client.Close()
	//
	//     offer, err := client.DiscoverOffer(ctx)
	//     if err != nil {
	//         lastErr = err
	//         continue
	//     }
	//
	//     ack, err := client.SendRequest(ctx, offer)
	//     if err != nil {
	//         lastErr = err
	//         continue
	//     }
	//
	//     lease.AssignedIP = ack.YourIPAddr
	//     lease.SubnetMask = ack.SubnetMask()
	//     lease.Gateway = ack.Router()
	//     lease.DNSServers = ack.DNS()
	//     lease.LeaseTime = ack.IPAddressLeaseTime
	//     lease.DHCPServerIP = ack.ServerIPAddr
	//     break
	// }
	//
	// if lastErr != nil {
	//     return nil, fmt.Errorf("%w: %v", ErrDHCPTimeout, lastErr)
	// }

	// Stub implementation: Simulate successful DHCP acquisition.
	lease.AssignedIP = net.ParseIP("192.168.1.100")
	lease.SubnetMask = net.CIDRMask(24, 32)
	lease.Gateway = net.ParseIP("192.168.1.1")
	lease.DNSServers = []net.IP{net.ParseIP("8.8.8.8"), net.ParseIP("8.8.4.4")}
	lease.LeaseTime = 24 * time.Hour
	lease.DHCPServerIP = net.ParseIP("192.168.1.1")

	// Calculate lease times.
	now := time.Now()
	lease.AcquiredAt = now
	lease.ExpiresAt = now.Add(lease.LeaseTime)
	lease.RenewAt = now.Add(time.Duration(float64(lease.LeaseTime) * di.config.LeaseRenewalThreshold))
	lease.LeaseState = LeaseStateBound

	// Apply IP configuration to interface.
	if di.interfaceConfig != nil {
		ipConfig, _ := ParseIPv4Config(
			lease.AssignedIP.String(),
			prefixLength(lease.SubnetMask),
			lease.Gateway.String(),
		)
		if ipConfig != nil {
			ipConfig.DNSServers = lease.DNSServers
			ipConfig.DHCPEnabled = true
			ipConfig.DHCPLeaseTime = lease.LeaseTime

			config := &InterfaceConfig{
				InterfaceName: interfaceName,
				HardwareAddr:  macAddr,
				IPv4Config:    ipConfig,
				MTU:           1500,
				State:         InterfaceStateUp,
				ConfigMethod:  ConfigMethodDHCP,
			}

			_ = di.interfaceConfig.ConfigureInterface(ctx, config)
		}
	}

	// Store lease.
	di.mu.Lock()
	di.dhcpLeases[interfaceName] = lease
	di.mu.Unlock()

	return lease, nil
}

// RenewDHCPLease extends lease lifetime before expiration.
func (di *DHCPIntegrator) RenewDHCPLease(ctx context.Context, interfaceName string) error {
	di.mu.RLock()
	lease, exists := di.dhcpLeases[interfaceName]
	di.mu.RUnlock()

	if !exists {
		return ErrLeaseNotFound
	}

	// Check if lease is expired.
	if lease.IsExpired() {
		// Must re-acquire.
		_, err := di.AcquireDHCPLease(ctx, interfaceName)
		return err
	}

	// Check if renewal is needed.
	if !lease.NeedsRenewal() {
		return nil // Too early to renew.
	}

	atomic.AddUint64(&di.leaseRenewals, 1)

	// Update lease state.
	di.mu.Lock()
	lease.LeaseState = LeaseStateRenewing
	di.mu.Unlock()

	// Perform DHCP REQUEST (renewal) with unicast to server.
	// In production, this would send unicast REQUEST to DHCPServerIP.
	//
	// For stub: Simulate successful renewal.
	now := time.Now()
	newLeaseTime := 24 * time.Hour

	di.mu.Lock()
	lease.LeaseTime = newLeaseTime
	lease.AcquiredAt = now
	lease.ExpiresAt = now.Add(newLeaseTime)
	lease.RenewAt = now.Add(time.Duration(float64(newLeaseTime) * di.config.LeaseRenewalThreshold))
	lease.LeaseState = LeaseStateBound
	di.mu.Unlock()

	return nil
}

// ReleaseDHCPLease explicitly releases lease back to DHCP server.
func (di *DHCPIntegrator) ReleaseDHCPLease(ctx context.Context, interfaceName string) error {
	di.mu.Lock()
	lease, exists := di.dhcpLeases[interfaceName]
	if !exists {
		di.mu.Unlock()
		return nil // Already released.
	}
	delete(di.dhcpLeases, interfaceName)
	di.mu.Unlock()

	atomic.AddUint64(&di.leaseReleases, 1)

	// Send DHCP RELEASE (fire-and-forget).
	// In production: client.Release(lease.AssignedIP)
	_ = lease

	// Remove IP from interface.
	if di.interfaceConfig != nil {
		_ = di.interfaceConfig.DeleteConfiguration(interfaceName)
	}

	return nil
}

// =============================================================================
// Lease Renewal Loop
// =============================================================================

// leaseRenewalLoop monitors lease expiration and triggers renewals.
func (di *DHCPIntegrator) leaseRenewalLoop() {
	defer di.wg.Done()

	ticker := time.NewTicker(di.config.LeaseRenewalInterval)
	defer ticker.Stop()

	for {
		select {
		case <-di.stopChan:
			return
		case <-ticker.C:
			di.checkLeaseRenewals()
		}
	}
}

// checkLeaseRenewals checks all leases for renewal/expiration.
func (di *DHCPIntegrator) checkLeaseRenewals() {
	di.mu.RLock()
	leasesToRenew := make([]string, 0)
	leasesExpired := make([]string, 0)

	for ifaceName, lease := range di.dhcpLeases {
		if lease.IsExpired() {
			leasesExpired = append(leasesExpired, ifaceName)
		} else if lease.NeedsRenewal() {
			leasesToRenew = append(leasesToRenew, ifaceName)
		}
	}
	di.mu.RUnlock()

	// Process renewals.
	ctx := context.Background()
	for _, ifaceName := range leasesToRenew {
		go func(name string) {
			_ = di.RenewDHCPLease(ctx, name)
		}(ifaceName)
	}

	// Process expirations.
	for _, ifaceName := range leasesExpired {
		atomic.AddUint64(&di.leaseExpirations, 1)
		go func(name string) {
			_, _ = di.AcquireDHCPLease(ctx, name)
		}(ifaceName)
	}
}

// =============================================================================
// Pool Synchronization
// =============================================================================

// syncAddressPoolsWithDHCPServer synchronizes interface subnets to DHCP server pools.
func (di *DHCPIntegrator) syncAddressPoolsWithDHCPServer(ctx context.Context) error {
	if di.interfaceConfig == nil {
		return nil
	}

	configs := di.interfaceConfig.GetAllConfigurations()
	if len(configs) == 0 {
		return nil
	}

	atomic.AddUint64(&di.poolSyncs, 1)

	for ifaceName, config := range configs {
		if config.IPv4Config == nil || config.IPv4Config.Network == nil {
			continue
		}

		// Create pool ID from interface name.
		poolID := fmt.Sprintf("pool-%s", ifaceName)

		// Sync with DHCP server.
		err := di.dhcpClient.CreateOrUpdatePool(
			ctx,
			poolID,
			config.IPv4Config.Network,
			config.IPv4Config.Gateway,
			config.IPv4Config.DNSServers,
			24*time.Hour, // Default lease time.
		)
		if err != nil {
			continue // Log and continue with other pools.
		}

		// Track pool status.
		di.mu.Lock()
		di.poolStatus[poolID] = &DHCPPoolStatus{
			PoolID:       poolID,
			Network:      config.IPv4Config.Network,
			Gateway:      config.IPv4Config.Gateway,
			IsSynced:     true,
			LastSyncTime: time.Now(),
		}
		di.mu.Unlock()
	}

	return nil
}

// SyncPool manually syncs a specific interface's subnet to DHCP server.
func (di *DHCPIntegrator) SyncPool(ctx context.Context, interfaceName string) error {
	if di.interfaceConfig == nil {
		return nil
	}

	config, err := di.interfaceConfig.GetInterfaceConfiguration(interfaceName)
	if err != nil {
		return err
	}

	if config.IPv4Config == nil || config.IPv4Config.Network == nil {
		return errors.New("interface has no IPv4 network configuration")
	}

	poolID := fmt.Sprintf("pool-%s", interfaceName)

	return di.dhcpClient.CreateOrUpdatePool(
		ctx,
		poolID,
		config.IPv4Config.Network,
		config.IPv4Config.Gateway,
		config.IPv4Config.DNSServers,
		24*time.Hour,
	)
}

// =============================================================================
// Static Reservations
// =============================================================================

// registerStaticReservations informs DHCP server of static IP assignments.
func (di *DHCPIntegrator) registerStaticReservations(ctx context.Context) error {
	if di.interfaceConfig == nil {
		return nil
	}

	configs := di.interfaceConfig.GetAllConfigurations()
	if len(configs) == 0 {
		return nil
	}

	for ifaceName, config := range configs {
		if config.ConfigMethod != ConfigMethodStatic {
			continue
		}

		if config.IPv4Config == nil || config.IPv4Config.Address == nil {
			continue
		}

		atomic.AddUint64(&di.reservationRegisters, 1)

		// Get MAC address.
		macAddr := config.HardwareAddr
		if macAddr == "" {
			iface, err := net.InterfaceByName(ifaceName)
			if err != nil {
				continue
			}
			macAddr = iface.HardwareAddr.String()
		}

		// Register with DHCP server.
		err := di.dhcpClient.AddReservation(ctx, macAddr, config.IPv4Config.Address, ifaceName)
		if err != nil {
			continue // Log and continue.
		}

		// Track reservation.
		di.mu.Lock()
		di.staticReservations[macAddr] = &StaticReservation{
			MACAddress:         macAddr,
			ReservedIP:         config.IPv4Config.Address,
			InterfaceName:      ifaceName,
			Hostname:           ifaceName,
			RegisteredWithDHCP: true,
			CreatedAt:          time.Now(),
		}
		di.mu.Unlock()
	}

	return nil
}

// AddStaticReservation adds a static IP reservation.
func (di *DHCPIntegrator) AddStaticReservation(ctx context.Context, macAddr string, ip net.IP, hostname string) error {
	err := di.dhcpClient.AddReservation(ctx, macAddr, ip, hostname)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrReservationFailed, err)
	}

	di.mu.Lock()
	di.staticReservations[macAddr] = &StaticReservation{
		MACAddress:         macAddr,
		ReservedIP:         ip,
		Hostname:           hostname,
		RegisteredWithDHCP: true,
		CreatedAt:          time.Now(),
	}
	di.mu.Unlock()

	return nil
}

// RemoveStaticReservation removes a static IP reservation.
func (di *DHCPIntegrator) RemoveStaticReservation(ctx context.Context, macAddr string) error {
	err := di.dhcpClient.RemoveReservation(ctx, macAddr)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrReservationFailed, err)
	}

	di.mu.Lock()
	delete(di.staticReservations, macAddr)
	di.mu.Unlock()

	return nil
}

// =============================================================================
// Static IP Exclusion
// =============================================================================

// excludeStaticIPsFromDHCP adds static IPs to DHCP exclusion lists.
func (di *DHCPIntegrator) excludeStaticIPsFromDHCP(ctx context.Context) error {
	if di.interfaceConfig == nil {
		return nil
	}

	configs := di.interfaceConfig.GetAllConfigurations()
	if len(configs) == 0 {
		return nil
	}

	for ifaceName, config := range configs {
		if config.ConfigMethod != ConfigMethodStatic {
			continue
		}

		if config.IPv4Config == nil || config.IPv4Config.Address == nil {
			continue
		}

		// Determine which pool contains this IP.
		poolID := fmt.Sprintf("pool-%s", ifaceName)

		// Add exclusion.
		_ = di.dhcpClient.AddExclusion(ctx, poolID, config.IPv4Config.Address)
	}

	return nil
}

// AddExclusion adds an IP address to exclusion list.
func (di *DHCPIntegrator) AddExclusion(ctx context.Context, poolID string, ip net.IP) error {
	return di.dhcpClient.AddExclusion(ctx, poolID, ip)
}

// RemoveExclusion removes an IP address from exclusion list.
func (di *DHCPIntegrator) RemoveExclusion(ctx context.Context, poolID string, ip net.IP) error {
	return di.dhcpClient.RemoveExclusion(ctx, poolID, ip)
}

// =============================================================================
// Query Methods
// =============================================================================

// GetDHCPLease retrieves active lease for interface.
func (di *DHCPIntegrator) GetDHCPLease(interfaceName string) (*DHCPLease, error) {
	di.mu.RLock()
	defer di.mu.RUnlock()

	lease, exists := di.dhcpLeases[interfaceName]
	if !exists {
		return nil, ErrLeaseNotFound
	}

	// Return copy.
	leaseCopy := *lease
	return &leaseCopy, nil
}

// GetAllLeases retrieves all active DHCP leases.
func (di *DHCPIntegrator) GetAllLeases() map[string]*DHCPLease {
	di.mu.RLock()
	defer di.mu.RUnlock()

	result := make(map[string]*DHCPLease, len(di.dhcpLeases))
	for name, lease := range di.dhcpLeases {
		leaseCopy := *lease
		result[name] = &leaseCopy
	}
	return result
}

// GetStaticReservations retrieves all static IP reservations.
func (di *DHCPIntegrator) GetStaticReservations() map[string]*StaticReservation {
	di.mu.RLock()
	defer di.mu.RUnlock()

	result := make(map[string]*StaticReservation, len(di.staticReservations))
	for mac, res := range di.staticReservations {
		resCopy := *res
		result[mac] = &resCopy
	}
	return result
}

// GetPoolStatus retrieves the status of all synced pools.
func (di *DHCPIntegrator) GetPoolStatus() map[string]*DHCPPoolStatus {
	di.mu.RLock()
	defer di.mu.RUnlock()

	result := make(map[string]*DHCPPoolStatus, len(di.poolStatus))
	for id, status := range di.poolStatus {
		statusCopy := *status
		result[id] = &statusCopy
	}
	return result
}

// =============================================================================
// Configuration Change Callback
// =============================================================================

// OnInterfaceConfigurationChange handles interface configuration changes.
func (di *DHCPIntegrator) OnInterfaceConfigurationChange(ctx context.Context, interfaceName string, config *InterfaceConfig) error {
	if config == nil {
		return nil
	}

	switch config.ConfigMethod {
	case ConfigMethodDHCP:
		// Acquire DHCP lease.
		_, err := di.AcquireDHCPLease(ctx, interfaceName)
		return err

	case ConfigMethodStatic:
		// Release any existing DHCP lease.
		di.mu.RLock()
		_, hasLease := di.dhcpLeases[interfaceName]
		di.mu.RUnlock()

		if hasLease {
			_ = di.ReleaseDHCPLease(ctx, interfaceName)
		}

		// Register static reservation.
		if di.config.EnableStaticReservations {
			_ = di.registerStaticReservations(ctx)
		}

		// Exclude from DHCP pool.
		if di.config.AutoExcludeStaticIPs {
			_ = di.excludeStaticIPsFromDHCP(ctx)
		}

	case ConfigMethodDHCPWithFallback:
		// Try DHCP first, fallback to static if failed.
		_, err := di.AcquireDHCPLease(ctx, interfaceName)
		if err != nil {
			// DHCP failed, static fallback should be applied by interface configurator.
			return nil
		}
	}

	// Sync pools if this is a LAN interface.
	if di.config.SyncPoolsOnStartup {
		_ = di.SyncPool(ctx, interfaceName)
	}

	return nil
}

// =============================================================================
// Health Check
// =============================================================================

// HealthCheck verifies the integrator is operational.
func (di *DHCPIntegrator) HealthCheck() error {
	di.runningMu.Lock()
	running := di.running
	di.runningMu.Unlock()

	if !running {
		return errors.New("DHCP integrator not running")
	}

	// Check DHCP server connection.
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	serverUp, err := di.dhcpClient.GetServerStatus(ctx)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrDHCPServerUnreachable, err)
	}

	if !serverUp {
		return ErrDHCPServerUnreachable
	}

	// Check for stuck leases.
	di.mu.RLock()
	for _, lease := range di.dhcpLeases {
		if lease.LeaseState == LeaseStateRequesting {
			if time.Since(lease.AcquiredAt) > di.config.DHCPClientTimeout*2 {
				di.mu.RUnlock()
				return errors.New("DHCP lease stuck in requesting state")
			}
		}
	}
	di.mu.RUnlock()

	return nil
}

// =============================================================================
// Statistics
// =============================================================================

// GetStatistics returns DHCP integration statistics.
func (di *DHCPIntegrator) GetStatistics() map[string]uint64 {
	return map[string]uint64{
		"lease_acquisitions":        atomic.LoadUint64(&di.leaseAcquisitions),
		"lease_renewals":            atomic.LoadUint64(&di.leaseRenewals),
		"lease_releases":            atomic.LoadUint64(&di.leaseReleases),
		"lease_expirations":         atomic.LoadUint64(&di.leaseExpirations),
		"pool_syncs":                atomic.LoadUint64(&di.poolSyncs),
		"reservation_registrations": atomic.LoadUint64(&di.reservationRegisters),
	}
}

// GetConfig returns the current configuration.
func (di *DHCPIntegrator) GetConfig() *DHCPIntegratorConfig {
	return di.config
}
