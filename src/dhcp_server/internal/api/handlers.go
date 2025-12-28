// Package api implements the gRPC API for DHCP server management.
// This file implements the gRPC service handlers.
package api

import (
	"context"
	"errors"
	"net"
	"sync"
	"time"
)

// ============================================================================
// Request/Response Types
// ============================================================================

// LeaseInfo contains lease information.
type LeaseInfo struct {
	MACAddress string
	IPAddress  string
	Hostname   string
	LeaseStart time.Time
	LeaseEnd   time.Time
	State      string
	PoolName   string
}

// PoolInfo contains pool information.
type PoolInfo struct {
	Name           string
	Subnet         string
	RangeStart     string
	RangeEnd       string
	Gateway        string
	DNSServers     []string
	LeaseTime      int64
	TotalIPs       int64
	UsableIPs      int64
	AllocatedIPs   int64
	AvailableIPs   int64
	UtilizationPct float64
	Active         bool
}

// ReservationInfo contains reservation information.
type ReservationInfo struct {
	MACAddress string
	IPAddress  string
	Hostname   string
	PoolName   string
	CreatedAt  time.Time
}

// ServerStats contains server statistics.
type ServerStats struct {
	Uptime            time.Duration
	TotalDiscover     int64
	TotalRequest      int64
	TotalDecline      int64
	TotalRelease      int64
	TotalOffer        int64
	TotalAck          int64
	TotalNak          int64
	ActiveLeases      int64
	TotalPools        int
	RequestsPerSecond float64
	AvgResponseTimeMs float64
}

// DNSIntegrationStatus contains DNS status.
type DNSIntegrationStatus struct {
	Available      bool
	LastUpdateTime time.Time
	PendingUpdates int
	TotalUpdates   int64
	ErrorRate      float64
}

// CAIntegrationStatus contains CA status.
type CAIntegrationStatus struct {
	Available         bool
	CACertURL         string
	InstallScriptURLs []string
	WPADURL           string
	CacheExpiration   time.Time
	ACKsWithCA        int64
	ACKsWithoutCA     int64
}

// ============================================================================
// Service Interfaces
// ============================================================================

// LeaseService provides lease operations.
type LeaseService interface {
	GetLease(ctx context.Context, mac string) (*LeaseInfo, error)
	GetAllLeases(ctx context.Context, poolFilter string, offset, limit int) ([]*LeaseInfo, int, error)
	GetLeasesByPool(ctx context.Context, poolName string) ([]*LeaseInfo, error)
	ReleaseLease(ctx context.Context, mac string) error
	GetLeaseHistory(ctx context.Context, mac string) ([]*LeaseInfo, error)
}

// PoolService provides pool operations.
type PoolService interface {
	GetPoolInfo(ctx context.Context, poolName string) (*PoolInfo, error)
	GetAllPools(ctx context.Context) ([]*PoolInfo, error)
	UpdatePoolLeaseTime(ctx context.Context, poolName string, leaseTime int64) error
}

// ReservationService provides reservation operations.
type ReservationService interface {
	CreateReservation(ctx context.Context, mac, ip, hostname, poolName string) error
	DeleteReservation(ctx context.Context, mac string) error
	GetReservation(ctx context.Context, mac string) (*ReservationInfo, error)
	GetAllReservations(ctx context.Context) ([]*ReservationInfo, error)
}

// StatsService provides statistics.
type StatsService interface {
	GetStats(ctx context.Context) (*ServerStats, error)
	GetPoolStats(ctx context.Context, poolName string) (*PoolInfo, error)
}

// DNSService provides DNS integration.
type DNSService interface {
	GetStatus(ctx context.Context) (*DNSIntegrationStatus, error)
	SyncRecords(ctx context.Context) (int, error)
}

// CAService provides CA integration.
type CAService interface {
	GetStatus(ctx context.Context) (*CAIntegrationStatus, error)
	RefreshCache(ctx context.Context) error
}

// ConfigService provides configuration.
type ConfigService interface {
	ReloadConfig(ctx context.Context) error
}

// ============================================================================
// DHCP API Handler
// ============================================================================

// DHCPAPIHandler implements the gRPC service handlers.
type DHCPAPIHandler struct {
	mu sync.RWMutex

	// Services
	leaseService       LeaseService
	poolService        PoolService
	reservationService ReservationService
	statsService       StatsService
	dnsService         DNSService
	caService          CAService
	configService      ConfigService
}

// NewDHCPAPIHandler creates a new API handler.
func NewDHCPAPIHandler() *DHCPAPIHandler {
	return &DHCPAPIHandler{}
}

// ============================================================================
// Service Setters
// ============================================================================

// SetLeaseService sets the lease service.
func (h *DHCPAPIHandler) SetLeaseService(svc LeaseService) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.leaseService = svc
}

// SetPoolService sets the pool service.
func (h *DHCPAPIHandler) SetPoolService(svc PoolService) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.poolService = svc
}

// SetReservationService sets the reservation service.
func (h *DHCPAPIHandler) SetReservationService(svc ReservationService) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.reservationService = svc
}

// SetStatsService sets the stats service.
func (h *DHCPAPIHandler) SetStatsService(svc StatsService) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.statsService = svc
}

// SetDNSService sets the DNS service.
func (h *DHCPAPIHandler) SetDNSService(svc DNSService) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.dnsService = svc
}

// SetCAService sets the CA service.
func (h *DHCPAPIHandler) SetCAService(svc CAService) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.caService = svc
}

// SetConfigService sets the config service.
func (h *DHCPAPIHandler) SetConfigService(svc ConfigService) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.configService = svc
}

// ============================================================================
// Lease Query Handlers
// ============================================================================

// GetLease retrieves lease information for a MAC address.
func (h *DHCPAPIHandler) GetLease(ctx context.Context, macAddress string) (*LeaseInfo, error) {
	h.mu.RLock()
	svc := h.leaseService
	h.mu.RUnlock()

	if svc == nil {
		return nil, ErrServiceNotAvailable
	}

	// Validate MAC address
	if _, err := net.ParseMAC(macAddress); err != nil {
		return nil, ErrInvalidMACAddress
	}

	return svc.GetLease(ctx, macAddress)
}

// GetAllLeases retrieves all active leases.
func (h *DHCPAPIHandler) GetAllLeases(ctx context.Context, poolFilter string, offset, limit int) ([]*LeaseInfo, int, error) {
	h.mu.RLock()
	svc := h.leaseService
	h.mu.RUnlock()

	if svc == nil {
		return nil, 0, ErrServiceNotAvailable
	}

	// Set defaults
	if limit <= 0 {
		limit = 100
	}
	if limit > 1000 {
		limit = 1000
	}

	return svc.GetAllLeases(ctx, poolFilter, offset, limit)
}

// GetLeasesByPool retrieves leases for a specific pool.
func (h *DHCPAPIHandler) GetLeasesByPool(ctx context.Context, poolName string) ([]*LeaseInfo, error) {
	h.mu.RLock()
	svc := h.leaseService
	h.mu.RUnlock()

	if svc == nil {
		return nil, ErrServiceNotAvailable
	}

	if poolName == "" {
		return nil, ErrInvalidPoolName
	}

	return svc.GetLeasesByPool(ctx, poolName)
}

// GetLeaseHistory retrieves lease history for a MAC address.
func (h *DHCPAPIHandler) GetLeaseHistory(ctx context.Context, macAddress string) ([]*LeaseInfo, error) {
	h.mu.RLock()
	svc := h.leaseService
	h.mu.RUnlock()

	if svc == nil {
		return nil, ErrServiceNotAvailable
	}

	if _, err := net.ParseMAC(macAddress); err != nil {
		return nil, ErrInvalidMACAddress
	}

	return svc.GetLeaseHistory(ctx, macAddress)
}

// ============================================================================
// Lease Management Handlers
// ============================================================================

// ReleaseLease administratively releases a lease.
func (h *DHCPAPIHandler) ReleaseLease(ctx context.Context, macAddress string) error {
	h.mu.RLock()
	svc := h.leaseService
	h.mu.RUnlock()

	if svc == nil {
		return ErrServiceNotAvailable
	}

	if _, err := net.ParseMAC(macAddress); err != nil {
		return ErrInvalidMACAddress
	}

	return svc.ReleaseLease(ctx, macAddress)
}

// CreateReservation creates a static MAC to IP reservation.
func (h *DHCPAPIHandler) CreateReservation(ctx context.Context, macAddress, ipAddress, hostname, poolName string) error {
	h.mu.RLock()
	svc := h.reservationService
	h.mu.RUnlock()

	if svc == nil {
		return ErrServiceNotAvailable
	}

	// Validate MAC
	if _, err := net.ParseMAC(macAddress); err != nil {
		return ErrInvalidMACAddress
	}

	// Validate IP
	if net.ParseIP(ipAddress) == nil {
		return ErrInvalidIPAddress
	}

	return svc.CreateReservation(ctx, macAddress, ipAddress, hostname, poolName)
}

// DeleteReservation removes a static reservation.
func (h *DHCPAPIHandler) DeleteReservation(ctx context.Context, macAddress string) error {
	h.mu.RLock()
	svc := h.reservationService
	h.mu.RUnlock()

	if svc == nil {
		return ErrServiceNotAvailable
	}

	if _, err := net.ParseMAC(macAddress); err != nil {
		return ErrInvalidMACAddress
	}

	return svc.DeleteReservation(ctx, macAddress)
}

// GetReservation retrieves a reservation by MAC.
func (h *DHCPAPIHandler) GetReservation(ctx context.Context, macAddress string) (*ReservationInfo, error) {
	h.mu.RLock()
	svc := h.reservationService
	h.mu.RUnlock()

	if svc == nil {
		return nil, ErrServiceNotAvailable
	}

	if _, err := net.ParseMAC(macAddress); err != nil {
		return nil, ErrInvalidMACAddress
	}

	return svc.GetReservation(ctx, macAddress)
}

// GetAllReservations retrieves all reservations.
func (h *DHCPAPIHandler) GetAllReservations(ctx context.Context) ([]*ReservationInfo, error) {
	h.mu.RLock()
	svc := h.reservationService
	h.mu.RUnlock()

	if svc == nil {
		return nil, ErrServiceNotAvailable
	}

	return svc.GetAllReservations(ctx)
}

// ============================================================================
// Pool Management Handlers
// ============================================================================

// GetPoolInfo retrieves pool information.
func (h *DHCPAPIHandler) GetPoolInfo(ctx context.Context, poolName string) (*PoolInfo, error) {
	h.mu.RLock()
	svc := h.poolService
	h.mu.RUnlock()

	if svc == nil {
		return nil, ErrServiceNotAvailable
	}

	if poolName == "" {
		return nil, ErrInvalidPoolName
	}

	return svc.GetPoolInfo(ctx, poolName)
}

// GetAllPools retrieves all pool information.
func (h *DHCPAPIHandler) GetAllPools(ctx context.Context) ([]*PoolInfo, error) {
	h.mu.RLock()
	svc := h.poolService
	h.mu.RUnlock()

	if svc == nil {
		return nil, ErrServiceNotAvailable
	}

	return svc.GetAllPools(ctx)
}

// UpdatePoolLeaseTime updates lease time for a pool.
func (h *DHCPAPIHandler) UpdatePoolLeaseTime(ctx context.Context, poolName string, leaseTimeSeconds int64) error {
	h.mu.RLock()
	svc := h.poolService
	h.mu.RUnlock()

	if svc == nil {
		return ErrServiceNotAvailable
	}

	if poolName == "" {
		return ErrInvalidPoolName
	}

	if leaseTimeSeconds < 60 {
		return ErrInvalidLeaseTime
	}

	return svc.UpdatePoolLeaseTime(ctx, poolName, leaseTimeSeconds)
}

// ============================================================================
// Statistics Handlers
// ============================================================================

// GetStats retrieves server statistics.
func (h *DHCPAPIHandler) GetStats(ctx context.Context) (*ServerStats, error) {
	h.mu.RLock()
	svc := h.statsService
	h.mu.RUnlock()

	if svc == nil {
		return nil, ErrServiceNotAvailable
	}

	return svc.GetStats(ctx)
}

// GetPoolStats retrieves pool statistics.
func (h *DHCPAPIHandler) GetPoolStats(ctx context.Context, poolName string) (*PoolInfo, error) {
	h.mu.RLock()
	svc := h.statsService
	h.mu.RUnlock()

	if svc == nil {
		return nil, ErrServiceNotAvailable
	}

	if poolName == "" {
		return nil, ErrInvalidPoolName
	}

	return svc.GetPoolStats(ctx, poolName)
}

// ============================================================================
// DNS Integration Handlers
// ============================================================================

// GetDNSIntegrationStatus retrieves DNS integration status.
func (h *DHCPAPIHandler) GetDNSIntegrationStatus(ctx context.Context) (*DNSIntegrationStatus, error) {
	h.mu.RLock()
	svc := h.dnsService
	h.mu.RUnlock()

	if svc == nil {
		return &DNSIntegrationStatus{Available: false}, nil
	}

	return svc.GetStatus(ctx)
}

// SyncDNSRecords triggers DNS synchronization.
func (h *DHCPAPIHandler) SyncDNSRecords(ctx context.Context) (int, error) {
	h.mu.RLock()
	svc := h.dnsService
	h.mu.RUnlock()

	if svc == nil {
		return 0, ErrServiceNotAvailable
	}

	return svc.SyncRecords(ctx)
}

// ============================================================================
// CA Integration Handlers
// ============================================================================

// GetCAIntegrationStatus retrieves CA integration status.
func (h *DHCPAPIHandler) GetCAIntegrationStatus(ctx context.Context) (*CAIntegrationStatus, error) {
	h.mu.RLock()
	svc := h.caService
	h.mu.RUnlock()

	if svc == nil {
		return &CAIntegrationStatus{Available: false}, nil
	}

	return svc.GetStatus(ctx)
}

// RefreshCACache refreshes the CA URL cache.
func (h *DHCPAPIHandler) RefreshCACache(ctx context.Context) error {
	h.mu.RLock()
	svc := h.caService
	h.mu.RUnlock()

	if svc == nil {
		return ErrServiceNotAvailable
	}

	return svc.RefreshCache(ctx)
}

// ============================================================================
// Configuration Handlers
// ============================================================================

// ReloadConfig reloads server configuration.
func (h *DHCPAPIHandler) ReloadConfig(ctx context.Context) error {
	h.mu.RLock()
	svc := h.configService
	h.mu.RUnlock()

	if svc == nil {
		return ErrServiceNotAvailable
	}

	return svc.ReloadConfig(ctx)
}

// ============================================================================
// Health Check
// ============================================================================

// HealthCheck performs a health check.
func (h *DHCPAPIHandler) HealthCheck(ctx context.Context) (bool, string) {
	// Check if basic services are available
	h.mu.RLock()
	leaseAvailable := h.leaseService != nil
	poolAvailable := h.poolService != nil
	h.mu.RUnlock()

	if !leaseAvailable || !poolAvailable {
		return false, "core services unavailable"
	}

	return true, "healthy"
}

// ============================================================================
// Errors
// ============================================================================

var (
	// ErrServiceNotAvailable is returned when a service is not available
	ErrServiceNotAvailable = errors.New("service not available")

	// ErrInvalidMACAddress is returned for invalid MAC addresses
	ErrInvalidMACAddress = errors.New("invalid MAC address format")

	// ErrInvalidIPAddress is returned for invalid IP addresses
	ErrInvalidIPAddress = errors.New("invalid IP address format")

	// ErrInvalidPoolName is returned for invalid pool names
	ErrInvalidPoolName = errors.New("invalid or empty pool name")

	// ErrInvalidLeaseTime is returned for invalid lease times
	ErrInvalidLeaseTime = errors.New("lease time must be at least 60 seconds")

	// ErrLeaseNotFound is returned when lease not found
	ErrLeaseNotFound = errors.New("lease not found")

	// ErrPoolNotFound is returned when pool not found
	ErrPoolNotFound = errors.New("pool not found")

	// ErrReservationExists is returned when reservation already exists
	ErrReservationExists = errors.New("reservation already exists for this MAC")

	// ErrIPAlreadyReserved is returned when IP is already reserved
	ErrIPAlreadyReserved = errors.New("IP address already reserved")

	// ErrIPNotInPool is returned when IP is not in pool range
	ErrIPNotInPool = errors.New("IP address not in pool range")
)
