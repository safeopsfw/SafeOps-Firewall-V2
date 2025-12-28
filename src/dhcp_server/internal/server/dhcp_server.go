// Package server implements the DHCP server core components.
// This file implements the main DHCP server coordinator.
package server

import (
	"context"
	"errors"
	"net/http"
	"sync"
	"sync/atomic"
	"time"
)

// ============================================================================
// DHCP Server Configuration
// ============================================================================

// DHCPServerConfig holds server configuration.
type DHCPServerConfig struct {
	ListenAddress        string
	ListenPort           int
	GRPCPort             int
	MetricsPort          int
	HealthPort           int
	ShutdownTimeout      time.Duration
	LeaseCleanupInterval time.Duration
	PoolCheckInterval    time.Duration
	CacheRefreshInterval time.Duration
	HealthCheckInterval  time.Duration
}

// DefaultDHCPServerConfig returns sensible defaults.
func DefaultDHCPServerConfig() *DHCPServerConfig {
	return &DHCPServerConfig{
		ListenAddress:        "0.0.0.0",
		ListenPort:           67,
		GRPCPort:             50054,
		MetricsPort:          9154,
		HealthPort:           8067,
		ShutdownTimeout:      30 * time.Second,
		LeaseCleanupInterval: 5 * time.Minute,
		PoolCheckInterval:    1 * time.Minute,
		CacheRefreshInterval: 30 * time.Minute,
		HealthCheckInterval:  30 * time.Second,
	}
}

// ============================================================================
// Component Interfaces
// ============================================================================

// LeaseManagerComponent defines lease manager operations.
type LeaseManagerComponent interface {
	Start(ctx context.Context) error
	Stop() error
	GetActiveLeaseCount() int64
}

// PoolManagerComponent defines pool manager operations.
type PoolManagerComponent interface {
	GetPoolUtilization() map[string]float64
}

// DNSIntegrationComponent defines DNS integration operations.
type DNSIntegrationComponent interface {
	Start(ctx context.Context) error
	Stop() error
	IsHealthy() bool
}

// CAIntegrationComponent defines CA integration operations.
type CAIntegrationComponent interface {
	IsHealthy() bool
	RefreshCache(ctx context.Context) error
}

// ============================================================================
// DHCP Server
// ============================================================================

// DHCPServer is the main DHCP server coordinator.
type DHCPServer struct {
	mu     sync.RWMutex
	config *DHCPServerConfig

	// Core components
	listener       *UDPListener
	sender         *UDPSender
	packetHandler  *DHCPPacketHandler
	messageBuilder *MessageBuilder

	// Integration components
	leaseManager   LeaseManagerComponent
	poolManager    PoolManagerComponent
	dnsIntegration DNSIntegrationComponent
	caIntegration  CAIntegrationComponent

	// Lifecycle
	running  atomic.Bool
	stopChan chan struct{}
	wg       sync.WaitGroup

	// Health server
	healthServer *http.Server

	// Statistics
	stats     ServerStats
	startTime time.Time
}

// ServerStats tracks server metrics.
type ServerStats struct {
	Uptime           time.Duration
	ActiveLeases     int64
	TotalRequests    int64
	SuccessfulLeases int64
	FailedRequests   int64
}

// ============================================================================
// Server Creation
// ============================================================================

// NewDHCPServer creates a new DHCP server.
func NewDHCPServer(config *DHCPServerConfig) *DHCPServer {
	if config == nil {
		config = DefaultDHCPServerConfig()
	}

	return &DHCPServer{
		config:   config,
		stopChan: make(chan struct{}),
	}
}

// ============================================================================
// Component Configuration
// ============================================================================

// SetListener sets the UDP listener.
func (s *DHCPServer) SetListener(listener *UDPListener) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.listener = listener
}

// SetSender sets the UDP sender.
func (s *DHCPServer) SetSender(sender *UDPSender) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.sender = sender
}

// SetPacketHandler sets the packet handler.
func (s *DHCPServer) SetPacketHandler(handler *DHCPPacketHandler) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.packetHandler = handler
}

// SetMessageBuilder sets the message builder.
func (s *DHCPServer) SetMessageBuilder(builder *MessageBuilder) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.messageBuilder = builder
}

// SetLeaseManager sets the lease manager.
func (s *DHCPServer) SetLeaseManager(lm LeaseManagerComponent) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.leaseManager = lm
}

// SetPoolManager sets the pool manager.
func (s *DHCPServer) SetPoolManager(pm PoolManagerComponent) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.poolManager = pm
}

// SetDNSIntegration sets the DNS integration.
func (s *DHCPServer) SetDNSIntegration(dns DNSIntegrationComponent) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.dnsIntegration = dns
}

// SetCAIntegration sets the CA integration.
func (s *DHCPServer) SetCAIntegration(ca CAIntegrationComponent) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.caIntegration = ca
}

// ============================================================================
// Server Lifecycle
// ============================================================================

// Start starts the DHCP server.
func (s *DHCPServer) Start(ctx context.Context) error {
	if s.running.Load() {
		return ErrServerAlreadyRunning
	}

	s.startTime = time.Now()
	s.stopChan = make(chan struct{})

	// Validate components
	if err := s.validateComponents(); err != nil {
		return err
	}

	// Wire components together
	s.wireComponents()

	// Start lease manager
	if s.leaseManager != nil {
		if err := s.leaseManager.Start(ctx); err != nil {
			return err
		}
	}

	// Start DNS integration
	if s.dnsIntegration != nil {
		if err := s.dnsIntegration.Start(ctx); err != nil {
			// Log but continue - DNS is not critical
			_ = err
		}
	}

	// Start UDP listener
	if s.listener != nil {
		if err := s.listener.Start(ctx); err != nil {
			return err
		}
	}

	// Start health server
	s.startHealthServer()

	// Start background tasks
	s.startBackgroundTasks()

	s.running.Store(true)

	return nil
}

// Stop stops the DHCP server gracefully.
func (s *DHCPServer) Stop() error {
	if !s.running.Load() {
		return nil
	}

	// Signal all goroutines to stop
	close(s.stopChan)

	// Stop accepting new requests
	if s.listener != nil {
		s.listener.Stop()
	}

	// Wait for in-flight requests with timeout
	done := make(chan struct{})
	go func() {
		s.wg.Wait()
		close(done)
	}()

	select {
	case <-done:
		// Clean shutdown
	case <-time.After(s.config.ShutdownTimeout):
		// Timeout waiting
	}

	// Stop components in reverse order
	if s.dnsIntegration != nil {
		s.dnsIntegration.Stop()
	}

	if s.leaseManager != nil {
		s.leaseManager.Stop()
	}

	// Stop health server
	if s.healthServer != nil {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		s.healthServer.Shutdown(ctx)
		cancel()
	}

	s.running.Store(false)

	return nil
}

// ============================================================================
// Component Wiring
// ============================================================================

func (s *DHCPServer) validateComponents() error {
	if s.listener == nil {
		return ErrNoListener
	}

	if s.packetHandler == nil {
		return ErrNoPacketHandler
	}

	return nil
}

func (s *DHCPServer) wireComponents() {
	// Wire listener to packet handler
	if s.listener != nil && s.packetHandler != nil {
		s.listener.SetPacketHandler(s.packetHandler)
	}

	// Wire sender to packet handler
	if s.sender != nil && s.packetHandler != nil {
		s.packetHandler.SetSender(s.sender)
	}

	// Wire message builder to packet handler
	if s.messageBuilder != nil && s.packetHandler != nil {
		s.packetHandler.SetMessageBuilder(s.messageBuilder)
	}

	// Share connection between listener and sender
	if s.listener != nil && s.sender != nil {
		conn := s.listener.GetConnection()
		if conn != nil {
			s.sender.SetConnection(conn)
		}
	}
}

// ============================================================================
// Health Server
// ============================================================================

func (s *DHCPServer) startHealthServer() {
	mux := http.NewServeMux()
	mux.HandleFunc("/health", s.healthHandler)
	mux.HandleFunc("/ready", s.readyHandler)
	mux.HandleFunc("/live", s.liveHandler)

	s.healthServer = &http.Server{
		Addr:    ":8067",
		Handler: mux,
	}

	s.wg.Add(1)
	go func() {
		defer s.wg.Done()
		s.healthServer.ListenAndServe()
	}()
}

func (s *DHCPServer) healthHandler(w http.ResponseWriter, r *http.Request) {
	status := s.GetHealthStatus()

	w.Header().Set("Content-Type", "application/json")

	if status.Healthy {
		w.WriteHeader(http.StatusOK)
	} else {
		w.WriteHeader(http.StatusServiceUnavailable)
	}

	// Write simple JSON response
	response := `{"status":"` + status.Status + `"}`
	w.Write([]byte(response))
}

func (s *DHCPServer) readyHandler(w http.ResponseWriter, r *http.Request) {
	if s.isReady() {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("ready"))
	} else {
		w.WriteHeader(http.StatusServiceUnavailable)
		w.Write([]byte("not ready"))
	}
}

func (s *DHCPServer) liveHandler(w http.ResponseWriter, r *http.Request) {
	if s.running.Load() {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("alive"))
	} else {
		w.WriteHeader(http.StatusServiceUnavailable)
		w.Write([]byte("not alive"))
	}
}

func (s *DHCPServer) isReady() bool {
	// Check critical components
	if s.listener == nil || !s.listener.IsRunning() {
		return false
	}

	return s.running.Load()
}

// ============================================================================
// Background Tasks
// ============================================================================

func (s *DHCPServer) startBackgroundTasks() {
	// Lease cleanup task
	s.wg.Add(1)
	go s.leaseCleanupTask()

	// Pool monitoring task
	s.wg.Add(1)
	go s.poolMonitoringTask()

	// Cache refresh task
	s.wg.Add(1)
	go s.cacheRefreshTask()
}

func (s *DHCPServer) leaseCleanupTask() {
	defer s.wg.Done()

	ticker := time.NewTicker(s.config.LeaseCleanupInterval)
	defer ticker.Stop()

	for {
		select {
		case <-s.stopChan:
			return
		case <-ticker.C:
			// Lease cleanup is handled by lease manager's expiry handler
		}
	}
}

func (s *DHCPServer) poolMonitoringTask() {
	defer s.wg.Done()

	ticker := time.NewTicker(s.config.PoolCheckInterval)
	defer ticker.Stop()

	for {
		select {
		case <-s.stopChan:
			return
		case <-ticker.C:
			s.checkPoolUtilization()
		}
	}
}

func (s *DHCPServer) cacheRefreshTask() {
	defer s.wg.Done()

	ticker := time.NewTicker(s.config.CacheRefreshInterval)
	defer ticker.Stop()

	for {
		select {
		case <-s.stopChan:
			return
		case <-ticker.C:
			s.refreshCaches()
		}
	}
}

func (s *DHCPServer) checkPoolUtilization() {
	s.mu.RLock()
	pm := s.poolManager
	s.mu.RUnlock()

	if pm == nil {
		return
	}

	utilization := pm.GetPoolUtilization()
	for poolName, pct := range utilization {
		if pct > 80 {
			// Log high utilization warning
			_ = poolName
		}
	}
}

func (s *DHCPServer) refreshCaches() {
	s.mu.RLock()
	ca := s.caIntegration
	s.mu.RUnlock()

	if ca == nil {
		return
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	ca.RefreshCache(ctx)
}

// ============================================================================
// Status and Statistics
// ============================================================================

// HealthStatus contains server health information.
type HealthStatus struct {
	Healthy         bool
	Status          string
	Uptime          time.Duration
	ActiveLeases    int64
	PoolUtilization map[string]float64
	ListenerRunning bool
	DNSHealthy      bool
	CAHealthy       bool
}

// GetHealthStatus returns current health status.
func (s *DHCPServer) GetHealthStatus() *HealthStatus {
	status := &HealthStatus{
		Uptime: time.Since(s.startTime),
	}

	// Check listener
	if s.listener != nil {
		status.ListenerRunning = s.listener.IsRunning()
	}

	// Check lease manager
	if s.leaseManager != nil {
		status.ActiveLeases = s.leaseManager.GetActiveLeaseCount()
	}

	// Check pool utilization
	if s.poolManager != nil {
		status.PoolUtilization = s.poolManager.GetPoolUtilization()
	}

	// Check DNS integration
	if s.dnsIntegration != nil {
		status.DNSHealthy = s.dnsIntegration.IsHealthy()
	} else {
		status.DNSHealthy = true // No DNS = not unhealthy
	}

	// Check CA integration
	if s.caIntegration != nil {
		status.CAHealthy = s.caIntegration.IsHealthy()
	} else {
		status.CAHealthy = true // No CA = not unhealthy
	}

	// Overall health determination
	status.Healthy = status.ListenerRunning
	if status.Healthy {
		status.Status = "healthy"
	} else {
		status.Status = "unhealthy"
	}

	return status
}

// GetStats returns server statistics.
func (s *DHCPServer) GetStats() *ServerStats {
	stats := &ServerStats{
		Uptime: time.Since(s.startTime),
	}

	if s.leaseManager != nil {
		stats.ActiveLeases = s.leaseManager.GetActiveLeaseCount()
	}

	if s.packetHandler != nil {
		handlerStats := s.packetHandler.GetStats()
		stats.TotalRequests = handlerStats.TotalProcessed
		stats.SuccessfulLeases = handlerStats.AckSent
		stats.FailedRequests = handlerStats.TotalDropped + handlerStats.HandlerErrors
	}

	return stats
}

// IsRunning returns whether server is running.
func (s *DHCPServer) IsRunning() bool {
	return s.running.Load()
}

// GetUptime returns server uptime.
func (s *DHCPServer) GetUptime() time.Duration {
	if s.startTime.IsZero() {
		return 0
	}
	return time.Since(s.startTime)
}

// ============================================================================
// Configuration Reload
// ============================================================================

// ReloadConfig reloads reloadable configuration.
func (s *DHCPServer) ReloadConfig(ctx context.Context) error {
	// Placeholder for configuration reload
	// Would reload pools, lease times, etc.
	return nil
}

// ============================================================================
// Errors
// ============================================================================

var (
	// ErrServerAlreadyRunning is returned when server already running
	ErrServerAlreadyRunning = errors.New("server already running")

	// ErrServerNotRunning is returned when server not running
	ErrServerNotRunning = errors.New("server not running")

	// ErrNoListener is returned when no listener configured
	ErrNoListener = errors.New("no UDP listener configured")

	// ErrStartupFailed is returned when startup fails
	ErrStartupFailed = errors.New("server startup failed")

	// ErrShutdownTimeout is returned when shutdown times out
	ErrShutdownTimeout = errors.New("shutdown timeout exceeded")
)
