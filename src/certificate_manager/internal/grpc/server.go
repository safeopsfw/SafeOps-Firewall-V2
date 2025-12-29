// Package grpc implements gRPC service handlers for the Certificate Manager.
package grpc

import (
	"context"
	"crypto/tls"
	"fmt"
	"log"
	"net"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"time"

	"certificate_manager/pkg/types"
)

// ============================================================================
// Server Configuration
// ============================================================================

// ServerConfig holds gRPC server configuration.
type ServerConfig struct {
	Host                 string
	Port                 int
	MaxRecvMsgSize       int           // Maximum receive message size (default: 4MB)
	MaxSendMsgSize       int           // Maximum send message size (default: 4MB)
	ConnectionTimeout    time.Duration // Connection timeout (default: 30s)
	MaxConcurrentStreams int
	MaxConnectionIdle    time.Duration
	MaxConnectionAge     time.Duration
	KeepaliveTime        time.Duration
	KeepaliveTimeout     time.Duration
	ReflectionEnabled    bool

	// TLS settings
	TLSEnabled  bool
	TLSCertPath string
	TLSKeyPath  string
	TLSCAPath   string // For mTLS client verification

	// Middleware configuration
	MiddlewareConfig *MiddlewareConfig
}

// DefaultServerConfig returns default server configuration.
func DefaultServerConfig() *ServerConfig {
	return &ServerConfig{
		Host:                 "0.0.0.0",
		Port:                 50060,           // Default gRPC port for Certificate Manager
		MaxRecvMsgSize:       4 * 1024 * 1024, // 4MB
		MaxSendMsgSize:       4 * 1024 * 1024, // 4MB
		ConnectionTimeout:    30 * time.Second,
		MaxConcurrentStreams: 100,
		MaxConnectionIdle:    5 * time.Minute,
		MaxConnectionAge:     30 * time.Minute,
		KeepaliveTime:        30 * time.Second,
		KeepaliveTimeout:     10 * time.Second,
		ReflectionEnabled:    true,
		TLSEnabled:           false,
		MiddlewareConfig:     DefaultMiddlewareConfig(),
	}
}

// ServerConfigFromTypes converts types.Config to ServerConfig.
func ServerConfigFromTypes(cfg *types.Config) *ServerConfig {
	return &ServerConfig{
		Host:                 cfg.GRPC.Host,
		Port:                 cfg.GRPC.Port,
		MaxConcurrentStreams: cfg.GRPC.MaxConcurrentStreams,
		MaxConnectionIdle:    cfg.GRPC.MaxConnectionIdle,
		MaxConnectionAge:     cfg.GRPC.MaxConnectionAge,
		KeepaliveTime:        cfg.GRPC.KeepaliveTime,
		KeepaliveTimeout:     cfg.GRPC.KeepaliveTimeout,
		ReflectionEnabled:    cfg.GRPC.ReflectionEnabled,
		TLSEnabled:           false, // Would be configured separately
		MiddlewareConfig:     LoadMiddlewareConfigFromTypes(cfg),
	}
}

// ============================================================================
// Certificate Manager Service
// ============================================================================

// CertificateManagerService implements the gRPC service for Certificate Manager.
type CertificateManagerService struct {
	config *types.Config

	// Handlers for different RPC groups
	certInfoHandler   *CertificateInfoHandler
	deviceHandler     *DeviceStatusHandler
	revocationHandler *RevocationHandler

	// Middleware chain
	middleware *MiddlewareChain

	// Server state
	mu       sync.RWMutex
	running  bool
	listener net.Listener
}

// NewCertificateManagerService creates a new Certificate Manager gRPC service.
func NewCertificateManagerService(cfg *types.Config) *CertificateManagerService {
	middlewareCfg := LoadMiddlewareConfigFromTypes(cfg)

	return &CertificateManagerService{
		config:            cfg,
		certInfoHandler:   NewCertificateInfoHandler(cfg),
		deviceHandler:     NewDeviceStatusHandler(nil, cfg), // Uses in-memory store
		revocationHandler: NewRevocationHandler(nil, cfg),   // Uses in-memory store
		middleware:        NewMiddlewareChain(middlewareCfg),
		running:           false,
	}
}

// ============================================================================
// Service Initialization
// ============================================================================

// Start starts the gRPC server.
func (s *CertificateManagerService) Start(serverCfg *ServerConfig) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.running {
		return fmt.Errorf("server already running")
	}

	address := fmt.Sprintf("%s:%d", serverCfg.Host, serverCfg.Port)

	listener, err := net.Listen("tcp", address)
	if err != nil {
		return fmt.Errorf("failed to listen on %s: %w", address, err)
	}
	s.listener = listener

	log.Printf("[gRPC Server] Starting Certificate Manager gRPC service on %s", address)
	log.Printf("[gRPC Server] Reflection enabled: %v", serverCfg.ReflectionEnabled)
	log.Printf("[gRPC Server] TLS enabled: %v", serverCfg.TLSEnabled)

	s.running = true

	// In a real implementation, this would:
	// 1. Create grpc.Server with options
	// 2. Register service handlers
	// 3. Start serving in a goroutine
	//
	// For now, we provide the handler methods that would be registered.

	log.Printf("[gRPC Server] Certificate Manager service started successfully")
	return nil
}

// Stop gracefully stops the gRPC server.
func (s *CertificateManagerService) Stop() error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if !s.running {
		return nil
	}

	log.Printf("[gRPC Server] Stopping Certificate Manager service...")

	if s.listener != nil {
		s.listener.Close()
	}

	s.running = false
	log.Printf("[gRPC Server] Service stopped")
	return nil
}

// IsRunning returns whether the server is running.
func (s *CertificateManagerService) IsRunning() bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.running
}

// ============================================================================
// RPC Method Handlers
// ============================================================================

// GetCertificateInfo implements the GetCertificateInfo RPC.
// This is the primary integration point for DHCP server.
func (s *CertificateManagerService) GetCertificateInfo(ctx context.Context) (*CertificateInfoResponse, error) {
	// This method is public - no authentication required
	return s.certInfoHandler.GetCertificateInfo()
}

// GetDeviceStatus implements the GetDeviceStatus RPC.
func (s *CertificateManagerService) GetDeviceStatus(ctx context.Context, req *DeviceStatusRequest) (*DeviceStatusResponse, error) {
	// Process through middleware
	authInfo, _, err := s.middleware.ProcessRequest(ctx, "/CertificateManager/GetDeviceStatus", nil, nil)
	if err != nil {
		return nil, err
	}
	_ = authInfo // Used for logging

	return s.deviceHandler.GetDeviceStatus(ctx, req)
}

// UpdateDeviceStatus implements the UpdateDeviceStatus RPC.
func (s *CertificateManagerService) UpdateDeviceStatus(ctx context.Context, req *UpdateDeviceStatusRequest) (*DeviceStatusResponse, error) {
	// Process through middleware - requires operator role
	authInfo, _, err := s.middleware.ProcessRequest(ctx, "/CertificateManager/UpdateDeviceStatus", nil, nil)
	if err != nil {
		return nil, err
	}
	_ = authInfo

	return s.deviceHandler.UpdateDeviceStatus(ctx, req)
}

// CheckRevocationStatus implements the CheckRevocationStatus RPC.
func (s *CertificateManagerService) CheckRevocationStatus(ctx context.Context, req *CheckRevocationStatusRequest) (*RevocationStatusResponse, error) {
	// Process through middleware - viewer role allowed
	authInfo, _, err := s.middleware.ProcessRequest(ctx, "/CertificateManager/CheckRevocationStatus", nil, nil)
	if err != nil {
		return nil, err
	}
	_ = authInfo

	return s.revocationHandler.CheckRevocationStatus(ctx, req)
}

// RevokeCertificate implements the RevokeCertificate RPC.
func (s *CertificateManagerService) RevokeCertificate(ctx context.Context, req *RevokeCertificateRequest) (*RevokeCertificateResponse, error) {
	// Process through middleware - requires admin role
	authInfo, _, err := s.middleware.ProcessRequest(ctx, "/CertificateManager/RevokeCertificate", nil, nil)
	if err != nil {
		return nil, err
	}

	// Add revoker identity from auth
	if authInfo != nil && req.RevokedBy == "" {
		req.RevokedBy = authInfo.ClientID
	}

	return s.revocationHandler.RevokeCertificate(ctx, req)
}

// ============================================================================
// List and Details RPC Methods
// ============================================================================

// ListCertificatesRequest for listing issued certificates.
type ListCertificatesRequest struct {
	CommonNameFilter string    `json:"common_name_filter"` // Filter by common name (supports wildcards)
	IssuedAfter      time.Time `json:"issued_after"`       // Filter: issued after timestamp
	IssuedBefore     time.Time `json:"issued_before"`      // Filter: issued before timestamp
	CertificateType  string    `json:"certificate_type"`   // Filter: "server", "client", "code_signing"
	IncludeRevoked   bool      `json:"include_revoked"`    // Include revoked certificates
	Limit            int       `json:"limit"`              // Max results (default 100, max 1000)
	Offset           int       `json:"offset"`             // Pagination offset
}

// CertificateSummary represents a certificate summary for lists.
type CertificateSummary struct {
	SerialNumber    string    `json:"serial_number"`
	CommonName      string    `json:"common_name"`
	SubjectAltNames []string  `json:"subject_alt_names"`
	NotBefore       time.Time `json:"not_before"`
	NotAfter        time.Time `json:"not_after"`
	IssuedAt        time.Time `json:"issued_at"`
	CertificateType string    `json:"certificate_type"`
	Revoked         bool      `json:"revoked"`
}

// ListCertificatesResponse contains the list of certificates.
type ListCertificatesResponse struct {
	Certificates []CertificateSummary `json:"certificates"`
	TotalCount   int                  `json:"total_count"` // Total matching certificates (for pagination)
	Limit        int                  `json:"limit"`
	Offset       int                  `json:"offset"`
}

// CertificateDetailsRequest for getting certificate details.
type CertificateDetailsRequest struct {
	SerialNumber string `json:"serial_number"`
}

// CertificateDetails contains detailed certificate information.
type CertificateDetails struct {
	SerialNumber     string    `json:"serial_number"`
	CommonName       string    `json:"common_name"`
	SubjectAltNames  []string  `json:"subject_alt_names"`
	SubjectDN        string    `json:"subject_dn"`
	IssuerDN         string    `json:"issuer_dn"`
	NotBefore        time.Time `json:"not_before"`
	NotBeforeUnix    int64     `json:"not_before_unix"`
	NotAfter         time.Time `json:"not_after"`
	NotAfterUnix     int64     `json:"not_after_unix"`
	IssuedAt         time.Time `json:"issued_at"`
	IssuedAtUnix     int64     `json:"issued_at_unix"`
	CertificateType  string    `json:"certificate_type"`
	CertificatePEM   string    `json:"certificate_pem"`
	KeyType          string    `json:"key_type"`
	KeySize          int       `json:"key_size"`
	SignatureAlgo    string    `json:"signature_algorithm"`
	Fingerprint      string    `json:"fingerprint_sha256"`
	Revoked          bool      `json:"revoked"`
	RevokedAt        time.Time `json:"revoked_at,omitempty"`
	RevocationReason string    `json:"revocation_reason,omitempty"`
	Found            bool      `json:"found"`
}

// ListIssuedCertificates implements the ListIssuedCertificates RPC.
// Returns a paginated list of all certificates issued by the CA.
func (s *CertificateManagerService) ListIssuedCertificates(ctx context.Context, req *ListCertificatesRequest) (*ListCertificatesResponse, error) {
	// Process through middleware - requires viewer role
	_, _, err := s.middleware.ProcessRequest(ctx, "/CertificateManager/ListIssuedCertificates", nil, nil)
	if err != nil {
		return nil, err
	}

	// Apply defaults
	limit := req.Limit
	if limit <= 0 {
		limit = 100 // Default limit
	}
	if limit > 1000 {
		limit = 1000 // Max limit
	}

	log.Printf("[gRPC] ListIssuedCertificates: filter=%s type=%s limit=%d offset=%d",
		req.CommonNameFilter, req.CertificateType, limit, req.Offset)

	// In a real implementation, this would query the certificate repository
	// For now, return empty list (placeholder)
	return &ListCertificatesResponse{
		Certificates: []CertificateSummary{},
		TotalCount:   0,
		Limit:        limit,
		Offset:       req.Offset,
	}, nil
}

// GetCertificateDetails implements the GetCertificateDetails RPC.
// Returns detailed information about a specific certificate by serial number.
func (s *CertificateManagerService) GetCertificateDetails(ctx context.Context, req *CertificateDetailsRequest) (*CertificateDetails, error) {
	// Process through middleware - requires viewer role
	_, _, err := s.middleware.ProcessRequest(ctx, "/CertificateManager/GetCertificateDetails", nil, nil)
	if err != nil {
		return nil, err
	}

	// Validate serial number
	if err := ValidateSerialNumber(req.SerialNumber); err != nil {
		return nil, err
	}

	log.Printf("[gRPC] GetCertificateDetails: serial=%s", req.SerialNumber)

	// In a real implementation, this would query the certificate repository
	// For now, return not found (placeholder)
	return &CertificateDetails{
		SerialNumber: req.SerialNumber,
		Found:        false,
	}, nil
}

// ============================================================================
// Graceful Shutdown
// ============================================================================

// WaitForShutdown waits for shutdown signal and gracefully stops the server.
func (s *CertificateManagerService) WaitForShutdown() {
	// Create channel to receive OS signals
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)

	// Wait for signal
	sig := <-sigChan
	log.Printf("[gRPC Server] Received signal: %v", sig)

	// Initiate graceful shutdown
	log.Printf("[gRPC Server] Initiating graceful shutdown...")

	// Create shutdown context with timeout
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// Stop the server
	if err := s.Stop(); err != nil {
		log.Printf("[gRPC Server] Error during shutdown: %v", err)
	}

	// Wait for context to complete or timeout
	<-shutdownCtx.Done()
	log.Printf("[gRPC Server] Graceful shutdown complete")
}

// ============================================================================
// DHCP Integration Methods
// ============================================================================

// GetDHCPOption224 returns the CA URL for DHCP Option 224.
func (s *CertificateManagerService) GetDHCPOption224() string {
	return s.certInfoHandler.GetDHCPOption224Value()
}

// GetDHCPOption225 returns install script URLs for DHCP Option 225.
func (s *CertificateManagerService) GetDHCPOption225() string {
	return s.certInfoHandler.GetDHCPOption225Value()
}

// GetCAFingerprint returns the CA fingerprint for verification.
func (s *CertificateManagerService) GetCAFingerprint() string {
	return s.certInfoHandler.GetCAFingerprint()
}

// RecordCADownload records a CA certificate download.
func (s *CertificateManagerService) RecordCADownload(ctx context.Context, clientIP string) error {
	return s.deviceHandler.RecordCADownload(ctx, clientIP)
}

// ============================================================================
// Statistics and Health
// ============================================================================

// ServiceStats contains aggregate service statistics.
type ServiceStats struct {
	DeviceStats     *DeviceStats     `json:"device_stats"`
	RevocationStats *RevocationStats `json:"revocation_stats"`
	ServerUptime    time.Duration    `json:"server_uptime"`
	IsRunning       bool             `json:"is_running"`
}

// startTime tracks when the service was started.
var startTime = time.Now()

// GetServiceStats returns aggregate service statistics.
func (s *CertificateManagerService) GetServiceStats(ctx context.Context) (*ServiceStats, error) {
	deviceStats, err := s.deviceHandler.GetDeviceStats(ctx)
	if err != nil {
		return nil, err
	}

	revocationStats, err := s.revocationHandler.GetRevocationStats(ctx)
	if err != nil {
		return nil, err
	}

	return &ServiceStats{
		DeviceStats:     deviceStats,
		RevocationStats: revocationStats,
		ServerUptime:    time.Since(startTime),
		IsRunning:       s.IsRunning(),
	}, nil
}

// HealthCheck returns the health status of the service.
func (s *CertificateManagerService) HealthCheck() map[string]interface{} {
	certInfo, err := s.certInfoHandler.GetCertificateInfo()

	return map[string]interface{}{
		"status":       "healthy",
		"running":      s.IsRunning(),
		"ca_available": certInfo != nil && certInfo.CAAvailable,
		"ca_error":     err != nil,
		"uptime_ms":    time.Since(startTime).Milliseconds(),
	}
}

// ============================================================================
// Configuration Updates
// ============================================================================

// UpdateConfig updates the service configuration (hot reload).
func (s *CertificateManagerService) UpdateConfig(cfg *types.Config) {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.config = cfg
	s.certInfoHandler.UpdateConfig(cfg)

	log.Printf("[gRPC Server] Configuration updated")
}

// AddAPIKey adds an API key for authentication.
func (s *CertificateManagerService) AddAPIKey(key, keyID string, role Role) {
	s.middleware.AddAPIKey(key, APIKeyConfig{
		KeyID:   keyID,
		Role:    role,
		Enabled: true,
	})
	log.Printf("[gRPC Server] Added API key: %s (role=%s)", keyID, role)
}

// SetInternalAPIKeys sets API keys that bypass rate limiting.
func (s *CertificateManagerService) SetInternalAPIKeys(keys []string) {
	s.middleware.SetInternalBypassKeys(keys)
	log.Printf("[gRPC Server] Set %d internal bypass keys", len(keys))
}

// ============================================================================
// TLS Configuration
// ============================================================================

// LoadTLSConfig loads TLS configuration for the server.
func LoadTLSConfig(certPath, keyPath, caPath string) (*tls.Config, error) {
	// Load server certificate
	cert, err := tls.LoadX509KeyPair(certPath, keyPath)
	if err != nil {
		return nil, fmt.Errorf("failed to load server certificate: %w", err)
	}

	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{cert},
		MinVersion:   tls.VersionTLS12,
		CipherSuites: []uint16{
			tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
		},
	}

	// If CA path provided, enable mTLS
	if caPath != "" {
		// Would load CA certificate pool for client verification
		tlsConfig.ClientAuth = tls.RequireAndVerifyClientCert
		log.Printf("[TLS] mTLS enabled with CA: %s", caPath)
	}

	return tlsConfig, nil
}

// ============================================================================
// Service Factory
// ============================================================================

// NewService creates and configures a complete Certificate Manager service.
func NewService(cfg *types.Config) (*CertificateManagerService, error) {
	if cfg == nil {
		return nil, fmt.Errorf("configuration required")
	}

	service := NewCertificateManagerService(cfg)

	// Add default internal API key for DHCP integration
	service.AddAPIKey("dhcp-internal-key", "dhcp-server", RoleInternal)
	service.AddAPIKey("tls-proxy-key", "tls-proxy", RoleOperator)

	// Set internal bypass keys
	service.SetInternalAPIKeys([]string{"dhcp-server", "tls-proxy"})

	log.Printf("[gRPC Server] Certificate Manager service initialized")
	return service, nil
}
