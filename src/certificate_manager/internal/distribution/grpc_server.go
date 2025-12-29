// Package distribution implements the gRPC service for certificate management.
package distribution

import (
	"context"
	"errors"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"certificate_manager/internal/ca"
	"certificate_manager/pkg/types"
)

// ============================================================================
// Constants
// ============================================================================

const (
	DefaultGRPCPort         = 50060
	DefaultShutdownTimeout  = 30 * time.Second
	StreamKeepAliveInterval = 30 * time.Second
)

// gRPC-like status codes
const (
	CodeOK              = 0
	CodeCancelled       = 1
	CodeUnknown         = 2
	CodeInvalidArg      = 3
	CodeNotFound        = 5
	CodeAlreadyExists   = 6
	CodePermDenied      = 7
	CodeInternal        = 13
	CodeUnavailable     = 14
	CodeUnauthenticated = 16
)

// ============================================================================
// Error Types
// ============================================================================

var (
	ErrServerAlreadyRunning = errors.New("gRPC server is already running")
	ErrServerNotRunning     = errors.New("gRPC server is not running")
	ErrInvalidRequest       = errors.New("invalid request")
	ErrUnauthorized         = errors.New("unauthorized")
)

// ============================================================================
// Request/Response Types (Proto-like structures)
// ============================================================================

// GetCertificateRequest for fetching a certificate
type GetCertificateRequest struct {
	Domain            string `json:"domain"`
	IncludeChain      bool   `json:"include_chain"`
	IncludePrivateKey bool   `json:"include_private_key"`
}

// GetCertificateResponse contains certificate data
type GetCertificateResponse struct {
	Domain          string    `json:"domain"`
	CertificatePEM  string    `json:"certificate_pem"`
	PrivateKeyPEM   string    `json:"private_key_pem,omitempty"`
	ChainPEM        string    `json:"chain_pem,omitempty"`
	SerialNumber    string    `json:"serial_number"`
	Issuer          string    `json:"issuer"`
	NotBefore       time.Time `json:"not_before"`
	NotAfter        time.Time `json:"not_after"`
	DaysUntilExpiry int       `json:"days_until_expiry"`
}

// IssueCertificateRequest for certificate issuance
type IssueCertificateRequest struct {
	Domains      []string `json:"domains"`
	KeyType      string   `json:"key_type"`
	ForceReissue bool     `json:"force_reissue"`
}

// IssueCertificateResponse contains new certificate details
type IssueCertificateResponse struct {
	Success       bool      `json:"success"`
	Domain        string    `json:"domain"`
	SerialNumber  string    `json:"serial_number"`
	NotAfter      time.Time `json:"not_after"`
	DistributedTo []string  `json:"distributed_to"`
	Error         string    `json:"error,omitempty"`
}

// RenewCertificateRequest for manual renewal
type RenewCertificateRequest struct {
	Domain     string `json:"domain"`
	ForceRenew bool   `json:"force_renew"`
}

// RenewCertificateResponse contains renewal result
type RenewCertificateResponse struct {
	Success       bool      `json:"success"`
	Domain        string    `json:"domain"`
	OldExpiry     time.Time `json:"old_expiry"`
	NewExpiry     time.Time `json:"new_expiry"`
	DistributedTo []string  `json:"distributed_to"`
	Error         string    `json:"error,omitempty"`
}

// DeleteCertificateRequest for certificate removal
type DeleteCertificateRequest struct {
	Domain  string `json:"domain"`
	CertID  int64  `json:"cert_id"`
	Confirm bool   `json:"confirm"`
}

// DeleteCertificateResponse confirms deletion
type DeleteCertificateResponse struct {
	Success bool   `json:"success"`
	Domain  string `json:"domain"`
	Message string `json:"message"`
}

// ListCertificatesRequest for inventory query
type ListCertificatesRequest struct {
	DomainFilter string `json:"domain_filter"`
	Status       string `json:"status"`
	ExpiringIn   int    `json:"expiring_in_days"`
	PageSize     int    `json:"page_size"`
	PageToken    string `json:"page_token"`
	SortBy       string `json:"sort_by"`
	SortDesc     bool   `json:"sort_desc"`
}

// ListCertificatesResponse contains certificate list
type ListCertificatesResponse struct {
	Certificates  []CertificateSummary `json:"certificates"`
	TotalCount    int                  `json:"total_count"`
	NextPageToken string               `json:"next_page_token"`
}

// CertificateSummary for list responses
type CertificateSummary struct {
	ID            int64     `json:"id"`
	Domain        string    `json:"domain"`
	SANs          []string  `json:"sans"`
	Status        string    `json:"status"`
	Issuer        string    `json:"issuer"`
	NotAfter      time.Time `json:"not_after"`
	DaysRemaining int       `json:"days_remaining"`
}

// RenewalStatusRequest for scheduler status
type RenewalStatusRequest struct{}

// RenewalStatusResponse contains renewal system status
type RenewalStatusResponse struct {
	Enabled             bool      `json:"enabled"`
	Running             bool      `json:"running"`
	LastCheckTime       time.Time `json:"last_check_time"`
	NextCheckTime       time.Time `json:"next_check_time"`
	CertificatesManaged int       `json:"certificates_managed"`
	RenewalsAttempted   int64     `json:"renewals_attempted"`
	RenewalsSucceeded   int64     `json:"renewals_succeeded"`
	RenewalsFailed      int64     `json:"renewals_failed"`
}

// DistributionStatusRequest for distribution status
type DistributionStatusRequest struct {
	ServiceFilter string `json:"service_filter"`
}

// DistributionStatusResponse contains distribution status
type DistributionStatusResponse struct {
	Running            bool                   `json:"running"`
	RegisteredServices int                    `json:"registered_services"`
	HealthyServices    int                    `json:"healthy_services"`
	PendingQueue       int                    `json:"pending_queue"`
	TotalDistributions int64                  `json:"total_distributions"`
	SuccessRate        float64                `json:"success_rate"`
	Services           []ServiceStatusSummary `json:"services"`
}

// ServiceStatusSummary for service status
type ServiceStatusSummary struct {
	Name        string    `json:"name"`
	Type        string    `json:"type"`
	Status      string    `json:"status"`
	LastPush    time.Time `json:"last_push"`
	SuccessRate float64   `json:"success_rate"`
}

// HealthCheckRequest for health status
type HealthCheckRequest struct {
	Service string `json:"service"`
}

// HealthCheckResponse contains health status
type HealthCheckResponse struct {
	Status     string                 `json:"status"` // SERVING, NOT_SERVING, UNKNOWN
	Components map[string]string      `json:"components"`
	Details    map[string]interface{} `json:"details,omitempty"`
}

// CertificateChangeEvent for streaming
type CertificateChangeEvent struct {
	Domain     string    `json:"domain"`
	ChangeType string    `json:"change_type"`
	Timestamp  time.Time `json:"timestamp"`
	NewExpiry  time.Time `json:"new_expiry,omitempty"`
}

// ============================================================================
// CertificateManagerServer Structure
// ============================================================================

// CertificateManagerServer implements the gRPC service
type CertificateManagerServer struct {
	certManager      *ca.CertificateManager
	renewalScheduler *ca.RenewalScheduler
	distributor      *Distributor
	watcher          *CertificateWatcher
	config           ServerConfig

	// Server state
	listener net.Listener
	running  atomic.Bool
	stopChan chan struct{}
	doneChan chan struct{}

	// Subscribers for streaming
	subscribers   map[string]chan *CertificateChangeEvent
	subscribersMu sync.RWMutex

	// Metrics
	metrics *ServerMetrics
}

// ServerConfig holds server configuration
type ServerConfig struct {
	Port                    int
	EnableTLS               bool
	TLSCertPath             string
	TLSKeyPath              string
	GracefulShutdownTimeout time.Duration
	EnableAuth              bool
	MaxConcurrentStreams    uint32
}

// ServerMetrics tracks API statistics
type ServerMetrics struct {
	TotalRequests      int64
	SuccessfulRequests int64
	FailedRequests     int64
	ActiveStreams      int64
	GetCertCalls       int64
	IssueCertCalls     int64
	RenewCertCalls     int64
	DeleteCertCalls    int64
	ListCertCalls      int64
	HealthCheckCalls   int64
	mu                 sync.RWMutex
}

// ============================================================================
// Constructor
// ============================================================================

// NewCertificateManagerServer creates a new gRPC server
func NewCertificateManagerServer(
	certManager *ca.CertificateManager,
	renewalScheduler *ca.RenewalScheduler,
	distributor *Distributor,
	watcher *CertificateWatcher,
	config ServerConfig,
) (*CertificateManagerServer, error) {
	// Apply defaults
	if config.Port <= 0 {
		config.Port = DefaultGRPCPort
	}
	if config.GracefulShutdownTimeout <= 0 {
		config.GracefulShutdownTimeout = DefaultShutdownTimeout
	}

	return &CertificateManagerServer{
		certManager:      certManager,
		renewalScheduler: renewalScheduler,
		distributor:      distributor,
		watcher:          watcher,
		config:           config,
		stopChan:         make(chan struct{}),
		doneChan:         make(chan struct{}),
		subscribers:      make(map[string]chan *CertificateChangeEvent),
		metrics:          &ServerMetrics{},
	}, nil
}

// ============================================================================
// Certificate Operations
// ============================================================================

// GetCertificate retrieves a certificate by domain
func (s *CertificateManagerServer) GetCertificate(ctx context.Context, req *GetCertificateRequest) (*GetCertificateResponse, error) {
	atomic.AddInt64(&s.metrics.TotalRequests, 1)
	atomic.AddInt64(&s.metrics.GetCertCalls, 1)

	// Validate request
	if req.Domain == "" {
		atomic.AddInt64(&s.metrics.FailedRequests, 1)
		return nil, newError(CodeInvalidArg, "domain is required")
	}

	// Get certificate
	cert, err := s.certManager.GetCertificate(ctx, req.Domain)
	if err != nil {
		atomic.AddInt64(&s.metrics.FailedRequests, 1)
		if errors.Is(err, ca.ErrCertificateNotFound) {
			return nil, newError(CodeNotFound, "certificate not found for domain: "+req.Domain)
		}
		return nil, newError(CodeInternal, err.Error())
	}

	atomic.AddInt64(&s.metrics.SuccessfulRequests, 1)

	// Build response
	resp := &GetCertificateResponse{
		Domain:          cert.CommonName,
		CertificatePEM:  cert.CertificatePEM,
		SerialNumber:    cert.SerialNumber,
		Issuer:          cert.Issuer,
		NotBefore:       cert.NotBefore,
		NotAfter:        cert.NotAfter,
		DaysUntilExpiry: cert.DaysUntilExpiry(),
	}

	if req.IncludePrivateKey {
		resp.PrivateKeyPEM = cert.PrivateKeyPEM
	}
	if req.IncludeChain {
		resp.ChainPEM = cert.ChainPEM
	}

	return resp, nil
}

// IssueCertificate issues a new certificate
func (s *CertificateManagerServer) IssueCertificate(ctx context.Context, req *IssueCertificateRequest) (*IssueCertificateResponse, error) {
	atomic.AddInt64(&s.metrics.TotalRequests, 1)
	atomic.AddInt64(&s.metrics.IssueCertCalls, 1)

	// Validate request
	if len(req.Domains) == 0 {
		atomic.AddInt64(&s.metrics.FailedRequests, 1)
		return nil, newError(CodeInvalidArg, "at least one domain is required")
	}

	// Issue certificate
	cert, err := s.certManager.IssueCertificate(ctx, req.Domains)
	if err != nil {
		atomic.AddInt64(&s.metrics.FailedRequests, 1)
		return &IssueCertificateResponse{
			Success: false,
			Domain:  req.Domains[0],
			Error:   err.Error(),
		}, nil
	}

	atomic.AddInt64(&s.metrics.SuccessfulRequests, 1)

	// Trigger distribution
	var distributedTo []string
	if s.distributor != nil {
		if err := s.distributor.DistributeCertificate(ctx, cert.CommonName); err == nil {
			services := s.distributor.findServicesForDomain(cert.CommonName)
			for _, svc := range services {
				distributedTo = append(distributedTo, svc.Endpoint.Name)
			}
		}
	}

	return &IssueCertificateResponse{
		Success:       true,
		Domain:        cert.CommonName,
		SerialNumber:  cert.SerialNumber,
		NotAfter:      cert.NotAfter,
		DistributedTo: distributedTo,
	}, nil
}

// RenewCertificate manually renews a certificate
func (s *CertificateManagerServer) RenewCertificate(ctx context.Context, req *RenewCertificateRequest) (*RenewCertificateResponse, error) {
	atomic.AddInt64(&s.metrics.TotalRequests, 1)
	atomic.AddInt64(&s.metrics.RenewCertCalls, 1)

	// Validate request
	if req.Domain == "" {
		atomic.AddInt64(&s.metrics.FailedRequests, 1)
		return nil, newError(CodeInvalidArg, "domain is required")
	}

	// Get existing certificate for old expiry
	oldCert, err := s.certManager.GetCertificate(ctx, req.Domain)
	if err != nil {
		atomic.AddInt64(&s.metrics.FailedRequests, 1)
		return nil, newError(CodeNotFound, "certificate not found for domain: "+req.Domain)
	}

	// Trigger renewal
	var newCert *types.Certificate
	if s.renewalScheduler != nil {
		result, err := s.renewalScheduler.RenewNow(ctx, req.Domain)
		if err != nil || !result.Success {
			errMsg := "renewal failed"
			if err != nil {
				errMsg = err.Error()
			} else if result.Error != "" {
				errMsg = result.Error
			}
			atomic.AddInt64(&s.metrics.FailedRequests, 1)
			return &RenewCertificateResponse{
				Success:   false,
				Domain:    req.Domain,
				OldExpiry: oldCert.NotAfter,
				Error:     errMsg,
			}, nil
		}
		// Get new certificate
		newCert, _ = s.certManager.GetCertificate(ctx, req.Domain)
	} else {
		// Direct issuance if no scheduler
		domains := []string{req.Domain}
		domains = append(domains, oldCert.SubjectAltNames...)
		newCert, err = s.certManager.IssueCertificate(ctx, domains)
		if err != nil {
			atomic.AddInt64(&s.metrics.FailedRequests, 1)
			return &RenewCertificateResponse{
				Success:   false,
				Domain:    req.Domain,
				OldExpiry: oldCert.NotAfter,
				Error:     err.Error(),
			}, nil
		}
	}

	atomic.AddInt64(&s.metrics.SuccessfulRequests, 1)

	// Trigger distribution
	var distributedTo []string
	if s.distributor != nil && newCert != nil {
		if err := s.distributor.DistributeCertificate(ctx, newCert.CommonName); err == nil {
			services := s.distributor.findServicesForDomain(newCert.CommonName)
			for _, svc := range services {
				distributedTo = append(distributedTo, svc.Endpoint.Name)
			}
		}
	}

	newExpiry := oldCert.NotAfter
	if newCert != nil {
		newExpiry = newCert.NotAfter
	}

	return &RenewCertificateResponse{
		Success:       true,
		Domain:        req.Domain,
		OldExpiry:     oldCert.NotAfter,
		NewExpiry:     newExpiry,
		DistributedTo: distributedTo,
	}, nil
}

// DeleteCertificate removes a certificate
func (s *CertificateManagerServer) DeleteCertificate(ctx context.Context, req *DeleteCertificateRequest) (*DeleteCertificateResponse, error) {
	atomic.AddInt64(&s.metrics.TotalRequests, 1)
	atomic.AddInt64(&s.metrics.DeleteCertCalls, 1)

	// Validate request
	if req.Domain == "" && req.CertID == 0 {
		atomic.AddInt64(&s.metrics.FailedRequests, 1)
		return nil, newError(CodeInvalidArg, "domain or cert_id is required")
	}

	if !req.Confirm {
		atomic.AddInt64(&s.metrics.FailedRequests, 1)
		return nil, newError(CodeInvalidArg, "confirmation required for deletion")
	}

	// Get certificate ID if only domain provided
	certID := req.CertID
	domain := req.Domain
	if certID == 0 {
		cert, err := s.certManager.GetCertificate(ctx, domain)
		if err != nil {
			atomic.AddInt64(&s.metrics.FailedRequests, 1)
			return nil, newError(CodeNotFound, "certificate not found")
		}
		certID = cert.ID
		domain = cert.CommonName
	}

	// Delete certificate
	if err := s.certManager.DeleteCertificate(ctx, certID, domain); err != nil {
		atomic.AddInt64(&s.metrics.FailedRequests, 1)
		return nil, newError(CodeInternal, err.Error())
	}

	atomic.AddInt64(&s.metrics.SuccessfulRequests, 1)

	return &DeleteCertificateResponse{
		Success: true,
		Domain:  domain,
		Message: "certificate deleted successfully",
	}, nil
}

// ListCertificates returns certificate inventory
func (s *CertificateManagerServer) ListCertificates(ctx context.Context, req *ListCertificatesRequest) (*ListCertificatesResponse, error) {
	atomic.AddInt64(&s.metrics.TotalRequests, 1)
	atomic.AddInt64(&s.metrics.ListCertCalls, 1)

	// Build options
	opts := ca.CertificateListOptions{
		Domain:     req.DomainFilter,
		Status:     types.CertificateStatus(req.Status),
		ExpiringIn: req.ExpiringIn,
		OrderBy:    req.SortBy,
		OrderDesc:  req.SortDesc,
	}

	if req.PageSize > 0 {
		opts.Limit = req.PageSize
	} else {
		opts.Limit = 100 // Default page size
	}

	// Get certificates
	summaries, err := s.certManager.ListCertificates(ctx, opts)
	if err != nil {
		atomic.AddInt64(&s.metrics.FailedRequests, 1)
		return nil, newError(CodeInternal, err.Error())
	}

	atomic.AddInt64(&s.metrics.SuccessfulRequests, 1)

	// Convert to response format
	certs := make([]CertificateSummary, len(summaries))
	for i, s := range summaries {
		certs[i] = CertificateSummary{
			ID:            s.ID,
			Domain:        s.CommonName,
			SANs:          s.SANs,
			Status:        string(s.Status),
			Issuer:        s.Issuer,
			NotAfter:      s.NotAfter,
			DaysRemaining: s.DaysRemaining,
		}
	}

	return &ListCertificatesResponse{
		Certificates: certs,
		TotalCount:   len(certs),
	}, nil
}

// ============================================================================
// Status Endpoints
// ============================================================================

// GetRenewalStatus returns renewal scheduler status
func (s *CertificateManagerServer) GetRenewalStatus(ctx context.Context, _ *RenewalStatusRequest) (*RenewalStatusResponse, error) {
	atomic.AddInt64(&s.metrics.TotalRequests, 1)

	if s.renewalScheduler == nil {
		return &RenewalStatusResponse{
			Enabled: false,
			Running: false,
		}, nil
	}

	status, err := s.renewalScheduler.GetRenewalStatus(ctx)
	if err != nil {
		return nil, newError(CodeInternal, err.Error())
	}

	atomic.AddInt64(&s.metrics.SuccessfulRequests, 1)

	return &RenewalStatusResponse{
		Enabled:             true,
		Running:             status.Running,
		LastCheckTime:       status.Metrics.LastCheckTime,
		NextCheckTime:       status.Metrics.NextCheckTime,
		CertificatesManaged: int(status.Metrics.TotalManaged),
		RenewalsAttempted:   status.Metrics.RenewalsAttempted,
		RenewalsSucceeded:   status.Metrics.RenewalsSucceeded,
		RenewalsFailed:      status.Metrics.RenewalsFailed,
	}, nil
}

// GetDistributionStatus returns distribution system status
func (s *CertificateManagerServer) GetDistributionStatus(_ context.Context, _ *DistributionStatusRequest) (*DistributionStatusResponse, error) {
	atomic.AddInt64(&s.metrics.TotalRequests, 1)

	if s.distributor == nil {
		return &DistributionStatusResponse{
			Running: false,
		}, nil
	}

	status := s.distributor.GetStatus()

	atomic.AddInt64(&s.metrics.SuccessfulRequests, 1)

	// Convert service summaries
	services := make([]ServiceStatusSummary, len(status.Services))
	for i, svc := range status.Services {
		services[i] = ServiceStatusSummary{
			Name:        svc.Name,
			Type:        svc.Type,
			Status:      svc.Status,
			LastPush:    svc.LastPush,
			SuccessRate: svc.SuccessRate,
		}
	}

	// Calculate success rate
	successRate := 0.0
	metrics := status.Metrics
	if metrics != nil {
		total := metrics.SuccessCount + metrics.FailureCount
		if total > 0 {
			successRate = float64(metrics.SuccessCount) / float64(total) * 100
		}
	}

	return &DistributionStatusResponse{
		Running:            status.Running,
		RegisteredServices: status.RegisteredServices,
		HealthyServices:    status.HealthyServices,
		PendingQueue:       status.PendingQueue,
		TotalDistributions: metrics.TotalDistributions,
		SuccessRate:        successRate,
		Services:           services,
	}, nil
}

// ============================================================================
// Health Check
// ============================================================================

// HealthCheck returns service health status
func (s *CertificateManagerServer) HealthCheck(ctx context.Context, _ *HealthCheckRequest) (*HealthCheckResponse, error) {
	atomic.AddInt64(&s.metrics.TotalRequests, 1)
	atomic.AddInt64(&s.metrics.HealthCheckCalls, 1)

	components := make(map[string]string)
	allHealthy := true

	// Check certificate manager
	if s.certManager != nil {
		components["certificate_manager"] = "SERVING"
	} else {
		components["certificate_manager"] = "NOT_SERVING"
		allHealthy = false
	}

	// Check renewal scheduler
	if s.renewalScheduler != nil && s.renewalScheduler.IsRunning() {
		components["renewal_scheduler"] = "SERVING"
	} else if s.renewalScheduler != nil {
		components["renewal_scheduler"] = "STOPPED"
	} else {
		components["renewal_scheduler"] = "NOT_CONFIGURED"
	}

	// Check distributor
	if s.distributor != nil {
		components["distributor"] = "SERVING"
	} else {
		components["distributor"] = "NOT_CONFIGURED"
	}

	// Check watcher
	if s.watcher != nil && s.watcher.IsRunning() {
		components["watcher"] = "SERVING"
	} else if s.watcher != nil {
		components["watcher"] = "STOPPED"
	} else {
		components["watcher"] = "NOT_CONFIGURED"
	}

	atomic.AddInt64(&s.metrics.SuccessfulRequests, 1)

	status := "SERVING"
	if !allHealthy {
		status = "DEGRADED"
	}

	return &HealthCheckResponse{
		Status:     status,
		Components: components,
	}, nil
}

// ============================================================================
// Streaming (Change Notifications)
// ============================================================================

// SubscribeToChanges registers for certificate change notifications
func (s *CertificateManagerServer) SubscribeToChanges(subscriberID string) (<-chan *CertificateChangeEvent, func()) {
	s.subscribersMu.Lock()
	defer s.subscribersMu.Unlock()

	ch := make(chan *CertificateChangeEvent, 100)
	s.subscribers[subscriberID] = ch
	atomic.AddInt64(&s.metrics.ActiveStreams, 1)

	// Return channel and unsubscribe function
	unsubscribe := func() {
		s.subscribersMu.Lock()
		defer s.subscribersMu.Unlock()
		if existingCh, exists := s.subscribers[subscriberID]; exists {
			close(existingCh)
			delete(s.subscribers, subscriberID)
			atomic.AddInt64(&s.metrics.ActiveStreams, -1)
		}
	}

	return ch, unsubscribe
}

// NotifyChange broadcasts a certificate change to all subscribers
func (s *CertificateManagerServer) NotifyChange(event *CertificateChangeEvent) {
	s.subscribersMu.RLock()
	defer s.subscribersMu.RUnlock()

	for _, ch := range s.subscribers {
		select {
		case ch <- event:
		default:
			// Channel full, skip
		}
	}
}

// ============================================================================
// Server Lifecycle
// ============================================================================

// Serve starts the gRPC server
func (s *CertificateManagerServer) Serve() error {
	if s.running.Load() {
		return ErrServerAlreadyRunning
	}

	// Create listener
	addr := formatAddr(s.config.Port)
	listener, err := net.Listen("tcp", addr)
	if err != nil {
		return err
	}
	s.listener = listener

	s.running.Store(true)
	s.stopChan = make(chan struct{})
	s.doneChan = make(chan struct{})

	// In production, this would use actual gRPC server
	// For now, just mark as running
	go func() {
		defer close(s.doneChan)
		<-s.stopChan
	}()

	return nil
}

// GracefulShutdown stops the server gracefully
func (s *CertificateManagerServer) GracefulShutdown() error {
	if !s.running.Load() {
		return ErrServerNotRunning
	}

	// Signal stop
	close(s.stopChan)

	// Wait with timeout
	select {
	case <-s.doneChan:
	case <-time.After(s.config.GracefulShutdownTimeout):
		// Force shutdown
	}

	// Close listener
	if s.listener != nil {
		s.listener.Close()
	}

	// Close all subscriber channels
	s.subscribersMu.Lock()
	for id, ch := range s.subscribers {
		close(ch)
		delete(s.subscribers, id)
	}
	s.subscribersMu.Unlock()

	s.running.Store(false)
	return nil
}

// IsRunning returns server state
func (s *CertificateManagerServer) IsRunning() bool {
	return s.running.Load()
}

// GetMetrics returns server metrics
func (s *CertificateManagerServer) GetMetrics() *ServerMetrics {
	return &ServerMetrics{
		TotalRequests:      atomic.LoadInt64(&s.metrics.TotalRequests),
		SuccessfulRequests: atomic.LoadInt64(&s.metrics.SuccessfulRequests),
		FailedRequests:     atomic.LoadInt64(&s.metrics.FailedRequests),
		ActiveStreams:      atomic.LoadInt64(&s.metrics.ActiveStreams),
		GetCertCalls:       atomic.LoadInt64(&s.metrics.GetCertCalls),
		IssueCertCalls:     atomic.LoadInt64(&s.metrics.IssueCertCalls),
		RenewCertCalls:     atomic.LoadInt64(&s.metrics.RenewCertCalls),
		DeleteCertCalls:    atomic.LoadInt64(&s.metrics.DeleteCertCalls),
		ListCertCalls:      atomic.LoadInt64(&s.metrics.ListCertCalls),
		HealthCheckCalls:   atomic.LoadInt64(&s.metrics.HealthCheckCalls),
	}
}

// ============================================================================
// Helper Functions
// ============================================================================

// GRPCError represents a gRPC-style error
type GRPCError struct {
	Code    int
	Message string
}

func (e *GRPCError) Error() string {
	return e.Message
}

// newError creates a new gRPC-style error
func newError(code int, message string) error {
	return &GRPCError{Code: code, Message: message}
}

// formatAddr formats address with port
func formatAddr(port int) string {
	return ":" + itoa(port)
}

// itoa converts int to string
func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var buf [20]byte
	i := len(buf)
	neg := n < 0
	if neg {
		n = -n
	}
	for n > 0 {
		i--
		buf[i] = byte('0' + n%10)
		n /= 10
	}
	if neg {
		i--
		buf[i] = '-'
	}
	return string(buf[i:])
}
