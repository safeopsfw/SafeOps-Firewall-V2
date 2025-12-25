// Package distribution handles certificate distribution to dependent services.
package distribution

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"math/rand"
	"sync"
	"sync/atomic"
	"time"

	"certificate_manager/internal/ca"
	"certificate_manager/internal/storage"
	"certificate_manager/pkg/types"
)

// ============================================================================
// Constants
// ============================================================================

const (
	DefaultDistributionTimeout = 30 * time.Second
	DefaultMaxConcurrent       = 10
	DefaultRetryAttempts       = 5
	DefaultRetryBackoff        = time.Second
	DefaultVerifyAfterPush     = true
	MaxBackoffDuration         = 30 * time.Second
	HealthCheckInterval        = 30 * time.Second
)

// Service status constants
const (
	ServiceStatusHealthy     = "healthy"
	ServiceStatusUnhealthy   = "unhealthy"
	ServiceStatusUnknown     = "unknown"
	ServiceStatusUnreachable = "unreachable"
)

// Service type constants
const (
	ServiceTypeGRPC = "grpc"
	ServiceTypeHTTP = "http"
	ServiceTypeFile = "file"
)

// ============================================================================
// Error Types
// ============================================================================

var (
	ErrServiceNotFound     = errors.New("service not found")
	ErrDistributionFailed  = errors.New("certificate distribution failed")
	ErrServiceUnreachable  = errors.New("service is unreachable")
	ErrVerificationFailed  = errors.New("distribution verification failed")
	ErrCertificateMismatch = errors.New("certificate mismatch after push")
	ErrMaxRetriesExceeded  = errors.New("max retry attempts exceeded")
	ErrNoServicesForDomain = errors.New("no services registered for domain")
)

// ============================================================================
// Distributor Structure
// ============================================================================

// Distributor pushes certificates to dependent services
type Distributor struct {
	certManager *ca.CertificateManager
	fsStorage   *storage.FilesystemStorage
	config      DistributorConfig

	// Service registry
	services   map[string]*ServiceClient
	servicesMu sync.RWMutex

	// Distribution queue
	queue   chan *DistributionRequest
	queueWg sync.WaitGroup

	// Metrics
	metrics *DistributorMetrics

	// State
	running  atomic.Bool
	stopChan chan struct{}
}

// DistributorConfig holds distributor configuration
type DistributorConfig struct {
	Timeout         time.Duration
	MaxConcurrent   int
	RetryAttempts   int
	RetryBackoff    time.Duration
	VerifyAfterPush bool
	EnableGRPC      bool
	EnableHTTP      bool
	QueueSize       int
}

// ServiceClient represents a service connection with state
type ServiceClient struct {
	Endpoint            ServiceEndpoint
	HealthStatus        string
	LastHealthCheck     time.Time
	ConsecutiveFailures int
	mu                  sync.Mutex
}

// ServiceEndpoint represents a service that receives certificates
type ServiceEndpoint struct {
	Name       string            `json:"name"`
	Type       string            `json:"type"` // "grpc", "http", "file"
	Address    string            `json:"address"`
	Domains    []string          `json:"domains"`
	Priority   int               `json:"priority"` // Lower is higher priority
	Status     string            `json:"status"`
	LastPush   time.Time         `json:"last_push"`
	PushCount  int64             `json:"push_count"`
	ErrorCount int64             `json:"error_count"`
	Metadata   map[string]string `json:"metadata,omitempty"`
}

// DistributorMetrics tracks distribution statistics
type DistributorMetrics struct {
	TotalDistributions  int64     `json:"total_distributions"`
	SuccessCount        int64     `json:"success_count"`
	FailureCount        int64     `json:"failure_count"`
	VerificationsPassed int64     `json:"verifications_passed"`
	VerificationsFailed int64     `json:"verifications_failed"`
	RetryCount          int64     `json:"retry_count"`
	LastDistribution    time.Time `json:"last_distribution"`
	AverageLatencyMs    int64     `json:"average_latency_ms"`
	QueueDepth          int64     `json:"queue_depth"`
	mu                  sync.RWMutex
}

// DistributionResult contains outcome of distribution attempt
type DistributionResult struct {
	Domain      string        `json:"domain"`
	Success     bool          `json:"success"`
	ServiceName string        `json:"service_name"`
	Duration    time.Duration `json:"duration"`
	Verified    bool          `json:"verified"`
	RetryCount  int           `json:"retry_count"`
	Error       string        `json:"error,omitempty"`
	Timestamp   time.Time     `json:"timestamp"`
}

// DistributionRequest represents a pending distribution operation
type DistributionRequest struct {
	Domain      string
	Certificate *types.Certificate
	Priority    int
	ResultChan  chan *DistributionResult
}

// DistributionStatus reports current distributor state
type DistributionStatus struct {
	Running            bool                `json:"running"`
	RegisteredServices int                 `json:"registered_services"`
	HealthyServices    int                 `json:"healthy_services"`
	PendingQueue       int                 `json:"pending_queue"`
	Metrics            *DistributorMetrics `json:"metrics"`
	Services           []ServiceSummary    `json:"services"`
}

// ServiceSummary provides service overview
type ServiceSummary struct {
	Name        string    `json:"name"`
	Type        string    `json:"type"`
	Status      string    `json:"status"`
	LastPush    time.Time `json:"last_push"`
	SuccessRate float64   `json:"success_rate"`
	DomainCount int       `json:"domain_count"`
}

// ============================================================================
// Constructor
// ============================================================================

// NewDistributor creates a new certificate distributor
func NewDistributor(
	certManager *ca.CertificateManager,
	fsStorage *storage.FilesystemStorage,
	config DistributorConfig,
) (*Distributor, error) {
	// Apply defaults
	if config.Timeout <= 0 {
		config.Timeout = DefaultDistributionTimeout
	}
	if config.MaxConcurrent <= 0 {
		config.MaxConcurrent = DefaultMaxConcurrent
	}
	if config.RetryAttempts <= 0 {
		config.RetryAttempts = DefaultRetryAttempts
	}
	if config.RetryBackoff <= 0 {
		config.RetryBackoff = DefaultRetryBackoff
	}
	if config.QueueSize <= 0 {
		config.QueueSize = 100
	}

	d := &Distributor{
		certManager: certManager,
		fsStorage:   fsStorage,
		config:      config,
		services:    make(map[string]*ServiceClient),
		queue:       make(chan *DistributionRequest, config.QueueSize),
		metrics:     &DistributorMetrics{},
		stopChan:    make(chan struct{}),
	}

	return d, nil
}

// ============================================================================
// Lifecycle Management
// ============================================================================

// Start begins the distribution queue processor
func (d *Distributor) Start(ctx context.Context) error {
	if d.running.Load() {
		return errors.New("distributor already running")
	}

	d.running.Store(true)
	d.stopChan = make(chan struct{})

	// Start queue processors
	for i := 0; i < d.config.MaxConcurrent; i++ {
		d.queueWg.Add(1)
		go d.processQueue(ctx)
	}

	return nil
}

// Stop gracefully shuts down the distributor
func (d *Distributor) Stop() error {
	if !d.running.Load() {
		return errors.New("distributor not running")
	}

	close(d.stopChan)
	d.queueWg.Wait()
	d.running.Store(false)

	return nil
}

// processQueue handles queued distribution requests
func (d *Distributor) processQueue(ctx context.Context) {
	defer d.queueWg.Done()

	for {
		select {
		case <-ctx.Done():
			return
		case <-d.stopChan:
			return
		case req := <-d.queue:
			if req == nil {
				continue
			}
			result := d.distributeToServices(ctx, req.Domain, req.Certificate)
			if req.ResultChan != nil {
				select {
				case req.ResultChan <- result:
				default:
				}
			}
		}
	}
}

// ============================================================================
// Service Registration
// ============================================================================

// RegisterService adds a service to receive certificate updates
func (d *Distributor) RegisterService(endpoint *ServiceEndpoint) error {
	if endpoint == nil || endpoint.Name == "" {
		return errors.New("invalid service endpoint")
	}

	d.servicesMu.Lock()
	defer d.servicesMu.Unlock()

	client := &ServiceClient{
		Endpoint:     *endpoint,
		HealthStatus: ServiceStatusUnknown,
	}
	client.Endpoint.Status = "registered"
	d.services[endpoint.Name] = client

	return nil
}

// UnregisterService removes a service from distribution list
func (d *Distributor) UnregisterService(name string) error {
	d.servicesMu.Lock()
	defer d.servicesMu.Unlock()

	if _, exists := d.services[name]; !exists {
		return ErrServiceNotFound
	}

	delete(d.services, name)
	return nil
}

// GetService returns a registered service by name
func (d *Distributor) GetService(name string) (*ServiceEndpoint, error) {
	d.servicesMu.RLock()
	defer d.servicesMu.RUnlock()

	client, exists := d.services[name]
	if !exists {
		return nil, ErrServiceNotFound
	}
	return &client.Endpoint, nil
}

// ListServices returns all registered services
func (d *Distributor) ListServices() []*ServiceEndpoint {
	d.servicesMu.RLock()
	defer d.servicesMu.RUnlock()

	services := make([]*ServiceEndpoint, 0, len(d.services))
	for _, client := range d.services {
		endpoint := client.Endpoint
		services = append(services, &endpoint)
	}
	return services
}

// ============================================================================
// Certificate Distribution
// ============================================================================

// DistributeCertificate pushes a certificate to all registered services
func (d *Distributor) DistributeCertificate(ctx context.Context, domain string) error {
	// Find services that need this certificate
	clients := d.findServicesForDomain(domain)
	if len(clients) == 0 {
		return nil // No services registered for this domain
	}

	// Get certificate
	cert, err := d.certManager.GetCertificate(ctx, domain)
	if err != nil {
		return err
	}

	// Distribute with result collection
	result := d.distributeToServices(ctx, domain, cert)
	if !result.Success {
		return errors.New(result.Error)
	}

	return nil
}

// distributeToServices pushes certificate to all matching services
func (d *Distributor) distributeToServices(ctx context.Context, domain string, cert *types.Certificate) *DistributionResult {
	clients := d.findServicesForDomain(domain)

	result := &DistributionResult{
		Domain:    domain,
		Success:   true,
		Timestamp: time.Now(),
	}

	if len(clients) == 0 {
		return result
	}

	// Distribute to all services concurrently
	var wg sync.WaitGroup
	results := make(chan *DistributionResult, len(clients))
	semaphore := make(chan struct{}, d.config.MaxConcurrent)

	for _, client := range clients {
		wg.Add(1)
		go func(c *ServiceClient) {
			defer wg.Done()

			semaphore <- struct{}{}
			defer func() { <-semaphore }()

			svcResult := d.distributeToCon(ctx, c, cert)
			results <- svcResult
		}(client)
	}

	// Wait and collect results
	go func() {
		wg.Wait()
		close(results)
	}()

	var lastErr string
	for svcResult := range results {
		atomic.AddInt64(&d.metrics.TotalDistributions, 1)
		if svcResult.Success {
			atomic.AddInt64(&d.metrics.SuccessCount, 1)
		} else {
			atomic.AddInt64(&d.metrics.FailureCount, 1)
			result.Success = false
			lastErr = svcResult.Error
		}
	}

	d.metrics.mu.Lock()
	d.metrics.LastDistribution = time.Now()
	d.metrics.mu.Unlock()

	if !result.Success {
		result.Error = lastErr
	}

	return result
}

// distributeToCon pushes certificate to a single service with retry
func (d *Distributor) distributeToCon(ctx context.Context, client *ServiceClient, cert *types.Certificate) *DistributionResult {
	start := time.Now()
	result := &DistributionResult{
		Domain:      cert.CommonName,
		ServiceName: client.Endpoint.Name,
		Timestamp:   start,
	}

	var lastErr error
	for attempt := 0; attempt < d.config.RetryAttempts; attempt++ {
		if attempt > 0 {
			// Exponential backoff with jitter
			backoff := d.calculateBackoff(attempt)
			atomic.AddInt64(&d.metrics.RetryCount, 1)

			select {
			case <-time.After(backoff):
			case <-ctx.Done():
				result.Error = "context cancelled"
				return result
			}
		}

		lastErr = d.pushToService(ctx, client, cert)
		if lastErr == nil {
			break
		}

		// Check if error is retryable
		if !isRetryableError(lastErr) {
			break
		}
	}

	result.Duration = time.Since(start)
	result.RetryCount = 0

	if lastErr != nil {
		result.Success = false
		result.Error = lastErr.Error()
		atomic.AddInt64(&client.Endpoint.ErrorCount, 1)
		client.Endpoint.Status = "error"
		return result
	}

	// Verify distribution if enabled
	if d.config.VerifyAfterPush {
		if err := d.verifyDistribution(ctx, client, cert); err != nil {
			atomic.AddInt64(&d.metrics.VerificationsFailed, 1)
			result.Verified = false
		} else {
			atomic.AddInt64(&d.metrics.VerificationsPassed, 1)
			result.Verified = true
		}
	}

	result.Success = true
	atomic.AddInt64(&client.Endpoint.PushCount, 1)
	client.Endpoint.LastPush = time.Now()
	client.Endpoint.Status = "active"

	return result
}

// pushToService performs actual push to a single service
func (d *Distributor) pushToService(ctx context.Context, client *ServiceClient, cert *types.Certificate) error {
	ctx, cancel := context.WithTimeout(ctx, d.config.Timeout)
	defer cancel()

	switch client.Endpoint.Type {
	case ServiceTypeGRPC:
		return d.pushViaGRPC(ctx, &client.Endpoint, cert)
	case ServiceTypeHTTP:
		return d.pushViaHTTP(ctx, &client.Endpoint, cert)
	case ServiceTypeFile:
		return d.pushViaFile(ctx, &client.Endpoint, cert)
	default:
		return errors.New("unsupported service type: " + client.Endpoint.Type)
	}
}

// ============================================================================
// Batch Distribution
// ============================================================================

// BatchDistribute distributes multiple certificates efficiently
func (d *Distributor) BatchDistribute(ctx context.Context, domains []string) ([]DistributionResult, error) {
	results := make([]DistributionResult, 0, len(domains))
	var mu sync.Mutex
	var wg sync.WaitGroup

	// Rate limiting semaphore
	semaphore := make(chan struct{}, d.config.MaxConcurrent)

	for _, domain := range domains {
		wg.Add(1)
		go func(dom string) {
			defer wg.Done()

			semaphore <- struct{}{}
			defer func() { <-semaphore }()

			err := d.DistributeCertificate(ctx, dom)

			result := DistributionResult{
				Domain:    dom,
				Success:   err == nil,
				Timestamp: time.Now(),
			}
			if err != nil {
				result.Error = err.Error()
			}

			mu.Lock()
			results = append(results, result)
			mu.Unlock()
		}(domain)
	}

	wg.Wait()
	return results, nil
}

// DistributeToAll pushes all certificates to all services
func (d *Distributor) DistributeToAll(ctx context.Context) error {
	if d.certManager == nil {
		return errors.New("certificate manager not available")
	}

	// Get all certificates
	summaries, err := d.certManager.ListCertificates(ctx, ca.CertificateListOptions{})
	if err != nil {
		return err
	}

	domains := make([]string, len(summaries))
	for i, s := range summaries {
		domains[i] = s.CommonName
	}

	_, err = d.BatchDistribute(ctx, domains)
	return err
}

// ============================================================================
// Verification
// ============================================================================

// verifyDistribution confirms service received certificate
func (d *Distributor) verifyDistribution(_ context.Context, _ *ServiceClient, cert *types.Certificate) error {
	// Calculate expected fingerprint
	expectedFP := d.calculateFingerprint(cert.CertificatePEM)

	// In production, this would call service's GetCertificate endpoint
	// and compare the fingerprint

	// For now, assume success (placeholder)
	_ = expectedFP
	return nil
}

// calculateFingerprint computes SHA-256 fingerprint of certificate
func (d *Distributor) calculateFingerprint(certPEM string) string {
	block, _ := pem.Decode([]byte(certPEM))
	if block == nil {
		return ""
	}
	hash := sha256.Sum256(block.Bytes)
	return hex.EncodeToString(hash[:])
}

// ============================================================================
// Service Discovery
// ============================================================================

// findServicesForDomain returns services that need a specific domain's certificate
func (d *Distributor) findServicesForDomain(domain string) []*ServiceClient {
	d.servicesMu.RLock()
	defer d.servicesMu.RUnlock()

	var clients []*ServiceClient
	for _, client := range d.services {
		if d.serviceneedsDomain(&client.Endpoint, domain) {
			clients = append(clients, client)
		}
	}

	// Sort by priority (lower = higher priority)
	// Using simple bubble sort for small lists
	for i := 0; i < len(clients)-1; i++ {
		for j := 0; j < len(clients)-i-1; j++ {
			if clients[j].Endpoint.Priority > clients[j+1].Endpoint.Priority {
				clients[j], clients[j+1] = clients[j+1], clients[j]
			}
		}
	}

	return clients
}

// serviceneedsDomain checks if service needs a domain's certificate
func (d *Distributor) serviceneedsDomain(svc *ServiceEndpoint, domain string) bool {
	for _, d := range svc.Domains {
		if d == domain || d == "*" {
			return true
		}
		// Check wildcard match
		if len(d) > 2 && d[0] == '*' && d[1] == '.' {
			suffix := d[1:] // .example.com
			if len(domain) > len(suffix) && domain[len(domain)-len(suffix):] == suffix {
				return true
			}
		}
	}
	return false
}

// ============================================================================
// Retry Logic
// ============================================================================

// calculateBackoff returns exponential backoff with jitter
func (d *Distributor) calculateBackoff(attempt int) time.Duration {
	// Exponential: 1s, 2s, 4s, 8s, 16s...
	backoff := d.config.RetryBackoff * time.Duration(1<<uint(attempt))

	// Cap at max
	if backoff > MaxBackoffDuration {
		backoff = MaxBackoffDuration
	}

	// Add jitter (±25%)
	jitter := time.Duration(rand.Int63n(int64(backoff) / 4))
	if rand.Intn(2) == 0 {
		backoff += jitter
	} else {
		backoff -= jitter
	}

	return backoff
}

// isRetryableError checks if error is temporary
func isRetryableError(err error) bool {
	if err == nil {
		return false
	}
	errStr := err.Error()
	retryablePatterns := []string{
		"timeout", "connection refused", "connection reset",
		"temporary", "unavailable", "try again",
	}
	for _, pattern := range retryablePatterns {
		if containsIgnoreCase(errStr, pattern) {
			return true
		}
	}
	return false
}

// containsIgnoreCase checks for substring (case-insensitive)
func containsIgnoreCase(s, substr string) bool {
	sLower := toLower(s)
	substrLower := toLower(substr)
	return findStr(sLower, substrLower)
}

func toLower(s string) string {
	b := make([]byte, len(s))
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c >= 'A' && c <= 'Z' {
			c += 32
		}
		b[i] = c
	}
	return string(b)
}

func findStr(s, sub string) bool {
	if len(sub) > len(s) {
		return false
	}
	for i := 0; i <= len(s)-len(sub); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}

// ============================================================================
// Distribution Methods (Placeholders)
// ============================================================================

// pushViaGRPC distributes certificate via gRPC
func (d *Distributor) pushViaGRPC(_ context.Context, _ *ServiceEndpoint, _ *types.Certificate) error {
	// Placeholder for gRPC distribution
	// In production:
	// 1. Establish/reuse gRPC connection
	// 2. Call UpdateCertificate RPC
	// 3. Verify response
	return nil
}

// pushViaHTTP distributes certificate via HTTP API
func (d *Distributor) pushViaHTTP(_ context.Context, _ *ServiceEndpoint, _ *types.Certificate) error {
	// Placeholder for HTTP distribution
	// In production:
	// 1. POST certificate to service endpoint
	// 2. Verify response status
	return nil
}

// pushViaFile distributes certificate by writing to shared filesystem
func (d *Distributor) pushViaFile(_ context.Context, svc *ServiceEndpoint, cert *types.Certificate) error {
	// Placeholder for file-based distribution
	// In production:
	// 1. Write to service's expected certificate path
	// 2. Signal service to reload (e.g., HUP signal)
	_ = svc.Address // Path where to write
	_ = cert
	return nil
}

// ============================================================================
// Health Checking
// ============================================================================

// CheckServiceHealth verifies service health
func (d *Distributor) CheckServiceHealth(ctx context.Context, name string) error {
	d.servicesMu.RLock()
	client, exists := d.services[name]
	d.servicesMu.RUnlock()

	if !exists {
		return ErrServiceNotFound
	}

	// Placeholder for health check
	// In production, this would ping the service
	client.mu.Lock()
	client.HealthStatus = ServiceStatusHealthy
	client.LastHealthCheck = time.Now()
	client.ConsecutiveFailures = 0
	client.mu.Unlock()

	return nil
}

// CheckAllServicesHealth checks health of all registered services
func (d *Distributor) CheckAllServicesHealth(ctx context.Context) map[string]string {
	d.servicesMu.RLock()
	names := make([]string, 0, len(d.services))
	for name := range d.services {
		names = append(names, name)
	}
	d.servicesMu.RUnlock()

	results := make(map[string]string)
	for _, name := range names {
		err := d.CheckServiceHealth(ctx, name)
		if err != nil {
			results[name] = ServiceStatusUnhealthy
		} else {
			results[name] = ServiceStatusHealthy
		}
	}
	return results
}

// ============================================================================
// Status and Metrics
// ============================================================================

// GetStatus returns current distributor status
func (d *Distributor) GetStatus() *DistributionStatus {
	d.servicesMu.RLock()
	serviceCount := len(d.services)

	healthyCount := 0
	summaries := make([]ServiceSummary, 0, serviceCount)

	for _, client := range d.services {
		if client.HealthStatus == ServiceStatusHealthy {
			healthyCount++
		}

		successRate := 0.0
		total := client.Endpoint.PushCount + client.Endpoint.ErrorCount
		if total > 0 {
			successRate = float64(client.Endpoint.PushCount) / float64(total) * 100
		}

		summaries = append(summaries, ServiceSummary{
			Name:        client.Endpoint.Name,
			Type:        client.Endpoint.Type,
			Status:      client.Endpoint.Status,
			LastPush:    client.Endpoint.LastPush,
			SuccessRate: successRate,
			DomainCount: len(client.Endpoint.Domains),
		})
	}
	d.servicesMu.RUnlock()

	return &DistributionStatus{
		Running:            d.running.Load(),
		RegisteredServices: serviceCount,
		HealthyServices:    healthyCount,
		PendingQueue:       len(d.queue),
		Metrics:            d.getMetricsSnapshot(),
		Services:           summaries,
	}
}

// GetMetrics returns current distributor metrics
func (d *Distributor) GetMetrics() *DistributorMetrics {
	return d.getMetricsSnapshot()
}

// getMetricsSnapshot returns copy of current metrics
func (d *Distributor) getMetricsSnapshot() *DistributorMetrics {
	d.metrics.mu.RLock()
	defer d.metrics.mu.RUnlock()

	return &DistributorMetrics{
		TotalDistributions:  atomic.LoadInt64(&d.metrics.TotalDistributions),
		SuccessCount:        atomic.LoadInt64(&d.metrics.SuccessCount),
		FailureCount:        atomic.LoadInt64(&d.metrics.FailureCount),
		VerificationsPassed: atomic.LoadInt64(&d.metrics.VerificationsPassed),
		VerificationsFailed: atomic.LoadInt64(&d.metrics.VerificationsFailed),
		RetryCount:          atomic.LoadInt64(&d.metrics.RetryCount),
		LastDistribution:    d.metrics.LastDistribution,
		AverageLatencyMs:    d.metrics.AverageLatencyMs,
		QueueDepth:          int64(len(d.queue)),
	}
}
