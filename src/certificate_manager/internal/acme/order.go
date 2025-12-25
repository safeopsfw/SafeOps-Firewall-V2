// Package acme implements certificate order management for ACME protocol.
package acme

import (
	"context"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"sync"
	"time"

	"certificate_manager/internal/generation"
	"certificate_manager/internal/storage"
	"certificate_manager/pkg/types"
)

// ============================================================================
// Constants
// ============================================================================

const (
	OrderTimeout       = 30 * time.Minute
	OrderPollInitial   = 2 * time.Second
	OrderPollMax       = 10 * time.Second
	OrderMaxRetries    = 3
	MaxDomainsPerOrder = 100 // Let's Encrypt limit
)

// Order status values from ACME protocol
const (
	OrderStatusPending    = "pending"
	OrderStatusReady      = "ready"
	OrderStatusProcessing = "processing"
	OrderStatusValid      = "valid"
	OrderStatusInvalid    = "invalid"
	OrderStatusExpired    = "expired"
)

// ============================================================================
// Error Types
// ============================================================================

var (
	ErrOrderCreationFailed      = errors.New("order creation failed")
	ErrOrderTimeout             = errors.New("order timeout exceeded")
	ErrOrderInvalid             = errors.New("order became invalid")
	ErrOrderExpired             = errors.New("order expired")
	ErrOrderNotReadyForFinalize = errors.New("order not ready for finalization")
	ErrTooManyDomains           = errors.New("too many domains in order")
	ErrNoDomains                = errors.New("no domains specified")
	ErrCertificateMismatch      = errors.New("certificate does not match requested domains")
)

// ============================================================================
// Order Manager Structure
// ============================================================================

// OrderManager coordinates certificate order lifecycle
type OrderManager struct {
	client    *Client
	validator *Validator
	db        *storage.Database
	config    types.AcmeConfig

	// Active orders tracking
	activeOrders sync.Map // orderURL -> *OrderState
	mu           sync.RWMutex
}

// OrderState tracks order progress
type OrderState struct {
	OrderURL       string
	Status         string
	Domains        []string
	Authorizations []AuthorizationState
	FinalizeURL    string
	CertificateURL string
	Expires        time.Time
	CreatedAt      time.Time
	UpdatedAt      time.Time
	Error          string
}

// AuthorizationState tracks individual domain authorization
type AuthorizationState struct {
	Domain    string
	URL       string
	Status    string
	Challenge types.ChallengeType
	Error     string
}

// OrderResult contains the outcome of an order
type OrderResult struct {
	Success        bool
	OrderURL       string
	CertificatePEM string
	ChainPEM       string
	FullChainPEM   string
	Domains        []string
	IssuedAt       time.Time
	ExpiresAt      time.Time
	Error          string
}

// ============================================================================
// Order Manager Initialization
// ============================================================================

// NewOrderManager creates a new order manager
func NewOrderManager(client *Client, validator *Validator, db *storage.Database, config types.AcmeConfig) *OrderManager {
	return &OrderManager{
		client:    client,
		validator: validator,
		db:        db,
		config:    config,
	}
}

// ============================================================================
// Order Manager Public API
// ============================================================================

// CreateOrder initiates a new certificate request
func (om *OrderManager) CreateOrder(ctx context.Context, domains []string) (*OrderState, error) {
	if len(domains) == 0 {
		return nil, ErrNoDomains
	}

	if len(domains) > MaxDomainsPerOrder {
		return nil, fmt.Errorf("%w: %d domains exceeds limit of %d", ErrTooManyDomains, len(domains), MaxDomainsPerOrder)
	}

	// Validate domains
	for _, domain := range domains {
		if err := types.ValidateDomain(domain); err != nil {
			return nil, fmt.Errorf("invalid domain %s: %w", domain, err)
		}
	}

	// Create order via ACME client
	var order *Order
	var lastErr error

	for attempt := 0; attempt < OrderMaxRetries; attempt++ {
		if attempt > 0 {
			time.Sleep(time.Duration(attempt) * time.Second)
		}

		order, lastErr = om.client.CreateOrder(ctx, domains)
		if lastErr == nil {
			break
		}

		// Check if error is retryable
		if !isOrderRetryable(lastErr) {
			return nil, fmt.Errorf("%w: %v", ErrOrderCreationFailed, lastErr)
		}
	}

	if lastErr != nil {
		return nil, fmt.Errorf("%w after %d attempts: %v", ErrOrderCreationFailed, OrderMaxRetries, lastErr)
	}

	// Create state object
	state := &OrderState{
		OrderURL:       order.URL,
		Status:         order.Status,
		Domains:        domains,
		Authorizations: make([]AuthorizationState, len(order.Authorizations)),
		FinalizeURL:    order.FinalizeURL,
		CertificateURL: order.CertificateURL,
		Expires:        order.Expires,
		CreatedAt:      time.Now(),
		UpdatedAt:      time.Now(),
	}

	for i, authzURL := range order.Authorizations {
		state.Authorizations[i] = AuthorizationState{
			URL:    authzURL,
			Status: "pending",
		}
	}

	// Track active order
	om.activeOrders.Store(order.URL, state)

	return state, nil
}

// GetOrderStatus returns current order state
func (om *OrderManager) GetOrderStatus(ctx context.Context, orderURL string) (*OrderState, error) {
	// Check cache first
	if cached, ok := om.activeOrders.Load(orderURL); ok {
		return cached.(*OrderState), nil
	}

	// Fetch from ACME server
	order, err := om.client.GetOrder(ctx, orderURL)
	if err != nil {
		return nil, err
	}

	state := &OrderState{
		OrderURL:       orderURL,
		Status:         order.Status,
		FinalizeURL:    order.FinalizeURL,
		CertificateURL: order.CertificateURL,
		Expires:        order.Expires,
		UpdatedAt:      time.Now(),
	}

	return state, nil
}

// CompleteOrder handles the full order workflow
func (om *OrderManager) CompleteOrder(ctx context.Context, domains []string, keyType types.KeyType) (*OrderResult, error) {
	// Create timeout context
	ctx, cancel := context.WithTimeout(ctx, OrderTimeout)
	defer cancel()

	// Step 1: Create order
	state, err := om.CreateOrder(ctx, domains)
	if err != nil {
		return &OrderResult{
			Success: false,
			Domains: domains,
			Error:   err.Error(),
		}, err
	}
	defer om.activeOrders.Delete(state.OrderURL)

	// Step 2: Complete authorizations
	if state.Status == OrderStatusPending {
		if err := om.completeAuthorizations(ctx, state); err != nil {
			return &OrderResult{
				Success:  false,
				OrderURL: state.OrderURL,
				Domains:  domains,
				Error:    err.Error(),
			}, err
		}
	}

	// Step 3: Wait for ready status
	if err := om.waitForReady(ctx, state); err != nil {
		return &OrderResult{
			Success:  false,
			OrderURL: state.OrderURL,
			Domains:  domains,
			Error:    err.Error(),
		}, err
	}

	// Step 4: Generate CSR and finalize
	if err := om.finalizeOrder(ctx, state, keyType); err != nil {
		return &OrderResult{
			Success:  false,
			OrderURL: state.OrderURL,
			Domains:  domains,
			Error:    err.Error(),
		}, err
	}

	// Step 5: Download certificate
	result, err := om.downloadCertificate(ctx, state)
	if err != nil {
		return &OrderResult{
			Success:  false,
			OrderURL: state.OrderURL,
			Domains:  domains,
			Error:    err.Error(),
		}, err
	}

	result.OrderURL = state.OrderURL
	result.Domains = domains
	result.Success = true
	result.IssuedAt = time.Now()

	return result, nil
}

// ============================================================================
// Authorization Coordination
// ============================================================================

// completeAuthorizations validates all domains in parallel
func (om *OrderManager) completeAuthorizations(ctx context.Context, state *OrderState) error {
	if om.validator == nil {
		return errors.New("validator not configured")
	}

	// Collect authorization URLs
	authzURLs := make([]string, len(state.Authorizations))
	for i, authz := range state.Authorizations {
		authzURLs[i] = authz.URL
	}

	// Validate all in parallel
	results, err := om.validator.ValidateMultiple(ctx, authzURLs)
	if err != nil {
		// Update state with individual results
		for i, result := range results {
			if result != nil {
				state.Authorizations[i].Status = "completed"
				state.Authorizations[i].Domain = result.Domain
				if !result.Success {
					state.Authorizations[i].Status = "failed"
					state.Authorizations[i].Error = result.Error
				}
			}
		}
		return err
	}

	// Check all succeeded
	for i, result := range results {
		state.Authorizations[i].Domain = result.Domain
		if result.Success {
			state.Authorizations[i].Status = "valid"
		} else {
			state.Authorizations[i].Status = "invalid"
			state.Authorizations[i].Error = result.Error
			return fmt.Errorf("authorization failed for %s: %s", result.Domain, result.Error)
		}
	}

	return nil
}

// ============================================================================
// Order Status Polling
// ============================================================================

// waitForReady blocks until order is ready for finalization
func (om *OrderManager) waitForReady(ctx context.Context, state *OrderState) error {
	pollInterval := OrderPollInitial

	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}

		// Fetch current status
		order, err := om.client.GetOrder(ctx, state.OrderURL)
		if err != nil {
			time.Sleep(pollInterval)
			continue
		}

		state.Status = order.Status
		state.UpdatedAt = time.Now()

		switch order.Status {
		case OrderStatusReady:
			// Ready for finalization
			state.FinalizeURL = order.FinalizeURL
			return nil

		case OrderStatusValid:
			// Already finalized
			state.CertificateURL = order.CertificateURL
			return nil

		case OrderStatusInvalid:
			if order.Error != nil {
				state.Error = order.Error.Detail
				return fmt.Errorf("%w: %s", ErrOrderInvalid, order.Error.Detail)
			}
			return ErrOrderInvalid

		case OrderStatusExpired:
			return ErrOrderExpired

		case OrderStatusPending, OrderStatusProcessing:
			// Still processing, continue polling
			time.Sleep(pollInterval)
			if pollInterval < OrderPollMax {
				pollInterval = pollInterval * 3 / 2
			}
			continue

		default:
			return fmt.Errorf("unexpected order status: %s", order.Status)
		}
	}
}

// ============================================================================
// Finalization Workflow
// ============================================================================

// finalizeOrder generates CSR and submits for finalization
func (om *OrderManager) finalizeOrder(ctx context.Context, state *OrderState, keyType types.KeyType) error {
	// Order must be in ready status
	if state.Status != OrderStatusReady && state.Status != OrderStatusValid {
		return ErrOrderNotReadyForFinalize
	}

	// If already valid, nothing to do
	if state.Status == OrderStatusValid {
		return nil
	}

	// Generate private key for the certificate
	keyInfo, err := generation.GeneratePrivateKey(keyType)
	if err != nil {
		return fmt.Errorf("failed to generate private key: %w", err)
	}

	// Generate CSR
	csrRequest := &types.CSRRequest{
		CommonName:      state.Domains[0],
		SubjectAltNames: state.Domains[1:],
		KeyType:         keyType,
	}
	csrPEM, err := generation.GenerateCSR(keyInfo, csrRequest)
	if err != nil {
		return fmt.Errorf("failed to generate CSR: %w", err)
	}

	// Parse CSR to get DER
	block, _ := pem.Decode(csrPEM)
	if block == nil {
		return errors.New("failed to decode CSR PEM")
	}

	// Submit CSR
	order, err := om.client.FinalizeOrder(ctx, state.FinalizeURL, block.Bytes)
	if err != nil {
		return fmt.Errorf("finalization failed: %w", err)
	}

	state.Status = order.Status
	state.UpdatedAt = time.Now()

	// Poll until certificate is ready
	if order.Status != OrderStatusValid {
		order, err = om.client.PollOrder(ctx, state.OrderURL)
		if err != nil {
			return err
		}
	}

	state.Status = order.Status
	state.CertificateURL = order.CertificateURL

	return nil
}

// ============================================================================
// Certificate Download
// ============================================================================

// downloadCertificate retrieves the issued certificate
func (om *OrderManager) downloadCertificate(ctx context.Context, state *OrderState) (*OrderResult, error) {
	if state.CertificateURL == "" {
		return nil, errors.New("certificate URL not available")
	}

	// Download certificate
	bundle, err := om.client.GetCertificate(ctx, state.CertificateURL)
	if err != nil {
		return nil, fmt.Errorf("failed to download certificate: %w", err)
	}

	// Validate certificate covers requested domains
	if err := om.validateCertificateDomains(bundle.Certificate, state.Domains); err != nil {
		return nil, err
	}

	// Parse certificate to get expiry
	expiresAt := time.Now().Add(90 * 24 * time.Hour) // Default
	if block, _ := pem.Decode([]byte(bundle.Certificate)); block != nil {
		if cert, err := x509.ParseCertificate(block.Bytes); err == nil {
			expiresAt = cert.NotAfter
		}
	}

	return &OrderResult{
		CertificatePEM: bundle.Certificate,
		ChainPEM:       joinChain(bundle.Chain),
		FullChainPEM:   bundle.FullChain,
		ExpiresAt:      expiresAt,
	}, nil
}

// validateCertificateDomains ensures certificate covers requested domains
func (om *OrderManager) validateCertificateDomains(certPEM string, domains []string) error {
	block, _ := pem.Decode([]byte(certPEM))
	if block == nil {
		return errors.New("failed to parse certificate PEM")
	}

	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return fmt.Errorf("failed to parse certificate: %w", err)
	}

	// Collect certificate domains
	certDomains := make(map[string]bool)
	certDomains[cert.Subject.CommonName] = true
	for _, san := range cert.DNSNames {
		certDomains[san] = true
	}

	// Check all requested domains are covered
	for _, domain := range domains {
		if !certDomains[domain] {
			return fmt.Errorf("%w: missing %s", ErrCertificateMismatch, domain)
		}
	}

	return nil
}

// joinChain concatenates chain certificates
func joinChain(chain []string) string {
	result := ""
	for _, cert := range chain {
		result += cert
	}
	return result
}

// ============================================================================
// Order Cancellation
// ============================================================================

// CancelOrder aborts a pending order
func (om *OrderManager) CancelOrder(orderURL string) error {
	om.activeOrders.Delete(orderURL)
	// Note: ACME protocol doesn't support explicit order cancellation
	// Orders just expire naturally
	return nil
}

// ============================================================================
// Order Retry Logic
// ============================================================================

// isOrderRetryable determines if order error is temporary
func isOrderRetryable(err error) bool {
	if err == nil {
		return false
	}

	errStr := err.Error()
	retryablePatterns := []string{
		"timeout",
		"connection refused",
		"connection reset",
		"temporary",
		"try again",
	}

	for _, pattern := range retryablePatterns {
		if containsIgnoreCase(errStr, pattern) {
			return true
		}
	}

	return false
}

func containsIgnoreCase(s, substr string) bool {
	return len(s) >= len(substr) &&
		(s == substr ||
			len(s) > len(substr) && contains(lower(s), lower(substr)))
}

func lower(s string) string {
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

func contains(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}

// ============================================================================
// Order Queries
// ============================================================================

// GetActiveOrders returns all in-progress orders
func (om *OrderManager) GetActiveOrders() []*OrderState {
	var orders []*OrderState
	om.activeOrders.Range(func(key, value interface{}) bool {
		orders = append(orders, value.(*OrderState))
		return true
	})
	return orders
}

// GetOrderByDomain finds order containing a specific domain
func (om *OrderManager) GetOrderByDomain(domain string) (*OrderState, bool) {
	var found *OrderState
	om.activeOrders.Range(func(key, value interface{}) bool {
		state := value.(*OrderState)
		for _, d := range state.Domains {
			if d == domain {
				found = state
				return false
			}
		}
		return true
	})
	return found, found != nil
}
