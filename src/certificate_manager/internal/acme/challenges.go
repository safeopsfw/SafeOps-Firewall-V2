// Package acme implements ACME challenge handlers for domain ownership validation.
package acme

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"certificate_manager/pkg/types"
)

// ============================================================================
// Constants
// ============================================================================

const (
	WellKnownPath         = "/.well-known/acme-challenge/"
	ACMEChallengeTTL      = 60 // DNS TTL in seconds
	DefaultHTTPPort       = 80
	PropagationTimeout    = 120 * time.Second
	PropagationPoll       = 5 * time.Second
	SelfCheckTimeout      = 10 * time.Second
	ChallengeMaxRetries   = 5
	ChallengeRetryBackoff = 2 * time.Second
)

// ============================================================================
// Error Types
// ============================================================================

var (
	ErrChallengeNotReady        = errors.New("challenge not ready for validation")
	ErrChallengeTimeout         = errors.New("challenge preparation timeout")
	ErrChallengeFailed          = errors.New("challenge validation failed")
	ErrUnsupportedChallenge     = errors.New("unsupported challenge type")
	ErrDNSProviderNotConfigured = errors.New("DNS provider not configured")
	ErrHTTPServerFailed         = errors.New("HTTP challenge server failed")
	ErrSelfCheckFailed          = errors.New("self-check failed")
)

// ============================================================================
// Challenge Handler Interface
// ============================================================================

// ChallengeHandler provides unified interface for challenge types
type ChallengeHandler interface {
	StartChallenge(ctx context.Context, challenge *types.Challenge) error
	CleanupChallenge(ctx context.Context, challenge *types.Challenge) error
	GetChallengeType() types.ChallengeType
	ValidateChallenge(ctx context.Context, challenge *types.Challenge) error
}

// ============================================================================
// Challenge Manager
// ============================================================================

// ChallengeManager coordinates all challenge operations
type ChallengeManager struct {
	httpHandler *HTTP01Handler
	dnsHandler  *DNS01Handler

	activeChallenges sync.Map // domain -> *types.Challenge
	mu               sync.RWMutex
}

// NewChallengeManager creates a new challenge manager
func NewChallengeManager(httpConfig types.HTTPChallengeConfig, dnsConfig types.DNSChallengeConfig) *ChallengeManager {
	cm := &ChallengeManager{}

	if httpConfig.Enabled {
		cm.httpHandler = NewHTTP01Handler(httpConfig)
	}

	if dnsConfig.Enabled {
		cm.dnsHandler = NewDNS01Handler(dnsConfig)
	}

	return cm
}

// GetHandler returns appropriate handler for challenge type
func (cm *ChallengeManager) GetHandler(challengeType types.ChallengeType) (ChallengeHandler, error) {
	switch challengeType {
	case types.ChallengeHTTP01:
		if cm.httpHandler == nil {
			return nil, fmt.Errorf("%w: HTTP-01 not configured", ErrUnsupportedChallenge)
		}
		return cm.httpHandler, nil
	case types.ChallengeDNS01:
		if cm.dnsHandler == nil {
			return nil, fmt.Errorf("%w: DNS-01 not configured", ErrUnsupportedChallenge)
		}
		return cm.dnsHandler, nil
	default:
		return nil, fmt.Errorf("%w: %s", ErrUnsupportedChallenge, challengeType)
	}
}

// PrepareChallenge sets up challenge for validation
func (cm *ChallengeManager) PrepareChallenge(ctx context.Context, challenge *types.Challenge, accountKey crypto.PrivateKey) error {
	// Compute key authorization
	keyAuth, err := ComputeKeyAuthorization(challenge.Token, accountKey)
	if err != nil {
		return fmt.Errorf("failed to compute key authorization: %w", err)
	}
	challenge.KeyAuthorization = keyAuth

	// Get handler
	handler, err := cm.GetHandler(challenge.Type)
	if err != nil {
		return err
	}

	// Track active challenge
	cm.activeChallenges.Store(challenge.Domain, challenge)

	// Start challenge
	if err := handler.StartChallenge(ctx, challenge); err != nil {
		cm.activeChallenges.Delete(challenge.Domain)
		return err
	}

	// Self-validate
	if err := handler.ValidateChallenge(ctx, challenge); err != nil {
		cm.activeChallenges.Delete(challenge.Domain)
		return fmt.Errorf("%w: %v", ErrSelfCheckFailed, err)
	}

	return nil
}

// CleanupChallenge removes challenge artifacts
func (cm *ChallengeManager) CleanupChallenge(ctx context.Context, challenge *types.Challenge) error {
	handler, err := cm.GetHandler(challenge.Type)
	if err != nil {
		return err
	}

	cm.activeChallenges.Delete(challenge.Domain)
	return handler.CleanupChallenge(ctx, challenge)
}

// ============================================================================
// HTTP-01 Challenge Handler
// ============================================================================

// HTTP01Handler implements HTTP-01 challenge
type HTTP01Handler struct {
	config     types.HTTPChallengeConfig
	server     *http.Server
	challenges sync.Map // token -> keyAuthorization
	running    bool
	mu         sync.Mutex
}

// NewHTTP01Handler creates a new HTTP-01 handler
func NewHTTP01Handler(config types.HTTPChallengeConfig) *HTTP01Handler {
	return &HTTP01Handler{
		config: config,
	}
}

// GetChallengeType returns HTTP-01
func (h *HTTP01Handler) GetChallengeType() types.ChallengeType {
	return types.ChallengeHTTP01
}

// StartChallenge prepares HTTP-01 challenge
func (h *HTTP01Handler) StartChallenge(ctx context.Context, challenge *types.Challenge) error {
	// Store challenge response
	h.challenges.Store(challenge.Token, challenge.KeyAuthorization)

	// Start HTTP server if not running
	h.mu.Lock()
	if !h.running {
		if err := h.startServer(); err != nil {
			h.mu.Unlock()
			return err
		}
		h.running = true
	}
	h.mu.Unlock()

	return nil
}

// startServer starts the HTTP challenge server
func (h *HTTP01Handler) startServer() error {
	port := h.config.Port
	if port == 0 {
		port = DefaultHTTPPort
	}

	bindAddr := h.config.BindAddress
	if bindAddr == "" {
		bindAddr = "0.0.0.0"
	}

	mux := http.NewServeMux()
	mux.HandleFunc(WellKnownPath, h.handleChallenge)

	h.server = &http.Server{
		Addr:    fmt.Sprintf("%s:%d", bindAddr, port),
		Handler: mux,
	}

	go func() {
		if err := h.server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			// Log error but don't return - server might be in use
		}
	}()

	// Wait a moment for server to start
	time.Sleep(100 * time.Millisecond)

	return nil
}

// handleChallenge serves HTTP-01 challenge responses
func (h *HTTP01Handler) handleChallenge(w http.ResponseWriter, r *http.Request) {
	// Extract token from path
	token := strings.TrimPrefix(r.URL.Path, WellKnownPath)

	keyAuth, ok := h.challenges.Load(token)
	if !ok {
		http.NotFound(w, r)
		return
	}

	w.Header().Set("Content-Type", "text/plain")
	w.WriteHeader(http.StatusOK)
	io.WriteString(w, keyAuth.(string))
}

// CleanupChallenge removes HTTP-01 artifacts
func (h *HTTP01Handler) CleanupChallenge(ctx context.Context, challenge *types.Challenge) error {
	h.challenges.Delete(challenge.Token)

	// Check if any challenges remain
	count := 0
	h.challenges.Range(func(key, value interface{}) bool {
		count++
		return false
	})

	// Stop server if no more challenges
	if count == 0 {
		h.mu.Lock()
		if h.running && h.server != nil {
			h.server.Shutdown(ctx)
			h.running = false
		}
		h.mu.Unlock()
	}

	return nil
}

// ValidateChallenge performs self-check for HTTP-01
func (h *HTTP01Handler) ValidateChallenge(ctx context.Context, challenge *types.Challenge) error {
	port := h.config.Port
	if port == 0 {
		port = DefaultHTTPPort
	}

	url := fmt.Sprintf("http://localhost:%d%s%s", port, WellKnownPath, challenge.Token)

	client := &http.Client{Timeout: SelfCheckTimeout}

	var lastErr error
	for i := 0; i < ChallengeMaxRetries; i++ {
		req, _ := http.NewRequestWithContext(ctx, "GET", url, nil)
		resp, err := client.Do(req)
		if err != nil {
			lastErr = err
			time.Sleep(ChallengeRetryBackoff)
			continue
		}

		body, _ := io.ReadAll(resp.Body)
		resp.Body.Close()

		if resp.StatusCode != http.StatusOK {
			lastErr = fmt.Errorf("HTTP %d", resp.StatusCode)
			time.Sleep(ChallengeRetryBackoff)
			continue
		}

		if string(body) != challenge.KeyAuthorization {
			lastErr = errors.New("response mismatch")
			time.Sleep(ChallengeRetryBackoff)
			continue
		}

		return nil // Success
	}

	return fmt.Errorf("HTTP-01 self-check failed after %d attempts: %v", ChallengeMaxRetries, lastErr)
}

// ============================================================================
// DNS-01 Challenge Handler
// ============================================================================

// DNS01Handler implements DNS-01 challenge
type DNS01Handler struct {
	config   types.DNSChallengeConfig
	provider DNSProvider
}

// DNSProvider interface for DNS operations
type DNSProvider interface {
	CreateTXTRecord(ctx context.Context, domain, value string) error
	DeleteTXTRecord(ctx context.Context, domain string) error
	GetProviderName() string
}

// NewDNS01Handler creates a new DNS-01 handler
func NewDNS01Handler(config types.DNSChallengeConfig) *DNS01Handler {
	h := &DNS01Handler{
		config: config,
	}

	// Initialize provider based on config
	switch strings.ToLower(config.Provider) {
	case "cloudflare":
		h.provider = NewCloudflareProvider(config.APIToken)
	case "manual":
		h.provider = NewManualProvider()
	default:
		h.provider = NewManualProvider()
	}

	return h
}

// GetChallengeType returns DNS-01
func (h *DNS01Handler) GetChallengeType() types.ChallengeType {
	return types.ChallengeDNS01
}

// StartChallenge prepares DNS-01 challenge
func (h *DNS01Handler) StartChallenge(ctx context.Context, challenge *types.Challenge) error {
	if h.provider == nil {
		return ErrDNSProviderNotConfigured
	}

	// Compute DNS record value
	recordValue := ComputeDNS01ChallengeValue(challenge.KeyAuthorization)

	// Get record name
	recordName := GetDNS01RecordName(challenge.Domain)

	// Create TXT record
	if err := h.provider.CreateTXTRecord(ctx, recordName, recordValue); err != nil {
		return fmt.Errorf("failed to create DNS TXT record: %w", err)
	}

	// Wait for propagation
	return h.waitForPropagation(ctx, recordName, recordValue)
}

// waitForPropagation waits for DNS record to propagate
func (h *DNS01Handler) waitForPropagation(ctx context.Context, recordName, expectedValue string) error {
	timeout := h.config.PropagationTimeout
	if timeout == 0 {
		timeout = PropagationTimeout
	}

	pollInterval := h.config.PollingInterval
	if pollInterval == 0 {
		pollInterval = PropagationPoll
	}

	deadline := time.Now().Add(timeout)

	for time.Now().Before(deadline) {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}

		// Query DNS for TXT record
		records, err := net.LookupTXT(recordName)
		if err == nil {
			for _, record := range records {
				if record == expectedValue {
					return nil // Found!
				}
			}
		}

		time.Sleep(pollInterval)
	}

	return fmt.Errorf("%w: DNS record not found after %v", ErrChallengeTimeout, timeout)
}

// CleanupChallenge removes DNS TXT record
func (h *DNS01Handler) CleanupChallenge(ctx context.Context, challenge *types.Challenge) error {
	if h.provider == nil {
		return nil
	}

	recordName := GetDNS01RecordName(challenge.Domain)
	return h.provider.DeleteTXTRecord(ctx, recordName)
}

// ValidateChallenge performs self-check for DNS-01
func (h *DNS01Handler) ValidateChallenge(ctx context.Context, challenge *types.Challenge) error {
	recordName := GetDNS01RecordName(challenge.Domain)
	expectedValue := ComputeDNS01ChallengeValue(challenge.KeyAuthorization)

	records, err := net.LookupTXT(recordName)
	if err != nil {
		return fmt.Errorf("DNS lookup failed: %w", err)
	}

	for _, record := range records {
		if record == expectedValue {
			return nil
		}
	}

	return errors.New("DNS-01 self-check failed: TXT record not found or incorrect")
}

// ============================================================================
// Key Authorization
// ============================================================================

// ComputeKeyAuthorization creates the ACME key authorization
func ComputeKeyAuthorization(token string, accountKey crypto.PrivateKey) (string, error) {
	thumbprint, err := ComputeJWKThumbprint(accountKey)
	if err != nil {
		return "", err
	}

	return token + "." + thumbprint, nil
}

// ComputeJWKThumbprint computes SHA-256 thumbprint of JWK
func ComputeJWKThumbprint(key crypto.PrivateKey) (string, error) {
	var jwk map[string]string

	switch k := key.(type) {
	case *rsa.PrivateKey:
		jwk = map[string]string{
			"e":   base64.RawURLEncoding.EncodeToString([]byte{1, 0, 1}), // 65537
			"kty": "RSA",
			"n":   base64.RawURLEncoding.EncodeToString(k.N.Bytes()),
		}
	case *ecdsa.PrivateKey:
		jwk = map[string]string{
			"crv": k.Curve.Params().Name,
			"kty": "EC",
			"x":   base64.RawURLEncoding.EncodeToString(k.X.Bytes()),
			"y":   base64.RawURLEncoding.EncodeToString(k.Y.Bytes()),
		}
	default:
		return "", fmt.Errorf("unsupported key type: %T", key)
	}

	// JSON encode (keys must be sorted alphabetically)
	thumbprintJSON, _ := json.Marshal(jwk)

	// SHA-256 hash
	hash := sha256.Sum256(thumbprintJSON)

	return base64.RawURLEncoding.EncodeToString(hash[:]), nil
}

// ComputeDNS01ChallengeValue computes DNS-01 TXT record value
func ComputeDNS01ChallengeValue(keyAuthorization string) string {
	hash := sha256.Sum256([]byte(keyAuthorization))
	return base64.RawURLEncoding.EncodeToString(hash[:])
}

// GetDNS01RecordName returns the TXT record name for DNS-01
func GetDNS01RecordName(domain string) string {
	// Handle wildcard domains
	domain = strings.TrimPrefix(domain, "*.")
	return "_acme-challenge." + domain
}

// ============================================================================
// DNS Providers
// ============================================================================

// CloudflareProvider implements DNS operations for Cloudflare
type CloudflareProvider struct {
	apiToken string
}

// NewCloudflareProvider creates a Cloudflare DNS provider
func NewCloudflareProvider(apiToken string) *CloudflareProvider {
	return &CloudflareProvider{apiToken: apiToken}
}

func (p *CloudflareProvider) GetProviderName() string {
	return "cloudflare"
}

func (p *CloudflareProvider) CreateTXTRecord(ctx context.Context, domain, value string) error {
	// Cloudflare API implementation would go here
	// For now, log the required action
	fmt.Printf("[Cloudflare] Create TXT record: %s = %s\n", domain, value)
	return nil
}

func (p *CloudflareProvider) DeleteTXTRecord(ctx context.Context, domain string) error {
	// Cloudflare API implementation would go here
	fmt.Printf("[Cloudflare] Delete TXT record: %s\n", domain)
	return nil
}

// ManualProvider for manual DNS configuration
type ManualProvider struct{}

// NewManualProvider creates a manual DNS provider
func NewManualProvider() *ManualProvider {
	return &ManualProvider{}
}

func (p *ManualProvider) GetProviderName() string {
	return "manual"
}

func (p *ManualProvider) CreateTXTRecord(ctx context.Context, domain, value string) error {
	fmt.Printf("\n=== MANUAL DNS ACTION REQUIRED ===\n")
	fmt.Printf("Create TXT record:\n")
	fmt.Printf("  Name:  %s\n", domain)
	fmt.Printf("  Value: %s\n", value)
	fmt.Printf("  TTL:   %d seconds\n", ACMEChallengeTTL)
	fmt.Printf("==================================\n\n")
	return nil
}

func (p *ManualProvider) DeleteTXTRecord(ctx context.Context, domain string) error {
	fmt.Printf("\n=== MANUAL DNS ACTION REQUIRED ===\n")
	fmt.Printf("Delete TXT record: %s\n", domain)
	fmt.Printf("==================================\n\n")
	return nil
}

// ============================================================================
// HTTP-01 File-Based Handler (Alternative)
// ============================================================================

// HTTP01FileHandler writes challenge files for external web server
type HTTP01FileHandler struct {
	webRoot string
}

// NewHTTP01FileHandler creates file-based HTTP-01 handler
func NewHTTP01FileHandler(webRoot string) *HTTP01FileHandler {
	return &HTTP01FileHandler{webRoot: webRoot}
}

func (h *HTTP01FileHandler) GetChallengeType() types.ChallengeType {
	return types.ChallengeHTTP01
}

func (h *HTTP01FileHandler) StartChallenge(ctx context.Context, challenge *types.Challenge) error {
	// Create .well-known/acme-challenge directory
	challengeDir := filepath.Join(h.webRoot, ".well-known", "acme-challenge")
	if err := os.MkdirAll(challengeDir, 0755); err != nil {
		return fmt.Errorf("failed to create challenge directory: %w", err)
	}

	// Write challenge file
	challengePath := filepath.Join(challengeDir, challenge.Token)
	if err := os.WriteFile(challengePath, []byte(challenge.KeyAuthorization), 0644); err != nil {
		return fmt.Errorf("failed to write challenge file: %w", err)
	}

	return nil
}

func (h *HTTP01FileHandler) CleanupChallenge(ctx context.Context, challenge *types.Challenge) error {
	challengePath := filepath.Join(h.webRoot, ".well-known", "acme-challenge", challenge.Token)
	os.Remove(challengePath)
	return nil
}

func (h *HTTP01FileHandler) ValidateChallenge(ctx context.Context, challenge *types.Challenge) error {
	challengePath := filepath.Join(h.webRoot, ".well-known", "acme-challenge", challenge.Token)

	data, err := os.ReadFile(challengePath)
	if err != nil {
		return fmt.Errorf("challenge file not found: %w", err)
	}

	if string(data) != challenge.KeyAuthorization {
		return errors.New("challenge file content mismatch")
	}

	return nil
}
