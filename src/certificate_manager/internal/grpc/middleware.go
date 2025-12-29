// Package grpc implements gRPC service handlers for the Certificate Manager.
package grpc

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"log"
	"net"
	"strings"
	"sync"
	"time"

	"certificate_manager/pkg/types"

	"golang.org/x/time/rate"
)

// ============================================================================
// Constants
// ============================================================================

const (
	// Metadata keys for authentication
	MetadataKeyAuthorization = "authorization"
	MetadataKeyAPIKey        = "x-api-key"
	MetadataKeyCorrelationID = "x-correlation-id"

	// Rate limit header keys
	HeaderRateLimitLimit     = "x-ratelimit-limit"
	HeaderRateLimitRemaining = "x-ratelimit-remaining"
	HeaderRateLimitReset     = "x-ratelimit-reset"
)

// Role represents authorization level
type Role string

const (
	RoleViewer   Role = "viewer"
	RoleOperator Role = "operator"
	RoleAdmin    Role = "admin"
	RoleInternal Role = "internal"
)

// ============================================================================
// Middleware Configuration
// ============================================================================

// MiddlewareConfig holds configuration for all interceptors.
type MiddlewareConfig struct {
	// Authentication
	APIKeys           map[string]APIKeyConfig // API key -> config
	RequireMTLS       bool                    // Require client certificates
	TrustedCACertPath string                  // Path to CA for validating client certs

	// Rate Limiting
	RateLimitEnabled      bool
	DefaultRateLimit      int           // Requests per window
	DefaultRateWindow     time.Duration // Rate limit window
	MethodRateLimits      map[string]int
	InternalBypassAPIKeys []string // API keys that bypass rate limiting

	// Logging
	LoggingEnabled bool
	AuditLogPath   string
}

// APIKeyConfig defines permissions for an API key.
type APIKeyConfig struct {
	KeyID       string
	Role        Role
	Description string
	Enabled     bool
}

// DefaultMiddlewareConfig returns a sensible default configuration.
func DefaultMiddlewareConfig() *MiddlewareConfig {
	return &MiddlewareConfig{
		APIKeys:           make(map[string]APIKeyConfig),
		RequireMTLS:       false,
		RateLimitEnabled:  true,
		DefaultRateLimit:  500,
		DefaultRateWindow: time.Hour,
		MethodRateLimits: map[string]int{
			"/CertificateManager/SignCertificate":    100,  // 100 per hour
			"/CertificateManager/RevokeCertificate":  10,   // 10 per hour
			"/CertificateManager/GetCertificateInfo": 1000, // 1000 per hour (DHCP)
		},
		InternalBypassAPIKeys: []string{},
		LoggingEnabled:        true,
	}
}

// ============================================================================
// Authentication Context
// ============================================================================

// authContextKey is the key for storing auth info in context
type authContextKey struct{}

// AuthInfo contains authenticated client information.
type AuthInfo struct {
	Authenticated bool
	ClientID      string // API key ID or certificate subject
	Role          Role
	AuthMethod    string // "api_key" or "mtls"
	ClientIP      string
}

// GetAuthInfo retrieves authentication info from context.
func GetAuthInfo(ctx context.Context) *AuthInfo {
	if info, ok := ctx.Value(authContextKey{}).(*AuthInfo); ok {
		return info
	}
	return nil
}

// setAuthInfo stores authentication info in context.
func setAuthInfo(ctx context.Context, info *AuthInfo) context.Context {
	return context.WithValue(ctx, authContextKey{}, info)
}

// ============================================================================
// Authentication Interceptor
// ============================================================================

// AuthInterceptor provides authentication and authorization for gRPC calls.
type AuthInterceptor struct {
	config *MiddlewareConfig
	mu     sync.RWMutex
}

// NewAuthInterceptor creates a new authentication interceptor.
func NewAuthInterceptor(cfg *MiddlewareConfig) *AuthInterceptor {
	return &AuthInterceptor{
		config: cfg,
	}
}

// Authenticate validates the request and returns AuthInfo.
func (a *AuthInterceptor) Authenticate(ctx context.Context, method string, metadata map[string][]string, tlsInfo *tls.ConnectionState) (*AuthInfo, error) {
	a.mu.RLock()
	defer a.mu.RUnlock()

	authInfo := &AuthInfo{
		Authenticated: false,
		ClientIP:      extractClientIP(ctx),
	}

	// Try API key authentication first
	if apiKey := extractAPIKey(metadata); apiKey != "" {
		if keyConfig, exists := a.config.APIKeys[apiKey]; exists && keyConfig.Enabled {
			authInfo.Authenticated = true
			authInfo.ClientID = keyConfig.KeyID
			authInfo.Role = keyConfig.Role
			authInfo.AuthMethod = "api_key"
			return authInfo, nil
		}
		log.Printf("[Auth] Invalid API key from %s", authInfo.ClientIP)
		return nil, fmt.Errorf("invalid API key")
	}

	// Try mTLS authentication
	if a.config.RequireMTLS {
		if tlsInfo == nil || len(tlsInfo.PeerCertificates) == 0 {
			log.Printf("[Auth] mTLS required but no client certificate from %s", authInfo.ClientIP)
			return nil, fmt.Errorf("client certificate required")
		}

		clientCert := tlsInfo.PeerCertificates[0]

		// Validate certificate expiry
		now := time.Now()
		if now.Before(clientCert.NotBefore) || now.After(clientCert.NotAfter) {
			log.Printf("[Auth] Client certificate expired from %s", authInfo.ClientIP)
			return nil, fmt.Errorf("client certificate expired")
		}

		authInfo.Authenticated = true
		authInfo.ClientID = clientCert.Subject.CommonName
		authInfo.Role = RoleOperator // Default role for mTLS
		authInfo.AuthMethod = "mtls"
		return authInfo, nil
	}

	// No authentication required for some methods
	if isPublicMethod(method) {
		authInfo.Authenticated = true
		authInfo.Role = RoleViewer
		authInfo.AuthMethod = "anonymous"
		return authInfo, nil
	}

	return nil, fmt.Errorf("authentication required")
}

// Authorize checks if the authenticated client has permission for the method.
func (a *AuthInterceptor) Authorize(authInfo *AuthInfo, method string) error {
	if authInfo == nil || !authInfo.Authenticated {
		return fmt.Errorf("not authenticated")
	}

	requiredRole := getRequiredRole(method)

	// Check if client role satisfies required role
	if !roleAuthorized(authInfo.Role, requiredRole) {
		log.Printf("[Auth] Authorization denied: %s (role=%s) for method %s (requires=%s)",
			authInfo.ClientID, authInfo.Role, method, requiredRole)
		return fmt.Errorf("insufficient permissions")
	}

	return nil
}

// extractAPIKey retrieves API key from metadata.
func extractAPIKey(metadata map[string][]string) string {
	// Check x-api-key header
	if keys, ok := metadata[MetadataKeyAPIKey]; ok && len(keys) > 0 {
		return keys[0]
	}

	// Check authorization header (Bearer token format)
	if auths, ok := metadata[MetadataKeyAuthorization]; ok && len(auths) > 0 {
		auth := auths[0]
		if strings.HasPrefix(auth, "Bearer ") {
			return strings.TrimPrefix(auth, "Bearer ")
		}
	}

	return ""
}

// extractClientIP gets client IP from context.
func extractClientIP(_ context.Context) string {
	// This would normally use peer.FromContext, but we'll use a simple approach
	return "unknown"
}

// isPublicMethod returns true for methods that don't require authentication.
func isPublicMethod(method string) bool {
	publicMethods := []string{
		"/CertificateManager/GetCertificateInfo", // DHCP integration
	}
	for _, m := range publicMethods {
		if strings.Contains(method, m) {
			return true
		}
	}
	return false
}

// getRequiredRole returns the minimum role required for a method.
func getRequiredRole(method string) Role {
	// Admin operations
	adminMethods := []string{
		"RevokeCertificate",
		"DeleteCertificate",
		"GenerateCA",
	}
	for _, m := range adminMethods {
		if strings.Contains(method, m) {
			return RoleAdmin
		}
	}

	// Operator operations
	operatorMethods := []string{
		"SignCertificate",
		"RenewCertificate",
		"ImportCertificate",
		"UpdateDeviceStatus",
	}
	for _, m := range operatorMethods {
		if strings.Contains(method, m) {
			return RoleOperator
		}
	}

	// Default to viewer for read operations
	return RoleViewer
}

// roleAuthorized checks if clientRole satisfies requiredRole.
func roleAuthorized(clientRole, requiredRole Role) bool {
	roleLevel := map[Role]int{
		RoleViewer:   1,
		RoleOperator: 2,
		RoleAdmin:    3,
		RoleInternal: 4, // Internal services have full access
	}

	return roleLevel[clientRole] >= roleLevel[requiredRole]
}

// ============================================================================
// Logging Interceptor
// ============================================================================

// LoggingInterceptor provides request/response logging for gRPC calls.
type LoggingInterceptor struct {
	enabled bool
	mu      sync.Mutex
}

// NewLoggingInterceptor creates a new logging interceptor.
func NewLoggingInterceptor(enabled bool) *LoggingInterceptor {
	return &LoggingInterceptor{
		enabled: enabled,
	}
}

// LogRequest logs an incoming gRPC request.
func (l *LoggingInterceptor) LogRequest(ctx context.Context, method string, authInfo *AuthInfo) string {
	if !l.enabled {
		return ""
	}

	correlationID := generateCorrelationID()
	clientID := "anonymous"
	if authInfo != nil && authInfo.ClientID != "" {
		clientID = authInfo.ClientID
	}

	log.Printf("[gRPC] Request: method=%s client=%s ip=%s correlationID=%s",
		method, clientID, authInfo.ClientIP, correlationID)

	return correlationID
}

// LogResponse logs a gRPC response.
func (l *LoggingInterceptor) LogResponse(correlationID string, method string, statusCode string, duration time.Duration, err error) {
	if !l.enabled {
		return
	}

	if err != nil {
		log.Printf("[gRPC] Response: method=%s status=%s duration=%dms error=%v correlationID=%s",
			method, statusCode, duration.Milliseconds(), err, correlationID)
	} else {
		log.Printf("[gRPC] Response: method=%s status=%s duration=%dms correlationID=%s",
			method, statusCode, duration.Milliseconds(), correlationID)
	}
}

// LogSecurityEvent logs security-related events (auth failures, rate limits).
func (l *LoggingInterceptor) LogSecurityEvent(eventType, method, clientIP, details string) {
	log.Printf("[Security] Event=%s method=%s ip=%s details=%s",
		eventType, method, clientIP, details)
}

// generateCorrelationID creates a unique ID for request tracing.
func generateCorrelationID() string {
	return fmt.Sprintf("req-%d", time.Now().UnixNano())
}

// ============================================================================
// Rate Limiting Interceptor
// ============================================================================

// RateLimitInterceptor provides rate limiting for gRPC calls.
type RateLimitInterceptor struct {
	config   *MiddlewareConfig
	limiters map[string]*clientLimiter
	mu       sync.RWMutex
}

// clientLimiter tracks rate limits per client.
type clientLimiter struct {
	limiter    *rate.Limiter
	lastAccess time.Time
}

// NewRateLimitInterceptor creates a new rate limiting interceptor.
func NewRateLimitInterceptor(cfg *MiddlewareConfig) *RateLimitInterceptor {
	r := &RateLimitInterceptor{
		config:   cfg,
		limiters: make(map[string]*clientLimiter),
	}

	// Start cleanup goroutine
	go r.cleanupLoop()

	return r
}

// Allow checks if the request should be allowed based on rate limits.
func (r *RateLimitInterceptor) Allow(clientID, method string) (bool, *RateLimitStatus) {
	if !r.config.RateLimitEnabled {
		return true, nil
	}

	// Check if client is allowed to bypass rate limiting
	if r.isBypassClient(clientID) {
		return true, nil
	}

	// Get or create limiter for this client+method combination
	key := fmt.Sprintf("%s:%s", clientID, method)
	limiter := r.getOrCreateLimiter(key, method)

	// Check if request is allowed
	allowed := limiter.limiter.Allow()

	// Build rate limit status
	limit := r.getLimitForMethod(method)
	status := &RateLimitStatus{
		Limit:     limit,
		Remaining: int(limiter.limiter.Tokens()),
		ResetTime: time.Now().Add(time.Hour),
	}

	return allowed, status
}

// RateLimitStatus contains rate limit information for response headers.
type RateLimitStatus struct {
	Limit     int
	Remaining int
	ResetTime time.Time
}

// getOrCreateLimiter gets or creates a rate limiter for a client+method.
func (r *RateLimitInterceptor) getOrCreateLimiter(key, method string) *clientLimiter {
	r.mu.Lock()
	defer r.mu.Unlock()

	if cl, exists := r.limiters[key]; exists {
		cl.lastAccess = time.Now()
		return cl
	}

	// Create new limiter based on method-specific or default limit
	limit := r.getLimitForMethod(method)

	// Convert to rate per second (limit is per hour)
	ratePerSecond := rate.Limit(float64(limit) / 3600.0)

	cl := &clientLimiter{
		limiter:    rate.NewLimiter(ratePerSecond, limit), // Burst = limit
		lastAccess: time.Now(),
	}
	r.limiters[key] = cl

	return cl
}

// getLimitForMethod returns the rate limit for a specific method.
func (r *RateLimitInterceptor) getLimitForMethod(method string) int {
	if limit, exists := r.config.MethodRateLimits[method]; exists {
		return limit
	}
	return r.config.DefaultRateLimit
}

// isBypassClient checks if client should bypass rate limiting.
func (r *RateLimitInterceptor) isBypassClient(clientID string) bool {
	for _, bypassKey := range r.config.InternalBypassAPIKeys {
		if clientID == bypassKey {
			return true
		}
	}
	return false
}

// cleanupLoop removes stale limiters periodically.
func (r *RateLimitInterceptor) cleanupLoop() {
	ticker := time.NewTicker(15 * time.Minute)
	defer ticker.Stop()

	for range ticker.C {
		r.cleanup()
	}
}

// cleanup removes limiters that haven't been used in the last hour.
func (r *RateLimitInterceptor) cleanup() {
	r.mu.Lock()
	defer r.mu.Unlock()

	cutoff := time.Now().Add(-1 * time.Hour)
	for key, cl := range r.limiters {
		if cl.lastAccess.Before(cutoff) {
			delete(r.limiters, key)
		}
	}
}

// ============================================================================
// Middleware Chain
// ============================================================================

// MiddlewareChain combines all interceptors in the correct order.
type MiddlewareChain struct {
	auth      *AuthInterceptor
	logging   *LoggingInterceptor
	rateLimit *RateLimitInterceptor
	config    *MiddlewareConfig
}

// NewMiddlewareChain creates a new middleware chain.
func NewMiddlewareChain(cfg *MiddlewareConfig) *MiddlewareChain {
	if cfg == nil {
		cfg = DefaultMiddlewareConfig()
	}

	return &MiddlewareChain{
		auth:      NewAuthInterceptor(cfg),
		logging:   NewLoggingInterceptor(cfg.LoggingEnabled),
		rateLimit: NewRateLimitInterceptor(cfg),
		config:    cfg,
	}
}

// ProcessRequest runs the full middleware chain for a request.
// Returns AuthInfo and error. If error is non-nil, request should be rejected.
func (m *MiddlewareChain) ProcessRequest(
	ctx context.Context,
	method string,
	metadata map[string][]string,
	tlsInfo *tls.ConnectionState,
) (*AuthInfo, *RateLimitStatus, error) {
	startTime := time.Now()

	// Step 1: Authenticate
	authInfo, err := m.auth.Authenticate(ctx, method, metadata, tlsInfo)
	if err != nil {
		m.logging.LogSecurityEvent("auth_failed", method, extractClientIP(ctx), err.Error())
		return nil, nil, fmt.Errorf("authentication failed: %w", err)
	}

	// Step 2: Log request
	correlationID := m.logging.LogRequest(ctx, method, authInfo)

	// Step 3: Check rate limit
	allowed, rateLimitStatus := m.rateLimit.Allow(authInfo.ClientID, method)
	if !allowed {
		m.logging.LogSecurityEvent("rate_limited", method, authInfo.ClientIP,
			fmt.Sprintf("client=%s", authInfo.ClientID))
		m.logging.LogResponse(correlationID, method, "RESOURCE_EXHAUSTED",
			time.Since(startTime), fmt.Errorf("rate limit exceeded"))
		return authInfo, rateLimitStatus, fmt.Errorf("rate limit exceeded")
	}

	// Step 4: Authorize
	if err := m.auth.Authorize(authInfo, method); err != nil {
		m.logging.LogSecurityEvent("authz_failed", method, authInfo.ClientIP,
			fmt.Sprintf("client=%s role=%s", authInfo.ClientID, authInfo.Role))
		m.logging.LogResponse(correlationID, method, "PERMISSION_DENIED",
			time.Since(startTime), err)
		return authInfo, rateLimitStatus, fmt.Errorf("authorization failed: %w", err)
	}

	// Store auth info and correlation ID in context for handler
	ctx = setAuthInfo(ctx, authInfo)

	return authInfo, rateLimitStatus, nil
}

// LogResponse logs the final response after handler execution.
func (m *MiddlewareChain) LogResponse(correlationID, method, status string, duration time.Duration, err error) {
	m.logging.LogResponse(correlationID, method, status, duration, err)
}

// ============================================================================
// Configuration Helpers
// ============================================================================

// LoadMiddlewareConfigFromTypes creates middleware config from types.Config.
func LoadMiddlewareConfigFromTypes(cfg *types.Config) *MiddlewareConfig {
	mwCfg := DefaultMiddlewareConfig()

	if cfg.Security != nil {
		mwCfg.RateLimitEnabled = cfg.Security.RateLimitEnabled

		// Load allowed IPs/subnets as bypass mechanisms if needed
		if !cfg.Security.RequireAuthentication {
			// If auth not required, some methods are public
		}
	}

	return mwCfg
}

// AddAPIKey registers an API key with the middleware.
func (m *MiddlewareChain) AddAPIKey(key string, config APIKeyConfig) {
	m.auth.mu.Lock()
	defer m.auth.mu.Unlock()
	m.auth.config.APIKeys[key] = config
}

// SetInternalBypassKeys sets API keys that bypass rate limiting.
func (m *MiddlewareChain) SetInternalBypassKeys(keys []string) {
	m.rateLimit.mu.Lock()
	defer m.rateLimit.mu.Unlock()
	m.rateLimit.config.InternalBypassAPIKeys = keys
}

// ============================================================================
// Client Certificate Validation
// ============================================================================

// ValidateClientCertificate validates a client certificate against the trusted CA.
func ValidateClientCertificate(clientCert *x509.Certificate, trustedCACert *x509.Certificate) error {
	if clientCert == nil {
		return fmt.Errorf("client certificate is nil")
	}

	// Create cert pool with trusted CA
	roots := x509.NewCertPool()
	roots.AddCert(trustedCACert)

	// Verify certificate chain
	opts := x509.VerifyOptions{
		Roots:       roots,
		CurrentTime: time.Now(),
		KeyUsages:   []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}

	_, err := clientCert.Verify(opts)
	if err != nil {
		return fmt.Errorf("certificate verification failed: %w", err)
	}

	return nil
}

// ============================================================================
// Utility Functions
// ============================================================================

// ExtractIPFromAddr extracts IP address from a net.Addr.
func ExtractIPFromAddr(addr net.Addr) string {
	if tcpAddr, ok := addr.(*net.TCPAddr); ok {
		return tcpAddr.IP.String()
	}
	return addr.String()
}
