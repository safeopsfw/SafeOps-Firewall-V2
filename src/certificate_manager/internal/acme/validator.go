// Package acme implements domain validation orchestration for ACME protocol.
package acme

import (
	"context"
	"crypto"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"time"

	"certificate_manager/pkg/types"
)

// ============================================================================
// Constants
// ============================================================================

const (
	ValidationTimeout      = 10 * time.Minute
	ValidationPollInitial  = 2 * time.Second
	ValidationPollMax      = 5 * time.Second
	ValidationMaxRetries   = 3
	ValidationRetryBackoff = 2 * time.Second
)

// Authorization status values from ACME protocol
const (
	AuthzStatusPending     = "pending"
	AuthzStatusValid       = "valid"
	AuthzStatusInvalid     = "invalid"
	AuthzStatusDeactivated = "deactivated"
	AuthzStatusExpired     = "expired"
	AuthzStatusRevoked     = "revoked"
)

// ============================================================================
// Error Types
// ============================================================================

var (
	ErrValidationTimeout   = errors.New("validation timeout exceeded")
	ErrValidationFailed    = errors.New("domain validation failed")
	ErrNoValidChallenges   = errors.New("no valid challenge types available")
	ErrAuthorizationFailed = errors.New("authorization failed")
	ErrValidationCanceled  = errors.New("validation was canceled")
)

// ============================================================================
// Validator Structure
// ============================================================================

// Validator orchestrates domain validation workflow
type Validator struct {
	challengeManager *ChallengeManager
	httpClient       *http.Client
	config           types.AcmeConfig
	accountKey       crypto.PrivateKey

	// State tracking
	validations sync.Map // domain -> *ValidationState
	mu          sync.RWMutex
}

// ValidationState tracks validation progress
type ValidationState struct {
	Domain           string
	AuthorizationURL string
	ChallengeType    types.ChallengeType
	ChallengeURL     string
	Status           string
	StartedAt        time.Time
	CompletedAt      time.Time
	Error            string
	Retries          int
}

// ValidationResult contains validation outcome
type ValidationResult struct {
	Domain    string        `json:"domain"`
	Success   bool          `json:"success"`
	Challenge string        `json:"challenge"`
	Duration  time.Duration `json:"duration"`
	Error     string        `json:"error,omitempty"`
	ErrorCode string        `json:"error_code,omitempty"`
}

// Authorization represents ACME authorization object
type Authorization struct {
	Identifier Identifier      `json:"identifier"`
	Status     string          `json:"status"`
	Expires    time.Time       `json:"expires"`
	Challenges []ACMEChallenge `json:"challenges"`
	Wildcard   bool            `json:"wildcard"`
}

// Identifier in ACME authorization
type Identifier struct {
	Type  string `json:"type"`
	Value string `json:"value"`
}

// ACMEChallenge from ACME protocol
type ACMEChallenge struct {
	Type      string     `json:"type"`
	URL       string     `json:"url"`
	Token     string     `json:"token"`
	Status    string     `json:"status"`
	Validated string     `json:"validated,omitempty"`
	Error     *ACMEError `json:"error,omitempty"`
}

// ACMEError from Let's Encrypt
type ACMEError struct {
	Type   string `json:"type"`
	Detail string `json:"detail"`
	Status int    `json:"status"`
}

// ============================================================================
// Validator Initialization
// ============================================================================

// NewValidator creates a new domain validator
func NewValidator(config types.AcmeConfig, challengeManager *ChallengeManager, accountKey crypto.PrivateKey) *Validator {
	return &Validator{
		challengeManager: challengeManager,
		httpClient: &http.Client{
			Timeout: 30 * time.Second,
		},
		config:     config,
		accountKey: accountKey,
	}
}

// ============================================================================
// Authorization Validation Interface
// ============================================================================

// ValidateAuthorization completes validation for single authorization
func (v *Validator) ValidateAuthorization(ctx context.Context, authzURL string) (*ValidationResult, error) {
	// Fetch authorization
	authz, err := v.fetchAuthorization(ctx, authzURL)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch authorization: %w", err)
	}

	domain := authz.Identifier.Value
	startTime := time.Now()

	// Track state
	state := &ValidationState{
		Domain:           domain,
		AuthorizationURL: authzURL,
		Status:           authz.Status,
		StartedAt:        startTime,
	}
	v.validations.Store(domain, state)
	defer v.validations.Delete(domain)

	// Check if already valid
	if authz.Status == AuthzStatusValid {
		return &ValidationResult{
			Domain:   domain,
			Success:  true,
			Duration: time.Since(startTime),
		}, nil
	}

	// Select best challenge
	challenge, challengeType, err := v.selectChallenge(authz)
	if err != nil {
		return nil, err
	}

	state.ChallengeType = challengeType
	state.ChallengeURL = challenge.URL

	// Create internal challenge object
	internalChallenge := &types.Challenge{
		Domain:        domain,
		Type:          challengeType,
		Token:         challenge.Token,
		ValidationURL: challenge.URL,
		Status:        types.ChallengeStatus(challenge.Status),
	}

	// Prepare challenge
	if err := v.challengeManager.PrepareChallenge(ctx, internalChallenge, v.accountKey); err != nil {
		return &ValidationResult{
			Domain:  domain,
			Success: false,
			Error:   fmt.Sprintf("challenge preparation failed: %v", err),
		}, err
	}

	// Ensure cleanup
	defer v.challengeManager.CleanupChallenge(ctx, internalChallenge)

	// Notify CA to validate
	if err := v.notifyChallenge(ctx, challenge.URL); err != nil {
		return &ValidationResult{
			Domain:  domain,
			Success: false,
			Error:   fmt.Sprintf("challenge notification failed: %v", err),
		}, err
	}

	// Poll for validation result
	result, err := v.pollAuthorization(ctx, authzURL, domain)
	if err != nil {
		state.Status = AuthzStatusInvalid
		state.Error = err.Error()
		return result, err
	}

	state.Status = AuthzStatusValid
	state.CompletedAt = time.Now()
	result.Duration = time.Since(startTime)
	result.Challenge = string(challengeType)

	return result, nil
}

// ValidateMultiple validates multiple domains concurrently
func (v *Validator) ValidateMultiple(ctx context.Context, authzURLs []string) ([]*ValidationResult, error) {
	results := make([]*ValidationResult, len(authzURLs))
	var wg sync.WaitGroup
	var mu sync.Mutex
	var firstErr error

	// Create context with timeout
	ctx, cancel := context.WithTimeout(ctx, ValidationTimeout)
	defer cancel()

	for i, authzURL := range authzURLs {
		wg.Add(1)
		go func(idx int, url string) {
			defer wg.Done()

			result, err := v.ValidateAuthorization(ctx, url)

			mu.Lock()
			defer mu.Unlock()

			if result != nil {
				results[idx] = result
			} else {
				results[idx] = &ValidationResult{
					Success: false,
					Error:   err.Error(),
				}
			}

			if err != nil && firstErr == nil {
				firstErr = err
			}
		}(i, authzURL)
	}

	wg.Wait()

	return results, firstErr
}

// GetValidationStatus returns current status of validation
func (v *Validator) GetValidationStatus(domain string) (*ValidationState, bool) {
	state, ok := v.validations.Load(domain)
	if !ok {
		return nil, false
	}
	return state.(*ValidationState), true
}

// CancelValidation aborts in-progress validation
func (v *Validator) CancelValidation(domain string) error {
	state, ok := v.validations.Load(domain)
	if !ok {
		return fmt.Errorf("no active validation for domain: %s", domain)
	}

	vs := state.(*ValidationState)
	vs.Status = "canceled"
	vs.Error = "validation canceled by user"

	return nil
}

// ============================================================================
// Challenge Selection Logic
// ============================================================================

// selectChallenge determines which challenge type to use
func (v *Validator) selectChallenge(authz *Authorization) (*ACMEChallenge, types.ChallengeType, error) {
	isWildcard := authz.Wildcard || strings.HasPrefix(authz.Identifier.Value, "*.")

	var http01, dns01 *ACMEChallenge

	for i := range authz.Challenges {
		switch authz.Challenges[i].Type {
		case "http-01":
			http01 = &authz.Challenges[i]
		case "dns-01":
			dns01 = &authz.Challenges[i]
		}
	}

	// Wildcard certificates MUST use DNS-01
	if isWildcard {
		if dns01 == nil {
			return nil, "", fmt.Errorf("%w: DNS-01 required for wildcard but not available", ErrNoValidChallenges)
		}
		if _, err := v.challengeManager.GetHandler(types.ChallengeDNS01); err != nil {
			return nil, "", fmt.Errorf("%w: DNS-01 not configured for wildcard certificate", ErrNoValidChallenges)
		}
		return dns01, types.ChallengeDNS01, nil
	}

	// Prefer configured challenge type
	preferredType := v.config.PreferredChallenge

	switch preferredType {
	case types.ChallengeDNS01:
		if dns01 != nil {
			if _, err := v.challengeManager.GetHandler(types.ChallengeDNS01); err == nil {
				return dns01, types.ChallengeDNS01, nil
			}
		}
		// Fall through to HTTP-01
		if http01 != nil {
			if _, err := v.challengeManager.GetHandler(types.ChallengeHTTP01); err == nil {
				return http01, types.ChallengeHTTP01, nil
			}
		}

	case types.ChallengeHTTP01:
		fallthrough
	default:
		if http01 != nil {
			if _, err := v.challengeManager.GetHandler(types.ChallengeHTTP01); err == nil {
				return http01, types.ChallengeHTTP01, nil
			}
		}
		// Fall through to DNS-01
		if dns01 != nil {
			if _, err := v.challengeManager.GetHandler(types.ChallengeDNS01); err == nil {
				return dns01, types.ChallengeDNS01, nil
			}
		}
	}

	return nil, "", ErrNoValidChallenges
}

// ============================================================================
// Authorization Polling
// ============================================================================

// pollAuthorization monitors validation progress
func (v *Validator) pollAuthorization(ctx context.Context, authzURL, domain string) (*ValidationResult, error) {
	pollInterval := ValidationPollInitial
	deadline := time.Now().Add(ValidationTimeout)

	for {
		select {
		case <-ctx.Done():
			return &ValidationResult{
				Domain:  domain,
				Success: false,
				Error:   "validation canceled",
			}, ErrValidationCanceled
		default:
		}

		if time.Now().After(deadline) {
			return &ValidationResult{
				Domain:  domain,
				Success: false,
				Error:   "validation timeout exceeded",
			}, ErrValidationTimeout
		}

		// Fetch current status
		authz, err := v.fetchAuthorization(ctx, authzURL)
		if err != nil {
			time.Sleep(pollInterval)
			continue
		}

		switch authz.Status {
		case AuthzStatusValid:
			return &ValidationResult{
				Domain:  domain,
				Success: true,
			}, nil

		case AuthzStatusInvalid:
			// Extract error details
			errorDetail := "unknown validation error"
			errorCode := ""
			for _, ch := range authz.Challenges {
				if ch.Error != nil {
					errorDetail = ch.Error.Detail
					errorCode = ch.Error.Type
					break
				}
			}
			return &ValidationResult{
				Domain:    domain,
				Success:   false,
				Error:     errorDetail,
				ErrorCode: errorCode,
			}, fmt.Errorf("%w: %s", ErrValidationFailed, errorDetail)

		case AuthzStatusPending, "processing":
			// Still in progress, continue polling
			time.Sleep(pollInterval)
			if pollInterval < ValidationPollMax {
				pollInterval = pollInterval * 3 / 2 // Increase by 50%
			}
			continue

		default:
			return &ValidationResult{
				Domain:  domain,
				Success: false,
				Error:   fmt.Sprintf("unexpected authorization status: %s", authz.Status),
			}, fmt.Errorf("unexpected authorization status: %s", authz.Status)
		}
	}
}

// ============================================================================
// ACME Protocol Communication
// ============================================================================

// fetchAuthorization retrieves authorization from ACME server
func (v *Validator) fetchAuthorization(ctx context.Context, authzURL string) (*Authorization, error) {
	req, err := http.NewRequestWithContext(ctx, "GET", authzURL, nil)
	if err != nil {
		return nil, err
	}

	resp, err := v.httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("authorization request failed with status %d", resp.StatusCode)
	}

	var authz Authorization
	if err := json.NewDecoder(resp.Body).Decode(&authz); err != nil {
		return nil, fmt.Errorf("failed to decode authorization: %w", err)
	}

	return &authz, nil
}

// notifyChallenge tells ACME server we're ready for validation
func (v *Validator) notifyChallenge(ctx context.Context, challengeURL string) error {
	// In actual implementation, this would:
	// 1. Create JWS-signed request with empty payload
	// 2. POST to challenge URL
	// 3. Verify response

	// For now, simulate the notification
	req, err := http.NewRequestWithContext(ctx, "POST", challengeURL, strings.NewReader("{}"))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/jose+json")

	resp, err := v.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("challenge notification failed: %w", err)
	}
	defer resp.Body.Close()

	// Accept 200 OK or 202 Accepted
	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusAccepted {
		return fmt.Errorf("challenge notification returned status %d", resp.StatusCode)
	}

	return nil
}

// ============================================================================
// Validation with Retry
// ============================================================================

// ValidateWithRetry attempts validation with retry logic
func (v *Validator) ValidateWithRetry(ctx context.Context, authzURL string) (*ValidationResult, error) {
	var lastResult *ValidationResult
	var lastErr error

	for attempt := 0; attempt < ValidationMaxRetries; attempt++ {
		if attempt > 0 {
			backoff := ValidationRetryBackoff * time.Duration(1<<(attempt-1))
			select {
			case <-ctx.Done():
				return nil, ctx.Err()
			case <-time.After(backoff):
			}
		}

		result, err := v.ValidateAuthorization(ctx, authzURL)
		lastResult = result
		lastErr = err

		if err == nil && result.Success {
			return result, nil
		}

		// Check if error is retryable
		if !isRetryableError(err) {
			return result, err
		}
	}

	if lastResult == nil {
		lastResult = &ValidationResult{
			Success: false,
			Error:   fmt.Sprintf("validation failed after %d attempts: %v", ValidationMaxRetries, lastErr),
		}
	}

	return lastResult, lastErr
}

// isRetryableError determines if validation error is temporary
func isRetryableError(err error) bool {
	if err == nil {
		return false
	}

	// Network errors are retryable
	errStr := err.Error()
	retryablePatterns := []string{
		"timeout",
		"connection refused",
		"connection reset",
		"temporary failure",
		"too many requests",
	}

	for _, pattern := range retryablePatterns {
		if strings.Contains(strings.ToLower(errStr), pattern) {
			return true
		}
	}

	return false
}

// ============================================================================
// Error Mapping
// ============================================================================

// MapACMEError translates ACME error to user-friendly message
func MapACMEError(err *ACMEError) string {
	if err == nil {
		return "unknown error"
	}

	// Map common ACME error types
	switch err.Type {
	case "urn:ietf:params:acme:error:connection":
		return "Let's Encrypt could not connect to your server. Ensure port 80 is accessible from the internet."
	case "urn:ietf:params:acme:error:dns":
		return "DNS lookup failed. Ensure the domain resolves correctly."
	case "urn:ietf:params:acme:error:incorrectResponse":
		return "Challenge response was incorrect. Check that the challenge file or DNS record is properly configured."
	case "urn:ietf:params:acme:error:rateLimited":
		return "Rate limit exceeded. Wait before retrying (usually 1 hour)."
	case "urn:ietf:params:acme:error:unauthorized":
		return "Domain validation failed. Verify domain ownership and try again."
	case "urn:ietf:params:acme:error:unknownHost":
		return "Domain does not exist in DNS. Check for typos in the domain name."
	default:
		return err.Detail
	}
}
