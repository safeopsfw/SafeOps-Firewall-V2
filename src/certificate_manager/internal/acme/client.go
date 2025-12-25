// Package acme implements the ACME protocol client for Let's Encrypt communication.
package acme

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/big"
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
	ContentTypeJOSE  = "application/jose+json"
	ContentTypePEM   = "application/pem-certificate-chain"
	UserAgentDefault = "SafeOPS-CertificateManager/1.0"

	HTTPTimeout        = 30 * time.Second
	ClientMaxRetries   = 3
	ClientRetryBackoff = 2 * time.Second
	NoncePoolSize      = 10
)

// ============================================================================
// Error Types
// ============================================================================

var (
	ErrNonceUnavailable    = errors.New("no nonce available")
	ErrBadNonce            = errors.New("bad nonce - retry required")
	ErrRateLimited         = errors.New("rate limited by Let's Encrypt")
	ErrOrderNotReady       = errors.New("order not ready for finalization")
	ErrCertificateNotReady = errors.New("certificate not yet available")
	ErrProtocolError       = errors.New("ACME protocol error")
)

// ============================================================================
// ACME Client Structure
// ============================================================================

// Client handles ACME protocol communication with Let's Encrypt
type Client struct {
	httpClient     *http.Client
	accountManager *AccountManager
	validator      *Validator
	directory      *Directory
	config         types.AcmeConfig

	// Nonce pool
	noncePool chan string
	nonceMu   sync.Mutex

	// Account info (cached after first use)
	accountURL string
	accountKey crypto.PrivateKey
}

// NewClient creates a new ACME client
func NewClient(config types.AcmeConfig, accountManager *AccountManager, validator *Validator) *Client {
	return &Client{
		httpClient: &http.Client{
			Timeout: HTTPTimeout,
		},
		accountManager: accountManager,
		validator:      validator,
		config:         config,
		noncePool:      make(chan string, NoncePoolSize),
	}
}

// ============================================================================
// Client Initialization
// ============================================================================

// Initialize prepares the client for use
func (c *Client) Initialize(ctx context.Context) error {
	// Fetch directory
	if err := c.fetchDirectory(ctx); err != nil {
		return fmt.Errorf("failed to fetch directory: %w", err)
	}

	// Pre-fetch some nonces
	for i := 0; i < 3; i++ {
		if nonce, err := c.fetchNonce(ctx); err == nil {
			select {
			case c.noncePool <- nonce:
			default:
			}
		}
	}

	return nil
}

// ============================================================================
// Directory Discovery
// ============================================================================

// fetchDirectory retrieves ACME directory from server
func (c *Client) fetchDirectory(ctx context.Context) error {
	req, err := http.NewRequestWithContext(ctx, "GET", c.config.DirectoryURL, nil)
	if err != nil {
		return err
	}
	req.Header.Set("User-Agent", UserAgentDefault)

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("directory request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("directory returned status %d", resp.StatusCode)
	}

	c.directory = &Directory{}
	if err := json.NewDecoder(resp.Body).Decode(c.directory); err != nil {
		return fmt.Errorf("failed to decode directory: %w", err)
	}

	return nil
}

// GetDirectory returns the ACME directory
func (c *Client) GetDirectory() *Directory {
	return c.directory
}

// ============================================================================
// Nonce Management
// ============================================================================

// fetchNonce gets a fresh nonce from ACME server
func (c *Client) fetchNonce(ctx context.Context) (string, error) {
	if c.directory == nil {
		return "", errors.New("directory not initialized")
	}

	req, err := http.NewRequestWithContext(ctx, "HEAD", c.directory.NewNonce, nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("User-Agent", UserAgentDefault)

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return "", err
	}
	resp.Body.Close()

	nonce := resp.Header.Get("Replay-Nonce")
	if nonce == "" {
		return "", ErrNonceUnavailable
	}

	return nonce, nil
}

// getNonce returns a nonce, fetching if pool is empty
func (c *Client) getNonce(ctx context.Context) (string, error) {
	select {
	case nonce := <-c.noncePool:
		return nonce, nil
	default:
		return c.fetchNonce(ctx)
	}
}

// returnNonce puts a nonce back in the pool
func (c *Client) returnNonce(nonce string) {
	if nonce == "" {
		return
	}
	select {
	case c.noncePool <- nonce:
	default:
		// Pool full, discard nonce
	}
}

// ============================================================================
// JWS Request Signing
// ============================================================================

// JWSHeader is the protected header for ACME requests
type JWSHeader struct {
	Algorithm string      `json:"alg"`
	Nonce     string      `json:"nonce"`
	URL       string      `json:"url"`
	KeyID     string      `json:"kid,omitempty"` // For account-bound requests
	JWK       interface{} `json:"jwk,omitempty"` // For new account requests
}

// signRequest creates a JWS-signed request body
func (c *Client) signRequest(payload interface{}, url, nonce string, useJWK bool) ([]byte, error) {
	// Encode payload
	var payloadB64 string
	if payload != nil {
		payloadJSON, err := json.Marshal(payload)
		if err != nil {
			return nil, err
		}
		payloadB64 = base64.RawURLEncoding.EncodeToString(payloadJSON)
	} else {
		payloadB64 = "" // POST-as-GET uses empty payload
	}

	// Build protected header
	header := JWSHeader{
		Algorithm: c.getSigningAlgorithm(),
		Nonce:     nonce,
		URL:       url,
	}

	if useJWK {
		header.JWK = c.getJWK()
	} else {
		header.KeyID = c.accountURL
	}

	headerJSON, err := json.Marshal(header)
	if err != nil {
		return nil, err
	}
	headerB64 := base64.RawURLEncoding.EncodeToString(headerJSON)

	// Create signature input
	signingInput := headerB64 + "." + payloadB64

	// Sign
	signature, err := c.sign([]byte(signingInput))
	if err != nil {
		return nil, err
	}
	signatureB64 := base64.RawURLEncoding.EncodeToString(signature)

	// Build flattened JWS
	jws := map[string]string{
		"protected": headerB64,
		"payload":   payloadB64,
		"signature": signatureB64,
	}

	return json.Marshal(jws)
}

// sign creates the signature for JWS
func (c *Client) sign(data []byte) ([]byte, error) {
	hash := sha256.Sum256(data)

	switch key := c.accountKey.(type) {
	case *rsa.PrivateKey:
		return rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA256, hash[:])

	case *ecdsa.PrivateKey:
		r, s, err := ecdsa.Sign(rand.Reader, key, hash[:])
		if err != nil {
			return nil, err
		}
		// ECDSA signature is r || s in fixed-size format
		keyBytes := (key.Curve.Params().BitSize + 7) / 8
		sig := make([]byte, keyBytes*2)
		r.FillBytes(sig[:keyBytes])
		s.FillBytes(sig[keyBytes:])
		return sig, nil

	default:
		return nil, fmt.Errorf("unsupported key type: %T", c.accountKey)
	}
}

// getSigningAlgorithm returns the JWS algorithm for the key type
func (c *Client) getSigningAlgorithm() string {
	switch key := c.accountKey.(type) {
	case *rsa.PrivateKey:
		return "RS256"
	case *ecdsa.PrivateKey:
		switch key.Curve.Params().BitSize {
		case 256:
			return "ES256"
		case 384:
			return "ES384"
		default:
			return "ES256"
		}
	default:
		return "RS256"
	}
}

// getJWK returns the JWK representation of the account public key
func (c *Client) getJWK() interface{} {
	switch key := c.accountKey.(type) {
	case *rsa.PrivateKey:
		return map[string]string{
			"kty": "RSA",
			"n":   base64.RawURLEncoding.EncodeToString(key.N.Bytes()),
			"e":   base64.RawURLEncoding.EncodeToString(big.NewInt(int64(key.E)).Bytes()),
		}
	case *ecdsa.PrivateKey:
		return map[string]string{
			"kty": "EC",
			"crv": key.Curve.Params().Name,
			"x":   base64.RawURLEncoding.EncodeToString(key.X.Bytes()),
			"y":   base64.RawURLEncoding.EncodeToString(key.Y.Bytes()),
		}
	default:
		return nil
	}
}

// ============================================================================
// HTTP Request Execution
// ============================================================================

// post sends a signed POST request to ACME endpoint
func (c *Client) post(ctx context.Context, url string, payload interface{}, useJWK bool) (*http.Response, error) {
	var lastErr error

	for attempt := 0; attempt < ClientMaxRetries; attempt++ {
		if attempt > 0 {
			time.Sleep(ClientRetryBackoff * time.Duration(1<<(attempt-1)))
		}

		// Get nonce
		nonce, err := c.getNonce(ctx)
		if err != nil {
			lastErr = err
			continue
		}

		// Sign request
		body, err := c.signRequest(payload, url, nonce, useJWK)
		if err != nil {
			return nil, err
		}

		// Build request
		req, err := http.NewRequestWithContext(ctx, "POST", url, bytes.NewReader(body))
		if err != nil {
			return nil, err
		}
		req.Header.Set("Content-Type", ContentTypeJOSE)
		req.Header.Set("User-Agent", UserAgentDefault)

		// Execute
		resp, err := c.httpClient.Do(req)
		if err != nil {
			lastErr = err
			continue
		}

		// Store new nonce from response
		if newNonce := resp.Header.Get("Replay-Nonce"); newNonce != "" {
			c.returnNonce(newNonce)
		}

		// Handle special status codes
		switch resp.StatusCode {
		case http.StatusBadRequest:
			// Check if it's a bad nonce error
			if c.isBadNonceError(resp) {
				resp.Body.Close()
				lastErr = ErrBadNonce
				continue
			}
		case http.StatusTooManyRequests:
			resp.Body.Close()
			lastErr = ErrRateLimited
			// Check Retry-After header
			if retryAfter := resp.Header.Get("Retry-After"); retryAfter != "" {
				// Parse and wait
			}
			continue
		}

		return resp, nil
	}

	return nil, fmt.Errorf("request failed after %d attempts: %w", ClientMaxRetries, lastErr)
}

// isBadNonceError checks if response is a bad nonce error
func (c *Client) isBadNonceError(resp *http.Response) bool {
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return false
	}
	return strings.Contains(string(body), "badNonce")
}

// postAsGet sends a POST-as-GET request (empty payload)
func (c *Client) postAsGet(ctx context.Context, url string) (*http.Response, error) {
	return c.post(ctx, url, nil, false)
}

// ============================================================================
// Account Operations
// ============================================================================

// SetAccount sets the account credentials for the client
func (c *Client) SetAccount(accountURL string, accountKey crypto.PrivateKey) {
	c.accountURL = accountURL
	c.accountKey = accountKey
}

// CreateAccount registers a new account with Let's Encrypt
func (c *Client) CreateAccount(ctx context.Context, email string, termsAgreed bool) (*Account, error) {
	if c.directory == nil {
		return nil, errors.New("directory not initialized")
	}

	payload := map[string]interface{}{
		"termsOfServiceAgreed": termsAgreed,
		"contact":              []string{"mailto:" + email},
	}

	resp, err := c.post(ctx, c.directory.NewAccount, payload, true)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusCreated {
		return nil, c.parseError(resp)
	}

	// Store account URL from Location header
	c.accountURL = resp.Header.Get("Location")

	var acctResp struct {
		Status  string   `json:"status"`
		Contact []string `json:"contact"`
		Orders  string   `json:"orders"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&acctResp); err != nil {
		return nil, err
	}

	return &Account{
		URL:      c.accountURL,
		Status:   acctResp.Status,
		Contacts: acctResp.Contact,
	}, nil
}

// ============================================================================
// Order Management
// ============================================================================

// Order represents an ACME certificate order
type Order struct {
	URL            string
	Status         string
	Expires        time.Time
	Identifiers    []Identifier
	Authorizations []string
	FinalizeURL    string
	CertificateURL string
	Error          *ACMEError
}

// CreateOrder initiates a new certificate order
func (c *Client) CreateOrder(ctx context.Context, domains []string) (*Order, error) {
	if c.directory == nil {
		return nil, errors.New("directory not initialized")
	}

	// Build identifiers
	identifiers := make([]map[string]string, len(domains))
	for i, domain := range domains {
		identifiers[i] = map[string]string{
			"type":  "dns",
			"value": domain,
		}
	}

	payload := map[string]interface{}{
		"identifiers": identifiers,
	}

	resp, err := c.post(ctx, c.directory.NewOrder, payload, false)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusCreated {
		return nil, c.parseError(resp)
	}

	return c.parseOrder(resp)
}

// GetOrder fetches current order status
func (c *Client) GetOrder(ctx context.Context, orderURL string) (*Order, error) {
	resp, err := c.postAsGet(ctx, orderURL)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, c.parseError(resp)
	}

	order, err := c.parseOrder(resp)
	if err != nil {
		return nil, err
	}
	order.URL = orderURL
	return order, nil
}

// parseOrder parses order response
func (c *Client) parseOrder(resp *http.Response) (*Order, error) {
	var orderResp struct {
		Status         string       `json:"status"`
		Expires        string       `json:"expires"`
		Identifiers    []Identifier `json:"identifiers"`
		Authorizations []string     `json:"authorizations"`
		Finalize       string       `json:"finalize"`
		Certificate    string       `json:"certificate"`
		Error          *ACMEError   `json:"error"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&orderResp); err != nil {
		return nil, err
	}

	order := &Order{
		URL:            resp.Header.Get("Location"),
		Status:         orderResp.Status,
		Identifiers:    orderResp.Identifiers,
		Authorizations: orderResp.Authorizations,
		FinalizeURL:    orderResp.Finalize,
		CertificateURL: orderResp.Certificate,
		Error:          orderResp.Error,
	}

	if orderResp.Expires != "" {
		order.Expires, _ = time.Parse(time.RFC3339, orderResp.Expires)
	}

	return order, nil
}

// FinalizeOrder submits CSR to finalize the order
func (c *Client) FinalizeOrder(ctx context.Context, finalizeURL string, csrDER []byte) (*Order, error) {
	payload := map[string]string{
		"csr": base64.RawURLEncoding.EncodeToString(csrDER),
	}

	resp, err := c.post(ctx, finalizeURL, payload, false)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, c.parseError(resp)
	}

	return c.parseOrder(resp)
}

// PollOrder waits for order to reach final state
func (c *Client) PollOrder(ctx context.Context, orderURL string) (*Order, error) {
	pollInterval := 2 * time.Second
	maxDuration := 5 * time.Minute
	deadline := time.Now().Add(maxDuration)

	for time.Now().Before(deadline) {
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		default:
		}

		order, err := c.GetOrder(ctx, orderURL)
		if err != nil {
			time.Sleep(pollInterval)
			continue
		}

		switch order.Status {
		case "valid":
			return order, nil
		case "invalid":
			if order.Error != nil {
				return nil, fmt.Errorf("%w: %s", ErrProtocolError, order.Error.Detail)
			}
			return nil, ErrProtocolError
		case "pending", "ready", "processing":
			time.Sleep(pollInterval)
			continue
		default:
			return nil, fmt.Errorf("unexpected order status: %s", order.Status)
		}
	}

	return nil, ErrValidationTimeout
}

// ============================================================================
// Authorization Handling
// ============================================================================

// GetAuthorization fetches authorization details
func (c *Client) GetAuthorization(ctx context.Context, authzURL string) (*Authorization, error) {
	resp, err := c.postAsGet(ctx, authzURL)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, c.parseError(resp)
	}

	var authz Authorization
	if err := json.NewDecoder(resp.Body).Decode(&authz); err != nil {
		return nil, err
	}

	return &authz, nil
}

// RespondToChallenge notifies CA that challenge is ready
func (c *Client) RespondToChallenge(ctx context.Context, challengeURL string) error {
	// Empty object payload triggers validation
	payload := map[string]interface{}{}

	resp, err := c.post(ctx, challengeURL, payload, false)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusAccepted {
		return c.parseError(resp)
	}

	return nil
}

// ============================================================================
// Certificate Retrieval
// ============================================================================

// CertificateBundle contains issued certificate and chain
type CertificateBundle struct {
	Certificate string   // Leaf certificate PEM
	Chain       []string // Intermediate certificates PEM
	FullChain   string   // Complete chain PEM
}

// GetCertificate downloads the issued certificate
func (c *Client) GetCertificate(ctx context.Context, certURL string) (*CertificateBundle, error) {
	resp, err := c.postAsGet(ctx, certURL)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, c.parseError(resp)
	}

	// Read PEM chain
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	return c.parseCertificateChain(string(body))
}

// parseCertificateChain separates leaf from intermediates
func (c *Client) parseCertificateChain(pemChain string) (*CertificateBundle, error) {
	certs := strings.Split(pemChain, "-----END CERTIFICATE-----")

	bundle := &CertificateBundle{
		FullChain: pemChain,
		Chain:     []string{},
	}

	for i, cert := range certs {
		cert = strings.TrimSpace(cert)
		if cert == "" {
			continue
		}
		cert += "-----END CERTIFICATE-----\n"

		if i == 0 {
			bundle.Certificate = cert
		} else {
			bundle.Chain = append(bundle.Chain, cert)
		}
	}

	return bundle, nil
}

// ============================================================================
// Certificate Revocation
// ============================================================================

// RevokeCertificate revokes a certificate
func (c *Client) RevokeCertificate(ctx context.Context, certDER []byte, reason int) error {
	if c.directory == nil {
		return errors.New("directory not initialized")
	}

	payload := map[string]interface{}{
		"certificate": base64.RawURLEncoding.EncodeToString(certDER),
	}

	if reason > 0 {
		payload["reason"] = reason
	}

	resp, err := c.post(ctx, c.directory.RevokeCert, payload, false)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return c.parseError(resp)
	}

	return nil
}

// ============================================================================
// Error Handling
// ============================================================================

// ACMEProblem represents an ACME problem document (RFC 7807)
type ACMEProblem struct {
	Type        string        `json:"type"`
	Detail      string        `json:"detail"`
	Status      int           `json:"status"`
	Instance    string        `json:"instance"`
	Subproblems []ACMEProblem `json:"subproblems,omitempty"`
}

// parseError extracts error from ACME response
func (c *Client) parseError(resp *http.Response) error {
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("HTTP %d: failed to read error body", resp.StatusCode)
	}

	var problem ACMEProblem
	if err := json.Unmarshal(body, &problem); err != nil {
		return fmt.Errorf("HTTP %d: %s", resp.StatusCode, string(body))
	}

	return fmt.Errorf("%s: %s", problem.Type, problem.Detail)
}

// ============================================================================
// High-Level Certificate Issuance
// ============================================================================

// IssueCertificate completes full certificate issuance workflow
func (c *Client) IssueCertificate(ctx context.Context, domains []string, csrDER []byte) (*CertificateBundle, error) {
	// Create order
	order, err := c.CreateOrder(ctx, domains)
	if err != nil {
		return nil, fmt.Errorf("failed to create order: %w", err)
	}

	// Complete authorizations
	if c.validator != nil {
		results, err := c.validator.ValidateMultiple(ctx, order.Authorizations)
		if err != nil {
			return nil, fmt.Errorf("authorization failed: %w", err)
		}

		// Check all succeeded
		for _, result := range results {
			if !result.Success {
				return nil, fmt.Errorf("validation failed for %s: %s", result.Domain, result.Error)
			}
		}
	}

	// Finalize order
	order, err = c.FinalizeOrder(ctx, order.FinalizeURL, csrDER)
	if err != nil {
		return nil, fmt.Errorf("failed to finalize order: %w", err)
	}

	// Poll until certificate is ready
	if order.Status != "valid" {
		order, err = c.PollOrder(ctx, order.URL)
		if err != nil {
			return nil, fmt.Errorf("order polling failed: %w", err)
		}
	}

	// Download certificate
	if order.CertificateURL == "" {
		return nil, ErrCertificateNotReady
	}

	cert, err := c.GetCertificate(ctx, order.CertificateURL)
	if err != nil {
		return nil, fmt.Errorf("failed to download certificate: %w", err)
	}

	return cert, nil
}
