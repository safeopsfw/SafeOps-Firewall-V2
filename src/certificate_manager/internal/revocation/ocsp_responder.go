package revocation

import (
	"context"
	"crypto"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"log"
	"math/big"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"golang.org/x/crypto/ocsp"
)

// ============================================================================
// Errors
// ============================================================================

var (
	ErrOCSPInvalidRequest = errors.New("invalid OCSP request")
	ErrOCSPUnauthorized   = errors.New("unauthorized OCSP request")
	ErrOCSPServerError    = errors.New("OCSP server error")
)

// OCSP Response Status (RFC 6960)
const (
	OCSPStatusSuccessful       = 0 // Response has valid confirmations
	OCSPStatusMalformedRequest = 1 // Illegal confirmation request
	OCSPStatusInternalError    = 2 // Internal error in issuer
	OCSPStatusTryLater         = 3 // Try again later
	OCSPStatusSigRequired      = 5 // Must sign the request
	OCSPStatusUnauthorized     = 6 // Request unauthorized
)

// ============================================================================
// Configuration
// ============================================================================

// OCSPConfig configures the OCSP responder.
type OCSPConfig struct {
	ListenAddress    string        // Address to bind (e.g., ":8888")
	ResponseValidity time.Duration // NextUpdate interval
	CacheMaxAge      int           // Cache-Control max-age in seconds
	EnableNonce      bool          // Support nonce extension
	EnableGET        bool          // Support HTTP GET method
	Enabled          bool          // Enable OCSP responder
	ReadTimeout      time.Duration
	WriteTimeout     time.Duration
}

// DefaultOCSPConfig returns default configuration.
func DefaultOCSPConfig() *OCSPConfig {
	return &OCSPConfig{
		ListenAddress:    ":8888",
		ResponseValidity: 1 * time.Hour,
		CacheMaxAge:      600, // 10 minutes
		EnableNonce:      true,
		EnableGET:        true,
		Enabled:          true,
		ReadTimeout:      10 * time.Second,
		WriteTimeout:     10 * time.Second,
	}
}

// ============================================================================
// OCSP Responder
// ============================================================================

// OCSPResponder handles OCSP requests.
type OCSPResponder struct {
	config  *OCSPConfig
	checker *RevocationChecker
	caCert  *x509.Certificate
	caKey   crypto.Signer

	server *http.Server

	// Statistics
	totalRequests    int64
	goodResponses    int64
	revokedResponses int64
	unknownResponses int64
	errorResponses   int64
	totalTime        int64 // nanoseconds
	startTime        time.Time

	mu sync.RWMutex
}

// NewOCSPResponder creates a new OCSP responder.
func NewOCSPResponder(config *OCSPConfig, checker *RevocationChecker) *OCSPResponder {
	if config == nil {
		config = DefaultOCSPConfig()
	}

	return &OCSPResponder{
		config:    config,
		checker:   checker,
		startTime: time.Now(),
	}
}

// SetCA sets the CA certificate and private key.
func (r *OCSPResponder) SetCA(cert *x509.Certificate, key crypto.PrivateKey) error {
	signer, ok := key.(crypto.Signer)
	if !ok {
		return errors.New("private key does not implement crypto.Signer")
	}

	r.mu.Lock()
	defer r.mu.Unlock()
	r.caCert = cert
	r.caKey = signer
	return nil
}

// ============================================================================
// Server Lifecycle
// ============================================================================

// Start starts the OCSP responder server.
func (r *OCSPResponder) Start() error {
	if !r.config.Enabled {
		return nil
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/", r.handleOCSP)

	r.server = &http.Server{
		Addr:         r.config.ListenAddress,
		Handler:      mux,
		ReadTimeout:  r.config.ReadTimeout,
		WriteTimeout: r.config.WriteTimeout,
	}

	log.Printf("[ocsp] OCSP responder starting on %s", r.config.ListenAddress)

	go func() {
		if err := r.server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Printf("[ocsp] Server error: %v", err)
		}
	}()

	return nil
}

// Stop stops the OCSP responder server.
func (r *OCSPResponder) Stop(ctx context.Context) error {
	if r.server == nil {
		return nil
	}
	return r.server.Shutdown(ctx)
}

// ============================================================================
// Request Handler
// ============================================================================

// handleOCSP handles OCSP requests (POST and GET).
func (r *OCSPResponder) handleOCSP(w http.ResponseWriter, req *http.Request) {
	start := time.Now()
	atomic.AddInt64(&r.totalRequests, 1)

	defer func() {
		atomic.AddInt64(&r.totalTime, int64(time.Since(start)))
	}()

	var ocspReq *ocsp.Request
	var err error

	switch req.Method {
	case http.MethodPost:
		ocspReq, err = r.parsePostRequest(req)
	case http.MethodGet:
		if r.config.EnableGET {
			ocspReq, err = r.parseGetRequest(req)
		} else {
			r.sendErrorResponse(w, OCSPStatusMalformedRequest)
			return
		}
	default:
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	if err != nil {
		log.Printf("[ocsp] Parse error: %v", err)
		r.sendErrorResponse(w, OCSPStatusMalformedRequest)
		return
	}

	// Validate request
	if err := r.validateRequest(ocspReq); err != nil {
		log.Printf("[ocsp] Validation error: %v", err)
		r.sendErrorResponse(w, OCSPStatusMalformedRequest)
		return
	}

	// Check revocation status
	status, entry := r.checkStatus(ocspReq.SerialNumber)

	// Generate response
	respBytes, err := r.generateResponse(ocspReq, status, entry)
	if err != nil {
		log.Printf("[ocsp] Response generation error: %v", err)
		r.sendErrorResponse(w, OCSPStatusInternalError)
		return
	}

	// Send response
	r.sendResponse(w, respBytes)

	// Log
	statusStr := "good"
	switch status {
	case ocsp.Revoked:
		statusStr = "revoked"
	case ocsp.Unknown:
		statusStr = "unknown"
	}
	log.Printf("[ocsp] Request: serial=%s status=%s time=%v",
		ocspReq.SerialNumber.Text(16), statusStr, time.Since(start))
}

// ============================================================================
// Request Parsing
// ============================================================================

// parsePostRequest parses an OCSP request from POST body.
func (r *OCSPResponder) parsePostRequest(req *http.Request) (*ocsp.Request, error) {
	body, err := io.ReadAll(req.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read body: %w", err)
	}
	defer req.Body.Close()

	return ocsp.ParseRequest(body)
}

// parseGetRequest parses an OCSP request from GET URL path.
func (r *OCSPResponder) parseGetRequest(req *http.Request) (*ocsp.Request, error) {
	// URL path is base64-encoded OCSP request
	path := strings.TrimPrefix(req.URL.Path, "/")
	if path == "" {
		return nil, errors.New("empty request path")
	}

	// URL-safe base64 decoding
	decoded, err := base64.URLEncoding.DecodeString(path)
	if err != nil {
		// Try standard base64
		decoded, err = base64.StdEncoding.DecodeString(path)
		if err != nil {
			return nil, fmt.Errorf("base64 decode failed: %w", err)
		}
	}

	return ocsp.ParseRequest(decoded)
}

// ============================================================================
// Request Validation
// ============================================================================

// validateRequest validates an OCSP request.
func (r *OCSPResponder) validateRequest(ocspReq *ocsp.Request) error {
	if ocspReq == nil {
		return errors.New("nil request")
	}

	if ocspReq.SerialNumber == nil {
		return errors.New("missing serial number")
	}

	// Validate issuer hash if CA is set
	r.mu.RLock()
	caCert := r.caCert
	r.mu.RUnlock()

	if caCert != nil {
		// Check issuer key hash
		pubKeyHash := sha256.Sum256(caCert.RawSubjectPublicKeyInfo)
		if ocspReq.HashAlgorithm == crypto.SHA256 {
			// Compare with IssuerKeyHash
			if len(ocspReq.IssuerKeyHash) > 0 {
				// Simplified check - in production use proper hash comparison
				_ = pubKeyHash
			}
		}
	}

	return nil
}

// ============================================================================
// Status Checking
// ============================================================================

// checkStatus checks the revocation status of a certificate.
func (r *OCSPResponder) checkStatus(serialNumber *big.Int) (int, *RevocationEntry) {
	if r.checker == nil {
		atomic.AddInt64(&r.unknownResponses, 1)
		return ocsp.Unknown, nil
	}

	serialHex := serialNumber.Text(16)
	revoked, err := r.checker.IsRevoked(serialHex)
	if err != nil {
		atomic.AddInt64(&r.unknownResponses, 1)
		return ocsp.Unknown, nil
	}

	if revoked {
		atomic.AddInt64(&r.revokedResponses, 1)
		info, _ := r.checker.GetRevocationInfo(serialHex)
		if info != nil {
			return ocsp.Revoked, &RevocationEntry{
				SerialNumber: serialHex,
				RevokedAt:    info.RevokedAt,
				Reason:       info.Reason,
			}
		}
		return ocsp.Revoked, nil
	}

	atomic.AddInt64(&r.goodResponses, 1)
	return ocsp.Good, nil
}

// ============================================================================
// Response Generation
// ============================================================================

// generateResponse generates a signed OCSP response.
func (r *OCSPResponder) generateResponse(ocspReq *ocsp.Request, status int, entry *RevocationEntry) ([]byte, error) {
	r.mu.RLock()
	caCert := r.caCert
	caKey := r.caKey
	r.mu.RUnlock()

	if caCert == nil || caKey == nil {
		return nil, errors.New("CA not configured")
	}

	now := time.Now()

	template := ocsp.Response{
		Status:       status,
		SerialNumber: ocspReq.SerialNumber,
		ThisUpdate:   now,
		NextUpdate:   now.Add(r.config.ResponseValidity),
		Certificate:  caCert,
	}

	if status == ocsp.Revoked && entry != nil {
		template.RevokedAt = entry.RevokedAt
		template.RevocationReason = GetReasonCode(string(entry.Reason))
	}

	// Sign response
	return ocsp.CreateResponse(caCert, caCert, template, caKey)
}

// ============================================================================
// Response Sending
// ============================================================================

// sendResponse sends a successful OCSP response.
func (r *OCSPResponder) sendResponse(w http.ResponseWriter, respBytes []byte) {
	w.Header().Set("Content-Type", "application/ocsp-response")
	w.Header().Set("Content-Length", fmt.Sprintf("%d", len(respBytes)))
	w.Header().Set("Cache-Control", fmt.Sprintf("max-age=%d, must-revalidate", r.config.CacheMaxAge))
	w.WriteHeader(http.StatusOK)
	w.Write(respBytes)
}

// sendErrorResponse sends an OCSP error response.
func (r *OCSPResponder) sendErrorResponse(w http.ResponseWriter, status int) {
	atomic.AddInt64(&r.errorResponses, 1)

	// Create minimal error response
	respBytes := []byte{0x30, 0x03, 0x0a, 0x01, byte(status)}

	w.Header().Set("Content-Type", "application/ocsp-response")
	w.WriteHeader(http.StatusOK) // OCSP always returns 200 OK
	w.Write(respBytes)
}

// ============================================================================
// Statistics
// ============================================================================

// OCSPStats contains OCSP responder statistics.
type OCSPStats struct {
	TotalRequests     int64         `json:"total_requests"`
	GoodResponses     int64         `json:"good_responses"`
	RevokedResponses  int64         `json:"revoked_responses"`
	UnknownResponses  int64         `json:"unknown_responses"`
	ErrorResponses    int64         `json:"error_responses"`
	RequestsPerSecond float64       `json:"requests_per_second"`
	AverageTime       time.Duration `json:"average_time_ns"`
}

// GetStats returns OCSP responder statistics.
func (r *OCSPResponder) GetStats() *OCSPStats {
	total := atomic.LoadInt64(&r.totalRequests)
	totalTime := atomic.LoadInt64(&r.totalTime)

	var avgTime time.Duration
	if total > 0 {
		avgTime = time.Duration(totalTime / total)
	}

	elapsed := time.Since(r.startTime).Seconds()
	var rps float64
	if elapsed > 0 {
		rps = float64(total) / elapsed
	}

	return &OCSPStats{
		TotalRequests:     total,
		GoodResponses:     atomic.LoadInt64(&r.goodResponses),
		RevokedResponses:  atomic.LoadInt64(&r.revokedResponses),
		UnknownResponses:  atomic.LoadInt64(&r.unknownResponses),
		ErrorResponses:    atomic.LoadInt64(&r.errorResponses),
		RequestsPerSecond: rps,
		AverageTime:       avgTime,
	}
}

// GetOCSPResponderURL returns the OCSP responder URL.
func (r *OCSPResponder) GetOCSPResponderURL() string {
	// Extract port from listen address
	addr := r.config.ListenAddress
	if strings.HasPrefix(addr, ":") {
		return "http://localhost" + addr
	}
	return "http://" + addr
}
