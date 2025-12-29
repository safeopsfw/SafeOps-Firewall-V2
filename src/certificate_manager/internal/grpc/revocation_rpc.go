// Package grpc implements gRPC service handlers for the Certificate Manager.
package grpc

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"log"
	"strings"
	"sync"
	"time"

	"certificate_manager/pkg/types"
)

// ============================================================================
// Revocation Status Types (mirrors proto messages)
// ============================================================================

// RevocationReason represents the reason for certificate revocation.
type RevocationReason int

const (
	ReasonUnspecified          RevocationReason = 0
	ReasonKeyCompromise        RevocationReason = 1
	ReasonCACompromise         RevocationReason = 2
	ReasonAffiliationChanged   RevocationReason = 3
	ReasonSuperseded           RevocationReason = 4
	ReasonCessationOfOperation RevocationReason = 5
	ReasonCertificateHold      RevocationReason = 6
	ReasonRemoveFromCRL        RevocationReason = 8
)

// RevocationReasonDescription returns human-readable description.
func RevocationReasonDescription(reason RevocationReason) string {
	descriptions := map[RevocationReason]string{
		ReasonUnspecified:          "Unspecified",
		ReasonKeyCompromise:        "Key Compromise",
		ReasonCACompromise:         "CA Compromise",
		ReasonAffiliationChanged:   "Affiliation Changed",
		ReasonSuperseded:           "Superseded",
		ReasonCessationOfOperation: "Cessation of Operation",
		ReasonCertificateHold:      "Certificate Hold",
		ReasonRemoveFromCRL:        "Remove from CRL",
	}
	if desc, ok := descriptions[reason]; ok {
		return desc
	}
	return "Unknown"
}

// Allowed revocation reasons (string format for validation)
var allowedRevocationReasons = map[string]RevocationReason{
	"compromised":            ReasonKeyCompromise,
	"key_compromise":         ReasonKeyCompromise,
	"superseded":             ReasonSuperseded,
	"cessation_of_operation": ReasonCessationOfOperation,
	"affiliation_changed":    ReasonAffiliationChanged,
	"privilege_withdrawn":    ReasonCertificateHold, // Map to certificate hold
	"ca_compromise":          ReasonCACompromise,
	"unspecified":            ReasonUnspecified,
}

// ValidateSerialNumber validates hex format of serial number.
func ValidateSerialNumber(serial string) error {
	if serial == "" {
		return errors.New("serial_number required")
	}

	// Remove any spaces or colons
	normalized := strings.ReplaceAll(strings.ReplaceAll(serial, ":", ""), " ", "")

	// Check if valid hex
	_, err := hex.DecodeString(normalized)
	if err != nil {
		return fmt.Errorf("invalid serial number format (expected hex string): %s", serial)
	}

	return nil
}

// ParseRevocationReason parses string reason to RevocationReason.
func ParseRevocationReason(reason string) (RevocationReason, error) {
	normalized := strings.ToLower(strings.TrimSpace(reason))
	if r, ok := allowedRevocationReasons[normalized]; ok {
		return r, nil
	}

	allowedList := make([]string, 0, len(allowedRevocationReasons))
	for k := range allowedRevocationReasons {
		allowedList = append(allowedList, k)
	}
	return 0, fmt.Errorf("invalid revocation reason. Must be one of: %s", strings.Join(allowedList, ", "))
}

// CheckRevocationStatusRequest for querying revocation status.
type CheckRevocationStatusRequest struct {
	SerialNumber string `json:"serial_number"`
	IssuerDN     string `json:"issuer_dn"`
}

// RevocationStatusResponse contains certificate revocation status.
type RevocationStatusResponse struct {
	IsRevoked         bool             `json:"is_revoked"`
	RevokedAt         time.Time        `json:"revoked_at"`
	RevocationReason  RevocationReason `json:"revocation_reason"`
	ReasonDescription string           `json:"reason_description"`
	ThisUpdate        time.Time        `json:"this_update"`
	NextUpdate        time.Time        `json:"next_update"`
	Found             bool             `json:"found"`
}

// RevokeCertificateRequest for revoking a certificate.
type RevokeCertificateRequest struct {
	SerialNumber string           `json:"serial_number"`
	Reason       RevocationReason `json:"reason"`
	RevokedBy    string           `json:"revoked_by"`
}

// RevokeCertificateResponse after revoking.
type RevokeCertificateResponse struct {
	Success      bool      `json:"success"`
	SerialNumber string    `json:"serial_number"`
	RevokedAt    time.Time `json:"revoked_at"`
	CRLUpdatedAt time.Time `json:"crl_updated_at"`
	Message      string    `json:"message"`
}

// ============================================================================
// Revocation Store Interface
// ============================================================================

// RevocationStore defines the interface for revocation data persistence.
type RevocationStore interface {
	GetRevocationStatus(ctx context.Context, serialNumber string) (*RevokedCertificate, error)
	RevokeCertificate(ctx context.Context, record *RevokedCertificate) error
	ListRevokedCertificates(ctx context.Context, filter RevocationFilter) ([]*RevokedCertificate, error)
	GetCRLEntries(ctx context.Context) ([]*RevokedCertificate, error)
}

// RevokedCertificate represents a revoked certificate record.
type RevokedCertificate struct {
	ID                    int64            `json:"id"`
	SerialNumber          string           `json:"serial_number"`
	RevokedAt             time.Time        `json:"revoked_at"`
	RevocationReason      RevocationReason `json:"revocation_reason"`
	CertificateCommonName string           `json:"certificate_common_name"`
	RevokedBy             string           `json:"revoked_by"`
	IssuerDN              string           `json:"issuer_dn"`
	CreatedAt             time.Time        `json:"created_at"`
}

// RevocationFilter for listing revoked certificates.
type RevocationFilter struct {
	Reason    *RevocationReason
	RevokedBy string
	Since     time.Time
	Limit     int
	Offset    int
}

// ============================================================================
// In-Memory Revocation Store (for development/testing)
// ============================================================================

// InMemoryRevocationStore provides an in-memory implementation.
type InMemoryRevocationStore struct {
	revoked map[string]*RevokedCertificate // key: serial number
	mu      sync.RWMutex
}

// NewInMemoryRevocationStore creates a new in-memory revocation store.
func NewInMemoryRevocationStore() *InMemoryRevocationStore {
	return &InMemoryRevocationStore{
		revoked: make(map[string]*RevokedCertificate),
	}
}

// GetRevocationStatus retrieves revocation status for a serial number.
func (s *InMemoryRevocationStore) GetRevocationStatus(ctx context.Context, serialNumber string) (*RevokedCertificate, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	if record, exists := s.revoked[serialNumber]; exists {
		return record, nil
	}
	return nil, errors.New("certificate not found in revocation list")
}

// RevokeCertificate adds a certificate to the revocation list.
func (s *InMemoryRevocationStore) RevokeCertificate(ctx context.Context, record *RevokedCertificate) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if _, exists := s.revoked[record.SerialNumber]; exists {
		return errors.New("certificate already revoked")
	}

	record.CreatedAt = time.Now()
	s.revoked[record.SerialNumber] = record
	return nil
}

// ListRevokedCertificates returns revoked certificates matching filter.
func (s *InMemoryRevocationStore) ListRevokedCertificates(ctx context.Context, filter RevocationFilter) ([]*RevokedCertificate, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	var results []*RevokedCertificate
	for _, record := range s.revoked {
		// Apply filters
		if filter.Reason != nil && record.RevocationReason != *filter.Reason {
			continue
		}
		if filter.RevokedBy != "" && record.RevokedBy != filter.RevokedBy {
			continue
		}
		if !filter.Since.IsZero() && record.RevokedAt.Before(filter.Since) {
			continue
		}
		results = append(results, record)
	}

	// Apply limit/offset
	if filter.Offset > 0 && filter.Offset < len(results) {
		results = results[filter.Offset:]
	}
	if filter.Limit > 0 && filter.Limit < len(results) {
		results = results[:filter.Limit]
	}

	return results, nil
}

// GetCRLEntries returns all revoked certificates for CRL generation.
func (s *InMemoryRevocationStore) GetCRLEntries(ctx context.Context) ([]*RevokedCertificate, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	results := make([]*RevokedCertificate, 0, len(s.revoked))
	for _, record := range s.revoked {
		results = append(results, record)
	}
	return results, nil
}

// ============================================================================
// Revocation RPC Handler
// ============================================================================

// AuditLogger interface for logging security events.
type AuditLogger interface {
	LogRevocation(ctx context.Context, serialNumber, commonName, revokedBy, reason, clientIP string, success bool) error
}

// RevocationHandler handles certificate revocation RPC requests.
type RevocationHandler struct {
	store         RevocationStore
	config        *types.Config
	auditLogger   AuditLogger
	crlUpdateTime time.Time
	mu            sync.RWMutex
}

// NewRevocationHandler creates a new revocation handler.
func NewRevocationHandler(store RevocationStore, cfg *types.Config) *RevocationHandler {
	if store == nil {
		store = NewInMemoryRevocationStore()
	}
	return &RevocationHandler{
		store:         store,
		config:        cfg,
		crlUpdateTime: time.Now(),
	}
}

// CheckRevocationStatus checks if a certificate is revoked.
// This implements the OCSP-like functionality for real-time revocation checking.
// This is a public method - no authentication required.
func (h *RevocationHandler) CheckRevocationStatus(ctx context.Context, req *CheckRevocationStatusRequest) (*RevocationStatusResponse, error) {
	// Validate serial number format
	if err := ValidateSerialNumber(req.SerialNumber); err != nil {
		return nil, err
	}

	log.Printf("[Revocation] Checking status for serial: %s", req.SerialNumber)

	// Query store (uses in-memory cache first for performance)
	record, err := h.store.GetRevocationStatus(ctx, req.SerialNumber)

	response := &RevocationStatusResponse{
		ThisUpdate: time.Now(),
		NextUpdate: time.Now().Add(1 * time.Hour), // OCSP response validity
	}

	if err != nil {
		// Not found = not revoked (good status)
		response.IsRevoked = false
		response.Found = false
		log.Printf("[Revocation] Serial %s: NOT REVOKED (not in revocation list)", req.SerialNumber)
		return response, nil
	}

	// Found in revocation list
	response.IsRevoked = true
	response.Found = true
	response.RevokedAt = record.RevokedAt
	response.RevocationReason = record.RevocationReason
	response.ReasonDescription = RevocationReasonDescription(record.RevocationReason)

	log.Printf("[Revocation] Serial %s: REVOKED at %s reason=%s",
		req.SerialNumber, record.RevokedAt.Format(time.RFC3339), response.ReasonDescription)

	return response, nil
}

// RevokeCertificate revokes a certificate and updates the CRL.
// This is an administrative operation requiring admin role.
// Authorization is enforced by middleware interceptor.
func (h *RevocationHandler) RevokeCertificate(ctx context.Context, req *RevokeCertificateRequest) (*RevokeCertificateResponse, error) {
	// Validate serial number format
	if err := ValidateSerialNumber(req.SerialNumber); err != nil {
		return nil, err
	}

	// Validate revoked_by is provided
	if req.RevokedBy == "" {
		return nil, errors.New("revoked_by (administrator identifier) required")
	}

	log.Printf("[Revocation] Revoking certificate: serial=%s reason=%s by=%s",
		req.SerialNumber, RevocationReasonDescription(req.Reason), req.RevokedBy)

	// Check if already revoked
	existing, _ := h.store.GetRevocationStatus(ctx, req.SerialNumber)
	if existing != nil {
		// Return AlreadyExists equivalent
		return &RevokeCertificateResponse{
			Success:      false,
			SerialNumber: req.SerialNumber,
			RevokedAt:    existing.RevokedAt,
			Message:      fmt.Sprintf("Certificate already revoked on %s", existing.RevokedAt.Format("2006-01-02")),
		}, nil
	}

	// Create revocation record
	record := &RevokedCertificate{
		SerialNumber:     req.SerialNumber,
		RevokedAt:        time.Now(),
		RevocationReason: req.Reason,
		RevokedBy:        req.RevokedBy,
	}

	if err := h.store.RevokeCertificate(ctx, record); err != nil {
		log.Printf("[Revocation] Database error revoking serial=%s: %v", req.SerialNumber, err)
		return nil, errors.New("unable to revoke certificate, please retry")
	}

	// Update CRL timestamp (triggers CRL regeneration)
	h.mu.Lock()
	h.crlUpdateTime = time.Now()
	h.mu.Unlock()

	// Log to audit trail
	if h.auditLogger != nil {
		clientIP := "unknown"
		if authInfo := GetAuthInfo(ctx); authInfo != nil {
			clientIP = authInfo.ClientIP
		}
		h.auditLogger.LogRevocation(ctx, req.SerialNumber, record.CertificateCommonName,
			req.RevokedBy, RevocationReasonDescription(req.Reason), clientIP, true)
	}

	log.Printf("[Revocation] Certificate revoked successfully: serial=%s", req.SerialNumber)

	return &RevokeCertificateResponse{
		Success:      true,
		SerialNumber: req.SerialNumber,
		RevokedAt:    record.RevokedAt,
		CRLUpdatedAt: h.crlUpdateTime,
		Message:      "Certificate revoked successfully",
	}, nil
}

// GetCRLUpdateTime returns the last CRL update timestamp.
func (h *RevocationHandler) GetCRLUpdateTime() time.Time {
	h.mu.RLock()
	defer h.mu.RUnlock()
	return h.crlUpdateTime
}

// GetCRLEntries returns all revoked certificates for CRL generation.
func (h *RevocationHandler) GetCRLEntries(ctx context.Context) ([]*RevokedCertificate, error) {
	return h.store.GetCRLEntries(ctx)
}

// ============================================================================
// Revocation Statistics
// ============================================================================

// RevocationStats contains aggregate revocation statistics.
type RevocationStats struct {
	TotalRevoked    int            `json:"total_revoked"`
	RevokedToday    int            `json:"revoked_today"`
	RevokedThisWeek int            `json:"revoked_this_week"`
	ByReason        map[string]int `json:"by_reason"`
	LastCRLUpdate   time.Time      `json:"last_crl_update"`
	NextCRLUpdate   time.Time      `json:"next_crl_update"`
}

// GetRevocationStats returns aggregate revocation statistics.
func (h *RevocationHandler) GetRevocationStats(ctx context.Context) (*RevocationStats, error) {
	entries, err := h.store.GetCRLEntries(ctx)
	if err != nil {
		return nil, err
	}

	stats := &RevocationStats{
		ByReason:      make(map[string]int),
		LastCRLUpdate: h.GetCRLUpdateTime(),
		NextCRLUpdate: h.GetCRLUpdateTime().Add(24 * time.Hour),
	}

	today := time.Now().Truncate(24 * time.Hour)
	weekAgo := today.AddDate(0, 0, -7)

	for _, entry := range entries {
		stats.TotalRevoked++

		if entry.RevokedAt.After(today) {
			stats.RevokedToday++
		}
		if entry.RevokedAt.After(weekAgo) {
			stats.RevokedThisWeek++
		}

		reasonDesc := RevocationReasonDescription(entry.RevocationReason)
		stats.ByReason[reasonDesc]++
	}

	return stats, nil
}

// ============================================================================
// OCSP Response Building
// ============================================================================

// OCSPResponse represents an OCSP response (simplified).
type OCSPResponse struct {
	Status           string    `json:"status"` // good, revoked, unknown
	SerialNumber     string    `json:"serial_number"`
	RevokedAt        time.Time `json:"revoked_at,omitempty"`
	RevocationReason int       `json:"revocation_reason,omitempty"`
	ThisUpdate       time.Time `json:"this_update"`
	NextUpdate       time.Time `json:"next_update"`
	ProducedAt       time.Time `json:"produced_at"`
}

// BuildOCSPResponse creates an OCSP response for a certificate.
func (h *RevocationHandler) BuildOCSPResponse(ctx context.Context, serialNumber string) (*OCSPResponse, error) {
	resp := &OCSPResponse{
		SerialNumber: serialNumber,
		ProducedAt:   time.Now(),
		ThisUpdate:   time.Now(),
		NextUpdate:   time.Now().Add(1 * time.Hour),
	}

	record, err := h.store.GetRevocationStatus(ctx, serialNumber)
	if err != nil {
		// Not found = good
		resp.Status = "good"
		return resp, nil
	}

	// Found = revoked
	resp.Status = "revoked"
	resp.RevokedAt = record.RevokedAt
	resp.RevocationReason = int(record.RevocationReason)

	return resp, nil
}
