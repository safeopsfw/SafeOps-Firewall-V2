package revocation

import (
	"crypto/x509"
	"encoding/hex"
	"strings"
	"sync/atomic"
	"time"
)

// ============================================================================
// Revocation Info
// ============================================================================

// RevocationInfo contains detailed revocation information.
type RevocationInfo struct {
	IsRevoked    bool             `json:"is_revoked"`
	SerialNumber string           `json:"serial_number"`
	RevokedAt    time.Time        `json:"revoked_at,omitempty"`
	Reason       RevocationReason `json:"reason,omitempty"`
	ReasonCode   int              `json:"reason_code,omitempty"`
	CommonName   string           `json:"common_name,omitempty"`
	RevokedBy    string           `json:"revoked_by,omitempty"`
}

// ============================================================================
// Reason Codes (RFC 5280)
// ============================================================================

// ReasonCode converts revocation reason to RFC 5280 CRLReason code.
var reasonCodes = map[RevocationReason]int{
	ReasonUnspecified:          0,
	ReasonKeyCompromise:        1,
	ReasonCACompromise:         2,
	ReasonAffiliationChanged:   3,
	ReasonSuperseded:           4,
	ReasonCessationOfOperation: 5,
	ReasonCertificateHold:      6,
	ReasonRemoveFromCRL:        8,
	ReasonPrivilegeWithdrawn:   9,
	ReasonAACompromise:         10,
}

// GetReasonCode returns the RFC 5280 CRLReason code for a reason string.
func GetReasonCode(reason string) int {
	if code, ok := reasonCodes[RevocationReason(reason)]; ok {
		return code
	}
	return 0 // unspecified
}

// GetReasonFromCode returns the reason string for an RFC 5280 code.
func GetReasonFromCode(code int) RevocationReason {
	for reason, c := range reasonCodes {
		if c == code {
			return reason
		}
	}
	return ReasonUnspecified
}

// ============================================================================
// Check Statistics
// ============================================================================

// CheckStats contains revocation check statistics.
type CheckStats struct {
	TotalChecks      int64         `json:"total_checks"`
	RevokedFound     int64         `json:"revoked_found"`
	NotRevokedFound  int64         `json:"not_revoked_found"`
	ChecksPerSecond  float64       `json:"checks_per_second"`
	AverageCheckTime time.Duration `json:"average_check_time_ns"`
}

// ============================================================================
// Revocation Checker
// ============================================================================

// RevocationChecker provides a high-level API for revocation checking.
type RevocationChecker struct {
	storage *RevocationStorage

	// Configuration
	enabled  bool
	failOpen bool // If check fails, allow (true) or deny (false)

	// Statistics
	totalChecks     int64
	revokedFound    int64
	notRevokedFound int64
	totalCheckTime  int64 // nanoseconds
	startTime       time.Time
}

// NewRevocationChecker creates a new revocation checker.
func NewRevocationChecker(storage *RevocationStorage) *RevocationChecker {
	return &RevocationChecker{
		storage:   storage,
		enabled:   true,
		failOpen:  false,
		startTime: time.Now(),
	}
}

// SetEnabled enables or disables revocation checking.
func (c *RevocationChecker) SetEnabled(enabled bool) {
	c.enabled = enabled
}

// SetFailOpen sets fail-open behavior (true = allow on error, false = deny).
func (c *RevocationChecker) SetFailOpen(failOpen bool) {
	c.failOpen = failOpen
}

// ============================================================================
// Core Check Methods
// ============================================================================

// IsRevoked checks if a certificate is revoked by serial number.
func (c *RevocationChecker) IsRevoked(serialNumber string) (bool, error) {
	if !c.enabled {
		return false, nil
	}

	start := time.Now()
	defer func() {
		atomic.AddInt64(&c.totalCheckTime, int64(time.Since(start)))
		atomic.AddInt64(&c.totalChecks, 1)
	}()

	normalized := NormalizeSerialNumber(serialNumber)

	if c.storage == nil {
		if c.failOpen {
			return false, nil
		}
		return true, ErrRevocationNotFound // Fail closed
	}

	revoked, _ := c.storage.IsRevoked(normalized)

	if revoked {
		atomic.AddInt64(&c.revokedFound, 1)
	} else {
		atomic.AddInt64(&c.notRevokedFound, 1)
	}

	return revoked, nil
}

// GetRevocationInfo returns detailed revocation information.
func (c *RevocationChecker) GetRevocationInfo(serialNumber string) (*RevocationInfo, error) {
	if !c.enabled {
		return &RevocationInfo{IsRevoked: false, SerialNumber: serialNumber}, nil
	}

	normalized := NormalizeSerialNumber(serialNumber)

	if c.storage == nil {
		return nil, ErrRevocationNotFound
	}

	revoked, entry := c.storage.IsRevoked(normalized)

	if !revoked {
		return &RevocationInfo{
			IsRevoked:    false,
			SerialNumber: normalized,
		}, nil
	}

	return &RevocationInfo{
		IsRevoked:    true,
		SerialNumber: entry.SerialNumber,
		RevokedAt:    entry.RevokedAt,
		Reason:       entry.Reason,
		ReasonCode:   GetReasonCode(string(entry.Reason)),
		CommonName:   entry.CommonName,
		RevokedBy:    entry.RevokedBy,
	}, nil
}

// IsCertificateRevoked checks revocation using an x509.Certificate object.
func (c *RevocationChecker) IsCertificateRevoked(cert *x509.Certificate) (bool, error) {
	if cert == nil {
		return false, nil
	}

	// Convert big.Int serial number to hex string
	serialHex := cert.SerialNumber.Text(16)
	return c.IsRevoked(serialHex)
}

// GetCertificateRevocationInfo returns detailed info for an x509.Certificate.
func (c *RevocationChecker) GetCertificateRevocationInfo(cert *x509.Certificate) (*RevocationInfo, error) {
	if cert == nil {
		return nil, nil
	}

	serialHex := cert.SerialNumber.Text(16)
	return c.GetRevocationInfo(serialHex)
}

// ============================================================================
// Batch Operations
// ============================================================================

// CheckMultiple checks multiple serial numbers at once.
func (c *RevocationChecker) CheckMultiple(serialNumbers []string) (map[string]bool, error) {
	results := make(map[string]bool, len(serialNumbers))

	for _, serial := range serialNumbers {
		revoked, err := c.IsRevoked(serial)
		if err != nil && !c.failOpen {
			return nil, err
		}
		results[NormalizeSerialNumber(serial)] = revoked
	}

	return results, nil
}

// CheckCertificateChain checks all certificates in a chain.
func (c *RevocationChecker) CheckCertificateChain(chain []*x509.Certificate) (bool, *x509.Certificate, error) {
	for _, cert := range chain {
		revoked, err := c.IsCertificateRevoked(cert)
		if err != nil {
			return false, nil, err
		}
		if revoked {
			return true, cert, nil // Return first revoked cert
		}
	}
	return false, nil, nil
}

// ============================================================================
// Serial Number Normalization
// ============================================================================

// NormalizeSerialNumber normalizes a serial number to uppercase hex.
func NormalizeSerialNumber(serial string) string {
	// Remove common prefixes
	serial = strings.TrimPrefix(serial, "0x")
	serial = strings.TrimPrefix(serial, "0X")

	// Remove colons, spaces, and other separators
	serial = strings.ReplaceAll(serial, ":", "")
	serial = strings.ReplaceAll(serial, " ", "")
	serial = strings.ReplaceAll(serial, "-", "")

	// Convert to uppercase and trim
	return strings.ToUpper(strings.TrimSpace(serial))
}

// FormatSerialNumber formats a serial number with colons for display.
func FormatSerialNumber(serial string) string {
	normalized := NormalizeSerialNumber(serial)
	if len(normalized) == 0 {
		return ""
	}

	var parts []string
	for i := 0; i < len(normalized); i += 2 {
		end := i + 2
		if end > len(normalized) {
			end = len(normalized)
		}
		parts = append(parts, normalized[i:end])
	}
	return strings.Join(parts, ":")
}

// SerialNumberFromBytes converts raw bytes to hex serial number.
func SerialNumberFromBytes(data []byte) string {
	return strings.ToUpper(hex.EncodeToString(data))
}

// ============================================================================
// Statistics
// ============================================================================

// GetCheckStatistics returns revocation check statistics.
func (c *RevocationChecker) GetCheckStatistics() *CheckStats {
	totalChecks := atomic.LoadInt64(&c.totalChecks)
	totalTime := atomic.LoadInt64(&c.totalCheckTime)

	var avgCheckTime time.Duration
	if totalChecks > 0 {
		avgCheckTime = time.Duration(totalTime / totalChecks)
	}

	elapsed := time.Since(c.startTime).Seconds()
	var checksPerSecond float64
	if elapsed > 0 {
		checksPerSecond = float64(totalChecks) / elapsed
	}

	return &CheckStats{
		TotalChecks:      totalChecks,
		RevokedFound:     atomic.LoadInt64(&c.revokedFound),
		NotRevokedFound:  atomic.LoadInt64(&c.notRevokedFound),
		ChecksPerSecond:  checksPerSecond,
		AverageCheckTime: avgCheckTime,
	}
}

// ResetStatistics resets the check statistics.
func (c *RevocationChecker) ResetStatistics() {
	atomic.StoreInt64(&c.totalChecks, 0)
	atomic.StoreInt64(&c.revokedFound, 0)
	atomic.StoreInt64(&c.notRevokedFound, 0)
	atomic.StoreInt64(&c.totalCheckTime, 0)
	c.startTime = time.Now()
}

// ============================================================================
// Convenience Methods
// ============================================================================

// MustNotBeRevoked returns an error if the certificate is revoked.
func (c *RevocationChecker) MustNotBeRevoked(serialNumber string) error {
	revoked, err := c.IsRevoked(serialNumber)
	if err != nil {
		return err
	}
	if revoked {
		info, _ := c.GetRevocationInfo(serialNumber)
		if info != nil {
			return &RevocationError{
				SerialNumber: serialNumber,
				Reason:       string(info.Reason),
				RevokedAt:    info.RevokedAt,
			}
		}
		return ErrAlreadyRevoked
	}
	return nil
}

// RevocationError provides detailed error information.
type RevocationError struct {
	SerialNumber string
	Reason       string
	RevokedAt    time.Time
}

func (e *RevocationError) Error() string {
	return "certificate " + e.SerialNumber + " was revoked at " + e.RevokedAt.Format(time.RFC3339) + " (reason: " + e.Reason + ")"
}
