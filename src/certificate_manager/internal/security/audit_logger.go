package security

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"time"
)

// ============================================================================
// Audit Operations
// ============================================================================

const (
	OpIssueCertificate     = "issue_certificate"
	OpRevokeCertificate    = "revoke_certificate"
	OpSignCRL              = "sign_crl"
	OpAccessCAKey          = "access_ca_key"
	OpRotatePassphrase     = "rotate_passphrase"
	OpBackupCreated        = "backup_created"
	OpBackupRestored       = "backup_restored"
	OpConfigurationChanged = "configuration_changed"
	OpOCSPResponse         = "ocsp_response"
	OpValidationFailed     = "validation_failed"
	OpAccessDenied         = "access_denied"
)

// ============================================================================
// Audit Entry
// ============================================================================

// AuditEntry represents a single audit log entry.
type AuditEntry struct {
	ID            int64                  `json:"id"`
	Timestamp     time.Time              `json:"timestamp"`
	Operation     string                 `json:"operation"`
	Subject       string                 `json:"subject"`
	SerialNumber  string                 `json:"serial_number,omitempty"`
	PerformedBy   string                 `json:"performed_by"`
	IPAddress     string                 `json:"ip_address,omitempty"`
	Success       bool                   `json:"success"`
	ErrorMessage  string                 `json:"error_message,omitempty"`
	Details       map[string]interface{} `json:"details,omitempty"`
	PrevEntryHash string                 `json:"prev_entry_hash"`
	EntryHash     string                 `json:"entry_hash"`
}

// ============================================================================
// Audit Filter
// ============================================================================

// AuditFilter filters audit log queries.
type AuditFilter struct {
	StartTime   *time.Time
	EndTime     *time.Time
	Operation   string
	PerformedBy string
	Subject     string
	SuccessOnly bool
	FailureOnly bool
	Limit       int
	Offset      int
}

// ============================================================================
// Configuration
// ============================================================================

// AuditLogConfig configures the audit logger.
type AuditLogConfig struct {
	Enabled           bool
	FilePath          string
	DatabaseEnabled   bool
	FileEnabled       bool
	RetentionDays     int
	ValidateOnStartup bool
}

// DefaultAuditLogConfig returns default configuration.
func DefaultAuditLogConfig() *AuditLogConfig {
	return &AuditLogConfig{
		Enabled:           true,
		FilePath:          "/var/log/safeops/ca_audit.log",
		DatabaseEnabled:   true,
		FileEnabled:       true,
		RetentionDays:     365,
		ValidateOnStartup: true,
	}
}

// ============================================================================
// Audit Logger
// ============================================================================

// AuditLogger provides tamper-proof audit logging.
type AuditLogger struct {
	config *AuditLogConfig

	mu            sync.Mutex
	lastEntryHash string
	nextID        int64
	entries       []*AuditEntry // In-memory cache

	// File logging
	file   *os.File
	fileMu sync.Mutex

	// Statistics
	totalEntries int64
	failedWrites int64
}

// NewAuditLogger creates a new audit logger.
func NewAuditLogger(config *AuditLogConfig) *AuditLogger {
	if config == nil {
		config = DefaultAuditLogConfig()
	}

	logger := &AuditLogger{
		config:        config,
		lastEntryHash: genesisHash(),
		nextID:        1,
		entries:       make([]*AuditEntry, 0, 1000),
	}

	return logger
}

// genesisHash returns the initial hash for the chain.
func genesisHash() string {
	return "0000000000000000000000000000000000000000000000000000000000000000"
}

// ============================================================================
// Initialization
// ============================================================================

// Initialize initializes the audit logger.
func (l *AuditLogger) Initialize() error {
	if !l.config.Enabled {
		return nil
	}

	// Initialize file logging
	if l.config.FileEnabled {
		if err := l.initFileLogging(); err != nil {
			return fmt.Errorf("failed to initialize file logging: %w", err)
		}
	}

	// Validate existing entries if enabled
	if l.config.ValidateOnStartup && len(l.entries) > 0 {
		if valid, err := l.ValidateChain(); !valid {
			log.Printf("[audit] WARNING: Hash chain validation failed: %v", err)
		}
	}

	return nil
}

// initFileLogging initializes file-based logging.
func (l *AuditLogger) initFileLogging() error {
	// Ensure directory exists
	dir := filepath.Dir(l.config.FilePath)
	if err := os.MkdirAll(dir, 0700); err != nil {
		return fmt.Errorf("failed to create log directory: %w", err)
	}

	// Open log file
	file, err := os.OpenFile(l.config.FilePath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0600)
	if err != nil {
		return fmt.Errorf("failed to open log file: %w", err)
	}

	l.file = file
	return nil
}

// Close closes the audit logger.
func (l *AuditLogger) Close() error {
	if l.file != nil {
		return l.file.Close()
	}
	return nil
}

// ============================================================================
// Logging Operations
// ============================================================================

// LogOperation logs a security operation.
func (l *AuditLogger) LogOperation(operation, subject, performedBy string, success bool, details map[string]interface{}) error {
	if !l.config.Enabled {
		return nil
	}

	l.mu.Lock()
	defer l.mu.Unlock()

	entry := &AuditEntry{
		ID:            l.nextID,
		Timestamp:     time.Now().UTC(),
		Operation:     operation,
		Subject:       subject,
		PerformedBy:   performedBy,
		Success:       success,
		Details:       details,
		PrevEntryHash: l.lastEntryHash,
	}

	// Calculate entry hash
	entry.EntryHash = l.calculateEntryHash(entry)

	// Store entry
	l.entries = append(l.entries, entry)
	l.lastEntryHash = entry.EntryHash
	l.nextID++
	atomic.AddInt64(&l.totalEntries, 1)

	// Write to file
	if l.config.FileEnabled {
		if err := l.writeToFile(entry); err != nil {
			atomic.AddInt64(&l.failedWrites, 1)
			log.Printf("[audit] Failed to write to file: %v", err)
		}
	}

	return nil
}

// LogOperationWithError logs a failed operation with error message.
func (l *AuditLogger) LogOperationWithError(operation, subject, performedBy, errorMsg string, details map[string]interface{}) error {
	if details == nil {
		details = make(map[string]interface{})
	}
	details["error"] = errorMsg

	return l.LogOperation(operation, subject, performedBy, false, details)
}

// ============================================================================
// Specialized Logging Methods
// ============================================================================

// LogCertificateIssuance logs certificate issuance.
func (l *AuditLogger) LogCertificateIssuance(domain, serialNumber, issuedBy string) error {
	return l.LogOperation(OpIssueCertificate, domain, issuedBy, true, map[string]interface{}{
		"serial_number": serialNumber,
	})
}

// LogCertificateRevocation logs certificate revocation.
func (l *AuditLogger) LogCertificateRevocation(serialNumber, reason, revokedBy string) error {
	return l.LogOperation(OpRevokeCertificate, serialNumber, revokedBy, true, map[string]interface{}{
		"reason": reason,
	})
}

// LogCAKeyAccess logs CA private key access.
func (l *AuditLogger) LogCAKeyAccess(operation, performedBy string, success bool) error {
	return l.LogOperation(OpAccessCAKey, operation, performedBy, success, nil)
}

// LogCRLGeneration logs CRL generation.
func (l *AuditLogger) LogCRLGeneration(crlNumber int64, revokedCount int, generatedBy string) error {
	return l.LogOperation(OpSignCRL, fmt.Sprintf("CRL#%d", crlNumber), generatedBy, true, map[string]interface{}{
		"revoked_count": revokedCount,
	})
}

// LogPassphraseRotation logs passphrase rotation.
func (l *AuditLogger) LogPassphraseRotation(rotatedBy string) error {
	return l.LogOperation(OpRotatePassphrase, "ca_passphrase", rotatedBy, true, nil)
}

// LogBackupCreation logs backup creation.
func (l *AuditLogger) LogBackupCreation(backupPath string, size int64, createdBy string) error {
	return l.LogOperation(OpBackupCreated, backupPath, createdBy, true, map[string]interface{}{
		"size_bytes": size,
	})
}

// LogConfigurationChange logs configuration changes.
func (l *AuditLogger) LogConfigurationChange(setting, oldValue, newValue, changedBy string) error {
	return l.LogOperation(OpConfigurationChanged, setting, changedBy, true, map[string]interface{}{
		"old_value": oldValue,
		"new_value": newValue,
	})
}

// LogAccessDenied logs access denial.
func (l *AuditLogger) LogAccessDenied(resource, attemptedBy, reason string) error {
	return l.LogOperation(OpAccessDenied, resource, attemptedBy, false, map[string]interface{}{
		"reason": reason,
	})
}

// ============================================================================
// Hash Chain
// ============================================================================

// calculateEntryHash calculates the SHA-256 hash of an audit entry.
func (l *AuditLogger) calculateEntryHash(entry *AuditEntry) string {
	data := fmt.Sprintf("%d|%s|%s|%s|%s|%t|%s",
		entry.ID,
		entry.Timestamp.Format(time.RFC3339Nano),
		entry.Operation,
		entry.Subject,
		entry.PerformedBy,
		entry.Success,
		entry.PrevEntryHash,
	)

	hash := sha256.Sum256([]byte(data))
	return hex.EncodeToString(hash[:])
}

// ValidateChain validates the hash chain integrity.
func (l *AuditLogger) ValidateChain() (bool, error) {
	l.mu.Lock()
	defer l.mu.Unlock()

	if len(l.entries) == 0 {
		return true, nil
	}

	prevHash := genesisHash()

	for i, entry := range l.entries {
		// Verify previous hash matches
		if entry.PrevEntryHash != prevHash {
			return false, fmt.Errorf("chain broken at entry %d: expected prevHash %s, got %s",
				entry.ID, prevHash, entry.PrevEntryHash)
		}

		// Recalculate and verify hash
		calculatedHash := l.calculateEntryHash(entry)
		if calculatedHash != entry.EntryHash {
			return false, fmt.Errorf("entry %d tampered: expected hash %s, got %s",
				entry.ID, calculatedHash, entry.EntryHash)
		}

		prevHash = entry.EntryHash
		_ = i // suppress unused variable warning
	}

	return true, nil
}

// ============================================================================
// File Writing
// ============================================================================

// writeToFile writes an audit entry to the log file.
func (l *AuditLogger) writeToFile(entry *AuditEntry) error {
	if l.file == nil {
		return nil
	}

	l.fileMu.Lock()
	defer l.fileMu.Unlock()

	// Format: [timestamp] OPERATION | subject | performedBy | success | hash
	status := "SUCCESS"
	if !entry.Success {
		status = "FAILED"
	}

	line := fmt.Sprintf("[%s] %s | %s | %s | %s | hash=%s\n",
		entry.Timestamp.Format(time.RFC3339),
		entry.Operation,
		entry.Subject,
		entry.PerformedBy,
		status,
		entry.EntryHash[:16], // Truncated hash for readability
	)

	_, err := l.file.WriteString(line)
	if err != nil {
		return err
	}

	return l.file.Sync()
}

// ============================================================================
// Query Interface
// ============================================================================

// GetAuditLog retrieves audit entries matching the filter.
func (l *AuditLogger) GetAuditLog(filter AuditFilter) []*AuditEntry {
	l.mu.Lock()
	defer l.mu.Unlock()

	var results []*AuditEntry

	for _, entry := range l.entries {
		// Apply filters
		if filter.StartTime != nil && entry.Timestamp.Before(*filter.StartTime) {
			continue
		}
		if filter.EndTime != nil && entry.Timestamp.After(*filter.EndTime) {
			continue
		}
		if filter.Operation != "" && entry.Operation != filter.Operation {
			continue
		}
		if filter.PerformedBy != "" && entry.PerformedBy != filter.PerformedBy {
			continue
		}
		if filter.Subject != "" && entry.Subject != filter.Subject {
			continue
		}
		if filter.SuccessOnly && !entry.Success {
			continue
		}
		if filter.FailureOnly && entry.Success {
			continue
		}

		results = append(results, entry)
	}

	// Apply pagination
	if filter.Offset > 0 && filter.Offset < len(results) {
		results = results[filter.Offset:]
	}
	if filter.Limit > 0 && filter.Limit < len(results) {
		results = results[:filter.Limit]
	}

	return results
}

// GetEntriesBySubject returns all entries for a subject.
func (l *AuditLogger) GetEntriesBySubject(subject string) []*AuditEntry {
	return l.GetAuditLog(AuditFilter{Subject: subject})
}

// GetFailedOperations returns failed operations since a given time.
func (l *AuditLogger) GetFailedOperations(since time.Time) []*AuditEntry {
	return l.GetAuditLog(AuditFilter{
		StartTime:   &since,
		FailureOnly: true,
	})
}

// GetKeyAccessLog returns all CA key access entries.
func (l *AuditLogger) GetKeyAccessLog() []*AuditEntry {
	return l.GetAuditLog(AuditFilter{Operation: OpAccessCAKey})
}

// ============================================================================
// Statistics
// ============================================================================

// AuditStats contains audit logger statistics.
type AuditStats struct {
	TotalEntries  int64     `json:"total_entries"`
	FailedWrites  int64     `json:"failed_writes"`
	ChainValid    bool      `json:"chain_valid"`
	LastEntryHash string    `json:"last_entry_hash"`
	OldestEntry   time.Time `json:"oldest_entry,omitempty"`
	NewestEntry   time.Time `json:"newest_entry,omitempty"`
}

// GetStats returns audit logger statistics.
func (l *AuditLogger) GetStats() *AuditStats {
	l.mu.Lock()
	defer l.mu.Unlock()

	stats := &AuditStats{
		TotalEntries:  atomic.LoadInt64(&l.totalEntries),
		FailedWrites:  atomic.LoadInt64(&l.failedWrites),
		LastEntryHash: l.lastEntryHash,
	}

	if len(l.entries) > 0 {
		stats.OldestEntry = l.entries[0].Timestamp
		stats.NewestEntry = l.entries[len(l.entries)-1].Timestamp
	}

	// Validate chain (quick check)
	stats.ChainValid, _ = l.ValidateChain()

	return stats
}

// ============================================================================
// Report Generation
// ============================================================================

// DailySummary contains daily audit summary.
type DailySummary struct {
	Date                string `json:"date"`
	CertificatesIssued  int    `json:"certificates_issued"`
	CertificatesRevoked int    `json:"certificates_revoked"`
	CRLsGenerated       int    `json:"crls_generated"`
	CAKeyAccesses       int    `json:"ca_key_accesses"`
	FailedOperations    int    `json:"failed_operations"`
}

// GenerateDailySummary generates a daily summary report.
func (l *AuditLogger) GenerateDailySummary(date time.Time) *DailySummary {
	startOfDay := time.Date(date.Year(), date.Month(), date.Day(), 0, 0, 0, 0, time.UTC)
	endOfDay := startOfDay.Add(24 * time.Hour)

	entries := l.GetAuditLog(AuditFilter{
		StartTime: &startOfDay,
		EndTime:   &endOfDay,
	})

	summary := &DailySummary{
		Date: date.Format("2006-01-02"),
	}

	for _, entry := range entries {
		switch entry.Operation {
		case OpIssueCertificate:
			summary.CertificatesIssued++
		case OpRevokeCertificate:
			summary.CertificatesRevoked++
		case OpSignCRL:
			summary.CRLsGenerated++
		case OpAccessCAKey:
			summary.CAKeyAccesses++
		}
		if !entry.Success {
			summary.FailedOperations++
		}
	}

	return summary
}

// ExportToJSON exports audit log entries to JSON.
func (l *AuditLogger) ExportToJSON() ([]byte, error) {
	l.mu.Lock()
	defer l.mu.Unlock()

	return json.MarshalIndent(l.entries, "", "  ")
}
