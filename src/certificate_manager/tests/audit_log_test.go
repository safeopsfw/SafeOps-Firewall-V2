// Package tests provides comprehensive testing for the Certificate Manager.
// This file tests the tamper-proof audit logging system.
package tests

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"
)

// ============================================================================
// Test Types
// ============================================================================

// AuditEntry represents an audit log entry for testing.
type AuditEntry struct {
	ID            int64     `json:"id"`
	Timestamp     time.Time `json:"timestamp"`
	Operation     string    `json:"operation"`
	Subject       string    `json:"subject"`
	SerialNumber  string    `json:"serial_number"`
	PerformedBy   string    `json:"performed_by"`
	IPAddress     string    `json:"ip_address"`
	Success       bool      `json:"success"`
	ErrorMessage  string    `json:"error_message,omitempty"`
	PrevEntryHash string    `json:"prev_entry_hash"`
	EntryHash     string    `json:"entry_hash"`
}

// MockAuditLogger provides audit logging for tests.
type MockAuditLogger struct {
	entries []AuditEntry
	mu      sync.RWMutex
	nextID  int64
}

// NewMockAuditLogger creates a new mock audit logger.
func NewMockAuditLogger() *MockAuditLogger {
	return &MockAuditLogger{
		entries: make([]AuditEntry, 0),
		nextID:  1,
	}
}

// LogOperation logs an operation to the audit trail.
func (l *MockAuditLogger) LogOperation(operation, subject, serial, performedBy, ip string, success bool, errMsg string) (*AuditEntry, error) {
	l.mu.Lock()
	defer l.mu.Unlock()

	entry := AuditEntry{
		ID:           l.nextID,
		Timestamp:    time.Now(),
		Operation:    operation,
		Subject:      subject,
		SerialNumber: serial,
		PerformedBy:  performedBy,
		IPAddress:    ip,
		Success:      success,
		ErrorMessage: errMsg,
	}

	// Set previous hash (hash chain)
	if len(l.entries) == 0 {
		entry.PrevEntryHash = strings.Repeat("0", 64) // Genesis block
	} else {
		prevEntry := l.entries[len(l.entries)-1]
		entry.PrevEntryHash = prevEntry.EntryHash
	}

	// Calculate this entry's hash
	entry.EntryHash = l.calculateHash(&entry)

	l.entries = append(l.entries, entry)
	l.nextID++

	return &entry, nil
}

// calculateHash computes SHA-256 hash of an entry.
func (l *MockAuditLogger) calculateHash(entry *AuditEntry) string {
	data := fmt.Sprintf("%d|%s|%s|%s|%s|%s|%s|%t|%s|%s",
		entry.ID,
		entry.Timestamp.UTC().Format(time.RFC3339Nano),
		entry.Operation,
		entry.Subject,
		entry.SerialNumber,
		entry.PerformedBy,
		entry.IPAddress,
		entry.Success,
		entry.ErrorMessage,
		entry.PrevEntryHash,
	)
	hash := sha256.Sum256([]byte(data))
	return hex.EncodeToString(hash[:])
}

// ValidateHashChain verifies the integrity of the hash chain.
func (l *MockAuditLogger) ValidateHashChain() (bool, int, error) {
	l.mu.RLock()
	defer l.mu.RUnlock()

	if len(l.entries) == 0 {
		return true, 0, nil
	}

	// Verify first entry
	if l.entries[0].PrevEntryHash != strings.Repeat("0", 64) {
		return false, 1, fmt.Errorf("first entry has invalid prev_hash")
	}

	// Verify chain
	for i := 1; i < len(l.entries); i++ {
		prevEntry := l.entries[i-1]
		currEntry := l.entries[i]

		// Recalculate previous entry's hash
		expectedPrevHash := l.calculateHash(&prevEntry)

		if currEntry.PrevEntryHash != expectedPrevHash {
			return false, i + 1, fmt.Errorf("hash chain broken at entry %d", i+1)
		}
	}

	return true, 0, nil
}

// GetEntries returns all entries.
func (l *MockAuditLogger) GetEntries() []AuditEntry {
	l.mu.RLock()
	defer l.mu.RUnlock()
	result := make([]AuditEntry, len(l.entries))
	copy(result, l.entries)
	return result
}

// GetEntry returns a specific entry by ID.
func (l *MockAuditLogger) GetEntry(id int64) *AuditEntry {
	l.mu.RLock()
	defer l.mu.RUnlock()
	for _, e := range l.entries {
		if e.ID == id {
			entryCopy := e
			return &entryCopy
		}
	}
	return nil
}

// ModifyEntry modifies an entry (for tamper testing).
func (l *MockAuditLogger) ModifyEntry(id int64, field, value string) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	for i, e := range l.entries {
		if e.ID == id {
			switch field {
			case "operation":
				l.entries[i].Operation = value
			case "subject":
				l.entries[i].Subject = value
			case "timestamp":
				t, _ := time.Parse(time.RFC3339, value)
				l.entries[i].Timestamp = t
			}
			return true
		}
	}
	return false
}

// DeleteEntry removes an entry (for tamper testing).
func (l *MockAuditLogger) DeleteEntry(id int64) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	for i, e := range l.entries {
		if e.ID == id {
			l.entries = append(l.entries[:i], l.entries[i+1:]...)
			return true
		}
	}
	return false
}

// QueryByOperation returns entries matching operation type.
func (l *MockAuditLogger) QueryByOperation(operation string) []AuditEntry {
	l.mu.RLock()
	defer l.mu.RUnlock()
	var result []AuditEntry
	for _, e := range l.entries {
		if e.Operation == operation {
			result = append(result, e)
		}
	}
	return result
}

// QueryByUser returns entries by performed_by.
func (l *MockAuditLogger) QueryByUser(user string) []AuditEntry {
	l.mu.RLock()
	defer l.mu.RUnlock()
	var result []AuditEntry
	for _, e := range l.entries {
		if e.PerformedBy == user {
			result = append(result, e)
		}
	}
	return result
}

// QueryBySerial returns entries by serial number.
func (l *MockAuditLogger) QueryBySerial(serial string) []AuditEntry {
	l.mu.RLock()
	defer l.mu.RUnlock()
	var result []AuditEntry
	for _, e := range l.entries {
		if e.SerialNumber == serial {
			result = append(result, e)
		}
	}
	return result
}

// ExportJSON exports all entries as JSON.
func (l *MockAuditLogger) ExportJSON() (string, error) {
	l.mu.RLock()
	defer l.mu.RUnlock()
	data, err := json.MarshalIndent(l.entries, "", "  ")
	if err != nil {
		return "", err
	}
	return string(data), nil
}

// Clear removes all entries.
func (l *MockAuditLogger) Clear() {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.entries = make([]AuditEntry, 0)
	l.nextID = 1
}

// ============================================================================
// Hash Chain Tests
// ============================================================================

// TestHashChain_FirstEntry tests the first entry in the hash chain.
func TestHashChain_FirstEntry(t *testing.T) {
	logger := NewMockAuditLogger()

	entry, err := logger.LogOperation("issue", "example.com", "3A:F2:E8:00:01", "admin", "192.168.1.100", true, "")
	if err != nil {
		t.Fatalf("Failed to log operation: %v", err)
	}

	// Verify first entry has genesis prev_hash
	expectedPrevHash := strings.Repeat("0", 64)
	if entry.PrevEntryHash != expectedPrevHash {
		t.Errorf("First entry prev_hash = %s, want %s", entry.PrevEntryHash, expectedPrevHash)
	}

	// Verify entry has ID 1
	if entry.ID != 1 {
		t.Errorf("First entry ID = %d, want 1", entry.ID)
	}

	// Verify hash is populated
	if entry.EntryHash == "" || len(entry.EntryHash) != 64 {
		t.Errorf("Entry hash invalid: %s", entry.EntryHash)
	}
}

// TestHashChain_SequentialEntries tests that sequential entries link correctly.
func TestHashChain_SequentialEntries(t *testing.T) {
	logger := NewMockAuditLogger()

	// Log 10 operations
	for i := 0; i < 10; i++ {
		_, err := logger.LogOperation(
			"issue",
			fmt.Sprintf("domain%d.com", i),
			fmt.Sprintf("3A:F2:E8:00:%02d", i),
			"operator",
			"192.168.1.100",
			true,
			"",
		)
		if err != nil {
			t.Fatalf("Failed to log operation %d: %v", i, err)
		}
	}

	entries := logger.GetEntries()
	if len(entries) != 10 {
		t.Fatalf("Expected 10 entries, got %d", len(entries))
	}

	// Verify each entry links to previous
	for i := 1; i < len(entries); i++ {
		prevEntry := entries[i-1]
		currEntry := entries[i]

		if currEntry.PrevEntryHash != prevEntry.EntryHash {
			t.Errorf("Entry %d prev_hash doesn't match entry %d hash", i+1, i)
		}
	}
}

// TestHashChain_HashCalculation verifies deterministic hash calculation.
func TestHashChain_HashCalculation(t *testing.T) {
	logger := NewMockAuditLogger()

	entry, _ := logger.LogOperation("sign", "test.com", "3A:F2:E8:00:01", "tls_proxy", "10.0.0.1", true, "")

	// Recalculate hash
	recalculated := logger.calculateHash(entry)

	if recalculated != entry.EntryHash {
		t.Errorf("Hash mismatch: calculated %s, stored %s", recalculated, entry.EntryHash)
	}
}

// TestHashChain_ChainIntegrity validates full chain integrity.
func TestHashChain_ChainIntegrity(t *testing.T) {
	logger := NewMockAuditLogger()

	// Log 20 operations
	for i := 0; i < 20; i++ {
		_, err := logger.LogOperation(
			"issue",
			fmt.Sprintf("domain%d.com", i),
			fmt.Sprintf("SERIAL:%02d", i),
			"admin",
			"192.168.1.1",
			true,
			"",
		)
		if err != nil {
			t.Fatalf("Failed to log operation: %v", err)
		}
	}

	valid, badEntry, err := logger.ValidateHashChain()
	if !valid {
		t.Errorf("Hash chain invalid at entry %d: %v", badEntry, err)
	}
}

// ============================================================================
// Tamper Detection Tests
// ============================================================================

// TestTamperDetection_ModifiedOperation tests detection of modified operation field.
func TestTamperDetection_ModifiedOperation(t *testing.T) {
	logger := NewMockAuditLogger()

	// Log 5 operations
	for i := 0; i < 5; i++ {
		logger.LogOperation("issue", fmt.Sprintf("domain%d.com", i), fmt.Sprintf("SER:%02d", i), "admin", "10.0.0.1", true, "")
	}

	// Tamper with entry #3
	logger.ModifyEntry(3, "operation", "TAMPERED")

	// Validate chain
	valid, badEntry, _ := logger.ValidateHashChain()

	if valid {
		t.Error("Tamper detection failed - chain reported as valid")
	}

	if badEntry != 4 {
		t.Errorf("Expected tamper detected at entry 4, got %d", badEntry)
	}
}

// TestTamperDetection_ModifiedTimestamp tests detection of modified timestamp.
func TestTamperDetection_ModifiedTimestamp(t *testing.T) {
	logger := NewMockAuditLogger()

	for i := 0; i < 5; i++ {
		logger.LogOperation("sign", "example.com", "SER:01", "proxy", "10.0.0.1", true, "")
	}

	// Modify timestamp of entry #2
	logger.ModifyEntry(2, "timestamp", "2020-01-01T00:00:00Z")

	valid, badEntry, _ := logger.ValidateHashChain()

	if valid {
		t.Error("Timestamp modification not detected")
	}

	if badEntry != 3 {
		t.Errorf("Expected tamper at entry 3, got %d", badEntry)
	}
}

// TestTamperDetection_DeletedEntry tests detection of deleted entries.
func TestTamperDetection_DeletedEntry(t *testing.T) {
	logger := NewMockAuditLogger()

	for i := 0; i < 10; i++ {
		logger.LogOperation("issue", fmt.Sprintf("d%d.com", i), fmt.Sprintf("S:%02d", i), "admin", "10.0.0.1", true, "")
	}

	// Delete entry #5
	logger.DeleteEntry(5)

	valid, _, _ := logger.ValidateHashChain()

	if valid {
		t.Error("Deleted entry not detected - chain invalid but reported valid")
	}
}

// TestTamperDetection_MultipleModifications tests detection of multiple tampers.
func TestTamperDetection_MultipleModifications(t *testing.T) {
	logger := NewMockAuditLogger()

	for i := 0; i < 20; i++ {
		logger.LogOperation("issue", fmt.Sprintf("test%d.com", i), fmt.Sprintf("S:%02d", i), "admin", "10.0.0.1", true, "")
	}

	// Tamper with multiple entries
	logger.ModifyEntry(5, "operation", "FAKE1")
	logger.ModifyEntry(10, "subject", "FAKE2")
	logger.ModifyEntry(15, "operation", "FAKE3")

	valid, badEntry, _ := logger.ValidateHashChain()

	if valid {
		t.Error("Multiple tampers not detected")
	}

	// First tamper should be detected at entry 6
	if badEntry != 6 {
		t.Errorf("Expected first tamper at entry 6, got %d", badEntry)
	}
}

// ============================================================================
// Audit Log Operations Tests
// ============================================================================

// TestLogOperation_Issue tests logging certificate issuance.
func TestLogOperation_Issue(t *testing.T) {
	logger := NewMockAuditLogger()

	entry, err := logger.LogOperation("issue", "example.com", "3A:F2:E8:D1", "operator", "192.168.1.50", true, "")
	if err != nil {
		t.Fatalf("Failed to log: %v", err)
	}

	if entry.Operation != "issue" {
		t.Errorf("Operation = %s, want issue", entry.Operation)
	}
	if entry.Subject != "example.com" {
		t.Errorf("Subject = %s, want example.com", entry.Subject)
	}
	if entry.SerialNumber != "3A:F2:E8:D1" {
		t.Errorf("SerialNumber = %s, want 3A:F2:E8:D1", entry.SerialNumber)
	}
	if entry.PerformedBy != "operator" {
		t.Errorf("PerformedBy = %s, want operator", entry.PerformedBy)
	}
	if !entry.Success {
		t.Error("Success = false, want true")
	}
}

// TestLogOperation_Revoke tests logging certificate revocation.
func TestLogOperation_Revoke(t *testing.T) {
	logger := NewMockAuditLogger()

	entry, _ := logger.LogOperation("revoke", "example.com (compromised)", "3A:F2:E8:D1", "admin", "192.168.1.1", true, "")

	if entry.Operation != "revoke" {
		t.Errorf("Operation = %s, want revoke", entry.Operation)
	}
	if !strings.Contains(entry.Subject, "compromised") {
		t.Error("Subject should include revocation reason")
	}
}

// TestLogOperation_Failed tests logging failed operations.
func TestLogOperation_Failed(t *testing.T) {
	logger := NewMockAuditLogger()

	entry, _ := logger.LogOperation("issue", "unauthorized.com", "N/A", "hacker", "10.0.0.99", false, "permission denied")

	if entry.Success {
		t.Error("Success = true, want false for failed operation")
	}
	if entry.ErrorMessage != "permission denied" {
		t.Errorf("ErrorMessage = %s, want 'permission denied'", entry.ErrorMessage)
	}
}

// ============================================================================
// Query and Retrieval Tests
// ============================================================================

// TestQueryAuditLog_ByOperation tests filtering by operation type.
func TestQueryAuditLog_ByOperation(t *testing.T) {
	logger := NewMockAuditLogger()

	// Log mixed operations
	logger.LogOperation("issue", "d1.com", "S:01", "admin", "10.0.0.1", true, "")
	logger.LogOperation("revoke", "d2.com", "S:02", "admin", "10.0.0.1", true, "")
	logger.LogOperation("issue", "d3.com", "S:03", "admin", "10.0.0.1", true, "")
	logger.LogOperation("sign", "d4.com", "S:04", "proxy", "10.0.0.1", true, "")
	logger.LogOperation("revoke", "d5.com", "S:05", "admin", "10.0.0.1", true, "")

	// Query revokes
	revokes := logger.QueryByOperation("revoke")
	if len(revokes) != 2 {
		t.Errorf("Expected 2 revoke entries, got %d", len(revokes))
	}

	// Query issues
	issues := logger.QueryByOperation("issue")
	if len(issues) != 2 {
		t.Errorf("Expected 2 issue entries, got %d", len(issues))
	}
}

// TestQueryAuditLog_ByUser tests filtering by user.
func TestQueryAuditLog_ByUser(t *testing.T) {
	logger := NewMockAuditLogger()

	logger.LogOperation("issue", "d1.com", "S:01", "admin", "10.0.0.1", true, "")
	logger.LogOperation("sign", "d2.com", "S:02", "tls_proxy", "10.0.0.1", true, "")
	logger.LogOperation("issue", "d3.com", "S:03", "admin", "10.0.0.1", true, "")
	logger.LogOperation("sign", "d4.com", "S:04", "tls_proxy", "10.0.0.1", true, "")

	adminOps := logger.QueryByUser("admin")
	if len(adminOps) != 2 {
		t.Errorf("Expected 2 admin operations, got %d", len(adminOps))
	}

	proxyOps := logger.QueryByUser("tls_proxy")
	if len(proxyOps) != 2 {
		t.Errorf("Expected 2 tls_proxy operations, got %d", len(proxyOps))
	}
}

// TestQueryAuditLog_BySerial tests filtering by serial number.
func TestQueryAuditLog_BySerial(t *testing.T) {
	logger := NewMockAuditLogger()

	serial := "3A:F2:E8:00:01"

	logger.LogOperation("issue", "example.com", serial, "admin", "10.0.0.1", true, "")
	logger.LogOperation("sign", "example.com", serial, "proxy", "10.0.0.1", true, "")
	logger.LogOperation("issue", "other.com", "OTHER:SERIAL", "admin", "10.0.0.1", true, "")
	logger.LogOperation("revoke", "example.com", serial, "admin", "10.0.0.1", true, "")

	entries := logger.QueryBySerial(serial)
	if len(entries) != 3 {
		t.Errorf("Expected 3 entries for serial, got %d", len(entries))
	}
}

// ============================================================================
// Export and Compliance Tests
// ============================================================================

// TestExportAuditLog_JSON tests JSON export.
func TestExportAuditLog_JSON(t *testing.T) {
	logger := NewMockAuditLogger()

	logger.LogOperation("issue", "test.com", "S:01", "admin", "10.0.0.1", true, "")
	logger.LogOperation("revoke", "test.com", "S:01", "admin", "10.0.0.1", true, "")

	jsonData, err := logger.ExportJSON()
	if err != nil {
		t.Fatalf("Export failed: %v", err)
	}

	// Verify valid JSON
	var entries []AuditEntry
	if err := json.Unmarshal([]byte(jsonData), &entries); err != nil {
		t.Errorf("Invalid JSON: %v", err)
	}

	if len(entries) != 2 {
		t.Errorf("Expected 2 entries in export, got %d", len(entries))
	}
}

// ============================================================================
// Concurrent Logging Tests
// ============================================================================

// TestConcurrentLogging tests thread-safe concurrent logging.
func TestConcurrentLogging(t *testing.T) {
	logger := NewMockAuditLogger()

	numGoroutines := 100
	var wg sync.WaitGroup
	wg.Add(numGoroutines)

	for i := 0; i < numGoroutines; i++ {
		go func(n int) {
			defer wg.Done()
			_, err := logger.LogOperation(
				"sign",
				fmt.Sprintf("concurrent%d.com", n),
				fmt.Sprintf("CONC:%03d", n),
				"worker",
				"10.0.0.1",
				true,
				"",
			)
			if err != nil {
				t.Errorf("Concurrent log failed: %v", err)
			}
		}(i)
	}

	wg.Wait()

	entries := logger.GetEntries()
	if len(entries) != numGoroutines {
		t.Errorf("Expected %d entries, got %d", numGoroutines, len(entries))
	}

	// Verify hash chain still valid
	valid, badEntry, err := logger.ValidateHashChain()
	if !valid {
		t.Errorf("Hash chain invalid after concurrent writes at entry %d: %v", badEntry, err)
	}
}

// TestConcurrentLogging_IDSequence verifies IDs are sequential.
func TestConcurrentLogging_IDSequence(t *testing.T) {
	logger := NewMockAuditLogger()

	numGoroutines := 50
	var wg sync.WaitGroup
	wg.Add(numGoroutines)

	for i := 0; i < numGoroutines; i++ {
		go func(n int) {
			defer wg.Done()
			logger.LogOperation("test", "test.com", "S:01", "user", "10.0.0.1", true, "")
		}(i)
	}

	wg.Wait()

	entries := logger.GetEntries()

	// Verify IDs are 1 to numGoroutines
	idMap := make(map[int64]bool)
	for _, e := range entries {
		if idMap[e.ID] {
			t.Errorf("Duplicate ID: %d", e.ID)
		}
		idMap[e.ID] = true
	}

	for i := int64(1); i <= int64(numGoroutines); i++ {
		if !idMap[i] {
			t.Errorf("Missing ID: %d", i)
		}
	}
}

// ============================================================================
// Performance Tests
// ============================================================================

// TestAuditLogPerformance_Write benchmarks write performance.
func TestAuditLogPerformance_Write(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping performance test in short mode")
	}

	logger := NewMockAuditLogger()
	numWrites := 10000

	start := time.Now()
	for i := 0; i < numWrites; i++ {
		logger.LogOperation("test", "perf.com", fmt.Sprintf("S:%06d", i), "bench", "10.0.0.1", true, "")
	}
	elapsed := time.Since(start)

	avgLatency := elapsed / time.Duration(numWrites)
	t.Logf("Wrote %d entries in %v (avg: %v per entry)", numWrites, elapsed, avgLatency)

	if avgLatency > time.Millisecond {
		t.Errorf("Average write latency %v exceeds 1ms", avgLatency)
	}
}

// TestAuditLogPerformance_Validation benchmarks chain validation.
func TestAuditLogPerformance_Validation(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping performance test in short mode")
	}

	logger := NewMockAuditLogger()
	numEntries := 10000

	// Populate log
	for i := 0; i < numEntries; i++ {
		logger.LogOperation("test", "perf.com", fmt.Sprintf("S:%06d", i), "bench", "10.0.0.1", true, "")
	}

	start := time.Now()
	valid, _, _ := logger.ValidateHashChain()
	elapsed := time.Since(start)

	if !valid {
		t.Error("Chain should be valid")
	}

	t.Logf("Validated %d entries in %v", numEntries, elapsed)

	if elapsed > 30*time.Second {
		t.Errorf("Validation took %v, exceeds 30s limit", elapsed)
	}
}

// ============================================================================
// Cleanup Tests
// ============================================================================

// TestAuditLogClear tests clearing the audit log.
func TestAuditLogClear(t *testing.T) {
	logger := NewMockAuditLogger()

	logger.LogOperation("issue", "test.com", "S:01", "admin", "10.0.0.1", true, "")
	logger.LogOperation("revoke", "test.com", "S:01", "admin", "10.0.0.1", true, "")

	if len(logger.GetEntries()) != 2 {
		t.Error("Expected 2 entries before clear")
	}

	logger.Clear()

	if len(logger.GetEntries()) != 0 {
		t.Error("Expected 0 entries after clear")
	}

	// Verify new entries start at ID 1
	entry, _ := logger.LogOperation("new", "new.com", "S:NEW", "admin", "10.0.0.1", true, "")
	if entry.ID != 1 {
		t.Errorf("After clear, first entry ID = %d, want 1", entry.ID)
	}
}

// ============================================================================
// Context Cancellation Tests
// ============================================================================

// TestAuditLogWithContext tests context-aware operations.
func TestAuditLogWithContext(t *testing.T) {
	logger := NewMockAuditLogger()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	// Simulate logging with context
	select {
	case <-ctx.Done():
		t.Error("Context cancelled before logging")
	default:
		_, err := logger.LogOperation("issue", "ctx.com", "S:CTX", "admin", "10.0.0.1", true, "")
		if err != nil {
			t.Errorf("Log with context failed: %v", err)
		}
	}
}
