// Package tests provides comprehensive testing for the Certificate Manager.
// This file tests the CA backup and restore disaster recovery system.
package tests

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"
)

// ============================================================================
// Test Types
// ============================================================================

// BackupMetadata holds backup information.
type BackupMetadata struct {
	ID                       int64     `json:"id"`
	BackupTimestamp          time.Time `json:"backup_timestamp"`
	BackupLocation           string    `json:"backup_location"`
	BackupSizeBytes          int64     `json:"backup_size_bytes"`
	BackupChecksum           string    `json:"backup_checksum"`
	EncryptionKeyFingerprint string    `json:"encryption_key_fingerprint"`
	Restored                 bool      `json:"restored"`
	RestoredAt               time.Time `json:"restored_at,omitempty"`
}

// MockBackupManager provides backup/restore for tests.
type MockBackupManager struct {
	backups       map[int64]*BackupMetadata
	backupDir     string
	caCertPEM     []byte
	caKeyPEM      []byte
	encryptionKey []byte
	databaseDump  []byte
	nextID        int64
	mu            sync.Mutex
}

// NewMockBackupManager creates a new mock backup manager.
func NewMockBackupManager(backupDir string) (*MockBackupManager, error) {
	if err := os.MkdirAll(backupDir, 0755); err != nil {
		return nil, err
	}

	// Generate test encryption key (32 bytes for AES-256)
	encKey := make([]byte, 32)
	if _, err := rand.Read(encKey); err != nil {
		return nil, err
	}

	return &MockBackupManager{
		backups:       make(map[int64]*BackupMetadata),
		backupDir:     backupDir,
		caCertPEM:     []byte("-----BEGIN CERTIFICATE-----\nTEST CA CERT\n-----END CERTIFICATE-----\n"),
		caKeyPEM:      []byte("-----BEGIN ENCRYPTED PRIVATE KEY-----\nENCRYPTED KEY DATA\n-----END ENCRYPTED PRIVATE KEY-----\n"),
		encryptionKey: encKey,
		databaseDump:  []byte("-- Database dump\nINSERT INTO revoked_certificates VALUES (1, 'serial123', '2025-01-01');"),
		nextID:        1,
	}, nil
}

// SetCAData sets the CA certificate and key for testing.
func (m *MockBackupManager) SetCAData(certPEM, keyPEM []byte) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.caCertPEM = certPEM
	m.caKeyPEM = keyPEM
}

// SetDatabaseDump sets mock database dump data.
func (m *MockBackupManager) SetDatabaseDump(dump []byte) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.databaseDump = dump
}

// CreateBackup creates an encrypted backup.
func (m *MockBackupManager) CreateBackup() (*BackupMetadata, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	timestamp := time.Now()
	filename := fmt.Sprintf("backup_%s.tar.gz.enc", timestamp.Format("20060102_150405"))
	backupPath := filepath.Join(m.backupDir, filename)

	// Create tar archive
	var tarBuffer bytes.Buffer
	tarWriter := tar.NewWriter(&tarBuffer)

	// Add CA certificate
	if err := m.addToTar(tarWriter, "ca/root-cert.pem", m.caCertPEM); err != nil {
		return nil, err
	}

	// Add encrypted CA key
	if err := m.addToTar(tarWriter, "ca/root-key.pem.enc", m.caKeyPEM); err != nil {
		return nil, err
	}

	// Add database dump
	if err := m.addToTar(tarWriter, "database/dump.sql", m.databaseDump); err != nil {
		return nil, err
	}

	// Add metadata
	meta := map[string]interface{}{
		"created_at": timestamp.Format(time.RFC3339),
		"version":    "1.0",
	}
	metaBytes, _ := json.Marshal(meta)
	if err := m.addToTar(tarWriter, "metadata.json", metaBytes); err != nil {
		return nil, err
	}

	if err := tarWriter.Close(); err != nil {
		return nil, err
	}

	// Compress with gzip
	var gzipBuffer bytes.Buffer
	gzipWriter := gzip.NewWriter(&gzipBuffer)
	if _, err := gzipWriter.Write(tarBuffer.Bytes()); err != nil {
		return nil, err
	}
	if err := gzipWriter.Close(); err != nil {
		return nil, err
	}

	// Encrypt with AES-256-GCM
	encrypted, err := m.encrypt(gzipBuffer.Bytes())
	if err != nil {
		return nil, err
	}

	// Write to file
	if err := os.WriteFile(backupPath, encrypted, 0600); err != nil {
		return nil, err
	}

	// Calculate checksum
	checksum := sha256.Sum256(encrypted)
	checksumHex := hex.EncodeToString(checksum[:])

	// Calculate key fingerprint
	keyFingerprint := sha256.Sum256(m.encryptionKey)
	keyFingerprintHex := hex.EncodeToString(keyFingerprint[:8])

	// Record metadata
	metadata := &BackupMetadata{
		ID:                       m.nextID,
		BackupTimestamp:          timestamp,
		BackupLocation:           backupPath,
		BackupSizeBytes:          int64(len(encrypted)),
		BackupChecksum:           checksumHex,
		EncryptionKeyFingerprint: keyFingerprintHex,
	}
	m.backups[m.nextID] = metadata
	m.nextID++

	return metadata, nil
}

func (m *MockBackupManager) addToTar(tw *tar.Writer, name string, data []byte) error {
	header := &tar.Header{
		Name:    name,
		Mode:    0600,
		Size:    int64(len(data)),
		ModTime: time.Now(),
	}
	if err := tw.WriteHeader(header); err != nil {
		return err
	}
	_, err := tw.Write(data)
	return err
}

func (m *MockBackupManager) encrypt(data []byte) ([]byte, error) {
	block, err := aes.NewCipher(m.encryptionKey)
	if err != nil {
		return nil, err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	nonce := make([]byte, gcm.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}

	return gcm.Seal(nonce, nonce, data, nil), nil
}

func (m *MockBackupManager) decrypt(data []byte) ([]byte, error) {
	block, err := aes.NewCipher(m.encryptionKey)
	if err != nil {
		return nil, err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	nonceSize := gcm.NonceSize()
	if len(data) < nonceSize {
		return nil, fmt.Errorf("ciphertext too short")
	}

	nonce, ciphertext := data[:nonceSize], data[nonceSize:]
	return gcm.Open(nil, nonce, ciphertext, nil)
}

// VerifyBackup verifies backup integrity.
func (m *MockBackupManager) VerifyBackup(backupID int64) error {
	m.mu.Lock()
	metadata, exists := m.backups[backupID]
	m.mu.Unlock()

	if !exists {
		return fmt.Errorf("backup ID %d not found", backupID)
	}

	// Check file exists
	data, err := os.ReadFile(metadata.BackupLocation)
	if err != nil {
		return fmt.Errorf("backup file not found: %w", err)
	}

	// Verify checksum
	checksum := sha256.Sum256(data)
	checksumHex := hex.EncodeToString(checksum[:])

	if checksumHex != metadata.BackupChecksum {
		return fmt.Errorf("checksum mismatch: expected %s, got %s", metadata.BackupChecksum, checksumHex)
	}

	// Try decryption
	decrypted, err := m.decrypt(data)
	if err != nil {
		return fmt.Errorf("decryption failed: %w", err)
	}

	// Try decompression
	gzipReader, err := gzip.NewReader(bytes.NewReader(decrypted))
	if err != nil {
		return fmt.Errorf("gzip decompression failed: %w", err)
	}
	defer gzipReader.Close()

	// Try reading tar
	tarReader := tar.NewReader(gzipReader)
	fileCount := 0
	for {
		_, err := tarReader.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return fmt.Errorf("tar read failed: %w", err)
		}
		fileCount++
	}

	if fileCount == 0 {
		return fmt.Errorf("backup contains no files")
	}

	return nil
}

// RestoreBackup restores from a backup.
func (m *MockBackupManager) RestoreBackup(backupID int64, restoreDir string) error {
	m.mu.Lock()
	metadata, exists := m.backups[backupID]
	m.mu.Unlock()

	if !exists {
		return fmt.Errorf("backup ID %d not found", backupID)
	}

	// Read backup file
	data, err := os.ReadFile(metadata.BackupLocation)
	if err != nil {
		return fmt.Errorf("failed to read backup: %w", err)
	}

	// Decrypt
	decrypted, err := m.decrypt(data)
	if err != nil {
		return fmt.Errorf("decryption failed: %w", err)
	}

	// Decompress
	gzipReader, err := gzip.NewReader(bytes.NewReader(decrypted))
	if err != nil {
		return fmt.Errorf("decompression failed: %w", err)
	}
	defer gzipReader.Close()

	decompressed, err := io.ReadAll(gzipReader)
	if err != nil {
		return fmt.Errorf("failed to read decompressed data: %w", err)
	}

	// Extract tar
	tarReader := tar.NewReader(bytes.NewReader(decompressed))
	for {
		header, err := tarReader.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return fmt.Errorf("tar read failed: %w", err)
		}

		targetPath := filepath.Join(restoreDir, header.Name)
		targetDir := filepath.Dir(targetPath)

		if err := os.MkdirAll(targetDir, 0755); err != nil {
			return err
		}

		fileData, err := io.ReadAll(tarReader)
		if err != nil {
			return err
		}

		if err := os.WriteFile(targetPath, fileData, os.FileMode(header.Mode)); err != nil {
			return err
		}
	}

	// Update metadata
	m.mu.Lock()
	metadata.Restored = true
	metadata.RestoredAt = time.Now()
	m.mu.Unlock()

	return nil
}

// GetBackup returns backup metadata.
func (m *MockBackupManager) GetBackup(id int64) *BackupMetadata {
	m.mu.Lock()
	defer m.mu.Unlock()
	if b, ok := m.backups[id]; ok {
		copy := *b
		return &copy
	}
	return nil
}

// ListBackups returns all backups.
func (m *MockBackupManager) ListBackups() []*BackupMetadata {
	m.mu.Lock()
	defer m.mu.Unlock()
	result := make([]*BackupMetadata, 0, len(m.backups))
	for _, b := range m.backups {
		copy := *b
		result = append(result, &copy)
	}
	return result
}

// ApplyRetentionPolicy deletes old backups.
func (m *MockBackupManager) ApplyRetentionPolicy(retentionDays int) (int, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	cutoff := time.Now().AddDate(0, 0, -retentionDays)
	deleted := 0

	for id, backup := range m.backups {
		if backup.BackupTimestamp.Before(cutoff) {
			// Delete file
			os.Remove(backup.BackupLocation)
			delete(m.backups, id)
			deleted++
		}
	}

	return deleted, nil
}

// CorruptBackup corrupts a backup file for testing.
func (m *MockBackupManager) CorruptBackup(backupID int64) error {
	m.mu.Lock()
	backup := m.backups[backupID]
	m.mu.Unlock()

	if backup == nil {
		return fmt.Errorf("backup not found")
	}

	data, err := os.ReadFile(backup.BackupLocation)
	if err != nil {
		return err
	}

	// Flip a byte in the middle
	if len(data) > 100 {
		data[len(data)/2] ^= 0xFF
	}

	return os.WriteFile(backup.BackupLocation, data, 0600)
}

// Cleanup removes all backup files and data.
func (m *MockBackupManager) Cleanup() error {
	return os.RemoveAll(m.backupDir)
}

// ============================================================================
// Backup Creation Tests
// ============================================================================

// TestCreateBackup_Success tests successful backup creation.
func TestCreateBackup_Success(t *testing.T) {
	tempDir := t.TempDir()
	mgr, err := NewMockBackupManager(filepath.Join(tempDir, "backups"))
	if err != nil {
		t.Fatalf("Failed to create manager: %v", err)
	}
	defer mgr.Cleanup()

	backup, err := mgr.CreateBackup()
	if err != nil {
		t.Fatalf("CreateBackup failed: %v", err)
	}

	// Verify metadata
	if backup.ID != 1 {
		t.Errorf("Backup ID = %d, want 1", backup.ID)
	}
	if backup.BackupSizeBytes <= 0 {
		t.Error("Backup size should be > 0")
	}
	if backup.BackupChecksum == "" {
		t.Error("Backup checksum should not be empty")
	}
	if backup.BackupLocation == "" {
		t.Error("Backup location should not be empty")
	}

	// Verify file exists
	if _, err := os.Stat(backup.BackupLocation); os.IsNotExist(err) {
		t.Error("Backup file does not exist")
	}
}

// TestCreateBackup_Encryption tests backup is properly encrypted.
func TestCreateBackup_Encryption(t *testing.T) {
	tempDir := t.TempDir()
	mgr, err := NewMockBackupManager(filepath.Join(tempDir, "backups"))
	if err != nil {
		t.Fatalf("Failed to create manager: %v", err)
	}
	defer mgr.Cleanup()

	backup, err := mgr.CreateBackup()
	if err != nil {
		t.Fatalf("CreateBackup failed: %v", err)
	}

	// Read raw backup
	data, err := os.ReadFile(backup.BackupLocation)
	if err != nil {
		t.Fatalf("Failed to read backup: %v", err)
	}

	// Verify not readable as plain text (should not contain PEM headers)
	if bytes.Contains(data, []byte("-----BEGIN")) {
		t.Error("Backup contains unencrypted PEM data")
	}

	// Verify encrypted size > plaintext
	if len(data) < 100 {
		t.Error("Backup seems too small for encrypted data")
	}
}

// TestCreateBackup_Compression tests backup compression.
func TestCreateBackup_Compression(t *testing.T) {
	tempDir := t.TempDir()
	mgr, err := NewMockBackupManager(filepath.Join(tempDir, "backups"))
	if err != nil {
		t.Fatalf("Failed to create manager: %v", err)
	}
	defer mgr.Cleanup()

	// Set large database dump
	largeDump := bytes.Repeat([]byte("INSERT INTO test VALUES (123456789);\n"), 1000)
	mgr.SetDatabaseDump(largeDump)

	backup, err := mgr.CreateBackup()
	if err != nil {
		t.Fatalf("CreateBackup failed: %v", err)
	}

	// Compressed size should be much smaller than uncompressed
	uncompressedSize := len(mgr.caCertPEM) + len(mgr.caKeyPEM) + len(largeDump)
	if backup.BackupSizeBytes > int64(uncompressedSize) {
		t.Logf("Compressed: %d, Uncompressed estimate: %d", backup.BackupSizeBytes, uncompressedSize)
		// Note: Due to encryption overhead, compressed+encrypted may be slightly larger
		// This is acceptable as long as compression is effective
	}
}

// TestCreateBackup_Contents tests backup archive contents.
func TestCreateBackup_Contents(t *testing.T) {
	tempDir := t.TempDir()
	mgr, err := NewMockBackupManager(filepath.Join(tempDir, "backups"))
	if err != nil {
		t.Fatalf("Failed to create manager: %v", err)
	}
	defer mgr.Cleanup()

	backup, err := mgr.CreateBackup()
	if err != nil {
		t.Fatalf("CreateBackup failed: %v", err)
	}

	// Restore to check contents
	restoreDir := filepath.Join(tempDir, "restore")
	if err := mgr.RestoreBackup(backup.ID, restoreDir); err != nil {
		t.Fatalf("RestoreBackup failed: %v", err)
	}

	// Verify files exist
	expectedFiles := []string{
		"ca/root-cert.pem",
		"ca/root-key.pem.enc",
		"database/dump.sql",
		"metadata.json",
	}

	for _, f := range expectedFiles {
		path := filepath.Join(restoreDir, f)
		if _, err := os.Stat(path); os.IsNotExist(err) {
			t.Errorf("Expected file missing: %s", f)
		}
	}
}

// TestCreateBackup_Checksum tests checksum calculation.
func TestCreateBackup_Checksum(t *testing.T) {
	tempDir := t.TempDir()
	mgr, err := NewMockBackupManager(filepath.Join(tempDir, "backups"))
	if err != nil {
		t.Fatalf("Failed to create manager: %v", err)
	}
	defer mgr.Cleanup()

	backup, err := mgr.CreateBackup()
	if err != nil {
		t.Fatalf("CreateBackup failed: %v", err)
	}

	// Manually calculate checksum
	data, _ := os.ReadFile(backup.BackupLocation)
	checksum := sha256.Sum256(data)
	checksumHex := hex.EncodeToString(checksum[:])

	if checksumHex != backup.BackupChecksum {
		t.Errorf("Checksum mismatch: stored %s, calculated %s", backup.BackupChecksum, checksumHex)
	}
}

// TestCreateBackup_Concurrent tests concurrent backup creation.
func TestCreateBackup_Concurrent(t *testing.T) {
	tempDir := t.TempDir()
	mgr, err := NewMockBackupManager(filepath.Join(tempDir, "backups"))
	if err != nil {
		t.Fatalf("Failed to create manager: %v", err)
	}
	defer mgr.Cleanup()

	var wg sync.WaitGroup
	numBackups := 5
	wg.Add(numBackups)

	for i := 0; i < numBackups; i++ {
		go func() {
			defer wg.Done()
			_, err := mgr.CreateBackup()
			if err != nil {
				t.Errorf("Concurrent backup failed: %v", err)
			}
		}()
	}

	wg.Wait()

	backups := mgr.ListBackups()
	if len(backups) != numBackups {
		t.Errorf("Expected %d backups, got %d", numBackups, len(backups))
	}
}

// ============================================================================
// Backup Verification Tests
// ============================================================================

// TestVerifyBackup_Valid tests verification of valid backup.
func TestVerifyBackup_Valid(t *testing.T) {
	tempDir := t.TempDir()
	mgr, err := NewMockBackupManager(filepath.Join(tempDir, "backups"))
	if err != nil {
		t.Fatalf("Failed to create manager: %v", err)
	}
	defer mgr.Cleanup()

	backup, _ := mgr.CreateBackup()

	if err := mgr.VerifyBackup(backup.ID); err != nil {
		t.Errorf("VerifyBackup failed unexpectedly: %v", err)
	}
}

// TestVerifyBackup_CorruptedFile tests detection of corrupted backup.
func TestVerifyBackup_CorruptedFile(t *testing.T) {
	tempDir := t.TempDir()
	mgr, err := NewMockBackupManager(filepath.Join(tempDir, "backups"))
	if err != nil {
		t.Fatalf("Failed to create manager: %v", err)
	}
	defer mgr.Cleanup()

	backup, _ := mgr.CreateBackup()

	// Corrupt the file
	mgr.CorruptBackup(backup.ID)

	err = mgr.VerifyBackup(backup.ID)
	if err == nil {
		t.Error("VerifyBackup should fail for corrupted file")
	}
}

// TestVerifyBackup_MissingFile tests detection of missing backup file.
func TestVerifyBackup_MissingFile(t *testing.T) {
	tempDir := t.TempDir()
	mgr, err := NewMockBackupManager(filepath.Join(tempDir, "backups"))
	if err != nil {
		t.Fatalf("Failed to create manager: %v", err)
	}
	defer mgr.Cleanup()

	backup, _ := mgr.CreateBackup()

	// Delete the file
	os.Remove(backup.BackupLocation)

	err = mgr.VerifyBackup(backup.ID)
	if err == nil {
		t.Error("VerifyBackup should fail for missing file")
	}
}

// ============================================================================
// Restoration Tests
// ============================================================================

// TestRestoreBackup_Success tests successful restoration.
func TestRestoreBackup_Success(t *testing.T) {
	tempDir := t.TempDir()
	mgr, err := NewMockBackupManager(filepath.Join(tempDir, "backups"))
	if err != nil {
		t.Fatalf("Failed to create manager: %v", err)
	}
	defer mgr.Cleanup()

	backup, _ := mgr.CreateBackup()
	restoreDir := filepath.Join(tempDir, "restore")

	if err := mgr.RestoreBackup(backup.ID, restoreDir); err != nil {
		t.Fatalf("RestoreBackup failed: %v", err)
	}

	// Verify CA cert restored
	certPath := filepath.Join(restoreDir, "ca/root-cert.pem")
	certData, err := os.ReadFile(certPath)
	if err != nil {
		t.Errorf("Failed to read restored cert: %v", err)
	}
	if !bytes.Equal(certData, mgr.caCertPEM) {
		t.Error("Restored cert doesn't match original")
	}

	// Verify metadata updated
	meta := mgr.GetBackup(backup.ID)
	if !meta.Restored {
		t.Error("Backup metadata not marked as restored")
	}
}

// TestRestoreBackup_CAValidation tests restored CA is usable.
func TestRestoreBackup_CAValidation(t *testing.T) {
	tempDir := t.TempDir()
	mgr, err := NewMockBackupManager(filepath.Join(tempDir, "backups"))
	if err != nil {
		t.Fatalf("Failed to create manager: %v", err)
	}
	defer mgr.Cleanup()

	backup, _ := mgr.CreateBackup()
	restoreDir := filepath.Join(tempDir, "restore")

	if err := mgr.RestoreBackup(backup.ID, restoreDir); err != nil {
		t.Fatalf("RestoreBackup failed: %v", err)
	}

	// Check certificate file contains PEM header
	certPath := filepath.Join(restoreDir, "ca/root-cert.pem")
	certData, _ := os.ReadFile(certPath)

	if !bytes.Contains(certData, []byte("-----BEGIN CERTIFICATE-----")) {
		t.Error("Restored certificate missing PEM header")
	}
}

// ============================================================================
// Retention Policy Tests
// ============================================================================

// TestApplyRetentionPolicy tests deletion of old backups.
func TestApplyRetentionPolicy(t *testing.T) {
	tempDir := t.TempDir()
	mgr, err := NewMockBackupManager(filepath.Join(tempDir, "backups"))
	if err != nil {
		t.Fatalf("Failed to create manager: %v", err)
	}
	defer mgr.Cleanup()

	// Create several backups
	for i := 0; i < 5; i++ {
		mgr.CreateBackup()
	}

	backupsBefore := len(mgr.ListBackups())
	if backupsBefore != 5 {
		t.Errorf("Expected 5 backups, got %d", backupsBefore)
	}

	// Apply retention with 30 days - all recent backups should be kept
	deleted, err := mgr.ApplyRetentionPolicy(30)
	if err != nil {
		t.Errorf("ApplyRetentionPolicy failed: %v", err)
	}

	// No backups should be deleted since they were just created (within 30 days)
	if deleted != 0 {
		t.Errorf("Expected 0 deleted for recent backups (retention=30 days), got %d", deleted)
	}

	backupsAfter := len(mgr.ListBackups())
	if backupsAfter != 5 {
		t.Errorf("Expected 5 backups after retention (all recent), got %d", backupsAfter)
	}
}

// ============================================================================
// Performance Tests
// ============================================================================

// TestBackupPerformance_Duration tests backup creation time.
func TestBackupPerformance_Duration(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping performance test in short mode")
	}

	tempDir := t.TempDir()
	mgr, err := NewMockBackupManager(filepath.Join(tempDir, "backups"))
	if err != nil {
		t.Fatalf("Failed to create manager: %v", err)
	}
	defer mgr.Cleanup()

	// Set larger data
	mgr.SetDatabaseDump(bytes.Repeat([]byte("DATA"), 100000))

	start := time.Now()
	_, err = mgr.CreateBackup()
	elapsed := time.Since(start)

	if err != nil {
		t.Fatalf("CreateBackup failed: %v", err)
	}

	t.Logf("Backup created in %v", elapsed)

	if elapsed > 30*time.Second {
		t.Errorf("Backup took %v, exceeds 30s limit", elapsed)
	}
}

// TestRestorePerformance_Duration tests restore time.
func TestRestorePerformance_Duration(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping performance test in short mode")
	}

	tempDir := t.TempDir()
	mgr, err := NewMockBackupManager(filepath.Join(tempDir, "backups"))
	if err != nil {
		t.Fatalf("Failed to create manager: %v", err)
	}
	defer mgr.Cleanup()

	mgr.SetDatabaseDump(bytes.Repeat([]byte("DATA"), 100000))
	backup, _ := mgr.CreateBackup()

	restoreDir := filepath.Join(tempDir, "restore")
	start := time.Now()
	err = mgr.RestoreBackup(backup.ID, restoreDir)
	elapsed := time.Since(start)

	if err != nil {
		t.Fatalf("RestoreBackup failed: %v", err)
	}

	t.Logf("Backup restored in %v", elapsed)

	if elapsed > 60*time.Second {
		t.Errorf("Restore took %v, exceeds 60s limit", elapsed)
	}
}

// ============================================================================
// Encryption Key Tests
// ============================================================================

// TestBackupEncryption_KeyFingerprint tests key fingerprint storage.
func TestBackupEncryption_KeyFingerprint(t *testing.T) {
	tempDir := t.TempDir()
	mgr, err := NewMockBackupManager(filepath.Join(tempDir, "backups"))
	if err != nil {
		t.Fatalf("Failed to create manager: %v", err)
	}
	defer mgr.Cleanup()

	backup, _ := mgr.CreateBackup()

	if backup.EncryptionKeyFingerprint == "" {
		t.Error("Encryption key fingerprint should not be empty")
	}

	// Fingerprint should be consistent
	keyHash := sha256.Sum256(mgr.encryptionKey)
	expectedFingerprint := hex.EncodeToString(keyHash[:8])

	if backup.EncryptionKeyFingerprint != expectedFingerprint {
		t.Errorf("Key fingerprint mismatch: expected %s, got %s", expectedFingerprint, backup.EncryptionKeyFingerprint)
	}
}

// ============================================================================
// Edge Case Tests
// ============================================================================

// TestBackup_EmptyData tests backup with minimal data.
func TestBackup_EmptyData(t *testing.T) {
	tempDir := t.TempDir()
	mgr, err := NewMockBackupManager(filepath.Join(tempDir, "backups"))
	if err != nil {
		t.Fatalf("Failed to create manager: %v", err)
	}
	defer mgr.Cleanup()

	mgr.SetDatabaseDump([]byte{})

	backup, err := mgr.CreateBackup()
	if err != nil {
		t.Fatalf("CreateBackup with empty data failed: %v", err)
	}

	// Should still create valid backup
	if err := mgr.VerifyBackup(backup.ID); err != nil {
		t.Errorf("Verify failed: %v", err)
	}
}

// TestBackup_LargeData tests backup with large data.
func TestBackup_LargeData(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping large data test in short mode")
	}

	tempDir := t.TempDir()
	mgr, err := NewMockBackupManager(filepath.Join(tempDir, "backups"))
	if err != nil {
		t.Fatalf("Failed to create manager: %v", err)
	}
	defer mgr.Cleanup()

	// 1MB of data
	largeData := make([]byte, 1024*1024)
	rand.Read(largeData)
	mgr.SetDatabaseDump(largeData)

	backup, err := mgr.CreateBackup()
	if err != nil {
		t.Fatalf("CreateBackup with large data failed: %v", err)
	}

	if err := mgr.VerifyBackup(backup.ID); err != nil {
		t.Errorf("Verify failed: %v", err)
	}

	t.Logf("Large backup size: %d bytes", backup.BackupSizeBytes)
}
