package security

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"log"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"time"

	"golang.org/x/crypto/pbkdf2"
)

// ============================================================================
// Errors
// ============================================================================

var (
	ErrBackupFailed      = errors.New("backup creation failed")
	ErrRestoreFailed     = errors.New("backup restoration failed")
	ErrBackupNotFound    = errors.New("backup not found")
	ErrBackupCorrupted   = errors.New("backup is corrupted or tampered")
	ErrInvalidPassphrase = errors.New("invalid backup passphrase")
)

// ============================================================================
// Configuration
// ============================================================================

// BackupConfig configures the backup system.
type BackupConfig struct {
	Enabled          bool
	Interval         time.Duration
	Location         string // Backup storage directory
	RetentionDaily   int    // Number of daily backups to keep
	RetentionWeekly  int    // Number of weekly backups to keep
	RetentionMonthly int    // Number of monthly backups to keep
	MaxAgeDays       int    // Maximum backup age
	CAKeyPath        string // Path to encrypted CA key
	CACertPath       string // Path to CA certificate
	PassphrasePath   string // Path to CA passphrase
	ConfigPath       string // Path to configuration
}

// DefaultBackupConfig returns default configuration.
func DefaultBackupConfig() *BackupConfig {
	return &BackupConfig{
		Enabled:          true,
		Interval:         24 * time.Hour,
		Location:         "/var/backups/safeops/ca/",
		RetentionDaily:   7,
		RetentionWeekly:  4,
		RetentionMonthly: 12,
		MaxAgeDays:       90,
		CAKeyPath:        "/etc/safeops/ca/root-key.pem.enc",
		CACertPath:       "/etc/safeops/ca/root-cert.pem",
		PassphrasePath:   "/etc/safeops/secrets/ca_passphrase",
		ConfigPath:       "/etc/safeops/config/certificate_manager.toml",
	}
}

// ============================================================================
// Backup Metadata
// ============================================================================

// BackupMetadata contains metadata about a backup.
type BackupMetadata struct {
	ID          string    `json:"id"`
	Timestamp   time.Time `json:"timestamp"`
	BackupPath  string    `json:"backup_path"`
	BackupSize  int64     `json:"backup_size"`
	Checksum    string    `json:"checksum"`
	PerformedBy string    `json:"performed_by"`
	BackupType  string    `json:"backup_type"` // "manual", "scheduled", "pre_restore"
	Encrypted   bool      `json:"encrypted"`
	Restored    bool      `json:"restored"`
	RestoredAt  time.Time `json:"restored_at,omitempty"`
	RestoredBy  string    `json:"restored_by,omitempty"`
}

// ============================================================================
// Backup Manager
// ============================================================================

// BackupManager handles CA backup and restore operations.
type BackupManager struct {
	config      *BackupConfig
	auditLogger *AuditLogger

	// Scheduler
	stopCh chan struct{}
	wg     sync.WaitGroup

	// Statistics
	backupCount  int64
	restoreCount int64
	totalSize    int64
	lastBackup   time.Time
}

// NewBackupManager creates a new backup manager.
func NewBackupManager(config *BackupConfig) *BackupManager {
	if config == nil {
		config = DefaultBackupConfig()
	}

	return &BackupManager{
		config: config,
		stopCh: make(chan struct{}),
	}
}

// SetAuditLogger sets the audit logger.
func (bm *BackupManager) SetAuditLogger(logger *AuditLogger) {
	bm.auditLogger = logger
}

// ============================================================================
// Backup Creation
// ============================================================================

// CreateBackup creates a complete backup of CA infrastructure.
func (bm *BackupManager) CreateBackup(passphrase, performedBy string) (*BackupMetadata, error) {
	// Generate backup ID
	timestamp := time.Now()
	backupID := fmt.Sprintf("backup_%s_%s",
		timestamp.Format("20060102_150405"),
		generateShortID())

	// Create temporary directory
	tmpDir, err := os.MkdirTemp("", "safeops_backup_")
	if err != nil {
		return nil, fmt.Errorf("%w: failed to create temp dir: %v", ErrBackupFailed, err)
	}
	defer os.RemoveAll(tmpDir)

	// Collect backup files
	backupFiles := make(map[string][]byte)

	// CA Certificate
	if data, err := os.ReadFile(bm.config.CACertPath); err == nil {
		backupFiles["ca/root-cert.pem"] = data
	}

	// Encrypted CA Key
	if data, err := os.ReadFile(bm.config.CAKeyPath); err == nil {
		backupFiles["ca/root-key.pem.enc"] = data
	}

	// CA Passphrase
	if data, err := os.ReadFile(bm.config.PassphrasePath); err == nil {
		backupFiles["secrets/passphrase"] = data
	}

	// Configuration
	if data, err := os.ReadFile(bm.config.ConfigPath); err == nil {
		backupFiles["config/certificate_manager.toml"] = data
	}

	// Create TAR archive
	tarBuffer := new(bytes.Buffer)
	if err := bm.createTarArchive(tarBuffer, backupFiles); err != nil {
		return nil, fmt.Errorf("%w: failed to create archive: %v", ErrBackupFailed, err)
	}

	// Compress with gzip
	gzipBuffer := new(bytes.Buffer)
	gzipWriter := gzip.NewWriter(gzipBuffer)
	if _, err := gzipWriter.Write(tarBuffer.Bytes()); err != nil {
		return nil, fmt.Errorf("%w: failed to compress: %v", ErrBackupFailed, err)
	}
	gzipWriter.Close()

	// Encrypt backup
	encryptedData, err := bm.encryptBackup(gzipBuffer.Bytes(), passphrase)
	if err != nil {
		return nil, fmt.Errorf("%w: failed to encrypt: %v", ErrBackupFailed, err)
	}

	// Calculate checksum
	checksum := sha256.Sum256(encryptedData)
	checksumHex := hex.EncodeToString(checksum[:])

	// Ensure backup directory exists
	if err := os.MkdirAll(bm.config.Location, 0700); err != nil {
		return nil, fmt.Errorf("%w: failed to create backup dir: %v", ErrBackupFailed, err)
	}

	// Write backup file
	backupFilename := backupID + ".tar.gz.enc"
	backupPath := filepath.Join(bm.config.Location, backupFilename)
	if err := os.WriteFile(backupPath, encryptedData, 0600); err != nil {
		return nil, fmt.Errorf("%w: failed to write backup: %v", ErrBackupFailed, err)
	}

	// Create metadata
	metadata := &BackupMetadata{
		ID:          backupID,
		Timestamp:   timestamp,
		BackupPath:  backupPath,
		BackupSize:  int64(len(encryptedData)),
		Checksum:    checksumHex,
		PerformedBy: performedBy,
		BackupType:  "manual",
		Encrypted:   true,
	}

	// Update statistics
	atomic.AddInt64(&bm.backupCount, 1)
	atomic.AddInt64(&bm.totalSize, metadata.BackupSize)
	bm.lastBackup = timestamp

	// Audit log
	if bm.auditLogger != nil {
		bm.auditLogger.LogBackupCreation(backupPath, metadata.BackupSize, performedBy)
	}

	log.Printf("[backup] Created backup: %s (%d bytes)", backupID, metadata.BackupSize)

	return metadata, nil
}

// createTarArchive creates a TAR archive from files.
func (bm *BackupManager) createTarArchive(w io.Writer, files map[string][]byte) error {
	tw := tar.NewWriter(w)
	defer tw.Close()

	for name, data := range files {
		header := &tar.Header{
			Name:    name,
			Mode:    0600,
			Size:    int64(len(data)),
			ModTime: time.Now(),
		}

		if err := tw.WriteHeader(header); err != nil {
			return err
		}

		if _, err := tw.Write(data); err != nil {
			return err
		}
	}

	return nil
}

// ============================================================================
// Backup Encryption
// ============================================================================

// encryptBackup encrypts backup data with AES-256-GCM.
func (bm *BackupManager) encryptBackup(data []byte, passphrase string) ([]byte, error) {
	// Generate salt
	salt := make([]byte, 16)
	if _, err := io.ReadFull(rand.Reader, salt); err != nil {
		return nil, err
	}

	// Derive key
	key := pbkdf2.Key([]byte(passphrase), salt, 100000, 32, sha256.New)

	// Generate nonce
	nonce := make([]byte, 12)
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, err
	}

	// Create cipher
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	// Encrypt
	ciphertext := gcm.Seal(nil, nonce, data, nil)

	// Build output: salt + nonce + ciphertext
	result := make([]byte, 0, len(salt)+len(nonce)+len(ciphertext))
	result = append(result, salt...)
	result = append(result, nonce...)
	result = append(result, ciphertext...)

	return result, nil
}

// decryptBackup decrypts backup data.
func (bm *BackupManager) decryptBackup(encryptedData []byte, passphrase string) ([]byte, error) {
	if len(encryptedData) < 28 { // salt (16) + nonce (12)
		return nil, ErrBackupCorrupted
	}

	// Extract salt, nonce, ciphertext
	salt := encryptedData[:16]
	nonce := encryptedData[16:28]
	ciphertext := encryptedData[28:]

	// Derive key
	key := pbkdf2.Key([]byte(passphrase), salt, 100000, 32, sha256.New)

	// Create cipher
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	// Decrypt
	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, ErrInvalidPassphrase
	}

	return plaintext, nil
}

// ============================================================================
// Backup Verification
// ============================================================================

// VerifyBackup verifies backup integrity.
func (bm *BackupManager) VerifyBackup(backupPath, expectedChecksum string) error {
	// Read backup
	data, err := os.ReadFile(backupPath)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrBackupNotFound, err)
	}

	// Calculate checksum
	checksum := sha256.Sum256(data)
	checksumHex := hex.EncodeToString(checksum[:])

	if checksumHex != expectedChecksum {
		return fmt.Errorf("%w: checksum mismatch", ErrBackupCorrupted)
	}

	return nil
}

// ============================================================================
// Backup Restoration
// ============================================================================

// RestoreBackup restores CA from backup.
func (bm *BackupManager) RestoreBackup(backupPath, passphrase, performedBy string) error {
	// Read encrypted backup
	encryptedData, err := os.ReadFile(backupPath)
	if err != nil {
		return fmt.Errorf("%w: failed to read backup: %v", ErrRestoreFailed, err)
	}

	// Decrypt
	compressedData, err := bm.decryptBackup(encryptedData, passphrase)
	if err != nil {
		return fmt.Errorf("%w: decryption failed: %v", ErrRestoreFailed, err)
	}

	// Decompress
	gzipReader, err := gzip.NewReader(bytes.NewReader(compressedData))
	if err != nil {
		return fmt.Errorf("%w: decompression failed: %v", ErrRestoreFailed, err)
	}
	defer gzipReader.Close()

	tarData, err := io.ReadAll(gzipReader)
	if err != nil {
		return fmt.Errorf("%w: decompression failed: %v", ErrRestoreFailed, err)
	}

	// Extract files
	files, err := bm.extractTarArchive(bytes.NewReader(tarData))
	if err != nil {
		return fmt.Errorf("%w: extraction failed: %v", ErrRestoreFailed, err)
	}

	// Restore files
	for name, data := range files {
		var targetPath string
		switch {
		case name == "ca/root-cert.pem":
			targetPath = bm.config.CACertPath
		case name == "ca/root-key.pem.enc":
			targetPath = bm.config.CAKeyPath
		case name == "secrets/passphrase":
			targetPath = bm.config.PassphrasePath
		case name == "config/certificate_manager.toml":
			targetPath = bm.config.ConfigPath
		default:
			continue
		}

		// Ensure directory exists
		if err := os.MkdirAll(filepath.Dir(targetPath), 0700); err != nil {
			return fmt.Errorf("%w: failed to create directory: %v", ErrRestoreFailed, err)
		}

		// Write file
		if err := os.WriteFile(targetPath, data, 0600); err != nil {
			return fmt.Errorf("%w: failed to write file: %v", ErrRestoreFailed, err)
		}

		log.Printf("[backup] Restored: %s", targetPath)
	}

	// Update statistics
	atomic.AddInt64(&bm.restoreCount, 1)

	// Audit log
	if bm.auditLogger != nil {
		bm.auditLogger.LogOperation(OpBackupRestored, backupPath, performedBy, true, nil)
	}

	log.Printf("[backup] Backup restored successfully by %s", performedBy)

	return nil
}

// extractTarArchive extracts files from TAR archive.
func (bm *BackupManager) extractTarArchive(r io.Reader) (map[string][]byte, error) {
	tr := tar.NewReader(r)
	files := make(map[string][]byte)

	for {
		header, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, err
		}

		data, err := io.ReadAll(tr)
		if err != nil {
			return nil, err
		}

		files[header.Name] = data
	}

	return files, nil
}

// ============================================================================
// Scheduler
// ============================================================================

// Start starts the backup scheduler.
func (bm *BackupManager) Start(passphrase string) error {
	if !bm.config.Enabled {
		return nil
	}

	// Run initial backup
	go func() {
		if _, err := bm.CreateBackup(passphrase, "scheduled"); err != nil {
			log.Printf("[backup] Initial backup failed: %v", err)
		}
	}()

	// Start scheduler
	bm.wg.Add(1)
	go bm.schedulerLoop(passphrase)

	return nil
}

// Stop stops the backup scheduler.
func (bm *BackupManager) Stop() {
	close(bm.stopCh)
	bm.wg.Wait()
}

// schedulerLoop runs periodic backups.
func (bm *BackupManager) schedulerLoop(passphrase string) {
	defer bm.wg.Done()

	ticker := time.NewTicker(bm.config.Interval)
	defer ticker.Stop()

	for {
		select {
		case <-bm.stopCh:
			return
		case <-ticker.C:
			if _, err := bm.CreateBackup(passphrase, "scheduled"); err != nil {
				log.Printf("[backup] Scheduled backup failed: %v", err)
			}
			// Enforce retention after backup
			bm.EnforceRetention()
		}
	}
}

// ============================================================================
// Retention Management
// ============================================================================

// EnforceRetention deletes old backups per retention policy.
func (bm *BackupManager) EnforceRetention() error {
	entries, err := os.ReadDir(bm.config.Location)
	if err != nil {
		return err
	}

	maxAge := time.Duration(bm.config.MaxAgeDays) * 24 * time.Hour
	cutoff := time.Now().Add(-maxAge)

	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}

		info, err := entry.Info()
		if err != nil {
			continue
		}

		// Delete if older than max age
		if info.ModTime().Before(cutoff) {
			backupPath := filepath.Join(bm.config.Location, entry.Name())
			if err := os.Remove(backupPath); err != nil {
				log.Printf("[backup] Failed to delete old backup: %v", err)
			} else {
				log.Printf("[backup] Deleted old backup: %s", entry.Name())
			}
		}
	}

	return nil
}

// ============================================================================
// Statistics
// ============================================================================

// BackupStats contains backup statistics.
type BackupStats struct {
	BackupCount   int64     `json:"backup_count"`
	RestoreCount  int64     `json:"restore_count"`
	TotalSize     int64     `json:"total_size_bytes"`
	LastBackup    time.Time `json:"last_backup"`
	BackupsOnDisk int       `json:"backups_on_disk"`
}

// GetStats returns backup statistics.
func (bm *BackupManager) GetStats() *BackupStats {
	backupsOnDisk := 0
	entries, err := os.ReadDir(bm.config.Location)
	if err == nil {
		for _, e := range entries {
			if !e.IsDir() {
				backupsOnDisk++
			}
		}
	}

	return &BackupStats{
		BackupCount:   atomic.LoadInt64(&bm.backupCount),
		RestoreCount:  atomic.LoadInt64(&bm.restoreCount),
		TotalSize:     atomic.LoadInt64(&bm.totalSize),
		LastBackup:    bm.lastBackup,
		BackupsOnDisk: backupsOnDisk,
	}
}

// ============================================================================
// Utility Functions
// ============================================================================

// generateShortID generates a short random ID.
func generateShortID() string {
	bytes := make([]byte, 4)
	rand.Read(bytes)
	return hex.EncodeToString(bytes)
}

// ListBackups returns all backups in the backup location.
func (bm *BackupManager) ListBackups() ([]BackupMetadata, error) {
	entries, err := os.ReadDir(bm.config.Location)
	if err != nil {
		return nil, err
	}

	var backups []BackupMetadata
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}

		info, err := entry.Info()
		if err != nil {
			continue
		}

		backups = append(backups, BackupMetadata{
			ID:         entry.Name(),
			Timestamp:  info.ModTime(),
			BackupPath: filepath.Join(bm.config.Location, entry.Name()),
			BackupSize: info.Size(),
			Encrypted:  true,
		})
	}

	return backups, nil
}
