// Package storage provides filesystem storage for certificates and private keys.
package storage

import (
	"bytes"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"certificate_manager/pkg/types"
)

// ============================================================================
// Constants
// ============================================================================

const (
	CertFileExtension  = ".crt"
	KeyFileExtension   = ".key"
	ChainFileExtension = ".chain.crt"
	FullChainExtension = ".fullchain.crt"
	BackupExtension    = ".backup"
	TempExtension      = ".tmp"

	DefaultCertPermissions = 0644 // World-readable certs
	DefaultKeyPermissions  = 0600 // Owner-only keys
	DefaultDirPermissions  = 0755

	DefaultBackupRetention = 5 // Keep last 5 versions
)

// ============================================================================
// Error Types
// ============================================================================

var (
	ErrFileNotFound     = errors.New("file not found")
	ErrPermissionDenied = errors.New("permission denied")
	ErrInvalidPEM       = errors.New("invalid PEM data")
	ErrKeyPermissions   = errors.New("private key has insecure permissions")
	ErrCertKeyMismatch  = errors.New("certificate and private key do not match")
	ErrStorageNotReady  = errors.New("storage not initialized")
)

// ============================================================================
// Filesystem Storage Structure
// ============================================================================

// FilesystemStorage manages file-based certificate storage
type FilesystemStorage struct {
	certPath   string
	keyPath    string
	chainPath  string
	backupPath string

	certPermissions int
	keyPermissions  int
	backupRetention int

	mu sync.RWMutex
}

// ============================================================================
// Storage Initialization
// ============================================================================

// NewFilesystemStorage creates a new filesystem storage instance
func NewFilesystemStorage(config types.StorageConfig) (*FilesystemStorage, error) {
	fs := &FilesystemStorage{
		certPath:        config.CertPath,
		keyPath:         config.KeyPath,
		chainPath:       config.ChainPath,
		backupPath:      config.BackupPath,
		certPermissions: DefaultCertPermissions,
		keyPermissions:  DefaultKeyPermissions,
		backupRetention: DefaultBackupRetention,
	}

	// Use cert path as key path if not specified
	if fs.keyPath == "" {
		fs.keyPath = fs.certPath
	}
	if fs.chainPath == "" {
		fs.chainPath = fs.certPath
	}
	if fs.backupPath == "" {
		fs.backupPath = filepath.Join(fs.certPath, "backups")
	}

	// Apply custom permissions if set
	if config.FilePermissions > 0 {
		fs.keyPermissions = config.FilePermissions
	}

	// Create directories
	dirs := []string{fs.certPath, fs.keyPath, fs.chainPath, fs.backupPath}
	for _, dir := range dirs {
		if dir == "" {
			continue
		}
		if err := os.MkdirAll(dir, DefaultDirPermissions); err != nil {
			return nil, fmt.Errorf("failed to create directory %s: %w", dir, err)
		}

		// Verify write permissions
		if err := verifyWritable(dir); err != nil {
			return nil, fmt.Errorf("directory not writable %s: %w", dir, err)
		}
	}

	return fs, nil
}

// verifyWritable checks if directory is writable
func verifyWritable(dir string) error {
	testFile := filepath.Join(dir, ".write_test")
	f, err := os.Create(testFile)
	if err != nil {
		return err
	}
	f.Close()
	return os.Remove(testFile)
}

// ============================================================================
// Certificate File Operations
// ============================================================================

// StoreCertificate writes PEM-encoded certificate to file
func (fs *FilesystemStorage) StoreCertificate(domain string, certPEM []byte) error {
	if err := validatePEM(certPEM, "CERTIFICATE"); err != nil {
		return err
	}

	path := fs.GetCertificatePath(domain)
	return fs.atomicWriteFile(path, certPEM, os.FileMode(fs.certPermissions))
}

// StoreFullChain writes certificate + chain to single file
func (fs *FilesystemStorage) StoreFullChain(domain string, certPEM, chainPEM []byte) error {
	if err := validatePEM(certPEM, "CERTIFICATE"); err != nil {
		return err
	}

	// Combine cert and chain
	fullChain := append(certPEM, chainPEM...)

	path := fs.GetFullChainPath(domain)
	return fs.atomicWriteFile(path, fullChain, os.FileMode(fs.certPermissions))
}

// StoreCertificateChain writes chain separately
func (fs *FilesystemStorage) StoreCertificateChain(domain string, chainPEM []byte) error {
	path := fs.GetChainPath(domain)
	return fs.atomicWriteFile(path, chainPEM, os.FileMode(fs.certPermissions))
}

// UpdateCertificate replaces certificate with backup
func (fs *FilesystemStorage) UpdateCertificate(domain string, certPEM []byte) error {
	// Backup existing certificate first
	if err := fs.BackupCertificate(domain); err != nil && !errors.Is(err, ErrFileNotFound) {
		return fmt.Errorf("backup failed: %w", err)
	}

	return fs.StoreCertificate(domain, certPEM)
}

// ============================================================================
// Private Key File Operations
// ============================================================================

// StorePrivateKey writes PEM-encoded private key with restrictive permissions
func (fs *FilesystemStorage) StorePrivateKey(domain string, keyPEM []byte) error {
	if err := validatePEM(keyPEM, "PRIVATE KEY"); err != nil {
		// Also accept RSA PRIVATE KEY and EC PRIVATE KEY
		if err := validatePEM(keyPEM, "RSA PRIVATE KEY"); err != nil {
			if err := validatePEM(keyPEM, "EC PRIVATE KEY"); err != nil {
				return ErrInvalidPEM
			}
		}
	}

	path := fs.GetPrivateKeyPath(domain)
	return fs.atomicWriteFile(path, keyPEM, os.FileMode(fs.keyPermissions))
}

// UpdatePrivateKey replaces key file with backup
func (fs *FilesystemStorage) UpdatePrivateKey(domain string, keyPEM []byte) error {
	// Backup existing key first
	if err := fs.BackupPrivateKey(domain); err != nil && !errors.Is(err, ErrFileNotFound) {
		return fmt.Errorf("backup failed: %w", err)
	}

	return fs.StorePrivateKey(domain, keyPEM)
}

// SecureKeyPermissions verifies and fixes key file permissions
func (fs *FilesystemStorage) SecureKeyPermissions(domain string) error {
	path := fs.GetPrivateKeyPath(domain)

	info, err := os.Stat(path)
	if err != nil {
		if os.IsNotExist(err) {
			return ErrFileNotFound
		}
		return err
	}

	mode := info.Mode().Perm()
	// Check if world or group readable
	if mode&0077 != 0 {
		// Fix permissions
		if err := os.Chmod(path, os.FileMode(fs.keyPermissions)); err != nil {
			return fmt.Errorf("failed to fix permissions: %w", err)
		}
	}

	return nil
}

// ============================================================================
// Certificate Retrieval Operations
// ============================================================================

// GetCertificate reads certificate file by domain name
func (fs *FilesystemStorage) GetCertificate(domain string) ([]byte, error) {
	path := fs.GetCertificatePath(domain)
	return fs.readFile(path)
}

// GetCertificateChain reads certificate chain file
func (fs *FilesystemStorage) GetCertificateChain(domain string) ([]byte, error) {
	path := fs.GetChainPath(domain)
	return fs.readFile(path)
}

// GetFullChain reads full chain file
func (fs *FilesystemStorage) GetFullChain(domain string) ([]byte, error) {
	path := fs.GetFullChainPath(domain)
	return fs.readFile(path)
}

// GetPrivateKey reads private key file with permission validation
func (fs *FilesystemStorage) GetPrivateKey(domain string) ([]byte, error) {
	path := fs.GetPrivateKeyPath(domain)

	// Validate permissions first
	info, err := os.Stat(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, ErrFileNotFound
		}
		return nil, err
	}

	// Check permissions (allow 0600 or stricter)
	mode := info.Mode().Perm()
	if mode&0077 != 0 {
		return nil, ErrKeyPermissions
	}

	return fs.readFile(path)
}

// readFile reads file contents
func (fs *FilesystemStorage) readFile(path string) ([]byte, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, ErrFileNotFound
		}
		if os.IsPermission(err) {
			return nil, ErrPermissionDenied
		}
		return nil, err
	}
	return data, nil
}

// ============================================================================
// File Naming and Organization
// ============================================================================

// GetCertificatePath builds full path for certificate file
func (fs *FilesystemStorage) GetCertificatePath(domain string) string {
	return filepath.Join(fs.certPath, sanitizeDomain(domain)+CertFileExtension)
}

// GetPrivateKeyPath builds full path for private key
func (fs *FilesystemStorage) GetPrivateKeyPath(domain string) string {
	return filepath.Join(fs.keyPath, sanitizeDomain(domain)+KeyFileExtension)
}

// GetChainPath builds full path for chain file
func (fs *FilesystemStorage) GetChainPath(domain string) string {
	return filepath.Join(fs.chainPath, sanitizeDomain(domain)+ChainFileExtension)
}

// GetFullChainPath builds full path for full chain file
func (fs *FilesystemStorage) GetFullChainPath(domain string) string {
	return filepath.Join(fs.certPath, sanitizeDomain(domain)+FullChainExtension)
}

// GetBackupPath builds timestamped backup path
func (fs *FilesystemStorage) GetBackupPath(domain, extension string) string {
	timestamp := time.Now().Format("2006-01-02_150405")
	filename := fmt.Sprintf("%s%s.%s%s", sanitizeDomain(domain), extension, timestamp, BackupExtension)
	return filepath.Join(fs.backupPath, filename)
}

// sanitizeDomain converts domain to safe filename
func sanitizeDomain(domain string) string {
	// Replace wildcards and special chars
	safe := strings.ReplaceAll(domain, "*.", "wildcard.")
	safe = strings.ReplaceAll(safe, "/", "_")
	safe = strings.ReplaceAll(safe, ":", "_")
	return safe
}

// ============================================================================
// Backup and Versioning
// ============================================================================

// BackupCertificate creates timestamped backup
func (fs *FilesystemStorage) BackupCertificate(domain string) error {
	srcPath := fs.GetCertificatePath(domain)
	dstPath := fs.GetBackupPath(domain, CertFileExtension)

	return fs.copyFile(srcPath, dstPath)
}

// BackupPrivateKey creates timestamped key backup
func (fs *FilesystemStorage) BackupPrivateKey(domain string) error {
	srcPath := fs.GetPrivateKeyPath(domain)
	dstPath := fs.GetBackupPath(domain, KeyFileExtension)

	return fs.copyFile(srcPath, dstPath)
}

// RestoreFromBackup reverts to previous certificate version
func (fs *FilesystemStorage) RestoreFromBackup(domain string, backupPath string) error {
	dstPath := fs.GetCertificatePath(domain)
	return fs.copyFile(backupPath, dstPath)
}

// ListBackups returns all backup versions for a domain
func (fs *FilesystemStorage) ListBackups(domain string) ([]string, error) {
	pattern := filepath.Join(fs.backupPath, sanitizeDomain(domain)+"*"+BackupExtension)

	matches, err := filepath.Glob(pattern)
	if err != nil {
		return nil, err
	}

	// Sort by modification time (newest first)
	sort.Slice(matches, func(i, j int) bool {
		infoI, _ := os.Stat(matches[i])
		infoJ, _ := os.Stat(matches[j])
		if infoI == nil || infoJ == nil {
			return false
		}
		return infoI.ModTime().After(infoJ.ModTime())
	})

	return matches, nil
}

// CleanOldBackups removes backups older than retention limit
func (fs *FilesystemStorage) CleanOldBackups(domain string) error {
	backups, err := fs.ListBackups(domain)
	if err != nil {
		return err
	}

	// Keep only the most recent backups
	if len(backups) <= fs.backupRetention {
		return nil
	}

	// Delete older backups
	for _, backup := range backups[fs.backupRetention:] {
		if err := os.Remove(backup); err != nil && !os.IsNotExist(err) {
			return fmt.Errorf("failed to delete backup %s: %w", backup, err)
		}
	}

	return nil
}

// ============================================================================
// Directory Structure Management
// ============================================================================

// ListStoredDomains returns all domains with stored certificates
func (fs *FilesystemStorage) ListStoredDomains() ([]string, error) {
	pattern := filepath.Join(fs.certPath, "*"+CertFileExtension)

	matches, err := filepath.Glob(pattern)
	if err != nil {
		return nil, err
	}

	domains := make([]string, 0, len(matches))
	for _, match := range matches {
		filename := filepath.Base(match)
		domain := strings.TrimSuffix(filename, CertFileExtension)
		// Restore wildcard format
		domain = strings.ReplaceAll(domain, "wildcard.", "*.")
		domains = append(domains, domain)
	}

	return domains, nil
}

// GetStorageUsage calculates total disk space used
func (fs *FilesystemStorage) GetStorageUsage() (int64, error) {
	var total int64

	dirs := []string{fs.certPath, fs.keyPath, fs.backupPath}
	seen := make(map[string]bool)

	for _, dir := range dirs {
		if dir == "" || seen[dir] {
			continue
		}
		seen[dir] = true

		err := filepath.Walk(dir, func(path string, info os.FileInfo, err error) error {
			if err != nil {
				return nil // Skip errors
			}
			if !info.IsDir() {
				total += info.Size()
			}
			return nil
		})
		if err != nil {
			return 0, err
		}
	}

	return total, nil
}

// CertificateExists checks if certificate file exists
func (fs *FilesystemStorage) CertificateExists(domain string) bool {
	path := fs.GetCertificatePath(domain)
	_, err := os.Stat(path)
	return err == nil
}

// ============================================================================
// Atomic Write Operations
// ============================================================================

// atomicWriteFile writes to temp file, syncs, then renames
func (fs *FilesystemStorage) atomicWriteFile(path string, data []byte, perm os.FileMode) error {
	fs.mu.Lock()
	defer fs.mu.Unlock()

	// Create temp file in same directory
	dir := filepath.Dir(path)
	tempFile, err := os.CreateTemp(dir, "*.tmp")
	if err != nil {
		return fmt.Errorf("failed to create temp file: %w", err)
	}
	tempPath := tempFile.Name()

	// Clean up temp file on failure
	defer func() {
		if tempPath != "" {
			os.Remove(tempPath)
		}
	}()

	// Write data
	if _, err := tempFile.Write(data); err != nil {
		tempFile.Close()
		return fmt.Errorf("failed to write data: %w", err)
	}

	// Sync to disk
	if err := tempFile.Sync(); err != nil {
		tempFile.Close()
		return fmt.Errorf("failed to sync file: %w", err)
	}

	// Close before rename
	if err := tempFile.Close(); err != nil {
		return fmt.Errorf("failed to close file: %w", err)
	}

	// Set permissions
	if err := os.Chmod(tempPath, perm); err != nil {
		return fmt.Errorf("failed to set permissions: %w", err)
	}

	// Atomic rename
	if err := os.Rename(tempPath, path); err != nil {
		return fmt.Errorf("failed to rename file: %w", err)
	}

	tempPath = "" // Prevent cleanup
	return nil
}

// copyFile copies a file atomically
func (fs *FilesystemStorage) copyFile(src, dst string) error {
	srcFile, err := os.Open(src)
	if err != nil {
		if os.IsNotExist(err) {
			return ErrFileNotFound
		}
		return err
	}
	defer srcFile.Close()

	srcInfo, err := srcFile.Stat()
	if err != nil {
		return err
	}

	data, err := io.ReadAll(srcFile)
	if err != nil {
		return err
	}

	return fs.atomicWriteFile(dst, data, srcInfo.Mode().Perm())
}

// ============================================================================
// Validation and Integrity Checks
// ============================================================================

// validatePEM checks if data is valid PEM format
func validatePEM(data []byte, expectedType string) error {
	block, _ := pem.Decode(data)
	if block == nil {
		return ErrInvalidPEM
	}

	// Check type if specified
	if expectedType != "" && !strings.Contains(block.Type, expectedType) {
		return fmt.Errorf("%w: expected %s, got %s", ErrInvalidPEM, expectedType, block.Type)
	}

	return nil
}

// ValidateCertificateFile checks PEM format and validity
func (fs *FilesystemStorage) ValidateCertificateFile(domain string) error {
	data, err := fs.GetCertificate(domain)
	if err != nil {
		return err
	}

	block, _ := pem.Decode(data)
	if block == nil {
		return ErrInvalidPEM
	}

	_, err = x509.ParseCertificate(block.Bytes)
	if err != nil {
		return fmt.Errorf("invalid certificate: %w", err)
	}

	return nil
}

// ValidateKeyFile checks key file exists and has correct permissions
func (fs *FilesystemStorage) ValidateKeyFile(domain string) error {
	_, err := fs.GetPrivateKey(domain)
	return err
}

// CheckCertKeyPair verifies certificate and private key match
func (fs *FilesystemStorage) CheckCertKeyPair(domain string) error {
	// Read certificate
	certPEM, err := fs.GetCertificate(domain)
	if err != nil {
		return fmt.Errorf("failed to read certificate: %w", err)
	}

	// Read private key
	keyPEM, err := fs.GetPrivateKey(domain)
	if err != nil {
		return fmt.Errorf("failed to read private key: %w", err)
	}

	// Parse certificate
	certBlock, _ := pem.Decode(certPEM)
	if certBlock == nil {
		return ErrInvalidPEM
	}

	cert, err := x509.ParseCertificate(certBlock.Bytes)
	if err != nil {
		return fmt.Errorf("failed to parse certificate: %w", err)
	}

	// Parse private key
	keyBlock, _ := pem.Decode(keyPEM)
	if keyBlock == nil {
		return ErrInvalidPEM
	}

	// Get public key from certificate and compare
	certPubKeyBytes, err := x509.MarshalPKIXPublicKey(cert.PublicKey)
	if err != nil {
		return err
	}

	// Parse the private key and extract public key
	var keyPubKeyBytes []byte
	switch keyBlock.Type {
	case "RSA PRIVATE KEY":
		rsaKey, err := x509.ParsePKCS1PrivateKey(keyBlock.Bytes)
		if err != nil {
			return err
		}
		keyPubKeyBytes, err = x509.MarshalPKIXPublicKey(&rsaKey.PublicKey)
		if err != nil {
			return err
		}
	case "EC PRIVATE KEY":
		ecKey, err := x509.ParseECPrivateKey(keyBlock.Bytes)
		if err != nil {
			return err
		}
		keyPubKeyBytes, err = x509.MarshalPKIXPublicKey(&ecKey.PublicKey)
		if err != nil {
			return err
		}
	case "PRIVATE KEY":
		key, err := x509.ParsePKCS8PrivateKey(keyBlock.Bytes)
		if err != nil {
			return err
		}
		keyPubKeyBytes, err = x509.MarshalPKIXPublicKey(publicKeyFromPrivate(key))
		if err != nil {
			return err
		}
	default:
		return fmt.Errorf("unsupported key type: %s", keyBlock.Type)
	}

	// Compare public keys
	if !bytes.Equal(certPubKeyBytes, keyPubKeyBytes) {
		return ErrCertKeyMismatch
	}

	return nil
}

// publicKeyFromPrivate extracts public key from private key
func publicKeyFromPrivate(key interface{}) interface{} {
	switch k := key.(type) {
	case interface{ Public() interface{} }:
		return k.Public()
	default:
		return nil
	}
}

// ============================================================================
// Cleanup and Maintenance
// ============================================================================

// DeleteCertificateFiles removes all files for a domain
func (fs *FilesystemStorage) DeleteCertificateFiles(domain string) error {
	files := []string{
		fs.GetCertificatePath(domain),
		fs.GetPrivateKeyPath(domain),
		fs.GetChainPath(domain),
		fs.GetFullChainPath(domain),
	}

	var lastErr error
	for _, file := range files {
		if err := os.Remove(file); err != nil && !os.IsNotExist(err) {
			lastErr = err
		}
	}

	return lastErr
}

// GenerateStorageReport creates summary of stored certificates
func (fs *FilesystemStorage) GenerateStorageReport() (*StorageReport, error) {
	domains, err := fs.ListStoredDomains()
	if err != nil {
		return nil, err
	}

	usage, err := fs.GetStorageUsage()
	if err != nil {
		return nil, err
	}

	report := &StorageReport{
		TotalDomains: len(domains),
		TotalBytes:   usage,
		Domains:      domains,
		GeneratedAt:  time.Now(),
		CertPath:     fs.certPath,
		KeyPath:      fs.keyPath,
		BackupPath:   fs.backupPath,
	}

	return report, nil
}

// StorageReport contains storage statistics
type StorageReport struct {
	TotalDomains int       `json:"total_domains"`
	TotalBytes   int64     `json:"total_bytes"`
	Domains      []string  `json:"domains"`
	GeneratedAt  time.Time `json:"generated_at"`
	CertPath     string    `json:"cert_path"`
	KeyPath      string    `json:"key_path"`
	BackupPath   string    `json:"backup_path"`
}
