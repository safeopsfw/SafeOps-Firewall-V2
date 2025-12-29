// Package ca implements secure filesystem storage for CA certificates and encrypted private keys.
// This file manages directory creation with restrictive permissions, atomic file writes,
// and secure storage/retrieval of CA artifacts to /etc/safeops/ca and /etc/safeops/secrets.
package ca

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"time"
)

// ============================================================================
// Storage Path Constants
// ============================================================================

const (
	// DefaultCADirectory is the CA certificate and key storage location
	DefaultCADirectory = "/etc/safeops/ca"
	// DefaultCADirectoryWindows is the Windows equivalent
	DefaultCADirectoryWindows = "C:\\ProgramData\\SafeOps\\ca"

	// DefaultSecretsDirectory is the passphrase storage location
	DefaultSecretsDirectory = "/etc/safeops/secrets"
	// DefaultSecretsDirectoryWindows is the Windows equivalent
	DefaultSecretsDirectoryWindows = "C:\\ProgramData\\SafeOps\\secrets"

	// CACertificateFilename is the CA certificate file (public)
	CACertificateFilename = "root-cert.pem"
	// CAPrivateKeyFilename is the encrypted private key file
	CAPrivateKeyFilename = "root-key.pem.enc"
	// CAPassphraseFilename is the passphrase file
	CAPassphraseFilename = "ca_passphrase"
	// CAMetadataFilename is the CA metadata JSON file
	CAMetadataFilename = "root-cert-metadata.json"
	// CRLFilename is the Certificate Revocation List
	CRLFilename = "crl.pem"

	// File permissions
	DirPermission         = 0700 // drwx------ (Owner only)
	CertificatePermission = 0644 // rw-r--r-- (World-readable, public cert)
	PrivateKeyPermission  = 0600 // rw------- (Owner only)
	PassphrasePermission  = 0400 // r-------- (Owner read-only)
	MetadataPermission    = 0644 // rw-r--r-- (World-readable metadata)
)

// ============================================================================
// Error Types
// ============================================================================

var (
	// ErrCANotFound indicates CA files do not exist
	ErrCANotFound = errors.New("CA certificate or private key not found")
	// ErrPassphraseNotFound indicates passphrase file not found
	ErrPassphraseNotFound = errors.New("passphrase file not found")
	// ErrInvalidPermissions indicates file has insecure permissions
	ErrInvalidPermissions = errors.New("file has insecure permissions")
	// ErrDirectoryCreationFailed indicates directory creation failed
	ErrDirectoryCreationFailed = errors.New("failed to create directory")
	// ErrFileWriteFailed indicates file write failed
	ErrFileWriteFailed = errors.New("failed to write file")
	// ErrFileReadFailed indicates file read failed
	ErrFileReadFailed = errors.New("failed to read file")
	// ErrInvalidCertificate indicates certificate parsing failed
	ErrInvalidCertificate = errors.New("invalid certificate format")
	// ErrInvalidPrivateKey indicates private key parsing failed
	ErrInvalidPrivateKey = errors.New("invalid private key format")
	// ErrNotCACertificate indicates certificate is not a CA
	ErrNotCACertificate = errors.New("certificate is not a CA certificate")
)

// ============================================================================
// Storage Configuration Structure
// ============================================================================

// CAStorageConfig defines storage paths for CA files.
// Allows configuration override for testing or non-standard deployments.
type CAStorageConfig struct {
	// CADirectory is the path to CA storage directory
	CADirectory string
	// SecretsDirectory is the path to secrets directory
	SecretsDirectory string
	// CACertPath is the full path to CA certificate file
	CACertPath string
	// CAKeyPath is the full path to encrypted private key file
	CAKeyPath string
	// PassphrasePath is the full path to passphrase file
	PassphrasePath string
	// MetadataPath is the full path to metadata JSON file
	MetadataPath string
}

// DefaultStorageConfig returns a CAStorageConfig with platform-appropriate defaults.
func DefaultStorageConfig() *CAStorageConfig {
	var caDir, secretsDir string

	if runtime.GOOS == "windows" {
		caDir = DefaultCADirectoryWindows
		secretsDir = DefaultSecretsDirectoryWindows
	} else {
		caDir = DefaultCADirectory
		secretsDir = DefaultSecretsDirectory
	}

	return &CAStorageConfig{
		CADirectory:      caDir,
		SecretsDirectory: secretsDir,
		CACertPath:       filepath.Join(caDir, CACertificateFilename),
		CAKeyPath:        filepath.Join(caDir, CAPrivateKeyFilename),
		PassphrasePath:   filepath.Join(secretsDir, CAPassphraseFilename),
		MetadataPath:     filepath.Join(caDir, CAMetadataFilename),
	}
}

// NewStorageConfig creates a CAStorageConfig with custom directories.
func NewStorageConfig(caDir, secretsDir string) *CAStorageConfig {
	return &CAStorageConfig{
		CADirectory:      caDir,
		SecretsDirectory: secretsDir,
		CACertPath:       filepath.Join(caDir, CACertificateFilename),
		CAKeyPath:        filepath.Join(caDir, CAPrivateKeyFilename),
		PassphrasePath:   filepath.Join(secretsDir, CAPassphraseFilename),
		MetadataPath:     filepath.Join(caDir, CAMetadataFilename),
	}
}

// ============================================================================
// Directory Creation
// ============================================================================

// EnsureDirectories creates CA and secrets directories with restrictive permissions.
// Directories are created with 0700 (drwx------) to allow only owner access.
func EnsureDirectories(config *CAStorageConfig) error {
	if config == nil {
		config = DefaultStorageConfig()
	}

	// Create CA directory
	if err := os.MkdirAll(config.CADirectory, DirPermission); err != nil {
		return fmt.Errorf("%w: %s: %v", ErrDirectoryCreationFailed, config.CADirectory, err)
	}

	// Ensure correct permissions on CA directory
	if err := os.Chmod(config.CADirectory, DirPermission); err != nil {
		return fmt.Errorf("failed to set permissions on %s: %w", config.CADirectory, err)
	}

	// Create secrets directory
	if err := os.MkdirAll(config.SecretsDirectory, DirPermission); err != nil {
		return fmt.Errorf("%w: %s: %v", ErrDirectoryCreationFailed, config.SecretsDirectory, err)
	}

	// Ensure correct permissions on secrets directory
	if err := os.Chmod(config.SecretsDirectory, DirPermission); err != nil {
		return fmt.Errorf("failed to set permissions on %s: %w", config.SecretsDirectory, err)
	}

	return nil
}

// ============================================================================
// Atomic Write Helper
// ============================================================================

// atomicWriteFile writes data to a file atomically using temp file + rename pattern.
// This ensures readers never see partial writes and prevents corruption during power loss.
func atomicWriteFile(path string, data []byte, perm os.FileMode) error {
	dir := filepath.Dir(path)

	// Create temporary file in same directory (required for atomic rename)
	tempFile, err := os.CreateTemp(dir, ".tmp-*")
	if err != nil {
		return fmt.Errorf("failed to create temp file: %w", err)
	}
	tempPath := tempFile.Name()

	// Cleanup on failure
	success := false
	defer func() {
		if !success {
			os.Remove(tempPath)
		}
	}()

	// Write data
	if _, err := tempFile.Write(data); err != nil {
		tempFile.Close()
		return fmt.Errorf("failed to write temp file: %w", err)
	}

	// Sync to disk before rename
	if err := tempFile.Sync(); err != nil {
		tempFile.Close()
		return fmt.Errorf("failed to sync temp file: %w", err)
	}

	if err := tempFile.Close(); err != nil {
		return fmt.Errorf("failed to close temp file: %w", err)
	}

	// Set permissions before rename
	if err := os.Chmod(tempPath, perm); err != nil {
		return fmt.Errorf("failed to set permissions: %w", err)
	}

	// Atomic rename
	if err := os.Rename(tempPath, path); err != nil {
		return fmt.Errorf("failed to rename temp file: %w", err)
	}

	success = true
	return nil
}

// ============================================================================
// CA Certificate Storage
// ============================================================================

// SaveCACertificate writes PEM-encoded CA certificate to disk.
// File is saved with 0644 permissions (world-readable) since certificates are public.
func SaveCACertificate(certPEM []byte, config *CAStorageConfig) error {
	if len(certPEM) == 0 {
		return errors.New("certificate PEM is empty")
	}

	if config == nil {
		config = DefaultStorageConfig()
	}

	// Validate PEM format
	block, _ := pem.Decode(certPEM)
	if block == nil || block.Type != "CERTIFICATE" {
		return fmt.Errorf("%w: expected CERTIFICATE PEM block", ErrInvalidCertificate)
	}

	// Write certificate atomically
	if err := atomicWriteFile(config.CACertPath, certPEM, CertificatePermission); err != nil {
		return fmt.Errorf("%w: %v", ErrFileWriteFailed, err)
	}

	return nil
}

// ============================================================================
// CA Private Key Storage
// ============================================================================

// SaveCAPrivateKey encrypts and saves private key to disk.
// Key is encrypted with AES-256-GCM and saved with 0600 permissions (owner-only).
func SaveCAPrivateKey(privateKeyPEM []byte, passphrase []byte, config *CAStorageConfig) error {
	if len(privateKeyPEM) == 0 {
		return errors.New("private key PEM is empty")
	}

	if config == nil {
		config = DefaultStorageConfig()
	}

	// Validate PEM format
	block, _ := pem.Decode(privateKeyPEM)
	if block == nil {
		return fmt.Errorf("%w: not valid PEM format", ErrInvalidPrivateKey)
	}

	// Encrypt private key
	encryptedData, err := EncryptPrivateKeyPEM(privateKeyPEM, passphrase)
	if err != nil {
		return fmt.Errorf("failed to encrypt private key: %w", err)
	}

	// Write encrypted key atomically
	if err := atomicWriteFile(config.CAKeyPath, encryptedData, PrivateKeyPermission); err != nil {
		return fmt.Errorf("%w: %v", ErrFileWriteFailed, err)
	}

	// Zero out sensitive data
	ZeroMemory(privateKeyPEM)

	return nil
}

// ============================================================================
// Passphrase Storage
// ============================================================================

// SavePassphrase writes encryption passphrase to secrets directory.
// File is saved with 0400 permissions (owner read-only) for immutability after creation.
func SavePassphrase(passphrase []byte, config *CAStorageConfig) error {
	if len(passphrase) < PassphraseLength {
		return fmt.Errorf("passphrase too short: got %d bytes, need at least %d",
			len(passphrase), PassphraseLength)
	}

	if config == nil {
		config = DefaultStorageConfig()
	}

	// Write passphrase atomically
	if err := atomicWriteFile(config.PassphrasePath, passphrase, PassphrasePermission); err != nil {
		return fmt.Errorf("%w: %v", ErrFileWriteFailed, err)
	}

	return nil
}

// ============================================================================
// Complete CA Save Function
// ============================================================================

// SaveCA orchestrates complete CA storage operation with rollback on failure.
// Saves certificate, encrypted private key, passphrase, and metadata atomically.
func SaveCA(result *RootCAResult, passphrase []byte, config *CAStorageConfig) error {
	if result == nil {
		return errors.New("RootCAResult is nil")
	}

	if config == nil {
		config = DefaultStorageConfig()
	}

	// Track files created for rollback
	var createdFiles []string
	cleanup := func() {
		for _, f := range createdFiles {
			os.Remove(f)
		}
	}

	// Step 1: Ensure directories exist
	if err := EnsureDirectories(config); err != nil {
		return fmt.Errorf("failed to create directories: %w", err)
	}

	// Step 2: Save CA certificate
	if err := SaveCACertificate(result.CertificatePEM, config); err != nil {
		cleanup()
		return fmt.Errorf("failed to save certificate: %w", err)
	}
	createdFiles = append(createdFiles, config.CACertPath)

	// Step 3: Save encrypted private key
	if err := SaveCAPrivateKey(result.PrivateKeyPEM, passphrase, config); err != nil {
		cleanup()
		return fmt.Errorf("failed to save private key: %w", err)
	}
	createdFiles = append(createdFiles, config.CAKeyPath)

	// Step 4: Save passphrase
	if err := SavePassphrase(passphrase, config); err != nil {
		cleanup()
		return fmt.Errorf("failed to save passphrase: %w", err)
	}
	createdFiles = append(createdFiles, config.PassphrasePath)

	// Step 5: Save metadata
	metadata, err := ExtractMetadata(result.Certificate)
	if err == nil {
		if saveErr := SaveCAMetadata(metadata, config); saveErr != nil {
			// Non-fatal: metadata is nice-to-have
			_ = saveErr
		}
	}

	return nil
}

// ============================================================================
// CA Certificate Load Function
// ============================================================================

// LoadCACertificate reads and parses CA certificate from disk.
// Validates that the certificate is a valid X.509 CA certificate.
func LoadCACertificate(config *CAStorageConfig) (*x509.Certificate, error) {
	if config == nil {
		config = DefaultStorageConfig()
	}

	// Read certificate file
	certPEM, err := os.ReadFile(config.CACertPath)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, ErrCANotFound
		}
		return nil, fmt.Errorf("%w: %v", ErrFileReadFailed, err)
	}

	// Parse PEM block
	block, _ := pem.Decode(certPEM)
	if block == nil || block.Type != "CERTIFICATE" {
		return nil, fmt.Errorf("%w: expected CERTIFICATE PEM block", ErrInvalidCertificate)
	}

	// Parse X.509 certificate
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrInvalidCertificate, err)
	}

	// Validate this is a CA certificate
	if !cert.IsCA {
		return nil, ErrNotCACertificate
	}

	return cert, nil
}

// LoadCACertificatePEM reads raw PEM certificate from disk.
func LoadCACertificatePEM(config *CAStorageConfig) ([]byte, error) {
	if config == nil {
		config = DefaultStorageConfig()
	}

	certPEM, err := os.ReadFile(config.CACertPath)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, ErrCANotFound
		}
		return nil, fmt.Errorf("%w: %v", ErrFileReadFailed, err)
	}

	return certPEM, nil
}

// ============================================================================
// CA Private Key Load Function
// ============================================================================

// LoadCAPrivateKey reads, decrypts, and parses CA private key from disk.
// Passphrase is loaded automatically from secrets directory.
func LoadCAPrivateKey(config *CAStorageConfig) (*rsa.PrivateKey, error) {
	if config == nil {
		config = DefaultStorageConfig()
	}

	// Load passphrase
	passphrase, err := LoadPassphrase(config)
	if err != nil {
		return nil, fmt.Errorf("failed to load passphrase: %w", err)
	}
	defer ZeroMemory(passphrase)

	// Read encrypted key file
	encryptedData, err := os.ReadFile(config.CAKeyPath)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, ErrCANotFound
		}
		return nil, fmt.Errorf("%w: %v", ErrFileReadFailed, err)
	}

	// Decrypt private key
	privateKeyPEM, err := DecryptPrivateKeyPEM(encryptedData, passphrase)
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt private key: %w", err)
	}
	defer ZeroMemory(privateKeyPEM)

	// Parse PEM block
	block, _ := pem.Decode(privateKeyPEM)
	if block == nil {
		return nil, fmt.Errorf("%w: not valid PEM format", ErrInvalidPrivateKey)
	}

	// Try PKCS#1 first (RSA PRIVATE KEY)
	if block.Type == "RSA PRIVATE KEY" {
		privateKey, err := x509.ParsePKCS1PrivateKey(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("%w: %v", ErrInvalidPrivateKey, err)
		}
		return privateKey, nil
	}

	// Try PKCS#8 (PRIVATE KEY)
	if block.Type == "PRIVATE KEY" {
		key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("%w: %v", ErrInvalidPrivateKey, err)
		}
		rsaKey, ok := key.(*rsa.PrivateKey)
		if !ok {
			return nil, fmt.Errorf("%w: not an RSA private key", ErrInvalidPrivateKey)
		}
		return rsaKey, nil
	}

	return nil, fmt.Errorf("%w: unexpected PEM type: %s", ErrInvalidPrivateKey, block.Type)
}

// LoadCAPrivateKeyWithPassphrase loads private key with explicit passphrase.
func LoadCAPrivateKeyWithPassphrase(passphrase []byte, config *CAStorageConfig) (*rsa.PrivateKey, error) {
	if config == nil {
		config = DefaultStorageConfig()
	}

	// Read encrypted key file
	encryptedData, err := os.ReadFile(config.CAKeyPath)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, ErrCANotFound
		}
		return nil, fmt.Errorf("%w: %v", ErrFileReadFailed, err)
	}

	// Decrypt private key
	privateKeyPEM, err := DecryptPrivateKeyPEM(encryptedData, passphrase)
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt private key: %w", err)
	}
	defer ZeroMemory(privateKeyPEM)

	// Parse PEM block
	block, _ := pem.Decode(privateKeyPEM)
	if block == nil {
		return nil, fmt.Errorf("%w: not valid PEM format", ErrInvalidPrivateKey)
	}

	// Parse RSA private key
	if block.Type == "RSA PRIVATE KEY" {
		return x509.ParsePKCS1PrivateKey(block.Bytes)
	}

	if block.Type == "PRIVATE KEY" {
		key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
		if err != nil {
			return nil, err
		}
		rsaKey, ok := key.(*rsa.PrivateKey)
		if !ok {
			return nil, fmt.Errorf("%w: not an RSA private key", ErrInvalidPrivateKey)
		}
		return rsaKey, nil
	}

	return nil, fmt.Errorf("%w: unexpected PEM type: %s", ErrInvalidPrivateKey, block.Type)
}

// ============================================================================
// Passphrase Load Function
// ============================================================================

// LoadPassphrase reads passphrase from secrets directory.
// Caller is responsible for zeroing passphrase after use.
func LoadPassphrase(config *CAStorageConfig) ([]byte, error) {
	if config == nil {
		config = DefaultStorageConfig()
	}

	passphrase, err := os.ReadFile(config.PassphrasePath)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, ErrPassphraseNotFound
		}
		return nil, fmt.Errorf("%w: %v", ErrFileReadFailed, err)
	}

	// Validate passphrase length
	if len(passphrase) < PassphraseLength {
		return nil, fmt.Errorf("passphrase too short: got %d bytes, need at least %d",
			len(passphrase), PassphraseLength)
	}

	return passphrase, nil
}

// ============================================================================
// CA Existence Check
// ============================================================================

// CAExists checks if CA certificate and private key files exist.
// Returns true only if certificate, encrypted key, and passphrase all exist.
func CAExists(config *CAStorageConfig) bool {
	if config == nil {
		config = DefaultStorageConfig()
	}

	// Check certificate file
	if _, err := os.Stat(config.CACertPath); os.IsNotExist(err) {
		return false
	}

	// Check encrypted key file
	if _, err := os.Stat(config.CAKeyPath); os.IsNotExist(err) {
		return false
	}

	// Check passphrase file
	if _, err := os.Stat(config.PassphrasePath); os.IsNotExist(err) {
		return false
	}

	return true
}

// CAFilesExist returns detailed existence status for each CA file.
func CAFilesExist(config *CAStorageConfig) map[string]bool {
	if config == nil {
		config = DefaultStorageConfig()
	}

	status := make(map[string]bool)

	_, err := os.Stat(config.CACertPath)
	status["certificate"] = err == nil

	_, err = os.Stat(config.CAKeyPath)
	status["private_key"] = err == nil

	_, err = os.Stat(config.PassphrasePath)
	status["passphrase"] = err == nil

	_, err = os.Stat(config.MetadataPath)
	status["metadata"] = err == nil

	return status
}

// ============================================================================
// CA Metadata Operations
// ============================================================================

// CAMetadataFile represents the stored metadata JSON structure.
type CAMetadataFile struct {
	SerialNumber string    `json:"serial_number"`
	Fingerprint  string    `json:"fingerprint"`
	Subject      string    `json:"subject"`
	Issuer       string    `json:"issuer"`
	NotBefore    time.Time `json:"not_before"`
	NotAfter     time.Time `json:"not_after"`
	KeyType      string    `json:"key_type"`
	KeySize      int       `json:"key_size"`
	IsCA         bool      `json:"is_ca"`
	Version      int       `json:"version"`
	GeneratedAt  time.Time `json:"generated_at"`
	LastLoadedAt time.Time `json:"last_loaded_at,omitempty"`
}

// SaveCAMetadata writes CA metadata to JSON file for fast access.
func SaveCAMetadata(metadata *CertificateMetadata, config *CAStorageConfig) error {
	if metadata == nil {
		return errors.New("metadata is nil")
	}

	if config == nil {
		config = DefaultStorageConfig()
	}

	// Convert to file format
	fileMetadata := CAMetadataFile{
		SerialNumber: metadata.SerialNumber,
		Fingerprint:  metadata.Fingerprint,
		Subject:      metadata.Subject,
		Issuer:       metadata.Issuer,
		NotBefore:    metadata.NotBefore,
		NotAfter:     metadata.NotAfter,
		KeyType:      metadata.KeyType,
		KeySize:      metadata.KeySize,
		IsCA:         metadata.IsCA,
		Version:      metadata.Version,
		GeneratedAt:  time.Now(),
	}

	// Serialize to JSON
	jsonData, err := json.MarshalIndent(fileMetadata, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal metadata: %w", err)
	}

	// Write atomically
	if err := atomicWriteFile(config.MetadataPath, jsonData, MetadataPermission); err != nil {
		return fmt.Errorf("%w: %v", ErrFileWriteFailed, err)
	}

	return nil
}

// LoadCAMetadata reads CA metadata from JSON file.
// Falls back to parsing certificate if metadata file is missing.
func LoadCAMetadata(config *CAStorageConfig) (*CertificateMetadata, error) {
	if config == nil {
		config = DefaultStorageConfig()
	}

	// Try loading from metadata file
	jsonData, err := os.ReadFile(config.MetadataPath)
	if err == nil {
		var fileMetadata CAMetadataFile
		if err := json.Unmarshal(jsonData, &fileMetadata); err == nil {
			return &CertificateMetadata{
				SerialNumber: fileMetadata.SerialNumber,
				Fingerprint:  fileMetadata.Fingerprint,
				Subject:      fileMetadata.Subject,
				Issuer:       fileMetadata.Issuer,
				NotBefore:    fileMetadata.NotBefore,
				NotAfter:     fileMetadata.NotAfter,
				KeyType:      fileMetadata.KeyType,
				KeySize:      fileMetadata.KeySize,
				IsCA:         fileMetadata.IsCA,
				Version:      fileMetadata.Version,
			}, nil
		}
	}

	// Fallback: Parse certificate
	cert, err := LoadCACertificate(config)
	if err != nil {
		return nil, fmt.Errorf("failed to load certificate: %w", err)
	}

	return ExtractMetadata(cert)
}

// ============================================================================
// File Permission Validation
// ============================================================================

// ValidateFilePermissions checks that a file has expected permissions.
// Returns error if permissions are more permissive than expected.
func ValidateFilePermissions(path string, expectedMode os.FileMode) error {
	info, err := os.Stat(path)
	if err != nil {
		return fmt.Errorf("failed to stat file: %w", err)
	}

	actualMode := info.Mode().Perm()

	// Check if actual permissions are more permissive than expected
	// More permissive means bits are set that shouldn't be
	if actualMode&^expectedMode != 0 {
		return fmt.Errorf("%w: %s has permissions %o, expected %o or more restrictive",
			ErrInvalidPermissions, path, actualMode, expectedMode)
	}

	return nil
}

// ValidateCAFilePermissions validates all CA file permissions.
func ValidateCAFilePermissions(config *CAStorageConfig) map[string]error {
	if config == nil {
		config = DefaultStorageConfig()
	}

	results := make(map[string]error)

	// Validate certificate (0644 allowed)
	results["certificate"] = ValidateFilePermissions(config.CACertPath, CertificatePermission)

	// Validate private key (0600 required)
	results["private_key"] = ValidateFilePermissions(config.CAKeyPath, PrivateKeyPermission)

	// Validate passphrase (0400 required)
	results["passphrase"] = ValidateFilePermissions(config.PassphrasePath, PassphrasePermission)

	// Validate directories
	results["ca_directory"] = ValidateFilePermissions(config.CADirectory, DirPermission)
	results["secrets_directory"] = ValidateFilePermissions(config.SecretsDirectory, DirPermission)

	return results
}

// ============================================================================
// Secure File Deletion
// ============================================================================

// SecureDeleteFile deletes a file after overwriting with random data.
// Note: Not fully effective on SSDs with wear leveling.
func SecureDeleteFile(path string) error {
	// Get file info
	info, err := os.Stat(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil // Already deleted
		}
		return fmt.Errorf("failed to stat file: %w", err)
	}

	fileSize := info.Size()
	if fileSize == 0 {
		return os.Remove(path)
	}

	// Open file for writing
	file, err := os.OpenFile(path, os.O_WRONLY, 0)
	if err != nil {
		return fmt.Errorf("failed to open file for overwrite: %w", err)
	}

	// Overwrite with random data (3 passes)
	randomData := make([]byte, fileSize)
	for pass := 0; pass < 3; pass++ {
		if _, err := io.ReadFull(rand.Reader, randomData); err != nil {
			file.Close()
			return fmt.Errorf("failed to generate random data: %w", err)
		}

		if _, err := file.WriteAt(randomData, 0); err != nil {
			file.Close()
			return fmt.Errorf("failed to overwrite file: %w", err)
		}

		if err := file.Sync(); err != nil {
			file.Close()
			return fmt.Errorf("failed to sync file: %w", err)
		}
	}

	file.Close()

	// Delete the file
	if err := os.Remove(path); err != nil {
		return fmt.Errorf("failed to delete file: %w", err)
	}

	return nil
}

// ============================================================================
// Utility Functions
// ============================================================================

// GetCAStoragePaths returns all relevant CA storage paths.
func GetCAStoragePaths(config *CAStorageConfig) map[string]string {
	if config == nil {
		config = DefaultStorageConfig()
	}

	return map[string]string{
		"ca_directory":      config.CADirectory,
		"secrets_directory": config.SecretsDirectory,
		"certificate":       config.CACertPath,
		"private_key":       config.CAKeyPath,
		"passphrase":        config.PassphrasePath,
		"metadata":          config.MetadataPath,
		"crl":               filepath.Join(config.CADirectory, CRLFilename),
	}
}

// BackupCA creates a backup of CA files to a specified directory.
func BackupCA(backupDir string, config *CAStorageConfig) error {
	if config == nil {
		config = DefaultStorageConfig()
	}

	// Create backup directory
	if err := os.MkdirAll(backupDir, DirPermission); err != nil {
		return fmt.Errorf("failed to create backup directory: %w", err)
	}

	// Copy certificate
	certPEM, err := os.ReadFile(config.CACertPath)
	if err != nil {
		return fmt.Errorf("failed to read certificate: %w", err)
	}
	certBackupPath := filepath.Join(backupDir, CACertificateFilename)
	if err := atomicWriteFile(certBackupPath, certPEM, CertificatePermission); err != nil {
		return fmt.Errorf("failed to backup certificate: %w", err)
	}

	// Copy encrypted key
	encryptedKey, err := os.ReadFile(config.CAKeyPath)
	if err != nil {
		return fmt.Errorf("failed to read encrypted key: %w", err)
	}
	keyBackupPath := filepath.Join(backupDir, CAPrivateKeyFilename)
	if err := atomicWriteFile(keyBackupPath, encryptedKey, PrivateKeyPermission); err != nil {
		return fmt.Errorf("failed to backup encrypted key: %w", err)
	}

	// Copy passphrase
	passphrase, err := os.ReadFile(config.PassphrasePath)
	if err != nil {
		return fmt.Errorf("failed to read passphrase: %w", err)
	}
	passphraseBackupPath := filepath.Join(backupDir, CAPassphraseFilename)
	if err := atomicWriteFile(passphraseBackupPath, passphrase, PassphrasePermission); err != nil {
		return fmt.Errorf("failed to backup passphrase: %w", err)
	}

	// Zero passphrase from memory
	ZeroMemory(passphrase)

	return nil
}

// RestoreCA restores CA files from a backup directory.
func RestoreCA(backupDir string, config *CAStorageConfig) error {
	if config == nil {
		config = DefaultStorageConfig()
	}

	// Ensure target directories exist
	if err := EnsureDirectories(config); err != nil {
		return fmt.Errorf("failed to create directories: %w", err)
	}

	// Restore certificate
	certBackupPath := filepath.Join(backupDir, CACertificateFilename)
	certPEM, err := os.ReadFile(certBackupPath)
	if err != nil {
		return fmt.Errorf("failed to read backup certificate: %w", err)
	}
	if err := atomicWriteFile(config.CACertPath, certPEM, CertificatePermission); err != nil {
		return fmt.Errorf("failed to restore certificate: %w", err)
	}

	// Restore encrypted key
	keyBackupPath := filepath.Join(backupDir, CAPrivateKeyFilename)
	encryptedKey, err := os.ReadFile(keyBackupPath)
	if err != nil {
		return fmt.Errorf("failed to read backup encrypted key: %w", err)
	}
	if err := atomicWriteFile(config.CAKeyPath, encryptedKey, PrivateKeyPermission); err != nil {
		return fmt.Errorf("failed to restore encrypted key: %w", err)
	}

	// Restore passphrase
	passphraseBackupPath := filepath.Join(backupDir, CAPassphraseFilename)
	passphrase, err := os.ReadFile(passphraseBackupPath)
	if err != nil {
		return fmt.Errorf("failed to read backup passphrase: %w", err)
	}
	if err := atomicWriteFile(config.PassphrasePath, passphrase, PassphrasePermission); err != nil {
		return fmt.Errorf("failed to restore passphrase: %w", err)
	}

	// Zero passphrase from memory
	ZeroMemory(passphrase)

	return nil
}
