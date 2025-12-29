package security

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"log"
	"os"
	"path/filepath"
	"time"

	"golang.org/x/crypto/pbkdf2"
)

// ============================================================================
// Errors
// ============================================================================

var (
	ErrDecryptionFailed = errors.New("decryption failed: authentication error or wrong passphrase")
	ErrInvalidKeyFormat = errors.New("invalid encrypted key format")
	ErrIntegrityFailed  = errors.New("key integrity verification failed")
	ErrPermissionDenied = errors.New("cannot set secure file permissions")
	ErrKeyFileNotFound  = errors.New("key file not found")
)

// ============================================================================
// Constants
// ============================================================================

const (
	DefaultIterations = 100000 // PBKDF2 iterations
	SaltSize          = 16     // Salt size in bytes
	NonceSize         = 12     // GCM nonce size
	KeySize           = 32     // AES-256 key size
)

// ============================================================================
// KDF Configuration
// ============================================================================

// KDFConfig configures key derivation parameters.
type KDFConfig struct {
	Algorithm  string // "PBKDF2"
	Hash       string // "SHA256"
	Iterations int    // Default: 100000
	SaltSize   int    // Default: 16 bytes
	KeySize    int    // Default: 32 bytes (AES-256)
}

// DefaultKDFConfig returns default KDF configuration.
func DefaultKDFConfig() *KDFConfig {
	return &KDFConfig{
		Algorithm:  "PBKDF2",
		Hash:       "SHA256",
		Iterations: DefaultIterations,
		SaltSize:   SaltSize,
		KeySize:    KeySize,
	}
}

// ============================================================================
// Key Protector
// ============================================================================

// KeyProtector provides CA private key protection.
type KeyProtector struct {
	config *KDFConfig
}

// NewKeyProtector creates a new key protector.
func NewKeyProtector(config *KDFConfig) *KeyProtector {
	if config == nil {
		config = DefaultKDFConfig()
	}
	return &KeyProtector{config: config}
}

// ============================================================================
// Encryption / Decryption
// ============================================================================

// EncryptPrivateKey encrypts a private key PEM with a passphrase.
func (p *KeyProtector) EncryptPrivateKey(privateKeyPEM []byte, passphrase string) ([]byte, error) {
	// Generate random salt
	salt := make([]byte, p.config.SaltSize)
	if _, err := io.ReadFull(rand.Reader, salt); err != nil {
		return nil, fmt.Errorf("failed to generate salt: %w", err)
	}

	// Generate random nonce
	nonce := make([]byte, NonceSize)
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, fmt.Errorf("failed to generate nonce: %w", err)
	}

	// Derive encryption key
	derivedKey := p.deriveKey(passphrase, salt)
	defer WipeMemory(derivedKey)

	// Create AES-256-GCM cipher
	block, err := aes.NewCipher(derivedKey)
	if err != nil {
		return nil, fmt.Errorf("failed to create cipher: %w", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("failed to create GCM: %w", err)
	}

	// Encrypt private key
	ciphertext := gcm.Seal(nil, nonce, privateKeyPEM, nil)

	// Build encrypted blob: salt + nonce + ciphertext (includes auth tag)
	blob := make([]byte, 0, len(salt)+len(nonce)+len(ciphertext))
	blob = append(blob, salt...)
	blob = append(blob, nonce...)
	blob = append(blob, ciphertext...)

	return blob, nil
}

// DecryptPrivateKey decrypts an encrypted private key blob.
func (p *KeyProtector) DecryptPrivateKey(encryptedBlob []byte, passphrase string) ([]byte, error) {
	minSize := p.config.SaltSize + NonceSize + 16 // salt + nonce + min GCM tag
	if len(encryptedBlob) < minSize {
		return nil, ErrInvalidKeyFormat
	}

	// Parse encrypted blob
	salt := encryptedBlob[:p.config.SaltSize]
	nonce := encryptedBlob[p.config.SaltSize : p.config.SaltSize+NonceSize]
	ciphertext := encryptedBlob[p.config.SaltSize+NonceSize:]

	// Derive decryption key
	derivedKey := p.deriveKey(passphrase, salt)
	defer WipeMemory(derivedKey)

	// Create AES-256-GCM cipher
	block, err := aes.NewCipher(derivedKey)
	if err != nil {
		return nil, fmt.Errorf("failed to create cipher: %w", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("failed to create GCM: %w", err)
	}

	// Decrypt and authenticate
	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, ErrDecryptionFailed
	}

	return plaintext, nil
}

// deriveKey derives an encryption key from passphrase using PBKDF2.
func (p *KeyProtector) deriveKey(passphrase string, salt []byte) []byte {
	return pbkdf2.Key([]byte(passphrase), salt, p.config.Iterations, p.config.KeySize, sha256.New)
}

// ============================================================================
// Passphrase Generation
// ============================================================================

// GeneratePassphrase generates a cryptographically random passphrase.
func GeneratePassphrase(length int) (string, error) {
	if length < 16 {
		length = 32
	}

	bytes := make([]byte, length)
	if _, err := io.ReadFull(rand.Reader, bytes); err != nil {
		return "", fmt.Errorf("failed to generate random bytes: %w", err)
	}

	return hex.EncodeToString(bytes), nil
}

// GenerateSecurePassphrase generates a 256-bit passphrase.
func GenerateSecurePassphrase() (string, error) {
	return GeneratePassphrase(32)
}

// ============================================================================
// Passphrase Rotation
// ============================================================================

// RotatePassphrase changes the encryption passphrase for a key file.
func (p *KeyProtector) RotatePassphrase(keyFilePath, oldPassphrase, newPassphrase string) error {
	// Read encrypted key
	encryptedBlob, err := os.ReadFile(keyFilePath)
	if err != nil {
		return fmt.Errorf("failed to read key file: %w", err)
	}

	// Decrypt with old passphrase
	privateKeyPEM, err := p.DecryptPrivateKey(encryptedBlob, oldPassphrase)
	if err != nil {
		return fmt.Errorf("failed to decrypt with old passphrase: %w", err)
	}
	defer WipeMemory(privateKeyPEM)

	// Re-encrypt with new passphrase
	newEncryptedBlob, err := p.EncryptPrivateKey(privateKeyPEM, newPassphrase)
	if err != nil {
		return fmt.Errorf("failed to encrypt with new passphrase: %w", err)
	}

	// Write to temporary file
	tmpPath := keyFilePath + ".tmp"
	if err := os.WriteFile(tmpPath, newEncryptedBlob, 0600); err != nil {
		return fmt.Errorf("failed to write temp file: %w", err)
	}

	// Atomic rename
	if err := os.Rename(tmpPath, keyFilePath); err != nil {
		os.Remove(tmpPath)
		return fmt.Errorf("failed to replace key file: %w", err)
	}

	log.Printf("[security] Passphrase rotated for key file: %s", keyFilePath)
	return nil
}

// ============================================================================
// Integrity Verification
// ============================================================================

// VerifyKeyIntegrityWithChecksum verifies key file against stored checksum.
func VerifyKeyIntegrityWithChecksum(keyFilePath, checksumFilePath string) error {
	// Read key file
	keyData, err := os.ReadFile(keyFilePath)
	if err != nil {
		return fmt.Errorf("failed to read key file: %w", err)
	}

	// Calculate hash
	hash := sha256.Sum256(keyData)
	actualChecksum := hex.EncodeToString(hash[:])

	// Read expected checksum
	expectedBytes, err := os.ReadFile(checksumFilePath)
	if err != nil {
		return fmt.Errorf("failed to read checksum file: %w", err)
	}

	expectedChecksum := string(expectedBytes)
	if actualChecksum != expectedChecksum {
		return fmt.Errorf("%w: expected %s, got %s", ErrIntegrityFailed, expectedChecksum, actualChecksum)
	}

	return nil
}

// VerifyKeyIntegrityWithDecryption verifies key by attempting decryption.
func (p *KeyProtector) VerifyKeyIntegrityWithDecryption(keyFilePath, passphrase string) error {
	// Read encrypted key
	encryptedBlob, err := os.ReadFile(keyFilePath)
	if err != nil {
		return fmt.Errorf("failed to read key file: %w", err)
	}

	// Attempt decryption
	privateKeyPEM, err := p.DecryptPrivateKey(encryptedBlob, passphrase)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrIntegrityFailed, err)
	}
	defer WipeMemory(privateKeyPEM)

	// Verify it's a valid PEM private key
	block, _ := pem.Decode(privateKeyPEM)
	if block == nil {
		return fmt.Errorf("%w: invalid PEM format", ErrIntegrityFailed)
	}

	// Try to parse the key
	switch block.Type {
	case "RSA PRIVATE KEY":
		_, err = x509.ParsePKCS1PrivateKey(block.Bytes)
	case "EC PRIVATE KEY":
		_, err = x509.ParseECPrivateKey(block.Bytes)
	case "PRIVATE KEY":
		_, err = x509.ParsePKCS8PrivateKey(block.Bytes)
	default:
		return fmt.Errorf("%w: unknown key type: %s", ErrIntegrityFailed, block.Type)
	}

	if err != nil {
		return fmt.Errorf("%w: %v", ErrIntegrityFailed, err)
	}

	return nil
}

// GenerateKeyChecksum generates and saves a checksum for a key file.
func GenerateKeyChecksum(keyFilePath, checksumFilePath string) error {
	// Read key file
	keyData, err := os.ReadFile(keyFilePath)
	if err != nil {
		return fmt.Errorf("failed to read key file: %w", err)
	}

	// Calculate hash
	hash := sha256.Sum256(keyData)
	checksum := hex.EncodeToString(hash[:])

	// Write checksum file
	if err := os.WriteFile(checksumFilePath, []byte(checksum), 0600); err != nil {
		return fmt.Errorf("failed to write checksum file: %w", err)
	}

	return nil
}

// ============================================================================
// Memory Security
// ============================================================================

// WipeMemory clears sensitive data from memory.
func WipeMemory(data []byte) {
	for i := range data {
		data[i] = 0
	}
}

// WipeString clears a string's underlying bytes (best effort).
func WipeString(s *string) {
	if s == nil || len(*s) == 0 {
		return
	}
	// Note: Go strings are immutable, this is best-effort
	*s = ""
}

// ============================================================================
// File Permissions
// ============================================================================

// SetSecurePermissions sets restrictive permissions on a file.
func SetSecurePermissions(filePath string) error {
	if err := os.Chmod(filePath, 0600); err != nil {
		return fmt.Errorf("%w: %v", ErrPermissionDenied, err)
	}
	return nil
}

// VerifySecurePermissions checks if file has secure permissions.
func VerifySecurePermissions(filePath string) error {
	info, err := os.Stat(filePath)
	if err != nil {
		return fmt.Errorf("failed to stat file: %w", err)
	}

	perm := info.Mode().Perm()
	// Check that group and world have no permissions
	if perm&0077 != 0 {
		return fmt.Errorf("insecure permissions: %o (should be 0600 or 0400)", perm)
	}

	return nil
}

// EnsureSecureDirectory ensures a directory exists with secure permissions.
func EnsureSecureDirectory(dirPath string) error {
	if err := os.MkdirAll(dirPath, 0700); err != nil {
		return fmt.Errorf("failed to create directory: %w", err)
	}
	return os.Chmod(dirPath, 0700)
}

// ============================================================================
// File Operations
// ============================================================================

// SaveEncryptedKey saves an encrypted key to a file securely.
func (p *KeyProtector) SaveEncryptedKey(privateKeyPEM []byte, passphrase, filePath string) error {
	// Ensure directory exists
	if err := EnsureSecureDirectory(filepath.Dir(filePath)); err != nil {
		return err
	}

	// Encrypt key
	encryptedBlob, err := p.EncryptPrivateKey(privateKeyPEM, passphrase)
	if err != nil {
		return err
	}

	// Write to temporary file
	tmpPath := filePath + ".tmp"
	if err := os.WriteFile(tmpPath, encryptedBlob, 0600); err != nil {
		return fmt.Errorf("failed to write file: %w", err)
	}

	// Atomic rename
	if err := os.Rename(tmpPath, filePath); err != nil {
		os.Remove(tmpPath)
		return fmt.Errorf("failed to rename file: %w", err)
	}

	// Generate checksum
	checksumPath := filePath + ".sha256"
	if err := GenerateKeyChecksum(filePath, checksumPath); err != nil {
		log.Printf("[security] Warning: failed to generate checksum: %v", err)
	}

	return nil
}

// LoadDecryptedKey loads and decrypts a key from a file.
func (p *KeyProtector) LoadDecryptedKey(filePath, passphrase string) ([]byte, error) {
	// Verify file exists
	if _, err := os.Stat(filePath); os.IsNotExist(err) {
		return nil, ErrKeyFileNotFound
	}

	// Verify permissions
	if err := VerifySecurePermissions(filePath); err != nil {
		log.Printf("[security] Warning: %v", err)
	}

	// Read encrypted data
	encryptedBlob, err := os.ReadFile(filePath)
	if err != nil {
		return nil, fmt.Errorf("failed to read key file: %w", err)
	}

	// Decrypt
	return p.DecryptPrivateKey(encryptedBlob, passphrase)
}

// ============================================================================
// Utility Functions
// ============================================================================

// KeyProtectionInfo contains information about key protection.
type KeyProtectionInfo struct {
	FilePath      string    `json:"file_path"`
	Encrypted     bool      `json:"encrypted"`
	Algorithm     string    `json:"algorithm"`
	KDFIterations int       `json:"kdf_iterations"`
	ChecksumValid bool      `json:"checksum_valid"`
	PermissionsOK bool      `json:"permissions_ok"`
	LastModified  time.Time `json:"last_modified"`
}

// GetKeyProtectionInfo returns protection info for a key file.
func (p *KeyProtector) GetKeyProtectionInfo(filePath string) (*KeyProtectionInfo, error) {
	info := &KeyProtectionInfo{
		FilePath:      filePath,
		Algorithm:     "AES-256-GCM",
		KDFIterations: p.config.Iterations,
	}

	// Check file exists
	stat, err := os.Stat(filePath)
	if err != nil {
		return info, err
	}
	info.LastModified = stat.ModTime()
	info.Encrypted = true // Assume encrypted if file exists

	// Check permissions
	info.PermissionsOK = VerifySecurePermissions(filePath) == nil

	// Check checksum
	checksumPath := filePath + ".sha256"
	info.ChecksumValid = VerifyKeyIntegrityWithChecksum(filePath, checksumPath) == nil

	return info, nil
}
