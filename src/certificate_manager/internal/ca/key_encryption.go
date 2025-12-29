// Package ca implements AES-256-GCM encryption for protecting CA private keys at rest.
// This file provides military-grade authenticated encryption using PBKDF2 key derivation
// with 100,000 iterations, ensuring private keys are never stored unencrypted on disk.
package ca

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"

	"golang.org/x/crypto/pbkdf2"
)

// ============================================================================
// Constants
// ============================================================================

const (
	// PassphraseLength is the auto-generated passphrase byte length (256 bits)
	PassphraseLength = 32
	// SaltLength is the PBKDF2 salt byte length (128 bits)
	SaltLength = 16
	// NonceLength is the AES-GCM nonce byte length (96 bits, standard for GCM)
	NonceLength = 12
	// PBKDF2Iterations is the key derivation iteration count (OWASP 2024 recommendation)
	PBKDF2Iterations = 100000
	// PBKDF2KeyLength is the derived key length for AES-256 (256 bits)
	PBKDF2KeyLength = 32
	// FormatVersion is the serialization format version for future compatibility
	FormatVersion = 1
	// AlgorithmAES256GCM is the algorithm identifier
	AlgorithmAES256GCM = "AES-256-GCM"
)

// ============================================================================
// Error Types
// ============================================================================

var (
	// ErrPassphraseTooShort indicates passphrase is below minimum length
	ErrPassphraseTooShort = errors.New("passphrase must be at least 32 bytes")
	// ErrInvalidPassphrase indicates passphrase validation failed
	ErrInvalidPassphrase = errors.New("invalid passphrase")
	// ErrEncryptionFailed indicates encryption operation failed
	ErrEncryptionFailed = errors.New("encryption failed")
	// ErrDecryptionFailed indicates decryption operation failed
	ErrDecryptionFailed = errors.New("decryption failed")
	// ErrAuthenticationFailed indicates GCM authentication tag verification failed
	ErrAuthenticationFailed = errors.New("authentication failed: ciphertext may be tampered or passphrase is incorrect")
	// ErrInvalidPEMFormat indicates input is not valid PEM format
	ErrInvalidPEMFormat = errors.New("invalid PEM format")
	// ErrSerializationFailed indicates serialization failed
	ErrSerializationFailed = errors.New("serialization failed")
	// ErrDeserializationFailed indicates deserialization failed
	ErrDeserializationFailed = errors.New("deserialization failed")
	// ErrInvalidFormatVersion indicates unsupported format version
	ErrInvalidFormatVersion = errors.New("unsupported format version")
	// ErrDataCorrupted indicates data corruption detected
	ErrDataCorrupted = errors.New("data corrupted: invalid field lengths")
)

// ============================================================================
// Encrypted Private Key Structure
// ============================================================================

// EncryptedPrivateKey contains the encrypted private key with metadata.
// This structure is serializable for storage and includes all data needed for decryption.
type EncryptedPrivateKey struct {
	// Ciphertext is the AES-256-GCM encrypted private key PEM (includes auth tag)
	Ciphertext []byte `json:"ciphertext"`
	// Salt is the PBKDF2 salt (16 bytes)
	Salt []byte `json:"salt"`
	// Nonce is the AES-GCM nonce (12 bytes)
	Nonce []byte `json:"nonce"`
	// Algorithm is the encryption algorithm identifier
	Algorithm string `json:"algorithm"`
	// PBKDF2Iterations is the iteration count used
	PBKDF2Iterations int `json:"pbkdf2_iterations"`
	// Version is the format version for compatibility
	Version int `json:"version"`
}

// ============================================================================
// Passphrase Generation
// ============================================================================

// GeneratePassphrase generates a cryptographically random 32-byte passphrase.
// Uses crypto/rand.Read() for secure random data, providing 256 bits of entropy.
// The passphrase should be stored separately at /etc/safeops/secrets/ca_passphrase.
//
// Security note: Never logs or prints passphrase to prevent leakage.
func GeneratePassphrase() ([]byte, error) {
	passphrase := make([]byte, PassphraseLength)
	_, err := io.ReadFull(rand.Reader, passphrase)
	if err != nil {
		return nil, fmt.Errorf("failed to generate passphrase: %w", err)
	}

	return passphrase, nil
}

// ============================================================================
// Salt and Nonce Generation
// ============================================================================

// GenerateSalt generates a cryptographically random 16-byte salt.
// A new salt is generated for each encryption operation to prevent
// rainbow table attacks and dictionary attacks.
func GenerateSalt() ([]byte, error) {
	salt := make([]byte, SaltLength)
	_, err := io.ReadFull(rand.Reader, salt)
	if err != nil {
		return nil, fmt.Errorf("failed to generate salt: %w", err)
	}

	return salt, nil
}

// GenerateNonce generates a cryptographically random 12-byte nonce (number used once).
// GCM mode requires a 96-bit (12-byte) nonce that MUST be unique for each
// encryption with the same key. Reusing a nonce breaks GCM security.
func GenerateNonce() ([]byte, error) {
	nonce := make([]byte, NonceLength)
	_, err := io.ReadFull(rand.Reader, nonce)
	if err != nil {
		return nil, fmt.Errorf("failed to generate nonce: %w", err)
	}

	return nonce, nil
}

// ============================================================================
// Key Derivation
// ============================================================================

// DeriveKey derives a 256-bit encryption key from passphrase using PBKDF2.
// Algorithm: PBKDF2-HMAC-SHA256 with 100,000 iterations.
// Same passphrase + salt always produces the same key (deterministic).
//
// Performance: ~100ms on modern hardware (intentionally slow to resist brute force).
func DeriveKey(passphrase []byte, salt []byte) []byte {
	return pbkdf2.Key(passphrase, salt, PBKDF2Iterations, PBKDF2KeyLength, sha256.New)
}

// ============================================================================
// Passphrase Validation
// ============================================================================

// ValidatePassphrase validates that the passphrase meets minimum security requirements.
// Checks:
// - Length >= 32 bytes (256 bits minimum)
// - Not all zeros (invalid/corrupted passphrase)
func ValidatePassphrase(passphrase []byte) error {
	if len(passphrase) < PassphraseLength {
		return fmt.Errorf("%w: got %d bytes, need at least %d",
			ErrPassphraseTooShort, len(passphrase), PassphraseLength)
	}

	// Check for all-zero passphrase (corrupted or invalid)
	allZero := true
	for _, b := range passphrase {
		if b != 0 {
			allZero = false
			break
		}
	}
	if allZero {
		return fmt.Errorf("%w: passphrase is all zeros", ErrInvalidPassphrase)
	}

	return nil
}

// ============================================================================
// Private Key Encryption
// ============================================================================

// EncryptPrivateKey encrypts PEM-encoded RSA private key using AES-256-GCM.
// Steps:
//  1. Generate random 16-byte salt
//  2. Derive 32-byte encryption key using PBKDF2(passphrase, salt, 100k iterations)
//  3. Generate random 12-byte nonce
//  4. Create AES-256 cipher block
//  5. Create GCM mode wrapper (authenticated encryption)
//  6. Encrypt privateKeyPEM using GCM.Seal()
//
// GCM provides confidentiality, authenticity, and AEAD (Authenticated Encryption
// with Associated Data).
func EncryptPrivateKey(privateKeyPEM []byte, passphrase []byte) (*EncryptedPrivateKey, error) {
	// Validate passphrase
	if err := ValidatePassphrase(passphrase); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrEncryptionFailed, err)
	}

	// Validate PEM format
	block, _ := pem.Decode(privateKeyPEM)
	if block == nil {
		return nil, fmt.Errorf("%w: input is not valid PEM", ErrInvalidPEMFormat)
	}

	// Step 1: Generate random salt
	salt, err := GenerateSalt()
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrEncryptionFailed, err)
	}

	// Step 2: Derive encryption key using PBKDF2
	key := DeriveKey(passphrase, salt)

	// Step 3: Generate random nonce
	nonce, err := GenerateNonce()
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrEncryptionFailed, err)
	}

	// Step 4: Create AES-256 cipher block
	block256, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("%w: failed to create AES cipher: %v", ErrEncryptionFailed, err)
	}

	// Step 5: Create GCM mode wrapper
	gcm, err := cipher.NewGCM(block256)
	if err != nil {
		return nil, fmt.Errorf("%w: failed to create GCM: %v", ErrEncryptionFailed, err)
	}

	// Step 6: Encrypt using GCM.Seal() - appends authentication tag
	ciphertext := gcm.Seal(nil, nonce, privateKeyPEM, nil)

	// Build result
	result := &EncryptedPrivateKey{
		Ciphertext:       ciphertext,
		Salt:             salt,
		Nonce:            nonce,
		Algorithm:        AlgorithmAES256GCM,
		PBKDF2Iterations: PBKDF2Iterations,
		Version:          FormatVersion,
	}

	return result, nil
}

// ============================================================================
// Private Key Decryption
// ============================================================================

// DecryptPrivateKey decrypts AES-256-GCM encrypted private key.
// Steps:
//  1. Derive encryption key using PBKDF2(passphrase, encrypted.Salt, 100k iterations)
//  2. Create AES-256 cipher block
//  3. Create GCM mode wrapper
//  4. Decrypt ciphertext using GCM.Open() with stored nonce
//  5. GCM.Open() automatically verifies authentication tag
//
// Security features:
// - Authentication tag verification prevents tampering detection
// - Wrong passphrase results in authentication failure (not garbage decryption)
// - Timing-safe comparison of authentication tags
func DecryptPrivateKey(encrypted *EncryptedPrivateKey, passphrase []byte) ([]byte, error) {
	if encrypted == nil {
		return nil, errors.New("encrypted key is nil")
	}

	// Validate passphrase
	if err := ValidatePassphrase(passphrase); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrDecryptionFailed, err)
	}

	// Validate encrypted key structure
	if len(encrypted.Salt) != SaltLength {
		return nil, fmt.Errorf("%w: invalid salt length", ErrDataCorrupted)
	}
	if len(encrypted.Nonce) != NonceLength {
		return nil, fmt.Errorf("%w: invalid nonce length", ErrDataCorrupted)
	}
	if len(encrypted.Ciphertext) == 0 {
		return nil, fmt.Errorf("%w: empty ciphertext", ErrDataCorrupted)
	}

	// Step 1: Derive encryption key using PBKDF2
	iterations := encrypted.PBKDF2Iterations
	if iterations == 0 {
		iterations = PBKDF2Iterations // Default for legacy data
	}
	key := pbkdf2.Key(passphrase, encrypted.Salt, iterations, PBKDF2KeyLength, sha256.New)

	// Step 2: Create AES-256 cipher block
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("%w: failed to create AES cipher: %v", ErrDecryptionFailed, err)
	}

	// Step 3: Create GCM mode wrapper
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("%w: failed to create GCM: %v", ErrDecryptionFailed, err)
	}

	// Step 4 & 5: Decrypt and verify authentication tag
	plaintext, err := gcm.Open(nil, encrypted.Nonce, encrypted.Ciphertext, nil)
	if err != nil {
		// GCM.Open() fails if authentication tag doesn't match
		// This can mean wrong passphrase or tampered ciphertext
		return nil, ErrAuthenticationFailed
	}

	return plaintext, nil
}

// ============================================================================
// Serialization Functions
// ============================================================================

// SerializeEncryptedKey serializes EncryptedPrivateKey to binary format for file storage.
// Format:
//   - 1 byte: Version
//   - 4 bytes: Salt length (16)
//   - 16 bytes: Salt
//   - 4 bytes: Nonce length (12)
//   - 12 bytes: Nonce
//   - 4 bytes: PBKDF2 iterations
//   - 4 bytes: Ciphertext length
//   - N bytes: Ciphertext
//   - Remaining: Metadata JSON (algorithm)
func SerializeEncryptedKey(encrypted *EncryptedPrivateKey) ([]byte, error) {
	if encrypted == nil {
		return nil, errors.New("encrypted key is nil")
	}

	// Calculate total size
	metadataJSON, err := json.Marshal(map[string]string{
		"algorithm": encrypted.Algorithm,
	})
	if err != nil {
		return nil, fmt.Errorf("%w: failed to marshal metadata: %v", ErrSerializationFailed, err)
	}

	totalSize := 1 + // version
		4 + len(encrypted.Salt) + // salt length + salt
		4 + len(encrypted.Nonce) + // nonce length + nonce
		4 + // pbkdf2 iterations
		4 + len(encrypted.Ciphertext) + // ciphertext length + ciphertext
		4 + len(metadataJSON) // metadata length + metadata

	data := make([]byte, 0, totalSize)

	// Version byte
	data = append(data, byte(encrypted.Version))

	// Salt
	saltLen := make([]byte, 4)
	binary.BigEndian.PutUint32(saltLen, uint32(len(encrypted.Salt)))
	data = append(data, saltLen...)
	data = append(data, encrypted.Salt...)

	// Nonce
	nonceLen := make([]byte, 4)
	binary.BigEndian.PutUint32(nonceLen, uint32(len(encrypted.Nonce)))
	data = append(data, nonceLen...)
	data = append(data, encrypted.Nonce...)

	// PBKDF2 iterations
	iterBytes := make([]byte, 4)
	binary.BigEndian.PutUint32(iterBytes, uint32(encrypted.PBKDF2Iterations))
	data = append(data, iterBytes...)

	// Ciphertext
	ctLen := make([]byte, 4)
	binary.BigEndian.PutUint32(ctLen, uint32(len(encrypted.Ciphertext)))
	data = append(data, ctLen...)
	data = append(data, encrypted.Ciphertext...)

	// Metadata JSON
	metaLen := make([]byte, 4)
	binary.BigEndian.PutUint32(metaLen, uint32(len(metadataJSON)))
	data = append(data, metaLen...)
	data = append(data, metadataJSON...)

	return data, nil
}

// DeserializeEncryptedKey parses binary-serialized EncryptedPrivateKey.
// Validates all field lengths to prevent buffer overflows.
func DeserializeEncryptedKey(data []byte) (*EncryptedPrivateKey, error) {
	if len(data) < 1 {
		return nil, fmt.Errorf("%w: data too short", ErrDeserializationFailed)
	}

	offset := 0

	// Version byte
	version := int(data[offset])
	offset++

	if version != FormatVersion {
		return nil, fmt.Errorf("%w: got version %d, expected %d",
			ErrInvalidFormatVersion, version, FormatVersion)
	}

	// Helper to read length-prefixed field
	readField := func(name string) ([]byte, error) {
		if offset+4 > len(data) {
			return nil, fmt.Errorf("%w: truncated %s length", ErrDataCorrupted, name)
		}
		fieldLen := int(binary.BigEndian.Uint32(data[offset:]))
		offset += 4

		if offset+fieldLen > len(data) {
			return nil, fmt.Errorf("%w: truncated %s data", ErrDataCorrupted, name)
		}
		fieldData := make([]byte, fieldLen)
		copy(fieldData, data[offset:offset+fieldLen])
		offset += fieldLen

		return fieldData, nil
	}

	// Salt
	salt, err := readField("salt")
	if err != nil {
		return nil, err
	}
	if len(salt) != SaltLength {
		return nil, fmt.Errorf("%w: invalid salt length %d", ErrDataCorrupted, len(salt))
	}

	// Nonce
	nonce, err := readField("nonce")
	if err != nil {
		return nil, err
	}
	if len(nonce) != NonceLength {
		return nil, fmt.Errorf("%w: invalid nonce length %d", ErrDataCorrupted, len(nonce))
	}

	// PBKDF2 iterations
	if offset+4 > len(data) {
		return nil, fmt.Errorf("%w: truncated iterations", ErrDataCorrupted)
	}
	iterations := int(binary.BigEndian.Uint32(data[offset:]))
	offset += 4

	// Ciphertext
	ciphertext, err := readField("ciphertext")
	if err != nil {
		return nil, err
	}

	// Metadata JSON
	metadataJSON, err := readField("metadata")
	if err != nil {
		return nil, err
	}

	// Parse metadata
	var metadata map[string]string
	if err := json.Unmarshal(metadataJSON, &metadata); err != nil {
		return nil, fmt.Errorf("%w: invalid metadata JSON: %v", ErrDeserializationFailed, err)
	}

	algorithm := metadata["algorithm"]
	if algorithm == "" {
		algorithm = AlgorithmAES256GCM
	}

	return &EncryptedPrivateKey{
		Ciphertext:       ciphertext,
		Salt:             salt,
		Nonce:            nonce,
		Algorithm:        algorithm,
		PBKDF2Iterations: iterations,
		Version:          version,
	}, nil
}

// ============================================================================
// High-Level Wrapper Functions
// ============================================================================

// EncryptPrivateKeyPEM is a high-level wrapper for encrypting PEM private key.
// It validates PEM format, encrypts the key, and serializes the result.
// Returns byte slice ready for file write.
func EncryptPrivateKeyPEM(privateKeyPEM []byte, passphrase []byte) ([]byte, error) {
	// Encrypt the private key
	encrypted, err := EncryptPrivateKey(privateKeyPEM, passphrase)
	if err != nil {
		return nil, err
	}

	// Serialize for storage
	data, err := SerializeEncryptedKey(encrypted)
	if err != nil {
		return nil, err
	}

	return data, nil
}

// DecryptPrivateKeyPEM is a high-level wrapper for decrypting PEM private key.
// It deserializes the encrypted data, decrypts it, and validates the result is valid PEM.
func DecryptPrivateKeyPEM(encryptedData []byte, passphrase []byte) ([]byte, error) {
	// Deserialize encrypted data
	encrypted, err := DeserializeEncryptedKey(encryptedData)
	if err != nil {
		return nil, err
	}

	// Decrypt private key
	privateKeyPEM, err := DecryptPrivateKey(encrypted, passphrase)
	if err != nil {
		return nil, err
	}

	// Validate decrypted data is valid PEM
	block, _ := pem.Decode(privateKeyPEM)
	if block == nil {
		return nil, fmt.Errorf("%w: decrypted data is not valid PEM", ErrDecryptionFailed)
	}

	return privateKeyPEM, nil
}

// ============================================================================
// Key Rotation
// ============================================================================

// RotatePassphrase changes encryption passphrase without exposing private key in memory
// longer than necessary.
// Steps:
//  1. Decrypt with old passphrase
//  2. Validate decrypted key is valid PEM
//  3. Encrypt with new passphrase
//  4. Return new EncryptedPrivateKey
//
// Use case: Periodic passphrase rotation for security compliance.
// The operation is atomic - old key remains valid if rotation fails.
func RotatePassphrase(oldPassphrase []byte, newPassphrase []byte, encryptedKey *EncryptedPrivateKey) (*EncryptedPrivateKey, error) {
	// Validate new passphrase before attempting decryption
	if err := ValidatePassphrase(newPassphrase); err != nil {
		return nil, fmt.Errorf("new passphrase validation failed: %w", err)
	}

	// Decrypt with old passphrase
	privateKeyPEM, err := DecryptPrivateKey(encryptedKey, oldPassphrase)
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt with old passphrase: %w", err)
	}

	// Encrypt with new passphrase
	newEncrypted, err := EncryptPrivateKey(privateKeyPEM, newPassphrase)
	if err != nil {
		return nil, fmt.Errorf("failed to encrypt with new passphrase: %w", err)
	}

	// Zero out plaintext private key in memory
	for i := range privateKeyPEM {
		privateKeyPEM[i] = 0
	}

	return newEncrypted, nil
}

// ============================================================================
// Utility Functions
// ============================================================================

// ZeroMemory securely zeros a byte slice to remove sensitive data from memory.
// Should be called after passphrase or key material is no longer needed.
func ZeroMemory(data []byte) {
	for i := range data {
		data[i] = 0
	}
}

// IsEncrypted checks if data appears to be an encrypted private key.
// Returns true if the data starts with the expected format version.
func IsEncrypted(data []byte) bool {
	if len(data) < 1 {
		return false
	}
	// Check for our format version byte
	return data[0] == FormatVersion
}

// GetEncryptionInfo returns metadata about encrypted key without decrypting.
func GetEncryptionInfo(encryptedData []byte) (map[string]interface{}, error) {
	encrypted, err := DeserializeEncryptedKey(encryptedData)
	if err != nil {
		return nil, err
	}

	return map[string]interface{}{
		"algorithm":         encrypted.Algorithm,
		"pbkdf2_iterations": encrypted.PBKDF2Iterations,
		"version":           encrypted.Version,
		"ciphertext_size":   len(encrypted.Ciphertext),
	}, nil
}
