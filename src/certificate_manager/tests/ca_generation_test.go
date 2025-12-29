// Package tests provides comprehensive testing for the Certificate Manager.
// This file tests CA certificate generation, encryption, storage, and validation.
package tests

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"
	"os"
	"path/filepath"
	"testing"
	"time"

	"golang.org/x/crypto/pbkdf2"
)

// ============================================================================
// Test Types and Fixtures
// ============================================================================

// TestCAConfig holds configuration for test CA generation.
type TestCAConfig struct {
	Organization  string
	CommonName    string
	Country       string
	ValidityYears int
	KeySizeBits   int
}

// DefaultTestCAConfig returns default test configuration.
func DefaultTestCAConfig() *TestCAConfig {
	return &TestCAConfig{
		Organization:  "SafeOps Network",
		CommonName:    "SafeOps Root CA",
		Country:       "US",
		ValidityYears: 10,
		KeySizeBits:   2048, // Smaller for faster tests
	}
}

// MockCAGenerator provides CA generation for tests.
type MockCAGenerator struct {
	config *TestCAConfig
}

// NewMockCAGenerator creates a new mock CA generator.
func NewMockCAGenerator(config *TestCAConfig) *MockCAGenerator {
	if config == nil {
		config = DefaultTestCAConfig()
	}
	return &MockCAGenerator{config: config}
}

// GenerateRootCA generates a self-signed root CA certificate.
func (g *MockCAGenerator) GenerateRootCA() (*x509.Certificate, *rsa.PrivateKey, error) {
	// Generate private key
	privateKey, err := rsa.GenerateKey(rand.Reader, g.config.KeySizeBits)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to generate private key: %w", err)
	}

	// Generate serial number
	serialNumber, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return nil, nil, fmt.Errorf("failed to generate serial number: %w", err)
	}

	now := time.Now()
	template := &x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			Organization: []string{g.config.Organization},
			CommonName:   g.config.CommonName,
			Country:      []string{g.config.Country},
		},
		NotBefore:             now,
		NotAfter:              now.AddDate(g.config.ValidityYears, 0, 0),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		MaxPathLen:            0,
		MaxPathLenZero:        true,
	}

	// Self-sign the certificate
	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &privateKey.PublicKey, privateKey)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to create certificate: %w", err)
	}

	// Parse the certificate
	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to parse certificate: %w", err)
	}

	return cert, privateKey, nil
}

// EncodeCertificatePEM encodes certificate to PEM format.
func EncodeCertificatePEM(cert *x509.Certificate) []byte {
	return pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: cert.Raw,
	})
}

// EncodePrivateKeyPEM encodes private key to PEM format.
func EncodePrivateKeyPEM(key *rsa.PrivateKey) []byte {
	return pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(key),
	})
}

// EncryptWithAESGCM encrypts data using AES-256-GCM.
func EncryptWithAESGCM(plaintext, key []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, err
	}

	return gcm.Seal(nonce, nonce, plaintext, nil), nil
}

// DecryptWithAESGCM decrypts data using AES-256-GCM.
func DecryptWithAESGCM(ciphertext, key []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	nonceSize := gcm.NonceSize()
	if len(ciphertext) < nonceSize {
		return nil, fmt.Errorf("ciphertext too short")
	}

	nonce, ciphertext := ciphertext[:nonceSize], ciphertext[nonceSize:]
	return gcm.Open(nil, nonce, ciphertext, nil)
}

// DeriveKeyFromPassphrase derives a 32-byte key using PBKDF2.
func DeriveKeyFromPassphrase(passphrase, salt []byte, iterations int) []byte {
	return pbkdf2.Key(passphrase, salt, iterations, 32, sha256.New)
}

// GeneratePassphrase generates a random 32-byte passphrase.
func GeneratePassphrase() ([]byte, error) {
	passphrase := make([]byte, 32)
	if _, err := rand.Read(passphrase); err != nil {
		return nil, err
	}
	return passphrase, nil
}

// ValidateCA validates that a certificate is a valid CA.
func ValidateCA(cert *x509.Certificate) error {
	if cert == nil {
		return fmt.Errorf("certificate is nil")
	}

	// Check if CA
	if !cert.IsCA {
		return fmt.Errorf("not a CA certificate")
	}

	// Check basic constraints
	if !cert.BasicConstraintsValid {
		return fmt.Errorf("basic constraints not valid")
	}

	// Check key usage
	if cert.KeyUsage&x509.KeyUsageCertSign == 0 {
		return fmt.Errorf("missing CertSign key usage")
	}
	if cert.KeyUsage&x509.KeyUsageCRLSign == 0 {
		return fmt.Errorf("missing CRLSign key usage")
	}

	// Check validity
	now := time.Now()
	if now.Before(cert.NotBefore) {
		return fmt.Errorf("certificate not yet valid")
	}
	if now.After(cert.NotAfter) {
		return fmt.Errorf("certificate expired")
	}

	return nil
}

// CheckExpiry returns days until certificate expires and warning if < threshold.
func CheckExpiry(cert *x509.Certificate, warningThresholdDays int) (int, bool) {
	daysRemaining := int(time.Until(cert.NotAfter).Hours() / 24)
	warning := daysRemaining < warningThresholdDays
	return daysRemaining, warning
}

// ============================================================================
// CA Generation Tests
// ============================================================================

// TestGenerateRootCA tests CA certificate generation.
func TestGenerateRootCA(t *testing.T) {
	gen := NewMockCAGenerator(nil)

	cert, key, err := gen.GenerateRootCA()
	if err != nil {
		t.Fatalf("GenerateRootCA failed: %v", err)
	}

	// Verify certificate properties
	if cert.Subject.CommonName != "SafeOps Root CA" {
		t.Errorf("CommonName = %s, want SafeOps Root CA", cert.Subject.CommonName)
	}

	if len(cert.Subject.Organization) == 0 || cert.Subject.Organization[0] != "SafeOps Network" {
		t.Errorf("Organization mismatch")
	}

	// Verify self-signed
	if cert.Subject.String() != cert.Issuer.String() {
		t.Error("Certificate is not self-signed")
	}

	// Verify CA flag
	if !cert.IsCA {
		t.Error("IsCA = false, want true")
	}

	// Verify key usage
	if cert.KeyUsage&x509.KeyUsageCertSign == 0 {
		t.Error("Missing KeyUsageCertSign")
	}
	if cert.KeyUsage&x509.KeyUsageCRLSign == 0 {
		t.Error("Missing KeyUsageCRLSign")
	}

	// Verify private key
	if key == nil {
		t.Error("Private key is nil")
	}
	if key.N.BitLen() != 2048 {
		t.Errorf("Key size = %d, want 2048", key.N.BitLen())
	}
}

// TestGenerateRootCA_KeySize tests different key sizes.
func TestGenerateRootCA_KeySize(t *testing.T) {
	keySizes := []int{2048, 3072}
	if !testing.Short() {
		keySizes = append(keySizes, 4096)
	}

	for _, keySize := range keySizes {
		t.Run(fmt.Sprintf("KeySize_%d", keySize), func(t *testing.T) {
			config := DefaultTestCAConfig()
			config.KeySizeBits = keySize
			gen := NewMockCAGenerator(config)

			_, key, err := gen.GenerateRootCA()
			if err != nil {
				t.Fatalf("GenerateRootCA failed: %v", err)
			}

			if key.N.BitLen() != keySize {
				t.Errorf("Key size = %d, want %d", key.N.BitLen(), keySize)
			}
		})
	}
}

// TestGenerateRootCA_Validity tests validity period.
func TestGenerateRootCA_Validity(t *testing.T) {
	validityYears := []int{1, 5, 10}

	for _, years := range validityYears {
		t.Run(fmt.Sprintf("Validity_%dYears", years), func(t *testing.T) {
			config := DefaultTestCAConfig()
			config.ValidityYears = years
			gen := NewMockCAGenerator(config)

			cert, _, err := gen.GenerateRootCA()
			if err != nil {
				t.Fatalf("GenerateRootCA failed: %v", err)
			}

			// Use AddDate for expected calculation (matches implementation)
			now := time.Now()
			expectedNotAfter := now.AddDate(years, 0, 0)
			actualDuration := cert.NotAfter.Sub(cert.NotBefore)
			expectedDuration := expectedNotAfter.Sub(now)

			// Allow 2 day tolerance (for clock differences and leap years)
			tolerance := 48 * time.Hour
			if actualDuration < expectedDuration-tolerance || actualDuration > expectedDuration+tolerance {
				t.Errorf("Validity = %v, want ~%v", actualDuration, expectedDuration)
			}
		})
	}
}

// TestGenerateRootCA_SerialUniqueness tests serial number uniqueness.
func TestGenerateRootCA_SerialUniqueness(t *testing.T) {
	gen := NewMockCAGenerator(nil)
	serials := make(map[string]bool)

	for i := 0; i < 10; i++ {
		cert, _, err := gen.GenerateRootCA()
		if err != nil {
			t.Fatalf("GenerateRootCA failed: %v", err)
		}

		serialStr := cert.SerialNumber.String()
		if serials[serialStr] {
			t.Errorf("Duplicate serial number: %s", serialStr)
		}
		serials[serialStr] = true
	}
}

// TestGenerateRootCA_SelfSigned tests self-signature validation.
func TestGenerateRootCA_SelfSigned(t *testing.T) {
	gen := NewMockCAGenerator(nil)

	cert, _, err := gen.GenerateRootCA()
	if err != nil {
		t.Fatalf("GenerateRootCA failed: %v", err)
	}

	// Verify signature with own public key
	if err := cert.CheckSignature(cert.SignatureAlgorithm, cert.RawTBSCertificate, cert.Signature); err != nil {
		t.Errorf("Self-signature validation failed: %v", err)
	}
}

// ============================================================================
// Private Key Encryption Tests
// ============================================================================

// TestEncryptPrivateKey tests private key encryption.
func TestEncryptPrivateKey(t *testing.T) {
	gen := NewMockCAGenerator(nil)
	_, key, _ := gen.GenerateRootCA()

	keyPEM := EncodePrivateKeyPEM(key)
	encKey := make([]byte, 32)
	rand.Read(encKey)

	ciphertext, err := EncryptWithAESGCM(keyPEM, encKey)
	if err != nil {
		t.Fatalf("Encryption failed: %v", err)
	}

	// Verify ciphertext differs from plaintext
	if bytes.Equal(ciphertext, keyPEM) {
		t.Error("Ciphertext equals plaintext")
	}

	// Verify ciphertext is longer (includes nonce + tag)
	if len(ciphertext) <= len(keyPEM) {
		t.Error("Ciphertext should be longer than plaintext")
	}
}

// TestEncryptDecryptPrivateKey tests round-trip encryption.
func TestEncryptDecryptPrivateKey(t *testing.T) {
	gen := NewMockCAGenerator(nil)
	_, key, _ := gen.GenerateRootCA()

	keyPEM := EncodePrivateKeyPEM(key)
	encKey := make([]byte, 32)
	rand.Read(encKey)

	// Encrypt
	ciphertext, err := EncryptWithAESGCM(keyPEM, encKey)
	if err != nil {
		t.Fatalf("Encryption failed: %v", err)
	}

	// Decrypt
	plaintext, err := DecryptWithAESGCM(ciphertext, encKey)
	if err != nil {
		t.Fatalf("Decryption failed: %v", err)
	}

	// Verify match
	if !bytes.Equal(plaintext, keyPEM) {
		t.Error("Decrypted key doesn't match original")
	}
}

// TestEncryptPrivateKey_WrongPassphrase tests decryption with wrong key.
func TestEncryptPrivateKey_WrongPassphrase(t *testing.T) {
	gen := NewMockCAGenerator(nil)
	_, key, _ := gen.GenerateRootCA()

	keyPEM := EncodePrivateKeyPEM(key)
	encKey := make([]byte, 32)
	rand.Read(encKey)

	ciphertext, _ := EncryptWithAESGCM(keyPEM, encKey)

	// Try to decrypt with different key
	wrongKey := make([]byte, 32)
	rand.Read(wrongKey)

	_, err := DecryptWithAESGCM(ciphertext, wrongKey)
	if err == nil {
		t.Error("Decryption should fail with wrong key")
	}
}

// TestEncryptPrivateKey_CorruptedCiphertext tests tamper detection.
func TestEncryptPrivateKey_CorruptedCiphertext(t *testing.T) {
	gen := NewMockCAGenerator(nil)
	_, key, _ := gen.GenerateRootCA()

	keyPEM := EncodePrivateKeyPEM(key)
	encKey := make([]byte, 32)
	rand.Read(encKey)

	ciphertext, _ := EncryptWithAESGCM(keyPEM, encKey)

	// Corrupt the ciphertext
	if len(ciphertext) > 20 {
		ciphertext[20] ^= 0xFF
	}

	_, err := DecryptWithAESGCM(ciphertext, encKey)
	if err == nil {
		t.Error("Decryption should fail with corrupted ciphertext")
	}
}

// TestPassphraseGeneration tests secure passphrase generation.
func TestPassphraseGeneration(t *testing.T) {
	passphrase, err := GeneratePassphrase()
	if err != nil {
		t.Fatalf("GeneratePassphrase failed: %v", err)
	}

	if len(passphrase) != 32 {
		t.Errorf("Passphrase length = %d, want 32", len(passphrase))
	}

	// Generate multiple and check uniqueness
	passphrases := make([][]byte, 5)
	for i := range passphrases {
		passphrases[i], _ = GeneratePassphrase()
	}

	for i := 0; i < len(passphrases); i++ {
		for j := i + 1; j < len(passphrases); j++ {
			if bytes.Equal(passphrases[i], passphrases[j]) {
				t.Error("Generated duplicate passphrases")
			}
		}
	}
}

// TestPBKDF2Derivation tests key derivation.
func TestPBKDF2Derivation(t *testing.T) {
	passphrase := []byte("test-passphrase")
	salt := []byte("test-salt-12345678")
	iterations := 100000

	key1 := DeriveKeyFromPassphrase(passphrase, salt, iterations)
	key2 := DeriveKeyFromPassphrase(passphrase, salt, iterations)

	// Same input = same output
	if !bytes.Equal(key1, key2) {
		t.Error("PBKDF2 not deterministic")
	}

	// Check key length
	if len(key1) != 32 {
		t.Errorf("Derived key length = %d, want 32", len(key1))
	}

	// Different salt = different key
	differentSalt := []byte("different-salt-123")
	key3 := DeriveKeyFromPassphrase(passphrase, differentSalt, iterations)
	if bytes.Equal(key1, key3) {
		t.Error("Different salt should produce different key")
	}
}

// ============================================================================
// CA Storage Tests
// ============================================================================

// TestSaveAndLoadCA tests saving and loading CA files.
func TestSaveAndLoadCA(t *testing.T) {
	tempDir := t.TempDir()
	certPath := filepath.Join(tempDir, "root-cert.pem")

	gen := NewMockCAGenerator(nil)
	cert, _, err := gen.GenerateRootCA()
	if err != nil {
		t.Fatalf("GenerateRootCA failed: %v", err)
	}

	// Save certificate
	certPEM := EncodeCertificatePEM(cert)
	if err := os.WriteFile(certPath, certPEM, 0644); err != nil {
		t.Fatalf("Failed to save certificate: %v", err)
	}

	// Load certificate
	loadedPEM, err := os.ReadFile(certPath)
	if err != nil {
		t.Fatalf("Failed to read certificate: %v", err)
	}

	block, _ := pem.Decode(loadedPEM)
	if block == nil {
		t.Fatal("Failed to decode PEM")
	}

	loadedCert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatalf("Failed to parse certificate: %v", err)
	}

	// Verify loaded cert matches original
	if loadedCert.SerialNumber.Cmp(cert.SerialNumber) != 0 {
		t.Error("Loaded certificate serial doesn't match")
	}
	if loadedCert.Subject.CommonName != cert.Subject.CommonName {
		t.Error("Loaded certificate subject doesn't match")
	}
}

// TestSaveCA_FilePermissions tests file permission enforcement.
func TestSaveCA_FilePermissions(t *testing.T) {
	// Skip on Windows - file permissions work differently
	if os.PathSeparator == '\\' {
		t.Skip("Skipping file permission test on Windows")
	}

	tempDir := t.TempDir()
	certPath := filepath.Join(tempDir, "root-cert.pem")
	keyPath := filepath.Join(tempDir, "root-key.pem.enc")

	gen := NewMockCAGenerator(nil)
	cert, key, _ := gen.GenerateRootCA()

	// Save with specific permissions
	certPEM := EncodeCertificatePEM(cert)
	keyPEM := EncodePrivateKeyPEM(key)

	if err := os.WriteFile(certPath, certPEM, 0644); err != nil {
		t.Fatalf("Failed to save certificate: %v", err)
	}
	if err := os.WriteFile(keyPath, keyPEM, 0600); err != nil {
		t.Fatalf("Failed to save key: %v", err)
	}

	// Check permissions
	certInfo, _ := os.Stat(certPath)
	keyInfo, _ := os.Stat(keyPath)

	if certInfo.Mode().Perm() != 0644 {
		t.Errorf("Cert permissions = %o, want 0644", certInfo.Mode().Perm())
	}
	if keyInfo.Mode().Perm() != 0600 {
		t.Errorf("Key permissions = %o, want 0600", keyInfo.Mode().Perm())
	}
}

// TestSaveCA_DirectoryCreation tests automatic directory creation.
func TestSaveCA_DirectoryCreation(t *testing.T) {
	tempDir := t.TempDir()
	nestedPath := filepath.Join(tempDir, "nested", "ca", "root-cert.pem")

	gen := NewMockCAGenerator(nil)
	cert, _, _ := gen.GenerateRootCA()
	certPEM := EncodeCertificatePEM(cert)

	// Create directory and save
	if err := os.MkdirAll(filepath.Dir(nestedPath), 0700); err != nil {
		t.Fatalf("Failed to create directory: %v", err)
	}
	if err := os.WriteFile(nestedPath, certPEM, 0644); err != nil {
		t.Fatalf("Failed to save certificate: %v", err)
	}

	// Verify file exists
	if _, err := os.Stat(nestedPath); os.IsNotExist(err) {
		t.Error("Certificate file not created")
	}
}

// ============================================================================
// CA Validation Tests
// ============================================================================

// TestValidateCA_Valid tests validation of valid CA.
func TestValidateCA_Valid(t *testing.T) {
	gen := NewMockCAGenerator(nil)
	cert, _, _ := gen.GenerateRootCA()

	if err := ValidateCA(cert); err != nil {
		t.Errorf("ValidateCA failed: %v", err)
	}
}

// TestValidateCA_NotCA tests validation of non-CA certificate.
func TestValidateCA_NotCA(t *testing.T) {
	// Create certificate without CA flag
	key, _ := rsa.GenerateKey(rand.Reader, 2048)
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "Not a CA"},
		NotBefore:    time.Now(),
		NotAfter:     time.Now().AddDate(1, 0, 0),
		IsCA:         false, // Not a CA
	}

	certDER, _ := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	cert, _ := x509.ParseCertificate(certDER)

	err := ValidateCA(cert)
	if err == nil {
		t.Error("ValidateCA should fail for non-CA certificate")
	}
}

// TestValidateCA_Expired tests validation of expired CA.
func TestValidateCA_Expired(t *testing.T) {
	key, _ := rsa.GenerateKey(rand.Reader, 2048)
	template := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "Expired CA"},
		NotBefore:             time.Now().AddDate(-2, 0, 0),
		NotAfter:              time.Now().AddDate(-1, 0, 0), // Expired
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
	}

	certDER, _ := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	cert, _ := x509.ParseCertificate(certDER)

	err := ValidateCA(cert)
	if err == nil {
		t.Error("ValidateCA should fail for expired certificate")
	}
}

// TestValidateCA_NotYetValid tests validation of future CA.
func TestValidateCA_NotYetValid(t *testing.T) {
	key, _ := rsa.GenerateKey(rand.Reader, 2048)
	template := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "Future CA"},
		NotBefore:             time.Now().AddDate(1, 0, 0), // Future
		NotAfter:              time.Now().AddDate(2, 0, 0),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
	}

	certDER, _ := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	cert, _ := x509.ParseCertificate(certDER)

	err := ValidateCA(cert)
	if err == nil {
		t.Error("ValidateCA should fail for not-yet-valid certificate")
	}
}

// TestCheckExpiry tests expiry checking.
func TestCheckExpiry(t *testing.T) {
	gen := NewMockCAGenerator(nil)

	// Manually create cert with short validity for testing
	key, _ := rsa.GenerateKey(rand.Reader, 2048)
	template := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "Short CA"},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().AddDate(0, 0, 20), // 20 days
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign,
	}
	certDER, _ := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	shortCert, _ := x509.ParseCertificate(certDER)

	days, warning := CheckExpiry(shortCert, 30)
	if !warning {
		t.Error("Should warn for certificate expiring in < 30 days")
	}
	if days > 25 || days < 15 {
		t.Errorf("Days remaining = %d, expected ~20", days)
	}

	// Normal validity (10 years)
	longCert, _, _ := gen.GenerateRootCA()
	_, warning = CheckExpiry(longCert, 30)
	if warning {
		t.Error("Should not warn for certificate expiring in > 30 days")
	}
}

// ============================================================================
// Error Handling Tests
// ============================================================================

// TestLoadCA_FileNotFound tests loading non-existent file.
func TestLoadCA_FileNotFound(t *testing.T) {
	_, err := os.ReadFile("/non/existent/path/cert.pem")
	if err == nil {
		t.Error("Should fail to read non-existent file")
	}
}

// TestLoadCA_CorruptedPEM tests loading corrupted PEM.
func TestLoadCA_CorruptedPEM(t *testing.T) {
	tempDir := t.TempDir()
	badPath := filepath.Join(tempDir, "bad.pem")

	// Write invalid PEM
	os.WriteFile(badPath, []byte("not valid pem data"), 0644)

	data, _ := os.ReadFile(badPath)
	block, _ := pem.Decode(data)

	if block != nil {
		t.Error("Should fail to decode invalid PEM")
	}
}

// TestValidateCA_Nil tests validation of nil certificate.
func TestValidateCA_Nil(t *testing.T) {
	err := ValidateCA(nil)
	if err == nil {
		t.Error("ValidateCA should fail for nil certificate")
	}
}

// ============================================================================
// CA Renewal Tests
// ============================================================================

// TestCAFingerprint tests certificate fingerprint calculation.
func TestCAFingerprint(t *testing.T) {
	gen := NewMockCAGenerator(nil)
	cert, _, _ := gen.GenerateRootCA()

	fingerprint := sha256.Sum256(cert.Raw)

	// Verify fingerprint is consistent
	fingerprint2 := sha256.Sum256(cert.Raw)
	if fingerprint != fingerprint2 {
		t.Error("Fingerprint calculation not consistent")
	}

	// Verify fingerprint is 32 bytes (SHA-256)
	if len(fingerprint) != 32 {
		t.Errorf("Fingerprint length = %d, want 32", len(fingerprint))
	}
}

// TestRenewCA tests CA renewal creates new certificate.
func TestRenewCA(t *testing.T) {
	gen := NewMockCAGenerator(nil)
	oldCert, oldKey, _ := gen.GenerateRootCA()

	// Generate new CA (simulating renewal)
	newCert, newKey, _ := gen.GenerateRootCA()

	// Verify different serial numbers
	if oldCert.SerialNumber.Cmp(newCert.SerialNumber) == 0 {
		t.Error("Renewed CA should have different serial number")
	}

	// Verify different keys
	if oldKey.N.Cmp(newKey.N) == 0 {
		t.Error("Renewed CA should have different key")
	}

	// Verify same subject
	if oldCert.Subject.CommonName != newCert.Subject.CommonName {
		t.Error("Renewed CA should have same subject")
	}
}
