// Package generation handles cryptographic key and CSR generation for certificates.
package generation

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"fmt"

	"certificate_manager/pkg/types"

	"golang.org/x/crypto/pbkdf2"
)

// ============================================================================
// Section 10: Constants
// ============================================================================

const (
	MinRSAKeySize     = 2048
	DefaultRSAKeySize = 4096
	PEMTypeRSA        = "RSA PRIVATE KEY"
	PEMTypeEC         = "EC PRIVATE KEY"
	PEMTypePKCS8      = "PRIVATE KEY"
	PEMTypePublicKey  = "PUBLIC KEY"

	// Encryption constants
	PBKDF2Iterations = 100000
	SaltSize         = 16
	AESKeySize       = 32 // AES-256
)

// Supported elliptic curves
var SupportedCurves = []elliptic.Curve{
	elliptic.P256(),
	elliptic.P384(),
}

// ============================================================================
// Section 2: Key Generation Functions
// ============================================================================

// GeneratePrivateKey creates a new private key of the specified type
func GeneratePrivateKey(keyType types.KeyType) (*types.PrivateKeyInfo, error) {
	if err := validateKeyType(keyType); err != nil {
		return nil, err
	}

	var key interface{}
	var err error

	switch keyType {
	case types.KeyRSA2048:
		key, err = generateRSAKey(2048)
	case types.KeyRSA4096:
		key, err = generateRSAKey(4096)
	case types.KeyECDSAP256:
		key, err = generateECDSAKey(elliptic.P256())
	case types.KeyECDSAP384:
		key, err = generateECDSAKey(elliptic.P384())
	default:
		return nil, fmt.Errorf("unsupported key type: %s", keyType)
	}

	if err != nil {
		return nil, fmt.Errorf("failed to generate %s key: %w", keyType, err)
	}

	// Encode to PEM
	pemData, err := EncodePrivateKeyToPEM(key)
	if err != nil {
		return nil, fmt.Errorf("failed to encode key to PEM: %w", err)
	}

	return &types.PrivateKeyInfo{
		Type: keyType,
		Key:  key,
		PEM:  pemData,
		Bits: keyType.BitSize(),
	}, nil
}

// generateRSAKey creates an RSA private key
func generateRSAKey(bits int) (*rsa.PrivateKey, error) {
	if bits < MinRSAKeySize {
		return nil, fmt.Errorf("RSA key size must be at least %d bits", MinRSAKeySize)
	}

	key, err := rsa.GenerateKey(rand.Reader, bits)
	if err != nil {
		return nil, fmt.Errorf("RSA key generation failed: %w", err)
	}

	// Validate generated key
	if err := key.Validate(); err != nil {
		return nil, fmt.Errorf("RSA key validation failed: %w", err)
	}

	return key, nil
}

// generateECDSAKey creates an ECDSA private key on the specified curve
func generateECDSAKey(curve elliptic.Curve) (*ecdsa.PrivateKey, error) {
	if !isSupportedCurve(curve) {
		return nil, fmt.Errorf("unsupported elliptic curve: %s", curve.Params().Name)
	}

	key, err := ecdsa.GenerateKey(curve, rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("ECDSA key generation failed: %w", err)
	}

	return key, nil
}

// validateKeyType ensures the key type is supported
func validateKeyType(kt types.KeyType) error {
	switch kt {
	case types.KeyRSA2048, types.KeyRSA4096, types.KeyECDSAP256, types.KeyECDSAP384:
		return nil
	default:
		return fmt.Errorf("unsupported key type: %s", kt)
	}
}

// isSupportedCurve checks if the curve is in supported list
func isSupportedCurve(curve elliptic.Curve) bool {
	for _, c := range SupportedCurves {
		if c == curve {
			return true
		}
	}
	return false
}

// ============================================================================
// Section 3: PEM Encoding Functions
// ============================================================================

// EncodePrivateKeyToPEM converts a private key to PEM format
func EncodePrivateKeyToPEM(key interface{}) (string, error) {
	switch k := key.(type) {
	case *rsa.PrivateKey:
		return encodeRSAToPEM(k)
	case *ecdsa.PrivateKey:
		return encodeECDSAToPEM(k)
	default:
		return "", fmt.Errorf("unsupported key type: %T", key)
	}
}

// encodeRSAToPEM encodes RSA private key to PEM
func encodeRSAToPEM(key *rsa.PrivateKey) (string, error) {
	if key == nil {
		return "", errors.New("RSA key is nil")
	}

	derBytes := x509.MarshalPKCS1PrivateKey(key)
	block := &pem.Block{
		Type:  PEMTypeRSA,
		Bytes: derBytes,
	}

	return string(pem.EncodeToMemory(block)), nil
}

// encodeECDSAToPEM encodes ECDSA private key to PEM
func encodeECDSAToPEM(key *ecdsa.PrivateKey) (string, error) {
	if key == nil {
		return "", errors.New("ECDSA key is nil")
	}

	derBytes, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return "", fmt.Errorf("failed to marshal ECDSA key: %w", err)
	}

	block := &pem.Block{
		Type:  PEMTypeEC,
		Bytes: derBytes,
	}

	return string(pem.EncodeToMemory(block)), nil
}

// EncodePublicKeyToPEM extracts and encodes the public key
func EncodePublicKeyToPEM(key interface{}) (string, error) {
	var pubKey interface{}

	switch k := key.(type) {
	case *rsa.PrivateKey:
		pubKey = &k.PublicKey
	case *ecdsa.PrivateKey:
		pubKey = &k.PublicKey
	case *rsa.PublicKey:
		pubKey = k
	case *ecdsa.PublicKey:
		pubKey = k
	default:
		return "", fmt.Errorf("unsupported key type: %T", key)
	}

	derBytes, err := x509.MarshalPKIXPublicKey(pubKey)
	if err != nil {
		return "", fmt.Errorf("failed to marshal public key: %w", err)
	}

	block := &pem.Block{
		Type:  PEMTypePublicKey,
		Bytes: derBytes,
	}

	return string(pem.EncodeToMemory(block)), nil
}

// ============================================================================
// Section 4: PEM Decoding Functions
// ============================================================================

// DecodePrivateKeyFromPEM parses a PEM-encoded private key
func DecodePrivateKeyFromPEM(pemData string) (*types.PrivateKeyInfo, error) {
	block, _ := pem.Decode([]byte(pemData))
	if block == nil {
		return nil, errors.New("failed to decode PEM block")
	}

	var key interface{}
	var err error

	switch block.Type {
	case PEMTypeRSA:
		key, err = parseRSAPrivateKey(block)
	case PEMTypeEC:
		key, err = parseECDSAPrivateKey(block)
	case PEMTypePKCS8:
		key, err = x509.ParsePKCS8PrivateKey(block.Bytes)
	default:
		return nil, fmt.Errorf("unsupported PEM type: %s", block.Type)
	}

	if err != nil {
		return nil, fmt.Errorf("failed to parse private key: %w", err)
	}

	keyType := identifyKeyType(key)
	return &types.PrivateKeyInfo{
		Type: keyType,
		Key:  key,
		PEM:  pemData,
		Bits: keyType.BitSize(),
	}, nil
}

// parseRSAPrivateKey parses RSA key from PEM block
func parseRSAPrivateKey(block *pem.Block) (*rsa.PrivateKey, error) {
	// Try PKCS1 first
	key, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err == nil {
		return key, nil
	}

	// Try PKCS8
	pkcs8Key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse RSA key: %w", err)
	}

	rsaKey, ok := pkcs8Key.(*rsa.PrivateKey)
	if !ok {
		return nil, errors.New("PKCS8 key is not RSA")
	}

	return rsaKey, nil
}

// parseECDSAPrivateKey parses ECDSA key from PEM block
func parseECDSAPrivateKey(block *pem.Block) (*ecdsa.PrivateKey, error) {
	key, err := x509.ParseECPrivateKey(block.Bytes)
	if err != nil {
		// Try PKCS8
		pkcs8Key, pkcs8Err := x509.ParsePKCS8PrivateKey(block.Bytes)
		if pkcs8Err != nil {
			return nil, fmt.Errorf("failed to parse ECDSA key: %w", err)
		}

		ecKey, ok := pkcs8Key.(*ecdsa.PrivateKey)
		if !ok {
			return nil, errors.New("PKCS8 key is not ECDSA")
		}
		return ecKey, nil
	}

	return key, nil
}

// identifyKeyType determines KeyType from key object
func identifyKeyType(key interface{}) types.KeyType {
	switch k := key.(type) {
	case *rsa.PrivateKey:
		bits := k.N.BitLen()
		if bits <= 2048 {
			return types.KeyRSA2048
		}
		return types.KeyRSA4096
	case *ecdsa.PrivateKey:
		switch k.Curve {
		case elliptic.P256():
			return types.KeyECDSAP256
		case elliptic.P384():
			return types.KeyECDSAP384
		}
	}
	return ""
}

// ============================================================================
// Section 5: Key Information Extraction
// ============================================================================

// GetKeyInfo wraps a key in PrivateKeyInfo with metadata
func GetKeyInfo(key interface{}) (*types.PrivateKeyInfo, error) {
	keyType := identifyKeyType(key)
	if keyType == "" {
		return nil, fmt.Errorf("unable to identify key type for: %T", key)
	}

	pemData, err := EncodePrivateKeyToPEM(key)
	if err != nil {
		return nil, err
	}

	return &types.PrivateKeyInfo{
		Type: keyType,
		Key:  key,
		PEM:  pemData,
		Bits: getKeySize(key),
	}, nil
}

// getKeySize returns the key size in bits
func getKeySize(key interface{}) int {
	switch k := key.(type) {
	case *rsa.PrivateKey:
		return k.N.BitLen()
	case *ecdsa.PrivateKey:
		return k.Curve.Params().BitSize
	case *rsa.PublicKey:
		return k.N.BitLen()
	case *ecdsa.PublicKey:
		return k.Curve.Params().BitSize
	default:
		return 0
	}
}

// GetKeyAlgorithm returns the algorithm name
func GetKeyAlgorithm(key interface{}) string {
	switch key.(type) {
	case *rsa.PrivateKey, *rsa.PublicKey:
		return "RSA"
	case *ecdsa.PrivateKey, *ecdsa.PublicKey:
		return "ECDSA"
	default:
		return "Unknown"
	}
}

// GetPublicKey extracts the public key component
func GetPublicKey(key interface{}) (interface{}, error) {
	switch k := key.(type) {
	case *rsa.PrivateKey:
		return &k.PublicKey, nil
	case *ecdsa.PrivateKey:
		return &k.PublicKey, nil
	case *rsa.PublicKey:
		return k, nil
	case *ecdsa.PublicKey:
		return k, nil
	default:
		return nil, fmt.Errorf("unsupported key type: %T", key)
	}
}

// ============================================================================
// Section 6: Key Validation Functions
// ============================================================================

// ValidatePrivateKey performs comprehensive key validation
func ValidatePrivateKey(key interface{}) error {
	if key == nil {
		return errors.New("key is nil")
	}

	switch k := key.(type) {
	case *rsa.PrivateKey:
		return validateRSAKey(k)
	case *ecdsa.PrivateKey:
		return validateECDSAKey(k)
	default:
		return fmt.Errorf("unsupported key type: %T", key)
	}
}

// validateRSAKey validates RSA key security requirements
func validateRSAKey(key *rsa.PrivateKey) error {
	if key == nil {
		return errors.New("RSA key is nil")
	}

	// Check minimum key size
	bits := key.N.BitLen()
	if bits < MinRSAKeySize {
		return fmt.Errorf("RSA key too weak: %d bits (minimum: %d)", bits, MinRSAKeySize)
	}

	// Validate key structure
	if err := key.Validate(); err != nil {
		return fmt.Errorf("RSA key validation failed: %w", err)
	}

	return nil
}

// validateECDSAKey validates ECDSA key requirements
func validateECDSAKey(key *ecdsa.PrivateKey) error {
	if key == nil {
		return errors.New("ECDSA key is nil")
	}

	// Check supported curve
	if !isSupportedCurve(key.Curve) {
		return fmt.Errorf("unsupported curve: %s", key.Curve.Params().Name)
	}

	// Verify key is on curve
	if !key.Curve.IsOnCurve(key.PublicKey.X, key.PublicKey.Y) {
		return errors.New("ECDSA public key point is not on curve")
	}

	return nil
}

// ValidateKeyStrength ensures key meets security standards
func ValidateKeyStrength(keyType types.KeyType, bits int) error {
	switch keyType {
	case types.KeyRSA2048:
		if bits < 2048 {
			return errors.New("RSA-2048 requires at least 2048 bits")
		}
	case types.KeyRSA4096:
		if bits < 4096 {
			return errors.New("RSA-4096 requires at least 4096 bits")
		}
	case types.KeyECDSAP256:
		if bits != 256 {
			return errors.New("ECDSA-P256 requires 256-bit curve")
		}
	case types.KeyECDSAP384:
		if bits != 384 {
			return errors.New("ECDSA-P384 requires 384-bit curve")
		}
	}
	return nil
}

// ============================================================================
// Section 7: Key Conversion Functions
// ============================================================================

// ConvertToPKCS8 converts any key to PKCS8 format
func ConvertToPKCS8(key interface{}) ([]byte, error) {
	return x509.MarshalPKCS8PrivateKey(key)
}

// ConvertFromPKCS8 parses PKCS8-encoded keys
func ConvertFromPKCS8(data []byte) (interface{}, error) {
	return x509.ParsePKCS8PrivateKey(data)
}

// ConvertPEMFormat converts between PEM formats
func ConvertPEMFormat(pemData string, targetFormat string) (string, error) {
	keyInfo, err := DecodePrivateKeyFromPEM(pemData)
	if err != nil {
		return "", err
	}

	switch targetFormat {
	case "pkcs8":
		derBytes, err := ConvertToPKCS8(keyInfo.Key)
		if err != nil {
			return "", err
		}
		block := &pem.Block{Type: PEMTypePKCS8, Bytes: derBytes}
		return string(pem.EncodeToMemory(block)), nil

	case "pkcs1":
		rsaKey, ok := keyInfo.Key.(*rsa.PrivateKey)
		if !ok {
			return "", errors.New("PKCS1 only supports RSA keys")
		}
		return encodeRSAToPEM(rsaKey)

	default:
		return "", fmt.Errorf("unsupported target format: %s", targetFormat)
	}
}

// ============================================================================
// Section 8: Utility Functions
// ============================================================================

// CompareKeys checks if two keys are identical
func CompareKeys(key1, key2 interface{}) bool {
	pem1, err := EncodePrivateKeyToPEM(key1)
	if err != nil {
		return false
	}
	pem2, err := EncodePrivateKeyToPEM(key2)
	if err != nil {
		return false
	}
	return pem1 == pem2
}

// GetFingerprint generates SHA-256 fingerprint of public key
func GetFingerprint(key interface{}) (string, error) {
	pubKey, err := GetPublicKey(key)
	if err != nil {
		return "", err
	}

	derBytes, err := x509.MarshalPKIXPublicKey(pubKey)
	if err != nil {
		return "", err
	}

	hash := sha256.Sum256(derBytes)
	return fmt.Sprintf("%x", hash), nil
}

// SerializeKey marshals key to binary format
func SerializeKey(key interface{}) ([]byte, error) {
	return ConvertToPKCS8(key)
}

// DeserializeKey unmarshals binary key data
func DeserializeKey(data []byte, keyType types.KeyType) (interface{}, error) {
	key, err := ConvertFromPKCS8(data)
	if err != nil {
		return nil, err
	}

	// Verify key type matches
	actualType := identifyKeyType(key)
	if actualType != keyType {
		return nil, fmt.Errorf("key type mismatch: expected %s, got %s", keyType, actualType)
	}

	return key, nil
}

// IsKeyEncrypted checks if PEM block is encrypted
func IsKeyEncrypted(pemData string) bool {
	block, _ := pem.Decode([]byte(pemData))
	if block == nil {
		return false
	}
	// Check for encrypted PEM headers
	_, ok := block.Headers["DEK-Info"]
	return ok || block.Type == "ENCRYPTED PRIVATE KEY"
}

// ============================================================================
// Section 9: Key Encryption Functions
// ============================================================================

// EncryptPrivateKey encrypts PEM with AES-256
func EncryptPrivateKey(key interface{}, password string) (string, error) {
	if len(password) < 8 {
		return "", errors.New("password must be at least 8 characters")
	}

	// Get PEM data
	pemData, err := EncodePrivateKeyToPEM(key)
	if err != nil {
		return "", err
	}

	// Generate salt
	salt := make([]byte, SaltSize)
	if _, err := rand.Read(salt); err != nil {
		return "", fmt.Errorf("failed to generate salt: %w", err)
	}

	// Derive encryption key
	encKey := deriveEncryptionKey(password, salt)

	// Create cipher
	block, err := aes.NewCipher(encKey)
	if err != nil {
		return "", fmt.Errorf("failed to create cipher: %w", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", fmt.Errorf("failed to create GCM: %w", err)
	}

	// Generate nonce
	nonce := make([]byte, gcm.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return "", fmt.Errorf("failed to generate nonce: %w", err)
	}

	// Encrypt
	ciphertext := gcm.Seal(nonce, nonce, []byte(pemData), nil)

	// Combine salt + ciphertext
	encrypted := append(salt, ciphertext...)

	// Encode as base64
	return base64.StdEncoding.EncodeToString(encrypted), nil
}

// DecryptPrivateKey decrypts PEM and parses key
func DecryptPrivateKey(encryptedPEM string, password string) (*types.PrivateKeyInfo, error) {
	// Decode base64
	data, err := base64.StdEncoding.DecodeString(encryptedPEM)
	if err != nil {
		return nil, fmt.Errorf("failed to decode encrypted data: %w", err)
	}

	if len(data) < SaltSize {
		return nil, errors.New("encrypted data too short")
	}

	// Extract salt
	salt := data[:SaltSize]
	ciphertext := data[SaltSize:]

	// Derive key
	encKey := deriveEncryptionKey(password, salt)

	// Create cipher
	block, err := aes.NewCipher(encKey)
	if err != nil {
		return nil, fmt.Errorf("failed to create cipher: %w", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("failed to create GCM: %w", err)
	}

	if len(ciphertext) < gcm.NonceSize() {
		return nil, errors.New("ciphertext too short")
	}

	// Extract nonce
	nonce := ciphertext[:gcm.NonceSize()]
	ciphertext = ciphertext[gcm.NonceSize():]

	// Decrypt
	pemData, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, errors.New("decryption failed: wrong password or corrupted data")
	}

	return DecodePrivateKeyFromPEM(string(pemData))
}

// deriveEncryptionKey uses PBKDF2 for key derivation
func deriveEncryptionKey(password string, salt []byte) []byte {
	return pbkdf2.Key([]byte(password), salt, PBKDF2Iterations, AESKeySize, sha256.New)
}
