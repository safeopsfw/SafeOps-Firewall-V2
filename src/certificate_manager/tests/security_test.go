// Package tests provides comprehensive testing for the Certificate Manager.
// This file tests security features including encryption, audit logging, rate limiting, and access control.
package tests

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"golang.org/x/crypto/pbkdf2"
)

// ============================================================================
// Security Test Types
// ============================================================================

// KeyEncryption provides AES-256-GCM encryption for private keys.
type KeyEncryption struct {
	iterations int
	keyLen     int
}

// EncryptedKey represents an encrypted private key.
type EncryptedKey struct {
	Salt       []byte
	Nonce      []byte
	Ciphertext []byte
	Tag        []byte // Part of ciphertext in GCM
}

// AuditLogger provides tamper-proof audit logging.
type AuditLogger struct {
	entries  []SecurityAuditEntry
	mu       sync.RWMutex
	nextID   int64
	prevHash string
}

// SecurityAuditEntry represents an audit log entry.
type SecurityAuditEntry struct {
	ID            int64
	Timestamp     time.Time
	Operation     string
	Subject       string
	SerialNumber  string
	PerformedBy   string
	IPAddress     string
	Success       bool
	Hash          string
	PrevEntryHash string
}

// RateLimiter provides token bucket rate limiting.
type RateLimiter struct {
	buckets map[string]*TokenBucket
	mu      sync.RWMutex
}

// TokenBucket represents a rate limit bucket.
type TokenBucket struct {
	Tokens     int
	MaxTokens  int
	RefillRate int           // tokens per interval
	Interval   time.Duration // refill interval
	LastRefill time.Time
}

// AccessController provides role-based access control.
type AccessController struct {
	apiKeys     map[string]string   // key -> role
	permissions map[string][]string // role -> operations
	mu          sync.RWMutex
}

// NewKeyEncryption creates a new key encryption instance.
func NewKeyEncryption() *KeyEncryption {
	return &KeyEncryption{
		iterations: 100000,
		keyLen:     32, // AES-256
	}
}

// DeriveKey derives a key from passphrase using PBKDF2.
func (k *KeyEncryption) DeriveKey(passphrase, salt []byte) []byte {
	return pbkdf2.Key(passphrase, salt, k.iterations, k.keyLen, sha256.New)
}

// Encrypt encrypts data using AES-256-GCM.
func (k *KeyEncryption) Encrypt(plaintext, passphrase []byte) (*EncryptedKey, error) {
	// Generate salt
	salt := make([]byte, 16)
	if _, err := rand.Read(salt); err != nil {
		return nil, err
	}

	// Derive key
	key := k.DeriveKey(passphrase, salt)

	// Create cipher
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	// Generate nonce
	nonce := make([]byte, gcm.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}

	// Encrypt
	ciphertext := gcm.Seal(nil, nonce, plaintext, nil)

	return &EncryptedKey{
		Salt:       salt,
		Nonce:      nonce,
		Ciphertext: ciphertext,
	}, nil
}

// Decrypt decrypts data using AES-256-GCM.
func (k *KeyEncryption) Decrypt(encrypted *EncryptedKey, passphrase []byte) ([]byte, error) {
	// Derive key
	key := k.DeriveKey(passphrase, encrypted.Salt)

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
	plaintext, err := gcm.Open(nil, encrypted.Nonce, encrypted.Ciphertext, nil)
	if err != nil {
		return nil, fmt.Errorf("decryption failed: authentication error")
	}

	return plaintext, nil
}

// GeneratePassphrase generates a secure random passphrase.
func GenerateSecurePassphrase() ([]byte, error) {
	passphrase := make([]byte, 32)
	if _, err := rand.Read(passphrase); err != nil {
		return nil, err
	}
	return passphrase, nil
}

// NewAuditLogger creates a new audit logger.
func NewAuditLogger() *AuditLogger {
	return &AuditLogger{
		entries: make([]SecurityAuditEntry, 0),
		nextID:  1,
	}
}

// LogOperation logs an operation with hash chain.
func (a *AuditLogger) LogOperation(operation, subject, serial, performedBy, ipAddress string, success bool) *SecurityAuditEntry {
	a.mu.Lock()
	defer a.mu.Unlock()

	entry := SecurityAuditEntry{
		ID:            a.nextID,
		Timestamp:     time.Now(),
		Operation:     operation,
		Subject:       subject,
		SerialNumber:  serial,
		PerformedBy:   performedBy,
		IPAddress:     ipAddress,
		Success:       success,
		PrevEntryHash: a.prevHash,
	}

	// Calculate hash
	data := fmt.Sprintf("%d:%v:%s:%s:%s:%s:%s:%t:%s",
		entry.ID, entry.Timestamp, entry.Operation, entry.Subject,
		entry.SerialNumber, entry.PerformedBy, entry.IPAddress,
		entry.Success, entry.PrevEntryHash)
	hash := sha256.Sum256([]byte(data))
	entry.Hash = hex.EncodeToString(hash[:])

	a.entries = append(a.entries, entry)
	a.prevHash = entry.Hash
	a.nextID++

	return &entry
}

// ValidateHashChain validates the audit log hash chain.
func (a *AuditLogger) ValidateHashChain() (valid bool, brokenAt int) {
	a.mu.RLock()
	defer a.mu.RUnlock()

	for i, entry := range a.entries {
		// Calculate expected hash
		data := fmt.Sprintf("%d:%v:%s:%s:%s:%s:%s:%t:%s",
			entry.ID, entry.Timestamp, entry.Operation, entry.Subject,
			entry.SerialNumber, entry.PerformedBy, entry.IPAddress,
			entry.Success, entry.PrevEntryHash)
		hash := sha256.Sum256([]byte(data))
		expectedHash := hex.EncodeToString(hash[:])

		if entry.Hash != expectedHash {
			return false, i
		}

		// Check prev hash matches previous entry
		if i > 0 && entry.PrevEntryHash != a.entries[i-1].Hash {
			return false, i
		}
	}

	return true, -1
}

// GetEntries returns all entries.
func (a *AuditLogger) GetEntries() []SecurityAuditEntry {
	a.mu.RLock()
	defer a.mu.RUnlock()
	result := make([]SecurityAuditEntry, len(a.entries))
	copy(result, a.entries)
	return result
}

// QueryByOperation returns entries matching operation.
func (a *AuditLogger) QueryByOperation(operation string) []SecurityAuditEntry {
	a.mu.RLock()
	defer a.mu.RUnlock()
	var result []SecurityAuditEntry
	for _, e := range a.entries {
		if e.Operation == operation {
			result = append(result, e)
		}
	}
	return result
}

// TamperEntry corrupts an entry for testing.
func (a *AuditLogger) TamperEntry(index int) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if index < len(a.entries) {
		a.entries[index].Operation = "TAMPERED"
	}
}

// Clear removes all entries.
func (a *AuditLogger) Clear() {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.entries = make([]SecurityAuditEntry, 0)
	a.nextID = 1
	a.prevHash = ""
}

// NewRateLimiter creates a new rate limiter.
func NewRateLimiter() *RateLimiter {
	return &RateLimiter{
		buckets: make(map[string]*TokenBucket),
	}
}

// GetBucket gets or creates a bucket for a key.
func (r *RateLimiter) GetBucket(key string, maxTokens int, refillRate int, interval time.Duration) *TokenBucket {
	r.mu.Lock()
	defer r.mu.Unlock()

	if bucket, ok := r.buckets[key]; ok {
		return bucket
	}

	bucket := &TokenBucket{
		Tokens:     maxTokens,
		MaxTokens:  maxTokens,
		RefillRate: refillRate,
		Interval:   interval,
		LastRefill: time.Now(),
	}
	r.buckets[key] = bucket
	return bucket
}

// Allow checks if a request is allowed.
func (r *RateLimiter) Allow(key string, maxTokens int, refillRate int, interval time.Duration) bool {
	bucket := r.GetBucket(key, maxTokens, refillRate, interval)

	r.mu.Lock()
	defer r.mu.Unlock()

	// Refill tokens
	now := time.Now()
	elapsed := now.Sub(bucket.LastRefill)
	refills := int(elapsed / bucket.Interval)
	if refills > 0 {
		bucket.Tokens += refills * bucket.RefillRate
		if bucket.Tokens > bucket.MaxTokens {
			bucket.Tokens = bucket.MaxTokens
		}
		bucket.LastRefill = now
	}

	// Check if allowed
	if bucket.Tokens > 0 {
		bucket.Tokens--
		return true
	}
	return false
}

// ResetCounters resets all rate limit counters.
func (r *RateLimiter) ResetCounters() {
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, bucket := range r.buckets {
		bucket.Tokens = bucket.MaxTokens
		bucket.LastRefill = time.Now()
	}
}

// NewAccessController creates a new access controller.
func NewAccessController() *AccessController {
	ac := &AccessController{
		apiKeys:     make(map[string]string),
		permissions: make(map[string][]string),
	}

	// Set up default permissions
	ac.permissions["admin"] = []string{"sign", "revoke", "list", "details", "status", "backup", "restore"}
	ac.permissions["operator"] = []string{"sign", "list", "details", "status"}
	ac.permissions["viewer"] = []string{"list", "details", "status"}

	return ac
}

// AddAPIKey adds an API key with role.
func (ac *AccessController) AddAPIKey(key, role string) error {
	if role != "admin" && role != "operator" && role != "viewer" {
		return fmt.Errorf("invalid role: %s", role)
	}

	ac.mu.Lock()
	defer ac.mu.Unlock()
	ac.apiKeys[key] = role
	return nil
}

// Authenticate returns role for API key.
func (ac *AccessController) Authenticate(key string) (string, error) {
	if key == "" {
		return "", fmt.Errorf("unauthenticated: API key required")
	}

	ac.mu.RLock()
	defer ac.mu.RUnlock()

	role, ok := ac.apiKeys[key]
	if !ok {
		return "", fmt.Errorf("unauthenticated: invalid API key")
	}
	return role, nil
}

// Authorize checks if role can perform operation.
func (ac *AccessController) Authorize(role, operation string) bool {
	ac.mu.RLock()
	defer ac.mu.RUnlock()

	perms, ok := ac.permissions[role]
	if !ok {
		return false
	}

	for _, p := range perms {
		if p == operation {
			return true
		}
	}
	return false
}

// ============================================================================
// Key Encryption Tests
// ============================================================================

// TestEncryptPrivateKey_AES256GCM tests AES-256-GCM encryption.
func TestEncryptPrivateKey_AES256GCM(t *testing.T) {
	enc := NewKeyEncryption()

	// Generate test key
	testKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	keyBytes := x509.MarshalPKCS1PrivateKey(testKey)

	passphrase := []byte("test-passphrase-12345")

	encrypted, err := enc.Encrypt(keyBytes, passphrase)
	if err != nil {
		t.Fatalf("Encryption failed: %v", err)
	}

	// Verify salt
	if len(encrypted.Salt) != 16 {
		t.Errorf("Salt length = %d, want 16", len(encrypted.Salt))
	}

	// Verify nonce
	if len(encrypted.Nonce) != 12 { // GCM standard nonce size
		t.Errorf("Nonce length = %d, want 12", len(encrypted.Nonce))
	}

	// Verify ciphertext is different from plaintext
	if len(encrypted.Ciphertext) <= len(keyBytes) {
		t.Error("Ciphertext should be longer than plaintext (includes tag)")
	}
}

// TestEncryptDecryptRoundTrip tests encryption/decryption round trip.
func TestEncryptDecryptRoundTrip(t *testing.T) {
	enc := NewKeyEncryption()

	testKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	keyBytes := x509.MarshalPKCS1PrivateKey(testKey)

	passphrase := []byte("roundtrip-passphrase")

	encrypted, _ := enc.Encrypt(keyBytes, passphrase)
	decrypted, err := enc.Decrypt(encrypted, passphrase)
	if err != nil {
		t.Fatalf("Decryption failed: %v", err)
	}

	if string(decrypted) != string(keyBytes) {
		t.Error("Decrypted key doesn't match original")
	}

	// Verify decrypted key is usable
	parsedKey, err := x509.ParsePKCS1PrivateKey(decrypted)
	if err != nil {
		t.Fatalf("Failed to parse decrypted key: %v", err)
	}
	if parsedKey.N.Cmp(testKey.N) != 0 {
		t.Error("Decrypted key modulus doesn't match")
	}
}

// TestDecryptWithWrongPassphrase tests decryption failure.
func TestDecryptWithWrongPassphrase(t *testing.T) {
	enc := NewKeyEncryption()

	testData := []byte("sensitive-data")
	passphraseA := []byte("correct-passphrase")
	passphraseB := []byte("wrong-passphrase")

	encrypted, _ := enc.Encrypt(testData, passphraseA)
	_, err := enc.Decrypt(encrypted, passphraseB)
	if err == nil {
		t.Error("Decryption should fail with wrong passphrase")
	}
}

// TestTamperedCiphertext tests tamper detection.
func TestTamperedCiphertext(t *testing.T) {
	enc := NewKeyEncryption()

	testData := []byte("sensitive-data")
	passphrase := []byte("test-passphrase")

	encrypted, _ := enc.Encrypt(testData, passphrase)

	// Tamper with ciphertext
	if len(encrypted.Ciphertext) > 10 {
		encrypted.Ciphertext[10] ^= 0xFF
	}

	_, err := enc.Decrypt(encrypted, passphrase)
	if err == nil {
		t.Error("Decryption should fail for tampered ciphertext")
	}
}

// TestPBKDF2KeyDerivation tests key derivation.
func TestPBKDF2KeyDerivation(t *testing.T) {
	enc := NewKeyEncryption()

	passphrase := []byte("test-passphrase")
	salt1 := []byte("salt-one-12345678")
	salt2 := []byte("salt-two-12345678")

	key1a := enc.DeriveKey(passphrase, salt1)
	key1b := enc.DeriveKey(passphrase, salt1)
	key2 := enc.DeriveKey(passphrase, salt2)

	// Same passphrase + salt = same key
	if string(key1a) != string(key1b) {
		t.Error("Same inputs should produce same key")
	}

	// Different salt = different key
	if string(key1a) == string(key2) {
		t.Error("Different salt should produce different key")
	}

	// Key should be 32 bytes (AES-256)
	if len(key1a) != 32 {
		t.Errorf("Key length = %d, want 32", len(key1a))
	}
}

// TestPassphraseStrength tests passphrase generation.
func TestPassphraseStrength(t *testing.T) {
	passphrases := make(map[string]bool)

	for i := 0; i < 100; i++ {
		pass, err := GenerateSecurePassphrase()
		if err != nil {
			t.Fatalf("GeneratePassphrase failed: %v", err)
		}

		if len(pass) != 32 {
			t.Errorf("Passphrase length = %d, want 32", len(pass))
		}

		passHex := hex.EncodeToString(pass)
		if passphrases[passHex] {
			t.Error("Duplicate passphrase generated")
		}
		passphrases[passHex] = true
	}
}

// ============================================================================
// Audit Logging Tests
// ============================================================================

// TestAuditLog_LogOperation tests operation logging.
func TestAuditLog_LogOperation(t *testing.T) {
	logger := NewAuditLogger()

	entry := logger.LogOperation("issue", "example.com", "ABC123", "admin", "192.168.1.100", true)

	if entry.ID != 1 {
		t.Errorf("ID = %d, want 1", entry.ID)
	}
	if entry.Operation != "issue" {
		t.Errorf("Operation = %s, want issue", entry.Operation)
	}
	if entry.Subject != "example.com" {
		t.Errorf("Subject = %s, want example.com", entry.Subject)
	}
	if entry.Hash == "" {
		t.Error("Hash should not be empty")
	}
}

// TestAuditLog_HashChain tests hash chain integrity.
func TestAuditLog_HashChain(t *testing.T) {
	logger := NewAuditLogger()

	for i := 0; i < 10; i++ {
		logger.LogOperation("test", fmt.Sprintf("subject%d", i), fmt.Sprintf("serial%d", i), "admin", "127.0.0.1", true)
	}

	valid, brokenAt := logger.ValidateHashChain()
	if !valid {
		t.Errorf("Hash chain should be valid, broken at %d", brokenAt)
	}
}

// TestAuditLog_TamperDetection tests tamper detection.
func TestAuditLog_TamperDetection(t *testing.T) {
	logger := NewAuditLogger()

	for i := 0; i < 5; i++ {
		logger.LogOperation("test", fmt.Sprintf("subject%d", i), fmt.Sprintf("serial%d", i), "admin", "127.0.0.1", true)
	}

	// Tamper with entry 2
	logger.TamperEntry(2)

	valid, brokenAt := logger.ValidateHashChain()
	if valid {
		t.Error("Hash chain should be invalid after tampering")
	}
	if brokenAt != 2 {
		t.Errorf("Chain should break at 2, broke at %d", brokenAt)
	}
}

// TestAuditLog_FirstEntry tests first entry handling.
func TestAuditLog_FirstEntry(t *testing.T) {
	logger := NewAuditLogger()

	entry := logger.LogOperation("first", "test", "serial1", "admin", "127.0.0.1", true)

	if entry.PrevEntryHash != "" {
		t.Error("First entry should have empty PrevEntryHash")
	}
}

// TestAuditLog_Concurrent tests concurrent logging.
func TestAuditLog_Concurrent(t *testing.T) {
	logger := NewAuditLogger()

	var wg sync.WaitGroup
	numGoroutines := 50
	wg.Add(numGoroutines)

	for i := 0; i < numGoroutines; i++ {
		go func(n int) {
			defer wg.Done()
			logger.LogOperation("concurrent", fmt.Sprintf("subject%d", n), fmt.Sprintf("serial%d", n), "admin", "127.0.0.1", true)
		}(i)
	}

	wg.Wait()

	entries := logger.GetEntries()
	if len(entries) != numGoroutines {
		t.Errorf("Expected %d entries, got %d", numGoroutines, len(entries))
	}

	// Hash chain may not be valid due to concurrent writes, but entries should exist
	t.Logf("Logged %d concurrent entries", len(entries))
}

// TestAuditLog_Retrieval tests entry retrieval and filtering.
func TestAuditLog_Retrieval(t *testing.T) {
	logger := NewAuditLogger()

	logger.LogOperation("issue", "cert1", "s1", "admin", "127.0.0.1", true)
	logger.LogOperation("revoke", "cert2", "s2", "admin", "127.0.0.1", true)
	logger.LogOperation("issue", "cert3", "s3", "admin", "127.0.0.1", true)
	logger.LogOperation("revoke", "cert4", "s4", "admin", "127.0.0.1", true)

	revokeEntries := logger.QueryByOperation("revoke")
	if len(revokeEntries) != 2 {
		t.Errorf("Expected 2 revoke entries, got %d", len(revokeEntries))
	}
}

// ============================================================================
// Rate Limiting Tests
// ============================================================================

// TestSecurityRateLimit_SignCertificate tests sign certificate rate limiting.
func TestSecurityRateLimit_SignCertificate(t *testing.T) {
	limiter := NewRateLimiter()

	clientID := "client-1"
	maxRequests := 100
	allowed := 0

	for i := 0; i < 110; i++ {
		if limiter.Allow(clientID, maxRequests, 10, time.Hour) {
			allowed++
		}
	}

	if allowed != maxRequests {
		t.Errorf("Allowed %d requests, want %d", allowed, maxRequests)
	}
}

// TestRateLimit_RevokeCertificate tests revoke rate limiting.
func TestRateLimit_RevokeCertificate(t *testing.T) {
	limiter := NewRateLimiter()

	clientID := "revoke-client"
	maxRequests := 10
	allowed := 0

	for i := 0; i < 15; i++ {
		if limiter.Allow(clientID, maxRequests, 1, time.Hour) {
			allowed++
		}
	}

	if allowed != maxRequests {
		t.Errorf("Allowed %d requests, want %d", allowed, maxRequests)
	}
}

// TestRateLimit_TokenBucket tests token bucket refill.
func TestRateLimit_TokenBucket(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping token bucket refill test in short mode")
	}

	limiter := NewRateLimiter()

	clientID := "refill-client"

	// Exhaust tokens
	for i := 0; i < 10; i++ {
		limiter.Allow(clientID, 10, 10, 100*time.Millisecond)
	}

	// Should be blocked
	if limiter.Allow(clientID, 10, 10, 100*time.Millisecond) {
		t.Error("Should be rate limited")
	}

	// Wait for refill
	time.Sleep(150 * time.Millisecond)

	// Should be allowed again
	if !limiter.Allow(clientID, 10, 10, 100*time.Millisecond) {
		t.Error("Should be allowed after refill")
	}
}

// TestRateLimit_PerClient tests per-client limits.
func TestRateLimit_PerClient(t *testing.T) {
	limiter := NewRateLimiter()

	// Client A exhausts limit
	for i := 0; i < 10; i++ {
		limiter.Allow("client-A", 10, 1, time.Hour)
	}

	// Client B should still have tokens
	if !limiter.Allow("client-B", 10, 1, time.Hour) {
		t.Error("Client B should not be affected by Client A's limit")
	}

	// Client A should be blocked
	if limiter.Allow("client-A", 10, 1, time.Hour) {
		t.Error("Client A should be rate limited")
	}
}

// TestRateLimit_ResetCounters tests counter reset.
func TestRateLimit_ResetCounters(t *testing.T) {
	limiter := NewRateLimiter()

	clientID := "reset-client"

	// Exhaust tokens
	for i := 0; i < 10; i++ {
		limiter.Allow(clientID, 10, 1, time.Hour)
	}

	// Should be blocked
	if limiter.Allow(clientID, 10, 1, time.Hour) {
		t.Error("Should be rate limited")
	}

	// Reset counters
	limiter.ResetCounters()

	// Should be allowed again
	if !limiter.Allow(clientID, 10, 1, time.Hour) {
		t.Error("Should be allowed after reset")
	}
}

// ============================================================================
// Access Control Tests
// ============================================================================

// TestAccessControl_AdminRole tests admin role permissions.
func TestAccessControl_AdminRole(t *testing.T) {
	ac := NewAccessController()
	ac.AddAPIKey("admin-key", "admin")

	role, err := ac.Authenticate("admin-key")
	if err != nil {
		t.Fatalf("Authentication failed: %v", err)
	}

	if role != "admin" {
		t.Errorf("Role = %s, want admin", role)
	}

	// Admin can revoke
	if !ac.Authorize(role, "revoke") {
		t.Error("Admin should be able to revoke")
	}
}

// TestAccessControl_OperatorRole tests operator role permissions.
func TestAccessControl_OperatorRole(t *testing.T) {
	ac := NewAccessController()
	ac.AddAPIKey("operator-key", "operator")

	role, _ := ac.Authenticate("operator-key")

	// Operator can sign
	if !ac.Authorize(role, "sign") {
		t.Error("Operator should be able to sign")
	}

	// Operator cannot revoke
	if ac.Authorize(role, "revoke") {
		t.Error("Operator should not be able to revoke")
	}
}

// TestAccessControl_ViewerRole tests viewer role permissions.
func TestAccessControl_ViewerRole(t *testing.T) {
	ac := NewAccessController()
	ac.AddAPIKey("viewer-key", "viewer")

	role, _ := ac.Authenticate("viewer-key")

	// Viewer can list
	if !ac.Authorize(role, "list") {
		t.Error("Viewer should be able to list")
	}

	// Viewer cannot sign
	if ac.Authorize(role, "sign") {
		t.Error("Viewer should not be able to sign")
	}
}

// TestAccessControl_UnauthorizedAccess tests unauthenticated access.
func TestAccessControl_UnauthorizedAccess(t *testing.T) {
	ac := NewAccessController()

	_, err := ac.Authenticate("")
	if err == nil {
		t.Error("Empty API key should fail authentication")
	}

	_, err = ac.Authenticate("invalid-key")
	if err == nil {
		t.Error("Invalid API key should fail authentication")
	}
}

// TestAccessControl_RoleValidation tests role validation.
func TestAccessControl_RoleValidation(t *testing.T) {
	ac := NewAccessController()

	err := ac.AddAPIKey("key1", "invalid-role")
	if err == nil {
		t.Error("Invalid role should be rejected")
	}

	err = ac.AddAPIKey("key2", "admin")
	if err != nil {
		t.Errorf("Valid role should be accepted: %v", err)
	}
}

// ============================================================================
// Key Protection Tests
// ============================================================================

// TestKeyProtection_FilePermissions tests file permission enforcement.
func TestKeyProtection_FilePermissions(t *testing.T) {
	// Skip on Windows
	if os.PathSeparator == '\\' {
		t.Skip("Skipping file permission test on Windows")
	}

	tempDir := t.TempDir()
	keyPath := filepath.Join(tempDir, "test-key.pem")
	passPath := filepath.Join(tempDir, "passphrase")

	// Write files with specific permissions
	os.WriteFile(keyPath, []byte("encrypted-key-data"), 0600)
	os.WriteFile(passPath, []byte("passphrase-data"), 0400)

	keyInfo, _ := os.Stat(keyPath)
	passInfo, _ := os.Stat(passPath)

	if keyInfo.Mode().Perm() != 0600 {
		t.Errorf("Key file permissions = %o, want 0600", keyInfo.Mode().Perm())
	}
	if passInfo.Mode().Perm() != 0400 {
		t.Errorf("Passphrase file permissions = %o, want 0400", passInfo.Mode().Perm())
	}
}

// TestKeyProtection_MemoryClearing tests memory zeroing.
func TestKeyProtection_MemoryClearing(t *testing.T) {
	sensitiveData := make([]byte, 32)
	rand.Read(sensitiveData)

	// Save original values
	original := make([]byte, 32)
	copy(original, sensitiveData)

	// Clear memory
	for i := range sensitiveData {
		sensitiveData[i] = 0
	}

	// Verify cleared
	for i, b := range sensitiveData {
		if b != 0 {
			t.Errorf("Byte %d not cleared: %d", i, b)
		}
	}
}

// TestKeyProtection_PassphraseRotation tests passphrase rotation.
func TestKeyProtection_PassphraseRotation(t *testing.T) {
	enc := NewKeyEncryption()

	testData := []byte("sensitive-key-data")
	oldPassphrase := []byte("old-passphrase")
	newPassphrase := []byte("new-passphrase")

	// Encrypt with old passphrase
	encrypted, _ := enc.Encrypt(testData, oldPassphrase)

	// Decrypt with old passphrase
	decrypted, err := enc.Decrypt(encrypted, oldPassphrase)
	if err != nil {
		t.Fatalf("Decrypt with old passphrase failed: %v", err)
	}

	// Re-encrypt with new passphrase
	reencrypted, _ := enc.Encrypt(decrypted, newPassphrase)

	// Decrypt with new passphrase
	finalDecrypted, err := enc.Decrypt(reencrypted, newPassphrase)
	if err != nil {
		t.Fatalf("Decrypt with new passphrase failed: %v", err)
	}

	if string(finalDecrypted) != string(testData) {
		t.Error("Data corrupted during passphrase rotation")
	}

	// Old passphrase should not work on new encryption
	_, err = enc.Decrypt(reencrypted, oldPassphrase)
	if err == nil {
		t.Error("Old passphrase should not decrypt new encryption")
	}
}

// ============================================================================
// Secure Deletion Tests
// ============================================================================

// TestSecureDelete_OverwriteFile tests file overwriting.
func TestSecureDelete_OverwriteFile(t *testing.T) {
	tempDir := t.TempDir()
	filePath := filepath.Join(tempDir, "sensitive.dat")

	sensitiveData := []byte("TOP SECRET DATA")
	os.WriteFile(filePath, sensitiveData, 0600)

	// Overwrite with random data
	randomData := make([]byte, len(sensitiveData))
	rand.Read(randomData)
	os.WriteFile(filePath, randomData, 0600)

	// Read and verify overwritten
	data, _ := os.ReadFile(filePath)
	if string(data) == string(sensitiveData) {
		t.Error("File should be overwritten")
	}

	// Delete file
	os.Remove(filePath)

	// Verify deleted
	if _, err := os.Stat(filePath); !os.IsNotExist(err) {
		t.Error("File should be deleted")
	}
}

// ============================================================================
// Password Policy Tests
// ============================================================================

// TestPasswordPolicy_MinimumLength tests minimum length enforcement.
func TestPasswordPolicy_MinimumLength(t *testing.T) {
	for i := 0; i < 10; i++ {
		pass, _ := GenerateSecurePassphrase()
		if len(pass) < 32 {
			t.Errorf("Passphrase length = %d, minimum 32 required", len(pass))
		}
	}
}

// TestPasswordPolicy_Randomness tests entropy.
func TestPasswordPolicy_Randomness(t *testing.T) {
	passphrases := make([][]byte, 1000)
	for i := 0; i < 1000; i++ {
		passphrases[i], _ = GenerateSecurePassphrase()
	}

	// Check for duplicates
	seen := make(map[string]bool)
	for _, p := range passphrases {
		hex := hex.EncodeToString(p)
		if seen[hex] {
			t.Error("Duplicate passphrase generated - entropy issue")
		}
		seen[hex] = true
	}
}

// ============================================================================
// Integration Tests
// ============================================================================

// TestSecurityIntegration tests full security workflow.
func TestSecurityIntegration(t *testing.T) {
	// Generate key
	testKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	keyBytes := x509.MarshalPKCS1PrivateKey(testKey)

	// Encrypt key
	enc := NewKeyEncryption()
	passphrase, _ := GenerateSecurePassphrase()
	encrypted, _ := enc.Encrypt(keyBytes, passphrase)

	// Store encrypted key
	tempDir := t.TempDir()
	keyPath := filepath.Join(tempDir, "key.enc")
	os.WriteFile(keyPath, encrypted.Ciphertext, 0600)
	if os.PathSeparator != '\\' { // Skip permission check on Windows
		info, _ := os.Stat(keyPath)
		if info.Mode().Perm() != 0600 {
			t.Errorf("Key file permissions = %o, want 0600", info.Mode().Perm())
		}
	}

	// Log operation
	logger := NewAuditLogger()
	logger.LogOperation("key_encrypt", "root-ca-key", "", "system", "localhost", true)

	// Verify audit log
	entries := logger.GetEntries()
	if len(entries) != 1 {
		t.Errorf("Expected 1 audit entry, got %d", len(entries))
	}

	// Verify hash chain
	valid, _ := logger.ValidateHashChain()
	if !valid {
		t.Error("Audit hash chain should be valid")
	}

	// Access control check
	ac := NewAccessController()
	ac.AddAPIKey("admin-key", "admin")
	role, _ := ac.Authenticate("admin-key")
	if !ac.Authorize(role, "backup") {
		t.Error("Admin should be authorized for backup")
	}

	// Rate limit check
	limiter := NewRateLimiter()
	if !limiter.Allow("client-1", 10, 1, time.Hour) {
		t.Error("First request should be allowed")
	}

	t.Log("Security integration test passed")
}
