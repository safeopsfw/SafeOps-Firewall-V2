//go:build hsm
// +build hsm

// Package hsm provides Hardware Security Module integration for CA key protection
package hsm

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/rsa"
	"errors"
	"fmt"
	"io"
	"log"
	"math/big"
	"sync"
	"time"

	"github.com/miekg/pkcs11"
)

// ============================================================================
// Errors
// ============================================================================

var (
	ErrHSMNotInitialized   = errors.New("HSM not initialized")
	ErrKeyNotFound         = errors.New("key not found in HSM")
	ErrInvalidKeyType      = errors.New("invalid key type")
	ErrHSMOperationFailed  = errors.New("HSM operation failed")
	ErrSessionNotAvailable = errors.New("no HSM session available")
	ErrPINRequired         = errors.New("HSM PIN required")
)

// ============================================================================
// Configuration
// ============================================================================

// PKCS11Config contains PKCS#11 HSM configuration
type PKCS11Config struct {
	LibraryPath string
	SlotID      uint
	PIN         string
	Label       string
	KeyType     string // "RSA" or "ECDSA"
	KeySize     int    // For RSA: 2048, 3072, 4096

	// Failover configuration
	BackupEnabled     bool
	BackupLibraryPath string
	BackupSlotID      uint
	BackupPIN         string

	// Performance tuning
	SessionPoolSize  int
	OperationTimeout time.Duration
	RetryAttempts    int
	RetryDelay       time.Duration
}

// DefaultPKCS11Config returns default configuration
func DefaultPKCS11Config() *PKCS11Config {
	return &PKCS11Config{
		LibraryPath:      "/usr/lib/softhsm/libsofthsm2.so",
		SlotID:           0,
		KeyType:          "RSA",
		KeySize:          4096,
		BackupEnabled:    false,
		SessionPoolSize:  10,
		OperationTimeout: 30 * time.Second,
		RetryAttempts:    3,
		RetryDelay:       1 * time.Second,
	}
}

// ============================================================================
// PKCS11 HSM Manager
// ============================================================================

// PKCS11Manager manages HSM operations via PKCS#11 interface
type PKCS11Manager struct {
	config  *PKCS11Config
	ctx     *pkcs11.Ctx
	session pkcs11.SessionHandle

	// Session pool for concurrent operations
	sessionPool chan pkcs11.SessionHandle
	poolMu      sync.Mutex

	// Backup HSM (for failover)
	backupCtx     *pkcs11.Ctx
	backupSession pkcs11.SessionHandle

	// Key handles
	privateKeyHandle pkcs11.ObjectHandle
	publicKeyHandle  pkcs11.ObjectHandle

	// Statistics
	operationCount int64
	failoverCount  int64
	errorCount     int64
	lastOperation  time.Time

	mu sync.RWMutex
}

// NewPKCS11Manager creates a new PKCS#11 HSM manager
func NewPKCS11Manager(config *PKCS11Config) (*PKCS11Manager, error) {
	if config == nil {
		config = DefaultPKCS11Config()
	}

	m := &PKCS11Manager{
		config:      config,
		sessionPool: make(chan pkcs11.SessionHandle, config.SessionPoolSize),
	}

	// Initialize primary HSM
	if err := m.initializePrimaryHSM(); err != nil {
		return nil, fmt.Errorf("failed to initialize primary HSM: %w", err)
	}

	// Initialize backup HSM if enabled
	if config.BackupEnabled {
		if err := m.initializeBackupHSM(); err != nil {
			log.Printf("[hsm] Warning: Failed to initialize backup HSM: %v", err)
			// Continue without backup
		} else {
			log.Printf("[hsm] Backup HSM initialized successfully")
		}
	}

	// Create session pool
	if err := m.createSessionPool(); err != nil {
		return nil, fmt.Errorf("failed to create session pool: %w", err)
	}

	log.Printf("[hsm] PKCS#11 HSM manager initialized successfully")
	return m, nil
}

// initializePrimaryHSM initializes the primary HSM
func (m *PKCS11Manager) initializePrimaryHSM() error {
	// Load PKCS#11 library
	ctx := pkcs11.New(m.config.LibraryPath)
	if ctx == nil {
		return errors.New("failed to load PKCS#11 library")
	}

	// Initialize library
	if err := ctx.Initialize(); err != nil {
		return fmt.Errorf("failed to initialize PKCS#11 library: %w", err)
	}

	// Open session
	session, err := ctx.OpenSession(m.config.SlotID, pkcs11.CKF_SERIAL_SESSION|pkcs11.CKF_RW_SESSION)
	if err != nil {
		ctx.Destroy()
		ctx.Finalize()
		return fmt.Errorf("failed to open HSM session: %w", err)
	}

	// Login
	if err := ctx.Login(session, pkcs11.CKU_USER, m.config.PIN); err != nil {
		ctx.CloseSession(session)
		ctx.Destroy()
		ctx.Finalize()
		return fmt.Errorf("failed to login to HSM: %w", err)
	}

	m.ctx = ctx
	m.session = session

	log.Printf("[hsm] Primary HSM initialized: Slot %d", m.config.SlotID)
	return nil
}

// initializeBackupHSM initializes the backup HSM
func (m *PKCS11Manager) initializeBackupHSM() error {
	ctx := pkcs11.New(m.config.BackupLibraryPath)
	if ctx == nil {
		return errors.New("failed to load backup PKCS#11 library")
	}

	if err := ctx.Initialize(); err != nil {
		return fmt.Errorf("failed to initialize backup PKCS#11 library: %w", err)
	}

	session, err := ctx.OpenSession(m.config.BackupSlotID, pkcs11.CKF_SERIAL_SESSION|pkcs11.CKF_RW_SESSION)
	if err != nil {
		ctx.Destroy()
		ctx.Finalize()
		return fmt.Errorf("failed to open backup HSM session: %w", err)
	}

	if err := ctx.Login(session, pkcs11.CKU_USER, m.config.BackupPIN); err != nil {
		ctx.CloseSession(session)
		ctx.Destroy()
		ctx.Finalize()
		return fmt.Errorf("failed to login to backup HSM: %w", err)
	}

	m.backupCtx = ctx
	m.backupSession = session

	log.Printf("[hsm] Backup HSM initialized: Slot %d", m.config.BackupSlotID)
	return nil
}

// createSessionPool creates a pool of HSM sessions for concurrent operations
func (m *PKCS11Manager) createSessionPool() error {
	for i := 0; i < m.config.SessionPoolSize; i++ {
		session, err := m.ctx.OpenSession(m.config.SlotID, pkcs11.CKF_SERIAL_SESSION|pkcs11.CKF_RW_SESSION)
		if err != nil {
			return fmt.Errorf("failed to create session %d: %w", i, err)
		}

		if err := m.ctx.Login(session, pkcs11.CKU_USER, m.config.PIN); err != nil {
			m.ctx.CloseSession(session)
			return fmt.Errorf("failed to login session %d: %w", i, err)
		}

		m.sessionPool <- session
	}

	log.Printf("[hsm] Created session pool with %d sessions", m.config.SessionPoolSize)
	return nil
}

// getSession retrieves a session from the pool
func (m *PKCS11Manager) getSession() (pkcs11.SessionHandle, error) {
	select {
	case session := <-m.sessionPool:
		return session, nil
	case <-time.After(m.config.OperationTimeout):
		return 0, ErrSessionNotAvailable
	}
}

// returnSession returns a session to the pool
func (m *PKCS11Manager) returnSession(session pkcs11.SessionHandle) {
	m.sessionPool <- session
}

// ============================================================================
// Key Management
// ============================================================================

// GenerateKeyPair generates a new key pair in the HSM
func (m *PKCS11Manager) GenerateKeyPair() (crypto.PublicKey, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	session, err := m.getSession()
	if err != nil {
		return nil, err
	}
	defer m.returnSession(session)

	var publicKey crypto.PublicKey

	switch m.config.KeyType {
	case "RSA":
		publicKey, err = m.generateRSAKeyPair(session)
	case "ECDSA":
		publicKey, err = m.generateECDSAKeyPair(session)
	default:
		return nil, ErrInvalidKeyType
	}

	if err != nil {
		return nil, fmt.Errorf("failed to generate key pair: %w", err)
	}

	log.Printf("[hsm] Generated %s key pair in HSM", m.config.KeyType)
	return publicKey, nil
}

// generateRSAKeyPair generates an RSA key pair in the HSM
func (m *PKCS11Manager) generateRSAKeyPair(session pkcs11.SessionHandle) (*rsa.PublicKey, error) {
	publicKeyTemplate := []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_CLASS, pkcs11.CKO_PUBLIC_KEY),
		pkcs11.NewAttribute(pkcs11.CKA_KEY_TYPE, pkcs11.CKK_RSA),
		pkcs11.NewAttribute(pkcs11.CKA_TOKEN, true),
		pkcs11.NewAttribute(pkcs11.CKA_LABEL, m.config.Label+" Public"),
		pkcs11.NewAttribute(pkcs11.CKA_ENCRYPT, true),
		pkcs11.NewAttribute(pkcs11.CKA_VERIFY, true),
		pkcs11.NewAttribute(pkcs11.CKA_MODULUS_BITS, m.config.KeySize),
		pkcs11.NewAttribute(pkcs11.CKA_PUBLIC_EXPONENT, []byte{0x01, 0x00, 0x01}), // 65537
	}

	privateKeyTemplate := []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_CLASS, pkcs11.CKO_PRIVATE_KEY),
		pkcs11.NewAttribute(pkcs11.CKA_KEY_TYPE, pkcs11.CKK_RSA),
		pkcs11.NewAttribute(pkcs11.CKA_TOKEN, true),
		pkcs11.NewAttribute(pkcs11.CKA_PRIVATE, true),
		pkcs11.NewAttribute(pkcs11.CKA_SENSITIVE, true),
		pkcs11.NewAttribute(pkcs11.CKA_EXTRACTABLE, false),
		pkcs11.NewAttribute(pkcs11.CKA_LABEL, m.config.Label+" Private"),
		pkcs11.NewAttribute(pkcs11.CKA_SIGN, true),
		pkcs11.NewAttribute(pkcs11.CKA_DECRYPT, true),
	}

	mechanism := []*pkcs11.Mechanism{
		pkcs11.NewMechanism(pkcs11.CKM_RSA_PKCS_KEY_PAIR_GEN, nil),
	}

	pubHandle, privHandle, err := m.ctx.GenerateKeyPair(
		session,
		mechanism,
		publicKeyTemplate,
		privateKeyTemplate,
	)

	if err != nil {
		return nil, fmt.Errorf("HSM key generation failed: %w", err)
	}

	m.publicKeyHandle = pubHandle
	m.privateKeyHandle = privHandle

	// Retrieve public key from HSM
	return m.retrieveRSAPublicKey(session, pubHandle)
}

// generateECDSAKeyPair generates an ECDSA key pair in the HSM
func (m *PKCS11Manager) generateECDSAKeyPair(session pkcs11.SessionHandle) (*ecdsa.PublicKey, error) {
	// ECDSA implementation would go here
	// Using P-256 curve by default
	return nil, errors.New("ECDSA key generation not yet implemented")
}

// retrieveRSAPublicKey retrieves the RSA public key from HSM
func (m *PKCS11Manager) retrieveRSAPublicKey(session pkcs11.SessionHandle, handle pkcs11.ObjectHandle) (*rsa.PublicKey, error) {
	attributes := []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_MODULUS, nil),
		pkcs11.NewAttribute(pkcs11.CKA_PUBLIC_EXPONENT, nil),
	}

	attrs, err := m.ctx.GetAttributeValue(session, handle, attributes)
	if err != nil {
		return nil, fmt.Errorf("failed to get public key attributes: %w", err)
	}

	modulus := attrs[0].Value
	exponent := attrs[1].Value

	// Convert exponent bytes to int
	var e int
	for _, b := range exponent {
		e = e*256 + int(b)
	}

	return &rsa.PublicKey{
		N: new(big.Int).SetBytes(modulus),
		E: e,
	}, nil
}

// FindKey finds an existing key in the HSM by label
func (m *PKCS11Manager) FindKey(label string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	session, err := m.getSession()
	if err != nil {
		return err
	}
	defer m.returnSession(session)

	// Search for private key
	template := []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_CLASS, pkcs11.CKO_PRIVATE_KEY),
		pkcs11.NewAttribute(pkcs11.CKA_LABEL, label+" Private"),
	}

	if err := m.ctx.FindObjectsInit(session, template); err != nil {
		return fmt.Errorf("failed to init find objects: %w", err)
	}
	defer m.ctx.FindObjectsFinal(session)

	handles, _, err := m.ctx.FindObjects(session, 1)
	if err != nil {
		return fmt.Errorf("failed to find objects: %w", err)
	}

	if len(handles) == 0 {
		return ErrKeyNotFound
	}

	m.privateKeyHandle = handles[0]

	// Search for public key
	pubTemplate := []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_CLASS, pkcs11.CKO_PUBLIC_KEY),
		pkcs11.NewAttribute(pkcs11.CKA_LABEL, label+" Public"),
	}

	if err := m.ctx.FindObjectsInit(session, pubTemplate); err != nil {
		return fmt.Errorf("failed to init find public key: %w", err)
	}
	defer m.ctx.FindObjectsFinal(session)

	pubHandles, _, err := m.ctx.FindObjects(session, 1)
	if err != nil {
		return fmt.Errorf("failed to find public key: %w", err)
	}

	if len(pubHandles) == 0 {
		return errors.New("public key not found")
	}

	m.publicKeyHandle = pubHandles[0]

	log.Printf("[hsm] Found key in HSM: %s", label)
	return nil
}

// ============================================================================
// Signing Operations
// ============================================================================

// Sign signs data using the private key in the HSM
func (m *PKCS11Manager) Sign(data []byte) ([]byte, error) {
	return m.SignWithRetry(data, m.config.RetryAttempts)
}

// SignWithRetry signs data with retry logic
func (m *PKCS11Manager) SignWithRetry(data []byte, attempts int) ([]byte, error) {
	var lastErr error

	for i := 0; i < attempts; i++ {
		signature, err := m.signAttempt(data)
		if err == nil {
			m.operationCount++
			m.lastOperation = time.Now()
			return signature, nil
		}

		lastErr = err
		log.Printf("[hsm] Sign attempt %d failed: %v", i+1, err)

		if i < attempts-1 {
			time.Sleep(m.config.RetryDelay)
		}
	}

	// Try backup HSM if available
	if m.config.BackupEnabled && m.backupCtx != nil {
		log.Printf("[hsm] Trying backup HSM after %d failed attempts", attempts)
		signature, err := m.signWithBackup(data)
		if err == nil {
			m.failoverCount++
			return signature, nil
		}
		log.Printf("[hsm] Backup HSM also failed: %v", err)
	}

	m.errorCount++
	return nil, fmt.Errorf("sign failed after %d attempts: %w", attempts, lastErr)
}

// signAttempt performs a single sign attempt
func (m *PKCS11Manager) signAttempt(data []byte) ([]byte, error) {
	session, err := m.getSession()
	if err != nil {
		return nil, err
	}
	defer m.returnSession(session)

	// Initialize signing operation
	mechanism := []*pkcs11.Mechanism{
		pkcs11.NewMechanism(pkcs11.CKM_SHA256_RSA_PKCS, nil),
	}

	if err := m.ctx.SignInit(session, mechanism, m.privateKeyHandle); err != nil {
		return nil, fmt.Errorf("sign init failed: %w", err)
	}

	// Perform signing
	signature, err := m.ctx.Sign(session, data)
	if err != nil {
		return nil, fmt.Errorf("sign operation failed: %w", err)
	}

	return signature, nil
}

// signWithBackup signs using the backup HSM
func (m *PKCS11Manager) signWithBackup(data []byte) ([]byte, error) {
	mechanism := []*pkcs11.Mechanism{
		pkcs11.NewMechanism(pkcs11.CKM_SHA256_RSA_PKCS, nil),
	}

	if err := m.backupCtx.SignInit(m.backupSession, mechanism, m.privateKeyHandle); err != nil {
		return nil, fmt.Errorf("backup sign init failed: %w", err)
	}

	signature, err := m.backupCtx.Sign(m.backupSession, data)
	if err != nil {
		return nil, fmt.Errorf("backup sign operation failed: %w", err)
	}

	return signature, nil
}

// ============================================================================
// Health & Statistics
// ============================================================================

// HealthCheck performs HSM health check
func (m *PKCS11Manager) HealthCheck() error {
	m.mu.RLock()
	defer m.mu.RUnlock()

	if m.ctx == nil {
		return ErrHSMNotInitialized
	}

	// Try a test operation
	testData := []byte("health check")
	_, err := m.signAttempt(testData)
	if err != nil {
		return fmt.Errorf("HSM health check failed: %w", err)
	}

	return nil
}

// GetStatistics returns HSM operation statistics
func (m *PKCS11Manager) GetStatistics() map[string]interface{} {
	m.mu.RLock()
	defer m.mu.RUnlock()

	return map[string]interface{}{
		"operation_count":   m.operationCount,
		"failover_count":    m.failoverCount,
		"error_count":       m.errorCount,
		"last_operation":    m.lastOperation,
		"session_pool_size": m.config.SessionPoolSize,
		"backup_enabled":    m.config.BackupEnabled,
	}
}

// ============================================================================
// Cleanup
// ============================================================================

// Close closes the HSM connection and cleans up resources
func (m *PKCS11Manager) Close() error {
	m.mu.Lock()
	defer m.mu.Unlock()

	// Close session pool
	close(m.sessionPool)
	for session := range m.sessionPool {
		m.ctx.Logout(session)
		m.ctx.CloseSession(session)
	}

	// Close main session
	if m.session != 0 {
		m.ctx.Logout(m.session)
		m.ctx.CloseSession(m.session)
	}

	// Finalize and destroy primary HSM
	if m.ctx != nil {
		m.ctx.Finalize()
		m.ctx.Destroy()
	}

	// Close backup HSM
	if m.backupCtx != nil {
		if m.backupSession != 0 {
			m.backupCtx.Logout(m.backupSession)
			m.backupCtx.CloseSession(m.backupSession)
		}
		m.backupCtx.Finalize()
		m.backupCtx.Destroy()
	}

	log.Printf("[hsm] HSM connection closed")
	return nil
}

// ============================================================================
// HSM Signer (implements crypto.Signer)
// ============================================================================

// HSMSigner implements crypto.Signer interface for HSM-backed keys
type HSMSigner struct {
	manager   *PKCS11Manager
	publicKey crypto.PublicKey
}

// Public returns the public key
func (s *HSMSigner) Public() crypto.PublicKey {
	return s.publicKey
}

// Sign signs the digest using the HSM
func (s *HSMSigner) Sign(rand io.Reader, digest []byte, opts crypto.SignerOpts) ([]byte, error) {
	return s.manager.Sign(digest)
}

// NewHSMSigner creates a new HSM signer
func (m *PKCS11Manager) NewSigner(publicKey crypto.PublicKey) crypto.Signer {
	return &HSMSigner{
		manager:   m,
		publicKey: publicKey,
	}
}
