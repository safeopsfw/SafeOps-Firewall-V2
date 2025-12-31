//go:build !hsm
// +build !hsm

// Package hsm provides Hardware Security Module integration for CA key protection
// This is the stub implementation when HSM support is not compiled in
package hsm

import (
	"crypto"
	"errors"
)

// HSM-related errors
var (
	ErrHSMNotInitialized   = errors.New("HSM not initialized")
	ErrKeyNotFound         = errors.New("key not found in HSM")
	ErrInvalidKeyType      = errors.New("invalid key type")
	ErrHSMOperationFailed  = errors.New("HSM operation failed")
	ErrSessionNotAvailable = errors.New("no HSM session available")
	ErrPINRequired         = errors.New("HSM PIN required")
	ErrHSMNotEnabled       = errors.New("HSM support not compiled in (build with -tags hsm)")
)

// PKCS11Config contains PKCS#11 HSM configuration (stub)
type PKCS11Config struct {
	LibraryPath string
	SlotID      uint
	PIN         string
	Label       string
	KeyType     string
	KeySize     int
}

// DefaultPKCS11Config returns default configuration
func DefaultPKCS11Config() *PKCS11Config {
	return &PKCS11Config{}
}

// PKCS11Manager is a stub manager when HSM support is not compiled
type PKCS11Manager struct{}

// NewPKCS11Manager returns an error since HSM is not enabled
func NewPKCS11Manager(config *PKCS11Config) (*PKCS11Manager, error) {
	return nil, ErrHSMNotEnabled
}

// GenerateKeyPair is not available without HSM support
func (m *PKCS11Manager) GenerateKeyPair() (crypto.PublicKey, error) {
	return nil, ErrHSMNotEnabled
}

// FindKey is not available without HSM support
func (m *PKCS11Manager) FindKey(label string) error {
	return ErrHSMNotEnabled
}

// Sign is not available without HSM support
func (m *PKCS11Manager) Sign(data []byte) ([]byte, error) {
	return nil, ErrHSMNotEnabled
}

// SignWithRetry is not available without HSM support
func (m *PKCS11Manager) SignWithRetry(data []byte, attempts int) ([]byte, error) {
	return nil, ErrHSMNotEnabled
}

// HealthCheck is not available without HSM support
func (m *PKCS11Manager) HealthCheck() error {
	return ErrHSMNotEnabled
}

// GetStatistics returns empty stats when HSM is not enabled
func (m *PKCS11Manager) GetStatistics() map[string]interface{} {
	return map[string]interface{}{
		"enabled": false,
		"error":   "HSM support not compiled in",
	}
}

// Close is a no-op when HSM is not enabled
func (m *PKCS11Manager) Close() error {
	return nil
}

// NewSigner is not available without HSM support
func (m *PKCS11Manager) NewSigner(publicKey crypto.PublicKey) crypto.Signer {
	return nil
}
