// Package acme implements ACME protocol for Let's Encrypt certificate issuance.
package acme

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"net/http"
	"strings"
	"time"

	"certificate_manager/internal/generation"
	"certificate_manager/internal/storage"
	"certificate_manager/pkg/types"
)

// ============================================================================
// Constants
// ============================================================================

const (
	AccountStatusValid       = "valid"
	AccountStatusDeactivated = "deactivated"
	AccountStatusRevoked     = "revoked"

	// ACME endpoints
	EndpointNewAccount = "newAccount"
	EndpointNewNonce   = "newNonce"
	EndpointNewOrder   = "newOrder"
	EndpointKeyChange  = "keyChange"

	// Retry configuration
	MaxRetries     = 3
	RetryDelay     = 2 * time.Second
	RequestTimeout = 30 * time.Second
)

// ============================================================================
// Error Types
// ============================================================================

var (
	ErrAccountNotFound     = errors.New("ACME account not found")
	ErrAccountDeactivated  = errors.New("ACME account is deactivated")
	ErrRegistrationFailed  = errors.New("ACME registration failed")
	ErrInvalidEmail        = errors.New("invalid email address")
	ErrTermsNotAgreed      = errors.New("terms of service must be agreed")
	ErrEABRequired         = errors.New("external account binding required")
	ErrKeyGenerationFailed = errors.New("failed to generate account key")
)

// ============================================================================
// Account Manager Interface
// ============================================================================

// AccountManager handles ACME account operations
type AccountManager struct {
	config     types.AcmeConfig
	db         *storage.Database
	httpClient *http.Client
	directory  *Directory
}

// Directory contains ACME server endpoints
type Directory struct {
	NewNonce   string `json:"newNonce"`
	NewAccount string `json:"newAccount"`
	NewOrder   string `json:"newOrder"`
	NewAuthz   string `json:"newAuthz"`
	RevokeCert string `json:"revokeCert"`
	KeyChange  string `json:"keyChange"`
	Meta       struct {
		TermsOfService          string   `json:"termsOfService"`
		Website                 string   `json:"website"`
		CAAIdentities           []string `json:"caaIdentities"`
		ExternalAccountRequired bool     `json:"externalAccountRequired"`
	} `json:"meta"`
}

// NewAccountManager creates a new account manager
func NewAccountManager(config types.AcmeConfig, db *storage.Database) *AccountManager {
	return &AccountManager{
		config: config,
		db:     db,
		httpClient: &http.Client{
			Timeout: RequestTimeout,
		},
	}
}

// ============================================================================
// Account Structure
// ============================================================================

// Account represents an ACME account with Let's Encrypt
type Account struct {
	ID              int64
	URL             string
	PrivateKey      crypto.PrivateKey
	PrivateKeyPEM   string
	Email           string
	Contacts        []string
	Status          string
	TermsOfService  string
	TermsAgreedAt   time.Time
	DirectoryURL    string
	ExternalBinding *ExternalAccountBinding
	CreatedAt       time.Time
	LastUsedAt      time.Time
}

// ExternalAccountBinding contains EAB credentials
type ExternalAccountBinding struct {
	KeyID   string `json:"keyId"`
	MACKey  string `json:"macKey"`
	BoundAt time.Time
}

// ============================================================================
// Account Manager Public API
// ============================================================================

// GetOrCreateAccount retrieves existing account or creates new one
func (am *AccountManager) GetOrCreateAccount(ctx context.Context) (*Account, error) {
	// Try to get existing account
	account, err := am.GetAccount(ctx, am.config.Email)
	if err == nil && account != nil {
		// Validate account is still active
		if account.Status == AccountStatusValid {
			return account, nil
		}
	}

	// No valid account found, create new one
	return am.CreateAccount(ctx)
}

// CreateAccount registers a new account with Let's Encrypt
func (am *AccountManager) CreateAccount(ctx context.Context) (*Account, error) {
	// Validate email
	if err := am.validateEmail(am.config.Email); err != nil {
		return nil, err
	}

	// Verify terms are agreed
	if !am.config.TermsAgreed {
		return nil, ErrTermsNotAgreed
	}

	// Fetch directory
	if err := am.fetchDirectory(ctx); err != nil {
		return nil, fmt.Errorf("failed to fetch ACME directory: %w", err)
	}

	// Check if EAB is required
	if am.directory.Meta.ExternalAccountRequired {
		if am.config.EABKeyID == "" || am.config.EABMACKey == "" {
			return nil, ErrEABRequired
		}
	}

	// Generate account key
	keyInfo, err := generation.GeneratePrivateKey(am.config.KeyType)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrKeyGenerationFailed, err)
	}

	// Create account object
	account := &Account{
		PrivateKey:    keyInfo.Key,
		PrivateKeyPEM: keyInfo.PEM,
		Email:         am.config.Email,
		Contacts:      []string{"mailto:" + am.config.Email},
		Status:        AccountStatusValid,
		DirectoryURL:  am.config.DirectoryURL,
		CreatedAt:     time.Now(),
		LastUsedAt:    time.Now(),
	}

	// Build registration payload
	payload := map[string]interface{}{
		"termsOfServiceAgreed": true,
		"contact":              account.Contacts,
	}

	// Add EAB if configured
	if am.config.EABKeyID != "" && am.config.EABMACKey != "" {
		eab, err := am.createExternalAccountBinding(keyInfo.Key)
		if err != nil {
			return nil, fmt.Errorf("failed to create EAB: %w", err)
		}
		payload["externalAccountBinding"] = eab
		account.ExternalBinding = &ExternalAccountBinding{
			KeyID:   am.config.EABKeyID,
			MACKey:  am.config.EABMACKey,
			BoundAt: time.Now(),
		}
	}

	// Register with ACME server (simulated for now - actual HTTP call would go here)
	account.URL = am.generateAccountURL()
	account.TermsOfService = am.directory.Meta.TermsOfService
	account.TermsAgreedAt = time.Now()

	// Store account in database
	if am.db != nil {
		dbAccount := &types.AcmeAccount{
			Email:           account.Email,
			PrivateKeyPEM:   account.PrivateKeyPEM,
			DirectoryURL:    account.DirectoryURL,
			RegistrationURL: account.URL,
			Status:          types.AccountStatus(account.Status),
			TermsAgreed:     true,
			CreatedAt:       account.CreatedAt,
			UpdatedAt:       time.Now(),
		}

		id, err := am.db.StoreACMEAccount(ctx, dbAccount)
		if err != nil {
			return nil, fmt.Errorf("failed to store account: %w", err)
		}
		account.ID = id
	}

	return account, nil
}

// GetAccount retrieves an existing account from storage
func (am *AccountManager) GetAccount(ctx context.Context, email string) (*Account, error) {
	if am.db == nil {
		return nil, ErrAccountNotFound
	}

	dbAccount, err := am.db.GetACMEAccount(ctx, email)
	if err != nil {
		if errors.Is(err, storage.ErrNotFound) {
			return nil, ErrAccountNotFound
		}
		return nil, err
	}

	// Parse private key
	keyInfo, err := generation.DecodePrivateKeyFromPEM(dbAccount.PrivateKeyPEM)
	if err != nil {
		return nil, fmt.Errorf("failed to parse account key: %w", err)
	}

	account := &Account{
		ID:            dbAccount.ID,
		URL:           dbAccount.RegistrationURL,
		PrivateKey:    keyInfo.Key,
		PrivateKeyPEM: dbAccount.PrivateKeyPEM,
		Email:         dbAccount.Email,
		Contacts:      []string{"mailto:" + dbAccount.Email},
		Status:        string(dbAccount.Status),
		DirectoryURL:  dbAccount.DirectoryURL,
		TermsAgreedAt: dbAccount.CreatedAt, // Assuming agreed at creation
		CreatedAt:     dbAccount.CreatedAt,
		LastUsedAt:    dbAccount.UpdatedAt,
	}

	return account, nil
}

// UpdateAccount updates account contact information
func (am *AccountManager) UpdateAccount(ctx context.Context, account *Account, newEmail string) error {
	if err := am.validateEmail(newEmail); err != nil {
		return err
	}

	account.Email = newEmail
	account.Contacts = []string{"mailto:" + newEmail}
	account.LastUsedAt = time.Now()

	// Update in database would go here
	return nil
}

// DeactivateAccount permanently disables the account
func (am *AccountManager) DeactivateAccount(ctx context.Context, account *Account) error {
	account.Status = AccountStatusDeactivated
	account.LastUsedAt = time.Now()

	// ACME deactivation request would go here
	// Update database status would go here

	return nil
}

// ValidateAccount verifies account is still active with CA
func (am *AccountManager) ValidateAccount(ctx context.Context, account *Account) error {
	if account.Status != AccountStatusValid {
		return ErrAccountDeactivated
	}

	// Query ACME server for current status would go here
	account.LastUsedAt = time.Now()

	return nil
}

// ============================================================================
// Key Management
// ============================================================================

// RolloverKey rotates the account private key
func (am *AccountManager) RolloverKey(ctx context.Context, account *Account) error {
	// Generate new key
	newKeyInfo, err := generation.GeneratePrivateKey(am.config.KeyType)
	if err != nil {
		return fmt.Errorf("failed to generate new key: %w", err)
	}

	// ACME key change request would go here
	// For now, just update the account

	account.PrivateKey = newKeyInfo.Key
	account.PrivateKeyPEM = newKeyInfo.PEM
	account.LastUsedAt = time.Now()

	return nil
}

// GetAccountKey returns the account's private key for signing
func (am *AccountManager) GetAccountKey(account *Account) crypto.PrivateKey {
	return account.PrivateKey
}

// ============================================================================
// Directory Operations
// ============================================================================

// fetchDirectory retrieves ACME directory from server
func (am *AccountManager) fetchDirectory(ctx context.Context) error {
	if am.directory != nil {
		return nil // Already fetched
	}

	req, err := http.NewRequestWithContext(ctx, "GET", am.config.DirectoryURL, nil)
	if err != nil {
		return err
	}

	resp, err := am.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("directory request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("directory returned status %d", resp.StatusCode)
	}

	am.directory = &Directory{}
	if err := json.NewDecoder(resp.Body).Decode(am.directory); err != nil {
		return fmt.Errorf("failed to decode directory: %w", err)
	}

	return nil
}

// GetDirectory returns the ACME directory
func (am *AccountManager) GetDirectory() *Directory {
	return am.directory
}

// ============================================================================
// Contact Information Management
// ============================================================================

// validateEmail checks email format
func (am *AccountManager) validateEmail(email string) error {
	if email == "" {
		return ErrInvalidEmail
	}

	// Basic email format validation
	if !strings.Contains(email, "@") || !strings.Contains(email, ".") {
		return fmt.Errorf("%w: %s", ErrInvalidEmail, email)
	}

	// Check for valid characters
	for _, c := range email {
		if c == ' ' || c == '\t' || c == '\n' {
			return fmt.Errorf("%w: contains whitespace", ErrInvalidEmail)
		}
	}

	return nil
}

// FormatContacts formats emails as ACME contacts
func FormatContacts(emails []string) []string {
	contacts := make([]string, len(emails))
	for i, email := range emails {
		if !strings.HasPrefix(email, "mailto:") {
			contacts[i] = "mailto:" + email
		} else {
			contacts[i] = email
		}
	}
	return contacts
}

// ============================================================================
// External Account Binding (EAB)
// ============================================================================

// createExternalAccountBinding creates EAB for registration
func (am *AccountManager) createExternalAccountBinding(accountKey crypto.PrivateKey) (map[string]interface{}, error) {
	// Get public key JWK
	pubKeyJWK, err := am.publicKeyToJWK(accountKey)
	if err != nil {
		return nil, err
	}

	// Create protected header
	protected := map[string]interface{}{
		"alg": "HS256",
		"kid": am.config.EABKeyID,
		"url": am.directory.NewAccount,
	}

	protectedJSON, _ := json.Marshal(protected)
	protectedB64 := base64.RawURLEncoding.EncodeToString(protectedJSON)

	payloadJSON, _ := json.Marshal(pubKeyJWK)
	payloadB64 := base64.RawURLEncoding.EncodeToString(payloadJSON)

	// Create signature
	signatureInput := protectedB64 + "." + payloadB64
	macKey, err := base64.RawURLEncoding.DecodeString(am.config.EABMACKey)
	if err != nil {
		return nil, fmt.Errorf("invalid MAC key: %w", err)
	}

	h := sha256.New()
	h.Write([]byte(signatureInput))
	h.Write(macKey) // Simplified - actual HMAC would be used
	signature := base64.RawURLEncoding.EncodeToString(h.Sum(nil))

	return map[string]interface{}{
		"protected": protectedB64,
		"payload":   payloadB64,
		"signature": signature,
	}, nil
}

// publicKeyToJWK converts public key to JWK format
func (am *AccountManager) publicKeyToJWK(key crypto.PrivateKey) (map[string]interface{}, error) {
	switch k := key.(type) {
	case *rsa.PrivateKey:
		return map[string]interface{}{
			"kty": "RSA",
			"n":   base64.RawURLEncoding.EncodeToString(k.N.Bytes()),
			"e":   base64.RawURLEncoding.EncodeToString(big.NewInt(int64(k.E)).Bytes()),
		}, nil

	case *ecdsa.PrivateKey:
		return map[string]interface{}{
			"kty": "EC",
			"crv": k.Curve.Params().Name,
			"x":   base64.RawURLEncoding.EncodeToString(k.X.Bytes()),
			"y":   base64.RawURLEncoding.EncodeToString(k.Y.Bytes()),
		}, nil

	default:
		return nil, fmt.Errorf("unsupported key type: %T", key)
	}
}

// ============================================================================
// Helper Functions
// ============================================================================

// generateAccountURL creates a placeholder account URL (actual comes from ACME)
func (am *AccountManager) generateAccountURL() string {
	// In real implementation, this comes from ACME server response
	baseURL := strings.TrimSuffix(am.config.DirectoryURL, "/directory")
	return fmt.Sprintf("%s/acme/acct/%d", baseURL, time.Now().UnixNano())
}

// ============================================================================
// Account Status Tracking
// ============================================================================

// IsAccountValid returns true if account is usable
func IsAccountValid(account *Account) bool {
	return account != nil && account.Status == AccountStatusValid
}

// GetAccountStatus returns the current account status
func GetAccountStatus(account *Account) string {
	if account == nil {
		return "unknown"
	}
	return account.Status
}

// AccountNeedsReregistration checks if account needs to be recreated
func AccountNeedsReregistration(account *Account) bool {
	if account == nil {
		return true
	}
	return account.Status == AccountStatusDeactivated || account.Status == AccountStatusRevoked
}
