package revocation

import (
	"crypto"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/pem"
	"errors"
	"fmt"
	"log"
	"math/big"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"time"
)

// ============================================================================
// Errors
// ============================================================================

var (
	ErrCRLGenerationFailed = errors.New("CRL generation failed")
	ErrCANotLoaded         = errors.New("CA certificate or key not loaded")
	ErrCRLValidationFailed = errors.New("CRL validation failed")
)

// OID for CRL Reason extension (2.5.29.21)
var oidCRLReason = asn1.ObjectIdentifier{2, 5, 29, 21}

// ============================================================================
// Configuration
// ============================================================================

// CRLGeneratorConfig configures the CRL generator.
type CRLGeneratorConfig struct {
	UpdateInterval time.Duration // How often to regenerate CRL
	ValidityPeriod time.Duration // CRL validity (NextUpdate - ThisUpdate)
	CRLFilePath    string        // Path to write CRL file
	CRLNumberFile  string        // Path to persist CRL number
	Enabled        bool          // Enable CRL generation
	ServerAddress  string        // HTTP server address for CRL URL
}

// DefaultCRLGeneratorConfig returns default configuration.
func DefaultCRLGeneratorConfig() *CRLGeneratorConfig {
	return &CRLGeneratorConfig{
		UpdateInterval: 24 * time.Hour,
		ValidityPeriod: 24 * time.Hour,
		CRLFilePath:    "/var/safeops/ca/crl.pem",
		CRLNumberFile:  "/var/safeops/ca/crl_number",
		Enabled:        true,
		ServerAddress:  "http://192.168.1.1",
	}
}

// ============================================================================
// CRL Generator
// ============================================================================

// CRLGenerator generates and manages Certificate Revocation Lists.
type CRLGenerator struct {
	config  *CRLGeneratorConfig
	storage *RevocationStorage
	caCert  *x509.Certificate
	caKey   crypto.PrivateKey

	// CRL number management
	crlNumberMu sync.Mutex
	crlNumber   int64

	// Scheduler
	stopCh chan struct{}
	wg     sync.WaitGroup

	// Statistics
	generationCount int64
	lastGenerated   time.Time
	lastCRLSize     int64
}

// NewCRLGenerator creates a new CRL generator.
func NewCRLGenerator(config *CRLGeneratorConfig, storage *RevocationStorage) *CRLGenerator {
	if config == nil {
		config = DefaultCRLGeneratorConfig()
	}

	return &CRLGenerator{
		config:  config,
		storage: storage,
		stopCh:  make(chan struct{}),
	}
}

// SetCA sets the CA certificate and private key for signing.
func (g *CRLGenerator) SetCA(cert *x509.Certificate, key crypto.PrivateKey) {
	g.caCert = cert
	g.caKey = key
}

// ============================================================================
// CRL Generation
// ============================================================================

// GenerateCRL generates a new CRL with all revoked certificates.
func (g *CRLGenerator) GenerateCRL() ([]byte, error) {
	if g.caCert == nil || g.caKey == nil {
		return nil, ErrCANotLoaded
	}

	// Get all revoked certificates
	revokedCerts, err := g.buildRevokedCertificatesList()
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrCRLGenerationFailed, err)
	}

	// Get next CRL number
	crlNumber := g.getNextCRLNumber()

	// Build CRL template
	now := time.Now()
	template := &x509.RevocationList{
		SignatureAlgorithm:  x509.SHA256WithRSA,
		Number:              big.NewInt(crlNumber),
		ThisUpdate:          now,
		NextUpdate:          now.Add(g.config.ValidityPeriod),
		RevokedCertificates: revokedCerts,
	}

	// Sign CRL - caKey must implement crypto.Signer
	signer, ok := g.caKey.(crypto.Signer)
	if !ok {
		return nil, fmt.Errorf("%w: CA key does not implement crypto.Signer", ErrCRLGenerationFailed)
	}

	crlDER, err := x509.CreateRevocationList(rand.Reader, template, g.caCert, signer)
	if err != nil {
		return nil, fmt.Errorf("%w: signing failed: %v", ErrCRLGenerationFailed, err)
	}

	// Update statistics
	atomic.AddInt64(&g.generationCount, 1)
	g.lastGenerated = now
	g.lastCRLSize = int64(len(crlDER))

	log.Printf("[crl] Generated CRL #%d with %d revoked certificates (%d bytes)",
		crlNumber, len(revokedCerts), len(crlDER))

	return crlDER, nil
}

// GenerateCRLPEM generates a PEM-encoded CRL.
func (g *CRLGenerator) GenerateCRLPEM() ([]byte, error) {
	crlDER, err := g.GenerateCRL()
	if err != nil {
		return nil, err
	}

	return pem.EncodeToMemory(&pem.Block{
		Type:  "X509 CRL",
		Bytes: crlDER,
	}), nil
}

// buildRevokedCertificatesList builds the list of revoked certificate entries.
func (g *CRLGenerator) buildRevokedCertificatesList() ([]pkix.RevokedCertificate, error) {
	if g.storage == nil {
		return []pkix.RevokedCertificate{}, nil
	}

	entries := g.storage.GetAllRevocations()
	revokedCerts := make([]pkix.RevokedCertificate, 0, len(entries))

	for _, entry := range entries {
		// Parse serial number from hex string
		serialBigInt := new(big.Int)
		serialBigInt.SetString(entry.SerialNumber, 16)

		// Encode reason code
		reasonExt, err := encodeReasonExtension(GetReasonCode(string(entry.Reason)))
		if err != nil {
			log.Printf("[crl] Warning: failed to encode reason for %s: %v", entry.SerialNumber, err)
			continue
		}

		revokedCert := pkix.RevokedCertificate{
			SerialNumber:   serialBigInt,
			RevocationTime: entry.RevokedAt,
			Extensions: []pkix.Extension{
				{
					Id:    oidCRLReason,
					Value: reasonExt,
				},
			},
		}

		revokedCerts = append(revokedCerts, revokedCert)
	}

	return revokedCerts, nil
}

// encodeReasonExtension encodes a CRL reason code as DER.
func encodeReasonExtension(code int) ([]byte, error) {
	// CRL reason is encoded as an ENUMERATED type
	return asn1.Marshal(asn1.Enumerated(code))
}

// ============================================================================
// CRL Number Management
// ============================================================================

// getNextCRLNumber returns and increments the CRL number.
func (g *CRLGenerator) getNextCRLNumber() int64 {
	g.crlNumberMu.Lock()
	defer g.crlNumberMu.Unlock()

	g.crlNumber++

	// Persist to file (best effort)
	g.persistCRLNumber()

	return g.crlNumber
}

// LoadCRLNumber loads the CRL number from persistent storage.
func (g *CRLGenerator) LoadCRLNumber() error {
	g.crlNumberMu.Lock()
	defer g.crlNumberMu.Unlock()

	data, err := os.ReadFile(g.config.CRLNumberFile)
	if err != nil {
		if os.IsNotExist(err) {
			g.crlNumber = 0
			return nil
		}
		return err
	}

	_, err = fmt.Sscanf(string(data), "%d", &g.crlNumber)
	return err
}

// persistCRLNumber saves the CRL number to file.
func (g *CRLGenerator) persistCRLNumber() {
	if g.config.CRLNumberFile == "" {
		return
	}

	// Ensure directory exists
	dir := filepath.Dir(g.config.CRLNumberFile)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return
	}

	data := fmt.Sprintf("%d", g.crlNumber)
	_ = os.WriteFile(g.config.CRLNumberFile, []byte(data), 0644)
}

// ============================================================================
// File Writing
// ============================================================================

// WriteCRLToFile writes the CRL to the configured file path.
func (g *CRLGenerator) WriteCRLToFile() error {
	crlPEM, err := g.GenerateCRLPEM()
	if err != nil {
		return err
	}

	return g.WriteCRLPEMToFile(crlPEM, g.config.CRLFilePath)
}

// WriteCRLPEMToFile writes PEM-encoded CRL to a file atomically.
func (g *CRLGenerator) WriteCRLPEMToFile(crlPEM []byte, filePath string) error {
	// Ensure directory exists
	dir := filepath.Dir(filePath)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return fmt.Errorf("failed to create directory: %w", err)
	}

	// Write to temporary file
	tmpPath := filePath + ".tmp"
	if err := os.WriteFile(tmpPath, crlPEM, 0644); err != nil {
		return fmt.Errorf("failed to write temp file: %w", err)
	}

	// Atomic rename
	if err := os.Rename(tmpPath, filePath); err != nil {
		os.Remove(tmpPath)
		return fmt.Errorf("failed to rename file: %w", err)
	}

	log.Printf("[crl] CRL written to %s (%d bytes)", filePath, len(crlPEM))
	return nil
}

// ============================================================================
// Scheduler
// ============================================================================

// Start starts the CRL generation scheduler.
func (g *CRLGenerator) Start() error {
	if !g.config.Enabled {
		return nil
	}

	// Load CRL number
	if err := g.LoadCRLNumber(); err != nil {
		log.Printf("[crl] Warning: failed to load CRL number: %v", err)
	}

	// Generate initial CRL
	if err := g.WriteCRLToFile(); err != nil {
		log.Printf("[crl] Warning: initial CRL generation failed: %v", err)
	}

	// Start scheduler
	g.wg.Add(1)
	go g.schedulerLoop()

	return nil
}

// Stop stops the scheduler.
func (g *CRLGenerator) Stop() {
	close(g.stopCh)
	g.wg.Wait()
}

// schedulerLoop runs the periodic CRL generation.
func (g *CRLGenerator) schedulerLoop() {
	defer g.wg.Done()

	ticker := time.NewTicker(g.config.UpdateInterval)
	defer ticker.Stop()

	for {
		select {
		case <-g.stopCh:
			return
		case <-ticker.C:
			if err := g.WriteCRLToFile(); err != nil {
				log.Printf("[crl] Scheduled CRL generation failed: %v", err)
			}
		}
	}
}

// TriggerUpdate manually triggers CRL regeneration.
func (g *CRLGenerator) TriggerUpdate() error {
	return g.WriteCRLToFile()
}

// ============================================================================
// Validation
// ============================================================================

// ValidateCRL validates a CRL against the CA certificate.
func (g *CRLGenerator) ValidateCRL(crlDER []byte) error {
	if g.caCert == nil {
		return ErrCANotLoaded
	}

	// Parse CRL
	crl, err := x509.ParseRevocationList(crlDER)
	if err != nil {
		return fmt.Errorf("%w: parse error: %v", ErrCRLValidationFailed, err)
	}

	// Verify signature
	if err := crl.CheckSignatureFrom(g.caCert); err != nil {
		return fmt.Errorf("%w: signature invalid: %v", ErrCRLValidationFailed, err)
	}

	// Check timestamps
	now := time.Now()
	if crl.ThisUpdate.After(now) {
		return fmt.Errorf("%w: ThisUpdate is in the future", ErrCRLValidationFailed)
	}
	if crl.NextUpdate.Before(now) {
		return fmt.Errorf("%w: CRL has expired (NextUpdate: %s)", ErrCRLValidationFailed, crl.NextUpdate)
	}

	return nil
}

// ============================================================================
// Statistics and Info
// ============================================================================

// CRLStats contains CRL generation statistics.
type CRLStats struct {
	GenerationCount  int64     `json:"generation_count"`
	LastGenerated    time.Time `json:"last_generated"`
	LastCRLSize      int64     `json:"last_crl_size_bytes"`
	CurrentCRLNumber int64     `json:"current_crl_number"`
	RevokedCount     int       `json:"revoked_count"`
}

// GetStats returns CRL generation statistics.
func (g *CRLGenerator) GetStats() *CRLStats {
	g.crlNumberMu.Lock()
	crlNumber := g.crlNumber
	g.crlNumberMu.Unlock()

	revokedCount := 0
	if g.storage != nil {
		revokedCount = g.storage.Count()
	}

	return &CRLStats{
		GenerationCount:  atomic.LoadInt64(&g.generationCount),
		LastGenerated:    g.lastGenerated,
		LastCRLSize:      atomic.LoadInt64(&g.lastCRLSize),
		CurrentCRLNumber: crlNumber,
		RevokedCount:     revokedCount,
	}
}

// GetCRLDistributionPointURL returns the CRL distribution point URL.
func (g *CRLGenerator) GetCRLDistributionPointURL() string {
	return g.config.ServerAddress + "/crl.pem"
}

// GetCRLFilePath returns the configured CRL file path.
func (g *CRLGenerator) GetCRLFilePath() string {
	return g.config.CRLFilePath
}
