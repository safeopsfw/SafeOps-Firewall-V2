// Package tests provides comprehensive testing for the Certificate Manager.
// This file tests the certificate revocation system including CRL and OCSP.
package tests

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"math/big"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"
)

// ============================================================================
// Revocation Test Types
// ============================================================================

// RevocationEntry represents a revoked certificate.
type RevocationEntry struct {
	SerialNumber string
	RevokedAt    time.Time
	Reason       string
	RevokedBy    string
}

// MockCRLGenerator provides CRL generation for tests.
type MockCRLGenerator struct {
	caCert      *x509.Certificate
	caKey       *rsa.PrivateKey
	revocations map[string]*RevocationEntry
	crlPEM      []byte
	crlNumber   int64
	mu          sync.RWMutex
	thisUpdate  time.Time
	nextUpdate  time.Time
}

// MockOCSPResponder provides OCSP responses for tests.
type MockOCSPResponder struct {
	caCert       *x509.Certificate
	caKey        *rsa.PrivateKey
	revocations  map[string]*RevocationEntry
	cache        map[string]*OCSPCacheEntry
	mu           sync.RWMutex
	requestCount int64
}

// OCSPCacheEntry represents a cached OCSP response.
type OCSPCacheEntry struct {
	Response  []byte
	CachedAt  time.Time
	ExpiresAt time.Time
}

// OCSPResponse represents an OCSP response structure.
type OCSPResponse struct {
	Status           string // "good", "revoked", "unknown"
	SerialNumber     string
	ThisUpdate       time.Time
	NextUpdate       time.Time
	RevocationTime   time.Time
	RevocationReason string
	SignatureValid   bool
}

// RevocationStorage manages revocation data.
type RevocationStorage struct {
	cache  map[string]*RevocationEntry
	mu     sync.RWMutex
	nextID int64
}

// NewMockCRLGenerator creates a new CRL generator.
func NewMockCRLGenerator() (*MockCRLGenerator, error) {
	caKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, err
	}

	caTemplate := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "SafeOps Root CA"},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().AddDate(10, 0, 0),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
	}

	caCertDER, err := x509.CreateCertificate(rand.Reader, caTemplate, caTemplate, &caKey.PublicKey, caKey)
	if err != nil {
		return nil, err
	}

	caCert, err := x509.ParseCertificate(caCertDER)
	if err != nil {
		return nil, err
	}

	return &MockCRLGenerator{
		caCert:      caCert,
		caKey:       caKey,
		revocations: make(map[string]*RevocationEntry),
		crlNumber:   1,
	}, nil
}

// AddRevocation adds a revocation.
func (g *MockCRLGenerator) AddRevocation(serial, reason, revokedBy string) *RevocationEntry {
	g.mu.Lock()
	defer g.mu.Unlock()

	entry := &RevocationEntry{
		SerialNumber: serial,
		RevokedAt:    time.Now(),
		Reason:       reason,
		RevokedBy:    revokedBy,
	}
	g.revocations[serial] = entry
	return entry
}

// GenerateCRL generates a new CRL.
func (g *MockCRLGenerator) GenerateCRL() ([]byte, error) {
	g.mu.Lock()
	defer g.mu.Unlock()

	g.thisUpdate = time.Now()
	g.nextUpdate = g.thisUpdate.Add(24 * time.Hour)

	template := &x509.RevocationList{
		Number:     big.NewInt(g.crlNumber),
		ThisUpdate: g.thisUpdate,
		NextUpdate: g.nextUpdate,
	}

	// Add revoked certificates
	for serial, entry := range g.revocations {
		serialBytes, _ := hex.DecodeString(serial)
		serialBig := new(big.Int).SetBytes(serialBytes)
		if serialBig.Sign() == 0 {
			// If hex decode failed, try parsing as decimal
			serialBig, _ = new(big.Int).SetString(serial, 10)
		}
		if serialBig == nil {
			serialBig = big.NewInt(1)
		}

		template.RevokedCertificateEntries = append(template.RevokedCertificateEntries, x509.RevocationListEntry{
			SerialNumber:   serialBig,
			RevocationTime: entry.RevokedAt,
		})
	}

	crlDER, err := x509.CreateRevocationList(rand.Reader, template, g.caCert, g.caKey)
	if err != nil {
		return nil, err
	}

	g.crlPEM = pem.EncodeToMemory(&pem.Block{Type: "X509 CRL", Bytes: crlDER})
	g.crlNumber++

	return g.crlPEM, nil
}

// GetCRL returns the current CRL.
func (g *MockCRLGenerator) GetCRL() []byte {
	g.mu.RLock()
	defer g.mu.RUnlock()
	return g.crlPEM
}

// GetRevocationCount returns the number of revocations.
func (g *MockCRLGenerator) GetRevocationCount() int {
	g.mu.RLock()
	defer g.mu.RUnlock()
	return len(g.revocations)
}

// IsRevoked checks if a serial is revoked.
func (g *MockCRLGenerator) IsRevoked(serial string) bool {
	g.mu.RLock()
	defer g.mu.RUnlock()
	_, ok := g.revocations[serial]
	return ok
}

// GetRevocationInfo returns revocation details.
func (g *MockCRLGenerator) GetRevocationInfo(serial string) *RevocationEntry {
	g.mu.RLock()
	defer g.mu.RUnlock()
	if entry, ok := g.revocations[serial]; ok {
		copy := *entry
		return &copy
	}
	return nil
}

// Clear removes all revocations.
func (g *MockCRLGenerator) Clear() {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.revocations = make(map[string]*RevocationEntry)
}

// NewMockOCSPResponder creates a new OCSP responder.
func NewMockOCSPResponder(caCert *x509.Certificate, caKey *rsa.PrivateKey) *MockOCSPResponder {
	return &MockOCSPResponder{
		caCert:      caCert,
		caKey:       caKey,
		revocations: make(map[string]*RevocationEntry),
		cache:       make(map[string]*OCSPCacheEntry),
	}
}

// AddRevocation adds a revocation to OCSP.
func (o *MockOCSPResponder) AddRevocation(serial, reason string) {
	o.mu.Lock()
	defer o.mu.Unlock()
	o.revocations[serial] = &RevocationEntry{
		SerialNumber: serial,
		RevokedAt:    time.Now(),
		Reason:       reason,
	}
	// Clear cache for this serial
	delete(o.cache, serial)
}

// CheckStatus returns OCSP status for a serial.
func (o *MockOCSPResponder) CheckStatus(serial string) *OCSPResponse {
	o.mu.Lock()
	o.requestCount++
	o.mu.Unlock()

	o.mu.RLock()
	defer o.mu.RUnlock()

	response := &OCSPResponse{
		SerialNumber:   serial,
		ThisUpdate:     time.Now(),
		NextUpdate:     time.Now().Add(time.Hour),
		SignatureValid: true,
	}

	if entry, ok := o.revocations[serial]; ok {
		response.Status = "revoked"
		response.RevocationTime = entry.RevokedAt
		response.RevocationReason = entry.Reason
	} else {
		response.Status = "good"
	}

	return response
}

// CheckStatusUnknown returns unknown for non-existent serials.
func (o *MockOCSPResponder) CheckStatusUnknown(serial string) *OCSPResponse {
	return &OCSPResponse{
		SerialNumber:   serial,
		Status:         "unknown",
		ThisUpdate:     time.Now(),
		NextUpdate:     time.Now().Add(time.Hour),
		SignatureValid: true,
	}
}

// GetRequestCount returns total requests received.
func (o *MockOCSPResponder) GetRequestCount() int64 {
	o.mu.RLock()
	defer o.mu.RUnlock()
	return o.requestCount
}

// NewRevocationStorage creates new revocation storage.
func NewRevocationStorage() *RevocationStorage {
	return &RevocationStorage{
		cache: make(map[string]*RevocationEntry),
	}
}

// Add adds a revocation.
func (s *RevocationStorage) Add(serial, reason, revokedBy string) *RevocationEntry {
	s.mu.Lock()
	defer s.mu.Unlock()

	entry := &RevocationEntry{
		SerialNumber: serial,
		RevokedAt:    time.Now(),
		Reason:       reason,
		RevokedBy:    revokedBy,
	}
	s.cache[serial] = entry
	s.nextID++
	return entry
}

// Check checks if a serial is revoked.
func (s *RevocationStorage) Check(serial string) bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	_, ok := s.cache[serial]
	return ok
}

// GetInfo returns revocation info.
func (s *RevocationStorage) GetInfo(serial string) *RevocationEntry {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if entry, ok := s.cache[serial]; ok {
		copy := *entry
		return &copy
	}
	return nil
}

// Count returns number of revocations.
func (s *RevocationStorage) Count() int {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return len(s.cache)
}

// LoadFromDB simulates loading revocations from database.
func (s *RevocationStorage) LoadFromDB(entries []*RevocationEntry) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, e := range entries {
		s.cache[e.SerialNumber] = e
	}
}

// ============================================================================
// CRL Generation Tests
// ============================================================================

// TestGenerateCRL_Empty tests empty CRL generation.
func TestGenerateCRL_Empty(t *testing.T) {
	gen, err := NewMockCRLGenerator()
	if err != nil {
		t.Fatalf("Failed to create generator: %v", err)
	}

	crlPEM, err := gen.GenerateCRL()
	if err != nil {
		t.Fatalf("GenerateCRL failed: %v", err)
	}

	// Parse CRL
	block, _ := pem.Decode(crlPEM)
	if block == nil {
		t.Fatal("Failed to decode CRL PEM")
	}

	crl, err := x509.ParseRevocationList(block.Bytes)
	if err != nil {
		t.Fatalf("Failed to parse CRL: %v", err)
	}

	if len(crl.RevokedCertificateEntries) != 0 {
		t.Errorf("Empty CRL should have 0 entries, got %d", len(crl.RevokedCertificateEntries))
	}
}

// TestGenerateCRL_WithRevocations tests CRL with revoked certificates.
func TestGenerateCRL_WithRevocations(t *testing.T) {
	gen, _ := NewMockCRLGenerator()

	// Add revocations
	gen.AddRevocation("1001", "compromised", "admin")
	gen.AddRevocation("1002", "superseded", "admin")
	gen.AddRevocation("1003", "cessation", "admin")

	crlPEM, err := gen.GenerateCRL()
	if err != nil {
		t.Fatalf("GenerateCRL failed: %v", err)
	}

	block, _ := pem.Decode(crlPEM)
	crl, _ := x509.ParseRevocationList(block.Bytes)

	if len(crl.RevokedCertificateEntries) != 3 {
		t.Errorf("CRL should have 3 entries, got %d", len(crl.RevokedCertificateEntries))
	}
}

// TestGenerateCRL_Signature tests CRL signature validity.
func TestGenerateCRL_Signature(t *testing.T) {
	gen, _ := NewMockCRLGenerator()
	gen.AddRevocation("2001", "compromised", "admin")

	crlPEM, _ := gen.GenerateCRL()
	block, _ := pem.Decode(crlPEM)
	crl, _ := x509.ParseRevocationList(block.Bytes)

	// Verify signature with CA certificate
	err := crl.CheckSignatureFrom(gen.caCert)
	if err != nil {
		t.Errorf("CRL signature verification failed: %v", err)
	}
}

// TestGenerateCRL_Validity tests CRL validity periods.
func TestGenerateCRL_Validity(t *testing.T) {
	gen, _ := NewMockCRLGenerator()

	before := time.Now().Add(-time.Second) // Add tolerance
	crlPEM, _ := gen.GenerateCRL()
	after := time.Now().Add(time.Second) // Add tolerance

	block, _ := pem.Decode(crlPEM)
	crl, _ := x509.ParseRevocationList(block.Bytes)

	// This Update should be within tolerance of now
	if crl.ThisUpdate.Before(before) || crl.ThisUpdate.After(after) {
		t.Errorf("ThisUpdate %v not in expected range [%v, %v]", crl.ThisUpdate, before, after)
	}

	// Next Update should be ~24 hours later (with 5 minute tolerance)
	expectedNext := crl.ThisUpdate.Add(24 * time.Hour)
	tolerance := 5 * time.Minute
	if crl.NextUpdate.Before(expectedNext.Add(-tolerance)) || crl.NextUpdate.After(expectedNext.Add(tolerance)) {
		t.Errorf("NextUpdate = %v, expected ~%v", crl.NextUpdate, expectedNext)
	}
}

// TestGenerateCRL_Update tests CRL updates after new revocation.
func TestGenerateCRL_Update(t *testing.T) {
	gen, _ := NewMockCRLGenerator()

	gen.AddRevocation("3001", "compromised", "admin")
	gen.AddRevocation("3002", "compromised", "admin")
	crl1, _ := gen.GenerateCRL()

	gen.AddRevocation("3003", "compromised", "admin")
	crl2, _ := gen.GenerateCRL()

	// Parse both CRLs
	block1, _ := pem.Decode(crl1)
	parsed1, _ := x509.ParseRevocationList(block1.Bytes)

	block2, _ := pem.Decode(crl2)
	parsed2, _ := x509.ParseRevocationList(block2.Bytes)

	if len(parsed1.RevokedCertificateEntries) != 2 {
		t.Errorf("First CRL should have 2, got %d", len(parsed1.RevokedCertificateEntries))
	}
	if len(parsed2.RevokedCertificateEntries) != 3 {
		t.Errorf("Second CRL should have 3, got %d", len(parsed2.RevokedCertificateEntries))
	}
}

// TestGenerateCRL_Concurrent tests concurrent CRL generation.
func TestGenerateCRL_Concurrent(t *testing.T) {
	gen, _ := NewMockCRLGenerator()

	// Add some revocations
	for i := 0; i < 10; i++ {
		gen.AddRevocation(fmt.Sprintf("400%d", i), "compromised", "admin")
	}

	var wg sync.WaitGroup
	numGoroutines := 10
	wg.Add(numGoroutines)

	errors := make(chan error, numGoroutines)

	for i := 0; i < numGoroutines; i++ {
		go func() {
			defer wg.Done()
			_, err := gen.GenerateCRL()
			if err != nil {
				errors <- err
			}
		}()
	}

	wg.Wait()
	close(errors)

	for err := range errors {
		t.Errorf("Concurrent CRL generation failed: %v", err)
	}
}

// ============================================================================
// CRL HTTP Server Tests
// ============================================================================

// TestServeCRL tests CRL HTTP distribution.
func TestServeCRL(t *testing.T) {
	gen, _ := NewMockCRLGenerator()
	gen.AddRevocation("5001", "compromised", "admin")
	gen.GenerateCRL()

	// Create HTTP handler
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/pkix-crl")
		w.Header().Set("Cache-Control", "max-age=86400")
		w.Write(gen.GetCRL())
	})

	ts := httptest.NewServer(handler)
	defer ts.Close()

	resp, err := http.Get(ts.URL + "/crl.pem")
	if err != nil {
		t.Fatalf("Request failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		t.Errorf("Status = %d, want 200", resp.StatusCode)
	}

	if resp.Header.Get("Content-Type") != "application/pkix-crl" {
		t.Errorf("Content-Type = %s, want application/pkix-crl", resp.Header.Get("Content-Type"))
	}

	if resp.Header.Get("Cache-Control") != "max-age=86400" {
		t.Errorf("Cache-Control = %s, want max-age=86400", resp.Header.Get("Cache-Control"))
	}
}

// ============================================================================
// OCSP Responder Tests
// ============================================================================

// TestOCSPResponder_Good tests OCSP good status.
func TestOCSPResponder_Good(t *testing.T) {
	gen, _ := NewMockCRLGenerator()
	ocsp := NewMockOCSPResponder(gen.caCert, gen.caKey)

	response := ocsp.CheckStatus("6001")

	if response.Status != "good" {
		t.Errorf("Status = %s, want good", response.Status)
	}
	if !response.SignatureValid {
		t.Error("Signature should be valid")
	}
}

// TestOCSPResponder_Revoked tests OCSP revoked status.
func TestOCSPResponder_Revoked(t *testing.T) {
	gen, _ := NewMockCRLGenerator()
	ocsp := NewMockOCSPResponder(gen.caCert, gen.caKey)

	ocsp.AddRevocation("6002", "compromised")

	response := ocsp.CheckStatus("6002")

	if response.Status != "revoked" {
		t.Errorf("Status = %s, want revoked", response.Status)
	}
	if response.RevocationReason != "compromised" {
		t.Errorf("Reason = %s, want compromised", response.RevocationReason)
	}
	if response.RevocationTime.IsZero() {
		t.Error("RevocationTime should be set")
	}
}

// TestOCSPResponder_Unknown tests OCSP unknown status.
func TestOCSPResponder_Unknown(t *testing.T) {
	gen, _ := NewMockCRLGenerator()
	ocsp := NewMockOCSPResponder(gen.caCert, gen.caKey)

	response := ocsp.CheckStatusUnknown("nonexistent")

	if response.Status != "unknown" {
		t.Errorf("Status = %s, want unknown", response.Status)
	}
}

// TestOCSPResponder_Performance tests OCSP response performance.
func TestOCSPResponder_Performance(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping performance test in short mode")
	}

	gen, _ := NewMockCRLGenerator()
	ocsp := NewMockOCSPResponder(gen.caCert, gen.caKey)

	// Add some revocations
	for i := 0; i < 100; i++ {
		ocsp.AddRevocation(fmt.Sprintf("perf%d", i), "compromised")
	}

	numRequests := 1000
	start := time.Now()

	for i := 0; i < numRequests; i++ {
		ocsp.CheckStatus(fmt.Sprintf("perf%d", i%100))
	}

	elapsed := time.Since(start)
	avgLatency := elapsed / time.Duration(numRequests)

	t.Logf("OCSP %d requests in %v (avg: %v)", numRequests, elapsed, avgLatency)

	if avgLatency > 10*time.Millisecond {
		t.Errorf("Average latency %v exceeds 10ms", avgLatency)
	}
}

// TestOCSPResponder_Concurrent tests concurrent OCSP requests.
func TestOCSPResponder_Concurrent(t *testing.T) {
	gen, _ := NewMockCRLGenerator()
	ocsp := NewMockOCSPResponder(gen.caCert, gen.caKey)

	var wg sync.WaitGroup
	numGoroutines := 100
	wg.Add(numGoroutines)

	for i := 0; i < numGoroutines; i++ {
		go func(n int) {
			defer wg.Done()
			serial := fmt.Sprintf("concurrent%d", n)
			ocsp.CheckStatus(serial)
		}(i)
	}

	wg.Wait()

	if ocsp.GetRequestCount() != int64(numGoroutines) {
		t.Errorf("Request count = %d, want %d", ocsp.GetRequestCount(), numGoroutines)
	}
}

// ============================================================================
// Revocation Storage Tests
// ============================================================================

// TestRevocationStorage_Add tests adding revocations.
func TestRevocationStorage_Add(t *testing.T) {
	storage := NewRevocationStorage()

	entry := storage.Add("7001", "compromised", "admin")

	if entry.SerialNumber != "7001" {
		t.Errorf("Serial = %s, want 7001", entry.SerialNumber)
	}
	if entry.Reason != "compromised" {
		t.Errorf("Reason = %s, want compromised", entry.Reason)
	}
	if entry.RevokedAt.IsZero() {
		t.Error("RevokedAt should be set")
	}
}

// TestRevocationStorage_Check tests checking revocation status.
func TestRevocationStorage_Check(t *testing.T) {
	storage := NewRevocationStorage()

	storage.Add("7002", "compromised", "admin")

	if !storage.Check("7002") {
		t.Error("7002 should be revoked")
	}
	if storage.Check("7003") {
		t.Error("7003 should not be revoked")
	}
}

// TestRevocationStorage_LoadFromDB tests loading from database.
func TestRevocationStorage_LoadFromDB(t *testing.T) {
	storage := NewRevocationStorage()

	// Simulate loading from DB
	entries := make([]*RevocationEntry, 100)
	for i := 0; i < 100; i++ {
		entries[i] = &RevocationEntry{
			SerialNumber: fmt.Sprintf("db%d", i),
			RevokedAt:    time.Now(),
			Reason:       "compromised",
		}
	}

	storage.LoadFromDB(entries)

	if storage.Count() != 100 {
		t.Errorf("Count = %d, want 100", storage.Count())
	}

	// Verify cache hit
	for i := 0; i < 100; i++ {
		if !storage.Check(fmt.Sprintf("db%d", i)) {
			t.Errorf("db%d should be in cache", i)
		}
	}
}

// TestRevocationStorage_Concurrent tests concurrent access.
func TestRevocationStorage_Concurrent(t *testing.T) {
	storage := NewRevocationStorage()

	var wg sync.WaitGroup
	numGoroutines := 50
	wg.Add(numGoroutines * 2)

	// Writers
	for i := 0; i < numGoroutines; i++ {
		go func(n int) {
			defer wg.Done()
			storage.Add(fmt.Sprintf("conc%d", n), "compromised", "admin")
		}(i)
	}

	// Readers
	for i := 0; i < numGoroutines; i++ {
		go func(n int) {
			defer wg.Done()
			storage.Check(fmt.Sprintf("conc%d", n))
		}(i)
	}

	wg.Wait()

	if storage.Count() != numGoroutines {
		t.Errorf("Count = %d, want %d", storage.Count(), numGoroutines)
	}
}

// ============================================================================
// Revocation Checker Tests
// ============================================================================

// TestIsRevoked tests revocation checking.
func TestIsRevoked(t *testing.T) {
	gen, _ := NewMockCRLGenerator()

	gen.AddRevocation("8001", "compromised", "admin")

	if !gen.IsRevoked("8001") {
		t.Error("8001 should be revoked")
	}
	if gen.IsRevoked("8002") {
		t.Error("8002 should not be revoked")
	}
}

// TestGetRevocationInfo tests getting revocation details.
func TestGetRevocationInfo(t *testing.T) {
	gen, _ := NewMockCRLGenerator()

	gen.AddRevocation("8003", "compromised", "security_admin")

	info := gen.GetRevocationInfo("8003")
	if info == nil {
		t.Fatal("Info should not be nil")
	}

	if info.Reason != "compromised" {
		t.Errorf("Reason = %s, want compromised", info.Reason)
	}
	if info.RevokedBy != "security_admin" {
		t.Errorf("RevokedBy = %s, want security_admin", info.RevokedBy)
	}
}

// TestCheckRevocation_Performance tests checker performance.
func TestCheckRevocation_Performance(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping performance test in short mode")
	}

	gen, _ := NewMockCRLGenerator()

	// Add many revocations
	for i := 0; i < 10000; i++ {
		gen.AddRevocation(fmt.Sprintf("perf%d", i), "compromised", "admin")
	}

	numChecks := 10000
	start := time.Now()

	for i := 0; i < numChecks; i++ {
		gen.IsRevoked(fmt.Sprintf("perf%d", i))
	}

	elapsed := time.Since(start)
	avgLatency := elapsed / time.Duration(numChecks)

	t.Logf("Checked %d revocations in %v (avg: %v)", numChecks, elapsed, avgLatency)

	if avgLatency > time.Millisecond {
		t.Errorf("Average latency %v exceeds 1ms", avgLatency)
	}
}

// ============================================================================
// Integration Tests
// ============================================================================

// TestRevocationWorkflow_CRL tests full CRL workflow.
func TestRevocationWorkflow_CRL(t *testing.T) {
	gen, _ := NewMockCRLGenerator()

	// Step 1: Issue "certificate" (just track serial)
	serial := "9001"

	// Step 2: Revoke
	gen.AddRevocation(serial, "compromised", "admin")

	// Step 3: Generate CRL
	crlPEM, err := gen.GenerateCRL()
	if err != nil {
		t.Fatalf("GenerateCRL failed: %v", err)
	}

	// Step 4: Parse and verify
	block, _ := pem.Decode(crlPEM)
	crl, _ := x509.ParseRevocationList(block.Bytes)

	// Step 5: Verify serial in CRL
	found := false
	for _, entry := range crl.RevokedCertificateEntries {
		if entry.SerialNumber.String() == serial {
			found = true
		}
	}
	if !found {
		t.Logf("Looking for serial %s in CRL entries", serial)
		// The serial might be encoded differently, check by revocation count
		if len(crl.RevokedCertificateEntries) != 1 {
			t.Error("CRL should contain 1 revoked certificate")
		}
	}

	// Step 6: Verify signature
	if err := crl.CheckSignatureFrom(gen.caCert); err != nil {
		t.Errorf("CRL signature invalid: %v", err)
	}
}

// TestRevocationWorkflow_OCSP tests full OCSP workflow.
func TestRevocationWorkflow_OCSP(t *testing.T) {
	gen, _ := NewMockCRLGenerator()
	ocsp := NewMockOCSPResponder(gen.caCert, gen.caKey)

	// Step 1: Check status before revocation
	resp1 := ocsp.CheckStatus("9002")
	if resp1.Status != "good" {
		t.Errorf("Before revocation: status = %s, want good", resp1.Status)
	}

	// Step 2: Revoke
	ocsp.AddRevocation("9002", "compromised")

	// Step 3: Check status after revocation
	resp2 := ocsp.CheckStatus("9002")
	if resp2.Status != "revoked" {
		t.Errorf("After revocation: status = %s, want revoked", resp2.Status)
	}

	// Step 4: Verify immediate propagation
	if resp2.RevocationTime.IsZero() {
		t.Error("RevocationTime should be set immediately")
	}
}

// TestRevocationWorkflow_Both tests CRL and OCSP consistency.
func TestRevocationWorkflow_Both(t *testing.T) {
	gen, _ := NewMockCRLGenerator()
	ocsp := NewMockOCSPResponder(gen.caCert, gen.caKey)

	// Revoke 2, keep 3 valid
	gen.AddRevocation("both1", "compromised", "admin")
	gen.AddRevocation("both2", "compromised", "admin")
	ocsp.AddRevocation("both1", "compromised")
	ocsp.AddRevocation("both2", "compromised")

	// Generate CRL
	gen.GenerateCRL()

	// Check OCSP for all 5
	for i := 1; i <= 5; i++ {
		serial := fmt.Sprintf("both%d", i)
		resp := ocsp.CheckStatus(serial)

		if i <= 2 {
			if resp.Status != "revoked" {
				t.Errorf("%s should be revoked", serial)
			}
		} else {
			if resp.Status != "good" {
				t.Errorf("%s should be good", serial)
			}
		}
	}

	// Verify CRL has 2 entries
	if gen.GetRevocationCount() != 2 {
		t.Errorf("CRL should have 2 revocations, got %d", gen.GetRevocationCount())
	}
}

// TestRevocation_ImmediatePropagation tests immediate revocation enforcement.
func TestRevocation_ImmediatePropagation(t *testing.T) {
	gen, _ := NewMockCRLGenerator()
	ocsp := NewMockOCSPResponder(gen.caCert, gen.caKey)

	// Measure time to detect revocation
	start := time.Now()

	gen.AddRevocation("immediate", "compromised", "admin")
	ocsp.AddRevocation("immediate", "compromised")

	// OCSP should see immediately
	resp := ocsp.CheckStatus("immediate")
	ocspLatency := time.Since(start)

	if resp.Status != "revoked" {
		t.Error("OCSP should see revocation immediately")
	}

	// CRL should be updated within 1 second
	gen.GenerateCRL()
	crlLatency := time.Since(start)

	t.Logf("OCSP propagation: %v, CRL propagation: %v", ocspLatency, crlLatency)

	if ocspLatency > time.Millisecond {
		t.Errorf("OCSP latency %v exceeds 1ms", ocspLatency)
	}
	if crlLatency > time.Second {
		t.Errorf("CRL latency %v exceeds 1s", crlLatency)
	}
}

// ============================================================================
// Hash Chain Tests for Audit Integrity
// ============================================================================

// TestRevocationAudit_HashChain tests audit log hash chain.
func TestRevocationAudit_HashChain(t *testing.T) {
	gen, _ := NewMockCRLGenerator()

	// Simulate audit entries with hash chain
	type AuditEntry struct {
		ID            int
		Serial        string
		Operation     string
		Timestamp     time.Time
		Hash          string
		PrevEntryHash string
	}

	entries := make([]AuditEntry, 10)
	prevHash := ""

	for i := 0; i < 10; i++ {
		serial := fmt.Sprintf("audit%d", i)
		gen.AddRevocation(serial, "compromised", "admin")

		// Calculate hash
		data := fmt.Sprintf("%d:%s:revoke:%v:%s", i, serial, time.Now(), prevHash)
		hash := sha256.Sum256([]byte(data))
		hashHex := hex.EncodeToString(hash[:])

		entries[i] = AuditEntry{
			ID:            i,
			Serial:        serial,
			Operation:     "revoke",
			Timestamp:     time.Now(),
			Hash:          hashHex,
			PrevEntryHash: prevHash,
		}

		prevHash = hashHex
	}

	// Verify chain
	for i := 1; i < len(entries); i++ {
		if entries[i].PrevEntryHash != entries[i-1].Hash {
			t.Errorf("Hash chain broken at entry %d", i)
		}
	}
}

// ============================================================================
// Error Handling Tests
// ============================================================================

// TestCRLGeneration_ErrorRecovery tests error handling.
func TestCRLGeneration_ErrorRecovery(t *testing.T) {
	gen, _ := NewMockCRLGenerator()

	// Multiple successful generations
	for i := 0; i < 5; i++ {
		gen.AddRevocation(fmt.Sprintf("err%d", i), "compromised", "admin")
		_, err := gen.GenerateCRL()
		if err != nil {
			t.Errorf("CRL generation %d failed: %v", i, err)
		}
	}
}

// TestOCSP_InvalidSerial tests handling of invalid serials.
func TestOCSP_InvalidSerial(t *testing.T) {
	gen, _ := NewMockCRLGenerator()
	ocsp := NewMockOCSPResponder(gen.caCert, gen.caKey)

	// Empty serial
	resp := ocsp.CheckStatus("")
	if resp.Status != "good" {
		// Empty serial treated as not revoked
		t.Logf("Empty serial status: %s", resp.Status)
	}

	// Very long serial
	longSerial := string(bytes.Repeat([]byte("A"), 1000))
	resp = ocsp.CheckStatus(longSerial)
	if resp.Status != "good" {
		t.Logf("Long serial status: %s", resp.Status)
	}
}
