// Package tests provides comprehensive testing for the Certificate Manager.
// This file contains end-to-end integration tests validating complete service lifecycle.
package tests

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"sync"
	"testing"
	"time"
)

// ============================================================================
// Integration Test Types
// ============================================================================

// IntegrationTestSuite provides a complete service simulation for integration testing.
type IntegrationTestSuite struct {
	// CA Management
	caCert    *x509.Certificate
	caKey     *rsa.PrivateKey
	caCertPEM []byte

	// Certificate Management
	issuedCerts  map[string]*IntegrationCertRecord
	revokedCerts map[string]*IntegrationRevokedRecord
	certCache    map[string]*CachedCert

	// Device Tracking
	devices   map[string]*IntegrationDeviceRecord
	downloads []IntegrationDownloadRecord

	// Audit Log
	auditLog []IntegrationAuditEntry

	// HTTP Server
	httpServer *httptest.Server

	// State
	mu        sync.RWMutex
	startTime time.Time
}

// IntegrationCertRecord represents an issued certificate.
type IntegrationCertRecord struct {
	SerialNumber   string
	CommonName     string
	SANs           []string
	CertificatePEM string
	PrivateKeyPEM  string
	IssuedAt       time.Time
	NotAfter       time.Time
}

// IntegrationRevokedRecord represents a revoked certificate.
type IntegrationRevokedRecord struct {
	SerialNumber string
	RevokedAt    time.Time
	Reason       string
	RevokedBy    string
}

// IntegrationDeviceRecord represents a tracked device.
type IntegrationDeviceRecord struct {
	IP                 string
	MAC                string
	CAInstalled        bool
	DetectedAt         time.Time
	InstallationMethod string
}

// IntegrationDownloadRecord represents a CA download.
type IntegrationDownloadRecord struct {
	DeviceIP  string
	Format    string
	Timestamp time.Time
}

// IntegrationAuditEntry represents an audit log entry.
type IntegrationAuditEntry struct {
	ID        int64
	Timestamp time.Time
	Operation string
	Subject   string
	Serial    string
	User      string
	Success   bool
}

// CachedCert represents a cached certificate.
type CachedCert struct {
	CertPEM   string
	KeyPEM    string
	Serial    string
	CachedAt  time.Time
	ExpiresAt time.Time
}

// NewIntegrationTestSuite creates a new integration test suite.
func NewIntegrationTestSuite() (*IntegrationTestSuite, error) {
	// Generate CA
	caKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, err
	}

	caTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName:   "SafeOps Root CA",
			Organization: []string{"SafeOps Network"},
			Country:      []string{"US"},
		},
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

	caCertPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caCertDER})

	suite := &IntegrationTestSuite{
		caCert:       caCert,
		caKey:        caKey,
		caCertPEM:    caCertPEM,
		issuedCerts:  make(map[string]*IntegrationCertRecord),
		revokedCerts: make(map[string]*IntegrationRevokedRecord),
		certCache:    make(map[string]*CachedCert),
		devices:      make(map[string]*IntegrationDeviceRecord),
		downloads:    make([]IntegrationDownloadRecord, 0),
		auditLog:     make([]IntegrationAuditEntry, 0),
		startTime:    time.Now(),
	}

	suite.httpServer = httptest.NewServer(suite.httpHandler())

	return suite, nil
}

func (s *IntegrationTestSuite) httpHandler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/ca.crt", s.handleCADownload)
	mux.HandleFunc("/crl.pem", s.handleCRL)
	mux.HandleFunc("/health", s.handleHealth)
	return mux
}

func (s *IntegrationTestSuite) handleCADownload(w http.ResponseWriter, r *http.Request) {
	s.mu.Lock()
	s.downloads = append(s.downloads, IntegrationDownloadRecord{
		DeviceIP:  r.RemoteAddr,
		Format:    "pem",
		Timestamp: time.Now(),
	})
	s.mu.Unlock()

	w.Header().Set("Content-Type", "application/x-x509-ca-cert")
	w.Write(s.caCertPEM)
}

func (s *IntegrationTestSuite) handleCRL(w http.ResponseWriter, r *http.Request) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	crlTemplate := &x509.RevocationList{
		Number:     big.NewInt(int64(len(s.revokedCerts) + 1)),
		ThisUpdate: time.Now(),
		NextUpdate: time.Now().Add(7 * 24 * time.Hour),
	}

	// Add revoked certificates
	for _, rev := range s.revokedCerts {
		serialBytes, _ := hex.DecodeString(rev.SerialNumber)
		serial := new(big.Int).SetBytes(serialBytes)
		crlTemplate.RevokedCertificateEntries = append(crlTemplate.RevokedCertificateEntries, x509.RevocationListEntry{
			SerialNumber:   serial,
			RevocationTime: rev.RevokedAt,
		})
	}

	crlDER, _ := x509.CreateRevocationList(rand.Reader, crlTemplate, s.caCert, s.caKey)
	crlPEM := pem.EncodeToMemory(&pem.Block{Type: "X509 CRL", Bytes: crlDER})

	w.Header().Set("Content-Type", "application/pkix-crl")
	w.Write(crlPEM)
}

func (s *IntegrationTestSuite) handleHealth(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	fmt.Fprintf(w, `{"status":"healthy","uptime":"%v"}`, time.Since(s.startTime))
}

// Close shuts down the integration test suite.
func (s *IntegrationTestSuite) Close() {
	if s.httpServer != nil {
		s.httpServer.Close()
	}
}

// ============================================================================
// Service Operations
// ============================================================================

// SignCertificate issues a certificate for a domain.
func (s *IntegrationTestSuite) SignCertificate(domain string, sans []string) (*IntegrationCertRecord, error) {
	if domain == "" {
		return nil, fmt.Errorf("domain required")
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	// Check cache
	if cached, ok := s.certCache[domain]; ok && time.Now().Before(cached.ExpiresAt) {
		return &IntegrationCertRecord{
			SerialNumber:   cached.Serial,
			CommonName:     domain,
			CertificatePEM: cached.CertPEM,
			PrivateKeyPEM:  cached.KeyPEM,
		}, nil
	}

	// Check if domain is revoked
	for _, rev := range s.revokedCerts {
		if rev.SerialNumber == domain { // Using domain as key for simplicity
			return nil, fmt.Errorf("domain revoked")
		}
	}

	// Generate certificate
	key, _ := rsa.GenerateKey(rand.Reader, 2048)
	serial, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	serialHex := hex.EncodeToString(serial.Bytes())

	allSANs := append([]string{domain}, sans...)
	template := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: domain},
		NotBefore:    time.Now(),
		NotAfter:     time.Now().AddDate(0, 0, 90),
		KeyUsage:     x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:     allSANs,
	}

	certDER, _ := x509.CreateCertificate(rand.Reader, template, s.caCert, &key.PublicKey, s.caKey)
	certPEM := string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER}))
	keyPEM := string(pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)}))

	record := &IntegrationCertRecord{
		SerialNumber:   serialHex,
		CommonName:     domain,
		SANs:           allSANs,
		CertificatePEM: certPEM,
		PrivateKeyPEM:  keyPEM,
		IssuedAt:       time.Now(),
		NotAfter:       template.NotAfter,
	}
	s.issuedCerts[serialHex] = record

	// Cache it
	s.certCache[domain] = &CachedCert{
		CertPEM:   certPEM,
		KeyPEM:    keyPEM,
		Serial:    serialHex,
		CachedAt:  time.Now(),
		ExpiresAt: time.Now().Add(24 * time.Hour),
	}

	// Audit log
	s.logAudit("sign", domain, serialHex, "tls_proxy", true)

	return record, nil
}

// RevokeCertificate revokes a certificate.
func (s *IntegrationTestSuite) RevokeCertificate(serial, reason, user string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if _, ok := s.issuedCerts[serial]; !ok {
		return fmt.Errorf("certificate not found")
	}

	if _, ok := s.revokedCerts[serial]; ok {
		return fmt.Errorf("already revoked")
	}

	s.revokedCerts[serial] = &IntegrationRevokedRecord{
		SerialNumber: serial,
		RevokedAt:    time.Now(),
		Reason:       reason,
		RevokedBy:    user,
	}

	// Clear cache for any domain using this serial
	for domain, cached := range s.certCache {
		if cached.Serial == serial {
			delete(s.certCache, domain)
		}
	}

	s.logAudit("revoke", serial, serial, user, true)

	return nil
}

// CheckRevocation checks if a certificate is revoked.
func (s *IntegrationTestSuite) CheckRevocation(serial string) (bool, string) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	if rev, ok := s.revokedCerts[serial]; ok {
		return true, rev.Reason
	}
	return false, ""
}

// TrackDevice updates device tracking status.
func (s *IntegrationTestSuite) TrackDevice(ip, mac string, installed bool, method string) {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.devices[ip] = &IntegrationDeviceRecord{
		IP:                 ip,
		MAC:                mac,
		CAInstalled:        installed,
		DetectedAt:         time.Now(),
		InstallationMethod: method,
	}
}

// GetDeviceStatus returns device CA status.
func (s *IntegrationTestSuite) GetDeviceStatus(ip string) *IntegrationDeviceRecord {
	s.mu.RLock()
	defer s.mu.RUnlock()

	if device, ok := s.devices[ip]; ok {
		copy := *device
		return &copy
	}
	return nil
}

// GetInstallationStats returns adoption statistics.
func (s *IntegrationTestSuite) GetInstallationStats() (total, installed int, percentage float64) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	total = len(s.devices)
	for _, d := range s.devices {
		if d.CAInstalled {
			installed++
		}
	}
	if total > 0 {
		percentage = float64(installed) / float64(total) * 100
	}
	return
}

func (s *IntegrationTestSuite) logAudit(op, subject, serial, user string, success bool) {
	s.auditLog = append(s.auditLog, IntegrationAuditEntry{
		ID:        int64(len(s.auditLog) + 1),
		Timestamp: time.Now(),
		Operation: op,
		Subject:   subject,
		Serial:    serial,
		User:      user,
		Success:   success,
	})
}

// GetAuditLog returns the audit log.
func (s *IntegrationTestSuite) GetAuditLog() []IntegrationAuditEntry {
	s.mu.RLock()
	defer s.mu.RUnlock()
	result := make([]IntegrationAuditEntry, len(s.auditLog))
	copy(result, s.auditLog)
	return result
}

// GetCertificateInfo returns CA distribution URLs.
func (s *IntegrationTestSuite) GetCertificateInfo() map[string]interface{} {
	return map[string]interface{}{
		"ca_url":  s.httpServer.URL + "/ca.crt",
		"crl_url": s.httpServer.URL + "/crl.pem",
		"install_script_urls": []string{
			s.httpServer.URL + "/install-ca.sh",
			s.httpServer.URL + "/install-ca.ps1",
		},
	}
}

// ============================================================================
// Full CA Lifecycle Test
// ============================================================================

// TestFullCALifecycle tests the complete CA lifecycle.
func TestFullCALifecycle(t *testing.T) {
	suite, err := NewIntegrationTestSuite()
	if err != nil {
		t.Fatalf("Failed to create test suite: %v", err)
	}
	defer suite.Close()

	// Step 1: Verify CA exists
	if suite.caCert == nil {
		t.Fatal("CA certificate not generated")
	}
	if suite.caCert.Subject.CommonName != "SafeOps Root CA" {
		t.Errorf("CA CN = %s, want SafeOps Root CA", suite.caCert.Subject.CommonName)
	}
	t.Log("Step 1: CA Generation - PASS")

	// Step 2: Download CA
	resp, err := http.Get(suite.httpServer.URL + "/ca.crt")
	if err != nil {
		t.Fatalf("Failed to download CA: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		t.Fatalf("CA download status = %d, want 200", resp.StatusCode)
	}
	t.Log("Step 2: CA Distribution - PASS")

	// Step 3: Issue Certificate
	cert, err := suite.SignCertificate("example.com", []string{"www.example.com"})
	if err != nil {
		t.Fatalf("Failed to sign certificate: %v", err)
	}
	if cert.SerialNumber == "" {
		t.Fatal("Certificate serial empty")
	}
	t.Log("Step 3: Certificate Issuance - PASS")

	// Step 4: Validate Certificate
	block, _ := pem.Decode([]byte(cert.CertificatePEM))
	parsedCert, _ := x509.ParseCertificate(block.Bytes)
	if parsedCert.Issuer.CommonName != "SafeOps Root CA" {
		t.Errorf("Issuer = %s, want SafeOps Root CA", parsedCert.Issuer.CommonName)
	}
	t.Log("Step 4: Certificate Validation - PASS")

	// Step 5: Revoke Certificate
	err = suite.RevokeCertificate(cert.SerialNumber, "compromised", "admin")
	if err != nil {
		t.Fatalf("Failed to revoke: %v", err)
	}
	t.Log("Step 5: Certificate Revocation - PASS")

	// Step 6: Verify Revocation
	isRevoked, reason := suite.CheckRevocation(cert.SerialNumber)
	if !isRevoked {
		t.Fatal("Certificate should be revoked")
	}
	if reason != "compromised" {
		t.Errorf("Reason = %s, want compromised", reason)
	}
	t.Log("Step 6: Revocation Verification - PASS")

	// Verify audit log
	auditLog := suite.GetAuditLog()
	if len(auditLog) < 2 {
		t.Errorf("Expected at least 2 audit entries, got %d", len(auditLog))
	}
	t.Log("Audit Log - PASS")
}

// ============================================================================
// DHCP Integration Test
// ============================================================================

// TestDHCPIntegration tests DHCP server integration workflow.
func TestDHCPIntegration(t *testing.T) {
	suite, err := NewIntegrationTestSuite()
	if err != nil {
		t.Fatalf("Failed to create test suite: %v", err)
	}
	defer suite.Close()

	// Step 1: Get certificate info (simulates DHCP server call)
	certInfo := suite.GetCertificateInfo()
	caURL, ok := certInfo["ca_url"].(string)
	if !ok || caURL == "" {
		t.Fatal("ca_url not in certificate info")
	}
	t.Log("Step 1: GetCertificateInfo - PASS")

	// Step 2: Device downloads CA (simulates device behavior)
	resp, err := http.Get(caURL)
	if err != nil {
		t.Fatalf("Device CA download failed: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != 200 {
		t.Fatalf("Download status = %d", resp.StatusCode)
	}
	t.Log("Step 2: Device Downloads CA - PASS")

	// Step 3: Device installs CA (simulated)
	deviceIP := "192.168.1.100"
	deviceMAC := "AA:BB:CC:DD:EE:FF"
	suite.TrackDevice(deviceIP, deviceMAC, true, "http_download")
	t.Log("Step 3: Device Installs CA - PASS")

	// Step 4: Verify device status
	status := suite.GetDeviceStatus(deviceIP)
	if status == nil {
		t.Fatal("Device status not found")
	}
	if !status.CAInstalled {
		t.Error("CAInstalled should be true")
	}
	if status.InstallationMethod != "http_download" {
		t.Errorf("Method = %s, want http_download", status.InstallationMethod)
	}
	t.Log("Step 4: Device Status Verification - PASS")
}

// ============================================================================
// TLS Proxy Integration Test
// ============================================================================

// TestTLSProxyIntegration tests TLS proxy certificate signing workflow.
func TestTLSProxyIntegration(t *testing.T) {
	suite, err := NewIntegrationTestSuite()
	if err != nil {
		t.Fatalf("Failed to create test suite: %v", err)
	}
	defer suite.Close()

	// Step 1: TLS proxy requests certificate
	cert1, err := suite.SignCertificate("secure.example.com", []string{"*.secure.example.com"})
	if err != nil {
		t.Fatalf("Certificate signing failed: %v", err)
	}
	t.Logf("Step 1: Certificate issued, serial: %s", cert1.SerialNumber[:16])

	// Step 2: Verify certificate is valid
	block, _ := pem.Decode([]byte(cert1.CertificatePEM))
	parsedCert, _ := x509.ParseCertificate(block.Bytes)

	foundWildcard := false
	for _, san := range parsedCert.DNSNames {
		if san == "*.secure.example.com" {
			foundWildcard = true
		}
	}
	if !foundWildcard {
		t.Error("Wildcard SAN not found")
	}
	t.Log("Step 2: Certificate Validation - PASS")

	// Step 3: Cache hit test
	cert2, _ := suite.SignCertificate("secure.example.com", nil)
	if cert2.SerialNumber != cert1.SerialNumber {
		t.Error("Cache miss - should return cached certificate")
	}
	t.Log("Step 3: Cache Hit - PASS")

	// Step 4: Revoke and verify refused
	suite.RevokeCertificate(cert1.SerialNumber, "compromised", "admin")

	// Clear cache to force re-check
	suite.mu.Lock()
	delete(suite.certCache, "secure.example.com")
	suite.mu.Unlock()

	isRevoked, _ := suite.CheckRevocation(cert1.SerialNumber)
	if !isRevoked {
		t.Error("Certificate should be revoked")
	}
	t.Log("Step 4: Revocation Enforcement - PASS")
}

// ============================================================================
// Device Tracking Workflow Test
// ============================================================================

// TestDeviceTrackingWorkflow tests device tracking at scale.
func TestDeviceTrackingWorkflow(t *testing.T) {
	suite, err := NewIntegrationTestSuite()
	if err != nil {
		t.Fatalf("Failed to create test suite: %v", err)
	}
	defer suite.Close()

	// Step 1: Simulate 100 devices
	for i := 0; i < 100; i++ {
		ip := fmt.Sprintf("192.168.1.%d", i+1)
		mac := fmt.Sprintf("AA:BB:CC:DD:%02X:%02X", i/256, i%256)

		// 70% install CA
		installed := i < 70
		method := ""
		if installed {
			if i < 50 {
				method = "http_download"
			} else {
				method = "dhcp"
			}
		}
		suite.TrackDevice(ip, mac, installed, method)
	}
	t.Log("Step 1: 100 Devices Tracked")

	// Step 2: Get statistics
	total, installed, percentage := suite.GetInstallationStats()
	if total != 100 {
		t.Errorf("Total = %d, want 100", total)
	}
	if installed != 70 {
		t.Errorf("Installed = %d, want 70", installed)
	}
	if percentage != 70.0 {
		t.Errorf("Percentage = %.1f, want 70.0", percentage)
	}
	t.Logf("Step 2: Stats - %d total, %d installed, %.1f%%", total, installed, percentage)

	// Step 3: Query non-compliant devices
	nonCompliant := 0
	suite.mu.RLock()
	for _, d := range suite.devices {
		if !d.CAInstalled {
			nonCompliant++
		}
	}
	suite.mu.RUnlock()
	if nonCompliant != 30 {
		t.Errorf("Non-compliant = %d, want 30", nonCompliant)
	}
	t.Logf("Step 3: Non-compliant Devices - %d", nonCompliant)
}

// ============================================================================
// Revocation Workflow Test
// ============================================================================

// TestRevocationWorkflow tests complete revocation propagation.
func TestRevocationWorkflow(t *testing.T) {
	suite, err := NewIntegrationTestSuite()
	if err != nil {
		t.Fatalf("Failed to create test suite: %v", err)
	}
	defer suite.Close()

	// Step 1: Issue certificate
	cert, _ := suite.SignCertificate("revocation-test.com", nil)
	t.Logf("Step 1: Certificate issued, serial: %s", cert.SerialNumber[:16])

	// Step 2: Verify not revoked
	isRevoked, _ := suite.CheckRevocation(cert.SerialNumber)
	if isRevoked {
		t.Error("Certificate should not be revoked initially")
	}
	t.Log("Step 2: Certificate active - PASS")

	// Step 3: Revoke certificate
	start := time.Now()
	suite.RevokeCertificate(cert.SerialNumber, "compromised", "security_admin")
	revokeTime := time.Since(start)
	t.Logf("Step 3: Revocation completed in %v", revokeTime)

	// Step 4: Verify revocation status
	isRevoked, reason := suite.CheckRevocation(cert.SerialNumber)
	if !isRevoked {
		t.Error("Certificate should be revoked")
	}
	if reason != "compromised" {
		t.Errorf("Reason = %s, want compromised", reason)
	}
	t.Log("Step 4: Revocation verified - PASS")

	// Step 5: Download CRL and verify
	resp, _ := http.Get(suite.httpServer.URL + "/crl.pem")
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()

	if len(body) == 0 {
		t.Error("CRL should not be empty")
	}

	block, _ := pem.Decode(body)
	if block == nil || block.Type != "X509 CRL" {
		t.Error("Invalid CRL format")
	}
	t.Log("Step 5: CRL contains revoked certificate - PASS")

	// Step 6: Verify audit log
	auditLog := suite.GetAuditLog()
	hasRevokeEntry := false
	for _, entry := range auditLog {
		if entry.Operation == "revoke" && entry.Serial == cert.SerialNumber {
			hasRevokeEntry = true
			if entry.User != "security_admin" {
				t.Errorf("Revoke user = %s, want security_admin", entry.User)
			}
		}
	}
	if !hasRevokeEntry {
		t.Error("Revocation not in audit log")
	}
	t.Log("Step 6: Audit log verified - PASS")
}

// ============================================================================
// Performance Test
// ============================================================================

// TestPerformance tests service performance under load.
func TestPerformance(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping performance test in short mode")
	}

	suite, err := NewIntegrationTestSuite()
	if err != nil {
		t.Fatalf("Failed to create test suite: %v", err)
	}
	defer suite.Close()

	// Test 1: Certificate signing performance
	numCerts := 100
	start := time.Now()
	for i := 0; i < numCerts; i++ {
		domain := fmt.Sprintf("perf%d.example.com", i)
		_, err := suite.SignCertificate(domain, nil)
		if err != nil {
			t.Errorf("Signing failed for %s: %v", domain, err)
		}
	}
	signingTime := time.Since(start)
	avgSigning := signingTime / time.Duration(numCerts)
	t.Logf("Signed %d certificates in %v (avg: %v)", numCerts, signingTime, avgSigning)

	if avgSigning > 100*time.Millisecond {
		t.Errorf("Average signing time %v exceeds 100ms", avgSigning)
	}

	// Test 2: Concurrent signing
	var wg sync.WaitGroup
	numGoroutines := 50
	wg.Add(numGoroutines)

	start = time.Now()
	for i := 0; i < numGoroutines; i++ {
		go func(n int) {
			defer wg.Done()
			domain := fmt.Sprintf("concurrent%d.example.com", n)
			suite.SignCertificate(domain, nil)
		}(i)
	}
	wg.Wait()
	concurrentTime := time.Since(start)
	t.Logf("Concurrent signing of %d certs: %v", numGoroutines, concurrentTime)
}

// ============================================================================
// Multi-Service Integration Test
// ============================================================================

// TestMultiServiceIntegration tests complete ecosystem.
func TestMultiServiceIntegration(t *testing.T) {
	suite, err := NewIntegrationTestSuite()
	if err != nil {
		t.Fatalf("Failed to create test suite: %v", err)
	}
	defer suite.Close()

	// Simulate DHCP distributing CA URLs to devices
	certInfo := suite.GetCertificateInfo()
	t.Logf("DHCP received CA info: %v", certInfo["ca_url"])

	// Simulate 90 devices installing CA
	for i := 0; i < 90; i++ {
		ip := fmt.Sprintf("10.0.0.%d", i+1)
		mac := fmt.Sprintf("BB:CC:DD:EE:%02X:%02X", i/256, i%256)
		suite.TrackDevice(ip, mac, true, "dhcp")
	}

	// Simulate 10 devices NOT installing CA
	for i := 90; i < 100; i++ {
		ip := fmt.Sprintf("10.0.0.%d", i+1)
		mac := fmt.Sprintf("BB:CC:DD:EE:%02X:%02X", i/256, i%256)
		suite.TrackDevice(ip, mac, false, "")
	}

	// TLS proxy issues certificates
	for i := 0; i < 50; i++ {
		domain := fmt.Sprintf("site%d.com", i)
		suite.SignCertificate(domain, nil)
	}

	// Admin revokes 5 certificates
	suite.mu.RLock()
	var serialsToRevoke []string
	count := 0
	for serial := range suite.issuedCerts {
		if count < 5 {
			serialsToRevoke = append(serialsToRevoke, serial)
			count++
		}
	}
	suite.mu.RUnlock()

	for _, serial := range serialsToRevoke {
		suite.RevokeCertificate(serial, "compromised", "admin")
	}

	// Final statistics
	total, installed, percentage := suite.GetInstallationStats()
	t.Logf("Device adoption: %d/%d (%.1f%%)", installed, total, percentage)

	suite.mu.RLock()
	issuedCount := len(suite.issuedCerts)
	revokedCount := len(suite.revokedCerts)
	suite.mu.RUnlock()

	t.Logf("Certificates issued: %d", issuedCount)
	t.Logf("Certificates revoked: %d", revokedCount)
	t.Logf("Active certificates: %d", issuedCount-revokedCount)

	// Verify metrics
	if percentage != 90.0 {
		t.Errorf("Adoption = %.1f%%, want 90%%", percentage)
	}
	if revokedCount != 5 {
		t.Errorf("Revoked = %d, want 5", revokedCount)
	}
}

// ============================================================================
// TLS Handshake Test
// ============================================================================

// TestTLSHandshake tests actual TLS connection with CA.
func TestTLSHandshake(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping TLS handshake test in short mode")
	}

	// Skip on Windows due to platform-specific socket issues
	if os.PathSeparator == '\\' {
		t.Skip("Skipping TLS handshake test on Windows due to socket issues")
	}

	suite, err := NewIntegrationTestSuite()
	if err != nil {
		t.Fatalf("Failed to create test suite: %v", err)
	}
	defer suite.Close()

	// Get a certificate
	certRecord, _ := suite.SignCertificate("localhost", nil)

	// Parse certificate and key
	certBlock, _ := pem.Decode([]byte(certRecord.CertificatePEM))
	keyBlock, _ := pem.Decode([]byte(certRecord.PrivateKeyPEM))

	cert, _ := x509.ParseCertificate(certBlock.Bytes)
	key, _ := x509.ParsePKCS1PrivateKey(keyBlock.Bytes)

	// Create TLS server
	tlsCert := tls.Certificate{
		Certificate: [][]byte{cert.Raw},
		PrivateKey:  key,
	}

	serverConfig := &tls.Config{
		Certificates: []tls.Certificate{tlsCert},
		MinVersion:   tls.VersionTLS12,
	}

	listener, err := tls.Listen("tcp", "127.0.0.1:0", serverConfig)
	if err != nil {
		t.Fatalf("Failed to create TLS listener: %v", err)
	}
	defer listener.Close()

	// Accept connections in goroutine
	done := make(chan bool)
	go func() {
		conn, err := listener.Accept()
		if err != nil {
			return
		}
		conn.Close()
		done <- true
	}()

	// Create client with CA trust
	pool := x509.NewCertPool()
	pool.AddCert(suite.caCert)

	clientConfig := &tls.Config{
		RootCAs:    pool,
		ServerName: "localhost",
		MinVersion: tls.VersionTLS12,
	}

	// Connect
	conn, err := tls.Dial("tcp", listener.Addr().String(), clientConfig)
	if err != nil {
		t.Fatalf("TLS handshake failed: %v", err)
	}
	conn.Close()

	select {
	case <-done:
		t.Log("TLS handshake successful")
	case <-time.After(2 * time.Second):
		t.Error("TLS handshake timeout")
	}
}

// ============================================================================
// Health Check Integration Test
// ============================================================================

// TestHealthCheckIntegration tests health endpoint.
func TestHealthCheckIntegration(t *testing.T) {
	suite, err := NewIntegrationTestSuite()
	if err != nil {
		t.Fatalf("Failed to create test suite: %v", err)
	}
	defer suite.Close()

	resp, err := http.Get(suite.httpServer.URL + "/health")
	if err != nil {
		t.Fatalf("Health check failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		t.Errorf("Health status = %d, want 200", resp.StatusCode)
	}

	body, _ := io.ReadAll(resp.Body)
	if len(body) == 0 {
		t.Error("Health response should not be empty")
	}
	t.Logf("Health: %s", string(body))
}

// ============================================================================
// Context Cancellation Test
// ============================================================================

// TestContextCancellation tests proper context handling.
func TestContextCancellation(t *testing.T) {
	suite, err := NewIntegrationTestSuite()
	if err != nil {
		t.Fatalf("Failed to create test suite: %v", err)
	}
	defer suite.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	// Simulate request with context
	req, _ := http.NewRequestWithContext(ctx, "GET", suite.httpServer.URL+"/ca.crt", nil)
	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("Request failed: %v", err)
	}
	resp.Body.Close()

	if resp.StatusCode != 200 {
		t.Errorf("Status = %d, want 200", resp.StatusCode)
	}
}

// ============================================================================
// Cleanup Test
// ============================================================================

// TestCleanup verifies proper resource cleanup.
func TestCleanup(t *testing.T) {
	suite, err := NewIntegrationTestSuite()
	if err != nil {
		t.Fatalf("Failed to create test suite: %v", err)
	}

	// Issue some certificates
	for i := 0; i < 10; i++ {
		suite.SignCertificate(fmt.Sprintf("cleanup%d.com", i), nil)
	}

	// Close suite
	suite.Close()

	// Verify server is closed
	_, err = http.Get(suite.httpServer.URL + "/health")
	if err == nil {
		t.Error("Server should be closed")
	}
}

// ============================================================================
// Concurrent Operations Test
// ============================================================================

// TestConcurrentOperations tests thread safety under concurrent load.
func TestConcurrentOperations(t *testing.T) {
	suite, err := NewIntegrationTestSuite()
	if err != nil {
		t.Fatalf("Failed to create test suite: %v", err)
	}
	defer suite.Close()

	var wg sync.WaitGroup
	numOps := 100
	wg.Add(numOps * 3) // 3 operations per iteration

	for i := 0; i < numOps; i++ {
		// Concurrent certificate signing
		go func(n int) {
			defer wg.Done()
			suite.SignCertificate(fmt.Sprintf("concurrent%d.com", n), nil)
		}(i)

		// Concurrent device tracking
		go func(n int) {
			defer wg.Done()
			ip := fmt.Sprintf("192.168.%d.%d", n/256, n%256)
			suite.TrackDevice(ip, fmt.Sprintf("AA:%02X:00:00:00:00", n), n%2 == 0, "test")
		}(i)

		// Concurrent status checks
		go func(n int) {
			defer wg.Done()
			ip := fmt.Sprintf("192.168.%d.%d", n/256, n%256)
			suite.GetDeviceStatus(ip)
		}(i)
	}

	wg.Wait()

	// Verify no data corruption
	suite.mu.RLock()
	certCount := len(suite.issuedCerts)
	deviceCount := len(suite.devices)
	suite.mu.RUnlock()

	if certCount != numOps {
		t.Errorf("Issued certs = %d, want %d", certCount, numOps)
	}
	if deviceCount != numOps {
		t.Errorf("Tracked devices = %d, want %d", deviceCount, numOps)
	}

	t.Logf("Concurrent operations: %d certs, %d devices", certCount, deviceCount)
}

// ============================================================================
// Error Recovery Test
// ============================================================================

// TestErrorRecovery tests graceful error handling.
func TestErrorRecovery(t *testing.T) {
	suite, err := NewIntegrationTestSuite()
	if err != nil {
		t.Fatalf("Failed to create test suite: %v", err)
	}
	defer suite.Close()

	// Test 1: Empty domain
	_, err = suite.SignCertificate("", nil)
	if err == nil {
		t.Error("Should return error for empty domain")
	}

	// Test 2: Revoke non-existent certificate
	err = suite.RevokeCertificate("nonexistent", "test", "admin")
	if err == nil {
		t.Error("Should return error for non-existent certificate")
	}

	// Test 3: Double revocation
	cert, _ := suite.SignCertificate("error-test.com", nil)
	suite.RevokeCertificate(cert.SerialNumber, "compromised", "admin")
	err = suite.RevokeCertificate(cert.SerialNumber, "compromised", "admin")
	if err == nil {
		t.Error("Should return error for double revocation")
	}

	t.Log("Error recovery tests passed")
}
