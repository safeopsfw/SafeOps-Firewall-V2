// Package tests provides comprehensive testing for the Certificate Manager.
// This file tests all gRPC service methods.
package tests

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"math/big"
	"sync"
	"testing"
	"time"
)

// ============================================================================
// Test Types
// ============================================================================

// CertificateInfoResponse represents GetCertificateInfo response.
type CertificateInfoResponse struct {
	CAURL             string   `json:"ca_url"`
	InstallScriptURLs []string `json:"install_script_urls"`
	WPADURL           string   `json:"wpad_url"`
	CRLURL            string   `json:"crl_url"`
	OCSPURL           string   `json:"ocsp_url"`
	CAFingerprint     string   `json:"ca_fingerprint_sha256"`
}

// DeviceStatusResponse represents GetDeviceStatus response.
type DeviceStatusResponse struct {
	DeviceIP           string    `json:"device_ip"`
	MACAddress         string    `json:"mac_address"`
	CAInstalled        bool      `json:"ca_installed"`
	DetectedAt         time.Time `json:"detected_at"`
	InstallationMethod string    `json:"installation_method"`
}

// CertificateResponse represents SignCertificate response.
type CertificateResponse struct {
	CertificatePEM string    `json:"certificate_pem"`
	PrivateKeyPEM  string    `json:"private_key_pem"`
	SerialNumber   string    `json:"serial_number"`
	NotBefore      time.Time `json:"not_before"`
	NotAfter       time.Time `json:"not_after"`
}

// RevokeResponse represents RevokeCertificate response.
type RevokeResponse struct {
	Success      bool      `json:"success"`
	Message      string    `json:"message"`
	CRLUpdatedAt time.Time `json:"crl_updated_at"`
}

// RevocationStatusResponse represents CheckRevocationStatus response.
type RevocationStatusResponse struct {
	IsRevoked        bool      `json:"is_revoked"`
	RevokedAt        time.Time `json:"revoked_at"`
	RevocationReason string    `json:"revocation_reason"`
}

// CertificateListResponse represents ListIssuedCertificates response.
type CertificateListResponse struct {
	Certificates []CertificateSummaryResponse `json:"certificates"`
	TotalCount   int                          `json:"total_count"`
}

// CertificateSummaryResponse represents a certificate summary.
type CertificateSummaryResponse struct {
	SerialNumber string    `json:"serial_number"`
	CommonName   string    `json:"common_name"`
	NotAfter     time.Time `json:"not_after"`
	Revoked      bool      `json:"revoked"`
}

// CertificateDetailsResponse represents GetCertificateDetails response.
type CertificateDetailsResponse struct {
	SerialNumber     string    `json:"serial_number"`
	CommonName       string    `json:"common_name"`
	SubjectAltNames  []string  `json:"subject_alt_names"`
	NotBefore        time.Time `json:"not_before"`
	NotAfter         time.Time `json:"not_after"`
	CertificatePEM   string    `json:"certificate_pem"`
	CertificateType  string    `json:"certificate_type"`
	Revoked          bool      `json:"revoked"`
	RevocationReason string    `json:"revocation_reason,omitempty"`
}

// MockGRPCServer provides a mock gRPC server for testing.
type MockGRPCServer struct {
	caCert       *x509.Certificate
	caKey        *rsa.PrivateKey
	issuedCerts  map[string]*IssuedCertRecord
	revokedCerts map[string]*RevokedCertRecord
	devices      map[string]*DeviceStatusResponse
	baseURL      string
	mu           sync.RWMutex
	apiKeys      map[string]string // apiKey -> role
	rateLimits   map[string]int    // method -> remaining calls
}

// IssuedCertRecord represents an issued certificate.
type IssuedCertRecord struct {
	SerialNumber    string
	CommonName      string
	SANs            []string
	CertificatePEM  string
	IssuedAt        time.Time
	NotAfter        time.Time
	CertificateType string
}

// RevokedCertRecord represents a revoked certificate.
type RevokedCertRecord struct {
	SerialNumber string
	RevokedAt    time.Time
	Reason       string
}

// NewMockGRPCServer creates a new mock gRPC server.
func NewMockGRPCServer() (*MockGRPCServer, error) {
	// Generate test CA
	caKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, err
	}

	caTemplate := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "SafeOps Root CA", Organization: []string{"SafeOps Network"}},
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

	return &MockGRPCServer{
		caCert:       caCert,
		caKey:        caKey,
		issuedCerts:  make(map[string]*IssuedCertRecord),
		revokedCerts: make(map[string]*RevokedCertRecord),
		devices:      make(map[string]*DeviceStatusResponse),
		baseURL:      "http://192.168.1.1",
		apiKeys: map[string]string{
			"admin-key-12345":  "admin",
			"viewer-key-67890": "viewer",
		},
		rateLimits: map[string]int{
			"SignCertificate":   100,
			"RevokeCertificate": 10,
		},
	}, nil
}

// GetCertificateInfo returns CA distribution URLs.
func (s *MockGRPCServer) GetCertificateInfo(_ context.Context) (*CertificateInfoResponse, error) {
	return &CertificateInfoResponse{
		CAURL: s.baseURL + "/ca.crt",
		InstallScriptURLs: []string{
			s.baseURL + "/install-ca.sh",
			s.baseURL + "/install-ca.ps1",
			s.baseURL + "/install-ca.pkg",
			s.baseURL + "/install-ca.mobileconfig",
		},
		WPADURL:       s.baseURL + "/wpad.dat",
		CRLURL:        s.baseURL + "/crl.pem",
		OCSPURL:       s.baseURL + ":8888/ocsp",
		CAFingerprint: "SHA256:AB:CD:EF:01:23:45:67:89",
	}, nil
}

// GetDeviceStatus returns device CA installation status.
func (s *MockGRPCServer) GetDeviceStatus(_ context.Context, ip, mac string) (*DeviceStatusResponse, error) {
	if ip == "" && mac == "" {
		return nil, fmt.Errorf("InvalidArgument: at least one of IP or MAC required")
	}

	s.mu.RLock()
	defer s.mu.RUnlock()

	key := ip
	if key == "" {
		key = mac
	}

	if device, ok := s.devices[key]; ok {
		return device, nil
	}

	// Device not found - return empty response (not an error)
	return &DeviceStatusResponse{
		DeviceIP:    ip,
		MACAddress:  mac,
		CAInstalled: false,
	}, nil
}

// AddDevice adds a device to the mock server.
func (s *MockGRPCServer) AddDevice(ip, mac string, installed bool) {
	s.mu.Lock()
	defer s.mu.Unlock()

	device := &DeviceStatusResponse{
		DeviceIP:    ip,
		MACAddress:  mac,
		CAInstalled: installed,
		DetectedAt:  time.Now(),
	}
	s.devices[ip] = device
	if mac != "" {
		s.devices[mac] = device
	}
}

// SignCertificate generates a certificate for a domain.
func (s *MockGRPCServer) SignCertificate(_ context.Context, domain string, sans []string) (*CertificateResponse, error) {
	if domain == "" {
		return nil, fmt.Errorf("InvalidArgument: domain is required")
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	// Check rate limit
	if s.rateLimits["SignCertificate"] <= 0 {
		return nil, fmt.Errorf("ResourceExhausted: rate limit exceeded")
	}
	s.rateLimits["SignCertificate"]--

	// Check if revoked
	for _, revoked := range s.revokedCerts {
		if revoked.Reason == domain {
			return nil, fmt.Errorf("PermissionDenied: domain has been revoked")
		}
	}

	// Check cache
	for _, cert := range s.issuedCerts {
		if cert.CommonName == domain && time.Since(cert.IssuedAt) < 24*time.Hour {
			return &CertificateResponse{
				CertificatePEM: cert.CertificatePEM,
				SerialNumber:   cert.SerialNumber,
				NotBefore:      cert.IssuedAt,
				NotAfter:       cert.NotAfter,
			}, nil
		}
	}

	// Generate new certificate
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
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})

	// Store in cache
	record := &IssuedCertRecord{
		SerialNumber:    serialHex,
		CommonName:      domain,
		SANs:            allSANs,
		CertificatePEM:  string(certPEM),
		IssuedAt:        time.Now(),
		NotAfter:        template.NotAfter,
		CertificateType: "server",
	}
	s.issuedCerts[serialHex] = record

	return &CertificateResponse{
		CertificatePEM: string(certPEM),
		PrivateKeyPEM:  string(keyPEM),
		SerialNumber:   serialHex,
		NotBefore:      template.NotBefore,
		NotAfter:       template.NotAfter,
	}, nil
}

// RevokeCertificate revokes a certificate.
func (s *MockGRPCServer) RevokeCertificate(_ context.Context, serial, reason, revokedBy, role string) (*RevokeResponse, error) {
	if serial == "" {
		return nil, fmt.Errorf("InvalidArgument: serial is required")
	}

	validReasons := map[string]bool{
		"compromised": true, "superseded": true, "cessation": true,
		"affiliation_changed": true, "privilege_withdrawn": true,
	}
	if !validReasons[reason] {
		return nil, fmt.Errorf("InvalidArgument: invalid revocation reason")
	}

	if role != "admin" {
		return nil, fmt.Errorf("PermissionDenied: admin role required")
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	// Check rate limit
	if s.rateLimits["RevokeCertificate"] <= 0 {
		return nil, fmt.Errorf("ResourceExhausted: rate limit exceeded")
	}
	s.rateLimits["RevokeCertificate"]--

	// Check if cert exists
	if _, ok := s.issuedCerts[serial]; !ok {
		return nil, fmt.Errorf("NotFound: certificate not found")
	}

	// Check if already revoked
	if _, ok := s.revokedCerts[serial]; ok {
		return nil, fmt.Errorf("AlreadyExists: certificate already revoked")
	}

	// Revoke
	s.revokedCerts[serial] = &RevokedCertRecord{
		SerialNumber: serial,
		RevokedAt:    time.Now(),
		Reason:       reason,
	}

	return &RevokeResponse{
		Success:      true,
		Message:      "Certificate revoked successfully",
		CRLUpdatedAt: time.Now(),
	}, nil
}

// CheckRevocationStatus checks if a certificate is revoked.
func (s *MockGRPCServer) CheckRevocationStatus(_ context.Context, serial string) (*RevocationStatusResponse, error) {
	if serial == "" {
		return nil, fmt.Errorf("InvalidArgument: serial is required")
	}

	s.mu.RLock()
	defer s.mu.RUnlock()

	if revoked, ok := s.revokedCerts[serial]; ok {
		return &RevocationStatusResponse{
			IsRevoked:        true,
			RevokedAt:        revoked.RevokedAt,
			RevocationReason: revoked.Reason,
		}, nil
	}

	return &RevocationStatusResponse{
		IsRevoked: false,
	}, nil
}

// ListIssuedCertificates returns issued certificates.
func (s *MockGRPCServer) ListIssuedCertificates(_ context.Context, commonName string, limit, offset int) (*CertificateListResponse, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	var matching []*IssuedCertRecord
	for _, cert := range s.issuedCerts {
		if commonName == "" || cert.CommonName == commonName {
			matching = append(matching, cert)
		}
	}

	total := len(matching)

	// Apply pagination
	if offset >= len(matching) {
		matching = nil
	} else {
		end := offset + limit
		if end > len(matching) {
			end = len(matching)
		}
		matching = matching[offset:end]
	}

	var summaries []CertificateSummaryResponse
	for _, cert := range matching {
		_, revoked := s.revokedCerts[cert.SerialNumber]
		summaries = append(summaries, CertificateSummaryResponse{
			SerialNumber: cert.SerialNumber,
			CommonName:   cert.CommonName,
			NotAfter:     cert.NotAfter,
			Revoked:      revoked,
		})
	}

	return &CertificateListResponse{
		Certificates: summaries,
		TotalCount:   total,
	}, nil
}

// GetCertificateDetails returns detailed certificate information.
func (s *MockGRPCServer) GetCertificateDetails(_ context.Context, serial string) (*CertificateDetailsResponse, error) {
	if serial == "" {
		return nil, fmt.Errorf("InvalidArgument: serial is required")
	}

	s.mu.RLock()
	defer s.mu.RUnlock()

	cert, ok := s.issuedCerts[serial]
	if !ok {
		return nil, fmt.Errorf("NotFound: certificate not found")
	}

	revoked, reason := false, ""
	if r, ok := s.revokedCerts[serial]; ok {
		revoked = true
		reason = r.Reason
	}

	return &CertificateDetailsResponse{
		SerialNumber:     cert.SerialNumber,
		CommonName:       cert.CommonName,
		SubjectAltNames:  cert.SANs,
		NotBefore:        cert.IssuedAt,
		NotAfter:         cert.NotAfter,
		CertificatePEM:   cert.CertificatePEM,
		CertificateType:  cert.CertificateType,
		Revoked:          revoked,
		RevocationReason: reason,
	}, nil
}

// Authenticate validates an API key.
func (s *MockGRPCServer) Authenticate(apiKey string) (string, error) {
	if apiKey == "" {
		return "", fmt.Errorf("Unauthenticated: API key required")
	}
	role, ok := s.apiKeys[apiKey]
	if !ok {
		return "", fmt.Errorf("Unauthenticated: invalid API key")
	}
	return role, nil
}

// ResetRateLimits resets rate limiting counters.
func (s *MockGRPCServer) ResetRateLimits() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.rateLimits["SignCertificate"] = 100
	s.rateLimits["RevokeCertificate"] = 10
}

// Clear removes all data.
func (s *MockGRPCServer) Clear() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.issuedCerts = make(map[string]*IssuedCertRecord)
	s.revokedCerts = make(map[string]*RevokedCertRecord)
	s.devices = make(map[string]*DeviceStatusResponse)
	s.ResetRateLimits()
}

// ============================================================================
// GetCertificateInfo Tests
// ============================================================================

// TestGetCertificateInfo_Success tests successful CA info retrieval.
func TestGetCertificateInfo_Success(t *testing.T) {
	server, _ := NewMockGRPCServer()

	resp, err := server.GetCertificateInfo(context.Background())
	if err != nil {
		t.Fatalf("GetCertificateInfo failed: %v", err)
	}

	if resp.CAURL == "" {
		t.Error("CAURL should not be empty")
	}
	if len(resp.InstallScriptURLs) == 0 {
		t.Error("InstallScriptURLs should not be empty")
	}
	if resp.CRLURL == "" {
		t.Error("CRLURL should not be empty")
	}
	if resp.OCSPURL == "" {
		t.Error("OCSPURL should not be empty")
	}
}

// TestGetCertificateInfo_InstallScripts tests script URLs.
func TestGetCertificateInfo_InstallScripts(t *testing.T) {
	server, _ := NewMockGRPCServer()

	resp, _ := server.GetCertificateInfo(context.Background())

	if len(resp.InstallScriptURLs) < 4 {
		t.Errorf("Expected at least 4 install scripts, got %d", len(resp.InstallScriptURLs))
	}

	// Check for platform scripts
	hasLinux, hasWindows, hasMacOS, hasiOS := false, false, false, false
	for _, url := range resp.InstallScriptURLs {
		if len(url) > 3 && url[len(url)-3:] == ".sh" {
			hasLinux = true
		}
		if len(url) > 4 && url[len(url)-4:] == ".ps1" {
			hasWindows = true
		}
		if len(url) > 4 && url[len(url)-4:] == ".pkg" {
			hasMacOS = true
		}
		if len(url) > 13 && url[len(url)-13:] == ".mobileconfig" {
			hasiOS = true
		}
	}

	if !hasLinux {
		t.Error("Missing Linux install script (.sh)")
	}
	if !hasWindows {
		t.Error("Missing Windows install script (.ps1)")
	}
	if !hasMacOS {
		t.Error("Missing macOS install script (.pkg)")
	}
	if !hasiOS {
		t.Error("Missing iOS install profile (.mobileconfig)")
	}
}

// ============================================================================
// GetDeviceStatus Tests
// ============================================================================

// TestGetDeviceStatus_ByIP tests device lookup by IP.
func TestGetDeviceStatus_ByIP(t *testing.T) {
	server, _ := NewMockGRPCServer()
	server.AddDevice("192.168.1.100", "AA:BB:CC:DD:EE:FF", true)

	resp, err := server.GetDeviceStatus(context.Background(), "192.168.1.100", "")
	if err != nil {
		t.Fatalf("GetDeviceStatus failed: %v", err)
	}

	if resp.DeviceIP != "192.168.1.100" {
		t.Errorf("DeviceIP = %s, want 192.168.1.100", resp.DeviceIP)
	}
	if !resp.CAInstalled {
		t.Error("CAInstalled = false, want true")
	}
}

// TestGetDeviceStatus_NotFound tests not found device.
func TestGetDeviceStatus_NotFound(t *testing.T) {
	server, _ := NewMockGRPCServer()

	resp, err := server.GetDeviceStatus(context.Background(), "192.168.1.200", "")
	if err != nil {
		t.Fatalf("GetDeviceStatus failed: %v", err)
	}

	if resp.CAInstalled {
		t.Error("CAInstalled should be false for unknown device")
	}
}

// TestGetDeviceStatus_InvalidRequest tests empty request.
func TestGetDeviceStatus_InvalidRequest(t *testing.T) {
	server, _ := NewMockGRPCServer()

	_, err := server.GetDeviceStatus(context.Background(), "", "")
	if err == nil {
		t.Error("Should return error for empty IP and MAC")
	}
}

// ============================================================================
// SignCertificate Tests
// ============================================================================

// TestSignCertificate_Success tests successful signing.
func TestSignCertificate_Success(t *testing.T) {
	server, _ := NewMockGRPCServer()

	resp, err := server.SignCertificate(context.Background(), "example.com", []string{"*.example.com"})
	if err != nil {
		t.Fatalf("SignCertificate failed: %v", err)
	}

	if resp.CertificatePEM == "" {
		t.Error("CertificatePEM should not be empty")
	}
	if resp.SerialNumber == "" {
		t.Error("SerialNumber should not be empty")
	}

	// Parse and validate certificate
	block, _ := pem.Decode([]byte(resp.CertificatePEM))
	if block == nil {
		t.Fatal("Failed to decode PEM")
	}

	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatalf("Failed to parse certificate: %v", err)
	}

	if cert.Subject.CommonName != "example.com" {
		t.Errorf("CommonName = %s, want example.com", cert.Subject.CommonName)
	}

	// Check SANs include both domain and wildcard
	foundDomain, foundWildcard := false, false
	for _, san := range cert.DNSNames {
		if san == "example.com" {
			foundDomain = true
		}
		if san == "*.example.com" {
			foundWildcard = true
		}
	}
	if !foundDomain {
		t.Error("Missing SAN: example.com")
	}
	if !foundWildcard {
		t.Error("Missing SAN: *.example.com")
	}
}

// TestSignCertificate_CacheHit tests certificate caching.
func TestSignCertificate_CacheHit(t *testing.T) {
	server, _ := NewMockGRPCServer()

	resp1, _ := server.SignCertificate(context.Background(), "cached.com", nil)
	resp2, _ := server.SignCertificate(context.Background(), "cached.com", nil)

	if resp1.SerialNumber != resp2.SerialNumber {
		t.Error("Second call should return cached certificate")
	}
}

// TestSignCertificate_InvalidDomain tests empty domain.
func TestSignCertificate_InvalidDomain(t *testing.T) {
	server, _ := NewMockGRPCServer()

	_, err := server.SignCertificate(context.Background(), "", nil)
	if err == nil {
		t.Error("Should return error for empty domain")
	}
}

// ============================================================================
// RevokeCertificate Tests
// ============================================================================

// TestRevokeCertificate_Success tests successful revocation.
func TestRevokeCertificate_Success(t *testing.T) {
	server, _ := NewMockGRPCServer()

	// First issue a certificate
	signResp, _ := server.SignCertificate(context.Background(), "revoke-test.com", nil)

	// Revoke it
	revokeResp, err := server.RevokeCertificate(context.Background(), signResp.SerialNumber, "compromised", "admin", "admin")
	if err != nil {
		t.Fatalf("RevokeCertificate failed: %v", err)
	}

	if !revokeResp.Success {
		t.Error("Success = false, want true")
	}
	if revokeResp.CRLUpdatedAt.IsZero() {
		t.Error("CRLUpdatedAt should be set")
	}
}

// TestRevokeCertificate_NotFound tests revoking non-existent cert.
func TestRevokeCertificate_NotFound(t *testing.T) {
	server, _ := NewMockGRPCServer()

	_, err := server.RevokeCertificate(context.Background(), "nonexistent", "compromised", "admin", "admin")
	if err == nil {
		t.Error("Should return error for non-existent certificate")
	}
}

// TestRevokeCertificate_AlreadyRevoked tests double revocation.
func TestRevokeCertificate_AlreadyRevoked(t *testing.T) {
	server, _ := NewMockGRPCServer()

	signResp, _ := server.SignCertificate(context.Background(), "double-revoke.com", nil)
	server.RevokeCertificate(context.Background(), signResp.SerialNumber, "compromised", "admin", "admin")

	_, err := server.RevokeCertificate(context.Background(), signResp.SerialNumber, "compromised", "admin", "admin")
	if err == nil {
		t.Error("Should return error for already revoked certificate")
	}
}

// TestRevokeCertificate_InvalidReason tests invalid reason.
func TestRevokeCertificate_InvalidReason(t *testing.T) {
	server, _ := NewMockGRPCServer()

	signResp, _ := server.SignCertificate(context.Background(), "bad-reason.com", nil)

	_, err := server.RevokeCertificate(context.Background(), signResp.SerialNumber, "invalid-reason", "admin", "admin")
	if err == nil {
		t.Error("Should return error for invalid reason")
	}
}

// TestRevokeCertificate_PermissionDenied tests non-admin revocation.
func TestRevokeCertificate_PermissionDenied(t *testing.T) {
	server, _ := NewMockGRPCServer()

	signResp, _ := server.SignCertificate(context.Background(), "permission-test.com", nil)

	_, err := server.RevokeCertificate(context.Background(), signResp.SerialNumber, "compromised", "viewer", "viewer")
	if err == nil {
		t.Error("Should return error for non-admin role")
	}
}

// ============================================================================
// CheckRevocationStatus Tests
// ============================================================================

// TestCheckRevocationStatus_NotRevoked tests non-revoked certificate.
func TestCheckRevocationStatus_NotRevoked(t *testing.T) {
	server, _ := NewMockGRPCServer()

	signResp, _ := server.SignCertificate(context.Background(), "not-revoked.com", nil)

	status, err := server.CheckRevocationStatus(context.Background(), signResp.SerialNumber)
	if err != nil {
		t.Fatalf("CheckRevocationStatus failed: %v", err)
	}

	if status.IsRevoked {
		t.Error("IsRevoked = true, want false")
	}
}

// TestCheckRevocationStatus_Revoked tests revoked certificate.
func TestCheckRevocationStatus_Revoked(t *testing.T) {
	server, _ := NewMockGRPCServer()

	signResp, _ := server.SignCertificate(context.Background(), "is-revoked.com", nil)
	server.RevokeCertificate(context.Background(), signResp.SerialNumber, "compromised", "admin", "admin")

	status, err := server.CheckRevocationStatus(context.Background(), signResp.SerialNumber)
	if err != nil {
		t.Fatalf("CheckRevocationStatus failed: %v", err)
	}

	if !status.IsRevoked {
		t.Error("IsRevoked = false, want true")
	}
	if status.RevocationReason != "compromised" {
		t.Errorf("Reason = %s, want compromised", status.RevocationReason)
	}
}

// ============================================================================
// ListIssuedCertificates Tests
// ============================================================================

// TestListIssuedCertificates_All tests listing all certs.
func TestListIssuedCertificates_All(t *testing.T) {
	server, _ := NewMockGRPCServer()

	// Issue some certificates
	for i := 0; i < 10; i++ {
		server.SignCertificate(context.Background(), fmt.Sprintf("domain%d.com", i), nil)
	}

	resp, err := server.ListIssuedCertificates(context.Background(), "", 100, 0)
	if err != nil {
		t.Fatalf("ListIssuedCertificates failed: %v", err)
	}

	if resp.TotalCount != 10 {
		t.Errorf("TotalCount = %d, want 10", resp.TotalCount)
	}
	if len(resp.Certificates) != 10 {
		t.Errorf("Got %d certificates, want 10", len(resp.Certificates))
	}
}

// TestListIssuedCertificates_Pagination tests pagination.
func TestListIssuedCertificates_Pagination(t *testing.T) {
	server, _ := NewMockGRPCServer()

	for i := 0; i < 25; i++ {
		server.SignCertificate(context.Background(), fmt.Sprintf("paged%d.com", i), nil)
	}

	// First page
	resp1, _ := server.ListIssuedCertificates(context.Background(), "", 10, 0)
	if len(resp1.Certificates) != 10 {
		t.Errorf("First page: got %d certs, want 10", len(resp1.Certificates))
	}
	if resp1.TotalCount != 25 {
		t.Errorf("TotalCount = %d, want 25", resp1.TotalCount)
	}

	// Second page
	resp2, _ := server.ListIssuedCertificates(context.Background(), "", 10, 10)
	if len(resp2.Certificates) != 10 {
		t.Errorf("Second page: got %d certs, want 10", len(resp2.Certificates))
	}

	// Third page (partial)
	resp3, _ := server.ListIssuedCertificates(context.Background(), "", 10, 20)
	if len(resp3.Certificates) != 5 {
		t.Errorf("Third page: got %d certs, want 5", len(resp3.Certificates))
	}
}

// ============================================================================
// GetCertificateDetails Tests
// ============================================================================

// TestGetCertificateDetails_Success tests successful detail retrieval.
func TestGetCertificateDetails_Success(t *testing.T) {
	server, _ := NewMockGRPCServer()

	signResp, _ := server.SignCertificate(context.Background(), "details.com", []string{"www.details.com"})

	details, err := server.GetCertificateDetails(context.Background(), signResp.SerialNumber)
	if err != nil {
		t.Fatalf("GetCertificateDetails failed: %v", err)
	}

	if details.CommonName != "details.com" {
		t.Errorf("CommonName = %s, want details.com", details.CommonName)
	}
	if len(details.SubjectAltNames) < 2 {
		t.Errorf("Expected at least 2 SANs, got %d", len(details.SubjectAltNames))
	}
	if details.CertificatePEM == "" {
		t.Error("CertificatePEM should not be empty")
	}
}

// TestGetCertificateDetails_NotFound tests non-existent cert.
func TestGetCertificateDetails_NotFound(t *testing.T) {
	server, _ := NewMockGRPCServer()

	_, err := server.GetCertificateDetails(context.Background(), "nonexistent")
	if err == nil {
		t.Error("Should return error for non-existent certificate")
	}
}

// ============================================================================
// Authentication Tests
// ============================================================================

// TestAuthentication_ValidAPIKey tests valid API key.
func TestAuthentication_ValidAPIKey(t *testing.T) {
	server, _ := NewMockGRPCServer()

	role, err := server.Authenticate("admin-key-12345")
	if err != nil {
		t.Fatalf("Authentication failed: %v", err)
	}

	if role != "admin" {
		t.Errorf("Role = %s, want admin", role)
	}
}

// TestAuthentication_InvalidAPIKey tests invalid API key.
func TestAuthentication_InvalidAPIKey(t *testing.T) {
	server, _ := NewMockGRPCServer()

	_, err := server.Authenticate("invalid-key")
	if err == nil {
		t.Error("Should return error for invalid API key")
	}
}

// TestAuthentication_MissingAPIKey tests missing API key.
func TestAuthentication_MissingAPIKey(t *testing.T) {
	server, _ := NewMockGRPCServer()

	_, err := server.Authenticate("")
	if err == nil {
		t.Error("Should return error for missing API key")
	}
}

// ============================================================================
// Rate Limiting Tests
// ============================================================================

// TestRateLimit_SignCertificate tests rate limiting.
func TestRateLimit_SignCertificate(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping rate limit test in short mode")
	}

	server, _ := NewMockGRPCServer()

	// Exhaust rate limit
	for i := 0; i < 100; i++ {
		_, err := server.SignCertificate(context.Background(), fmt.Sprintf("rate%d.com", i), nil)
		if err != nil {
			t.Fatalf("Request %d failed unexpectedly: %v", i, err)
		}
	}

	// Next request should fail
	_, err := server.SignCertificate(context.Background(), "rate-exceeded.com", nil)
	if err == nil {
		t.Error("Should return rate limit error")
	}
}

// ============================================================================
// Concurrent Tests
// ============================================================================

// TestConcurrentSignCertificate tests concurrent signing.
func TestConcurrentSignCertificate(t *testing.T) {
	server, _ := NewMockGRPCServer()

	var wg sync.WaitGroup
	numGoroutines := 20
	wg.Add(numGoroutines)

	for i := 0; i < numGoroutines; i++ {
		go func(n int) {
			defer wg.Done()
			_, err := server.SignCertificate(context.Background(), fmt.Sprintf("concurrent%d.com", n), nil)
			if err != nil {
				t.Errorf("Concurrent sign failed: %v", err)
			}
		}(i)
	}

	wg.Wait()
}
