// Package tests provides comprehensive testing for the Certificate Manager.
// This file tests the HTTP distribution server endpoints.
package tests

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"
)

// ============================================================================
// Test Types
// ============================================================================

// MockHTTPServer provides a mock HTTP distribution server for testing.
type MockHTTPServer struct {
	caCert       *x509.Certificate
	caCertPEM    []byte
	caCertDER    []byte
	crlPEM       []byte
	downloads    []DownloadRecord
	baseURL      string
	proxyAddress string
	mu           sync.Mutex
}

// DownloadRecord tracks a download event.
type DownloadRecord struct {
	DeviceIP  string
	Format    string
	Timestamp time.Time
}

// NewMockHTTPServer creates a new mock HTTP server.
func NewMockHTTPServer() (*MockHTTPServer, error) {
	// Generate test CA
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

	// Generate test CRL
	crlTemplate := &x509.RevocationList{
		Number:     big.NewInt(1),
		ThisUpdate: time.Now(),
		NextUpdate: time.Now().Add(7 * 24 * time.Hour),
	}
	crlDER, _ := x509.CreateRevocationList(rand.Reader, crlTemplate, caCert, caKey)
	crlPEM := pem.EncodeToMemory(&pem.Block{Type: "X509 CRL", Bytes: crlDER})

	return &MockHTTPServer{
		caCert:       caCert,
		caCertPEM:    caCertPEM,
		caCertDER:    caCertDER,
		crlPEM:       crlPEM,
		downloads:    make([]DownloadRecord, 0),
		baseURL:      "http://192.168.1.1",
		proxyAddress: "192.168.1.2:3129",
	}, nil
}

// Handler returns the HTTP handler for the mock server.
func (s *MockHTTPServer) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/ca.crt", s.handleCACrt)
	mux.HandleFunc("/ca.der", s.handleCADer)
	mux.HandleFunc("/crl.pem", s.handleCRL)
	mux.HandleFunc("/install-ca.sh", s.handleLinuxScript)
	mux.HandleFunc("/install-ca.ps1", s.handleWindowsScript)
	mux.HandleFunc("/install-ca.pkg", s.handleMacOSPackage)
	mux.HandleFunc("/install-ca.mobileconfig", s.handleiOSProfile)
	mux.HandleFunc("/trust-guide.html", s.handleTrustGuide)
	mux.HandleFunc("/ca-qr-code.png", s.handleQRCode)
	mux.HandleFunc("/wpad.dat", s.handleWPAD)
	mux.HandleFunc("/health", s.handleHealth)
	return s.addSecurityHeaders(mux)
}

func (s *MockHTTPServer) addSecurityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("Content-Security-Policy", "default-src 'self'")
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Methods", "GET, OPTIONS")
		next.ServeHTTP(w, r)
	})
}

func (s *MockHTTPServer) recordDownload(ip, format string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.downloads = append(s.downloads, DownloadRecord{
		DeviceIP:  ip,
		Format:    format,
		Timestamp: time.Now(),
	})
}

func (s *MockHTTPServer) handleCACrt(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		w.Header().Set("Allow", "GET")
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	s.recordDownload(r.RemoteAddr, "pem")
	w.Header().Set("Content-Type", "application/x-x509-ca-cert")
	w.Header().Set("Content-Disposition", "attachment; filename=safeops-root-ca.crt")
	w.Write(s.caCertPEM)
}

func (s *MockHTTPServer) handleCADer(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		w.Header().Set("Allow", "GET")
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	s.recordDownload(r.RemoteAddr, "der")
	w.Header().Set("Content-Type", "application/x-x509-ca-cert")
	w.Header().Set("Content-Disposition", "attachment; filename=safeops-root-ca.der")
	w.Write(s.caCertDER)
}

func (s *MockHTTPServer) handleCRL(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/pkix-crl")
	w.Write(s.crlPEM)
}

func (s *MockHTTPServer) handleLinuxScript(w http.ResponseWriter, r *http.Request) {
	script := fmt.Sprintf(`#!/bin/bash
# SafeOps CA Installation Script for Linux
set -e

CA_URL="%s/ca.crt"
CA_FILE="/usr/local/share/ca-certificates/safeops-root-ca.crt"

echo "Downloading SafeOps Root CA..."
curl -sSL "$CA_URL" -o "$CA_FILE"

echo "Updating CA certificates..."
update-ca-certificates

echo "SafeOps Root CA installed successfully!"
`, s.baseURL)

	w.Header().Set("Content-Type", "application/x-sh")
	w.Header().Set("Content-Disposition", "attachment; filename=install-ca.sh")
	w.Write([]byte(script))
}

func (s *MockHTTPServer) handleWindowsScript(w http.ResponseWriter, r *http.Request) {
	script := fmt.Sprintf(`# SafeOps CA Installation Script for Windows
# Run as Administrator

$CAUrl = "%s/ca.crt"
$CAPath = "$env:TEMP\safeops-root-ca.crt"

Write-Host "Downloading SafeOps Root CA..."
Invoke-WebRequest -Uri $CAUrl -OutFile $CAPath

Write-Host "Installing certificate..."
Import-Certificate -FilePath $CAPath -CertStoreLocation Cert:\LocalMachine\Root

Write-Host "SafeOps Root CA installed successfully!"
Remove-Item $CAPath
`, s.baseURL)

	w.Header().Set("Content-Type", "application/x-powershell")
	w.Header().Set("Content-Disposition", "attachment; filename=install-ca.ps1")
	w.Write([]byte(script))
}

func (s *MockHTTPServer) handleMacOSPackage(w http.ResponseWriter, r *http.Request) {
	// Simplified package data for testing
	script := fmt.Sprintf(`#!/bin/bash
# SafeOps CA Installation for macOS
security add-trusted-cert -d -r trustRoot -k /Library/Keychains/System.keychain %s/ca.crt
`, s.baseURL)

	w.Header().Set("Content-Type", "application/x-apple-aspen-config")
	w.Header().Set("Content-Disposition", "attachment; filename=install-ca.pkg")
	w.Write([]byte(script))
}

func (s *MockHTTPServer) handleiOSProfile(w http.ResponseWriter, r *http.Request) {
	profile := fmt.Sprintf(`<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>PayloadContent</key>
    <array>
        <dict>
            <key>PayloadCertificateFileName</key>
            <string>safeops-root-ca.crt</string>
            <key>PayloadContent</key>
            <data>%s</data>
            <key>PayloadDescription</key>
            <string>SafeOps Root CA Certificate</string>
            <key>PayloadDisplayName</key>
            <string>SafeOps Root CA</string>
            <key>PayloadIdentifier</key>
            <string>com.safeops.ca.rootcert</string>
            <key>PayloadType</key>
            <string>com.apple.security.root</string>
            <key>PayloadUUID</key>
            <string>A1B2C3D4-E5F6-7890-ABCD-EF1234567890</string>
            <key>PayloadVersion</key>
            <integer>1</integer>
        </dict>
    </array>
    <key>PayloadDisplayName</key>
    <string>SafeOps Network Trust Profile</string>
    <key>PayloadIdentifier</key>
    <string>com.safeops.trust-profile</string>
    <key>PayloadType</key>
    <string>Configuration</string>
    <key>PayloadUUID</key>
    <string>F0E1D2C3-B4A5-6789-0123-456789ABCDEF</string>
    <key>PayloadVersion</key>
    <integer>1</integer>
</dict>
</plist>`, "BASE64_CERT_DATA")

	w.Header().Set("Content-Type", "application/x-apple-aspen-config")
	w.Header().Set("Content-Disposition", "attachment; filename=SafeOps-Trust.mobileconfig")
	w.Write([]byte(profile))
}

func (s *MockHTTPServer) handleTrustGuide(w http.ResponseWriter, r *http.Request) {
	html := fmt.Sprintf(`<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>SafeOps CA Trust Guide</title>
    <style>
        body { font-family: Arial, sans-serif; max-width: 800px; margin: 0 auto; padding: 20px; }
        h1 { color: #2c3e50; }
        .platform { margin: 20px 0; padding: 15px; border: 1px solid #ddd; border-radius: 5px; }
        .qr-code { text-align: center; margin: 20px 0; }
        img { max-width: 256px; }
        @media (max-width: 600px) { body { padding: 10px; } }
    </style>
</head>
<body>
    <h1>SafeOps Network Trust Configuration</h1>
    
    <div class="qr-code">
        <h2>Scan to Download CA Certificate</h2>
        <img src="/ca-qr-code.png" alt="QR Code for CA Download">
        <p><a href="/ca.crt">Direct Download</a></p>
    </div>

    <div class="platform" id="windows">
        <h2>Windows</h2>
        <p>Download and run <a href="/install-ca.ps1">install-ca.ps1</a> as Administrator.</p>
    </div>

    <div class="platform" id="macos">
        <h2>macOS</h2>
        <p>Download <a href="/ca.crt">ca.crt</a> and add to Keychain Access.</p>
    </div>

    <div class="platform" id="linux">
        <h2>Linux</h2>
        <p>Run: <code>curl -sSL %s/install-ca.sh | sudo bash</code></p>
    </div>

    <div class="platform" id="firefox">
        <h2>Firefox</h2>
        <p>Import <a href="/ca.crt">ca.crt</a> via Preferences > Privacy & Security > Certificates.</p>
    </div>

    <div class="platform" id="ios">
        <h2>iOS / iPadOS</h2>
        <p>Download <a href="/install-ca.mobileconfig">SafeOps-Trust.mobileconfig</a> and install via Settings.</p>
    </div>

    <div class="platform" id="android">
        <h2>Android</h2>
        <p>Download <a href="/ca.crt">ca.crt</a> and install via Settings > Security > Encryption & Credentials.</p>
    </div>
</body>
</html>`, s.baseURL)

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Write([]byte(html))
}

func (s *MockHTTPServer) handleQRCode(w http.ResponseWriter, r *http.Request) {
	// PNG header (first 8 bytes of a valid PNG)
	pngHeader := []byte{0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A}
	// Minimal valid PNG (1x1 pixel)
	pngData := append(pngHeader, []byte{
		0x00, 0x00, 0x00, 0x0D, 0x49, 0x48, 0x44, 0x52, 0x00, 0x00, 0x01, 0x00,
		0x00, 0x00, 0x01, 0x00, 0x08, 0x02, 0x00, 0x00, 0x00, 0x90, 0x77, 0x53,
	}...)

	w.Header().Set("Content-Type", "image/png")
	w.Write(pngData)
}

func (s *MockHTTPServer) handleWPAD(w http.ResponseWriter, r *http.Request) {
	pac := fmt.Sprintf(`function FindProxyForURL(url, host) {
    // Bypass proxy for localhost
    if (host === "localhost" || host === "127.0.0.1") {
        return "DIRECT";
    }
    
    // Bypass proxy for internal networks
    if (isInNet(host, "192.168.0.0", "255.255.0.0") ||
        isInNet(host, "10.0.0.0", "255.0.0.0") ||
        dnsDomainIs(host, ".local")) {
        return "DIRECT";
    }
    
    // Use SafeOps TLS Proxy for all other traffic
    return "PROXY %s";
}
`, s.proxyAddress)

	w.Header().Set("Content-Type", "application/x-ns-proxy-autoconfig")
	w.Write([]byte(pac))
}

func (s *MockHTTPServer) handleHealth(w http.ResponseWriter, r *http.Request) {
	health := `{
    "status": "healthy",
    "timestamp": "` + time.Now().Format(time.RFC3339) + `",
    "components": {
        "ca_certificate": "ok",
        "http_server": "ok",
        "crl": "ok"
    }
}`
	w.Header().Set("Content-Type", "application/json")
	w.Write([]byte(health))
}

// GetDownloads returns recorded downloads.
func (s *MockHTTPServer) GetDownloads() []DownloadRecord {
	s.mu.Lock()
	defer s.mu.Unlock()
	result := make([]DownloadRecord, len(s.downloads))
	copy(result, s.downloads)
	return result
}

// ============================================================================
// CA Certificate Download Tests
// ============================================================================

// TestDownloadCA_PEM tests PEM certificate download.
func TestDownloadCA_PEM(t *testing.T) {
	server, _ := NewMockHTTPServer()
	ts := httptest.NewServer(server.Handler())
	defer ts.Close()

	resp, err := http.Get(ts.URL + "/ca.crt")
	if err != nil {
		t.Fatalf("Request failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Errorf("Status = %d, want 200", resp.StatusCode)
	}

	contentType := resp.Header.Get("Content-Type")
	if contentType != "application/x-x509-ca-cert" {
		t.Errorf("Content-Type = %s, want application/x-x509-ca-cert", contentType)
	}

	disposition := resp.Header.Get("Content-Disposition")
	if !strings.Contains(disposition, "filename=") {
		t.Error("Content-Disposition should include filename")
	}

	body, _ := io.ReadAll(resp.Body)
	block, _ := pem.Decode(body)
	if block == nil {
		t.Fatal("Response is not valid PEM")
	}

	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatalf("Failed to parse certificate: %v", err)
	}

	if cert.Subject.CommonName != "SafeOps Root CA" {
		t.Errorf("CN = %s, want SafeOps Root CA", cert.Subject.CommonName)
	}
}

// TestDownloadCA_DER tests DER certificate download.
func TestDownloadCA_DER(t *testing.T) {
	server, _ := NewMockHTTPServer()
	ts := httptest.NewServer(server.Handler())
	defer ts.Close()

	resp, err := http.Get(ts.URL + "/ca.der")
	if err != nil {
		t.Fatalf("Request failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Errorf("Status = %d, want 200", resp.StatusCode)
	}

	body, _ := io.ReadAll(resp.Body)
	cert, err := x509.ParseCertificate(body)
	if err != nil {
		t.Fatalf("Failed to parse DER certificate: %v", err)
	}

	if cert.Subject.CommonName != "SafeOps Root CA" {
		t.Errorf("CN = %s, want SafeOps Root CA", cert.Subject.CommonName)
	}
}

// TestDownloadCA_DownloadTracking tests download recording.
func TestDownloadCA_DownloadTracking(t *testing.T) {
	server, _ := NewMockHTTPServer()
	ts := httptest.NewServer(server.Handler())
	defer ts.Close()

	http.Get(ts.URL + "/ca.crt")
	http.Get(ts.URL + "/ca.der")

	downloads := server.GetDownloads()
	if len(downloads) != 2 {
		t.Errorf("Expected 2 downloads, got %d", len(downloads))
	}

	if downloads[0].Format != "pem" {
		t.Errorf("First download format = %s, want pem", downloads[0].Format)
	}
	if downloads[1].Format != "der" {
		t.Errorf("Second download format = %s, want der", downloads[1].Format)
	}
}

// ============================================================================
// Install Script Download Tests
// ============================================================================

// TestDownloadInstallScript_Linux tests Linux script.
func TestDownloadInstallScript_Linux(t *testing.T) {
	server, _ := NewMockHTTPServer()
	ts := httptest.NewServer(server.Handler())
	defer ts.Close()

	resp, err := http.Get(ts.URL + "/install-ca.sh")
	if err != nil {
		t.Fatalf("Request failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Errorf("Status = %d, want 200", resp.StatusCode)
	}

	contentType := resp.Header.Get("Content-Type")
	if contentType != "application/x-sh" {
		t.Errorf("Content-Type = %s, want application/x-sh", contentType)
	}

	body, _ := io.ReadAll(resp.Body)
	script := string(body)

	if !strings.HasPrefix(script, "#!/bin/bash") {
		t.Error("Script should start with shebang")
	}
	if !strings.Contains(script, "update-ca-certificates") {
		t.Error("Script should contain update-ca-certificates command")
	}
	if !strings.Contains(script, "/ca.crt") {
		t.Error("Script should contain CA download URL")
	}
}

// TestDownloadInstallScript_Windows tests Windows script.
func TestDownloadInstallScript_Windows(t *testing.T) {
	server, _ := NewMockHTTPServer()
	ts := httptest.NewServer(server.Handler())
	defer ts.Close()

	resp, err := http.Get(ts.URL + "/install-ca.ps1")
	if err != nil {
		t.Fatalf("Request failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Errorf("Status = %d, want 200", resp.StatusCode)
	}

	contentType := resp.Header.Get("Content-Type")
	if contentType != "application/x-powershell" {
		t.Errorf("Content-Type = %s, want application/x-powershell", contentType)
	}

	body, _ := io.ReadAll(resp.Body)
	script := string(body)

	if !strings.Contains(script, "Import-Certificate") {
		t.Error("Script should contain Import-Certificate cmdlet")
	}
	if !strings.Contains(script, "Cert:\\LocalMachine\\Root") {
		t.Error("Script should target LocalMachine\\Root store")
	}
}

// TestDownloadInstallScript_iOS tests iOS profile.
func TestDownloadInstallScript_iOS(t *testing.T) {
	server, _ := NewMockHTTPServer()
	ts := httptest.NewServer(server.Handler())
	defer ts.Close()

	resp, err := http.Get(ts.URL + "/install-ca.mobileconfig")
	if err != nil {
		t.Fatalf("Request failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Errorf("Status = %d, want 200", resp.StatusCode)
	}

	contentType := resp.Header.Get("Content-Type")
	if contentType != "application/x-apple-aspen-config" {
		t.Errorf("Content-Type = %s, want application/x-apple-aspen-config", contentType)
	}

	body, _ := io.ReadAll(resp.Body)
	profile := string(body)

	if !strings.Contains(profile, "<?xml") {
		t.Error("Profile should be XML")
	}
	if !strings.Contains(profile, "PayloadType") {
		t.Error("Profile should contain PayloadType")
	}
	if !strings.Contains(profile, "Configuration") {
		t.Error("Profile PayloadType should be Configuration")
	}
	if !strings.Contains(profile, "PayloadUUID") {
		t.Error("Profile should contain PayloadUUID")
	}
}

// ============================================================================
// CRL Download Tests
// ============================================================================

// TestDownloadCRL tests CRL download.
func TestDownloadCRL(t *testing.T) {
	server, _ := NewMockHTTPServer()
	ts := httptest.NewServer(server.Handler())
	defer ts.Close()

	resp, err := http.Get(ts.URL + "/crl.pem")
	if err != nil {
		t.Fatalf("Request failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Errorf("Status = %d, want 200", resp.StatusCode)
	}

	contentType := resp.Header.Get("Content-Type")
	if contentType != "application/pkix-crl" {
		t.Errorf("Content-Type = %s, want application/pkix-crl", contentType)
	}

	body, _ := io.ReadAll(resp.Body)
	block, _ := pem.Decode(body)
	if block == nil {
		t.Fatal("Response is not valid PEM")
	}

	if block.Type != "X509 CRL" {
		t.Errorf("PEM type = %s, want X509 CRL", block.Type)
	}
}

// ============================================================================
// Trust Guide Tests
// ============================================================================

// TestDownloadTrustGuide tests trust guide HTML.
func TestDownloadTrustGuide(t *testing.T) {
	server, _ := NewMockHTTPServer()
	ts := httptest.NewServer(server.Handler())
	defer ts.Close()

	resp, err := http.Get(ts.URL + "/trust-guide.html")
	if err != nil {
		t.Fatalf("Request failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Errorf("Status = %d, want 200", resp.StatusCode)
	}

	contentType := resp.Header.Get("Content-Type")
	if !strings.Contains(contentType, "text/html") {
		t.Errorf("Content-Type = %s, want text/html", contentType)
	}

	body, _ := io.ReadAll(resp.Body)
	html := string(body)

	if !strings.Contains(html, "<!DOCTYPE html>") {
		t.Error("Should be valid HTML5 document")
	}
	if !strings.Contains(html, "viewport") {
		t.Error("Should include viewport meta tag for mobile")
	}

	// Check platform sections
	platforms := []string{"windows", "macos", "linux", "firefox", "ios", "android"}
	for _, p := range platforms {
		if !strings.Contains(html, fmt.Sprintf(`id="%s"`, p)) {
			t.Errorf("Missing platform section: %s", p)
		}
	}

	if !strings.Contains(html, "ca-qr-code.png") {
		t.Error("Should include QR code image")
	}
}

// ============================================================================
// QR Code Tests
// ============================================================================

// TestDownloadQRCode tests QR code PNG download.
func TestDownloadQRCode(t *testing.T) {
	server, _ := NewMockHTTPServer()
	ts := httptest.NewServer(server.Handler())
	defer ts.Close()

	resp, err := http.Get(ts.URL + "/ca-qr-code.png")
	if err != nil {
		t.Fatalf("Request failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Errorf("Status = %d, want 200", resp.StatusCode)
	}

	contentType := resp.Header.Get("Content-Type")
	if contentType != "image/png" {
		t.Errorf("Content-Type = %s, want image/png", contentType)
	}

	body, _ := io.ReadAll(resp.Body)

	// Check PNG signature
	pngHeader := []byte{0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A}
	if len(body) < 8 || !bytes.Equal(body[:8], pngHeader) {
		t.Error("Response is not a valid PNG file")
	}
}

// ============================================================================
// WPAD Tests
// ============================================================================

// TestDownloadWPAD tests WPAD PAC file.
func TestDownloadWPAD(t *testing.T) {
	server, _ := NewMockHTTPServer()
	ts := httptest.NewServer(server.Handler())
	defer ts.Close()

	resp, err := http.Get(ts.URL + "/wpad.dat")
	if err != nil {
		t.Fatalf("Request failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Errorf("Status = %d, want 200", resp.StatusCode)
	}

	contentType := resp.Header.Get("Content-Type")
	if contentType != "application/x-ns-proxy-autoconfig" {
		t.Errorf("Content-Type = %s, want application/x-ns-proxy-autoconfig", contentType)
	}

	body, _ := io.ReadAll(resp.Body)
	pac := string(body)

	if !strings.Contains(pac, "FindProxyForURL") {
		t.Error("PAC file should define FindProxyForURL function")
	}
	if !strings.Contains(pac, "PROXY") {
		t.Error("PAC file should return PROXY directive")
	}
	if !strings.Contains(pac, "192.168.1.2:3129") {
		t.Error("PAC file should contain proxy address")
	}
	if !strings.Contains(pac, "DIRECT") {
		t.Error("PAC file should have DIRECT bypass rules")
	}
}

// ============================================================================
// Health Check Tests
// ============================================================================

// TestHealthCheck tests health endpoint.
func TestHealthCheck(t *testing.T) {
	server, _ := NewMockHTTPServer()
	ts := httptest.NewServer(server.Handler())
	defer ts.Close()

	resp, err := http.Get(ts.URL + "/health")
	if err != nil {
		t.Fatalf("Request failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Errorf("Status = %d, want 200", resp.StatusCode)
	}

	contentType := resp.Header.Get("Content-Type")
	if contentType != "application/json" {
		t.Errorf("Content-Type = %s, want application/json", contentType)
	}

	body, _ := io.ReadAll(resp.Body)
	health := string(body)

	if !strings.Contains(health, `"status"`) {
		t.Error("Health response should contain status field")
	}
	if !strings.Contains(health, `"healthy"`) {
		t.Error("Health status should be healthy")
	}
	if !strings.Contains(health, `"components"`) {
		t.Error("Health response should contain components")
	}
}

// ============================================================================
// Error Handling Tests
// ============================================================================

// TestNotFound tests 404 response.
func TestHTTPNotFound(t *testing.T) {
	server, _ := NewMockHTTPServer()
	ts := httptest.NewServer(server.Handler())
	defer ts.Close()

	resp, err := http.Get(ts.URL + "/nonexistent")
	if err != nil {
		t.Fatalf("Request failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusNotFound {
		t.Errorf("Status = %d, want 404", resp.StatusCode)
	}
}

// TestMethodNotAllowed tests 405 response.
func TestMethodNotAllowed(t *testing.T) {
	server, _ := NewMockHTTPServer()
	ts := httptest.NewServer(server.Handler())
	defer ts.Close()

	resp, err := http.Post(ts.URL+"/ca.crt", "text/plain", nil)
	if err != nil {
		t.Fatalf("Request failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusMethodNotAllowed {
		t.Errorf("Status = %d, want 405", resp.StatusCode)
	}

	allow := resp.Header.Get("Allow")
	if !strings.Contains(allow, "GET") {
		t.Error("Allow header should include GET")
	}
}

// ============================================================================
// Security Header Tests
// ============================================================================

// TestSecurityHeaders tests security headers.
func TestSecurityHeaders(t *testing.T) {
	server, _ := NewMockHTTPServer()
	ts := httptest.NewServer(server.Handler())
	defer ts.Close()

	resp, err := http.Get(ts.URL + "/ca.crt")
	if err != nil {
		t.Fatalf("Request failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.Header.Get("X-Content-Type-Options") != "nosniff" {
		t.Error("Missing X-Content-Type-Options: nosniff")
	}
	if resp.Header.Get("X-Frame-Options") != "DENY" {
		t.Error("Missing X-Frame-Options: DENY")
	}
	if resp.Header.Get("Content-Security-Policy") == "" {
		t.Error("Missing Content-Security-Policy header")
	}
}

// TestCORS tests CORS headers.
func TestCORS(t *testing.T) {
	server, _ := NewMockHTTPServer()
	ts := httptest.NewServer(server.Handler())
	defer ts.Close()

	resp, err := http.Get(ts.URL + "/ca.crt")
	if err != nil {
		t.Fatalf("Request failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.Header.Get("Access-Control-Allow-Origin") == "" {
		t.Error("Missing Access-Control-Allow-Origin header")
	}
	if resp.Header.Get("Access-Control-Allow-Methods") == "" {
		t.Error("Missing Access-Control-Allow-Methods header")
	}
}

// ============================================================================
// Concurrent Download Tests
// ============================================================================

// TestConcurrentDownloads tests concurrent request handling.
func TestConcurrentDownloads(t *testing.T) {
	server, _ := NewMockHTTPServer()
	ts := httptest.NewServer(server.Handler())
	defer ts.Close()

	var wg sync.WaitGroup
	numRequests := 50
	wg.Add(numRequests)

	errors := make(chan error, numRequests)

	for i := 0; i < numRequests; i++ {
		go func() {
			defer wg.Done()
			resp, err := http.Get(ts.URL + "/ca.crt")
			if err != nil {
				errors <- err
				return
			}
			defer resp.Body.Close()
			if resp.StatusCode != http.StatusOK {
				errors <- fmt.Errorf("status %d", resp.StatusCode)
			}
		}()
	}

	wg.Wait()
	close(errors)

	for err := range errors {
		t.Errorf("Concurrent request failed: %v", err)
	}

	downloads := server.GetDownloads()
	if len(downloads) != numRequests {
		t.Errorf("Expected %d downloads recorded, got %d", numRequests, len(downloads))
	}
}
