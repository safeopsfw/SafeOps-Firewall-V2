package integration

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"log"
	"math/big"
	"net/http"
	"os"
	"path/filepath"
	"time"
)

// StepCAClient manages communication with Step-CA for certificate generation
type StepCAClient struct {
	baseURL    string
	token      string
	httpClient *http.Client

	// Root CA certificate and key (generated once at startup)
	rootCACert       []byte
	rootCAKey        []byte
	rootCACertParsed *x509.Certificate
	rootCAKeyParsed  *ecdsa.PrivateKey
}

// CertificateResponse represents Step-CA certificate response
type CertificateResponse struct {
	Certificate string `json:"crt"`
	PrivateKey  string `json:"key"`
	CA          string `json:"ca"`
}

// CertificateRequest represents Step-CA certificate request
type CertificateRequest struct {
	CommonName string   `json:"commonName"`
	SANs       []string `json:"sans"`
	Duration   string   `json:"duration"`
}

// NewStepCAClient creates a new Step-CA API client
func NewStepCAClient(baseURL, token string) *StepCAClient {
	// Create HTTP client with TLS verification disabled (since Step-CA uses self-signed cert)
	httpClient := &http.Client{
		Timeout: 10 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: true,
			},
		},
	}

	return &StepCAClient{
		baseURL:    baseURL,
		token:      token,
		httpClient: httpClient,
	}
}

// GenerateCertificate requests a new certificate for a domain from Step-CA
func (c *StepCAClient) GenerateCertificate(domain string) (*CertificateResponse, error) {
	log.Printf("[Step-CA Client] Requesting certificate for domain: %s", domain)

	// For Phase 3B, we'll use Step-CA's ACME or certificate API
	// This is a simplified implementation - real Step-CA uses ACME protocol

	// Build request
	reqBody := CertificateRequest{
		CommonName: domain,
		SANs:       []string{domain, "*." + domain},
		Duration:   "24h",
	}

	jsonData, err := json.Marshal(reqBody)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal request: %w", err)
	}

	// Make request to Step-CA API (placeholder - actual endpoint depends on Step-CA setup)
	url := fmt.Sprintf("%s/1.0/sign", c.baseURL)

	req, err := http.NewRequest("POST", url, bytes.NewBuffer(jsonData))
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("Content-Type", "application/json")
	if c.token != "" {
		req.Header.Set("Authorization", "Bearer "+c.token)
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		log.Printf("[Step-CA Client] Request failed: %v", err)
		// Return stub certificate for Phase 3B testing
		return c.generateStubCertificate(domain), nil
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusCreated {
		bodyBytes, _ := io.ReadAll(resp.Body)
		log.Printf("[Step-CA Client] API error: %d - %s", resp.StatusCode, string(bodyBytes))
		// Return stub certificate
		return c.generateStubCertificate(domain), nil
	}

	// Parse response
	var certResp CertificateResponse
	if err := json.NewDecoder(resp.Body).Decode(&certResp); err != nil {
		log.Printf("[Step-CA Client] Failed to decode response: %v", err)
		return c.generateStubCertificate(domain), nil
	}

	log.Printf("[Step-CA Client] Certificate generated successfully for %s", domain)
	return &certResp, nil
}

// generateStubCertificate creates a self-signed certificate for testing
func (c *StepCAClient) generateStubCertificate(domain string) *CertificateResponse {
	log.Printf("[Step-CA Client] Generating self-signed certificate for %s", domain)

	// Generate ECDSA private key
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		log.Printf("[Step-CA Client] Key generation failed: %v", err)
		return &CertificateResponse{
			Certificate: "-----BEGIN CERTIFICATE-----\nFAILED\n-----END CERTIFICATE-----",
			PrivateKey:  "-----BEGIN PRIVATE KEY-----\nFAILED\n-----END PRIVATE KEY-----",
			CA:          "",
		}
	}

	// Create certificate template
	serialNumber, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	template := x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			Organization: []string{"SafeOps Network"},
			CommonName:   domain,
		},
		DNSNames:              []string{domain},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}

	// Self-sign the certificate
	certDER, err := x509.CreateCertificate(rand.Reader, &template, &template, &priv.PublicKey, priv)
	if err != nil {
		log.Printf("[Step-CA Client] Certificate creation failed: %v", err)
		return &CertificateResponse{
			Certificate: "-----BEGIN CERTIFICATE-----\nFAILED\n-----END CERTIFICATE-----",
			PrivateKey:  "-----BEGIN PRIVATE KEY-----\nFAILED\n-----END PRIVATE KEY-----",
			CA:          "",
		}
	}

	// Encode certificate to PEM
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})

	// Encode private key to PEM
	privBytes, err := x509.MarshalECPrivateKey(priv)
	if err != nil {
		log.Printf("[Step-CA Client] Key marshaling failed: %v", err)
		return &CertificateResponse{
			Certificate: string(certPEM),
			PrivateKey:  "-----BEGIN PRIVATE KEY-----\nFAILED\n-----END PRIVATE KEY-----",
			CA:          "",
		}
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: privBytes})

	log.Printf("[Step-CA Client] ✓ Self-signed certificate generated for %s", domain)

	return &CertificateResponse{
		Certificate: string(certPEM),
		PrivateKey:  string(keyPEM),
		CA:          string(certPEM), // Use same cert as CA for self-signed
	}
}

// GetRootCAFromStepCA retrieves the root CA certificate from Step-CA API (legacy method)
func (c *StepCAClient) GetRootCAFromStepCA() (string, error) {
	url := fmt.Sprintf("%s/roots.pem", c.baseURL)

	resp, err := c.httpClient.Get(url)
	if err != nil {
		return "", fmt.Errorf("failed to get root CA: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("failed to get root CA: status %d", resp.StatusCode)
	}

	bodyBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", fmt.Errorf("failed to read root CA: %w", err)
	}

	return string(bodyBytes), nil
}

// VerifyConnection tests connection to Step-CA
func (c *StepCAClient) VerifyConnection() error {
	url := fmt.Sprintf("%s/health", c.baseURL)

	resp, err := c.httpClient.Get(url)
	if err != nil {
		return fmt.Errorf("failed to connect to Step-CA: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("Step-CA health check failed: status %d", resp.StatusCode)
	}

	return nil
}

// GenerateRootCA generates a self-signed root CA certificate for SafeOps
// This CA will be used to sign all domain certificates for MITM inspection
func (c *StepCAClient) GenerateRootCA() error {
	log.Println("[Step-CA Client] Generating SafeOps Root CA...")

	// Generate CA private key (ECDSA P-256)
	caPriv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return fmt.Errorf("failed to generate CA key: %w", err)
	}

	// Create serial number for CA cert
	serialNumber, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return fmt.Errorf("failed to generate serial number: %w", err)
	}

	// Create root CA certificate template
	caTemplate := x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			Organization: []string{"SafeOps Network"},
			CommonName:   "SafeOps Root CA",
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(10 * 365 * 24 * time.Hour), // Valid for 10 years
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true, // This is a CA certificate!
		MaxPathLen:            2,
	}

	// Self-sign CA certificate
	caCertDER, err := x509.CreateCertificate(rand.Reader, &caTemplate, &caTemplate, &caPriv.PublicKey, caPriv)
	if err != nil {
		return fmt.Errorf("failed to create CA cert: %w", err)
	}

	// Encode CA certificate to PEM
	c.rootCACert = pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: caCertDER,
	})

	// Encode CA private key to PEM
	caPrivBytes, err := x509.MarshalECPrivateKey(caPriv)
	if err != nil {
		return fmt.Errorf("failed to marshal CA key: %w", err)
	}

	c.rootCAKey = pem.EncodeToMemory(&pem.Block{
		Type:  "EC PRIVATE KEY",
		Bytes: caPrivBytes,
	})

	// Parse for signing domain certs
	c.rootCACertParsed, err = x509.ParseCertificate(caCertDER)
	if err != nil {
		return fmt.Errorf("failed to parse CA cert: %w", err)
	}

	c.rootCAKeyParsed = caPriv

	log.Printf("[Step-CA Client] ✅ Root CA generated successfully")
	log.Printf("[Step-CA Client]    Subject: %s", c.rootCACertParsed.Subject.String())
	log.Printf("[Step-CA Client]    Valid: %s to %s", c.rootCACertParsed.NotBefore, c.rootCACertParsed.NotAfter)
	log.Printf("[Step-CA Client]    IsCA: %v, MaxPathLen: %d", c.rootCACertParsed.IsCA, c.rootCACertParsed.MaxPathLen)

	return nil
}

// GetRootCA returns the PEM-encoded root CA certificate
func (c *StepCAClient) GetRootCA() string {
	return string(c.rootCACert)
}

// SaveRootCAToFile saves the root CA certificate to a file
func (c *StepCAClient) SaveRootCAToFile(certPath string) error {
	// Create certs directory if it doesn't exist
	dir := filepath.Dir(certPath)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return fmt.Errorf("failed to create certs directory: %w", err)
	}

	if err := os.WriteFile(certPath, c.rootCACert, 0644); err != nil {
		return fmt.Errorf("failed to save CA cert: %w", err)
	}

	log.Printf("[Step-CA Client] ✅ Root CA saved to %s", certPath)
	return nil
}
