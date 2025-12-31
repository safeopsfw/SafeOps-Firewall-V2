// Package stepca provides certificate verification functionality
package stepca

import (
	"crypto/x509"
	"fmt"
)

// VerifyClientCertificate verifies that a client certificate was signed by our root CA
func (c *Client) VerifyClientCertificate(clientCert *x509.Certificate) error {
	c.mu.RLock()
	rootCA := c.rootCA
	c.mu.RUnlock()

	if rootCA == nil {
		return fmt.Errorf("root CA not loaded")
	}

	if clientCert == nil {
		return fmt.Errorf("client certificate is nil")
	}

	// Create certificate pool with our root CA
	roots := x509.NewCertPool()
	roots.AddCert(rootCA)

	// Verify the certificate chain
	opts := x509.VerifyOptions{
		Roots: roots,
	}

	_, err := clientCert.Verify(opts)
	if err != nil {
		return fmt.Errorf("certificate verification failed: %w", err)
	}

	return nil
}

// VerifyCertificateBytes verifies a certificate from raw DER bytes
func (c *Client) VerifyCertificateBytes(certDER []byte) error {
	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		return fmt.Errorf("failed to parse certificate: %w", err)
	}

	return c.VerifyClientCertificate(cert)
}

// IsCertificateFromOurCA checks if a certificate was issued by our CA
// This is a quick check that doesn't do full chain validation
func (c *Client) IsCertificateFromOurCA(clientCert *x509.Certificate) bool {
	c.mu.RLock()
	rootCA := c.rootCA
	c.mu.RUnlock()

	if rootCA == nil || clientCert == nil {
		return false
	}

	// Check if the issuer matches our root CA's subject
	return clientCert.Issuer.CommonName == rootCA.Subject.CommonName
}

// GetVerificationResult returns detailed verification information
func (c *Client) GetVerificationResult(clientCert *x509.Certificate) *VerificationResult {
	result := &VerificationResult{
		Verified: false,
	}

	if clientCert == nil {
		result.Error = "no client certificate provided"
		return result
	}

	result.Subject = clientCert.Subject.CommonName
	result.Issuer = clientCert.Issuer.CommonName
	result.SerialNumber = clientCert.SerialNumber.String()

	// Check if from our CA
	if !c.IsCertificateFromOurCA(clientCert) {
		result.Error = "certificate not issued by our CA"
		return result
	}

	// Full verification
	err := c.VerifyClientCertificate(clientCert)
	if err != nil {
		result.Error = err.Error()
		return result
	}

	result.Verified = true
	return result
}

// VerificationResult contains the result of certificate verification
type VerificationResult struct {
	Verified     bool   `json:"verified"`
	Subject      string `json:"subject,omitempty"`
	Issuer       string `json:"issuer,omitempty"`
	SerialNumber string `json:"serial_number,omitempty"`
	Error        string `json:"error,omitempty"`
}
