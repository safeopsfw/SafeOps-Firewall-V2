// Package device_tracking provides device CA installation tracking for the Certificate Manager.
package device_tracking

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"sync"
	"time"

	"certificate_manager/pkg/types"
)

// Detector performs CA installation detection on network devices
type Detector struct {
	tracker     *Tracker
	testCert    *tls.Certificate // Certificate signed by SafeOps CA for testing
	testHost    string           // Hostname for test connections
	testPort    int              // Port for test connections
	timeout     time.Duration    // Connection timeout
	concurrency int              // Maximum concurrent detection attempts

	// Rate limiting
	rateLimiter chan struct{}
}

// DetectorConfig configures the CA installation detector
type DetectorConfig struct {
	TestCertPath string        // Path to test certificate
	TestKeyPath  string        // Path to test key
	TestHost     string        // Hostname for tests
	TestPort     int           // Port for tests (default: 8443)
	Timeout      time.Duration // Connection timeout
	Concurrency  int           // Max concurrent detections
}

// DefaultDetectorConfig returns default detector configuration
func DefaultDetectorConfig() *DetectorConfig {
	return &DetectorConfig{
		TestHost:    "ca-test.safeops.local",
		TestPort:    8443,
		Timeout:     10 * time.Second,
		Concurrency: 10,
	}
}

// NewDetector creates a new CA installation detector
func NewDetector(tracker *Tracker, cfg *DetectorConfig) (*Detector, error) {
	if cfg == nil {
		cfg = DefaultDetectorConfig()
	}

	d := &Detector{
		tracker:     tracker,
		testHost:    cfg.TestHost,
		testPort:    cfg.TestPort,
		timeout:     cfg.Timeout,
		concurrency: cfg.Concurrency,
		rateLimiter: make(chan struct{}, cfg.Concurrency),
	}

	// Load test certificate if paths provided
	if cfg.TestCertPath != "" && cfg.TestKeyPath != "" {
		cert, err := tls.LoadX509KeyPair(cfg.TestCertPath, cfg.TestKeyPath)
		if err != nil {
			return nil, fmt.Errorf("failed to load test certificate: %w", err)
		}
		d.testCert = &cert
	}

	return d, nil
}

// DetectInstallation checks if a device has the SafeOps CA installed
func (d *Detector) DetectInstallation(ctx context.Context, deviceIP net.IP) (*types.InstallationDetection, error) {
	// Rate limiting
	select {
	case d.rateLimiter <- struct{}{}:
		defer func() { <-d.rateLimiter }()
	case <-ctx.Done():
		return nil, ctx.Err()
	}

	detection := &types.InstallationDetection{
		DeviceID:           types.GenerateDeviceID(deviceIP, ""),
		DetectionTimestamp: time.Now(),
		DetectionMethod:    types.DetectionTLSHandshake,
	}

	// Perform TLS handshake test
	tlsConfig := &tls.Config{
		InsecureSkipVerify: false, // Device must trust our CA
		ServerName:         d.testHost,
		MinVersion:         tls.VersionTLS12,
	}

	// Add test certificate if available
	if d.testCert != nil {
		tlsConfig.Certificates = []tls.Certificate{*d.testCert}
	}

	addr := fmt.Sprintf("%s:%d", deviceIP.String(), d.testPort)
	dialer := &net.Dialer{
		Timeout: d.timeout,
	}

	conn, err := tls.DialWithDialer(dialer, "tcp", addr, tlsConfig)
	if err != nil {
		detection.TLSHandshakeSuccess = false
		detection.CertificateAccepted = false
		detection.ErrorMessage = err.Error()
		detection.ConfidenceScore = 0.0
		return detection, nil // Return detection result, not error
	}
	defer conn.Close()

	// Successful handshake
	detection.TLSHandshakeSuccess = true
	detection.CertificateAccepted = true
	detection.ConfidenceScore = 1.0

	// Get TLS connection state
	state := conn.ConnectionState()
	detection.TLSVersion = tlsVersionString(state.Version)
	detection.CipherSuite = tls.CipherSuiteName(state.CipherSuite)
	detection.SNI = state.ServerName

	return detection, nil
}

// DetectMultiple checks CA installation for multiple devices concurrently
func (d *Detector) DetectMultiple(ctx context.Context, devices []net.IP) ([]*types.InstallationDetection, error) {
	results := make([]*types.InstallationDetection, len(devices))
	var wg sync.WaitGroup
	var mu sync.Mutex
	var firstErr error

	for i, ip := range devices {
		wg.Add(1)
		go func(idx int, deviceIP net.IP) {
			defer wg.Done()

			detection, err := d.DetectInstallation(ctx, deviceIP)
			if err != nil {
				mu.Lock()
				if firstErr == nil {
					firstErr = err
				}
				mu.Unlock()
				return
			}

			mu.Lock()
			results[idx] = detection
			mu.Unlock()
		}(i, ip)
	}

	wg.Wait()
	return results, firstErr
}

// DetectAndUpdate detects installation and updates device status
func (d *Detector) DetectAndUpdate(ctx context.Context, deviceIP net.IP) (*types.InstallationDetection, error) {
	detection, err := d.DetectInstallation(ctx, deviceIP)
	if err != nil {
		return nil, err
	}

	// Get or create device
	device, err := d.tracker.GetDeviceStatus(ctx, deviceIP)
	if err != nil {
		return detection, nil // Return detection even if tracking fails
	}

	if device == nil {
		// Track new device
		_, err = d.tracker.TrackDevice(ctx, types.DeviceInfo{
			IPAddress: deviceIP,
		})
		if err != nil {
			return detection, nil
		}
		device, _ = d.tracker.GetDeviceStatus(ctx, deviceIP)
	}

	// Update device status based on detection
	if device != nil {
		if detection.CertificateAccepted {
			err = d.tracker.MarkCAInstalled(ctx, device.DeviceID, detection.DetectionMethod)
		} else {
			err = d.tracker.MarkCANotInstalled(ctx, device.DeviceID, detection.DetectionMethod)
		}
	}

	return detection, nil
}

// ScanSubnet scans all devices in a subnet for CA installation
func (d *Detector) ScanSubnet(ctx context.Context, subnet *net.IPNet) ([]*types.InstallationDetection, error) {
	var ips []net.IP

	// Generate all IPs in subnet
	for ip := subnet.IP.Mask(subnet.Mask); subnet.Contains(ip); incrementIP(ip) {
		// Skip network and broadcast addresses
		ipCopy := make(net.IP, len(ip))
		copy(ipCopy, ip)
		ips = append(ips, ipCopy)
	}

	// Remove first (network) and last (broadcast) for IPv4
	if len(ips) > 2 && len(subnet.IP) == net.IPv4len || len(subnet.IP) == 16 && subnet.IP.To4() != nil {
		ips = ips[1 : len(ips)-1]
	}

	return d.DetectMultiple(ctx, ips)
}

// TestConnection tests if the detector can reach the test endpoint
func (d *Detector) TestConnection(ctx context.Context) error {
	addr := fmt.Sprintf("%s:%d", d.testHost, d.testPort)
	dialer := &net.Dialer{
		Timeout: d.timeout,
	}

	conn, err := dialer.DialContext(ctx, "tcp", addr)
	if err != nil {
		return fmt.Errorf("test connection failed: %w", err)
	}
	conn.Close()
	return nil
}

// Helper functions

func tlsVersionString(version uint16) string {
	switch version {
	case tls.VersionTLS10:
		return "TLS 1.0"
	case tls.VersionTLS11:
		return "TLS 1.1"
	case tls.VersionTLS12:
		return "TLS 1.2"
	case tls.VersionTLS13:
		return "TLS 1.3"
	default:
		return fmt.Sprintf("Unknown (0x%04x)", version)
	}
}

func incrementIP(ip net.IP) {
	for j := len(ip) - 1; j >= 0; j-- {
		ip[j]++
		if ip[j] > 0 {
			break
		}
	}
}
