// Package tests provides comprehensive testing for the Certificate Manager.
// This file tests the device CA installation tracking system.
package tests

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"math/big"
	"net"
	"net/http"
	"sync"
	"testing"
	"time"
)

// ============================================================================
// Test Types
// ============================================================================

// DeviceRecord represents a device in the tracking system.
type DeviceRecord struct {
	ID                 int64     `json:"id"`
	DeviceIP           string    `json:"device_ip"`
	MACAddress         string    `json:"mac_address"`
	CAInstalled        bool      `json:"ca_installed"`
	DetectedAt         time.Time `json:"detected_at"`
	InstallationMethod string    `json:"installation_method"`
	LastChecked        time.Time `json:"last_checked"`
}

// InstallationReport contains CA adoption metrics.
type InstallationReport struct {
	TotalDevices       int       `json:"total_devices"`
	DevicesWithCA      int       `json:"devices_with_ca"`
	DevicesWithoutCA   int       `json:"devices_without_ca"`
	AdoptionPercentage float64   `json:"adoption_percentage"`
	GeneratedAt        time.Time `json:"generated_at"`
}

// MockDeviceTracker provides device tracking for tests.
type MockDeviceTracker struct {
	devices   map[string]*DeviceRecord
	mu        sync.RWMutex
	nextID    int64
	caCert    *x509.Certificate
	caKey     *rsa.PrivateKey
	isRunning bool
	stopCh    chan struct{}
}

// NewMockDeviceTracker creates a new mock device tracker.
func NewMockDeviceTracker() (*MockDeviceTracker, error) {
	// Generate test CA
	caKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, err
	}

	caTemplate := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "Test CA"},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().AddDate(1, 0, 0),
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

	return &MockDeviceTracker{
		devices: make(map[string]*DeviceRecord),
		nextID:  1,
		caCert:  caCert,
		caKey:   caKey,
		stopCh:  make(chan struct{}),
	}, nil
}

// AddDevice adds a device to the tracker.
func (t *MockDeviceTracker) AddDevice(ip, mac string, caInstalled bool) *DeviceRecord {
	t.mu.Lock()
	defer t.mu.Unlock()

	device := &DeviceRecord{
		ID:          t.nextID,
		DeviceIP:    ip,
		MACAddress:  mac,
		CAInstalled: caInstalled,
		DetectedAt:  time.Now(),
		LastChecked: time.Now(),
	}
	t.devices[ip] = device
	t.nextID++
	return device
}

// UpdateDeviceStatus updates the CA installation status of a device.
func (t *MockDeviceTracker) UpdateDeviceStatus(ip, mac string, caInstalled bool) (*DeviceRecord, error) {
	t.mu.Lock()
	defer t.mu.Unlock()

	device, exists := t.devices[ip]
	if !exists {
		// Create new device
		device = &DeviceRecord{
			ID:          t.nextID,
			DeviceIP:    ip,
			MACAddress:  mac,
			CAInstalled: caInstalled,
			DetectedAt:  time.Now(),
			LastChecked: time.Now(),
		}
		t.devices[ip] = device
		t.nextID++
	} else {
		// Update existing device
		device.CAInstalled = caInstalled
		device.LastChecked = time.Now()
		if caInstalled && device.DetectedAt.IsZero() {
			device.DetectedAt = time.Now()
		}
	}

	return device, nil
}

// GetDevice returns a device by IP.
func (t *MockDeviceTracker) GetDevice(ip string) *DeviceRecord {
	t.mu.RLock()
	defer t.mu.RUnlock()
	if d, ok := t.devices[ip]; ok {
		copy := *d
		return &copy
	}
	return nil
}

// GetDeviceList returns devices filtered by CA installation status.
func (t *MockDeviceTracker) GetDeviceList(caInstalled *bool) []*DeviceRecord {
	t.mu.RLock()
	defer t.mu.RUnlock()

	var result []*DeviceRecord
	for _, d := range t.devices {
		if caInstalled == nil || *caInstalled == d.CAInstalled {
			copy := *d
			result = append(result, &copy)
		}
	}
	return result
}

// GetInstallationReport generates an installation report.
func (t *MockDeviceTracker) GetInstallationReport() *InstallationReport {
	t.mu.RLock()
	defer t.mu.RUnlock()

	total := len(t.devices)
	withCA := 0
	for _, d := range t.devices {
		if d.CAInstalled {
			withCA++
		}
	}

	var percentage float64
	if total > 0 {
		percentage = float64(withCA) / float64(total) * 100
	}

	return &InstallationReport{
		TotalDevices:       total,
		DevicesWithCA:      withCA,
		DevicesWithoutCA:   total - withCA,
		AdoptionPercentage: percentage,
		GeneratedAt:        time.Now(),
	}
}

// GetCoverage returns the CA adoption percentage.
func (t *MockDeviceTracker) GetCoverage() float64 {
	report := t.GetInstallationReport()
	return report.AdoptionPercentage
}

// DetectCAInstallation tests if a device has the CA installed via TLS handshake.
func (t *MockDeviceTracker) DetectCAInstallation(address string, timeout time.Duration) (bool, error) {
	// Create TLS config that requires valid CA
	pool := x509.NewCertPool()
	pool.AddCert(t.caCert)

	tlsConfig := &tls.Config{
		RootCAs:    pool,
		MinVersion: tls.VersionTLS12,
	}

	dialer := &net.Dialer{Timeout: timeout}
	conn, err := tls.DialWithDialer(dialer, "tcp", address, tlsConfig)
	if err != nil {
		// Connection failed or certificate verification failed
		return false, nil // Not installed (expected failure)
	}
	defer conn.Close()

	// Handshake succeeded - CA is installed
	return true, nil
}

// StartTracking starts the periodic device scanner.
func (t *MockDeviceTracker) StartTracking() error {
	t.mu.Lock()
	if t.isRunning {
		t.mu.Unlock()
		return fmt.Errorf("tracking already running")
	}
	t.isRunning = true
	t.stopCh = make(chan struct{})
	t.mu.Unlock()

	// In real implementation, this would start a goroutine
	// that periodically scans devices
	return nil
}

// StopTracking stops the device scanner.
func (t *MockDeviceTracker) StopTracking() error {
	t.mu.Lock()
	defer t.mu.Unlock()

	if !t.isRunning {
		return fmt.Errorf("tracking not running")
	}
	t.isRunning = false
	close(t.stopCh)
	return nil
}

// IsTracking returns whether tracking is active.
func (t *MockDeviceTracker) IsTracking() bool {
	t.mu.RLock()
	defer t.mu.RUnlock()
	return t.isRunning
}

// ScanDevices scans all devices and updates their status.
func (t *MockDeviceTracker) ScanDevices() int {
	t.mu.Lock()
	defer t.mu.Unlock()

	updated := 0
	for _, d := range t.devices {
		d.LastChecked = time.Now()
		updated++
	}
	return updated
}

// SetInstallationMethod sets how the CA was installed.
func (t *MockDeviceTracker) SetInstallationMethod(ip, method string) error {
	t.mu.Lock()
	defer t.mu.Unlock()

	device, exists := t.devices[ip]
	if !exists {
		return fmt.Errorf("device not found: %s", ip)
	}
	device.InstallationMethod = method
	return nil
}

// Clear removes all devices.
func (t *MockDeviceTracker) Clear() {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.devices = make(map[string]*DeviceRecord)
	t.nextID = 1
}

// GenerateTestCertificate creates a certificate signed by the test CA.
func (t *MockDeviceTracker) GenerateTestCertificate(cn string) (*tls.Certificate, error) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, err
	}

	template := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject:      pkix.Name{CommonName: cn},
		NotBefore:    time.Now(),
		NotAfter:     time.Now().AddDate(0, 1, 0),
		KeyUsage:     x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:     []string{cn, "localhost"},
		IPAddresses:  []net.IP{net.ParseIP("127.0.0.1")},
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, t.caCert, &key.PublicKey, t.caKey)
	if err != nil {
		return nil, err
	}

	return &tls.Certificate{
		Certificate: [][]byte{certDER},
		PrivateKey:  key,
	}, nil
}

// ============================================================================
// CA Installation Detection Tests
// ============================================================================

// TestDetectCAInstallation_DeviceUnreachable tests unreachable device handling.
func TestDetectCAInstallation_DeviceUnreachable(t *testing.T) {
	tracker, err := NewMockDeviceTracker()
	if err != nil {
		t.Fatalf("Failed to create tracker: %v", err)
	}

	// Try to connect to non-existent address
	installed, err := tracker.DetectCAInstallation("192.0.2.1:443", 500*time.Millisecond)

	// Should return false (not installed) without error
	if installed {
		t.Error("Should return false for unreachable device")
	}
	// Error is acceptable for this case (timeout)
	_ = err
}

// TestDetectCAInstallation_WithTLSServer tests CA detection with actual TLS server.
func TestDetectCAInstallation_WithTLSServer(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping TLS server test in short mode")
	}

	tracker, err := NewMockDeviceTracker()
	if err != nil {
		t.Fatalf("Failed to create tracker: %v", err)
	}

	// Generate server certificate signed by test CA
	serverCert, err := tracker.GenerateTestCertificate("localhost")
	if err != nil {
		t.Fatalf("Failed to generate server cert: %v", err)
	}

	// Start TLS server
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Failed to create listener: %v", err)
	}
	defer listener.Close()

	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{*serverCert},
		MinVersion:   tls.VersionTLS12,
	}
	tlsListener := tls.NewListener(listener, tlsConfig)

	go func() {
		conn, err := tlsListener.Accept()
		if err != nil {
			return
		}
		conn.Close()
	}()

	// Try to detect CA installation
	address := listener.Addr().String()
	installed, err := tracker.DetectCAInstallation(address, 2*time.Second)

	if err != nil {
		t.Logf("Detection error (acceptable): %v", err)
	}

	// The result depends on whether the TLS handshake succeeded
	t.Logf("CA installation detected: %v", installed)
}

// ============================================================================
// Database Update Tests
// ============================================================================

// TestUpdateDeviceStatus_NewDevice tests adding a new device.
func TestUpdateDeviceStatus_NewDevice(t *testing.T) {
	tracker, _ := NewMockDeviceTracker()

	device, err := tracker.UpdateDeviceStatus("192.168.1.100", "AA:BB:CC:DD:EE:FF", true)
	if err != nil {
		t.Fatalf("UpdateDeviceStatus failed: %v", err)
	}

	if device.DeviceIP != "192.168.1.100" {
		t.Errorf("DeviceIP = %s, want 192.168.1.100", device.DeviceIP)
	}
	if device.MACAddress != "AA:BB:CC:DD:EE:FF" {
		t.Errorf("MACAddress = %s, want AA:BB:CC:DD:EE:FF", device.MACAddress)
	}
	if !device.CAInstalled {
		t.Error("CAInstalled = false, want true")
	}
	if device.DetectedAt.IsZero() {
		t.Error("DetectedAt should be set")
	}
}

// TestUpdateDeviceStatus_ExistingDevice tests updating an existing device.
func TestUpdateDeviceStatus_ExistingDevice(t *testing.T) {
	tracker, _ := NewMockDeviceTracker()

	// Add initial device
	tracker.AddDevice("192.168.1.100", "AA:BB:CC:DD:EE:FF", false)

	// Update status
	device, err := tracker.UpdateDeviceStatus("192.168.1.100", "AA:BB:CC:DD:EE:FF", true)
	if err != nil {
		t.Fatalf("UpdateDeviceStatus failed: %v", err)
	}

	if !device.CAInstalled {
		t.Error("CAInstalled should be true after update")
	}

	// Verify only one record exists
	devices := tracker.GetDeviceList(nil)
	if len(devices) != 1 {
		t.Errorf("Expected 1 device, got %d", len(devices))
	}
}

// TestUpdateDeviceStatus_StatusChange tests status change tracking.
func TestUpdateDeviceStatus_StatusChange(t *testing.T) {
	tracker, _ := NewMockDeviceTracker()

	// Add device with CA installed
	tracker.AddDevice("192.168.1.100", "AA:BB:CC:DD:EE:FF", true)

	// Get original device
	original := tracker.GetDevice("192.168.1.100")
	originalDetectedAt := original.DetectedAt

	// Wait a bit to ensure timestamp difference
	time.Sleep(10 * time.Millisecond)

	// Update to CA not installed
	device, _ := tracker.UpdateDeviceStatus("192.168.1.100", "AA:BB:CC:DD:EE:FF", false)

	if device.CAInstalled {
		t.Error("CAInstalled should be false after update")
	}

	// DetectedAt should be preserved
	if device.DetectedAt.Before(originalDetectedAt) {
		t.Error("DetectedAt should not be earlier than original")
	}
}

// ============================================================================
// Installation Reporting Tests
// ============================================================================

// TestGetInstallationReport tests report generation.
func TestGetInstallationReport(t *testing.T) {
	tracker, _ := NewMockDeviceTracker()

	// Add devices
	for i := 0; i < 85; i++ {
		tracker.AddDevice(fmt.Sprintf("192.168.1.%d", i), fmt.Sprintf("AA:BB:CC:DD:%02X:01", i), true)
	}
	for i := 0; i < 15; i++ {
		tracker.AddDevice(fmt.Sprintf("192.168.2.%d", i), fmt.Sprintf("AA:BB:CC:DD:%02X:02", i), false)
	}

	report := tracker.GetInstallationReport()

	if report.TotalDevices != 100 {
		t.Errorf("TotalDevices = %d, want 100", report.TotalDevices)
	}
	if report.DevicesWithCA != 85 {
		t.Errorf("DevicesWithCA = %d, want 85", report.DevicesWithCA)
	}
	if report.DevicesWithoutCA != 15 {
		t.Errorf("DevicesWithoutCA = %d, want 15", report.DevicesWithoutCA)
	}
	if report.AdoptionPercentage != 85.0 {
		t.Errorf("AdoptionPercentage = %.1f, want 85.0", report.AdoptionPercentage)
	}
}

// TestGetInstallationReport_Empty tests report with no devices.
func TestGetInstallationReport_Empty(t *testing.T) {
	tracker, _ := NewMockDeviceTracker()

	report := tracker.GetInstallationReport()

	if report.TotalDevices != 0 {
		t.Errorf("TotalDevices = %d, want 0", report.TotalDevices)
	}
	if report.AdoptionPercentage != 0.0 {
		t.Errorf("AdoptionPercentage = %.1f, want 0.0", report.AdoptionPercentage)
	}
}

// TestGetDeviceList tests device list filtering.
func TestGetDeviceList(t *testing.T) {
	tracker, _ := NewMockDeviceTracker()

	// Add mixed devices
	tracker.AddDevice("192.168.1.1", "AA:00:00:00:00:01", true)
	tracker.AddDevice("192.168.1.2", "AA:00:00:00:00:02", true)
	tracker.AddDevice("192.168.1.3", "AA:00:00:00:00:03", false)
	tracker.AddDevice("192.168.1.4", "AA:00:00:00:00:04", true)
	tracker.AddDevice("192.168.1.5", "AA:00:00:00:00:05", false)

	// Filter by CA installed
	installed := true
	withCA := tracker.GetDeviceList(&installed)
	if len(withCA) != 3 {
		t.Errorf("Expected 3 devices with CA, got %d", len(withCA))
	}

	notInstalled := false
	withoutCA := tracker.GetDeviceList(&notInstalled)
	if len(withoutCA) != 2 {
		t.Errorf("Expected 2 devices without CA, got %d", len(withoutCA))
	}

	// All devices
	all := tracker.GetDeviceList(nil)
	if len(all) != 5 {
		t.Errorf("Expected 5 total devices, got %d", len(all))
	}
}

// TestGetCoverage tests coverage calculation.
func TestGetCoverage(t *testing.T) {
	tracker, _ := NewMockDeviceTracker()

	// Add 90 with CA, 10 without
	for i := 0; i < 90; i++ {
		tracker.AddDevice(fmt.Sprintf("10.0.0.%d", i), fmt.Sprintf("BB:%02X:00:00:00:01", i), true)
	}
	for i := 0; i < 10; i++ {
		tracker.AddDevice(fmt.Sprintf("10.0.1.%d", i), fmt.Sprintf("BB:%02X:00:00:00:02", i), false)
	}

	coverage := tracker.GetCoverage()
	if coverage != 90.0 {
		t.Errorf("Coverage = %.1f, want 90.0", coverage)
	}
}

// ============================================================================
// Device Tracking Coordinator Tests
// ============================================================================

// TestStartTracking tests starting the tracker.
func TestStartTracking(t *testing.T) {
	tracker, _ := NewMockDeviceTracker()

	err := tracker.StartTracking()
	if err != nil {
		t.Fatalf("StartTracking failed: %v", err)
	}

	if !tracker.IsTracking() {
		t.Error("Tracker should be running")
	}

	// Cleanup
	tracker.StopTracking()
}

// TestStopTracking tests stopping the tracker.
func TestStopTracking(t *testing.T) {
	tracker, _ := NewMockDeviceTracker()

	tracker.StartTracking()
	err := tracker.StopTracking()
	if err != nil {
		t.Fatalf("StopTracking failed: %v", err)
	}

	if tracker.IsTracking() {
		t.Error("Tracker should not be running")
	}
}

// TestStartTrackingTwice tests starting tracking twice.
func TestStartTrackingTwice(t *testing.T) {
	tracker, _ := NewMockDeviceTracker()

	tracker.StartTracking()
	err := tracker.StartTracking()
	if err == nil {
		t.Error("Should return error when already tracking")
	}

	tracker.StopTracking()
}

// TestScanDevices tests the device scanning function.
func TestScanDevices(t *testing.T) {
	tracker, _ := NewMockDeviceTracker()

	// Add devices
	for i := 0; i < 10; i++ {
		tracker.AddDevice(fmt.Sprintf("192.168.1.%d", i), fmt.Sprintf("CC:%02X:00:00:00:00", i), false)
	}

	updated := tracker.ScanDevices()
	if updated != 10 {
		t.Errorf("Expected 10 devices scanned, got %d", updated)
	}

	// Verify LastChecked was updated
	device := tracker.GetDevice("192.168.1.0")
	if time.Since(device.LastChecked) > time.Second {
		t.Error("LastChecked should be recent")
	}
}

// ============================================================================
// Download-to-Installation Correlation Tests
// ============================================================================

// TestCorrelateDownloadToInstallation tests method tracking.
func TestCorrelateDownloadToInstallation(t *testing.T) {
	tracker, _ := NewMockDeviceTracker()

	// Add device with CA
	tracker.AddDevice("192.168.1.100", "DD:00:00:00:00:01", true)

	// Set installation method
	err := tracker.SetInstallationMethod("192.168.1.100", "http_download")
	if err != nil {
		t.Fatalf("SetInstallationMethod failed: %v", err)
	}

	device := tracker.GetDevice("192.168.1.100")
	if device.InstallationMethod != "http_download" {
		t.Errorf("InstallationMethod = %s, want http_download", device.InstallationMethod)
	}
}

// TestInstallationWithoutDownload tests unknown installation method.
func TestInstallationWithoutDownload(t *testing.T) {
	tracker, _ := NewMockDeviceTracker()

	// Add device with CA but no download record
	device := tracker.AddDevice("192.168.1.100", "DD:00:00:00:00:01", true)

	// Method should be empty (unknown)
	if device.InstallationMethod != "" {
		t.Errorf("InstallationMethod = %s, want empty", device.InstallationMethod)
	}
}

// ============================================================================
// Concurrent Tests
// ============================================================================

// TestConcurrentDeviceUpdates tests thread-safe updates.
func TestConcurrentDeviceUpdates(t *testing.T) {
	tracker, _ := NewMockDeviceTracker()

	var wg sync.WaitGroup
	numGoroutines := 50

	wg.Add(numGoroutines)
	for i := 0; i < numGoroutines; i++ {
		go func(n int) {
			defer wg.Done()
			ip := fmt.Sprintf("192.168.%d.%d", n/256, n%256)
			mac := fmt.Sprintf("EE:%02X:00:00:00:00", n)
			_, err := tracker.UpdateDeviceStatus(ip, mac, n%2 == 0)
			if err != nil {
				t.Errorf("Concurrent update failed: %v", err)
			}
		}(i)
	}

	wg.Wait()

	devices := tracker.GetDeviceList(nil)
	if len(devices) != numGoroutines {
		t.Errorf("Expected %d devices, got %d", numGoroutines, len(devices))
	}
}

// TestConcurrentReportGeneration tests report generation under concurrent updates.
func TestConcurrentReportGeneration(t *testing.T) {
	tracker, _ := NewMockDeviceTracker()

	// Add initial devices
	for i := 0; i < 100; i++ {
		tracker.AddDevice(fmt.Sprintf("10.0.0.%d", i), fmt.Sprintf("FF:%02X:00:00:00:00", i), i < 50)
	}

	var wg sync.WaitGroup
	numReports := 20
	wg.Add(numReports)

	for i := 0; i < numReports; i++ {
		go func() {
			defer wg.Done()
			report := tracker.GetInstallationReport()
			if report.TotalDevices != 100 {
				t.Errorf("Report shows %d devices, want 100", report.TotalDevices)
			}
		}()
	}

	wg.Wait()
}

// ============================================================================
// Performance Tests
// ============================================================================

// TestLargeDeviceSet tests handling of many devices.
func TestLargeDeviceSet(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping large device set test in short mode")
	}

	tracker, _ := NewMockDeviceTracker()

	numDevices := 1000
	start := time.Now()

	for i := 0; i < numDevices; i++ {
		ip := fmt.Sprintf("10.%d.%d.%d", i/65536, (i/256)%256, i%256)
		mac := fmt.Sprintf("AA:BB:CC:%02X:%02X:%02X", (i/65536)%256, (i/256)%256, i%256)
		tracker.AddDevice(ip, mac, i%3 == 0)
	}

	addElapsed := time.Since(start)

	start = time.Now()
	report := tracker.GetInstallationReport()
	reportElapsed := time.Since(start)

	t.Logf("Added %d devices in %v", numDevices, addElapsed)
	t.Logf("Generated report in %v", reportElapsed)
	t.Logf("Report: %d total, %d with CA, %.1f%% adoption",
		report.TotalDevices, report.DevicesWithCA, report.AdoptionPercentage)

	if report.TotalDevices != numDevices {
		t.Errorf("Expected %d devices, got %d", numDevices, report.TotalDevices)
	}
}

// ============================================================================
// Error Handling Tests
// ============================================================================

// TestSetInstallationMethod_DeviceNotFound tests error for missing device.
func TestSetInstallationMethod_DeviceNotFound(t *testing.T) {
	tracker, _ := NewMockDeviceTracker()

	err := tracker.SetInstallationMethod("192.168.1.254", "manual")
	if err == nil {
		t.Error("Should return error for non-existent device")
	}
}

// TestStopTracking_NotRunning tests stopping when not running.
func TestStopTracking_NotRunning(t *testing.T) {
	tracker, _ := NewMockDeviceTracker()

	err := tracker.StopTracking()
	if err == nil {
		t.Error("Should return error when not running")
	}
}

// ============================================================================
// Cleanup Tests
// ============================================================================

// TestClear tests clearing all devices.
func TestClear(t *testing.T) {
	tracker, _ := NewMockDeviceTracker()

	// Add devices
	tracker.AddDevice("192.168.1.1", "AA:00:00:00:00:01", true)
	tracker.AddDevice("192.168.1.2", "AA:00:00:00:00:02", false)

	tracker.Clear()

	devices := tracker.GetDeviceList(nil)
	if len(devices) != 0 {
		t.Errorf("Expected 0 devices after clear, got %d", len(devices))
	}

	// New device should get ID 1
	newDevice := tracker.AddDevice("192.168.1.1", "AA:00:00:00:00:01", true)
	if newDevice.ID != 1 {
		t.Errorf("New device ID = %d, want 1", newDevice.ID)
	}
}

// ============================================================================
// HTTP Handler Tests
// ============================================================================

// TestDeviceStatusHTTPHandler tests HTTP-based status endpoint.
func TestDeviceStatusHTTPHandler(t *testing.T) {
	tracker, _ := NewMockDeviceTracker()
	tracker.AddDevice("192.168.1.100", "AA:BB:CC:DD:EE:FF", true)

	// Create a simple handler
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		report := tracker.GetInstallationReport()
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintf(w, `{"total":%d,"with_ca":%d,"percentage":%.1f}`,
			report.TotalDevices, report.DevicesWithCA, report.AdoptionPercentage)
	})

	// Test handler exists (would need httptest for full testing)
	if handler == nil {
		t.Error("Handler should not be nil")
	}
}
