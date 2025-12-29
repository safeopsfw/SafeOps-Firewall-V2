package distribution

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// ============================================================================
// Configuration Types
// ============================================================================

// DownloadTrackerConfig contains configuration for the download tracker.
type DownloadTrackerConfig struct {
	Enabled             bool          // Enable download tracking
	BatchSize           int           // Number of downloads to buffer before batch insert
	BatchInterval       time.Duration // Time interval for flushing buffered downloads
	AnomalyEnabled      bool          // Enable anomaly detection
	MaxDownloadsPerHour int           // Max downloads per IP per hour before anomaly
	ExpectedNetworkCIDR string        // Expected network range (e.g., "192.168.1.0/24")
	RetentionDays       int           // Days to keep download records
}

// DownloadEvent represents a single download event.
type DownloadEvent struct {
	ID           int64     `json:"id"`
	Timestamp    time.Time `json:"timestamp"`
	DeviceIP     string    `json:"device_ip"`
	MACAddress   string    `json:"mac_address,omitempty"`
	ResourceType string    `json:"resource_type"` // ca.crt, ca.der, install-ca.sh, etc.
	Format       string    `json:"format"`        // PEM, DER, PKCS7, MobileConfig, Script
	UserAgent    string    `json:"user_agent"`
	Referrer     string    `json:"referrer,omitempty"`
	StatusCode   int       `json:"status_code"`
	BytesSent    int64     `json:"bytes_sent"`
	Duration     int64     `json:"duration_ms"`
}

// ============================================================================
// Error Types
// ============================================================================

var (
	ErrTrackerDisabled = errors.New("download tracker is disabled")
	ErrInvalidIP       = errors.New("invalid IP address")
	ErrBatchFull       = errors.New("batch buffer is full")
)

// ============================================================================
// Download Metrics
// ============================================================================

// DownloadMetrics contains real-time download statistics.
type DownloadMetrics struct {
	TotalDownloads      int64            `json:"total_downloads"`
	SuccessfulDownloads int64            `json:"successful_downloads"`
	FailedDownloads     int64            `json:"failed_downloads"`
	ByFormat            map[string]int64 `json:"by_format"`
	ByPlatform          map[string]int64 `json:"by_platform"`
	UniqueIPs           int              `json:"unique_ips"`
	LastDownload        time.Time        `json:"last_download"`
	DownloadsPerHour    float64          `json:"downloads_per_hour"`
}

// metricsStore holds thread-safe metrics counters.
type metricsStore struct {
	mu                  sync.RWMutex
	totalDownloads      int64
	successfulDownloads int64
	failedDownloads     int64
	byFormat            map[string]int64
	byPlatform          map[string]int64
	uniqueIPs           map[string]struct{}
	lastDownload        time.Time
	hourlyDownloads     []time.Time // Sliding window for rate calculation
}

func newMetricsStore() *metricsStore {
	return &metricsStore{
		byFormat:        make(map[string]int64),
		byPlatform:      make(map[string]int64),
		uniqueIPs:       make(map[string]struct{}),
		hourlyDownloads: make([]time.Time, 0),
	}
}

// ============================================================================
// Anomaly Detection
// ============================================================================

// AnomalyType represents types of detected anomalies.
type AnomalyType string

const (
	AnomalyRapidDownloads  AnomalyType = "rapid_downloads"
	AnomalyExternalIP      AnomalyType = "external_ip"
	AnomalySuspiciousAgent AnomalyType = "suspicious_user_agent"
	AnomalyHighVolume      AnomalyType = "high_volume"
)

// Anomaly represents a detected anomaly event.
type Anomaly struct {
	Type        AnomalyType `json:"type"`
	DeviceIP    string      `json:"device_ip"`
	Description string      `json:"description"`
	Timestamp   time.Time   `json:"timestamp"`
	Severity    string      `json:"severity"` // low, medium, high
	Count       int         `json:"count"`
}

// anomalyDetector tracks anomaly patterns.
type anomalyDetector struct {
	mu                sync.RWMutex
	ipDownloadCounts  map[string][]time.Time // IP -> timestamps of recent downloads
	maxPerHour        int
	expectedNetwork   *net.IPNet
	suspiciousAgents  []string
	detectedAnomalies []Anomaly
	anomalyCount      int64
}

func newAnomalyDetector(config *DownloadTrackerConfig) *anomalyDetector {
	ad := &anomalyDetector{
		ipDownloadCounts: make(map[string][]time.Time),
		maxPerHour:       config.MaxDownloadsPerHour,
		suspiciousAgents: []string{
			"curl", "wget", "python", "scanner", "bot", "crawler",
		},
		detectedAnomalies: make([]Anomaly, 0),
	}

	// Parse expected network
	if config.ExpectedNetworkCIDR != "" {
		_, network, err := net.ParseCIDR(config.ExpectedNetworkCIDR)
		if err == nil {
			ad.expectedNetwork = network
		}
	}

	if ad.maxPerHour == 0 {
		ad.maxPerHour = 10 // Default
	}

	return ad
}

// ============================================================================
// Download Tracker
// ============================================================================

// DownloadTracker tracks and logs CA certificate downloads.
type DownloadTracker struct {
	config  *DownloadTrackerConfig
	metrics *metricsStore
	anomaly *anomalyDetector

	// Batch buffer
	batchMu     sync.Mutex
	batchBuffer []*DownloadEvent
	batchTicker *time.Ticker
	stopCh      chan struct{}
	wg          sync.WaitGroup

	// Callbacks
	onBatchFlush func([]*DownloadEvent) error
	onAnomaly    func(Anomaly)
}

// NewDownloadTracker creates a new download tracker.
func NewDownloadTracker(config *DownloadTrackerConfig) *DownloadTracker {
	if config == nil {
		config = DefaultDownloadTrackerConfig()
	}

	dt := &DownloadTracker{
		config:      config,
		metrics:     newMetricsStore(),
		batchBuffer: make([]*DownloadEvent, 0, config.BatchSize),
		stopCh:      make(chan struct{}),
	}

	if config.AnomalyEnabled {
		dt.anomaly = newAnomalyDetector(config)
	}

	return dt
}

// DefaultDownloadTrackerConfig returns default configuration.
func DefaultDownloadTrackerConfig() *DownloadTrackerConfig {
	return &DownloadTrackerConfig{
		Enabled:             true,
		BatchSize:           50,
		BatchInterval:       30 * time.Second,
		AnomalyEnabled:      true,
		MaxDownloadsPerHour: 10,
		ExpectedNetworkCIDR: "192.168.0.0/16",
		RetentionDays:       90,
	}
}

// Start starts the background batch flushing goroutine.
func (dt *DownloadTracker) Start() {
	if !dt.config.Enabled {
		return
	}

	dt.batchTicker = time.NewTicker(dt.config.BatchInterval)
	dt.wg.Add(1)

	go func() {
		defer dt.wg.Done()
		for {
			select {
			case <-dt.batchTicker.C:
				dt.FlushBatch()
			case <-dt.stopCh:
				dt.FlushBatch() // Final flush
				return
			}
		}
	}()
}

// Stop stops the download tracker.
func (dt *DownloadTracker) Stop() {
	if dt.batchTicker != nil {
		dt.batchTicker.Stop()
	}
	close(dt.stopCh)
	dt.wg.Wait()
}

// SetBatchFlushCallback sets the callback for batch flush events.
func (dt *DownloadTracker) SetBatchFlushCallback(fn func([]*DownloadEvent) error) {
	dt.onBatchFlush = fn
}

// SetAnomalyCallback sets the callback for anomaly events.
func (dt *DownloadTracker) SetAnomalyCallback(fn func(Anomaly)) {
	dt.onAnomaly = fn
}

// ============================================================================
// Tracking Functions
// ============================================================================

// TrackDownload records a download event.
func (dt *DownloadTracker) TrackDownload(event *DownloadEvent) error {
	if !dt.config.Enabled {
		return ErrTrackerDisabled
	}

	if event == nil {
		return errors.New("event cannot be nil")
	}

	// Validate IP
	if net.ParseIP(event.DeviceIP) == nil {
		return fmt.Errorf("%w: %s", ErrInvalidIP, event.DeviceIP)
	}

	// Set timestamp if not set
	if event.Timestamp.IsZero() {
		event.Timestamp = time.Now()
	}

	// Detect platform from User-Agent
	platform := detectPlatformFromUA(event.UserAgent)

	// Update metrics
	dt.updateMetrics(event, platform)

	// Check for anomalies
	if dt.anomaly != nil {
		dt.checkAnomalies(event)
	}

	// Add to batch buffer
	dt.batchMu.Lock()
	dt.batchBuffer = append(dt.batchBuffer, event)
	shouldFlush := len(dt.batchBuffer) >= dt.config.BatchSize
	dt.batchMu.Unlock()

	// Flush if batch is full
	if shouldFlush {
		go dt.FlushBatch()
	}

	return nil
}

// TrackDownloadSimple is a convenience method for tracking downloads.
func (dt *DownloadTracker) TrackDownloadSimple(
	ip string,
	resourceType string,
	format string,
	userAgent string,
	statusCode int,
	bytesSent int64,
) error {
	event := &DownloadEvent{
		Timestamp:    time.Now(),
		DeviceIP:     ip,
		ResourceType: resourceType,
		Format:       format,
		UserAgent:    userAgent,
		StatusCode:   statusCode,
		BytesSent:    bytesSent,
	}
	return dt.TrackDownload(event)
}

// ============================================================================
// Metrics Functions
// ============================================================================

// updateMetrics updates the metrics store with a new download.
func (dt *DownloadTracker) updateMetrics(event *DownloadEvent, platform string) {
	dt.metrics.mu.Lock()
	defer dt.metrics.mu.Unlock()

	atomic.AddInt64(&dt.metrics.totalDownloads, 1)

	if event.StatusCode >= 200 && event.StatusCode < 300 {
		atomic.AddInt64(&dt.metrics.successfulDownloads, 1)
	} else {
		atomic.AddInt64(&dt.metrics.failedDownloads, 1)
	}

	// Track by format
	if event.Format != "" {
		dt.metrics.byFormat[event.Format]++
	}

	// Track by platform
	if platform != "" {
		dt.metrics.byPlatform[platform]++
	}

	// Track unique IPs
	dt.metrics.uniqueIPs[event.DeviceIP] = struct{}{}

	// Update last download
	dt.metrics.lastDownload = event.Timestamp

	// Track hourly downloads (sliding window)
	now := time.Now()
	hourAgo := now.Add(-time.Hour)

	// Prune old entries
	newHourly := make([]time.Time, 0)
	for _, t := range dt.metrics.hourlyDownloads {
		if t.After(hourAgo) {
			newHourly = append(newHourly, t)
		}
	}
	newHourly = append(newHourly, now)
	dt.metrics.hourlyDownloads = newHourly
}

// GetMetrics returns current download metrics.
func (dt *DownloadTracker) GetMetrics() *DownloadMetrics {
	dt.metrics.mu.RLock()
	defer dt.metrics.mu.RUnlock()

	metrics := &DownloadMetrics{
		TotalDownloads:      atomic.LoadInt64(&dt.metrics.totalDownloads),
		SuccessfulDownloads: atomic.LoadInt64(&dt.metrics.successfulDownloads),
		FailedDownloads:     atomic.LoadInt64(&dt.metrics.failedDownloads),
		ByFormat:            make(map[string]int64),
		ByPlatform:          make(map[string]int64),
		UniqueIPs:           len(dt.metrics.uniqueIPs),
		LastDownload:        dt.metrics.lastDownload,
	}

	// Copy maps
	for k, v := range dt.metrics.byFormat {
		metrics.ByFormat[k] = v
	}
	for k, v := range dt.metrics.byPlatform {
		metrics.ByPlatform[k] = v
	}

	// Calculate hourly rate
	metrics.DownloadsPerHour = float64(len(dt.metrics.hourlyDownloads))

	return metrics
}

// GetTotalDownloads returns the total download count.
func (dt *DownloadTracker) GetTotalDownloads() int64 {
	return atomic.LoadInt64(&dt.metrics.totalDownloads)
}

// GetUniqueIPCount returns the number of unique IPs.
func (dt *DownloadTracker) GetUniqueIPCount() int {
	dt.metrics.mu.RLock()
	defer dt.metrics.mu.RUnlock()
	return len(dt.metrics.uniqueIPs)
}

// ============================================================================
// Anomaly Detection Functions
// ============================================================================

// checkAnomalies checks for anomalous download patterns.
func (dt *DownloadTracker) checkAnomalies(event *DownloadEvent) {
	if dt.anomaly == nil {
		return
	}

	dt.anomaly.mu.Lock()
	defer dt.anomaly.mu.Unlock()

	// Check rapid downloads from same IP
	dt.checkRapidDownloads(event)

	// Check external IP
	dt.checkExternalIP(event)

	// Check suspicious User-Agent
	dt.checkSuspiciousAgent(event)
}

// checkRapidDownloads detects rapid repeated downloads.
func (dt *DownloadTracker) checkRapidDownloads(event *DownloadEvent) {
	now := time.Now()
	hourAgo := now.Add(-time.Hour)

	// Get downloads for this IP
	timestamps := dt.anomaly.ipDownloadCounts[event.DeviceIP]

	// Prune old entries
	newTimestamps := make([]time.Time, 0)
	for _, t := range timestamps {
		if t.After(hourAgo) {
			newTimestamps = append(newTimestamps, t)
		}
	}
	newTimestamps = append(newTimestamps, now)
	dt.anomaly.ipDownloadCounts[event.DeviceIP] = newTimestamps

	// Check threshold
	if len(newTimestamps) > dt.anomaly.maxPerHour {
		anomaly := Anomaly{
			Type:        AnomalyRapidDownloads,
			DeviceIP:    event.DeviceIP,
			Description: fmt.Sprintf("IP %s exceeded %d downloads in 1 hour (count: %d)", event.DeviceIP, dt.anomaly.maxPerHour, len(newTimestamps)),
			Timestamp:   now,
			Severity:    "medium",
			Count:       len(newTimestamps),
		}
		dt.recordAnomaly(anomaly)
	}
}

// checkExternalIP detects downloads from outside expected network.
func (dt *DownloadTracker) checkExternalIP(event *DownloadEvent) {
	if dt.anomaly.expectedNetwork == nil {
		return
	}

	ip := net.ParseIP(event.DeviceIP)
	if ip == nil {
		return
	}

	if !dt.anomaly.expectedNetwork.Contains(ip) {
		anomaly := Anomaly{
			Type:        AnomalyExternalIP,
			DeviceIP:    event.DeviceIP,
			Description: fmt.Sprintf("Download from IP %s outside expected network %s", event.DeviceIP, dt.anomaly.expectedNetwork.String()),
			Timestamp:   time.Now(),
			Severity:    "high",
			Count:       1,
		}
		dt.recordAnomaly(anomaly)
	}
}

// checkSuspiciousAgent detects suspicious User-Agent strings.
func (dt *DownloadTracker) checkSuspiciousAgent(event *DownloadEvent) {
	ua := strings.ToLower(event.UserAgent)

	for _, suspicious := range dt.anomaly.suspiciousAgents {
		if strings.Contains(ua, suspicious) {
			anomaly := Anomaly{
				Type:        AnomalySuspiciousAgent,
				DeviceIP:    event.DeviceIP,
				Description: fmt.Sprintf("Suspicious User-Agent from %s: %s", event.DeviceIP, event.UserAgent),
				Timestamp:   time.Now(),
				Severity:    "low",
				Count:       1,
			}
			dt.recordAnomaly(anomaly)
			return
		}
	}
}

// recordAnomaly records a detected anomaly.
func (dt *DownloadTracker) recordAnomaly(anomaly Anomaly) {
	atomic.AddInt64(&dt.anomaly.anomalyCount, 1)
	dt.anomaly.detectedAnomalies = append(dt.anomaly.detectedAnomalies, anomaly)

	// Keep only last 1000 anomalies
	if len(dt.anomaly.detectedAnomalies) > 1000 {
		dt.anomaly.detectedAnomalies = dt.anomaly.detectedAnomalies[len(dt.anomaly.detectedAnomalies)-1000:]
	}

	// Call anomaly callback
	if dt.onAnomaly != nil {
		go dt.onAnomaly(anomaly)
	}
}

// GetAnomalies returns recent anomalies.
func (dt *DownloadTracker) GetAnomalies(limit int) []Anomaly {
	if dt.anomaly == nil {
		return nil
	}

	dt.anomaly.mu.RLock()
	defer dt.anomaly.mu.RUnlock()

	if limit <= 0 || limit > len(dt.anomaly.detectedAnomalies) {
		limit = len(dt.anomaly.detectedAnomalies)
	}

	// Return newest first
	result := make([]Anomaly, limit)
	for i := 0; i < limit; i++ {
		result[i] = dt.anomaly.detectedAnomalies[len(dt.anomaly.detectedAnomalies)-1-i]
	}
	return result
}

// GetAnomalyCount returns total anomaly count.
func (dt *DownloadTracker) GetAnomalyCount() int64 {
	if dt.anomaly == nil {
		return 0
	}
	return atomic.LoadInt64(&dt.anomaly.anomalyCount)
}

// ============================================================================
// Batch Operations
// ============================================================================

// FlushBatch flushes the batch buffer to persistent storage.
func (dt *DownloadTracker) FlushBatch() {
	dt.batchMu.Lock()
	if len(dt.batchBuffer) == 0 {
		dt.batchMu.Unlock()
		return
	}

	// Copy and clear buffer
	batch := make([]*DownloadEvent, len(dt.batchBuffer))
	copy(batch, dt.batchBuffer)
	dt.batchBuffer = dt.batchBuffer[:0]
	dt.batchMu.Unlock()

	// Call flush callback
	if dt.onBatchFlush != nil {
		if err := dt.onBatchFlush(batch); err != nil {
			// Log error but don't fail - metrics are still in memory
			_ = err
		}
	}
}

// GetBufferedCount returns the number of buffered events.
func (dt *DownloadTracker) GetBufferedCount() int {
	dt.batchMu.Lock()
	defer dt.batchMu.Unlock()
	return len(dt.batchBuffer)
}

// ============================================================================
// Statistics Functions
// ============================================================================

// DownloadStats contains download statistics summary.
type DownloadStats struct {
	TotalDownloads    int64            `json:"total_downloads"`
	UniqueDevices     int              `json:"unique_devices"`
	FormatBreakdown   map[string]int64 `json:"format_breakdown"`
	PlatformBreakdown map[string]int64 `json:"platform_breakdown"`
	HourlyRate        float64          `json:"hourly_rate"`
	AnomalyCount      int64            `json:"anomaly_count"`
	TopFormats        []FormatCount    `json:"top_formats"`
	TopPlatforms      []PlatformCount  `json:"top_platforms"`
}

// FormatCount represents download count by format.
type FormatCount struct {
	Format string `json:"format"`
	Count  int64  `json:"count"`
}

// PlatformCount represents download count by platform.
type PlatformCount struct {
	Platform string `json:"platform"`
	Count    int64  `json:"count"`
}

// GetStats returns comprehensive download statistics.
func (dt *DownloadTracker) GetStats() *DownloadStats {
	metrics := dt.GetMetrics()

	stats := &DownloadStats{
		TotalDownloads:    metrics.TotalDownloads,
		UniqueDevices:     metrics.UniqueIPs,
		FormatBreakdown:   metrics.ByFormat,
		PlatformBreakdown: metrics.ByPlatform,
		HourlyRate:        metrics.DownloadsPerHour,
		AnomalyCount:      dt.GetAnomalyCount(),
	}

	// Build top formats
	for format, count := range metrics.ByFormat {
		stats.TopFormats = append(stats.TopFormats, FormatCount{Format: format, Count: count})
	}

	// Build top platforms
	for platform, count := range metrics.ByPlatform {
		stats.TopPlatforms = append(stats.TopPlatforms, PlatformCount{Platform: platform, Count: count})
	}

	return stats
}

// ============================================================================
// Platform Detection
// ============================================================================

// detectPlatformFromUA detects the platform from User-Agent string.
func detectPlatformFromUA(userAgent string) string {
	ua := strings.ToLower(userAgent)

	if strings.Contains(ua, "iphone") || strings.Contains(ua, "ipad") {
		return "iOS"
	}
	if strings.Contains(ua, "android") {
		return "Android"
	}
	if strings.Contains(ua, "windows") {
		return "Windows"
	}
	if strings.Contains(ua, "macintosh") || strings.Contains(ua, "mac os") {
		return "macOS"
	}
	if strings.Contains(ua, "linux") {
		return "Linux"
	}
	if strings.Contains(ua, "curl") {
		return "CLI/curl"
	}
	if strings.Contains(ua, "wget") {
		return "CLI/wget"
	}

	return "Unknown"
}

// ============================================================================
// Repository Integration
// ============================================================================

// DownloadRepository interface for database operations.
type DownloadRecorder interface {
	RecordDownload(ctx context.Context, event *DownloadEvent) error
	BulkRecordDownloads(ctx context.Context, events []*DownloadEvent) error
}

// SetRepository sets the download repository for database persistence.
func (dt *DownloadTracker) SetRepository(repo DownloadRecorder) {
	dt.SetBatchFlushCallback(func(events []*DownloadEvent) error {
		// Convert events for repository
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		return repo.BulkRecordDownloads(ctx, events)
	})
}
