// Package monitoring provides Prometheus metrics exposition for Certificate Manager.
package monitoring

import (
	"context"
	"fmt"
	"log"
	"net/http"
	"sync"
	"time"
)

// ============================================================================
// Prometheus Metric Types (simplified for standalone implementation)
// ============================================================================

// MetricType represents the type of Prometheus metric.
type MetricType string

const (
	MetricCounter   MetricType = "counter"
	MetricGauge     MetricType = "gauge"
	MetricHistogram MetricType = "histogram"
)

// Metric represents a single Prometheus metric.
type Metric struct {
	Name         string
	Type         MetricType
	Help         string
	Labels       map[string]string
	Value        float64
	Buckets      []float64          // For histograms
	BucketCounts map[float64]uint64 // For histograms
	Sum          float64            // For histograms
	Count        uint64             // For histograms
}

// ============================================================================
// Metric Names (Constants)
// ============================================================================

const (
	MetricsNamespace = "certificate_manager"

	// Certificate metrics
	MetricCertificatesIssuedTotal    = "certificates_issued_total"
	MetricCertificatesRevokedTotal   = "certificates_revoked_total"
	MetricCertificatesActive         = "certificates_active"
	MetricCertificatesExpiringSoon   = "certificates_expiring_soon"
	MetricCertSigningDurationSeconds = "certificate_signing_duration_seconds"

	// Device metrics
	MetricDevicesTotal                = "devices_total"
	MetricDevicesWithCAInstalled      = "devices_with_ca_installed"
	MetricCAAdoptionPercentage        = "ca_adoption_percentage"
	MetricNewDeviceInstallationsTotal = "new_device_installations_total"

	// Download metrics
	MetricCADownloadsTotal       = "ca_downloads_total"
	MetricDownloadConversionRate = "download_conversion_rate"

	// Revocation metrics
	MetricCRLUpdateDurationSeconds    = "crl_update_duration_seconds"
	MetricCRLSizeBytes                = "crl_size_bytes"
	MetricCRLEntriesTotal             = "crl_entries_total"
	MetricOCSPRequestsTotal           = "ocsp_requests_total"
	MetricOCSPResponseDurationSeconds = "ocsp_response_duration_seconds"

	// gRPC metrics
	MetricGRPCRequestsTotal          = "grpc_requests_total"
	MetricGRPCRequestDurationSeconds = "grpc_request_duration_seconds"
	MetricGRPCErrorRate              = "grpc_error_rate"

	// HTTP metrics
	MetricHTTPRequestsTotal          = "http_requests_total"
	MetricHTTPRequestDurationSeconds = "http_request_duration_seconds"

	// System metrics
	MetricDiskSpaceAvailableBytes   = "disk_space_available_bytes"
	MetricDatabaseConnectionsActive = "database_connections_active"
	MetricCacheHitRate              = "cache_hit_rate"
)

// ============================================================================
// Metrics Collector
// ============================================================================

// MetricsCollector collects and exposes Prometheus metrics.
type MetricsCollector struct {
	// Stats source
	statsCollector *StatsCollector

	// Counters (thread-safe)
	counters   map[string]*CounterMetric
	countersMu sync.RWMutex

	// Gauges (thread-safe)
	gauges   map[string]*GaugeMetric
	gaugesMu sync.RWMutex

	// Histograms (thread-safe)
	histograms   map[string]*HistogramMetric
	histogramsMu sync.RWMutex

	// Background update
	updateInterval time.Duration
	stopChan       chan struct{}
	running        bool
	runningMu      sync.Mutex
}

// CounterMetric represents a counter with labels.
type CounterMetric struct {
	Name   string
	Help   string
	Values map[string]float64 // labelKey -> value
	mu     sync.Mutex
}

// GaugeMetric represents a gauge with labels.
type GaugeMetric struct {
	Name   string
	Help   string
	Values map[string]float64 // labelKey -> value
	mu     sync.Mutex
}

// HistogramMetric represents a histogram with buckets.
type HistogramMetric struct {
	Name    string
	Help    string
	Buckets []float64
	// Per-label series
	Series map[string]*HistogramSeries
	mu     sync.Mutex
}

// HistogramSeries holds histogram data for one label combination.
type HistogramSeries struct {
	BucketCounts map[float64]uint64
	Sum          float64
	Count        uint64
}

// NewMetricsCollector creates a new metrics collector.
func NewMetricsCollector(statsCollector *StatsCollector) *MetricsCollector {
	mc := &MetricsCollector{
		statsCollector: statsCollector,
		counters:       make(map[string]*CounterMetric),
		gauges:         make(map[string]*GaugeMetric),
		histograms:     make(map[string]*HistogramMetric),
		updateInterval: 60 * time.Second,
		stopChan:       make(chan struct{}),
	}

	// Register all metrics
	mc.registerMetrics()

	return mc
}

// ============================================================================
// Metric Registration
// ============================================================================

// registerMetrics registers all Certificate Manager metrics.
func (mc *MetricsCollector) registerMetrics() {
	// Certificate counters
	mc.registerCounter(MetricCertificatesIssuedTotal,
		"Total certificates issued by CA")
	mc.registerCounter(MetricCertificatesRevokedTotal,
		"Total certificates revoked")

	// Certificate gauges
	mc.registerGauge(MetricCertificatesActive,
		"Currently active certificates (valid and not revoked)")
	mc.registerGauge(MetricCertificatesExpiringSoon,
		"Certificates expiring within threshold")

	// Certificate histograms
	mc.registerHistogram(MetricCertSigningDurationSeconds,
		"Time to sign a certificate",
		[]float64{0.01, 0.05, 0.1, 0.5, 1.0, 5.0, 10.0})

	// Device gauges
	mc.registerGauge(MetricDevicesTotal, "Total unique devices seen")
	mc.registerGauge(MetricDevicesWithCAInstalled, "Devices with CA installed")
	mc.registerGauge(MetricCAAdoptionPercentage, "Percentage of devices with CA")

	// Device counters
	mc.registerCounter(MetricNewDeviceInstallationsTotal,
		"New CA installations detected")

	// Download counters
	mc.registerCounter(MetricCADownloadsTotal, "CA certificate downloads by format")

	// Download gauges
	mc.registerGauge(MetricDownloadConversionRate,
		"Percentage of downloads that resulted in installation")

	// Revocation histograms
	mc.registerHistogram(MetricCRLUpdateDurationSeconds,
		"Time to generate and sign CRL",
		[]float64{0.1, 0.5, 1.0, 5.0, 10.0, 30.0})

	// Revocation gauges
	mc.registerGauge(MetricCRLSizeBytes, "Size of current CRL file in bytes")
	mc.registerGauge(MetricCRLEntriesTotal, "Number of revoked certificates in CRL")

	// OCSP counters
	mc.registerCounter(MetricOCSPRequestsTotal, "Total OCSP requests received")

	// OCSP histograms
	mc.registerHistogram(MetricOCSPResponseDurationSeconds,
		"OCSP response latency",
		[]float64{0.001, 0.005, 0.01, 0.05, 0.1, 0.5})

	// gRPC counters
	mc.registerCounter(MetricGRPCRequestsTotal, "Total gRPC requests received")

	// gRPC histograms
	mc.registerHistogram(MetricGRPCRequestDurationSeconds,
		"gRPC request latency",
		[]float64{0.01, 0.05, 0.1, 0.5, 1.0, 5.0})

	// gRPC gauges
	mc.registerGauge(MetricGRPCErrorRate, "Percentage of failed gRPC requests")

	// HTTP counters
	mc.registerCounter(MetricHTTPRequestsTotal, "Total HTTP requests to distribution server")

	// HTTP histograms
	mc.registerHistogram(MetricHTTPRequestDurationSeconds,
		"HTTP request latency",
		[]float64{0.001, 0.005, 0.01, 0.05, 0.1, 0.5})

	// System gauges
	mc.registerGauge(MetricDiskSpaceAvailableBytes, "Available disk space")
	mc.registerGauge(MetricDatabaseConnectionsActive, "Active database connections")
	mc.registerGauge(MetricCacheHitRate, "Certificate signing cache hit rate")

	log.Println("[Metrics] All metrics registered")
}

func (mc *MetricsCollector) registerCounter(name, help string) {
	mc.countersMu.Lock()
	defer mc.countersMu.Unlock()

	mc.counters[name] = &CounterMetric{
		Name:   name,
		Help:   help,
		Values: make(map[string]float64),
	}
}

func (mc *MetricsCollector) registerGauge(name, help string) {
	mc.gaugesMu.Lock()
	defer mc.gaugesMu.Unlock()

	mc.gauges[name] = &GaugeMetric{
		Name:   name,
		Help:   help,
		Values: make(map[string]float64),
	}
}

func (mc *MetricsCollector) registerHistogram(name, help string, buckets []float64) {
	mc.histogramsMu.Lock()
	defer mc.histogramsMu.Unlock()

	mc.histograms[name] = &HistogramMetric{
		Name:    name,
		Help:    help,
		Buckets: buckets,
		Series:  make(map[string]*HistogramSeries),
	}
}

// ============================================================================
// Counter Operations
// ============================================================================

// IncCounter increments a counter metric.
func (mc *MetricsCollector) IncCounter(name string, labels map[string]string) {
	mc.AddCounter(name, 1, labels)
}

// AddCounter adds to a counter metric.
func (mc *MetricsCollector) AddCounter(name string, value float64, labels map[string]string) {
	mc.countersMu.RLock()
	counter, exists := mc.counters[name]
	mc.countersMu.RUnlock()

	if !exists {
		return
	}

	labelKey := labelsToKey(labels)

	counter.mu.Lock()
	counter.Values[labelKey] += value
	counter.mu.Unlock()
}

// ============================================================================
// Gauge Operations
// ============================================================================

// SetGauge sets a gauge metric value.
func (mc *MetricsCollector) SetGauge(name string, value float64, labels map[string]string) {
	mc.gaugesMu.RLock()
	gauge, exists := mc.gauges[name]
	mc.gaugesMu.RUnlock()

	if !exists {
		return
	}

	labelKey := labelsToKey(labels)

	gauge.mu.Lock()
	gauge.Values[labelKey] = value
	gauge.mu.Unlock()
}

// ============================================================================
// Histogram Operations
// ============================================================================

// ObserveHistogram records a value in a histogram.
func (mc *MetricsCollector) ObserveHistogram(name string, value float64, labels map[string]string) {
	mc.histogramsMu.RLock()
	histogram, exists := mc.histograms[name]
	mc.histogramsMu.RUnlock()

	if !exists {
		return
	}

	labelKey := labelsToKey(labels)

	histogram.mu.Lock()
	defer histogram.mu.Unlock()

	series, exists := histogram.Series[labelKey]
	if !exists {
		series = &HistogramSeries{
			BucketCounts: make(map[float64]uint64),
		}
		for _, bucket := range histogram.Buckets {
			series.BucketCounts[bucket] = 0
		}
		histogram.Series[labelKey] = series
	}

	// Update bucket counts
	for _, bucket := range histogram.Buckets {
		if value <= bucket {
			series.BucketCounts[bucket]++
		}
	}

	series.Sum += value
	series.Count++
}

// ============================================================================
// Convenience Methods
// ============================================================================

// RecordCertificateIssued records a certificate issuance.
func (mc *MetricsCollector) RecordCertificateIssued(certType, issuedFor string) {
	mc.IncCounter(MetricCertificatesIssuedTotal, map[string]string{
		"certificate_type": certType,
		"issued_for":       issuedFor,
	})
}

// RecordCertificateRevoked records a certificate revocation.
func (mc *MetricsCollector) RecordCertificateRevoked(reason, revokedBy string) {
	mc.IncCounter(MetricCertificatesRevokedTotal, map[string]string{
		"revocation_reason": reason,
		"revoked_by":        revokedBy,
	})
}

// RecordCertificateSigningDuration records certificate signing latency.
func (mc *MetricsCollector) RecordCertificateSigningDuration(duration time.Duration, certType string) {
	mc.ObserveHistogram(MetricCertSigningDurationSeconds, duration.Seconds(), map[string]string{
		"certificate_type": certType,
	})
}

// RecordCADownload records a CA certificate download.
func (mc *MetricsCollector) RecordCADownload(format, platform string) {
	mc.IncCounter(MetricCADownloadsTotal, map[string]string{
		"format":   format,
		"platform": platform,
	})
}

// RecordOCSPRequest records an OCSP request.
func (mc *MetricsCollector) RecordOCSPRequest(responseStatus string) {
	mc.IncCounter(MetricOCSPRequestsTotal, map[string]string{
		"response_status": responseStatus,
	})
}

// RecordOCSPResponseDuration records OCSP response latency.
func (mc *MetricsCollector) RecordOCSPResponseDuration(duration time.Duration, status string) {
	mc.ObserveHistogram(MetricOCSPResponseDurationSeconds, duration.Seconds(), map[string]string{
		"response_status": status,
	})
}

// RecordGRPCRequest records a gRPC request.
func (mc *MetricsCollector) RecordGRPCRequest(method, status string) {
	mc.IncCounter(MetricGRPCRequestsTotal, map[string]string{
		"method": method,
		"status": status,
	})
}

// RecordGRPCRequestDuration records gRPC request latency.
func (mc *MetricsCollector) RecordGRPCRequestDuration(duration time.Duration, method string) {
	mc.ObserveHistogram(MetricGRPCRequestDurationSeconds, duration.Seconds(), map[string]string{
		"method": method,
	})
}

// RecordHTTPRequest records an HTTP request.
func (mc *MetricsCollector) RecordHTTPRequest(endpoint string, statusCode int) {
	mc.IncCounter(MetricHTTPRequestsTotal, map[string]string{
		"endpoint":    endpoint,
		"status_code": fmt.Sprintf("%d", statusCode),
	})
}

// RecordHTTPRequestDuration records HTTP request latency.
func (mc *MetricsCollector) RecordHTTPRequestDuration(duration time.Duration, endpoint string) {
	mc.ObserveHistogram(MetricHTTPRequestDurationSeconds, duration.Seconds(), map[string]string{
		"endpoint": endpoint,
	})
}

// RecordCRLUpdateDuration records CRL generation latency.
func (mc *MetricsCollector) RecordCRLUpdateDuration(duration time.Duration) {
	mc.ObserveHistogram(MetricCRLUpdateDurationSeconds, duration.Seconds(), nil)
}

// RecordNewDeviceInstallation records a new CA installation.
func (mc *MetricsCollector) RecordNewDeviceInstallation(method string) {
	mc.IncCounter(MetricNewDeviceInstallationsTotal, map[string]string{
		"installation_method": method,
	})
}

// ============================================================================
// Background Updates
// ============================================================================

// StartBackgroundUpdates starts periodic gauge updates from stats.
func (mc *MetricsCollector) StartBackgroundUpdates() {
	mc.runningMu.Lock()
	if mc.running {
		mc.runningMu.Unlock()
		return
	}
	mc.running = true
	mc.runningMu.Unlock()

	log.Println("[Metrics] Starting background metric updates")

	go func() {
		ticker := time.NewTicker(mc.updateInterval)
		defer ticker.Stop()

		// Run initial update
		mc.updateGaugesFromStats()

		for {
			select {
			case <-ticker.C:
				mc.updateGaugesFromStats()
			case <-mc.stopChan:
				log.Println("[Metrics] Background updates stopped")
				return
			}
		}
	}()
}

// StopBackgroundUpdates stops periodic updates.
func (mc *MetricsCollector) StopBackgroundUpdates() {
	mc.runningMu.Lock()
	defer mc.runningMu.Unlock()

	if mc.running {
		close(mc.stopChan)
		mc.running = false
	}
}

// updateGaugesFromStats fetches current statistics and updates gauges.
func (mc *MetricsCollector) updateGaugesFromStats() {
	if mc.statsCollector == nil {
		return
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// Update certificate stats
	certStats, err := mc.statsCollector.GetCertificateStats(ctx)
	if err == nil {
		mc.SetGauge(MetricCertificatesActive, float64(certStats.ActiveCertificates), nil)
		mc.SetGauge(MetricCertificatesExpiringSoon, float64(certStats.ExpiringSoon7Days),
			map[string]string{"days": "7"})
		mc.SetGauge(MetricCertificatesExpiringSoon, float64(certStats.ExpiringSoon30Days),
			map[string]string{"days": "30"})
	}

	// Update device stats
	deviceStats, err := mc.statsCollector.GetDeviceAdoptionStats(ctx)
	if err == nil {
		mc.SetGauge(MetricDevicesTotal, float64(deviceStats.TotalDevices), nil)
		mc.SetGauge(MetricDevicesWithCAInstalled, float64(deviceStats.DevicesWithCA), nil)
		mc.SetGauge(MetricCAAdoptionPercentage, deviceStats.AdoptionPercentage, nil)
	}

	// Update download stats
	downloadStats, err := mc.statsCollector.GetDownloadStats(ctx)
	if err == nil {
		mc.SetGauge(MetricDownloadConversionRate, downloadStats.DownloadConversionRate, nil)
	}

	// Update revocation stats
	revocationStats, err := mc.statsCollector.GetRevocationStats(ctx)
	if err == nil {
		mc.SetGauge(MetricCRLSizeBytes, float64(revocationStats.CRLSizeBytes), nil)
		mc.SetGauge(MetricCRLEntriesTotal, float64(revocationStats.TotalRevoked), nil)
	}

	// Update performance stats
	perfStats, err := mc.statsCollector.GetPerformanceStats(ctx)
	if err == nil {
		mc.SetGauge(MetricGRPCErrorRate, perfStats.GRPCErrorRate, nil)
		mc.SetGauge(MetricCacheHitRate, perfStats.CacheHitRate, nil)
		mc.SetGauge(MetricDatabaseConnectionsActive, 0, nil) // Would come from DB pool
	}

	log.Println("[Metrics] Gauges updated from stats")
}

// ============================================================================
// Prometheus Exposition Format
// ============================================================================

// HTTPHandler returns an HTTP handler for the /metrics endpoint.
func (mc *MetricsCollector) HTTPHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain; version=0.0.4; charset=utf-8")
		w.WriteHeader(http.StatusOK)

		// Write counters
		mc.countersMu.RLock()
		for name, counter := range mc.counters {
			mc.writeCounter(w, name, counter)
		}
		mc.countersMu.RUnlock()

		// Write gauges
		mc.gaugesMu.RLock()
		for name, gauge := range mc.gauges {
			mc.writeGauge(w, name, gauge)
		}
		mc.gaugesMu.RUnlock()

		// Write histograms
		mc.histogramsMu.RLock()
		for name, histogram := range mc.histograms {
			mc.writeHistogram(w, name, histogram)
		}
		mc.histogramsMu.RUnlock()
	})
}

func (mc *MetricsCollector) writeCounter(w http.ResponseWriter, name string, counter *CounterMetric) {
	fullName := fmt.Sprintf("%s_%s", MetricsNamespace, name)

	counter.mu.Lock()
	defer counter.mu.Unlock()

	if len(counter.Values) == 0 {
		fmt.Fprintf(w, "# HELP %s %s\n", fullName, counter.Help)
		fmt.Fprintf(w, "# TYPE %s counter\n", fullName)
		fmt.Fprintf(w, "%s 0\n\n", fullName)
		return
	}

	fmt.Fprintf(w, "# HELP %s %s\n", fullName, counter.Help)
	fmt.Fprintf(w, "# TYPE %s counter\n", fullName)

	for labelKey, value := range counter.Values {
		if labelKey == "" {
			fmt.Fprintf(w, "%s %g\n", fullName, value)
		} else {
			fmt.Fprintf(w, "%s{%s} %g\n", fullName, labelKey, value)
		}
	}
	fmt.Fprintln(w)
}

func (mc *MetricsCollector) writeGauge(w http.ResponseWriter, name string, gauge *GaugeMetric) {
	fullName := fmt.Sprintf("%s_%s", MetricsNamespace, name)

	gauge.mu.Lock()
	defer gauge.mu.Unlock()

	if len(gauge.Values) == 0 {
		fmt.Fprintf(w, "# HELP %s %s\n", fullName, gauge.Help)
		fmt.Fprintf(w, "# TYPE %s gauge\n", fullName)
		fmt.Fprintf(w, "%s 0\n\n", fullName)
		return
	}

	fmt.Fprintf(w, "# HELP %s %s\n", fullName, gauge.Help)
	fmt.Fprintf(w, "# TYPE %s gauge\n", fullName)

	for labelKey, value := range gauge.Values {
		if labelKey == "" {
			fmt.Fprintf(w, "%s %g\n", fullName, value)
		} else {
			fmt.Fprintf(w, "%s{%s} %g\n", fullName, labelKey, value)
		}
	}
	fmt.Fprintln(w)
}

func (mc *MetricsCollector) writeHistogram(w http.ResponseWriter, name string, histogram *HistogramMetric) {
	fullName := fmt.Sprintf("%s_%s", MetricsNamespace, name)

	histogram.mu.Lock()
	defer histogram.mu.Unlock()

	fmt.Fprintf(w, "# HELP %s %s\n", fullName, histogram.Help)
	fmt.Fprintf(w, "# TYPE %s histogram\n", fullName)

	if len(histogram.Series) == 0 {
		// Write empty histogram
		for _, bucket := range histogram.Buckets {
			fmt.Fprintf(w, "%s_bucket{le=\"%g\"} 0\n", fullName, bucket)
		}
		fmt.Fprintf(w, "%s_bucket{le=\"+Inf\"} 0\n", fullName)
		fmt.Fprintf(w, "%s_sum 0\n", fullName)
		fmt.Fprintf(w, "%s_count 0\n\n", fullName)
		return
	}

	for labelKey, series := range histogram.Series {
		labelPrefix := ""
		if labelKey != "" {
			labelPrefix = labelKey + ","
		}

		// Write bucket counts (cumulative)
		for _, bucket := range histogram.Buckets {
			count := series.BucketCounts[bucket]
			if labelKey == "" {
				fmt.Fprintf(w, "%s_bucket{le=\"%g\"} %d\n", fullName, bucket, count)
			} else {
				fmt.Fprintf(w, "%s_bucket{%sle=\"%g\"} %d\n", fullName, labelPrefix, bucket, count)
			}
		}

		// +Inf bucket
		if labelKey == "" {
			fmt.Fprintf(w, "%s_bucket{le=\"+Inf\"} %d\n", fullName, series.Count)
			fmt.Fprintf(w, "%s_sum %g\n", fullName, series.Sum)
			fmt.Fprintf(w, "%s_count %d\n", fullName, series.Count)
		} else {
			fmt.Fprintf(w, "%s_bucket{%sle=\"+Inf\"} %d\n", fullName, labelPrefix, series.Count)
			fmt.Fprintf(w, "%s_sum{%s} %g\n", fullName, labelKey, series.Sum)
			fmt.Fprintf(w, "%s_count{%s} %d\n", fullName, labelKey, series.Count)
		}
	}
	fmt.Fprintln(w)
}

// ============================================================================
// Metrics Server
// ============================================================================

// MetricsServer serves the /metrics endpoint.
type MetricsServer struct {
	collector *MetricsCollector
	server    *http.Server
	port      int
}

// NewMetricsServer creates a new metrics server.
func NewMetricsServer(collector *MetricsCollector, port int) *MetricsServer {
	if port == 0 {
		port = 9160 // Default metrics port
	}

	return &MetricsServer{
		collector: collector,
		port:      port,
	}
}

// Start starts the metrics HTTP server.
func (ms *MetricsServer) Start() error {
	mux := http.NewServeMux()
	mux.Handle("/metrics", ms.collector.HTTPHandler())

	ms.server = &http.Server{
		Addr:         fmt.Sprintf(":%d", ms.port),
		Handler:      mux,
		ReadTimeout:  10 * time.Second,
		WriteTimeout: 10 * time.Second,
	}

	log.Printf("[Metrics] Starting metrics server on port %d", ms.port)

	go func() {
		if err := ms.server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Printf("[Metrics] Server error: %v", err)
		}
	}()

	return nil
}

// Stop gracefully stops the metrics server.
func (ms *MetricsServer) Stop(ctx context.Context) error {
	if ms.server == nil {
		return nil
	}

	log.Println("[Metrics] Stopping metrics server")
	return ms.server.Shutdown(ctx)
}

// ============================================================================
// Helper Functions
// ============================================================================

// labelsToKey converts a label map to a Prometheus label string.
func labelsToKey(labels map[string]string) string {
	if len(labels) == 0 {
		return ""
	}

	result := ""
	first := true
	for k, v := range labels {
		if !first {
			result += ","
		}
		result += fmt.Sprintf("%s=\"%s\"", k, v)
		first = false
	}
	return result
}

// ============================================================================
// Global Metrics Instance
// ============================================================================

var (
	globalMetrics *MetricsCollector
	globalMu      sync.RWMutex
)

// GetGlobalMetrics returns the global metrics collector instance.
func GetGlobalMetrics() *MetricsCollector {
	globalMu.RLock()
	defer globalMu.RUnlock()
	return globalMetrics
}

// SetGlobalMetrics sets the global metrics collector instance.
func SetGlobalMetrics(mc *MetricsCollector) {
	globalMu.Lock()
	defer globalMu.Unlock()
	globalMetrics = mc
}

// InitGlobalMetrics initializes and returns the global metrics collector.
func InitGlobalMetrics(statsCollector *StatsCollector) *MetricsCollector {
	mc := NewMetricsCollector(statsCollector)
	SetGlobalMetrics(mc)
	return mc
}
