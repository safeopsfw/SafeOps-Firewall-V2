// Package metrics provides Prometheus metrics utilities.
package metrics

import (
	"net/http"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

// Counter wraps prometheus.Counter
type Counter struct {
	counter prometheus.Counter
}

// NewCounter creates a new counter
func NewCounter(name, help string) *Counter {
	c := prometheus.NewCounter(prometheus.CounterOpts{
		Name: name,
		Help: help,
	})
	prometheus.MustRegister(c)
	return &Counter{counter: c}
}

// Inc increments the counter by 1
func (c *Counter) Inc() {
	c.counter.Inc()
}

// Add adds the given value to the counter
func (c *Counter) Add(v float64) {
	c.counter.Add(v)
}

// CounterVec wraps prometheus.CounterVec
type CounterVec struct {
	counterVec *prometheus.CounterVec
}

// NewCounterVec creates a new counter vector
func NewCounterVec(name, help string, labels []string) *CounterVec {
	c := prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: name,
		Help: help,
	}, labels)
	prometheus.MustRegister(c)
	return &CounterVec{counterVec: c}
}

// WithLabels returns a counter for the given label values
func (c *CounterVec) WithLabels(labels prometheus.Labels) prometheus.Counter {
	return c.counterVec.With(labels)
}

// Inc increments the counter for the given labels
func (c *CounterVec) Inc(labels prometheus.Labels) {
	c.counterVec.With(labels).Inc()
}

// Gauge wraps prometheus.Gauge
type Gauge struct {
	gauge prometheus.Gauge
}

// NewGauge creates a new gauge
func NewGauge(name, help string) *Gauge {
	g := prometheus.NewGauge(prometheus.GaugeOpts{
		Name: name,
		Help: help,
	})
	prometheus.MustRegister(g)
	return &Gauge{gauge: g}
}

// Set sets the gauge to the given value
func (g *Gauge) Set(v float64) {
	g.gauge.Set(v)
}

// Inc increments the gauge by 1
func (g *Gauge) Inc() {
	g.gauge.Inc()
}

// Dec decrements the gauge by 1
func (g *Gauge) Dec() {
	g.gauge.Dec()
}

// Add adds the given value to the gauge
func (g *Gauge) Add(v float64) {
	g.gauge.Add(v)
}

// Sub subtracts the given value from the gauge
func (g *Gauge) Sub(v float64) {
	g.gauge.Sub(v)
}

// GaugeVec wraps prometheus.GaugeVec
type GaugeVec struct {
	gaugeVec *prometheus.GaugeVec
}

// NewGaugeVec creates a new gauge vector
func NewGaugeVec(name, help string, labels []string) *GaugeVec {
	g := prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Name: name,
		Help: help,
	}, labels)
	prometheus.MustRegister(g)
	return &GaugeVec{gaugeVec: g}
}

// WithLabels returns a gauge for the given label values
func (g *GaugeVec) WithLabels(labels prometheus.Labels) prometheus.Gauge {
	return g.gaugeVec.With(labels)
}

// Set sets the gauge for the given labels
func (g *GaugeVec) Set(labels prometheus.Labels, v float64) {
	g.gaugeVec.With(labels).Set(v)
}

// Histogram wraps prometheus.Histogram
type Histogram struct {
	histogram prometheus.Histogram
}

// NewHistogram creates a new histogram
func NewHistogram(name, help string, buckets []float64) *Histogram {
	h := prometheus.NewHistogram(prometheus.HistogramOpts{
		Name:    name,
		Help:    help,
		Buckets: buckets,
	})
	prometheus.MustRegister(h)
	return &Histogram{histogram: h}
}

// Observe records a value
func (h *Histogram) Observe(v float64) {
	h.histogram.Observe(v)
}

// Timer returns a timer that observes duration on stop
func (h *Histogram) Timer() *Timer {
	return &Timer{
		histogram: h.histogram,
		start:     time.Now(),
	}
}

// HistogramVec wraps prometheus.HistogramVec
type HistogramVec struct {
	histogramVec *prometheus.HistogramVec
}

// NewHistogramVec creates a new histogram vector
func NewHistogramVec(name, help string, labels []string, buckets []float64) *HistogramVec {
	h := prometheus.NewHistogramVec(prometheus.HistogramOpts{
		Name:    name,
		Help:    help,
		Buckets: buckets,
	}, labels)
	prometheus.MustRegister(h)
	return &HistogramVec{histogramVec: h}
}

// WithLabels returns a histogram for the given label values
func (h *HistogramVec) WithLabels(labels prometheus.Labels) prometheus.Observer {
	return h.histogramVec.With(labels)
}

// Observe records a value for the given labels
func (h *HistogramVec) Observe(labels prometheus.Labels, v float64) {
	h.histogramVec.With(labels).Observe(v)
}

// Summary wraps prometheus.Summary
type Summary struct {
	summary prometheus.Summary
}

// NewSummary creates a new summary with default quantiles
func NewSummary(name, help string) *Summary {
	s := prometheus.NewSummary(prometheus.SummaryOpts{
		Name: name,
		Help: help,
	})
	prometheus.MustRegister(s)
	return &Summary{summary: s}
}

// NewSummaryWithQuantiles creates a summary with custom quantiles
func NewSummaryWithQuantiles(name, help string, objectives map[float64]float64) *Summary {
	s := prometheus.NewSummary(prometheus.SummaryOpts{
		Name:       name,
		Help:       help,
		Objectives: objectives,
	})
	prometheus.MustRegister(s)
	return &Summary{summary: s}
}

// Observe records a value
func (s *Summary) Observe(v float64) {
	s.summary.Observe(v)
}

// Timer for measuring durations
type Timer struct {
	histogram prometheus.Histogram
	start     time.Time
}

// Stop stops the timer and records the duration
func (t *Timer) Stop() time.Duration {
	duration := time.Since(t.start)
	t.histogram.Observe(duration.Seconds())
	return duration
}

// Pre-configured bucket sets for different measurement scales

// DefaultBuckets for HTTP latency (milliseconds to seconds range)
var DefaultBuckets = []float64{.005, .01, .025, .05, .1, .25, .5, 1, 2.5, 5, 10}

// LatencyMicroBuckets for microsecond-level measurements
var LatencyMicroBuckets = []float64{
	0.000001, 0.000005, 0.00001, 0.000025, 0.00005, // 1-50 µs
	0.0001, 0.00025, 0.0005, 0.001, // 100-1000 µs
}

// LatencyMilliBuckets for millisecond-level measurements
var LatencyMilliBuckets = []float64{
	0.001, 0.002, 0.005, 0.01, 0.025, // 1-25 ms
	0.05, 0.1, 0.25, 0.5, 1.0, // 50ms-1s
}

// LatencySecondsBuckets for second-level measurements
var LatencySecondsBuckets = DefaultBuckets

// ByteBuckets for byte-level sizes (64B to 128KB)
var ByteBuckets = prometheus.ExponentialBuckets(64, 2, 12)

// SizeKBBuckets for kilobyte-level sizes
var SizeKBBuckets = []float64{
	1, 5, 10, 25, 50, // KB
	100, 250, 500, 1024, // KB to MB
}

// SizeMBBuckets for megabyte-level sizes
var SizeMBBuckets = []float64{
	1, 5, 10, 25, 50, // MB
	100, 250, 500, 1024, 10240, // MB to GB
}

// DefaultQuantiles for summaries (p50, p90, p95, p99)
var DefaultQuantiles = map[float64]float64{
	0.5:  0.05,  // p50 with 5% error
	0.9:  0.01,  // p90 with 1% error
	0.95: 0.01,  // p95 with 1% error
	0.99: 0.001, // p99 with 0.1% error
}

// Common metric collection
type CommonMetrics struct {
	RequestsTotal    *CounterVec
	RequestDuration  *HistogramVec
	RequestsInFlight *Gauge
	ErrorsTotal      *CounterVec
}

// NewCommonMetrics creates common service metrics
func NewCommonMetrics(namespace string) *CommonMetrics {
	return &CommonMetrics{
		RequestsTotal: NewCounterVec(
			namespace+"_requests_total",
			"Total number of requests",
			[]string{"method", "path", "status"},
		),
		RequestDuration: NewHistogramVec(
			namespace+"_request_duration_seconds",
			"Request duration in seconds",
			[]string{"method", "path"},
			DefaultBuckets,
		),
		RequestsInFlight: NewGauge(
			namespace+"_requests_in_flight",
			"Number of requests currently being processed",
		),
		ErrorsTotal: NewCounterVec(
			namespace+"_errors_total",
			"Total number of errors",
			[]string{"type"},
		),
	}
}

// Handler returns the Prometheus HTTP handler
func Handler() http.Handler {
	return promhttp.Handler()
}
// ============================================================================
// MetricsRegistry - High-Level Metrics Recording API
// ============================================================================

// MetricsRegistry provides a centralized registry for common service metrics
type MetricsRegistry struct {
namespace string

// Core service metrics
requestsTotal   *prometheus.CounterVec
requestDuration *prometheus.HistogramVec
errorsTotal     *prometheus.CounterVec

// Database metrics
dbQueryDuration *prometheus.HistogramVec
dbQueriesTotal  *prometheus.CounterVec

// Cache metrics
cacheHitsTotal   *prometheus.CounterVec
cacheMissesTotal *prometheus.CounterVec
}

// NewMetricsRegistry creates a new metrics registry with pre-configured metrics
func NewMetricsRegistry(namespace string) *MetricsRegistry {
mr := &MetricsRegistry{
namespace: namespace,

requestsTotal: prometheus.NewCounterVec(
prometheus.CounterOpts{
Namespace: namespace,
Name:      "requests_total",
Help:      "Total number of requests processed",
},
[]string{"service", "method", "status"},
),

requestDuration: prometheus.NewHistogramVec(
prometheus.HistogramOpts{
Namespace: namespace,
Name:      "request_duration_seconds",
Help:      "Request duration in seconds",
Buckets:   DefaultBuckets,
},
[]string{"service", "method"},
),

errorsTotal: prometheus.NewCounterVec(
prometheus.CounterOpts{
Namespace: namespace,
Name:      "errors_total",
Help:      "Total number of errors",
},
[]string{"service", "type"},
),

dbQueryDuration: prometheus.NewHistogramVec(
prometheus.HistogramOpts{
Namespace: namespace,
Name:      "db_query_duration_seconds",
Help:      "Database query duration in seconds",
Buckets:   []float64{.001, .005, .01, .025, .05, .1, .25, .5, 1, 2.5, 5},
},
[]string{"query_type"},
),

dbQueriesTotal: prometheus.NewCounterVec(
prometheus.CounterOpts{
Namespace: namespace,
Name:      "db_queries_total",
Help:      "Total number of database queries",
},
[]string{"query_type", "status"},
),

cacheHitsTotal: prometheus.NewCounterVec(
prometheus.CounterOpts{
Namespace: namespace,
Name:      "cache_hits_total",
Help:      "Total number of cache hits",
},
[]string{"operation"},
),

cacheMissesTotal: prometheus.NewCounterVec(
prometheus.CounterOpts{
Namespace: namespace,
Name:      "cache_misses_total",
Help:      "Total number of cache misses",
},
[]string{"operation"},
),
}

// Register all metrics
prometheus.MustRegister(mr.requestsTotal)
prometheus.MustRegister(mr.requestDuration)
prometheus.MustRegister(mr.errorsTotal)
prometheus.MustRegister(mr.dbQueryDuration)
prometheus.MustRegister(mr.dbQueriesTotal)
prometheus.MustRegister(mr.cacheHitsTotal)
prometheus.MustRegister(mr.cacheMissesTotal)

return mr
}

// RecordRequest records a service request with duration
func (mr *MetricsRegistry) RecordRequest(service, method string, duration time.Duration, status string) {
mr.requestsTotal.WithLabelValues(service, method, status).Inc()
mr.requestDuration.WithLabelValues(service, method).Observe(duration.Seconds())
}

// RecordError records an error occurrence
func (mr *MetricsRegistry) RecordError(service, errorType string) {
mr.errorsTotal.WithLabelValues(service, errorType).Inc()
}

// RecordDBQuery records a database query with duration and result
func (mr *MetricsRegistry) RecordDBQuery(queryType string, duration time.Duration, err error) {
mr.dbQueryDuration.WithLabelValues(queryType).Observe(duration.Seconds())

status := "success"
if err != nil {
status = "error"
}
mr.dbQueriesTotal.WithLabelValues(queryType, status).Inc()
}

// RecordCacheHit records a cache hit
func (mr *MetricsRegistry) RecordCacheHit(operation string) {
mr.cacheHitsTotal.WithLabelValues(operation).Inc()
}

// RecordCacheMiss records a cache miss
func (mr *MetricsRegistry) RecordCacheMiss(operation string) {
mr.cacheMissesTotal.WithLabelValues(operation).Inc()
}

// GetRequestsTotal returns the requests counter
func (mr *MetricsRegistry) GetRequestsTotal() *prometheus.CounterVec {
return mr.requestsTotal
}

// GetRequestDuration returns the request duration histogram
func (mr *MetricsRegistry) GetRequestDuration() *prometheus.HistogramVec {
return mr.requestDuration
}

// GetErrorsTotal returns the errors counter
func (mr *MetricsRegistry) GetErrorsTotal() *prometheus.CounterVec {
return mr.errorsTotal
}

// GetDBQueryDuration returns the database query duration histogram
func (mr *MetricsRegistry) GetDBQueryDuration() *prometheus.HistogramVec {
return mr.dbQueryDuration
}
