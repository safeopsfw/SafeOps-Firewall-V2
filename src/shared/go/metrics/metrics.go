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

// NewSummary creates a new summary
func NewSummary(name, help string) *Summary {
	s := prometheus.NewSummary(prometheus.SummaryOpts{
		Name: name,
		Help: help,
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

// DefaultBuckets for HTTP latency
var DefaultBuckets = []float64{.005, .01, .025, .05, .1, .25, .5, 1, 2.5, 5, 10}

// ByteBuckets for sizes
var ByteBuckets = prometheus.ExponentialBuckets(64, 2, 12)

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
