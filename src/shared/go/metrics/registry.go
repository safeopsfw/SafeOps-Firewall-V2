// Package metrics provides a custom metrics registry.
package metrics

import (
	"fmt"
	"regexp"
	"sync"

	"github.com/prometheus/client_golang/prometheus"
)

// Registry manages metric registration
type Registry struct {
	namespace string
	subsystem string
	registry  *prometheus.Registry

	counters   map[string]*Counter
	gauges     map[string]*Gauge
	histograms map[string]*Histogram

	// Conflict detection metadata
	metricMetadata map[string]*metricMeta

	mu sync.RWMutex
}

// metricMeta tracks metadata for conflict detection
type metricMeta struct {
	metricType string // "counter", "gauge", "histogram", "summary"
	helpText   string
	labels     []string
	buckets    []float64 // for histograms
}

// NewRegistry creates a new metrics registry
func NewRegistry(namespace string) *Registry {
	return &Registry{
		namespace:      namespace,
		registry:       prometheus.NewRegistry(),
		counters:       make(map[string]*Counter),
		gauges:         make(map[string]*Gauge),
		histograms:     make(map[string]*Histogram),
		metricMetadata: make(map[string]*metricMeta),
	}
}

// WithSubsystem sets the subsystem
func (r *Registry) WithSubsystem(subsystem string) *Registry {
	r.subsystem = subsystem
	return r
}

// fullName builds the full metric name
func (r *Registry) fullName(name string) string {
	if r.subsystem != "" {
		return r.namespace + "_" + r.subsystem + "_" + name
	}
	return r.namespace + "_" + name
}

// Counter returns or creates a counter
func (r *Registry) Counter(name, help string) *Counter {
	r.mu.Lock()
	defer r.mu.Unlock()

	fullName := r.fullName(name)
	if c, ok := r.counters[fullName]; ok {
		return c
	}

	// Validate counter naming convention
	if err := ValidateCounterName(fullName); err != nil {
		// Log warning but don't fail
		logWarning("Counter naming convention: %v", err)
	}

	// Check for conflicts with other metric types
	if meta, exists := r.metricMetadata[fullName]; exists {
		if meta.metricType != "counter" {
			panic(fmt.Sprintf("metric '%s' already registered as %s, cannot register as counter", fullName, meta.metricType))
		}
		// Warn if help text changed
		if meta.helpText != help {
			logWarning("Counter '%s' help text changed from '%s' to '%s'", fullName, meta.helpText, help)
		}
	}

	counter := prometheus.NewCounter(prometheus.CounterOpts{
		Namespace: r.namespace,
		Subsystem: r.subsystem,
		Name:      name,
		Help:      help,
	})

	r.registry.MustRegister(counter)
	c := &Counter{counter: counter}
	r.counters[fullName] = c

	// Store metadata
	r.metricMetadata[fullName] = &metricMeta{
		metricType: "counter",
		helpText:   help,
	}

	return c
}

// Gauge returns or creates a gauge
func (r *Registry) Gauge(name, help string) *Gauge {
	r.mu.Lock()
	defer r.mu.Unlock()

	fullName := r.fullName(name)
	if g, ok := r.gauges[fullName]; ok {
		return g
	}

	// Check for conflicts
	if meta, exists := r.metricMetadata[fullName]; exists {
		if meta.metricType != "gauge" {
			panic(fmt.Sprintf("metric '%s' already registered as %s, cannot register as gauge", fullName, meta.metricType))
		}
		if meta.helpText != help {
			logWarning("Gauge '%s' help text changed from '%s' to '%s'", fullName, meta.helpText, help)
		}
	}

	gauge := prometheus.NewGauge(prometheus.GaugeOpts{
		Namespace: r.namespace,
		Subsystem: r.subsystem,
		Name:      name,
		Help:      help,
	})

	r.registry.MustRegister(gauge)
	g := &Gauge{gauge: gauge}
	r.gauges[fullName] = g

	// Store metadata
	r.metricMetadata[fullName] = &metricMeta{
		metricType: "gauge",
		helpText:   help,
	}

	return g
}

// Histogram returns or creates a histogram
func (r *Registry) Histogram(name, help string, buckets []float64) *Histogram {
	r.mu.Lock()
	defer r.mu.Unlock()

	fullName := r.fullName(name)
	if h, ok := r.histograms[fullName]; ok {
		return h
	}

	if buckets == nil {
		buckets = DefaultBuckets
	}

	// Check for conflicts
	if meta, exists := r.metricMetadata[fullName]; exists {
		if meta.metricType != "histogram" {
			panic(fmt.Sprintf("metric '%s' already registered as %s, cannot register as histogram", fullName, meta.metricType))
		}
		if meta.helpText != help {
			logWarning("Histogram '%s' help text changed from '%s' to '%s'", fullName, meta.helpText, help)
		}
		// Warn if buckets changed
		if !bucketsEqual(meta.buckets, buckets) {
			logWarning("Histogram '%s' buckets changed", fullName)
		}
	}

	histogram := prometheus.NewHistogram(prometheus.HistogramOpts{
		Namespace: r.namespace,
		Subsystem: r.subsystem,
		Name:      name,
		Help:      help,
		Buckets:   buckets,
	})

	r.registry.MustRegister(histogram)
	h := &Histogram{histogram: histogram}
	r.histograms[fullName] = h

	// Store metadata
	r.metricMetadata[fullName] = &metricMeta{
		metricType: "histogram",
		helpText:   help,
		buckets:    buckets,
	}

	return h
}

// Gatherer returns the underlying gatherer
func (r *Registry) Gatherer() prometheus.Gatherer {
	return r.registry
}

// MustRegister registers collectors with the registry or panics on error
func (r *Registry) MustRegister(collectors ...prometheus.Collector) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.registry.MustRegister(collectors...)
}

// Register registers a collector with the registry
func (r *Registry) Register(collector prometheus.Collector) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.registry.Register(collector)
}

// Unregister removes a collector from the registry
func (r *Registry) Unregister(collector prometheus.Collector) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.registry.Unregister(collector)
}

// Reset clears all collectors from the registry (useful for testing)
func (r *Registry) Reset() {
	r.mu.Lock()
	defer r.mu.Unlock()

	// Create new registry and maps
	r.registry = prometheus.NewRegistry()
	r.counters = make(map[string]*Counter)
	r.gauges = make(map[string]*Gauge)
	r.histograms = make(map[string]*Histogram)
}

// Global registry
var defaultRegistry = NewRegistry("safeops")

// DefaultRegistry returns the default registry
func DefaultRegistry() *Registry {
	return defaultRegistry
}

// SetDefaultRegistry sets the default registry
func SetDefaultRegistry(r *Registry) {
	defaultRegistry = r
}

// Convenience functions using default registry

// GetCounter returns a counter from the default registry
func GetCounter(name, help string) *Counter {
	return defaultRegistry.Counter(name, help)
}

// GetGauge returns a gauge from the default registry
func GetGauge(name, help string) *Gauge {
	return defaultRegistry.Gauge(name, help)
}

// GetHistogram returns a histogram from the default registry
func GetHistogram(name, help string, buckets []float64) *Histogram {
	return defaultRegistry.Histogram(name, help, buckets)
}

// MustRegister registers collectors with the default registry or panics
func MustRegister(collectors ...prometheus.Collector) {
	defaultRegistry.MustRegister(collectors...)
}

// Register registers a collector with the default registry
func Register(collector prometheus.Collector) error {
	return defaultRegistry.Register(collector)
}

// Unregister removes a collector from the default registry
func Unregister(collector prometheus.Collector) bool {
	return defaultRegistry.Unregister(collector)
}

// ResetDefaultRegistry resets the default registry (for testing)
func ResetDefaultRegistry() {
	defaultRegistry.Reset()
}

// Metric name validation regex (Prometheus standard)
var metricNameRegex = regexp.MustCompile(`^[a-zA-Z_:][a-zA-Z0-9_:]*$`)

// Label name validation regex
var labelNameRegex = regexp.MustCompile(`^[a-zA-Z_][a-zA-Z0-9_]*$`)

// Reserved label names that cannot be used
var reservedLabels = map[string]bool{
	"__name__": true,
	"job":      true,
	"instance": true,
}

// ValidateMetricName validates a metric name against Prometheus conventions
func ValidateMetricName(name string) error {
	if name == "" {
		return fmt.Errorf("metric name cannot be empty")
	}

	if !metricNameRegex.MatchString(name) {
		return fmt.Errorf("invalid metric name '%s': must match [a-zA-Z_:][a-zA-Z0-9_:]*", name)
	}

	if len(name) > 100 {
		return fmt.Errorf("metric name '%s' too long: %d chars (max 100)", name, len(name))
	}

	return nil
}

// ValidateLabelName validates a label name against Prometheus conventions
func ValidateLabelName(name string) error {
	if name == "" {
		return fmt.Errorf("label name cannot be empty")
	}

	if reservedLabels[name] {
		return fmt.Errorf("label name '%s' is reserved", name)
	}

	if !labelNameRegex.MatchString(name) {
		return fmt.Errorf("invalid label name '%s': must match [a-zA-Z_][a-zA-Z0-9_]*", name)
	}

	return nil
}

// ValidateLabelNames validates multiple label names
func ValidateLabelNames(names []string) error {
	if len(names) > 15 {
		return fmt.Errorf("too many labels: %d (recommended max: 15)", len(names))
	}

	for _, name := range names {
		if err := ValidateLabelName(name); err != nil {
			return err
		}
	}

	return nil
}

// ValidateCounterName validates that a counter name ends with _total
func ValidateCounterName(name string) error {
	if len(name) < 6 || name[len(name)-6:] != "_total" {
		return fmt.Errorf("counter '%s' should end with '_total' suffix", name)
	}
	return nil
}

// bucketsEqual compares two bucket slices for equality
func bucketsEqual(a, b []float64) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// logWarning logs a warning message
func logWarning(format string, args ...interface{}) {
	fmt.Printf("METRICS WARNING: "+format+"\n", args...)
}
