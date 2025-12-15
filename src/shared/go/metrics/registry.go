// Package metrics provides a custom metrics registry.
package metrics

import (
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

	mu sync.RWMutex
}

// NewRegistry creates a new metrics registry
func NewRegistry(namespace string) *Registry {
	return &Registry{
		namespace:  namespace,
		registry:   prometheus.NewRegistry(),
		counters:   make(map[string]*Counter),
		gauges:     make(map[string]*Gauge),
		histograms: make(map[string]*Histogram),
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

	counter := prometheus.NewCounter(prometheus.CounterOpts{
		Namespace: r.namespace,
		Subsystem: r.subsystem,
		Name:      name,
		Help:      help,
	})

	r.registry.MustRegister(counter)
	c := &Counter{counter: counter}
	r.counters[fullName] = c
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

	gauge := prometheus.NewGauge(prometheus.GaugeOpts{
		Namespace: r.namespace,
		Subsystem: r.subsystem,
		Name:      name,
		Help:      help,
	})

	r.registry.MustRegister(gauge)
	g := &Gauge{gauge: gauge}
	r.gauges[fullName] = g
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
	return h
}

// Gatherer returns the underlying gatherer
func (r *Registry) Gatherer() prometheus.Gatherer {
	return r.registry
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
