// Package metrics provides Prometheus metrics collection for the firewall engine.
package metrics

import (
	"errors"
	"fmt"
	"sync"

	"github.com/prometheus/client_golang/prometheus"
)

// ============================================================================
// Errors
// ============================================================================

var (
	// ErrAlreadyRegistered is returned when trying to register twice.
	ErrAlreadyRegistered = errors.New("metrics already registered")

	// ErrNotRegistered is returned when accessing unregistered metrics.
	ErrNotRegistered = errors.New("metrics not registered")
)

// ============================================================================
// Metrics Registry
// ============================================================================

// Registry holds all registered Prometheus metrics.
type Registry struct {
	mu         sync.RWMutex
	registered bool

	// Prometheus registry (use default or custom)
	promRegistry *prometheus.Registry

	// Counters
	PacketsTotal      *prometheus.CounterVec
	BytesTotal        *prometheus.CounterVec
	RuleHitsTotal     *prometheus.CounterVec
	CacheHitsTotal    prometheus.Counter
	CacheMissesTotal  prometheus.Counter
	ErrorsTotal       *prometheus.CounterVec
	ConnectionsTotal  *prometheus.CounterVec
	VerdictsSentTotal prometheus.Counter

	// Histograms
	LatencySeconds     *prometheus.HistogramVec
	RuleEvalSeconds    prometheus.Histogram
	CacheLookupSeconds prometheus.Histogram

	// Gauges
	Up                prometheus.Gauge
	EngineHealth      *prometheus.GaugeVec
	CacheEntries      prometheus.Gauge
	CacheCapacity     prometheus.Gauge
	CacheHitRate      prometheus.Gauge
	ConnectionsActive prometheus.Gauge
	RulesLoaded       prometheus.Gauge
	MemoryBytes       *prometheus.GaugeVec
	Goroutines        prometheus.Gauge
	WFPFilters        *prometheus.GaugeVec
	PacketsPerSecond  prometheus.Gauge
	BytesPerSecond    prometheus.Gauge
	StartTimeSeconds  prometheus.Gauge
}

// NewRegistry creates a new metrics registry.
func NewRegistry() *Registry {
	return &Registry{
		promRegistry: prometheus.NewRegistry(),
	}
}

// NewDefaultRegistry creates a registry using the default Prometheus registry.
func NewDefaultRegistry() *Registry {
	return &Registry{
		promRegistry: nil, // Will use prometheus.DefaultRegisterer
	}
}

// Register creates and registers all metrics.
func (r *Registry) Register() error {
	r.mu.Lock()
	defer r.mu.Unlock()

	if r.registered {
		return ErrAlreadyRegistered
	}

	// Create metrics
	r.createCounters()
	r.createHistograms()
	r.createGauges()

	// Register all metrics
	if err := r.registerAll(); err != nil {
		return fmt.Errorf("failed to register metrics: %w", err)
	}

	r.registered = true
	return nil
}

// MustRegister registers metrics and panics on error.
func (r *Registry) MustRegister() {
	if err := r.Register(); err != nil {
		panic(fmt.Sprintf("failed to register metrics: %v", err))
	}
}

// createCounters creates all counter metrics.
func (r *Registry) createCounters() {
	r.PacketsTotal = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: Namespace,
			Name:      MetricPacketsTotal,
			Help:      MetricHelp[MetricPacketsTotal],
		},
		[]string{LabelAction, LabelProtocol},
	)

	r.BytesTotal = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: Namespace,
			Name:      MetricBytesTotal,
			Help:      MetricHelp[MetricBytesTotal],
		},
		[]string{LabelAction, LabelDirection},
	)

	r.RuleHitsTotal = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: Namespace,
			Name:      MetricRuleHitsTotal,
			Help:      MetricHelp[MetricRuleHitsTotal],
		},
		[]string{LabelRule, LabelAction},
	)

	r.CacheHitsTotal = prometheus.NewCounter(
		prometheus.CounterOpts{
			Namespace: Namespace,
			Name:      MetricCacheHitsTotal,
			Help:      MetricHelp[MetricCacheHitsTotal],
		},
	)

	r.CacheMissesTotal = prometheus.NewCounter(
		prometheus.CounterOpts{
			Namespace: Namespace,
			Name:      MetricCacheMissesTotal,
			Help:      MetricHelp[MetricCacheMissesTotal],
		},
	)

	r.ErrorsTotal = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: Namespace,
			Name:      MetricErrorsTotal,
			Help:      MetricHelp[MetricErrorsTotal],
		},
		[]string{LabelErrorType},
	)

	r.ConnectionsTotal = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: Namespace,
			Name:      MetricConnectionsTotal,
			Help:      MetricHelp[MetricConnectionsTotal],
		},
		[]string{LabelAction},
	)

	r.VerdictsSentTotal = prometheus.NewCounter(
		prometheus.CounterOpts{
			Namespace: Namespace,
			Name:      MetricVerdictsSentTotal,
			Help:      MetricHelp[MetricVerdictsSentTotal],
		},
	)
}

// createHistograms creates all histogram metrics.
func (r *Registry) createHistograms() {
	r.LatencySeconds = prometheus.NewHistogramVec(
		prometheus.HistogramOpts{
			Namespace: Namespace,
			Name:      MetricLatencySeconds,
			Help:      MetricHelp[MetricLatencySeconds],
			Buckets:   LatencyBuckets,
		},
		[]string{LabelEngine},
	)

	r.RuleEvalSeconds = prometheus.NewHistogram(
		prometheus.HistogramOpts{
			Namespace: Namespace,
			Name:      MetricRuleEvalSeconds,
			Help:      MetricHelp[MetricRuleEvalSeconds],
			Buckets:   RuleEvalBuckets,
		},
	)

	r.CacheLookupSeconds = prometheus.NewHistogram(
		prometheus.HistogramOpts{
			Namespace: Namespace,
			Name:      MetricCacheLookupSeconds,
			Help:      MetricHelp[MetricCacheLookupSeconds],
			Buckets:   CacheLookupBuckets,
		},
	)
}

// createGauges creates all gauge metrics.
func (r *Registry) createGauges() {
	r.Up = prometheus.NewGauge(
		prometheus.GaugeOpts{
			Namespace: Namespace,
			Name:      MetricUp,
			Help:      MetricHelp[MetricUp],
		},
	)

	r.EngineHealth = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Namespace: Namespace,
			Name:      MetricEngineHealth,
			Help:      MetricHelp[MetricEngineHealth],
		},
		[]string{LabelEngine},
	)

	r.CacheEntries = prometheus.NewGauge(
		prometheus.GaugeOpts{
			Namespace: Namespace,
			Name:      MetricCacheEntries,
			Help:      MetricHelp[MetricCacheEntries],
		},
	)

	r.CacheCapacity = prometheus.NewGauge(
		prometheus.GaugeOpts{
			Namespace: Namespace,
			Name:      MetricCacheCapacity,
			Help:      MetricHelp[MetricCacheCapacity],
		},
	)

	r.CacheHitRate = prometheus.NewGauge(
		prometheus.GaugeOpts{
			Namespace: Namespace,
			Name:      MetricCacheHitRate,
			Help:      MetricHelp[MetricCacheHitRate],
		},
	)

	r.ConnectionsActive = prometheus.NewGauge(
		prometheus.GaugeOpts{
			Namespace: Namespace,
			Name:      MetricConnectionsActive,
			Help:      MetricHelp[MetricConnectionsActive],
		},
	)

	r.RulesLoaded = prometheus.NewGauge(
		prometheus.GaugeOpts{
			Namespace: Namespace,
			Name:      MetricRulesLoaded,
			Help:      MetricHelp[MetricRulesLoaded],
		},
	)

	r.MemoryBytes = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Namespace: Namespace,
			Name:      MetricMemoryBytes,
			Help:      MetricHelp[MetricMemoryBytes],
		},
		[]string{LabelComponent},
	)

	r.Goroutines = prometheus.NewGauge(
		prometheus.GaugeOpts{
			Namespace: Namespace,
			Name:      MetricGoroutines,
			Help:      MetricHelp[MetricGoroutines],
		},
	)

	r.WFPFilters = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Namespace: Namespace,
			Name:      MetricWFPFilters,
			Help:      MetricHelp[MetricWFPFilters],
		},
		[]string{LabelLayer},
	)

	r.PacketsPerSecond = prometheus.NewGauge(
		prometheus.GaugeOpts{
			Namespace: Namespace,
			Name:      MetricPacketsPerSecond,
			Help:      MetricHelp[MetricPacketsPerSecond],
		},
	)

	r.BytesPerSecond = prometheus.NewGauge(
		prometheus.GaugeOpts{
			Namespace: Namespace,
			Name:      MetricBytesPerSecond,
			Help:      MetricHelp[MetricBytesPerSecond],
		},
	)

	r.StartTimeSeconds = prometheus.NewGauge(
		prometheus.GaugeOpts{
			Namespace: Namespace,
			Name:      MetricStartTimeSeconds,
			Help:      MetricHelp[MetricStartTimeSeconds],
		},
	)
}

// registerAll registers all metrics with Prometheus.
func (r *Registry) registerAll() error {
	registerer := r.getRegisterer()

	// Register counters
	collectors := []prometheus.Collector{
		r.PacketsTotal,
		r.BytesTotal,
		r.RuleHitsTotal,
		r.CacheHitsTotal,
		r.CacheMissesTotal,
		r.ErrorsTotal,
		r.ConnectionsTotal,
		r.VerdictsSentTotal,
		// Histograms
		r.LatencySeconds,
		r.RuleEvalSeconds,
		r.CacheLookupSeconds,
		// Gauges
		r.Up,
		r.EngineHealth,
		r.CacheEntries,
		r.CacheCapacity,
		r.CacheHitRate,
		r.ConnectionsActive,
		r.RulesLoaded,
		r.MemoryBytes,
		r.Goroutines,
		r.WFPFilters,
		r.PacketsPerSecond,
		r.BytesPerSecond,
		r.StartTimeSeconds,
	}

	for _, c := range collectors {
		if err := registerer.Register(c); err != nil {
			// Check if already registered (not an error in some cases)
			var are prometheus.AlreadyRegisteredError
			if errors.As(err, &are) {
				continue
			}
			return fmt.Errorf("failed to register collector: %w", err)
		}
	}

	return nil
}

// getRegisterer returns the prometheus registerer to use.
func (r *Registry) getRegisterer() prometheus.Registerer {
	if r.promRegistry != nil {
		return r.promRegistry
	}
	return prometheus.DefaultRegisterer
}

// GetPrometheusRegistry returns the underlying Prometheus registry (if custom).
func (r *Registry) GetPrometheusRegistry() *prometheus.Registry {
	return r.promRegistry
}

// IsRegistered returns true if metrics are registered.
func (r *Registry) IsRegistered() bool {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.registered
}

// ============================================================================
// Global Registry
// ============================================================================

var (
	globalRegistry     *Registry
	globalRegistryOnce sync.Once
)

// DefaultRegistry returns the global default registry.
func DefaultRegistry() *Registry {
	globalRegistryOnce.Do(func() {
		globalRegistry = NewDefaultRegistry()
	})
	return globalRegistry
}

// SetGlobalRegistry sets the global registry.
func SetGlobalRegistry(r *Registry) {
	globalRegistry = r
}

// ============================================================================
// Quick Access Functions (use default registry)
// ============================================================================

// RecordPacket increments packet counter.
func RecordPacket(action, protocol string) {
	if r := DefaultRegistry(); r.registered {
		r.PacketsTotal.WithLabelValues(action, protocol).Inc()
	}
}

// RecordBytes increments bytes counter.
func RecordBytes(action, direction string, bytes float64) {
	if r := DefaultRegistry(); r.registered {
		r.BytesTotal.WithLabelValues(action, direction).Add(bytes)
	}
}

// RecordCacheHit increments cache hit counter.
func RecordCacheHit() {
	if r := DefaultRegistry(); r.registered {
		r.CacheHitsTotal.Inc()
	}
}

// RecordCacheMiss increments cache miss counter.
func RecordCacheMiss() {
	if r := DefaultRegistry(); r.registered {
		r.CacheMissesTotal.Inc()
	}
}
