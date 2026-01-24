// Package metrics provides Prometheus metrics collection for the firewall engine.
package metrics

import (
	"time"
)

// ============================================================================
// Metric Namespace and Subsystem
// ============================================================================

const (
	// Namespace is the prefix for all firewall metrics.
	Namespace = "firewall"

	// Subsystem prefixes for grouping related metrics.
	SubsystemPacket      = "packet"
	SubsystemCache       = "cache"
	SubsystemConnection  = "connection"
	SubsystemRule        = "rule"
	SubsystemEngine      = "engine"
	SubsystemWFP         = "wfp"
	SubsystemPerformance = "perf"
	SubsystemResource    = "resource"
)

// ============================================================================
// Counter Metric Names
// ============================================================================

const (
	// MetricPacketsTotal counts total packets processed.
	// Labels: action, protocol
	MetricPacketsTotal = "packets_total"

	// MetricBytesTotal counts total bytes transferred.
	// Labels: action, direction
	MetricBytesTotal = "bytes_total"

	// MetricRuleHitsTotal counts rule matches.
	// Labels: rule_name, action
	MetricRuleHitsTotal = "rule_hits_total"

	// MetricCacheHitsTotal counts cache hits.
	MetricCacheHitsTotal = "cache_hits_total"

	// MetricCacheMissesTotal counts cache misses.
	MetricCacheMissesTotal = "cache_misses_total"

	// MetricErrorsTotal counts errors by type.
	// Labels: error_type
	MetricErrorsTotal = "errors_total"

	// MetricConnectionsTotal counts connections processed.
	// Labels: action
	MetricConnectionsTotal = "connections_total"

	// MetricVerdictsSentTotal counts verdicts sent to SafeOps Engine.
	MetricVerdictsSentTotal = "verdicts_sent_total"
)

// ============================================================================
// Histogram Metric Names
// ============================================================================

const (
	// MetricLatencySeconds measures packet processing latency.
	// Labels: engine
	MetricLatencySeconds = "latency_seconds"

	// MetricRuleEvalSeconds measures rule evaluation time.
	MetricRuleEvalSeconds = "rule_eval_seconds"

	// MetricCacheLookupSeconds measures cache lookup time.
	MetricCacheLookupSeconds = "cache_lookup_seconds"
)

// ============================================================================
// Gauge Metric Names
// ============================================================================

const (
	// MetricUp indicates if firewall is running (1=up, 0=down).
	MetricUp = "up"

	// MetricEngineHealth indicates engine health (1=healthy, 0=unhealthy).
	// Labels: engine
	MetricEngineHealth = "engine_health"

	// MetricCacheEntries is the current number of cache entries.
	MetricCacheEntries = "cache_entries"

	// MetricCacheCapacity is the maximum cache capacity.
	MetricCacheCapacity = "cache_capacity"

	// MetricCacheHitRate is the current cache hit rate (0.0-1.0).
	MetricCacheHitRate = "cache_hit_rate"

	// MetricConnectionsActive is the number of active connections.
	MetricConnectionsActive = "connections_active"

	// MetricRulesLoaded is the number of loaded rules.
	MetricRulesLoaded = "rules_loaded"

	// MetricMemoryBytes is memory usage in bytes.
	// Labels: component
	MetricMemoryBytes = "memory_bytes"

	// MetricGoroutines is the number of active goroutines.
	MetricGoroutines = "goroutines"

	// MetricWFPFilters is the number of WFP filters installed.
	// Labels: layer
	MetricWFPFilters = "wfp_filters"

	// MetricPacketsPerSecond is the current packets per second rate.
	MetricPacketsPerSecond = "packets_per_second"

	// MetricBytesPerSecond is the current bytes per second rate.
	MetricBytesPerSecond = "bytes_per_second"

	// MetricStartTimeSeconds is the firewall start timestamp.
	MetricStartTimeSeconds = "start_time_seconds"
)

// ============================================================================
// Metric Help Text
// ============================================================================

// MetricHelp contains help text for each metric (displayed in Prometheus UI).
var MetricHelp = map[string]string{
	// Counters
	MetricPacketsTotal:      "Total number of packets processed",
	MetricBytesTotal:        "Total bytes transferred",
	MetricRuleHitsTotal:     "Total rule match count by rule name and action",
	MetricCacheHitsTotal:    "Total verdict cache hits",
	MetricCacheMissesTotal:  "Total verdict cache misses",
	MetricErrorsTotal:       "Total errors by type",
	MetricConnectionsTotal:  "Total connections processed",
	MetricVerdictsSentTotal: "Total verdicts sent to SafeOps Engine",

	// Histograms
	MetricLatencySeconds:     "Packet processing latency in seconds",
	MetricRuleEvalSeconds:    "Rule evaluation time in seconds",
	MetricCacheLookupSeconds: "Cache lookup time in seconds",

	// Gauges
	MetricUp:                "Firewall is running (1=up, 0=down)",
	MetricEngineHealth:      "Engine health status (1=healthy, 0=unhealthy)",
	MetricCacheEntries:      "Current number of entries in verdict cache",
	MetricCacheCapacity:     "Maximum capacity of verdict cache",
	MetricCacheHitRate:      "Current cache hit rate (0.0-1.0)",
	MetricConnectionsActive: "Number of active tracked connections",
	MetricRulesLoaded:       "Number of firewall rules currently loaded",
	MetricMemoryBytes:       "Memory usage in bytes by component",
	MetricGoroutines:        "Number of active goroutines",
	MetricWFPFilters:        "Number of WFP filters installed by layer",
	MetricPacketsPerSecond:  "Current packets per second throughput",
	MetricBytesPerSecond:    "Current bytes per second throughput",
	MetricStartTimeSeconds:  "Firewall start time as Unix timestamp",
}

// ============================================================================
// Histogram Buckets
// ============================================================================

// LatencyBuckets defines histogram buckets for packet processing latency.
// Range: 10μs to 100ms (covers expected latency spectrum).
var LatencyBuckets = []float64{
	0.00001, // 10μs
	0.00002, // 20μs
	0.00005, // 50μs
	0.0001,  // 100μs
	0.0002,  // 200μs
	0.0005,  // 500μs
	0.001,   // 1ms
	0.002,   // 2ms
	0.005,   // 5ms
	0.01,    // 10ms
	0.05,    // 50ms
	0.1,     // 100ms
}

// RuleEvalBuckets defines histogram buckets for rule evaluation time.
// Range: 1μs to 1ms (very fast operations).
var RuleEvalBuckets = []float64{
	0.000001, // 1μs
	0.000002, // 2μs
	0.000005, // 5μs
	0.00001,  // 10μs
	0.00002,  // 20μs
	0.00005,  // 50μs
	0.0001,   // 100μs
	0.0002,   // 200μs
	0.0005,   // 500μs
	0.001,    // 1ms
}

// CacheLookupBuckets defines histogram buckets for cache lookups.
// Range: 100ns to 100μs (very fast operations).
var CacheLookupBuckets = []float64{
	0.0000001, // 100ns
	0.0000002, // 200ns
	0.0000005, // 500ns
	0.000001,  // 1μs
	0.000002,  // 2μs
	0.000005,  // 5μs
	0.00001,   // 10μs
	0.00002,   // 20μs
	0.00005,   // 50μs
	0.0001,    // 100μs
}

// ============================================================================
// Bucket Helpers
// ============================================================================

// SecondsFromDuration converts duration to seconds for histogram observation.
func SecondsFromDuration(d time.Duration) float64 {
	return d.Seconds()
}

// MicrosecondsFromDuration converts duration to microseconds.
func MicrosecondsFromDuration(d time.Duration) float64 {
	return float64(d.Microseconds())
}

// ============================================================================
// Full Metric Names (with namespace)
// ============================================================================

// FullMetricName returns the fully qualified metric name with namespace.
func FullMetricName(metric string) string {
	return Namespace + "_" + metric
}

// FullMetricNameWithSubsystem returns the fully qualified metric name
// with namespace and subsystem.
func FullMetricNameWithSubsystem(subsystem, metric string) string {
	return Namespace + "_" + subsystem + "_" + metric
}

// ============================================================================
// Metric Type Enum
// ============================================================================

// MetricType represents the type of a Prometheus metric.
type MetricType int

const (
	// MetricTypeCounter is a cumulative counter that only increases.
	MetricTypeCounter MetricType = iota

	// MetricTypeGauge is a value that can go up or down.
	MetricTypeGauge

	// MetricTypeHistogram measures distribution of values.
	MetricTypeHistogram

	// MetricTypeSummary is a client-side quantile calculator.
	MetricTypeSummary
)

// String returns the string representation of the metric type.
func (t MetricType) String() string {
	switch t {
	case MetricTypeCounter:
		return "counter"
	case MetricTypeGauge:
		return "gauge"
	case MetricTypeHistogram:
		return "histogram"
	case MetricTypeSummary:
		return "summary"
	default:
		return "unknown"
	}
}

// ============================================================================
// Metric Definition
// ============================================================================

// MetricDef defines a metric's metadata.
type MetricDef struct {
	Name      string     // Metric name (without namespace)
	Subsystem string     // Metric subsystem (optional)
	Help      string     // Help text
	Type      MetricType // Counter, Gauge, Histogram, Summary
	Labels    []string   // Label names
	Buckets   []float64  // For histograms only
}

// FullName returns the fully qualified metric name.
func (m MetricDef) FullName() string {
	if m.Subsystem != "" {
		return FullMetricNameWithSubsystem(m.Subsystem, m.Name)
	}
	return FullMetricName(m.Name)
}

// ============================================================================
// All Metric Definitions
// ============================================================================

// AllMetrics contains definitions for all firewall metrics.
var AllMetrics = []MetricDef{
	// Counters
	{Name: MetricPacketsTotal, Help: MetricHelp[MetricPacketsTotal], Type: MetricTypeCounter, Labels: []string{"action", "protocol"}},
	{Name: MetricBytesTotal, Help: MetricHelp[MetricBytesTotal], Type: MetricTypeCounter, Labels: []string{"action", "direction"}},
	{Name: MetricRuleHitsTotal, Help: MetricHelp[MetricRuleHitsTotal], Type: MetricTypeCounter, Labels: []string{"rule", "action"}},
	{Name: MetricCacheHitsTotal, Help: MetricHelp[MetricCacheHitsTotal], Type: MetricTypeCounter},
	{Name: MetricCacheMissesTotal, Help: MetricHelp[MetricCacheMissesTotal], Type: MetricTypeCounter},
	{Name: MetricErrorsTotal, Help: MetricHelp[MetricErrorsTotal], Type: MetricTypeCounter, Labels: []string{"type"}},
	{Name: MetricConnectionsTotal, Help: MetricHelp[MetricConnectionsTotal], Type: MetricTypeCounter, Labels: []string{"action"}},
	{Name: MetricVerdictsSentTotal, Help: MetricHelp[MetricVerdictsSentTotal], Type: MetricTypeCounter},

	// Histograms
	{Name: MetricLatencySeconds, Help: MetricHelp[MetricLatencySeconds], Type: MetricTypeHistogram, Labels: []string{"engine"}, Buckets: LatencyBuckets},
	{Name: MetricRuleEvalSeconds, Help: MetricHelp[MetricRuleEvalSeconds], Type: MetricTypeHistogram, Buckets: RuleEvalBuckets},
	{Name: MetricCacheLookupSeconds, Help: MetricHelp[MetricCacheLookupSeconds], Type: MetricTypeHistogram, Buckets: CacheLookupBuckets},

	// Gauges
	{Name: MetricUp, Help: MetricHelp[MetricUp], Type: MetricTypeGauge},
	{Name: MetricEngineHealth, Help: MetricHelp[MetricEngineHealth], Type: MetricTypeGauge, Labels: []string{"engine"}},
	{Name: MetricCacheEntries, Help: MetricHelp[MetricCacheEntries], Type: MetricTypeGauge},
	{Name: MetricCacheCapacity, Help: MetricHelp[MetricCacheCapacity], Type: MetricTypeGauge},
	{Name: MetricCacheHitRate, Help: MetricHelp[MetricCacheHitRate], Type: MetricTypeGauge},
	{Name: MetricConnectionsActive, Help: MetricHelp[MetricConnectionsActive], Type: MetricTypeGauge},
	{Name: MetricRulesLoaded, Help: MetricHelp[MetricRulesLoaded], Type: MetricTypeGauge},
	{Name: MetricMemoryBytes, Help: MetricHelp[MetricMemoryBytes], Type: MetricTypeGauge, Labels: []string{"component"}},
	{Name: MetricGoroutines, Help: MetricHelp[MetricGoroutines], Type: MetricTypeGauge},
	{Name: MetricWFPFilters, Help: MetricHelp[MetricWFPFilters], Type: MetricTypeGauge, Labels: []string{"layer"}},
	{Name: MetricPacketsPerSecond, Help: MetricHelp[MetricPacketsPerSecond], Type: MetricTypeGauge},
	{Name: MetricBytesPerSecond, Help: MetricHelp[MetricBytesPerSecond], Type: MetricTypeGauge},
	{Name: MetricStartTimeSeconds, Help: MetricHelp[MetricStartTimeSeconds], Type: MetricTypeGauge},
}

// GetMetricDef looks up a metric definition by name.
func GetMetricDef(name string) (MetricDef, bool) {
	for _, m := range AllMetrics {
		if m.Name == name {
			return m, true
		}
	}
	return MetricDef{}, false
}
