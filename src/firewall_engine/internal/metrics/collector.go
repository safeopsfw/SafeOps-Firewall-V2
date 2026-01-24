// Package metrics provides Prometheus metrics collection for the firewall engine.
package metrics

import (
	"runtime"
	"sync"
	"time"
)

// ============================================================================
// Collector Interface
// ============================================================================

// Collector collects metrics from the firewall engine.
type Collector interface {
	// Packet metrics
	RecordPacket(action, protocol string, bytes int)
	RecordPacketWithDirection(action, protocol, direction string, bytes int)

	// Latency metrics
	RecordLatency(engine string, duration time.Duration)
	RecordRuleEvalLatency(duration time.Duration)
	RecordCacheLookupLatency(duration time.Duration)

	// Cache metrics
	RecordCacheHit()
	RecordCacheMiss()
	SetCacheSize(entries int)
	SetCacheCapacity(capacity int)
	SetCacheHitRate(rate float64)

	// Connection metrics
	RecordConnection(action string)
	SetActiveConnections(count int)

	// Rule metrics
	RecordRuleHit(ruleName, action string)
	SetRulesLoaded(count int)

	// Error metrics
	RecordError(errType string)

	// Verdict metrics
	RecordVerdictSent()

	// Health metrics
	SetEngineHealth(engine string, healthy bool)
	SetUp(up bool)

	// Resource metrics
	SetMemoryUsage(component string, bytes int64)
	SetWFPFilters(layer string, count int)
	UpdateResourceMetrics()

	// Rate metrics
	SetPacketsPerSecond(rate float64)
	SetBytesPerSecond(rate float64)

	// Lifecycle
	SetStartTime(t time.Time)
	Start()
	Stop()
}

// ============================================================================
// Metrics Collector Implementation
// ============================================================================

// MetricsCollector implements the Collector interface.
type MetricsCollector struct {
	registry  *Registry
	validator *CardinalityValidator

	// Start time
	startTime time.Time

	// Resource update ticker
	ticker    *time.Ticker
	stopCh    chan struct{}
	mu        sync.Mutex
	isRunning bool

	// Counters for rate calculation
	lastPacketCount uint64
	lastByteCount   uint64
	lastUpdateTime  time.Time
	packetCounter   uint64
	byteCounter     uint64
}

// NewCollector creates a new metrics collector.
func NewCollector(registry *Registry) *MetricsCollector {
	if registry == nil {
		registry = DefaultRegistry()
	}

	return &MetricsCollector{
		registry:       registry,
		validator:      NewCardinalityValidator(),
		startTime:      time.Now(),
		stopCh:         make(chan struct{}),
		lastUpdateTime: time.Now(),
	}
}

// ============================================================================
// Packet Metrics
// ============================================================================

// RecordPacket records a packet with the given action and protocol.
func (c *MetricsCollector) RecordPacket(action, protocol string, bytes int) {
	if !c.registry.IsRegistered() {
		return
	}

	c.registry.PacketsTotal.WithLabelValues(action, protocol).Inc()
	c.packetCounter++

	if bytes > 0 {
		c.byteCounter += uint64(bytes)
	}
}

// RecordPacketWithDirection records a packet with direction info.
func (c *MetricsCollector) RecordPacketWithDirection(action, protocol, direction string, bytes int) {
	if !c.registry.IsRegistered() {
		return
	}

	// Record packet count
	c.registry.PacketsTotal.WithLabelValues(action, protocol).Inc()
	c.packetCounter++

	// Record bytes with direction
	if bytes > 0 {
		c.registry.BytesTotal.WithLabelValues(action, direction).Add(float64(bytes))
		c.byteCounter += uint64(bytes)
	}
}

// ============================================================================
// Latency Metrics
// ============================================================================

// RecordLatency records packet processing latency.
func (c *MetricsCollector) RecordLatency(engine string, duration time.Duration) {
	if !c.registry.IsRegistered() {
		return
	}

	c.registry.LatencySeconds.WithLabelValues(engine).Observe(SecondsFromDuration(duration))
}

// RecordRuleEvalLatency records rule evaluation time.
func (c *MetricsCollector) RecordRuleEvalLatency(duration time.Duration) {
	if !c.registry.IsRegistered() {
		return
	}

	c.registry.RuleEvalSeconds.Observe(SecondsFromDuration(duration))
}

// RecordCacheLookupLatency records cache lookup time.
func (c *MetricsCollector) RecordCacheLookupLatency(duration time.Duration) {
	if !c.registry.IsRegistered() {
		return
	}

	c.registry.CacheLookupSeconds.Observe(SecondsFromDuration(duration))
}

// ============================================================================
// Cache Metrics
// ============================================================================

// RecordCacheHit records a cache hit.
func (c *MetricsCollector) RecordCacheHit() {
	if !c.registry.IsRegistered() {
		return
	}

	c.registry.CacheHitsTotal.Inc()
}

// RecordCacheMiss records a cache miss.
func (c *MetricsCollector) RecordCacheMiss() {
	if !c.registry.IsRegistered() {
		return
	}

	c.registry.CacheMissesTotal.Inc()
}

// SetCacheSize sets the current cache size.
func (c *MetricsCollector) SetCacheSize(entries int) {
	if !c.registry.IsRegistered() {
		return
	}

	c.registry.CacheEntries.Set(float64(entries))
}

// SetCacheCapacity sets the cache capacity.
func (c *MetricsCollector) SetCacheCapacity(capacity int) {
	if !c.registry.IsRegistered() {
		return
	}

	c.registry.CacheCapacity.Set(float64(capacity))
}

// SetCacheHitRate sets the current cache hit rate.
func (c *MetricsCollector) SetCacheHitRate(rate float64) {
	if !c.registry.IsRegistered() {
		return
	}

	c.registry.CacheHitRate.Set(rate)
}

// ============================================================================
// Connection Metrics
// ============================================================================

// RecordConnection records a connection event.
func (c *MetricsCollector) RecordConnection(action string) {
	if !c.registry.IsRegistered() {
		return
	}

	c.registry.ConnectionsTotal.WithLabelValues(action).Inc()
}

// SetActiveConnections sets the number of active connections.
func (c *MetricsCollector) SetActiveConnections(count int) {
	if !c.registry.IsRegistered() {
		return
	}

	c.registry.ConnectionsActive.Set(float64(count))
}

// ============================================================================
// Rule Metrics
// ============================================================================

// RecordRuleHit records a rule match.
func (c *MetricsCollector) RecordRuleHit(ruleName, action string) {
	if !c.registry.IsRegistered() {
		return
	}

	// Validate cardinality to prevent explosion
	sanitizedName := SanitizeRuleName(ruleName)
	if err := c.validator.ValidateLabel(LabelRule, sanitizedName); err != nil {
		// Log warning but don't fail
		// Use a generic "other" bucket for high-cardinality rules
		sanitizedName = "other"
	}

	c.registry.RuleHitsTotal.WithLabelValues(sanitizedName, action).Inc()
}

// SetRulesLoaded sets the number of loaded rules.
func (c *MetricsCollector) SetRulesLoaded(count int) {
	if !c.registry.IsRegistered() {
		return
	}

	c.registry.RulesLoaded.Set(float64(count))
}

// ============================================================================
// Error Metrics
// ============================================================================

// RecordError records an error by type.
func (c *MetricsCollector) RecordError(errType string) {
	if !c.registry.IsRegistered() {
		return
	}

	c.registry.ErrorsTotal.WithLabelValues(errType).Inc()
}

// ============================================================================
// Verdict Metrics
// ============================================================================

// RecordVerdictSent records a verdict sent to SafeOps Engine.
func (c *MetricsCollector) RecordVerdictSent() {
	if !c.registry.IsRegistered() {
		return
	}

	c.registry.VerdictsSentTotal.Inc()
}

// ============================================================================
// Health Metrics
// ============================================================================

// SetEngineHealth sets the health status of an engine.
func (c *MetricsCollector) SetEngineHealth(engine string, healthy bool) {
	if !c.registry.IsRegistered() {
		return
	}

	value := 0.0
	if healthy {
		value = 1.0
	}
	c.registry.EngineHealth.WithLabelValues(engine).Set(value)
}

// SetUp sets the firewall up status.
func (c *MetricsCollector) SetUp(up bool) {
	if !c.registry.IsRegistered() {
		return
	}

	value := 0.0
	if up {
		value = 1.0
	}
	c.registry.Up.Set(value)
}

// ============================================================================
// Resource Metrics
// ============================================================================

// SetMemoryUsage sets memory usage for a component.
func (c *MetricsCollector) SetMemoryUsage(component string, bytes int64) {
	if !c.registry.IsRegistered() {
		return
	}

	c.registry.MemoryBytes.WithLabelValues(component).Set(float64(bytes))
}

// SetWFPFilters sets the WFP filter count for a layer.
func (c *MetricsCollector) SetWFPFilters(layer string, count int) {
	if !c.registry.IsRegistered() {
		return
	}

	c.registry.WFPFilters.WithLabelValues(layer).Set(float64(count))
}

// UpdateResourceMetrics updates resource usage metrics.
func (c *MetricsCollector) UpdateResourceMetrics() {
	if !c.registry.IsRegistered() {
		return
	}

	// Update goroutine count
	c.registry.Goroutines.Set(float64(runtime.NumGoroutine()))

	// Update memory stats
	var memStats runtime.MemStats
	runtime.ReadMemStats(&memStats)
	c.registry.MemoryBytes.WithLabelValues(ComponentTotal).Set(float64(memStats.Alloc))
}

// ============================================================================
// Rate Metrics
// ============================================================================

// SetPacketsPerSecond sets the current packets per second rate.
func (c *MetricsCollector) SetPacketsPerSecond(rate float64) {
	if !c.registry.IsRegistered() {
		return
	}

	c.registry.PacketsPerSecond.Set(rate)
}

// SetBytesPerSecond sets the current bytes per second rate.
func (c *MetricsCollector) SetBytesPerSecond(rate float64) {
	if !c.registry.IsRegistered() {
		return
	}

	c.registry.BytesPerSecond.Set(rate)
}

// calculateRates calculates current rates based on counter deltas.
func (c *MetricsCollector) calculateRates() {
	now := time.Now()
	duration := now.Sub(c.lastUpdateTime).Seconds()

	if duration > 0 {
		packetDelta := c.packetCounter - c.lastPacketCount
		byteDelta := c.byteCounter - c.lastByteCount

		pps := float64(packetDelta) / duration
		bps := float64(byteDelta) / duration

		c.SetPacketsPerSecond(pps)
		c.SetBytesPerSecond(bps)
	}

	c.lastPacketCount = c.packetCounter
	c.lastByteCount = c.byteCounter
	c.lastUpdateTime = now
}

// ============================================================================
// Lifecycle
// ============================================================================

// SetStartTime sets the firewall start time.
func (c *MetricsCollector) SetStartTime(t time.Time) {
	c.startTime = t
	if c.registry.IsRegistered() {
		c.registry.StartTimeSeconds.Set(float64(t.Unix()))
	}
}

// Start starts the collector background tasks.
func (c *MetricsCollector) Start() {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.isRunning {
		return
	}

	c.isRunning = true
	c.ticker = time.NewTicker(1 * time.Second)

	// Set initial metrics
	c.SetUp(true)
	c.SetStartTime(c.startTime)

	// Start background update loop
	go c.updateLoop()
}

// Stop stops the collector.
func (c *MetricsCollector) Stop() {
	c.mu.Lock()
	defer c.mu.Unlock()

	if !c.isRunning {
		return
	}

	c.isRunning = false
	close(c.stopCh)

	if c.ticker != nil {
		c.ticker.Stop()
	}

	c.SetUp(false)
}

// updateLoop periodically updates resource and rate metrics.
func (c *MetricsCollector) updateLoop() {
	for {
		select {
		case <-c.stopCh:
			return
		case <-c.ticker.C:
			c.UpdateResourceMetrics()
			c.calculateRates()
		}
	}
}

// ============================================================================
// No-op Collector (for testing or disabled metrics)
// ============================================================================

// noopCollector is a no-op implementation of Collector.
type noopCollector struct{}

// NewNoopCollector creates a collector that does nothing.
func NewNoopCollector() Collector {
	return &noopCollector{}
}

func (n *noopCollector) RecordPacket(action, protocol string, bytes int)                         {}
func (n *noopCollector) RecordPacketWithDirection(action, protocol, direction string, bytes int) {}
func (n *noopCollector) RecordLatency(engine string, duration time.Duration)                     {}
func (n *noopCollector) RecordRuleEvalLatency(duration time.Duration)                            {}
func (n *noopCollector) RecordCacheLookupLatency(duration time.Duration)                         {}
func (n *noopCollector) RecordCacheHit()                                                         {}
func (n *noopCollector) RecordCacheMiss()                                                        {}
func (n *noopCollector) SetCacheSize(entries int)                                                {}
func (n *noopCollector) SetCacheCapacity(capacity int)                                           {}
func (n *noopCollector) SetCacheHitRate(rate float64)                                            {}
func (n *noopCollector) RecordConnection(action string)                                          {}
func (n *noopCollector) SetActiveConnections(count int)                                          {}
func (n *noopCollector) RecordRuleHit(ruleName, action string)                                   {}
func (n *noopCollector) SetRulesLoaded(count int)                                                {}
func (n *noopCollector) RecordError(errType string)                                              {}
func (n *noopCollector) RecordVerdictSent()                                                      {}
func (n *noopCollector) SetEngineHealth(engine string, healthy bool)                             {}
func (n *noopCollector) SetUp(up bool)                                                           {}
func (n *noopCollector) SetMemoryUsage(component string, bytes int64)                            {}
func (n *noopCollector) SetWFPFilters(layer string, count int)                                   {}
func (n *noopCollector) UpdateResourceMetrics()                                                  {}
func (n *noopCollector) SetPacketsPerSecond(rate float64)                                        {}
func (n *noopCollector) SetBytesPerSecond(rate float64)                                          {}
func (n *noopCollector) SetStartTime(t time.Time)                                                {}
func (n *noopCollector) Start()                                                                  {}
func (n *noopCollector) Stop()                                                                   {}
