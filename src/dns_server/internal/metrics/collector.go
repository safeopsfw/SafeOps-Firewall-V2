// Package metrics implements Prometheus metrics for DNS server.
package metrics

import (
	"log"
	"net/http"
	"sync/atomic"
	"time"
)

// ============================================================================
// Metrics Collector
// ============================================================================

// Collector tracks DNS server metrics
type Collector struct {
	// Query counters
	queriesTotal     uint64
	queriesBlocked   uint64
	queriesCached    uint64
	queriesForwarded uint64

	// Response times
	avgResponseTime int64 // Nanoseconds

	// Cache stats
	cacheHits   uint64
	cacheMisses uint64

	// Error counters
	errorsTotal    uint64
	upstreamErrors uint64

	// Captive portal
	redirectsTotal   uint64
	enrollmentsTotal uint64

	startTime time.Time
}

// NewCollector creates a new metrics collector
func NewCollector() *Collector {
	return &Collector{
		startTime: time.Now(),
	}
}

// ============================================================================
// Recording Methods
// ============================================================================

// RecordQuery records a DNS query
func (c *Collector) RecordQuery(blocked, cached, forwarded bool, responseTime time.Duration) {
	atomic.AddUint64(&c.queriesTotal, 1)

	if blocked {
		atomic.AddUint64(&c.queriesBlocked, 1)
	}
	if cached {
		atomic.AddUint64(&c.queriesCached, 1)
		atomic.AddUint64(&c.cacheHits, 1)
	} else {
		atomic.AddUint64(&c.cacheMisses, 1)
	}
	if forwarded {
		atomic.AddUint64(&c.queriesForwarded, 1)
	}

	// Update average response time (simple moving average)
	newAvg := (atomic.LoadInt64(&c.avgResponseTime) + responseTime.Nanoseconds()) / 2
	atomic.StoreInt64(&c.avgResponseTime, newAvg)
}

// RecordError records an error
func (c *Collector) RecordError(isUpstreamError bool) {
	atomic.AddUint64(&c.errorsTotal, 1)
	if isUpstreamError {
		atomic.AddUint64(&c.upstreamErrors, 1)
	}
}

// RecordRedirect records a captive portal redirect
func (c *Collector) RecordRedirect() {
	atomic.AddUint64(&c.redirectsTotal, 1)
}

// RecordEnrollment records a device enrollment
func (c *Collector) RecordEnrollment() {
	atomic.AddUint64(&c.enrollmentsTotal, 1)
}

// ============================================================================
// Statistics
// ============================================================================

// Stats contains all metrics
type Stats struct {
	QueriesTotal     uint64
	QueriesBlocked   uint64
	QueriesCached    uint64
	QueriesForwarded uint64
	AvgResponseMs    float64
	CacheHitRate     float64
	ErrorsTotal      uint64
	UpstreamErrors   uint64
	RedirectsTotal   uint64
	EnrollmentsTotal uint64
	UptimeSeconds    int64
}

// GetStats returns current metrics
func (c *Collector) GetStats() Stats {
	total := atomic.LoadUint64(&c.queriesTotal)
	hits := atomic.LoadUint64(&c.cacheHits)
	misses := atomic.LoadUint64(&c.cacheMisses)

	var hitRate float64
	if hits+misses > 0 {
		hitRate = float64(hits) / float64(hits+misses) * 100
	}

	return Stats{
		QueriesTotal:     total,
		QueriesBlocked:   atomic.LoadUint64(&c.queriesBlocked),
		QueriesCached:    atomic.LoadUint64(&c.queriesCached),
		QueriesForwarded: atomic.LoadUint64(&c.queriesForwarded),
		AvgResponseMs:    float64(atomic.LoadInt64(&c.avgResponseTime)) / 1e6,
		CacheHitRate:     hitRate,
		ErrorsTotal:      atomic.LoadUint64(&c.errorsTotal),
		UpstreamErrors:   atomic.LoadUint64(&c.upstreamErrors),
		RedirectsTotal:   atomic.LoadUint64(&c.redirectsTotal),
		EnrollmentsTotal: atomic.LoadUint64(&c.enrollmentsTotal),
		UptimeSeconds:    int64(time.Since(c.startTime).Seconds()),
	}
}

// ============================================================================
// Prometheus Export
// ============================================================================

// Handler returns HTTP handler for /metrics endpoint
func (c *Collector) Handler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		stats := c.GetStats()

		w.Header().Set("Content-Type", "text/plain")
		w.Write([]byte(formatPrometheusMetrics(stats)))
	})
}

func formatPrometheusMetrics(s Stats) string {
	return `# HELP dns_queries_total Total DNS queries
# TYPE dns_queries_total counter
dns_queries_total ` + formatUint(s.QueriesTotal) + `

# HELP dns_queries_blocked_total Blocked DNS queries
# TYPE dns_queries_blocked_total counter
dns_queries_blocked_total ` + formatUint(s.QueriesBlocked) + `

# HELP dns_queries_cached_total Cached DNS responses
# TYPE dns_queries_cached_total counter
dns_queries_cached_total ` + formatUint(s.QueriesCached) + `

# HELP dns_queries_forwarded_total Forwarded DNS queries
# TYPE dns_queries_forwarded_total counter
dns_queries_forwarded_total ` + formatUint(s.QueriesForwarded) + `

# HELP dns_cache_hit_rate Cache hit rate percentage
# TYPE dns_cache_hit_rate gauge
dns_cache_hit_rate ` + formatFloat(s.CacheHitRate) + `

# HELP dns_errors_total Total errors
# TYPE dns_errors_total counter
dns_errors_total ` + formatUint(s.ErrorsTotal) + `

# HELP dns_captive_redirects_total Captive portal redirects
# TYPE dns_captive_redirects_total counter
dns_captive_redirects_total ` + formatUint(s.RedirectsTotal) + `

# HELP dns_device_enrollments_total Device enrollments
# TYPE dns_device_enrollments_total counter
dns_device_enrollments_total ` + formatUint(s.EnrollmentsTotal) + `

# HELP dns_uptime_seconds Server uptime
# TYPE dns_uptime_seconds gauge
dns_uptime_seconds ` + formatInt(s.UptimeSeconds) + `
`
}

func formatUint(v uint64) string {
	return string([]byte{byte(v/10000000000%10) + '0', byte(v/1000000000%10) + '0',
		byte(v/100000000%10) + '0', byte(v/10000000%10) + '0',
		byte(v/1000000%10) + '0', byte(v/100000%10) + '0',
		byte(v/10000%10) + '0', byte(v/1000%10) + '0',
		byte(v/100%10) + '0', byte(v/10%10) + '0', byte(v%10) + '0'})
}

func formatFloat(v float64) string {
	return formatInt(int64(v*100)/100) + "." + formatInt(int64(v*100)%100)
}

func formatInt(v int64) string {
	if v < 0 {
		return "-" + formatUint(uint64(-v))
	}
	return formatUint(uint64(v))
}

// StartMetricsServer starts the Prometheus metrics HTTP server
func StartMetricsServer(addr string, collector *Collector) {
	http.Handle("/metrics", collector.Handler())
	go func() {
		log.Printf("Metrics server listening on %s", addr)
		if err := http.ListenAndServe(addr, nil); err != nil {
			log.Printf("Metrics server error: %v", err)
		}
	}()
}
