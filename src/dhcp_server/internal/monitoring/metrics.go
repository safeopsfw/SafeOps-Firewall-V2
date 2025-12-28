// Package monitoring provides monitoring and alerting for DHCP server.
// This file implements Prometheus metrics collection and export.
package monitoring

import (
	"net/http"
	"sync"
	"sync/atomic"
	"time"
)

// ============================================================================
// Metrics Configuration
// ============================================================================

// MetricsConfig holds metrics configuration.
type MetricsConfig struct {
	Port    int
	Path    string
	Enabled bool
}

// DefaultMetricsConfig returns sensible defaults.
func DefaultMetricsConfig() *MetricsConfig {
	return &MetricsConfig{
		Port:    9154,
		Path:    "/metrics",
		Enabled: true,
	}
}

// ============================================================================
// DHCP Metrics
// ============================================================================

// DHCPMetrics holds all DHCP server metrics.
type DHCPMetrics struct {
	mu sync.RWMutex

	// Request counters
	DiscoverReceived int64
	RequestReceived  int64
	DeclineReceived  int64
	ReleaseReceived  int64
	InformReceived   int64

	// Response counters
	OfferSent  int64
	AckSent    int64
	NakSent    int64
	SendErrors int64

	// Lease counters
	LeasesAllocated int64
	LeasesRenewed   int64
	LeasesReleased  int64
	LeasesExpired   int64

	// Allocation failures by reason
	AllocationFailures map[string]int64

	// Current state gauges
	ActiveLeases       int64
	PendingOffers      int64
	ReservedIPs        int64
	ConcurrentRequests int64

	// Pool utilization
	PoolUtilization map[string]*PoolMetrics

	// DNS integration
	DNSUpdatesSuccess int64
	DNSUpdatesFailure int64
	DNSAvailable      bool

	// CA integration
	CARequestsSuccess int64
	CARequestsFailure int64
	CACacheHits       int64
	CACacheMisses     int64
	CAAvailable       bool
	CAOptionsSent     int64

	// Database
	DBQueriesTotal int64
	DBErrorsTotal  int64
	DBAvailable    bool
	DBConnections  int64

	// Network
	PacketsReceived int64
	PacketsSent     int64
	BroadcastsSent  int64
	UnicastsSent    int64
	RelaySent       int64
	InvalidPackets  int64

	// Component health
	ComponentHealth map[string]bool

	// Performance
	ResponseTimes    []float64
	ProcessingTimes  []float64
	DBQueryTimes     []float64
	DNSUpdateTimes   []float64
	maxHistogramSize int

	// Server info
	StartTime time.Time
	Version   string
	BuildDate string
}

// PoolMetrics contains metrics for a single pool.
type PoolMetrics struct {
	TotalIPs     int64
	UsableIPs    int64
	AllocatedIPs int64
	AvailableIPs int64
	ReservedIPs  int64
	Utilization  float64
	Exhausted    bool
	Warning      bool
}

// ============================================================================
// Metrics Manager
// ============================================================================

// MetricsManager manages Prometheus metrics.
type MetricsManager struct {
	mu      sync.RWMutex
	config  *MetricsConfig
	metrics *DHCPMetrics
	server  *http.Server
}

// NewMetricsManager creates a new metrics manager.
func NewMetricsManager(config *MetricsConfig) *MetricsManager {
	if config == nil {
		config = DefaultMetricsConfig()
	}

	return &MetricsManager{
		config: config,
		metrics: &DHCPMetrics{
			AllocationFailures: make(map[string]int64),
			PoolUtilization:    make(map[string]*PoolMetrics),
			ComponentHealth:    make(map[string]bool),
			ResponseTimes:      make([]float64, 0, 1000),
			ProcessingTimes:    make([]float64, 0, 1000),
			DBQueryTimes:       make([]float64, 0, 1000),
			DNSUpdateTimes:     make([]float64, 0, 1000),
			maxHistogramSize:   1000,
			StartTime:          time.Now(),
		},
	}
}

// ============================================================================
// Lifecycle
// ============================================================================

// Start starts the metrics HTTP server.
func (m *MetricsManager) Start() error {
	if !m.config.Enabled {
		return nil
	}

	mux := http.NewServeMux()
	mux.HandleFunc(m.config.Path, m.handleMetrics)

	m.server = &http.Server{
		Addr:    ":9154",
		Handler: mux,
	}

	go m.server.ListenAndServe()

	return nil
}

// Stop stops the metrics HTTP server.
func (m *MetricsManager) Stop() error {
	if m.server != nil {
		return m.server.Close()
	}
	return nil
}

// ============================================================================
// Request Metrics
// ============================================================================

// RecordDiscover records a DISCOVER message.
func (m *MetricsManager) RecordDiscover() {
	atomic.AddInt64(&m.metrics.DiscoverReceived, 1)
}

// RecordRequest records a REQUEST message.
func (m *MetricsManager) RecordRequest() {
	atomic.AddInt64(&m.metrics.RequestReceived, 1)
}

// RecordDecline records a DECLINE message.
func (m *MetricsManager) RecordDecline() {
	atomic.AddInt64(&m.metrics.DeclineReceived, 1)
}

// RecordRelease records a RELEASE message.
func (m *MetricsManager) RecordRelease() {
	atomic.AddInt64(&m.metrics.ReleaseReceived, 1)
}

// RecordInform records an INFORM message.
func (m *MetricsManager) RecordInform() {
	atomic.AddInt64(&m.metrics.InformReceived, 1)
}

// ============================================================================
// Response Metrics
// ============================================================================

// RecordOffer records an OFFER sent.
func (m *MetricsManager) RecordOffer() {
	atomic.AddInt64(&m.metrics.OfferSent, 1)
}

// RecordAck records an ACK sent.
func (m *MetricsManager) RecordAck() {
	atomic.AddInt64(&m.metrics.AckSent, 1)
}

// RecordNak records a NAK sent.
func (m *MetricsManager) RecordNak() {
	atomic.AddInt64(&m.metrics.NakSent, 1)
}

// RecordSendError records a send error.
func (m *MetricsManager) RecordSendError() {
	atomic.AddInt64(&m.metrics.SendErrors, 1)
}

// ============================================================================
// Lease Metrics
// ============================================================================

// RecordLeaseAllocated records a lease allocation.
func (m *MetricsManager) RecordLeaseAllocated() {
	atomic.AddInt64(&m.metrics.LeasesAllocated, 1)
}

// RecordLeaseRenewed records a lease renewal.
func (m *MetricsManager) RecordLeaseRenewed() {
	atomic.AddInt64(&m.metrics.LeasesRenewed, 1)
}

// RecordLeaseReleased records a lease release.
func (m *MetricsManager) RecordLeaseReleased() {
	atomic.AddInt64(&m.metrics.LeasesReleased, 1)
}

// RecordLeaseExpired records a lease expiration.
func (m *MetricsManager) RecordLeaseExpired() {
	atomic.AddInt64(&m.metrics.LeasesExpired, 1)
}

// RecordAllocationFailure records an allocation failure.
func (m *MetricsManager) RecordAllocationFailure(reason string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.metrics.AllocationFailures[reason]++
}

// SetActiveLeases sets the active lease count.
func (m *MetricsManager) SetActiveLeases(count int64) {
	atomic.StoreInt64(&m.metrics.ActiveLeases, count)
}

// SetPendingOffers sets the pending offers count.
func (m *MetricsManager) SetPendingOffers(count int64) {
	atomic.StoreInt64(&m.metrics.PendingOffers, count)
}

// ============================================================================
// Pool Metrics
// ============================================================================

// UpdatePoolMetrics updates metrics for a pool.
func (m *MetricsManager) UpdatePoolMetrics(poolName string, stats *PoolMetrics) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.metrics.PoolUtilization[poolName] = stats
}

// ============================================================================
// Integration Metrics
// ============================================================================

// RecordDNSUpdate records a DNS update attempt.
func (m *MetricsManager) RecordDNSUpdate(success bool) {
	if success {
		atomic.AddInt64(&m.metrics.DNSUpdatesSuccess, 1)
	} else {
		atomic.AddInt64(&m.metrics.DNSUpdatesFailure, 1)
	}
}

// SetDNSAvailable sets DNS availability.
func (m *MetricsManager) SetDNSAvailable(available bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.metrics.DNSAvailable = available
}

// RecordCARequest records a CA request.
func (m *MetricsManager) RecordCARequest(success bool) {
	if success {
		atomic.AddInt64(&m.metrics.CARequestsSuccess, 1)
	} else {
		atomic.AddInt64(&m.metrics.CARequestsFailure, 1)
	}
}

// RecordCACacheHit records a CA cache hit.
func (m *MetricsManager) RecordCACacheHit() {
	atomic.AddInt64(&m.metrics.CACacheHits, 1)
}

// RecordCACacheMiss records a CA cache miss.
func (m *MetricsManager) RecordCACacheMiss() {
	atomic.AddInt64(&m.metrics.CACacheMisses, 1)
}

// RecordCAOptionsSent records CA options included in ACK.
func (m *MetricsManager) RecordCAOptionsSent() {
	atomic.AddInt64(&m.metrics.CAOptionsSent, 1)
}

// SetCAAvailable sets CA availability.
func (m *MetricsManager) SetCAAvailable(available bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.metrics.CAAvailable = available
}

// ============================================================================
// Database Metrics
// ============================================================================

// RecordDBQuery records a database query.
func (m *MetricsManager) RecordDBQuery() {
	atomic.AddInt64(&m.metrics.DBQueriesTotal, 1)
}

// RecordDBError records a database error.
func (m *MetricsManager) RecordDBError() {
	atomic.AddInt64(&m.metrics.DBErrorsTotal, 1)
}

// SetDBAvailable sets database availability.
func (m *MetricsManager) SetDBAvailable(available bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.metrics.DBAvailable = available
}

// SetDBConnections sets active connection count.
func (m *MetricsManager) SetDBConnections(count int64) {
	atomic.StoreInt64(&m.metrics.DBConnections, count)
}

// ============================================================================
// Network Metrics
// ============================================================================

// RecordPacketReceived records a received packet.
func (m *MetricsManager) RecordPacketReceived() {
	atomic.AddInt64(&m.metrics.PacketsReceived, 1)
}

// RecordPacketSent records a sent packet.
func (m *MetricsManager) RecordPacketSent(method string) {
	atomic.AddInt64(&m.metrics.PacketsSent, 1)
	switch method {
	case "broadcast":
		atomic.AddInt64(&m.metrics.BroadcastsSent, 1)
	case "unicast":
		atomic.AddInt64(&m.metrics.UnicastsSent, 1)
	case "relay":
		atomic.AddInt64(&m.metrics.RelaySent, 1)
	}
}

// RecordInvalidPacket records an invalid packet.
func (m *MetricsManager) RecordInvalidPacket() {
	atomic.AddInt64(&m.metrics.InvalidPackets, 1)
}

// ============================================================================
// Component Health
// ============================================================================

// SetComponentHealth sets health status for a component.
func (m *MetricsManager) SetComponentHealth(component string, healthy bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.metrics.ComponentHealth[component] = healthy
}

// ============================================================================
// Performance Metrics
// ============================================================================

// RecordResponseTime records a response time observation.
func (m *MetricsManager) RecordResponseTime(duration time.Duration) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.addHistogramValue(&m.metrics.ResponseTimes, duration.Seconds())
}

// RecordProcessingTime records a processing time observation.
func (m *MetricsManager) RecordProcessingTime(duration time.Duration) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.addHistogramValue(&m.metrics.ProcessingTimes, duration.Seconds())
}

// RecordDBQueryTime records a database query time.
func (m *MetricsManager) RecordDBQueryTime(duration time.Duration) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.addHistogramValue(&m.metrics.DBQueryTimes, duration.Seconds())
}

// RecordDNSUpdateTime records a DNS update time.
func (m *MetricsManager) RecordDNSUpdateTime(duration time.Duration) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.addHistogramValue(&m.metrics.DNSUpdateTimes, duration.Seconds())
}

func (m *MetricsManager) addHistogramValue(slice *[]float64, value float64) {
	*slice = append(*slice, value)
	if len(*slice) > m.metrics.maxHistogramSize {
		*slice = (*slice)[1:]
	}
}

// SetConcurrentRequests sets current concurrent request count.
func (m *MetricsManager) SetConcurrentRequests(count int64) {
	atomic.StoreInt64(&m.metrics.ConcurrentRequests, count)
}

// ============================================================================
// Metrics Export
// ============================================================================

func (m *MetricsManager) handleMetrics(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")

	// Write metrics in Prometheus format
	m.writeMetrics(w)
}

func (m *MetricsManager) writeMetrics(w http.ResponseWriter) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	// Uptime
	uptime := time.Since(m.metrics.StartTime).Seconds()
	writeGauge(w, "dhcp_server_uptime_seconds", "Seconds since server started", uptime)

	// Request counters
	writeCounter(w, "dhcp_discover_received_total", "DISCOVER messages received", float64(m.metrics.DiscoverReceived))
	writeCounter(w, "dhcp_request_received_total", "REQUEST messages received", float64(m.metrics.RequestReceived))
	writeCounter(w, "dhcp_decline_received_total", "DECLINE messages received", float64(m.metrics.DeclineReceived))
	writeCounter(w, "dhcp_release_received_total", "RELEASE messages received", float64(m.metrics.ReleaseReceived))
	writeCounter(w, "dhcp_inform_received_total", "INFORM messages received", float64(m.metrics.InformReceived))

	// Response counters
	writeCounter(w, "dhcp_offer_sent_total", "OFFER messages sent", float64(m.metrics.OfferSent))
	writeCounter(w, "dhcp_ack_sent_total", "ACK messages sent", float64(m.metrics.AckSent))
	writeCounter(w, "dhcp_nak_sent_total", "NAK messages sent", float64(m.metrics.NakSent))
	writeCounter(w, "dhcp_send_errors_total", "Send errors", float64(m.metrics.SendErrors))

	// Lease counters
	writeCounter(w, "dhcp_leases_allocated_total", "Leases allocated", float64(m.metrics.LeasesAllocated))
	writeCounter(w, "dhcp_leases_renewed_total", "Leases renewed", float64(m.metrics.LeasesRenewed))
	writeCounter(w, "dhcp_leases_released_total", "Leases released", float64(m.metrics.LeasesReleased))
	writeCounter(w, "dhcp_leases_expired_total", "Leases expired", float64(m.metrics.LeasesExpired))

	// Lease gauges
	writeGauge(w, "dhcp_leases_active", "Active leases", float64(m.metrics.ActiveLeases))
	writeGauge(w, "dhcp_leases_pending", "Pending offers", float64(m.metrics.PendingOffers))
	writeGauge(w, "dhcp_concurrent_requests", "Concurrent requests", float64(m.metrics.ConcurrentRequests))

	// Pool metrics
	for poolName, pool := range m.metrics.PoolUtilization {
		writeGaugeLabeled(w, "dhcp_pool_utilization_percent", "Pool utilization", pool.Utilization, "pool_name", poolName)
		writeGaugeLabeled(w, "dhcp_pool_total_ips", "Total IPs", float64(pool.TotalIPs), "pool_name", poolName)
		writeGaugeLabeled(w, "dhcp_pool_allocated_ips", "Allocated IPs", float64(pool.AllocatedIPs), "pool_name", poolName)
		writeGaugeLabeled(w, "dhcp_pool_available_ips", "Available IPs", float64(pool.AvailableIPs), "pool_name", poolName)
	}

	// DNS metrics
	writeCounter(w, "dhcp_dns_updates_success_total", "DNS updates succeeded", float64(m.metrics.DNSUpdatesSuccess))
	writeCounter(w, "dhcp_dns_updates_failure_total", "DNS updates failed", float64(m.metrics.DNSUpdatesFailure))
	writeGaugeBool(w, "dhcp_dns_service_available", "DNS available", m.metrics.DNSAvailable)

	// CA metrics
	writeCounter(w, "dhcp_ca_requests_success_total", "CA requests succeeded", float64(m.metrics.CARequestsSuccess))
	writeCounter(w, "dhcp_ca_requests_failure_total", "CA requests failed", float64(m.metrics.CARequestsFailure))
	writeCounter(w, "dhcp_ca_cache_hits_total", "CA cache hits", float64(m.metrics.CACacheHits))
	writeCounter(w, "dhcp_ca_cache_misses_total", "CA cache misses", float64(m.metrics.CACacheMisses))
	writeCounter(w, "dhcp_ca_options_sent_total", "ACKs with CA options", float64(m.metrics.CAOptionsSent))
	writeGaugeBool(w, "dhcp_ca_service_available", "CA available", m.metrics.CAAvailable)

	// Database metrics
	writeCounter(w, "dhcp_database_queries_total", "Database queries", float64(m.metrics.DBQueriesTotal))
	writeCounter(w, "dhcp_database_errors_total", "Database errors", float64(m.metrics.DBErrorsTotal))
	writeGaugeBool(w, "dhcp_database_available", "Database available", m.metrics.DBAvailable)
	writeGauge(w, "dhcp_database_connections", "Database connections", float64(m.metrics.DBConnections))

	// Network metrics
	writeCounter(w, "dhcp_packets_received_total", "Packets received", float64(m.metrics.PacketsReceived))
	writeCounter(w, "dhcp_packets_sent_total", "Packets sent", float64(m.metrics.PacketsSent))
	writeCounter(w, "dhcp_broadcasts_sent_total", "Broadcasts sent", float64(m.metrics.BroadcastsSent))
	writeCounter(w, "dhcp_unicasts_sent_total", "Unicasts sent", float64(m.metrics.UnicastsSent))
	writeCounter(w, "dhcp_relay_sent_total", "Relay packets sent", float64(m.metrics.RelaySent))
	writeCounter(w, "dhcp_invalid_packets_total", "Invalid packets", float64(m.metrics.InvalidPackets))

	// Component health
	for component, healthy := range m.metrics.ComponentHealth {
		writeGaugeLabeledBool(w, "dhcp_component_healthy", "Component health", healthy, "component", component)
	}
}

// ============================================================================
// Prometheus Format Helpers
// ============================================================================

func writeCounter(w http.ResponseWriter, name, help string, value float64) {
	w.Write([]byte("# HELP " + name + " " + help + "\n"))
	w.Write([]byte("# TYPE " + name + " counter\n"))
	w.Write([]byte(name + " " + formatFloat(value) + "\n"))
}

func writeGauge(w http.ResponseWriter, name, help string, value float64) {
	w.Write([]byte("# HELP " + name + " " + help + "\n"))
	w.Write([]byte("# TYPE " + name + " gauge\n"))
	w.Write([]byte(name + " " + formatFloat(value) + "\n"))
}

func writeGaugeBool(w http.ResponseWriter, name, help string, value bool) {
	v := 0.0
	if value {
		v = 1.0
	}
	writeGauge(w, name, help, v)
}

func writeGaugeLabeled(w http.ResponseWriter, name, help string, value float64, labelName, labelValue string) {
	w.Write([]byte("# HELP " + name + " " + help + "\n"))
	w.Write([]byte("# TYPE " + name + " gauge\n"))
	w.Write([]byte(name + `{` + labelName + `="` + labelValue + `"} ` + formatFloat(value) + "\n"))
}

func writeGaugeLabeledBool(w http.ResponseWriter, name, help string, value bool, labelName, labelValue string) {
	v := 0.0
	if value {
		v = 1.0
	}
	writeGaugeLabeled(w, name, help, v, labelName, labelValue)
}

// GetMetrics returns current metrics snapshot.
func (m *MetricsManager) GetMetrics() *DHCPMetrics {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.metrics
}
