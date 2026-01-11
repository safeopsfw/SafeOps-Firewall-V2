// Package grpc provides gRPC server and handlers for the NIC Management service.
package grpc

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"time"

	"github.com/google/uuid"

	"safeops/nic_management/internal/performance"
)

// =============================================================================
// Stream Handlers Error Types
// =============================================================================

var (
	// ErrMaxStreamsExceeded indicates max concurrent streams exceeded.
	ErrMaxStreamsExceeded = errors.New("max concurrent streams exceeded")
	// ErrStreamClosed indicates stream was closed.
	ErrStreamClosed = errors.New("stream closed")
	// ErrInvalidInterval indicates invalid update interval.
	ErrInvalidInterval = errors.New("invalid update interval")
)

// =============================================================================
// Stream Types
// =============================================================================

// StreamType represents the type of stream.
type StreamType string

const (
	StreamTypeMetrics     StreamType = "metrics"
	StreamTypeConnections StreamType = "connections"
	StreamTypeInterfaces  StreamType = "interfaces"
	StreamTypeFailovers   StreamType = "failovers"
	StreamTypeRouting     StreamType = "routing"
)

// =============================================================================
// Metrics Bitmask Constants
// =============================================================================

const (
	MetricsThroughput      uint32 = 1 << 0
	MetricsPacketRate      uint32 = 1 << 1
	MetricsErrors          uint32 = 1 << 2
	MetricsConnectionCount uint32 = 1 << 3
	MetricsUtilization     uint32 = 1 << 4
	MetricsAll             uint32 = 0xFFFFFFFF
)

// =============================================================================
// Stream Info Structure
// =============================================================================

// StreamInfo contains information about an active stream.
type StreamInfo struct {
	ID             string        `json:"id"`
	ClientID       string        `json:"client_id"`
	Type           StreamType    `json:"type"`
	StartedAt      time.Time     `json:"started_at"`
	BytesSent      uint64        `json:"bytes_sent"`
	MessagesSent   uint64        `json:"messages_sent"`
	LastSentAt     time.Time     `json:"last_sent_at"`
	UpdateInterval time.Duration `json:"update_interval"`
}

// =============================================================================
// Metrics Update Structure
// =============================================================================

// MetricsUpdate contains a metrics update message.
type MetricsUpdate struct {
	Timestamp  time.Time                            `json:"timestamp"`
	Interfaces map[string]*InterfaceMetricsSnapshot `json:"interfaces"`
}

// InterfaceMetricsSnapshot contains metrics for one interface.
type InterfaceMetricsSnapshot struct {
	InterfaceName   string  `json:"interface_name"`
	ThroughputMbps  float64 `json:"throughput_mbps"`
	RxMbps          float64 `json:"rx_mbps"`
	TxMbps          float64 `json:"tx_mbps"`
	PacketsPerSec   uint64  `json:"packets_per_sec"`
	ErrorsPerSec    float64 `json:"errors_per_sec"`
	Utilization     float64 `json:"utilization"`
	ConnectionCount int     `json:"connection_count"`
	CompositeScore  float64 `json:"composite_score"`
}

// =============================================================================
// Connection State Update Structure
// =============================================================================

// ConnectionStateUpdate contains a connection state change.
type ConnectionStateUpdate struct {
	Timestamp time.Time `json:"timestamp"`
	SrcIP     string    `json:"src_ip"`
	DstIP     string    `json:"dst_ip"`
	SrcPort   uint16    `json:"src_port"`
	DstPort   uint16    `json:"dst_port"`
	Protocol  uint8     `json:"protocol"`
	OldState  string    `json:"old_state"`
	NewState  string    `json:"new_state"`
	Interface string    `json:"interface"`
}

// =============================================================================
// Interface Event Structure
// =============================================================================

// InterfaceEvent contains an interface state change event.
type InterfaceEvent struct {
	Timestamp   time.Time              `json:"timestamp"`
	InterfaceID string                 `json:"interface_id"`
	EventType   string                 `json:"event_type"`
	OldState    string                 `json:"old_state,omitempty"`
	NewState    string                 `json:"new_state,omitempty"`
	Details     map[string]interface{} `json:"details,omitempty"`
}

// =============================================================================
// Failover Event Structure
// =============================================================================

// FailoverEvent contains a WAN failover/recovery event.
type FailoverEvent struct {
	Timestamp        time.Time `json:"timestamp"`
	EventType        string    `json:"event_type"` // FAILOVER or RECOVERY
	FailedWan        string    `json:"failed_wan"`
	ActiveWan        string    `json:"active_wan"`
	AffectedSessions int       `json:"affected_sessions"`
	Reason           string    `json:"reason,omitempty"`
}

// =============================================================================
// Routing Table Update Structure
// =============================================================================

// RoutingTableUpdate contains a routing table change.
type RoutingTableUpdate struct {
	Timestamp   time.Time `json:"timestamp"`
	ChangeType  string    `json:"change_type"` // ROUTE_ADDED, ROUTE_REMOVED, ROUTE_MODIFIED
	Destination string    `json:"destination"`
	Gateway     string    `json:"gateway"`
	Interface   string    `json:"interface"`
	Metric      int       `json:"metric"`
}

// =============================================================================
// Stream Request Structures
// =============================================================================

// StreamMetricsRequest contains parameters for metrics streaming.
type StreamMetricsRequest struct {
	InterfaceFilter  []string      `json:"interface_filter,omitempty"`
	UpdateInterval   time.Duration `json:"update_interval"`
	MetricsToInclude uint32        `json:"metrics_to_include"`
}

// StreamConnectionsRequest contains parameters for connection streaming.
type StreamConnectionsRequest struct {
	StateFilter    []string `json:"state_filter,omitempty"`
	ProtocolFilter []string `json:"protocol_filter,omitempty"`
}

// StreamInterfaceEventsRequest contains parameters for interface event streaming.
type StreamInterfaceEventsRequest struct {
	EventTypes []string `json:"event_types,omitempty"`
}

// =============================================================================
// Active Stream Entry
// =============================================================================

// activeStream represents an active streaming connection.
type activeStream struct {
	Info     *StreamInfo
	Cancel   context.CancelFunc
	SendChan chan interface{}
	mu       sync.Mutex
}

// =============================================================================
// Stream Handlers Configuration
// =============================================================================

// StreamHandlersConfig contains streaming configuration.
type StreamHandlersConfig struct {
	MaxConcurrentStreams   int           `json:"max_concurrent_streams"`
	DefaultMetricsInterval time.Duration `json:"default_metrics_interval"`
	MinMetricsInterval     time.Duration `json:"min_metrics_interval"`
	EventBufferSize        int           `json:"event_buffer_size"`
	MaxBytesPerStream      int64         `json:"max_bytes_per_stream"`
}

// DefaultStreamHandlersConfig returns the default configuration.
func DefaultStreamHandlersConfig() *StreamHandlersConfig {
	return &StreamHandlersConfig{
		MaxConcurrentStreams:   200,
		DefaultMetricsInterval: 5 * time.Second,
		MinMetricsInterval:     1 * time.Second,
		EventBufferSize:        1000,
		MaxBytesPerStream:      10 * 1024 * 1024, // 10 MB/s.
	}
}

// =============================================================================
// Stream Handlers
// =============================================================================

// StreamHandlers manages streaming RPCs.
type StreamHandlers struct {
	// Dependencies.
	metricsAggregator *performance.MetricsAggregator

	// Configuration.
	config *StreamHandlersConfig

	// Active streams.
	activeStreams map[string]*activeStream
	streamsMu     sync.RWMutex

	// Statistics.
	totalStreamsCreated uint64
	totalBytesSent      uint64
	totalMessagesSent   uint64
	streamErrors        uint64

	// Lifecycle.
	stopChan  chan struct{}
	running   bool
	runningMu sync.Mutex
}

// NewStreamHandlers creates a new stream handlers instance.
func NewStreamHandlers(
	metricsAggregator *performance.MetricsAggregator,
	config *StreamHandlersConfig,
) *StreamHandlers {
	if config == nil {
		config = DefaultStreamHandlersConfig()
	}

	return &StreamHandlers{
		metricsAggregator: metricsAggregator,
		config:            config,
		activeStreams:     make(map[string]*activeStream),
		stopChan:          make(chan struct{}),
	}
}

// =============================================================================
// Lifecycle Management
// =============================================================================

// Start begins stream handlers.
func (sh *StreamHandlers) Start(ctx context.Context) error {
	sh.runningMu.Lock()
	defer sh.runningMu.Unlock()

	if sh.running {
		return nil
	}

	sh.running = true
	return nil
}

// Stop gracefully shuts down stream handlers.
func (sh *StreamHandlers) Stop() error {
	sh.runningMu.Lock()
	if !sh.running {
		sh.runningMu.Unlock()
		return nil
	}
	sh.running = false
	sh.runningMu.Unlock()

	// Close all active streams.
	sh.CloseAllStreams()

	close(sh.stopChan)
	return nil
}

// =============================================================================
// Metrics Streaming
// =============================================================================

// MetricsSender is an interface for sending metrics updates.
type MetricsSender interface {
	Send(*MetricsUpdate) error
}

// StreamMetrics starts streaming metrics to a client.
func (sh *StreamHandlers) StreamMetrics(
	ctx context.Context,
	request *StreamMetricsRequest,
	sender MetricsSender,
) error {
	// Validate request.
	if err := sh.validateMetricsRequest(request); err != nil {
		return err
	}

	// Check max streams.
	if sh.getActiveStreamCount() >= sh.config.MaxConcurrentStreams {
		return ErrMaxStreamsExceeded
	}

	// Create stream context.
	streamCtx, cancel := context.WithCancel(ctx)
	defer cancel()

	// Register stream.
	streamID := uuid.New().String()
	stream := sh.registerStream(streamID, StreamTypeMetrics, request.UpdateInterval)
	defer sh.unregisterStream(streamID)

	// Start streaming loop.
	ticker := time.NewTicker(request.UpdateInterval)
	defer ticker.Stop()

	for {
		select {
		case <-streamCtx.Done():
			return nil
		case <-sh.stopChan:
			return ErrStreamClosed
		case <-ticker.C:
			update := sh.collectMetricsUpdate(request)
			if err := sender.Send(update); err != nil {
				atomic.AddUint64(&sh.streamErrors, 1)
				return err
			}
			sh.recordMessageSent(stream, 0) // Size would be calculated from proto.
		}
	}
}

// validateMetricsRequest validates a metrics stream request.
func (sh *StreamHandlers) validateMetricsRequest(request *StreamMetricsRequest) error {
	if request.UpdateInterval < sh.config.MinMetricsInterval {
		request.UpdateInterval = sh.config.DefaultMetricsInterval
	}
	if request.MetricsToInclude == 0 {
		request.MetricsToInclude = MetricsAll
	}
	return nil
}

// collectMetricsUpdate collects current metrics for streaming.
func (sh *StreamHandlers) collectMetricsUpdate(request *StreamMetricsRequest) *MetricsUpdate {
	update := &MetricsUpdate{
		Timestamp:  time.Now(),
		Interfaces: make(map[string]*InterfaceMetricsSnapshot),
	}

	if sh.metricsAggregator == nil {
		return update
	}

	// Get all metrics snapshots.
	snapshots := sh.metricsAggregator.GetAllSnapshots()

	for name, metrics := range snapshots {
		// Apply interface filter.
		if len(request.InterfaceFilter) > 0 {
			found := false
			for _, filter := range request.InterfaceFilter {
				if filter == name {
					found = true
					break
				}
			}
			if !found {
				continue
			}
		}

		snapshot := &InterfaceMetricsSnapshot{
			InterfaceName: name,
		}

		// Include requested metrics.
		if request.MetricsToInclude&MetricsThroughput != 0 {
			snapshot.ThroughputMbps = metrics.Throughput.TotalMbps
			snapshot.RxMbps = metrics.Throughput.RxMbps
			snapshot.TxMbps = metrics.Throughput.TxMbps
		}
		if request.MetricsToInclude&MetricsPacketRate != 0 {
			snapshot.PacketsPerSec = metrics.PacketRate.TotalPacketsPerSec
		}
		if request.MetricsToInclude&MetricsErrors != 0 {
			snapshot.ErrorsPerSec = metrics.ErrorRates.TotalErrorsPerSec
		}
		if request.MetricsToInclude&MetricsUtilization != 0 {
			snapshot.Utilization = metrics.Utilization.TotalUtilization
		}

		snapshot.CompositeScore = metrics.CompositeScore

		update.Interfaces[name] = snapshot
	}

	return update
}

// =============================================================================
// Connection State Streaming
// =============================================================================

// ConnectionStateSender is an interface for sending connection updates.
type ConnectionStateSender interface {
	Send(*ConnectionStateUpdate) error
}

// StreamConnectionStates starts streaming connection state changes.
func (sh *StreamHandlers) StreamConnectionStates(
	ctx context.Context,
	request *StreamConnectionsRequest,
	sender ConnectionStateSender,
	eventChan <-chan *ConnectionStateUpdate,
) error {
	// Check max streams.
	if sh.getActiveStreamCount() >= sh.config.MaxConcurrentStreams {
		return ErrMaxStreamsExceeded
	}

	// Create stream context.
	streamCtx, cancel := context.WithCancel(ctx)
	defer cancel()

	// Register stream.
	streamID := uuid.New().String()
	stream := sh.registerStream(streamID, StreamTypeConnections, 0)
	defer sh.unregisterStream(streamID)

	// Buffer for backpressure handling.
	buffer := make([]*ConnectionStateUpdate, 0, sh.config.EventBufferSize)

	for {
		select {
		case <-streamCtx.Done():
			return nil
		case <-sh.stopChan:
			return ErrStreamClosed
		case event := <-eventChan:
			if event == nil {
				continue
			}

			// Apply filters.
			if !sh.matchesConnectionFilter(event, request) {
				continue
			}

			// Try to send, buffer if backpressure.
			if err := sender.Send(event); err != nil {
				// Buffer the event.
				if len(buffer) < sh.config.EventBufferSize {
					buffer = append(buffer, event)
				} else {
					// Drop oldest.
					buffer = append(buffer[1:], event)
				}
				continue
			}

			sh.recordMessageSent(stream, 0)

			// Try to drain buffer.
			for len(buffer) > 0 {
				if err := sender.Send(buffer[0]); err != nil {
					break
				}
				buffer = buffer[1:]
				sh.recordMessageSent(stream, 0)
			}
		}
	}
}

// matchesConnectionFilter checks if an event matches the filter.
func (sh *StreamHandlers) matchesConnectionFilter(
	event *ConnectionStateUpdate,
	request *StreamConnectionsRequest,
) bool {
	// Check state filter.
	if len(request.StateFilter) > 0 {
		found := false
		for _, state := range request.StateFilter {
			if state == event.NewState {
				found = true
				break
			}
		}
		if !found {
			return false
		}
	}

	// Check protocol filter.
	if len(request.ProtocolFilter) > 0 {
		protoName := protocolName(event.Protocol)
		found := false
		for _, proto := range request.ProtocolFilter {
			if proto == protoName {
				found = true
				break
			}
		}
		if !found {
			return false
		}
	}

	return true
}

// protocolName returns protocol name from number.
func protocolName(proto uint8) string {
	switch proto {
	case 6:
		return "TCP"
	case 17:
		return "UDP"
	case 1:
		return "ICMP"
	default:
		return "OTHER"
	}
}

// =============================================================================
// Interface Events Streaming
// =============================================================================

// InterfaceEventSender is an interface for sending interface events.
type InterfaceEventSender interface {
	Send(*InterfaceEvent) error
}

// StreamInterfaceEvents starts streaming interface events.
func (sh *StreamHandlers) StreamInterfaceEvents(
	ctx context.Context,
	request *StreamInterfaceEventsRequest,
	sender InterfaceEventSender,
	eventChan <-chan *InterfaceEvent,
) error {
	// Check max streams.
	if sh.getActiveStreamCount() >= sh.config.MaxConcurrentStreams {
		return ErrMaxStreamsExceeded
	}

	// Create stream context.
	streamCtx, cancel := context.WithCancel(ctx)
	defer cancel()

	// Register stream.
	streamID := uuid.New().String()
	stream := sh.registerStream(streamID, StreamTypeInterfaces, 0)
	defer sh.unregisterStream(streamID)

	for {
		select {
		case <-streamCtx.Done():
			return nil
		case <-sh.stopChan:
			return ErrStreamClosed
		case event := <-eventChan:
			if event == nil {
				continue
			}

			// Apply event type filter.
			if len(request.EventTypes) > 0 {
				found := false
				for _, t := range request.EventTypes {
					if t == event.EventType {
						found = true
						break
					}
				}
				if !found {
					continue
				}
			}

			if err := sender.Send(event); err != nil {
				atomic.AddUint64(&sh.streamErrors, 1)
				return err
			}
			sh.recordMessageSent(stream, 0)
		}
	}
}

// =============================================================================
// Failover Events Streaming
// =============================================================================

// FailoverEventSender is an interface for sending failover events.
type FailoverEventSender interface {
	Send(*FailoverEvent) error
}

// StreamWanFailovers starts streaming WAN failover events.
func (sh *StreamHandlers) StreamWanFailovers(
	ctx context.Context,
	sender FailoverEventSender,
	eventChan <-chan *FailoverEvent,
) error {
	// Check max streams.
	if sh.getActiveStreamCount() >= sh.config.MaxConcurrentStreams {
		return ErrMaxStreamsExceeded
	}

	// Create stream context.
	streamCtx, cancel := context.WithCancel(ctx)
	defer cancel()

	// Register stream.
	streamID := uuid.New().String()
	stream := sh.registerStream(streamID, StreamTypeFailovers, 0)
	defer sh.unregisterStream(streamID)

	for {
		select {
		case <-streamCtx.Done():
			return nil
		case <-sh.stopChan:
			return ErrStreamClosed
		case event := <-eventChan:
			if event == nil {
				continue
			}

			if err := sender.Send(event); err != nil {
				atomic.AddUint64(&sh.streamErrors, 1)
				return err
			}
			sh.recordMessageSent(stream, 0)
		}
	}
}

// =============================================================================
// Routing Table Streaming
// =============================================================================

// RoutingTableSender is an interface for sending routing updates.
type RoutingTableSender interface {
	Send(*RoutingTableUpdate) error
}

// StreamRoutingTableUpdates starts streaming routing table changes.
func (sh *StreamHandlers) StreamRoutingTableUpdates(
	ctx context.Context,
	sender RoutingTableSender,
	eventChan <-chan *RoutingTableUpdate,
) error {
	// Check max streams.
	if sh.getActiveStreamCount() >= sh.config.MaxConcurrentStreams {
		return ErrMaxStreamsExceeded
	}

	// Create stream context.
	streamCtx, cancel := context.WithCancel(ctx)
	defer cancel()

	// Register stream.
	streamID := uuid.New().String()
	stream := sh.registerStream(streamID, StreamTypeRouting, 0)
	defer sh.unregisterStream(streamID)

	for {
		select {
		case <-streamCtx.Done():
			return nil
		case <-sh.stopChan:
			return ErrStreamClosed
		case event := <-eventChan:
			if event == nil {
				continue
			}

			if err := sender.Send(event); err != nil {
				atomic.AddUint64(&sh.streamErrors, 1)
				return err
			}
			sh.recordMessageSent(stream, 0)
		}
	}
}

// =============================================================================
// Stream Management
// =============================================================================

// registerStream registers a new active stream.
func (sh *StreamHandlers) registerStream(
	streamID string,
	streamType StreamType,
	updateInterval time.Duration,
) *activeStream {
	sh.streamsMu.Lock()
	defer sh.streamsMu.Unlock()

	stream := &activeStream{
		Info: &StreamInfo{
			ID:             streamID,
			ClientID:       streamID, // Would be extracted from metadata in production.
			Type:           streamType,
			StartedAt:      time.Now(),
			UpdateInterval: updateInterval,
		},
	}

	sh.activeStreams[streamID] = stream
	atomic.AddUint64(&sh.totalStreamsCreated, 1)

	return stream
}

// unregisterStream removes an active stream.
func (sh *StreamHandlers) unregisterStream(streamID string) {
	sh.streamsMu.Lock()
	defer sh.streamsMu.Unlock()

	if stream, exists := sh.activeStreams[streamID]; exists {
		if stream.Cancel != nil {
			stream.Cancel()
		}
		delete(sh.activeStreams, streamID)
	}
}

// recordMessageSent records a message was sent on a stream.
func (sh *StreamHandlers) recordMessageSent(stream *activeStream, size int) {
	stream.mu.Lock()
	stream.Info.MessagesSent++
	stream.Info.BytesSent += uint64(size)
	stream.Info.LastSentAt = time.Now()
	stream.mu.Unlock()

	atomic.AddUint64(&sh.totalMessagesSent, 1)
	atomic.AddUint64(&sh.totalBytesSent, uint64(size))
}

// getActiveStreamCount returns the number of active streams.
func (sh *StreamHandlers) getActiveStreamCount() int {
	sh.streamsMu.RLock()
	defer sh.streamsMu.RUnlock()
	return len(sh.activeStreams)
}

// =============================================================================
// Stream Query Methods
// =============================================================================

// ActiveStreamsInfo contains active streams summary.
type ActiveStreamsInfo struct {
	TotalActiveStreams int                `json:"total_active_streams"`
	StreamsByType      map[StreamType]int `json:"streams_by_type"`
	Streams            []*StreamInfo      `json:"streams"`
}

// GetActiveStreams returns information about active streams.
func (sh *StreamHandlers) GetActiveStreams() *ActiveStreamsInfo {
	sh.streamsMu.RLock()
	defer sh.streamsMu.RUnlock()

	info := &ActiveStreamsInfo{
		TotalActiveStreams: len(sh.activeStreams),
		StreamsByType:      make(map[StreamType]int),
		Streams:            make([]*StreamInfo, 0, len(sh.activeStreams)),
	}

	for _, stream := range sh.activeStreams {
		stream.mu.Lock()
		infoCopy := *stream.Info
		stream.mu.Unlock()

		info.Streams = append(info.Streams, &infoCopy)
		info.StreamsByType[stream.Info.Type]++
	}

	return info
}

// CloseAllStreams closes all active streams.
func (sh *StreamHandlers) CloseAllStreams() {
	sh.streamsMu.Lock()
	streams := make([]*activeStream, 0, len(sh.activeStreams))
	for _, stream := range sh.activeStreams {
		streams = append(streams, stream)
	}
	sh.streamsMu.Unlock()

	// Cancel all streams.
	for _, stream := range streams {
		if stream.Cancel != nil {
			stream.Cancel()
		}
	}

	// Wait a bit for graceful shutdown.
	time.Sleep(100 * time.Millisecond)

	// Clear the map.
	sh.streamsMu.Lock()
	sh.activeStreams = make(map[string]*activeStream)
	sh.streamsMu.Unlock()
}

// CloseStream closes a specific stream.
func (sh *StreamHandlers) CloseStream(streamID string) error {
	sh.streamsMu.Lock()
	defer sh.streamsMu.Unlock()

	stream, exists := sh.activeStreams[streamID]
	if !exists {
		return errors.New("stream not found")
	}

	if stream.Cancel != nil {
		stream.Cancel()
	}
	delete(sh.activeStreams, streamID)

	return nil
}

// =============================================================================
// Statistics
// =============================================================================

// StreamStats contains streaming statistics.
type StreamStats struct {
	TotalStreamsCreated uint64 `json:"total_streams_created"`
	ActiveStreamCount   int    `json:"active_stream_count"`
	TotalBytesSent      uint64 `json:"total_bytes_sent"`
	TotalMessagesSent   uint64 `json:"total_messages_sent"`
	StreamErrors        uint64 `json:"stream_errors"`
}

// GetStreamStats returns streaming statistics.
func (sh *StreamHandlers) GetStreamStats() *StreamStats {
	return &StreamStats{
		TotalStreamsCreated: atomic.LoadUint64(&sh.totalStreamsCreated),
		ActiveStreamCount:   sh.getActiveStreamCount(),
		TotalBytesSent:      atomic.LoadUint64(&sh.totalBytesSent),
		TotalMessagesSent:   atomic.LoadUint64(&sh.totalMessagesSent),
		StreamErrors:        atomic.LoadUint64(&sh.streamErrors),
	}
}

// =============================================================================
// Health Check
// =============================================================================

// HealthCheck verifies stream handlers are operational.
func (sh *StreamHandlers) HealthCheck() error {
	sh.runningMu.Lock()
	running := sh.running
	sh.runningMu.Unlock()

	if !running {
		return errors.New("stream handlers not running")
	}

	return nil
}

// GetConfig returns the current configuration.
func (sh *StreamHandlers) GetConfig() *StreamHandlersConfig {
	return sh.config
}
