// Package integration provides cross-service integration components
// for the NIC Management service.
package integration

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/google/uuid"
)

// =============================================================================
// Logger Hooks Error Types
// =============================================================================

var (
	// ErrLoggerNotEnabled indicates logger integration is disabled.
	ErrLoggerNotEnabled = errors.New("logger integration not enabled")
	// ErrLoggerServiceUnavailable indicates logger service is down.
	ErrLoggerServiceUnavailable = errors.New("logger service unavailable")
	// ErrLogQueueFull indicates log queue is full.
	ErrLogQueueFull = errors.New("log queue full")
)

// =============================================================================
// Log Entry Event Types
// =============================================================================

const (
	LogEventNewConnection        = "NEW_CONNECTION"
	LogEventWANFailover          = "WAN_FAILOVER"
	LogEventInterfaceStateChange = "INTERFACE_STATE_CHANGE"
	LogEventNATMappingCreated    = "NAT_MAPPING_CREATED"
	LogEventNATMappingDeleted    = "NAT_MAPPING_DELETED"
	LogEventFirewallBlock        = "FIREWALL_BLOCK"
	LogEventThreatDetected       = "THREAT_DETECTED"
	LogEventConfigChange         = "CONFIG_CHANGE"
)

// =============================================================================
// Log Severity Constants
// =============================================================================

// LogSeverity represents log severity level.
type LogSeverity int

const (
	SeverityInfo LogSeverity = iota
	SeverityWarning
	SeverityError
	SeverityCritical
)

// String returns the string representation.
func (s LogSeverity) String() string {
	switch s {
	case SeverityInfo:
		return "INFO"
	case SeverityWarning:
		return "WARNING"
	case SeverityError:
		return "ERROR"
	case SeverityCritical:
		return "CRITICAL"
	default:
		return "UNKNOWN"
	}
}

// =============================================================================
// Failover Type Constants
// =============================================================================

// FailoverType represents failover trigger type.
type FailoverType string

const (
	FailoverTypeAutomatic FailoverType = "AUTOMATIC"
	FailoverTypeManual    FailoverType = "MANUAL"
)

// =============================================================================
// Interface State Event Types
// =============================================================================

// InterfaceEventType represents interface state change type.
type InterfaceEventType string

const (
	InterfaceEventUp                InterfaceEventType = "INTERFACE_UP"
	InterfaceEventDown              InterfaceEventType = "INTERFACE_DOWN"
	InterfaceEventCableConnected    InterfaceEventType = "CABLE_CONNECTED"
	InterfaceEventCableDisconnected InterfaceEventType = "CABLE_DISCONNECTED"
	InterfaceEventHotplugAdded      InterfaceEventType = "HOTPLUG_ADDED"
	InterfaceEventHotplugRemoved    InterfaceEventType = "HOTPLUG_REMOVED"
)

// =============================================================================
// Threat Action Constants
// =============================================================================

// ThreatAction represents IDS/IPS action.
type ThreatAction string

const (
	ThreatActionAlert ThreatAction = "ALERT"
	ThreatActionBlock ThreatAction = "BLOCK"
)

// =============================================================================
// Log Entry Structure
// =============================================================================

// LogEntry represents a single log entry.
type LogEntry struct {
	ID        string                 `json:"id"`
	EventType string                 `json:"event_type"`
	Timestamp time.Time              `json:"timestamp"`
	Severity  LogSeverity            `json:"severity"`
	Source    string                 `json:"source"`
	Data      map[string]interface{} `json:"data"`
	Priority  bool                   `json:"priority"` // High priority for immediate delivery.
}

// NewLogEntry creates a new log entry.
func NewLogEntry(eventType string, severity LogSeverity) *LogEntry {
	return &LogEntry{
		ID:        uuid.New().String(),
		EventType: eventType,
		Timestamp: time.Now(),
		Severity:  severity,
		Source:    "nic-management",
		Data:      make(map[string]interface{}),
	}
}

// =============================================================================
// Logger Hooks Configuration
// =============================================================================

// LoggerHooksConfig contains logger integration configuration.
type LoggerHooksConfig struct {
	// Enabled enables logger integration.
	Enabled bool `json:"enabled"`
	// ServiceAddress is the Network Logger gRPC address.
	ServiceAddress string `json:"service_address"`
	// LogQueueSize is the standard queue capacity.
	LogQueueSize int `json:"log_queue_size"`
	// PriorityQueueSize is the priority queue capacity.
	PriorityQueueSize int `json:"priority_queue_size"`
	// BatchSize is entries per batch.
	BatchSize int `json:"batch_size"`
	// FlushInterval is max time between flushes.
	FlushInterval time.Duration `json:"flush_interval"`
	// IncludePacketSamples enables packet payloads for security events.
	IncludePacketSamples bool `json:"include_packet_samples"`
	// MaxPacketSampleSize is max bytes for packet samples.
	MaxPacketSampleSize int `json:"max_packet_sample_size"`
}

// DefaultLoggerHooksConfig returns the default configuration.
func DefaultLoggerHooksConfig() *LoggerHooksConfig {
	return &LoggerHooksConfig{
		Enabled:              true,
		ServiceAddress:       "localhost:50066",
		LogQueueSize:         50000,
		PriorityQueueSize:    5000,
		BatchSize:            100,
		FlushInterval:        5 * time.Second,
		IncludePacketSamples: true,
		MaxPacketSampleSize:  256,
	}
}

// =============================================================================
// Logger Hooks
// =============================================================================

// LoggerHooks manages logger integration.
type LoggerHooks struct {
	// Configuration.
	config *LoggerHooksConfig

	// Queues.
	logQueue      chan *LogEntry
	priorityQueue chan *LogEntry

	// Statistics.
	logsSent         uint64
	logsDropped      uint64
	batchesSent      uint64
	priorityLogsSent uint64
	sendErrors       uint64

	// Lifecycle.
	wg        sync.WaitGroup
	stopChan  chan struct{}
	running   bool
	runningMu sync.Mutex
}

// NewLoggerHooks creates a new logger hooks instance.
func NewLoggerHooks(config *LoggerHooksConfig) *LoggerHooks {
	if config == nil {
		config = DefaultLoggerHooksConfig()
	}

	return &LoggerHooks{
		config:        config,
		logQueue:      make(chan *LogEntry, config.LogQueueSize),
		priorityQueue: make(chan *LogEntry, config.PriorityQueueSize),
		stopChan:      make(chan struct{}),
	}
}

// =============================================================================
// Lifecycle Management
// =============================================================================

// Start begins logger integration.
func (lh *LoggerHooks) Start(ctx context.Context) error {
	lh.runningMu.Lock()
	defer lh.runningMu.Unlock()

	if lh.running {
		return nil
	}

	if !lh.config.Enabled {
		lh.running = true
		return nil
	}

	// Start log processor (batching).
	lh.wg.Add(1)
	go lh.logProcessor()

	// Start priority processor (immediate).
	lh.wg.Add(1)
	go lh.priorityProcessor()

	lh.running = true
	return nil
}

// Stop gracefully shuts down logger integration.
func (lh *LoggerHooks) Stop() error {
	lh.runningMu.Lock()
	if !lh.running {
		lh.runningMu.Unlock()
		return nil
	}
	lh.running = false
	lh.runningMu.Unlock()

	// Flush remaining logs.
	_ = lh.Flush()

	close(lh.stopChan)

	// Wait for workers with timeout.
	done := make(chan struct{})
	go func() {
		lh.wg.Wait()
		close(done)
	}()

	select {
	case <-done:
		// Workers finished cleanly.
	case <-time.After(30 * time.Second):
		// Timeout waiting for workers.
	}

	return nil
}

// logProcessor processes standard log entries with batching.
func (lh *LoggerHooks) logProcessor() {
	defer lh.wg.Done()

	batch := make([]*LogEntry, 0, lh.config.BatchSize)
	flushTimer := time.NewTimer(lh.config.FlushInterval)
	defer flushTimer.Stop()

	for {
		select {
		case <-lh.stopChan:
			// Send remaining batch.
			if len(batch) > 0 {
				lh.sendBatch(batch)
			}
			return

		case entry := <-lh.logQueue:
			if entry != nil {
				batch = append(batch, entry)
				if len(batch) >= lh.config.BatchSize {
					lh.sendBatch(batch)
					batch = make([]*LogEntry, 0, lh.config.BatchSize)
					flushTimer.Reset(lh.config.FlushInterval)
				}
			}

		case <-flushTimer.C:
			// Flush partial batch.
			if len(batch) > 0 {
				lh.sendBatch(batch)
				batch = make([]*LogEntry, 0, lh.config.BatchSize)
			}
			flushTimer.Reset(lh.config.FlushInterval)
		}
	}
}

// priorityProcessor processes high-priority logs immediately.
func (lh *LoggerHooks) priorityProcessor() {
	defer lh.wg.Done()

	for {
		select {
		case <-lh.stopChan:
			// Drain remaining priority logs.
			for {
				select {
				case entry := <-lh.priorityQueue:
					if entry != nil {
						lh.sendEntry(entry)
					}
				default:
					return
				}
			}

		case entry := <-lh.priorityQueue:
			if entry != nil {
				lh.sendEntry(entry)
			}
		}
	}
}

// sendBatch sends a batch of log entries.
func (lh *LoggerHooks) sendBatch(batch []*LogEntry) {
	if len(batch) == 0 {
		return
	}

	// In production, this would call Network Logger via gRPC:
	//
	// ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	// defer cancel()
	//
	// entries := make([]*pb.LogEntry, len(batch))
	// for i, e := range batch {
	//     entries[i] = convertToProto(e)
	// }
	//
	// retries := 0
	// for retries < 3 {
	//     _, err := lh.loggerClient.BatchLogEntries(ctx, &pb.BatchLogEntriesRequest{
	//         Entries: entries,
	//     })
	//     if err == nil {
	//         break
	//     }
	//     retries++
	//     time.Sleep(time.Duration(retries) * time.Second)
	// }

	atomic.AddUint64(&lh.logsSent, uint64(len(batch)))
	atomic.AddUint64(&lh.batchesSent, 1)
}

// sendEntry sends a single log entry immediately.
func (lh *LoggerHooks) sendEntry(entry *LogEntry) {
	_ = entry // Used in production gRPC call.
	// In production, this would call Network Logger via gRPC:
	//
	// ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	// defer cancel()
	//
	// _, err := lh.loggerClient.LogEntry(ctx, convertToProto(entry))
	// if err != nil {
	//     atomic.AddUint64(&lh.sendErrors, 1)
	//     return
	// }

	atomic.AddUint64(&lh.priorityLogsSent, 1)
	atomic.AddUint64(&lh.logsSent, 1)
}

// =============================================================================
// Logging Hooks
// =============================================================================

// LogNewConnection logs a new connection.
func (lh *LoggerHooks) LogNewConnection(
	fiveTuple *FiveTuple,
	wanInterface string,
	natMapping *NATMapping,
	qosPriority string,
) {
	if !lh.config.Enabled {
		return
	}

	entry := NewLogEntry(LogEventNewConnection, SeverityInfo)
	entry.Data["source_ip"] = fiveTuple.SrcIP.String()
	entry.Data["source_port"] = fiveTuple.SrcPort
	entry.Data["dest_ip"] = fiveTuple.DstIP.String()
	entry.Data["dest_port"] = fiveTuple.DstPort
	entry.Data["protocol"] = fiveTuple.Protocol
	entry.Data["wan_interface"] = wanInterface
	entry.Data["qos_priority"] = qosPriority

	if natMapping != nil {
		entry.Data["nat_wan_ip"] = natMapping.TranslatedIP.String()
		entry.Data["nat_wan_port"] = natMapping.TranslatedPort
	}

	lh.enqueue(entry)
}

// LogWANFailover logs a WAN failover event.
func (lh *LoggerHooks) LogWANFailover(
	failedWan string,
	activeWan string,
	failoverType FailoverType,
	reason string,
	affectedSessions int,
	executionTimeMs int64,
) {
	if !lh.config.Enabled {
		return
	}

	entry := NewLogEntry(LogEventWANFailover, SeverityCritical)
	entry.Priority = true
	entry.Data["failed_wan"] = failedWan
	entry.Data["active_wan"] = activeWan
	entry.Data["failover_type"] = string(failoverType)
	entry.Data["reason"] = reason
	entry.Data["affected_sessions"] = affectedSessions
	entry.Data["execution_time_ms"] = executionTimeMs

	lh.enqueuePriority(entry)
}

// LogInterfaceStateChange logs an interface state change.
func (lh *LoggerHooks) LogInterfaceStateChange(
	interfaceID string,
	eventType InterfaceEventType,
	oldState string,
	newState string,
	details map[string]interface{},
) {
	if !lh.config.Enabled {
		return
	}

	severity := SeverityInfo
	priority := false

	// High priority for DOWN/REMOVED events.
	switch eventType {
	case InterfaceEventDown, InterfaceEventHotplugRemoved, InterfaceEventCableDisconnected:
		severity = SeverityWarning
		priority = true
	}

	entry := NewLogEntry(LogEventInterfaceStateChange, severity)
	entry.Priority = priority
	entry.Data["interface_id"] = interfaceID
	entry.Data["change_type"] = string(eventType)
	entry.Data["old_state"] = oldState
	entry.Data["new_state"] = newState

	for k, v := range details {
		entry.Data[k] = v
	}

	if priority {
		lh.enqueuePriority(entry)
	} else {
		lh.enqueue(entry)
	}
}

// LogNATMappingCreated logs a new NAT mapping.
func (lh *LoggerHooks) LogNATMappingCreated(
	lanIP net.IP,
	lanPort uint16,
	wanIP net.IP,
	wanPort uint16,
	protocol uint8,
	externalIP net.IP,
	externalPort uint16,
) {
	if !lh.config.Enabled {
		return
	}

	entry := NewLogEntry(LogEventNATMappingCreated, SeverityInfo)
	entry.Data["lan_endpoint"] = fmt.Sprintf("%s:%d", lanIP.String(), lanPort)
	entry.Data["wan_endpoint"] = fmt.Sprintf("%s:%d", wanIP.String(), wanPort)
	entry.Data["external_endpoint"] = fmt.Sprintf("%s:%d", externalIP.String(), externalPort)
	entry.Data["protocol"] = protocol

	lh.enqueue(entry)
}

// LogNATMappingDeleted logs a deleted NAT mapping.
func (lh *LoggerHooks) LogNATMappingDeleted(
	lanIP net.IP,
	lanPort uint16,
	wanIP net.IP,
	wanPort uint16,
	protocol uint8,
	reason string,
) {
	if !lh.config.Enabled {
		return
	}

	entry := NewLogEntry(LogEventNATMappingDeleted, SeverityInfo)
	entry.Data["lan_endpoint"] = fmt.Sprintf("%s:%d", lanIP.String(), lanPort)
	entry.Data["wan_endpoint"] = fmt.Sprintf("%s:%d", wanIP.String(), wanPort)
	entry.Data["protocol"] = protocol
	entry.Data["reason"] = reason

	lh.enqueue(entry)
}

// LogFirewallBlock logs a firewall block event.
func (lh *LoggerHooks) LogFirewallBlock(
	fiveTuple *FiveTuple,
	direction PacketDirection,
	reason string,
	packetSample []byte,
) {
	if !lh.config.Enabled {
		return
	}

	entry := NewLogEntry(LogEventFirewallBlock, SeverityWarning)
	entry.Priority = true
	entry.Data["source_ip"] = fiveTuple.SrcIP.String()
	entry.Data["source_port"] = fiveTuple.SrcPort
	entry.Data["dest_ip"] = fiveTuple.DstIP.String()
	entry.Data["dest_port"] = fiveTuple.DstPort
	entry.Data["protocol"] = fiveTuple.Protocol
	entry.Data["direction"] = direction.String()
	entry.Data["reason"] = reason

	if lh.config.IncludePacketSamples && len(packetSample) > 0 {
		sampleSize := len(packetSample)
		if sampleSize > 128 { // Use 128 for firewall blocks.
			sampleSize = 128
		}
		entry.Data["packet_sample"] = hex.EncodeToString(packetSample[:sampleSize])
	}

	lh.enqueuePriority(entry)
}

// LogThreatDetected logs a threat detection event.
func (lh *LoggerHooks) LogThreatDetected(
	fiveTuple *FiveTuple,
	threatName string,
	cveID string,
	mitreAttack string,
	severity string,
	action ThreatAction,
	packetSample []byte,
) {
	if !lh.config.Enabled {
		return
	}

	logSeverity := SeverityWarning
	if action == ThreatActionBlock {
		logSeverity = SeverityCritical
	}

	entry := NewLogEntry(LogEventThreatDetected, logSeverity)
	entry.Priority = true
	entry.Data["source_ip"] = fiveTuple.SrcIP.String()
	entry.Data["dest_ip"] = fiveTuple.DstIP.String()
	entry.Data["source_port"] = fiveTuple.SrcPort
	entry.Data["dest_port"] = fiveTuple.DstPort
	entry.Data["protocol"] = fiveTuple.Protocol
	entry.Data["threat_name"] = threatName
	entry.Data["cve_id"] = cveID
	entry.Data["mitre_attack"] = mitreAttack
	entry.Data["threat_severity"] = severity
	entry.Data["action"] = string(action)

	if lh.config.IncludePacketSamples && len(packetSample) > 0 {
		sampleSize := len(packetSample)
		if sampleSize > lh.config.MaxPacketSampleSize {
			sampleSize = lh.config.MaxPacketSampleSize
		}
		entry.Data["packet_sample"] = hex.EncodeToString(packetSample[:sampleSize])
	}

	lh.enqueuePriority(entry)
}

// =============================================================================
// Queue Management
// =============================================================================

// enqueue adds a log entry to the standard queue.
func (lh *LoggerHooks) enqueue(entry *LogEntry) {
	select {
	case lh.logQueue <- entry:
		// Enqueued successfully.
	default:
		// Queue full, drop.
		atomic.AddUint64(&lh.logsDropped, 1)
	}
}

// enqueuePriority adds a log entry to the priority queue.
func (lh *LoggerHooks) enqueuePriority(entry *LogEntry) {
	select {
	case lh.priorityQueue <- entry:
		// Enqueued successfully.
	default:
		// Priority queue full, try standard queue.
		select {
		case lh.logQueue <- entry:
		default:
			atomic.AddUint64(&lh.logsDropped, 1)
		}
	}
}

// Flush manually flushes all pending log entries.
func (lh *LoggerHooks) Flush() error {
	// Drain priority queue first.
	for {
		select {
		case entry := <-lh.priorityQueue:
			if entry != nil {
				lh.sendEntry(entry)
			}
		default:
			goto drainStandard
		}
	}

drainStandard:
	// Batch drain standard queue.
	batch := make([]*LogEntry, 0, lh.config.BatchSize)
	timeout := time.After(30 * time.Second)

	for {
		select {
		case entry := <-lh.logQueue:
			if entry != nil {
				batch = append(batch, entry)
				if len(batch) >= lh.config.BatchSize {
					lh.sendBatch(batch)
					batch = make([]*LogEntry, 0, lh.config.BatchSize)
				}
			}
		case <-timeout:
			// Timeout, send remaining.
			if len(batch) > 0 {
				lh.sendBatch(batch)
			}
			return nil
		default:
			// Queue empty.
			if len(batch) > 0 {
				lh.sendBatch(batch)
			}
			return nil
		}
	}
}

// =============================================================================
// Statistics
// =============================================================================

// LoggerStats contains logger statistics.
type LoggerStats struct {
	TotalLogsSent       uint64  `json:"total_logs_sent"`
	CurrentQueueDepth   int     `json:"current_queue_depth"`
	PriorityQueueDepth  int     `json:"priority_queue_depth"`
	DroppedLogCount     uint64  `json:"dropped_log_count"`
	BatchesSent         uint64  `json:"batches_sent"`
	AvgBatchSize        float64 `json:"avg_batch_size"`
	PriorityLogsSent    uint64  `json:"priority_logs_sent"`
	SendErrors          uint64  `json:"send_errors"`
	LoggerServiceStatus string  `json:"logger_service_status"`
}

// GetLoggerStats returns logger statistics.
func (lh *LoggerHooks) GetLoggerStats() *LoggerStats {
	logsSent := atomic.LoadUint64(&lh.logsSent)
	batchesSent := atomic.LoadUint64(&lh.batchesSent)

	var avgBatchSize float64
	if batchesSent > 0 {
		// Approximate, doesn't account for priority logs.
		avgBatchSize = float64(logsSent-atomic.LoadUint64(&lh.priorityLogsSent)) / float64(batchesSent)
	}

	status := "UP"
	if !lh.config.Enabled {
		status = "DISABLED"
	}

	return &LoggerStats{
		TotalLogsSent:       logsSent,
		CurrentQueueDepth:   len(lh.logQueue),
		PriorityQueueDepth:  len(lh.priorityQueue),
		DroppedLogCount:     atomic.LoadUint64(&lh.logsDropped),
		BatchesSent:         batchesSent,
		AvgBatchSize:        avgBatchSize,
		PriorityLogsSent:    atomic.LoadUint64(&lh.priorityLogsSent),
		SendErrors:          atomic.LoadUint64(&lh.sendErrors),
		LoggerServiceStatus: status,
	}
}

// =============================================================================
// Health Check
// =============================================================================

// HealthCheck verifies logger integration is operational.
func (lh *LoggerHooks) HealthCheck() error {
	if !lh.config.Enabled {
		return nil
	}

	lh.runningMu.Lock()
	running := lh.running
	lh.runningMu.Unlock()

	if !running {
		return errors.New("logger hooks not running")
	}

	// Check queues not full.
	queueUtil := float64(len(lh.logQueue)) / float64(cap(lh.logQueue))
	if queueUtil > 0.9 {
		return errors.New("log queue near capacity")
	}

	return nil
}

// IsEnabled returns whether logger integration is enabled.
func (lh *LoggerHooks) IsEnabled() bool {
	return lh.config.Enabled
}

// GetConfig returns the current configuration.
func (lh *LoggerHooks) GetConfig() *LoggerHooksConfig {
	return lh.config
}
