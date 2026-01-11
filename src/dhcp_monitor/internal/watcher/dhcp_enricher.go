//go:build windows
// +build windows

// Package watcher provides DHCP Event Log monitoring for hostname enrichment
package watcher

import (
	"context"
	"encoding/xml"
	"fmt"
	"log"
	"net"
	"os/exec"
	"regexp"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// =============================================================================
// DHCP EVENT ID CONSTANTS
// =============================================================================

const (
	EventIDLeaseAssigned = 10 // DHCP lease granted
	EventIDLeaseRenewed  = 11 // Existing lease renewed
	EventIDLeaseReleased = 12 // Client released lease
	EventIDLeaseExpired  = 13 // Lease expiration
	EventIDLeaseDeleted  = 14 // Lease manually deleted
)

// Event Log channel names
const (
	DHCPServerChannel      = "Microsoft-Windows-Dhcp-Server/Operational"
	DHCPServerAdminChannel = "Microsoft-Windows-Dhcp-Server/Admin"
)

// =============================================================================
// DHCP EVENT DATA STRUCT
// =============================================================================

// DHCPEventData represents a parsed DHCP event log entry
type DHCPEventData struct {
	EventID     int       `json:"event_id"`
	Timestamp   time.Time `json:"timestamp"`
	IPAddress   net.IP    `json:"ip_address"`
	MACAddress  string    `json:"mac_address"`
	Hostname    string    `json:"hostname"`
	LeaseStart  time.Time `json:"lease_start"`
	LeaseExpiry time.Time `json:"lease_expiry"`
	ScopeID     string    `json:"scope_id"`
	RecordID    string    `json:"record_id"`
}

// XML structures for Event Log parsing
type eventXML struct {
	XMLName xml.Name  `xml:"Event"`
	System  systemXML `xml:"System"`
	Data    []dataXML `xml:"EventData>Data"`
}

type systemXML struct {
	EventID       int    `xml:"EventID"`
	TimeCreated   string `xml:"TimeCreated>SystemTime,attr"`
	EventRecordID int64  `xml:"EventRecordID"`
}

type dataXML struct {
	Name  string `xml:"Name,attr"`
	Value string `xml:",chardata"`
}

// =============================================================================
// ENRICHER STATISTICS
// =============================================================================

// EnricherStatistics contains runtime metrics
type EnricherStatistics struct {
	TotalEventsProcessed int64     `json:"total_events_processed"`
	HostnamesEnriched    int64     `json:"hostnames_enriched"`
	LeasesTracked        int64     `json:"leases_tracked"`
	LastPollTime         time.Time `json:"last_poll_time"`
	ProcessedCacheSize   int       `json:"processed_cache_size"`
}

// =============================================================================
// DHCP ENRICHER STRUCT
// =============================================================================

// DHCPEnricher monitors DHCP Event Log for hostname extraction
type DHCPEnricher struct {
	eventChannel EventChannel
	pollInterval time.Duration
	lastPollTime time.Time

	ctx    context.Context
	cancel context.CancelFunc
	wg     sync.WaitGroup

	isRunning bool
	mutex     sync.Mutex

	macNormalizer   *regexp.Regexp
	processedEvents map[string]bool
	processMutex    sync.RWMutex

	// Statistics
	totalEvents    int64
	hostnamesFound int64
	leasesTracked  int64
}

// NewDHCPEnricher creates a new DHCP enricher
func NewDHCPEnricher(eventChan EventChannel, pollInterval time.Duration) (*DHCPEnricher, error) {
	if pollInterval < 10*time.Second {
		pollInterval = 30 * time.Second
	}

	// MAC address normalizer regex (removes separators)
	macRegex := regexp.MustCompile(`[^0-9A-Fa-f]`)

	return &DHCPEnricher{
		eventChannel:    eventChan,
		pollInterval:    pollInterval,
		lastPollTime:    time.Now().Add(-pollInterval), // Capture recent events on first poll
		macNormalizer:   macRegex,
		processedEvents: make(map[string]bool),
		isRunning:       false,
	}, nil
}

// =============================================================================
// LIFECYCLE METHODS
// =============================================================================

// Start begins Event Log monitoring
func (e *DHCPEnricher) Start(ctx context.Context) error {
	e.mutex.Lock()
	defer e.mutex.Unlock()

	if e.isRunning {
		return fmt.Errorf("DHCP enricher already running")
	}

	// Check if Event Log is available
	if !e.isEventLogAvailable() {
		log.Println("[DHCP_ENRICHER] Warning: DHCP Server Event Log not available (DHCP Server role not installed)")
		log.Println("[DHCP_ENRICHER] Hostname enrichment will be disabled")
		return nil // Don't fail, just disable enrichment
	}

	e.ctx, e.cancel = context.WithCancel(ctx)

	// Launch polling goroutine
	e.wg.Add(1)
	go e.runEventLogPolling()

	// Launch cache cleanup goroutine
	e.wg.Add(1)
	go e.runCacheCleanup()

	e.isRunning = true
	log.Printf("[DHCP_ENRICHER] Started with poll_interval=%v", e.pollInterval)

	return nil
}

// Stop gracefully shuts down the enricher
func (e *DHCPEnricher) Stop() error {
	e.mutex.Lock()
	defer e.mutex.Unlock()

	if !e.isRunning {
		return nil
	}

	if e.cancel != nil {
		e.cancel()
	}

	// Wait for goroutines
	done := make(chan struct{})
	go func() {
		e.wg.Wait()
		close(done)
	}()

	select {
	case <-done:
		log.Println("[DHCP_ENRICHER] Stopped cleanly")
	case <-time.After(5 * time.Second):
		log.Println("[DHCP_ENRICHER] Warning: shutdown timeout")
	}

	// Clear caches
	e.processMutex.Lock()
	e.processedEvents = make(map[string]bool)
	e.processMutex.Unlock()

	e.isRunning = false
	return nil
}

// IsRunning returns enricher status
func (e *DHCPEnricher) IsRunning() bool {
	e.mutex.Lock()
	defer e.mutex.Unlock()
	return e.isRunning
}

// =============================================================================
// POLLING GOROUTINES
// =============================================================================

// runEventLogPolling periodically queries DHCP Event Log
func (e *DHCPEnricher) runEventLogPolling() {
	defer e.wg.Done()

	log.Printf("[DHCP_ENRICHER] Event Log polling started (interval=%v)", e.pollInterval)

	ticker := time.NewTicker(e.pollInterval)
	defer ticker.Stop()

	for {
		select {
		case <-e.ctx.Done():
			log.Println("[DHCP_ENRICHER] Polling stopped")
			return

		case <-ticker.C:
			e.pollEventLog()
		}
	}
}

// pollEventLog queries DHCP events since last poll
func (e *DHCPEnricher) pollEventLog() {
	e.mutex.Lock()
	since := e.lastPollTime
	e.mutex.Unlock()

	// Build query command using wevtutil
	query := e.buildEventQuery(since)

	// Execute query
	cmd := exec.CommandContext(e.ctx, "wevtutil", "qe", DHCPServerChannel,
		"/q:"+query, "/f:xml", "/rd:true")

	output, err := cmd.Output()
	if err != nil {
		// Event Log may not exist if DHCP Server not installed
		return
	}

	// Parse XML events (may be multiple events concatenated)
	events := e.parseEventLogOutput(string(output))

	for _, dhcpEvent := range events {
		// Check deduplication
		if e.isProcessed(dhcpEvent.RecordID) {
			continue
		}

		// Create and send network event
		networkEvent := e.createNetworkEvent(dhcpEvent)
		if networkEvent != nil {
			e.sendEvent(networkEvent)

			// Update statistics
			atomic.AddInt64(&e.totalEvents, 1)
			if dhcpEvent.Hostname != "" {
				atomic.AddInt64(&e.hostnamesFound, 1)
			}
			if dhcpEvent.EventID == EventIDLeaseRenewed || dhcpEvent.EventID == EventIDLeaseExpired {
				atomic.AddInt64(&e.leasesTracked, 1)
			}
		}

		// Mark as processed
		e.markProcessed(dhcpEvent.RecordID)
	}

	// Update last poll time
	e.mutex.Lock()
	e.lastPollTime = time.Now()
	e.mutex.Unlock()
}

// runCacheCleanup periodically clears processed events cache
func (e *DHCPEnricher) runCacheCleanup() {
	defer e.wg.Done()

	cleanupInterval := 10 * time.Minute
	ticker := time.NewTicker(cleanupInterval)
	defer ticker.Stop()

	for {
		select {
		case <-e.ctx.Done():
			return

		case <-ticker.C:
			e.cleanProcessedCache()
		}
	}
}

// =============================================================================
// EVENT LOG PARSING
// =============================================================================

// buildEventQuery constructs XPath query for DHCP events
func (e *DHCPEnricher) buildEventQuery(since time.Time) string {
	// Format time for XPath
	timeStr := since.UTC().Format("2006-01-02T15:04:05.000Z")

	// XPath query for DHCP lease events since last poll
	return fmt.Sprintf("*[System[TimeCreated[@SystemTime>='%s'] and (EventID=10 or EventID=11 or EventID=12 or EventID=13 or EventID=14)]]", timeStr)
}

// parseEventLogOutput parses wevtutil XML output
func (e *DHCPEnricher) parseEventLogOutput(output string) []*DHCPEventData {
	var events []*DHCPEventData

	// Split by Event tags (events are concatenated)
	eventStrings := strings.Split(output, "</Event>")

	for _, eventStr := range eventStrings {
		eventStr = strings.TrimSpace(eventStr)
		if eventStr == "" || !strings.Contains(eventStr, "<Event") {
			continue
		}
		eventStr += "</Event>"

		event, err := e.parseEventRecord(eventStr)
		if err != nil {
			continue
		}

		events = append(events, event)
	}

	return events
}

// parseEventRecord parses a single Event Log XML record
func (e *DHCPEnricher) parseEventRecord(recordXML string) (*DHCPEventData, error) {
	var evt eventXML
	if err := xml.Unmarshal([]byte(recordXML), &evt); err != nil {
		return nil, fmt.Errorf("XML parse error: %w", err)
	}

	dhcpEvent := &DHCPEventData{
		EventID:  evt.System.EventID,
		RecordID: fmt.Sprintf("%d", evt.System.EventRecordID),
	}

	// Parse timestamp
	if evt.System.TimeCreated != "" {
		if t, err := time.Parse(time.RFC3339, evt.System.TimeCreated); err == nil {
			dhcpEvent.Timestamp = t
		}
	}
	if dhcpEvent.Timestamp.IsZero() {
		dhcpEvent.Timestamp = time.Now()
	}

	// Extract EventData fields
	for _, data := range evt.Data {
		switch data.Name {
		case "IPAddress":
			dhcpEvent.IPAddress = net.ParseIP(data.Value)
		case "MACAddress":
			dhcpEvent.MACAddress = e.normalizeMACAddress(data.Value)
		case "HostName", "Hostname":
			dhcpEvent.Hostname = strings.TrimSpace(data.Value)
		case "ScopeId":
			dhcpEvent.ScopeID = data.Value
		case "LeaseStartTime":
			if t, err := time.Parse(time.RFC3339, data.Value); err == nil {
				dhcpEvent.LeaseStart = t
			}
		case "LeaseExpiryTime":
			if t, err := time.Parse(time.RFC3339, data.Value); err == nil {
				dhcpEvent.LeaseExpiry = t
			}
		}
	}

	return dhcpEvent, nil
}

// normalizeMACAddress converts Windows MAC formats to AA:BB:CC:DD:EE:FF
func (e *DHCPEnricher) normalizeMACAddress(mac string) string {
	// Remove all non-hex characters
	hex := e.macNormalizer.ReplaceAllString(mac, "")
	hex = strings.ToUpper(hex)

	if len(hex) != 12 {
		return mac // Return original if invalid
	}

	// Format with colons
	return fmt.Sprintf("%s:%s:%s:%s:%s:%s",
		hex[0:2], hex[2:4], hex[4:6],
		hex[6:8], hex[8:10], hex[10:12])
}

// =============================================================================
// EVENT CREATION
// =============================================================================

// createNetworkEvent converts DHCPEventData to NetworkEvent
func (e *DHCPEnricher) createNetworkEvent(dhcpEvent *DHCPEventData) *NetworkEvent {
	if dhcpEvent.MACAddress == "" || dhcpEvent.IPAddress == nil {
		return nil
	}

	var eventType string
	switch dhcpEvent.EventID {
	case EventIDLeaseAssigned:
		if dhcpEvent.Hostname != "" {
			eventType = EventTypeHostnameUpdated
		} else {
			eventType = EventTypeDeviceDetected
		}
	case EventIDLeaseRenewed:
		eventType = EventTypeLeaseRenewed
	case EventIDLeaseReleased, EventIDLeaseExpired:
		eventType = EventTypeDeviceOffline
	default:
		return nil
	}

	event := &NetworkEvent{
		EventType:       eventType,
		Timestamp:       dhcpEvent.Timestamp,
		MACAddress:      dhcpEvent.MACAddress,
		IPAddress:       dhcpEvent.IPAddress,
		Hostname:        dhcpEvent.Hostname,
		DetectionSource: DetectionSourceDHCPEvent,
		Metadata:        make(map[string]string),
	}

	// Add lease metadata
	if !dhcpEvent.LeaseStart.IsZero() {
		event.Metadata["lease_start"] = dhcpEvent.LeaseStart.Format(time.RFC3339)
	}
	if !dhcpEvent.LeaseExpiry.IsZero() {
		event.Metadata["lease_expiry"] = dhcpEvent.LeaseExpiry.Format(time.RFC3339)
	}
	if dhcpEvent.ScopeID != "" {
		event.Metadata["scope_id"] = dhcpEvent.ScopeID
	}
	event.Metadata["dhcp_event_id"] = fmt.Sprintf("%d", dhcpEvent.EventID)

	return event
}

// =============================================================================
// HELPER METHODS
// =============================================================================

// isEventLogAvailable checks if DHCP Server Event Log exists
func (e *DHCPEnricher) isEventLogAvailable() bool {
	cmd := exec.Command("wevtutil", "gl", DHCPServerChannel)
	err := cmd.Run()
	return err == nil
}

// isProcessed checks deduplication cache
func (e *DHCPEnricher) isProcessed(recordID string) bool {
	e.processMutex.RLock()
	defer e.processMutex.RUnlock()
	return e.processedEvents[recordID]
}

// markProcessed adds to deduplication cache
func (e *DHCPEnricher) markProcessed(recordID string) {
	e.processMutex.Lock()
	defer e.processMutex.Unlock()
	e.processedEvents[recordID] = true
}

// cleanProcessedCache clears the deduplication cache
func (e *DHCPEnricher) cleanProcessedCache() {
	e.processMutex.Lock()
	defer e.processMutex.Unlock()

	size := len(e.processedEvents)
	e.processedEvents = make(map[string]bool)

	if size > 0 {
		log.Printf("[DHCP_ENRICHER] Cache cleanup: cleared %d entries", size)
	}
}

// sendEvent sends an event with timeout
func (e *DHCPEnricher) sendEvent(event *NetworkEvent) {
	select {
	case e.eventChannel <- event:
		log.Printf("[DHCP_ENRICHER] Event sent: %s MAC=%s Hostname=%s",
			event.EventType, event.MACAddress, event.Hostname)
	case <-time.After(100 * time.Millisecond):
		log.Println("[DHCP_ENRICHER] Warning: event channel send timeout")
	case <-e.ctx.Done():
		return
	}
}

// GetStatistics returns runtime metrics
func (e *DHCPEnricher) GetStatistics() *EnricherStatistics {
	e.mutex.Lock()
	lastPoll := e.lastPollTime
	e.mutex.Unlock()

	e.processMutex.RLock()
	cacheSize := len(e.processedEvents)
	e.processMutex.RUnlock()

	return &EnricherStatistics{
		TotalEventsProcessed: atomic.LoadInt64(&e.totalEvents),
		HostnamesEnriched:    atomic.LoadInt64(&e.hostnamesFound),
		LeasesTracked:        atomic.LoadInt64(&e.leasesTracked),
		LastPollTime:         lastPoll,
		ProcessedCacheSize:   cacheSize,
	}
}
