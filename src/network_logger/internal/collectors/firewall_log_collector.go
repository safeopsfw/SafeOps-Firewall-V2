package collectors

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net"
	"os"
	"sync"
	"time"

	"github.com/safeops/network_logger/pkg/models"
)

// FirewallFlowLog represents a flow-based firewall log entry (one per connection)
type FirewallFlowLog struct {
	TimestampIST    string          `json:"timestamp_ist"`      // Flow start time
	FlowEnd         string          `json:"flow_end,omitempty"` // Flow end time
	FlowID          string          `json:"flow_id"`
	EventID         string          `json:"event_id"`
	SrcIP           string          `json:"src_ip"`
	DstIP           string          `json:"dst_ip"`
	SrcPort         uint16          `json:"src_port,omitempty"`
	DstPort         uint16          `json:"dst_port,omitempty"`
	Protocol        string          `json:"protocol"`
	Direction       string          `json:"direction"`
	Action          string          `json:"action"` // allow, block, drop
	Reason          string          `json:"reason"`
	PacketsToServer int64           `json:"packets_toserver"`
	PacketsToClient int64           `json:"packets_toclient"`
	BytesToServer   int64           `json:"bytes_toserver"`
	BytesToClient   int64           `json:"bytes_toclient"`
	FlowDuration    float64         `json:"flow_duration,omitempty"` // Seconds
	TCPFlags        string          `json:"tcp_flags,omitempty"`     // Observed flags
	TLSSni          string          `json:"tls_sni,omitempty"`
	SrcGeo          *models.GeoInfo `json:"src_geo,omitempty"`
	DstGeo          *models.GeoInfo `json:"dst_geo,omitempty"`
	FlowState       string          `json:"flow_state"` // new, established, closed, blocked
}

// FWFlowState tracks an active firewall connection (renamed to avoid conflict with biflow)
type FWFlowState struct {
	FlowID          string
	SrcIP           string
	DstIP           string
	SrcPort         uint16
	DstPort         uint16
	Protocol        string
	Direction       string
	FirstSeen       time.Time
	LastSeen        time.Time
	PacketsToServer int64
	PacketsToClient int64
	BytesToServer   int64
	BytesToClient   int64
	TCPFlagsSeen    map[string]bool
	TLSSni          string
	SrcGeo          *models.GeoInfo
	DstGeo          *models.GeoInfo
	State           string // new, established, closed
}

// FirewallCollector processes packets into flow-based firewall logs
type FirewallCollector struct {
	logPath       string
	logQueue      chan *FirewallFlowLog
	mu            sync.Mutex
	file          *os.File
	writer        *bufio.Writer
	logsWritten   int64
	flowsDropped  int64
	cycleInterval time.Duration

	// Active flow tracking
	activeFlows map[string]*FWFlowState
	flowsMu     sync.RWMutex
	flowTimeout time.Duration // Idle timeout before logging flow
}

const (
	maxActiveFlows = 100000 // Max concurrent flows to track
)

// NewFirewallCollector creates a new flow-based firewall collector
func NewFirewallCollector(logPath string, cycleInterval time.Duration) *FirewallCollector {
	return &FirewallCollector{
		logPath:       logPath,
		logQueue:      make(chan *FirewallFlowLog, 5000),
		cycleInterval: cycleInterval,
		activeFlows:   make(map[string]*FWFlowState),
		flowTimeout:   60 * time.Second, // Log flows idle for 60s
	}
}

// Start begins the firewall collector
func (c *FirewallCollector) Start(ctx context.Context) {
	c.openFile()
	go c.logWriter(ctx)
	go c.cycleLoop(ctx)
	go c.flowTimeoutChecker(ctx)
}

// Process processes a packet and updates flow state
func (c *FirewallCollector) Process(pkt *models.PacketLog) {
	if pkt.Layers.Network == nil {
		return
	}

	flowKey := c.generateFlowKey(pkt)
	isBlocked := c.isBlockedPacket(pkt)

	// Blocked packets are logged immediately
	if isBlocked {
		c.logBlockedPacket(pkt)
		return
	}

	// Update or create flow state
	c.updateFlowState(flowKey, pkt)
}

// generateFlowKey creates a unique bidirectional flow key
func (c *FirewallCollector) generateFlowKey(pkt *models.PacketLog) string {
	srcIP := pkt.Layers.Network.SrcIP
	dstIP := pkt.Layers.Network.DstIP
	var srcPort, dstPort uint16
	proto := "other"

	if pkt.Layers.Transport != nil {
		srcPort = pkt.Layers.Transport.SrcPort
		dstPort = pkt.Layers.Transport.DstPort
		switch pkt.Layers.Network.Protocol {
		case 6:
			proto = "TCP"
		case 17:
			proto = "UDP"
		}
	} else if pkt.Layers.Network.Protocol == 1 {
		proto = "ICMP"
	}

	// Normalize: smaller IP first for consistent bidirectional matching
	// This matches BiflowCollector's normalization for cross-log correlation
	if srcIP > dstIP || (srcIP == dstIP && srcPort > dstPort) {
		srcIP, dstIP = dstIP, srcIP
		srcPort, dstPort = dstPort, srcPort
	}

	return fmt.Sprintf("%s:%d-%s:%d/%s", srcIP, srcPort, dstIP, dstPort, proto)
}

// isBlockedPacket checks if this packet should be blocked
func (c *FirewallCollector) isBlockedPacket(pkt *models.PacketLog) bool {
	// RST packets indicate connection reset/drop
	if pkt.Layers.Transport != nil && pkt.Layers.Transport.TCPFlags != nil {
		if pkt.Layers.Transport.TCPFlags.RST {
			return true
		}
	}
	return false
}

// logBlockedPacket immediately logs blocked/dropped packets
func (c *FirewallCollector) logBlockedPacket(pkt *models.PacketLog) {
	// Get packet size from IP header
	var pktSize int64 = 0
	if pkt.Layers.Network != nil {
		pktSize = int64(pkt.Layers.Network.TotalLength)
	}

	fwLog := &FirewallFlowLog{
		TimestampIST:    pkt.Timestamp.ISO8601,
		FlowEnd:         pkt.Timestamp.ISO8601,
		FlowID:          c.generateFlowKey(pkt),
		EventID:         pkt.PacketID,
		SrcIP:           pkt.Layers.Network.SrcIP,
		DstIP:           pkt.Layers.Network.DstIP,
		Protocol:        c.getProtocolName(pkt),
		Direction:       c.classifyDirection(pkt.Layers.Network.SrcIP, pkt.Layers.Network.DstIP),
		Action:          "drop",
		Reason:          "RST flag",
		PacketsToServer: 1,
		BytesToServer:   pktSize,
		SrcGeo:          pkt.SrcGeo,
		DstGeo:          pkt.DstGeo,
		FlowState:       "blocked",
	}

	if pkt.Layers.Transport != nil {
		fwLog.SrcPort = pkt.Layers.Transport.SrcPort
		fwLog.DstPort = pkt.Layers.Transport.DstPort
		if pkt.Layers.Transport.TCPFlags != nil {
			fwLog.TCPFlags = formatTCPFlags(pkt.Layers.Transport.TCPFlags)
		}
	}

	c.queueLog(fwLog)
}

// updateFlowState updates or creates flow tracking state
func (c *FirewallCollector) updateFlowState(flowKey string, pkt *models.PacketLog) {
	c.flowsMu.Lock()
	defer c.flowsMu.Unlock()

	now := time.Now()
	flow, exists := c.activeFlows[flowKey]

	// Get packet size from IP header
	var pktSize int64 = 0
	if pkt.Layers.Network != nil {
		pktSize = int64(pkt.Layers.Network.TotalLength)
	}

	// Check for TCP control flags
	isSYN := false
	isFIN := false
	if pkt.Layers.Transport != nil && pkt.Layers.Transport.TCPFlags != nil {
		flags := pkt.Layers.Transport.TCPFlags
		isSYN = flags.SYN && !flags.ACK
		isFIN = flags.FIN
	}

	if !exists {
		// New flow
		flow = &FWFlowState{
			FlowID:       flowKey,
			SrcIP:        pkt.Layers.Network.SrcIP,
			DstIP:        pkt.Layers.Network.DstIP,
			Protocol:     c.getProtocolName(pkt),
			Direction:    c.classifyDirection(pkt.Layers.Network.SrcIP, pkt.Layers.Network.DstIP),
			FirstSeen:    now,
			LastSeen:     now,
			TCPFlagsSeen: make(map[string]bool),
			SrcGeo:       pkt.SrcGeo,
			DstGeo:       pkt.DstGeo,
			State:        "new",
		}

		if pkt.Layers.Transport != nil {
			flow.SrcPort = pkt.Layers.Transport.SrcPort
			flow.DstPort = pkt.Layers.Transport.DstPort
		}

		// Check if cache is too large
		if len(c.activeFlows) >= maxActiveFlows {
			c.evictOldestFlows()
		}

		c.activeFlows[flowKey] = flow
	}

	// Update flow stats
	flow.LastSeen = now

	// Track direction for byte/packet counts
	isForward := pkt.Layers.Network.SrcIP == flow.SrcIP
	if isForward {
		flow.PacketsToServer++
		flow.BytesToServer += pktSize
	} else {
		flow.PacketsToClient++
		flow.BytesToClient += pktSize
	}

	// Track TCP flags
	if pkt.Layers.Transport != nil && pkt.Layers.Transport.TCPFlags != nil {
		flags := pkt.Layers.Transport.TCPFlags
		if flags.SYN {
			flow.TCPFlagsSeen["SYN"] = true
		}
		if flags.ACK {
			flow.TCPFlagsSeen["ACK"] = true
		}
		if flags.FIN {
			flow.TCPFlagsSeen["FIN"] = true
		}
		if flags.RST {
			flow.TCPFlagsSeen["RST"] = true
		}
		if flags.PSH {
			flow.TCPFlagsSeen["PSH"] = true
		}
	}

	// Extract TLS SNI if available
	if pkt.ParsedApplication.TLS != nil && pkt.ParsedApplication.TLS.ClientHello != nil {
		if pkt.ParsedApplication.TLS.ClientHello.SNI != "" {
			flow.TLSSni = pkt.ParsedApplication.TLS.ClientHello.SNI
		}
	}

	// Update state
	if isSYN && flow.State == "new" {
		flow.State = "new"
	} else if flow.PacketsToClient > 0 {
		flow.State = "established"
	}

	// Log connection end on FIN
	if isFIN {
		flow.State = "closed"
		c.logAndRemoveFlow(flowKey, flow, "FIN")
	}
}

// logAndRemoveFlow logs the flow and removes it from tracking
func (c *FirewallCollector) logAndRemoveFlow(flowKey string, flow *FWFlowState, reason string) {
	now := time.Now()
	duration := now.Sub(flow.FirstSeen).Seconds()

	fwLog := &FirewallFlowLog{
		TimestampIST:    flow.FirstSeen.Format(time.RFC3339),
		FlowEnd:         now.Format(time.RFC3339),
		FlowID:          flow.FlowID,
		EventID:         fmt.Sprintf("fw_%s", flowKey[:minInt(20, len(flowKey))]),
		SrcIP:           flow.SrcIP,
		DstIP:           flow.DstIP,
		SrcPort:         flow.SrcPort,
		DstPort:         flow.DstPort,
		Protocol:        flow.Protocol,
		Direction:       flow.Direction,
		Action:          "allow",
		Reason:          reason,
		PacketsToServer: flow.PacketsToServer,
		PacketsToClient: flow.PacketsToClient,
		BytesToServer:   flow.BytesToServer,
		BytesToClient:   flow.BytesToClient,
		FlowDuration:    duration,
		TCPFlags:        c.formatFlagsSeen(flow.TCPFlagsSeen),
		TLSSni:          flow.TLSSni,
		SrcGeo:          flow.SrcGeo,
		DstGeo:          flow.DstGeo,
		FlowState:       flow.State,
	}

	c.queueLog(fwLog)
	delete(c.activeFlows, flowKey)
}

// formatFlagsSeen converts flag map to string
func (c *FirewallCollector) formatFlagsSeen(flags map[string]bool) string {
	result := ""
	for flag := range flags {
		if result != "" {
			result += ","
		}
		result += flag
	}
	return result
}

// flowTimeoutChecker periodically checks for idle flows and logs them
func (c *FirewallCollector) flowTimeoutChecker(ctx context.Context) {
	ticker := time.NewTicker(10 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			// Log all remaining flows on shutdown
			c.flushAllFlows()
			return
		case <-ticker.C:
			c.checkFlowTimeouts()
		}
	}
}

// checkFlowTimeouts logs flows that have been idle
func (c *FirewallCollector) checkFlowTimeouts() {
	c.flowsMu.Lock()
	defer c.flowsMu.Unlock()

	now := time.Now()
	toRemove := []string{}

	for flowKey, flow := range c.activeFlows {
		if now.Sub(flow.LastSeen) > c.flowTimeout {
			toRemove = append(toRemove, flowKey)
		}
	}

	for _, flowKey := range toRemove {
		flow := c.activeFlows[flowKey]
		c.logAndRemoveFlowLocked(flowKey, flow, "timeout")
	}
}

// logAndRemoveFlowLocked logs flow (caller must hold lock)
func (c *FirewallCollector) logAndRemoveFlowLocked(flowKey string, flow *FWFlowState, reason string) {
	now := time.Now()
	duration := now.Sub(flow.FirstSeen).Seconds()

	fwLog := &FirewallFlowLog{
		TimestampIST:    flow.FirstSeen.Format(time.RFC3339),
		FlowEnd:         now.Format(time.RFC3339),
		FlowID:          flow.FlowID,
		EventID:         fmt.Sprintf("fw_%s", flowKey[:minInt(20, len(flowKey))]),
		SrcIP:           flow.SrcIP,
		DstIP:           flow.DstIP,
		SrcPort:         flow.SrcPort,
		DstPort:         flow.DstPort,
		Protocol:        flow.Protocol,
		Direction:       flow.Direction,
		Action:          "allow",
		Reason:          reason,
		PacketsToServer: flow.PacketsToServer,
		PacketsToClient: flow.PacketsToClient,
		BytesToServer:   flow.BytesToServer,
		BytesToClient:   flow.BytesToClient,
		FlowDuration:    duration,
		TCPFlags:        c.formatFlagsSeen(flow.TCPFlagsSeen),
		TLSSni:          flow.TLSSni,
		SrcGeo:          flow.SrcGeo,
		DstGeo:          flow.DstGeo,
		FlowState:       flow.State,
	}

	c.queueLog(fwLog)
	delete(c.activeFlows, flowKey)
}

// flushAllFlows logs all active flows on shutdown
func (c *FirewallCollector) flushAllFlows() {
	c.flowsMu.Lock()
	defer c.flowsMu.Unlock()

	for flowKey, flow := range c.activeFlows {
		c.logAndRemoveFlowLocked(flowKey, flow, "shutdown")
	}
}

// evictOldestFlows removes oldest flows when cache is full
func (c *FirewallCollector) evictOldestFlows() {
	// Remove 10% of flows (oldest first)
	toRemove := len(c.activeFlows) / 10
	removed := 0

	for flowKey, flow := range c.activeFlows {
		c.logAndRemoveFlowLocked(flowKey, flow, "eviction")
		removed++
		if removed >= toRemove {
			break
		}
	}
}

// queueLog adds a log to the write queue
func (c *FirewallCollector) queueLog(fwLog *FirewallFlowLog) {
	select {
	case c.logQueue <- fwLog:
	default:
		c.mu.Lock()
		c.flowsDropped++
		c.mu.Unlock()
	}
}

// getProtocolName returns protocol string from packet
func (c *FirewallCollector) getProtocolName(pkt *models.PacketLog) string {
	if pkt.Layers.Network == nil {
		return "OTHER"
	}
	switch pkt.Layers.Network.Protocol {
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

// classifyDirection classifies traffic direction
func (c *FirewallCollector) classifyDirection(srcIP, dstIP string) string {
	srcPrivate := isPrivateIP(srcIP)
	dstPrivate := isPrivateIP(dstIP)

	if srcPrivate && dstPrivate {
		return "east-west"
	}
	if srcPrivate && !dstPrivate {
		return "outbound"
	}
	if !srcPrivate && dstPrivate {
		return "inbound"
	}
	return "north-south"
}

func (c *FirewallCollector) openFile() error {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.file != nil {
		if c.writer != nil {
			c.writer.Flush()
		}
		c.file.Close()
	}

	file, err := os.OpenFile(c.logPath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0644)
	if err != nil {
		log.Printf("❌ Failed to open firewall log: %v", err)
		return err
	}

	c.file = file
	c.writer = bufio.NewWriter(file)
	c.logsWritten = 0
	return nil
}

func (c *FirewallCollector) logWriter(ctx context.Context) {
	batch := make([]*FirewallFlowLog, 0, 50)
	ticker := time.NewTicker(500 * time.Millisecond)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			if len(batch) > 0 {
				c.writeBatch(batch)
			}
			c.closeFile()
			return
		case fwLog := <-c.logQueue:
			batch = append(batch, fwLog)
			if len(batch) >= 50 {
				c.writeBatch(batch)
				batch = make([]*FirewallFlowLog, 0, 50)
			}
		case <-ticker.C:
			if len(batch) > 0 {
				c.writeBatch(batch)
				batch = make([]*FirewallFlowLog, 0, 50)
			}
		}
	}
}

func (c *FirewallCollector) writeBatch(batch []*FirewallFlowLog) {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.writer == nil {
		return
	}

	for _, fwLog := range batch {
		data, err := json.Marshal(fwLog)
		if err != nil {
			continue
		}
		c.writer.Write(data)
		c.writer.WriteByte('\n')
		c.logsWritten++
	}
	c.writer.Flush()
}

func (c *FirewallCollector) cycleLoop(ctx context.Context) {
	ticker := time.NewTicker(c.cycleInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			c.mu.Lock()
			logsWritten := c.logsWritten
			flowsDropped := c.flowsDropped
			c.flowsDropped = 0
			c.mu.Unlock()

			c.flowsMu.RLock()
			activeFlows := len(c.activeFlows)
			c.flowsMu.RUnlock()

			log.Printf("🔄 Firewall log rotated: %d flows logged, %d dropped, %d active", logsWritten, flowsDropped, activeFlows)
			c.openFile()
		}
	}
}

func (c *FirewallCollector) closeFile() {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.writer != nil {
		c.writer.Flush()
		c.writer = nil
	}
	if c.file != nil {
		c.file.Close()
		c.file = nil
	}
}

// GetStats returns collector statistics
func (c *FirewallCollector) GetStats() map[string]interface{} {
	c.mu.Lock()
	logsWritten := c.logsWritten
	flowsDropped := c.flowsDropped
	queueSize := len(c.logQueue)
	c.mu.Unlock()

	c.flowsMu.RLock()
	activeFlows := len(c.activeFlows)
	c.flowsMu.RUnlock()

	return map[string]interface{}{
		"logs_written":  logsWritten,
		"flows_dropped": flowsDropped,
		"queue_size":    queueSize,
		"active_flows":  activeFlows,
	}
}

// minInt helper function
func minInt(a, b int) int {
	if a < b {
		return a
	}
	return b
}

func isPrivateIP(ipStr string) bool {
	ip := net.ParseIP(ipStr)
	if ip == nil {
		return false
	}
	privateRanges := []string{"10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "127.0.0.0/8", "169.254.0.0/16"}
	for _, cidr := range privateRanges {
		_, network, _ := net.ParseCIDR(cidr)
		if network.Contains(ip) {
			return true
		}
	}
	return false
}

func formatTCPFlags(f *models.TCPFlags) string {
	if f == nil {
		return ""
	}
	var flags string
	if f.SYN {
		flags += "S"
	}
	if f.ACK {
		flags += "A"
	}
	if f.FIN {
		flags += "F"
	}
	if f.RST {
		flags += "R"
	}
	if f.PSH {
		flags += "P"
	}
	if f.URG {
		flags += "U"
	}
	return flags
}
