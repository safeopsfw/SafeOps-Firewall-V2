package collectors

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"sync"
	"time"

	"github.com/safeops/network_logger/pkg/models"
)

// NetflowLog represents a NetFlow log entry
type NetflowLog struct {
	Timestamp       string          `json:"timestamp"`
	FlowID          string          `json:"flow_id"`
	EventID         string          `json:"event_id"`
	SrcIP           string          `json:"src_ip"`
	DstIP           string          `json:"dst_ip"`
	SrcPort         uint16          `json:"src_port,omitempty"`
	DstPort         uint16          `json:"dst_port,omitempty"`
	Protocol        string          `json:"protocol"`
	Direction       string          `json:"direction"`
	Initiator       string          `json:"initiator"`
	PacketsToServer int             `json:"packets_toserver"`
	PacketsToclient int             `json:"packets_toclient"`
	BytesToServer   int64           `json:"bytes_toserver"`
	BytesToClient   int64           `json:"bytes_toclient"`
	FlowDuration    float64         `json:"flow_duration,omitempty"`
	FlowState       string          `json:"flow_state,omitempty"`
	SrcGeo          *models.GeoInfo `json:"src_geo,omitempty"`
	DstGeo          *models.GeoInfo `json:"dst_geo,omitempty"`
}

// FlowState tracks aggregated flow data
type FlowState struct {
	FlowID          string
	SrcIP           string
	DstIP           string
	SrcPort         uint16
	DstPort         uint16
	Protocol        string
	Direction       string
	Initiator       string
	PacketsToServer int
	PacketsToClient int
	BytesToServer   int64
	BytesToClient   int64
	FirstSeen       time.Time
	LastSeen        time.Time
	SrcGeo          *models.GeoInfo
	DstGeo          *models.GeoInfo
}

// BiflowCollector aggregates packets into flows and splits by direction
type BiflowCollector struct {
	eastWestPath   string
	northSouthPath string
	unknownPath    string

	flows  map[string]*FlowState
	flowMu sync.Mutex

	ewFile        *os.File
	nsFile        *os.File
	unknownFile   *os.File
	ewWriter      *bufio.Writer
	nsWriter      *bufio.Writer
	unknownWriter *bufio.Writer
	writerMu      sync.Mutex

	flowTimeout     time.Duration
	cycleInterval   time.Duration
	cleanupInterval time.Duration

	ewLogsWritten      int64
	nsLogsWritten      int64
	unknownLogsWritten int64
}

// NewBiflowCollector creates a new BiFlow collector
func NewBiflowCollector(eastWestPath, northSouthPath, unknownPath string, cycleInterval time.Duration) *BiflowCollector {
	return &BiflowCollector{
		eastWestPath:    eastWestPath,
		northSouthPath:  northSouthPath,
		unknownPath:     unknownPath,
		flows:           make(map[string]*FlowState),
		flowTimeout:     60 * time.Second,
		cycleInterval:   cycleInterval,
		cleanupInterval: 15 * time.Second,
	}
}

// Start begins the BiFlow collector
func (c *BiflowCollector) Start(ctx context.Context) {
	c.openFiles()
	go c.cleanupLoop(ctx)
	go c.cycleLoop(ctx)
}

// Process processes a packet and updates flow state
func (c *BiflowCollector) Process(pkt *models.PacketLog) {
	if pkt.Layers.Network == nil {
		return
	}

	srcIP := pkt.Layers.Network.SrcIP
	dstIP := pkt.Layers.Network.DstIP
	var srcPort, dstPort uint16
	if pkt.Layers.Transport != nil {
		srcPort = pkt.Layers.Transport.SrcPort
		dstPort = pkt.Layers.Transport.DstPort
	}

	proto := "TCP"
	switch pkt.Layers.Network.Protocol {
	case 17:
		proto = "UDP"
	case 1:
		proto = "ICMP"
	}

	// Generate normalized flow key
	flowKey, isForward := c.generateFlowKey(srcIP, dstIP, srcPort, dstPort, proto)

	c.flowMu.Lock()
	defer c.flowMu.Unlock()

	flow, exists := c.flows[flowKey]
	if !exists {
		// Create new flow
		flow = &FlowState{
			FlowID:    flowKey,
			SrcIP:     srcIP,
			DstIP:     dstIP,
			SrcPort:   srcPort,
			DstPort:   dstPort,
			Protocol:  proto,
			Direction: c.classifyDirection(srcIP, dstIP),
			Initiator: c.classifyInitiator(srcIP),
			FirstSeen: time.Now(),
			LastSeen:  time.Now(),
			SrcGeo:    pkt.SrcGeo,
			DstGeo:    pkt.DstGeo,
		}
		c.flows[flowKey] = flow
	}

	// Update flow statistics
	flow.LastSeen = time.Now()
	pktSize := int64(pkt.CaptureInfo.WireLength)
	if isForward {
		flow.PacketsToServer++
		flow.BytesToServer += pktSize
	} else {
		flow.PacketsToClient++
		flow.BytesToClient += pktSize
	}

	// Update geo if not set
	if flow.SrcGeo == nil && pkt.SrcGeo != nil {
		flow.SrcGeo = pkt.SrcGeo
	}
	if flow.DstGeo == nil && pkt.DstGeo != nil {
		flow.DstGeo = pkt.DstGeo
	}
}

// generateFlowKey creates a normalized bidirectional flow key
func (c *BiflowCollector) generateFlowKey(srcIP, dstIP string, srcPort, dstPort uint16, proto string) (string, bool) {
	if srcIP < dstIP || (srcIP == dstIP && srcPort < dstPort) {
		return fmt.Sprintf("%s:%d-%s:%d/%s", srcIP, srcPort, dstIP, dstPort, proto), true
	}
	return fmt.Sprintf("%s:%d-%s:%d/%s", dstIP, dstPort, srcIP, srcPort, proto), false
}

// classifyDirection classifies traffic as east-west or north-south
func (c *BiflowCollector) classifyDirection(srcIP, dstIP string) string {
	srcPrivate := isPrivateIP(srcIP)
	dstPrivate := isPrivateIP(dstIP)

	if srcPrivate && dstPrivate {
		return "east-west"
	}
	return "north-south"
}

// classifyInitiator classifies the initiator
func (c *BiflowCollector) classifyInitiator(srcIP string) string {
	if !isPrivateIP(srcIP) {
		return "internet"
	}
	return "local"
}

// cleanupLoop periodically logs expired flows
func (c *BiflowCollector) cleanupLoop(ctx context.Context) {
	ticker := time.NewTicker(c.cleanupInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			c.flushAllFlows()
			return
		case <-ticker.C:
			c.cleanupExpiredFlows()
		}
	}
}

// cleanupExpiredFlows logs and removes expired flows
func (c *BiflowCollector) cleanupExpiredFlows() {
	now := time.Now()
	expired := make([]*FlowState, 0)

	c.flowMu.Lock()
	for key, flow := range c.flows {
		if now.Sub(flow.LastSeen) > c.flowTimeout {
			expired = append(expired, flow)
			delete(c.flows, key)
		}
	}
	c.flowMu.Unlock()

	// Log expired flows
	for _, flow := range expired {
		c.logFlow(flow)
	}
}

// flushAllFlows logs all remaining flows
func (c *BiflowCollector) flushAllFlows() {
	c.flowMu.Lock()
	flows := make([]*FlowState, 0, len(c.flows))
	for _, flow := range c.flows {
		flows = append(flows, flow)
	}
	c.flows = make(map[string]*FlowState)
	c.flowMu.Unlock()

	for _, flow := range flows {
		c.logFlow(flow)
	}

	c.closeFiles()
}

// logFlow writes a flow to the appropriate log file
func (c *BiflowCollector) logFlow(flow *FlowState) {
	nfLog := &NetflowLog{
		Timestamp:       flow.FirstSeen.Format(time.RFC3339),
		FlowID:          flow.FlowID,
		EventID:         "flow_" + flow.FlowID[:16],
		SrcIP:           flow.SrcIP,
		DstIP:           flow.DstIP,
		SrcPort:         flow.SrcPort,
		DstPort:         flow.DstPort,
		Protocol:        flow.Protocol,
		Direction:       flow.Direction,
		Initiator:       flow.Initiator,
		PacketsToServer: flow.PacketsToServer,
		PacketsToclient: flow.PacketsToClient,
		BytesToServer:   flow.BytesToServer,
		BytesToClient:   flow.BytesToClient,
		FlowDuration:    flow.LastSeen.Sub(flow.FirstSeen).Seconds(),
		SrcGeo:          flow.SrcGeo,
		DstGeo:          flow.DstGeo,
	}

	data, err := json.Marshal(nfLog)
	if err != nil {
		return
	}

	c.writerMu.Lock()
	defer c.writerMu.Unlock()

	// Route to appropriate file
	switch flow.Direction {
	case "east-west":
		if c.ewWriter != nil {
			c.ewWriter.Write(data)
			c.ewWriter.WriteByte('\n')
			c.ewWriter.Flush()
			c.ewLogsWritten++
		}
	default: // north-south
		if c.nsWriter != nil {
			c.nsWriter.Write(data)
			c.nsWriter.WriteByte('\n')
			c.nsWriter.Flush()
			c.nsLogsWritten++
		}
	}
}

func (c *BiflowCollector) openFiles() error {
	c.writerMu.Lock()
	defer c.writerMu.Unlock()

	// Ensure directories exist
	os.MkdirAll("../../logs/netflow", 0755)

	var err error

	// East-West file
	c.ewFile, err = os.OpenFile(c.eastWestPath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0644)
	if err == nil {
		c.ewWriter = bufio.NewWriter(c.ewFile)
	}

	// North-South file
	c.nsFile, err = os.OpenFile(c.northSouthPath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0644)
	if err == nil {
		c.nsWriter = bufio.NewWriter(c.nsFile)
	}

	// Unknown file
	c.unknownFile, err = os.OpenFile(c.unknownPath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0644)
	if err == nil {
		c.unknownWriter = bufio.NewWriter(c.unknownFile)
	}

	c.ewLogsWritten = 0
	c.nsLogsWritten = 0
	c.unknownLogsWritten = 0

	return nil
}

func (c *BiflowCollector) cycleLoop(ctx context.Context) {
	ticker := time.NewTicker(c.cycleInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			c.flushAllFlows()
			c.openFiles()
		}
	}
}

func (c *BiflowCollector) closeFiles() {
	c.writerMu.Lock()
	defer c.writerMu.Unlock()

	if c.ewWriter != nil {
		c.ewWriter.Flush()
	}
	if c.ewFile != nil {
		c.ewFile.Close()
	}
	if c.nsWriter != nil {
		c.nsWriter.Flush()
	}
	if c.nsFile != nil {
		c.nsFile.Close()
	}
	if c.unknownWriter != nil {
		c.unknownWriter.Flush()
	}
	if c.unknownFile != nil {
		c.unknownFile.Close()
	}
}

// GetStats returns collector statistics
func (c *BiflowCollector) GetStats() map[string]interface{} {
	c.flowMu.Lock()
	activeFlows := len(c.flows)
	c.flowMu.Unlock()

	c.writerMu.Lock()
	defer c.writerMu.Unlock()

	return map[string]interface{}{
		"active_flows":       activeFlows,
		"east_west_logged":   c.ewLogsWritten,
		"north_south_logged": c.nsLogsWritten,
		"unknown_logged":     c.unknownLogsWritten,
	}
}
