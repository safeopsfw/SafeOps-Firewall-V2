package collectors

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/safeops/network_logger/internal/writer"
	"github.com/safeops/network_logger/pkg/models"
)

// NetflowLog represents an IPFIX-enriched NetFlow record
type NetflowLog struct {
	Timestamp    string `json:"timestamp"`
	FlowID       string `json:"flow_id"`
	CommunityID  string `json:"community_id,omitempty"`
	SrcIP        string `json:"src_ip"`
	DstIP        string `json:"dst_ip"`
	SrcPort      uint16 `json:"src_port,omitempty"`
	DstPort      uint16 `json:"dst_port,omitempty"`
	Protocol     string `json:"protocol"`
	ProtocolNum  uint8  `json:"proto,omitempty"`
	Direction    string `json:"direction"`
	Initiator    string `json:"initiator"`
	AppProto     string `json:"app_proto,omitempty"`
	FlowEndReason string `json:"flow_end_reason,omitempty"`

	// Byte/packet counters (IPFIX standard naming)
	PacketsToServer int   `json:"pkts_toserver"`
	PacketsToClient int   `json:"pkts_toclient"`
	BytesToServer   int64 `json:"bytes_toserver"`
	BytesToClient   int64 `json:"bytes_toclient"`

	// Flow timing
	FlowStart    string  `json:"flow_start"`
	FlowEnd      string  `json:"flow_end"`
	FlowDuration float64 `json:"flow_duration_sec,omitempty"`

	// TCP specifics
	TCPFlagsTS   string `json:"tcp_flags_ts,omitempty"`   // Aggregate flags seen to-server
	TCPFlagsTC   string `json:"tcp_flags_tc,omitempty"`   // Aggregate flags seen to-client
	TCPState     string `json:"tcp_state,omitempty"`

	// IP header fields (IPFIX)
	ToS  uint8 `json:"tos,omitempty"`
	DSCP uint8 `json:"dscp,omitempty"`

	// GeoIP
	SrcGeo *models.GeoInfo `json:"src_geo,omitempty"`
	DstGeo *models.GeoInfo `json:"dst_geo,omitempty"`
}

// FlowState tracks aggregated flow data with IPFIX enrichments
type FlowState struct {
	FlowID      string
	CommunityID string
	SrcIP       string
	DstIP       string
	SrcPort     uint16
	DstPort     uint16
	Protocol    string
	ProtocolNum uint8
	Direction   string
	Initiator   string
	AppProto    string

	PacketsToServer int
	PacketsToClient int
	BytesToServer   int64
	BytesToClient   int64

	FirstSeen time.Time
	LastSeen  time.Time

	// TCP flag aggregation across flow lifetime
	TCPFlagsSeen   [2]uint8 // [0]=toserver, [1]=toclient
	TCPState       string
	FlowEndReason  string

	// IP header
	ToS  uint8
	DSCP uint8

	SrcGeo *models.GeoInfo
	DstGeo *models.GeoInfo
}

// BiflowCollector aggregates packets into IPFIX-enriched flows and splits by direction
type BiflowCollector struct {
	ewWriter *writer.RotatingWriter
	nsWriter *writer.RotatingWriter

	flows  map[string]*FlowState
	flowMu sync.Mutex

	flowTimeout     time.Duration
	cleanupInterval time.Duration

	ewLogsWritten int64
	nsLogsWritten int64
	statsMu       sync.Mutex
}

// NewBiflowCollector creates a new BiFlow collector with rotating writers
func NewBiflowCollector(eastWestPath, northSouthPath string, maxBytes int64, maxFiles int) *BiflowCollector {
	return &BiflowCollector{
		ewWriter:        writer.NewRotatingWriter(eastWestPath, maxBytes, maxFiles),
		nsWriter:        writer.NewRotatingWriter(northSouthPath, maxBytes, maxFiles),
		flows:           make(map[string]*FlowState),
		flowTimeout:     30 * time.Second,
		cleanupInterval: 10 * time.Second,
	}
}

// Start begins the BiFlow collector
func (c *BiflowCollector) Start(ctx context.Context) error {
	if err := c.ewWriter.Start(ctx); err != nil {
		return fmt.Errorf("east-west writer: %w", err)
	}
	if err := c.nsWriter.Start(ctx); err != nil {
		return fmt.Errorf("north-south writer: %w", err)
	}
	go c.cleanupLoop(ctx)
	return nil
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

	var protoNum uint8 = pkt.Layers.Network.Protocol
	proto := "OTHER"
	switch protoNum {
	case 6:
		proto = "TCP"
	case 17:
		proto = "UDP"
	case 1:
		proto = "ICMP"
	case 58:
		proto = "ICMPv6"
	}

	// Generate normalized flow key
	flowKey, isForward := c.generateFlowKey(srcIP, dstIP, srcPort, dstPort, proto)

	c.flowMu.Lock()
	defer c.flowMu.Unlock()

	flow, exists := c.flows[flowKey]
	if !exists {
		flow = &FlowState{
			FlowID:      flowKey,
			CommunityID: pkt.CommunityID,
			SrcIP:       srcIP,
			DstIP:       dstIP,
			SrcPort:     srcPort,
			DstPort:     dstPort,
			Protocol:    proto,
			ProtocolNum: protoNum,
			Direction:   classifyFlowDirection(srcIP, dstIP),
			Initiator:   classifyInitiator(srcIP),
			AppProto:    pkt.AppProto,
			FirstSeen:   time.Now(),
			LastSeen:    time.Now(),
			ToS:         pkt.Layers.Network.TOS,
			DSCP:        pkt.Layers.Network.DSCP,
			SrcGeo:      pkt.SrcGeo,
			DstGeo:      pkt.DstGeo,
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

	// Aggregate TCP flags across flow lifetime
	if pkt.Layers.Transport != nil && pkt.Layers.Transport.TCPFlags != nil {
		flags := pkt.Layers.Transport.TCPFlags
		idx := 0
		if !isForward {
			idx = 1
		}
		if flags.SYN {
			flow.TCPFlagsSeen[idx] |= 0x02
		}
		if flags.ACK {
			flow.TCPFlagsSeen[idx] |= 0x10
		}
		if flags.FIN {
			flow.TCPFlagsSeen[idx] |= 0x01
		}
		if flags.RST {
			flow.TCPFlagsSeen[idx] |= 0x04
		}
		if flags.PSH {
			flow.TCPFlagsSeen[idx] |= 0x08
		}
		if flags.URG {
			flow.TCPFlagsSeen[idx] |= 0x20
		}
		if flags.ECE {
			flow.TCPFlagsSeen[idx] |= 0x40
		}
		if flags.CWR {
			flow.TCPFlagsSeen[idx] |= 0x80
		}

		// Track TCP state
		flow.TCPState = tcpFlowState(flags)

		// Detect flow end reason from flags
		if flags.RST {
			flow.FlowEndReason = "forced_end"
		} else if flags.FIN {
			flow.FlowEndReason = "end_detected"
		}
	}

	// Update app_proto if we see a better classification later
	if flow.AppProto == "" && pkt.AppProto != "" {
		flow.AppProto = pkt.AppProto
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

// cleanupLoop periodically emits expired flows
func (c *BiflowCollector) cleanupLoop(ctx context.Context) {
	ticker := time.NewTicker(c.cleanupInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			c.flushAllFlows("shutdown")
			return
		case <-ticker.C:
			c.cleanupExpiredFlows()
		}
	}
}

// cleanupExpiredFlows emits and removes expired flows
func (c *BiflowCollector) cleanupExpiredFlows() {
	now := time.Now()
	expired := make([]*FlowState, 0)

	c.flowMu.Lock()
	for key, flow := range c.flows {
		if now.Sub(flow.LastSeen) > c.flowTimeout {
			if flow.FlowEndReason == "" {
				flow.FlowEndReason = "idle_timeout"
			}
			expired = append(expired, flow)
			delete(c.flows, key)
		}
	}
	c.flowMu.Unlock()

	for _, flow := range expired {
		c.emitFlow(flow)
	}
}

// flushAllFlows emits all remaining flows
func (c *BiflowCollector) flushAllFlows(reason string) {
	c.flowMu.Lock()
	flows := make([]*FlowState, 0, len(c.flows))
	for _, flow := range c.flows {
		if flow.FlowEndReason == "" {
			flow.FlowEndReason = reason
		}
		flows = append(flows, flow)
	}
	c.flows = make(map[string]*FlowState)
	c.flowMu.Unlock()

	for _, flow := range flows {
		c.emitFlow(flow)
	}
}

// emitFlow writes a flow record to the appropriate rotating writer
func (c *BiflowCollector) emitFlow(flow *FlowState) {
	nfLog := &NetflowLog{
		Timestamp:       flow.FirstSeen.Format(time.RFC3339Nano),
		FlowID:          flow.FlowID,
		CommunityID:     flow.CommunityID,
		SrcIP:           flow.SrcIP,
		DstIP:           flow.DstIP,
		SrcPort:         flow.SrcPort,
		DstPort:         flow.DstPort,
		Protocol:        flow.Protocol,
		ProtocolNum:     flow.ProtocolNum,
		Direction:       flow.Direction,
		Initiator:       flow.Initiator,
		AppProto:        flow.AppProto,
		FlowEndReason:   flow.FlowEndReason,
		PacketsToServer: flow.PacketsToServer,
		PacketsToClient: flow.PacketsToClient,
		BytesToServer:   flow.BytesToServer,
		BytesToClient:   flow.BytesToClient,
		FlowStart:       flow.FirstSeen.Format(time.RFC3339Nano),
		FlowEnd:         flow.LastSeen.Format(time.RFC3339Nano),
		FlowDuration:    flow.LastSeen.Sub(flow.FirstSeen).Seconds(),
		TCPFlagsTS:      formatFlagByte(flow.TCPFlagsSeen[0]),
		TCPFlagsTC:      formatFlagByte(flow.TCPFlagsSeen[1]),
		TCPState:        flow.TCPState,
		ToS:             flow.ToS,
		DSCP:            flow.DSCP,
		SrcGeo:          flow.SrcGeo,
		DstGeo:          flow.DstGeo,
	}

	c.statsMu.Lock()
	switch flow.Direction {
	case "east-west":
		c.ewWriter.WriteJSON(nfLog)
		c.ewLogsWritten++
	default:
		c.nsWriter.WriteJSON(nfLog)
		c.nsLogsWritten++
	}
	c.statsMu.Unlock()
}

// GetStats returns collector statistics
func (c *BiflowCollector) GetStats() map[string]interface{} {
	c.flowMu.Lock()
	activeFlows := len(c.flows)
	c.flowMu.Unlock()

	c.statsMu.Lock()
	defer c.statsMu.Unlock()

	ewStats := c.ewWriter.GetStats()
	nsStats := c.nsWriter.GetStats()

	return map[string]interface{}{
		"active_flows":       activeFlows,
		"east_west_logged":   c.ewLogsWritten,
		"north_south_logged": c.nsLogsWritten,
		"ew_file_size":       ewStats["current_size"],
		"ns_file_size":       nsStats["current_size"],
	}
}

// classifyFlowDirection classifies traffic as east-west or north-south
func classifyFlowDirection(srcIP, dstIP string) string {
	srcPrivate := isPrivateIP(srcIP)
	dstPrivate := isPrivateIP(dstIP)
	if srcPrivate && dstPrivate {
		return "east-west"
	}
	return "north-south"
}

// classifyInitiator classifies the flow initiator
func classifyInitiator(srcIP string) string {
	if !isPrivateIP(srcIP) {
		return "internet"
	}
	return "local"
}

// tcpFlowState returns the latest TCP state based on flags
func tcpFlowState(flags *models.TCPFlags) string {
	if flags == nil {
		return ""
	}
	if flags.RST {
		return "reset"
	}
	if flags.FIN {
		return "closing"
	}
	if flags.SYN && flags.ACK {
		return "established"
	}
	if flags.SYN {
		return "new"
	}
	if flags.ACK {
		return "established"
	}
	return ""
}

// formatFlagByte converts aggregated TCP flag byte to human-readable string
func formatFlagByte(b uint8) string {
	if b == 0 {
		return ""
	}
	flags := ""
	if b&0x02 != 0 {
		flags += "S"
	}
	if b&0x10 != 0 {
		flags += "A"
	}
	if b&0x01 != 0 {
		flags += "F"
	}
	if b&0x04 != 0 {
		flags += "R"
	}
	if b&0x08 != 0 {
		flags += "P"
	}
	if b&0x20 != 0 {
		flags += "U"
	}
	if b&0x40 != 0 {
		flags += "E"
	}
	if b&0x80 != 0 {
		flags += "C"
	}
	return flags
}

