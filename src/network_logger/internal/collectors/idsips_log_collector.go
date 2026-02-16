package collectors

import (
	"context"
	"fmt"
	"net"
	"sync"
	"time"

	"github.com/safeops/network_logger/internal/writer"
	"github.com/safeops/network_logger/pkg/models"
)

// EVEEvent represents a Suricata-compatible EVE JSON event
type EVEEvent struct {
	Timestamp   string              `json:"timestamp"`
	EventType   string              `json:"event_type"`
	SrcIP       string              `json:"src_ip"`
	SrcPort     uint16              `json:"src_port,omitempty"`
	DstIP       string              `json:"dst_ip"`
	DstPort     uint16              `json:"dst_port,omitempty"`
	Proto       string              `json:"proto"`
	CommunityID string              `json:"community_id,omitempty"`
	FlowID      string              `json:"flow_id,omitempty"`
	AppProto    string              `json:"app_proto,omitempty"`
	Direction   string              `json:"direction,omitempty"`
	DNS         *EVEDns             `json:"dns,omitempty"`
	HTTP        *EVEHTTP            `json:"http,omitempty"`
	TLS         *EVETLS             `json:"tls,omitempty"`
	Flow        *EVEFlow            `json:"flow,omitempty"`
	Process     *models.ProcessInfo `json:"process,omitempty"`
	SrcGeo      *models.GeoInfo     `json:"src_geo,omitempty"`
	DstGeo      *models.GeoInfo     `json:"dst_geo,omitempty"`
}

// EVEDns represents DNS event data in EVE format
type EVEDns struct {
	Type    string         `json:"type"`
	ID      uint16         `json:"id,omitempty"`
	RRName  string         `json:"rrname,omitempty"`
	RRType  string         `json:"rrtype,omitempty"`
	Rcode   string         `json:"rcode,omitempty"`
	Answers []EVEDnsAnswer `json:"answers,omitempty"`
}

// EVEDnsAnswer represents a DNS answer in EVE format
type EVEDnsAnswer struct {
	RRName string `json:"rrname"`
	RRType string `json:"rrtype"`
	TTL    uint32 `json:"ttl,omitempty"`
	RData  string `json:"rdata"`
}

// EVEHTTP represents HTTP event data in EVE format
type EVEHTTP struct {
	Hostname      string `json:"hostname,omitempty"`
	URL           string `json:"url,omitempty"`
	HTTPMethod    string `json:"http_method,omitempty"`
	HTTPUserAgent string `json:"http_user_agent,omitempty"`
	HTTPReferer   string `json:"http_refer,omitempty"`
	Protocol      string `json:"protocol,omitempty"`
	Status        int    `json:"status,omitempty"`
	Length        int    `json:"length,omitempty"`
}

// EVETLS represents TLS event data in EVE format
type EVETLS struct {
	SNI         string `json:"sni,omitempty"`
	Version     string `json:"version,omitempty"`
	JA3         string `json:"ja3,omitempty"`
	JA3S        string `json:"ja3s,omitempty"`
	Certificate bool   `json:"certificate,omitempty"`
}

// EVEFlow represents flow event data in EVE format
type EVEFlow struct {
	PktsToServer  int    `json:"pkts_toserver"`
	PktsToClient  int    `json:"pkts_toclient"`
	BytesToServer int64  `json:"bytes_toserver"`
	BytesToClient int64  `json:"bytes_toclient"`
	Start         string `json:"start,omitempty"`
	End           string `json:"end,omitempty"`
	State         string `json:"state,omitempty"`
	Reason        string `json:"reason,omitempty"`
}

// idsFlowState tracks a flow for EVE flow-end events
type idsFlowState struct {
	FlowID        string
	SrcIP         string
	DstIP         string
	SrcPort       uint16
	DstPort       uint16
	Proto         string
	CommunityID   string
	Direction     string
	AppProto      string
	PktsToServer  int
	PktsToClient  int
	BytesToServer int64
	BytesToClient int64
	FirstSeen     time.Time
	LastSeen      time.Time
	TCPFlags      map[string]bool
	State         string
	Process       *models.ProcessInfo
	SrcGeo        *models.GeoInfo
	DstGeo        *models.GeoInfo
}

// IDSCollector produces Suricata EVE JSON-compatible event logs
type IDSCollector struct {
	writer      *writer.RotatingWriter
	dedupFilter *DuplicateFilter
	flows       map[string]*idsFlowState
	flowsMu     sync.RWMutex
	flowTimeout time.Duration
}

// NewIDSCollector creates a new EVE JSON IDS collector
func NewIDSCollector(logPath string, _ time.Duration) *IDSCollector {
	return &IDSCollector{
		writer:      writer.NewRotatingWriter(logPath, 50*1024*1024, 3),
		dedupFilter: NewDuplicateFilter(),
		flows:       make(map[string]*idsFlowState),
		flowTimeout: 60 * time.Second,
	}
}

// Start begins the IDS collector
func (c *IDSCollector) Start(ctx context.Context) {
	c.writer.Start(ctx)
	go c.flowCleanupLoop(ctx)
}

// Process processes a packet and generates EVE events
func (c *IDSCollector) Process(pkt *models.PacketLog) {
	if pkt.Layers.Network == nil {
		return
	}

	switch {
	case pkt.ParsedApplication.DNS != nil:
		c.processDNS(pkt)
	case pkt.ParsedApplication.HTTP != nil:
		c.processHTTP(pkt)
	case pkt.ParsedApplication.TLS != nil && pkt.ParsedApplication.TLS.ClientHello != nil:
		c.processTLS(pkt)
	}

	if pkt.Layers.Transport != nil {
		c.updateFlow(pkt)
	}
}

func (c *IDSCollector) processDNS(pkt *models.PacketLog) {
	dns := pkt.ParsedApplication.DNS
	if dns == nil || len(dns.Queries) == 0 {
		return
	}

	for _, q := range dns.Queries {
		evt := c.baseEvent(pkt, "dns")
		evt.AppProto = "dns"

		eveDns := &EVEDns{
			ID:     dns.TransactionID,
			RRName: q.Name,
			RRType: q.Type,
		}

		if dns.QR == 0 {
			eveDns.Type = "query"
		} else {
			eveDns.Type = "answer"
			eveDns.Rcode = dns.RcodeString
			for _, a := range dns.Answers {
				eveDns.Answers = append(eveDns.Answers, EVEDnsAnswer{
					RRName: a.Name, RRType: a.Type, TTL: a.TTL, RData: a.Data,
				})
			}
		}

		evt.DNS = eveDns
		c.writer.WriteJSON(evt)
	}
}

func (c *IDSCollector) processHTTP(pkt *models.PacketLog) {
	http := pkt.ParsedApplication.HTTP
	if http == nil {
		return
	}

	dedupKey := fmt.Sprintf("http:%s:%s:%s", http.Host, http.Method, http.URI)
	if c.isDuplicate(pkt, dedupKey) {
		return
	}

	evt := c.baseEvent(pkt, "http")
	evt.AppProto = "http"
	evt.HTTP = &EVEHTTP{
		Hostname: http.Host, URL: http.URI,
		HTTPMethod: http.Method, HTTPUserAgent: http.UserAgent,
		HTTPReferer: http.Referer, Protocol: http.Version,
		Status: http.StatusCode, Length: http.BodyLength,
	}
	c.writer.WriteJSON(evt)
}

func (c *IDSCollector) processTLS(pkt *models.PacketLog) {
	tls := pkt.ParsedApplication.TLS
	if tls == nil || tls.ClientHello == nil {
		return
	}

	sni := tls.ClientHello.SNI
	dedupKey := fmt.Sprintf("tls:%s", sni)
	if c.isDuplicate(pkt, dedupKey) {
		return
	}

	evt := c.baseEvent(pkt, "tls")
	evt.AppProto = "tls"
	evt.TLS = &EVETLS{
		SNI: sni, Version: tls.ClientHello.Version,
		JA3: tls.JA3Hash, JA3S: tls.JA3SHash,
		Certificate: tls.CertificatesPresent,
	}
	c.writer.WriteJSON(evt)
}

func (c *IDSCollector) baseEvent(pkt *models.PacketLog, eventType string) *EVEEvent {
	evt := &EVEEvent{
		Timestamp: pkt.Timestamp.ISO8601, EventType: eventType,
		SrcIP: pkt.Layers.Network.SrcIP, DstIP: pkt.Layers.Network.DstIP,
		CommunityID: pkt.CommunityID, Direction: pkt.Direction,
		SrcGeo: pkt.SrcGeo, DstGeo: pkt.DstGeo,
	}

	switch pkt.Layers.Network.Protocol {
	case 6:
		evt.Proto = "TCP"
	case 17:
		evt.Proto = "UDP"
	case 1:
		evt.Proto = "ICMP"
	default:
		evt.Proto = fmt.Sprintf("%d", pkt.Layers.Network.Protocol)
	}

	if pkt.Layers.Transport != nil {
		evt.SrcPort = pkt.Layers.Transport.SrcPort
		evt.DstPort = pkt.Layers.Transport.DstPort
	}

	if pkt.FlowContext != nil {
		evt.FlowID = pkt.FlowContext.FlowID
		evt.Process = pkt.FlowContext.ProcessInfo
	}

	return evt
}

func (c *IDSCollector) updateFlow(pkt *models.PacketLog) {
	flowKey := c.generateFlowKey(pkt)

	c.flowsMu.Lock()
	defer c.flowsMu.Unlock()

	now := time.Now()
	flow, exists := c.flows[flowKey]
	pktSize := int64(pkt.CaptureInfo.WireLength)

	if !exists {
		proto := "TCP"
		switch pkt.Layers.Network.Protocol {
		case 17:
			proto = "UDP"
		case 1:
			proto = "ICMP"
		}

		flow = &idsFlowState{
			FlowID: flowKey, SrcIP: pkt.Layers.Network.SrcIP, DstIP: pkt.Layers.Network.DstIP,
			Proto: proto, CommunityID: pkt.CommunityID, Direction: pkt.Direction,
			AppProto: pkt.AppProto, FirstSeen: now, LastSeen: now,
			TCPFlags: make(map[string]bool), State: "new",
			SrcGeo: pkt.SrcGeo, DstGeo: pkt.DstGeo,
		}
		if pkt.Layers.Transport != nil {
			flow.SrcPort = pkt.Layers.Transport.SrcPort
			flow.DstPort = pkt.Layers.Transport.DstPort
		}
		c.flows[flowKey] = flow
	}

	flow.LastSeen = now
	if pkt.FlowContext != nil && pkt.FlowContext.ProcessInfo != nil {
		flow.Process = pkt.FlowContext.ProcessInfo
	}
	if flow.AppProto == "" && pkt.AppProto != "" {
		flow.AppProto = pkt.AppProto
	}

	isForward := pkt.Layers.Network.SrcIP == flow.SrcIP
	if isForward {
		flow.PktsToServer++
		flow.BytesToServer += pktSize
	} else {
		flow.PktsToClient++
		flow.BytesToClient += pktSize
	}

	if pkt.Layers.Transport != nil && pkt.Layers.Transport.TCPFlags != nil {
		flags := pkt.Layers.Transport.TCPFlags
		if flags.SYN {
			flow.TCPFlags["SYN"] = true
		}
		if flags.ACK {
			flow.TCPFlags["ACK"] = true
			flow.State = "established"
		}
		if flags.FIN {
			flow.TCPFlags["FIN"] = true
			flow.State = "closed"
			c.emitFlowEnd(flow, "fin")
			delete(c.flows, flowKey)
		}
		if flags.RST {
			flow.TCPFlags["RST"] = true
			flow.State = "closed"
			c.emitFlowEnd(flow, "rst")
			delete(c.flows, flowKey)
		}
	}
}

func (c *IDSCollector) emitFlowEnd(flow *idsFlowState, reason string) {
	evt := &EVEEvent{
		Timestamp: time.Now().Format(time.RFC3339Nano), EventType: "flow",
		SrcIP: flow.SrcIP, DstIP: flow.DstIP, SrcPort: flow.SrcPort, DstPort: flow.DstPort,
		Proto: flow.Proto, CommunityID: flow.CommunityID, FlowID: flow.FlowID,
		AppProto: flow.AppProto, Direction: flow.Direction,
		Process: flow.Process, SrcGeo: flow.SrcGeo, DstGeo: flow.DstGeo,
		Flow: &EVEFlow{
			PktsToServer: flow.PktsToServer, PktsToClient: flow.PktsToClient,
			BytesToServer: flow.BytesToServer, BytesToClient: flow.BytesToClient,
			Start: flow.FirstSeen.Format(time.RFC3339Nano),
			End: flow.LastSeen.Format(time.RFC3339Nano),
			State: flow.State, Reason: reason,
		},
	}
	c.writer.WriteJSON(evt)
}

func (c *IDSCollector) flowCleanupLoop(ctx context.Context) {
	ticker := time.NewTicker(15 * time.Second)
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

func (c *IDSCollector) cleanupExpiredFlows() {
	now := time.Now()
	c.flowsMu.Lock()
	defer c.flowsMu.Unlock()
	for key, flow := range c.flows {
		if now.Sub(flow.LastSeen) > c.flowTimeout {
			c.emitFlowEnd(flow, "timeout")
			delete(c.flows, key)
		}
	}
}

func (c *IDSCollector) flushAllFlows() {
	c.flowsMu.Lock()
	defer c.flowsMu.Unlock()
	for key, flow := range c.flows {
		c.emitFlowEnd(flow, "shutdown")
		delete(c.flows, key)
	}
}

func (c *IDSCollector) generateFlowKey(pkt *models.PacketLog) string {
	srcIP := pkt.Layers.Network.SrcIP
	dstIP := pkt.Layers.Network.DstIP
	var srcPort, dstPort uint16
	proto := "OTHER"

	if pkt.Layers.Transport != nil {
		srcPort = pkt.Layers.Transport.SrcPort
		dstPort = pkt.Layers.Transport.DstPort
	}
	switch pkt.Layers.Network.Protocol {
	case 6:
		proto = "TCP"
	case 17:
		proto = "UDP"
	case 1:
		proto = "ICMP"
	}

	if srcIP > dstIP || (srcIP == dstIP && srcPort > dstPort) {
		srcIP, dstIP = dstIP, srcIP
		srcPort, dstPort = dstPort, srcPort
	}
	return fmt.Sprintf("%s:%d-%s:%d/%s", srcIP, srcPort, dstIP, dstPort, proto)
}

func (c *IDSCollector) isDuplicate(pkt *models.PacketLog, dedupKey string) bool {
	idsLog := &IDSLog{FlowID: c.generateFlowKey(pkt), Protocol: dedupKey}
	isDup, _ := c.dedupFilter.IsDuplicate(idsLog)
	return isDup
}

// GetStats returns collector statistics
func (c *IDSCollector) GetStats() map[string]interface{} {
	c.flowsMu.RLock()
	activeFlows := len(c.flows)
	c.flowsMu.RUnlock()
	writerStats := c.writer.GetStats()
	return map[string]interface{}{
		"active_flows":  activeFlows,
		"lines_written": writerStats["lines_written"],
	}
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

// IDSLog kept for DuplicateFilter compatibility
type IDSLog struct {
	TimestampIST string           `json:"timestamp_ist,omitempty"`
	PacketID     string           `json:"packet_id,omitempty"`
	FlowID       string           `json:"flow_id"`
	SrcIP        string           `json:"src_ip,omitempty"`
	DstIP        string           `json:"dst_ip,omitempty"`
	SrcPort      uint16           `json:"src_port,omitempty"`
	DstPort      uint16           `json:"dst_port,omitempty"`
	Protocol     string           `json:"protocol,omitempty"`
	SrcGeo       *models.GeoInfo  `json:"src_geo,omitempty"`
	DstGeo       *models.GeoInfo  `json:"dst_geo,omitempty"`
	HTTP         *models.HTTPData `json:"http,omitempty"`
	DNS          *models.DNSData  `json:"dns,omitempty"`
	TLS          *TLSCompact      `json:"tls,omitempty"`
	TCPFlags     string           `json:"tcp_flags,omitempty"`
}

type TLSCompact struct {
	SNI     string `json:"sni,omitempty"`
	Version string `json:"version,omitempty"`
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
