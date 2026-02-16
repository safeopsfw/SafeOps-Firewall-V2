package collectors

import (
	"context"
	"sort"
	"sync"
	"time"

	"github.com/safeops/network_logger/internal/writer"
	"github.com/safeops/network_logger/pkg/models"
)

// IPSummaryRecord is the 5-minute per-IP aggregation written to ip_summary.jsonl
type IPSummaryRecord struct {
	Timestamp    string `json:"timestamp"`      // Window start ISO8601
	WindowEnd    string `json:"window_end"`      // Window end ISO8601
	IP           string `json:"ip"`
	IsPrivate    bool   `json:"is_private"`
	Direction    string `json:"direction,omitempty"` // "local" or "internet"

	// Traffic totals
	PacketsSent  int64 `json:"packets_sent"`
	PacketsRecv  int64 `json:"packets_recv"`
	BytesSent    int64 `json:"bytes_sent"`
	BytesRecv    int64 `json:"bytes_recv"`

	// Flow counts
	FlowsInitiated int `json:"flows_initiated"`
	FlowsReceived  int `json:"flows_received"`

	// Protocol breakdown
	Protocols map[string]int64 `json:"protocols,omitempty"` // TCP/UDP/ICMP -> packet count

	// Top destinations (top 10 by bytes)
	TopDests []DestSummary `json:"top_destinations,omitempty"`

	// Top ports contacted (top 10 by packet count)
	TopPorts []PortSummary `json:"top_ports,omitempty"`

	// App protocol breakdown
	AppProtos map[string]int64 `json:"app_protos,omitempty"` // dns/http/tls -> count

	// DNS summary
	DNSQueries    int `json:"dns_queries,omitempty"`
	DNSNXDomains  int `json:"dns_nxdomains,omitempty"`

	// GeoIP (most seen country for external IPs)
	Geo *models.GeoInfo `json:"geo,omitempty"`
}

// DestSummary tracks per-destination stats within a summary window
type DestSummary struct {
	IP    string `json:"ip"`
	Bytes int64  `json:"bytes"`
	Pkts  int    `json:"pkts"`
	Port  uint16 `json:"port,omitempty"`
}

// PortSummary tracks per-port stats
type PortSummary struct {
	Port  uint16 `json:"port"`
	Proto string `json:"proto"`
	Pkts  int    `json:"pkts"`
}

// ipAccum accumulates per-IP stats during a summary window
type ipAccum struct {
	PacketsSent    int64
	PacketsRecv    int64
	BytesSent      int64
	BytesRecv      int64
	FlowsInit      int
	FlowsRecv      int
	Protocols      map[string]int64
	Destinations   map[string]*destAccum // dstIP -> accum
	Ports          map[portKey]*int      // port+proto -> count
	AppProtos      map[string]int64
	DNSQueries     int
	DNSNXDomains   int
	IsPrivate      bool
	Geo            *models.GeoInfo
	flowsSeen      map[string]bool // track unique flow keys to count initiator
}

type destAccum struct {
	Bytes int64
	Pkts  int
	Port  uint16
}

type portKey struct {
	Port  uint16
	Proto string
}

// IPSummaryCollector produces 5-minute per-IP aggregations
type IPSummaryCollector struct {
	writer   *writer.RotatingWriter
	window   time.Duration

	accums   map[string]*ipAccum // IP -> accumulator
	mu       sync.Mutex
	windowStart time.Time

	recordsWritten int64
	statsMu        sync.Mutex
}

// NewIPSummaryCollector creates a new IP summary collector
func NewIPSummaryCollector(path string, windowMinutes int, maxBytes int64, maxFiles int) *IPSummaryCollector {
	if windowMinutes <= 0 {
		windowMinutes = 5
	}
	return &IPSummaryCollector{
		writer:      writer.NewRotatingWriter(path, maxBytes, maxFiles),
		window:      time.Duration(windowMinutes) * time.Minute,
		accums:      make(map[string]*ipAccum),
		windowStart: time.Now(),
	}
}

// Start begins the IP summary collector
func (c *IPSummaryCollector) Start(ctx context.Context) error {
	if err := c.writer.Start(ctx); err != nil {
		return err
	}
	go c.flushLoop(ctx)
	return nil
}

// Process accumulates packet data for IP summaries
func (c *IPSummaryCollector) Process(pkt *models.PacketLog) {
	if pkt.Layers.Network == nil {
		return
	}

	srcIP := pkt.Layers.Network.SrcIP
	dstIP := pkt.Layers.Network.DstIP
	pktSize := int64(pkt.CaptureInfo.WireLength)

	var proto string
	var dstPort uint16
	switch pkt.Layers.Network.Protocol {
	case 6:
		proto = "TCP"
	case 17:
		proto = "UDP"
	case 1:
		proto = "ICMP"
	default:
		proto = "OTHER"
	}
	if pkt.Layers.Transport != nil {
		dstPort = pkt.Layers.Transport.DstPort
	}

	c.mu.Lock()
	defer c.mu.Unlock()

	// Accumulate for source IP (sender)
	srcAccum := c.getOrCreateAccum(srcIP, pkt.SrcGeo)
	srcAccum.PacketsSent++
	srcAccum.BytesSent += pktSize
	srcAccum.Protocols[proto]++

	// Track destination from src perspective
	da := srcAccum.Destinations[dstIP]
	if da == nil {
		da = &destAccum{Port: dstPort}
		srcAccum.Destinations[dstIP] = da
	}
	da.Bytes += pktSize
	da.Pkts++

	// Track ports contacted
	if dstPort > 0 {
		pk := portKey{Port: dstPort, Proto: proto}
		if cnt, ok := srcAccum.Ports[pk]; ok {
			*cnt++
		} else {
			v := 1
			srcAccum.Ports[pk] = &v
		}
	}

	// Track flow initiation (SYN without ACK = new flow)
	if pkt.Layers.Transport != nil && pkt.Layers.Transport.TCPFlags != nil {
		flags := pkt.Layers.Transport.TCPFlags
		flowKey := srcIP + "->" + dstIP
		if flags.SYN && !flags.ACK && !srcAccum.flowsSeen[flowKey] {
			srcAccum.FlowsInit++
			srcAccum.flowsSeen[flowKey] = true
		}
	}

	// App proto tracking
	if pkt.AppProto != "" {
		srcAccum.AppProtos[pkt.AppProto]++
	}

	// DNS tracking
	if pkt.ParsedApplication.DNS != nil {
		dns := pkt.ParsedApplication.DNS
		if dns.QR == 0 { // query
			srcAccum.DNSQueries++
		}
		if dns.RcodeString == "NXDOMAIN" {
			srcAccum.DNSNXDomains++
		}
	}

	// Accumulate for destination IP (receiver)
	dstAccum := c.getOrCreateAccum(dstIP, pkt.DstGeo)
	dstAccum.PacketsRecv++
	dstAccum.BytesRecv += pktSize
	dstAccum.Protocols[proto]++

	// Track flow reception
	if pkt.Layers.Transport != nil && pkt.Layers.Transport.TCPFlags != nil {
		flags := pkt.Layers.Transport.TCPFlags
		flowKey := srcIP + "->" + dstIP
		if flags.SYN && !flags.ACK && !dstAccum.flowsSeen[flowKey] {
			dstAccum.FlowsRecv++
			dstAccum.flowsSeen[flowKey] = true
		}
	}
}

func (c *IPSummaryCollector) getOrCreateAccum(ip string, geo *models.GeoInfo) *ipAccum {
	a, ok := c.accums[ip]
	if !ok {
		a = &ipAccum{
			Protocols:    make(map[string]int64),
			Destinations: make(map[string]*destAccum),
			Ports:        make(map[portKey]*int),
			AppProtos:    make(map[string]int64),
			IsPrivate:    isPrivateIP(ip),
			flowsSeen:    make(map[string]bool),
		}
		c.accums[ip] = a
	}
	if a.Geo == nil && geo != nil {
		a.Geo = geo
	}
	return a
}

// flushLoop emits summaries every window interval
func (c *IPSummaryCollector) flushLoop(ctx context.Context) {
	ticker := time.NewTicker(c.window)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			c.flush()
			return
		case <-ticker.C:
			c.flush()
		}
	}
}

func (c *IPSummaryCollector) flush() {
	c.mu.Lock()
	accums := c.accums
	windowStart := c.windowStart
	c.accums = make(map[string]*ipAccum)
	c.windowStart = time.Now()
	c.mu.Unlock()

	windowEnd := time.Now()
	startStr := windowStart.Format(time.RFC3339)
	endStr := windowEnd.Format(time.RFC3339)

	for ip, a := range accums {
		// Skip IPs with negligible traffic
		totalPkts := a.PacketsSent + a.PacketsRecv
		if totalPkts < 2 {
			continue
		}

		direction := "local"
		if !a.IsPrivate {
			direction = "internet"
		}

		rec := &IPSummaryRecord{
			Timestamp:      startStr,
			WindowEnd:      endStr,
			IP:             ip,
			IsPrivate:      a.IsPrivate,
			Direction:      direction,
			PacketsSent:    a.PacketsSent,
			PacketsRecv:    a.PacketsRecv,
			BytesSent:      a.BytesSent,
			BytesRecv:      a.BytesRecv,
			FlowsInitiated: a.FlowsInit,
			FlowsReceived:  a.FlowsRecv,
			DNSQueries:     a.DNSQueries,
			DNSNXDomains:   a.DNSNXDomains,
			Geo:            a.Geo,
		}

		// Protocols (only include if non-empty)
		if len(a.Protocols) > 0 {
			rec.Protocols = a.Protocols
		}

		// App protos
		if len(a.AppProtos) > 0 {
			rec.AppProtos = a.AppProtos
		}

		// Top destinations (top 10 by bytes)
		rec.TopDests = topDestinations(a.Destinations, 10)

		// Top ports (top 10 by count)
		rec.TopPorts = topPorts(a.Ports, 10)

		c.writer.WriteJSON(rec)

		c.statsMu.Lock()
		c.recordsWritten++
		c.statsMu.Unlock()
	}
}

func topDestinations(dests map[string]*destAccum, n int) []DestSummary {
	if len(dests) == 0 {
		return nil
	}

	all := make([]DestSummary, 0, len(dests))
	for ip, d := range dests {
		all = append(all, DestSummary{
			IP:    ip,
			Bytes: d.Bytes,
			Pkts:  d.Pkts,
			Port:  d.Port,
		})
	}

	sort.Slice(all, func(i, j int) bool {
		return all[i].Bytes > all[j].Bytes
	})

	if len(all) > n {
		all = all[:n]
	}
	return all
}

func topPorts(ports map[portKey]*int, n int) []PortSummary {
	if len(ports) == 0 {
		return nil
	}

	all := make([]PortSummary, 0, len(ports))
	for pk, cnt := range ports {
		all = append(all, PortSummary{
			Port:  pk.Port,
			Proto: pk.Proto,
			Pkts:  *cnt,
		})
	}

	sort.Slice(all, func(i, j int) bool {
		return all[i].Pkts > all[j].Pkts
	})

	if len(all) > n {
		all = all[:n]
	}
	return all
}

// GetStats returns collector statistics
func (c *IPSummaryCollector) GetStats() map[string]interface{} {
	c.mu.Lock()
	activeIPs := len(c.accums)
	c.mu.Unlock()

	c.statsMu.Lock()
	defer c.statsMu.Unlock()

	wStats := c.writer.GetStats()

	return map[string]interface{}{
		"active_ips":      activeIPs,
		"records_written": c.recordsWritten,
		"file_size":       wStats["current_size"],
	}
}
