package collectors

import (
	"context"
	"fmt"
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
	Process     *models.ProcessInfo `json:"process,omitempty"`
	SrcGeo      *models.GeoInfo     `json:"src_geo,omitempty"`
	DstGeo      *models.GeoInfo     `json:"dst_geo,omitempty"`
}

// EVEDns represents DNS event data in EVE format
// Only responses are logged (contains query name + answers + rcode)
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
	ContentType   string `json:"content_type,omitempty"`
}

// EVETLS represents TLS event data in EVE format
type EVETLS struct {
	SNI         string `json:"sni,omitempty"`
	Version     string `json:"version,omitempty"`
	JA3         string `json:"ja3,omitempty"`
	JA3S        string `json:"ja3s,omitempty"`
	Cipher      string `json:"cipher,omitempty"`
	Certificate bool   `json:"certificate,omitempty"`
}

// dedupWindow is the time-based deduplication window.
// Same event key within this window is suppressed.
const dedupWindow = 60 * time.Second

// dedupMaxEntries caps the dedup cache to prevent memory leak.
const dedupMaxEntries = 100000

// IDSCollector produces Suricata EVE JSON-compatible event logs
// Logs protocol metadata only: DNS responses, HTTP requests, TLS handshakes
// Flow events are NOT logged here — BiflowCollector handles those
// (east_west.jsonl and north_south.jsonl have richer flow data)
type IDSCollector struct {
	writer *writer.RotatingWriter

	// Time-based dedup: eventKey -> lastLoggedTime
	dedupCache map[string]time.Time
	dedupMu    sync.Mutex
}

// NewIDSCollector creates a new EVE JSON IDS collector
func NewIDSCollector(logPath string, _ interface{}) *IDSCollector {
	return &IDSCollector{
		writer:     writer.NewRotatingWriter(logPath, 50*1024*1024, 3),
		dedupCache: make(map[string]time.Time),
	}
}

// Start begins the IDS collector and its dedup cleanup goroutine
func (c *IDSCollector) Start(ctx context.Context) {
	c.writer.Start(ctx)

	// Periodic dedup cache cleanup
	go func() {
		ticker := time.NewTicker(5 * time.Minute)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				c.pruneDedup()
			}
		}
	}()
}

// Process processes a packet and generates EVE events
// Only logs: DNS responses, HTTP requests, TLS ClientHellos
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
}

// processDNS logs DNS responses only (responses contain query name + answers + rcode).
// Queries without responses are not logged — responses always have the full picture.
// Deduplicates by domain+type within 60s window.
func (c *IDSCollector) processDNS(pkt *models.PacketLog) {
	dns := pkt.ParsedApplication.DNS
	if dns == nil || len(dns.Queries) == 0 {
		return
	}

	// Only log responses (QR=1). Responses contain the query info + answers.
	if dns.QR == 0 {
		return
	}

	for _, q := range dns.Queries {
		// Dedup by domain+type (e.g., "dns:example.com:A")
		dedupKey := fmt.Sprintf("dns:%s:%s", q.Name, q.Type)
		if c.isDeduplicate(dedupKey) {
			continue
		}

		evt := c.baseEvent(pkt, "dns")
		evt.AppProto = "dns"

		eveDns := &EVEDns{
			Type:   "answer",
			ID:     dns.TransactionID,
			RRName: q.Name,
			RRType: q.Type,
			Rcode:  dns.RcodeString,
		}

		for _, a := range dns.Answers {
			eveDns.Answers = append(eveDns.Answers, EVEDnsAnswer{
				RRName: a.Name, RRType: a.Type, TTL: a.TTL, RData: a.Data,
			})
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
	if c.isDeduplicate(dedupKey) {
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

	// Extract content-type from response headers if available
	if http.Headers != nil {
		if ct, ok := http.Headers["Content-Type"]; ok {
			evt.HTTP.ContentType = ct
		}
		if ct, ok := http.Headers["content-type"]; ok && evt.HTTP.ContentType == "" {
			evt.HTTP.ContentType = ct
		}
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
	if c.isDeduplicate(dedupKey) {
		return
	}

	evt := c.baseEvent(pkt, "tls")
	evt.AppProto = "tls"
	evt.TLS = &EVETLS{
		SNI: sni, Version: tls.ClientHello.Version,
		JA3: tls.JA3Hash, JA3S: tls.JA3SHash,
		Certificate: tls.CertificatesPresent,
	}

	// Add negotiated cipher suite (first from the ClientHello list)
	if len(tls.ClientHello.CipherSuites) > 0 {
		evt.TLS.Cipher = tls.ClientHello.CipherSuites[0]
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

// isDeduplicate returns true if the same event key was logged within the dedup window.
// If not a duplicate, records the current time for the key.
func (c *IDSCollector) isDeduplicate(key string) bool {
	now := time.Now()

	c.dedupMu.Lock()
	defer c.dedupMu.Unlock()

	if lastSeen, exists := c.dedupCache[key]; exists {
		if now.Sub(lastSeen) < dedupWindow {
			return true
		}
	}

	c.dedupCache[key] = now

	// Inline prune if cache is too large
	if len(c.dedupCache) > dedupMaxEntries {
		cutoff := now.Add(-dedupWindow)
		for k, t := range c.dedupCache {
			if t.Before(cutoff) {
				delete(c.dedupCache, k)
			}
		}
	}

	return false
}

// pruneDedup removes expired entries from the dedup cache
func (c *IDSCollector) pruneDedup() {
	cutoff := time.Now().Add(-dedupWindow)

	c.dedupMu.Lock()
	defer c.dedupMu.Unlock()

	for k, t := range c.dedupCache {
		if t.Before(cutoff) {
			delete(c.dedupCache, k)
		}
	}
}

// GetStats returns collector statistics
func (c *IDSCollector) GetStats() map[string]interface{} {
	writerStats := c.writer.GetStats()

	c.dedupMu.Lock()
	dedupSize := len(c.dedupCache)
	c.dedupMu.Unlock()

	return map[string]interface{}{
		"lines_written": writerStats["lines_written"],
		"dedup_cache":   dedupSize,
	}
}
