// Package logging provides structured logging for the firewall engine.
// VerdictLogger writes per-packet firewall decisions to JSONL files
// in a format suitable for SOC analysis / SIEM ingestion.
//
// Log format (one JSON object per line):
//
//	{"ts":"2026-02-18T12:01:03.456Z","src":"192.168.1.5","sp":49231,"dst":"93.184.216.34","dp":443,
//	 "proto":"TCP","action":"DROP","detector":"domain_filter","domain":"example.com",
//	 "reason":"Domain blocked: example.com (matched: exact, source: DNS)","size":64,"flags":"S","ttl":60}
//
// Storage optimization:
//   - ALL traffic logged (ALLOW sampled at 1:100, DROP/BLOCK/REDIRECT always)
//   - Short field names to minimize storage (src, dst, sp, dp, proto)
//   - 5-minute time-based rotation (plain JSONL, no compression)
//   - Max 20 rotated files in bin/logs/
//   - Buffered writes (64KB) — flushes every 2 seconds or on buffer full
package logging

import (
	"bufio"
	"crypto/sha1"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"time"
)

// VerdictEntry is a single firewall log entry for SOC/NOC monitoring.
// ALL traffic is logged (ALLOW sampled, DROP/BLOCK/REDIRECT always).
// Field names are short for storage efficiency (SOC/SIEM tools map them on ingest).
//
// Compatible with: Splunk CIM (Network Traffic), ELK ECS, QRadar LEEF, Suricata EVE.
type VerdictEntry struct {
	Timestamp string `json:"ts"`               // ISO 8601 with ms
	EventType string `json:"event_type"`       // "firewall" (always — for SIEM event categorization)
	SrcIP     string `json:"src"`              // source IP
	SrcPort   uint32 `json:"sp"`               // source port
	DstIP     string `json:"dst"`              // destination IP
	DstPort   uint32 `json:"dp"`               // destination port
	Proto     string `json:"proto"`            // TCP/UDP/ICMP
	Action    string `json:"action"`           // ALLOW/DROP/BLOCK/REDIRECT
	Detector  string `json:"detector"`         // which module decided (e.g. "domain_filter", "geoip", "ddos")
	Domain    string `json:"domain,omitempty"` // domain if available (DNS/SNI)
	Reason    string `json:"reason"`           // human-readable reason
	Size      uint32 `json:"size,omitempty"`   // packet size in bytes
	Flags     string `json:"flags,omitempty"`  // TCP flags (S/A/F/R/P/U)
	CacheTTL  uint32 `json:"ttl,omitempty"`    // verdict cache TTL seconds

	// Enrichment fields (SOC/SIEM correlation)
	Direction   string `json:"dir"`               // north_south / east_west
	TrafficType string `json:"ttype"`             // inbound / outbound / internal / transit
	CommunityID string `json:"cid,omitempty"`     // community_id v1 (Suricata-compatible SHA1 flow hash)
	FlowID      uint64 `json:"flow_id,omitempty"` // monotonic flow identifier
	SrcGeo      string `json:"src_geo,omitempty"` // source country code (ISO 3166-1 alpha-2)
	DstGeo      string `json:"dst_geo,omitempty"` // destination country code
	SrcASN      string `json:"src_asn,omitempty"` // source ASN (e.g. "AS15169")
	DstASN      string `json:"dst_asn,omitempty"` // destination ASN

	// Severity hint for SOC dashboards (derived from detector + action)
	Severity string `json:"severity,omitempty"` // CRITICAL/HIGH/MEDIUM/LOW/INFO
}

// VerdictLoggerConfig controls the SOC/NOC firewall log output.
type VerdictLoggerConfig struct {
	Dir          string        // directory for firewall log files (e.g. bin/logs)
	LogAllows    bool          // log ALLOW decisions (default true for SOC visibility)
	AllowSampleN int           // if LogAllows, sample 1 in N (default 100 — every 100th ALLOW)
	FlushInterval time.Duration // buffer flush interval (default 2s)
	MaxFileSize  int64         // max file size in bytes before truncation (default 500MB, 0 = unlimited)
}

// DefaultVerdictLoggerConfig returns production defaults for SOC/NOC monitoring.
// Single file (firewall.jsonl) — SIEM tails it in realtime.
// ALLOW traffic sampled at 1:100. DROP/BLOCK/REDIRECT always logged at 100%.
func DefaultVerdictLoggerConfig() VerdictLoggerConfig {
	return VerdictLoggerConfig{
		LogAllows:     true,
		AllowSampleN:  100,
		FlushInterval: 2 * time.Second,
		MaxFileSize:   500 * 1024 * 1024, // 500MB safety limit
	}
}

// VerdictFileLogger writes firewall log entries to a single JSONL file for SIEM realtime tailing.
type VerdictFileLogger struct {
	mu       sync.Mutex
	cfg      VerdictLoggerConfig
	writer   *bufio.Writer
	file     *os.File
	curSize  int64
	stopCh   chan struct{}
	stopped  atomic.Bool

	// Stats
	written  atomic.Int64
	dropped  atomic.Int64
	allowCtr atomic.Int64
}

const verdictActiveFile = "firewall.jsonl"

// NewVerdictFileLogger creates a firewall logger writing to cfg.Dir/firewall.jsonl.
// Single file, no rotation — designed for SIEM realtime tailing.
func NewVerdictFileLogger(cfg VerdictLoggerConfig) (*VerdictFileLogger, error) {
	if cfg.Dir == "" {
		return nil, fmt.Errorf("verdict logger: dir is required")
	}
	if cfg.AllowSampleN <= 0 {
		cfg.AllowSampleN = 100
	}
	if cfg.FlushInterval <= 0 {
		cfg.FlushInterval = 2 * time.Second
	}
	if cfg.MaxFileSize <= 0 {
		cfg.MaxFileSize = 500 * 1024 * 1024
	}

	if err := os.MkdirAll(cfg.Dir, 0755); err != nil {
		return nil, fmt.Errorf("verdict logger: create dir %s: %w", cfg.Dir, err)
	}

	vl := &VerdictFileLogger{
		cfg:    cfg,
		stopCh: make(chan struct{}),
	}

	if err := vl.openActive(); err != nil {
		return nil, err
	}

	// Background ticker: flush buffer periodically
	go vl.backgroundLoop()

	return vl, nil
}

// Log writes a firewall log entry for SOC/NOC monitoring. Non-blocking: drops on error.
// DROP/BLOCK/REDIRECT are always logged. ALLOW is sampled at 1:N for visibility.
func (vl *VerdictFileLogger) Log(entry VerdictEntry) {
	if vl.stopped.Load() {
		return
	}

	// Filter: skip ALLOWs unless sampling says yes
	if entry.Action == "ALLOW" {
		if !vl.cfg.LogAllows {
			return
		}
		if vl.allowCtr.Add(1)%int64(vl.cfg.AllowSampleN) != 0 {
			return
		}
	}

	if entry.Timestamp == "" {
		entry.Timestamp = time.Now().UTC().Format("2006-01-02T15:04:05.000Z")
	}

	// Auto-populate event_type for SIEM categorization
	if entry.EventType == "" {
		entry.EventType = "firewall"
	}

	// Auto-derive severity from action + detector if not set
	if entry.Severity == "" {
		entry.Severity = deriveSeverity(entry.Action, entry.Detector)
	}

	data, err := json.Marshal(entry)
	if err != nil {
		vl.dropped.Add(1)
		return
	}

	vl.mu.Lock()
	defer vl.mu.Unlock()

	n, err := vl.writer.Write(data)
	if err != nil {
		vl.dropped.Add(1)
		return
	}
	vl.curSize += int64(n)

	if err := vl.writer.WriteByte('\n'); err != nil {
		vl.dropped.Add(1)
		return
	}
	vl.curSize++

	vl.written.Add(1)
}

// Stop flushes and closes the logger.
func (vl *VerdictFileLogger) Stop() error {
	if vl.stopped.Swap(true) {
		return nil
	}
	close(vl.stopCh)

	vl.mu.Lock()
	defer vl.mu.Unlock()
	return vl.closeFile()
}

// Stats returns logger statistics.
func (vl *VerdictFileLogger) Stats() VerdictLoggerStats {
	return VerdictLoggerStats{
		Written: vl.written.Load(),
		Dropped: vl.dropped.Load(),
	}
}

// VerdictLoggerStats holds logger statistics.
type VerdictLoggerStats struct {
	Written int64 `json:"written"`
	Dropped int64 `json:"dropped"`
}

// --- internal ---

func (vl *VerdictFileLogger) openActive() error {
	path := filepath.Join(vl.cfg.Dir, verdictActiveFile)
	f, err := os.OpenFile(path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0644)
	if err != nil {
		return fmt.Errorf("verdict logger: open %s: %w", path, err)
	}

	info, err := f.Stat()
	if err != nil {
		f.Close()
		return err
	}

	vl.file = f
	vl.writer = bufio.NewWriterSize(f, 64*1024)
	vl.curSize = info.Size()
	return nil
}

// truncateFile resets firewall.jsonl when it exceeds MaxFileSize.
// SIEM should have consumed the data by now. This is a safety valve only.
func (vl *VerdictFileLogger) truncateFile() {
	if vl.writer != nil {
		vl.writer.Flush()
	}
	if vl.file != nil {
		vl.file.Truncate(0)
		vl.file.Seek(0, 0)
		vl.writer.Reset(vl.file)
		vl.curSize = 0
	}
}

func (vl *VerdictFileLogger) closeFile() error {
	if vl.writer != nil {
		if err := vl.writer.Flush(); err != nil {
			return err
		}
	}
	if vl.file != nil {
		if err := vl.file.Close(); err != nil {
			return err
		}
		vl.file = nil
		vl.writer = nil
	}
	return nil
}

// backgroundLoop handles periodic flushing and file size safety checks.
func (vl *VerdictFileLogger) backgroundLoop() {
	flushTicker := time.NewTicker(vl.cfg.FlushInterval)
	defer flushTicker.Stop()

	for {
		select {
		case <-vl.stopCh:
			return
		case <-flushTicker.C:
			vl.mu.Lock()
			if vl.writer != nil {
				vl.writer.Flush()
			}
			// Safety: truncate if file exceeds max size (SIEM should have consumed it)
			if vl.cfg.MaxFileSize > 0 && vl.curSize > vl.cfg.MaxFileSize {
				vl.truncateFile()
			}
			vl.mu.Unlock()
		}
	}
}

// deriveSeverity maps action+detector to SOC severity level.
// CRITICAL: DDoS, brute force bans. HIGH: blocks, geo blocks. MEDIUM: drops.
// LOW: rate limits. INFO: allowed traffic.
func deriveSeverity(action, detector string) string {
	switch action {
	case "ALLOW":
		return "INFO"
	case "REDIRECT":
		return "MEDIUM"
	case "BLOCK":
		switch detector {
		case "ddos", "brute_force":
			return "CRITICAL"
		case "geoip", "threat_intel":
			return "HIGH"
		default:
			return "HIGH"
		}
	case "DROP":
		switch detector {
		case "ddos", "brute_force":
			return "CRITICAL"
		case "port_scan", "custom_rule":
			return "HIGH"
		case "rate_limit":
			return "LOW"
		default:
			return "MEDIUM"
		}
	default:
		return "MEDIUM"
	}
}

// ============================================================================
// Enrichment Helpers — Community ID, Traffic Type, Flow ID
// ============================================================================

// flowIDCounter is a monotonic counter for flow identifiers.
var flowIDCounter atomic.Uint64

// NextFlowID returns a monotonically increasing flow identifier.
func NextFlowID() uint64 {
	return flowIDCounter.Add(1)
}

// ComputeCommunityID computes a Community ID v1 hash (Suricata-compatible).
// Format: "1:" + base64(SHA1(seed + ordered_src_ip + ordered_dst_ip + proto + pad + ordered_src_port + ordered_dst_port))
// IPs and ports are ordered so that the same flow always produces the same hash
// regardless of direction.
func ComputeCommunityID(srcIP, dstIP string, srcPort, dstPort uint32, protoNum uint8) string {
	src := net.ParseIP(srcIP)
	dst := net.ParseIP(dstIP)
	if src == nil || dst == nil {
		return ""
	}

	// Normalize to 4-byte IPv4
	src4 := src.To4()
	dst4 := dst.To4()
	if src4 != nil {
		src = src4
	}
	if dst4 != nil {
		dst = dst4
	}

	// Order: lower IP first. If IPs equal, lower port first.
	swap := false
	cmp := compareIPs(src, dst)
	if cmp > 0 {
		swap = true
	} else if cmp == 0 && srcPort > dstPort {
		swap = true
	}

	var orderedSrc, orderedDst net.IP
	var orderedSP, orderedDP uint32
	if swap {
		orderedSrc, orderedDst = dst, src
		orderedSP, orderedDP = dstPort, srcPort
	} else {
		orderedSrc, orderedDst = src, dst
		orderedSP, orderedDP = srcPort, dstPort
	}

	h := sha1.New()
	// Seed = 0 (2 bytes)
	binary.Write(h, binary.BigEndian, uint16(0))
	h.Write(orderedSrc)
	h.Write(orderedDst)
	binary.Write(h, binary.BigEndian, protoNum)
	h.Write([]byte{0}) // padding
	binary.Write(h, binary.BigEndian, uint16(orderedSP))
	binary.Write(h, binary.BigEndian, uint16(orderedDP))

	return "1:" + base64.StdEncoding.EncodeToString(h.Sum(nil))
}

// compareIPs compares two net.IP byte slices. Returns -1, 0, or 1.
func compareIPs(a, b net.IP) int {
	aLen, bLen := len(a), len(b)
	minLen := aLen
	if bLen < minLen {
		minLen = bLen
	}
	for i := 0; i < minLen; i++ {
		if a[i] < b[i] {
			return -1
		}
		if a[i] > b[i] {
			return 1
		}
	}
	if aLen < bLen {
		return -1
	}
	if aLen > bLen {
		return 1
	}
	return 0
}

// ClassifyDirection determines if traffic is north_south (one endpoint public)
// or east_west (both endpoints private RFC1918).
func ClassifyDirection(srcIP, dstIP string) string {
	srcPrivate := isPrivateIP(srcIP)
	dstPrivate := isPrivateIP(dstIP)
	if srcPrivate && dstPrivate {
		return "east_west"
	}
	return "north_south"
}

// ClassifyTrafficType determines traffic type based on IP classification.
// inbound = public src → private dst, outbound = private src → public dst,
// internal = both private.
func ClassifyTrafficType(srcIP, dstIP string) string {
	srcPrivate := isPrivateIP(srcIP)
	dstPrivate := isPrivateIP(dstIP)
	if srcPrivate && dstPrivate {
		return "internal"
	}
	if srcPrivate && !dstPrivate {
		return "outbound"
	}
	if !srcPrivate && dstPrivate {
		return "inbound"
	}
	return "transit"
}

// ProtocolNumber converts protocol name to IANA number.
func ProtocolNumber(proto string) uint8 {
	switch proto {
	case "TCP":
		return 6
	case "UDP":
		return 17
	case "ICMP":
		return 1
	default:
		return 0
	}
}

// isPrivateIP returns true if the IP is RFC1918 or loopback.
func isPrivateIP(ipStr string) bool {
	ip := net.ParseIP(ipStr)
	if ip == nil {
		return false
	}
	// Standard private ranges
	for _, cidr := range privateRanges {
		if cidr.Contains(ip) {
			return true
		}
	}
	return false
}

var privateRanges = func() []*net.IPNet {
	cidrs := []string{
		"10.0.0.0/8",
		"172.16.0.0/12",
		"192.168.0.0/16",
		"127.0.0.0/8",
		"169.254.0.0/16",
		"::1/128",
		"fc00::/7",
		"fe80::/10",
	}
	var nets []*net.IPNet
	for _, c := range cidrs {
		_, n, _ := net.ParseCIDR(c)
		if n != nil {
			nets = append(nets, n)
		}
	}
	return nets
}()

// TCPFlagsToString converts TCP flags bitmask to readable string.
// e.g., 0x02 = "S", 0x12 = "SA", 0x04 = "R"
func TCPFlagsToString(flags uint32) string {
	if flags == 0 {
		return ""
	}
	var s []byte
	if flags&0x20 != 0 {
		s = append(s, 'U')
	}
	if flags&0x10 != 0 {
		s = append(s, 'A')
	}
	if flags&0x08 != 0 {
		s = append(s, 'P')
	}
	if flags&0x04 != 0 {
		s = append(s, 'R')
	}
	if flags&0x02 != 0 {
		s = append(s, 'S')
	}
	if flags&0x01 != 0 {
		s = append(s, 'F')
	}
	return string(s)
}
