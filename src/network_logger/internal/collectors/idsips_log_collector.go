package collectors

import (
	"bufio"
	"context"
	"encoding/json"
	"log"
	"net"
	"os"
	"sync"
	"time"

	"github.com/safeops/network_logger/pkg/models"
)

// IDSLog represents a compact IDS alert log
type IDSLog struct {
	TimestampIST string           `json:"timestamp_ist"`
	PacketID     string           `json:"packet_id"`
	SrcIP        string           `json:"src_ip"`
	DstIP        string           `json:"dst_ip"`
	SrcPort      uint16           `json:"src_port,omitempty"`
	DstPort      uint16           `json:"dst_port,omitempty"`
	Protocol     string           `json:"protocol"`
	SrcGeo       *models.GeoInfo  `json:"src_geo,omitempty"`
	DstGeo       *models.GeoInfo  `json:"dst_geo,omitempty"`
	HTTP         *models.HTTPData `json:"http,omitempty"`
	DNS          *models.DNSData  `json:"dns,omitempty"`
	TLS          *TLSCompact      `json:"tls,omitempty"`
	TCPFlags     string           `json:"tcp_flags,omitempty"`
}

// TLSCompact is a compact TLS representation for IDS logs
type TLSCompact struct {
	SNI     string `json:"sni,omitempty"`
	Version string `json:"version,omitempty"`
}

// IDSCollector processes packets into IDS alerts
type IDSCollector struct {
	logPath       string
	batchQueue    chan *IDSLog
	mu            sync.Mutex
	file          *os.File
	writer        *bufio.Writer
	batchSize     int
	logsWritten   int64
	cycleInterval time.Duration
}

// NewIDSCollector creates a new IDS collector
func NewIDSCollector(logPath string, cycleInterval time.Duration) *IDSCollector {
	return &IDSCollector{
		logPath:       logPath,
		batchQueue:    make(chan *IDSLog, 5000),
		batchSize:     50,
		cycleInterval: cycleInterval,
	}
}

// Start begins the IDS collector
func (c *IDSCollector) Start(ctx context.Context) {
	c.openFile()
	go c.batchWriter(ctx)
	go c.cycleLoop(ctx)
}

// Process processes a packet and generates IDS log if applicable
func (c *IDSCollector) Process(pkt *models.PacketLog) {
	// Only log packets with application layer data
	if !c.hasAppLayerData(pkt) {
		return
	}

	// Skip TCP handshakes and pure ACKs
	if c.isTCPControl(pkt) {
		return
	}

	// Convert to IDS log
	idsLog := c.toIDSLog(pkt)
	if idsLog == nil {
		return
	}

	select {
	case c.batchQueue <- idsLog:
	default:
		// Queue full, drop
	}
}

// hasAppLayerData checks if packet has ACTUAL meaningful app layer content
// Only returns true if there's a domain, host, query, or SNI to log
func (c *IDSCollector) hasAppLayerData(pkt *models.PacketLog) bool {
	app := pkt.ParsedApplication

	// HTTP: must have host or method
	if app.HTTP != nil && (app.HTTP.Host != "" || app.HTTP.Method != "") {
		return true
	}

	// DNS: must have query
	if app.DNS != nil && len(app.DNS.Queries) > 0 {
		return true
	}

	// TLS: must have SNI
	if app.TLS != nil && app.TLS.ClientHello != nil && app.TLS.ClientHello.SNI != "" {
		return true
	}

	// SSH/FTP/SMTP: any parsed data
	if app.DetectedProtocol == "ssh" || app.DetectedProtocol == "ftp" || app.DetectedProtocol == "smtp" {
		return true
	}

	return false
}

// isTCPControl checks if packet is TCP control (handshake/close)
func (c *IDSCollector) isTCPControl(pkt *models.PacketLog) bool {
	if pkt.Layers.Transport == nil || pkt.Layers.Transport.TCPFlags == nil {
		return false
	}
	flags := pkt.Layers.Transport.TCPFlags

	// Skip SYN, SYN-ACK, FIN, RST
	if flags.SYN || flags.FIN || flags.RST {
		return true
	}
	// Skip pure ACKs (no PSH)
	if flags.ACK && !flags.PSH && !flags.SYN && !flags.FIN && !flags.RST {
		return true
	}
	return false
}

// toIDSLog converts a packet to IDS log format
func (c *IDSCollector) toIDSLog(pkt *models.PacketLog) *IDSLog {
	if pkt.Layers.Network == nil {
		return nil
	}

	// IST timestamp (UTC+5:30)
	ist := pkt.Timestamp.ISO8601 // Already has timezone

	idsLog := &IDSLog{
		TimestampIST: ist,
		PacketID:     pkt.PacketID,
		SrcIP:        pkt.Layers.Network.SrcIP,
		DstIP:        pkt.Layers.Network.DstIP,
		SrcGeo:       pkt.SrcGeo,
		DstGeo:       pkt.DstGeo,
	}

	// Protocol
	switch pkt.Layers.Network.Protocol {
	case 6:
		idsLog.Protocol = "TCP"
	case 17:
		idsLog.Protocol = "UDP"
	case 1:
		idsLog.Protocol = "ICMP"
	default:
		idsLog.Protocol = "OTHER"
	}

	// Ports
	if pkt.Layers.Transport != nil {
		idsLog.SrcPort = pkt.Layers.Transport.SrcPort
		idsLog.DstPort = pkt.Layers.Transport.DstPort

		// TCP flags
		if pkt.Layers.Transport.TCPFlags != nil {
			idsLog.TCPFlags = formatTCPFlags(pkt.Layers.Transport.TCPFlags)
		}
	}

	// App layer data
	if pkt.ParsedApplication.HTTP != nil {
		idsLog.HTTP = pkt.ParsedApplication.HTTP
	}
	if pkt.ParsedApplication.DNS != nil {
		idsLog.DNS = pkt.ParsedApplication.DNS
	}
	if pkt.ParsedApplication.TLS != nil && pkt.ParsedApplication.TLS.ClientHello != nil {
		idsLog.TLS = &TLSCompact{
			SNI:     pkt.ParsedApplication.TLS.ClientHello.SNI,
			Version: pkt.ParsedApplication.TLS.ClientHello.Version,
		}
	}

	return idsLog
}

func (c *IDSCollector) openFile() error {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.file != nil {
		if c.writer != nil {
			c.writer.Flush()
		}
		c.file.Close()
	}

	// Note: log directory is created by main.go with absolute path

	file, err := os.OpenFile(c.logPath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0644)
	if err != nil {
		return err
	}

	c.file = file
	c.writer = bufio.NewWriter(file)
	c.logsWritten = 0
	return nil
}

func (c *IDSCollector) batchWriter(ctx context.Context) {
	batch := make([]*IDSLog, 0, c.batchSize)
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
		case log := <-c.batchQueue:
			batch = append(batch, log)
			if len(batch) >= c.batchSize {
				c.writeBatch(batch)
				batch = make([]*IDSLog, 0, c.batchSize)
			}
		case <-ticker.C:
			if len(batch) > 0 {
				c.writeBatch(batch)
				batch = make([]*IDSLog, 0, c.batchSize)
			}
		}
	}
}

func (c *IDSCollector) writeBatch(batch []*IDSLog) {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.writer == nil {
		return
	}

	for _, log := range batch {
		data, err := json.Marshal(log)
		if err != nil {
			continue
		}
		c.writer.Write(data)
		c.writer.WriteByte('\n')
		c.logsWritten++
	}
	c.writer.Flush()
}

func (c *IDSCollector) cycleLoop(ctx context.Context) {
	ticker := time.NewTicker(c.cycleInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			log.Printf("🔄 IDS log cycled (5-min rotation)")
			c.openFile()
		}
	}
}

func (c *IDSCollector) closeFile() {
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
func (c *IDSCollector) GetStats() map[string]interface{} {
	c.mu.Lock()
	defer c.mu.Unlock()
	return map[string]interface{}{
		"logs_written": c.logsWritten,
		"queue_size":   len(c.batchQueue),
	}
}

// formatTCPFlags formats TCP flags as a string
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

// isPrivateIP checks if IP is private
func isPrivateIP(ipStr string) bool {
	ip := net.ParseIP(ipStr)
	if ip == nil {
		return false
	}
	privateRanges := []string{
		"10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16",
		"127.0.0.0/8", "169.254.0.0/16",
	}
	for _, cidr := range privateRanges {
		_, network, _ := net.ParseCIDR(cidr)
		if network.Contains(ip) {
			return true
		}
	}
	return false
}
