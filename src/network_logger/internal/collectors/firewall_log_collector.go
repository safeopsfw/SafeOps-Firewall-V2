package collectors

import (
	"bufio"
	"context"
	"encoding/json"
	"log"
	"os"
	"sync"
	"time"

	"github.com/safeops/network_logger/pkg/models"
)

// FirewallLog represents a firewall log entry
type FirewallLog struct {
	Action       string          `json:"action"`
	Reason       string          `json:"reason"`
	TimestampIST string          `json:"timestamp_ist"`
	EventID      string          `json:"event_id"`
	SrcIP        string          `json:"src_ip"`
	DstIP        string          `json:"dst_ip"`
	SrcPort      uint16          `json:"src_port,omitempty"`
	DstPort      uint16          `json:"dst_port,omitempty"`
	Protocol     string          `json:"protocol"`
	Direction    string          `json:"direction"`
	SrcGeo       *models.GeoInfo `json:"src_geo,omitempty"`
	DstGeo       *models.GeoInfo `json:"dst_geo,omitempty"`
	TCPFlags     string          `json:"tcp_flags,omitempty"`
	TotalBytes   int64           `json:"total_bytes,omitempty"`
	TLSSni       string          `json:"tls_sni,omitempty"`
}

// FirewallCollector processes packets into firewall logs
type FirewallCollector struct {
	logPath       string
	batchQueue    chan *FirewallLog
	mu            sync.Mutex
	file          *os.File
	writer        *bufio.Writer
	batchSize     int
	logsWritten   int64
	cycleInterval time.Duration
}

// NewFirewallCollector creates a new firewall collector
func NewFirewallCollector(logPath string, cycleInterval time.Duration) *FirewallCollector {
	return &FirewallCollector{
		logPath:       logPath,
		batchQueue:    make(chan *FirewallLog, 5000),
		batchSize:     50,
		cycleInterval: cycleInterval,
	}
}

// Start begins the firewall collector
func (c *FirewallCollector) Start(ctx context.Context) {
	c.openFile()
	go c.batchWriter(ctx)
	go c.cycleLoop(ctx)
}

// Process processes a packet and generates firewall log
func (c *FirewallCollector) Process(pkt *models.PacketLog) {
	if pkt.Layers.Network == nil {
		return
	}

	fwLog := c.toFirewallLog(pkt)
	if fwLog == nil {
		return
	}

	select {
	case c.batchQueue <- fwLog:
	default:
	}
}

// toFirewallLog converts a packet to firewall log format
func (c *FirewallCollector) toFirewallLog(pkt *models.PacketLog) *FirewallLog {
	// Determine action based on TCP flags
	action, reason := c.determineAction(pkt)

	fwLog := &FirewallLog{
		Action:       action,
		Reason:       reason,
		TimestampIST: pkt.Timestamp.ISO8601,
		EventID:      pkt.PacketID,
		SrcIP:        pkt.Layers.Network.SrcIP,
		DstIP:        pkt.Layers.Network.DstIP,
		SrcGeo:       pkt.SrcGeo,
		DstGeo:       pkt.DstGeo,
	}

	// Protocol
	switch pkt.Layers.Network.Protocol {
	case 6:
		fwLog.Protocol = "TCP"
	case 17:
		fwLog.Protocol = "UDP"
	case 1:
		fwLog.Protocol = "ICMP"
	default:
		fwLog.Protocol = "OTHER"
	}

	// Direction
	fwLog.Direction = c.classifyDirection(pkt.Layers.Network.SrcIP, pkt.Layers.Network.DstIP)

	// Ports
	if pkt.Layers.Transport != nil {
		fwLog.SrcPort = pkt.Layers.Transport.SrcPort
		fwLog.DstPort = pkt.Layers.Transport.DstPort

		if pkt.Layers.Transport.TCPFlags != nil {
			fwLog.TCPFlags = formatTCPFlags(pkt.Layers.Transport.TCPFlags)
		}
	}

	// Flow context
	if pkt.FlowContext != nil {
		fwLog.TotalBytes = pkt.FlowContext.BytesForward + pkt.FlowContext.BytesBackward
	}

	// TLS SNI
	if pkt.ParsedApplication.TLS != nil && pkt.ParsedApplication.TLS.ClientHello != nil {
		fwLog.TLSSni = pkt.ParsedApplication.TLS.ClientHello.SNI
	}

	return fwLog
}

// determineAction determines firewall action based on packet
func (c *FirewallCollector) determineAction(pkt *models.PacketLog) (string, string) {
	if pkt.Layers.Transport != nil && pkt.Layers.Transport.TCPFlags != nil {
		flags := pkt.Layers.Transport.TCPFlags
		if flags.RST {
			return "drop", "RST flag"
		}
		if flags.FIN {
			return "allow", "FIN flag"
		}
		if flags.SYN && !flags.ACK {
			return "allow", "SYN"
		}
		if flags.SYN && flags.ACK {
			return "allow", "SYN-ACK"
		}
	}
	return "allow", "Implicit allow"
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

	os.MkdirAll("../../logs", 0755)

	file, err := os.OpenFile(c.logPath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0644)
	if err != nil {
		return err
	}

	c.file = file
	c.writer = bufio.NewWriter(file)
	c.logsWritten = 0
	return nil
}

func (c *FirewallCollector) batchWriter(ctx context.Context) {
	batch := make([]*FirewallLog, 0, c.batchSize)
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
				batch = make([]*FirewallLog, 0, c.batchSize)
			}
		case <-ticker.C:
			if len(batch) > 0 {
				c.writeBatch(batch)
				batch = make([]*FirewallLog, 0, c.batchSize)
			}
		}
	}
}

func (c *FirewallCollector) writeBatch(batch []*FirewallLog) {
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

func (c *FirewallCollector) cycleLoop(ctx context.Context) {
	ticker := time.NewTicker(c.cycleInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			log.Printf("🔄 Firewall log cycled (5-min rotation)")
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
	defer c.mu.Unlock()
	return map[string]interface{}{
		"logs_written": c.logsWritten,
		"queue_size":   len(c.batchQueue),
	}
}
