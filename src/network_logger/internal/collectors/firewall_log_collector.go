package collectors

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
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

// FirewallCollector processes packets into firewall logs with connection-level deduplication
type FirewallCollector struct {
	logPath       string
	batchQueue    chan *FirewallLog
	mu            sync.Mutex
	file          *os.File
	writer        *bufio.Writer
	batchSize     int
	logsWritten   int64
	logsDropped   int64 // Deduplicated/dropped logs
	cycleInterval time.Duration

	// Connection-level deduplication
	connCache   map[string]int64 // connection_key -> last_seen_unix_timestamp
	connCacheMu sync.RWMutex
	dedupWindow int64 // Seconds to suppress duplicate connections
}

const (
	maxConnCacheSize = 50000    // Max connections to track
	maxFileSizeBytes = 10 << 20 // 10 MB - force rotate if exceeded
)

// NewFirewallCollector creates a new firewall collector with connection dedup
func NewFirewallCollector(logPath string, cycleInterval time.Duration) *FirewallCollector {
	return &FirewallCollector{
		logPath:       logPath,
		batchQueue:    make(chan *FirewallLog, 5000),
		batchSize:     50,
		cycleInterval: cycleInterval,
		connCache:     make(map[string]int64),
		dedupWindow:   30, // 30 second dedup window per connection
	}
}

// Start begins the firewall collector
func (c *FirewallCollector) Start(ctx context.Context) {
	c.openFile()
	go c.batchWriter(ctx)
	go c.cycleLoop(ctx)
	go c.connCacheCleanup(ctx)
}

// Process processes a packet and generates firewall log
// Uses connection-level deduplication to reduce log volume
func (c *FirewallCollector) Process(pkt *models.PacketLog) {
	if pkt.Layers.Network == nil {
		return
	}

	// Check if this is a TCP control packet (always log these)
	isTCPControl := c.isTCPControlPacket(pkt)

	// For non-control packets, apply connection-level dedup
	if !isTCPControl {
		connKey := c.generateConnectionKey(pkt)
		if !c.shouldLogConnection(connKey) {
			c.mu.Lock()
			c.logsDropped++
			c.mu.Unlock()
			return // Duplicate connection within window, skip
		}
	}

	fwLog := c.toFirewallLog(pkt)
	if fwLog == nil {
		return
	}

	select {
	case c.batchQueue <- fwLog:
	default:
		// Queue full, drop this log
		c.mu.Lock()
		c.logsDropped++
		c.mu.Unlock()
	}
}

// isTCPControlPacket checks if packet is SYN, FIN, or RST
func (c *FirewallCollector) isTCPControlPacket(pkt *models.PacketLog) bool {
	if pkt.Layers.Transport == nil || pkt.Layers.Transport.TCPFlags == nil {
		return false
	}
	flags := pkt.Layers.Transport.TCPFlags
	return flags.SYN || flags.FIN || flags.RST
}

// generateConnectionKey creates a unique key for this connection
func (c *FirewallCollector) generateConnectionKey(pkt *models.PacketLog) string {
	if pkt.Layers.Network == nil {
		return ""
	}

	srcIP := pkt.Layers.Network.SrcIP
	dstIP := pkt.Layers.Network.DstIP
	var srcPort, dstPort uint16
	proto := "other"

	if pkt.Layers.Transport != nil {
		srcPort = pkt.Layers.Transport.SrcPort
		dstPort = pkt.Layers.Transport.DstPort
		if pkt.Layers.Network.Protocol == 6 {
			proto = "tcp"
		} else if pkt.Layers.Network.Protocol == 17 {
			proto = "udp"
		}
	}

	// Normalize: ensure consistent ordering (lower IP first)
	if srcIP > dstIP || (srcIP == dstIP && srcPort > dstPort) {
		srcIP, dstIP = dstIP, srcIP
		srcPort, dstPort = dstPort, srcPort
	}

	return fmt.Sprintf("%s:%d-%s:%d-%s", srcIP, srcPort, dstIP, dstPort, proto)
}

// shouldLogConnection checks if this connection should be logged (not a duplicate)
func (c *FirewallCollector) shouldLogConnection(connKey string) bool {
	if connKey == "" {
		return true // Can't determine, log it
	}

	now := time.Now().Unix()

	c.connCacheMu.RLock()
	lastSeen, exists := c.connCache[connKey]
	c.connCacheMu.RUnlock()

	if exists && (now-lastSeen) < c.dedupWindow {
		return false // Within dedup window, skip
	}

	// Update cache
	c.connCacheMu.Lock()
	c.connCache[connKey] = now
	c.connCacheMu.Unlock()

	return true
}

// connCacheCleanup periodically cleans up old connection entries
func (c *FirewallCollector) connCacheCleanup(ctx context.Context) {
	ticker := time.NewTicker(60 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			c.cleanupConnCache()
		}
	}
}

// cleanupConnCache removes expired entries from connection cache
func (c *FirewallCollector) cleanupConnCache() {
	c.connCacheMu.Lock()
	defer c.connCacheMu.Unlock()

	now := time.Now().Unix()
	expireThreshold := c.dedupWindow * 2 // Keep for 2x window

	// Remove expired entries
	for key, timestamp := range c.connCache {
		if now-timestamp > expireThreshold {
			delete(c.connCache, key)
		}
	}

	// If still too large, remove oldest 20%
	if len(c.connCache) > maxConnCacheSize {
		toRemove := len(c.connCache) / 5
		removed := 0
		for key := range c.connCache {
			delete(c.connCache, key)
			removed++
			if removed >= toRemove {
				break
			}
		}
	}
}

// toFirewallLog converts a packet to firewall log format
func (c *FirewallCollector) toFirewallLog(pkt *models.PacketLog) *FirewallLog {
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

	// Note: log directory is created by main.go with absolute path

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

// checkFileSize checks if file exceeds max size and triggers rotation
func (c *FirewallCollector) checkFileSize() bool {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.file == nil {
		return false
	}

	info, err := c.file.Stat()
	if err != nil {
		return false
	}

	return info.Size() > maxFileSizeBytes
}

func (c *FirewallCollector) batchWriter(ctx context.Context) {
	batch := make([]*FirewallLog, 0, c.batchSize)
	ticker := time.NewTicker(500 * time.Millisecond)
	sizeCheckTicker := time.NewTicker(10 * time.Second)
	defer ticker.Stop()
	defer sizeCheckTicker.Stop()

	for {
		select {
		case <-ctx.Done():
			if len(batch) > 0 {
				c.writeBatch(batch)
			}
			c.closeFile()
			return
		case fwLog := <-c.batchQueue:
			batch = append(batch, fwLog)
			if len(batch) >= c.batchSize {
				c.writeBatch(batch)
				batch = make([]*FirewallLog, 0, c.batchSize)
			}
		case <-ticker.C:
			if len(batch) > 0 {
				c.writeBatch(batch)
				batch = make([]*FirewallLog, 0, c.batchSize)
			}
		case <-sizeCheckTicker.C:
			// Force rotate if file too large
			if c.checkFileSize() {
				log.Printf("⚠️ Firewall log exceeded 10MB, forcing rotation")
				c.openFile()
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
			logsDropped := c.logsDropped
			c.logsDropped = 0 // Reset dropped counter
			c.mu.Unlock()

			log.Printf("🔄 Firewall log rotated: %d logs written, %d deduplicated", logsWritten, logsDropped)
			c.openFile()

			// Clear connection cache on rotation for fresh dedup window
			c.connCacheMu.Lock()
			c.connCache = make(map[string]int64)
			c.connCacheMu.Unlock()
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
	logsDropped := c.logsDropped
	queueSize := len(c.batchQueue)
	c.mu.Unlock()

	c.connCacheMu.RLock()
	connCacheSize := len(c.connCache)
	c.connCacheMu.RUnlock()

	return map[string]interface{}{
		"logs_written":      logsWritten,
		"logs_deduplicated": logsDropped,
		"queue_size":        queueSize,
		"conn_cache_size":   connCacheSize,
	}
}
