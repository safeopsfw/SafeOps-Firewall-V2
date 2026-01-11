package dedup

import (
	"crypto/md5"
	"fmt"
	"sync"
	"time"

	"github.com/safeops/network_logger/pkg/models"
)

// Engine manages packet deduplication
type Engine struct {
	cache       map[string]int64 // signature -> timestamp
	mu          sync.RWMutex
	maxSize     int
	windowSecs  int64
	stats       map[string]int64
	statsM      sync.RWMutex
}

// NewEngine creates a new deduplication engine
func NewEngine(maxSize int, windowSecs int64) *Engine {
	return &Engine{
		cache:      make(map[string]int64),
		maxSize:    maxSize,
		windowSecs: windowSecs,
		stats:      make(map[string]int64),
	}
}

// ShouldLog determines if a packet should be logged
// Smart dedup: Prevent spam but don't lose important data
func (e *Engine) ShouldLog(pkt *models.PacketLog) (shouldLog bool, reason string) {
	// ALWAYS log DNS (critical for threat detection)
	if pkt.ParsedApplication.DetectedProtocol == "dns" {
		e.incrementStat("dns_protocol")
		return true, "dns_protocol"
	}

	// ALWAYS log HTTP (web traffic analysis)
	if pkt.ParsedApplication.DetectedProtocol == "http" {
		e.incrementStat("http_protocol")
		return true, "http_protocol"
	}

	// ALWAYS log TLS handshake (security analysis)
	if pkt.ParsedApplication.DetectedProtocol == "tls" {
		e.incrementStat("tls_protocol")
		return true, "tls_protocol"
	}

	// ALWAYS log critical ports (SSH, RDP, SMB, etc.)
	if e.isCriticalPort(pkt) {
		e.incrementStat("critical_port")
		return true, "critical_port"
	}

	// ALWAYS log TCP control packets (connection tracking)
	if pkt.Layers.Transport != nil && pkt.Layers.Transport.TCPFlags != nil {
		flags := pkt.Layers.Transport.TCPFlags
		if flags.SYN || flags.FIN || flags.RST {
			e.incrementStat("tcp_control")
			return true, "tcp_control"
		}
	}

	// ALWAYS log DHCP (device discovery)
	if pkt.Layers.Transport != nil {
		if pkt.Layers.Transport.SrcPort == 67 || pkt.Layers.Transport.DstPort == 67 ||
			pkt.Layers.Transport.SrcPort == 68 || pkt.Layers.Transport.DstPort == 68 {
			e.incrementStat("dhcp_protocol")
			return true, "dhcp_protocol"
		}
	}

	// Check for duplicate (spam prevention only)
	sig := e.computeSignature(pkt)
	if e.isDuplicate(sig) {
		e.incrementStat("duplicate_spam")
		return false, "duplicate_spam"
	}

	// Add to cache
	e.addToCache(sig)
	e.incrementStat("unique")
	return true, "unique"
}

// computeSignature generates a signature for the packet
func (e *Engine) computeSignature(pkt *models.PacketLog) string {
	var sig string

	if pkt.Layers.Network != nil && pkt.Layers.Transport != nil {
		// Include: src_ip, dst_ip, src_port, dst_port, protocol, payload_hash
		payloadHash := ""
		if pkt.Layers.Payload != nil && len(pkt.Layers.Payload.DataHex) > 0 {
			hash := md5.Sum([]byte(pkt.Layers.Payload.DataHex))
			payloadHash = fmt.Sprintf("%x", hash)
		}

		sig = fmt.Sprintf("%s:%d-%s:%d-%s",
			pkt.Layers.Network.SrcIP,
			pkt.Layers.Transport.SrcPort,
			pkt.Layers.Network.DstIP,
			pkt.Layers.Transport.DstPort,
			payloadHash,
		)
	} else {
		// Fallback: use packet ID
		sig = pkt.PacketID
	}

	return sig
}

// isDuplicate checks if signature exists in cache
func (e *Engine) isDuplicate(sig string) bool {
	e.mu.RLock()
	defer e.mu.RUnlock()

	timestamp, exists := e.cache[sig]
	if !exists {
		return false
	}

	// Check if within window
	now := time.Now().Unix()
	if now-timestamp > e.windowSecs {
		return false
	}

	return true
}

// addToCache adds signature to cache
func (e *Engine) addToCache(sig string) {
	e.mu.Lock()
	defer e.mu.Unlock()

	// Cleanup if cache is full
	if len(e.cache) >= e.maxSize {
		e.cleanupOldEntries()
	}

	e.cache[sig] = time.Now().Unix()
}

// cleanupOldEntries removes old cache entries
func (e *Engine) cleanupOldEntries() {
	now := time.Now().Unix()

	for sig, timestamp := range e.cache {
		if now-timestamp > e.windowSecs {
			delete(e.cache, sig)
		}
	}

	// If still too large, remove 10% oldest
	if len(e.cache) >= e.maxSize {
		toRemove := e.maxSize / 10
		removed := 0
		for sig := range e.cache {
			delete(e.cache, sig)
			removed++
			if removed >= toRemove {
				break
			}
		}
	}
}

// isCriticalPort checks if packet uses a critical port
func (e *Engine) isCriticalPort(pkt *models.PacketLog) bool {
	if pkt.Layers.Transport == nil {
		return false
	}

	criticalPorts := []uint16{
		21,   // FTP
		22,   // SSH
		23,   // Telnet
		25,   // SMTP
		53,   // DNS (fallback)
		80,   // HTTP (fallback)
		110,  // POP3
		143,  // IMAP
		443,  // HTTPS (fallback)
		445,  // SMB
		3306, // MySQL
		3389, // RDP
		5432, // PostgreSQL
		5900, // VNC
		6379, // Redis
		8080, // HTTP Alt
		8443, // HTTPS Alt
	}

	srcPort := pkt.Layers.Transport.SrcPort
	dstPort := pkt.Layers.Transport.DstPort

	for _, port := range criticalPorts {
		if srcPort == port || dstPort == port {
			return true
		}
	}

	return false
}

// incrementStat increments a statistic counter
func (e *Engine) incrementStat(key string) {
	e.statsM.Lock()
	defer e.statsM.Unlock()

	e.stats[key]++
}

// GetStats returns deduplication statistics
func (e *Engine) GetStats() map[string]int64 {
	e.statsM.RLock()
	defer e.statsM.RUnlock()

	// Create copy
	stats := make(map[string]int64)
	for k, v := range e.stats {
		stats[k] = v
	}

	return stats
}

// GetCacheSize returns current cache size
func (e *Engine) GetCacheSize() int {
	e.mu.RLock()
	defer e.mu.RUnlock()

	return len(e.cache)
}
