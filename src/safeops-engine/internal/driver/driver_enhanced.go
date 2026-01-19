package driver

import (
	"net"
	"sync"
	"sync/atomic"
	"time"

	"safeops-engine/internal/logger"
	"safeops-engine/internal/metadata"
	"safeops-engine/internal/parser"
	"safeops-engine/internal/verdict"
)

// EnhancedDriver extends Driver with verdict engine and metadata extraction
type EnhancedDriver struct {
	*Driver // Embed base driver

	// Verdict engine for blocking/redirecting
	verdict *verdict.Engine

	// Parsers for domain extraction
	dnsParser  *parser.DNSParser
	tlsParser  *parser.TLSParser
	httpParser *parser.HTTPParser
	dhcpParser *parser.DHCPParser

	// Metadata stream for IDS/IPS
	metadataStream *metadata.MetadataStream

	// Flow tracking
	flows     sync.Map // metadata.FlowKey → *metadata.FlowStats
	flowCount uint64

	// IP statistics tracking
	ipStats sync.Map // string(IP) → *metadata.IPStats

	// DNS cache (IP → Domain mapping)
	dnsCache     sync.Map // string(IP) → string(Domain)
	dnsCacheTTL  sync.Map // string(IP) → time.Time (expiry)

	// MAC address cache for verdict injection
	macCache sync.Map // string(IP) → [6]byte

	// Statistics
	domainsExtracted uint64
	flowsTracked     uint64
	metadataSent     uint64
	metadataDropped  uint64
}

// NewEnhanced creates an enhanced driver with verdict engine and parsers
func NewEnhanced(log *logger.Logger, metadataBufferSize int) (*EnhancedDriver, error) {
	baseDriver, err := Open(log)
	if err != nil {
		return nil, err
	}

	ed := &EnhancedDriver{
		Driver:         baseDriver,
		verdict:        verdict.New(baseDriver.api),
		dnsParser:      parser.NewDNSParser(),
		tlsParser:      parser.NewTLSParser(),
		httpParser:     parser.NewHTTPParser(),
		dhcpParser:     parser.NewDHCPParser(),
		metadataStream: metadata.NewMetadataStream(metadataBufferSize),
	}

	// Set enhanced packet handler
	baseDriver.SetHandler(ed.handlePacketEnhanced)

	log.Info("Enhanced driver initialized", map[string]interface{}{
		"metadata_buffer": metadataBufferSize,
	})

	return ed, nil
}

// GetVerdictEngine returns the verdict engine for external control
func (ed *EnhancedDriver) GetVerdictEngine() *verdict.Engine {
	return ed.verdict
}

// GetMetadataStream returns the metadata stream for IDS/IPS
func (ed *EnhancedDriver) GetMetadataStream() *metadata.MetadataStream {
	return ed.metadataStream
}

// handlePacketEnhanced is the main packet handler with verdict and metadata extraction
func (ed *EnhancedDriver) handlePacketEnhanced(pkt *ParsedPacket) bool {
	// === STEP 1: Check verdict engine (FAST PATH) ===
	// Check IP blocklist
	if v := ed.verdict.CheckIP(pkt.DstIP); v != verdict.VerdictAllow {
		ed.handleVerdict(pkt, v)
		return false // DROP
	}

	// Check port blocklist
	if v := ed.verdict.CheckPort(pkt.DstPort); v != verdict.VerdictAllow {
		ed.handleVerdict(pkt, v)
		return false // DROP
	}

	// === STEP 2: Extract MAC addresses (cache for future verdict injection) ===
	ed.cacheMACAddresses(pkt)

	// === STEP 3: Extract domain and metadata ===
	meta := ed.extractMetadata(pkt)

	// === STEP 4: Update flow tracking ===
	ed.updateFlowTracking(pkt, meta)

	// === STEP 5: Update IP statistics ===
	ed.updateIPStats(pkt, meta)

	// === STEP 6: Check DNS redirect ===
	if meta.IsDNSQuery && meta.Domain != "" {
		if redirectIP, shouldRedirect := ed.verdict.CheckDNSRedirect(meta.Domain); shouldRedirect {
			ed.injectDNSRedirect(pkt, meta.Domain, redirectIP)
			return false // Drop original query
		}
	}

	// === STEP 7: Send metadata to IDS/IPS (non-blocking) ===
	if ed.metadataStream.Send(meta) {
		atomic.AddUint64(&ed.metadataSent, 1)
	} else {
		atomic.AddUint64(&ed.metadataDropped, 1)
	}

	// === STEP 8: Always forward (unless blocked above) ===
	return true // ALLOW
}

// extractMetadata extracts all available metadata from packet
func (ed *EnhancedDriver) extractMetadata(pkt *ParsedPacket) *metadata.PacketMetadata {
	meta := &metadata.PacketMetadata{
		Timestamp:   time.Now().UnixNano(),
		SrcIP:       pkt.SrcIP.String(),
		DstIP:       pkt.DstIP.String(),
		SrcPort:     pkt.SrcPort,
		DstPort:     pkt.DstPort,
		Protocol:    pkt.Protocol,
		PacketSize:  uint16(len(pkt.RawBuffer.Buffer[:pkt.RawBuffer.Length])),
		AdapterName: pkt.AdapterName,
	}

	if pkt.Direction == DirectionInbound {
		meta.Direction = "INBOUND"
	} else {
		meta.Direction = "OUTBOUND"
	}

	// === Extract domain based on protocol ===
	switch pkt.DstPort {
	case 53: // DNS
		meta.IsDNSQuery = ed.dnsParser.IsDNSQuery(pkt.Payload)
		if meta.IsDNSQuery {
			domain := ed.dnsParser.ExtractDomain(pkt.Payload)
			if domain != "" {
				meta.Domain = domain
				meta.DomainSource = "DNS"
				atomic.AddUint64(&ed.domainsExtracted, 1)
			}
		} else {
			meta.IsDNSResponse = !meta.IsDNSQuery
			// Cache DNS response for IP→Domain mapping
			ed.cacheDNSResponse(pkt)
		}

	case 443: // HTTPS
		// Try to extract SNI from TLS ClientHello
		sni := ed.tlsParser.ExtractSNI(pkt.Payload)
		if sni != "" {
			meta.Domain = sni
			meta.DomainSource = "SNI"
			meta.IsHTTPSProbe = true
			atomic.AddUint64(&ed.domainsExtracted, 1)

			// Cache SNI → IP mapping
			ed.dnsCache.Store(pkt.DstIP.String(), sni)
			ed.dnsCacheTTL.Store(pkt.DstIP.String(), time.Now().Add(1*time.Hour))
		} else {
			// Try to lookup from DNS cache
			if domain, ok := ed.lookupDNSCache(pkt.DstIP); ok {
				meta.Domain = domain
				meta.DomainSource = "DNS-Cache"
			}
		}

	case 80: // HTTP
		meta.IsHTTP = true
		host := ed.httpParser.ExtractHost(pkt.Payload)
		if host != "" {
			meta.Domain = host
			meta.DomainSource = "HTTP"
			atomic.AddUint64(&ed.domainsExtracted, 1)

			// Cache HTTP Host → IP mapping
			ed.dnsCache.Store(pkt.DstIP.String(), host)
			ed.dnsCacheTTL.Store(pkt.DstIP.String(), time.Now().Add(1*time.Hour))
		}

		// Extract HTTP method
		if ed.httpParser.IsHTTPRequest(pkt.Payload) {
			meta.HTTPMethod = ed.extractHTTPMethod(pkt.Payload)
		}

	case 67, 68: // DHCP
		dhcpMsg := ed.dhcpParser.Parse(pkt.Payload)
		if dhcpMsg != nil && dhcpMsg.Hostname != "" {
			meta.DHCPHostname = dhcpMsg.Hostname
			meta.DomainSource = "DHCP"
			meta.DHCPMessageType = parser.GetMessageTypeName(dhcpMsg.MessageType)
		}

	default:
		// For other ports, try DNS cache lookup
		if domain, ok := ed.lookupDNSCache(pkt.DstIP); ok {
			meta.Domain = domain
			meta.DomainSource = "DNS-Cache"
		}
	}

	// === Extract TCP flags ===
	if pkt.Protocol == ProtoTCP {
		tcpFlags := ed.extractTCPFlags(pkt)
		meta.TCPFlags = tcpFlags
		meta.IsSYN = (tcpFlags & 0x02) != 0
		meta.IsACK = (tcpFlags & 0x10) != 0
		meta.IsRST = (tcpFlags & 0x04) != 0
		meta.IsFIN = (tcpFlags & 0x01) != 0
	}

	// === Extract ICMP info ===
	if pkt.Protocol == 1 { // ICMP
		if len(pkt.Payload) >= 2 {
			// ICMP is at IP payload, need to extract from raw buffer
			data := pkt.RawBuffer.Buffer[:pkt.RawBuffer.Length]
			if len(data) >= 35 {
				meta.ICMPType = data[34]
				meta.ICMPCode = data[35]
			}
		}
	}

	return meta
}

// updateFlowTracking updates flow statistics
func (ed *EnhancedDriver) updateFlowTracking(pkt *ParsedPacket, meta *metadata.PacketMetadata) {
	flowKey := metadata.NewFlowKey(pkt.SrcIP, pkt.DstIP, pkt.SrcPort, pkt.DstPort, pkt.Protocol)

	val, exists := ed.flows.LoadOrStore(flowKey, &metadata.FlowStats{
		SrcIP:     pkt.SrcIP,
		DstIP:     pkt.DstIP,
		SrcPort:   pkt.SrcPort,
		DstPort:   pkt.DstPort,
		Protocol:  pkt.Protocol,
		FirstSeen: time.Now(),
		LastSeen:  time.Now(),
		Domain:    meta.Domain,
	})

	flow := val.(*metadata.FlowStats)
	atomic.AddUint64(&flow.PacketCount, 1)
	atomic.AddUint64(&flow.ByteCount, uint64(meta.PacketSize))
	flow.LastSeen = time.Now()

	if !exists {
		meta.IsNewFlow = true
		atomic.AddUint64(&ed.flowsTracked, 1)
	}

	meta.FlowID = flowKey.String()
	meta.FlowPacketNum = flow.PacketCount
}

// updateIPStats updates per-IP statistics
func (ed *EnhancedDriver) updateIPStats(pkt *ParsedPacket, meta *metadata.PacketMetadata) {
	key := pkt.SrcIP.String()

	val, _ := ed.ipStats.LoadOrStore(key, metadata.NewIPStats())
	stats := val.(*metadata.IPStats)

	atomic.AddUint64(&stats.TotalPackets, 1)

	switch pkt.Protocol {
	case ProtoTCP:
		atomic.AddUint64(&stats.TCPConnections, 1)
		if meta.IsSYN {
			atomic.AddUint64(&stats.SYNCount, 1)
		}
		stats.UniquePortsMap[pkt.DstPort] = true

	case ProtoUDP:
		atomic.AddUint64(&stats.UDPFlows, 1)

	case 1: // ICMP
		atomic.AddUint64(&stats.ICMPPackets, 1)
	}
}

// cacheDNSResponse caches DNS responses for IP→Domain mapping (proper parsing)
func (ed *EnhancedDriver) cacheDNSResponse(pkt *ParsedPacket) {
	// Parse DNS response answers (IP→Domain mapping)
	answers := ed.dnsParser.ParseDNSResponse(pkt.Payload)
	if len(answers) == 0 {
		return
	}

	for _, answer := range answers {
		if answer.IP != "" && answer.Domain != "" {
			// Cache with TTL from DNS response
			ttl := time.Duration(answer.TTL) * time.Second
			if ttl < 60*time.Second {
				ttl = 60 * time.Second // Minimum 60 seconds
			}
			if ttl > 3600*time.Second {
				ttl = 3600 * time.Second // Maximum 1 hour
			}

			ed.dnsCache.Store(answer.IP, answer.Domain)
			ed.dnsCacheTTL.Store(answer.IP, time.Now().Add(ttl))
		}
	}
}

// lookupDNSCache looks up domain from DNS cache
func (ed *EnhancedDriver) lookupDNSCache(ip net.IP) (string, bool) {
	key := ip.String()

	// Check TTL
	if expiry, ok := ed.dnsCacheTTL.Load(key); ok {
		if time.Now().After(expiry.(time.Time)) {
			// Expired
			ed.dnsCache.Delete(key)
			ed.dnsCacheTTL.Delete(key)
			return "", false
		}
	}

	if domain, ok := ed.dnsCache.Load(key); ok {
		return domain.(string), true
	}

	return "", false
}

// cacheMACAddresses caches MAC addresses from Ethernet header
func (ed *EnhancedDriver) cacheMACAddresses(pkt *ParsedPacket) {
	data := pkt.RawBuffer.Buffer[:pkt.RawBuffer.Length]
	if len(data) < 14 {
		return
	}

	var srcMAC, dstMAC [6]byte
	copy(srcMAC[:], data[6:12])
	copy(dstMAC[:], data[0:6])

	ed.macCache.Store(pkt.SrcIP.String(), srcMAC)
	ed.macCache.Store(pkt.DstIP.String(), dstMAC)
}

// extractTCPFlags extracts TCP flags from raw packet
func (ed *EnhancedDriver) extractTCPFlags(pkt *ParsedPacket) uint8 {
	data := pkt.RawBuffer.Buffer[:pkt.RawBuffer.Length]
	if len(data) < 48 { // Eth(14) + IP(20) + TCP(14 for flags offset)
		return 0
	}

	// TCP flags at offset 47 (Eth 14 + IP 20 + TCP 13)
	return data[47]
}

// extractHTTPMethod extracts HTTP method from payload
func (ed *EnhancedDriver) extractHTTPMethod(payload []byte) string {
	methods := []string{"GET", "POST", "PUT", "DELETE", "HEAD", "OPTIONS", "PATCH", "CONNECT", "TRACE"}
	for _, method := range methods {
		if len(payload) >= len(method) && string(payload[:len(method)]) == method {
			return method
		}
	}
	return ""
}

// handleVerdict executes the verdict action
func (ed *EnhancedDriver) handleVerdict(pkt *ParsedPacket, v verdict.Verdict) {
	switch v {
	case verdict.VerdictBlock:
		// Send TCP RST to kill connection
		if pkt.Protocol == ProtoTCP {
			ed.sendTCPReset(pkt)
		}

	case verdict.VerdictDrop:
		// Silently drop (do nothing)

	case verdict.VerdictRedirect:
		// Handle redirect (DNS only)
		if pkt.DstPort == 53 {
			// DNS redirect handled in main handler
		}
	}
}

// sendTCPReset sends TCP RST using verdict engine
func (ed *EnhancedDriver) sendTCPReset(pkt *ParsedPacket) {
	// Get MAC addresses from cache
	var srcMAC, dstMAC [6]byte

	if mac, ok := ed.macCache.Load(pkt.SrcIP.String()); ok {
		srcMAC = mac.([6]byte)
	}
	if mac, ok := ed.macCache.Load(pkt.DstIP.String()); ok {
		dstMAC = mac.([6]byte)
	}

	// Send RST
	ed.verdict.SendTCPReset(
		pkt.AdapterHandle,
		pkt.SrcIP, pkt.DstIP,
		pkt.SrcPort, pkt.DstPort,
		srcMAC, dstMAC,
	)
}

// injectDNSRedirect injects fake DNS response
func (ed *EnhancedDriver) injectDNSRedirect(pkt *ParsedPacket, domain string, redirectIP net.IP) {
	data := pkt.RawBuffer.Buffer[:pkt.RawBuffer.Length]

	var srcMAC, dstMAC [6]byte
	if len(data) >= 14 {
		copy(srcMAC[:], data[6:12])
		copy(dstMAC[:], data[0:6])
	}

	ed.verdict.InjectDNSResponse(
		pkt.AdapterHandle,
		data,
		domain,
		redirectIP,
		srcMAC, dstMAC,
	)
}

// GetEnhancedStats returns enhanced statistics
func (ed *EnhancedDriver) GetEnhancedStats() map[string]interface{} {
	read, written, dropped := ed.GetStats()

	flowCount := 0
	ed.flows.Range(func(_, _ interface{}) bool {
		flowCount++
		return true
	})

	ipCount := 0
	ed.ipStats.Range(func(_, _ interface{}) bool {
		ipCount++
		return true
	})

	dnsCount := 0
	ed.dnsCache.Range(func(_, _ interface{}) bool {
		dnsCount++
		return true
	})

	stats := map[string]interface{}{
		"packets_read":      read,
		"packets_written":   written,
		"packets_dropped":   dropped,
		"domains_extracted": atomic.LoadUint64(&ed.domainsExtracted),
		"flows_tracked":     flowCount,
		"ips_tracked":       ipCount,
		"dns_cache_entries": dnsCount,
		"metadata_sent":     atomic.LoadUint64(&ed.metadataSent),
		"metadata_dropped":  atomic.LoadUint64(&ed.metadataDropped),
	}

	// Merge verdict engine stats
	verdictStats := ed.verdict.GetStats()
	for k, v := range verdictStats {
		stats[k] = v
	}

	return stats
}

// GetIPStats returns statistics for a specific IP
func (ed *EnhancedDriver) GetIPStats(ip string) *metadata.IPStats {
	if val, ok := ed.ipStats.Load(ip); ok {
		return val.(*metadata.IPStats)
	}
	return nil
}

// GetFlowStats returns all flow statistics
func (ed *EnhancedDriver) GetFlowStats() []*metadata.FlowStats {
	var flows []*metadata.FlowStats
	ed.flows.Range(func(_, value interface{}) bool {
		flows = append(flows, value.(*metadata.FlowStats))
		return true
	})
	return flows
}

// CleanupStaleFlows removes flows that haven't seen packets in given duration
func (ed *EnhancedDriver) CleanupStaleFlows(maxIdle time.Duration) int {
	now := time.Now()
	removed := 0

	ed.flows.Range(func(key, value interface{}) bool {
		flow := value.(*metadata.FlowStats)
		if now.Sub(flow.LastSeen) > maxIdle {
			ed.flows.Delete(key)
			removed++
		}
		return true
	})

	return removed
}
