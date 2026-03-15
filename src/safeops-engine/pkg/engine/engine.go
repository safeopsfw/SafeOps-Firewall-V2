// Package engine provides public API for SafeOps Engine integration
package engine

import (
	"bufio"
	"context"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"

	"safeops-engine/internal/config"
	"safeops-engine/internal/driver"
	"safeops-engine/internal/logger"
	"safeops-engine/internal/parser"
	"safeops-engine/internal/verdict"
	"safeops-engine/pkg/blockpage"
	"safeops-engine/pkg/control"
	grpcserver "safeops-engine/pkg/grpc"
	"safeops-engine/pkg/stream"
)

var (
	globalEngine *Engine
	once         sync.Once
	mu           sync.RWMutex
)

// blockedPort represents a port+protocol pair to block
type blockedPort struct {
	port     uint16
	blockTCP bool
	blockUDP bool
}

// Engine represents the SafeOps Engine instance
type Engine struct {
	log         *logger.Logger
	driver      *driver.Driver
	verdict     *verdict.Engine
	broadcaster *stream.Broadcaster
	grpcServer      *grpcserver.Server
	controlServer   *control.Server
	blockPageServer *blockpage.Server
	ctx             context.Context
	cancel          context.CancelFunc

	// Parsers for domain extraction (slow path only)
	dnsParser  *parser.DNSParser
	tlsParser  *parser.TLSParser
	httpParser *parser.HTTPParser

	// Domain blocklist (domain -> true)
	blockedDomains sync.Map

	// DoH server IPs (known DNS-over-HTTPS resolvers to block)
	// These are dedicated DNS resolver IPs, NOT shared hosting IPs.
	// Blocking DoH forces browsers to use system DNS where our redirect works.
	// Key: IP string, Value: true
	dohServers sync.Map

	// VPN port blocklist
	blockedPorts []blockedPort

	// MAC address cache for RST/injection (IP string -> [6]byte)
	macCache sync.Map

	// Flow cache: tracks inspected TCP connections on ports 80/443.
	// After initial domain extraction (SNI/Host), subsequent data packets
	// on the same flow skip slow-path. Key: "srcIP:srcPort-dstIP:dstPort"
	// Value: true (inspected). Pruned periodically.
	inspectedFlows sync.Map
	flowCount      uint64 // approximate count for periodic pruning

	// Stats
	fastPathPackets uint64
	slowPathPackets uint64
	domainsBlocked  uint64
	dohBlocked      uint64
	vpnBlocked      uint64
	sampledPackets  uint64

	// Sampling: send every Nth fast-path packet to Firewall Engine
	// for security checks (DDoS, rate limiting, port scan, GeoIP).
	// Web traffic (DNS/HTTP/HTTPS) is always sent (not sampled).
	sampleRate uint64 // send 1 in N fast-path packets (0 = disabled)
}

// GetEngine returns the global SafeOps Engine instance
func GetEngine() *Engine {
	mu.RLock()
	defer mu.RUnlock()
	return globalEngine
}

// Initialize creates and starts the SafeOps Engine
func Initialize() (*Engine, error) {
	var err error
	once.Do(func() {
		// Resolve log path relative to executable directory
		exeDir := "."
		if exe, exeErr := os.Executable(); exeErr == nil {
			exeDir = filepath.Dir(exe)
		}
		logFile := filepath.Join(exeDir, "..", "data", "logs", "engine.log")
		// Ensure the log directory exists
		os.MkdirAll(filepath.Dir(logFile), 0755)

		logCfg := config.LoggingConfig{
			Level:  "info",
			Format: "json",
			File:   logFile,
		}

		log := logger.New(logCfg)
		log.StartRotation()

		ctx, cancel := context.WithCancel(context.Background())

		// Open driver
		drv, drvErr := driver.Open(log)
		if drvErr != nil {
			err = fmt.Errorf("failed to open driver: %w", drvErr)
			cancel()
			return
		}

		// Set tunnel mode
		if tunnelErr := drv.SetTunnelModeAll(); tunnelErr != nil {
			err = fmt.Errorf("failed to set tunnel mode: %w", tunnelErr)
			drv.Close()
			cancel()
			return
		}

		// Create verdict engine for blocking/injection
		verdictEngine := verdict.New(drv.GetAPI())

		// Create broadcaster with 10k buffer
		broadcaster := stream.NewBroadcaster(10000)

		// Create gRPC server (with verdict engine for enforcement)
		grpcSrv, grpcErr := grpcserver.NewServer(log, drv, verdictEngine, "127.0.0.1:50051")
		if grpcErr != nil {
			err = fmt.Errorf("failed to create gRPC server: %w", grpcErr)
			drv.Close()
			cancel()
			return
		}

		eng := &Engine{
			log:         log,
			driver:      drv,
			verdict:     verdictEngine,
			broadcaster: broadcaster,
			grpcServer:  grpcSrv,
			ctx:         ctx,
			cancel:      cancel,
			sampleRate:  100, // Send 1-in-100 fast-path packets for security checks (DDoS, GeoIP, etc.)
			dnsParser:   parser.NewDNSParser(),
			tlsParser:   parser.NewTLSParser(),
			httpParser:  parser.NewHTTPParser(),
		}

		// Flush Windows DNS cache on startup — critical for defeating DoH bypass.
		// When engine restarts, stale DNS cache entries let browsers reach blocked sites.
		flushDNSCache(log)

		// Domain blocklist is populated by the Firewall Engine via BlockDomain().
		// The Firewall Engine loads domains.txt + threat intel + categories and
		// pushes them here via in-process BlocklistSync. No file loading here.
		log.Info("Domain blocklist: waiting for Firewall Engine sync", nil)
		fmt.Println("  Domain blocklist: managed by Firewall Engine (in-process sync)")

		// Load DoH server blocklist — blocks DNS-over-HTTPS to force system DNS
		dohPath := resolveConfigFile("doh_servers.txt")
		if dohPath != "" {
			dohCount, dohErr := eng.LoadDoHServersFromFile(dohPath)
			if dohErr != nil {
				log.Warn("Failed to load DoH servers file", map[string]interface{}{
					"path":  dohPath,
					"error": dohErr.Error(),
				})
			} else {
				log.Info("DoH server blocklist loaded", map[string]interface{}{
					"path":  dohPath,
					"count": dohCount,
				})
				fmt.Printf("  DoH blocklist:    %d DoH resolver IPs blocked\n", dohCount)
			}
		}

		// Load VPN port blocklist
		vpnPath := resolveConfigFile("blocked_ports.txt")
		if vpnPath != "" {
			vpnCount, vpnErr := eng.LoadBlockedPortsFromFile(vpnPath)
			if vpnErr != nil {
				log.Warn("Failed to load blocked ports file", map[string]interface{}{
					"path":  vpnPath,
					"error": vpnErr.Error(),
				})
			} else {
				log.Info("VPN port blocklist loaded", map[string]interface{}{
					"path":  vpnPath,
					"count": vpnCount,
				})
				fmt.Printf("  VPN port blocks:  %d port rules loaded\n", vpnCount)
			}
		}

		// Set packet handler with fast-path / slow-path split
		drv.SetHandler(eng.handlePacket)

		// Start gRPC server
		if startErr := grpcSrv.Start(); startErr != nil {
			err = fmt.Errorf("failed to start gRPC server: %w", startErr)
			drv.Close()
			cancel()
			return
		}

		// Start control API server (non-fatal if it fails)
		controlSrv := control.NewServer(log, verdictEngine, eng, "127.0.0.1:50052")
		if ctrlErr := controlSrv.Start(); ctrlErr != nil {
			log.Warn("Control API server failed to start", map[string]interface{}{
				"error": ctrlErr.Error(),
			})
		} else {
			eng.controlServer = controlSrv
		}

		// Start block page server on HTTP :80 and HTTPS :443 (non-fatal if ports taken)
		// DNS-redirected domains resolve to 127.0.0.1 → browser connects here → sees block page
		bpSrv := blockpage.NewServer(log, "127.0.0.1:80", "127.0.0.1:443")
		if bpErr := bpSrv.Start(); bpErr != nil {
			log.Warn("Block page server failed to start", map[string]interface{}{
				"error": bpErr.Error(),
			})
		} else {
			eng.blockPageServer = bpSrv
			fmt.Println("  Block page server: http://127.0.0.1:80 + https://127.0.0.1:443")
		}

		// Start packet processing
		go drv.ProcessPacketsAll(ctx)

		log.Info("SafeOps Engine initialized", map[string]interface{}{
			"version":        "4.0.0",
			"mode":           "fast-slow-path",
			"grpc_listen":    "127.0.0.1:50051",
			"control_listen": "127.0.0.1:50052",
			"block_page":     "127.0.0.1:80",
		})

		mu.Lock()
		globalEngine = eng
		mu.Unlock()
	})

	return globalEngine, err
}

// handlePacket is the main packet handler with fast-path / slow-path split
func (e *Engine) handlePacket(pkt *driver.ParsedPacket) bool {
	dstPort := pkt.DstPort
	srcPort := pkt.SrcPort

	// ============ VPN PORT BLOCKING (before fast/slow split) ============
	// Check blocked ports — VPN/tunnel protocols. ONLY for non-local destinations
	// to avoid killing LAN traffic (DHCP, IPSec for network auth, etc.)
	if !isLocalIP(pkt.DstIP) && e.isPortBlocked(dstPort, pkt.Protocol) {
		atomic.AddUint64(&e.vpnBlocked, 1)
		// Broadcast to Firewall Engine before blocking (so it can generate alerts)
		e.grpcServer.BroadcastPacket(pkt)
		if pkt.Protocol == driver.ProtoTCP {
			e.sendTCPReset(pkt)
		}
		return false
	}

	// ============ DoH BLOCKING (before DNS interception) ============
	// Block connections to known DNS-over-HTTPS resolver IPs on port 443.
	// This forces browsers to fall back to system DNS where our redirect works.
	// Only block outbound (non-local dst) to avoid interfering with LAN.
	if dstPort == 443 && !isLocalIP(pkt.DstIP) {
		dstStr := pkt.DstIP.String()
		if _, isDoH := e.dohServers.Load(dstStr); isDoH {
			atomic.AddUint64(&e.dohBlocked, 1)
			// Broadcast to Firewall Engine before blocking (so it can generate alerts)
			e.grpcServer.BroadcastPacket(pkt)
			if pkt.Protocol == driver.ProtoTCP {
				e.sendTCPReset(pkt)
			}
			return false // drop DoH UDP (QUIC) too
		}
	}

	// ============ FAST PATH: Non-web traffic ============
	// O(1) port check - if not web traffic, skip domain extraction
	// but still broadcast to Firewall Engine for security checks
	// (DDoS, rate limiting, port scan, brute force, GeoIP, threat intel).
	if !isWebTraffic(dstPort, srcPort) {
		atomic.AddUint64(&e.fastPathPackets, 1)

		// Only check IP blocklist (sync.Map.Load = O(1), no alloc)
		if v := e.verdict.CheckIP(pkt.DstIP); v != verdict.VerdictAllow {
			e.handleVerdictAction(pkt, v)
			return false
		}
		if v := e.verdict.CheckIP(pkt.SrcIP); v != verdict.VerdictAllow {
			e.handleVerdictAction(pkt, v)
			return false
		}

		// Broadcast to Firewall Engine for security monitoring (DDoS, rate limit, etc.).
		// Uses NoCache variant so flood/DDoS counters always increment even when
		// a cached DROP verdict exists. Without this, cached verdicts prevent
		// flood detection from ever reaching the threshold.
		if e.sampleRate > 0 {
			count := atomic.LoadUint64(&e.fastPathPackets)
			if count%e.sampleRate == 0 {
				atomic.AddUint64(&e.sampledPackets, 1)
				e.grpcServer.BroadcastPacketNoCache(pkt)
			}
		}

		// Check gRPC verdict cache (cached verdicts from Firewall Engine
		// still apply to fast-path traffic for enforcement)
		shouldAllow := e.grpcServer.CheckVerdictCache(pkt)
		if !shouldAllow {
			return false
		}

		return true
	}

	// ============ SLOW PATH: Web traffic (DNS/HTTP/HTTPS) ============
	atomic.AddUint64(&e.slowPathPackets, 1)

	// Step 0: Flow cache — if this TCP flow on port 80/443 has already been
	// inspected (domain extracted, verdict applied), skip expensive processing.
	// DNS (port 53) is always inspected since each query is a new domain lookup.
	if pkt.Protocol == driver.ProtoTCP && (dstPort == 80 || dstPort == 443) {
		if _, inspected := e.inspectedFlows.Load(flowKey(pkt)); inspected {
			// Already inspected this flow — fast-pass through.
			// Still check gRPC verdict cache for external engine verdicts.
			atomic.AddUint64(&e.fastPathPackets, 1)
			shouldAllow := e.grpcServer.CheckVerdictCache(pkt)
			return shouldAllow
		}
	}

	// Step 1: Check IP blocklist
	if v := e.verdict.CheckIP(pkt.DstIP); v != verdict.VerdictAllow {
		e.handleVerdictAction(pkt, v)
		return false
	}

	// Step 2: Cache MAC addresses for future RST/injection
	e.cacheMACAddresses(pkt)

	// Step 3: Handle DNS queries - check redirect & domain blocking
	if dstPort == 53 && pkt.Protocol == driver.ProtoUDP {
		if e.dnsParser.IsDNSQuery(pkt.Payload) {
			domain := strings.ToLower(e.dnsParser.ExtractDomain(pkt.Payload))
			if domain != "" {
				pkt.Domain = domain
				pkt.DomainSource = "DNS"

				// Check domain blocklist
				if e.isDomainBlocked(domain) {
					// Broadcast to Firewall Engine before blocking (so it can track/alert)
					e.grpcServer.BroadcastPacket(pkt)
					e.injectDNSRedirect(pkt, domain, net.ParseIP("127.0.0.1"))
					atomic.AddUint64(&e.domainsBlocked, 1)
					return false
				}

				// Check DNS redirect rules
				if redirectIP, ok := e.verdict.CheckDNSRedirect(domain); ok {
					e.injectDNSRedirect(pkt, domain, redirectIP)
					return false
				}
			}
		}
	}

	// Step 4: Cache DNS responses (for domain source tracking, NOT for IP blocking)
	if srcPort == 53 && pkt.Protocol == driver.ProtoUDP {
		// Just let it pass - we don't block CDN IPs
	}

	// Step 5: Extract domain from TLS SNI (port 443 TCP)
	if dstPort == 443 && pkt.Protocol == driver.ProtoTCP {
		sni := strings.ToLower(e.tlsParser.ExtractSNI(pkt.Payload))
		if sni != "" {
			pkt.Domain = sni
			pkt.DomainSource = "SNI"

			// Check domain blocklist - send RST for blocked HTTPS
			// BUT: if dst is 127.0.0.1 (our block page server), let it through
			// so the browser sees the block page instead of a connection reset.
			if e.isDomainBlocked(sni) {
				dstStr := pkt.DstIP.String()
				if dstStr == "127.0.0.1" || dstStr == "::1" {
					// Let it through to block page server
				} else {
					// Broadcast to Firewall Engine before blocking
					e.grpcServer.BroadcastPacket(pkt)
					e.sendTCPReset(pkt)
					atomic.AddUint64(&e.domainsBlocked, 1)
					return false
				}
			}
		}

		// Mark this TCP flow as inspected — subsequent data packets skip slow-path.
		// Done after SNI extraction attempt (even if no SNI found, the ClientHello
		// was the first packet; data packets won't have SNI anyway).
		e.markFlowInspected(pkt)
	}

	// Step 5b: Extract domain from QUIC Initial packet (UDP 443)
	// QUIC Initial packets contain a TLS ClientHello with SNI
	if dstPort == 443 && pkt.Protocol == driver.ProtoUDP {
		sni := e.extractQUICSNI(pkt.Payload)
		if sni != "" {
			pkt.Domain = sni
			pkt.DomainSource = "QUIC"

			if e.isDomainBlocked(sni) {
				// Broadcast to Firewall Engine before blocking
				e.grpcServer.BroadcastPacket(pkt)
				// Can't RST UDP — just drop. The browser will fall back to TCP 443.
				atomic.AddUint64(&e.domainsBlocked, 1)
				return false
			}
		}
	}

	// Step 6: Extract domain from HTTP Host (port 80)
	if dstPort == 80 && pkt.Protocol == driver.ProtoTCP {
		host := strings.ToLower(e.httpParser.ExtractHost(pkt.Payload))
		if host != "" {
			pkt.Domain = host
			pkt.DomainSource = "HTTP"

			// Check domain blocklist - inject HTML block page for HTTP
			if e.isDomainBlocked(host) {
				// Broadcast to Firewall Engine before blocking
				e.grpcServer.BroadcastPacket(pkt)
				e.injectHTMLBlockPage(pkt, host)
				atomic.AddUint64(&e.domainsBlocked, 1)
				return false
			}
		}

		// Mark this TCP flow as inspected.
		e.markFlowInspected(pkt)
	}

	// Step 7: Check gRPC verdict cache (for external service verdicts)
	shouldAllow := e.grpcServer.BroadcastPacket(pkt)
	if !shouldAllow {
		return false
	}

	// Step 8: Broadcast to in-process subscribers (only if any exist)
	if e.broadcaster.SubscriberCount() > 0 {
		meta := stream.ConvertPacket(pkt)
		e.broadcaster.Broadcast(meta)
	}

	return true
}

// isWebTraffic returns true for OUTBOUND DNS/HTTP/HTTPS/QUIC traffic.
// Only outbound has extractable domain info:
//   dstPort 53:  DNS queries   → intercept & redirect
//   dstPort 80:  HTTP requests → extract Host header, block page
//   dstPort 443: HTTPS/QUIC    → extract SNI from ClientHello
//
// Response packets (srcPort 53/443) do NOT need slow-path processing —
// DNS responses don't need re-parsing (query already redirected), and
// TLS ServerHello has no SNI. Processing every response packet wastes
// CPU and causes packet queue backlog that kills LAN adapters.
func isWebTraffic(dstPort, srcPort uint16) bool {
	_ = srcPort // explicitly unused — responses skip slow path
	return dstPort == 53 || dstPort == 80 || dstPort == 443
}

// isLocalIP returns true for loopback, private (RFC1918), link-local, and multicast addresses.
// Used to skip VPN/DoH blocking for LAN traffic — blocking local IPs kills
// Ethernet, DHCP, network discovery, IPSec auth, etc.
func isLocalIP(ip net.IP) bool {
	if ip == nil {
		return false
	}
	// Loopback
	if ip.IsLoopback() {
		return true
	}
	// Link-local
	if ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() {
		return true
	}
	// Multicast
	if ip.IsMulticast() {
		return true
	}
	// Private ranges (RFC 1918)
	ip4 := ip.To4()
	if ip4 != nil {
		// 10.0.0.0/8
		if ip4[0] == 10 {
			return true
		}
		// 172.16.0.0/12
		if ip4[0] == 172 && ip4[1] >= 16 && ip4[1] <= 31 {
			return true
		}
		// 192.168.0.0/16
		if ip4[0] == 192 && ip4[1] == 168 {
			return true
		}
		// 169.254.0.0/16 (APIPA / link-local)
		if ip4[0] == 169 && ip4[1] == 254 {
			return true
		}
	}
	return false
}

// flowKey builds a string key for tracking inspected TCP flows.
func flowKey(pkt *driver.ParsedPacket) string {
	return fmt.Sprintf("%s:%d-%s:%d", pkt.SrcIP, pkt.SrcPort, pkt.DstIP, pkt.DstPort)
}

// markFlowInspected records that a TCP flow has been through domain extraction.
func (e *Engine) markFlowInspected(pkt *driver.ParsedPacket) {
	e.inspectedFlows.Store(flowKey(pkt), true)
	count := atomic.AddUint64(&e.flowCount, 1)
	// Prune old flows every 50k entries to prevent memory leak
	if count > 50000 && count%10000 == 0 {
		go e.pruneFlows()
	}
}

// pruneFlows clears the inspected flows cache.
// Called periodically when flow count gets high.
func (e *Engine) pruneFlows() {
	e.inspectedFlows.Range(func(key, _ interface{}) bool {
		e.inspectedFlows.Delete(key)
		return true
	})
	atomic.StoreUint64(&e.flowCount, 0)
}

// handleVerdictAction executes the appropriate action for a verdict
func (e *Engine) handleVerdictAction(pkt *driver.ParsedPacket, v verdict.Verdict) {
	switch v {
	case verdict.VerdictBlock:
		if pkt.Protocol == driver.ProtoTCP {
			if pkt.DstPort == 80 {
				// HTTP: inject block page first, then RST
				e.injectHTMLBlockPage(pkt, "")
			}
			e.sendTCPReset(pkt)
		}
	case verdict.VerdictDrop:
		// Silent drop - do nothing
	case verdict.VerdictRedirect:
		// DNS redirect handled in slow path DNS section
	}
}

// cacheMACAddresses stores MAC addresses from Ethernet header for future injections
func (e *Engine) cacheMACAddresses(pkt *driver.ParsedPacket) {
	data := pkt.RawBuffer.Buffer[:pkt.RawBuffer.Length]
	if len(data) < 14 {
		return
	}

	var srcMAC, dstMAC [6]byte
	copy(dstMAC[:], data[0:6])
	copy(srcMAC[:], data[6:12])

	e.macCache.Store(pkt.SrcIP.String(), srcMAC)
	e.macCache.Store(pkt.DstIP.String(), dstMAC)
}

// getMACAddresses extracts MAC addresses from packet's raw Ethernet header
func getMACAddresses(pkt *driver.ParsedPacket) (srcMAC, dstMAC [6]byte) {
	data := pkt.RawBuffer.Buffer[:pkt.RawBuffer.Length]
	if len(data) >= 14 {
		copy(dstMAC[:], data[0:6])
		copy(srcMAC[:], data[6:12])
	}
	return
}

// isDomainBlocked checks if a domain (or its parent) is blocked
func (e *Engine) isDomainBlocked(domain string) bool {
	domain = strings.ToLower(domain)

	// Exact match
	if _, ok := e.blockedDomains.Load(domain); ok {
		return true
	}

	// Check parent domains (e.g., "cdn.malware.com" matches "malware.com")
	parts := strings.Split(domain, ".")
	for i := 1; i < len(parts)-1; i++ {
		parent := strings.Join(parts[i:], ".")
		if _, ok := e.blockedDomains.Load(parent); ok {
			return true
		}
	}

	return false
}

// sendTCPReset sends TCP RST to both endpoints to kill the connection
func (e *Engine) sendTCPReset(pkt *driver.ParsedPacket) {
	srcMAC, dstMAC := getMACAddresses(pkt)

	e.verdict.SendTCPReset(
		pkt.AdapterHandle,
		pkt.SrcIP, pkt.DstIP,
		pkt.SrcPort, pkt.DstPort,
		srcMAC, dstMAC,
	)
}

// injectDNSRedirect injects a fake DNS response redirecting to the given IP
func (e *Engine) injectDNSRedirect(pkt *driver.ParsedPacket, domain string, redirectIP net.IP) {
	data := pkt.RawBuffer.Buffer[:pkt.RawBuffer.Length]

	var srcMAC, dstMAC [6]byte
	if len(data) >= 14 {
		copy(srcMAC[:], data[6:12])
		copy(dstMAC[:], data[0:6])
	}

	err := e.verdict.InjectDNSResponse(
		pkt.AdapterHandle,
		data,
		domain,
		redirectIP,
		srcMAC, dstMAC,
	)
	if err != nil {
		e.log.Error("Failed to inject DNS redirect", map[string]interface{}{
			"domain": domain,
			"error":  err.Error(),
		})
	}
	// DNS redirect success is silent — the Firewall Engine handles domain block alerts.
	// Only errors are logged to avoid flooding the SafeOps Engine terminal.
}

// injectHTMLBlockPage injects an HTML block page for HTTP traffic and sends RST
func (e *Engine) injectHTMLBlockPage(pkt *driver.ParsedPacket, domain string) {
	srcMAC, dstMAC := getMACAddresses(pkt)

	reason := "Domain blocked by SafeOps Firewall"
	if domain != "" {
		reason = fmt.Sprintf("Access to %s blocked by SafeOps Firewall", domain)
	}

	err := e.verdict.InjectHTMLBlockPage(
		pkt.AdapterHandle,
		pkt.SrcIP, pkt.DstIP,
		pkt.SrcPort, pkt.DstPort,
		srcMAC, dstMAC,
		reason,
		"DOMAIN-BLOCK",
	)
	if err != nil {
		e.log.Error("Failed to inject HTML block page", map[string]interface{}{
			"domain": domain,
			"error":  err.Error(),
		})
	}

	// Also send RST to kill the connection
	e.sendTCPReset(pkt)
}

// extractQUICSNI extracts SNI from a QUIC Initial packet.
// QUIC Initial packets carry a TLS ClientHello inside the CRYPTO frame.
// The QUIC header format: flags(1) + version(4) + DCID len(1) + DCID + SCID len(1) + SCID + ...
// We look for the TLS ClientHello pattern inside the payload.
func (e *Engine) extractQUICSNI(payload []byte) string {
	if len(payload) < 50 {
		return ""
	}

	// QUIC long header: first bit set, next bit is "fixed" bit
	// Form bit (0x80) must be set for long header (Initial packet)
	if payload[0]&0x80 == 0 {
		return "" // Short header — not an Initial packet
	}

	// QUIC version is at bytes 1-4
	// Skip version check - just look for TLS ClientHello inside

	// Skip QUIC header to find TLS ClientHello
	// Instead of fully parsing QUIC (complex with variable-length encoding),
	// scan for the TLS ClientHello signature: 0x01 followed by valid length
	// The ClientHello appears inside a CRYPTO frame in the QUIC payload.

	// Look for TLS handshake marker (type=0x16 is TLS record, but in QUIC
	// the ClientHello is directly embedded without TLS record header)
	// Search for ClientHello type byte (0x01) followed by 3-byte length
	for i := 5; i < len(payload)-50; i++ {
		// ClientHello starts with handshake type 0x01
		if payload[i] == 0x01 {
			// Check if the next 3 bytes form a reasonable length
			if i+4 > len(payload) {
				continue
			}
			chLen := int(payload[i+1])<<16 | int(payload[i+2])<<8 | int(payload[i+3])
			if chLen < 30 || chLen > len(payload)-i {
				continue
			}

			// Try to parse as a ClientHello: version(2) + random(32) + sessionID(1+var) + ...
			chStart := i + 4
			if chStart+34 > len(payload) {
				continue
			}

			// Version should be 0x0303 (TLS 1.2) or 0x0301 (TLS 1.0) for compat
			ver := uint16(payload[chStart])<<8 | uint16(payload[chStart+1])
			if ver != 0x0303 && ver != 0x0301 && ver != 0x0302 {
				continue
			}

			// Build a synthetic TLS record for our existing parser:
			// Record header: 0x16 + version(2) + length(2) + handshake data
			syntheticLen := len(payload) - i
			if syntheticLen > 4096 {
				syntheticLen = 4096
			}
			synthetic := make([]byte, 5+syntheticLen)
			synthetic[0] = 0x16                                // Content type: Handshake
			synthetic[1] = 0x03                                // Version major
			synthetic[2] = 0x03                                // Version minor
			synthetic[3] = byte((syntheticLen) >> 8)           // Length high
			synthetic[4] = byte((syntheticLen) & 0xFF)         // Length low
			copy(synthetic[5:], payload[i:i+syntheticLen])

			sni := e.tlsParser.ExtractSNI(synthetic)
			if sni != "" {
				return sni
			}
		}
	}

	return ""
}

// ============ Public API for rule management ============

// BlockDomain adds a domain to the blocklist
// DNS queries get redirected to 127.0.0.1, SNI gets RST, HTTP gets block page
func (e *Engine) BlockDomain(domain string) {
	domain = strings.ToLower(strings.TrimSpace(domain))
	if domain == "" {
		return
	}

	e.blockedDomains.Store(domain, true)
	e.verdict.AddDNSRedirect(domain, net.ParseIP("127.0.0.1"))

	e.log.Info("Domain blocked", map[string]interface{}{
		"domain": domain,
	})
}

// UnblockDomain removes a domain from the blocklist
func (e *Engine) UnblockDomain(domain string) {
	domain = strings.ToLower(strings.TrimSpace(domain))
	if domain == "" {
		return
	}

	e.blockedDomains.Delete(domain)
	e.verdict.RemoveDNSRedirect(domain)

	e.log.Info("Domain unblocked", map[string]interface{}{
		"domain": domain,
	})
}

// GetBlockedDomains returns all currently blocked domains
func (e *Engine) GetBlockedDomains() []string {
	var domains []string
	e.blockedDomains.Range(func(key, _ interface{}) bool {
		domains = append(domains, key.(string))
		return true
	})
	return domains
}

// LoadDomainsFromFile reads a domains.txt file and adds all domains to the blocklist.
// File format: one domain per line, # for comments, blank lines ignored.
// Blocking: DNS→redirect 127.0.0.1, HTTPS→RST (SNI match), HTTP→block page.
func (e *Engine) LoadDomainsFromFile(path string) (int, error) {
	f, err := os.Open(path)
	if err != nil {
		return 0, fmt.Errorf("open domains file: %w", err)
	}
	defer f.Close()

	count := 0
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, "//") {
			continue
		}
		domain := strings.ToLower(line)
		e.blockedDomains.Store(domain, true)
		e.verdict.AddDNSRedirect(domain, net.ParseIP("127.0.0.1"))
		count++
	}

	if err := scanner.Err(); err != nil {
		return count, fmt.Errorf("reading domains file: %w", err)
	}

	e.log.Info("Loaded domain blocklist from file", map[string]interface{}{
		"path":  path,
		"count": count,
	})

	return count, nil
}

// resolveDomainsFile searches for domains.txt relative to the binary location.
// Search order: <exeDir>/configs/domains.txt, <exeDir>/../configs/domains.txt, ./configs/domains.txt
func resolveDomainsFile() string {
	return resolveConfigFile("domains.txt")
}

// resolveConfigFile searches for a config file relative to the binary location.
// Search order: <exeDir>/configs/<name>, <exeDir>/../configs/<name>, ./configs/<name>
func resolveConfigFile(name string) string {
	exePath, err := os.Executable()
	if err == nil {
		exeDir := filepath.Dir(exePath)
		candidates := []string{
			filepath.Join(exeDir, "configs", name),
			filepath.Join(exeDir, "..", "configs", name),
		}
		for _, c := range candidates {
			if _, err := os.Stat(c); err == nil {
				return c
			}
		}
	}
	// Fallback: current directory
	if _, err := os.Stat(filepath.Join("configs", name)); err == nil {
		return filepath.Join("configs", name)
	}
	return ""
}

// flushDNSCache flushes the Windows DNS resolver cache.
// This is critical on engine restart — stale cached DNS entries let browsers
// connect to blocked domains without going through our DNS redirect.
func flushDNSCache(log *logger.Logger) {
	cmd := exec.Command("ipconfig", "/flushdns")
	output, err := cmd.CombinedOutput()
	if err != nil {
		log.Warn("Failed to flush DNS cache", map[string]interface{}{
			"error": err.Error(),
		})
		fmt.Println("  DNS cache flush:  FAILED (run as admin)")
	} else {
		log.Info("DNS cache flushed", map[string]interface{}{
			"output": strings.TrimSpace(string(output)),
		})
		fmt.Println("  DNS cache flush:  OK (stale entries cleared)")
	}
}

// LoadDoHServersFromFile reads a doh_servers.txt file and adds all IPs to the DoH blocklist.
func (e *Engine) LoadDoHServersFromFile(path string) (int, error) {
	f, err := os.Open(path)
	if err != nil {
		return 0, fmt.Errorf("open DoH servers file: %w", err)
	}
	defer f.Close()

	count := 0
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		// Validate it's a real IP
		if net.ParseIP(line) == nil {
			continue
		}
		e.dohServers.Store(line, true)
		count++
	}

	if err := scanner.Err(); err != nil {
		return count, fmt.Errorf("reading DoH servers file: %w", err)
	}

	e.log.Info("Loaded DoH server blocklist from file", map[string]interface{}{
		"path":  path,
		"count": count,
	})
	return count, nil
}

// LoadBlockedPortsFromFile reads a blocked_ports.txt file.
// Format: port/protocol  # comment
// Protocol: tcp, udp, or both
func (e *Engine) LoadBlockedPortsFromFile(path string) (int, error) {
	f, err := os.Open(path)
	if err != nil {
		return 0, fmt.Errorf("open blocked ports file: %w", err)
	}
	defer f.Close()

	var ports []blockedPort
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		// Remove inline comment
		if idx := strings.Index(line, "#"); idx >= 0 {
			line = strings.TrimSpace(line[:idx])
		}

		// Parse "port/protocol"
		parts := strings.SplitN(line, "/", 2)
		if len(parts) != 2 {
			continue
		}

		portNum, err := strconv.Atoi(strings.TrimSpace(parts[0]))
		if err != nil || portNum < 1 || portNum > 65535 {
			continue
		}

		proto := strings.ToLower(strings.TrimSpace(parts[1]))
		bp := blockedPort{port: uint16(portNum)}
		switch proto {
		case "tcp":
			bp.blockTCP = true
		case "udp":
			bp.blockUDP = true
		case "both":
			bp.blockTCP = true
			bp.blockUDP = true
		default:
			continue
		}

		ports = append(ports, bp)
	}

	if err := scanner.Err(); err != nil {
		return len(ports), fmt.Errorf("reading blocked ports file: %w", err)
	}

	e.blockedPorts = ports

	e.log.Info("Loaded blocked ports from file", map[string]interface{}{
		"path":  path,
		"count": len(ports),
	})
	return len(ports), nil
}

// isPortBlocked checks if a destination port is in the VPN port blocklist
func (e *Engine) isPortBlocked(port uint16, protocol uint8) bool {
	for _, bp := range e.blockedPorts {
		if bp.port == port {
			if protocol == driver.ProtoTCP && bp.blockTCP {
				return true
			}
			if protocol == driver.ProtoUDP && bp.blockUDP {
				return true
			}
		}
	}
	return false
}

// GetVerdictEngine returns the verdict engine for external control
func (e *Engine) GetVerdictEngine() *verdict.Engine {
	return e.verdict
}

// GetEnhancedStats returns detailed engine statistics
func (e *Engine) GetEnhancedStats() map[string]interface{} {
	read, written, dropped := e.driver.GetStats()

	blockedDomainCount := 0
	e.blockedDomains.Range(func(_, _ interface{}) bool {
		blockedDomainCount++
		return true
	})

	dohCount := 0
	e.dohServers.Range(func(_, _ interface{}) bool {
		dohCount++
		return true
	})

	stats := map[string]interface{}{
		"packets_read":         read,
		"packets_written":      written,
		"packets_dropped":      dropped,
		"fast_path_packets":    atomic.LoadUint64(&e.fastPathPackets),
		"slow_path_packets":    atomic.LoadUint64(&e.slowPathPackets),
		"sampled_packets":      atomic.LoadUint64(&e.sampledPackets),
		"sample_rate":          e.sampleRate,
		"domains_blocked":      atomic.LoadUint64(&e.domainsBlocked),
		"doh_blocked":          atomic.LoadUint64(&e.dohBlocked),
		"vpn_blocked":          atomic.LoadUint64(&e.vpnBlocked),
		"blocked_domain_count": blockedDomainCount,
		"doh_server_count":     dohCount,
		"vpn_port_rules":       len(e.blockedPorts),
		"grpc_subscribers":     e.grpcServer.SubscriberCount(),
	}

	// Merge verdict engine stats
	verdictStats := e.verdict.GetStats()
	for k, v := range verdictStats {
		stats[k] = v
	}

	return stats
}

// ============ Existing public API ============

// SubscribeToMetadata creates a subscription to the packet metadata stream
func (e *Engine) SubscribeToMetadata(subscriberID string) *stream.Subscriber {
	e.log.Info("New metadata subscriber", map[string]interface{}{
		"subscriber_id": subscriberID,
		"total_subs":    e.broadcaster.SubscriberCount() + 1,
	})
	return e.broadcaster.Subscribe(subscriberID)
}

// UnsubscribeFromMetadata removes a metadata subscription
func (e *Engine) UnsubscribeFromMetadata(subscriberID string) {
	e.broadcaster.Unsubscribe(subscriberID)
	e.log.Info("Metadata subscriber removed", map[string]interface{}{
		"subscriber_id": subscriberID,
		"total_subs":    e.broadcaster.SubscriberCount(),
	})
}

// GetStats returns packet statistics
func (e *Engine) GetStats() (read, written, dropped uint64) {
	return e.driver.GetStats()
}

// Shutdown stops the engine
func (e *Engine) Shutdown() {
	e.log.Info("Shutting down SafeOps Engine", nil)

	// Stop block page server
	if e.blockPageServer != nil {
		e.blockPageServer.Stop()
	}

	// Stop control API server
	if e.controlServer != nil {
		e.controlServer.Stop()
	}

	// Stop gRPC server (disconnects subscribers)
	if e.grpcServer != nil {
		e.grpcServer.Stop()
	}

	// Cancel context AFTER servers are stopped — this stops the packet
	// processing goroutine. Any packets still queued in the driver will
	// be flushed by Close().
	e.cancel()

	// Close driver: resets adapter modes (disables tunnel), flushes
	// packet queues, then closes the driver handle. This restores
	// normal network connectivity.
	e.driver.Close()
	e.log.Close()
}
