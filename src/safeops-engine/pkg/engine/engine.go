// Package engine provides public API for SafeOps Engine integration
package engine

import (
	"bufio"
	"context"
	"fmt"
	"net"
	"os"
	"path/filepath"
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

	// MAC address cache for RST/injection (IP string -> [6]byte)
	macCache sync.Map

	// Stats
	fastPathPackets uint64
	slowPathPackets uint64
	domainsBlocked  uint64
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
		logCfg := config.LoggingConfig{
			Level:  "info",
			Format: "json",
			File:   "D:/SafeOpsFV2/data/logs/engine.log",
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
			sampleRate:  10, // Send 1 in 10 fast-path packets to Firewall Engine
			dnsParser:   parser.NewDNSParser(),
			tlsParser:   parser.NewTLSParser(),
			httpParser:  parser.NewHTTPParser(),
		}

		// Load domain blocklist from file (if found)
		domainsPath := resolveDomainsFile()
		if domainsPath != "" {
			domainCount, loadErr := eng.LoadDomainsFromFile(domainsPath)
			if loadErr != nil {
				log.Warn("Failed to load domains file", map[string]interface{}{
					"path":  domainsPath,
					"error": loadErr.Error(),
				})
			} else {
				log.Info("Domain blocklist loaded", map[string]interface{}{
					"path":  domainsPath,
					"count": domainCount,
				})
				fmt.Printf("  Domain blocklist: %d domains from %s\n", domainCount, domainsPath)
			}
		} else {
			log.Info("No domains.txt found — domain blocking via file disabled", nil)
			fmt.Println("  Domain blocklist: no domains.txt found (use control API to add domains)")
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

	// ============ FAST PATH: Non-web traffic ============
	// O(1) port check - if not web traffic, minimal processing
	// Fast path does NOT broadcast to gRPC — millions of packets/sec would
	// overflow any gRPC channel. Only web traffic (DNS/HTTP/HTTPS) goes to
	// the Firewall Engine for domain-based policy decisions.
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

		// Check gRPC verdict cache (cached verdicts from Firewall Engine
		// still apply to fast-path traffic without re-broadcasting)
		shouldAllow := e.grpcServer.CheckVerdictCache(pkt)
		if !shouldAllow {
			return false
		}

		// Sample: send every Nth fast-path packet to Firewall Engine
		// for security checks (DDoS, rate limiting, port scan, GeoIP).
		// Non-blocking — if channel is full, sample is silently dropped.
		if e.sampleRate > 0 {
			count := atomic.LoadUint64(&e.fastPathPackets)
			if count%e.sampleRate == 0 {
				atomic.AddUint64(&e.sampledPackets, 1)
				e.grpcServer.BroadcastPacket(pkt)
			}
		}

		return true
	}

	// ============ SLOW PATH: Web traffic (DNS/HTTP/HTTPS) ============
	atomic.AddUint64(&e.slowPathPackets, 1)

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
			domain := e.dnsParser.ExtractDomain(pkt.Payload)
			if domain != "" {
				pkt.Domain = domain
				pkt.DomainSource = "DNS"

				// Check domain blocklist
				if e.isDomainBlocked(domain) {
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

	// Step 5: Extract domain from TLS SNI (port 443)
	if dstPort == 443 && pkt.Protocol == driver.ProtoTCP {
		sni := e.tlsParser.ExtractSNI(pkt.Payload)
		if sni != "" {
			pkt.Domain = sni
			pkt.DomainSource = "SNI"

			// Check domain blocklist - send RST for blocked HTTPS
			if e.isDomainBlocked(sni) {
				e.sendTCPReset(pkt)
				atomic.AddUint64(&e.domainsBlocked, 1)
				return false
			}
		}
	}

	// Step 6: Extract domain from HTTP Host (port 80)
	if dstPort == 80 && pkt.Protocol == driver.ProtoTCP {
		host := e.httpParser.ExtractHost(pkt.Payload)
		if host != "" {
			pkt.Domain = host
			pkt.DomainSource = "HTTP"

			// Check domain blocklist - inject HTML block page for HTTP
			if e.isDomainBlocked(host) {
				e.injectHTMLBlockPage(pkt, host)
				atomic.AddUint64(&e.domainsBlocked, 1)
				return false
			}
		}
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

// isWebTraffic returns true for DNS/HTTP/HTTPS ports
func isWebTraffic(dstPort, srcPort uint16) bool {
	return dstPort == 53 || dstPort == 80 || dstPort == 443 || srcPort == 53
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
	} else {
		e.log.Info("DNS redirect injected", map[string]interface{}{
			"domain":      domain,
			"redirect_ip": redirectIP.String(),
		})
	}
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
	exePath, err := os.Executable()
	if err == nil {
		exeDir := filepath.Dir(exePath)
		candidates := []string{
			filepath.Join(exeDir, "configs", "domains.txt"),
			filepath.Join(exeDir, "..", "configs", "domains.txt"),
		}
		for _, c := range candidates {
			if _, err := os.Stat(c); err == nil {
				return c
			}
		}
	}
	// Fallback: current directory
	if _, err := os.Stat(filepath.Join("configs", "domains.txt")); err == nil {
		return filepath.Join("configs", "domains.txt")
	}
	return ""
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

	stats := map[string]interface{}{
		"packets_read":       read,
		"packets_written":    written,
		"packets_dropped":    dropped,
		"fast_path_packets":  atomic.LoadUint64(&e.fastPathPackets),
		"slow_path_packets":  atomic.LoadUint64(&e.slowPathPackets),
		"sampled_packets":    atomic.LoadUint64(&e.sampledPackets),
		"sample_rate":        e.sampleRate,
		"domains_blocked":    atomic.LoadUint64(&e.domainsBlocked),
		"blocked_domain_count": blockedDomainCount,
		"grpc_subscribers":   e.grpcServer.SubscriberCount(),
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
