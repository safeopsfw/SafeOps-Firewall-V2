// ============================================================================
// SafeOps TLS Proxy - Transparent HTTPS Proxy Listener
// ============================================================================
// File: D:\SafeOpsFV2\src\tls_proxy\internal\transparent\proxy_listener.go
// Purpose: Transparent HTTPS proxy that intercepts TLS connections on gateway
//
// Architecture:
//   This proxy listens on the gateway IP (192.168.137.1:443) and intercepts
//   ALL HTTPS traffic from devices on the network. It performs MITM inspection
//   by establishing dual TLS connections.
//
// Flow:
//   1. Device connects to gateway:443 (thinks it's connecting to real server)
//   2. Proxy reads ClientHello to extract SNI (domain name)
//   3. Proxy gets/generates certificate for that domain
//   4. Proxy completes TLS handshake with device (using generated cert)
//   5. Proxy establishes TLS connection to real server
//   6. Proxy bidirectionally proxies traffic with inspection
//
// Security:
//   - Only inspects devices that have installed SafeOps Root CA
//   - Verifies device trust status via DHCP Monitor
//   - Falls back to direct forwarding for untrusted devices
//
// Author: SafeOps Phase 3B
// Date: 2026-01-04
// ============================================================================

package transparent

import (
	"crypto/tls"
	"fmt"
	"io"
	"log"
	"net"
	"sync"
	"time"

	"tls_proxy/internal/certcache"
	"tls_proxy/internal/integration"
	"tls_proxy/internal/sni_parser"
)

// TransparentProxy is a transparent HTTPS proxy for MITM inspection
type TransparentProxy struct {
	listener     net.Listener
	certCache    *certcache.CertificateCache
	dhcpMonitor  *integration.DHCPMonitorClient
	inspector    *TrafficInspector
	listenAddr   string
	activeConns  int64
	totalConns   int64
	mu           sync.RWMutex
	shutdownChan chan struct{}
}

// NewTransparentProxy creates a new transparent proxy
func NewTransparentProxy(
	listenAddr string,
	certCache *certcache.CertificateCache,
	dhcpMonitor *integration.DHCPMonitorClient,
	logHTTP bool,
) *TransparentProxy {
	return &TransparentProxy{
		certCache:    certCache,
		dhcpMonitor:  dhcpMonitor,
		listenAddr:   listenAddr,
		inspector:    NewTrafficInspector(logHTTP, false, 2048),
		shutdownChan: make(chan struct{}),
	}
}

// Start starts the transparent proxy (blocking)
func (p *TransparentProxy) Start() error {
	listener, err := net.Listen("tcp", p.listenAddr)
	if err != nil {
		return fmt.Errorf("failed to start transparent proxy: %w", err)
	}

	p.listener = listener
	log.Printf("[Transparent Proxy] ✓ Listening on %s for HTTPS MITM", p.listenAddr)

	for {
		select {
		case <-p.shutdownChan:
			log.Println("[Transparent Proxy] Shutting down...")
			return nil
		default:
		}

		conn, err := listener.Accept()
		if err != nil {
			select {
			case <-p.shutdownChan:
				return nil
			default:
				log.Printf("[Transparent Proxy] Accept error: %v", err)
				continue
			}
		}

		// Increment connection counters
		p.mu.Lock()
		p.activeConns++
		p.totalConns++
		p.mu.Unlock()

		// Handle connection in goroutine
		go p.handleConnection(conn)
	}
}

// handleConnection handles a single HTTPS connection with MITM
func (p *TransparentProxy) handleConnection(clientConn net.Conn) {
	defer func() {
		clientConn.Close()
		p.mu.Lock()
		p.activeConns--
		p.mu.Unlock()
	}()

	clientAddr := clientConn.RemoteAddr().String()
	clientIP, _, _ := net.SplitHostPort(clientAddr)

	log.Printf("[Transparent Proxy] New connection from %s", clientAddr)

	// Set read deadline for initial handshake
	clientConn.SetReadDeadline(time.Now().Add(10 * time.Second))

	// Peek at first packet to extract SNI without consuming it
	// We need to read the ClientHello to get the SNI
	buffer := make([]byte, 4096)
	n, err := clientConn.Read(buffer)
	if err != nil {
		log.Printf("[Transparent Proxy] Failed to read ClientHello: %v", err)
		return
	}

	clientHello := buffer[:n]

	// Extract SNI from ClientHello
	sniInfo, err := sni_parser.ExtractSNI(clientHello)
	if err != nil || !sniInfo.Found {
		log.Printf("[Transparent Proxy] No SNI found in ClientHello, closing connection")
		return
	}

	domain := sniInfo.Domain
	log.Printf("[Transparent Proxy] SNI: %s from %s", domain, clientIP)

	// Check device trust status
	if p.dhcpMonitor != nil {
		deviceInfo, err := p.dhcpMonitor.GetDeviceByIP(nil, clientIP)
		if err == nil {
			if !deviceInfo.CaCertInstalled || deviceInfo.TrustStatus != "TRUSTED" {
				log.Printf("[Transparent Proxy] ⚠️  Device %s not trusted or CA not installed - closing", clientIP)
				// Note: We can't forward to real server here because we already consumed the ClientHello
				// Device will retry and should be handled by packet processor to forward directly
				return
			}
		}
	}

	// Get or generate certificate for this domain
	certEntry, err := p.certCache.GetOrGenerate(domain)
	if err != nil {
		log.Printf("[Transparent Proxy] Failed to get certificate for %s: %v", domain, err)
		return
	}

	// Create TLS config for client-facing connection
	clientTLSConfig := &tls.Config{
		Certificates: []tls.Certificate{*certEntry.Certificate},
		MinVersion:   tls.VersionTLS12,
	}

	// We need to replay the ClientHello we already read
	// Create a custom connection that includes the buffered data
	bufferedConn := &bufferedConn{
		Conn:   clientConn,
		buffer: clientHello,
		offset: 0,
	}

	// Wrap client connection with TLS
	clientTLS := tls.Server(bufferedConn, clientTLSConfig)

	// Remove read deadline for handshake
	clientConn.SetReadDeadline(time.Time{})

	// Perform TLS handshake with client
	if err := clientTLS.Handshake(); err != nil {
		log.Printf("[Transparent Proxy] Client TLS handshake failed for %s: %v", domain, err)
		return
	}

	log.Printf("[Transparent Proxy] ✓ Client TLS handshake successful: %s", domain)

	// Establish TLS connection to real server
	serverTLSConfig := &tls.Config{
		ServerName:         domain,
		InsecureSkipVerify: false, // Verify real server certificate
		MinVersion:         tls.VersionTLS12,
	}

	serverConn, err := tls.Dial("tcp", domain+":443", serverTLSConfig)
	if err != nil {
		log.Printf("[Transparent Proxy] Failed to connect to real server %s: %v", domain, err)
		return
	}
	defer serverConn.Close()

	log.Printf("[Transparent Proxy] ✓ Server TLS connection established: %s", domain)
	log.Printf("[Transparent Proxy] ✓✓✓ DUAL TLS ACTIVE: %s ↔ Proxy ↔ %s ✓✓✓", clientIP, domain)

	// Proxy traffic bidirectionally with inspection
	p.proxyConnections(clientTLS, serverConn, domain, clientIP)

	log.Printf("[Transparent Proxy] Connection closed: %s", domain)
}

// proxyConnections proxies data bidirectionally between client and server
func (p *TransparentProxy) proxyConnections(clientConn, serverConn net.Conn, domain, clientIP string) {
	var wg sync.WaitGroup
	wg.Add(2)

	// Client → Server (upload)
	go func() {
		defer wg.Done()
		p.proxyDirection(clientConn, serverConn, "upload", domain, clientIP)
	}()

	// Server → Client (download)
	go func() {
		defer wg.Done()
		p.proxyDirection(serverConn, clientConn, "download", domain, clientIP)
	}()

	wg.Wait()
}

// proxyDirection proxies data in one direction with inspection
func (p *TransparentProxy) proxyDirection(src, dst net.Conn, direction, domain, clientIP string) {
	buffer := make([]byte, 32768) // 32KB buffer

	for {
		// Read from source
		n, err := src.Read(buffer)
		if err != nil {
			if err != io.EOF {
				log.Printf("[Transparent Proxy] Read error (%s %s): %v", domain, direction, err)
			}
			return
		}

		if n == 0 {
			continue
		}

		data := buffer[:n]

		// Inspect decrypted traffic (console logging only)
		if p.inspector != nil {
			p.inspector.InspectData(domain, clientIP, direction, data)
		}

		// Write to destination
		_, err = dst.Write(data)
		if err != nil {
			log.Printf("[Transparent Proxy] Write error (%s %s): %v", domain, direction, err)
			return
		}
	}
}

// Stop stops the transparent proxy
func (p *TransparentProxy) Stop() {
	close(p.shutdownChan)
	if p.listener != nil {
		p.listener.Close()
	}
	log.Println("[Transparent Proxy] Stopped")
}

// GetStats returns proxy statistics
func (p *TransparentProxy) GetStats() map[string]interface{} {
	p.mu.RLock()
	defer p.mu.RUnlock()

	return map[string]interface{}{
		"active_connections": p.activeConns,
		"total_connections":  p.totalConns,
		"listen_address":     p.listenAddr,
	}
}

// bufferedConn wraps a connection and prepends buffered data
type bufferedConn struct {
	net.Conn
	buffer []byte
	offset int
}

// Read reads from buffered data first, then from underlying connection
func (bc *bufferedConn) Read(p []byte) (int, error) {
	if bc.offset < len(bc.buffer) {
		n := copy(p, bc.buffer[bc.offset:])
		bc.offset += n
		return n, nil
	}
	return bc.Conn.Read(p)
}

// TrafficInspector inspects decrypted HTTPS traffic
type TrafficInspector struct {
	logHTTP       bool
	logBinary     bool
	maxLogSize    int
	inspectedData int64
	mu            sync.Mutex
}

// NewTrafficInspector creates a new traffic inspector
func NewTrafficInspector(logHTTP, logBinary bool, maxLogSize int) *TrafficInspector {
	if maxLogSize == 0 {
		maxLogSize = 1024
	}

	return &TrafficInspector{
		logHTTP:    logHTTP,
		logBinary:  logBinary,
		maxLogSize: maxLogSize,
	}
}

// InspectData inspects decrypted data
func (i *TrafficInspector) InspectData(domain, clientIP, direction string, data []byte) {
	if len(data) == 0 {
		return
	}

	i.mu.Lock()
	i.inspectedData += int64(len(data))
	i.mu.Unlock()

	// Check if data looks like HTTP
	if isHTTPData(data) && i.logHTTP {
		i.logHTTPData(domain, clientIP, direction, data)
	} else if i.logBinary {
		log.Printf("[Traffic Inspector] %s (%s %s) Binary: %d bytes", domain, clientIP, direction, len(data))
	}
}

// logHTTPData logs HTTP-like data
func (i *TrafficInspector) logHTTPData(domain, clientIP, direction string, data []byte) {
	logSize := len(data)
	if logSize > i.maxLogSize {
		logSize = i.maxLogSize
	}

	snippet := string(data[:logSize])
	log.Printf("[Traffic Inspector] %s (%s %s) HTTP:\n%s", domain, clientIP, direction, snippet)
}

// isHTTPData checks if data looks like HTTP
func isHTTPData(data []byte) bool {
	if len(data) < 4 {
		return false
	}

	// Check for common HTTP methods and response codes
	httpPrefixes := []string{"GET ", "POST ", "PUT ", "DELETE ", "PATCH ", "HEAD ", "HTTP/"}
	for _, prefix := range httpPrefixes {
		if len(data) >= len(prefix) && string(data[:len(prefix)]) == prefix {
			return true
		}
	}

	return false
}

// GetStats returns inspection statistics
func (i *TrafficInspector) GetStats() map[string]interface{} {
	i.mu.Lock()
	defer i.mu.Unlock()

	return map[string]interface{}{
		"inspected_bytes": i.inspectedData,
		"log_http":        i.logHTTP,
		"log_binary":      i.logBinary,
	}
}
