package mitm_handler

import (
	"crypto/tls"
	"fmt"
	"io"
	"log"
	"net"
	"sync"
	"time"

	"tls_proxy/internal/certcache"
	"tls_proxy/internal/sni_parser"
)

// DualTLSHandler manages dual TLS connections for MITM
// Device ↔ [TLS] ↔ Proxy ↔ [TLS] ↔ Server
type DualTLSHandler struct {
	certCache *certcache.CertificateCache
	inspector *TrafficInspector
}

// ConnectionPair represents both sides of a proxied connection
type ConnectionPair struct {
	ClientConn net.Conn
	ServerConn net.Conn
	Domain     string
	StartTime  time.Time
	BytesUp    int64
	BytesDown  int64
}

// NewDualTLSHandler creates a new dual TLS handler
func NewDualTLSHandler(certCache *certcache.CertificateCache, inspector *TrafficInspector) *DualTLSHandler {
	return &DualTLSHandler{
		certCache: certCache,
		inspector: inspector,
	}
}

// HandleConnection handles a TLS connection with MITM inspection
func (h *DualTLSHandler) HandleConnection(clientConn net.Conn, clientHelloPacket []byte) error {
	defer clientConn.Close()

	// Extract SNI from ClientHello
	sniInfo, err := sni_parser.ExtractSNI(clientHelloPacket)
	if err != nil || !sniInfo.Found {
		log.Printf("[MITM] Failed to extract SNI: %v", err)
		return fmt.Errorf("no SNI found")
	}

	domain := sniInfo.Domain
	log.Printf("[MITM] Intercepting TLS connection to %s (TLS version: %s)",
		domain, sni_parser.FormatTLSVersion(sniInfo.TLSVersion))

	// Get or generate certificate for this domain
	certEntry, err := h.certCache.GetOrGenerate(domain)
	if err != nil {
		log.Printf("[MITM] Failed to get certificate for %s: %v", domain, err)
		return err
	}

	// Create TLS config for client-facing connection
	clientTLSConfig := &tls.Config{
		Certificates: []tls.Certificate{*certEntry.Certificate},
		ServerName:   domain,
	}

	// Establish TLS connection with client (Device ↔ Proxy)
	clientTLS := tls.Server(clientConn, clientTLSConfig)
	if err := clientTLS.Handshake(); err != nil {
		log.Printf("[MITM] Client TLS handshake failed for %s: %v", domain, err)
		return err
	}

	log.Printf("[MITM] Client TLS handshake successful for %s", domain)

	// Establish TLS connection to real server (Proxy ↔ Server)
	serverTLSConfig := &tls.Config{
		ServerName:         domain,
		InsecureSkipVerify: false, // Verify real server certificate
	}

	serverConn, err := tls.Dial("tcp", domain+":443", serverTLSConfig)
	if err != nil {
		log.Printf("[MITM] Server TLS dial failed for %s: %v", domain, err)
		return err
	}
	defer serverConn.Close()

	log.Printf("[MITM] Server TLS connection established to %s", domain)

	// Create connection pair
	pair := &ConnectionPair{
		ClientConn: clientTLS,
		ServerConn: serverConn,
		Domain:     domain,
		StartTime:  time.Now(),
	}

	// Start bidirectional proxying with inspection
	h.proxyConnections(pair)

	duration := time.Since(pair.StartTime)
	log.Printf("[MITM] Connection closed: %s (duration: %v, up: %d bytes, down: %d bytes)",
		domain, duration, pair.BytesUp, pair.BytesDown)

	return nil
}

// proxyConnections proxies data between client and server with inspection
func (h *DualTLSHandler) proxyConnections(pair *ConnectionPair) {
	var wg sync.WaitGroup
	wg.Add(2)

	// Client → Server (upload)
	go func() {
		defer wg.Done()
		h.proxyDirection(pair.ClientConn, pair.ServerConn, "upload", pair)
	}()

	// Server → Client (download)
	go func() {
		defer wg.Done()
		h.proxyDirection(pair.ServerConn, pair.ClientConn, "download", pair)
	}()

	wg.Wait()
}

// proxyDirection proxies data in one direction with inspection
func (h *DualTLSHandler) proxyDirection(src, dst net.Conn, direction string, pair *ConnectionPair) {
	buffer := make([]byte, 32768) // 32KB buffer

	for {
		// Read from source
		n, err := src.Read(buffer)
		if err != nil {
			if err != io.EOF {
				log.Printf("[MITM] Read error (%s %s): %v", pair.Domain, direction, err)
			}
			return
		}

		if n == 0 {
			continue
		}

		data := buffer[:n]

		// Inspect traffic
		if h.inspector != nil {
			h.inspector.InspectData(pair.Domain, direction, data)
		}

		// Update byte counts
		if direction == "upload" {
			pair.BytesUp += int64(n)
		} else {
			pair.BytesDown += int64(n)
		}

		// Write to destination
		_, err = dst.Write(data)
		if err != nil {
			log.Printf("[MITM] Write error (%s %s): %v", pair.Domain, direction, err)
			return
		}
	}
}

// TrafficInspector inspects decrypted TLS traffic
type TrafficInspector struct {
	logHTTP       bool
	logBinary     bool
	maxLogSize    int
	inspectedData int64
}

// NewTrafficInspector creates a new traffic inspector
func NewTrafficInspector(logHTTP, logBinary bool, maxLogSize int) *TrafficInspector {
	if maxLogSize == 0 {
		maxLogSize = 1024 // Default 1KB max log
	}

	return &TrafficInspector{
		logHTTP:    logHTTP,
		logBinary:  logBinary,
		maxLogSize: maxLogSize,
	}
}

// InspectData inspects decrypted data
func (i *TrafficInspector) InspectData(domain, direction string, data []byte) {
	if len(data) == 0 {
		return
	}

	i.inspectedData += int64(len(data))

	// Check if data looks like HTTP
	if isHTTPData(data) && i.logHTTP {
		i.logHTTPData(domain, direction, data)
	} else if i.logBinary {
		i.logBinaryData(domain, direction, data)
	}
}

// logHTTPData logs HTTP-like data
func (i *TrafficInspector) logHTTPData(domain, direction string, data []byte) {
	logSize := len(data)
	if logSize > i.maxLogSize {
		logSize = i.maxLogSize
	}

	log.Printf("[Traffic Inspector] %s (%s) HTTP: %s", domain, direction, string(data[:logSize]))
}

// logBinaryData logs binary data summary
func (i *TrafficInspector) logBinaryData(domain, direction string, data []byte) {
	log.Printf("[Traffic Inspector] %s (%s) Binary: %d bytes", domain, direction, len(data))
}

// isHTTPData checks if data looks like HTTP
func isHTTPData(data []byte) bool {
	if len(data) < 4 {
		return false
	}

	// Check for common HTTP methods and response codes
	httpPrefixes := []string{"GET ", "POST ", "PUT ", "DELETE ", "HTTP/"}
	for _, prefix := range httpPrefixes {
		if len(data) >= len(prefix) && string(data[:len(prefix)]) == prefix {
			return true
		}
	}

	return false
}

// GetStats returns inspection statistics
func (i *TrafficInspector) GetStats() map[string]interface{} {
	return map[string]interface{}{
		"inspected_bytes": i.inspectedData,
		"log_http":        i.logHTTP,
		"log_binary":      i.logBinary,
	}
}
