// ============================================================================
// SafeOps TLS Proxy - TCP Connection Manager for MITM
// ============================================================================
// File: D:\SafeOpsFV2\src\tls_proxy\internal\tcp\connection_manager.go
// Purpose: Manages TCP connection hijacking for HTTPS MITM inspection
//
// Architecture Challenge:
//   WinDivert captures packets at the kernel level, giving us individual
//   packets rather than TCP connections. To perform MITM, we need to:
//
//   1. Detect TLS ClientHello packet from device
//   2. DROP the original packet (prevent it from reaching destination)
//   3. Establish connection WITH device (using generated cert)
//   4. Establish connection TO real server (verify server cert)
//   5. Proxy decrypted traffic bidirectionally
//
// Flow:
//   Device → TLS ClientHello → [WinDivert captures] → TLS Proxy
//     ↓
//   TLS Proxy: DROP packet (don't forward to real server)
//     ↓
//   TLS Proxy: Accept connection from device on port 443
//     ↓
//   Device ←[TLS handshake]→ TLS Proxy ←[TLS handshake]→ Real Server
//     ↓
//   Decrypted traffic flows through proxy
//
// Implementation:
//   This module manages active MITM connections using a connection pool.
//   Each connection is tracked by source IP + source port + domain.
//
// Author: SafeOps Phase 3B
// Date: 2026-01-04
// ============================================================================

package tcp

import (
	"crypto/tls"
	"fmt"
	"io"
	"log"
	"net"
	"sync"
	"time"

	"tls_proxy/internal/certcache"
)

// ConnectionKey uniquely identifies a TCP connection
type ConnectionKey struct {
	SourceIP   string
	SourcePort uint32
	Domain     string
}

// String returns string representation of connection key
func (k ConnectionKey) String() string {
	return fmt.Sprintf("%s:%d→%s", k.SourceIP, k.SourcePort, k.Domain)
}

// MITMConnection represents an active MITM TLS connection
type MITMConnection struct {
	Key           ConnectionKey
	ClientConn    net.Conn      // Connection to device
	ServerConn    net.Conn      // Connection to real server
	Domain        string        // Target domain
	StartTime     time.Time     // When connection started
	BytesUp       int64         // Bytes uploaded (device → server)
	BytesDown     int64         // Bytes downloaded (server → device)
	Active        bool          // Connection is active
	mu            sync.Mutex    // Protects connection state
	onClose       func(string)  // Callback when connection closes
}

// ConnectionManager manages active MITM connections
type ConnectionManager struct {
	connections map[ConnectionKey]*MITMConnection
	mu          sync.RWMutex
	certCache   *certcache.CertificateCache
	inspector   TrafficInspector // Interface for inspecting decrypted traffic
}

// TrafficInspector interface for inspecting decrypted traffic
type TrafficInspector interface {
	InspectData(domain, direction string, data []byte)
}

// NewConnectionManager creates a new connection manager
func NewConnectionManager(certCache *certcache.CertificateCache, inspector TrafficInspector) *ConnectionManager {
	return &ConnectionManager{
		connections: make(map[ConnectionKey]*MITMConnection),
		certCache:   certCache,
		inspector:   inspector,
	}
}

// StartMITM initiates MITM for a TLS connection
// This is called when we detect a ClientHello packet
func (cm *ConnectionManager) StartMITM(sourceIP string, sourcePort uint32, domain string) error {
	key := ConnectionKey{
		SourceIP:   sourceIP,
		SourcePort: sourcePort,
		Domain:     domain,
	}

	// Check if connection already exists
	cm.mu.RLock()
	if _, exists := cm.connections[key]; exists {
		cm.mu.RUnlock()
		log.Printf("[Connection Manager] MITM already active for %s", key.String())
		return nil
	}
	cm.mu.RUnlock()

	log.Printf("[Connection Manager] Starting MITM for %s", key.String())

	// Get or generate certificate for this domain
	certEntry, err := cm.certCache.GetOrGenerate(domain)
	if err != nil {
		return fmt.Errorf("failed to get certificate: %w", err)
	}

	// Create TLS config for client-facing connection
	clientTLSConfig := &tls.Config{
		Certificates: []tls.Certificate{*certEntry.Certificate},
		ServerName:   domain,
		MinVersion:   tls.VersionTLS12,
	}

	// Create TLS config for server connection
	serverTLSConfig := &tls.Config{
		ServerName:         domain,
		InsecureSkipVerify: false, // Verify real server certificate
		MinVersion:         tls.VersionTLS12,
	}

	// Establish connection to real server FIRST
	serverConn, err := tls.Dial("tcp", domain+":443", serverTLSConfig)
	if err != nil {
		return fmt.Errorf("failed to connect to server %s: %w", domain, err)
	}

	log.Printf("[Connection Manager] ✓ Connected to real server: %s", domain)

	// Listen for client connection on dynamic port
	// Note: We can't directly hijack the connection in Go due to OS limitations
	// This is a simplified version - real implementation would need lower-level networking
	listener, err := net.Listen("tcp", ":0") // Dynamic port
	if err != nil {
		serverConn.Close()
		return fmt.Errorf("failed to create listener: %w", err)
	}

	localPort := listener.Addr().(*net.TCPAddr).Port
	log.Printf("[Connection Manager] Listening on port %d for client connection", localPort)

	// Accept client connection (with timeout)
	go func() {
		listener.(*net.TCPListener).SetDeadline(time.Now().Add(5 * time.Second))
		clientConn, err := listener.Accept()
		listener.Close()

		if err != nil {
			log.Printf("[Connection Manager] Failed to accept client: %v", err)
			serverConn.Close()
			return
		}

		log.Printf("[Connection Manager] ✓ Client connected from %s", clientConn.RemoteAddr())

		// Wrap with TLS
		clientTLS := tls.Server(clientConn, clientTLSConfig)
		if err := clientTLS.Handshake(); err != nil {
			log.Printf("[Connection Manager] Client TLS handshake failed: %v", err)
			clientConn.Close()
			serverConn.Close()
			return
		}

		log.Printf("[Connection Manager] ✓ Dual TLS established for %s", domain)

		// Create MITM connection
		mitmConn := &MITMConnection{
			Key:        key,
			ClientConn: clientTLS,
			ServerConn: serverConn,
			Domain:     domain,
			StartTime:  time.Now(),
			Active:     true,
			onClose: func(connKey string) {
				cm.removeConnection(key)
			},
		}

		// Store connection
		cm.mu.Lock()
		cm.connections[key] = mitmConn
		cm.mu.Unlock()

		// Start proxying
		cm.proxyConnection(mitmConn)
	}()

	return nil
}

// proxyConnection proxies traffic bidirectionally with inspection
func (cm *ConnectionManager) proxyConnection(conn *MITMConnection) {
	defer func() {
		conn.Active = false
		conn.ClientConn.Close()
		conn.ServerConn.Close()

		duration := time.Since(conn.StartTime)
		log.Printf("[Connection Manager] Connection closed: %s (duration: %v, up: %d bytes, down: %d bytes)",
			conn.Key.String(), duration, conn.BytesUp, conn.BytesDown)

		if conn.onClose != nil {
			conn.onClose(conn.Key.String())
		}
	}()

	var wg sync.WaitGroup
	wg.Add(2)

	// Client → Server (upload)
	go func() {
		defer wg.Done()
		cm.proxyDirection(conn.ClientConn, conn.ServerConn, "upload", conn)
	}()

	// Server → Client (download)
	go func() {
		defer wg.Done()
		cm.proxyDirection(conn.ServerConn, conn.ClientConn, "download", conn)
	}()

	wg.Wait()
}

// proxyDirection proxies data in one direction with inspection
func (cm *ConnectionManager) proxyDirection(src, dst net.Conn, direction string, conn *MITMConnection) {
	buffer := make([]byte, 32768) // 32KB buffer

	for {
		// Read from source
		n, err := src.Read(buffer)
		if err != nil {
			if err != io.EOF {
				log.Printf("[Connection Manager] Read error (%s %s): %v", conn.Domain, direction, err)
			}
			return
		}

		if n == 0 {
			continue
		}

		data := buffer[:n]

		// Inspect decrypted traffic
		if cm.inspector != nil {
			cm.inspector.InspectData(conn.Domain, direction, data)
		}

		// Update byte counts
		conn.mu.Lock()
		if direction == "upload" {
			conn.BytesUp += int64(n)
		} else {
			conn.BytesDown += int64(n)
		}
		conn.mu.Unlock()

		// Write to destination
		_, err = dst.Write(data)
		if err != nil {
			log.Printf("[Connection Manager] Write error (%s %s): %v", conn.Domain, direction, err)
			return
		}
	}
}

// removeConnection removes a connection from the pool
func (cm *ConnectionManager) removeConnection(key ConnectionKey) {
	cm.mu.Lock()
	defer cm.mu.Unlock()

	delete(cm.connections, key)
	log.Printf("[Connection Manager] Removed connection: %s (total active: %d)", key.String(), len(cm.connections))
}

// GetActiveConnections returns the number of active connections
func (cm *ConnectionManager) GetActiveConnections() int {
	cm.mu.RLock()
	defer cm.mu.RUnlock()
	return len(cm.connections)
}

// GetStats returns connection statistics
func (cm *ConnectionManager) GetStats() map[string]interface{} {
	cm.mu.RLock()
	defer cm.mu.RUnlock()

	totalUp := int64(0)
	totalDown := int64(0)
	activeCount := 0

	for _, conn := range cm.connections {
		if conn.Active {
			activeCount++
			conn.mu.Lock()
			totalUp += conn.BytesUp
			totalDown += conn.BytesDown
			conn.mu.Unlock()
		}
	}

	return map[string]interface{}{
		"active_connections": activeCount,
		"total_connections":  len(cm.connections),
		"bytes_uploaded":     totalUp,
		"bytes_downloaded":   totalDown,
	}
}

// Close closes all active connections
func (cm *ConnectionManager) Close() {
	cm.mu.Lock()
	defer cm.mu.Unlock()

	for _, conn := range cm.connections {
		conn.Active = false
		conn.ClientConn.Close()
		conn.ServerConn.Close()
	}

	cm.connections = make(map[ConnectionKey]*MITMConnection)
	log.Println("[Connection Manager] All connections closed")
}
