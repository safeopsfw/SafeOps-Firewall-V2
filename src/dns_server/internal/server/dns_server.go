// Package server implements UDP and TCP DNS listeners.
package server

import (
	"context"
	"log"
	"net"
	"sync"
	"time"

	"safeops/dns_server/internal/protocol"
)

// ============================================================================
// UDP Server
// ============================================================================

// UDPServer handles DNS queries over UDP
type UDPServer struct {
	addr    string
	handler *protocol.Handler
	conn    *net.UDPConn
	running bool
	wg      sync.WaitGroup
	mu      sync.Mutex
}

// NewUDPServer creates a new UDP DNS server
func NewUDPServer(addr string, handler *protocol.Handler) *UDPServer {
	return &UDPServer{
		addr:    addr,
		handler: handler,
	}
}

// Start begins listening for UDP DNS queries
func (s *UDPServer) Start() error {
	addr, err := net.ResolveUDPAddr("udp", s.addr)
	if err != nil {
		return err
	}

	conn, err := net.ListenUDP("udp", addr)
	if err != nil {
		return err
	}

	s.mu.Lock()
	s.conn = conn
	s.running = true
	s.mu.Unlock()

	log.Printf("DNS UDP server listening on %s", s.addr)

	s.wg.Add(1)
	go s.serve()

	return nil
}

// Stop gracefully shuts down the UDP server
func (s *UDPServer) Stop() error {
	s.mu.Lock()
	s.running = false
	if s.conn != nil {
		s.conn.Close()
	}
	s.mu.Unlock()

	s.wg.Wait()
	log.Printf("DNS UDP server stopped")
	return nil
}

func (s *UDPServer) serve() {
	defer s.wg.Done()

	buffer := make([]byte, 512) // Standard DNS UDP packet size

	for {
		s.mu.Lock()
		running := s.running
		s.mu.Unlock()

		if !running {
			break
		}

		// Set read deadline for graceful shutdown
		s.conn.SetReadDeadline(time.Now().Add(1 * time.Second))

		n, clientAddr, err := s.conn.ReadFromUDP(buffer)
		if err != nil {
			if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
				continue
			}
			if !s.running {
				break
			}
			log.Printf("UDP read error: %v", err)
			continue
		}

		// Handle query in goroutine
		packet := make([]byte, n)
		copy(packet, buffer[:n])
		go s.handleQuery(packet, clientAddr)
	}
}

func (s *UDPServer) handleQuery(packet []byte, clientAddr *net.UDPAddr) {
	// Parse query
	query, err := protocol.ParseDNSPacket(packet)
	if err != nil {
		log.Printf("Failed to parse DNS packet: %v", err)
		return
	}

	// Process query
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	response := s.handler.HandleQuery(ctx, query, clientAddr.IP)

	// Serialize response
	responseBytes, err := protocol.SerializeDNSMessage(response)
	if err != nil {
		log.Printf("Failed to serialize response: %v", err)
		return
	}

	// Check if response needs truncation
	if len(responseBytes) > 512 {
		response.Flags.TC = true // Set truncated flag
		responseBytes, _ = protocol.SerializeDNSMessage(response)
		if len(responseBytes) > 512 {
			responseBytes = responseBytes[:512]
		}
	}

	// Send response
	_, err = s.conn.WriteToUDP(responseBytes, clientAddr)
	if err != nil {
		log.Printf("UDP write error: %v", err)
	}
}

// ============================================================================
// TCP Server
// ============================================================================

// TCPServer handles DNS queries over TCP
type TCPServer struct {
	addr     string
	handler  *protocol.Handler
	listener net.Listener
	running  bool
	wg       sync.WaitGroup
	mu       sync.Mutex
}

// NewTCPServer creates a new TCP DNS server
func NewTCPServer(addr string, handler *protocol.Handler) *TCPServer {
	return &TCPServer{
		addr:    addr,
		handler: handler,
	}
}

// Start begins listening for TCP DNS connections
func (s *TCPServer) Start() error {
	listener, err := net.Listen("tcp", s.addr)
	if err != nil {
		return err
	}

	s.mu.Lock()
	s.listener = listener
	s.running = true
	s.mu.Unlock()

	log.Printf("DNS TCP server listening on %s", s.addr)

	s.wg.Add(1)
	go s.serve()

	return nil
}

// Stop gracefully shuts down the TCP server
func (s *TCPServer) Stop() error {
	s.mu.Lock()
	s.running = false
	if s.listener != nil {
		s.listener.Close()
	}
	s.mu.Unlock()

	s.wg.Wait()
	log.Printf("DNS TCP server stopped")
	return nil
}

func (s *TCPServer) serve() {
	defer s.wg.Done()

	for {
		s.mu.Lock()
		running := s.running
		s.mu.Unlock()

		if !running {
			break
		}

		conn, err := s.listener.Accept()
		if err != nil {
			if !s.running {
				break
			}
			log.Printf("TCP accept error: %v", err)
			continue
		}

		s.wg.Add(1)
		go s.handleConnection(conn)
	}
}

func (s *TCPServer) handleConnection(conn net.Conn) {
	defer s.wg.Done()
	defer conn.Close()

	// Set connection deadline
	conn.SetDeadline(time.Now().Add(30 * time.Second))

	clientIP := conn.RemoteAddr().(*net.TCPAddr).IP

	for {
		// Read 2-byte length prefix
		lengthBuf := make([]byte, 2)
		_, err := conn.Read(lengthBuf)
		if err != nil {
			return // Connection closed or timeout
		}

		// Calculate message length
		msgLength := int(lengthBuf[0])<<8 | int(lengthBuf[1])
		if msgLength > 65535 || msgLength < 12 {
			return
		}

		// Read DNS message
		msgBuf := make([]byte, msgLength)
		totalRead := 0
		for totalRead < msgLength {
			n, err := conn.Read(msgBuf[totalRead:])
			if err != nil {
				return
			}
			totalRead += n
		}

		// Parse query
		query, err := protocol.ParseDNSPacket(msgBuf)
		if err != nil {
			log.Printf("Failed to parse TCP DNS packet: %v", err)
			continue
		}

		// Process query
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		response := s.handler.HandleQuery(ctx, query, clientIP)
		cancel()

		// Serialize response
		responseBytes, err := protocol.SerializeDNSMessage(response)
		if err != nil {
			log.Printf("Failed to serialize response: %v", err)
			continue
		}

		// Write length prefix + response
		tcpResponse := make([]byte, 2+len(responseBytes))
		tcpResponse[0] = byte(len(responseBytes) >> 8)
		tcpResponse[1] = byte(len(responseBytes))
		copy(tcpResponse[2:], responseBytes)

		_, err = conn.Write(tcpResponse)
		if err != nil {
			return
		}
	}
}

// ============================================================================
// Combined DNS Server
// ============================================================================

// DNSServer runs both UDP and TCP DNS servers
type DNSServer struct {
	udp     *UDPServer
	tcp     *TCPServer
	handler *protocol.Handler
}

// NewDNSServer creates a combined UDP+TCP DNS server
func NewDNSServer(addr string, handler *protocol.Handler) *DNSServer {
	return &DNSServer{
		udp:     NewUDPServer(addr, handler),
		tcp:     NewTCPServer(addr, handler),
		handler: handler,
	}
}

// Start begins listening on both UDP and TCP
func (s *DNSServer) Start() error {
	if err := s.udp.Start(); err != nil {
		return err
	}
	if err := s.tcp.Start(); err != nil {
		s.udp.Stop()
		return err
	}
	return nil
}

// Stop gracefully shuts down both servers
func (s *DNSServer) Stop() error {
	s.udp.Stop()
	s.tcp.Stop()
	return nil
}

// GetHandler returns the DNS handler
func (s *DNSServer) GetHandler() *protocol.Handler {
	return s.handler
}
