// Package dns implements the UDP DNS server.
package dns

import (
	"context"
	"log"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/miekg/dns"

	"dns_server/internal/models"
	"dns_server/internal/recursive"
)

// =============================================================================
// UDP SERVER - Main DNS Query Handler
// =============================================================================

// UDPServer handles incoming DNS queries over UDP.
type UDPServer struct {
	// bindAddress is the UDP listen address (e.g., ":53")
	bindAddress string

	// cache is the DNS response cache
	cache *DNSCache

	// zoneResolver checks for authoritative zones
	zoneResolver *ZoneResolver

	// upstreamResolver forwards queries to upstream DNS
	upstreamResolver *recursive.UpstreamResolver

	// responseBuilder constructs DNS response packets
	responseBuilder *ResponseBuilder

	// conn is the UDP connection
	conn *net.UDPConn

	// running indicates if server is accepting connections
	running bool

	// mutex protects running flag
	mutex sync.RWMutex

	// wg tracks in-flight queries
	wg sync.WaitGroup

	// ctx for cancellation
	ctx    context.Context
	cancel context.CancelFunc
}

// =============================================================================
// CONSTRUCTOR
// =============================================================================

// NewUDPServer creates a new UDP DNS server with all dependencies.
func NewUDPServer(
	bindAddress string,
	cache *DNSCache,
	zoneResolver *ZoneResolver,
	upstreamResolver *recursive.UpstreamResolver,
	responseBuilder *ResponseBuilder,
) *UDPServer {
	ctx, cancel := context.WithCancel(context.Background())

	return &UDPServer{
		bindAddress:      bindAddress,
		cache:            cache,
		zoneResolver:     zoneResolver,
		upstreamResolver: upstreamResolver,
		responseBuilder:  responseBuilder,
		running:          false,
		ctx:              ctx,
		cancel:           cancel,
	}
}

// =============================================================================
// SERVER LIFECYCLE
// =============================================================================

// Start begins listening for DNS queries on the configured address.
func (s *UDPServer) Start() error {
	addr, err := net.ResolveUDPAddr("udp", s.bindAddress)
	if err != nil {
		return err
	}

	conn, err := net.ListenUDP("udp", addr)
	if err != nil {
		return err
	}

	s.conn = conn
	s.setRunning(true)

	log.Printf("UDP server listening on %s", s.bindAddress)

	// Read buffer
	buffer := make([]byte, 4096)

	for s.isRunning() {
		// Set read deadline to allow checking running flag
		s.conn.SetReadDeadline(time.Now().Add(1 * time.Second))

		n, clientAddr, err := s.conn.ReadFromUDP(buffer)
		if err != nil {
			if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
				continue // Normal timeout, check running flag
			}
			if !s.isRunning() {
				break // Server shutting down
			}
			log.Printf("Read error: %v", err)
			continue
		}

		// Copy packet data for goroutine
		packet := make([]byte, n)
		copy(packet, buffer[:n])

		// Handle query in goroutine
		s.wg.Add(1)
		go s.handleQuery(packet, clientAddr)
	}

	return nil
}

// Shutdown gracefully stops the UDP server.
func (s *UDPServer) Shutdown() error {
	log.Println("Shutting down UDP server...")

	s.setRunning(false)
	s.cancel()

	// Close connection to unblock ReadFromUDP
	if s.conn != nil {
		s.conn.Close()
	}

	// Wait for in-flight queries with timeout
	done := make(chan struct{})
	go func() {
		s.wg.Wait()
		close(done)
	}()

	select {
	case <-done:
		log.Println("All queries completed")
	case <-time.After(5 * time.Second):
		log.Println("Shutdown timeout, some queries may be dropped")
	}

	return nil
}

// =============================================================================
// QUERY HANDLING
// =============================================================================

// handleQuery processes a single DNS query.
func (s *UDPServer) handleQuery(packet []byte, clientAddr *net.UDPAddr) {
	defer s.wg.Done()

	// Parse incoming DNS message
	msg := new(dns.Msg)
	if err := msg.Unpack(packet); err != nil {
		log.Printf("Failed to parse DNS query from %s: %v", clientAddr, err)
		return
	}

	// Must have at least one question
	if len(msg.Question) == 0 {
		log.Printf("Empty question from %s", clientAddr)
		return
	}

	// Extract query info
	question := msg.Question[0]
	query := &models.DNSQuery{
		Domain:           strings.TrimSuffix(strings.ToLower(question.Name), "."),
		QueryType:        s.queryTypeToString(question.Qtype),
		ClientIP:         clientAddr.IP.String(),
		QueryID:          msg.Id,
		RecursionDesired: msg.RecursionDesired,
	}

	log.Printf("Query: %s %s from %s", query.QueryType, query.Domain, query.ClientIP)

	// Resolve query
	var response []byte
	var err error

	// Step 1: Check authoritative zones (Phase 1: always false)
	if s.zoneResolver.IsAuthoritative(query) {
		// Phase 2+: Would handle authoritative response here
		response, err = s.responseBuilder.BuildServFailResponse(query)
	} else {
		// Step 2: Check cache
		entry, cacheResult := s.cache.Get(query.Domain)

		if cacheResult == models.CacheHit {
			log.Printf("Cache HIT: %s -> %s", query.Domain, entry.IP)
			response, err = s.responseBuilder.BuildResponseFromCache(query, entry)
		} else {
			// Step 3: Forward to upstream
			log.Printf("Cache MISS: %s, forwarding to upstream", query.Domain)
			result := s.upstreamResolver.Resolve(query)

			if result.Success {
				log.Printf("Upstream resolved: %s -> %s (TTL: %d)", query.Domain, result.IP, result.TTL)
				// Cache the result
				s.cache.Set(query.Domain, result.IP, result.TTL)
				response, err = s.responseBuilder.BuildResponseFromUpstream(query, result)
			} else {
				log.Printf("Upstream failed for %s: %v", query.Domain, result.Error)
				// Check if NXDOMAIN
				if result.Error != nil && strings.Contains(result.Error.Error(), "NXDOMAIN") {
					response, err = s.responseBuilder.BuildNXDomainResponse(query)
				} else {
					response, err = s.responseBuilder.BuildServFailResponse(query)
				}
			}
		}
	}

	if err != nil {
		log.Printf("Failed to build response: %v", err)
		return
	}

	// Send response
	_, err = s.conn.WriteToUDP(response, clientAddr)
	if err != nil {
		log.Printf("Failed to send response to %s: %v", clientAddr, err)
	}
}

// =============================================================================
// HELPER METHODS
// =============================================================================

// isRunning returns whether the server is accepting connections.
func (s *UDPServer) isRunning() bool {
	s.mutex.RLock()
	defer s.mutex.RUnlock()
	return s.running
}

// setRunning updates the running state.
func (s *UDPServer) setRunning(running bool) {
	s.mutex.Lock()
	defer s.mutex.Unlock()
	s.running = running
}

// queryTypeToString converts DNS query type to string.
func (s *UDPServer) queryTypeToString(qtype uint16) string {
	switch qtype {
	case dns.TypeA:
		return models.QueryTypeA
	case dns.TypeAAAA:
		return models.QueryTypeAAAA
	case dns.TypePTR:
		return models.QueryTypePTR
	case dns.TypeCNAME:
		return models.QueryTypeCNAME
	default:
		return models.QueryTypeA
	}
}

// =============================================================================
// STATISTICS
// =============================================================================

// GetCacheStats returns current cache statistics.
func (s *UDPServer) GetCacheStats() CacheStats {
	return s.cache.GetStats()
}

// GetBindAddress returns the server's bind address.
func (s *UDPServer) GetBindAddress() string {
	return s.bindAddress
}
