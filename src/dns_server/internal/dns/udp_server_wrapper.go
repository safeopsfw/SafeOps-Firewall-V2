// Package dns provides Phase 3A wrapper for TLS Proxy integration.
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
)

// UDPServerWithTLSProxy wraps the UDPServer to inject TLS Proxy decisions.
type UDPServerWithTLSProxy struct {
	baseServer       *UDPServer
	tlsProxyResolver *TLSProxyResolver
	conn             *net.UDPConn
	running          bool
	mutex            sync.RWMutex
	wg               sync.WaitGroup
	ctx              context.Context
	cancel           context.CancelFunc
}

// NewUDPServerWithTLSProxy creates a wrapped server with TLS Proxy integration.
func NewUDPServerWithTLSProxy(baseServer *UDPServer, tlsProxyResolver *TLSProxyResolver) *UDPServerWithTLSProxy {
	ctx, cancel := context.WithCancel(context.Background())
	return &UDPServerWithTLSProxy{
		baseServer:       baseServer,
		tlsProxyResolver: tlsProxyResolver,
		ctx:              ctx,
		cancel:           cancel,
	}
}

// Start begins listening for DNS queries with TLS Proxy integration.
func (s *UDPServerWithTLSProxy) Start() error {
	bindAddr := s.baseServer.GetBindAddress()
	addr, err := net.ResolveUDPAddr("udp", bindAddr)
	if err != nil {
		return err
	}

	conn, err := net.ListenUDP("udp", addr)
	if err != nil {
		return err
	}

	s.conn = conn
	s.setRunning(true)

	log.Printf("UDP server with TLS Proxy listening on %s", bindAddr)

	buffer := make([]byte, 4096)

	for s.isRunning() {
		s.conn.SetReadDeadline(time.Now().Add(1 * time.Second))

		n, clientAddr, err := s.conn.ReadFromUDP(buffer)
		if err != nil {
			if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
				continue
			}
			if !s.isRunning() {
				break
			}
			log.Printf("Read error: %v", err)
			continue
		}

		packet := make([]byte, n)
		copy(packet, buffer[:n])

		s.wg.Add(1)
		go s.handleQueryWithTLSProxy(packet, clientAddr)
	}

	return nil
}

// handleQueryWithTLSProxy processes queries with TLS Proxy decision injection.
func (s *UDPServerWithTLSProxy) handleQueryWithTLSProxy(packet []byte, clientAddr *net.UDPAddr) {
	defer s.wg.Done()

	msg := new(dns.Msg)
	if err := msg.Unpack(packet); err != nil {
		log.Printf("Failed to parse DNS query: %v", err)
		return
	}

	if len(msg.Question) == 0 {
		return
	}

	question := msg.Question[0]
	query := &models.DNSQuery{
		Domain:           strings.TrimSuffix(strings.ToLower(question.Name), "."),
		QueryType:        queryTypeToString(question.Qtype),
		ClientIP:         clientAddr.IP.String(),
		QueryID:          msg.Id,
		RecursionDesired: msg.RecursionDesired,
	}

	log.Printf("Query: %s %s from %s", query.QueryType, query.Domain, query.ClientIP)

	var response []byte
	var err error

	// PHASE 3A: Step 0 - Query TLS Proxy FIRST
	if s.tlsProxyResolver != nil && s.tlsProxyResolver.IsEnabled() {
		decision := s.tlsProxyResolver.GetDecision(query)

		if decision.ShouldHandle {
			// TLS Proxy told us to handle this
			if decision.Block {
				// Block with NXDOMAIN
				log.Printf("[TLS Proxy] Blocking %s", query.Domain)
				response, err = s.baseServer.responseBuilder.BuildNXDomainResponse(query)
			} else if decision.IP != "" {
				// Return specific IP from TLS Proxy
				log.Printf("[TLS Proxy] Returning %s -> %s", query.Domain, decision.IP)
				result := &models.UpstreamResult{
					Success:      true,
					IP:           decision.IP,
					TTL:          int(decision.TTL),
					ResponseTime: 0,
					Error:        nil,
				}
				response, err = s.baseServer.responseBuilder.BuildResponseFromUpstream(query, result)
			}

			if response != nil {
				s.conn.WriteToUDP(response, clientAddr)
				return
			}
		}

		// If decision.Forward=true, fall through to normal resolution
	}

	// Normal resolution flow (check zone -> cache -> upstream)
	if s.baseServer.zoneResolver.IsAuthoritative(query) {
		response, err = s.baseServer.responseBuilder.BuildServFailResponse(query)
	} else {
		entry, cacheResult := s.baseServer.cache.Get(query.Domain)

		if cacheResult == models.CacheHit {
			log.Printf("Cache HIT: %s -> %s", query.Domain, entry.IP)
			response, err = s.baseServer.responseBuilder.BuildResponseFromCache(query, entry)
		} else {
			log.Printf("Cache MISS: %s, forwarding to upstream", query.Domain)
			result := s.baseServer.upstreamResolver.Resolve(query)

			if result.Success {
				log.Printf("Upstream resolved: %s -> %s (TTL: %d)", query.Domain, result.IP, result.TTL)
				s.baseServer.cache.Set(query.Domain, result.IP, result.TTL)
				response, err = s.baseServer.responseBuilder.BuildResponseFromUpstream(query, result)
			} else {
				if result.Error != nil && strings.Contains(result.Error.Error(), "NXDOMAIN") {
					response, err = s.baseServer.responseBuilder.BuildNXDomainResponse(query)
				} else {
					response, err = s.baseServer.responseBuilder.BuildServFailResponse(query)
				}
			}
		}
	}

	if err != nil {
		log.Printf("Failed to build response: %v", err)
		return
	}

	s.conn.WriteToUDP(response, clientAddr)
}

// Shutdown gracefully stops the server.
func (s *UDPServerWithTLSProxy) Shutdown() error {
	log.Println("Shutting down UDP server with TLS Proxy...")

	s.setRunning(false)
	s.cancel()

	if s.conn != nil {
		s.conn.Close()
	}

	done := make(chan struct{})
	go func() {
		s.wg.Wait()
		close(done)
	}()

	select {
	case <-done:
		log.Println("All queries completed")
	case <-time.After(5 * time.Second):
		log.Println("Shutdown timeout")
	}

	if s.tlsProxyResolver != nil {
		s.tlsProxyResolver.Close()
	}

	return nil
}

func (s *UDPServerWithTLSProxy) isRunning() bool {
	s.mutex.RLock()
	defer s.mutex.RUnlock()
	return s.running
}

func (s *UDPServerWithTLSProxy) setRunning(running bool) {
	s.mutex.Lock()
	defer s.mutex.Unlock()
	s.running = running
}

func queryTypeToString(qtype uint16) string {
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
