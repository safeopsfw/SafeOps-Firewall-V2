// Package dns_hijack provides DNS hijacking for captive portal redirect
package dns_hijack

import (
	"context"
	"dhcp_monitor/internal/storage"
	"fmt"
	"net"
	"sync"
	"time"

	"github.com/miekg/dns"
)

// Server is a DNS server that hijacks queries for unenrolled devices
type Server struct {
	config      Config
	db          *storage.Database
	dnsServer   *dns.Server
	upstreamDNS string

	// Statistics
	mu               sync.RWMutex
	queriesTotal     uint64
	queriesHijacked  uint64
	queriesForwarded uint64
	queryErrors      uint64
}

// Config holds DNS server configuration
type Config struct {
	// Port to listen on (default: 53)
	Port int

	// Portal IP to return for hijacked queries
	PortalIP string

	// Upstream DNS server for enrolled devices (e.g., "8.8.8.8:53")
	UpstreamDNS string

	// TTL for hijacked responses (0 = no caching)
	HijackTTL uint32

	// Enable DNS hijacking (if false, just forwards all queries)
	Enabled bool
}

// New creates a new DNS hijacking server
func New(cfg Config, db *storage.Database) (*Server, error) {
	if cfg.Port == 0 {
		cfg.Port = 53
	}
	if cfg.UpstreamDNS == "" {
		cfg.UpstreamDNS = "8.8.8.8:53"
	}
	if cfg.HijackTTL == 0 {
		cfg.HijackTTL = 0 // No caching for hijacked responses
	}

	// Validate portal IP
	if net.ParseIP(cfg.PortalIP) == nil {
		return nil, fmt.Errorf("invalid portal IP: %s", cfg.PortalIP)
	}

	return &Server{
		config:      cfg,
		db:          db,
		upstreamDNS: cfg.UpstreamDNS,
	}, nil
}

// Start starts the DNS server
func (s *Server) Start(ctx context.Context) error {
	// Create DNS handler
	dns.HandleFunc(".", s.handleDNSQuery)

	// Create UDP server
	s.dnsServer = &dns.Server{
		Addr: fmt.Sprintf(":%d", s.config.Port),
		Net:  "udp",
	}

	// Start server in background
	go func() {
		fmt.Printf("[INFO] DNS hijack server listening on port %d\n", s.config.Port)
		if err := s.dnsServer.ListenAndServe(); err != nil {
			fmt.Printf("[ERROR] DNS server error: %v\n", err)
		}
	}()

	// Wait for context cancellation
	<-ctx.Done()
	return s.Stop()
}

// Stop stops the DNS server
func (s *Server) Stop() error {
	if s.dnsServer != nil {
		fmt.Println("[INFO] Stopping DNS hijack server...")
		return s.dnsServer.Shutdown()
	}
	return nil
}

// handleDNSQuery processes DNS queries
func (s *Server) handleDNSQuery(w dns.ResponseWriter, r *dns.Msg) {
	s.mu.Lock()
	s.queriesTotal++
	s.mu.Unlock()

	// Get client IP
	clientAddr := w.RemoteAddr().String()
	clientIP, _, _ := net.SplitHostPort(clientAddr)

	// Check if device is in database
	device, err := s.db.GetDeviceByIP(clientIP)
	if err != nil {
		fmt.Printf("[ERROR] Database error for IP %s: %v\n", clientIP, err)
		s.forwardQuery(w, r)
		return
	}

	// If DNS hijacking is disabled, always forward
	if !s.config.Enabled {
		s.forwardQuery(w, r)
		return
	}

	// Smart one-time redirect logic:
	// 1. If device has already seen portal -> forward to real DNS (normal internet)
	// 2. If device is unknown or hasn't seen portal -> hijack ONCE to show portal
	if device != nil && device.SeenPortal {
		// Device has already been shown the portal - allow normal DNS
		s.forwardQuery(w, r)
		return
	}

	// Device not seen portal yet OR unknown device - hijack to show portal once
	s.hijackQuery(w, r, clientIP)
}

// hijackQuery returns the portal IP for all queries (captive portal trigger)
func (s *Server) hijackQuery(w dns.ResponseWriter, r *dns.Msg, clientIP string) {
	s.mu.Lock()
	s.queriesHijacked++
	s.mu.Unlock()

	m := new(dns.Msg)
	m.SetReply(r)
	m.Authoritative = true

	// Only respond to A record queries
	for _, question := range r.Question {
		if question.Qtype == dns.TypeA {
			// Return portal IP
			rr := &dns.A{
				Hdr: dns.RR_Header{
					Name:   question.Name,
					Rrtype: dns.TypeA,
					Class:  dns.ClassINET,
					Ttl:    s.config.HijackTTL,
				},
				A: net.ParseIP(s.config.PortalIP),
			}
			m.Answer = append(m.Answer, rr)
		} else {
			// For other query types, return NXDOMAIN or forward
			// (Some devices check for AAAA, MX, etc.)
			s.forwardQuery(w, r)
			return
		}
	}

	// Send hijacked response
	if err := w.WriteMsg(m); err != nil {
		fmt.Printf("[ERROR] Failed to write DNS response: %v\n", err)
	}

	// Log first hijack for this device
	if clientIP != "" {
		fmt.Printf("[INFO] DNS hijacked for unenrolled device %s\n", clientIP)
	}
}

// forwardQuery forwards the query to upstream DNS
func (s *Server) forwardQuery(w dns.ResponseWriter, r *dns.Msg) {
	s.mu.Lock()
	s.queriesForwarded++
	s.mu.Unlock()

	// Create DNS client
	c := new(dns.Client)
	c.Timeout = 5 * time.Second

	// Forward to upstream
	resp, _, err := c.Exchange(r, s.upstreamDNS)
	if err != nil {
		s.mu.Lock()
		s.queryErrors++
		s.mu.Unlock()

		fmt.Printf("[ERROR] Upstream DNS error: %v\n", err)

		// Return SERVFAIL
		m := new(dns.Msg)
		m.SetReply(r)
		m.Rcode = dns.RcodeServerFailure
		w.WriteMsg(m)
		return
	}

	// Return upstream response
	if err := w.WriteMsg(resp); err != nil {
		fmt.Printf("[ERROR] Failed to write DNS response: %v\n", err)
	}
}

// GetStats returns DNS server statistics
func (s *Server) GetStats() Stats {
	s.mu.RLock()
	defer s.mu.RUnlock()

	return Stats{
		QueriesTotal:     s.queriesTotal,
		QueriesHijacked:  s.queriesHijacked,
		QueriesForwarded: s.queriesForwarded,
		QueryErrors:      s.queryErrors,
	}
}

// Stats holds DNS server statistics
type Stats struct {
	QueriesTotal     uint64
	QueriesHijacked  uint64
	QueriesForwarded uint64
	QueryErrors      uint64
}
