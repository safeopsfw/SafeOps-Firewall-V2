// Package resolver implements recursive DNS resolution.
package resolver

import (
	"context"
	"fmt"
	"log"
	"net"
	"sync"
	"time"

	"safeops/dns_server/internal/protocol"
)

// ============================================================================
// Recursive Resolver
// ============================================================================

// Resolver forwards DNS queries to upstream servers
type Resolver struct {
	upstreams  []string
	currentIdx int
	mu         sync.Mutex
	timeout    time.Duration
	retries    int
}

// Config holds resolver configuration
type Config struct {
	Upstreams []string      // Upstream DNS server addresses (e.g., "8.8.8.8:53")
	Timeout   time.Duration // Query timeout
	Retries   int           // Number of retries
}

// DefaultConfig returns default resolver configuration
func DefaultConfig() *Config {
	return &Config{
		Upstreams: []string{"8.8.8.8:53", "1.1.1.1:53", "8.8.4.4:53"},
		Timeout:   2 * time.Second,
		Retries:   2,
	}
}

// New creates a new recursive resolver
func New(cfg *Config) *Resolver {
	if cfg == nil {
		cfg = DefaultConfig()
	}

	return &Resolver{
		upstreams:  cfg.Upstreams,
		timeout:    cfg.Timeout,
		retries:    cfg.Retries,
		currentIdx: 0,
	}
}

// ============================================================================
// Resolution
// ============================================================================

// Resolve forwards a query to upstream servers
func (r *Resolver) Resolve(ctx context.Context, q protocol.Question) ([]protocol.ResourceRecord, error) {
	// Build query message
	query := protocol.NewMessage(uint16(time.Now().UnixNano() & 0xFFFF))
	query.Flags.RD = true // Recursion desired
	query.Questions = []protocol.Question{q}

	// Serialize query
	queryBytes, err := protocol.SerializeDNSMessage(query)
	if err != nil {
		return nil, fmt.Errorf("failed to serialize query: %w", err)
	}

	// Try upstreams with retries
	var lastErr error
	for attempt := 0; attempt <= r.retries; attempt++ {
		upstream := r.getNextUpstream()

		response, err := r.sendQuery(ctx, upstream, queryBytes)
		if err != nil {
			lastErr = err
			log.Printf("Upstream %s failed: %v", upstream, err)
			continue
		}

		if response.Flags.RCODE != protocol.RCodeNoError {
			// Non-error response codes like NXDOMAIN are valid
			if response.Flags.RCODE == protocol.RCodeNXDomain {
				return nil, nil
			}
			continue
		}

		return response.Answers, nil
	}

	return nil, fmt.Errorf("all upstreams failed: %w", lastErr)
}

func (r *Resolver) sendQuery(ctx context.Context, upstream string, query []byte) (*protocol.Message, error) {
	// Create UDP connection
	conn, err := net.DialTimeout("udp", upstream, r.timeout)
	if err != nil {
		return nil, fmt.Errorf("dial failed: %w", err)
	}
	defer conn.Close()

	// Set deadline
	deadline, ok := ctx.Deadline()
	if !ok {
		deadline = time.Now().Add(r.timeout)
	}
	conn.SetDeadline(deadline)

	// Send query
	_, err = conn.Write(query)
	if err != nil {
		return nil, fmt.Errorf("write failed: %w", err)
	}

	// Read response
	buffer := make([]byte, 512)
	n, err := conn.Read(buffer)
	if err != nil {
		return nil, fmt.Errorf("read failed: %w", err)
	}

	// Parse response
	response, err := protocol.ParseDNSPacket(buffer[:n])
	if err != nil {
		return nil, fmt.Errorf("parse failed: %w", err)
	}

	return response, nil
}

func (r *Resolver) getNextUpstream() string {
	r.mu.Lock()
	defer r.mu.Unlock()

	upstream := r.upstreams[r.currentIdx]
	r.currentIdx = (r.currentIdx + 1) % len(r.upstreams)
	return upstream
}

// ============================================================================
// Configuration
// ============================================================================

// SetUpstreams updates the upstream servers
func (r *Resolver) SetUpstreams(upstreams []string) {
	r.mu.Lock()
	r.upstreams = upstreams
	r.currentIdx = 0
	r.mu.Unlock()
}

// GetUpstreams returns current upstream servers
func (r *Resolver) GetUpstreams() []string {
	r.mu.Lock()
	defer r.mu.Unlock()
	result := make([]string, len(r.upstreams))
	copy(result, r.upstreams)
	return result
}
