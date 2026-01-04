// Package dns provides TLS Proxy DNS decision integration.
package dns

import (
	"context"
	"log"
	"time"

	"dns_server/internal/integration"
	"dns_server/internal/models"
	pb "dns_server/proto"
)

// TLSProxyResolver handles DNS decisions from TLS Proxy.
type TLSProxyResolver struct {
	client  *integration.TLSProxyClient
	enabled bool
}

// NewTLSProxyResolver creates a new TLS Proxy resolver.
func NewTLSProxyResolver(tlsProxyAddress string, timeout time.Duration) (*TLSProxyResolver, error) {
	if tlsProxyAddress == "" {
		log.Println("[TLS Proxy] Disabled - no address configured")
		return &TLSProxyResolver{enabled: false}, nil
	}

	client, err := integration.NewTLSProxyClient(tlsProxyAddress, timeout)
	if err != nil {
		log.Printf("[TLS Proxy] Failed to connect: %v", err)
		return &TLSProxyResolver{enabled: false}, nil // Non-fatal, continue without TLS Proxy
	}

	log.Printf("[TLS Proxy] Enabled at %s", tlsProxyAddress)
	return &TLSProxyResolver{
		client:  client,
		enabled: true,
	}, nil
}

// TLSProxyDecision represents a decision from TLS Proxy.
type TLSProxyDecision struct {
	ShouldHandle bool   // Should DNS Server handle this decision?
	IP           string // IP to return (if ShouldHandle=true)
	TTL          uint32 // TTL for the response
	Block        bool   // Should block (NXDOMAIN)
	Forward      bool   // Should forward to upstream
}

// GetDecision queries TLS Proxy for DNS decision.
func (r *TLSProxyResolver) GetDecision(query *models.DNSQuery) *TLSProxyDecision {
	if !r.enabled || r.client == nil {
		return &TLSProxyDecision{Forward: true} // Forward to upstream by default
	}

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	resp, err := r.client.GetDNSDecision(ctx, query.Domain, query.ClientIP, query.QueryType)
	if err != nil {
		log.Printf("[TLS Proxy] Query failed for %s: %v, forwarding to upstream", query.Domain, err)
		return &TLSProxyDecision{Forward: true}
	}

	log.Printf("[TLS Proxy] Decision for %s: %v", query.Domain, resp.Decision)

	switch resp.Decision {
	case pb.DecisionType_RETURN_IP:
		// TLS Proxy provides exact IP to return
		log.Printf("[TLS Proxy] Returning IP %s (TTL: %d) for %s", resp.IpAddress, resp.Ttl, query.Domain)
		return &TLSProxyDecision{
			ShouldHandle: true,
			IP:           resp.IpAddress,
			TTL:          resp.Ttl,
		}

	case pb.DecisionType_FORWARD_UPSTREAM:
		// Forward to upstream DNS
		log.Printf("[TLS Proxy] Forwarding %s to upstream DNS", query.Domain)
		return &TLSProxyDecision{Forward: true}

	case pb.DecisionType_BLOCK:
		// Block the domain (NXDOMAIN)
		log.Printf("[TLS Proxy] Blocking %s (NXDOMAIN)", query.Domain)
		return &TLSProxyDecision{
			ShouldHandle: true,
			Block:        true,
		}

	case pb.DecisionType_REDIRECT:
		// Redirect to another domain (Phase 3B feature, not implemented yet)
		log.Printf("[TLS Proxy] Redirect decision for %s -> %s (not implemented, forwarding)", query.Domain, resp.RedirectDomain)
		return &TLSProxyDecision{Forward: true}

	default:
		log.Printf("[TLS Proxy] Unknown decision type %v for %s, forwarding", resp.Decision, query.Domain)
		return &TLSProxyDecision{Forward: true}
	}
}

// Close closes the TLS Proxy client connection.
func (r *TLSProxyResolver) Close() error {
	if r.client != nil {
		return r.client.Close()
	}
	return nil
}

// IsEnabled returns whether TLS Proxy integration is enabled.
func (r *TLSProxyResolver) IsEnabled() bool {
	return r.enabled
}
