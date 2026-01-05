package brain

import (
	"context"
	"log"
	"net"
	"strings"

	"tls_proxy/internal/integration"
	pb "tls_proxy/proto"
)

// DecisionEngine is the core Phase 3A brain that makes DNS and packet decisions
type DecisionEngine struct {
	dhcpMonitor *integration.DHCPMonitorClient
	config      *DecisionConfig
}

// DecisionConfig holds decision engine configuration
type DecisionConfig struct {
	// Internal domains that should resolve to gateway IP
	InternalDomains []string

	// Default Gateway IP (fallback if client IP parsing fails)
	GatewayIP string

	// Policy mode: STRICT or PERMISSIVE
	PolicyMode string

	// Default TTL for DNS responses
	DefaultTTL uint32
}

// NewDecisionEngine creates a new decision engine
func NewDecisionEngine(dhcpMonitor *integration.DHCPMonitorClient, config *DecisionConfig) *DecisionEngine {
	if config == nil {
		config = &DecisionConfig{
			InternalDomains: []string{"portal.safeops.local", "captive.safeops.local", "safeops.local", "safeops.captiveportal.local"},
			GatewayIP:       "192.168.137.1", // Fallback only
			PolicyMode:      "PERMISSIVE",
			DefaultTTL:      300,
		}
	}

	return &DecisionEngine{
		dhcpMonitor: dhcpMonitor,
		config:      config,
	}
}

// getGatewayForClient calculates the gateway IP based on client's subnet
// This automatically works for ANY NIC - no config needed!
// Example: Client 192.168.171.50 → Gateway 192.168.171.1
func (e *DecisionEngine) getGatewayForClient(clientIP string) string {
	ip := net.ParseIP(clientIP)
	if ip == nil {
		log.Printf("[Decision Engine] Failed to parse client IP %s, using fallback", clientIP)
		return e.config.GatewayIP
	}

	// Get IPv4 representation
	ip4 := ip.To4()
	if ip4 == nil {
		log.Printf("[Decision Engine] Client IP %s is not IPv4, using fallback", clientIP)
		return e.config.GatewayIP
	}

	// Replace last octet with .1 to get gateway
	gatewayIP := net.IPv4(ip4[0], ip4[1], ip4[2], 1).String()
	log.Printf("[Decision Engine] Client %s → Gateway %s (auto-detected)", clientIP, gatewayIP)
	return gatewayIP
}

// GetDNSDecision decides what DNS response to return
// DYNAMIC: portal.safeops.local returns gateway based on client's subnet
// Works automatically for ANY NIC!
func (e *DecisionEngine) GetDNSDecision(ctx context.Context, domain, clientIP, queryType string) (*pb.DNSDecisionResponse, error) {
	// Check if domain is internal (portal.safeops.local, captive.safeops.local)
	if e.isInternalDomain(domain) {
		// DYNAMIC: Calculate gateway IP from client's subnet
		gatewayIP := e.getGatewayForClient(clientIP)
		log.Printf("[Decision Engine] Internal domain %s → Gateway %s (for client %s)", domain, gatewayIP, clientIP)
		return &pb.DNSDecisionResponse{
			Decision:  pb.DecisionType_RETURN_IP,
			IpAddress: gatewayIP,
			Ttl:       e.config.DefaultTTL,
			Reason:    "Internal domain - dynamic gateway for client subnet",
		}, nil
	}

	// All other domains → Forward upstream
	return &pb.DNSDecisionResponse{
		Decision: pb.DecisionType_FORWARD_UPSTREAM,
		Ttl:      e.config.DefaultTTL,
		Reason:   "Forward upstream - manual portal access",
	}, nil
}

// isInternalDomain checks if a domain is internal (captive portal, etc.)
func (e *DecisionEngine) isInternalDomain(domain string) bool {
	domain = strings.ToLower(strings.TrimSuffix(domain, "."))

	for _, internal := range e.config.InternalDomains {
		internal = strings.ToLower(strings.TrimSuffix(internal, "."))

		// Exact match
		if domain == internal {
			return true
		}

		// Subdomain match
		if strings.HasSuffix(domain, "."+internal) {
			return true
		}
	}

	return false
}

// UpdateConfig updates the decision engine configuration
func (e *DecisionEngine) UpdateConfig(config *DecisionConfig) {
	e.config = config
	log.Printf("[Decision Engine] Configuration updated: PolicyMode=%s, GatewayIP=%s",
		config.PolicyMode, config.GatewayIP)
}

// GetConfig returns the current configuration
func (e *DecisionEngine) GetConfig() *DecisionConfig {
	return e.config
}
