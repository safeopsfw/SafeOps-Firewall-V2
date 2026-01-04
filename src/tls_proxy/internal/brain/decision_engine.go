package brain

import (
	"context"
	"log"
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

	// Gateway IP to return for captive portal
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
			InternalDomains: []string{"captive.safeops.local", "safeops.local"},
			GatewayIP:       "192.168.137.1",
			PolicyMode:      "STRICT",
			DefaultTTL:      300,
		}
	}

	return &DecisionEngine{
		dhcpMonitor: dhcpMonitor,
		config:      config,
	}
}

// GetDNSDecision decides what DNS response to return
// Phase 3A Logic:
// 1. Check if domain is internal (captive.safeops.local) → Return gateway IP
// 2. Query DHCP Monitor for device trust status
// 3. If UNTRUSTED → Block or redirect (depending on policy)
// 4. If TRUSTED → Forward to upstream DNS
func (e *DecisionEngine) GetDNSDecision(ctx context.Context, domain, clientIP, queryType string) (*pb.DNSDecisionResponse, error) {
	log.Printf("[Decision Engine] DNS query: domain=%s, client=%s, type=%s", domain, clientIP, queryType)

	// Step 1: Check if domain is internal
	if e.isInternalDomain(domain) {
		log.Printf("[Decision Engine] Internal domain %s → Return gateway IP %s", domain, e.config.GatewayIP)
		return &pb.DNSDecisionResponse{
			Decision:   pb.DecisionType_RETURN_IP,
			IpAddress:  e.config.GatewayIP,
			Ttl:        e.config.DefaultTTL,
			Reason:     "Internal domain - captive portal",
		}, nil
	}

	// Step 2: Query DHCP Monitor for device trust status
	deviceInfo, err := e.dhcpMonitor.GetDeviceByIP(ctx, clientIP)
	if err != nil {
		log.Printf("[Decision Engine] Failed to query DHCP Monitor for %s: %v", clientIP, err)
		// On error, default to FORWARD_UPSTREAM (fail open for now)
		return &pb.DNSDecisionResponse{
			Decision: pb.DecisionType_FORWARD_UPSTREAM,
			Ttl:      e.config.DefaultTTL,
			Reason:   "DHCP Monitor query failed - fail open",
		}, nil
	}

	log.Printf("[Decision Engine] Device %s trust status: %s", clientIP, deviceInfo.TrustStatus)

	// Step 3: Make decision based on trust status
	switch deviceInfo.TrustStatus {
	case "TRUSTED":
		// Device is trusted → Forward to upstream DNS
		log.Printf("[Decision Engine] Device %s is TRUSTED → Forward to upstream", clientIP)
		return &pb.DNSDecisionResponse{
			Decision: pb.DecisionType_FORWARD_UPSTREAM,
			Ttl:      e.config.DefaultTTL,
			Reason:   "Device trusted",
		}, nil

	case "UNTRUSTED":
		// Device is untrusted → Policy decision
		if e.config.PolicyMode == "STRICT" {
			// STRICT mode: Block all external DNS for untrusted devices
			log.Printf("[Decision Engine] Device %s is UNTRUSTED (STRICT mode) → Block", clientIP)
			return &pb.DNSDecisionResponse{
				Decision: pb.DecisionType_BLOCK,
				Ttl:      60, // Short TTL for blocked responses
				Reason:   "Device untrusted - strict mode",
			}, nil
		} else {
			// PERMISSIVE mode: Allow DNS but log
			log.Printf("[Decision Engine] Device %s is UNTRUSTED (PERMISSIVE mode) → Allow", clientIP)
			return &pb.DNSDecisionResponse{
				Decision: pb.DecisionType_FORWARD_UPSTREAM,
				Ttl:      e.config.DefaultTTL,
				Reason:   "Device untrusted - permissive mode",
			}, nil
		}

	case "BLOCKED":
		// Device is blocked → Always block
		log.Printf("[Decision Engine] Device %s is BLOCKED → Block", clientIP)
		return &pb.DNSDecisionResponse{
			Decision: pb.DecisionType_BLOCK,
			Ttl:      60,
			Reason:   "Device blocked",
		}, nil

	default:
		// Unknown trust status → Fail safe (block in strict mode, allow in permissive)
		log.Printf("[Decision Engine] Device %s has unknown trust status '%s'", clientIP, deviceInfo.TrustStatus)
		if e.config.PolicyMode == "STRICT" {
			return &pb.DNSDecisionResponse{
				Decision: pb.DecisionType_BLOCK,
				Ttl:      60,
				Reason:   "Unknown trust status - fail safe",
			}, nil
		}
		return &pb.DNSDecisionResponse{
			Decision: pb.DecisionType_FORWARD_UPSTREAM,
			Ttl:      e.config.DefaultTTL,
			Reason:   "Unknown trust status - permissive mode",
		}, nil
	}
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
