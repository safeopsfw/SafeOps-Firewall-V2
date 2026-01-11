package classifier

import (
	"strings"

	"safeops-engine/internal/driver"
)

// Action represents what to do with a packet
type Action int

const (
	// ActionBypass - pass packet through directly (gaming, VoIP, streaming)
	ActionBypass Action = iota

	// ActionRedirectDNS - redirect to dnsproxy
	ActionRedirectDNS

	// ActionRedirectHTTP - tunnel through mitmproxy SOCKS5
	ActionRedirectHTTP

	// ActionDrop - drop the packet (blocked)
	ActionDrop
)

func (a Action) String() string {
	switch a {
	case ActionBypass:
		return "BYPASS"
	case ActionRedirectDNS:
		return "DNS"
	case ActionRedirectHTTP:
		return "HTTP"
	case ActionDrop:
		return "DROP"
	default:
		return "UNKNOWN"
	}
}

// Classifier decides what to do with each packet
type Classifier struct {
	// Stats
	bypassCount uint64
	dnsCount    uint64
	httpCount   uint64
	dropCount   uint64
}

// New creates a new classifier
func New() *Classifier {
	return &Classifier{}
}

// Classify determines what action to take for a packet
func (c *Classifier) Classify(pkt *driver.ParsedPacket) Action {
	// Non-TCP/UDP packets - bypass
	if pkt.Protocol != driver.ProtoTCP && pkt.Protocol != driver.ProtoUDP {
		c.bypassCount++
		return ActionBypass
	}

	// Determine the relevant port based on direction
	// Outbound: check destination port
	// Inbound: check source port (response)
	var port uint16
	if pkt.Direction == driver.DirectionOutbound {
		port = pkt.DstPort
	} else {
		port = pkt.SrcPort
	}

	// Check for DHCP (CRITICAL: Always bypass - needed for network operation)
	if (port == PortDHCPServer || port == PortDHCPClient) && pkt.Protocol == driver.ProtoUDP {
		c.bypassCount++
		return ActionBypass
	}

	// Check for DNS (UDP port 53)
	if port == PortDNS && pkt.Protocol == driver.ProtoUDP {
		c.dnsCount++
		return ActionRedirectDNS
	}

	// Check for HTTP/HTTPS
	if port == PortHTTP || port == PortHTTPS {
		// Check if it's a gaming/bypass domain via SNI (TODO: implement SNI extraction)
		// For now, redirect all HTTP/HTTPS
		c.httpCount++
		return ActionRedirectHTTP
	}

	// Check gaming ports
	if GamingPorts[port] {
		c.bypassCount++
		return ActionBypass
	}

	// Check VoIP ports
	if VoIPPorts[port] {
		c.bypassCount++
		return ActionBypass
	}

	// Check streaming ports
	if StreamingPorts[port] {
		c.bypassCount++
		return ActionBypass
	}

	// Default: bypass (don't interfere with unknown traffic)
	c.bypassCount++
	return ActionBypass
}

// ClassifyWithSNI classifies with optional SNI hostname check
func (c *Classifier) ClassifyWithSNI(pkt *driver.ParsedPacket, sni string) Action {
	// If SNI is provided, check bypass domains first
	if sni != "" {
		for _, domain := range BypassDomains {
			if strings.HasSuffix(sni, domain) {
				c.bypassCount++
				return ActionBypass
			}
		}
	}

	// Fall back to port-based classification
	return c.Classify(pkt)
}

// GetStats returns classification statistics
func (c *Classifier) GetStats() (bypass, dns, http, drop uint64) {
	return c.bypassCount, c.dnsCount, c.httpCount, c.dropCount
}
