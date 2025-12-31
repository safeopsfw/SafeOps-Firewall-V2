// Package captive implements DNS response redirection for unenrolled devices.
package captive

import (
	"net"
	"safeops/dns_server/internal/protocol"
)

// ============================================================================
// DNS Redirect Builder
// ============================================================================

// Redirector creates DNS responses that redirect to the captive portal
type Redirector struct {
	portalIP    net.IP
	portalIPv6  net.IP
	redirectTTL uint32
}

// NewRedirector creates a new DNS redirector
func NewRedirector(portalIP string, redirectTTL uint32) *Redirector {
	if redirectTTL == 0 {
		redirectTTL = 60 // Short TTL for redirects
	}

	return &Redirector{
		portalIP:    net.ParseIP(portalIP).To4(),
		portalIPv6:  nil, // IPv6 redirect is optional
		redirectTTL: redirectTTL,
	}
}

// ============================================================================
// Redirect Response Building
// ============================================================================

// CreateRedirectResponse creates a DNS response that redirects to portal
func (r *Redirector) CreateRedirectResponse(query *protocol.Message) *protocol.Message {
	response := protocol.NewMessage(query.ID)
	response.Flags.QR = true
	response.Flags.Opcode = query.Flags.Opcode
	response.Flags.AA = true // We're authoritative for redirect
	response.Flags.RD = query.Flags.RD
	response.Flags.RA = true
	response.Flags.RCODE = protocol.RCodeNoError

	// Copy questions
	response.Questions = make([]protocol.Question, len(query.Questions))
	copy(response.Questions, query.Questions)

	// Generate redirect answer for each question
	for _, q := range query.Questions {
		answer := r.createRedirectAnswer(q)
		if answer != nil {
			response.Answers = append(response.Answers, *answer)
		}
	}

	return response
}

func (r *Redirector) createRedirectAnswer(q protocol.Question) *protocol.ResourceRecord {
	switch q.Type {
	case protocol.TypeA:
		if r.portalIP != nil {
			return &protocol.ResourceRecord{
				Name:       q.Name,
				Type:       protocol.TypeA,
				Class:      protocol.ClassIN,
				TTL:        r.redirectTTL,
				RData:      r.portalIP,
				ParsedData: r.portalIP,
			}
		}

	case protocol.TypeAAAA:
		// If we have IPv6 portal address, use it
		if r.portalIPv6 != nil {
			return &protocol.ResourceRecord{
				Name:       q.Name,
				Type:       protocol.TypeAAAA,
				Class:      protocol.ClassIN,
				TTL:        r.redirectTTL,
				RData:      r.portalIPv6,
				ParsedData: r.portalIPv6,
			}
		}
		// Otherwise, return empty - browser will fall back to IPv4

	case protocol.TypeCNAME, protocol.TypeMX, protocol.TypeTXT:
		// For these types, also redirect to portal IP
		if r.portalIP != nil {
			return &protocol.ResourceRecord{
				Name:       q.Name,
				Type:       protocol.TypeA,
				Class:      protocol.ClassIN,
				TTL:        r.redirectTTL,
				RData:      r.portalIP,
				ParsedData: r.portalIP,
			}
		}
	}

	return nil
}

// ============================================================================
// Captive Portal Detection Responses
// ============================================================================

// CreateCaptiveCheckResponse creates response for captive portal detection URLs
func (r *Redirector) CreateCaptiveCheckResponse(query *protocol.Message, osType string) *protocol.Message {
	// For captive portal detection, we ALWAYS redirect to portal IP
	// This triggers the OS to show "Sign in to network" notification
	return r.CreateRedirectResponse(query)
}

// ============================================================================
// Configuration
// ============================================================================

// SetPortalIP updates the portal IP address
func (r *Redirector) SetPortalIP(ip string) {
	parsed := net.ParseIP(ip)
	if parsed != nil {
		if ipv4 := parsed.To4(); ipv4 != nil {
			r.portalIP = ipv4
		} else {
			r.portalIPv6 = parsed
		}
	}
}

// SetRedirectTTL sets the TTL for redirect responses
func (r *Redirector) SetRedirectTTL(ttl uint32) {
	r.redirectTTL = ttl
}

// GetPortalIP returns the current portal IPv4 address
func (r *Redirector) GetPortalIP() net.IP {
	return r.portalIP
}
