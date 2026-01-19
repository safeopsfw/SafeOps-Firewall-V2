package redirect

import (
	"encoding/binary"
	"fmt"
	"net"

	"github.com/wiresock/ndisapi-go"
)

// DNSRedirector provides DNS packet manipulation utilities
type DNSRedirector struct{}

// NewDNSRedirector creates a new DNS redirector
func NewDNSRedirector() *DNSRedirector {
	return &DNSRedirector{}
}

// ForgeDNSResponse creates a fake DNS response pointing to a specific IP
// This is used to redirect domains to a captive portal or block page
func (r *DNSRedirector) ForgeDNSResponse(buffer *ndisapi.IntermediateBuffer, redirectIP string) error {
	data := buffer.Buffer[:buffer.Length]

	if len(data) < 42 {
		return fmt.Errorf("packet too small for DNS")
	}

	// Parse the original DNS query to get the domain name
	// We'll create a response with the same transaction ID

	// Modify DNS flags to make it a response
	// Set QR bit (query/response) to 1 (response)
	flags := binary.BigEndian.Uint16(data[16:18]) // DNS header at offset 14 (Ethernet) + 2
	flags |= 0x8000                               // Set QR bit
	binary.BigEndian.PutUint16(data[16:18], flags)

	// Set answer count to 1
	binary.BigEndian.PutUint16(data[20:22], 1)

	// Add answer section (simplified - just append A record)
	// This is a basic implementation - production would need proper DNS encoding

	ip := net.ParseIP(redirectIP)
	if ip == nil {
		return fmt.Errorf("invalid IP address: %s", redirectIP)
	}

	// Note: This is a simplified implementation
	// Full implementation would properly encode the DNS answer section

	return nil
}

// RedirectDNSToIP modifies a DNS query to point to a different IP
// Used by Firewall Engine to redirect blocked domains
func (r *DNSRedirector) RedirectDNSToIP(buffer *ndisapi.IntermediateBuffer, targetIP string) error {
	// This would be called by external engines (Firewall/IDS/IPS)
	// to redirect DNS queries to a captive portal

	return r.ForgeDNSResponse(buffer, targetIP)
}
