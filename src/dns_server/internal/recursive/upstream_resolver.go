// Package recursive implements upstream DNS resolution for external domain queries.
package recursive

import (
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/miekg/dns"

	"dns_server/internal/models"
)

// =============================================================================
// UPSTREAM RESOLVER - Forwards queries to 8.8.8.8 and 1.1.1.1
// =============================================================================

// UpstreamResolver forwards DNS queries to upstream public DNS servers.
type UpstreamResolver struct {
	// upstreamServers is an ordered list of upstream DNS server addresses
	// Format: "IP:port" (e.g., "8.8.8.8:53")
	upstreamServers []string

	// timeout is the maximum time to wait for upstream response
	timeout time.Duration

	// retries is the number of retry attempts per upstream server
	retries int

	// client is a reusable DNS client configured for UDP transport
	client *dns.Client
}

// =============================================================================
// CONSTRUCTOR
// =============================================================================

// NewUpstreamResolver creates a new upstream resolver with the specified configuration.
// upstreamServers: list of DNS server addresses (e.g., ["8.8.8.8:53", "1.1.1.1:53"])
// timeout: maximum time to wait for each upstream query (e.g., 3 * time.Second)
func NewUpstreamResolver(upstreamServers []string, timeout time.Duration) *UpstreamResolver {
	// Default upstream servers if none provided
	if len(upstreamServers) == 0 {
		upstreamServers = []string{"8.8.8.8:53", "1.1.1.1:53", "8.8.4.4:53"}
	}

	// Validate and fix server addresses (ensure :53 port)
	for i, server := range upstreamServers {
		if !strings.Contains(server, ":") {
			upstreamServers[i] = server + ":53"
		}
	}

	// Default timeout if not specified
	if timeout == 0 {
		timeout = 3 * time.Second
	}

	return &UpstreamResolver{
		upstreamServers: upstreamServers,
		timeout:         timeout,
		retries:         2,
		client: &dns.Client{
			Net:     "udp",
			Timeout: timeout,
		},
	}
}

// NewUpstreamResolverWithRetries creates resolver with custom retry count.
func NewUpstreamResolverWithRetries(upstreamServers []string, timeout time.Duration, retries int) *UpstreamResolver {
	resolver := NewUpstreamResolver(upstreamServers, timeout)
	resolver.retries = retries
	return resolver
}

// =============================================================================
// RESOLVE METHOD
// =============================================================================

// Resolve forwards a DNS query to upstream servers and returns the result.
// Tries each upstream server in order until one responds successfully.
func (r *UpstreamResolver) Resolve(query *models.DNSQuery) *models.UpstreamResult {
	startTime := time.Now()

	// Build DNS query message
	msg := r.buildDNSQuery(query)

	// Try each upstream server
	var lastErr error
	for _, server := range r.upstreamServers {
		response, rtt, err := r.queryServer(msg, server)
		if err != nil {
			lastErr = r.handleUpstreamError(err, server)
			continue
		}

		// Check response code
		if response.Rcode == dns.RcodeNameError {
			// NXDOMAIN - domain doesn't exist (valid response)
			return &models.UpstreamResult{
				Success:      false,
				IP:           "",
				TTL:          0,
				ResponseTime: rtt,
				Error:        errors.New("NXDOMAIN: domain does not exist"),
			}
		}

		if response.Rcode != dns.RcodeSuccess {
			lastErr = fmt.Errorf("upstream %s returned RCODE %d", server, response.Rcode)
			continue
		}

		// Parse A record from answer section
		ip, ttl, err := r.parseARecord(response)
		if err != nil {
			lastErr = err
			continue
		}

		// Success!
		return &models.UpstreamResult{
			Success:      true,
			IP:           ip,
			TTL:          int(ttl),
			ResponseTime: rtt,
			Error:        nil,
		}
	}

	// All upstream servers failed
	return &models.UpstreamResult{
		Success:      false,
		IP:           "",
		TTL:          0,
		ResponseTime: time.Since(startTime),
		Error:        fmt.Errorf("all upstream servers failed: %v", lastErr),
	}
}

// =============================================================================
// PRIVATE METHODS
// =============================================================================

// queryServer sends a DNS query to a specific upstream server with retry handling.
func (r *UpstreamResolver) queryServer(msg *dns.Msg, server string) (*dns.Msg, time.Duration, error) {
	var lastErr error

	for attempt := 0; attempt <= r.retries; attempt++ {
		startTime := time.Now()

		response, rtt, err := r.client.Exchange(msg, server)
		if err != nil {
			lastErr = err
			// Retry on timeout, but not on other errors
			if isTimeoutError(err) {
				continue
			}
			return nil, time.Since(startTime), err
		}

		return response, rtt, nil
	}

	return nil, 0, fmt.Errorf("query to %s failed after %d retries: %v", server, r.retries, lastErr)
}

// parseARecord extracts the IPv4 address from a DNS response answer section.
func (r *UpstreamResolver) parseARecord(msg *dns.Msg) (string, uint32, error) {
	if len(msg.Answer) == 0 {
		return "", 0, errors.New("no answer records in response")
	}

	// Look for A record in answer section
	for _, answer := range msg.Answer {
		if a, ok := answer.(*dns.A); ok {
			ip := a.A.String()
			ttl := a.Hdr.Ttl
			return ip, ttl, nil
		}
	}

	// Check for CNAME and follow it (simplified - just return error for now)
	for _, answer := range msg.Answer {
		if _, ok := answer.(*dns.CNAME); ok {
			return "", 0, errors.New("CNAME record found, A record resolution required")
		}
	}

	return "", 0, errors.New("no A record found in answer section")
}

// buildDNSQuery converts a models.DNSQuery to a miekg/dns query message.
func (r *UpstreamResolver) buildDNSQuery(query *models.DNSQuery) *dns.Msg {
	msg := new(dns.Msg)

	// Set query ID
	msg.Id = query.QueryID

	// Set recursion desired
	msg.RecursionDesired = true

	// Determine query type
	qtype := dns.TypeA
	switch query.QueryType {
	case models.QueryTypeA:
		qtype = dns.TypeA
	case models.QueryTypeAAAA:
		qtype = dns.TypeAAAA
	case models.QueryTypePTR:
		qtype = dns.TypePTR
	case models.QueryTypeCNAME:
		qtype = dns.TypeCNAME
	}

	// Set question section
	msg.SetQuestion(dns.Fqdn(query.Domain), qtype)

	return msg
}

// handleUpstreamError categorizes and wraps upstream errors.
func (r *UpstreamResolver) handleUpstreamError(err error, server string) error {
	if isTimeoutError(err) {
		return fmt.Errorf("timeout querying %s: %v", server, err)
	}
	if isConnectionRefused(err) {
		return fmt.Errorf("connection refused to %s: %v", server, err)
	}
	return fmt.Errorf("error querying %s: %v", server, err)
}

// =============================================================================
// HELPER FUNCTIONS
// =============================================================================

// isTimeoutError checks if an error is a timeout error.
func isTimeoutError(err error) bool {
	if err == nil {
		return false
	}
	errStr := strings.ToLower(err.Error())
	return strings.Contains(errStr, "timeout") || strings.Contains(errStr, "i/o timeout")
}

// isConnectionRefused checks if an error is a connection refused error.
func isConnectionRefused(err error) bool {
	if err == nil {
		return false
	}
	return strings.Contains(strings.ToLower(err.Error()), "connection refused")
}

// =============================================================================
// CONFIGURATION METHODS
// =============================================================================

// SetUpstreamServers updates the list of upstream DNS servers.
func (r *UpstreamResolver) SetUpstreamServers(servers []string) {
	r.upstreamServers = servers
}

// GetUpstreamServers returns the current list of upstream DNS servers.
func (r *UpstreamResolver) GetUpstreamServers() []string {
	result := make([]string, len(r.upstreamServers))
	copy(result, r.upstreamServers)
	return result
}

// SetTimeout updates the query timeout.
func (r *UpstreamResolver) SetTimeout(timeout time.Duration) {
	r.timeout = timeout
	r.client.Timeout = timeout
}

// GetTimeout returns the current query timeout.
func (r *UpstreamResolver) GetTimeout() time.Duration {
	return r.timeout
}
