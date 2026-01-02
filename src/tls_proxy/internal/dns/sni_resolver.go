// Package dns implements DNS client for SNI domain resolution.
package dns

import (
	"errors"
	"fmt"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/miekg/dns"

	"tls_proxy/internal/config"
)

// =============================================================================
// ERROR DEFINITIONS
// =============================================================================

var (
	ErrEmptySNI      = errors.New("SNI parameter is empty")
	ErrInvalidSNI    = errors.New("SNI is not a valid domain name")
	ErrNXDOMAIN      = errors.New("domain does not exist (NXDOMAIN)")
	ErrQueryTimeout  = errors.New("DNS query timed out")
	ErrNoAnswer      = errors.New("DNS response contains no answer records")
	ErrNoARecord     = errors.New("DNS response contains no A records")
	ErrServerFailure = errors.New("DNS server failure (SERVFAIL)")
	ErrQueryRefused  = errors.New("DNS query refused by server")
	ErrNetworkError  = errors.New("network error communicating with DNS server")
)

// =============================================================================
// STATISTICS
// =============================================================================

// ResolverStats tracks DNS resolver performance metrics.
type ResolverStats struct {
	// TotalQueries is the count of all Resolve() calls
	TotalQueries uint64

	// SuccessfulResolutions is the count of queries returning valid IPs
	SuccessfulResolutions uint64

	// FailedResolutions is the count of queries returning errors
	FailedResolutions uint64

	// NXDomainCount is the count of non-existent domain errors
	NXDomainCount uint64

	// TimeoutCount is the count of timed out queries
	TimeoutCount uint64

	// TotalResponseTime is cumulative response time for average calculation
	TotalResponseTime time.Duration

	// LastQueryTime is the timestamp of most recent query
	LastQueryTime time.Time
}

// AverageResponseTime returns the mean response time across all queries.
func (s *ResolverStats) AverageResponseTime() time.Duration {
	if s.TotalQueries == 0 {
		return 0
	}
	return s.TotalResponseTime / time.Duration(s.TotalQueries)
}

// SuccessRate returns the percentage of successful resolutions.
func (s *ResolverStats) SuccessRate() float64 {
	if s.TotalQueries == 0 {
		return 0
	}
	return float64(s.SuccessfulResolutions) / float64(s.TotalQueries) * 100
}

// =============================================================================
// SNI RESOLVER
// =============================================================================

// SNIResolver queries the local DNS Server to resolve SNI domains.
type SNIResolver struct {
	// DNSServerAddress is the DNS Server endpoint (e.g., "localhost:53")
	DNSServerAddress string

	// QueryTimeout is the deadline for DNS queries
	QueryTimeout time.Duration

	// client is the DNS client instance for sending queries
	client *dns.Client

	// stats tracks resolver performance metrics
	stats ResolverStats

	// mutex protects stats updates
	mutex sync.RWMutex
}

// =============================================================================
// CONSTRUCTOR
// =============================================================================

// NewSNIResolver creates a new SNI resolver with configuration.
func NewSNIResolver(cfg *config.Config) *SNIResolver {
	return &SNIResolver{
		DNSServerAddress: cfg.DNSServerAddress,
		QueryTimeout:     cfg.DNSQueryTimeout,
		client: &dns.Client{
			Net:     "udp",
			Timeout: cfg.DNSQueryTimeout,
		},
		stats: ResolverStats{},
	}
}

// NewSNIResolverWithAddress creates a resolver with explicit address.
func NewSNIResolverWithAddress(dnsServerAddress string, queryTimeout time.Duration) *SNIResolver {
	return &SNIResolver{
		DNSServerAddress: dnsServerAddress,
		QueryTimeout:     queryTimeout,
		client: &dns.Client{
			Net:     "udp",
			Timeout: queryTimeout,
		},
		stats: ResolverStats{},
	}
}

// =============================================================================
// DNS RESOLUTION
// =============================================================================

// Resolve queries the DNS Server for an A record and returns the IP address.
// Returns the resolved IP address string and nil error on success.
// Returns empty string and descriptive error if resolution fails.
func (r *SNIResolver) Resolve(sni string) (string, error) {
	startTime := time.Now()

	// Update last query time
	r.mutex.Lock()
	r.stats.TotalQueries++
	r.stats.LastQueryTime = startTime
	r.mutex.Unlock()

	// Validate SNI parameter
	if sni == "" {
		r.recordFailure()
		return "", ErrEmptySNI
	}

	// Check if SNI is already an IP address
	if ip := net.ParseIP(sni); ip != nil {
		r.recordSuccess(time.Since(startTime))
		return sni, nil
	}

	// Validate domain format
	if !isValidDomainName(sni) {
		r.recordFailure()
		return "", ErrInvalidSNI
	}

	// Construct DNS A record query
	msg := new(dns.Msg)
	msg.SetQuestion(dns.Fqdn(sni), dns.TypeA)
	msg.RecursionDesired = true

	// Send query to DNS Server
	response, rtt, err := r.client.Exchange(msg, r.DNSServerAddress)
	if err != nil {
		r.handleError(err)
		return "", r.classifyError(err)
	}

	// Parse response
	ip, err := r.parseResponse(response)
	if err != nil {
		r.handleResponseError(err)
		return "", err
	}

	// Record success
	r.recordSuccess(rtt)
	return ip, nil
}

// ResolveWithDetails returns additional resolution information.
type ResolutionResult struct {
	IP           string
	TTL          uint32
	ResponseTime time.Duration
	Error        error
	Success      bool
}

// ResolveWithDetails returns detailed resolution result.
func (r *SNIResolver) ResolveWithDetails(sni string) *ResolutionResult {
	startTime := time.Now()

	ip, err := r.Resolve(sni)

	return &ResolutionResult{
		IP:           ip,
		ResponseTime: time.Since(startTime),
		Error:        err,
		Success:      err == nil,
	}
}

// =============================================================================
// RESPONSE PARSING
// =============================================================================

// parseResponse extracts the IP address from a DNS response.
func (r *SNIResolver) parseResponse(response *dns.Msg) (string, error) {
	// Check response code
	switch response.Rcode {
	case dns.RcodeSuccess:
		// Continue parsing
	case dns.RcodeNameError:
		return "", ErrNXDOMAIN
	case dns.RcodeServerFailure:
		return "", ErrServerFailure
	case dns.RcodeRefused:
		return "", ErrQueryRefused
	default:
		return "", fmt.Errorf("DNS error code: %d", response.Rcode)
	}

	// Check for answer records
	if len(response.Answer) == 0 {
		return "", ErrNoAnswer
	}

	// Find first A record
	for _, answer := range response.Answer {
		if a, ok := answer.(*dns.A); ok {
			return a.A.String(), nil
		}
	}

	return "", ErrNoARecord
}

// =============================================================================
// ERROR HANDLING
// =============================================================================

// classifyError converts network errors to resolver errors.
func (r *SNIResolver) classifyError(err error) error {
	errStr := strings.ToLower(err.Error())

	if strings.Contains(errStr, "timeout") || strings.Contains(errStr, "i/o timeout") {
		return ErrQueryTimeout
	}

	if strings.Contains(errStr, "connection refused") {
		return fmt.Errorf("%w: DNS server not running on %s", ErrNetworkError, r.DNSServerAddress)
	}

	if strings.Contains(errStr, "no such host") {
		return ErrNXDOMAIN
	}

	return fmt.Errorf("%w: %v", ErrNetworkError, err)
}

// handleError updates statistics for network errors.
func (r *SNIResolver) handleError(err error) {
	r.mutex.Lock()
	defer r.mutex.Unlock()

	r.stats.FailedResolutions++

	errStr := strings.ToLower(err.Error())
	if strings.Contains(errStr, "timeout") {
		r.stats.TimeoutCount++
	}
}

// handleResponseError updates statistics for response errors.
func (r *SNIResolver) handleResponseError(err error) {
	r.mutex.Lock()
	defer r.mutex.Unlock()

	r.stats.FailedResolutions++

	if errors.Is(err, ErrNXDOMAIN) {
		r.stats.NXDomainCount++
	}
}

// recordSuccess updates statistics for successful resolution.
func (r *SNIResolver) recordSuccess(responseTime time.Duration) {
	r.mutex.Lock()
	defer r.mutex.Unlock()

	r.stats.SuccessfulResolutions++
	r.stats.TotalResponseTime += responseTime
}

// recordFailure updates statistics for validation failures.
func (r *SNIResolver) recordFailure() {
	r.mutex.Lock()
	defer r.mutex.Unlock()

	r.stats.FailedResolutions++
}

// =============================================================================
// VALIDATION HELPERS
// =============================================================================

// isValidDomainName performs basic domain name validation.
func isValidDomainName(domain string) bool {
	if domain == "" || len(domain) > 253 {
		return false
	}

	// Check for valid characters
	for _, r := range domain {
		if !((r >= 'a' && r <= 'z') ||
			(r >= 'A' && r <= 'Z') ||
			(r >= '0' && r <= '9') ||
			r == '-' || r == '.') {
			return false
		}
	}

	// Must not start or end with hyphen or dot
	if domain[0] == '-' || domain[0] == '.' ||
		domain[len(domain)-1] == '-' || domain[len(domain)-1] == '.' {
		return false
	}

	return true
}

// =============================================================================
// STATISTICS ACCESS
// =============================================================================

// GetStats returns a copy of resolver statistics.
func (r *SNIResolver) GetStats() ResolverStats {
	r.mutex.RLock()
	defer r.mutex.RUnlock()

	return ResolverStats{
		TotalQueries:          r.stats.TotalQueries,
		SuccessfulResolutions: r.stats.SuccessfulResolutions,
		FailedResolutions:     r.stats.FailedResolutions,
		NXDomainCount:         r.stats.NXDomainCount,
		TimeoutCount:          r.stats.TimeoutCount,
		TotalResponseTime:     r.stats.TotalResponseTime,
		LastQueryTime:         r.stats.LastQueryTime,
	}
}

// GetDNSServerAddress returns the configured DNS server address.
func (r *SNIResolver) GetDNSServerAddress() string {
	return r.DNSServerAddress
}

// GetQueryTimeout returns the configured query timeout.
func (r *SNIResolver) GetQueryTimeout() time.Duration {
	return r.QueryTimeout
}
