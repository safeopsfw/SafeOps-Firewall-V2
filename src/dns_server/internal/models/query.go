// Package models defines core data structures for DNS queries and cache entries.
package models

import (
	"time"
)

// =============================================================================
// DNS QUERY STRUCTURE
// =============================================================================

// DNSQuery represents an incoming DNS query received by the UDP server.
type DNSQuery struct {
	// Domain is the fully qualified domain name being queried (e.g., "www.google.com").
	// Stored in lowercase for case-insensitive cache lookups and comparison.
	Domain string

	// QueryType is the DNS record type requested.
	// Phase 1 supports "A" (IPv4 address).
	// Future phases: "AAAA" (IPv6), "PTR" (reverse lookup), "CNAME" (canonical name).
	QueryType string

	// ClientIP is the source IP address of the DNS client making the request.
	// Used for query logging (future phase) and potential client-specific filtering.
	ClientIP string

	// QueryID is the DNS protocol transaction ID from the original query packet header.
	// Must be echoed in the response for proper client correlation per RFC 1035.
	QueryID uint16

	// RecursionDesired is the RD flag from DNS header indicating whether client
	// wants recursive resolution. Always true for standard client queries.
	RecursionDesired bool
}

// =============================================================================
// CACHE ENTRY STRUCTURE
// =============================================================================

// CacheEntry represents a cached DNS resolution result stored in the in-memory cache.
type CacheEntry struct {
	// IP is the resolved IPv4 address in dotted-decimal notation (e.g., "142.250.185.46").
	// Stored as string for simplicity and JSON serialization compatibility.
	IP string

	// TTL is the time-to-live in seconds indicating how long this entry remains valid.
	// Copied from the upstream DNS response's answer section.
	TTL int

	// Timestamp is when this entry was added to the cache.
	// Used to calculate remaining TTL and trigger expiration checks during cache retrievals.
	Timestamp time.Time

	// OriginalTTL is the initial TTL value from upstream response.
	// Preserved for cache statistics and debugging without being decremented.
	OriginalTTL int

	// QueryType is the DNS record type this cache entry represents ("A", "AAAA", etc.).
	// Allows future multi-type caching where "example.com" could have separate A and AAAA entries.
	QueryType string
}

// IsExpired calculates if current time exceeds Timestamp + TTL.
// Returns true if the cache entry has expired.
func (c *CacheEntry) IsExpired() bool {
	return time.Now().After(c.Timestamp.Add(time.Duration(c.TTL) * time.Second))
}

// RemainingTTL returns seconds until expiration.
// Used when building DNS responses with decremented TTL values.
// Returns 0 if already expired.
func (c *CacheEntry) RemainingTTL() int {
	elapsed := time.Since(c.Timestamp)
	remaining := c.TTL - int(elapsed.Seconds())
	if remaining < 0 {
		return 0
	}
	return remaining
}

// =============================================================================
// CACHE RESULT ENUMERATION
// =============================================================================

// CacheResult represents the outcome of a cache lookup operation.
type CacheResult int

const (
	// CacheHit indicates query found in cache with valid (non-expired) TTL.
	// No upstream query needed.
	CacheHit CacheResult = iota

	// CacheMiss indicates query not found in cache.
	// Must forward to upstream resolver.
	CacheMiss

	// CacheExpired indicates entry exists in cache but TTL expired.
	// Treat as miss and refresh from upstream.
	CacheExpired

	// CacheInvalid indicates entry found but data corrupted or malformed.
	// Remove and query upstream.
	CacheInvalid
)

// String returns a human-readable representation of the cache result.
func (r CacheResult) String() string {
	switch r {
	case CacheHit:
		return "HIT"
	case CacheMiss:
		return "MISS"
	case CacheExpired:
		return "EXPIRED"
	case CacheInvalid:
		return "INVALID"
	default:
		return "UNKNOWN"
	}
}

// =============================================================================
// UPSTREAM RESULT STRUCTURE
// =============================================================================

// UpstreamResult represents the outcome of forwarding a query to upstream DNS (8.8.8.8).
type UpstreamResult struct {
	// Success indicates whether upstream query completed successfully
	// without timeout or network errors.
	Success bool

	// IP is the resolved IP address from upstream response.
	// Empty string if Success is false.
	IP string

	// TTL is the time-to-live from upstream answer section.
	// Zero if query failed.
	TTL int

	// ResponseTime is how long the upstream query took.
	// Used for latency metrics and timeout detection.
	ResponseTime time.Duration

	// Error captures the failure reason if Success is false.
	// Examples: timeout, network unreachable, NXDOMAIN, SERVFAIL.
	Error error
}

// =============================================================================
// QUERY TYPE CONSTANTS
// =============================================================================

const (
	// QueryTypeA represents IPv4 address record lookup.
	QueryTypeA = "A"

	// QueryTypeAAAA represents IPv6 address record lookup (future).
	QueryTypeAAAA = "AAAA"

	// QueryTypePTR represents reverse DNS lookup (future).
	QueryTypePTR = "PTR"

	// QueryTypeCNAME represents canonical name lookup (future).
	QueryTypeCNAME = "CNAME"
)
