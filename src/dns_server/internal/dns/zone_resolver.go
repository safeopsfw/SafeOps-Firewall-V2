// Package dns implements DNS protocol handling including zone resolution.
package dns

import (
	"strings"

	"dns_server/internal/models"
)

// =============================================================================
// ZONE RESOLVER - Authoritative Zone Checking
// =============================================================================
// Phase 1: Stub implementation that always returns false.
// All queries are treated as recursive lookups forwarded to upstream DNS.
//
// Phase 2+: Will integrate with PostgreSQL to check dns_zones table
// and provide authoritative answers for safeops.local domain.
// =============================================================================

// ZoneResolver checks if queries should be handled authoritatively.
type ZoneResolver struct {
	// enabled indicates whether authoritative zone checking is active.
	// Phase 1: Always false (no authoritative zones configured).
	enabled bool

	// zoneDomains is the list of domains this server is authoritative for.
	// Phase 2+: e.g., ["safeops.local", "10.in-addr.arpa"]
	zoneDomains []string

	// db is the PostgreSQL connection for zone queries.
	// Phase 2+: Will be initialized with database connection pool.
	// db *sql.DB
}

// AuthoritativeAnswer represents authoritative zone record data.
// Phase 2+: Used by GetZoneData() to return zone records.
type AuthoritativeAnswer struct {
	// IP is the resolved IP address from zone records
	IP string

	// TTL is the time-to-live for the zone record
	TTL int

	// RecordType is the DNS record type (A, AAAA, PTR, etc.)
	RecordType string

	// Found indicates if a matching record was found
	Found bool
}

// =============================================================================
// CONSTRUCTOR
// =============================================================================

// NewZoneResolver creates a new zone resolver.
// Phase 1: Returns disabled resolver with no authoritative zones.
// Phase 2+: Will accept database connection for zone table queries.
func NewZoneResolver() *ZoneResolver {
	return &ZoneResolver{
		enabled:     false, // Phase 1: Always disabled
		zoneDomains: []string{},
	}
}

// NewZoneResolverWithZones creates a zone resolver with predefined zones.
// Phase 2+: Used for testing or static zone configuration.
func NewZoneResolverWithZones(zones []string) *ZoneResolver {
	return &ZoneResolver{
		enabled:     len(zones) > 0,
		zoneDomains: zones,
	}
}

// =============================================================================
// AUTHORITATIVE CHECKING
// =============================================================================

// IsAuthoritative checks if this server should answer authoritatively for a query.
// Phase 1: Always returns false (all queries forwarded to upstream).
// Phase 2+: Will check if query domain matches configured authoritative zones.
func (zr *ZoneResolver) IsAuthoritative(query *models.DNSQuery) bool {
	// Phase 1: No authoritative zones configured
	// Return false to forward all queries to upstream resolver
	if !zr.enabled {
		return false
	}

	// Phase 2+ logic: Check if domain matches any configured zone
	domain := strings.ToLower(query.Domain)
	for _, zone := range zr.zoneDomains {
		if zr.isInZone(domain, zone) {
			return true
		}
	}

	return false
}

// GetZoneData retrieves authoritative zone records for a domain.
// Phase 1: Returns nil (never called since IsAuthoritative() always false).
// Phase 2+: Will query PostgreSQL dns_records table for matching records.
func (zr *ZoneResolver) GetZoneData(query *models.DNSQuery) *AuthoritativeAnswer {
	// Phase 1: Stub implementation - no authoritative data available
	// This method is never called in Phase 1 since IsAuthoritative() returns false
	return nil

	// Phase 2+ implementation will:
	// 1. Query dns_records table for query.Domain
	// 2. Filter by query.QueryType (A, AAAA, PTR)
	// 3. Return AuthoritativeAnswer with IP and TTL from database
	// 4. Handle NXDOMAIN if domain in zone but no record exists
}

// LoadZones refreshes the zone list from the database.
// Phase 1: Returns nil immediately (no zones to load).
// Phase 2+: Will query dns_zones table and populate zoneDomains slice.
func (zr *ZoneResolver) LoadZones() error {
	// Phase 1: No database connection, nothing to load
	return nil

	// Phase 2+ implementation will:
	// 1. Query: SELECT domain FROM dns_zones WHERE enabled = true
	// 2. Populate zr.zoneDomains with results
	// 3. Cache SOA records for performance
	// 4. Set zr.enabled = true if zones found
}

// =============================================================================
// HELPER METHODS
// =============================================================================

// isInZone checks if a domain falls within a configured zone.
// Handles both exact matches and subdomain matches.
// Example: "server1.safeops.local" is in zone "safeops.local"
func (zr *ZoneResolver) isInZone(domain, zone string) bool {
	domain = strings.ToLower(strings.TrimSuffix(domain, "."))
	zone = strings.ToLower(strings.TrimSuffix(zone, "."))

	// Exact match
	if domain == zone {
		return true
	}

	// Subdomain match: domain ends with ".zone"
	// e.g., "server1.safeops.local" ends with ".safeops.local"
	if strings.HasSuffix(domain, "."+zone) {
		return true
	}

	return false
}

// =============================================================================
// CONFIGURATION METHODS
// =============================================================================

// Enable enables authoritative zone checking.
// Phase 2+: Called after database connection established and zones loaded.
func (zr *ZoneResolver) Enable() {
	zr.enabled = true
}

// Disable disables authoritative zone checking.
// All queries will be forwarded to upstream resolver.
func (zr *ZoneResolver) Disable() {
	zr.enabled = false
}

// IsEnabled returns whether authoritative zone checking is active.
func (zr *ZoneResolver) IsEnabled() bool {
	return zr.enabled
}

// GetZones returns the list of configured authoritative zones.
func (zr *ZoneResolver) GetZones() []string {
	result := make([]string, len(zr.zoneDomains))
	copy(result, zr.zoneDomains)
	return result
}

// AddZone adds a zone to the authoritative zone list.
// Phase 2+: Used for dynamic zone configuration.
func (zr *ZoneResolver) AddZone(zone string) {
	zone = strings.ToLower(strings.TrimSuffix(zone, "."))
	zr.zoneDomains = append(zr.zoneDomains, zone)
	if len(zr.zoneDomains) > 0 {
		zr.enabled = true
	}
}

// RemoveZone removes a zone from the authoritative zone list.
func (zr *ZoneResolver) RemoveZone(zone string) {
	zone = strings.ToLower(strings.TrimSuffix(zone, "."))
	for i, z := range zr.zoneDomains {
		if z == zone {
			zr.zoneDomains = append(zr.zoneDomains[:i], zr.zoneDomains[i+1:]...)
			break
		}
	}
	if len(zr.zoneDomains) == 0 {
		zr.enabled = false
	}
}
