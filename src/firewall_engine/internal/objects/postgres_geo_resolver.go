// Package objects provides reusable network objects for firewall rules.
package objects

import (
	"context"
	"database/sql"
	"fmt"
	"net"
	"strings"
	"sync"
	"time"
)

// ============================================================================
// PostgreSQL GeoIP Resolver - Implements GeoResolver using threat_intel DB
// ============================================================================

// PostgresGeoResolver implements GeoResolver using the ip_geolocation table
// from the threat_intel PostgreSQL database.
type PostgresGeoResolver struct {
	db        *sql.DB
	tableName string

	// Query timeout
	timeout time.Duration

	// In-memory cache for frequently accessed countries/ASNs
	cache    map[string]geoCacheEntry
	cacheMu  sync.RWMutex
	cacheTTL time.Duration

	// Statistics
	queryCount  uint64
	cacheHits   uint64
	cacheMisses uint64
}

type geoCacheEntry struct {
	cidrs     []*net.IPNet
	expiresAt time.Time
}

// PostgresGeoConfig contains configuration for the PostgreSQL resolver.
type PostgresGeoConfig struct {
	// DB is the database connection.
	DB *sql.DB

	// TableName is the table to query (default: ip_geolocation).
	TableName string

	// Timeout is the query timeout (default: 5 seconds).
	Timeout time.Duration

	// CacheTTL is how long to cache results (default: 1 hour).
	CacheTTL time.Duration
}

// NewPostgresGeoResolver creates a new PostgreSQL-based GeoIP resolver.
func NewPostgresGeoResolver(config *PostgresGeoConfig) (*PostgresGeoResolver, error) {
	if config == nil || config.DB == nil {
		return nil, fmt.Errorf("database connection is required")
	}

	tableName := config.TableName
	if tableName == "" {
		tableName = "ip_geolocation"
	}

	timeout := config.Timeout
	if timeout == 0 {
		timeout = 5 * time.Second
	}

	cacheTTL := config.CacheTTL
	if cacheTTL == 0 {
		cacheTTL = time.Hour
	}

	return &PostgresGeoResolver{
		db:        config.DB,
		tableName: tableName,
		timeout:   timeout,
		cache:     make(map[string]geoCacheEntry),
		cacheTTL:  cacheTTL,
	}, nil
}

// ResolveCountry returns CIDRs for a country code (e.g., "RU", "CN").
// It queries the ip_geolocation table for IP ranges belonging to that country.
func (r *PostgresGeoResolver) ResolveCountry(countryCode string) ([]*net.IPNet, error) {
	countryCode = strings.ToUpper(strings.TrimSpace(countryCode))
	if countryCode == "" {
		return nil, fmt.Errorf("country code is required")
	}

	cacheKey := "country:" + countryCode

	// Check cache first
	if cidrs, ok := r.getFromCache(cacheKey); ok {
		r.cacheHits++
		return cidrs, nil
	}
	r.cacheMisses++

	// Query database for IP ranges in this country
	ctx, cancel := context.WithTimeout(context.Background(), r.timeout)
	defer cancel()

	r.queryCount++

	// Query for IP ranges with this country code
	// The query returns IP ranges which we convert to CIDRs
	query := fmt.Sprintf(`
		SELECT ip_address::text, ip_end::text
		FROM %s
		WHERE country_code = $1
		AND ip_address IS NOT NULL
		ORDER BY ip_address
	`, r.tableName)

	rows, err := r.db.QueryContext(ctx, query, countryCode)
	if err != nil {
		return nil, fmt.Errorf("failed to query country %s: %w", countryCode, err)
	}
	defer rows.Close()

	var cidrs []*net.IPNet

	for rows.Next() {
		var ipStart, ipEnd sql.NullString
		if err := rows.Scan(&ipStart, &ipEnd); err != nil {
			continue
		}

		if !ipStart.Valid {
			continue
		}

		// Convert IP range to CIDR(s)
		rangeCIDRs, err := ipRangeToCIDRs(ipStart.String, ipEnd.String)
		if err != nil {
			// If range conversion fails, try as single IP
			ip := net.ParseIP(ipStart.String)
			if ip != nil {
				var mask net.IPMask
				if ip.To4() != nil {
					mask = net.CIDRMask(32, 32) // /32 for IPv4
				} else {
					mask = net.CIDRMask(128, 128) // /128 for IPv6
				}
				cidrs = append(cidrs, &net.IPNet{IP: ip, Mask: mask})
			}
			continue
		}
		cidrs = append(cidrs, rangeCIDRs...)
	}

	// Cache the result
	r.putInCache(cacheKey, cidrs)

	return cidrs, nil
}

// ResolveASN returns CIDRs for an ASN (e.g., "AS15169" or "15169").
func (r *PostgresGeoResolver) ResolveASN(asn string) ([]*net.IPNet, error) {
	asn = strings.TrimSpace(asn)
	if asn == "" {
		return nil, fmt.Errorf("ASN is required")
	}

	// Remove "AS" prefix if present
	asn = strings.TrimPrefix(strings.ToUpper(asn), "AS")

	cacheKey := "asn:" + asn

	// Check cache first
	if cidrs, ok := r.getFromCache(cacheKey); ok {
		r.cacheHits++
		return cidrs, nil
	}
	r.cacheMisses++

	ctx, cancel := context.WithTimeout(context.Background(), r.timeout)
	defer cancel()

	r.queryCount++

	// Query for IP ranges with this ASN
	query := fmt.Sprintf(`
		SELECT ip_address::text, ip_end::text
		FROM %s
		WHERE asn = $1
		AND ip_address IS NOT NULL
		ORDER BY ip_address
	`, r.tableName)

	rows, err := r.db.QueryContext(ctx, query, asn)
	if err != nil {
		return nil, fmt.Errorf("failed to query ASN %s: %w", asn, err)
	}
	defer rows.Close()

	var cidrs []*net.IPNet

	for rows.Next() {
		var ipStart, ipEnd sql.NullString
		if err := rows.Scan(&ipStart, &ipEnd); err != nil {
			continue
		}

		if !ipStart.Valid {
			continue
		}

		// Convert IP range to CIDR(s)
		rangeCIDRs, err := ipRangeToCIDRs(ipStart.String, ipEnd.String)
		if err != nil {
			// If range conversion fails, try as single IP
			ip := net.ParseIP(ipStart.String)
			if ip != nil {
				var mask net.IPMask
				if ip.To4() != nil {
					mask = net.CIDRMask(32, 32)
				} else {
					mask = net.CIDRMask(128, 128)
				}
				cidrs = append(cidrs, &net.IPNet{IP: ip, Mask: mask})
			}
			continue
		}
		cidrs = append(cidrs, rangeCIDRs...)
	}

	// Cache the result
	r.putInCache(cacheKey, cidrs)

	return cidrs, nil
}

// LookupIP returns the country code and ASN for an IP.
func (r *PostgresGeoResolver) LookupIP(ip net.IP) (string, string, error) {
	if ip == nil {
		return "", "", fmt.Errorf("IP is nil")
	}

	ipStr := ip.String()

	ctx, cancel := context.WithTimeout(context.Background(), r.timeout)
	defer cancel()

	r.queryCount++

	// Query for exact match or range containment
	// Uses PostgreSQL's inet type for efficient IP matching
	query := fmt.Sprintf(`
		SELECT country_code, asn
		FROM %s
		WHERE ip_address = $1::inet
		   OR ($1::inet BETWEEN ip_address AND ip_end)
		ORDER BY ip_address DESC
		LIMIT 1
	`, r.tableName)

	var countryCode sql.NullString
	var asn sql.NullInt64

	err := r.db.QueryRowContext(ctx, query, ipStr).Scan(&countryCode, &asn)
	if err != nil {
		if err == sql.ErrNoRows {
			return "", "", nil // Not found, not an error
		}
		return "", "", fmt.Errorf("failed to lookup IP %s: %w", ipStr, err)
	}

	asnStr := ""
	if asn.Valid && asn.Int64 > 0 {
		asnStr = fmt.Sprintf("AS%d", asn.Int64)
	}

	return countryCode.String, asnStr, nil
}

// ============================================================================
// Cache Operations
// ============================================================================

func (r *PostgresGeoResolver) getFromCache(key string) ([]*net.IPNet, bool) {
	r.cacheMu.RLock()
	defer r.cacheMu.RUnlock()

	entry, ok := r.cache[key]
	if !ok {
		return nil, false
	}

	if time.Now().After(entry.expiresAt) {
		return nil, false // Expired
	}

	return entry.cidrs, true
}

func (r *PostgresGeoResolver) putInCache(key string, cidrs []*net.IPNet) {
	r.cacheMu.Lock()
	defer r.cacheMu.Unlock()

	r.cache[key] = geoCacheEntry{
		cidrs:     cidrs,
		expiresAt: time.Now().Add(r.cacheTTL),
	}
}

// ClearCache clears the resolver cache.
func (r *PostgresGeoResolver) ClearCache() {
	r.cacheMu.Lock()
	defer r.cacheMu.Unlock()
	r.cache = make(map[string]geoCacheEntry)
}

// PruneExpiredCache removes expired entries from cache.
func (r *PostgresGeoResolver) PruneExpiredCache() int {
	r.cacheMu.Lock()
	defer r.cacheMu.Unlock()

	now := time.Now()
	pruned := 0

	for key, entry := range r.cache {
		if now.After(entry.expiresAt) {
			delete(r.cache, key)
			pruned++
		}
	}

	return pruned
}

// ============================================================================
// Statistics
// ============================================================================

// PostgresGeoStats contains resolver statistics.
type PostgresGeoStats struct {
	QueryCount   uint64  `json:"query_count"`
	CacheHits    uint64  `json:"cache_hits"`
	CacheMisses  uint64  `json:"cache_misses"`
	CacheSize    int     `json:"cache_size"`
	CacheHitRate float64 `json:"cache_hit_rate"`
}

// GetStats returns current statistics.
func (r *PostgresGeoResolver) GetStats() PostgresGeoStats {
	r.cacheMu.RLock()
	cacheSize := len(r.cache)
	r.cacheMu.RUnlock()

	stats := PostgresGeoStats{
		QueryCount:  r.queryCount,
		CacheHits:   r.cacheHits,
		CacheMisses: r.cacheMisses,
		CacheSize:   cacheSize,
	}

	total := stats.CacheHits + stats.CacheMisses
	if total > 0 {
		stats.CacheHitRate = float64(stats.CacheHits) / float64(total)
	}

	return stats
}

// ============================================================================
// IP Range to CIDR Conversion
// ============================================================================

// ipRangeToCIDRs converts an IP range to a list of CIDRs.
// This is an approximation that creates the smallest CIDR covering the range.
func ipRangeToCIDRs(startStr, endStr string) ([]*net.IPNet, error) {
	if endStr == "" {
		endStr = startStr
	}

	startIP := net.ParseIP(startStr)
	endIP := net.ParseIP(endStr)

	if startIP == nil {
		return nil, fmt.Errorf("invalid start IP: %s", startStr)
	}
	if endIP == nil {
		endIP = startIP
	}

	// For simplicity, create a single CIDR that covers the range
	// This may be larger than the actual range but is efficient for matching
	cidrs := rangeToCIDRs(startIP, endIP)
	return cidrs, nil
}

// rangeToCIDRs converts an IP range to the smallest set of CIDRs.
// Simplified implementation that creates covering CIDRs.
func rangeToCIDRs(start, end net.IP) []*net.IPNet {
	var result []*net.IPNet

	// Normalize to IPv4 if possible
	start4 := start.To4()
	end4 := end.To4()

	if start4 != nil && end4 != nil {
		// IPv4
		result = rangeToCIDRsIPv4(start4, end4)
	} else {
		// IPv6 or mixed - just use a /64 approximation
		_, cidr, _ := net.ParseCIDR(start.String() + "/64")
		if cidr != nil {
			result = append(result, cidr)
		}
	}

	return result
}

// rangeToCIDRsIPv4 converts an IPv4 range to CIDRs.
func rangeToCIDRsIPv4(start, end net.IP) []*net.IPNet {
	var result []*net.IPNet

	startInt := ipv4ToUint32(start)
	endInt := ipv4ToUint32(end)

	if startInt > endInt {
		startInt, endInt = endInt, startInt
	}

	for startInt <= endInt {
		// Find the largest CIDR that fits
		maxSize := 32
		for maxSize > 0 {
			mask := uint32(1<<(32-maxSize+1) - 1)
			if (startInt & mask) != 0 {
				break
			}
			lastIP := startInt | mask
			if lastIP > endInt {
				break
			}
			maxSize--
		}

		cidr := &net.IPNet{
			IP:   uint32ToIPv4(startInt),
			Mask: net.CIDRMask(maxSize, 32),
		}
		result = append(result, cidr)

		// Move to next range
		startInt += 1 << (32 - maxSize)
		if startInt == 0 {
			break // Overflow
		}
	}

	return result
}

func ipv4ToUint32(ip net.IP) uint32 {
	ip = ip.To4()
	if ip == nil {
		return 0
	}
	return uint32(ip[0])<<24 | uint32(ip[1])<<16 | uint32(ip[2])<<8 | uint32(ip[3])
}

func uint32ToIPv4(n uint32) net.IP {
	return net.IPv4(byte(n>>24), byte(n>>16), byte(n>>8), byte(n))
}

// ============================================================================
// Connection Helper
// ============================================================================

// CreatePostgresConnection creates a PostgreSQL connection for the resolver.
// This is a convenience function that mirrors the threat_intel pattern.
func CreatePostgresConnection(host string, port int, database, user, password string) (*sql.DB, error) {
	connStr := fmt.Sprintf(
		"host=%s port=%d dbname=%s user=%s password=%s sslmode=disable",
		host, port, database, user, password,
	)

	db, err := sql.Open("postgres", connStr)
	if err != nil {
		return nil, fmt.Errorf("failed to open database: %w", err)
	}

	// Configure connection pool
	db.SetMaxOpenConns(10)
	db.SetMaxIdleConns(5)
	db.SetConnMaxLifetime(time.Hour)

	// Test connection
	if err := db.Ping(); err != nil {
		db.Close()
		return nil, fmt.Errorf("failed to connect to database: %w", err)
	}

	return db, nil
}
