package geoip

import (
	"database/sql"
	"fmt"
	"log"
	"net"
	"sync"
	"time"

	_ "github.com/lib/pq"
)

// Config for PostgreSQL connection
type Config struct {
	Host     string
	Port     int
	Database string
	User     string
	Password string
}

// DefaultConfig returns the default PostgreSQL config for threat_intel_db
func DefaultConfig() Config {
	return Config{
		Host:     "localhost",
		Port:     5432,
		Database: "threat_intel_db",
		User:     "postgres",
		Password: "admin",
	}
}

// GeoInfo contains geolocation data for an IP
type GeoInfo struct {
	Country     string  `json:"country,omitempty"`
	CountryName string  `json:"country_name,omitempty"`
	City        string  `json:"city,omitempty"`
	Latitude    float64 `json:"lat,omitempty"`
	Longitude   float64 `json:"lon,omitempty"`
	ASN         int     `json:"asn,omitempty"`
	ASNOrg      string  `json:"asn_org,omitempty"`
}

// Lookup provides GeoIP lookups with caching
type Lookup struct {
	db             *sql.DB
	cache          map[string]*GeoInfo
	cacheMu        sync.RWMutex
	cacheMax       int
	enabled        bool
	unknownTracker *UnknownIPTracker
}

// NewLookup creates a new GeoIP lookup with PostgreSQL backend
func NewLookup(cfg Config) *Lookup {
	connStr := fmt.Sprintf(
		"host=%s port=%d user=%s password=%s dbname=%s sslmode=disable",
		cfg.Host, cfg.Port, cfg.User, cfg.Password, cfg.Database,
	)

	db, err := sql.Open("postgres", connStr)
	if err != nil {
		log.Printf("⚠️  GeoIP: Failed to connect to PostgreSQL: %v", err)
		return &Lookup{enabled: false, cache: make(map[string]*GeoInfo)}
	}

	// Configure connection pool
	db.SetMaxOpenConns(5)
	db.SetMaxIdleConns(2)
	db.SetConnMaxLifetime(5 * time.Minute)

	// Test connection
	if err := db.Ping(); err != nil {
		log.Printf("⚠️  GeoIP: PostgreSQL not available: %v", err)
		return &Lookup{enabled: false, cache: make(map[string]*GeoInfo)}
	}

	log.Println("✅ GeoIP: Connected to threat_intel_db")

	return &Lookup{
		db:             db,
		cache:          make(map[string]*GeoInfo),
		cacheMax:       10000,
		enabled:        true,
		unknownTracker: nil, // Set externally via SetUnknownTracker
	}
}

// IsEnabled returns whether GeoIP lookup is available
func (l *Lookup) IsEnabled() bool {
	return l.enabled
}

// Lookup returns geo info for an IP address
func (l *Lookup) Lookup(ipStr string) *GeoInfo {
	if !l.enabled || ipStr == "" {
		return nil
	}

	// Skip internal/private IPs
	if isInternalIP(ipStr) {
		return &GeoInfo{Country: "XX", CountryName: "Private"}
	}

	// Check cache first
	l.cacheMu.RLock()
	if cached, ok := l.cache[ipStr]; ok {
		l.cacheMu.RUnlock()
		return cached
	}
	l.cacheMu.RUnlock()

	// Query database
	geo := l.queryDB(ipStr)

	// Track unknown IPs (not in database and not private)
	if geo == nil && l.unknownTracker != nil {
		l.unknownTracker.Track(ipStr)
	}

	// Cache result
	l.cacheMu.Lock()
	if len(l.cache) >= l.cacheMax {
		// Simple cleanup: remove 20% of cache
		i := 0
		for k := range l.cache {
			if i >= l.cacheMax/5 {
				break
			}
			delete(l.cache, k)
			i++
		}
	}
	l.cache[ipStr] = geo
	l.cacheMu.Unlock()

	return geo
}

// queryDB queries PostgreSQL for IP geo data
func (l *Lookup) queryDB(ipStr string) *GeoInfo {
	query := `
		SELECT
			country_code,
			country_name,
			city,
			latitude,
			longitude,
			asn,
			asn_org
		FROM ip_geolocation
		WHERE ip_address = $1::inet 
		   OR ($1::inet BETWEEN ip_address AND ip_end)
		ORDER BY ip_address DESC
		LIMIT 1
	`

	var geo GeoInfo
	var lat, lon sql.NullFloat64
	var asn sql.NullInt64
	var countryCode, countryName, city, asnOrg sql.NullString

	err := l.db.QueryRow(query, ipStr).Scan(
		&countryCode,
		&countryName,
		&city,
		&lat,
		&lon,
		&asn,
		&asnOrg,
	)

	if err != nil {
		return nil
	}

	if countryCode.Valid {
		geo.Country = countryCode.String
	}
	if countryName.Valid {
		geo.CountryName = countryName.String
	}
	if city.Valid {
		geo.City = city.String
	}
	if lat.Valid {
		geo.Latitude = lat.Float64
	}
	if lon.Valid {
		geo.Longitude = lon.Float64
	}
	if asn.Valid {
		geo.ASN = int(asn.Int64)
	}
	if asnOrg.Valid {
		geo.ASNOrg = asnOrg.String
	}

	return &geo
}

// Close closes the database connection
func (l *Lookup) Close() {
	if l.unknownTracker != nil {
		l.unknownTracker.Close()
	}
	if l.db != nil {
		l.db.Close()
	}
}

// SetUnknownTracker sets the unknown IP tracker
func (l *Lookup) SetUnknownTracker(tracker *UnknownIPTracker) {
	l.unknownTracker = tracker
}

// GetStats returns cache statistics
func (l *Lookup) GetStats() map[string]interface{} {
	l.cacheMu.RLock()
	defer l.cacheMu.RUnlock()

	return map[string]interface{}{
		"enabled":    l.enabled,
		"cache_size": len(l.cache),
		"cache_max":  l.cacheMax,
	}
}

// isInternalIP checks if an IP is private/internal
func isInternalIP(ipStr string) bool {
	ip := net.ParseIP(ipStr)
	if ip == nil {
		return false
	}

	// Check for private ranges
	privateRanges := []string{
		"10.0.0.0/8",
		"172.16.0.0/12",
		"192.168.0.0/16",
		"127.0.0.0/8",
		"169.254.0.0/16",
		"::1/128",
		"fc00::/7",
		"fe80::/10",
	}

	for _, cidr := range privateRanges {
		_, network, _ := net.ParseCIDR(cidr)
		if network.Contains(ip) {
			return true
		}
	}

	return false
}
