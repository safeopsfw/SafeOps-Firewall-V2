// Package types provides common types and data structures for threat intelligence
package types

import (
	"encoding/json"
	"math"
	"time"
)

// ============================================================================
// Threat Level Enumeration
// ============================================================================

// ThreatLevel represents the assessed threat level for a country or region
type ThreatLevel string

const (
	ThreatLevelLow      ThreatLevel = "Low"
	ThreatLevelMedium   ThreatLevel = "Medium"
	ThreatLevelHigh     ThreatLevel = "High"
	ThreatLevelCritical ThreatLevel = "Critical"
	ThreatLevelUnknown  ThreatLevel = "Unknown"
)

// ============================================================================
// Region Type Enumeration
// ============================================================================

// RegionType defines the classification type for a region
type RegionType string

const (
	RegionTypeContinent     RegionType = "Continent"
	RegionTypeGeopolitical  RegionType = "GeopoliticalRegion"
	RegionTypeEconomicBloc  RegionType = "EconomicBloc"
	RegionTypeThreatContext RegionType = "ThreatContext"
	RegionTypeCustom        RegionType = "Custom"
)

// ============================================================================
// Geographic Coordinates Structure
// ============================================================================

// Coordinates represents a geographic point with latitude and longitude
type Coordinates struct {
	Latitude  float64 `json:"latitude" yaml:"latitude"`
	Longitude float64 `json:"longitude" yaml:"longitude"`
	Altitude  float64 `json:"altitude,omitempty" yaml:"altitude,omitempty"` // Meters above sea level
	Accuracy  float64 `json:"accuracy,omitempty" yaml:"accuracy,omitempty"` // Position accuracy in meters
}

// IsValid validates coordinate values are within valid ranges
func (c *Coordinates) IsValid() bool {
	return c.Latitude >= -90.0 && c.Latitude <= 90.0 &&
		c.Longitude >= -180.0 && c.Longitude <= 180.0
}

// DistanceTo calculates the distance to another coordinate in kilometers
// Uses Haversine formula for great-circle distance
func (c *Coordinates) DistanceTo(other *Coordinates) float64 {
	const earthRadiusKm = 6371.0

	// Convert to radians
	lat1 := c.Latitude * math.Pi / 180.0
	lon1 := c.Longitude * math.Pi / 180.0
	lat2 := other.Latitude * math.Pi / 180.0
	lon2 := other.Longitude * math.Pi / 180.0

	// Haversine formula
	dLat := lat2 - lat1
	dLon := lon2 - lon1

	a := math.Sin(dLat/2)*math.Sin(dLat/2) +
		math.Cos(lat1)*math.Cos(lat2)*
			math.Sin(dLon/2)*math.Sin(dLon/2)

	c_val := 2 * math.Atan2(math.Sqrt(a), math.Sqrt(1-a))

	return earthRadiusKm * c_val
}

// BoundingBox calculates the bounding box for a given radius (in km)
// Returns min/max latitude and longitude
func (c *Coordinates) BoundingBox(radiusKm float64) (minLat, maxLat, minLon, maxLon float64) {
	const earthRadiusKm = 6371.0

	// Angular distance in radians
	angularDistance := radiusKm / earthRadiusKm

	minLat = c.Latitude - (angularDistance * 180.0 / math.Pi)
	maxLat = c.Latitude + (angularDistance * 180.0 / math.Pi)

	// Longitude adjustment based on latitude
	latRad := c.Latitude * math.Pi / 180.0
	lonDelta := angularDistance * 180.0 / math.Pi / math.Cos(latRad)

	minLon = c.Longitude - lonDelta
	maxLon = c.Longitude + lonDelta

	// Clamp to valid ranges
	if minLat < -90.0 {
		minLat = -90.0
	}
	if maxLat > 90.0 {
		maxLat = 90.0
	}
	if minLon < -180.0 {
		minLon = -180.0
	}
	if maxLon > 180.0 {
		maxLon = 180.0
	}

	return minLat, maxLat, minLon, maxLon
}

// ============================================================================
// Geolocation Result Structure
// ============================================================================

// Geolocation represents complete geolocation information for an IP address
type Geolocation struct {
	// IP Information
	IPAddress string `json:"ip_address" yaml:"ip_address"`
	IPNetwork string `json:"ip_network,omitempty" yaml:"ip_network,omitempty"` // CIDR notation

	// Country Information
	CountryCode string `json:"country_code" yaml:"country_code"` // ISO 3166-1 alpha-2
	CountryName string `json:"country_name" yaml:"country_name"`

	// Regional Information
	Region     string `json:"region,omitempty" yaml:"region,omitempty"`
	City       string `json:"city,omitempty" yaml:"city,omitempty"`
	PostalCode string `json:"postal_code,omitempty" yaml:"postal_code,omitempty"`

	// Geographic Coordinates
	Latitude       float64 `json:"latitude,omitempty" yaml:"latitude,omitempty"`
	Longitude      float64 `json:"longitude,omitempty" yaml:"longitude,omitempty"`
	AccuracyRadius int     `json:"accuracy_radius,omitempty" yaml:"accuracy_radius,omitempty"` // Kilometers

	// Additional Context
	TimeZone      string `json:"timezone,omitempty" yaml:"timezone,omitempty"`
	Continent     string `json:"continent,omitempty" yaml:"continent,omitempty"`
	ContinentCode string `json:"continent_code,omitempty" yaml:"continent_code,omitempty"` // Two-letter code

	// Flags
	IsAnonymousProxy    bool `json:"is_anonymous_proxy" yaml:"is_anonymous_proxy"`
	IsSatelliteProvider bool `json:"is_satellite_provider" yaml:"is_satellite_provider"`

	// Metadata
	DataSource  string    `json:"data_source" yaml:"data_source"`
	LastUpdated time.Time `json:"last_updated" yaml:"last_updated"`
}

// GetCoordinates returns a Coordinates struct from this geolocation
func (g *Geolocation) GetCoordinates() *Coordinates {
	return &Coordinates{
		Latitude:  g.Latitude,
		Longitude: g.Longitude,
		Accuracy:  float64(g.AccuracyRadius * 1000), // Convert km to meters
	}
}

// HasCoordinates returns true if geolocation includes coordinate data
func (g *Geolocation) HasCoordinates() bool {
	return g.Latitude != 0.0 || g.Longitude != 0.0
}

// ============================================================================
// Country Metadata Structure
// ============================================================================

// CountryMetadata represents comprehensive information about a country
type CountryMetadata struct {
	// Identifiers
	CountryCode string `json:"country_code" yaml:"country_code"` // ISO 3166-1 alpha-2
	CountryName string `json:"country_name" yaml:"country_name"`
	ISO3        string `json:"iso3" yaml:"iso3"`                 // ISO 3166-1 alpha-3
	NumericCode int    `json:"numeric_code" yaml:"numeric_code"` // ISO 3166-1 numeric

	// Geographic Classification
	Region    string `json:"region" yaml:"region"`
	SubRegion string `json:"sub_region,omitempty" yaml:"sub_region,omitempty"`

	// Demographics & Infrastructure
	Population          int64   `json:"population,omitempty" yaml:"population,omitempty"`
	AreaSqKm            float64 `json:"area_sq_km,omitempty" yaml:"area_sq_km,omitempty"`
	InternetUsers       int64   `json:"internet_users,omitempty" yaml:"internet_users,omitempty"`
	InternetPenetration float64 `json:"internet_penetration,omitempty" yaml:"internet_penetration,omitempty"` // Percentage
	HostingProviders    int     `json:"hosting_providers,omitempty" yaml:"hosting_providers,omitempty"`

	// Threat Intelligence
	ThreatLevel     ThreatLevel `json:"threat_level" yaml:"threat_level"`
	ThreatScore     float64     `json:"threat_score" yaml:"threat_score"` // 0-100
	CommonThreats   []string    `json:"common_threats,omitempty" yaml:"common_threats,omitempty"`
	IsHighRisk      bool        `json:"is_high_risk" yaml:"is_high_risk"`
	IsDatacenterHub bool        `json:"is_datacenter_hub" yaml:"is_datacenter_hub"`

	// Additional Context
	Notes       string    `json:"notes,omitempty" yaml:"notes,omitempty"`
	LastUpdated time.Time `json:"last_updated" yaml:"last_updated"`
}

// ============================================================================
// Regional Classification Structure
// ============================================================================

// Region defines hierarchical geographic regions for analysis
type Region struct {
	RegionID       string     `json:"region_id" yaml:"region_id"`
	RegionName     string     `json:"region_name" yaml:"region_name"`
	RegionType     RegionType `json:"region_type" yaml:"region_type"`
	ParentRegionID string     `json:"parent_region_id,omitempty" yaml:"parent_region_id,omitempty"`
	Countries      []string   `json:"countries" yaml:"countries"` // List of country codes
	Description    string     `json:"description,omitempty" yaml:"description,omitempty"`
}

// ContainsCountry checks if a country code is in this region
func (r *Region) ContainsCountry(countryCode string) bool {
	for _, code := range r.Countries {
		if code == countryCode {
			return true
		}
	}
	return false
}

// ============================================================================
// IP Range to Country Mapping
// ============================================================================

// IPRangeMapping represents a mapping from an IP network to a country
type IPRangeMapping struct {
	// Network Range
	NetworkStart uint64 `json:"network_start" yaml:"network_start"` // Integer representation for sorting
	NetworkEnd   uint64 `json:"network_end" yaml:"network_end"`
	NetworkCIDR  string `json:"network_cidr" yaml:"network_cidr"` // CIDR notation for display

	// Country
	CountryCode string `json:"country_code" yaml:"country_code"` // ISO 3166-1 alpha-2

	// Metadata
	DataSource  string    `json:"data_source" yaml:"data_source"`
	LastUpdated time.Time `json:"last_updated" yaml:"last_updated"`
	Version     int       `json:"version" yaml:"version"` // IP version (4 or 6)
}

// ContainsIP checks if a given IP integer is within this range
func (m *IPRangeMapping) ContainsIP(ipInt uint64) bool {
	return ipInt >= m.NetworkStart && ipInt <= m.NetworkEnd
}

// ============================================================================
// Geolocation Lookup Result
// ============================================================================

// GeoLookupResult combines geolocation with country metadata for enriched context
type GeoLookupResult struct {
	Geolocation     *Geolocation     `json:"geolocation"`
	CountryMetadata *CountryMetadata `json:"country_metadata,omitempty"`
	LookupTime      time.Time        `json:"lookup_time"`
	CacheHit        bool             `json:"cache_hit"`
}

// ToJSON converts the lookup result to JSON
func (r *GeoLookupResult) ToJSON() (string, error) {
	bytes, err := json.Marshal(r)
	if err != nil {
		return "", err
	}
	return string(bytes), nil
}

// ============================================================================
// Predefined Continent Codes
// ============================================================================

var ContinentCodes = map[string]string{
	"AF": "Africa",
	"AN": "Antarctica",
	"AS": "Asia",
	"EU": "Europe",
	"NA": "North America",
	"OC": "Oceania",
	"SA": "South America",
}

// ============================================================================
// Helper Functions
// ============================================================================

// IsValidCountryCode validates an ISO 3166-1 alpha-2 country code
func IsValidCountryCode(code string) bool {
	// Country code must be exactly 2 uppercase letters
	if len(code) != 2 {
		return false
	}

	for _, char := range code {
		if char < 'A' || char > 'Z' {
			return false
		}
	}

	return true
}

// IsValidContinentCode validates a two-letter continent code
func IsValidContinentCode(code string) bool {
	_, exists := ContinentCodes[code]
	return exists
}

// GetContinentName returns the continent name for a given code
func GetContinentName(code string) string {
	if name, exists := ContinentCodes[code]; exists {
		return name
	}
	return "Unknown"
}

// ============================================================================
// Geolocation Statistics
// ============================================================================

// GeoStats holds statistics for geolocation data
type GeoStats struct {
	TotalMappings     int64            `json:"total_mappings"`
	IPv4Mappings      int64            `json:"ipv4_mappings"`
	IPv6Mappings      int64            `json:"ipv6_mappings"`
	CountriesCovered  int              `json:"countries_covered"`
	DataSources       []string         `json:"data_sources"`
	LastUpdate        time.Time        `json:"last_update"`
	CoverageByCountry map[string]int64 `json:"coverage_by_country,omitempty"`
}

// ============================================================================
// Default Values
// ============================================================================

// NewGeolocation creates a new Geolocation with default values
func NewGeolocation(ip, countryCode string) *Geolocation {
	return &Geolocation{
		IPAddress:           ip,
		CountryCode:         countryCode,
		IsAnonymousProxy:    false,
		IsSatelliteProvider: false,
		LastUpdated:         time.Now(),
	}
}

// NewCountryMetadata creates a new CountryMetadata with default values
func NewCountryMetadata(countryCode, countryName string) *CountryMetadata {
	return &CountryMetadata{
		CountryCode:     countryCode,
		CountryName:     countryName,
		ThreatLevel:     ThreatLevelUnknown,
		ThreatScore:     0.0,
		IsHighRisk:      false,
		IsDatacenterHub: false,
		LastUpdated:     time.Now(),
	}
}

// NewRegion creates a new Region with default values
func NewRegion(id, name string, regionType RegionType) *Region {
	return &Region{
		RegionID:   id,
		RegionName: name,
		RegionType: regionType,
		Countries:  make([]string, 0),
	}
}
