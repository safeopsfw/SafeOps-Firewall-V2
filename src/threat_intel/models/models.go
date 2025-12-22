package models

import "time"

// ThreatData represents a generic threat intelligence entry
type ThreatData struct {
	ID          int64     `json:"id"`
	Value       string    `json:"value"`
	Type        string    `json:"type"`
	ThreatScore int       `json:"threat_score"`
	Confidence  int       `json:"confidence"`
	Category    string    `json:"category"`
	FirstSeen   time.Time `json:"first_seen"`
	LastSeen    time.Time `json:"last_seen"`
	Source      string    `json:"source"`
	Metadata    string    `json:"metadata"`
}

// IPBlacklist represents an IP blacklist entry
type IPBlacklist struct {
	ID          int64     `json:"id"`
	IPAddress   string    `json:"ip_address"`
	ThreatScore int       `json:"threat_score"`
	Category    string    `json:"category"`
	FirstSeen   time.Time `json:"first_seen"`
	LastSeen    time.Time `json:"last_seen"`
	Source      string    `json:"source"`
	Metadata    string    `json:"metadata"`
}

// DomainIntel represents a domain intelligence entry
type DomainIntel struct {
	ID          int64     `json:"id"`
	Domain      string    `json:"domain"`
	ThreatScore int       `json:"threat_score"`
	Category    string    `json:"category"`
	FirstSeen   time.Time `json:"first_seen"`
	LastSeen    time.Time `json:"last_seen"`
	Source      string    `json:"source"`
	Metadata    string    `json:"metadata"`
}

// HashIntel represents a hash intelligence entry
type HashIntel struct {
	ID          int64     `json:"id"`
	HashValue   string    `json:"hash_value"`
	HashType    string    `json:"hash_type"`
	ThreatScore int       `json:"threat_score"`
	Category    string    `json:"category"`
	FirstSeen   time.Time `json:"first_seen"`
	LastSeen    time.Time `json:"last_seen"`
	Source      string    `json:"source"`
	Metadata    string    `json:"metadata"`
}

// IOC represents an Indicator of Compromise
type IOC struct {
	ID          int64     `json:"id"`
	IOCValue    string    `json:"ioc_value"`
	IOCType     string    `json:"ioc_type"`
	ThreatScore int       `json:"threat_score"`
	Confidence  int       `json:"confidence"`
	Category    string    `json:"category"`
	FirstSeen   time.Time `json:"first_seen"`
	LastSeen    time.Time `json:"last_seen"`
	Source      string    `json:"source"`
	Metadata    string    `json:"metadata"`
}

// IPGeo represents IP geolocation data
type IPGeo struct {
	ID          int64   `json:"id"`
	IPAddress   string  `json:"ip_address"`
	CountryCode string  `json:"country_code"`
	CountryName string  `json:"country_name"`
	Region      string  `json:"region"`
	City        string  `json:"city"`
	Latitude    float64 `json:"latitude"`
	Longitude   float64 `json:"longitude"`
	ISP         string  `json:"isp"`
	ASN         int     `json:"asn"`
	ASNOrg      string  `json:"asn_org"`
}

// Feed represents a threat intelligence feed source
type Feed struct {
	ID              int       `json:"id"`
	FeedName        string    `json:"feed_name"`
	FeedURL         string    `json:"feed_url"`
	FeedType        string    `json:"feed_type"`
	UpdateFrequency int       `json:"update_frequency"`
	LastFetch       time.Time `json:"last_fetch"`
	LastSuccess     time.Time `json:"last_success"`
	Status          string    `json:"status"`
}
