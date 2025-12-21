// Package types provides common types and data structures for threat intelligence
package types

import (
	"encoding/json"
	"time"
)

// ============================================================================
// Threat Type Enumeration
// ============================================================================

// ThreatType represents malicious activity classification
type ThreatType string

const (
	ThreatMalware          ThreatType = "malware"
	ThreatMalwareC2        ThreatType = "malware_c2"
	ThreatPhishing         ThreatType = "phishing"
	ThreatScam             ThreatType = "scam"
	ThreatSpam             ThreatType = "spam"
	ThreatScanner          ThreatType = "scanner"
	ThreatBruteForce       ThreatType = "brute_force"
	ThreatDDoS             ThreatType = "ddos"
	ThreatExploit          ThreatType = "exploit"
	ThreatRansomware       ThreatType = "ransomware"
	ThreatBotnetMember     ThreatType = "botnet_member"
	ThreatProxyAbuse       ThreatType = "proxy_abuse"
	ThreatCryptomining     ThreatType = "cryptomining"
	ThreatDataExfiltration ThreatType = "data_exfiltration"
	ThreatSuspicious       ThreatType = "suspicious"
	ThreatUnknown          ThreatType = "unknown"
)

// String returns the string representation of threat type
func (tt ThreatType) String() string {
	return string(tt)
}

// ============================================================================
// Severity Level Enumeration
// ============================================================================

// Severity represents threat severity classification
type Severity string

const (
	SeverityLow      Severity = "Low"
	SeverityMedium   Severity = "Medium"
	SeverityHigh     Severity = "High"
	SeverityCritical Severity = "Critical"
)

// String returns the string representation of severity
func (s Severity) String() string {
	return string(s)
}

// Score returns a numeric score for severity (for sorting/comparison)
func (s Severity) Score() int {
	switch s {
	case SeverityLow:
		return 1
	case SeverityMedium:
		return 2
	case SeverityHigh:
		return 3
	case SeverityCritical:
		return 4
	default:
		return 0
	}
}

// ============================================================================
// Confidence Level Classification
// ============================================================================

// ConfidenceLevel represents confidence classification
type ConfidenceLevel string

const (
	ConfidenceVeryLow  ConfidenceLevel = "VeryLow"  // 0-20
	ConfidenceLow      ConfidenceLevel = "Low"      // 21-40
	ConfidenceMedium   ConfidenceLevel = "Medium"   // 41-60
	ConfidenceHigh     ConfidenceLevel = "High"     // 61-80
	ConfidenceVeryHigh ConfidenceLevel = "VeryHigh" // 81-100
)

// GetConfidenceLevel returns the confidence level for a numeric score
func GetConfidenceLevel(score float64) ConfidenceLevel {
	switch {
	case score <= 20:
		return ConfidenceVeryLow
	case score <= 40:
		return ConfidenceLow
	case score <= 60:
		return ConfidenceMedium
	case score <= 80:
		return ConfidenceHigh
	default:
		return ConfidenceVeryHigh
	}
}

// ============================================================================
// Source Type Enumeration
// ============================================================================

// SourceType represents the type of reputation source
type SourceType string

const (
	SourceTypeOpenSource SourceType = "OpenSource"
	SourceTypeCommercial SourceType = "Commercial"
	SourceTypeInternal   SourceType = "Internal"
	SourceTypeCommunity  SourceType = "Community"
)

// ============================================================================
// Reputation Source Structure
// ============================================================================

// ReputationSource represents a single source contributing to reputation
type ReputationSource struct {
	SourceName       string     `json:"source_name" yaml:"source_name"`
	SourceType       SourceType `json:"source_type" yaml:"source_type"`
	SourceURL        string     `json:"source_url,omitempty" yaml:"source_url,omitempty"`
	ReportedAt       time.Time  `json:"reported_at" yaml:"reported_at"`
	ThreatType       ThreatType `json:"threat_type" yaml:"threat_type"`
	Confidence       float64    `json:"confidence,omitempty" yaml:"confidence,omitempty"` // Source-provided confidence
	SourceConfidence float64    `json:"source_confidence" yaml:"source_confidence"`       // Reliability of source itself (0-100)
	IsActive         bool       `json:"is_active" yaml:"is_active"`
	RawData          string     `json:"raw_data,omitempty" yaml:"raw_data,omitempty"` // Original data for audit
}

// ============================================================================
// IP Reputation Structure
// ============================================================================

// IPReputation represents complete reputation information for an IP address
type IPReputation struct {
	// Core Identification
	IPAddress string `json:"ip_address" yaml:"ip_address"`

	// Threat Classification
	ThreatType  ThreatType   `json:"threat_type" yaml:"threat_type"`                       // Primary classification
	ThreatTypes []ThreatType `json:"threat_types,omitempty" yaml:"threat_types,omitempty"` // All applicable types
	Confidence  float64      `json:"confidence" yaml:"confidence"`                         // 0-100
	Severity    Severity     `json:"severity" yaml:"severity"`

	// Temporal Tracking
	FirstSeen        time.Time `json:"first_seen" yaml:"first_seen"`
	LastSeen         time.Time `json:"last_seen" yaml:"last_seen"`
	ObservationCount int       `json:"observation_count" yaml:"observation_count"`

	// Source Attribution
	Sources     []ReputationSource `json:"sources,omitempty" yaml:"sources,omitempty"`
	SourceCount int                `json:"source_count" yaml:"source_count"`

	// Additional Context
	Tags []string `json:"tags,omitempty" yaml:"tags,omitempty"`

	// Enrichment Data
	Geolocation    *Geolocation `json:"geolocation,omitempty" yaml:"geolocation,omitempty"`
	ASN            int          `json:"asn,omitempty" yaml:"asn,omitempty"`
	ASNOrg         string       `json:"asn_org,omitempty" yaml:"asn_org,omitempty"`
	IsAnonymizer   bool         `json:"is_anonymizer" yaml:"is_anonymizer"`
	AnonymizerType string       `json:"anonymizer_type,omitempty" yaml:"anonymizer_type,omitempty"` // Tor, VPN, Proxy, Datacenter

	// Status
	IsActive    bool      `json:"is_active" yaml:"is_active"`
	Notes       string    `json:"notes,omitempty" yaml:"notes,omitempty"`
	LastUpdated time.Time `json:"last_updated" yaml:"last_updated"`
}

// GetConfidenceLevel returns the confidence level classification
func (r *IPReputation) GetConfidenceLevel() ConfidenceLevel {
	return GetConfidenceLevel(r.Confidence)
}

// IsHighConfidence returns true if confidence is high or very high
func (r *IPReputation) IsHighConfidence() bool {
	return r.Confidence >= 61.0
}

// IsCriticalThreat returns true if severity is high or critical
func (r *IPReputation) IsCriticalThreat() bool {
	return r.Severity == SeverityHigh || r.Severity == SeverityCritical
}

// GetPrimarySource returns the most recent or highest confidence source
func (r *IPReputation) GetPrimarySource() *ReputationSource {
	if len(r.Sources) == 0 {
		return nil
	}

	// Return first source (could enhance to sort by confidence)
	return &r.Sources[0]
}

// ToJSON converts the reputation to JSON string
func (r *IPReputation) ToJSON() (string, error) {
	bytes, err := json.Marshal(r)
	if err != nil {
		return "", err
	}
	return string(bytes), nil
}

// ============================================================================
// Domain Reputation Structure
// ============================================================================

// DomainReputation represents complete reputation information for a domain
type DomainReputation struct {
	// Core Identification
	Domain     string `json:"domain" yaml:"domain"`
	ApexDomain string `json:"apex_domain,omitempty" yaml:"apex_domain,omitempty"`
	TLD        string `json:"tld,omitempty" yaml:"tld,omitempty"`

	// Threat Classification
	ThreatType  ThreatType   `json:"threat_type" yaml:"threat_type"`
	ThreatTypes []ThreatType `json:"threat_types,omitempty" yaml:"threat_types,omitempty"`
	Confidence  float64      `json:"confidence" yaml:"confidence"`
	Severity    Severity     `json:"severity" yaml:"severity"`

	// Temporal Tracking
	FirstSeen        time.Time `json:"first_seen" yaml:"first_seen"`
	LastSeen         time.Time `json:"last_seen" yaml:"last_seen"`
	ObservationCount int       `json:"observation_count" yaml:"observation_count"`

	// Source Attribution
	Sources     []ReputationSource `json:"sources,omitempty" yaml:"sources,omitempty"`
	SourceCount int                `json:"source_count" yaml:"source_count"`

	// Additional Context
	Tags []string `json:"tags,omitempty" yaml:"tags,omitempty"`

	// WHOIS Data
	RegistrarName    string    `json:"registrar_name,omitempty" yaml:"registrar_name,omitempty"`
	RegistrationDate time.Time `json:"registration_date,omitempty" yaml:"registration_date,omitempty"`
	ExpirationDate   time.Time `json:"expiration_date,omitempty" yaml:"expiration_date,omitempty"`
	Nameservers      []string  `json:"nameservers,omitempty" yaml:"nameservers,omitempty"`

	// Domain Characteristics
	IsIDN             bool `json:"is_idn" yaml:"is_idn"`
	IsDGA             bool `json:"is_dga" yaml:"is_dga"` // Domain Generation Algorithm
	IsNewlyRegistered bool `json:"is_newly_registered" yaml:"is_newly_registered"`
	HasHTTPS          bool `json:"has_https" yaml:"has_https"`

	// Status
	IsActive    bool      `json:"is_active" yaml:"is_active"`
	Notes       string    `json:"notes,omitempty" yaml:"notes,omitempty"`
	LastUpdated time.Time `json:"last_updated" yaml:"last_updated"`
}

// GetConfidenceLevel returns the confidence level classification
func (r *DomainReputation) GetConfidenceLevel() ConfidenceLevel {
	return GetConfidenceLevel(r.Confidence)
}

// IsHighConfidence returns true if confidence is high or very high
func (r *DomainReputation) IsHighConfidence() bool {
	return r.Confidence >= 61.0
}

// IsCriticalThreat returns true if severity is high or critical
func (r *DomainReputation) IsCriticalThreat() bool {
	return r.Severity == SeverityHigh || r.Severity == SeverityCritical
}

// GetPrimarySource returns the most recent or highest confidence source
func (r *DomainReputation) GetPrimarySource() *ReputationSource {
	if len(r.Sources) == 0 {
		return nil
	}
	return &r.Sources[0]
}

// ToJSON converts the reputation to JSON string
func (r *DomainReputation) ToJSON() (string, error) {
	bytes, err := json.Marshal(r)
	if err != nil {
		return "", err
	}
	return string(bytes), nil
}

// ============================================================================
// Helper Functions
// ============================================================================

// CalculateAggregateConfidence calculates confidence from multiple sources
func CalculateAggregateConfidence(sources []ReputationSource) float64 {
	if len(sources) == 0 {
		return 0.0
	}

	// Base confidence from source count
	baseConfidence := float64(len(sources)) * 15.0
	if baseConfidence > 60.0 {
		baseConfidence = 60.0
	}

	// Add bonus for high-quality sources
	qualityBonus := 0.0
	for _, source := range sources {
		if source.SourceConfidence >= 80.0 {
			qualityBonus += 10.0
		} else if source.SourceConfidence >= 60.0 {
			qualityBonus += 5.0
		}
	}

	if qualityBonus > 30.0 {
		qualityBonus = 30.0
	}

	// Combine and cap at 100
	confidence := baseConfidence + qualityBonus
	if confidence > 100.0 {
		confidence = 100.0
	}

	return confidence
}

// DetermineSeverity determines severity based on threat type
func DetermineSeverity(threatType ThreatType) Severity {
	switch threatType {
	case ThreatRansomware, ThreatDataExfiltration, ThreatMalwareC2:
		return SeverityCritical
	case ThreatMalware, ThreatPhishing, ThreatExploit, ThreatDDoS:
		return SeverityHigh
	case ThreatScam, ThreatBotnetMember, ThreatBruteForce:
		return SeverityMedium
	case ThreatScanner, ThreatSpam, ThreatSuspicious:
		return SeverityLow
	default:
		return SeverityMedium
	}
}

// ============================================================================
// Default Values
// ============================================================================

// NewIPReputation creates a new IPReputation with default values
func NewIPReputation(ip string, threatType ThreatType) *IPReputation {
	now := time.Now()
	return &IPReputation{
		IPAddress:        ip,
		ThreatType:       threatType,
		ThreatTypes:      []ThreatType{threatType},
		Confidence:       50.0,
		Severity:         DetermineSeverity(threatType),
		FirstSeen:        now,
		LastSeen:         now,
		ObservationCount: 1,
		SourceCount:      0,
		Sources:          make([]ReputationSource, 0),
		Tags:             make([]string, 0),
		IsAnonymizer:     false,
		IsActive:         true,
		LastUpdated:      now,
	}
}

// NewDomainReputation creates a new DomainReputation with default values
func NewDomainReputation(domain string, threatType ThreatType) *DomainReputation {
	now := time.Now()
	return &DomainReputation{
		Domain:            domain,
		ThreatType:        threatType,
		ThreatTypes:       []ThreatType{threatType},
		Confidence:        50.0,
		Severity:          DetermineSeverity(threatType),
		FirstSeen:         now,
		LastSeen:          now,
		ObservationCount:  1,
		SourceCount:       0,
		Sources:           make([]ReputationSource, 0),
		Tags:              make([]string, 0),
		IsIDN:             false,
		IsDGA:             false,
		IsNewlyRegistered: false,
		HasHTTPS:          false,
		IsActive:          true,
		LastUpdated:       now,
	}
}

// NewReputationSource creates a new ReputationSource with default values
func NewReputationSource(name string, sourceType SourceType, threatType ThreatType) *ReputationSource {
	return &ReputationSource{
		SourceName:       name,
		SourceType:       sourceType,
		ThreatType:       threatType,
		ReportedAt:       time.Now(),
		SourceConfidence: 50.0,
		IsActive:         true,
	}
}
