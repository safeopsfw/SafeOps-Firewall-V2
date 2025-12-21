// Package types provides common types and data structures for threat intelligence
package types

import (
	"encoding/json"
	"time"
)

// ============================================================================
// IOC Type Enumeration
// ============================================================================

// IOCType represents the type of indicator of compromise
type IOCType string

const (
	IOCTypeIPv4        IOCType = "ipv4"
	IOCTypeIPv6        IOCType = "ipv6"
	IOCTypeDomain      IOCType = "domain"
	IOCTypeURL         IOCType = "url"
	IOCTypeMD5         IOCType = "md5"
	IOCTypeSHA1        IOCType = "sha1"
	IOCTypeSHA256      IOCType = "sha256"
	IOCTypeSHA512      IOCType = "sha512"
	IOCTypeEmail       IOCType = "email"
	IOCTypeFilePattern IOCType = "file_pattern"
	IOCTypeMutex       IOCType = "mutex"
	IOCTypeRegistry    IOCType = "registry"
)

// String returns the string representation of IOC type
func (t IOCType) String() string {
	return string(t)
}

// ============================================================================
// IOC Relationship Type
// ============================================================================

// RelationshipType represents the type of relationship between IOCs
type RelationshipType string

const (
	RelationSameCampaign       RelationshipType = "same_campaign"
	RelationSameInfrastructure RelationshipType = "same_infrastructure"
	RelationDomainResolvesTo   RelationshipType = "domain_resolves_to"
	RelationURLOnDomain        RelationshipType = "url_on_domain"
	RelationFileDownloadedFrom RelationshipType = "file_downloaded_from"
	RelationC2Communication    RelationshipType = "c2_communication"
	RelationRedirectsTo        RelationshipType = "redirects_to"
	RelationSubdomainOf        RelationshipType = "subdomain_of"
	RelationVariantOf          RelationshipType = "variant_of"
)

// ============================================================================
// Base IOC Structure
// ============================================================================

// IOC represents a generic indicator of compromise
type IOC struct {
	// Core Identification
	ID              string  `json:"id" yaml:"id"`
	IOCType         IOCType `json:"ioc_type" yaml:"ioc_type"`
	Value           string  `json:"value" yaml:"value"`                       // Raw value as string
	NormalizedValue string  `json:"normalized_value" yaml:"normalized_value"` // Normalized for deduplication

	// Classification
	ThreatType ThreatType `json:"threat_type" yaml:"threat_type"`
	Confidence float64    `json:"confidence" yaml:"confidence"`
	Severity   Severity   `json:"severity" yaml:"severity"`

	// Temporal
	FirstSeen time.Time `json:"first_seen" yaml:"first_seen"`
	LastSeen  time.Time `json:"last_seen" yaml:"last_seen"`
	ExpiresAt time.Time `json:"expires_at,omitempty" yaml:"expires_at,omitempty"`

	// Source Attribution
	Sources     []string `json:"sources,omitempty" yaml:"sources,omitempty"`
	SourceCount int      `json:"source_count" yaml:"source_count"`

	// Context
	Tags     []string               `json:"tags,omitempty" yaml:"tags,omitempty"`
	Metadata map[string]interface{} `json:"metadata,omitempty" yaml:"metadata,omitempty"`

	// Status
	IsActive  bool      `json:"is_active" yaml:"is_active"`
	CreatedAt time.Time `json:"created_at" yaml:"created_at"`
	UpdatedAt time.Time `json:"updated_at" yaml:"updated_at"`
}

// ToJSON converts IOC to JSON string
func (ioc *IOC) ToJSON() (string, error) {
	bytes, err := json.Marshal(ioc)
	if err != nil {
		return "", err
	}
	return string(bytes), nil
}

// IsExpired checks if the IOC has expired
func (ioc *IOC) IsExpired() bool {
	if ioc.ExpiresAt.IsZero() {
		return false // No expiration set
	}
	return time.Now().After(ioc.ExpiresAt)
}

// ============================================================================
// IP-Based IOC Structure
// ============================================================================

// IPBasedIOC represents an IP address IOC with enrichment
type IPBasedIOC struct {
	IOC // Embedded base IOC

	// IP-Specific Fields
	IPAddress     string `json:"ip_address" yaml:"ip_address"`
	IPVersion     int    `json:"ip_version" yaml:"ip_version"` // 4 or 6
	IsPublic      bool   `json:"is_public" yaml:"is_public"`
	NetworkPrefix string `json:"network_prefix,omitempty" yaml:"network_prefix,omitempty"` // CIDR notation

	// Geolocation
	Geolocation *Geolocation `json:"geolocation,omitempty" yaml:"geolocation,omitempty"`
	CountryCode string       `json:"country_code,omitempty" yaml:"country_code,omitempty"`

	// Network Information
	ASN             int    `json:"asn,omitempty" yaml:"asn,omitempty"`
	ASNOrganization string `json:"asn_organization,omitempty" yaml:"asn_organization,omitempty"`

	// Anonymizer Detection
	IsAnonymizer   bool   `json:"is_anonymizer" yaml:"is_anonymizer"`
	AnonymizerType string `json:"anonymizer_type,omitempty" yaml:"anonymizer_type,omitempty"` // Tor, VPN, Proxy, Datacenter

	// Hosting
	IsHostingProvider   bool   `json:"is_hosting_provider" yaml:"is_hosting_provider"`
	HostingProviderName string `json:"hosting_provider_name,omitempty" yaml:"hosting_provider_name,omitempty"`

	// DNS
	ReverseDNS string `json:"reverse_dns,omitempty" yaml:"reverse_dns,omitempty"`
	OpenPorts  []int  `json:"open_ports,omitempty" yaml:"open_ports,omitempty"`

	// Reputation
	ReputationData *IPReputation `json:"reputation_data,omitempty" yaml:"reputation_data,omitempty"`

	// Relationships
	RelatedIPs []string `json:"related_ips,omitempty" yaml:"related_ips,omitempty"`
}

// ============================================================================
// Domain-Based IOC Structure
// ============================================================================

// DomainBasedIOC represents a domain IOC with enrichment
type DomainBasedIOC struct {
	IOC // Embedded base IOC

	// Domain-Specific Fields
	Domain         string `json:"domain" yaml:"domain"`
	ApexDomain     string `json:"apex_domain,omitempty" yaml:"apex_domain,omitempty"`
	TLD            string `json:"tld,omitempty" yaml:"tld,omitempty"`
	EffectiveTLD   string `json:"effective_tld,omitempty" yaml:"effective_tld,omitempty"`
	SubdomainDepth int    `json:"subdomain_depth" yaml:"subdomain_depth"`

	// IDN & DGA
	IsIDN           bool   `json:"is_idn" yaml:"is_idn"`
	PunycodeVersion string `json:"punycode_version,omitempty" yaml:"punycode_version,omitempty"`
	IsDGA           bool   `json:"is_dga" yaml:"is_dga"`
	DGAFamily       string `json:"dga_family,omitempty" yaml:"dga_family,omitempty"`

	// WHOIS Data
	RegistrarName    string    `json:"registrar_name,omitempty" yaml:"registrar_name,omitempty"`
	RegistrationDate time.Time `json:"registration_date,omitempty" yaml:"registration_date,omitempty"`
	ExpirationDate   time.Time `json:"expiration_date,omitempty" yaml:"expiration_date,omitempty"`
	UpdatedDate      time.Time `json:"updated_date,omitempty" yaml:"updated_date,omitempty"`

	// DNS Records
	Nameservers []string `json:"nameservers,omitempty" yaml:"nameservers,omitempty"`
	DNSRecords  []string `json:"dns_records,omitempty" yaml:"dns_records,omitempty"` // A/AAAA records
	MXRecords   []string `json:"mx_records,omitempty" yaml:"mx_records,omitempty"`

	// SSL/TLS
	HasHTTPS       bool   `json:"has_https" yaml:"has_https"`
	SSLCertificate string `json:"ssl_certificate,omitempty" yaml:"ssl_certificate,omitempty"`

	// Characteristics
	IsNewlyRegistered bool `json:"is_newly_registered" yaml:"is_newly_registered"`

	// Reputation
	ReputationData *DomainReputation `json:"reputation_data,omitempty" yaml:"reputation_data,omitempty"`

	// Relationships
	SimilarDomains []string `json:"similar_domains,omitempty" yaml:"similar_domains,omitempty"`
	RelatedDomains []string `json:"related_domains,omitempty" yaml:"related_domains,omitempty"`
}

// ============================================================================
// Hash-Based IOC Structure
// ============================================================================

// HashBasedIOC represents a file hash IOC with enrichment
type HashBasedIOC struct {
	IOC // Embedded base IOC

	// Hash-Specific Fields
	Hash            string            `json:"hash" yaml:"hash"`
	HashType        IOCType           `json:"hash_type" yaml:"hash_type"`                                   // md5, sha1, sha256, sha512
	AlternateHashes map[string]string `json:"alternate_hashes,omitempty" yaml:"alternate_hashes,omitempty"` // Other hash types for same file

	// File Metadata
	FileSize int64  `json:"file_size,omitempty" yaml:"file_size,omitempty"`
	FileName string `json:"file_name,omitempty" yaml:"file_name,omitempty"`
	FileType string `json:"file_type,omitempty" yaml:"file_type,omitempty"` // exe, dll, pdf, doc
	MimeType string `json:"mime_type,omitempty" yaml:"mime_type,omitempty"`

	// Malware Classification
	MalwareFamily   string `json:"malware_family,omitempty" yaml:"malware_family,omitempty"`
	MalwarePlatform string `json:"malware_platform,omitempty" yaml:"malware_platform,omitempty"` // Windows, Linux, macOS, Android

	// Packing & Obfuscation
	IsPacked bool    `json:"is_packed" yaml:"is_packed"`
	Packer   string  `json:"packer,omitempty" yaml:"packer,omitempty"`
	Entropy  float64 `json:"entropy,omitempty" yaml:"entropy,omitempty"`

	// Detection Stats
	VirusTotalDetections int      `json:"virustotal_detections,omitempty" yaml:"virustotal_detections,omitempty"`
	VirusTotalTotal      int      `json:"virustotal_total,omitempty" yaml:"virustotal_total,omitempty"`
	SandboxReports       []string `json:"sandbox_reports,omitempty" yaml:"sandbox_reports,omitempty"`

	// Signatures
	YaraRuleMatches []string `json:"yara_rule_matches,omitempty" yaml:"yara_rule_matches,omitempty"`
	Signatures      []string `json:"signatures,omitempty" yaml:"signatures,omitempty"`

	// Submission History
	FirstSubmission time.Time `json:"first_submission,omitempty" yaml:"first_submission,omitempty"`
	LastSubmission  time.Time `json:"last_submission,omitempty" yaml:"last_submission,omitempty"`
	SubmissionCount int       `json:"submission_count,omitempty" yaml:"submission_count,omitempty"`

	// Relationships
	RelatedHashes []string `json:"related_hashes,omitempty" yaml:"related_hashes,omitempty"`
}

// ============================================================================
// URL-Based IOC Structure
// ============================================================================

// URLBasedIOC represents a URL IOC with enrichment
type URLBasedIOC struct {
	IOC // Embedded base IOC

	// URL-Specific Fields
	URL         string `json:"url" yaml:"url"`
	Scheme      string `json:"scheme,omitempty" yaml:"scheme,omitempty"` // http, https, ftp
	Domain      string `json:"domain,omitempty" yaml:"domain,omitempty"`
	Port        int    `json:"port,omitempty" yaml:"port,omitempty"`
	Path        string `json:"path,omitempty" yaml:"path,omitempty"`
	QueryString string `json:"query_string,omitempty" yaml:"query_string,omitempty"`
	Fragment    string `json:"fragment,omitempty" yaml:"fragment,omitempty"`

	// Defanging
	IsDefanged       bool   `json:"is_defanged" yaml:"is_defanged"`
	OriginalDefanged string `json:"original_defanged,omitempty" yaml:"original_defanged,omitempty"`

	// HTTP Response
	HTTPStatus    int    `json:"http_status,omitempty" yaml:"http_status,omitempty"`
	HTTPRedirect  string `json:"http_redirect,omitempty" yaml:"http_redirect,omitempty"`
	ContentType   string `json:"content_type,omitempty" yaml:"content_type,omitempty"`
	PageTitle     string `json:"page_title,omitempty" yaml:"page_title,omitempty"`
	ScreenshotURL string `json:"screenshot_url,omitempty" yaml:"screenshot_url,omitempty"`

	// Phishing
	IsPhishing     bool   `json:"is_phishing" yaml:"is_phishing"`
	PhishingTarget string `json:"phishing_target,omitempty" yaml:"phishing_target,omitempty"` // Brand being impersonated

	// Relationships
	RelatedURLs []string `json:"related_urls,omitempty" yaml:"related_urls,omitempty"`
}

// ============================================================================
// IOC Relationship Structure
// ============================================================================

// IOCRelationship represents a relationship between two IOCs
type IOCRelationship struct {
	SourceIOCID      string                 `json:"source_ioc_id" yaml:"source_ioc_id"`
	TargetIOCID      string                 `json:"target_ioc_id" yaml:"target_ioc_id"`
	RelationshipType RelationshipType       `json:"relationship_type" yaml:"relationship_type"`
	Confidence       float64                `json:"confidence" yaml:"confidence"` // 0-100
	FirstObserved    time.Time              `json:"first_observed" yaml:"first_observed"`
	LastObserved     time.Time              `json:"last_observed" yaml:"last_observed"`
	ObservationCount int                    `json:"observation_count" yaml:"observation_count"`
	Bidirectional    bool                   `json:"bidirectional" yaml:"bidirectional"`
	Metadata         map[string]interface{} `json:"metadata,omitempty" yaml:"metadata,omitempty"`
}

// ============================================================================
// IOC Metadata Structure
// ============================================================================

// IOCMetadata provides flexible key-value storage for additional context
type IOCMetadata struct {
	Campaign    string   `json:"campaign,omitempty" yaml:"campaign,omitempty"`
	Actor       string   `json:"actor,omitempty" yaml:"actor,omitempty"`
	TTPs        []string `json:"ttps,omitempty" yaml:"ttps,omitempty"` // MITRE ATT&CK IDs
	CVE         []string `json:"cve,omitempty" yaml:"cve,omitempty"`
	Industry    string   `json:"industry,omitempty" yaml:"industry,omitempty"`   // Targeted industry
	Geography   string   `json:"geography,omitempty" yaml:"geography,omitempty"` // Targeted region
	Description string   `json:"description,omitempty" yaml:"description,omitempty"`
	References  []string `json:"references,omitempty" yaml:"references,omitempty"` // URLs to reports
	Mitigations []string `json:"mitigations,omitempty" yaml:"mitigations,omitempty"`
}

// ============================================================================
// Helper Functions
// ============================================================================

// NewIOC creates a new IOC with default values
func NewIOC(iocType IOCType, value string) *IOC {
	now := time.Now()
	return &IOC{
		IOCType:         iocType,
		Value:           value,
		NormalizedValue: value, // Should be normalized by caller
		ThreatType:      ThreatUnknown,
		Confidence:      50.0,
		Severity:        SeverityMedium,
		FirstSeen:       now,
		LastSeen:        now,
		SourceCount:     0,
		Sources:         make([]string, 0),
		Tags:            make([]string, 0),
		Metadata:        make(map[string]interface{}),
		IsActive:        true,
		CreatedAt:       now,
		UpdatedAt:       now,
	}
}

// NewIPBasedIOC creates a new IP-based IOC
func NewIPBasedIOC(ipAddress string, ipVersion int) *IPBasedIOC {
	iocType := IOCTypeIPv4
	if ipVersion == 6 {
		iocType = IOCTypeIPv6
	}

	return &IPBasedIOC{
		IOC:               *NewIOC(iocType, ipAddress),
		IPAddress:         ipAddress,
		IPVersion:         ipVersion,
		IsPublic:          true, // Should be set by caller
		IsAnonymizer:      false,
		IsHostingProvider: false,
		OpenPorts:         make([]int, 0),
		RelatedIPs:        make([]string, 0),
	}
}

// NewDomainBasedIOC creates a new domain-based IOC
func NewDomainBasedIOC(domain string) *DomainBasedIOC {
	return &DomainBasedIOC{
		IOC:               *NewIOC(IOCTypeDomain, domain),
		Domain:            domain,
		IsIDN:             false,
		IsDGA:             false,
		HasHTTPS:          false,
		IsNewlyRegistered: false,
		Nameservers:       make([]string, 0),
		DNSRecords:        make([]string, 0),
		MXRecords:         make([]string, 0),
		SimilarDomains:    make([]string, 0),
		RelatedDomains:    make([]string, 0),
	}
}

// NewHashBasedIOC creates a new hash-based IOC
func NewHashBasedIOC(hash string, hashType IOCType) *HashBasedIOC {
	return &HashBasedIOC{
		IOC:             *NewIOC(hashType, hash),
		Hash:            hash,
		HashType:        hashType,
		AlternateHashes: make(map[string]string),
		IsPacked:        false,
		SandboxReports:  make([]string, 0),
		YaraRuleMatches: make([]string, 0),
		Signatures:      make([]string, 0),
		RelatedHashes:   make([]string, 0),
	}
}

// NewURLBasedIOC creates a new URL-based IOC
func NewURLBasedIOC(url string) *URLBasedIOC {
	return &URLBasedIOC{
		IOC:         *NewIOC(IOCTypeURL, url),
		URL:         url,
		IsDefanged:  false,
		IsPhishing:  false,
		RelatedURLs: make([]string, 0),
	}
}

// NewIOCRelationship creates a new IOC relationship
func NewIOCRelationship(sourceID, targetID string, relationType RelationshipType) *IOCRelationship {
	now := time.Now()
	return &IOCRelationship{
		SourceIOCID:      sourceID,
		TargetIOCID:      targetID,
		RelationshipType: relationType,
		Confidence:       50.0,
		FirstObserved:    now,
		LastObserved:     now,
		ObservationCount: 1,
		Bidirectional:    false,
		Metadata:         make(map[string]interface{}),
	}
}
