package enrichment

// =============================================================================
// Data Models for IP Enrichment
// =============================================================================

// UnknownIP represents a row from the unknown_ips.csv file
type UnknownIP struct {
	IPAddress   string `json:"ip_address"`
	Count       int    `json:"count"`
	LastUpdated string `json:"last_updated"`
}

// =============================================================================
// ip-api.com Batch API Response
// POST http://ip-api.com/batch (up to 100 IPs per request)
// =============================================================================

// IPAPIResponse represents a single result from ip-api.com
type IPAPIResponse struct {
	Status      string  `json:"status"`      // "success" or "fail"
	Message     string  `json:"message"`     // Error message if status=fail
	Country     string  `json:"country"`     // "United States"
	CountryCode string  `json:"countryCode"` // "US"
	Region      string  `json:"region"`      // "CA" (state/province code)
	RegionName  string  `json:"regionName"`  // "California"
	City        string  `json:"city"`        // "San Jose"
	Zip         string  `json:"zip"`         // "95141"
	Lat         float64 `json:"lat"`         // 37.3861
	Lon         float64 `json:"lon"`         // -122.0839
	Timezone    string  `json:"timezone"`    // "America/Los_Angeles"
	ISP         string  `json:"isp"`         // "Cloudflare, Inc."
	Org         string  `json:"org"`         // "Cloudflare, Inc."
	AS          string  `json:"as"`          // "AS13335 Cloudflare, Inc."
	ASName      string  `json:"asname"`      // "CLOUDFLARENET"
	Mobile      bool    `json:"mobile"`      // false
	Proxy       bool    `json:"proxy"`       // false
	Hosting     bool    `json:"hosting"`     // true
	Query       string  `json:"query"`       // "1.1.1.1" (the IP that was looked up)
}

// =============================================================================
// ipwho.is Fallback API Response
// GET https://ipwho.is/{ip}
// =============================================================================

// IPWhoIsResponse represents the response from ipwho.is (fallback)
type IPWhoIsResponse struct {
	IP          string  `json:"ip"`
	Success     bool    `json:"success"`
	Type        string  `json:"type"` // "IPv4" or "IPv6"
	Continent   string  `json:"continent"`
	Country     string  `json:"country"`
	CountryCode string  `json:"country_code"`
	Region      string  `json:"region"`
	City        string  `json:"city"`
	Latitude    float64 `json:"latitude"`
	Longitude   float64 `json:"longitude"`
	Postal      string  `json:"postal"`
	IsEU        bool    `json:"is_eu"`
	Timezone    struct {
		ID string `json:"id"` // "America/Los_Angeles"
	} `json:"timezone"`
	Connection struct {
		ASN    int    `json:"asn"`    // 13335
		Org    string `json:"org"`    // "Cloudflare, Inc."
		ISP    string `json:"isp"`    // "Cloudflare, Inc."
		Domain string `json:"domain"` // "cloudflare.com"
	} `json:"connection"`
}

// =============================================================================
// Enrichment Result Summary
// =============================================================================

// EnrichResult holds the summary of an enrichment run
type EnrichResult struct {
	TotalCSV     int // Total IPs read from CSV
	Skipped      int // Filtered out (private, multicast, etc.)
	Lookups      int // IPs sent for API lookup
	Success      int // Successfully looked up + stored
	Failed       int // API lookup failures
	DBErrors     int // Database insert failures
	FallbackUsed int // IPs resolved via fallback API
	Batches      int // Number of batch API calls made
}
