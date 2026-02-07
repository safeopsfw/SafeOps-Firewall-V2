package enrichment

import (
	"bytes"
	"context"
	"encoding/csv"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	"threat_intel/src/storage"
)

// =============================================================================
// Enrichment Configuration
// =============================================================================

// EnrichConfig holds configuration for the enricher
type EnrichConfig struct {
	CSVPath         string        // Path to unknown_ips.csv
	BatchSize       int           // Max IPs per batch request (ip-api.com max: 100)
	RateDelay       time.Duration // Delay between batch requests (4s for 15 req/min)
	FallbackEnabled bool          // Use ipwho.is as fallback for failures
	DBConfig        *storage.DBConfig
}

// DefaultEnrichConfig returns sensible defaults
func DefaultEnrichConfig(csvPath string) *EnrichConfig {
	return &EnrichConfig{
		CSVPath:         csvPath,
		BatchSize:       100,
		RateDelay:       4 * time.Second,
		FallbackEnabled: true,
		DBConfig:        storage.DefaultDBConfig(),
	}
}

// =============================================================================
// Enricher
// =============================================================================

// Enricher handles IP geolocation enrichment from CSV files
type Enricher struct {
	config   *EnrichConfig
	geoStore *storage.IPGeoStorage
	db       *storage.DB
	client   *http.Client
	logger   *log.Logger
}

// NewEnricher creates a new enricher instance
func NewEnricher(config *EnrichConfig) (*Enricher, error) {
	if config == nil {
		return nil, fmt.Errorf("config is required")
	}

	logger := log.New(os.Stdout, "[ENRICH] ", log.LstdFlags)

	// Connect to database
	logger.Println("Connecting to database...")
	db, err := storage.NewDB(config.DBConfig)
	if err != nil {
		return nil, fmt.Errorf("database connection failed: %w", err)
	}

	if err := db.Ping(); err != nil {
		db.Close()
		return nil, fmt.Errorf("database ping failed: %w", err)
	}
	logger.Println("  ✓ Database connected")

	geoStore := storage.NewIPGeoStorage(db)

	// HTTP client with reasonable timeout
	client := &http.Client{
		Timeout: 30 * time.Second,
	}

	return &Enricher{
		config:   config,
		geoStore: geoStore,
		db:       db,
		client:   client,
		logger:   logger,
	}, nil
}

// Close closes database connection
func (e *Enricher) Close() {
	if e.db != nil {
		e.db.Close()
	}
}

// =============================================================================
// Main Run Method
// =============================================================================

// Run executes the full enrichment pipeline
func (e *Enricher) Run() (*EnrichResult, error) {
	result := &EnrichResult{}
	startTime := time.Now()

	e.logger.Println("===========================================")
	e.logger.Println("IP Geolocation Enrichment")
	e.logger.Println("===========================================")

	// Step 1: Read CSV
	e.logger.Printf("Reading CSV: %s\n", e.config.CSVPath)
	unknownIPs, err := e.readCSV(e.config.CSVPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read CSV: %w", err)
	}
	result.TotalCSV = len(unknownIPs)
	e.logger.Printf("  Loaded %d IPs from CSV\n", result.TotalCSV)

	// Step 2: Filter to public IPs only
	e.logger.Println("Filtering to public routable IPs...")
	var allIPs []string
	for _, u := range unknownIPs {
		allIPs = append(allIPs, u.IPAddress)
	}
	publicIPs := e.filterPublicIPs(allIPs)
	result.Skipped = result.TotalCSV - len(publicIPs)
	result.Lookups = len(publicIPs)
	e.logger.Printf("  %d public IPs to look up (skipped %d non-routable)\n", result.Lookups, result.Skipped)

	if len(publicIPs) == 0 {
		e.logger.Println("  No public IPs to enrich. Done.")
		return result, nil
	}

	// Step 3: Batch lookup via ip-api.com
	e.logger.Println("Looking up IPs via ip-api.com batch API...")
	apiResults, failedIPs := e.batchLookup(publicIPs)
	result.Batches = (len(publicIPs) + e.config.BatchSize - 1) / e.config.BatchSize

	// Step 4: Fallback for failed IPs
	if e.config.FallbackEnabled && len(failedIPs) > 0 {
		e.logger.Printf("  %d IPs failed, trying fallback (ipwho.is)...\n", len(failedIPs))
		for _, ip := range failedIPs {
			resp, err := e.fallbackLookup(ip)
			if err != nil {
				e.logger.Printf("    Fallback failed for %s: %v\n", ip, err)
				continue
			}
			apiResults = append(apiResults, *resp)
			result.FallbackUsed++
		}
	}

	// Step 5: Store results in database
	// NOTE: ip_geolocation table has no UNIQUE constraint on ip_address (dropped for bulk range inserts).
	// So we use direct INSERT with a pre-check to avoid duplicates.
	e.logger.Println("Storing results in ip_geolocation table...")
	ctx := context.Background()
	for _, apiResp := range apiResults {
		if apiResp.Status != "success" {
			result.Failed++
			continue
		}

		record := e.toGeoRecord(&apiResp)
		if err := e.upsertGeoRecord(ctx, &record); err != nil {
			e.logger.Printf("    DB error for %s: %v\n", apiResp.Query, err)
			result.DBErrors++
		} else {
			result.Success++
		}
	}

	// Summary
	duration := time.Since(startTime)
	e.logger.Println("===========================================")
	e.logger.Println("Enrichment Complete")
	e.logger.Printf("  CSV Total:     %d\n", result.TotalCSV)
	e.logger.Printf("  Skipped:       %d (non-routable)\n", result.Skipped)
	e.logger.Printf("  Looked up:     %d\n", result.Lookups)
	e.logger.Printf("  Success:       %d\n", result.Success)
	e.logger.Printf("  Failed:        %d\n", result.Failed)
	e.logger.Printf("  DB Errors:     %d\n", result.DBErrors)
	e.logger.Printf("  Fallback Used: %d\n", result.FallbackUsed)
	e.logger.Printf("  Batches:       %d\n", result.Batches)
	e.logger.Printf("  Duration:      %s\n", duration)
	e.logger.Println("===========================================")

	return result, nil
}

// =============================================================================
// CSV Reading
// =============================================================================

// readCSV parses the unknown_ips.csv file
func (e *Enricher) readCSV(path string) ([]UnknownIP, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("failed to open file: %w", err)
	}
	defer file.Close()

	reader := csv.NewReader(file)

	// Read header
	header, err := reader.Read()
	if err != nil {
		return nil, fmt.Errorf("failed to read header: %w", err)
	}

	// Validate header
	if len(header) < 1 || !strings.Contains(strings.ToLower(header[0]), "ip") {
		return nil, fmt.Errorf("unexpected CSV header: %v (expected ip_address,count,last_updated)", header)
	}

	var results []UnknownIP
	for {
		record, err := reader.Read()
		if err == io.EOF {
			break
		}
		if err != nil {
			continue // Skip malformed lines
		}

		if len(record) < 1 || record[0] == "" {
			continue
		}

		ip := strings.TrimSpace(record[0])
		count := 0
		lastUpdated := ""

		if len(record) > 1 {
			count, _ = strconv.Atoi(strings.TrimSpace(record[1]))
		}
		if len(record) > 2 {
			lastUpdated = strings.TrimSpace(record[2])
		}

		results = append(results, UnknownIP{
			IPAddress:   ip,
			Count:       count,
			LastUpdated: lastUpdated,
		})
	}

	return results, nil
}

// =============================================================================
// IP Filtering
// =============================================================================

// filterPublicIPs filters out non-routable/special IPs
func (e *Enricher) filterPublicIPs(ips []string) []string {
	var public []string
	seen := make(map[string]bool) // Deduplicate

	for _, ipStr := range ips {
		ipStr = strings.TrimSpace(ipStr)
		if ipStr == "" || seen[ipStr] {
			continue
		}
		seen[ipStr] = true

		if e.isPublicIP(ipStr) {
			public = append(public, ipStr)
		}
	}

	return public
}

// isPublicIP checks if an IP is a publicly routable address
func (e *Enricher) isPublicIP(ipStr string) bool {
	// Parse the IP
	ip := net.ParseIP(ipStr)
	if ip == nil {
		return false // Invalid IP
	}

	// Skip unspecified
	if ip.IsUnspecified() { // 0.0.0.0 or ::
		return false
	}

	// Skip loopback (127.x.x.x or ::1)
	if ip.IsLoopback() {
		return false
	}

	// Skip link-local (169.254.x.x or fe80::)
	if ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() {
		return false
	}

	// Skip multicast (224.0.0.0/4 or ff00::/8)
	if ip.IsMulticast() {
		return false
	}

	// Skip broadcast
	if ipStr == "255.255.255.255" {
		return false
	}

	// Skip private (RFC1918: 10.x, 172.16-31.x, 192.168.x)
	if ip.IsPrivate() {
		return false
	}

	// For IPv4
	if ip4 := ip.To4(); ip4 != nil {
		// Skip 100.64.0.0/10 (CGNAT / shared address space)
		if ip4[0] == 100 && ip4[1] >= 64 && ip4[1] <= 127 {
			return false
		}
		return true
	}

	// For IPv6
	// Skip NAT64 prefix 64:ff9b::/96
	nat64Prefix := net.ParseIP("64:ff9b::")
	if nat64Prefix != nil && len(ip) == 16 && len(nat64Prefix) == 16 {
		match := true
		for i := 0; i < 12; i++ { // First 96 bits (12 bytes)
			if ip[i] != nat64Prefix[i] {
				match = false
				break
			}
		}
		if match {
			return false
		}
	}

	// Only allow global unicast IPv6 (2000::/3)
	if ip.IsGlobalUnicast() {
		// Additional check: skip non-standard/random-looking IPv6
		// Global unicast starts with 2 or 3 in the first nibble
		ipHex := fmt.Sprintf("%x", ip[0])
		if len(ipHex) > 0 && (ipHex[0] == '2' || ipHex[0] == '3') {
			return true
		}
		// Also allow well-known ranges like 2001:, 2400:, 2600:, 2a00:, etc.
		return false
	}

	return false
}

// =============================================================================
// ip-api.com Batch Lookup
// =============================================================================

// batchLookup queries ip-api.com batch endpoint for geolocation data
func (e *Enricher) batchLookup(ips []string) ([]IPAPIResponse, []string) {
	var allResults []IPAPIResponse
	var failedIPs []string

	batchSize := e.config.BatchSize
	totalBatches := (len(ips) + batchSize - 1) / batchSize

	for i := 0; i < len(ips); i += batchSize {
		end := i + batchSize
		if end > len(ips) {
			end = len(ips)
		}
		batch := ips[i:end]
		batchNum := (i / batchSize) + 1

		e.logger.Printf("  Batch %d/%d: %d IPs...\n", batchNum, totalBatches, len(batch))

		results, failed, err := e.callBatchAPI(batch)
		if err != nil {
			e.logger.Printf("    Batch %d failed entirely: %v\n", batchNum, err)
			failedIPs = append(failedIPs, batch...)
			continue
		}

		successCount := 0
		for _, r := range results {
			if r.Status == "success" {
				successCount++
			} else {
				failedIPs = append(failedIPs, r.Query)
			}
		}
		failedIPs = append(failedIPs, failed...)

		allResults = append(allResults, results...)
		e.logger.Printf("    Batch %d: %d OK, %d failed\n", batchNum, successCount, len(batch)-successCount)

		// Rate limit: wait between batches (skip wait on last batch)
		if end < len(ips) {
			e.logger.Printf("    Waiting %s (rate limit)...\n", e.config.RateDelay)
			time.Sleep(e.config.RateDelay)
		}
	}

	return allResults, failedIPs
}

// callBatchAPI makes a single batch request to ip-api.com
func (e *Enricher) callBatchAPI(ips []string) ([]IPAPIResponse, []string, error) {
	// Build request body - array of objects with field selection
	type batchItem struct {
		Query  string `json:"query"`
		Fields string `json:"fields"`
	}

	fields := "status,message,country,countryCode,region,regionName,city,zip,lat,lon,timezone,isp,org,as,asname,mobile,proxy,hosting,query"

	items := make([]batchItem, len(ips))
	for i, ip := range ips {
		items[i] = batchItem{
			Query:  ip,
			Fields: fields,
		}
	}

	body, err := json.Marshal(items)
	if err != nil {
		return nil, ips, fmt.Errorf("failed to marshal request: %w", err)
	}

	// POST to batch endpoint
	resp, err := e.client.Post("http://ip-api.com/batch", "application/json", bytes.NewReader(body))
	if err != nil {
		return nil, ips, fmt.Errorf("batch request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		respBody, _ := io.ReadAll(resp.Body)
		return nil, ips, fmt.Errorf("batch API returned %d: %s", resp.StatusCode, string(respBody))
	}

	// Parse response
	var results []IPAPIResponse
	if err := json.NewDecoder(resp.Body).Decode(&results); err != nil {
		return nil, ips, fmt.Errorf("failed to decode response: %w", err)
	}

	// Separate successful from failed
	var successful []IPAPIResponse
	var failed []string
	for _, r := range results {
		if r.Status == "success" {
			successful = append(successful, r)
		} else {
			failed = append(failed, r.Query)
		}
	}

	return results, nil, nil // Return all results, caller checks status
}

// =============================================================================
// ipwho.is Fallback Lookup
// =============================================================================

// fallbackLookup queries ipwho.is for a single IP (fallback)
func (e *Enricher) fallbackLookup(ip string) (*IPAPIResponse, error) {
	url := fmt.Sprintf("https://ipwho.is/%s", ip)

	resp, err := e.client.Get(url)
	if err != nil {
		return nil, fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("HTTP %d", resp.StatusCode)
	}

	var whois IPWhoIsResponse
	if err := json.NewDecoder(resp.Body).Decode(&whois); err != nil {
		return nil, fmt.Errorf("decode failed: %w", err)
	}

	if !whois.Success {
		return nil, fmt.Errorf("lookup failed for %s", ip)
	}

	// Convert to IPAPIResponse format for uniform processing
	result := &IPAPIResponse{
		Status:      "success",
		Country:     whois.Country,
		CountryCode: whois.CountryCode,
		RegionName:  whois.Region,
		City:        whois.City,
		Lat:         whois.Latitude,
		Lon:         whois.Longitude,
		Timezone:    whois.Timezone.ID,
		ISP:         whois.Connection.ISP,
		Org:         whois.Connection.Org,
		AS:          fmt.Sprintf("AS%d %s", whois.Connection.ASN, whois.Connection.Org),
		ASName:      whois.Connection.Org,
		Query:       ip,
	}

	return result, nil
}

// =============================================================================
// Database Upsert (manual, since ip_geolocation has no UNIQUE on ip_address)
// =============================================================================

// upsertGeoRecord inserts or updates a geo record without relying on ON CONFLICT
func (e *Enricher) upsertGeoRecord(ctx context.Context, record *storage.IPGeoRecord) error {
	// Check if IP already exists
	var exists bool
	err := e.db.QueryRowContext(ctx,
		"SELECT EXISTS(SELECT 1 FROM ip_geolocation WHERE ip_address = $1::inet)",
		record.IPAddress,
	).Scan(&exists)
	if err != nil {
		return fmt.Errorf("existence check failed: %w", err)
	}

	if exists {
		// UPDATE existing record
		query := `
			UPDATE ip_geolocation SET
				country_code = COALESCE($2, country_code),
				country_name = COALESCE($3, country_name),
				city = COALESCE($4, city),
				region = COALESCE($5, region),
				latitude = $6,
				longitude = $7,
				asn = COALESCE($8, asn),
				asn_org = COALESCE($9, asn_org),
				isp = COALESCE($10, isp),
				timezone = COALESCE($11, timezone),
				is_mobile = $12,
				is_hosting = $13,
				sources = $14,
				confidence = $15,
				last_updated = NOW()
			WHERE ip_address = $1::inet
		`
		_, err = e.db.ExecContext(ctx, query,
			record.IPAddress,
			nullIfEmpty(record.CountryCode),
			nullIfEmpty(record.CountryName),
			nullIfEmpty(record.City),
			nullIfEmpty(record.Region),
			record.Latitude,
			record.Longitude,
			nullIfZero(record.ASN),
			nullIfEmpty(record.ASNOrg),
			nullIfEmpty(record.ISP),
			nullIfEmpty(record.Timezone),
			record.IsMobile,
			record.IsHosting,
			fmt.Sprintf(`["%s"]`, "ip-api.com"),
			record.Confidence,
		)
	} else {
		// INSERT new record
		query := `
			INSERT INTO ip_geolocation (
				ip_address, country_code, country_name, city, region,
				latitude, longitude, asn, asn_org, isp, timezone,
				is_mobile, is_hosting, sources, confidence,
				last_updated, created_at
			) VALUES (
				$1::inet, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11,
				$12, $13, $14, $15, NOW(), NOW()
			)
		`
		_, err = e.db.ExecContext(ctx, query,
			record.IPAddress,
			record.CountryCode,
			record.CountryName,
			record.City,
			record.Region,
			record.Latitude,
			record.Longitude,
			record.ASN,
			record.ASNOrg,
			record.ISP,
			record.Timezone,
			record.IsMobile,
			record.IsHosting,
			fmt.Sprintf(`["%s"]`, "ip-api.com"),
			record.Confidence,
		)
	}

	return err
}

// nullIfEmpty returns nil for empty strings (for COALESCE to work)
func nullIfEmpty(s string) interface{} {
	if s == "" {
		return nil
	}
	return s
}

// nullIfZero returns nil for zero values
func nullIfZero(n int) interface{} {
	if n == 0 {
		return nil
	}
	return n
}

// =============================================================================
// Data Conversion
// =============================================================================

// toGeoRecord converts an API response to a storage.IPGeoRecord
func (e *Enricher) toGeoRecord(resp *IPAPIResponse) storage.IPGeoRecord {
	now := time.Now()

	return storage.IPGeoRecord{
		IPAddress:   resp.Query,
		CountryCode: resp.CountryCode,
		CountryName: resp.Country,
		City:        resp.City,
		Region:      resp.RegionName,
		Latitude:    resp.Lat,
		Longitude:   resp.Lon,
		ASN:         parseASN(resp.AS),
		ASNOrg:      resp.ASName,
		ISP:         resp.ISP,
		Timezone:    resp.Timezone,
		IsMobile:    resp.Mobile,
		IsHosting:   resp.Hosting,
		Sources:     []string{"ip-api.com"},
		Confidence:  80, // High confidence from direct API lookup
		LastUpdated: now,
		CreatedAt:   now,
	}
}

// parseASN extracts the ASN number from a string like "AS13335 Cloudflare, Inc."
func parseASN(asStr string) int {
	asStr = strings.TrimSpace(asStr)
	if asStr == "" {
		return 0
	}

	// Remove "AS" prefix
	asStr = strings.TrimPrefix(asStr, "AS")

	// Take only the numeric part (before space)
	parts := strings.Fields(asStr)
	if len(parts) == 0 {
		return 0
	}

	num, err := strconv.Atoi(parts[0])
	if err != nil {
		return 0
	}
	return num
}
