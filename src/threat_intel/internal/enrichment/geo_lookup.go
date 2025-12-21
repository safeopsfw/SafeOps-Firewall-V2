package enrichment

import (
	"container/list"
	"context"
	"fmt"
	"net"
	"sync"
	"time"

	"github.com/safeops/threat-intel/pkg/types"
	"github.com/safeops/threat-intel/pkg/utils"
)

// GeoLookupService manages geolocation enrichment operations
type GeoLookupService struct {
	cache               *GeoLookupCache
	cacheSize           int
	cacheTTL            time.Duration
	fallbackEnabled     bool
	confidenceThreshold float64
	logger              Logger

	// Statistics
	totalLookups       uint64
	cacheHits          uint64
	databaseHits       uint64
	fallbackHits       uint64
	enrichmentFailures uint64
}

// GeoLookupCache implements LRU cache for geolocation results
type GeoLookupCache struct {
	entries map[string]*cacheEntry
	lruList *list.List
	maxSize int
	mutex   sync.RWMutex
	hits    uint64
	misses  uint64
}

type cacheEntry struct {
	result    *GeoResult
	element   *list.Element
	timestamp time.Time
}

// GeoResult contains enriched geographic information
type GeoResult struct {
	IP           string
	Country      string
	CountryName  string
	Region       string
	City         string
	Latitude     float64
	Longitude    float64
	PostalCode   string
	Timezone     string
	ASN          uint32
	Organization string
	Confidence   float64
	Source       string
	LastUpdated  time.Time
}

// Logger interface for structured logging
type Logger interface {
	Debugf(format string, args ...interface{})
	Infof(format string, args ...interface{})
	Warnf(format string, args ...interface{})
	Errorf(format string, args ...interface{})
}

// GeoNetwork represents a network-to-geography mapping
type GeoNetwork struct {
	Network     *net.IPNet
	Country     string
	CountryName string
	Region      string
	City        string
	Latitude    float64
	Longitude   float64
}

// NewGeoLookupService creates a new geolocation enrichment service
func NewGeoLookupService(cacheSize int, cacheTTL time.Duration, logger Logger) (*GeoLookupService, error) {
	if logger == nil {
		return nil, fmt.Errorf("logger cannot be nil")
	}

	if cacheSize <= 0 {
		cacheSize = 10000 // default
	}

	if cacheTTL <= 0 {
		cacheTTL = time.Hour // default 1 hour
	}

	cache := &GeoLookupCache{
		entries: make(map[string]*cacheEntry),
		lruList: list.New(),
		maxSize: cacheSize,
	}

	return &GeoLookupService{
		cache:               cache,
		cacheSize:           cacheSize,
		cacheTTL:            cacheTTL,
		fallbackEnabled:     false,
		confidenceThreshold: 0.5,
		logger:              logger,
	}, nil
}

// EnrichIP enriches a single IP address IOC with geolocation data
func (s *GeoLookupService) EnrichIP(ioc *types.IOC, ctx context.Context) error {
	// Validate IOC type
	if ioc.IOCType != types.IOCTypeIPv4 && ioc.IOCType != types.IOCTypeIPv6 {
		return fmt.Errorf("IOC is not an IP address type")
	}

	s.totalLookups++

	// Check cache first
	if result, found := s.cacheGet(ioc.Value); found {
		s.cacheHits++
		s.populateIOCMetadata(ioc, result)
		s.logger.Debugf("Geo cache hit for %s: %s, %s", ioc.Value, result.City, result.Country)
		return nil
	}

	// Database lookup (simulated - would query geo_intelligence repository)
	result, err := s.lookupInDatabase(ioc.Value, ctx)
	if err != nil {
		s.logger.Warnf("Database lookup failed for %s: %v", ioc.Value, err)
	}

	if result != nil && s.validateGeoResult(result) {
		s.databaseHits++
		s.populateIOCMetadata(ioc, result)
		s.cachePut(ioc.Value, result)
		return nil
	}

	// Fallback lookup if enabled
	if s.fallbackEnabled {
		result, err = s.lookupWithFallback(ioc.Value, ctx)
		if err == nil && result != nil && s.validateGeoResult(result) {
			s.fallbackHits++
			s.populateIOCMetadata(ioc, result)
			s.cachePut(ioc.Value, result)
			return nil
		}
	}

	s.enrichmentFailures++
	return fmt.Errorf("no geolocation data found for %s", ioc.Value)
}

// EnrichIPBatch enriches multiple IP addresses in batch
func (s *GeoLookupService) EnrichIPBatch(iocs []*types.IOC, ctx context.Context, batchSize int) (int, error) {
	if batchSize <= 0 {
		batchSize = 100
	}

	// Filter to IP-type IOCs only
	ipIOCs := make([]*types.IOC, 0)
	for _, ioc := range iocs {
		if ioc.IOCType == types.IOCTypeIPv4 || ioc.IOCType == types.IOCTypeIPv6 {
			ipIOCs = append(ipIOCs, ioc)
		}
	}

	successCount := 0

	// Process in batches
	for i := 0; i < len(ipIOCs); i += batchSize {
		end := i + batchSize
		if end > len(ipIOCs) {
			end = len(ipIOCs)
		}

		batch := ipIOCs[i:end]

		// Enrich each in batch
		for _, ioc := range batch {
			if err := s.EnrichIP(ioc, ctx); err == nil {
				successCount++
			}
		}
	}

	s.logger.Infof("Batch enrichment: %d/%d IPs enriched", successCount, len(ipIOCs))
	return successCount, nil
}

// lookupInDatabase queries geolocation database
func (s *GeoLookupService) lookupInDatabase(ipStr string, ctx context.Context) (*GeoResult, error) {
	ip := net.ParseIP(ipStr)
	if ip == nil {
		return nil, fmt.Errorf("invalid IP address: %s", ipStr)
	}

	// Simulated database lookup - in production would query geo_intelligence table
	// This is a placeholder that returns nil (not found)
	// Real implementation would use PostgreSQL INET operators for CIDR matching

	// Example query would be:
	// SELECT * FROM geo_intelligence WHERE network >>= $1 ORDER BY masklen(network) DESC LIMIT 1

	return nil, nil
}

// lookupWithFallback attempts external API lookup
func (s *GeoLookupService) lookupWithFallback(ipStr string, ctx context.Context) (*GeoResult, error) {
	// Simulated fallback API lookup
	// Real implementation would call external geolocation API

	// Skip private IPs
	if !utils.IsPublicIP(ipStr) {
		return nil, fmt.Errorf("private IP address")
	}

	// Placeholder - would make HTTP request to API
	return nil, fmt.Errorf("fallback not implemented")
}

// cacheGet retrieves result from cache
func (s *GeoLookupService) cacheGet(ip string) (*GeoResult, bool) {
	s.cache.mutex.RLock()
	defer s.cache.mutex.RUnlock()

	entry, exists := s.cache.entries[ip]
	if !exists {
		s.cache.misses++
		return nil, false
	}

	// Check TTL
	if time.Since(entry.timestamp) > s.cacheTTL {
		s.cache.misses++
		return nil, false
	}

	// Update LRU position
	s.cache.lruList.MoveToFront(entry.element)
	s.cache.hits++

	return entry.result, true
}

// cachePut stores result in cache
func (s *GeoLookupService) cachePut(ip string, result *GeoResult) {
	s.cache.mutex.Lock()
	defer s.cache.mutex.Unlock()

	// Check if entry already exists
	if entry, exists := s.cache.entries[ip]; exists {
		// Update existing entry
		entry.result = result
		entry.timestamp = time.Now()
		s.cache.lruList.MoveToFront(entry.element)
		return
	}

	// Evict if at capacity
	if s.cache.lruList.Len() >= s.cache.maxSize {
		s.evictLRU()
	}

	// Add new entry
	element := s.cache.lruList.PushFront(ip)
	s.cache.entries[ip] = &cacheEntry{
		result:    result,
		element:   element,
		timestamp: time.Now(),
	}
}

// evictLRU removes least recently used entry
func (s *GeoLookupService) evictLRU() {
	if s.cache.lruList.Len() == 0 {
		return
	}

	// Get back element (least recently used)
	element := s.cache.lruList.Back()
	if element == nil {
		return
	}

	// Remove from list and map
	ip := element.Value.(string)
	s.cache.lruList.Remove(element)
	delete(s.cache.entries, ip)
}

// populateIOCMetadata applies geolocation results to IOC
func (s *GeoLookupService) populateIOCMetadata(ioc *types.IOC, result *GeoResult) {
	if ioc.Metadata == nil {
		ioc.Metadata = make(map[string]interface{})
	}

	// Create geographic metadata structure
	geoData := map[string]interface{}{
		"country":      result.Country,
		"country_name": result.CountryName,
		"region":       result.Region,
		"city":         result.City,
		"latitude":     result.Latitude,
		"longitude":    result.Longitude,
		"postal_code":  result.PostalCode,
		"timezone":     result.Timezone,
		"asn":          result.ASN,
		"organization": result.Organization,
		"confidence":   result.Confidence,
		"source":       result.Source,
		"last_updated": result.LastUpdated,
	}

	ioc.Metadata["geographic"] = geoData
	ioc.Metadata["geo_enriched"] = true
	ioc.Metadata["geo_enriched_at"] = time.Now()
}

// validateGeoResult validates result quality
func (s *GeoLookupService) validateGeoResult(result *GeoResult) bool {
	if result == nil {
		return false
	}

	// Check confidence threshold
	if result.Confidence < s.confidenceThreshold {
		return false
	}

	// Validate country code (2-letter ISO)
	if len(result.Country) != 2 {
		return false
	}

	// Validate coordinates
	if result.Latitude < -90 || result.Latitude > 90 {
		return false
	}
	if result.Longitude < -180 || result.Longitude > 180 {
		return false
	}

	// Check data staleness (1 year)
	if time.Since(result.LastUpdated) > 365*24*time.Hour {
		return false
	}

	return true
}

// calculateConfidence computes confidence score
func (s *GeoLookupService) calculateConfidence(result *GeoResult) float64 {
	baseScore := 0.5

	// Adjust based on source
	switch result.Source {
	case "database":
		baseScore = 0.9
	case "maxmind":
		baseScore = 0.85
	case "api":
		baseScore = 0.6
	}

	// Increase for field completeness
	if result.City != "" {
		baseScore += 0.05
	}
	if result.Region != "" {
		baseScore += 0.03
	}
	if result.Timezone != "" {
		baseScore += 0.02
	}

	// Decrease for stale data
	age := time.Since(result.LastUpdated)
	if age > 180*24*time.Hour { // 6 months
		baseScore -= 0.1
	}

	// Cap at 1.0
	if baseScore > 1.0 {
		baseScore = 1.0
	}
	if baseScore < 0.1 {
		baseScore = 0.1
	}

	return baseScore
}

// getCIDRMatch finds most specific network containing IP
func (s *GeoLookupService) getCIDRMatch(ip net.IP, networks []GeoNetwork) (*GeoNetwork, bool) {
	var bestMatch *GeoNetwork
	var longestPrefix int

	for i := range networks {
		network := &networks[i]
		if network.Network.Contains(ip) {
			ones, _ := network.Network.Mask.Size()
			if ones > longestPrefix {
				longestPrefix = ones
				bestMatch = network
			}
		}
	}

	if bestMatch != nil {
		return bestMatch, true
	}

	return nil, false
}

// GetStatistics returns cache performance statistics
func (s *GeoLookupService) GetStatistics() map[string]interface{} {
	s.cache.mutex.RLock()
	defer s.cache.mutex.RUnlock()

	hitRate := 0.0
	totalRequests := s.cache.hits + s.cache.misses
	if totalRequests > 0 {
		hitRate = float64(s.cache.hits) / float64(totalRequests) * 100
	}

	return map[string]interface{}{
		"total_lookups":       s.totalLookups,
		"cache_hits":          s.cacheHits,
		"cache_hit_rate":      hitRate,
		"database_hits":       s.databaseHits,
		"fallback_hits":       s.fallbackHits,
		"enrichment_failures": s.enrichmentFailures,
		"cache_size":          s.cache.lruList.Len(),
		"cache_max_size":      s.cache.maxSize,
	}
}

// SetFallbackEnabled enables or disables API fallback
func (s *GeoLookupService) SetFallbackEnabled(enabled bool) {
	s.fallbackEnabled = enabled
}

// SetConfidenceThreshold sets minimum confidence score
func (s *GeoLookupService) SetConfidenceThreshold(threshold float64) {
	if threshold >= 0 && threshold <= 1.0 {
		s.confidenceThreshold = threshold
	}
}

// ClearCache empties the cache
func (s *GeoLookupService) ClearCache() {
	s.cache.mutex.Lock()
	defer s.cache.mutex.Unlock()

	s.cache.entries = make(map[string]*cacheEntry)
	s.cache.lruList = list.New()
	s.logger.Infof("Geo lookup cache cleared")
}

// Close performs cleanup
func (s *GeoLookupService) Close() error {
	stats := s.GetStatistics()
	s.logger.Infof("Geo lookup service closed. Stats: %v", stats)
	return nil
}
