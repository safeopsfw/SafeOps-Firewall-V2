// Package objects provides reusable network objects for firewall rules.
package objects

import (
	"fmt"
	"net"
	"sync"
	"time"

	"firewall_engine/pkg/models"
)

// ============================================================================
// Geo Object Manager - GeoIP/ASN management
// ============================================================================

// GeoResolver is the interface for resolving GeoIP data.
// This is typically implemented by a PostgreSQL-backed service.
type GeoResolver interface {
	// ResolveCountry returns CIDRs for a country code (e.g., "RU", "CN").
	ResolveCountry(countryCode string) ([]*net.IPNet, error)

	// ResolveASN returns CIDRs for an ASN (e.g., "AS15169").
	ResolveASN(asn string) ([]*net.IPNet, error)

	// LookupIP returns the country code and ASN for an IP.
	LookupIP(ip net.IP) (countryCode string, asn string, err error)
}

// GeoObjectManager manages GeoIP and ASN-based address objects.
// It caches resolved CIDRs to avoid repeated database lookups.
type GeoObjectManager struct {
	mu       sync.RWMutex
	objects  map[string]*models.GeoObject
	resolver GeoResolver

	// Cache configuration
	defaultCacheTTL time.Duration

	// Statistics
	lookupCount  uint64
	cacheHits    uint64
	cacheMisses  uint64
	resolveCount uint64
}

// GeoManagerConfig contains configuration for the GeoObjectManager.
type GeoManagerConfig struct {
	// Resolver is the GeoIP data source.
	Resolver GeoResolver

	// DefaultCacheTTL is how long to cache resolved CIDRs.
	// Default: 1 hour
	DefaultCacheTTL time.Duration
}

// NewGeoObjectManager creates a new geo object manager.
func NewGeoObjectManager(config *GeoManagerConfig) *GeoObjectManager {
	m := &GeoObjectManager{
		objects:         make(map[string]*models.GeoObject),
		defaultCacheTTL: time.Hour, // Default 1 hour
	}

	if config != nil {
		m.resolver = config.Resolver
		if config.DefaultCacheTTL > 0 {
			m.defaultCacheTTL = config.DefaultCacheTTL
		}
	}

	return m
}

// SetResolver sets the GeoIP resolver.
func (m *GeoObjectManager) SetResolver(resolver GeoResolver) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.resolver = resolver
}

// Register adds a new geo object.
func (m *GeoObjectManager) Register(obj *models.GeoObject) error {
	if obj == nil {
		return fmt.Errorf("geo object is nil")
	}
	if obj.Name == "" {
		return fmt.Errorf("geo object name is required")
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	// Set default cache TTL if not specified
	if obj.CacheTTL <= 0 {
		obj.CacheTTL = int(m.defaultCacheTTL.Seconds())
	}

	m.objects[obj.Name] = obj
	return nil
}

// Unregister removes a geo object by name.
func (m *GeoObjectManager) Unregister(name string) bool {
	m.mu.Lock()
	defer m.mu.Unlock()

	if _, exists := m.objects[name]; !exists {
		return false
	}

	delete(m.objects, name)
	return true
}

// Get returns a geo object by name.
func (m *GeoObjectManager) Get(name string) (*models.GeoObject, bool) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	obj, ok := m.objects[name]
	return obj, ok
}

// Exists checks if a geo object exists.
func (m *GeoObjectManager) Exists(name string) bool {
	m.mu.RLock()
	defer m.mu.RUnlock()

	_, ok := m.objects[name]
	return ok
}

// Contains checks if an IP is contained in the named geo object.
// This will resolve CIDRs from the database if needed.
func (m *GeoObjectManager) Contains(objectName string, ip net.IP) (bool, error) {
	m.mu.RLock()
	obj, ok := m.objects[objectName]
	m.mu.RUnlock()

	if !ok {
		return false, fmt.Errorf("geo object not found: %s", objectName)
	}

	m.lookupCount++

	// Check if we need to refresh the cache
	if obj.NeedsRefresh() {
		if err := m.refreshObject(obj); err != nil {
			// If refresh fails, use stale cache if available
			if len(obj.CachedCIDRs) == 0 {
				return false, fmt.Errorf("failed to resolve geo object %s: %w", objectName, err)
			}
			// Log warning but continue with stale data
		}
	} else {
		m.cacheHits++
	}

	return obj.Contains(ip), nil
}

// refreshObject resolves CIDRs for a geo object from the database.
func (m *GeoObjectManager) refreshObject(obj *models.GeoObject) error {
	if m.resolver == nil {
		return fmt.Errorf("no geo resolver configured")
	}

	m.cacheMisses++
	m.resolveCount++

	var allCIDRs []*net.IPNet

	for _, value := range obj.Values {
		var cidrs []*net.IPNet
		var err error

		switch obj.Type {
		case models.ObjectTypeGeo:
			cidrs, err = m.resolver.ResolveCountry(value)
		case models.ObjectTypeASN:
			cidrs, err = m.resolver.ResolveASN(value)
		default:
			continue
		}

		if err != nil {
			return fmt.Errorf("failed to resolve %s: %w", value, err)
		}

		allCIDRs = append(allCIDRs, cidrs...)
	}

	obj.SetCachedCIDRs(allCIDRs)
	return nil
}

// ContainsString checks if an IP string is contained in the named geo object.
func (m *GeoObjectManager) ContainsString(objectName string, ipStr string) (bool, error) {
	ip := net.ParseIP(ipStr)
	if ip == nil {
		return false, fmt.Errorf("invalid IP address: %s", ipStr)
	}
	return m.Contains(objectName, ip)
}

// LookupCountry returns the country code for an IP.
func (m *GeoObjectManager) LookupCountry(ip net.IP) (string, error) {
	if m.resolver == nil {
		return "", fmt.Errorf("no geo resolver configured")
	}

	country, _, err := m.resolver.LookupIP(ip)
	return country, err
}

// LookupASN returns the ASN for an IP.
func (m *GeoObjectManager) LookupASN(ip net.IP) (string, error) {
	if m.resolver == nil {
		return "", fmt.Errorf("no geo resolver configured")
	}

	_, asn, err := m.resolver.LookupIP(ip)
	return asn, err
}

// All returns all registered geo objects.
func (m *GeoObjectManager) All() []*models.GeoObject {
	m.mu.RLock()
	defer m.mu.RUnlock()

	result := make([]*models.GeoObject, 0, len(m.objects))
	for _, obj := range m.objects {
		result = append(result, obj)
	}
	return result
}

// Names returns all registered object names.
func (m *GeoObjectManager) Names() []string {
	m.mu.RLock()
	defer m.mu.RUnlock()

	result := make([]string, 0, len(m.objects))
	for name := range m.objects {
		result = append(result, name)
	}
	return result
}

// Count returns the number of registered objects.
func (m *GeoObjectManager) Count() int {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return len(m.objects)
}

// Clear removes all geo objects.
func (m *GeoObjectManager) Clear() {
	m.mu.Lock()
	defer m.mu.Unlock()

	m.objects = make(map[string]*models.GeoObject)
}

// RefreshAll refreshes all cached geo objects.
func (m *GeoObjectManager) RefreshAll() error {
	m.mu.Lock()
	defer m.mu.Unlock()

	for _, obj := range m.objects {
		if err := m.refreshObject(obj); err != nil {
			return err
		}
	}
	return nil
}

// ============================================================================
// Statistics
// ============================================================================

// GeoStats contains statistics about geo objects.
type GeoStats struct {
	ObjectCount  int     `json:"object_count"`
	TotalValues  int     `json:"total_values"`
	CachedCIDRs  int     `json:"cached_cidrs"`
	LookupCount  uint64  `json:"lookup_count"`
	CacheHits    uint64  `json:"cache_hits"`
	CacheMisses  uint64  `json:"cache_misses"`
	ResolveCount uint64  `json:"resolve_count"`
	CacheHitRate float64 `json:"cache_hit_rate"`
}

// GetStats returns current statistics.
func (m *GeoObjectManager) GetStats() GeoStats {
	m.mu.RLock()
	defer m.mu.RUnlock()

	stats := GeoStats{
		ObjectCount:  len(m.objects),
		LookupCount:  m.lookupCount,
		CacheHits:    m.cacheHits,
		CacheMisses:  m.cacheMisses,
		ResolveCount: m.resolveCount,
	}

	for _, obj := range m.objects {
		stats.TotalValues += len(obj.Values)
		stats.CachedCIDRs += len(obj.CachedCIDRs)
	}

	if stats.LookupCount > 0 {
		stats.CacheHitRate = float64(stats.CacheHits) / float64(stats.LookupCount)
	}

	return stats
}

// ============================================================================
// Null Geo Resolver (for testing/offline mode)
// ============================================================================

// NullGeoResolver is a no-op resolver that returns empty results.
// Used when GeoIP database is not available.
type NullGeoResolver struct{}

func (r *NullGeoResolver) ResolveCountry(string) ([]*net.IPNet, error) {
	return nil, nil
}

func (r *NullGeoResolver) ResolveASN(string) ([]*net.IPNet, error) {
	return nil, nil
}

func (r *NullGeoResolver) LookupIP(net.IP) (string, string, error) {
	return "", "", nil
}
