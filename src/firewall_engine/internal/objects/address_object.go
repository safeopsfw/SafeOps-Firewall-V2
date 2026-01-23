// Package objects provides reusable network objects for firewall rules.
// Objects are referenced by name in rules and resolved during rule evaluation.
//
// Supported object types:
// - Address: IP addresses, CIDR networks, IP ranges
// - Port: Port numbers, port ranges
// - Domain: Domain patterns with wildcard support
// - Geo: Country codes and ASN numbers (via PostgreSQL GeoIP)
package objects

import (
	"fmt"
	"net"
	"strings"
	"sync"

	"firewall_engine/pkg/models"
)

// ============================================================================
// Address Object Manager - IP/CIDR/Range management
// ============================================================================

// AddressObjectManager manages a collection of address objects.
// It provides efficient IP matching operations with caching.
type AddressObjectManager struct {
	mu      sync.RWMutex
	objects map[string]*models.AddressObject

	// Precomputed lookup structures for performance
	// These are rebuilt when objects change
	cidrLookup map[string][]*net.IPNet // object name -> CIDRs
	ipLookup   map[string]bool         // individual IP -> exists (for exact match)
}

// NewAddressObjectManager creates a new address object manager.
func NewAddressObjectManager() *AddressObjectManager {
	return &AddressObjectManager{
		objects:    make(map[string]*models.AddressObject),
		cidrLookup: make(map[string][]*net.IPNet),
		ipLookup:   make(map[string]bool),
	}
}

// Register adds a new address object.
func (m *AddressObjectManager) Register(obj *models.AddressObject) error {
	if obj == nil {
		return fmt.Errorf("address object is nil")
	}
	if obj.Name == "" {
		return fmt.Errorf("address object name is required")
	}

	// Initialize the object (parse addresses)
	if err := obj.Initialize(); err != nil {
		return fmt.Errorf("failed to initialize address object %q: %w", obj.Name, err)
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	m.objects[obj.Name] = obj
	m.cidrLookup[obj.Name] = obj.ParsedCIDRs

	// Add individual IPs to lookup
	for _, ip := range obj.ParsedIPs {
		m.ipLookup[ip.String()] = true
	}

	return nil
}

// Unregister removes an address object by name.
func (m *AddressObjectManager) Unregister(name string) bool {
	m.mu.Lock()
	defer m.mu.Unlock()

	if _, exists := m.objects[name]; !exists {
		return false
	}

	delete(m.objects, name)
	delete(m.cidrLookup, name)

	// Rebuild IP lookup (simpler than tracking which IPs belong to which object)
	m.rebuildIPLookup()

	return true
}

// rebuildIPLookup rebuilds the IP exact-match lookup.
// Must be called with lock held.
func (m *AddressObjectManager) rebuildIPLookup() {
	m.ipLookup = make(map[string]bool)
	for _, obj := range m.objects {
		for _, ip := range obj.ParsedIPs {
			m.ipLookup[ip.String()] = true
		}
	}
}

// Get returns an address object by name.
func (m *AddressObjectManager) Get(name string) (*models.AddressObject, bool) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	obj, ok := m.objects[name]
	return obj, ok
}

// Exists checks if an address object exists.
func (m *AddressObjectManager) Exists(name string) bool {
	m.mu.RLock()
	defer m.mu.RUnlock()

	_, ok := m.objects[name]
	return ok
}

// Contains checks if an IP is contained in the named object.
func (m *AddressObjectManager) Contains(objectName string, ip string) bool {
	m.mu.RLock()
	defer m.mu.RUnlock()

	obj, ok := m.objects[objectName]
	if !ok {
		return false
	}

	return obj.Contains(ip)
}

// ContainsIP checks if a net.IP is contained in the named object.
func (m *AddressObjectManager) ContainsIP(objectName string, ip net.IP) bool {
	m.mu.RLock()
	defer m.mu.RUnlock()

	obj, ok := m.objects[objectName]
	if !ok {
		return false
	}

	return obj.ContainsIP(ip)
}

// MatchesAny checks if an IP matches any of the named objects.
func (m *AddressObjectManager) MatchesAny(objectNames []string, ip net.IP) (string, bool) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	for _, name := range objectNames {
		obj, ok := m.objects[name]
		if ok && obj.ContainsIP(ip) {
			return name, true
		}
	}

	return "", false
}

// All returns all registered address objects.
func (m *AddressObjectManager) All() []*models.AddressObject {
	m.mu.RLock()
	defer m.mu.RUnlock()

	result := make([]*models.AddressObject, 0, len(m.objects))
	for _, obj := range m.objects {
		result = append(result, obj)
	}
	return result
}

// Names returns all registered object names.
func (m *AddressObjectManager) Names() []string {
	m.mu.RLock()
	defer m.mu.RUnlock()

	result := make([]string, 0, len(m.objects))
	for name := range m.objects {
		result = append(result, name)
	}
	return result
}

// Count returns the number of registered objects.
func (m *AddressObjectManager) Count() int {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return len(m.objects)
}

// Clear removes all address objects.
func (m *AddressObjectManager) Clear() {
	m.mu.Lock()
	defer m.mu.Unlock()

	m.objects = make(map[string]*models.AddressObject)
	m.cidrLookup = make(map[string][]*net.IPNet)
	m.ipLookup = make(map[string]bool)
}

// ============================================================================
// Matcher Functions for Rule Evaluation
// ============================================================================

// MatchAddress checks if an IP matches an address specification.
// The spec can be:
// - "ANY" - matches any address
// - Object name - looks up and matches against the object
// - "!ObjectName" - negated object match
// - Direct CIDR - parses and matches
// - Direct IP - exact match
func (m *AddressObjectManager) MatchAddress(spec string, ip net.IP) bool {
	if spec == "" || strings.ToUpper(spec) == "ANY" || spec == "0.0.0.0/0" {
		return true
	}

	// Handle negation
	negated := false
	if strings.HasPrefix(spec, "!") {
		negated = true
		spec = strings.TrimPrefix(spec, "!")
	}

	var matches bool

	// Try as object reference first
	if m.Exists(spec) {
		matches = m.ContainsIP(spec, ip)
	} else if strings.Contains(spec, "/") {
		// Try as CIDR
		_, network, err := net.ParseCIDR(spec)
		if err == nil {
			matches = network.Contains(ip)
		}
	} else {
		// Try as single IP
		specIP := net.ParseIP(spec)
		if specIP != nil {
			matches = specIP.Equal(ip)
		}
	}

	if negated {
		return !matches
	}
	return matches
}

// MatchAddressString is a convenience wrapper for MatchAddress with string IP.
func (m *AddressObjectManager) MatchAddressString(spec string, ipStr string) bool {
	ip := net.ParseIP(ipStr)
	if ip == nil {
		return false
	}
	return m.MatchAddress(spec, ip)
}

// ============================================================================
// Statistics
// ============================================================================

// Stats returns statistics about the address object manager.
type AddressStats struct {
	ObjectCount  int `json:"object_count"`
	TotalCIDRs   int `json:"total_cidrs"`
	TotalIPs     int `json:"total_ips"`
	TotalRanges  int `json:"total_ranges"`
	TotalEntries int `json:"total_entries"`
}

// GetStats returns current statistics.
func (m *AddressObjectManager) GetStats() AddressStats {
	m.mu.RLock()
	defer m.mu.RUnlock()

	stats := AddressStats{
		ObjectCount: len(m.objects),
	}

	for _, obj := range m.objects {
		stats.TotalCIDRs += len(obj.ParsedCIDRs)
		stats.TotalIPs += len(obj.ParsedIPs)
		stats.TotalRanges += len(obj.IPRanges)
	}

	stats.TotalEntries = stats.TotalCIDRs + stats.TotalIPs + stats.TotalRanges

	return stats
}
