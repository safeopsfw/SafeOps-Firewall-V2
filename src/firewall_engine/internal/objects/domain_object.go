// Package objects provides reusable network objects for firewall rules.
package objects

import (
	"fmt"
	"strings"
	"sync"

	"firewall_engine/pkg/models"
)

// ============================================================================
// Domain Object Manager - Domain pattern management
// ============================================================================

// DomainObjectManager manages a collection of domain objects.
// It provides efficient domain matching with wildcard support.
type DomainObjectManager struct {
	mu      sync.RWMutex
	objects map[string]*models.DomainObject

	// Aggregated lookup for fast matching across all objects
	exactDomains     map[string][]string // domain -> object names that contain it
	wildcardSuffixes map[string][]string // suffix -> object names
}

// NewDomainObjectManager creates a new domain object manager.
func NewDomainObjectManager() *DomainObjectManager {
	return &DomainObjectManager{
		objects:          make(map[string]*models.DomainObject),
		exactDomains:     make(map[string][]string),
		wildcardSuffixes: make(map[string][]string),
	}
}

// Register adds a new domain object.
func (m *DomainObjectManager) Register(obj *models.DomainObject) error {
	if obj == nil {
		return fmt.Errorf("domain object is nil")
	}
	if obj.Name == "" {
		return fmt.Errorf("domain object name is required")
	}

	// Initialize the object (parse patterns)
	if err := obj.Initialize(); err != nil {
		return fmt.Errorf("failed to initialize domain object %q: %w", obj.Name, err)
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	m.objects[obj.Name] = obj

	// Build aggregated lookups
	for domain := range obj.ExactDomains {
		m.exactDomains[domain] = append(m.exactDomains[domain], obj.Name)
	}
	for _, suffix := range obj.WildcardSuffixes {
		m.wildcardSuffixes[suffix] = append(m.wildcardSuffixes[suffix], obj.Name)
	}

	return nil
}

// Unregister removes a domain object by name.
func (m *DomainObjectManager) Unregister(name string) bool {
	m.mu.Lock()
	defer m.mu.Unlock()

	if _, exists := m.objects[name]; !exists {
		return false
	}

	delete(m.objects, name)
	m.rebuildLookups()

	return true
}

// rebuildLookups rebuilds the aggregated domain lookups.
// Must be called with lock held.
func (m *DomainObjectManager) rebuildLookups() {
	m.exactDomains = make(map[string][]string)
	m.wildcardSuffixes = make(map[string][]string)

	for name, obj := range m.objects {
		for domain := range obj.ExactDomains {
			m.exactDomains[domain] = append(m.exactDomains[domain], name)
		}
		for _, suffix := range obj.WildcardSuffixes {
			m.wildcardSuffixes[suffix] = append(m.wildcardSuffixes[suffix], name)
		}
	}
}

// Get returns a domain object by name.
func (m *DomainObjectManager) Get(name string) (*models.DomainObject, bool) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	obj, ok := m.objects[name]
	return obj, ok
}

// Exists checks if a domain object exists.
func (m *DomainObjectManager) Exists(name string) bool {
	m.mu.RLock()
	defer m.mu.RUnlock()

	_, ok := m.objects[name]
	return ok
}

// Contains checks if a domain matches patterns in the named object.
func (m *DomainObjectManager) Contains(objectName string, domain string) bool {
	m.mu.RLock()
	defer m.mu.RUnlock()

	obj, ok := m.objects[objectName]
	if !ok {
		return false
	}

	return obj.Contains(domain)
}

// FindMatchingObjects returns all object names that contain the given domain.
func (m *DomainObjectManager) FindMatchingObjects(domain string) []string {
	m.mu.RLock()
	defer m.mu.RUnlock()

	domain = strings.ToLower(strings.TrimSpace(domain))
	if domain == "" {
		return nil
	}

	seen := make(map[string]bool)
	var result []string

	// Check exact matches
	if names, ok := m.exactDomains[domain]; ok {
		for _, name := range names {
			if !seen[name] {
				seen[name] = true
				result = append(result, name)
			}
		}
	}

	// Check wildcard suffixes
	for suffix, names := range m.wildcardSuffixes {
		if strings.HasSuffix(domain, suffix) {
			for _, name := range names {
				if !seen[name] {
					seen[name] = true
					result = append(result, name)
				}
			}
		}
	}

	return result
}

// All returns all registered domain objects.
func (m *DomainObjectManager) All() []*models.DomainObject {
	m.mu.RLock()
	defer m.mu.RUnlock()

	result := make([]*models.DomainObject, 0, len(m.objects))
	for _, obj := range m.objects {
		result = append(result, obj)
	}
	return result
}

// Names returns all registered object names.
func (m *DomainObjectManager) Names() []string {
	m.mu.RLock()
	defer m.mu.RUnlock()

	result := make([]string, 0, len(m.objects))
	for name := range m.objects {
		result = append(result, name)
	}
	return result
}

// Count returns the number of registered objects.
func (m *DomainObjectManager) Count() int {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return len(m.objects)
}

// Clear removes all domain objects.
func (m *DomainObjectManager) Clear() {
	m.mu.Lock()
	defer m.mu.Unlock()

	m.objects = make(map[string]*models.DomainObject)
	m.exactDomains = make(map[string][]string)
	m.wildcardSuffixes = make(map[string][]string)
}

// ============================================================================
// Matcher Functions for Rule Evaluation
// ============================================================================

// MatchDomain checks if a domain matches a domain specification.
// The spec can be:
// - Empty - matches any domain
// - Object name - looks up and matches against the object
// - Direct pattern - matches against the pattern (*.facebook.com)
func (m *DomainObjectManager) MatchDomain(objectName string, directPattern string, domain string) bool {
	if domain == "" {
		// No domain extracted from packet
		// If rule requires domain match, this doesn't match
		return objectName == "" && directPattern == ""
	}

	domain = strings.ToLower(strings.TrimSpace(domain))

	// Check object reference
	if objectName != "" {
		return m.Contains(objectName, domain)
	}

	// Check direct pattern
	if directPattern != "" {
		return matchDomainPattern(directPattern, domain)
	}

	// No domain filter specified, matches any
	return true
}

// matchDomainPattern matches a domain against a single pattern.
func matchDomainPattern(pattern, domain string) bool {
	pattern = strings.ToLower(strings.TrimSpace(pattern))
	domain = strings.ToLower(strings.TrimSpace(domain))

	if pattern == "" || domain == "" {
		return false
	}

	// Exact match
	if pattern == domain {
		return true
	}

	// Wildcard prefix: *.facebook.com
	if strings.HasPrefix(pattern, "*.") {
		suffix := strings.TrimPrefix(pattern, "*")
		// Check if domain ends with suffix or equals base domain
		baseDomain := strings.TrimPrefix(suffix, ".")
		return strings.HasSuffix(domain, suffix) || domain == baseDomain
	}

	// Wildcard suffix: facebook.*
	if strings.HasSuffix(pattern, ".*") {
		prefix := strings.TrimSuffix(pattern, "*")
		return strings.HasPrefix(domain, prefix)
	}

	return false
}

// ============================================================================
// Statistics
// ============================================================================

// DomainStats contains statistics about domain objects.
type DomainStats struct {
	ObjectCount      int `json:"object_count"`
	ExactPatterns    int `json:"exact_patterns"`
	WildcardPatterns int `json:"wildcard_patterns"`
	TotalPatterns    int `json:"total_patterns"`
}

// GetStats returns current statistics.
func (m *DomainObjectManager) GetStats() DomainStats {
	m.mu.RLock()
	defer m.mu.RUnlock()

	stats := DomainStats{
		ObjectCount: len(m.objects),
	}

	for _, obj := range m.objects {
		stats.ExactPatterns += len(obj.ExactDomains)
		stats.WildcardPatterns += len(obj.WildcardSuffixes) + len(obj.WildcardPrefixes)
	}

	stats.TotalPatterns = stats.ExactPatterns + stats.WildcardPatterns

	return stats
}
