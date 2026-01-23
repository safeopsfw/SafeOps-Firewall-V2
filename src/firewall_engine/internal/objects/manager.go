// Package objects provides reusable network objects for firewall rules.
package objects

import (
	"encoding/json"
	"fmt"
	"sync"
	"time"

	"firewall_engine/internal/config"
	"firewall_engine/pkg/models"
)

// ============================================================================
// Object Manager - Unified CRUD operations for all objects
// ============================================================================

// Manager provides unified management of all object types.
// It coordinates the individual object managers and provides
// high-level operations like loading from configuration.
type Manager struct {
	mu sync.RWMutex

	addresses *AddressObjectManager
	ports     *PortObjectManager
	domains   *DomainObjectManager
	geo       *GeoObjectManager

	// Unified resolver for rule matching
	resolver *Resolver

	// Metadata
	loadedAt time.Time
	version  string
}

// NewManager creates a new unified object manager.
func NewManager() *Manager {
	m := &Manager{
		addresses: NewAddressObjectManager(),
		ports:     NewPortObjectManager(),
		domains:   NewDomainObjectManager(),
		geo:       NewGeoObjectManager(nil),
		loadedAt:  time.Now(),
	}

	m.resolver = NewResolver(m.addresses, m.ports, m.domains, m.geo)

	return m
}

// ============================================================================
// Loading from Configuration
// ============================================================================

// LoadFromConfig loads all objects from a configuration.
func (m *Manager) LoadFromConfig(cfg *config.Config) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	// Clear existing objects
	m.addresses.Clear()
	m.ports.Clear()
	m.domains.Clear()
	m.geo.Clear()

	// Load address objects
	for _, aoCfg := range cfg.AddressObjects {
		obj := aoCfg.ToModel()
		if err := m.addresses.Register(obj); err != nil {
			return fmt.Errorf("failed to load address object %q: %w", aoCfg.ObjectName, err)
		}
	}

	// Load port objects
	for _, poCfg := range cfg.PortObjects {
		obj := poCfg.ToModel()
		if err := m.ports.Register(obj); err != nil {
			return fmt.Errorf("failed to load port object %q: %w", poCfg.ObjectName, err)
		}
	}

	// Load domain objects
	for _, doCfg := range cfg.DomainObjects {
		obj := doCfg.ToModel()
		if err := m.domains.Register(obj); err != nil {
			return fmt.Errorf("failed to load domain object %q: %w", doCfg.ObjectName, err)
		}
	}

	m.loadedAt = time.Now()
	m.version = cfg.Version

	return nil
}

// LoadDefaults loads the default objects from configuration defaults.
func (m *Manager) LoadDefaults() error {
	defaults := config.Defaults()
	return m.LoadFromConfig(defaults)
}

// ============================================================================
// Address Object CRUD
// ============================================================================

// AddAddressObject adds a new address object.
func (m *Manager) AddAddressObject(name string, addresses []string) error {
	obj := models.NewAddressObject(name, addresses)
	return m.addresses.Register(obj)
}

// GetAddressObject returns an address object by name.
func (m *Manager) GetAddressObject(name string) (*models.AddressObject, bool) {
	return m.addresses.Get(name)
}

// RemoveAddressObject removes an address object by name.
func (m *Manager) RemoveAddressObject(name string) bool {
	return m.addresses.Unregister(name)
}

// ============================================================================
// Port Object CRUD
// ============================================================================

// AddPortObject adds a new port object.
func (m *Manager) AddPortObject(name string, ports []int) error {
	obj := models.NewPortObject(name, ports)
	return m.ports.Register(obj)
}

// GetPortObject returns a port object by name.
func (m *Manager) GetPortObject(name string) (*models.PortObject, bool) {
	return m.ports.Get(name)
}

// RemovePortObject removes a port object by name.
func (m *Manager) RemovePortObject(name string) bool {
	return m.ports.Unregister(name)
}

// ============================================================================
// Domain Object CRUD
// ============================================================================

// AddDomainObject adds a new domain object.
func (m *Manager) AddDomainObject(name string, patterns []string) error {
	obj := models.NewDomainObject(name, patterns)
	return m.domains.Register(obj)
}

// GetDomainObject returns a domain object by name.
func (m *Manager) GetDomainObject(name string) (*models.DomainObject, bool) {
	return m.domains.Get(name)
}

// RemoveDomainObject removes a domain object by name.
func (m *Manager) RemoveDomainObject(name string) bool {
	return m.domains.Unregister(name)
}

// ============================================================================
// Geo Object CRUD
// ============================================================================

// AddGeoObject adds a new geo object.
func (m *Manager) AddGeoObject(name string, objType models.ObjectType, values []string) error {
	obj := models.NewGeoObject(name, objType, values)
	return m.geo.Register(obj)
}

// GetGeoObject returns a geo object by name.
func (m *Manager) GetGeoObject(name string) (*models.GeoObject, bool) {
	return m.geo.Get(name)
}

// RemoveGeoObject removes a geo object by name.
func (m *Manager) RemoveGeoObject(name string) bool {
	return m.geo.Unregister(name)
}

// SetGeoResolver sets the GeoIP resolver for geo objects.
func (m *Manager) SetGeoResolver(resolver GeoResolver) {
	m.geo.SetResolver(resolver)
}

// ============================================================================
// Unified Operations
// ============================================================================

// Resolver returns the object resolver for rule matching.
func (m *Manager) Resolver() *Resolver {
	return m.resolver
}

// ObjectExists checks if an object with the given name exists.
func (m *Manager) ObjectExists(name string) bool {
	return m.resolver.ObjectExists(name)
}

// GetObjectType returns the type of object with the given name.
func (m *Manager) GetObjectType(name string) string {
	return m.resolver.GetObjectType(name)
}

// AllNames returns all object names across all types.
func (m *Manager) AllNames() []string {
	names := make([]string, 0)
	names = append(names, m.addresses.Names()...)
	names = append(names, m.ports.Names()...)
	names = append(names, m.domains.Names()...)
	names = append(names, m.geo.Names()...)
	return names
}

// Clear removes all objects from all managers.
func (m *Manager) Clear() {
	m.mu.Lock()
	defer m.mu.Unlock()

	m.addresses.Clear()
	m.ports.Clear()
	m.domains.Clear()
	m.geo.Clear()
}

// ============================================================================
// Accessors for Individual Managers
// ============================================================================

// Addresses returns the address object manager.
func (m *Manager) Addresses() *AddressObjectManager {
	return m.addresses
}

// Ports returns the port object manager.
func (m *Manager) Ports() *PortObjectManager {
	return m.ports
}

// Domains returns the domain object manager.
func (m *Manager) Domains() *DomainObjectManager {
	return m.domains
}

// Geo returns the geo object manager.
func (m *Manager) Geo() *GeoObjectManager {
	return m.geo
}

// ============================================================================
// Statistics
// ============================================================================

// ManagerStats contains combined statistics for all object types.
type ManagerStats struct {
	AddressStats AddressStats `json:"address_stats"`
	PortStats    PortStats    `json:"port_stats"`
	DomainStats  DomainStats  `json:"domain_stats"`
	GeoStats     GeoStats     `json:"geo_stats"`
	TotalObjects int          `json:"total_objects"`
	LoadedAt     time.Time    `json:"loaded_at"`
	Version      string       `json:"version,omitempty"`
}

// GetStats returns combined statistics.
func (m *Manager) GetStats() ManagerStats {
	stats := ManagerStats{
		AddressStats: m.addresses.GetStats(),
		PortStats:    m.ports.GetStats(),
		DomainStats:  m.domains.GetStats(),
		GeoStats:     m.geo.GetStats(),
		LoadedAt:     m.loadedAt,
		Version:      m.version,
	}

	stats.TotalObjects = stats.AddressStats.ObjectCount +
		stats.PortStats.ObjectCount +
		stats.DomainStats.ObjectCount +
		stats.GeoStats.ObjectCount

	return stats
}

// MarshalJSON implements json.Marshaler for Manager stats.
func (m *Manager) MarshalJSON() ([]byte, error) {
	return json.Marshal(m.GetStats())
}

// ============================================================================
// Validation
// ============================================================================

// ValidateObjectReference checks if an object reference is valid.
// Returns the object type if valid, empty string and error if not.
func (m *Manager) ValidateObjectReference(name string) (string, error) {
	if name == "" {
		return "", fmt.Errorf("object name is empty")
	}

	objType := m.GetObjectType(name)
	if objType == "" {
		return "", fmt.Errorf("object not found: %s", name)
	}

	return objType, nil
}

// ValidateRuleReferences validates all object references in a rule.
func (m *Manager) ValidateRuleReferences(rule *models.FirewallRule) []string {
	var errors []string

	// Check source address
	if rule.SourceAddress != "" && !isSpecialAddress(rule.SourceAddress) {
		normalized := rule.NormalizedSourceAddress
		if normalized == "" {
			normalized = rule.SourceAddress
		}
		if !m.ObjectExists(normalized) && !isDirectAddress(normalized) {
			errors = append(errors, fmt.Sprintf("unknown source address object: %s", normalized))
		}
	}

	// Check destination address
	if rule.DestinationAddress != "" && !isSpecialAddress(rule.DestinationAddress) {
		normalized := rule.NormalizedDestAddress
		if normalized == "" {
			normalized = rule.DestinationAddress
		}
		if !m.ObjectExists(normalized) && !isDirectAddress(normalized) {
			errors = append(errors, fmt.Sprintf("unknown destination address object: %s", normalized))
		}
	}

	// Check port objects
	if rule.SourcePortObject != "" && !m.ports.Exists(rule.SourcePortObject) {
		errors = append(errors, fmt.Sprintf("unknown source port object: %s", rule.SourcePortObject))
	}
	if rule.DestinationPortObject != "" && !m.ports.Exists(rule.DestinationPortObject) {
		errors = append(errors, fmt.Sprintf("unknown destination port object: %s", rule.DestinationPortObject))
	}

	// Check domain object
	if rule.DomainObject != "" && !m.domains.Exists(rule.DomainObject) {
		errors = append(errors, fmt.Sprintf("unknown domain object: %s", rule.DomainObject))
	}

	return errors
}

// isSpecialAddress checks if an address is a special keyword.
func isSpecialAddress(addr string) bool {
	upper := toUpper(addr)
	return upper == "ANY" || upper == "0.0.0.0/0" || upper == "::/0"
}

// isDirectAddress checks if an address is a direct IP/CIDR.
func isDirectAddress(addr string) bool {
	// Contains / for CIDR or is parseable as IP
	if contains(addr, "/") || contains(addr, ".") || contains(addr, ":") {
		return true
	}
	return false
}

// Helper functions to avoid import cycles
func toUpper(s string) string {
	result := make([]byte, len(s))
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c >= 'a' && c <= 'z' {
			c -= 32
		}
		result[i] = c
	}
	return string(result)
}

func contains(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}
