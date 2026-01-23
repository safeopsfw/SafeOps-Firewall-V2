// Package objects provides reusable network objects for firewall rules.
package objects

import (
	"fmt"
	"sync"

	"firewall_engine/pkg/models"
)

// ============================================================================
// Port Object Manager - Port number/range management
// ============================================================================

// PortObjectManager manages a collection of port objects.
// It provides efficient port matching operations.
type PortObjectManager struct {
	mu      sync.RWMutex
	objects map[string]*models.PortObject
}

// NewPortObjectManager creates a new port object manager.
func NewPortObjectManager() *PortObjectManager {
	return &PortObjectManager{
		objects: make(map[string]*models.PortObject),
	}
}

// Register adds a new port object.
func (m *PortObjectManager) Register(obj *models.PortObject) error {
	if obj == nil {
		return fmt.Errorf("port object is nil")
	}
	if obj.Name == "" {
		return fmt.Errorf("port object name is required")
	}

	// Initialize the object (parse ports/ranges)
	if err := obj.Initialize(); err != nil {
		return fmt.Errorf("failed to initialize port object %q: %w", obj.Name, err)
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	m.objects[obj.Name] = obj
	return nil
}

// Unregister removes a port object by name.
func (m *PortObjectManager) Unregister(name string) bool {
	m.mu.Lock()
	defer m.mu.Unlock()

	if _, exists := m.objects[name]; !exists {
		return false
	}

	delete(m.objects, name)
	return true
}

// Get returns a port object by name.
func (m *PortObjectManager) Get(name string) (*models.PortObject, bool) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	obj, ok := m.objects[name]
	return obj, ok
}

// Exists checks if a port object exists.
func (m *PortObjectManager) Exists(name string) bool {
	m.mu.RLock()
	defer m.mu.RUnlock()

	_, ok := m.objects[name]
	return ok
}

// Contains checks if a port is contained in the named object.
func (m *PortObjectManager) Contains(objectName string, port uint16) bool {
	m.mu.RLock()
	defer m.mu.RUnlock()

	obj, ok := m.objects[objectName]
	if !ok {
		return false
	}

	return obj.Contains(port)
}

// ContainsWithProtocol checks if a port matches considering protocol.
func (m *PortObjectManager) ContainsWithProtocol(objectName string, port uint16, proto models.Protocol) bool {
	m.mu.RLock()
	defer m.mu.RUnlock()

	obj, ok := m.objects[objectName]
	if !ok {
		return false
	}

	// Check protocol match
	if !obj.MatchesProtocol(proto) {
		return false
	}

	return obj.Contains(port)
}

// All returns all registered port objects.
func (m *PortObjectManager) All() []*models.PortObject {
	m.mu.RLock()
	defer m.mu.RUnlock()

	result := make([]*models.PortObject, 0, len(m.objects))
	for _, obj := range m.objects {
		result = append(result, obj)
	}
	return result
}

// Names returns all registered object names.
func (m *PortObjectManager) Names() []string {
	m.mu.RLock()
	defer m.mu.RUnlock()

	result := make([]string, 0, len(m.objects))
	for name := range m.objects {
		result = append(result, name)
	}
	return result
}

// Count returns the number of registered objects.
func (m *PortObjectManager) Count() int {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return len(m.objects)
}

// Clear removes all port objects.
func (m *PortObjectManager) Clear() {
	m.mu.Lock()
	defer m.mu.Unlock()

	m.objects = make(map[string]*models.PortObject)
}

// ============================================================================
// Matcher Functions for Rule Evaluation
// ============================================================================

// MatchPort checks if a port matches a port specification.
// The spec can be:
// - Empty/nil ports - matches any port
// - Object name string - looks up and matches against the object
// - Direct port list - matches against the list
func (m *PortObjectManager) MatchPort(objectName string, ports []int, port uint16, proto models.Protocol) bool {
	// If no ports specified, match any
	if objectName == "" && len(ports) == 0 {
		return true
	}

	// Check object reference
	if objectName != "" {
		return m.ContainsWithProtocol(objectName, port, proto)
	}

	// Check direct port list
	for _, p := range ports {
		if uint16(p) == port {
			return true
		}
	}

	return false
}

// MatchSourcePort matches source port in rule.
func (m *PortObjectManager) MatchSourcePort(rule *models.FirewallRule, port uint16, proto models.Protocol) bool {
	return m.MatchPort(rule.SourcePortObject, rule.SourcePort, port, proto)
}

// MatchDestinationPort matches destination port in rule.
func (m *PortObjectManager) MatchDestinationPort(rule *models.FirewallRule, port uint16, proto models.Protocol) bool {
	return m.MatchPort(rule.DestinationPortObject, rule.DestinationPort, port, proto)
}

// ============================================================================
// Statistics
// ============================================================================

// PortStats contains statistics about port objects.
type PortStats struct {
	ObjectCount int `json:"object_count"`
	TotalPorts  int `json:"total_ports"`
	TotalRanges int `json:"total_ranges"`
}

// GetStats returns current statistics.
func (m *PortObjectManager) GetStats() PortStats {
	m.mu.RLock()
	defer m.mu.RUnlock()

	stats := PortStats{
		ObjectCount: len(m.objects),
	}

	for _, obj := range m.objects {
		stats.TotalPorts += len(obj.ParsedPorts)
		stats.TotalRanges += len(obj.Ranges)
	}

	return stats
}
