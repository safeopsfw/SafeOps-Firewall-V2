// Package validation provides comprehensive validation for firewall rules.
package validation

import (
	"fmt"

	"firewall_engine/internal/config"
)

// ============================================================================
// Circular Reference Detector
// ============================================================================

// CircularDetector detects circular references in object definitions.
// For example, if object A references object B, and B references A.
type CircularDetector struct {
	// Object reference graphs
	addressRefs map[string][]string // object -> objects it references
	portRefs    map[string][]string
	domainRefs  map[string][]string

	// Visit state for DFS
	visiting map[string]bool
	visited  map[string]bool

	// Detected cycles
	cycles [][]string
}

// NewCircularDetector creates a new circular reference detector.
func NewCircularDetector() *CircularDetector {
	return &CircularDetector{
		addressRefs: make(map[string][]string),
		portRefs:    make(map[string][]string),
		domainRefs:  make(map[string][]string),
		visiting:    make(map[string]bool),
		visited:     make(map[string]bool),
		cycles:      make([][]string, 0),
	}
}

// DetectAll detects all circular references in the configuration.
func (d *CircularDetector) DetectAll(cfg *config.Config) *ValidationResult {
	result := NewValidationResult()

	// Reset state
	d.reset()

	// Build reference graphs
	d.buildReferenceGraphs(cfg)

	// Detect cycles in each graph
	d.detectAddressCycles(result)
	d.detectPortCycles(result)
	d.detectDomainCycles(result)

	return result
}

// reset clears all state for a new detection run.
func (d *CircularDetector) reset() {
	d.addressRefs = make(map[string][]string)
	d.portRefs = make(map[string][]string)
	d.domainRefs = make(map[string][]string)
	d.visiting = make(map[string]bool)
	d.visited = make(map[string]bool)
	d.cycles = make([][]string, 0)
}

// buildReferenceGraphs builds the reference graphs from configuration.
func (d *CircularDetector) buildReferenceGraphs(cfg *config.Config) {
	// Build address object references
	// Note: In our current design, address objects contain raw values (IPs/CIDRs),
	// not references to other objects. But we support object-to-object refs for future use.
	// For now, we'll detect if any address values look like object references.
	addressNames := make(map[string]bool)
	for _, obj := range cfg.AddressObjects {
		addressNames[obj.ObjectName] = true
	}

	for _, obj := range cfg.AddressObjects {
		refs := make([]string, 0)
		addrs := obj.Addresses
		if len(addrs) == 0 {
			addrs = obj.Values
		}
		for _, addr := range addrs {
			// Check if this looks like an object reference
			if addressNames[addr] && addr != obj.ObjectName {
				refs = append(refs, addr)
			}
		}
		if len(refs) > 0 {
			d.addressRefs[obj.ObjectName] = refs
		}
	}

	// Build port object references (similar logic)
	portNames := make(map[string]bool)
	for _, obj := range cfg.PortObjects {
		portNames[obj.ObjectName] = true
	}

	// Port objects don't typically reference other port objects,
	// but we track this for completeness.

	// Domain objects similarly don't typically reference each other.
}

// detectAddressCycles detects cycles in the address object graph.
func (d *CircularDetector) detectAddressCycles(result *ValidationResult) {
	d.visiting = make(map[string]bool)
	d.visited = make(map[string]bool)

	for name := range d.addressRefs {
		if !d.visited[name] {
			path := []string{}
			d.dfs(name, d.addressRefs, path, "address_object", result)
		}
	}
}

// detectPortCycles detects cycles in the port object graph.
func (d *CircularDetector) detectPortCycles(result *ValidationResult) {
	d.visiting = make(map[string]bool)
	d.visited = make(map[string]bool)

	for name := range d.portRefs {
		if !d.visited[name] {
			path := []string{}
			d.dfs(name, d.portRefs, path, "port_object", result)
		}
	}
}

// detectDomainCycles detects cycles in the domain object graph.
func (d *CircularDetector) detectDomainCycles(result *ValidationResult) {
	d.visiting = make(map[string]bool)
	d.visited = make(map[string]bool)

	for name := range d.domainRefs {
		if !d.visited[name] {
			path := []string{}
			d.dfs(name, d.domainRefs, path, "domain_object", result)
		}
	}
}

// dfs performs depth-first search to detect cycles.
func (d *CircularDetector) dfs(node string, graph map[string][]string, path []string, category string, result *ValidationResult) {
	if d.visiting[node] {
		// Found a cycle! Find where the cycle starts.
		cycleStart := -1
		for i, n := range path {
			if n == node {
				cycleStart = i
				break
			}
		}
		if cycleStart >= 0 {
			cycle := append(path[cycleStart:], node)
			d.cycles = append(d.cycles, cycle)
			result.AddError("circular", fmt.Sprintf("%s.%s", category, node),
				fmt.Sprintf("circular reference detected: %v", cycle))
		}
		return
	}

	if d.visited[node] {
		return
	}

	d.visiting[node] = true
	path = append(path, node)

	for _, ref := range graph[node] {
		d.dfs(ref, graph, path, category, result)
	}

	d.visiting[node] = false
	d.visited[node] = true
}

// ============================================================================
// Cross-Reference Detection
// ============================================================================

// CheckCrossReferences checks for references between different object types.
// For example, a rule referring to a non-existent object.
func (d *CircularDetector) CheckCrossReferences(cfg *config.Config) *ValidationResult {
	result := NewValidationResult()

	// Collect all object names by type
	addressObjects := make(map[string]bool)
	portObjects := make(map[string]bool)
	domainObjects := make(map[string]bool)

	for _, obj := range cfg.AddressObjects {
		addressObjects[obj.ObjectName] = true
	}
	for _, obj := range cfg.PortObjects {
		portObjects[obj.ObjectName] = true
	}
	for _, obj := range cfg.DomainObjects {
		domainObjects[obj.ObjectName] = true
	}

	// Check rule references
	for i, rule := range cfg.Rules {
		path := fmt.Sprintf("rules[%d]", i)

		// Check if source_address is an object reference
		if isObjectReference(rule.SourceAddress) {
			if !addressObjects[rule.SourceAddress] {
				result.AddWarning("circular", path+".source_address",
					fmt.Sprintf("reference to undefined address object: %s", rule.SourceAddress))
			}
		}

		// Check if destination_address is an object reference
		if isObjectReference(rule.DestinationAddress) {
			if !addressObjects[rule.DestinationAddress] {
				result.AddWarning("circular", path+".destination_address",
					fmt.Sprintf("reference to undefined address object: %s", rule.DestinationAddress))
			}
		}

		// Check domain object reference
		if rule.Domain != "" && domainObjects[rule.Domain] == false {
			// Could be a direct pattern or an object
			// We only warn if it looks like an object name (no wildcards)
			if !containsWildcard(rule.Domain) && !containsDot(rule.Domain) {
				result.AddWarning("circular", path+".domain",
					fmt.Sprintf("possible reference to undefined domain object: %s", rule.Domain))
			}
		}
	}

	return result
}

// isObjectReference checks if a string looks like an object reference.
// Object references are alphanumeric names, not IPs or CIDRs.
func isObjectReference(s string) bool {
	if s == "" || s == "ANY" {
		return false
	}
	// If it contains / (CIDR) or . (IP) or : (IPv6), it's not an object reference
	for _, c := range s {
		if c == '/' || c == '.' || c == ':' || c == '-' {
			return false
		}
	}
	// If it starts with !, strip it
	if len(s) > 0 && s[0] == '!' {
		s = s[1:]
	}
	// Check if it looks like an identifier
	return len(s) > 0 && isValidObjectName(s)
}

// containsWildcard checks if a string contains wildcards.
func containsWildcard(s string) bool {
	for _, c := range s {
		if c == '*' || c == '?' {
			return true
		}
	}
	return false
}

// containsDot checks if a string contains a dot.
func containsDot(s string) bool {
	for _, c := range s {
		if c == '.' {
			return true
		}
	}
	return false
}

// ============================================================================
// Self-Reference Detection
// ============================================================================

// DetectSelfReferences detects objects that reference themselves.
func (d *CircularDetector) DetectSelfReferences(cfg *config.Config) *ValidationResult {
	result := NewValidationResult()

	// Check address objects
	for i, obj := range cfg.AddressObjects {
		addrs := obj.Addresses
		if len(addrs) == 0 {
			addrs = obj.Values
		}
		for _, addr := range addrs {
			if addr == obj.ObjectName {
				result.AddError("circular", fmt.Sprintf("address_objects[%d].addresses", i),
					fmt.Sprintf("object '%s' references itself", obj.ObjectName))
			}
		}
	}

	return result
}
