// Package objects provides reusable network objects for firewall rules.
package objects

import (
	"fmt"
	"net"
	"strings"

	"firewall_engine/pkg/models"
)

// ============================================================================
// Object Resolver - Resolve object references in rules
// ============================================================================

// Resolver resolves object references used in firewall rules.
// It unifies all object managers and provides a single interface
// for rule evaluation to resolve object names to actual values.
type Resolver struct {
	addresses *AddressObjectManager
	ports     *PortObjectManager
	domains   *DomainObjectManager
	geo       *GeoObjectManager
}

// NewResolver creates a new object resolver with the given managers.
func NewResolver(
	addresses *AddressObjectManager,
	ports *PortObjectManager,
	domains *DomainObjectManager,
	geo *GeoObjectManager,
) *Resolver {
	return &Resolver{
		addresses: addresses,
		ports:     ports,
		domains:   domains,
		geo:       geo,
	}
}

// NewResolverWithDefaults creates a resolver with default managers.
func NewResolverWithDefaults() *Resolver {
	return &Resolver{
		addresses: NewAddressObjectManager(),
		ports:     NewPortObjectManager(),
		domains:   NewDomainObjectManager(),
		geo:       NewGeoObjectManager(nil),
	}
}

// ============================================================================
// Address Resolution
// ============================================================================

// ResolveAddress resolves an address specification to determine if an IP matches.
// Spec can be: object name, CIDR, IP, "ANY", or negated (!ObjectName)
func (r *Resolver) ResolveAddress(spec string, ip net.IP) (bool, error) {
	if ip == nil {
		return false, fmt.Errorf("IP is nil")
	}

	spec = strings.TrimSpace(spec)

	// Handle empty or ANY
	if spec == "" || strings.ToUpper(spec) == "ANY" || spec == "0.0.0.0/0" {
		return true, nil
	}

	// Handle negation
	negated := false
	if strings.HasPrefix(spec, "!") {
		negated = true
		spec = strings.TrimPrefix(spec, "!")
	}

	var matches bool
	var err error

	// Try as address object
	if r.addresses != nil && r.addresses.Exists(spec) {
		matches = r.addresses.ContainsIP(spec, ip)
	} else if r.geo != nil && r.geo.Exists(spec) {
		// Try as geo object
		matches, err = r.geo.Contains(spec, ip)
		if err != nil {
			return false, err
		}
	} else if strings.Contains(spec, "/") {
		// Try as CIDR
		_, network, parseErr := net.ParseCIDR(spec)
		if parseErr != nil {
			return false, fmt.Errorf("invalid CIDR: %s", spec)
		}
		matches = network.Contains(ip)
	} else {
		// Try as single IP
		specIP := net.ParseIP(spec)
		if specIP == nil {
			return false, fmt.Errorf("unknown object or invalid address: %s", spec)
		}
		matches = specIP.Equal(ip)
	}

	if negated {
		return !matches, nil
	}
	return matches, nil
}

// ResolveAddressString resolves address spec with string IP.
func (r *Resolver) ResolveAddressString(spec string, ipStr string) (bool, error) {
	ip := net.ParseIP(ipStr)
	if ip == nil {
		return false, fmt.Errorf("invalid IP: %s", ipStr)
	}
	return r.ResolveAddress(spec, ip)
}

// ============================================================================
// Port Resolution
// ============================================================================

// ResolvePort resolves a port specification to determine if a port matches.
// Spec can be: object name or direct port list
func (r *Resolver) ResolvePort(objectName string, directPorts []int, port uint16, proto models.Protocol) bool {
	// If no port filter, match any
	if objectName == "" && len(directPorts) == 0 {
		return true
	}

	// Check object reference
	if objectName != "" && r.ports != nil {
		return r.ports.ContainsWithProtocol(objectName, port, proto)
	}

	// Check direct port list
	for _, p := range directPorts {
		if uint16(p) == port {
			return true
		}
	}

	return false
}

// ============================================================================
// Domain Resolution
// ============================================================================

// ResolveDomain resolves a domain specification to determine if a domain matches.
// Spec can be: object name or direct pattern
func (r *Resolver) ResolveDomain(objectName string, directPattern string, domain string) bool {
	// If no domain filter, match any
	if objectName == "" && directPattern == "" {
		return true
	}

	// If packet has no domain, return false (filter requires domain)
	if domain == "" {
		return false
	}

	domain = strings.ToLower(strings.TrimSpace(domain))

	// Check object reference
	if objectName != "" && r.domains != nil {
		return r.domains.Contains(objectName, domain)
	}

	// Check direct pattern
	if directPattern != "" {
		return matchDomainPattern(directPattern, domain)
	}

	return false
}

// ============================================================================
// Complete Rule Matching
// ============================================================================

// MatchRule evaluates all object-based conditions in a rule against a packet.
// Returns (matches bool, reason string, error)
func (r *Resolver) MatchRule(rule *models.FirewallRule, pkt *models.PacketMetadata) (bool, string, error) {
	// === Direction ===
	if !rule.Direction.Matches(pkt.Direction) {
		return false, "direction mismatch", nil
	}

	// === Protocol ===
	if !rule.Protocol.Matches(pkt.Protocol) {
		return false, "protocol mismatch", nil
	}

	// === Source Address ===
	if rule.SourceAddress != "" {
		srcIP := pkt.SrcIPParsed
		if srcIP == nil {
			srcIP = net.ParseIP(pkt.SrcIP)
		}
		matches, err := r.ResolveAddress(rule.SourceAddress, srcIP)
		if err != nil {
			return false, "", fmt.Errorf("source address resolution failed: %w", err)
		}
		if !matches {
			return false, "source address mismatch", nil
		}
	}

	// === Destination Address ===
	if rule.DestinationAddress != "" {
		dstIP := pkt.DstIPParsed
		if dstIP == nil {
			dstIP = net.ParseIP(pkt.DstIP)
		}
		matches, err := r.ResolveAddress(rule.DestinationAddress, dstIP)
		if err != nil {
			return false, "", fmt.Errorf("destination address resolution failed: %w", err)
		}
		if !matches {
			return false, "destination address mismatch", nil
		}
	}

	// === Source Port ===
	if rule.HasSourcePorts() {
		if !r.ResolvePort(rule.SourcePortObject, rule.SourcePort, pkt.SrcPort, pkt.Protocol) {
			return false, "source port mismatch", nil
		}
	}

	// === Destination Port ===
	if rule.HasDestinationPorts() {
		if !r.ResolvePort(rule.DestinationPortObject, rule.DestinationPort, pkt.DstPort, pkt.Protocol) {
			return false, "destination port mismatch", nil
		}
	}

	// === Domain ===
	if rule.HasDomainMatch() {
		if !r.ResolveDomain(rule.DomainObject, rule.Domain, pkt.Domain) {
			return false, "domain mismatch", nil
		}
	}

	// === Connection State ===
	if rule.HasStateMatch() {
		if !rule.MatchesState(pkt.ConnectionState) {
			return false, "connection state mismatch", nil
		}
	}

	// === Interface ===
	if rule.Interface != "" {
		if !strings.EqualFold(rule.Interface, pkt.AdapterName) {
			return false, "interface mismatch", nil
		}
	}

	// All conditions matched
	return true, "all conditions matched", nil
}

// ============================================================================
// Object Existence Checks
// ============================================================================

// ObjectExists checks if an object name exists in any manager.
func (r *Resolver) ObjectExists(name string) bool {
	if r.addresses != nil && r.addresses.Exists(name) {
		return true
	}
	if r.ports != nil && r.ports.Exists(name) {
		return true
	}
	if r.domains != nil && r.domains.Exists(name) {
		return true
	}
	if r.geo != nil && r.geo.Exists(name) {
		return true
	}
	return false
}

// GetObjectType returns the type of object with the given name.
func (r *Resolver) GetObjectType(name string) string {
	if r.addresses != nil && r.addresses.Exists(name) {
		return "address"
	}
	if r.ports != nil && r.ports.Exists(name) {
		return "port"
	}
	if r.domains != nil && r.domains.Exists(name) {
		return "domain"
	}
	if r.geo != nil && r.geo.Exists(name) {
		return "geo"
	}
	return ""
}

// ============================================================================
// Accessors
// ============================================================================

// Addresses returns the address object manager.
func (r *Resolver) Addresses() *AddressObjectManager {
	return r.addresses
}

// Ports returns the port object manager.
func (r *Resolver) Ports() *PortObjectManager {
	return r.ports
}

// Domains returns the domain object manager.
func (r *Resolver) Domains() *DomainObjectManager {
	return r.domains
}

// Geo returns the geo object manager.
func (r *Resolver) Geo() *GeoObjectManager {
	return r.geo
}

// ============================================================================
// Statistics
// ============================================================================

// ResolverStats contains combined statistics.
type ResolverStats struct {
	AddressStats AddressStats `json:"address_stats"`
	PortStats    PortStats    `json:"port_stats"`
	DomainStats  DomainStats  `json:"domain_stats"`
	GeoStats     GeoStats     `json:"geo_stats"`
}

// GetStats returns combined statistics from all managers.
func (r *Resolver) GetStats() ResolverStats {
	stats := ResolverStats{}

	if r.addresses != nil {
		stats.AddressStats = r.addresses.GetStats()
	}
	if r.ports != nil {
		stats.PortStats = r.ports.GetStats()
	}
	if r.domains != nil {
		stats.DomainStats = r.domains.GetStats()
	}
	if r.geo != nil {
		stats.GeoStats = r.geo.GetStats()
	}

	return stats
}
