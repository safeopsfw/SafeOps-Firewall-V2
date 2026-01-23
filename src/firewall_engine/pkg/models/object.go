// Package models defines all core data structures used throughout the firewall engine.
package models

import (
	"encoding/json"
	"fmt"
	"net"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"
)

// ============================================================================
// Object Types - Reusable address/port/domain collections
// ============================================================================

// ObjectType represents the type of a reusable object.
type ObjectType string

const (
	// ObjectTypeCIDRList is a list of CIDR network ranges.
	ObjectTypeCIDRList ObjectType = "CIDR_LIST"

	// ObjectTypeIPList is a list of individual IP addresses.
	ObjectTypeIPList ObjectType = "IP_LIST"

	// ObjectTypeIPRange is a range of IP addresses (start-end).
	ObjectTypeIPRange ObjectType = "IP_RANGE"

	// ObjectTypePortList is a list of ports.
	ObjectTypePortList ObjectType = "PORT_LIST"

	// ObjectTypePortRange is a range of ports.
	ObjectTypePortRange ObjectType = "PORT_RANGE"

	// ObjectTypeDomainList is a list of domain patterns.
	ObjectTypeDomainList ObjectType = "DOMAIN_LIST"

	// ObjectTypeGeo is a GeoIP-based address set (country codes).
	ObjectTypeGeo ObjectType = "GEO"

	// ObjectTypeASN is an ASN-based address set.
	ObjectTypeASN ObjectType = "ASN"
)

// IsValid checks if the object type is recognized.
func (ot ObjectType) IsValid() bool {
	switch ot {
	case ObjectTypeCIDRList, ObjectTypeIPList, ObjectTypeIPRange,
		ObjectTypePortList, ObjectTypePortRange, ObjectTypeDomainList,
		ObjectTypeGeo, ObjectTypeASN:
		return true
	default:
		return false
	}
}

// ============================================================================
// Address Object - IP/CIDR collections
// ============================================================================

// AddressObject represents a reusable collection of IP addresses or CIDRs.
type AddressObject struct {
	// ID is the unique identifier for this object.
	ID uuid.UUID `json:"id,omitempty"`

	// Name is the unique name for referencing this object in rules.
	Name string `json:"object_name" toml:"object_name"`

	// Description explains the purpose of this object.
	Description string `json:"description,omitempty" toml:"description"`

	// Type indicates the type of address object.
	Type ObjectType `json:"type,omitempty" toml:"type"`

	// Addresses contains the raw address strings from config.
	Addresses []string `json:"addresses" toml:"addresses"`

	// Values is an alias for Addresses (for GeoIP/ASN compatibility).
	Values []string `json:"values,omitempty" toml:"values"`

	// ParsedCIDRs contains the parsed CIDR networks for matching.
	ParsedCIDRs []*net.IPNet `json:"-" toml:"-"`

	// ParsedIPs contains individual parsed IPs for exact matching.
	ParsedIPs []net.IP `json:"-" toml:"-"`

	// IPRanges contains parsed IP ranges for range matching.
	IPRanges []IPRange `json:"-" toml:"-"`

	// IsNegated indicates if this object should be negated in matching.
	IsNegated bool `json:"-" toml:"-"`

	// Timestamps
	CreatedAt  time.Time `json:"created_at,omitempty"`
	ModifiedAt time.Time `json:"modified_at,omitempty"`
}

// IPRange represents a range of IP addresses.
type IPRange struct {
	Start net.IP
	End   net.IP
}

// NewAddressObject creates a new address object.
func NewAddressObject(name string, addresses []string) *AddressObject {
	obj := &AddressObject{
		ID:         uuid.New(),
		Name:       name,
		Type:       ObjectTypeCIDRList,
		Addresses:  addresses,
		CreatedAt:  time.Now(),
		ModifiedAt: time.Now(),
	}
	return obj
}

// Initialize parses the addresses and prepares for matching.
func (ao *AddressObject) Initialize() error {
	// Use Values if Addresses is empty
	addrs := ao.Addresses
	if len(addrs) == 0 {
		addrs = ao.Values
	}

	ao.ParsedCIDRs = make([]*net.IPNet, 0, len(addrs))
	ao.ParsedIPs = make([]net.IP, 0)
	ao.IPRanges = make([]IPRange, 0)

	for _, addr := range addrs {
		addr = strings.TrimSpace(addr)
		if addr == "" {
			continue
		}

		// Check for IP range (192.168.1.1-192.168.1.100)
		if strings.Contains(addr, "-") && !strings.Contains(addr, "/") {
			parts := strings.SplitN(addr, "-", 2)
			if len(parts) == 2 {
				startIP := net.ParseIP(strings.TrimSpace(parts[0]))
				endIP := net.ParseIP(strings.TrimSpace(parts[1]))
				if startIP != nil && endIP != nil {
					ao.IPRanges = append(ao.IPRanges, IPRange{Start: startIP, End: endIP})
					continue
				}
			}
		}

		// Check for CIDR notation
		if strings.Contains(addr, "/") {
			_, network, err := net.ParseCIDR(addr)
			if err != nil {
				return fmt.Errorf("invalid CIDR %q: %w", addr, err)
			}
			ao.ParsedCIDRs = append(ao.ParsedCIDRs, network)
			continue
		}

		// Try as single IP
		ip := net.ParseIP(addr)
		if ip != nil {
			ao.ParsedIPs = append(ao.ParsedIPs, ip)
			continue
		}

		// Unknown format
		return fmt.Errorf("invalid address format %q", addr)
	}

	return nil
}

// Contains checks if the given IP is contained in this object.
func (ao *AddressObject) Contains(ip string) bool {
	parsedIP := net.ParseIP(ip)
	if parsedIP == nil {
		return false
	}
	return ao.ContainsIP(parsedIP)
}

// ContainsIP checks if the given net.IP is contained in this object.
func (ao *AddressObject) ContainsIP(ip net.IP) bool {
	// Check CIDRs
	for _, cidr := range ao.ParsedCIDRs {
		if cidr.Contains(ip) {
			return true
		}
	}

	// Check individual IPs
	for _, objIP := range ao.ParsedIPs {
		if objIP.Equal(ip) {
			return true
		}
	}

	// Check IP ranges
	for _, r := range ao.IPRanges {
		if ipInRange(ip, r.Start, r.End) {
			return true
		}
	}

	return false
}

// ipInRange checks if ip is within the range [start, end].
func ipInRange(ip, start, end net.IP) bool {
	// Convert to same format for comparison
	ip = ip.To16()
	start = start.To16()
	end = end.To16()

	if ip == nil || start == nil || end == nil {
		return false
	}

	// Compare bytes
	for i := 0; i < len(ip); i++ {
		if ip[i] < start[i] {
			return false
		}
		if ip[i] > end[i] {
			return false
		}
		// If we're between start and end at this byte, check next byte
		if ip[i] > start[i] && ip[i] < end[i] {
			return true
		}
	}
	return true
}

// Count returns the approximate number of addresses in this object.
func (ao *AddressObject) Count() int {
	count := len(ao.ParsedIPs)
	for _, cidr := range ao.ParsedCIDRs {
		ones, bits := cidr.Mask.Size()
		count += 1 << (bits - ones)
	}
	return count
}

// String returns a human-readable summary.
func (ao *AddressObject) String() string {
	return fmt.Sprintf("[AddressObject: %s] %d CIDRs, %d IPs, %d ranges",
		ao.Name, len(ao.ParsedCIDRs), len(ao.ParsedIPs), len(ao.IPRanges))
}

// ============================================================================
// Port Object - Port collections
// ============================================================================

// PortObject represents a reusable collection of ports.
type PortObject struct {
	// ID is the unique identifier for this object.
	ID uuid.UUID `json:"id,omitempty"`

	// Name is the unique name for referencing this object in rules.
	Name string `json:"object_name" toml:"object_name"`

	// Description explains the purpose of this object.
	Description string `json:"description,omitempty" toml:"description"`

	// Protocol specifies which protocol these ports apply to (TCP, UDP, BOTH).
	Protocol string `json:"protocol,omitempty" toml:"protocol"`

	// Ports contains the port numbers.
	Ports []int `json:"ports" toml:"ports"`

	// PortRanges contains port range strings (e.g., "1000-2000").
	PortRanges []string `json:"port_ranges,omitempty" toml:"port_ranges"`

	// ParsedPorts contains all individual ports (including expanded ranges).
	ParsedPorts map[uint16]bool `json:"-" toml:"-"`

	// Ranges contains parsed port ranges for efficient checking.
	Ranges []PortRange `json:"-" toml:"-"`

	// Timestamps
	CreatedAt  time.Time `json:"created_at,omitempty"`
	ModifiedAt time.Time `json:"modified_at,omitempty"`
}

// PortRange represents a range of ports.
type PortRange struct {
	Start uint16
	End   uint16
}

// NewPortObject creates a new port object.
func NewPortObject(name string, ports []int) *PortObject {
	return &PortObject{
		ID:          uuid.New(),
		Name:        name,
		Ports:       ports,
		Protocol:    "BOTH",
		ParsedPorts: make(map[uint16]bool),
		CreatedAt:   time.Now(),
		ModifiedAt:  time.Now(),
	}
}

// Initialize parses the ports and prepares for matching.
func (po *PortObject) Initialize() error {
	po.ParsedPorts = make(map[uint16]bool)
	po.Ranges = make([]PortRange, 0)

	// Add individual ports
	for _, port := range po.Ports {
		if port < 1 || port > 65535 {
			return fmt.Errorf("invalid port number: %d", port)
		}
		po.ParsedPorts[uint16(port)] = true
	}

	// Parse port ranges
	for _, rangeStr := range po.PortRanges {
		parts := strings.SplitN(rangeStr, "-", 2)
		if len(parts) != 2 {
			return fmt.Errorf("invalid port range format: %s", rangeStr)
		}

		start, err := strconv.ParseUint(strings.TrimSpace(parts[0]), 10, 16)
		if err != nil {
			return fmt.Errorf("invalid port range start: %s", parts[0])
		}

		end, err := strconv.ParseUint(strings.TrimSpace(parts[1]), 10, 16)
		if err != nil {
			return fmt.Errorf("invalid port range end: %s", parts[1])
		}

		if start > end || start < 1 || end > 65535 {
			return fmt.Errorf("invalid port range: %d-%d", start, end)
		}

		po.Ranges = append(po.Ranges, PortRange{
			Start: uint16(start),
			End:   uint16(end),
		})
	}

	return nil
}

// Contains checks if the given port is in this object.
func (po *PortObject) Contains(port uint16) bool {
	// Check individual ports
	if po.ParsedPorts[port] {
		return true
	}

	// Check ranges
	for _, r := range po.Ranges {
		if port >= r.Start && port <= r.End {
			return true
		}
	}

	return false
}

// ContainsInt checks if the given port (as int) is in this object.
func (po *PortObject) ContainsInt(port int) bool {
	if port < 1 || port > 65535 {
		return false
	}
	return po.Contains(uint16(port))
}

// MatchesProtocol checks if this object applies to the given protocol.
func (po *PortObject) MatchesProtocol(proto Protocol) bool {
	upper := strings.ToUpper(po.Protocol)
	switch upper {
	case "BOTH", "ANY", "":
		return true
	case "TCP":
		return proto == ProtocolTCP
	case "UDP":
		return proto == ProtocolUDP
	default:
		return true
	}
}

// GetAllPorts returns all ports including expanded ranges.
func (po *PortObject) GetAllPorts() []uint16 {
	result := make([]uint16, 0, len(po.ParsedPorts))
	for port := range po.ParsedPorts {
		result = append(result, port)
	}
	for _, r := range po.Ranges {
		for p := r.Start; p <= r.End; p++ {
			result = append(result, p)
		}
	}
	return result
}

// Count returns the total number of ports in this object.
func (po *PortObject) Count() int {
	count := len(po.ParsedPorts)
	for _, r := range po.Ranges {
		count += int(r.End - r.Start + 1)
	}
	return count
}

// String returns a human-readable summary.
func (po *PortObject) String() string {
	return fmt.Sprintf("[PortObject: %s] %d ports, %d ranges, protocol=%s",
		po.Name, len(po.ParsedPorts), len(po.Ranges), po.Protocol)
}

// ============================================================================
// Domain Object - Domain pattern collections
// ============================================================================

// DomainObject represents a reusable collection of domain patterns.
type DomainObject struct {
	// ID is the unique identifier for this object.
	ID uuid.UUID `json:"id,omitempty"`

	// Name is the unique name for referencing this object in rules.
	Name string `json:"object_name" toml:"object_name"`

	// Description explains the purpose of this object.
	Description string `json:"description,omitempty" toml:"description"`

	// Values contains the domain patterns.
	// Supports exact matches (facebook.com) and wildcards (*.facebook.com)
	Values []string `json:"values" toml:"values"`

	// ExactDomains contains domains for exact matching (lowercase).
	ExactDomains map[string]bool `json:"-" toml:"-"`

	// WildcardSuffixes contains domain suffixes for wildcard matching.
	// *.facebook.com becomes .facebook.com for suffix matching
	WildcardSuffixes []string `json:"-" toml:"-"`

	// WildcardPrefixes contains domain prefixes for prefix matching.
	// facebook.* becomes facebook. for prefix matching
	WildcardPrefixes []string `json:"-" toml:"-"`

	// Timestamps
	CreatedAt  time.Time `json:"created_at,omitempty"`
	ModifiedAt time.Time `json:"modified_at,omitempty"`
}

// NewDomainObject creates a new domain object.
func NewDomainObject(name string, values []string) *DomainObject {
	return &DomainObject{
		ID:               uuid.New(),
		Name:             name,
		Values:           values,
		ExactDomains:     make(map[string]bool),
		WildcardSuffixes: make([]string, 0),
		WildcardPrefixes: make([]string, 0),
		CreatedAt:        time.Now(),
		ModifiedAt:       time.Now(),
	}
}

// Initialize parses the domain patterns and prepares for matching.
func (do *DomainObject) Initialize() error {
	do.ExactDomains = make(map[string]bool)
	do.WildcardSuffixes = make([]string, 0)
	do.WildcardPrefixes = make([]string, 0)

	for _, pattern := range do.Values {
		pattern = strings.TrimSpace(strings.ToLower(pattern))
		if pattern == "" {
			continue
		}

		if strings.HasPrefix(pattern, "*.") {
			// Wildcard suffix: *.facebook.com matches www.facebook.com
			suffix := strings.TrimPrefix(pattern, "*")
			do.WildcardSuffixes = append(do.WildcardSuffixes, suffix)
			// Also add the base domain for exact matching
			baseDomain := strings.TrimPrefix(suffix, ".")
			do.ExactDomains[baseDomain] = true
		} else if strings.HasSuffix(pattern, ".*") {
			// Wildcard prefix: facebook.* matches facebook.com, facebook.net
			prefix := strings.TrimSuffix(pattern, "*")
			do.WildcardPrefixes = append(do.WildcardPrefixes, prefix)
		} else if strings.Contains(pattern, "*") {
			// Complex pattern - treat as suffix match for simplicity
			// Remove all asterisks and use as contains
			suffix := strings.ReplaceAll(pattern, "*", "")
			if suffix != "" {
				do.WildcardSuffixes = append(do.WildcardSuffixes, suffix)
			}
		} else {
			// Exact match
			do.ExactDomains[pattern] = true
		}
	}

	return nil
}

// Contains checks if the given domain matches any pattern in this object.
func (do *DomainObject) Contains(domain string) bool {
	domain = strings.ToLower(strings.TrimSpace(domain))
	if domain == "" {
		return false
	}

	// Check exact match
	if do.ExactDomains[domain] {
		return true
	}

	// Check wildcard suffixes (*.facebook.com matches www.facebook.com)
	for _, suffix := range do.WildcardSuffixes {
		if strings.HasSuffix(domain, suffix) {
			return true
		}
	}

	// Check wildcard prefixes (facebook.* matches facebook.com)
	for _, prefix := range do.WildcardPrefixes {
		if strings.HasPrefix(domain, prefix) {
			return true
		}
	}

	return false
}

// Count returns the number of patterns in this object.
func (do *DomainObject) Count() int {
	return len(do.Values)
}

// String returns a human-readable summary.
func (do *DomainObject) String() string {
	return fmt.Sprintf("[DomainObject: %s] %d exact, %d wildcards",
		do.Name, len(do.ExactDomains), len(do.WildcardSuffixes)+len(do.WildcardPrefixes))
}

// ============================================================================
// Service Object - Combined protocol/port definition
// ============================================================================

// ServiceObject represents a service definition (protocol + ports).
type ServiceObject struct {
	// ID is the unique identifier for this object.
	ID uuid.UUID `json:"id,omitempty"`

	// Name is the unique name for referencing this object.
	Name string `json:"object_name" toml:"object_name"`

	// Description explains the purpose of this service.
	Description string `json:"description,omitempty" toml:"description"`

	// Protocol is the IP protocol (TCP, UDP).
	Protocol string `json:"protocol" toml:"protocol"`

	// Ports contains the port numbers for this service.
	Ports []int `json:"ports" toml:"ports"`

	// ParsedProtocol is the parsed protocol type.
	ParsedProtocol Protocol `json:"-" toml:"-"`

	// ParsedPorts contains parsed ports for matching.
	ParsedPorts map[uint16]bool `json:"-" toml:"-"`
}

// NewServiceObject creates a new service object.
func NewServiceObject(name, protocol string, ports []int) *ServiceObject {
	return &ServiceObject{
		ID:          uuid.New(),
		Name:        name,
		Protocol:    protocol,
		Ports:       ports,
		ParsedPorts: make(map[uint16]bool),
	}
}

// Initialize parses the service definition.
func (so *ServiceObject) Initialize() error {
	// Parse protocol
	proto, err := ProtocolFromString(so.Protocol)
	if err != nil {
		return fmt.Errorf("invalid protocol %q: %w", so.Protocol, err)
	}
	so.ParsedProtocol = proto

	// Parse ports
	so.ParsedPorts = make(map[uint16]bool)
	for _, port := range so.Ports {
		if port < 1 || port > 65535 {
			return fmt.Errorf("invalid port number: %d", port)
		}
		so.ParsedPorts[uint16(port)] = true
	}

	return nil
}

// Matches checks if the given protocol and port match this service.
func (so *ServiceObject) Matches(proto Protocol, port uint16) bool {
	if so.ParsedProtocol != ProtocolAny && so.ParsedProtocol != proto {
		return false
	}
	if len(so.ParsedPorts) == 0 {
		return true
	}
	return so.ParsedPorts[port]
}

// ============================================================================
// GeoIP Object - Country/ASN-based address sets
// ============================================================================

// GeoObject represents a geographic or ASN-based address set.
// This is a placeholder for PostgreSQL GeoIP integration.
type GeoObject struct {
	// ID is the unique identifier for this object.
	ID uuid.UUID `json:"id,omitempty"`

	// Name is the unique name for referencing this object.
	Name string `json:"object_name" toml:"object_name"`

	// Description explains the purpose of this object.
	Description string `json:"description,omitempty" toml:"description"`

	// Type is GEO for country codes, ASN for autonomous system numbers.
	Type ObjectType `json:"type" toml:"type"`

	// Values contains country codes (RU, CN) or ASN numbers (AS15169).
	Values []string `json:"values" toml:"values"`

	// CachedCIDRs contains resolved CIDRs from GeoIP database.
	// This is populated by the GeoIP resolver service.
	CachedCIDRs []*net.IPNet `json:"-" toml:"-"`

	// LastResolved is when CIDRs were last fetched from database.
	LastResolved time.Time `json:"-" toml:"-"`

	// CacheTTL is how long (seconds) to cache the resolved CIDRs.
	CacheTTL int `json:"cache_ttl,omitempty" toml:"cache_ttl"`
}

// NewGeoObject creates a new GeoIP object.
func NewGeoObject(name string, objType ObjectType, values []string) *GeoObject {
	return &GeoObject{
		ID:     uuid.New(),
		Name:   name,
		Type:   objType,
		Values: values,
	}
}

// NeedsRefresh checks if the cached CIDRs need to be refreshed.
func (go_obj *GeoObject) NeedsRefresh() bool {
	if go_obj.CachedCIDRs == nil {
		return true
	}
	if go_obj.CacheTTL <= 0 {
		return false
	}
	return time.Since(go_obj.LastResolved) > time.Duration(go_obj.CacheTTL)*time.Second
}

// SetCachedCIDRs updates the cached CIDRs.
func (go_obj *GeoObject) SetCachedCIDRs(cidrs []*net.IPNet) {
	go_obj.CachedCIDRs = cidrs
	go_obj.LastResolved = time.Now()
}

// Contains checks if the given IP is in this GeoIP object.
// Requires CachedCIDRs to be populated by GeoIP resolver.
func (go_obj *GeoObject) Contains(ip net.IP) bool {
	for _, cidr := range go_obj.CachedCIDRs {
		if cidr.Contains(ip) {
			return true
		}
	}
	return false
}

// ============================================================================
// Object Collections
// ============================================================================

// ObjectCollection holds all reusable objects for rule references.
type ObjectCollection struct {
	AddressObjects map[string]*AddressObject `json:"address_objects,omitempty"`
	PortObjects    map[string]*PortObject    `json:"port_objects,omitempty"`
	DomainObjects  map[string]*DomainObject  `json:"domain_objects,omitempty"`
	ServiceObjects map[string]*ServiceObject `json:"service_objects,omitempty"`
	GeoObjects     map[string]*GeoObject     `json:"geo_objects,omitempty"`
}

// NewObjectCollection creates an empty object collection.
func NewObjectCollection() *ObjectCollection {
	return &ObjectCollection{
		AddressObjects: make(map[string]*AddressObject),
		PortObjects:    make(map[string]*PortObject),
		DomainObjects:  make(map[string]*DomainObject),
		ServiceObjects: make(map[string]*ServiceObject),
		GeoObjects:     make(map[string]*GeoObject),
	}
}

// GetAddressObject retrieves an address object by name.
func (oc *ObjectCollection) GetAddressObject(name string) (*AddressObject, bool) {
	obj, ok := oc.AddressObjects[name]
	return obj, ok
}

// GetPortObject retrieves a port object by name.
func (oc *ObjectCollection) GetPortObject(name string) (*PortObject, bool) {
	obj, ok := oc.PortObjects[name]
	return obj, ok
}

// GetDomainObject retrieves a domain object by name.
func (oc *ObjectCollection) GetDomainObject(name string) (*DomainObject, bool) {
	obj, ok := oc.DomainObjects[name]
	return obj, ok
}

// AddAddressObject adds an address object to the collection.
func (oc *ObjectCollection) AddAddressObject(obj *AddressObject) error {
	if err := obj.Initialize(); err != nil {
		return err
	}
	oc.AddressObjects[obj.Name] = obj
	return nil
}

// AddPortObject adds a port object to the collection.
func (oc *ObjectCollection) AddPortObject(obj *PortObject) error {
	if err := obj.Initialize(); err != nil {
		return err
	}
	oc.PortObjects[obj.Name] = obj
	return nil
}

// AddDomainObject adds a domain object to the collection.
func (oc *ObjectCollection) AddDomainObject(obj *DomainObject) error {
	if err := obj.Initialize(); err != nil {
		return err
	}
	oc.DomainObjects[obj.Name] = obj
	return nil
}

// MarshalJSON implements json.Marshaler.
func (oc *ObjectCollection) MarshalJSON() ([]byte, error) {
	type Alias ObjectCollection
	return json.Marshal((*Alias)(oc))
}
