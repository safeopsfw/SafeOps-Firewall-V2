// Package config provides configuration loading, parsing, and validation
// for the firewall engine. It loads rules, objects, and settings from TOML files.
//
// The configuration system supports:
// - firewall.toml: Main firewall rules, policies, and objects
// - firewall_objects.toml: Additional reusable objects
// - Engine settings via YAML (for engine-specific configuration)
//
// Configuration is thread-safe and supports hot-reload.
package config

import (
	"fmt"
	"sync"
	"time"

	"firewall_engine/pkg/models"
)

// ============================================================================
// Main Configuration Structure
// ============================================================================

// Config represents the complete firewall configuration.
// This is the top-level structure that aggregates all configuration sections.
type Config struct {
	mu sync.RWMutex

	// === Core Settings ===

	// DefaultPolicies defines fallback actions when no rule matches.
	DefaultPolicies *DefaultPoliciesConfig `toml:"default_policies" json:"default_policies"`

	// ConnectionTracking configures stateful inspection.
	ConnectionTracking *ConnectionTrackingConfig `toml:"connection_tracking" json:"connection_tracking"`

	// === Security Zones ===

	// SecurityZones defines zone-based firewall grouping.
	SecurityZones *SecurityZonesConfig `toml:"security_zones" json:"security_zones"`

	// === Objects ===

	// AddressObjects are reusable IP/CIDR collections.
	AddressObjects []*AddressObjectConfig `toml:"address_objects" json:"address_objects,omitempty"`

	// PortObjects are reusable port collections.
	PortObjects []*PortObjectConfig `toml:"port_objects" json:"port_objects,omitempty"`

	// ServiceObjects are reusable service definitions (protocol + port).
	ServiceObjects []*ServiceObjectConfig `toml:"service_objects" json:"service_objects,omitempty"`

	// DomainObjects are reusable domain pattern collections.
	DomainObjects []*DomainObjectConfig `toml:"domain_objects" json:"domain_objects,omitempty"`

	// === Rules ===

	// RuleGroups organizes rules into logical groups.
	RuleGroups []*RuleGroupConfig `toml:"rule_groups" json:"rule_groups,omitempty"`

	// Rules contains individual firewall rules.
	Rules []*RuleConfig `toml:"rules" json:"rules,omitempty"`

	// === NAT ===

	// NAT configures Network Address Translation.
	NAT *NATConfig `toml:"nat" json:"nat,omitempty"`

	// PortForwarding configures inbound port forwarding.
	PortForwarding *PortForwardingConfig `toml:"port_forwarding" json:"port_forwarding,omitempty"`

	// === Advanced ===

	// Advanced contains additional firewall behavior settings.
	Advanced *AdvancedConfig `toml:"advanced" json:"advanced,omitempty"`

	// === Metadata ===

	// LoadedAt is when this configuration was loaded.
	LoadedAt time.Time `json:"loaded_at,omitempty"`

	// SourceFile is the path to the main configuration file.
	SourceFile string `json:"source_file,omitempty"`

	// Version is the configuration schema version.
	Version string `toml:"version" json:"version,omitempty"`
}

// ============================================================================
// Default Policies Configuration
// ============================================================================

// DefaultPoliciesConfig defines fallback actions when no rule matches.
type DefaultPoliciesConfig struct {
	// DefaultInboundPolicy is the action for inbound traffic.
	// Valid values: "ALLOW", "DENY", "REJECT"
	DefaultInboundPolicy string `toml:"default_inbound_policy" json:"default_inbound_policy"`

	// DefaultOutboundPolicy is the action for outbound traffic.
	DefaultOutboundPolicy string `toml:"default_outbound_policy" json:"default_outbound_policy"`

	// DefaultForwardPolicy is the action for forwarded traffic.
	DefaultForwardPolicy string `toml:"default_forward_policy" json:"default_forward_policy"`

	// PolicyLogEnabled logs packets that hit default policies.
	PolicyLogEnabled bool `toml:"policy_log_enabled" json:"policy_log_enabled"`

	// RejectWithICMP sends ICMP unreachable for REJECT action.
	RejectWithICMP bool `toml:"reject_with_icmp" json:"reject_with_icmp"`
}

// ToModel converts to the models.DefaultPolicies type.
func (dp *DefaultPoliciesConfig) ToModel() (*models.DefaultPolicies, error) {
	inbound, err := models.VerdictFromString(dp.DefaultInboundPolicy)
	if err != nil {
		return nil, fmt.Errorf("invalid inbound policy: %w", err)
	}

	outbound, err := models.VerdictFromString(dp.DefaultOutboundPolicy)
	if err != nil {
		return nil, fmt.Errorf("invalid outbound policy: %w", err)
	}

	forward := models.VerdictBlock
	if dp.DefaultForwardPolicy != "" {
		forward, err = models.VerdictFromString(dp.DefaultForwardPolicy)
		if err != nil {
			return nil, fmt.Errorf("invalid forward policy: %w", err)
		}
	}

	return &models.DefaultPolicies{
		InboundPolicy:    inbound,
		OutboundPolicy:   outbound,
		ForwardPolicy:    forward,
		PolicyLogEnabled: dp.PolicyLogEnabled,
		RejectWithICMP:   dp.RejectWithICMP,
	}, nil
}

// ============================================================================
// Connection Tracking Configuration
// ============================================================================

// ConnectionTrackingConfig configures stateful packet inspection.
type ConnectionTrackingConfig struct {
	// ConnectionTrackingEnabled enables stateful inspection.
	ConnectionTrackingEnabled bool `toml:"connection_tracking_enabled" json:"connection_tracking_enabled"`

	// TrackTCPState tracks TCP connection states.
	TrackTCPState bool `toml:"track_tcp_state" json:"track_tcp_state"`

	// TrackUDPState enables pseudo-stateful UDP tracking.
	TrackUDPState bool `toml:"track_udp_state" json:"track_udp_state"`

	// TrackICMPState enables ICMP request/reply matching.
	TrackICMPState bool `toml:"track_icmp_state" json:"track_icmp_state"`

	// ConnectionTimeoutTCP is the TCP established timeout (seconds).
	ConnectionTimeoutTCP int `toml:"connection_timeout_tcp" json:"connection_timeout_tcp"`

	// ConnectionTimeoutUDP is the UDP session timeout (seconds).
	ConnectionTimeoutUDP int `toml:"connection_timeout_udp" json:"connection_timeout_udp"`

	// ConnectionTimeoutICMP is the ICMP timeout (seconds).
	ConnectionTimeoutICMP int `toml:"connection_timeout_icmp" json:"connection_timeout_icmp"`

	// MaxConnections is the maximum tracked connections.
	MaxConnections int `toml:"max_connections" json:"max_connections"`

	// CleanupIntervalSeconds is how often to clean expired connections.
	// Default: 300 (5 minutes). Minimum: 30.
	CleanupIntervalSeconds int `toml:"cleanup_interval_seconds" json:"cleanup_interval_seconds"`

	// ConnectionLogging logs connection state changes.
	ConnectionLogging bool `toml:"connection_logging" json:"connection_logging"`
}

// ============================================================================
// Security Zones Configuration
// ============================================================================

// SecurityZonesConfig defines zone-based firewall grouping.
type SecurityZonesConfig struct {
	// Zones is the list of security zones.
	Zones []*ZoneConfig `toml:"zones" json:"zones,omitempty"`

	// InterZoneDefaults defines default policies between zones.
	InterZoneDefaults map[string]string `toml:"inter_zone_defaults" json:"inter_zone_defaults,omitempty"`
}

// ZoneConfig defines a security zone.
type ZoneConfig struct {
	// ZoneName is the unique zone identifier.
	ZoneName string `toml:"zone_name" json:"zone_name"`

	// Interfaces is the list of interfaces in this zone.
	Interfaces []string `toml:"interfaces" json:"interfaces"`

	// Description describes the zone's purpose.
	Description string `toml:"description" json:"description,omitempty"`
}

// ============================================================================
// Object Configurations
// ============================================================================

// AddressObjectConfig defines a reusable address collection.
type AddressObjectConfig struct {
	// ObjectName is the unique name for referencing.
	ObjectName string `toml:"object_name" json:"object_name"`

	// Description describes the object's purpose.
	Description string `toml:"description" json:"description,omitempty"`

	// Type is the object type (CIDR_LIST, IP_LIST, IP_RANGE, GEO).
	Type string `toml:"type" json:"type,omitempty"`

	// Addresses contains the IP addresses or CIDRs.
	Addresses []string `toml:"addresses" json:"addresses,omitempty"`

	// Values is an alias for addresses (for GeoIP compatibility).
	Values []string `toml:"values" json:"values,omitempty"`
}

// ToModel converts to models.AddressObject.
func (ao *AddressObjectConfig) ToModel() *models.AddressObject {
	addrs := ao.Addresses
	if len(addrs) == 0 {
		addrs = ao.Values
	}

	obj := models.NewAddressObject(ao.ObjectName, addrs)
	obj.Description = ao.Description
	if ao.Type != "" {
		obj.Type = models.ObjectType(ao.Type)
	}
	return obj
}

// PortObjectConfig defines a reusable port collection.
type PortObjectConfig struct {
	// ObjectName is the unique name for referencing.
	ObjectName string `toml:"object_name" json:"object_name"`

	// Description describes the object's purpose.
	Description string `toml:"description" json:"description,omitempty"`

	// Protocol specifies TCP, UDP, or BOTH.
	Protocol string `toml:"protocol" json:"protocol,omitempty"`

	// Ports contains the port numbers.
	Ports []int `toml:"ports" json:"ports"`

	// PortRanges contains port range strings ("1000-2000").
	PortRanges []string `toml:"port_ranges" json:"port_ranges,omitempty"`
}

// ToModel converts to models.PortObject.
func (po *PortObjectConfig) ToModel() *models.PortObject {
	obj := models.NewPortObject(po.ObjectName, po.Ports)
	obj.Description = po.Description
	obj.Protocol = po.Protocol
	obj.PortRanges = po.PortRanges
	return obj
}

// ServiceObjectConfig defines a service (protocol + port).
type ServiceObjectConfig struct {
	// ObjectName is the unique name for referencing.
	ObjectName string `toml:"object_name" json:"object_name"`

	// Description describes the service.
	Description string `toml:"description" json:"description,omitempty"`

	// Protocol is the IP protocol (TCP, UDP).
	Protocol string `toml:"protocol" json:"protocol"`

	// Ports contains the port numbers.
	Ports []int `toml:"ports" json:"ports"`
}

// ToModel converts to models.ServiceObject.
func (so *ServiceObjectConfig) ToModel() *models.ServiceObject {
	return models.NewServiceObject(so.ObjectName, so.Protocol, so.Ports)
}

// DomainObjectConfig defines a reusable domain pattern collection.
type DomainObjectConfig struct {
	// ObjectName is the unique name for referencing.
	ObjectName string `toml:"object_name" json:"object_name"`

	// Description describes the object's purpose.
	Description string `toml:"description" json:"description,omitempty"`

	// Values contains the domain patterns.
	Values []string `toml:"values" json:"values"`
}

// ToModel converts to models.DomainObject.
func (do *DomainObjectConfig) ToModel() *models.DomainObject {
	obj := models.NewDomainObject(do.ObjectName, do.Values)
	obj.Description = do.Description
	return obj
}

// ============================================================================
// Rule Group Configuration
// ============================================================================

// RuleGroupConfig defines a logical group of rules.
type RuleGroupConfig struct {
	// GroupName is the unique group identifier.
	GroupName string `toml:"group_name" json:"group_name"`

	// Description describes the group's purpose.
	Description string `toml:"description" json:"description,omitempty"`

	// Enabled indicates if rules in this group are active.
	Enabled bool `toml:"enabled" json:"enabled"`

	// Priority determines group evaluation order (lower = higher priority).
	Priority int `toml:"priority" json:"priority"`
}

// ToModel converts to models.RuleGroup.
func (rg *RuleGroupConfig) ToModel() *models.RuleGroup {
	group := models.NewRuleGroup(rg.GroupName, rg.Priority)
	group.Description = rg.Description
	group.Enabled = rg.Enabled
	return group
}

// ============================================================================
// Rule Configuration
// ============================================================================

// RuleConfig defines a single firewall rule.
type RuleConfig struct {
	// RuleID is the numeric rule ID.
	RuleID int `toml:"rule_id" json:"rule_id"`

	// RuleName is the human-readable rule name.
	RuleName string `toml:"rule_name" json:"rule_name"`

	// Enabled indicates if this rule is active.
	Enabled bool `toml:"enabled" json:"enabled"`

	// Group is the rule group this belongs to.
	Group string `toml:"group" json:"group,omitempty"`

	// Priority determines evaluation order within the group.
	Priority int `toml:"priority" json:"priority"`

	// Action is the verdict (ALLOW, DENY, DROP, REDIRECT, REJECT).
	Action string `toml:"action" json:"action"`

	// Direction is INBOUND, OUTBOUND, or ANY.
	Direction string `toml:"direction" json:"direction"`

	// Protocol is TCP, UDP, ICMP, or ANY.
	Protocol string `toml:"protocol" json:"protocol"`

	// SourceAddress is the source IP/CIDR or object reference.
	SourceAddress string `toml:"source_address" json:"source_address,omitempty"`

	// SourcePort is the source port(s).
	SourcePort []int `toml:"source_port" json:"source_port,omitempty"`

	// DestinationAddress is the destination IP/CIDR or object reference.
	DestinationAddress string `toml:"destination_address" json:"destination_address,omitempty"`

	// DestinationPort is the destination port(s).
	DestinationPort []int `toml:"destination_port" json:"destination_port,omitempty"`

	// Domain is the domain pattern to match.
	Domain string `toml:"domain" json:"domain,omitempty"`

	// Interface is the network interface (WAN, LAN, WIFI).
	Interface string `toml:"interface" json:"interface,omitempty"`

	// State is the connection state filter (NEW, ESTABLISHED, RELATED).
	State string `toml:"state" json:"state,omitempty"`

	// LogEnabled logs rule matches.
	LogEnabled bool `toml:"log_enabled" json:"log_enabled"`

	// Description explains the rule's purpose.
	Description string `toml:"description" json:"description,omitempty"`

	// RedirectIP is the destination IP for REDIRECT rules.
	RedirectIP string `toml:"redirect_ip" json:"redirect_ip,omitempty"`

	// RedirectPort is the destination port for REDIRECT rules.
	RedirectPort int `toml:"redirect_port" json:"redirect_port,omitempty"`
}

// ToModel converts to models.FirewallRule.
func (rc *RuleConfig) ToModel() (*models.FirewallRule, error) {
	rule := models.NewFirewallRule(rc.RuleName)
	rule.RuleID = rc.RuleID
	rule.Enabled = rc.Enabled
	rule.GroupName = rc.Group
	rule.Priority = rc.Priority
	rule.Description = rc.Description
	rule.LogEnabled = rc.LogEnabled

	// Parse action
	action, err := models.VerdictFromString(rc.Action)
	if err != nil {
		return nil, fmt.Errorf("rule %q: invalid action %q: %w", rc.RuleName, rc.Action, err)
	}
	rule.Action = action

	// Parse direction
	if rc.Direction != "" {
		dir, err := models.DirectionFromString(rc.Direction)
		if err != nil {
			return nil, fmt.Errorf("rule %q: invalid direction %q: %w", rc.RuleName, rc.Direction, err)
		}
		rule.Direction = dir
	}

	// Parse protocol
	if rc.Protocol != "" {
		proto, err := models.ProtocolFromString(rc.Protocol)
		if err != nil {
			return nil, fmt.Errorf("rule %q: invalid protocol %q: %w", rc.RuleName, rc.Protocol, err)
		}
		rule.Protocol = proto
	}

	// Copy address/port matchers
	rule.SourceAddress = rc.SourceAddress
	rule.SourcePort = rc.SourcePort
	rule.DestinationAddress = rc.DestinationAddress
	rule.DestinationPort = rc.DestinationPort
	rule.Domain = rc.Domain
	rule.Interface = rc.Interface
	rule.State = rc.State
	rule.RedirectIP = rc.RedirectIP
	rule.RedirectPort = uint16(rc.RedirectPort)

	// Initialize computed fields
	if err := rule.Initialize(); err != nil {
		return nil, fmt.Errorf("rule %q: %w", rc.RuleName, err)
	}

	return rule, nil
}

// ============================================================================
// NAT Configuration
// ============================================================================

// NATConfig configures Network Address Translation.
type NATConfig struct {
	// NATEnabled enables NAT functionality.
	NATEnabled bool `toml:"nat_enabled" json:"nat_enabled"`

	// Rules contains NAT rules.
	Rules []*NATRuleConfig `toml:"rules" json:"rules,omitempty"`
}

// NATRuleConfig defines a single NAT rule.
type NATRuleConfig struct {
	// NATType is MASQUERADE, SNAT, or DNAT.
	NATType string `toml:"nat_type" json:"nat_type"`

	// Interface is the network interface.
	Interface string `toml:"interface" json:"interface"`

	// SourceAddress is the source address to match.
	SourceAddress string `toml:"source_address" json:"source_address,omitempty"`

	// DestinationPort is the destination port to match.
	DestinationPort int `toml:"destination_port" json:"destination_port,omitempty"`

	// TranslatedAddress is the translated destination (for DNAT).
	TranslatedAddress string `toml:"translated_address" json:"translated_address,omitempty"`

	// TranslatedPort is the translated port (for DNAT).
	TranslatedPort int `toml:"translated_port" json:"translated_port,omitempty"`

	// Protocol is the IP protocol.
	Protocol string `toml:"protocol" json:"protocol,omitempty"`

	// Enabled indicates if this rule is active.
	Enabled bool `toml:"enabled" json:"enabled"`

	// Description explains the rule's purpose.
	Description string `toml:"description" json:"description,omitempty"`
}

// ============================================================================
// Port Forwarding Configuration
// ============================================================================

// PortForwardingConfig configures inbound port forwarding.
type PortForwardingConfig struct {
	// Forwards contains port forwarding rules.
	Forwards []*PortForwardConfig `toml:"forwards" json:"forwards,omitempty"`
}

// PortForwardConfig defines a single port forward.
type PortForwardConfig struct {
	// ExternalPort is the external (WAN) port.
	ExternalPort int `toml:"external_port" json:"external_port"`

	// InternalAddress is the internal (LAN) destination.
	InternalAddress string `toml:"internal_address" json:"internal_address"`

	// InternalPort is the internal destination port.
	InternalPort int `toml:"internal_port" json:"internal_port"`

	// Protocol is TCP, UDP, or BOTH.
	Protocol string `toml:"protocol" json:"protocol"`

	// Enabled indicates if this forward is active.
	Enabled bool `toml:"enabled" json:"enabled"`

	// Description explains the forward's purpose.
	Description string `toml:"description" json:"description,omitempty"`
}

// ============================================================================
// Advanced Configuration
// ============================================================================

// AdvancedConfig contains additional firewall behavior settings.
type AdvancedConfig struct {
	// FragmentHandling is DROP, ALLOW, or REASSEMBLE.
	FragmentHandling string `toml:"fragment_handling" json:"fragment_handling,omitempty"`

	// InvalidPacketAction is DROP or LOG_AND_DROP.
	InvalidPacketAction string `toml:"invalid_packet_action" json:"invalid_packet_action,omitempty"`

	// StrictTCPValidation enforces RFC-compliant TCP state.
	StrictTCPValidation bool `toml:"strict_tcp_validation" json:"strict_tcp_validation"`

	// ICMPRateLimit is ICMP packets per second (0 = unlimited).
	ICMPRateLimit int `toml:"icmp_rate_limit" json:"icmp_rate_limit,omitempty"`

	// LogMartianPackets logs packets with invalid source addresses.
	LogMartianPackets bool `toml:"log_martian_packets" json:"log_martian_packets"`

	// RPFCheck is STRICT, LOOSE, or DISABLED.
	RPFCheck string `toml:"rpf_check" json:"rpf_check,omitempty"`

	// SYNFloodProtection is connections per second (0 = disabled).
	SYNFloodProtection int `toml:"syn_flood_protection" json:"syn_flood_protection,omitempty"`
}

// ============================================================================
// Config Methods
// ============================================================================

// NewConfig creates a new empty configuration.
func NewConfig() *Config {
	return &Config{
		DefaultPolicies:    &DefaultPoliciesConfig{},
		ConnectionTracking: &ConnectionTrackingConfig{},
		SecurityZones:      &SecurityZonesConfig{},
		AddressObjects:     make([]*AddressObjectConfig, 0),
		PortObjects:        make([]*PortObjectConfig, 0),
		ServiceObjects:     make([]*ServiceObjectConfig, 0),
		DomainObjects:      make([]*DomainObjectConfig, 0),
		RuleGroups:         make([]*RuleGroupConfig, 0),
		Rules:              make([]*RuleConfig, 0),
		NAT:                &NATConfig{},
		PortForwarding:     &PortForwardingConfig{},
		Advanced:           &AdvancedConfig{},
		LoadedAt:           time.Now(),
	}
}

// RuleCount returns the total number of rules.
func (c *Config) RuleCount() int {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return len(c.Rules)
}

// ObjectCount returns the total number of objects.
func (c *Config) ObjectCount() int {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return len(c.AddressObjects) + len(c.PortObjects) +
		len(c.ServiceObjects) + len(c.DomainObjects)
}

// GetRuleGroup returns the rule group configuration by name.
func (c *Config) GetRuleGroup(name string) *RuleGroupConfig {
	c.mu.RLock()
	defer c.mu.RUnlock()
	for _, group := range c.RuleGroups {
		if group.GroupName == name {
			return group
		}
	}
	return nil
}

// GetRulesForGroup returns all rules belonging to a group.
func (c *Config) GetRulesForGroup(groupName string) []*RuleConfig {
	c.mu.RLock()
	defer c.mu.RUnlock()

	var rules []*RuleConfig
	for _, rule := range c.Rules {
		if rule.Group == groupName {
			rules = append(rules, rule)
		}
	}
	return rules
}
