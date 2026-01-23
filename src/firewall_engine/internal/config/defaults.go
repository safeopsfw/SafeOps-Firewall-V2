// Package config provides configuration loading, parsing, and validation.
package config

import (
	"firewall_engine/pkg/models"
)

// ============================================================================
// Default Configuration Values
// ============================================================================

// Default timeout values in seconds.
const (
	// DefaultTCPTimeout is the default TCP established connection timeout.
	DefaultTCPTimeout = 3600 // 1 hour

	// DefaultUDPTimeout is the default UDP session timeout.
	DefaultUDPTimeout = 180 // 3 minutes

	// DefaultICMPTimeout is the default ICMP timeout.
	DefaultICMPTimeout = 30 // 30 seconds

	// DefaultMaxConnections is the default max tracked connections.
	DefaultMaxConnections = 1000000 // 1 million

	// DefaultICMPRateLimit is the default ICMP rate limit.
	DefaultICMPRateLimit = 100 // 100 packets/second

	// DefaultCacheTTL is the default verdict cache TTL.
	DefaultCacheTTL = 60 // 60 seconds

	// DefaultCacheSize is the default verdict cache size.
	DefaultCacheSize = 100000 // 100K entries
)

// Default policy values.
const (
	// DefaultInboundPolicy is the default inbound action.
	DefaultInboundPolicy = "DENY"

	// DefaultOutboundPolicy is the default outbound action.
	DefaultOutboundPolicy = "ALLOW"

	// DefaultForwardPolicy is the default forward action.
	DefaultForwardPolicy = "DENY"

	// DefaultFragmentHandling is the default fragment handling mode.
	DefaultFragmentHandling = "REASSEMBLE"

	// DefaultInvalidPacketAction is the default invalid packet action.
	DefaultInvalidPacketAction = "LOG_AND_DROP"

	// DefaultRPFCheck is the default reverse path forwarding check mode.
	DefaultRPFCheck = "STRICT"
)

// Defaults returns a Config with sensible default values.
// These defaults provide a secure baseline configuration.
func Defaults() *Config {
	return &Config{
		DefaultPolicies: &DefaultPoliciesConfig{
			DefaultInboundPolicy:  DefaultInboundPolicy,
			DefaultOutboundPolicy: DefaultOutboundPolicy,
			DefaultForwardPolicy:  DefaultForwardPolicy,
			PolicyLogEnabled:      true,
			RejectWithICMP:        true,
		},

		ConnectionTracking: &ConnectionTrackingConfig{
			ConnectionTrackingEnabled: true,
			TrackTCPState:             true,
			TrackUDPState:             true,
			TrackICMPState:            true,
			ConnectionTimeoutTCP:      DefaultTCPTimeout,
			ConnectionTimeoutUDP:      DefaultUDPTimeout,
			ConnectionTimeoutICMP:     DefaultICMPTimeout,
			MaxConnections:            DefaultMaxConnections,
			ConnectionLogging:         false, // Off by default for performance
		},

		SecurityZones: &SecurityZonesConfig{
			Zones: []*ZoneConfig{
				{
					ZoneName:    "WAN",
					Interfaces:  []string{"Ethernet"},
					Description: "Internet-facing zone",
				},
				{
					ZoneName:    "LAN",
					Interfaces:  []string{"Ethernet 2"},
					Description: "Trusted internal network",
				},
				{
					ZoneName:    "WIFI",
					Interfaces:  []string{"Wi-Fi"},
					Description: "Wireless network",
				},
			},
			InterZoneDefaults: map[string]string{
				"WAN_to_LAN":   "DENY",
				"WAN_to_WIFI":  "DENY",
				"LAN_to_WAN":   "ALLOW",
				"LAN_to_WIFI":  "ALLOW",
				"WIFI_to_WAN":  "ALLOW",
				"WIFI_to_LAN":  "DENY",
				"WIFI_to_WIFI": "DENY", // Client isolation
			},
		},

		AddressObjects: DefaultAddressObjects(),
		PortObjects:    DefaultPortObjects(),
		ServiceObjects: DefaultServiceObjects(),
		DomainObjects:  make([]*DomainObjectConfig, 0),
		RuleGroups:     DefaultRuleGroups(),
		Rules:          make([]*RuleConfig, 0),

		NAT: &NATConfig{
			NATEnabled: true,
			Rules:      make([]*NATRuleConfig, 0),
		},

		PortForwarding: &PortForwardingConfig{
			Forwards: make([]*PortForwardConfig, 0),
		},

		Advanced: &AdvancedConfig{
			FragmentHandling:    DefaultFragmentHandling,
			InvalidPacketAction: DefaultInvalidPacketAction,
			StrictTCPValidation: true,
			ICMPRateLimit:       DefaultICMPRateLimit,
			LogMartianPackets:   true,
			RPFCheck:            DefaultRPFCheck,
			SYNFloodProtection:  0, // Disabled, handled by DDoS protection
		},
	}
}

// DefaultAddressObjects returns commonly used address objects.
func DefaultAddressObjects() []*AddressObjectConfig {
	return []*AddressObjectConfig{
		{
			ObjectName:  "RFC1918_PRIVATE",
			Description: "Private IP address ranges (RFC 1918)",
			Type:        "CIDR_LIST",
			Addresses: []string{
				"10.0.0.0/8",
				"172.16.0.0/12",
				"192.168.0.0/16",
			},
		},
		{
			ObjectName:  "BOGON_ADDRESSES",
			Description: "Invalid/reserved addresses that should never appear on WAN",
			Type:        "CIDR_LIST",
			Addresses: []string{
				"0.0.0.0/8",
				"10.0.0.0/8",
				"127.0.0.0/8",
				"169.254.0.0/16",
				"172.16.0.0/12",
				"192.0.0.0/24",
				"192.0.2.0/24",
				"192.168.0.0/16",
				"198.18.0.0/15",
				"198.51.100.0/24",
				"203.0.113.0/24",
				"224.0.0.0/4",
				"240.0.0.0/4",
			},
		},
		{
			ObjectName:  "TRUSTED_DNS",
			Description: "Trusted DNS servers",
			Type:        "IP_LIST",
			Addresses: []string{
				"8.8.8.8",        // Google DNS
				"8.8.4.4",        // Google DNS
				"1.1.1.1",        // Cloudflare DNS
				"1.0.0.1",        // Cloudflare DNS
				"9.9.9.9",        // Quad9 DNS
				"208.67.222.222", // OpenDNS
			},
		},
		{
			ObjectName:  "MULTICAST",
			Description: "Multicast address range",
			Type:        "CIDR_LIST",
			Addresses: []string{
				"224.0.0.0/4",
			},
		},
		{
			ObjectName:  "LINK_LOCAL",
			Description: "Link-local addresses (APIPA)",
			Type:        "CIDR_LIST",
			Addresses: []string{
				"169.254.0.0/16",
			},
		},
	}
}

// DefaultPortObjects returns commonly used port objects.
func DefaultPortObjects() []*PortObjectConfig {
	return []*PortObjectConfig{
		{
			ObjectName:  "WEB_PORTS",
			Description: "HTTP and HTTPS ports",
			Protocol:    "TCP",
			Ports:       []int{80, 443},
		},
		{
			ObjectName:  "WEB_EXTENDED",
			Description: "Extended web ports including common alternatives",
			Protocol:    "TCP",
			Ports:       []int{80, 443, 8080, 8443},
		},
		{
			ObjectName:  "MAIL_PORTS",
			Description: "Email service ports",
			Protocol:    "TCP",
			Ports:       []int{25, 110, 143, 465, 587, 993, 995},
		},
		{
			ObjectName:  "DNS_PORTS",
			Description: "DNS service ports",
			Protocol:    "BOTH",
			Ports:       []int{53},
		},
		{
			ObjectName:  "MANAGEMENT_PORTS",
			Description: "Management service ports (SSH, RDP)",
			Protocol:    "TCP",
			Ports:       []int{22, 3389},
		},
		{
			ObjectName:  "DHCP_PORTS",
			Description: "DHCP service ports",
			Protocol:    "UDP",
			Ports:       []int{67, 68},
		},
		{
			ObjectName:  "NTP_PORTS",
			Description: "Network Time Protocol ports",
			Protocol:    "UDP",
			Ports:       []int{123},
		},
		{
			ObjectName:  "HIGH_PORTS",
			Description: "Ephemeral/high ports range",
			Protocol:    "BOTH",
			PortRanges:  []string{"1024-65535"},
		},
	}
}

// DefaultServiceObjects returns commonly used service objects.
func DefaultServiceObjects() []*ServiceObjectConfig {
	return []*ServiceObjectConfig{
		{
			ObjectName:  "HTTPS",
			Description: "HTTPS web traffic",
			Protocol:    "TCP",
			Ports:       []int{443},
		},
		{
			ObjectName:  "HTTP",
			Description: "HTTP web traffic",
			Protocol:    "TCP",
			Ports:       []int{80},
		},
		{
			ObjectName:  "DNS",
			Description: "DNS queries",
			Protocol:    "UDP",
			Ports:       []int{53},
		},
		{
			ObjectName:  "DNS_TCP",
			Description: "DNS over TCP (zone transfers, large queries)",
			Protocol:    "TCP",
			Ports:       []int{53},
		},
		{
			ObjectName:  "NTP",
			Description: "Network Time Protocol",
			Protocol:    "UDP",
			Ports:       []int{123},
		},
		{
			ObjectName:  "SSH",
			Description: "Secure Shell",
			Protocol:    "TCP",
			Ports:       []int{22},
		},
		{
			ObjectName:  "RDP",
			Description: "Remote Desktop Protocol",
			Protocol:    "TCP",
			Ports:       []int{3389},
		},
		{
			ObjectName:  "ICMP",
			Description: "ICMP (ping, traceroute)",
			Protocol:    "ICMP",
			Ports:       []int{},
		},
	}
}

// DefaultRuleGroups returns the default rule groups.
func DefaultRuleGroups() []*RuleGroupConfig {
	return []*RuleGroupConfig{
		{
			GroupName:   "anti_spoofing",
			Description: "Anti-spoofing and bogon filtering",
			Enabled:     true,
			Priority:    100,
		},
		{
			GroupName:   "management",
			Description: "Management access rules",
			Enabled:     true,
			Priority:    200,
		},
		{
			GroupName:   "services",
			Description: "Network service rules (DNS, NTP, DHCP)",
			Enabled:     true,
			Priority:    300,
		},
		{
			GroupName:   "outbound_internet",
			Description: "Outbound internet access rules",
			Enabled:     true,
			Priority:    400,
		},
		{
			GroupName:   "port_forwards",
			Description: "Inbound port forwarding rules",
			Enabled:     true,
			Priority:    500,
		},
		{
			GroupName:   "custom",
			Description: "User-defined custom rules",
			Enabled:     true,
			Priority:    900,
		},
	}
}

// MergeWithDefaults merges the loaded configuration with defaults.
// Missing values are filled with defaults.
func MergeWithDefaults(cfg *Config) *Config {
	defaults := Defaults()

	if cfg == nil {
		return defaults
	}

	// Merge default policies
	if cfg.DefaultPolicies == nil {
		cfg.DefaultPolicies = defaults.DefaultPolicies
	} else {
		if cfg.DefaultPolicies.DefaultInboundPolicy == "" {
			cfg.DefaultPolicies.DefaultInboundPolicy = defaults.DefaultPolicies.DefaultInboundPolicy
		}
		if cfg.DefaultPolicies.DefaultOutboundPolicy == "" {
			cfg.DefaultPolicies.DefaultOutboundPolicy = defaults.DefaultPolicies.DefaultOutboundPolicy
		}
		if cfg.DefaultPolicies.DefaultForwardPolicy == "" {
			cfg.DefaultPolicies.DefaultForwardPolicy = defaults.DefaultPolicies.DefaultForwardPolicy
		}
	}

	// Merge connection tracking
	if cfg.ConnectionTracking == nil {
		cfg.ConnectionTracking = defaults.ConnectionTracking
	} else {
		if cfg.ConnectionTracking.ConnectionTimeoutTCP == 0 {
			cfg.ConnectionTracking.ConnectionTimeoutTCP = defaults.ConnectionTracking.ConnectionTimeoutTCP
		}
		if cfg.ConnectionTracking.ConnectionTimeoutUDP == 0 {
			cfg.ConnectionTracking.ConnectionTimeoutUDP = defaults.ConnectionTracking.ConnectionTimeoutUDP
		}
		if cfg.ConnectionTracking.ConnectionTimeoutICMP == 0 {
			cfg.ConnectionTracking.ConnectionTimeoutICMP = defaults.ConnectionTracking.ConnectionTimeoutICMP
		}
		if cfg.ConnectionTracking.MaxConnections == 0 {
			cfg.ConnectionTracking.MaxConnections = defaults.ConnectionTracking.MaxConnections
		}
	}

	// Merge advanced
	if cfg.Advanced == nil {
		cfg.Advanced = defaults.Advanced
	} else {
		if cfg.Advanced.FragmentHandling == "" {
			cfg.Advanced.FragmentHandling = defaults.Advanced.FragmentHandling
		}
		if cfg.Advanced.InvalidPacketAction == "" {
			cfg.Advanced.InvalidPacketAction = defaults.Advanced.InvalidPacketAction
		}
		if cfg.Advanced.RPFCheck == "" {
			cfg.Advanced.RPFCheck = defaults.Advanced.RPFCheck
		}
		if cfg.Advanced.ICMPRateLimit == 0 {
			cfg.Advanced.ICMPRateLimit = defaults.Advanced.ICMPRateLimit
		}
	}

	// Merge security zones if empty
	if cfg.SecurityZones == nil || len(cfg.SecurityZones.Zones) == 0 {
		cfg.SecurityZones = defaults.SecurityZones
	}

	// Initialize nil collections
	if cfg.AddressObjects == nil {
		cfg.AddressObjects = make([]*AddressObjectConfig, 0)
	}
	if cfg.PortObjects == nil {
		cfg.PortObjects = make([]*PortObjectConfig, 0)
	}
	if cfg.ServiceObjects == nil {
		cfg.ServiceObjects = make([]*ServiceObjectConfig, 0)
	}
	if cfg.DomainObjects == nil {
		cfg.DomainObjects = make([]*DomainObjectConfig, 0)
	}
	if cfg.RuleGroups == nil {
		cfg.RuleGroups = make([]*RuleGroupConfig, 0)
	}
	if cfg.Rules == nil {
		cfg.Rules = make([]*RuleConfig, 0)
	}
	if cfg.NAT == nil {
		cfg.NAT = defaults.NAT
	}
	if cfg.PortForwarding == nil {
		cfg.PortForwarding = defaults.PortForwarding
	}

	return cfg
}

// DefaultModels returns default models ready for use.
type DefaultModels struct {
	Policies       *models.DefaultPolicies
	AddressObjects map[string]*models.AddressObject
	PortObjects    map[string]*models.PortObject
	ServiceObjects map[string]*models.ServiceObject
}

// ToDefaultModels converts default config to initialized models.
func ToDefaultModels() (*DefaultModels, error) {
	cfg := Defaults()

	policies, err := cfg.DefaultPolicies.ToModel()
	if err != nil {
		return nil, err
	}

	dm := &DefaultModels{
		Policies:       policies,
		AddressObjects: make(map[string]*models.AddressObject),
		PortObjects:    make(map[string]*models.PortObject),
		ServiceObjects: make(map[string]*models.ServiceObject),
	}

	// Initialize address objects
	for _, ao := range cfg.AddressObjects {
		obj := ao.ToModel()
		if err := obj.Initialize(); err != nil {
			return nil, err
		}
		dm.AddressObjects[obj.Name] = obj
	}

	// Initialize port objects
	for _, po := range cfg.PortObjects {
		obj := po.ToModel()
		if err := obj.Initialize(); err != nil {
			return nil, err
		}
		dm.PortObjects[obj.Name] = obj
	}

	// Initialize service objects
	for _, so := range cfg.ServiceObjects {
		obj := so.ToModel()
		if err := obj.Initialize(); err != nil {
			return nil, err
		}
		dm.ServiceObjects[obj.Name] = obj
	}

	return dm, nil
}
