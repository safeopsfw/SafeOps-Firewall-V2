// Package types provides NIC-specific type definitions including interface metadata,
// capabilities, driver information, states, and WiFi-specific configurations.
// These types map directly to database schema and gRPC proto definitions.
package types

import (
	"fmt"
	"time"
)

// =============================================================================
// Interface Classification Types
// =============================================================================

// InterfaceType represents the classification of a network interface.
type InterfaceType string

const (
	// InterfaceTypeWAN represents a Wide Area Network interface (internet-facing).
	InterfaceTypeWAN InterfaceType = "WAN"
	// InterfaceTypeLAN represents a Local Area Network interface.
	InterfaceTypeLAN InterfaceType = "LAN"
	// InterfaceTypeWIFI represents a wireless network interface.
	InterfaceTypeWIFI InterfaceType = "WIFI"
	// InterfaceTypeVIRTUAL represents a virtual network interface (VPN, bridge, etc.).
	InterfaceTypeVIRTUAL InterfaceType = "VIRTUAL"
	// InterfaceTypeLOOPBACK represents the loopback interface.
	InterfaceTypeLOOPBACK InterfaceType = "LOOPBACK"
	// InterfaceTypeBRIDGE represents a network bridge interface.
	InterfaceTypeBRIDGE InterfaceType = "BRIDGE"
	// InterfaceTypeUNKNOWN represents an unclassified interface.
	InterfaceTypeUNKNOWN InterfaceType = "UNKNOWN"
)

// IsValid returns true if the interface type is valid.
func (t InterfaceType) IsValid() bool {
	switch t {
	case InterfaceTypeWAN, InterfaceTypeLAN, InterfaceTypeWIFI, InterfaceTypeVIRTUAL,
		InterfaceTypeLOOPBACK, InterfaceTypeBRIDGE, InterfaceTypeUNKNOWN:
		return true
	default:
		return false
	}
}

// IsRoutable returns true if the interface type can route traffic.
func (t InterfaceType) IsRoutable() bool {
	return t == InterfaceTypeWAN || t == InterfaceTypeLAN || t == InterfaceTypeWIFI
}

// String returns the string representation.
func (t InterfaceType) String() string {
	return string(t)
}

// InterfaceRole represents the operational role of an interface.
type InterfaceRole string

const (
	// InterfaceRolePrimary is the primary active interface.
	InterfaceRolePrimary InterfaceRole = "PRIMARY"
	// InterfaceRoleBackup is a backup interface for failover.
	InterfaceRoleBackup InterfaceRole = "BACKUP"
	// InterfaceRoleLoadBalanced participates in load balancing.
	InterfaceRoleLoadBalanced InterfaceRole = "LOAD_BALANCED"
	// InterfaceRoleMonitorOnly is for monitoring only, no traffic routing.
	InterfaceRoleMonitorOnly InterfaceRole = "MONITOR_ONLY"
	// InterfaceRoleIsolated is isolated from other networks.
	InterfaceRoleIsolated InterfaceRole = "ISOLATED"
	// InterfaceRoleDisabled is administratively disabled.
	InterfaceRoleDisabled InterfaceRole = "DISABLED"
)

// =============================================================================
// Interface State Types
// =============================================================================

// InterfaceState represents the operational state of a network interface.
type InterfaceState string

const (
	// InterfaceStateUnknown indicates the state cannot be determined.
	InterfaceStateUnknown InterfaceState = "UNKNOWN"
	// InterfaceStateUP indicates the interface is up and operational.
	InterfaceStateUP InterfaceState = "UP"
	// InterfaceStateDOWN indicates the interface is down.
	InterfaceStateDOWN InterfaceState = "DOWN"
	// InterfaceStateDORMANT indicates the interface is dormant (waiting for carrier).
	InterfaceStateDORMANT InterfaceState = "DORMANT"
	// InterfaceStateERROR indicates the interface has an error.
	InterfaceStateERROR InterfaceState = "ERROR"
	// InterfaceStateNotPresent indicates the interface hardware is not present.
	InterfaceStateNotPresent InterfaceState = "NOT_PRESENT"
	// InterfaceStateLowerLayerDown indicates a lower layer (physical) is down.
	InterfaceStateLowerLayerDown InterfaceState = "LOWER_LAYER_DOWN"
)

// IsOperational returns true if the interface can transmit/receive traffic.
func (s InterfaceState) IsOperational() bool {
	return s == InterfaceStateUP
}

// String returns the string representation.
func (s InterfaceState) String() string {
	return string(s)
}

// DuplexMode represents the duplex mode of a network interface.
type DuplexMode string

const (
	// DuplexFull indicates full-duplex operation.
	DuplexFull DuplexMode = "FULL"
	// DuplexHalf indicates half-duplex operation.
	DuplexHalf DuplexMode = "HALF"
	// DuplexAuto indicates auto-negotiation.
	DuplexAuto DuplexMode = "AUTO"
	// DuplexUnknown indicates the duplex mode is unknown.
	DuplexUnknown DuplexMode = "UNKNOWN"
)

// =============================================================================
// Network Interface Struct
// =============================================================================

// NetworkInterface represents complete information about a network interface.
type NetworkInterface struct {
	// Identity
	ID          string `json:"id" yaml:"id" db:"id"`
	Name        string `json:"name" yaml:"name" db:"interface_name"`
	Alias       string `json:"alias,omitempty" yaml:"alias,omitempty" db:"alias"`
	Description string `json:"description,omitempty" yaml:"description,omitempty" db:"description"`

	// Classification
	Type InterfaceType `json:"type" yaml:"type" db:"interface_type"`
	Role InterfaceRole `json:"role,omitempty" yaml:"role,omitempty" db:"role"`

	// Network Configuration
	MACAddress  string   `json:"mac_address" yaml:"mac_address" db:"mac_address"`
	IPAddress   string   `json:"ip_address,omitempty" yaml:"ip_address,omitempty" db:"ip_address"`
	IPv6Address string   `json:"ipv6_address,omitempty" yaml:"ipv6_address,omitempty" db:"ipv6_address"`
	Netmask     string   `json:"netmask,omitempty" yaml:"netmask,omitempty" db:"netmask"`
	Gateway     string   `json:"gateway,omitempty" yaml:"gateway,omitempty" db:"gateway"`
	DNSServers  []string `json:"dns_servers,omitempty" yaml:"dns_servers,omitempty" db:"dns_servers"`
	MTU         int      `json:"mtu" yaml:"mtu" db:"mtu"`

	// Physical State
	State     InterfaceState `json:"state" yaml:"state" db:"state"`
	SpeedMbps int            `json:"speed_mbps,omitempty" yaml:"speed_mbps,omitempty" db:"speed_mbps"`
	Duplex    DuplexMode     `json:"duplex,omitempty" yaml:"duplex,omitempty" db:"duplex"`

	// Flags
	IsEnabled  bool `json:"is_enabled" yaml:"is_enabled" db:"is_enabled"`
	IsVirtual  bool `json:"is_virtual" yaml:"is_virtual" db:"is_virtual"`
	IsDHCP     bool `json:"is_dhcp" yaml:"is_dhcp" db:"is_dhcp"`
	IsWireless bool `json:"is_wireless" yaml:"is_wireless" db:"is_wireless"`

	// Driver Information
	DriverName      string `json:"driver_name,omitempty" yaml:"driver_name,omitempty" db:"driver_name"`
	DriverVersion   string `json:"driver_version,omitempty" yaml:"driver_version,omitempty" db:"driver_version"`
	FirmwareVersion string `json:"firmware_version,omitempty" yaml:"firmware_version,omitempty" db:"firmware_version"`
	PCIAddress      string `json:"pci_address,omitempty" yaml:"pci_address,omitempty" db:"pci_address"`
	HardwareID      string `json:"hardware_id,omitempty" yaml:"hardware_id,omitempty" db:"hardware_id"`
	VendorName      string `json:"vendor_name,omitempty" yaml:"vendor_name,omitempty" db:"vendor_name"`
	DeviceModel     string `json:"device_model,omitempty" yaml:"device_model,omitempty" db:"device_model"`

	// WiFi-specific fields (only populated for wireless interfaces)
	WiFiInfo *WiFiInterfaceInfo `json:"wifi_info,omitempty" yaml:"wifi_info,omitempty"`

	// VLAN Configuration
	VLANInfo *VLANConfig `json:"vlan_info,omitempty" yaml:"vlan_info,omitempty"`

	// Timestamps
	CreatedAt time.Time `json:"created_at" yaml:"created_at" db:"created_at"`
	UpdatedAt time.Time `json:"updated_at" yaml:"updated_at" db:"updated_at"`
}

// IsWAN returns true if this is a WAN interface.
func (n *NetworkInterface) IsWAN() bool {
	return n.Type == InterfaceTypeWAN
}

// IsLAN returns true if this is a LAN interface.
func (n *NetworkInterface) IsLAN() bool {
	return n.Type == InterfaceTypeLAN
}

// IsWiFi returns true if this is a WiFi interface.
func (n *NetworkInterface) IsWiFi() bool {
	return n.Type == InterfaceTypeWIFI || n.IsWireless
}

// IsUp returns true if the interface is operational.
func (n *NetworkInterface) IsUp() bool {
	return n.State == InterfaceStateUP && n.IsEnabled
}

// DisplayName returns the alias if available, otherwise the system name.
func (n *NetworkInterface) DisplayName() string {
	if n.Alias != "" {
		return n.Alias
	}
	return n.Name
}

// =============================================================================
// WiFi Interface Types
// =============================================================================

// WiFiBand represents the WiFi frequency band.
type WiFiBand string

const (
	WiFiBand2_4GHz WiFiBand = "2.4GHz"
	WiFiBand5GHz   WiFiBand = "5GHz"
	WiFiBand6GHz   WiFiBand = "6GHz" // WiFi 6E
	WiFiBandDual   WiFiBand = "dual"
	WiFiBandTri    WiFiBand = "tri" // 2.4 + 5 + 6 GHz
)

// WiFiMode represents the WiFi operational mode.
type WiFiMode string

const (
	// WiFiModeStation is client/station mode (connecting to AP).
	WiFiModeStation WiFiMode = "STATION"
	// WiFiModeAP is access point mode.
	WiFiModeAP WiFiMode = "AP"
	// WiFiModeAdhoc is peer-to-peer ad-hoc mode.
	WiFiModeAdhoc WiFiMode = "ADHOC"
	// WiFiModeMonitor is monitor/promiscuous mode.
	WiFiModeMonitor WiFiMode = "MONITOR"
	// WiFiModeMesh is mesh networking mode.
	WiFiModeMesh WiFiMode = "MESH"
)

// WiFiSecurity represents the WiFi security protocol.
type WiFiSecurity string

const (
	WiFiSecurityOpen    WiFiSecurity = "OPEN"
	WiFiSecurityWEP     WiFiSecurity = "WEP"
	WiFiSecurityWPA     WiFiSecurity = "WPA"
	WiFiSecurityWPA2    WiFiSecurity = "WPA2"
	WiFiSecurityWPA3    WiFiSecurity = "WPA3"
	WiFiSecurityWPAWPA2 WiFiSecurity = "WPA/WPA2"
)

// WiFiInterfaceInfo contains WiFi-specific interface information.
type WiFiInterfaceInfo struct {
	// Current connection details (Station mode)
	SSID           string       `json:"ssid,omitempty" yaml:"ssid,omitempty"`
	BSSID          string       `json:"bssid,omitempty" yaml:"bssid,omitempty"` // AP MAC address
	Security       WiFiSecurity `json:"security,omitempty" yaml:"security,omitempty"`
	SignalStrength int          `json:"signal_strength,omitempty" yaml:"signal_strength,omitempty"` // dBm
	SignalQuality  int          `json:"signal_quality,omitempty" yaml:"signal_quality,omitempty"`   // 0-100%
	NoiseLevel     int          `json:"noise_level,omitempty" yaml:"noise_level,omitempty"`         // dBm

	// Physical layer
	Mode         WiFiMode `json:"mode" yaml:"mode"`
	Band         WiFiBand `json:"band,omitempty" yaml:"band,omitempty"`
	Channel      int      `json:"channel,omitempty" yaml:"channel,omitempty"`
	ChannelWidth int      `json:"channel_width,omitempty" yaml:"channel_width,omitempty"` // MHz (20, 40, 80, 160)
	Frequency    float64  `json:"frequency,omitempty" yaml:"frequency,omitempty"`         // MHz

	// Data rates
	TxRate  float64 `json:"tx_rate,omitempty" yaml:"tx_rate,omitempty"`   // Mbps
	RxRate  float64 `json:"rx_rate,omitempty" yaml:"rx_rate,omitempty"`   // Mbps
	MaxRate float64 `json:"max_rate,omitempty" yaml:"max_rate,omitempty"` // Mbps

	// Capabilities
	SupportedBands    []WiFiBand     `json:"supported_bands,omitempty" yaml:"supported_bands,omitempty"`
	SupportedModes    []WiFiMode     `json:"supported_modes,omitempty" yaml:"supported_modes,omitempty"`
	SupportedSecurity []WiFiSecurity `json:"supported_security,omitempty" yaml:"supported_security,omitempty"`
	SupportsAP        bool           `json:"supports_ap" yaml:"supports_ap"`
	SupportsMonitor   bool           `json:"supports_monitor" yaml:"supports_monitor"`
	Supports80211ac   bool           `json:"supports_80211ac" yaml:"supports_80211ac"` // WiFi 5
	Supports80211ax   bool           `json:"supports_80211ax" yaml:"supports_80211ax"` // WiFi 6
	Supports80211be   bool           `json:"supports_80211be" yaml:"supports_80211be"` // WiFi 7

	// Access Point mode settings (when in AP mode)
	APConfig *WiFiAPConfig `json:"ap_config,omitempty" yaml:"ap_config,omitempty"`

	// Connected clients (when in AP mode)
	ConnectedClients int `json:"connected_clients,omitempty" yaml:"connected_clients,omitempty"`
}

// WiFiAPConfig represents access point configuration.
type WiFiAPConfig struct {
	SSID           string       `json:"ssid" yaml:"ssid"`
	HiddenSSID     bool         `json:"hidden_ssid" yaml:"hidden_ssid"`
	Security       WiFiSecurity `json:"security" yaml:"security"`
	Password       string       `json:"-" yaml:"-"` // Never serialize password
	Band           WiFiBand     `json:"band" yaml:"band"`
	Channel        int          `json:"channel" yaml:"channel"`
	ChannelWidth   int          `json:"channel_width" yaml:"channel_width"`
	MaxClients     int          `json:"max_clients" yaml:"max_clients"`
	Enabled        bool         `json:"enabled" yaml:"enabled"`
	CountryCode    string       `json:"country_code" yaml:"country_code"`       // ISO 3166 country code
	BeaconInterval int          `json:"beacon_interval" yaml:"beacon_interval"` // ms
}

// WiFiClient represents a connected WiFi client.
type WiFiClient struct {
	MACAddress     string    `json:"mac_address"`
	IPAddress      string    `json:"ip_address,omitempty"`
	Hostname       string    `json:"hostname,omitempty"`
	SignalStrength int       `json:"signal_strength"` // dBm
	TxRate         float64   `json:"tx_rate"`         // Mbps
	RxRate         float64   `json:"rx_rate"`         // Mbps
	ConnectedAt    time.Time `json:"connected_at"`
	LastActivity   time.Time `json:"last_activity"`
	RxBytes        uint64    `json:"rx_bytes"`
	TxBytes        uint64    `json:"tx_bytes"`
}

// WiFiScanResult represents a scanned WiFi network.
type WiFiScanResult struct {
	SSID           string       `json:"ssid"`
	BSSID          string       `json:"bssid"`
	SignalStrength int          `json:"signal_strength"` // dBm
	SignalQuality  int          `json:"signal_quality"`  // 0-100%
	Channel        int          `json:"channel"`
	Frequency      float64      `json:"frequency"` // MHz
	Band           WiFiBand     `json:"band"`
	Security       WiFiSecurity `json:"security"`
	IsSecured      bool         `json:"is_secured"`
	ScannedAt      time.Time    `json:"scanned_at"`
}

// =============================================================================
// VLAN Configuration
// =============================================================================

// VLANConfig represents VLAN configuration for an interface.
type VLANConfig struct {
	Enabled   bool   `json:"enabled" yaml:"enabled"`
	ID        int    `json:"id" yaml:"id"`                                 // VLAN ID (1-4094)
	Name      string `json:"name" yaml:"name"`                             // VLAN name
	ParentNIC string `json:"parent_nic" yaml:"parent_nic"`                 // Parent interface
	Priority  int    `json:"priority,omitempty" yaml:"priority,omitempty"` // 802.1p priority (0-7)
}

// IsValid returns true if the VLAN configuration is valid.
func (v *VLANConfig) IsValid() bool {
	return v.ID >= 1 && v.ID <= 4094
}

// =============================================================================
// Interface Capabilities
// =============================================================================

// InterfaceCapabilities represents hardware capabilities of an interface.
type InterfaceCapabilities struct {
	// Speed and Duplex
	MaxSpeedMbps         int          `json:"max_speed_mbps" yaml:"max_speed_mbps"`
	SupportedSpeeds      []int        `json:"supported_speeds,omitempty" yaml:"supported_speeds,omitempty"` // Mbps
	SupportedDuplexModes []DuplexMode `json:"supported_duplex_modes,omitempty" yaml:"supported_duplex_modes,omitempty"`
	AutoNegotiation      bool         `json:"auto_negotiation" yaml:"auto_negotiation"`

	// MTU
	MaxMTU      int  `json:"max_mtu" yaml:"max_mtu"`
	MinMTU      int  `json:"min_mtu" yaml:"min_mtu"`
	JumboFrames bool `json:"jumbo_frames" yaml:"jumbo_frames"`

	// VLAN
	SupportsVLAN bool `json:"supports_vlan" yaml:"supports_vlan"`
	MaxVLANs     int  `json:"max_vlans,omitempty" yaml:"max_vlans,omitempty"`

	// Offload Features
	HardwareChecksumOffload bool `json:"hardware_checksum_offload" yaml:"hardware_checksum_offload"`
	TSOEnabled              bool `json:"tso_enabled" yaml:"tso_enabled"` // TCP Segmentation Offload
	GSOEnabled              bool `json:"gso_enabled" yaml:"gso_enabled"` // Generic Segmentation Offload
	GROEnabled              bool `json:"gro_enabled" yaml:"gro_enabled"` // Generic Receive Offload
	LROEnabled              bool `json:"lro_enabled" yaml:"lro_enabled"` // Large Receive Offload
	ScatterGather           bool `json:"scatter_gather" yaml:"scatter_gather"`

	// Queues
	TxQueueLength int `json:"tx_queue_length,omitempty" yaml:"tx_queue_length,omitempty"`
	RxQueueLength int `json:"rx_queue_length,omitempty" yaml:"rx_queue_length,omitempty"`
	NumTxQueues   int `json:"num_tx_queues,omitempty" yaml:"num_tx_queues,omitempty"`
	NumRxQueues   int `json:"num_rx_queues,omitempty" yaml:"num_rx_queues,omitempty"`

	// Advanced
	SupportsWakeOnLAN  bool `json:"supports_wake_on_lan" yaml:"supports_wake_on_lan"`
	SupportsTimestamps bool `json:"supports_timestamps" yaml:"supports_timestamps"` // Hardware timestamps
	SupportsBPF        bool `json:"supports_bpf" yaml:"supports_bpf"`               // BPF/XDP support
}

// =============================================================================
// Driver Information
// =============================================================================

// DriverInfo contains network driver and firmware information.
type DriverInfo struct {
	DriverName      string `json:"driver_name" yaml:"driver_name" db:"driver_name"`
	DriverVersion   string `json:"driver_version" yaml:"driver_version" db:"driver_version"`
	FirmwareVersion string `json:"firmware_version" yaml:"firmware_version" db:"firmware_version"`
	PCIAddress      string `json:"pci_address,omitempty" yaml:"pci_address,omitempty" db:"pci_address"`
	USBAddress      string `json:"usb_address,omitempty" yaml:"usb_address,omitempty"`
	HardwareID      string `json:"hardware_id,omitempty" yaml:"hardware_id,omitempty" db:"hardware_id"`
	VendorID        string `json:"vendor_id,omitempty" yaml:"vendor_id,omitempty"`
	DeviceID        string `json:"device_id,omitempty" yaml:"device_id,omitempty"`
	SubsystemID     string `json:"subsystem_id,omitempty" yaml:"subsystem_id,omitempty"`
	VendorName      string `json:"vendor_name,omitempty" yaml:"vendor_name,omitempty"`
	DeviceModel     string `json:"device_model,omitempty" yaml:"device_model,omitempty"`
	IsVirtual       bool   `json:"is_virtual" yaml:"is_virtual"`
	BusType         string `json:"bus_type,omitempty" yaml:"bus_type,omitempty"` // PCI, USB, virtual
}

// String returns a human-readable description of the driver.
func (d *DriverInfo) String() string {
	return fmt.Sprintf("%s (%s v%s)", d.DeviceModel, d.DriverName, d.DriverVersion)
}

// =============================================================================
// Interface Statistics
// =============================================================================

// InterfaceStatistics contains performance metrics for an interface.
type InterfaceStatistics struct {
	InterfaceID   string `json:"interface_id" db:"interface_id"`
	InterfaceName string `json:"interface_name" db:"interface_name"`

	// Byte counters
	RxBytes uint64 `json:"rx_bytes" db:"rx_bytes"`
	TxBytes uint64 `json:"tx_bytes" db:"tx_bytes"`

	// Packet counters
	RxPackets uint64 `json:"rx_packets" db:"rx_packets"`
	TxPackets uint64 `json:"tx_packets" db:"tx_packets"`

	// Error counters
	RxErrors  uint64 `json:"rx_errors" db:"rx_errors"`
	TxErrors  uint64 `json:"tx_errors" db:"tx_errors"`
	RxDropped uint64 `json:"rx_dropped" db:"rx_dropped"`
	TxDropped uint64 `json:"tx_dropped" db:"tx_dropped"`

	// Additional counters
	Multicast  uint64 `json:"multicast" db:"multicast"`
	Collisions uint64 `json:"collisions" db:"collisions"`
	RxOverrun  uint64 `json:"rx_overrun,omitempty" db:"rx_overrun"`
	TxCarrier  uint64 `json:"tx_carrier,omitempty" db:"tx_carrier"`

	// Throughput (calculated rates)
	ThroughputRxBps  uint64  `json:"throughput_rx_bps" db:"throughput_rx_bps"`
	ThroughputTxBps  uint64  `json:"throughput_tx_bps" db:"throughput_tx_bps"`
	ThroughputRxMbps float64 `json:"throughput_rx_mbps"`
	ThroughputTxMbps float64 `json:"throughput_tx_mbps"`

	// Packet rates
	PacketRateRxPps uint64 `json:"packet_rate_rx_pps" db:"packet_rate_rx_pps"`
	PacketRateTxPps uint64 `json:"packet_rate_tx_pps" db:"packet_rate_tx_pps"`

	// Utilization
	UtilizationPercent float64 `json:"utilization_percent,omitempty"`
	ErrorRatePercent   float64 `json:"error_rate_percent,omitempty"`

	// Active connections (if tracked)
	ActiveConnections int `json:"active_connections,omitempty" db:"active_connections"`

	// Timestamp
	CollectedAt time.Time `json:"collected_at" db:"collected_at"`
}

// CalculateThroughputMbps calculates the throughput in Mbps from bps values.
func (s *InterfaceStatistics) CalculateThroughputMbps() {
	s.ThroughputRxMbps = float64(s.ThroughputRxBps) / 1_000_000
	s.ThroughputTxMbps = float64(s.ThroughputTxBps) / 1_000_000
}

// TotalBytes returns the total bytes transferred (rx + tx).
func (s *InterfaceStatistics) TotalBytes() uint64 {
	return s.RxBytes + s.TxBytes
}

// TotalPackets returns the total packets transferred (rx + tx).
func (s *InterfaceStatistics) TotalPackets() uint64 {
	return s.RxPackets + s.TxPackets
}

// TotalErrors returns the total error count (rx + tx).
func (s *InterfaceStatistics) TotalErrors() uint64 {
	return s.RxErrors + s.TxErrors
}

// =============================================================================
// Interface Detection Types
// =============================================================================

// InterfaceDetectionHint provides hints for automatic interface classification.
type InterfaceDetectionHint struct {
	NamePatterns   []string `json:"name_patterns" yaml:"name_patterns"`             // e.g., ["eth*", "enp*"]
	DriverPatterns []string `json:"driver_patterns" yaml:"driver_patterns"`         // e.g., ["e1000*", "rtl*"]
	HasGateway     bool     `json:"has_gateway" yaml:"has_gateway"`                 // Has default gateway
	HasPublicIP    bool     `json:"has_public_ip" yaml:"has_public_ip"`             // Has public IP address
	IsWireless     bool     `json:"is_wireless" yaml:"is_wireless"`                 // Is wireless interface
	PCIClass       string   `json:"pci_class,omitempty" yaml:"pci_class,omitempty"` // PCI device class
}

// WiFiDetectionPatterns contains patterns for detecting WiFi interfaces.
var WiFiDetectionPatterns = InterfaceDetectionHint{
	NamePatterns: []string{
		"wlan*",     // Linux wireless
		"wlp*",      // Linux predictable naming
		"wlx*",      // Linux USB wireless
		"Wi-Fi*",    // Windows
		"Wireless*", // Windows
		"ath*",      // Atheros
		"iwl*",      // Intel Wireless
		"brcm*",     // Broadcom
		"rt*wlan*",  // Ralink/MediaTek
	},
	DriverPatterns: []string{
		"iwlwifi",  // Intel
		"ath9k",    // Atheros
		"ath10k",   // Atheros 802.11ac
		"ath11k",   // Atheros 802.11ax
		"brcmfmac", // Broadcom FullMAC
		"brcmsmac", // Broadcom SoftMAC
		"rt2800*",  // Ralink
		"mt76*",    // MediaTek
		"rtl8*",    // Realtek
		"rtw*",     // Realtek newer
	},
	IsWireless: true,
}

// =============================================================================
// Interface List and Summary
// =============================================================================

// InterfaceList represents a list of interfaces with summary counts.
type InterfaceList struct {
	Interfaces []NetworkInterface `json:"interfaces"`
	TotalCount int                `json:"total_count"`
	WANCount   int                `json:"wan_count"`
	LANCount   int                `json:"lan_count"`
	WiFiCount  int                `json:"wifi_count"`
	UpCount    int                `json:"up_count"`
	DownCount  int                `json:"down_count"`
}

// NewInterfaceList creates an InterfaceList from a slice of interfaces.
func NewInterfaceList(interfaces []NetworkInterface) *InterfaceList {
	list := &InterfaceList{
		Interfaces: interfaces,
		TotalCount: len(interfaces),
	}

	for _, iface := range interfaces {
		switch iface.Type {
		case InterfaceTypeWAN:
			list.WANCount++
		case InterfaceTypeLAN:
			list.LANCount++
		case InterfaceTypeWIFI:
			list.WiFiCount++
		}

		if iface.State == InterfaceStateUP {
			list.UpCount++
		} else {
			list.DownCount++
		}
	}

	return list
}
