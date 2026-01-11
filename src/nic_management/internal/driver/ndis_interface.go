//go:build windows
// +build windows

// Package driver implements Windows NDIS wrapper for low-level network interface
// control and configuration. It provides direct access to Windows network driver
// capabilities including interface state management, speed/duplex configuration,
// hardware address retrieval, and driver statistics.
package driver

import (
	"fmt"
	"net"
	"strings"
	"sync"
	"syscall"
	"time"
	"unsafe"

	"github.com/StackExchange/wmi"
	"golang.org/x/sys/windows"

	"safeops/nic_management/pkg/types"
)

// =============================================================================
// Windows DLL and Procedure Declarations
// =============================================================================

var (
	// Use different names to avoid conflict with iphlpapi_wrapper.go
	ndisModiphlpapi = windows.NewLazySystemDLL("iphlpapi.dll")
	ndisModnetapi32 = windows.NewLazySystemDLL("netapi32.dll")

	ndisProcGetAdaptersInfo       = ndisModiphlpapi.NewProc("GetAdaptersInfo")
	ndisProcGetIfTable            = ndisModiphlpapi.NewProc("GetIfTable")
	ndisProcSetIfEntry            = ndisModiphlpapi.NewProc("SetIfEntry")
	ndisProcGetIfEntry            = ndisModiphlpapi.NewProc("GetIfEntry")
	ndisProcGetNumberOfInterfaces = ndisModiphlpapi.NewProc("GetNumberOfInterfaces")
)

// =============================================================================
// Constants
// =============================================================================

const (
	// Interface admin status
	IF_ADMIN_STATUS_UP   = 1
	IF_ADMIN_STATUS_DOWN = 2

	// Interface oper status
	IF_OPER_STATUS_UP          = 1
	IF_OPER_STATUS_DOWN        = 2
	IF_OPER_STATUS_TESTING     = 3
	IF_OPER_STATUS_UNKNOWN     = 4
	IF_OPER_STATUS_DORMANT     = 5
	IF_OPER_STATUS_NOT_PRESENT = 6
	IF_OPER_STATUS_LOWER_DOWN  = 7

	// Interface types
	IF_TYPE_ETHERNET  = 6
	IF_TYPE_LOOPBACK  = 24
	IF_TYPE_TUNNEL    = 131
	IF_TYPE_IEEE80211 = 71 // WiFi

	// Max lengths
	MAX_INTERFACE_NAME_LEN         = 256
	MAX_ADAPTER_NAME_LENGTH        = 256
	MAX_ADAPTER_DESCRIPTION_LENGTH = 128
	MAX_ADAPTER_ADDRESS_LENGTH     = 8

	// Error codes - use package-level constants from iphlpapi_wrapper.go
	// ERROR_BUFFER_OVERFLOW and ERROR_SUCCESS are defined there
)

// =============================================================================
// Windows API Structures
// =============================================================================

// MIB_IFROW represents a row in the interface table (MIB-II ifTable)
type MIB_IFROW struct {
	Name            [MAX_INTERFACE_NAME_LEN]uint16
	Index           uint32
	Type            uint32
	Mtu             uint32
	Speed           uint32
	PhysAddrLen     uint32
	PhysAddr        [MAX_ADAPTER_ADDRESS_LENGTH]byte
	AdminStatus     uint32
	OperStatus      uint32
	LastChange      uint32
	InOctets        uint32
	InUcastPkts     uint32
	InNUcastPkts    uint32
	InDiscards      uint32
	InErrors        uint32
	InUnknownProtos uint32
	OutOctets       uint32
	OutUcastPkts    uint32
	OutNUcastPkts   uint32
	OutDiscards     uint32
	OutErrors       uint32
	OutQLen         uint32
	DescrLen        uint32
	Descr           [256]byte
}

// MIB_IFTABLE represents the interface table
type MIB_IFTABLE struct {
	NumEntries uint32
	Table      [1]MIB_IFROW // Variable length array
}

// IP_ADAPTER_INFO represents adapter information from GetAdaptersInfo
type IP_ADAPTER_INFO struct {
	Next                *IP_ADAPTER_INFO
	ComboIndex          uint32
	AdapterName         [MAX_ADAPTER_NAME_LENGTH + 4]byte
	Description         [MAX_ADAPTER_DESCRIPTION_LENGTH + 4]byte
	AddressLength       uint32
	Address             [MAX_ADAPTER_ADDRESS_LENGTH]byte
	Index               uint32
	Type                uint32
	DhcpEnabled         uint32
	CurrentIpAddress    *IP_ADDR_STRING
	IpAddressList       IP_ADDR_STRING
	GatewayList         IP_ADDR_STRING
	DhcpServer          IP_ADDR_STRING
	HaveWins            uint32
	PrimaryWinsServer   IP_ADDR_STRING
	SecondaryWinsServer IP_ADDR_STRING
	LeaseObtained       int64
	LeaseExpires        int64
}

// IP_ADDR_STRING represents an IP address string
type IP_ADDR_STRING struct {
	Next      *IP_ADDR_STRING
	IpAddress [16]byte
	IpMask    [16]byte
	Context   uint32
}

// =============================================================================
// NDISInterface Structure
// =============================================================================

// NDISInterface represents an NDIS network adapter.
type NDISInterface struct {
	Index       uint32 `json:"index"`
	GUID        string `json:"guid"`
	Name        string `json:"name"`
	Description string `json:"description"`
	MACAddress  string `json:"mac_address"`
	AdminStatus uint32 `json:"admin_status"`
	OperStatus  uint32 `json:"oper_status"`
	Speed       uint64 `json:"speed_bps"`
	MTU         uint32 `json:"mtu"`
	Type        uint32 `json:"type"`
	IsPhysical  bool   `json:"is_physical"`
	IsEnabled   bool   `json:"is_enabled"`
	IsConnected bool   `json:"is_connected"`
}

// Type aliases for compatibility - use types from pkg/types for full versions
// These local types are for NDIS-specific data that maps to the full types
type (
	// InterfaceStatistics is an alias to types.InterfaceStatistics
	InterfaceStatistics = types.InterfaceStatistics
	// DriverInfo is an alias to types.DriverInfo
	DriverInfo = types.DriverInfo
	// InterfaceCapabilities is an alias to types.InterfaceCapabilities
	InterfaceCapabilities = types.InterfaceCapabilities
)

// =============================================================================
// WMI Structures
// =============================================================================

// Win32_NetworkAdapter represents WMI network adapter info
type Win32_NetworkAdapter struct {
	AdapterType         string
	AdapterTypeID       uint16
	AutoSense           bool
	Availability        uint16
	Caption             string
	Description         string
	DeviceID            string
	GUID                string
	Index               uint32
	Installed           bool
	InterfaceIndex      uint32
	MACAddress          string
	Manufacturer        string
	MaxSpeed            uint64
	Name                string
	NetConnectionID     string
	NetConnectionStatus uint16
	NetEnabled          bool
	PhysicalAdapter     bool
	PNPDeviceID         string
	ProductName         string
	ServiceName         string
	Speed               uint64
	TimeOfLastReset     time.Time
}

// Win32_NetworkAdapterConfiguration represents WMI adapter config
type Win32_NetworkAdapterConfiguration struct {
	Index                uint32
	Description          string
	DHCPEnabled          bool
	IPAddress            []string
	IPSubnet             []string
	DefaultIPGateway     []string
	DNSServerSearchOrder []string
	MACAddress           string
	MTU                  uint32
}

// =============================================================================
// NDIS Interface Enumeration
// =============================================================================

var enumMutex sync.Mutex

// EnumerateNDISInterfaces discovers all NDIS network adapters.
func EnumerateNDISInterfaces() ([]*NDISInterface, error) {
	enumMutex.Lock()
	defer enumMutex.Unlock()

	// Query WMI for network adapters
	var adapters []Win32_NetworkAdapter
	query := "SELECT * FROM Win32_NetworkAdapter WHERE NetConnectionID IS NOT NULL"
	err := wmi.Query(query, &adapters)
	if err != nil {
		return nil, fmt.Errorf("WMI query failed: %w", err)
	}

	interfaces := make([]*NDISInterface, 0, len(adapters))

	for _, adapter := range adapters {
		iface := &NDISInterface{
			Index:       adapter.InterfaceIndex,
			GUID:        adapter.GUID,
			Name:        adapter.NetConnectionID,
			Description: adapter.Description,
			MACAddress:  adapter.MACAddress,
			Speed:       adapter.Speed,
			Type:        uint32(adapter.AdapterTypeID),
			IsPhysical:  adapter.PhysicalAdapter,
			IsEnabled:   adapter.NetEnabled,
			IsConnected: adapter.NetConnectionStatus == 2, // Connected
		}

		// Get additional info from GetIfTable
		ifRow, err := getIfRowByIndex(adapter.InterfaceIndex)
		if err == nil {
			iface.MTU = ifRow.Mtu
			iface.AdminStatus = ifRow.AdminStatus
			iface.OperStatus = ifRow.OperStatus
			if iface.MACAddress == "" && ifRow.PhysAddrLen > 0 {
				iface.MACAddress = formatMACAddress(ifRow.PhysAddr[:ifRow.PhysAddrLen])
			}
		}

		interfaces = append(interfaces, iface)
	}

	return interfaces, nil
}

// EnumerateAllInterfaces gets all interfaces from the system interface table.
func EnumerateAllInterfaces() ([]*NDISInterface, error) {
	enumMutex.Lock()
	defer enumMutex.Unlock()

	// Get number of interfaces
	var numIfaces uint32
	ret, _, _ := ndisProcGetNumberOfInterfaces.Call(uintptr(unsafe.Pointer(&numIfaces)))
	if ret != 0 {
		return nil, fmt.Errorf("GetNumberOfInterfaces failed: %d", ret)
	}

	// Allocate buffer for interface table
	bufSize := uint32(unsafe.Sizeof(MIB_IFTABLE{})) + uint32(numIfaces)*uint32(unsafe.Sizeof(MIB_IFROW{}))
	buf := make([]byte, bufSize)

	ret, _, _ = ndisProcGetIfTable.Call(
		uintptr(unsafe.Pointer(&buf[0])),
		uintptr(unsafe.Pointer(&bufSize)),
		0, // Don't sort
	)

	if ret != 0 && ret != ERROR_BUFFER_OVERFLOW {
		return nil, fmt.Errorf("GetIfTable failed: %d", ret)
	}

	// Parse the table
	table := (*MIB_IFTABLE)(unsafe.Pointer(&buf[0]))
	interfaces := make([]*NDISInterface, 0, table.NumEntries)

	// Use slice header trick to avoid pointer arithmetic warning
	// This creates a slice view over the variable-length array
	rowSize := int(unsafe.Sizeof(MIB_IFROW{}))
	tableOffset := int(unsafe.Offsetof(table.Table))

	for i := uint32(0); i < table.NumEntries; i++ {
		// Calculate offset within buffer and cast to MIB_IFROW
		offset := tableOffset + int(i)*rowSize
		row := (*MIB_IFROW)(unsafe.Pointer(&buf[offset]))

		iface := &NDISInterface{
			Index:       row.Index,
			Description: bytesToString(row.Descr[:row.DescrLen]),
			Name:        syscall.UTF16ToString(row.Name[:]),
			MACAddress:  formatMACAddress(row.PhysAddr[:row.PhysAddrLen]),
			AdminStatus: row.AdminStatus,
			OperStatus:  row.OperStatus,
			Speed:       uint64(row.Speed),
			MTU:         row.Mtu,
			Type:        row.Type,
			IsEnabled:   row.AdminStatus == IF_ADMIN_STATUS_UP,
			IsConnected: row.OperStatus == IF_OPER_STATUS_UP,
			IsPhysical:  row.Type == IF_TYPE_ETHERNET || row.Type == IF_TYPE_IEEE80211,
		}

		interfaces = append(interfaces, iface)
	}

	return interfaces, nil
}

// getIfRowByIndex retrieves interface info by index.
func getIfRowByIndex(index uint32) (*MIB_IFROW, error) {
	row := &MIB_IFROW{Index: index}
	ret, _, _ := ndisProcGetIfEntry.Call(uintptr(unsafe.Pointer(row)))
	if ret != 0 {
		return nil, fmt.Errorf("GetIfEntry failed for index %d: %d", index, ret)
	}
	return row, nil
}

// =============================================================================
// Interface State Management
// =============================================================================

// SetInterfaceState enables or disables an interface.
// Requires administrator privileges.
func SetInterfaceState(interfaceIndex uint32, enabled bool) error {
	row, err := getIfRowByIndex(interfaceIndex)
	if err != nil {
		return err
	}

	if enabled {
		row.AdminStatus = IF_ADMIN_STATUS_UP
	} else {
		row.AdminStatus = IF_ADMIN_STATUS_DOWN
	}

	ret, _, _ := ndisProcSetIfEntry.Call(uintptr(unsafe.Pointer(row)))
	if ret != 0 {
		return fmt.Errorf("SetIfEntry failed: %d (may require administrator privileges)", ret)
	}

	return nil
}

// EnableInterface brings an interface up.
func EnableInterface(interfaceIndex uint32) error {
	return SetInterfaceState(interfaceIndex, true)
}

// DisableInterface brings an interface down.
func DisableInterface(interfaceIndex uint32) error {
	return SetInterfaceState(interfaceIndex, false)
}

// =============================================================================
// Speed and Duplex Configuration
// =============================================================================

// DuplexMode represents interface duplex setting
type DuplexMode string

const (
	DuplexAuto DuplexMode = "AUTO"
	DuplexFull DuplexMode = "FULL"
	DuplexHalf DuplexMode = "HALF"
)

// SetSpeedAndDuplex configures interface link speed and duplex mode.
// Note: Not all adapters support manual speed/duplex configuration.
// speedMbps: Link speed in Mbps (10, 100, 1000, 10000, 0 for auto)
// duplex: "AUTO", "FULL", or "HALF"
func SetSpeedAndDuplex(interfaceIndex uint32, speedMbps int, duplex DuplexMode) error {
	// Get adapter GUID for WMI query
	guid, err := IndexToGUID(interfaceIndex)
	if err != nil {
		return fmt.Errorf("failed to get adapter GUID: %w", err)
	}

	// Query WMI for adapter to check if it supports manual configuration
	var adapters []Win32_NetworkAdapter
	query := fmt.Sprintf("SELECT * FROM Win32_NetworkAdapter WHERE GUID = '%s'", guid)
	err = wmi.Query(query, &adapters)
	if err != nil {
		return fmt.Errorf("WMI query failed: %w", err)
	}

	if len(adapters) == 0 {
		return fmt.Errorf("adapter not found for index %d", interfaceIndex)
	}

	adapter := adapters[0]

	// Validate speed against max supported
	if speedMbps > 0 {
		maxSpeedMbps := adapter.MaxSpeed / 1000000
		if uint64(speedMbps) > maxSpeedMbps && maxSpeedMbps > 0 {
			return fmt.Errorf("requested speed %d Mbps exceeds max supported %d Mbps", speedMbps, maxSpeedMbps)
		}
	}

	// Validate duplex mode
	switch duplex {
	case DuplexAuto, DuplexFull, DuplexHalf:
		// Valid
	default:
		return fmt.Errorf("invalid duplex mode: %s (use AUTO, FULL, or HALF)", duplex)
	}

	// Note: Windows does not directly support setting speed/duplex via standard APIs.
	// This typically requires driver-specific registry modifications or netsh commands.
	// For most adapters, autonegotiation is preferred and manual override may not work.

	// Attempt via netsh (requires admin privileges)
	// This is a best-effort approach as not all drivers support this
	if speedMbps == 0 && duplex == DuplexAuto {
		// Auto-negotiation - this is the default and usually works
		return nil
	}

	// For manual speed/duplex, we would need to modify registry settings
	// at HKLM\SYSTEM\CurrentControlSet\Control\Class\{4d36e972-...}\<instance>\*SpeedDuplex
	// This is driver-specific and not reliably cross-compatible

	return fmt.Errorf("manual speed/duplex configuration requires driver-specific registry changes; "+
		"use Device Manager or adapter properties instead (requested: %d Mbps, %s)", speedMbps, duplex)
}

// GetSpeedAndDuplex retrieves current speed and duplex settings.
func GetSpeedAndDuplex(interfaceIndex uint32) (speedMbps uint64, duplex DuplexMode, err error) {
	row, err := getIfRowByIndex(interfaceIndex)
	if err != nil {
		return 0, "", err
	}

	// Speed is in bits per second, convert to Mbps
	speedMbps = uint64(row.Speed) / 1000000

	// Windows MIB_IFROW doesn't expose duplex directly
	// Query WMI for more details
	var adapters []Win32_NetworkAdapter
	query := fmt.Sprintf("SELECT * FROM Win32_NetworkAdapter WHERE InterfaceIndex = %d", interfaceIndex)
	wmiErr := wmi.Query(query, &adapters)
	if wmiErr == nil && len(adapters) > 0 {
		// Most adapters use full duplex at gigabit+ speeds
		if speedMbps >= 1000 {
			duplex = DuplexFull
		} else {
			// Could be either, default to auto
			duplex = DuplexAuto
		}
	} else {
		duplex = DuplexAuto
	}

	return speedMbps, duplex, nil
}

// =============================================================================
// MTU Configuration
// =============================================================================

// SetMTU sets the Maximum Transmission Unit for an interface.
// Valid range is typically 576-9000 bytes.
func SetMTU(interfaceIndex uint32, mtu uint32) error {
	if mtu < 576 || mtu > 9000 {
		return fmt.Errorf("MTU must be between 576 and 9000, got %d", mtu)
	}

	row, err := getIfRowByIndex(interfaceIndex)
	if err != nil {
		return err
	}

	row.Mtu = mtu

	ret, _, _ := ndisProcSetIfEntry.Call(uintptr(unsafe.Pointer(row)))
	if ret != 0 {
		return fmt.Errorf("SetIfEntry failed for MTU change: %d", ret)
	}

	return nil
}

// GetMTU retrieves the current MTU for an interface.
func GetMTU(interfaceIndex uint32) (uint32, error) {
	row, err := getIfRowByIndex(interfaceIndex)
	if err != nil {
		return 0, err
	}
	return row.Mtu, nil
}

// =============================================================================
// MAC Address Retrieval
// =============================================================================

// GetMACAddress retrieves the hardware MAC address for an interface.
func GetMACAddress(interfaceIndex uint32) (string, error) {
	row, err := getIfRowByIndex(interfaceIndex)
	if err != nil {
		return "", err
	}

	if row.PhysAddrLen == 0 {
		return "", fmt.Errorf("no physical address for interface %d", interfaceIndex)
	}

	return formatMACAddress(row.PhysAddr[:row.PhysAddrLen]), nil
}

// =============================================================================
// Interface Statistics
// =============================================================================

// GetInterfaceStatistics retrieves interface counters.
func GetInterfaceStatistics(interfaceIndex uint32) (*InterfaceStatistics, error) {
	row, err := getIfRowByIndex(interfaceIndex)
	if err != nil {
		return nil, err
	}

	return &InterfaceStatistics{
		RxBytes:   uint64(row.InOctets),
		TxBytes:   uint64(row.OutOctets),
		RxPackets: uint64(row.InUcastPkts) + uint64(row.InNUcastPkts),
		TxPackets: uint64(row.OutUcastPkts) + uint64(row.OutNUcastPkts),
		RxErrors:  uint64(row.InErrors),
		TxErrors:  uint64(row.OutErrors),
		RxDropped: uint64(row.InDiscards),
		TxDropped: uint64(row.OutDiscards),
	}, nil
}

// =============================================================================
// Driver Information
// =============================================================================

// GetDriverInfo retrieves driver information via WMI.
func GetDriverInfo(interfaceIndex uint32) (*DriverInfo, error) {
	var adapters []Win32_NetworkAdapter
	query := fmt.Sprintf("SELECT * FROM Win32_NetworkAdapter WHERE InterfaceIndex = %d", interfaceIndex)

	err := wmi.Query(query, &adapters)
	if err != nil {
		return nil, fmt.Errorf("WMI query failed: %w", err)
	}

	if len(adapters) == 0 {
		return nil, fmt.Errorf("adapter not found for index %d", interfaceIndex)
	}

	adapter := adapters[0]
	return &DriverInfo{
		DriverName:  adapter.ServiceName,
		VendorName:  adapter.Manufacturer,
		DeviceModel: adapter.Name,
		HardwareID:  adapter.PNPDeviceID,
		IsVirtual:   !adapter.PhysicalAdapter,
		BusType:     "PCI", // Default assumption
	}, nil
}

// =============================================================================
// Interface Capabilities
// =============================================================================

// GetInterfaceCapabilities retrieves hardware capabilities.
func GetInterfaceCapabilities(interfaceIndex uint32) (*InterfaceCapabilities, error) {
	var adapters []Win32_NetworkAdapter
	query := fmt.Sprintf("SELECT * FROM Win32_NetworkAdapter WHERE InterfaceIndex = %d", interfaceIndex)

	err := wmi.Query(query, &adapters)
	if err != nil {
		return nil, fmt.Errorf("WMI query failed: %w", err)
	}

	if len(adapters) == 0 {
		return nil, fmt.Errorf("adapter not found for index %d", interfaceIndex)
	}

	adapter := adapters[0]

	// Get MTU from config
	var configs []Win32_NetworkAdapterConfiguration
	configQuery := fmt.Sprintf("SELECT * FROM Win32_NetworkAdapterConfiguration WHERE Index = %d", adapter.Index)
	_ = wmi.Query(configQuery, &configs)

	var maxMTU uint32 = 1500
	if len(configs) > 0 && configs[0].MTU > 0 {
		maxMTU = configs[0].MTU
	}

	return &InterfaceCapabilities{
		MaxSpeedMbps:            int(adapter.MaxSpeed / 1000000),
		SupportedSpeeds:         []int{10, 100, 1000, 10000},    // Common supported speeds
		SupportsVLAN:            adapter.PhysicalAdapter,        // Physical adapters typically support VLAN
		HardwareChecksumOffload: true,                           // Assume supported for physical adapters
		TSOEnabled:              adapter.MaxSpeed >= 1000000000, // 1Gbps+ usually has TSO
		MaxMTU:                  int(maxMTU),
		MinMTU:                  576,
		JumboFrames:             maxMTU > 1500,
	}, nil
}

// =============================================================================
// GUID to Index Conversion
// =============================================================================

// GUIDToIndex converts an interface GUID to interface index.
func GUIDToIndex(guid string) (uint32, error) {
	var adapters []Win32_NetworkAdapter
	query := fmt.Sprintf("SELECT InterfaceIndex FROM Win32_NetworkAdapter WHERE GUID = '%s'", guid)

	err := wmi.Query(query, &adapters)
	if err != nil {
		return 0, fmt.Errorf("WMI query failed: %w", err)
	}

	if len(adapters) == 0 {
		return 0, fmt.Errorf("adapter not found for GUID %s", guid)
	}

	return adapters[0].InterfaceIndex, nil
}

// IndexToGUID converts an interface index to GUID.
func IndexToGUID(index uint32) (string, error) {
	var adapters []Win32_NetworkAdapter
	query := fmt.Sprintf("SELECT GUID FROM Win32_NetworkAdapter WHERE InterfaceIndex = %d", index)

	err := wmi.Query(query, &adapters)
	if err != nil {
		return "", fmt.Errorf("WMI query failed: %w", err)
	}

	if len(adapters) == 0 {
		return "", fmt.Errorf("adapter not found for index %d", index)
	}

	return adapters[0].GUID, nil
}

// =============================================================================
// Helper Functions
// =============================================================================

// formatMACAddress converts bytes to colon-separated hex string.
func formatMACAddress(mac []byte) string {
	if len(mac) == 0 {
		return ""
	}
	hw := net.HardwareAddr(mac)
	return hw.String()
}

// bytesToString converts a null-terminated byte slice to string.
func bytesToString(b []byte) string {
	for i, c := range b {
		if c == 0 {
			return string(b[:i])
		}
	}
	return string(b)
}

// IsVirtualAdapter detects virtual adapters by name/description keywords.
func IsVirtualAdapter(name string, description string) bool {
	virtKeywords := []string{
		"hyper-v",
		"vmware",
		"virtualbox",
		"virtual",
		"vethernet",
		"tap-",
		"tun-",
		"loopback",
		"docker",
		"wsl",
		"vpn",
		"tunnel",
	}

	combined := strings.ToLower(name + " " + description)
	for _, keyword := range virtKeywords {
		if strings.Contains(combined, keyword) {
			return true
		}
	}
	return false
}

// GetInterfaceByName finds an interface by its name.
func GetInterfaceByName(name string) (*NDISInterface, error) {
	interfaces, err := EnumerateNDISInterfaces()
	if err != nil {
		return nil, err
	}

	for _, iface := range interfaces {
		if strings.EqualFold(iface.Name, name) {
			return iface, nil
		}
	}

	return nil, fmt.Errorf("interface not found: %s", name)
}

// GetPhysicalInterfaces returns only physical (non-virtual) interfaces.
func GetPhysicalInterfaces() ([]*NDISInterface, error) {
	interfaces, err := EnumerateNDISInterfaces()
	if err != nil {
		return nil, err
	}

	physical := make([]*NDISInterface, 0)
	for _, iface := range interfaces {
		if iface.IsPhysical && !IsVirtualAdapter(iface.Name, iface.Description) {
			physical = append(physical, iface)
		}
	}

	return physical, nil
}
