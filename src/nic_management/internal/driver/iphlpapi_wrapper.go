//go:build windows
// +build windows

// Package driver provides a comprehensive wrapper around the Windows IP Helper API
// (iphlpapi.dll), enabling the NIC Management service to query and configure network
// interface properties, IP addresses, routing tables, and adapter statistics.
package driver

import (
	"fmt"
	"net"
	"strings"
	"sync"
	"syscall"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"

	"safeops/nic_management/pkg/types"
)

// =============================================================================
// Windows DLL and Procedure Declarations
// =============================================================================

var (
	modiphlpapi = windows.NewLazySystemDLL("iphlpapi.dll")
	modws2_32   = windows.NewLazySystemDLL("ws2_32.dll")

	// IP Helper API procedures
	procGetAdaptersAddresses     = modiphlpapi.NewProc("GetAdaptersAddresses")
	procGetIfTable2              = modiphlpapi.NewProc("GetIfTable2")
	procGetIfEntry2              = modiphlpapi.NewProc("GetIfEntry2")
	procFreeMibTable             = modiphlpapi.NewProc("FreeMibTable")
	procGetIpAddrTable           = modiphlpapi.NewProc("GetIpAddrTable")
	procGetIpForwardTable2       = modiphlpapi.NewProc("GetIpForwardTable2")
	procCreateIpForwardEntry2    = modiphlpapi.NewProc("CreateIpForwardEntry2")
	procDeleteIpForwardEntry2    = modiphlpapi.NewProc("DeleteIpForwardEntry2")
	procGetIpNetTable2           = modiphlpapi.NewProc("GetIpNetTable2")
	procDeleteIpNetEntry2        = modiphlpapi.NewProc("DeleteIpNetEntry2")
	procNotifyIpInterfaceChange  = modiphlpapi.NewProc("NotifyIpInterfaceChange")
	procCancelMibChangeNotify2   = modiphlpapi.NewProc("CancelMibChangeNotify2")
	procGetBestRoute2            = modiphlpapi.NewProc("GetBestRoute2")
	procInitializeIpForwardEntry = modiphlpapi.NewProc("InitializeIpForwardEntry")
)

// =============================================================================
// Constants
// =============================================================================

const (
	// Address family
	AF_UNSPEC = 0
	AF_INET   = 2
	AF_INET6  = 23

	// GetAdaptersAddresses flags
	GAA_FLAG_SKIP_UNICAST             = 0x0001
	GAA_FLAG_SKIP_ANYCAST             = 0x0002
	GAA_FLAG_SKIP_MULTICAST           = 0x0004
	GAA_FLAG_SKIP_DNS_SERVER          = 0x0008
	GAA_FLAG_INCLUDE_PREFIX           = 0x0010
	GAA_FLAG_SKIP_FRIENDLY_NAME       = 0x0020
	GAA_FLAG_INCLUDE_WINS_INFO        = 0x0040
	GAA_FLAG_INCLUDE_GATEWAYS         = 0x0080
	GAA_FLAG_INCLUDE_ALL_INTERFACES   = 0x0100
	GAA_FLAG_INCLUDE_ALL_COMPARTMENTS = 0x0200

	// Interface operational status
	IfOperStatusUp             = 1
	IfOperStatusDown           = 2
	IfOperStatusTesting        = 3
	IfOperStatusUnknown        = 4
	IfOperStatusDormant        = 5
	IfOperStatusNotPresent     = 6
	IfOperStatusLowerLayerDown = 7

	// Route protocols
	MIB_IPPROTO_OTHER   = 1
	MIB_IPPROTO_LOCAL   = 2
	MIB_IPPROTO_NETMGMT = 3 // Static route
	MIB_IPPROTO_ICMP    = 4
	MIB_IPPROTO_EGP     = 5
	MIB_IPPROTO_GGP     = 6
	MIB_IPPROTO_HELLO   = 7
	MIB_IPPROTO_RIP     = 8
	MIB_IPPROTO_IS_IS   = 9
	MIB_IPPROTO_ES_IS   = 10
	MIB_IPPROTO_CISCO   = 11
	MIB_IPPROTO_BBN     = 12
	MIB_IPPROTO_OSPF    = 13
	MIB_IPPROTO_BGP     = 14

	// ARP neighbor states
	NlnsUnreachable = 0
	NlnsIncomplete  = 1
	NlnsProbe       = 2
	NlnsDelay       = 3
	NlnsStale       = 4
	NlnsReachable   = 5
	NlnsPermanent   = 6

	// Error codes
	ERROR_SUCCESS           = 0
	ERROR_BUFFER_OVERFLOW   = 111
	ERROR_INVALID_PARAMETER = 87
	ERROR_NOT_SUPPORTED     = 50
	ERROR_NO_DATA           = 232
	ERROR_FILE_NOT_FOUND    = 2
	ERROR_ACCESS_DENIED     = 5

	// Notification types
	MibAddInstance           = 1
	MibDeleteInstance        = 2
	MibParameterNotification = 3
)

// =============================================================================
// Windows API Structures
// =============================================================================

// SOCKADDR_IN represents IPv4 socket address
type SOCKADDR_IN struct {
	Family uint16
	Port   uint16
	Addr   [4]byte
	Zero   [8]byte
}

// SOCKADDR_IN6 represents IPv6 socket address
type SOCKADDR_IN6 struct {
	Family   uint16
	Port     uint16
	FlowInfo uint32
	Addr     [16]byte
	ScopeID  uint32
}

// SOCKADDR_INET is a union of IPv4 and IPv6 addresses
type SOCKADDR_INET struct {
	Family uint16
	Data   [26]byte // Large enough for both IPv4 and IPv6
}

// SOCKET_ADDRESS represents a socket address with length
type SOCKET_ADDRESS struct {
	Sockaddr       uintptr
	SockaddrLength int32
}

// IP_ADAPTER_UNICAST_ADDRESS represents a unicast address
type IP_ADAPTER_UNICAST_ADDRESS struct {
	Length             uint32
	Flags              uint32
	Next               *IP_ADAPTER_UNICAST_ADDRESS
	Address            SOCKET_ADDRESS
	PrefixOrigin       int32
	SuffixOrigin       int32
	DadState           int32
	ValidLifetime      uint32
	PreferredLifetime  uint32
	LeaseLifetime      uint32
	OnLinkPrefixLength uint8
}

// IP_ADAPTER_DNS_SERVER_ADDRESS represents a DNS server address
type IP_ADAPTER_DNS_SERVER_ADDRESS struct {
	Length   uint32
	Reserved uint32
	Next     *IP_ADAPTER_DNS_SERVER_ADDRESS
	Address  SOCKET_ADDRESS
}

// IP_ADAPTER_GATEWAY_ADDRESS represents a gateway address
type IP_ADAPTER_GATEWAY_ADDRESS struct {
	Length   uint32
	Reserved uint32
	Next     *IP_ADAPTER_GATEWAY_ADDRESS
	Address  SOCKET_ADDRESS
}

// IP_ADAPTER_ADDRESSES represents adapter information
type IP_ADAPTER_ADDRESSES struct {
	Length                 uint32
	IfIndex                uint32
	Next                   *IP_ADAPTER_ADDRESSES
	AdapterName            *byte
	FirstUnicastAddress    *IP_ADAPTER_UNICAST_ADDRESS
	FirstAnycastAddress    uintptr
	FirstMulticastAddress  uintptr
	FirstDnsServerAddress  *IP_ADAPTER_DNS_SERVER_ADDRESS
	DnsSuffix              *uint16
	Description            *uint16
	FriendlyName           *uint16
	PhysicalAddress        [8]byte
	PhysicalAddressLength  uint32
	Flags                  uint32
	Mtu                    uint32
	IfType                 uint32
	OperStatus             uint32
	Ipv6IfIndex            uint32
	ZoneIndices            [16]uint32
	FirstPrefix            uintptr
	TransmitLinkSpeed      uint64
	ReceiveLinkSpeed       uint64
	FirstWinsServerAddress uintptr
	FirstGatewayAddress    *IP_ADAPTER_GATEWAY_ADDRESS
	Ipv4Metric             uint32
	Ipv6Metric             uint32
	Luid                   uint64
	Dhcpv4Server           SOCKET_ADDRESS
	CompartmentId          uint32
	NetworkGuid            [16]byte
	ConnectionType         uint32
	TunnelType             uint32
	Dhcpv6Server           SOCKET_ADDRESS
	Dhcpv6ClientDuid       [130]byte
	Dhcpv6ClientDuidLength uint32
	Dhcpv6Iaid             uint32
}

// MIB_IF_ROW2 represents extended interface information
type MIB_IF_ROW2 struct {
	InterfaceLuid               uint64
	InterfaceIndex              uint32
	InterfaceGuid               [16]byte
	Alias                       [514]byte // 257 * 2 bytes (UTF-16)
	Description                 [514]byte
	PhysicalAddressLength       uint32
	PhysicalAddress             [32]byte
	PermanentPhysicalAddress    [32]byte
	Mtu                         uint32
	Type                        uint32
	TunnelType                  uint32
	MediaType                   uint32
	PhysicalMediumType          uint32
	AccessType                  uint32
	DirectionType               uint32
	InterfaceAndOperStatusFlags uint8
	OperStatus                  uint32
	AdminStatus                 uint32
	MediaConnectState           uint32
	NetworkGuid                 [16]byte
	ConnectionType              uint32
	TransmitLinkSpeed           uint64
	ReceiveLinkSpeed            uint64
	InOctets                    uint64
	InUcastPkts                 uint64
	InNUcastPkts                uint64
	InDiscards                  uint64
	InErrors                    uint64
	InUnknownProtos             uint64
	InUcastOctets               uint64
	InMulticastOctets           uint64
	InBroadcastOctets           uint64
	OutOctets                   uint64
	OutUcastPkts                uint64
	OutNUcastPkts               uint64
	OutDiscards                 uint64
	OutErrors                   uint64
	OutUcastOctets              uint64
	OutMulticastOctets          uint64
	OutBroadcastOctets          uint64
	OutQLen                     uint64
}

// MIB_IPADDRROW represents an IP address entry
type MIB_IPADDRROW struct {
	Addr      uint32
	Index     uint32
	Mask      uint32
	BCastAddr uint32
	ReasmSize uint32
	Unused1   uint16
	Type      uint16
}

// MIB_IPADDRTABLE represents the IP address table
type MIB_IPADDRTABLE struct {
	NumEntries uint32
	Table      [1]MIB_IPADDRROW // Variable length
}

// IP_ADDRESS_PREFIX represents an IP address prefix
type IP_ADDRESS_PREFIX struct {
	Prefix       SOCKADDR_INET
	PrefixLength uint8
	_            [3]byte // Padding
}

// MIB_IPFORWARD_ROW2 represents a routing table entry
type MIB_IPFORWARD_ROW2 struct {
	InterfaceLuid        uint64
	InterfaceIndex       uint32
	DestinationPrefix    IP_ADDRESS_PREFIX
	NextHop              SOCKADDR_INET
	SitePrefixLength     uint8
	ValidLifetime        uint32
	PreferredLifetime    uint32
	Metric               uint32
	Protocol             uint32
	Loopback             uint8
	AutoconfigureAddress uint8
	Publish              uint8
	Immortal             uint8
	Age                  uint32
	Origin               uint32
}

// MIB_IPNET_ROW2 represents an ARP table entry
type MIB_IPNET_ROW2 struct {
	Address               SOCKADDR_INET
	InterfaceIndex        uint32
	InterfaceLuid         uint64
	PhysicalAddress       [32]byte
	PhysicalAddressLength uint32
	State                 uint32
	Flags                 uint8
	ReachabilityTime      uint32
}

// =============================================================================
// NIC Information Structure for external use
// =============================================================================

// NICInfo represents network adapter information
type NICInfo struct {
	Index         uint32   `json:"index"`
	Name          string   `json:"name"`
	FriendlyName  string   `json:"friendly_name"`
	Description   string   `json:"description"`
	MACAddress    string   `json:"mac_address"`
	OperStatus    uint32   `json:"oper_status"`
	OperStatusStr string   `json:"oper_status_str"`
	Mtu           uint32   `json:"mtu"`
	IfType        uint32   `json:"if_type"`
	TransmitSpeed uint64   `json:"transmit_speed_bps"`
	ReceiveSpeed  uint64   `json:"receive_speed_bps"`
	IPv4Addresses []string `json:"ipv4_addresses"`
	IPv6Addresses []string `json:"ipv6_addresses"`
	Gateways      []string `json:"gateways"`
	DNSServers    []string `json:"dns_servers"`
	Luid          uint64   `json:"luid"`
	IPv4Metric    uint32   `json:"ipv4_metric"`
	IPv6Metric    uint32   `json:"ipv6_metric"`
}

// RouteEntry represents a routing table entry
type RouteEntry struct {
	Destination    string `json:"destination"`
	PrefixLength   uint8  `json:"prefix_length"`
	NextHop        string `json:"next_hop"`
	InterfaceIndex uint32 `json:"interface_index"`
	Metric         uint32 `json:"metric"`
	Protocol       uint32 `json:"protocol"`
	ProtocolStr    string `json:"protocol_str"`
	Age            uint32 `json:"age_seconds"`
}

// ARPEntry represents an ARP table entry
type ARPEntry struct {
	IPAddress      string `json:"ip_address"`
	MACAddress     string `json:"mac_address"`
	InterfaceIndex uint32 `json:"interface_index"`
	State          uint32 `json:"state"`
	StateStr       string `json:"state_str"`
}

// =============================================================================
// Adapter Information Retrieval
// =============================================================================

var adapterCacheMu sync.RWMutex
var adapterCache []*NICInfo
var adapterCacheTime time.Time
var adapterCacheTTL = 5 * time.Second

// GetAdaptersList retrieves all network adapters using GetAdaptersAddresses API.
func GetAdaptersList() ([]*NICInfo, error) {
	// Check cache
	adapterCacheMu.RLock()
	if time.Since(adapterCacheTime) < adapterCacheTTL && adapterCache != nil {
		result := adapterCache
		adapterCacheMu.RUnlock()
		return result, nil
	}
	adapterCacheMu.RUnlock()

	// Initial buffer size (15KB)
	bufferSize := uint32(15000)
	var adapters *IP_ADAPTER_ADDRESSES

	flags := uint32(GAA_FLAG_INCLUDE_PREFIX | GAA_FLAG_INCLUDE_GATEWAYS |
		GAA_FLAG_INCLUDE_ALL_INTERFACES)

	// Retry with larger buffer if needed
	for attempts := 0; attempts < 3; attempts++ {
		buffer := make([]byte, bufferSize)
		adapters = (*IP_ADAPTER_ADDRESSES)(unsafe.Pointer(&buffer[0]))

		ret, _, _ := procGetAdaptersAddresses.Call(
			uintptr(AF_UNSPEC),
			uintptr(flags),
			0,
			uintptr(unsafe.Pointer(adapters)),
			uintptr(unsafe.Pointer(&bufferSize)),
		)

		if ret == ERROR_SUCCESS {
			break
		}
		if ret == ERROR_BUFFER_OVERFLOW {
			// Retry with suggested buffer size
			continue
		}
		return nil, fmt.Errorf("GetAdaptersAddresses failed: %w", convertWindowsError(syscall.Errno(ret)))
	}

	result := make([]*NICInfo, 0)

	// Iterate through adapter linked list
	for adapter := adapters; adapter != nil; adapter = adapter.Next {
		nic := &NICInfo{
			Index:         adapter.IfIndex,
			Mtu:           adapter.Mtu,
			IfType:        adapter.IfType,
			OperStatus:    adapter.OperStatus,
			OperStatusStr: operStatusToString(adapter.OperStatus),
			TransmitSpeed: adapter.TransmitLinkSpeed,
			ReceiveSpeed:  adapter.ReceiveLinkSpeed,
			Luid:          adapter.Luid,
			IPv4Metric:    adapter.Ipv4Metric,
			IPv6Metric:    adapter.Ipv6Metric,
		}

		// Get adapter name (ASCII string)
		if adapter.AdapterName != nil {
			nic.Name = windows.BytePtrToString(adapter.AdapterName)
		}

		// Get friendly name (wide string)
		if adapter.FriendlyName != nil {
			nic.FriendlyName = windows.UTF16PtrToString(adapter.FriendlyName)
		}

		// Get description (wide string)
		if adapter.Description != nil {
			nic.Description = windows.UTF16PtrToString(adapter.Description)
		}

		// Get MAC address
		if adapter.PhysicalAddressLength > 0 {
			nic.MACAddress = formatMACFromBytes(adapter.PhysicalAddress[:adapter.PhysicalAddressLength])
		}

		// Get unicast addresses
		nic.IPv4Addresses = make([]string, 0)
		nic.IPv6Addresses = make([]string, 0)
		for addr := adapter.FirstUnicastAddress; addr != nil; addr = addr.Next {
			ipStr := socketAddressToIP(addr.Address)
			if ipStr != "" {
				if strings.Contains(ipStr, ":") {
					nic.IPv6Addresses = append(nic.IPv6Addresses, ipStr)
				} else {
					nic.IPv4Addresses = append(nic.IPv4Addresses, ipStr)
				}
			}
		}

		// Get gateway addresses
		nic.Gateways = make([]string, 0)
		for gw := adapter.FirstGatewayAddress; gw != nil; gw = gw.Next {
			ipStr := socketAddressToIP(gw.Address)
			if ipStr != "" {
				nic.Gateways = append(nic.Gateways, ipStr)
			}
		}

		// Get DNS server addresses
		nic.DNSServers = make([]string, 0)
		for dns := adapter.FirstDnsServerAddress; dns != nil; dns = dns.Next {
			ipStr := socketAddressToIP(dns.Address)
			if ipStr != "" {
				nic.DNSServers = append(nic.DNSServers, ipStr)
			}
		}

		result = append(result, nic)
	}

	// Update cache
	adapterCacheMu.Lock()
	adapterCache = result
	adapterCacheTime = time.Now()
	adapterCacheMu.Unlock()

	return result, nil
}

// GetAdapterByIndex retrieves a single adapter by interface index.
func GetAdapterByIndex(ifIndex uint32) (*NICInfo, error) {
	adapters, err := GetAdaptersList()
	if err != nil {
		return nil, err
	}

	for _, adapter := range adapters {
		if adapter.Index == ifIndex {
			return adapter, nil
		}
	}

	return nil, fmt.Errorf("adapter with index %d not found", ifIndex)
}

// GetAdapterByName retrieves a single adapter by name.
func GetAdapterByName(name string) (*NICInfo, error) {
	adapters, err := GetAdaptersList()
	if err != nil {
		return nil, err
	}

	nameLower := strings.ToLower(name)
	for _, adapter := range adapters {
		if strings.EqualFold(adapter.Name, name) ||
			strings.EqualFold(adapter.FriendlyName, name) ||
			strings.ToLower(adapter.FriendlyName) == nameLower {
			return adapter, nil
		}
	}

	return nil, fmt.Errorf("adapter with name '%s' not found", name)
}

// =============================================================================
// Interface Statistics
// =============================================================================

// GetIPHLPInterfaceStats retrieves comprehensive interface statistics.
// Named with IPHLP prefix to avoid collision with ndis_interface.go
func GetIPHLPInterfaceStats(ifIndex uint32) (*types.InterfaceStatistics, error) {
	row := &MIB_IF_ROW2{InterfaceIndex: ifIndex}

	ret, _, _ := procGetIfEntry2.Call(uintptr(unsafe.Pointer(row)))
	if ret != ERROR_SUCCESS {
		return nil, fmt.Errorf("GetIfEntry2 failed: %w", convertWindowsError(syscall.Errno(ret)))
	}

	return &types.InterfaceStatistics{
		RxBytes:         row.InOctets,
		TxBytes:         row.OutOctets,
		RxPackets:       row.InUcastPkts + row.InNUcastPkts,
		TxPackets:       row.OutUcastPkts + row.OutNUcastPkts,
		RxErrors:        row.InErrors,
		TxErrors:        row.OutErrors,
		RxDropped:       row.InDiscards,
		TxDropped:       row.OutDiscards,
		ThroughputRxBps: row.ReceiveLinkSpeed,
		ThroughputTxBps: row.TransmitLinkSpeed,
		CollectedAt:     time.Now(),
	}, nil
}

// GetInterfaceSpeedDuplex retrieves link speed and duplex mode.
func GetInterfaceSpeedDuplex(ifIndex uint32) (speedBps uint64, duplex string, err error) {
	row := &MIB_IF_ROW2{InterfaceIndex: ifIndex}

	ret, _, _ := procGetIfEntry2.Call(uintptr(unsafe.Pointer(row)))
	if ret != ERROR_SUCCESS {
		return 0, "", fmt.Errorf("GetIfEntry2 failed: %w", convertWindowsError(syscall.Errno(ret)))
	}

	speedBps = row.TransmitLinkSpeed

	// Determine duplex mode based on transmit/receive speed equality
	if row.TransmitLinkSpeed == 0 || row.ReceiveLinkSpeed == 0 {
		duplex = "UNKNOWN"
	} else if row.TransmitLinkSpeed == row.ReceiveLinkSpeed {
		duplex = "FULL"
	} else {
		duplex = "HALF"
	}

	return speedBps, duplex, nil
}

// =============================================================================
// Routing Table Functions
// =============================================================================

// GetRoutingTable retrieves the complete IPv4 routing table.
func GetRoutingTable() ([]*RouteEntry, error) {
	var table uintptr

	ret, _, _ := procGetIpForwardTable2.Call(
		uintptr(AF_INET),
		uintptr(unsafe.Pointer(&table)),
	)

	if ret != ERROR_SUCCESS {
		return nil, fmt.Errorf("GetIpForwardTable2 failed: %w", convertWindowsError(syscall.Errno(ret)))
	}
	defer procFreeMibTable.Call(table)

	// Parse table header
	numEntries := *(*uint32)(unsafe.Pointer(table))
	if numEntries == 0 {
		return []*RouteEntry{}, nil
	}

	routes := make([]*RouteEntry, 0, numEntries)
	entrySize := unsafe.Sizeof(MIB_IPFORWARD_ROW2{})
	basePtr := table + 8 // Skip NumEntries and padding

	for i := uint32(0); i < numEntries; i++ {
		offset := basePtr + uintptr(i)*entrySize
		row := (*MIB_IPFORWARD_ROW2)(unsafe.Pointer(offset))

		route := &RouteEntry{
			PrefixLength:   row.DestinationPrefix.PrefixLength,
			InterfaceIndex: row.InterfaceIndex,
			Metric:         row.Metric,
			Protocol:       row.Protocol,
			ProtocolStr:    protocolToString(row.Protocol),
			Age:            row.Age,
		}

		// Extract destination address
		route.Destination = sockaddrInetToString(&row.DestinationPrefix.Prefix)

		// Extract next hop
		route.NextHop = sockaddrInetToString(&row.NextHop)

		routes = append(routes, route)
	}

	return routes, nil
}

// AddRoute adds a new routing table entry.
func AddRoute(destination net.IPNet, gateway net.IP, ifIndex uint32, metric uint32) error {
	row := MIB_IPFORWARD_ROW2{
		InterfaceIndex:    ifIndex,
		Metric:            metric,
		Protocol:          MIB_IPPROTO_NETMGMT,
		ValidLifetime:     0xFFFFFFFF,
		PreferredLifetime: 0xFFFFFFFF,
	}

	// Set destination prefix
	dest4 := destination.IP.To4()
	if dest4 == nil {
		return fmt.Errorf("only IPv4 destinations supported")
	}
	row.DestinationPrefix.Prefix.Family = AF_INET
	copy(row.DestinationPrefix.Prefix.Data[2:6], dest4)
	ones, _ := destination.Mask.Size()
	row.DestinationPrefix.PrefixLength = uint8(ones)

	// Set next hop
	gw4 := gateway.To4()
	if gw4 == nil {
		return fmt.Errorf("only IPv4 gateways supported")
	}
	row.NextHop.Family = AF_INET
	copy(row.NextHop.Data[2:6], gw4)

	ret, _, _ := procCreateIpForwardEntry2.Call(uintptr(unsafe.Pointer(&row)))
	if ret != ERROR_SUCCESS {
		return fmt.Errorf("CreateIpForwardEntry2 failed: %w", convertWindowsError(syscall.Errno(ret)))
	}

	return nil
}

// DeleteRoute removes a routing table entry.
func DeleteRoute(destination net.IPNet, gateway net.IP, ifIndex uint32) error {
	row := MIB_IPFORWARD_ROW2{
		InterfaceIndex: ifIndex,
	}

	// Set destination prefix
	dest4 := destination.IP.To4()
	if dest4 == nil {
		return fmt.Errorf("only IPv4 destinations supported")
	}
	row.DestinationPrefix.Prefix.Family = AF_INET
	copy(row.DestinationPrefix.Prefix.Data[2:6], dest4)
	ones, _ := destination.Mask.Size()
	row.DestinationPrefix.PrefixLength = uint8(ones)

	// Set next hop
	gw4 := gateway.To4()
	if gw4 != nil {
		row.NextHop.Family = AF_INET
		copy(row.NextHop.Data[2:6], gw4)
	}

	ret, _, _ := procDeleteIpForwardEntry2.Call(uintptr(unsafe.Pointer(&row)))
	if ret != ERROR_SUCCESS {
		return fmt.Errorf("DeleteIpForwardEntry2 failed: %w", convertWindowsError(syscall.Errno(ret)))
	}

	return nil
}

// GetDefaultGateway retrieves the default gateway for an interface.
func GetDefaultGateway(ifIndex uint32) (net.IP, error) {
	routes, err := GetRoutingTable()
	if err != nil {
		return nil, err
	}

	for _, route := range routes {
		if route.InterfaceIndex == ifIndex &&
			route.Destination == "0.0.0.0" &&
			route.PrefixLength == 0 {
			return net.ParseIP(route.NextHop), nil
		}
	}

	return nil, fmt.Errorf("no default gateway for interface %d", ifIndex)
}

// SetDefaultGateway sets the default gateway for an interface.
func SetDefaultGateway(ifIndex uint32, gateway net.IP) error {
	// Delete existing default route
	_, defaultNet, _ := net.ParseCIDR("0.0.0.0/0")
	existingGW, err := GetDefaultGateway(ifIndex)
	if err == nil && existingGW != nil {
		_ = DeleteRoute(*defaultNet, existingGW, ifIndex)
	}

	// Add new default route
	return AddRoute(*defaultNet, gateway, ifIndex, 0)
}

// =============================================================================
// ARP Table Functions
// =============================================================================

// GetARPTable retrieves the complete ARP table.
func GetARPTable() ([]*ARPEntry, error) {
	var table uintptr

	ret, _, _ := procGetIpNetTable2.Call(
		uintptr(AF_INET),
		uintptr(unsafe.Pointer(&table)),
	)

	if ret != ERROR_SUCCESS {
		if ret == ERROR_NO_DATA {
			return []*ARPEntry{}, nil
		}
		return nil, fmt.Errorf("GetIpNetTable2 failed: %w", convertWindowsError(syscall.Errno(ret)))
	}
	defer procFreeMibTable.Call(table)

	// Parse table header
	numEntries := *(*uint32)(unsafe.Pointer(table))
	if numEntries == 0 {
		return []*ARPEntry{}, nil
	}

	entries := make([]*ARPEntry, 0, numEntries)
	entrySize := unsafe.Sizeof(MIB_IPNET_ROW2{})
	basePtr := table + 8

	for i := uint32(0); i < numEntries; i++ {
		offset := basePtr + uintptr(i)*entrySize
		row := (*MIB_IPNET_ROW2)(unsafe.Pointer(offset))

		entry := &ARPEntry{
			InterfaceIndex: row.InterfaceIndex,
			State:          row.State,
			StateStr:       arpStateToString(row.State),
		}

		entry.IPAddress = sockaddrInetToString(&row.Address)
		if row.PhysicalAddressLength > 0 {
			entry.MACAddress = formatMACFromBytes(row.PhysicalAddress[:row.PhysicalAddressLength])
		}

		entries = append(entries, entry)
	}

	return entries, nil
}

// GetARPEntry retrieves the MAC address for a specific IP.
func GetARPEntry(ip net.IP) (net.HardwareAddr, error) {
	entries, err := GetARPTable()
	if err != nil {
		return nil, err
	}

	ipStr := ip.String()
	for _, entry := range entries {
		if entry.IPAddress == ipStr && entry.MACAddress != "" {
			return net.ParseMAC(entry.MACAddress)
		}
	}

	return nil, fmt.Errorf("ARP entry for %s not found", ip)
}

// =============================================================================
// Interface Change Notifications
// =============================================================================

// NotificationCallback is the callback type for interface changes.
type NotificationCallback func(ifIndex uint32, changeType string)

var notificationCallbacks = make(map[uintptr]NotificationCallback)
var notificationMu sync.RWMutex

// RegisterInterfaceChangeCallback registers a callback for interface changes.
func RegisterInterfaceChangeCallback(callback NotificationCallback) (uintptr, error) {
	var handle uintptr

	// Create Windows callback
	cb := syscall.NewCallback(func(callerContext uintptr, row uintptr, notificationType uint32) uintptr {
		var ifIndex uint32
		var changeType string

		if row != 0 {
			// Extract interface index from MIB_IPINTERFACE_ROW
			ifIndex = *(*uint32)(unsafe.Pointer(row + 8)) // Offset to InterfaceIndex
		}

		switch notificationType {
		case MibAddInstance:
			changeType = "ADDED"
		case MibDeleteInstance:
			changeType = "REMOVED"
		case MibParameterNotification:
			changeType = "MODIFIED"
		default:
			changeType = "UNKNOWN"
		}

		// Call user callback in goroutine
		notificationMu.RLock()
		if cb, ok := notificationCallbacks[handle]; ok {
			go cb(ifIndex, changeType)
		}
		notificationMu.RUnlock()

		return 0
	})

	ret, _, _ := procNotifyIpInterfaceChange.Call(
		uintptr(AF_UNSPEC),
		cb,
		0,
		0,
		uintptr(unsafe.Pointer(&handle)),
	)

	if ret != ERROR_SUCCESS {
		return 0, fmt.Errorf("NotifyIpInterfaceChange failed: %w", convertWindowsError(syscall.Errno(ret)))
	}

	notificationMu.Lock()
	notificationCallbacks[handle] = callback
	notificationMu.Unlock()

	return handle, nil
}

// UnregisterInterfaceChangeCallback unregisters a notification callback.
func UnregisterInterfaceChangeCallback(handle uintptr) error {
	ret, _, _ := procCancelMibChangeNotify2.Call(handle)
	if ret != ERROR_SUCCESS {
		return fmt.Errorf("CancelMibChangeNotify2 failed: %w", convertWindowsError(syscall.Errno(ret)))
	}

	notificationMu.Lock()
	delete(notificationCallbacks, handle)
	notificationMu.Unlock()

	return nil
}

// =============================================================================
// Helper Functions
// =============================================================================

// convertWindowsError translates Windows error codes to Go errors.
func convertWindowsError(errno syscall.Errno) error {
	switch errno {
	case ERROR_BUFFER_OVERFLOW:
		return fmt.Errorf("buffer too small")
	case ERROR_INVALID_PARAMETER:
		return fmt.Errorf("invalid parameter")
	case ERROR_NOT_SUPPORTED:
		return fmt.Errorf("operation not supported")
	case ERROR_NO_DATA:
		return fmt.Errorf("no data available")
	case ERROR_FILE_NOT_FOUND:
		return fmt.Errorf("interface not found")
	case ERROR_ACCESS_DENIED:
		return fmt.Errorf("access denied, administrator privileges required")
	default:
		return fmt.Errorf("error code %d", errno)
	}
}

// operStatusToString converts operational status to string.
func operStatusToString(status uint32) string {
	switch status {
	case IfOperStatusUp:
		return "UP"
	case IfOperStatusDown:
		return "DOWN"
	case IfOperStatusTesting:
		return "TESTING"
	case IfOperStatusUnknown:
		return "UNKNOWN"
	case IfOperStatusDormant:
		return "DORMANT"
	case IfOperStatusNotPresent:
		return "NOT_PRESENT"
	case IfOperStatusLowerLayerDown:
		return "LOWER_LAYER_DOWN"
	default:
		return fmt.Sprintf("STATUS_%d", status)
	}
}

// protocolToString converts route protocol to string.
func protocolToString(protocol uint32) string {
	switch protocol {
	case MIB_IPPROTO_OTHER:
		return "OTHER"
	case MIB_IPPROTO_LOCAL:
		return "LOCAL"
	case MIB_IPPROTO_NETMGMT:
		return "STATIC"
	case MIB_IPPROTO_ICMP:
		return "ICMP"
	case MIB_IPPROTO_RIP:
		return "RIP"
	case MIB_IPPROTO_OSPF:
		return "OSPF"
	case MIB_IPPROTO_BGP:
		return "BGP"
	default:
		return fmt.Sprintf("PROTO_%d", protocol)
	}
}

// arpStateToString converts ARP state to string.
func arpStateToString(state uint32) string {
	switch state {
	case NlnsUnreachable:
		return "UNREACHABLE"
	case NlnsIncomplete:
		return "INCOMPLETE"
	case NlnsProbe:
		return "PROBE"
	case NlnsDelay:
		return "DELAY"
	case NlnsStale:
		return "STALE"
	case NlnsReachable:
		return "REACHABLE"
	case NlnsPermanent:
		return "PERMANENT"
	default:
		return fmt.Sprintf("STATE_%d", state)
	}
}

// formatMACFromBytes formats MAC address from byte slice.
func formatMACFromBytes(mac []byte) string {
	if len(mac) == 0 {
		return ""
	}
	parts := make([]string, len(mac))
	for i, b := range mac {
		parts[i] = fmt.Sprintf("%02X", b)
	}
	return strings.Join(parts, ":")
}

// socketAddressToIP extracts IP string from SOCKET_ADDRESS.
func socketAddressToIP(addr SOCKET_ADDRESS) string {
	if addr.Sockaddr == 0 {
		return ""
	}

	family := *(*uint16)(unsafe.Pointer(addr.Sockaddr))

	switch family {
	case AF_INET:
		sockIn := (*SOCKADDR_IN)(unsafe.Pointer(addr.Sockaddr))
		ip := net.IPv4(sockIn.Addr[0], sockIn.Addr[1], sockIn.Addr[2], sockIn.Addr[3])
		return ip.String()
	case AF_INET6:
		sockIn6 := (*SOCKADDR_IN6)(unsafe.Pointer(addr.Sockaddr))
		ip := net.IP(sockIn6.Addr[:])
		return ip.String()
	}

	return ""
}

// sockaddrInetToString converts SOCKADDR_INET to IP string.
func sockaddrInetToString(addr *SOCKADDR_INET) string {
	switch addr.Family {
	case AF_INET:
		ip := net.IPv4(addr.Data[2], addr.Data[3], addr.Data[4], addr.Data[5])
		return ip.String()
	case AF_INET6:
		ip := net.IP(addr.Data[2:18])
		return ip.String()
	}
	return ""
}

// ipToUint32 converts net.IP to uint32 in network byte order.
func ipToUint32(ip net.IP) uint32 {
	ip4 := ip.To4()
	if ip4 == nil {
		return 0
	}
	return uint32(ip4[0])<<24 | uint32(ip4[1])<<16 | uint32(ip4[2])<<8 | uint32(ip4[3])
}

// uint32ToIP converts uint32 to net.IP.
func uint32ToIP(addr uint32) net.IP {
	return net.IPv4(
		byte(addr>>24),
		byte(addr>>16),
		byte(addr>>8),
		byte(addr),
	)
}

// ValidateIPAddress validates an IP address.
func ValidateIPAddress(ip net.IP) error {
	if ip == nil {
		return fmt.Errorf("IP address is nil")
	}
	if ip.To4() == nil {
		return fmt.Errorf("only IPv4 addresses supported")
	}
	return nil
}

// ValidateSubnetMask validates a subnet mask.
func ValidateSubnetMask(mask net.IPMask) error {
	if len(mask) == 0 {
		return fmt.Errorf("subnet mask is empty")
	}
	ones, bits := mask.Size()
	if bits == 0 {
		return fmt.Errorf("invalid subnet mask format")
	}
	if ones < 8 || ones > 30 {
		return fmt.Errorf("subnet mask should be between /8 and /30")
	}
	return nil
}
