//go:build windows
// +build windows

// Package platform provides Windows IP Helper API wrappers for device detection
// using pure Go syscalls (no CGO required)
package platform

import (
	"fmt"
	"net"
	"sync"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
)

var (
	iphlpapi            = windows.NewLazySystemDLL("iphlpapi.dll")
	procGetIpNetTable   = iphlpapi.NewProc("GetIpNetTable")
	procGetAdaptersInfo = iphlpapi.NewProc("GetAdaptersInfo")
	procGetIfEntry      = iphlpapi.NewProc("GetIfEntry")
)

// ARP entry types
const (
	MIB_IPNET_TYPE_OTHER   = 1
	MIB_IPNET_TYPE_INVALID = 2
	MIB_IPNET_TYPE_DYNAMIC = 3
	MIB_IPNET_TYPE_STATIC  = 4
)

// MIB_IPNETROW represents an ARP table entry (legacy API, works on all Windows)
type MIB_IPNETROW struct {
	Index       uint32
	PhysAddrLen uint32
	PhysAddr    [8]byte
	Addr        uint32 // IPv4 address as uint32
	Type        uint32
}

// MIB_IPNETTABLE represents the ARP table
type MIB_IPNETTABLE struct {
	NumEntries uint32
	Table      [1]MIB_IPNETROW // Variable length array
}

// IP_ADAPTER_INFO for adapter enumeration
type IP_ADAPTER_INFO struct {
	Next                *IP_ADAPTER_INFO
	ComboIndex          uint32
	AdapterName         [260]byte
	Description         [132]byte
	AddressLength       uint32
	Address             [8]byte
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

type IP_ADDR_STRING struct {
	Next      *IP_ADDR_STRING
	IpAddress [16]byte
	IpMask    [16]byte
	Context   uint32
}

// MIB_IFROW for interface info
type MIB_IFROW struct {
	Name            [256]uint16
	Index           uint32
	Type            uint32
	Mtu             uint32
	Speed           uint32
	PhysAddrLen     uint32
	PhysAddr        [8]byte
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

// NotificationType represents the type of IP address change
type NotificationType uint32

const (
	NotifyTypeAdd             NotificationType = 1
	NotifyTypeDelete          NotificationType = 2
	NotifyTypeParameterChange NotificationType = 3
)

// IPNotification represents an IP address change notification
type IPNotification struct {
	NotifyType     NotificationType
	InterfaceIndex uint32
	IPAddress      string
}

// ARPEntry represents an ARP table entry
type ARPEntry struct {
	IPAddress      string
	MACAddress     string
	InterfaceIndex uint32
	Type           string // dynamic, static, other
	State          string // reachable, unreachable, stale
}

// InterfaceInfo represents network interface details
type InterfaceInfo struct {
	Index        uint32
	Name         string
	FriendlyName string
	Description  string
	Type         uint32
	OperStatus   uint32
	PhysicalAddr string
	MTU          uint32
}

// Callback management (polling-based since pure Go can't use NotifyUnicastIpAddressChange)
var (
	callbackMutex sync.RWMutex
	callbackFunc  func(notification IPNotification)
	pollingActive bool
	stopPolling   chan struct{}
)

// RegisterIPChangeCallback starts polling for IP changes (pure Go alternative)
// Note: Uses polling since NotifyUnicastIpAddressChange requires CGO
func RegisterIPChangeCallback(callback func(notification IPNotification)) error {
	callbackMutex.Lock()
	defer callbackMutex.Unlock()

	if pollingActive {
		return fmt.Errorf("IP change callback already registered")
	}

	callbackFunc = callback
	pollingActive = true
	stopPolling = make(chan struct{})

	// Start polling goroutine (500ms interval for reasonable detection speed)
	go pollForIPChanges()

	return nil
}

// UnregisterIPChangeCallback stops IP change polling
func UnregisterIPChangeCallback() error {
	callbackMutex.Lock()
	defer callbackMutex.Unlock()

	if !pollingActive {
		return nil
	}

	close(stopPolling)
	pollingActive = false
	callbackFunc = nil
	return nil
}

// pollForIPChanges polls ARP table for new entries
func pollForIPChanges() {
	var lastEntries = make(map[string]bool)

	// Initial snapshot
	entries, _ := GetARPTable()
	for _, e := range entries {
		lastEntries[e.IPAddress] = true
	}

	ticker := time.NewTicker(500 * time.Millisecond)
	defer ticker.Stop()

	for {
		select {
		case <-stopPolling:
			return
		case <-ticker.C:

			entries, err := GetARPTable()
			if err != nil {
				continue
			}

			currentEntries := make(map[string]bool)
			for _, e := range entries {
				currentEntries[e.IPAddress] = true

				// Check if this is a new entry
				if !lastEntries[e.IPAddress] {
					callbackMutex.RLock()
					cb := callbackFunc
					callbackMutex.RUnlock()

					if cb != nil {
						notification := IPNotification{
							NotifyType:     NotifyTypeAdd,
							InterfaceIndex: e.InterfaceIndex,
							IPAddress:      e.IPAddress,
						}
						go cb(notification)
					}
				}
			}

			// Check for removed entries
			for ip := range lastEntries {
				if !currentEntries[ip] {
					callbackMutex.RLock()
					cb := callbackFunc
					callbackMutex.RUnlock()

					if cb != nil {
						notification := IPNotification{
							NotifyType:     NotifyTypeDelete,
							InterfaceIndex: 0,
							IPAddress:      ip,
						}
						go cb(notification)
					}
				}
			}

			lastEntries = currentEntries
		}
	}
}

// GetARPTable returns all ARP table entries using GetIpNetTable
func GetARPTable() ([]ARPEntry, error) {
	// First call to get required size
	var size uint32 = 0
	procGetIpNetTable.Call(0, uintptr(unsafe.Pointer(&size)), 0)

	if size == 0 {
		return []ARPEntry{}, nil
	}

	// Allocate buffer
	buffer := make([]byte, size)
	ret, _, _ := procGetIpNetTable.Call(
		uintptr(unsafe.Pointer(&buffer[0])),
		uintptr(unsafe.Pointer(&size)),
		0,
	)

	if ret != 0 {
		return nil, fmt.Errorf("GetIpNetTable failed: error %d", ret)
	}

	// Parse table
	table := (*MIB_IPNETTABLE)(unsafe.Pointer(&buffer[0]))
	if table.NumEntries == 0 {
		return []ARPEntry{}, nil
	}

	entries := make([]ARPEntry, 0, table.NumEntries)

	// Calculate offset to first row
	rowOffset := unsafe.Offsetof(table.Table)
	rowSize := unsafe.Sizeof(MIB_IPNETROW{})

	for i := uint32(0); i < table.NumEntries; i++ {
		rowPtr := (*MIB_IPNETROW)(unsafe.Pointer(uintptr(unsafe.Pointer(&buffer[0])) + rowOffset + uintptr(i)*rowSize))

		// Convert IP address
		ipBytes := make([]byte, 4)
		ipBytes[0] = byte(rowPtr.Addr)
		ipBytes[1] = byte(rowPtr.Addr >> 8)
		ipBytes[2] = byte(rowPtr.Addr >> 16)
		ipBytes[3] = byte(rowPtr.Addr >> 24)
		ipAddr := net.IPv4(ipBytes[0], ipBytes[1], ipBytes[2], ipBytes[3]).String()

		// Convert MAC address
		macAddr := fmt.Sprintf("%02X:%02X:%02X:%02X:%02X:%02X",
			rowPtr.PhysAddr[0], rowPtr.PhysAddr[1],
			rowPtr.PhysAddr[2], rowPtr.PhysAddr[3],
			rowPtr.PhysAddr[4], rowPtr.PhysAddr[5])

		// Skip invalid entries
		if macAddr == "00:00:00:00:00:00" {
			continue
		}

		// Determine type
		entryType := "other"
		switch rowPtr.Type {
		case MIB_IPNET_TYPE_DYNAMIC:
			entryType = "dynamic"
		case MIB_IPNET_TYPE_STATIC:
			entryType = "static"
		case MIB_IPNET_TYPE_INVALID:
			continue // Skip invalid entries
		}

		entries = append(entries, ARPEntry{
			IPAddress:      ipAddr,
			MACAddress:     macAddr,
			InterfaceIndex: rowPtr.Index,
			Type:           entryType,
			State:          "reachable",
		})
	}

	return entries, nil
}

// GetARPEntryByIP returns ARP entry for specific IP address
func GetARPEntryByIP(ipAddress string) (*ARPEntry, error) {
	entries, err := GetARPTable()
	if err != nil {
		return nil, err
	}

	for _, entry := range entries {
		if entry.IPAddress == ipAddress {
			return &entry, nil
		}
	}

	return nil, fmt.Errorf("ARP entry not found for IP: %s", ipAddress)
}

// GetARPEntryByMAC returns ARP entry for specific MAC address
func GetARPEntryByMAC(macAddress string) (*ARPEntry, error) {
	entries, err := GetARPTable()
	if err != nil {
		return nil, err
	}

	for _, entry := range entries {
		if entry.MACAddress == macAddress {
			return &entry, nil
		}
	}

	return nil, fmt.Errorf("ARP entry not found for MAC: %s", macAddress)
}

// GetNetworkInterfaces returns all network interfaces
func GetNetworkInterfaces() ([]InterfaceInfo, error) {
	// Get required buffer size
	var size uint32 = 0
	procGetAdaptersInfo.Call(0, uintptr(unsafe.Pointer(&size)))

	if size == 0 {
		size = 15000 // Default size
	}

	buffer := make([]byte, size)
	ret, _, _ := procGetAdaptersInfo.Call(
		uintptr(unsafe.Pointer(&buffer[0])),
		uintptr(unsafe.Pointer(&size)),
	)

	if ret != 0 {
		return nil, fmt.Errorf("GetAdaptersInfo failed: error %d", ret)
	}

	var interfaces []InterfaceInfo
	adapter := (*IP_ADAPTER_INFO)(unsafe.Pointer(&buffer[0]))

	for adapter != nil {
		// Get interface details
		ifRow := MIB_IFROW{Index: adapter.Index}
		procGetIfEntry.Call(uintptr(unsafe.Pointer(&ifRow)))

		info := InterfaceInfo{
			Index:       adapter.Index,
			Name:        bytesToString(adapter.AdapterName[:]),
			Description: bytesToString(adapter.Description[:]),
			Type:        adapter.Type,
			OperStatus:  ifRow.OperStatus,
			MTU:         ifRow.Mtu,
		}

		// MAC address
		if adapter.AddressLength >= 6 {
			info.PhysicalAddr = fmt.Sprintf("%02X:%02X:%02X:%02X:%02X:%02X",
				adapter.Address[0], adapter.Address[1],
				adapter.Address[2], adapter.Address[3],
				adapter.Address[4], adapter.Address[5])
		}

		// Friendly name from description
		info.FriendlyName = info.Description

		interfaces = append(interfaces, info)
		adapter = adapter.Next
	}

	return interfaces, nil
}

// GetInterfaceByIndex returns interface info for specific index
func GetInterfaceByIndex(ifIndex uint32) (*InterfaceInfo, error) {
	interfaces, err := GetNetworkInterfaces()
	if err != nil {
		return nil, err
	}

	for _, iface := range interfaces {
		if iface.Index == ifIndex {
			return &iface, nil
		}
	}

	return nil, fmt.Errorf("interface not found: index %d", ifIndex)
}

// GetInterfaceName returns the name for an interface index
func GetInterfaceName(ifIndex uint32) (string, error) {
	iface, err := GetInterfaceByIndex(ifIndex)
	if err != nil {
		return "", err
	}
	return iface.FriendlyName, nil
}

// IsIPChangeCallbackRegistered returns whether callback is active
func IsIPChangeCallbackRegistered() bool {
	callbackMutex.RLock()
	defer callbackMutex.RUnlock()
	return pollingActive
}

// Helper: Convert null-terminated byte array to string
func bytesToString(b []byte) string {
	for i, v := range b {
		if v == 0 {
			return string(b[:i])
		}
	}
	return string(b)
}
