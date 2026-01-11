//go:build windows
// +build windows

// Package driver implements Windows-specific packet capture using WinPcap/Npcap.
// This provides a Go-friendly abstraction over the libpcap C API for capturing
// raw network packets on Windows systems.
package driver

/*
#cgo CFLAGS: -I"C:/Npcap/Include"
#cgo LDFLAGS: -L"C:/Npcap/Lib/x64" -lwpcap -lPacket

#include <stdlib.h>
#include <pcap.h>

// Helper to check if wpcap.dll is available
int check_wpcap_available() {
    HMODULE hLib = LoadLibraryA("wpcap.dll");
    if (hLib == NULL) {
        return 0;
    }
    FreeLibrary(hLib);
    return 1;
}
*/
import "C"

import (
	"fmt"
	"net"
	"sync"
	"time"
	"unsafe"
)

// =============================================================================
// Constants
// =============================================================================

const (
	// DefaultSnaplen is the default snapshot length (max bytes to capture per packet)
	DefaultSnaplen = 65535

	// DefaultTimeout is the default read timeout for packet capture
	DefaultTimeout = 100 * time.Millisecond

	// MaxPacketSize is the maximum Ethernet frame size
	MaxPacketSize = 65535

	// ErrorBufferSize is the size of the error buffer for pcap functions
	ErrorBufferSize = C.PCAP_ERRBUF_SIZE
)

// =============================================================================
// Types
// =============================================================================

// WinPcapDevice represents a Windows network device for packet capture.
type WinPcapDevice struct {
	handle      *C.pcap_t
	deviceName  string
	description string
	isLoopback  bool
	snaplen     int
	promiscuous bool
	timeout     time.Duration
	isOpen      bool

	mu sync.Mutex
}

// NetworkDevice represents a discovered network device.
type NetworkDevice struct {
	Name        string   // Device name (e.g., "\Device\NPF_{GUID}")
	Description string   // Human-readable description
	Addresses   []string // IP addresses assigned to device
	IsLoopback  bool     // True if loopback adapter
	Flags       uint32   // Device flags
}

// PacketMetadata contains metadata about a captured packet.
type PacketMetadata struct {
	Timestamp     time.Time // Packet arrival timestamp
	CaptureLength int       // Bytes captured
	ActualLength  int       // Original packet length (may be truncated)
}

// CaptureStats contains packet capture statistics.
type CaptureStats struct {
	PacketsReceived           uint64 // Packets captured
	PacketsDropped            uint64 // Packets dropped by kernel
	PacketsDroppedByInterface uint64 // Packets dropped by NIC
}

// =============================================================================
// Device Enumeration
// =============================================================================

// EnumerateDevices discovers all network interfaces available for packet capture.
func EnumerateDevices() ([]*NetworkDevice, error) {
	var alldevs *C.pcap_if_t
	var errbuf [ErrorBufferSize]C.char

	// Find all devices
	if C.pcap_findalldevs(&alldevs, &errbuf[0]) == -1 {
		return nil, fmt.Errorf("pcap_findalldevs failed: %s", C.GoString(&errbuf[0]))
	}
	defer C.pcap_freealldevs(alldevs)

	var devices []*NetworkDevice

	// Iterate through device list
	for dev := alldevs; dev != nil; dev = dev.next {
		device := &NetworkDevice{
			Name:        C.GoString(dev.name),
			Description: C.GoString(dev.description),
			Flags:       uint32(dev.flags),
			IsLoopback:  (dev.flags & C.PCAP_IF_LOOPBACK) != 0,
		}

		// Extract addresses
		for addr := dev.addresses; addr != nil; addr = addr.next {
			if addr.addr == nil {
				continue
			}

			// Convert sockaddr to IP address
			ip := sockaddrToIP(addr.addr)
			if ip != "" {
				device.Addresses = append(device.Addresses, ip)
			}
		}

		devices = append(devices, device)
	}

	return devices, nil
}

// sockaddrToIP converts a C sockaddr to a Go IP string.
func sockaddrToIP(sa *C.struct_sockaddr) string {
	if sa == nil {
		return ""
	}

	switch sa.sa_family {
	case C.AF_INET:
		// IPv4
		sa4 := (*C.struct_sockaddr_in)(unsafe.Pointer(sa))
		ip := make(net.IP, 4)
		copy(ip, (*[4]byte)(unsafe.Pointer(&sa4.sin_addr))[:])
		return ip.String()
	case C.AF_INET6:
		// IPv6
		sa6 := (*C.struct_sockaddr_in6)(unsafe.Pointer(sa))
		ip := make(net.IP, 16)
		copy(ip, (*[16]byte)(unsafe.Pointer(&sa6.sin6_addr))[:])
		return ip.String()
	default:
		return ""
	}
}

// =============================================================================
// Device Opening and Closing
// =============================================================================

// OpenDevice opens a network device for packet capture.
func OpenDevice(deviceName string, snaplen int, promiscuous bool, timeout time.Duration) (*WinPcapDevice, error) {
	if snaplen <= 0 {
		snaplen = DefaultSnaplen
	}

	var errbuf [ErrorBufferSize]C.char
	cDeviceName := C.CString(deviceName)
	defer C.free(unsafe.Pointer(cDeviceName))

	// Convert timeout to milliseconds
	timeoutMs := int(timeout.Milliseconds())
	if timeoutMs <= 0 {
		timeoutMs = 1 // Minimum 1ms timeout
	}

	// Promiscuous mode flag
	promiscFlag := C.int(0)
	if promiscuous {
		promiscFlag = 1
	}

	// Open the device
	handle := C.pcap_open_live(
		cDeviceName,
		C.int(snaplen),
		promiscFlag,
		C.int(timeoutMs),
		&errbuf[0],
	)

	if handle == nil {
		return nil, fmt.Errorf("pcap_open_live failed for %s: %s", deviceName, C.GoString(&errbuf[0]))
	}

	device := &WinPcapDevice{
		handle:      handle,
		deviceName:  deviceName,
		snaplen:     snaplen,
		promiscuous: promiscuous,
		timeout:     timeout,
		isOpen:      true,
	}

	return device, nil
}

// Close closes the packet capture device and releases resources.
func (d *WinPcapDevice) Close() error {
	d.mu.Lock()
	defer d.mu.Unlock()

	if !d.isOpen || d.handle == nil {
		return nil
	}

	C.pcap_close(d.handle)
	d.handle = nil
	d.isOpen = false

	return nil
}

// IsOpen returns true if the device is currently open.
func (d *WinPcapDevice) IsOpen() bool {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.isOpen
}

// Name returns the device name.
func (d *WinPcapDevice) Name() string {
	return d.deviceName
}

// =============================================================================
// Packet Filter
// =============================================================================

// SetFilter compiles and applies a BPF filter expression.
// Example filter strings: "tcp port 80", "udp", "icmp", "host 192.168.1.1"
func (d *WinPcapDevice) SetFilter(filter string) error {
	d.mu.Lock()
	defer d.mu.Unlock()

	if !d.isOpen || d.handle == nil {
		return fmt.Errorf("device not open")
	}

	cFilter := C.CString(filter)
	defer C.free(unsafe.Pointer(cFilter))

	var fp C.struct_bpf_program

	// Compile the filter
	if C.pcap_compile(d.handle, &fp, cFilter, 1, C.PCAP_NETMASK_UNKNOWN) == -1 {
		return fmt.Errorf("pcap_compile failed: %s", d.getLastError())
	}
	defer C.pcap_freecode(&fp)

	// Apply the filter
	if C.pcap_setfilter(d.handle, &fp) == -1 {
		return fmt.Errorf("pcap_setfilter failed: %s", d.getLastError())
	}

	return nil
}

// =============================================================================
// Packet Reception
// =============================================================================

// NextPacket captures the next packet from the device.
// Returns nil, nil if timeout occurs (no packet available).
func (d *WinPcapDevice) NextPacket() ([]byte, *PacketMetadata, error) {
	d.mu.Lock()
	defer d.mu.Unlock()

	if !d.isOpen || d.handle == nil {
		return nil, nil, fmt.Errorf("device not open")
	}

	var header *C.struct_pcap_pkthdr
	var data *C.u_char

	result := C.pcap_next_ex(d.handle, &header, &data)

	switch result {
	case 1:
		// Packet received successfully
		captureLen := int(header.caplen)
		actualLen := int(header.len)

		// Copy packet data to Go slice
		packetData := C.GoBytes(unsafe.Pointer(data), C.int(captureLen))

		// Extract timestamp
		timestamp := time.Unix(
			int64(header.ts.tv_sec),
			int64(header.ts.tv_usec)*1000, // Convert microseconds to nanoseconds
		)

		metadata := &PacketMetadata{
			Timestamp:     timestamp,
			CaptureLength: captureLen,
			ActualLength:  actualLen,
		}

		return packetData, metadata, nil

	case 0:
		// Timeout - no packet available
		return nil, nil, nil

	case -1:
		// Error
		return nil, nil, fmt.Errorf("pcap_next_ex error: %s", d.getLastError())

	case -2:
		// End of file (when reading from savefile)
		return nil, nil, fmt.Errorf("end of capture file")

	default:
		return nil, nil, fmt.Errorf("pcap_next_ex unexpected return: %d", result)
	}
}

// =============================================================================
// Packet Injection
// =============================================================================

// SendPacket injects a raw packet onto the network.
// The packet should be a complete Ethernet frame.
func (d *WinPcapDevice) SendPacket(packet []byte) error {
	d.mu.Lock()
	defer d.mu.Unlock()

	if !d.isOpen || d.handle == nil {
		return fmt.Errorf("device not open")
	}

	if len(packet) == 0 {
		return fmt.Errorf("empty packet")
	}

	if len(packet) > MaxPacketSize {
		return fmt.Errorf("packet too large: %d bytes (max %d)", len(packet), MaxPacketSize)
	}

	result := C.pcap_sendpacket(
		d.handle,
		(*C.u_char)(unsafe.Pointer(&packet[0])),
		C.int(len(packet)),
	)

	if result == -1 {
		return fmt.Errorf("pcap_sendpacket failed: %s", d.getLastError())
	}

	return nil
}

// =============================================================================
// Statistics
// =============================================================================

// GetStats retrieves packet capture statistics.
func (d *WinPcapDevice) GetStats() (*CaptureStats, error) {
	d.mu.Lock()
	defer d.mu.Unlock()

	if !d.isOpen || d.handle == nil {
		return nil, fmt.Errorf("device not open")
	}

	var stats C.struct_pcap_stat

	if C.pcap_stats(d.handle, &stats) == -1 {
		return nil, fmt.Errorf("pcap_stats failed: %s", d.getLastError())
	}

	return &CaptureStats{
		PacketsReceived:           uint64(stats.ps_recv),
		PacketsDropped:            uint64(stats.ps_drop),
		PacketsDroppedByInterface: uint64(stats.ps_ifdrop),
	}, nil
}

// =============================================================================
// Error Handling
// =============================================================================

// getLastError retrieves the last error message from libpcap.
func (d *WinPcapDevice) getLastError() string {
	if d.handle == nil {
		return "no device handle"
	}
	return C.GoString(C.pcap_geterr(d.handle))
}

// =============================================================================
// Helper Functions
// =============================================================================

// IsWinPcapInstalled checks if WinPcap/Npcap is installed on the system.
func IsWinPcapInstalled() bool {
	return C.check_wpcap_available() == 1
}

// GetWinPcapVersion returns the WinPcap/Npcap version string.
func GetWinPcapVersion() (string, error) {
	version := C.pcap_lib_version()
	if version == nil {
		return "", fmt.Errorf("unable to get WinPcap version")
	}
	return C.GoString(version), nil
}

// GetDataLinkType returns the data link type of the device.
func (d *WinPcapDevice) GetDataLinkType() (int, error) {
	d.mu.Lock()
	defer d.mu.Unlock()

	if !d.isOpen || d.handle == nil {
		return 0, fmt.Errorf("device not open")
	}

	dlt := C.pcap_datalink(d.handle)
	return int(dlt), nil
}

// GetDataLinkName returns the name of a data link type.
func GetDataLinkName(dlt int) string {
	name := C.pcap_datalink_val_to_name(C.int(dlt))
	if name == nil {
		return "UNKNOWN"
	}
	return C.GoString(name)
}

// SetNonBlocking sets the device to non-blocking mode.
func (d *WinPcapDevice) SetNonBlocking(nonblock bool) error {
	d.mu.Lock()
	defer d.mu.Unlock()

	if !d.isOpen || d.handle == nil {
		return fmt.Errorf("device not open")
	}

	var errbuf [ErrorBufferSize]C.char
	mode := C.int(0)
	if nonblock {
		mode = 1
	}

	if C.pcap_setnonblock(d.handle, mode, &errbuf[0]) == -1 {
		return fmt.Errorf("pcap_setnonblock failed: %s", C.GoString(&errbuf[0]))
	}

	return nil
}

// =============================================================================
// Callback-based Capture (for high-performance scenarios)
// =============================================================================

// PacketHandler is the callback function type for packet processing.
type PacketHandler func(packet []byte, metadata *PacketMetadata)

// CaptureLoop starts a capture loop that calls handler for each packet.
// Returns when count packets are captured, or on error.
// Use count = -1 for infinite capture (until Break is called).
func (d *WinPcapDevice) CaptureLoop(count int, handler PacketHandler) error {
	d.mu.Lock()
	if !d.isOpen || d.handle == nil {
		d.mu.Unlock()
		return fmt.Errorf("device not open")
	}
	d.mu.Unlock()

	// For Windows, we use a simple loop instead of pcap_loop
	// because CGO callback support is complex
	captured := 0
	for count == -1 || captured < count {
		packet, metadata, err := d.NextPacket()
		if err != nil {
			return err
		}
		if packet != nil {
			handler(packet, metadata)
			captured++
		}
	}

	return nil
}

// BreakLoop breaks out of a CaptureLoop.
func (d *WinPcapDevice) BreakLoop() {
	d.mu.Lock()
	defer d.mu.Unlock()

	if d.isOpen && d.handle != nil {
		C.pcap_breakloop(d.handle)
	}
}
