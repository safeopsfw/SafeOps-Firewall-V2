package driver

import (
	"context"
	"encoding/binary"
	"fmt"
	"net"
	"strings"
	"sync"
	"sync/atomic"

	"safeops-engine/internal/logger"

	"github.com/wiresock/ndisapi-go"
	"golang.org/x/sys/windows"
)

// PacketDirection indicates if packet is inbound or outbound
type PacketDirection int

const (
	DirectionInbound  PacketDirection = 1
	DirectionOutbound PacketDirection = 2
)

// Protocol constants
const (
	ProtoTCP uint8 = 6
	ProtoUDP uint8 = 17
)

// ParsedPacket contains extracted packet information
type ParsedPacket struct {
	Direction     PacketDirection
	SrcIP         net.IP
	DstIP         net.IP
	SrcPort       uint16
	DstPort       uint16
	Protocol      uint8
	Payload       []byte
	RawBuffer     *ndisapi.IntermediateBuffer
	AdapterHandle ndisapi.Handle
	AdapterName   string

	// Domain extraction (for Firewall/IDS/IPS engines)
	Domain       string // Extracted domain name (from DNS/SNI/HTTP)
	DomainSource string // Source of domain: "DNS", "SNI", "HTTP", or empty
}

// PacketHandler is called for each captured packet
// Return true to pass packet through, false to drop
type PacketHandler func(pkt *ParsedPacket) bool

// Adapter represents a network adapter
type Adapter struct {
	Index  int
	Name   string
	Handle ndisapi.Handle
	MAC    string
}

// Driver wraps the WinpkFilter (NDISAPI) driver
type Driver struct {
	log         *logger.Logger
	api         *ndisapi.NdisApi
	adapterList *ndisapi.TcpAdapterList
	adapters    []Adapter // All physical adapters we're monitoring
	handler     PacketHandler

	// Stats
	packetsRead    uint64
	packetsWritten uint64
	packetsDropped uint64

	mu sync.RWMutex
}

// Open initializes the WinpkFilter driver
func Open(log *logger.Logger) (*Driver, error) {
	log.Info("Opening WinpkFilter driver (NDISAPI)", nil)

	api, err := ndisapi.NewNdisApi()
	if err != nil {
		return nil, fmt.Errorf("failed to open NDISAPI driver: %w", err)
	}

	if !api.IsDriverLoaded() {
		return nil, fmt.Errorf("WinpkFilter driver is not loaded")
	}

	version, err := api.GetVersion()
	if err != nil {
		return nil, fmt.Errorf("failed to get driver version: %w", err)
	}

	major := (version >> 24) & 0xFF
	minor := (version >> 16) & 0xFF
	revision := version & 0xFFFF

	log.Info("WinpkFilter driver opened", map[string]interface{}{
		"version": fmt.Sprintf("%d.%d.%d", major, minor, revision),
	})

	d := &Driver{
		log: log,
		api: api,
	}

	return d, nil
}

// SetHandler sets the packet handler callback
func (d *Driver) SetHandler(h PacketHandler) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.handler = h
}

// GetAdapters returns all network adapters
func (d *Driver) GetAdapters() ([]Adapter, error) {
	adapterList, err := d.api.GetTcpipBoundAdaptersInfo()
	if err != nil {
		return nil, fmt.Errorf("failed to get adapters: %w", err)
	}

	d.adapterList = adapterList

	adapters := make([]Adapter, 0, adapterList.AdapterCount)
	for i := uint32(0); i < adapterList.AdapterCount; i++ {
		name := d.api.ConvertWindows2000AdapterName(string(adapterList.AdapterNameList[i][:]))
		adapters = append(adapters, Adapter{
			Index:  int(i),
			Name:   name,
			Handle: adapterList.AdapterHandle[i],
			MAC:    formatMAC(adapterList.CurrentAddress[i][:]),
		})
	}

	return adapters, nil
}

// isPhysicalAdapter checks if an adapter is physical (not virtual).
// Must work on ANY system — no hardcoded adapter names.
// Filters by name patterns AND MAC OUI prefixes (for adapters with
// generic names like "Ethernet 2" that are actually VirtualBox).
func isPhysicalAdapter(adapter Adapter) bool {
	// Skip adapters with null MAC (disabled/virtual)
	if adapter.MAC == "00:00:00:00:00:00" {
		return false
	}

	// Skip known virtual adapter name patterns
	virtualPatterns := []string{
		"VMware", "VirtualBox", "vEthernet", "Hyper-V",
		"Loopback", "Bluetooth", "WAN Miniport",
		"Teredo", "ISATAP", "6to4",
	}
	for _, pattern := range virtualPatterns {
		if strings.Contains(adapter.Name, pattern) {
			return false
		}
	}

	// Skip "Local Area Connection*" — Windows auto-generated virtual adapters
	if strings.HasPrefix(strings.ToLower(adapter.Name), "local area connection*") {
		return false
	}

	// Skip virtual adapters by MAC OUI (first 3 bytes).
	// Catches adapters with generic names like "Ethernet 2" that are actually virtual.
	virtualMACs := []string{
		"0a:00:27", "08:00:27", // VirtualBox
		"00:50:56", "00:0c:29", // VMware
		"00:15:5d",             // Hyper-V
		"00:03:ff",             // Microsoft virtual
	}
	for _, prefix := range virtualMACs {
		if strings.HasPrefix(adapter.MAC, prefix) {
			return false
		}
	}

	return true
}

// SetTunnelModeAll sets tunnel mode on all physical adapters
func (d *Driver) SetTunnelModeAll() error {
	allAdapters, err := d.GetAdapters()
	if err != nil {
		return err
	}

	d.adapters = nil

	for _, adapter := range allAdapters {
		if !isPhysicalAdapter(adapter) {
			d.log.Info("Skipping virtual adapter", map[string]interface{}{
				"name": adapter.Name,
				"mac":  adapter.MAC,
			})
			fmt.Printf("  Skipping adapter: %s [%s] (virtual)\n", adapter.Name, adapter.MAC)
			continue
		}

		mode := ndisapi.AdapterMode{
			AdapterHandle: adapter.Handle,
			Flags:         ndisapi.MSTCP_FLAG_SENT_TUNNEL | ndisapi.MSTCP_FLAG_RECV_TUNNEL,
		}

		if err := d.api.SetAdapterMode(&mode); err != nil {
			d.log.Warn("Failed to set tunnel mode", map[string]interface{}{
				"adapter": adapter.Name,
				"error":   err.Error(),
			})
			continue
		}

		d.log.Info("Tunnel mode activated", map[string]interface{}{
			"adapter": adapter.Name,
			"mac":     adapter.MAC,
		})
		fmt.Printf("  Tunneled adapter: %s [%s]\n", adapter.Name, adapter.MAC)
		d.adapters = append(d.adapters, adapter)
	}

	if len(d.adapters) == 0 {
		return fmt.Errorf("no physical adapters found")
	}

	d.log.Info("Monitoring adapters", map[string]interface{}{"count": len(d.adapters)})
	return nil
}

// ProcessPacketsAll processes packets from all monitored adapters
func (d *Driver) ProcessPacketsAll(ctx context.Context) {
	d.log.Info("Multi-NIC packet processing started", map[string]interface{}{
		"adapters": len(d.adapters),
	})

	// Create event for packet arrival
	event, err := windows.CreateEvent(nil, 0, 0, nil)
	if err != nil {
		d.log.Error("Failed to create event", map[string]interface{}{"error": err.Error()})
		return
	}
	defer windows.CloseHandle(event)

	// Set event for all adapters
	for _, adapter := range d.adapters {
		if err := d.api.SetPacketEvent(adapter.Handle, event); err != nil {
			d.log.Error("Failed to set packet event", map[string]interface{}{
				"adapter": adapter.Name,
				"error":   err.Error(),
			})
		}
	}

	d.log.Info("Waiting for packets on all NICs...", nil)

	// Main packet loop
	for {
		select {
		case <-ctx.Done():
			d.log.Info("Packet processing loop stopped", nil)
			return
		default:
			result, _ := windows.WaitForSingleObject(event, 100)

			if result == windows.WAIT_OBJECT_0 {
				// Read from all adapters
				for _, adapter := range d.adapters {
					d.readAndProcessFromAdapter(adapter)
				}
			}
		}
	}
}

// readAndProcessFromAdapter reads packets from a specific adapter
func (d *Driver) readAndProcessFromAdapter(adapter Adapter) {
	buffer := &ndisapi.IntermediateBuffer{}
	request := &ndisapi.EtherRequest{
		AdapterHandle:  adapter.Handle,
		EthernetPacket: ndisapi.EthernetPacket{Buffer: buffer},
	}

	for {
		// NOTE: ndisapi-go ReadPacket returns TRUE on ERROR, FALSE on success (inverted!)
		hasError := d.api.ReadPacket(request)
		if hasError {
			return
		}

		atomic.AddUint64(&d.packetsRead, 1)
		d.processPacket(buffer, adapter)
	}
}

// processPacket handles a single packet
func (d *Driver) processPacket(buffer *ndisapi.IntermediateBuffer, adapter Adapter) {
	parsed := d.parsePacket(buffer, adapter)
	if parsed == nil {
		d.reinjectPacket(buffer, adapter.Handle)
		return
	}

	d.mu.RLock()
	handler := d.handler
	d.mu.RUnlock()

	shouldPass := true
	if handler != nil {
		shouldPass = handler(parsed)
	}

	if shouldPass {
		d.reinjectPacket(buffer, adapter.Handle)
		atomic.AddUint64(&d.packetsWritten, 1)
	} else {
		atomic.AddUint64(&d.packetsDropped, 1)
	}
}

// parsePacket extracts IP/TCP/UDP information from raw packet (IPv4 + IPv6)
func (d *Driver) parsePacket(buffer *ndisapi.IntermediateBuffer, adapter Adapter) *ParsedPacket {
	data := buffer.Buffer[:buffer.Length]

	if len(data) < 34 {
		return nil
	}

	etherType := binary.BigEndian.Uint16(data[12:14])

	// IPv4
	if etherType == 0x0800 {
		return d.parseIPv4(buffer, adapter, data[14:])
	}

	// IPv6
	if etherType == 0x86DD {
		return d.parseIPv6(buffer, adapter, data[14:])
	}

	return nil
}

// parseIPv4 handles IPv4 packets
func (d *Driver) parseIPv4(buffer *ndisapi.IntermediateBuffer, adapter Adapter, ipHeader []byte) *ParsedPacket {
	if len(ipHeader) < 20 {
		return nil
	}

	version := ipHeader[0] >> 4
	if version != 4 {
		return nil
	}

	headerLen := int(ipHeader[0]&0x0F) * 4
	if headerLen < 20 || len(ipHeader) < headerLen {
		return nil
	}

	protocol := ipHeader[9]
	srcIP := net.IP(ipHeader[12:16])
	dstIP := net.IP(ipHeader[16:20])

	direction := DirectionOutbound
	if buffer.DeviceFlags == ndisapi.PACKET_FLAG_ON_RECEIVE {
		direction = DirectionInbound
	}

	parsed := &ParsedPacket{
		Direction:     direction,
		SrcIP:         srcIP,
		DstIP:         dstIP,
		Protocol:      protocol,
		RawBuffer:     buffer,
		AdapterHandle: adapter.Handle,
		AdapterName:   adapter.Name,
	}

	transportHeader := ipHeader[headerLen:]
	if len(transportHeader) < 4 {
		return parsed
	}

	if protocol == ProtoTCP || protocol == ProtoUDP {
		parsed.SrcPort = binary.BigEndian.Uint16(transportHeader[0:2])
		parsed.DstPort = binary.BigEndian.Uint16(transportHeader[2:4])

		payloadOffset := 4
		if protocol == ProtoTCP && len(transportHeader) >= 13 {
			tcpHeaderLen := int(transportHeader[12]>>4) * 4
			if tcpHeaderLen >= 20 {
				payloadOffset = tcpHeaderLen
			}
		} else if protocol == ProtoUDP {
			payloadOffset = 8
		}

		if len(transportHeader) > payloadOffset {
			parsed.Payload = transportHeader[payloadOffset:]
		}
	}

	return parsed
}

// parseIPv6 handles IPv6 packets (minimal, fast)
func (d *Driver) parseIPv6(buffer *ndisapi.IntermediateBuffer, adapter Adapter, ipHeader []byte) *ParsedPacket {
	if len(ipHeader) < 40 {
		return nil
	}

	version := ipHeader[0] >> 4
	if version != 6 {
		return nil
	}

	protocol := ipHeader[6] // Next header
	srcIP := net.IP(ipHeader[8:24])
	dstIP := net.IP(ipHeader[24:40])

	direction := DirectionOutbound
	if buffer.DeviceFlags == ndisapi.PACKET_FLAG_ON_RECEIVE {
		direction = DirectionInbound
	}

	parsed := &ParsedPacket{
		Direction:     direction,
		SrcIP:         srcIP,
		DstIP:         dstIP,
		Protocol:      protocol,
		RawBuffer:     buffer,
		AdapterHandle: adapter.Handle,
		AdapterName:   adapter.Name,
	}

	// IPv6 header is always 40 bytes (no options in base header)
	transportHeader := ipHeader[40:]
	if len(transportHeader) < 4 {
		return parsed
	}

	if protocol == ProtoTCP || protocol == ProtoUDP {
		parsed.SrcPort = binary.BigEndian.Uint16(transportHeader[0:2])
		parsed.DstPort = binary.BigEndian.Uint16(transportHeader[2:4])

		payloadOffset := 4
		if protocol == ProtoTCP && len(transportHeader) >= 13 {
			tcpHeaderLen := int(transportHeader[12]>>4) * 4
			if tcpHeaderLen >= 20 {
				payloadOffset = tcpHeaderLen
			}
		} else if protocol == ProtoUDP {
			payloadOffset = 8
		}

		if len(transportHeader) > payloadOffset {
			parsed.Payload = transportHeader[payloadOffset:]
		}
	}

	return parsed
}

// reinjectPacket sends a packet back to the network stack
func (d *Driver) reinjectPacket(buffer *ndisapi.IntermediateBuffer, adapterHandle ndisapi.Handle) {
	request := &ndisapi.EtherRequest{
		AdapterHandle:  adapterHandle,
		EthernetPacket: ndisapi.EthernetPacket{Buffer: buffer},
	}

	if buffer.DeviceFlags == ndisapi.PACKET_FLAG_ON_SEND {
		d.api.SendPacketToAdapter(request)
	} else {
		d.api.SendPacketToMstcp(request)
	}
}

// GetStats returns packet statistics
func (d *Driver) GetStats() (read, written, dropped uint64) {
	return atomic.LoadUint64(&d.packetsRead),
		atomic.LoadUint64(&d.packetsWritten),
		atomic.LoadUint64(&d.packetsDropped)
}

// GetAPI returns the underlying NDISAPI handle for verdict engine creation
func (d *Driver) GetAPI() *ndisapi.NdisApi {
	return d.api
}

// Close closes the driver
func (d *Driver) Close() error {
	d.log.Info("Closing WinpkFilter driver", nil)

	// Step 1: Reset all adapter modes FIRST (stops intercepting new packets)
	for _, adapter := range d.adapters {
		mode := ndisapi.AdapterMode{
			AdapterHandle: adapter.Handle,
			Flags:         0,
		}
		if err := d.api.SetAdapterMode(&mode); err != nil {
			d.log.Warn("Failed to reset adapter mode", map[string]interface{}{
				"adapter": adapter.Name,
				"error":   err.Error(),
			})
		} else {
			d.log.Info("Adapter mode reset (tunnel disabled)", map[string]interface{}{
				"adapter": adapter.Name,
			})
		}
	}

	// Step 2: Flush queued packets (releases any packets still held by the driver)
	for _, adapter := range d.adapters {
		if err := d.api.FlushAdapterPacketQueue(adapter.Handle); err != nil {
			d.log.Warn("Failed to flush adapter packet queue", map[string]interface{}{
				"adapter": adapter.Name,
				"error":   err.Error(),
			})
		} else {
			d.log.Info("Adapter packet queue flushed", map[string]interface{}{
				"adapter": adapter.Name,
			})
		}
	}

	// Step 3: Close the driver handle
	if d.api != nil {
		d.api.Close()
	}

	read, written, dropped := d.GetStats()
	d.log.Info("Driver stats", map[string]interface{}{
		"packets_read":    read,
		"packets_written": written,
		"packets_dropped": dropped,
	})

	return nil
}

// formatMAC formats a MAC address to string
func formatMAC(mac []byte) string {
	if len(mac) < 6 {
		return "00:00:00:00:00:00"
	}
	return fmt.Sprintf("%02x:%02x:%02x:%02x:%02x:%02x",
		mac[0], mac[1], mac[2], mac[3], mac[4], mac[5])
}
