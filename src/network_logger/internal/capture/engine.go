package capture

import (
	"context"
	"fmt"
	"log"
	"sync"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"github.com/safeops/network_logger/pkg/models"
)

// CaptureEngine manages packet capture from multiple interfaces
type CaptureEngine struct {
	handles      map[string]*pcap.Handle
	packetQueue  chan *models.RawPacket
	stopChan     chan struct{}
	mu           sync.RWMutex
	config       CaptureConfig
	packetSource map[string]*gopacket.PacketSource
}

// CaptureConfig contains capture configuration
type CaptureConfig struct {
	Promiscuous    bool
	SnapshotLength int32
	Timeout        time.Duration
	BPFFilter      string
}

// NewCaptureEngine creates a new packet capture engine
func NewCaptureEngine(config CaptureConfig) *CaptureEngine {
	if config.SnapshotLength == 0 {
		config.SnapshotLength = 1600
	}
	if config.Timeout == 0 {
		config.Timeout = pcap.BlockForever
	}

	return &CaptureEngine{
		handles:      make(map[string]*pcap.Handle),
		packetQueue:  make(chan *models.RawPacket, 10000), // Buffered channel
		stopChan:     make(chan struct{}),
		config:       config,
		packetSource: make(map[string]*gopacket.PacketSource),
	}
}

// AddInterface adds an interface to capture from
func (e *CaptureEngine) AddInterface(ifName string) error {
	e.mu.Lock()
	defer e.mu.Unlock()

	// Check if already capturing
	if _, exists := e.handles[ifName]; exists {
		return nil
	}

	// Open interface
	handle, err := pcap.OpenLive(
		ifName,
		e.config.SnapshotLength,
		e.config.Promiscuous,
		e.config.Timeout,
	)
	if err != nil {
		return fmt.Errorf("failed to open interface %s: %w", ifName, err)
	}

	// Apply BPF filter if specified
	if e.config.BPFFilter != "" {
		if err := handle.SetBPFFilter(e.config.BPFFilter); err != nil {
			handle.Close()
			return fmt.Errorf("failed to set BPF filter on %s: %w", ifName, err)
		}
	}

	e.handles[ifName] = handle
	e.packetSource[ifName] = gopacket.NewPacketSource(handle, handle.LinkType())

	log.Printf("📡 Started capturing on: %s", ifName)

	return nil
}

// Start begins packet capture on all interfaces
func (e *CaptureEngine) Start(ctx context.Context, interfaces []string) error {
	// Add all interfaces
	for _, ifName := range interfaces {
		if err := e.AddInterface(ifName); err != nil {
			log.Printf("⚠️  Warning: Could not capture on %s: %v", ifName, err)
			continue
		}

		// Start capture goroutine for this interface
		go e.captureLoop(ctx, ifName)
	}

	if len(e.handles) == 0 {
		return fmt.Errorf("no interfaces available for capture")
	}

	return nil
}

// captureLoop captures packets from a single interface
func (e *CaptureEngine) captureLoop(ctx context.Context, ifName string) {
	e.mu.RLock()
	source, exists := e.packetSource[ifName]
	e.mu.RUnlock()

	if !exists {
		return
	}

	packets := source.Packets()

	for {
		select {
		case <-ctx.Done():
			return
		case <-e.stopChan:
			return
		case packet, ok := <-packets:
			if !ok {
				return
			}

			// Convert to RawPacket
			rawPkt := &models.RawPacket{
				Data:      packet.Data(),
				Timestamp: packet.Metadata().Timestamp,
				Length:    packet.Metadata().CaptureLength,
				WireLen:   packet.Metadata().Length,
				Interface: ifName,
			}

			// Send to processing queue (non-blocking)
			select {
			case e.packetQueue <- rawPkt:
			default:
				// Queue full, drop packet (prevents blocking)
			}
		}
	}
}

// GetPacketQueue returns the packet queue channel
func (e *CaptureEngine) GetPacketQueue() <-chan *models.RawPacket {
	return e.packetQueue
}

// Stop stops all packet capture
func (e *CaptureEngine) Stop() {
	close(e.stopChan)

	e.mu.Lock()
	defer e.mu.Unlock()

	for ifName, handle := range e.handles {
		handle.Close()
		log.Printf("🛑 Stopped capturing on: %s", ifName)
	}

	close(e.packetQueue)
}

// GetStats returns capture statistics for all interfaces
func (e *CaptureEngine) GetStats() map[string]*pcap.Stats {
	e.mu.RLock()
	defer e.mu.RUnlock()

	stats := make(map[string]*pcap.Stats)
	for ifName, handle := range e.handles {
		if stat, err := handle.Stats(); err == nil {
			stats[ifName] = stat
		}
	}

	return stats
}

// ParsePacketLayers extracts basic layer information from packet data
func ParsePacketLayers(data []byte) (*PacketLayers, error) {
	packet := gopacket.NewPacket(data, layers.LayerTypeEthernet, gopacket.Default)

	pl := &PacketLayers{}

	// Extract Ethernet layer
	if ethLayer := packet.Layer(layers.LayerTypeEthernet); ethLayer != nil {
		eth, _ := ethLayer.(*layers.Ethernet)
		pl.Ethernet = eth
	}

	// Extract IPv4 layer
	if ipv4Layer := packet.Layer(layers.LayerTypeIPv4); ipv4Layer != nil {
		ipv4, _ := ipv4Layer.(*layers.IPv4)
		pl.IPv4 = ipv4
	}

	// Extract IPv6 layer
	if ipv6Layer := packet.Layer(layers.LayerTypeIPv6); ipv6Layer != nil {
		ipv6, _ := ipv6Layer.(*layers.IPv6)
		pl.IPv6 = ipv6
	}

	// Extract TCP layer
	if tcpLayer := packet.Layer(layers.LayerTypeTCP); tcpLayer != nil {
		tcp, _ := tcpLayer.(*layers.TCP)
		pl.TCP = tcp
	}

	// Extract UDP layer
	if udpLayer := packet.Layer(layers.LayerTypeUDP); udpLayer != nil {
		udp, _ := udpLayer.(*layers.UDP)
		pl.UDP = udp
	}

	// Extract DNS layer
	if dnsLayer := packet.Layer(layers.LayerTypeDNS); dnsLayer != nil {
		dns, _ := dnsLayer.(*layers.DNS)
		pl.DNS = dns
	}

	// Extract ICMPv4 layer
	if icmpLayer := packet.Layer(layers.LayerTypeICMPv4); icmpLayer != nil {
		icmp, _ := icmpLayer.(*layers.ICMPv4)
		pl.ICMPv4 = icmp
	}

	// Extract ARP layer
	if arpLayer := packet.Layer(layers.LayerTypeARP); arpLayer != nil {
		arp, _ := arpLayer.(*layers.ARP)
		pl.ARP = arp
	}

	// Extract application layer
	if appLayer := packet.ApplicationLayer(); appLayer != nil {
		pl.Payload = appLayer.Payload()
	}

	return pl, nil
}

// PacketLayers contains parsed gopacket layers
type PacketLayers struct {
	Ethernet *layers.Ethernet
	IPv4     *layers.IPv4
	IPv6     *layers.IPv6
	TCP      *layers.TCP
	UDP      *layers.UDP
	DNS      *layers.DNS
	ICMPv4   *layers.ICMPv4
	ARP      *layers.ARP
	Payload  []byte
}
