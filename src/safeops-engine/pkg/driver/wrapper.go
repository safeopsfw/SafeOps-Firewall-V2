// Package driver provides a public API wrapper around the internal driver package
package driver

import (
	"context"
	"net"
	"time"

	"safeops-engine/internal/config"
	"safeops-engine/internal/driver"
	"safeops-engine/internal/logger"
)

// PacketDirection indicates if packet is inbound or outbound
type PacketDirection int

const (
	DirectionInbound  PacketDirection = 1
	DirectionOutbound PacketDirection = 2
)

// ParsedPacket contains extracted packet information
type ParsedPacket struct {
	Timestamp    time.Time
	Direction    PacketDirection
	SrcIP        net.IP
	DstIP        net.IP
	SrcPort      uint16
	DstPort      uint16
	Protocol     uint8
	Payload      []byte
	AdapterName  string
	Domain       string
	DomainSource string
}

// PacketHandler is called for each captured packet
// Return true to pass packet through, false to drop
type PacketHandler func(pkt *ParsedPacket) bool

// Driver wraps the internal WinpkFilter driver
type Driver struct {
	internal *driver.Driver
	log      *logger.Logger
}

// Open initializes the WinpkFilter driver
func Open() (*Driver, error) {
	// Create logger
	log := logger.New(config.LoggingConfig{
		Level:  "info",
		Format: "json",
	})

	drv, err := driver.Open(log)
	if err != nil {
		return nil, err
	}

	return &Driver{internal: drv, log: log}, nil
}

// Close closes the driver
func (d *Driver) Close() error {
	if d.log != nil {
		d.log.Close()
	}
	return d.internal.Close()
}

// SetPacketHandler sets the packet handler function
func (d *Driver) SetPacketHandler(handler PacketHandler) {
	d.internal.SetHandler(func(pkt *driver.ParsedPacket) bool {
		// Convert internal packet to public packet
		pubPkt := &ParsedPacket{
			Timestamp:    time.Now(),
			SrcIP:        pkt.SrcIP,
			DstIP:        pkt.DstIP,
			SrcPort:      pkt.SrcPort,
			DstPort:      pkt.DstPort,
			Protocol:     pkt.Protocol,
			Payload:      pkt.Payload,
			AdapterName:  pkt.AdapterName,
			Domain:       pkt.Domain,
			DomainSource: pkt.DomainSource,
		}

		if pkt.Direction == driver.DirectionInbound {
			pubPkt.Direction = DirectionInbound
		} else {
			pubPkt.Direction = DirectionOutbound
		}

		return handler(pubPkt)
	})
}

// StartCapture starts packet capture
func (d *Driver) StartCapture(ctx context.Context) error {
	// Set tunnel mode on all physical adapters
	if err := d.internal.SetTunnelModeAll(); err != nil {
		return err
	}

	// Start processing packets in background
	go d.internal.ProcessPacketsAll(ctx)

	return nil
}

// GetStats returns packet statistics
func (d *Driver) GetStats() (read, written, dropped uint64) {
	return d.internal.GetStats()
}
