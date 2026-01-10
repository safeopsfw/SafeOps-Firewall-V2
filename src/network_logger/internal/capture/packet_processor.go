package capture

import (
	"crypto/md5"
	"encoding/hex"
	"fmt"
	"time"

	"github.com/safeops/network_logger/internal/dedup"
	"github.com/safeops/network_logger/internal/flow"
	"github.com/safeops/network_logger/internal/hotspot"
	"github.com/safeops/network_logger/internal/parser"
	"github.com/safeops/network_logger/internal/process"
	"github.com/safeops/network_logger/internal/stats"
	"github.com/safeops/network_logger/internal/tls"
	"github.com/safeops/network_logger/pkg/models"
)

// PacketProcessor processes raw packets into structured logs
type PacketProcessor struct {
	ethParser      *parser.EthernetParser
	ipParser       *parser.IPParser
	transportParser *parser.TransportParser
	dnsParser      *parser.DNSParser
	httpParser     *parser.HTTPParser
	tlsParser      *parser.TLSParser
	flowTracker    *flow.Tracker
	dedupEngine    *dedup.Engine
	processCorr    *process.Correlator
	hotspotTracker *hotspot.DeviceTracker
	tlsDecryptor   *tls.Decryptor
	statsCollector *stats.Collector
}

// NewPacketProcessor creates a new packet processor
func NewPacketProcessor(
	flowTracker *flow.Tracker,
	dedupEngine *dedup.Engine,
	processCorr *process.Correlator,
	hotspotTracker *hotspot.DeviceTracker,
	tlsDecryptor *tls.Decryptor,
	statsCollector *stats.Collector,
) *PacketProcessor {
	return &PacketProcessor{
		ethParser:       parser.NewEthernetParser(),
		ipParser:        parser.NewIPParser(),
		transportParser: parser.NewTransportParser(),
		dnsParser:       parser.NewDNSParser(),
		httpParser:      parser.NewHTTPParser(),
		tlsParser:       parser.NewTLSParser(),
		flowTracker:     flowTracker,
		dedupEngine:     dedupEngine,
		processCorr:     processCorr,
		hotspotTracker:  hotspotTracker,
		tlsDecryptor:    tlsDecryptor,
		statsCollector:  statsCollector,
	}
}

// ProcessPacket converts a raw packet into a structured log entry
func (p *PacketProcessor) ProcessPacket(rawPkt *models.RawPacket) (*models.PacketLog, error) {
	// Update stats
	p.statsCollector.IncrementCaptured()
	p.statsCollector.AddBytes(int64(rawPkt.WireLen))

	// Parse packet layers
	layers, err := ParsePacketLayers(rawPkt.Data)
	if err != nil {
		return nil, err
	}

	// Generate packet ID
	hash := md5.Sum(rawPkt.Data)
	packetID := fmt.Sprintf("pkt_%x", hash[:8])

	// Build packet log
	pktLog := &models.PacketLog{
		PacketID: packetID,
		Timestamp: models.Timestamp{
			Epoch:   float64(rawPkt.Timestamp.UnixNano()) / 1e9,
			ISO8601: rawPkt.Timestamp.Format(time.RFC3339Nano),
		},
		CaptureInfo: models.CaptureInfo{
			Interface:     rawPkt.Interface,
			CaptureLength: rawPkt.Length,
			WireLength:    rawPkt.WireLen,
		},
		Layers: models.Layers{},
	}

	// Parse Ethernet layer
	if layers.Ethernet != nil {
		pktLog.Layers.Datalink = p.ethParser.Parse(layers.Ethernet)
	}

	// Parse IP layer
	if layers.IPv4 != nil {
		pktLog.Layers.Network = p.ipParser.ParseIPv4(layers.IPv4)
	} else if layers.IPv6 != nil {
		pktLog.Layers.Network = p.ipParser.ParseIPv6(layers.IPv6)
	}

	// Filter out localhost traffic (127.0.0.0/8)
	if pktLog.Layers.Network != nil {
		srcIP := pktLog.Layers.Network.SrcIP
		dstIP := pktLog.Layers.Network.DstIP

		// Check if either IP is localhost
		if isLocalhostIP(srcIP) || isLocalhostIP(dstIP) {
			return nil, nil // Skip localhost packets
		}
	}

	// Parse Transport layer
	var flags *models.TCPFlags
	if layers.TCP != nil {
		pktLog.Layers.Transport = p.transportParser.ParseTCP(layers.TCP)
		flags = pktLog.Layers.Transport.TCPFlags
	} else if layers.UDP != nil {
		pktLog.Layers.Transport = p.transportParser.ParseUDP(layers.UDP)
	}

	// Parse Payload
	if len(layers.Payload) > 0 {
		pktLog.Layers.Payload = &models.PayloadLayer{
			Length:  len(layers.Payload),
			DataHex: hex.EncodeToString(layers.Payload),
		}
		if len(layers.Payload) <= 128 {
			pktLog.Layers.Payload.Preview = string(layers.Payload)
		} else {
			pktLog.Layers.Payload.Preview = string(layers.Payload[:128])
		}
	}

	// Parse Application layer protocols
	pktLog.ParsedApplication = p.parseApplicationLayer(layers)

	// Flow tracking
	if pktLog.Layers.Network != nil && pktLog.Layers.Transport != nil {
		proto := "TCP"
		if pktLog.Layers.Transport.Protocol == 17 {
			proto = "UDP"
		}

		flowContext := p.flowTracker.UpdateFlow(
			pktLog.Layers.Network.SrcIP,
			pktLog.Layers.Network.DstIP,
			pktLog.Layers.Transport.SrcPort,
			pktLog.Layers.Transport.DstPort,
			proto,
			rawPkt.WireLen,
			flags,
		)

		pktLog.FlowContext = flowContext

		// Process correlation
		if procInfo := p.processCorr.GetProcessInfo(
			pktLog.Layers.Network.SrcIP,
			pktLog.Layers.Transport.SrcPort,
			pktLog.Layers.Network.DstIP,
			pktLog.Layers.Transport.DstPort,
			proto,
		); procInfo != nil {
			pktLog.FlowContext.ProcessInfo = procInfo
		}
	}

	// Hotspot device tracking
	if pktLog.Layers.Network != nil {
		srcIP := pktLog.Layers.Network.SrcIP
		dstIP := pktLog.Layers.Network.DstIP

		if p.hotspotTracker.IsHotspotIP(srcIP) && pktLog.Layers.Datalink != nil {
			pktLog.HotspotDevice = p.hotspotTracker.TrackDevice(srcIP, pktLog.Layers.Datalink.SrcMAC)
		} else if p.hotspotTracker.IsHotspotIP(dstIP) && pktLog.Layers.Datalink != nil {
			pktLog.HotspotDevice = p.hotspotTracker.TrackDevice(dstIP, pktLog.Layers.Datalink.DstMAC)
		}
	}

	// Deduplication
	shouldLog, reason := p.dedupEngine.ShouldLog(pktLog)
	pktLog.Deduplication = models.Deduplication{
		Unique: shouldLog,
		Reason: reason,
	}

	if !shouldLog {
		p.statsCollector.IncrementDeduplicated()
		return nil, nil
	}

	p.statsCollector.IncrementLogged()

	return pktLog, nil
}

// parseApplicationLayer detects and parses application layer protocols
func (p *PacketProcessor) parseApplicationLayer(layers *PacketLayers) models.ParsedApplication {
	app := models.ParsedApplication{
		DetectedProtocol: "unknown",
		Confidence:       "low",
	}

	// DNS
	if layers.DNS != nil {
		app.DetectedProtocol = "dns"
		app.Confidence = "high"
		app.DNS = p.dnsParser.Parse(layers.DNS)
		return app
	}

	// Check ports for protocol detection
	var srcPort, dstPort uint16
	if layers.TCP != nil {
		srcPort = uint16(layers.TCP.SrcPort)
		dstPort = uint16(layers.TCP.DstPort)
	} else if layers.UDP != nil {
		srcPort = uint16(layers.UDP.SrcPort)
		dstPort = uint16(layers.UDP.DstPort)
	}

	// HTTP
	if parser.IsHTTPPort(srcPort) || parser.IsHTTPPort(dstPort) {
		if len(layers.Payload) > 0 {
			if httpData := p.httpParser.Parse(layers.Payload); httpData != nil {
				app.DetectedProtocol = "http"
				app.Confidence = "high"
				app.HTTP = httpData
				if httpData.UserAgent != "" {
					app.UserAgent = httpData.UserAgent
				}
				return app
			}
		}
	}

	// TLS
	if parser.IsHTTPSPort(srcPort) || parser.IsHTTPSPort(dstPort) {
		if len(layers.Payload) > 0 {
			if tlsData := p.tlsParser.Parse(layers.Payload); tlsData != nil {
				app.DetectedProtocol = "tls"
				app.Confidence = "high"
				app.TLS = tlsData
				return app
			}
		}
	}

	// Fallback: Check if payload looks like a known protocol
	if len(layers.Payload) > 0 {
		app.DetectedProtocol = "data"
		app.Confidence = "medium"
	}

	return app
}

// isLocalhostIP checks if an IP address is localhost (127.0.0.0/8 or ::1)
func isLocalhostIP(ip string) bool {
	// Check IPv4 localhost (127.0.0.0/8)
	if len(ip) >= 4 && ip[:4] == "127." {
		return true
	}
	// Check IPv6 localhost (::1)
	if ip == "::1" || ip == "0:0:0:0:0:0:0:1" {
		return true
	}
	return false
}
