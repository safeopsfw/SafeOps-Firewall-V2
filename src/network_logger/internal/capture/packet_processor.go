package capture

import (
	"crypto/md5"
	"crypto/sha1"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"net"
	"time"

	"github.com/safeops/network_logger/internal/dedup"
	"github.com/safeops/network_logger/internal/flow"
	"github.com/safeops/network_logger/internal/geoip"
	"github.com/safeops/network_logger/internal/hotspot"
	"github.com/safeops/network_logger/internal/parser"
	"github.com/safeops/network_logger/internal/process"
	"github.com/safeops/network_logger/internal/stats"
	"github.com/safeops/network_logger/internal/tls"
	"github.com/safeops/network_logger/pkg/models"
)

// PacketProcessor processes raw packets into structured logs
type PacketProcessor struct {
	ethParser       *parser.EthernetParser
	ipParser        *parser.IPParser
	transportParser *parser.TransportParser
	dnsParser       *parser.DNSParser
	httpParser      *parser.HTTPParser
	tlsParser       *parser.TLSParser
	flowTracker     *flow.Tracker
	dedupEngine     *dedup.Engine
	processCorr     *process.Correlator
	hotspotTracker  *hotspot.DeviceTracker
	tlsDecryptor    *tls.Decryptor
	statsCollector  *stats.Collector
	geoLookup       *geoip.Lookup
	localSubnets    []*net.IPNet
}

// NewPacketProcessor creates a new packet processor
func NewPacketProcessor(
	flowTracker *flow.Tracker,
	dedupEngine *dedup.Engine,
	processCorr *process.Correlator,
	hotspotTracker *hotspot.DeviceTracker,
	tlsDecryptor *tls.Decryptor,
	statsCollector *stats.Collector,
	geoLookup *geoip.Lookup,
) *PacketProcessor {
	localCIDRs := []string{
		"10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16",
		"169.254.0.0/16", "fe80::/10",
	}
	var localNets []*net.IPNet
	for _, cidr := range localCIDRs {
		_, network, _ := net.ParseCIDR(cidr)
		if network != nil {
			localNets = append(localNets, network)
		}
	}

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
		geoLookup:       geoLookup,
		localSubnets:    localNets,
	}
}

// ProcessPacket converts a raw packet into a structured log entry
func (p *PacketProcessor) ProcessPacket(rawPkt *models.RawPacket) (*models.PacketLog, error) {
	p.statsCollector.IncrementCaptured()
	p.statsCollector.AddBytes(int64(rawPkt.WireLen))

	layers, err := ParsePacketLayers(rawPkt.Data)
	if err != nil {
		return nil, err
	}

	hash := md5.Sum(rawPkt.Data)
	packetID := fmt.Sprintf("pkt_%x", hash[:8])

	pktLog := &models.PacketLog{
		PacketID:  packetID,
		EventType: "packet",
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

	// L2: Ethernet
	if layers.Ethernet != nil {
		pktLog.Layers.Datalink = p.ethParser.Parse(layers.Ethernet)
	}

	// L2: ARP
	if layers.ARP != nil {
		pktLog.Layers.ARP = p.parseARP(layers)
		pktLog.AppProto = "arp"
		p.statsCollector.IncrementLogged()
		return pktLog, nil
	}

	// L3: IP
	if layers.IPv4 != nil {
		pktLog.Layers.Network = p.ipParser.ParseIPv4(layers.IPv4)
	} else if layers.IPv6 != nil {
		pktLog.Layers.Network = p.ipParser.ParseIPv6(layers.IPv6)
	}

	// Filter localhost
	if pktLog.Layers.Network != nil {
		srcIP := pktLog.Layers.Network.SrcIP
		dstIP := pktLog.Layers.Network.DstIP

		if isLocalhostIP(srcIP) || isLocalhostIP(dstIP) {
			return nil, nil
		}

		// GeoIP
		if p.geoLookup != nil && p.geoLookup.IsEnabled() {
			if srcGeo := p.geoLookup.Lookup(srcIP); srcGeo != nil {
				pktLog.SrcGeo = &models.GeoInfo{
					Country: srcGeo.Country, CountryName: srcGeo.CountryName,
					City: srcGeo.City, Latitude: srcGeo.Latitude, Longitude: srcGeo.Longitude,
					ASN: srcGeo.ASN, ASNOrg: srcGeo.ASNOrg,
				}
			}
			if dstGeo := p.geoLookup.Lookup(dstIP); dstGeo != nil {
				pktLog.DstGeo = &models.GeoInfo{
					Country: dstGeo.Country, CountryName: dstGeo.CountryName,
					City: dstGeo.City, Latitude: dstGeo.Latitude, Longitude: dstGeo.Longitude,
					ASN: dstGeo.ASN, ASNOrg: dstGeo.ASNOrg,
				}
			}
		}

		// Direction
		pktLog.Direction = p.classifyDirection(srcIP, dstIP)
	}

	// L3.5: ICMPv4
	if layers.ICMPv4 != nil {
		pktLog.Layers.ICMP = &models.ICMPLayer{
			Type:     uint8(layers.ICMPv4.TypeCode.Type()),
			Code:     uint8(layers.ICMPv4.TypeCode.Code()),
			Checksum: layers.ICMPv4.Checksum,
			ID:       layers.ICMPv4.Id,
			Seq:      layers.ICMPv4.Seq,
		}
		pktLog.AppProto = "icmp"
	}

	// L4: Transport
	var flags *models.TCPFlags
	if layers.TCP != nil {
		pktLog.Layers.Transport = p.transportParser.ParseTCP(layers.TCP)
		flags = pktLog.Layers.Transport.TCPFlags
	} else if layers.UDP != nil {
		pktLog.Layers.Transport = p.transportParser.ParseUDP(layers.UDP)
	}

	// Community ID
	if pktLog.Layers.Network != nil {
		pktLog.CommunityID = p.computeCommunityID(pktLog)
	}

	// Payload (512 bytes hex for IDS)
	if len(layers.Payload) > 0 {
		maxHexLen := 512
		hexData := layers.Payload
		if len(hexData) > maxHexLen {
			hexData = hexData[:maxHexLen]
		}

		pktLog.Layers.Payload = &models.PayloadLayer{
			Length:  len(layers.Payload),
			DataHex: hex.EncodeToString(hexData),
		}

		previewLen := 64
		if len(layers.Payload) < previewLen {
			previewLen = len(layers.Payload)
		}
		pktLog.Layers.Payload.Preview = sanitizePrintable(layers.Payload[:previewLen])
	}

	// L7: Application
	pktLog.ParsedApplication = p.parseApplicationLayer(layers)

	// Set app_proto
	if pktLog.AppProto == "" {
		proto := pktLog.ParsedApplication.DetectedProtocol
		if proto != "unknown" && proto != "data" {
			pktLog.AppProto = proto
		}
	}

	// Flow tracking
	if pktLog.Layers.Network != nil && pktLog.Layers.Transport != nil {
		proto := "TCP"
		if pktLog.Layers.Transport.Protocol == 17 {
			proto = "UDP"
		}

		flowContext := p.flowTracker.UpdateFlow(
			pktLog.Layers.Network.SrcIP, pktLog.Layers.Network.DstIP,
			pktLog.Layers.Transport.SrcPort, pktLog.Layers.Transport.DstPort,
			proto, rawPkt.WireLen, flags,
		)
		pktLog.FlowContext = flowContext

		if procInfo := p.processCorr.GetProcessInfo(
			pktLog.Layers.Network.SrcIP, pktLog.Layers.Transport.SrcPort,
			pktLog.Layers.Network.DstIP, pktLog.Layers.Transport.DstPort,
			proto,
		); procInfo != nil {
			pktLog.FlowContext.ProcessInfo = procInfo
		}
	}

	// Hotspot device tracking
	if pktLog.Layers.Network != nil && pktLog.Layers.Datalink != nil {
		srcIP := pktLog.Layers.Network.SrcIP
		dstIP := pktLog.Layers.Network.DstIP
		wireLen := rawPkt.WireLen
		iface := rawPkt.Interface

		if p.hotspotTracker.IsHotspotIP(srcIP) {
			pktLog.HotspotDevice = p.hotspotTracker.TrackDevice(srcIP, pktLog.Layers.Datalink.SrcMAC)
			p.hotspotTracker.UpdateStats(srcIP, wireLen, true, iface)
		}
		if p.hotspotTracker.IsHotspotIP(dstIP) {
			if pktLog.HotspotDevice == nil {
				pktLog.HotspotDevice = p.hotspotTracker.TrackDevice(dstIP, pktLog.Layers.Datalink.DstMAC)
			} else {
				p.hotspotTracker.TrackDevice(dstIP, pktLog.Layers.Datalink.DstMAC)
			}
			p.hotspotTracker.UpdateStats(dstIP, wireLen, false, iface)
		}
	}

	// Dedup
	shouldLog, _ := p.dedupEngine.ShouldLog(pktLog)
	if !shouldLog {
		p.statsCollector.IncrementDeduplicated()
		return nil, nil
	}

	p.statsCollector.IncrementLogged()
	return pktLog, nil
}

// parseARP extracts ARP layer data
func (p *PacketProcessor) parseARP(layers *PacketLayers) *models.ARPLayer {
	arp := layers.ARP
	if arp == nil {
		return nil
	}
	opStr := "unknown"
	switch arp.Operation {
	case 1:
		opStr = "request"
	case 2:
		opStr = "reply"
	}
	return &models.ARPLayer{
		Operation:       arp.Operation,
		OperationString: opStr,
		SenderMAC:       net.HardwareAddr(arp.SourceHwAddress).String(),
		SenderIP:        net.IP(arp.SourceProtAddress).String(),
		TargetMAC:       net.HardwareAddr(arp.DstHwAddress).String(),
		TargetIP:        net.IP(arp.DstProtAddress).String(),
	}
}

// classifyDirection classifies packet direction
func (p *PacketProcessor) classifyDirection(srcIP, dstIP string) string {
	srcLocal := p.isLocalIP(srcIP)
	dstLocal := p.isLocalIP(dstIP)
	if srcLocal && dstLocal {
		return "internal"
	}
	if srcLocal && !dstLocal {
		return "outbound"
	}
	if !srcLocal && dstLocal {
		return "inbound"
	}
	return "external"
}

func (p *PacketProcessor) isLocalIP(ipStr string) bool {
	ip := net.ParseIP(ipStr)
	if ip == nil {
		return false
	}
	for _, network := range p.localSubnets {
		if network.Contains(ip) {
			return true
		}
	}
	return false
}

// computeCommunityID computes Community ID v1 hash
func (p *PacketProcessor) computeCommunityID(pkt *models.PacketLog) string {
	if pkt.Layers.Network == nil {
		return ""
	}

	srcIP := net.ParseIP(pkt.Layers.Network.SrcIP)
	dstIP := net.ParseIP(pkt.Layers.Network.DstIP)
	if srcIP == nil || dstIP == nil {
		return ""
	}
	if v4 := srcIP.To4(); v4 != nil {
		srcIP = v4
	}
	if v4 := dstIP.To4(); v4 != nil {
		dstIP = v4
	}

	proto := pkt.Layers.Network.Protocol
	var srcPort, dstPort uint16
	if pkt.Layers.Transport != nil {
		srcPort = pkt.Layers.Transport.SrcPort
		dstPort = pkt.Layers.Transport.DstPort
	}
	if pkt.Layers.ICMP != nil {
		srcPort = uint16(pkt.Layers.ICMP.Type)
		dstPort = uint16(pkt.Layers.ICMP.Code)
	}

	// Determine ordering
	isOrdered := true
	cmpLen := len(srcIP)
	if len(dstIP) < cmpLen {
		cmpLen = len(dstIP)
	}
	for i := 0; i < cmpLen; i++ {
		if srcIP[i] < dstIP[i] {
			break
		}
		if srcIP[i] > dstIP[i] {
			isOrdered = false
			break
		}
	}
	if srcIP.Equal(dstIP) {
		isOrdered = srcPort <= dstPort
	}

	if !isOrdered {
		srcIP, dstIP = dstIP, srcIP
		srcPort, dstPort = dstPort, srcPort
	}

	// seed(2) + src_ip + dst_ip + proto(1) + pad(1) + src_port(2) + dst_port(2)
	buf := make([]byte, 0, 2+len(srcIP)+len(dstIP)+4)
	portBytes := make([]byte, 2)

	binary.BigEndian.PutUint16(portBytes, 0) // seed=0
	buf = append(buf, portBytes...)
	buf = append(buf, srcIP...)
	buf = append(buf, dstIP...)
	buf = append(buf, proto, 0)
	binary.BigEndian.PutUint16(portBytes, srcPort)
	buf = append(buf, portBytes...)
	binary.BigEndian.PutUint16(portBytes, dstPort)
	buf = append(buf, portBytes...)

	h := sha1.Sum(buf)
	return "1:" + base64.StdEncoding.EncodeToString(h[:])
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
		if app.DNS != nil {
			app.DNS.RcodeString = dnsRcodeToString(app.DNS.Rcode)
		}
		return app
	}

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
				if tlsData.ClientHello != nil {
					tlsData.JA3Hash = p.tlsParser.ComputeJA3(tlsData.ClientHello)
				}
				if tlsData.ServerHello != nil {
					tlsData.JA3SHash = p.tlsParser.ComputeJA3S(tlsData.ServerHello)
				}
				return app
			}
		}
	}

	// SSH (port 22)
	if srcPort == 22 || dstPort == 22 {
		app.DetectedProtocol = "ssh"
		if len(layers.Payload) > 3 && string(layers.Payload[:3]) == "SSH" {
			app.Confidence = "high"
		} else {
			app.Confidence = "medium"
		}
		return app
	}

	// FTP (port 21)
	if srcPort == 21 || dstPort == 21 {
		app.DetectedProtocol = "ftp"
		app.Confidence = "medium"
		return app
	}

	// SMTP (port 25, 587)
	if srcPort == 25 || dstPort == 25 || srcPort == 587 || dstPort == 587 {
		app.DetectedProtocol = "smtp"
		app.Confidence = "medium"
		return app
	}

	// SMB (port 445)
	if srcPort == 445 || dstPort == 445 {
		app.DetectedProtocol = "smb"
		app.Confidence = "medium"
		return app
	}

	// RDP (port 3389)
	if srcPort == 3389 || dstPort == 3389 {
		app.DetectedProtocol = "rdp"
		app.Confidence = "medium"
		return app
	}

	if len(layers.Payload) > 0 {
		app.DetectedProtocol = "data"
		app.Confidence = "medium"
	}

	return app
}

func dnsRcodeToString(rcode uint8) string {
	switch rcode {
	case 0:
		return "NOERROR"
	case 1:
		return "FORMERR"
	case 2:
		return "SERVFAIL"
	case 3:
		return "NXDOMAIN"
	case 4:
		return "NOTIMP"
	case 5:
		return "REFUSED"
	default:
		return fmt.Sprintf("RCODE%d", rcode)
	}
}

func sanitizePrintable(data []byte) string {
	result := make([]byte, 0, len(data))
	for _, b := range data {
		if b >= 32 && b < 127 {
			result = append(result, b)
		} else {
			result = append(result, '.')
		}
	}
	return string(result)
}

func isLocalhostIP(ip string) bool {
	if len(ip) >= 4 && ip[:4] == "127." {
		return true
	}
	if ip == "::1" || ip == "0:0:0:0:0:0:0:1" {
		return true
	}
	return false
}
