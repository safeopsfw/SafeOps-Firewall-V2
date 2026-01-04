package grpc

import (
	"context"
	"fmt"
	"log"

	"tls_proxy/internal/certcache"
	"tls_proxy/internal/injector"
	"tls_proxy/internal/integration"
	"tls_proxy/internal/mitm_handler"
	"tls_proxy/internal/packet"
	"tls_proxy/internal/sni_parser"
	pb "tls_proxy/proto"
)

// MITMPacketProcessor handles packets with full TLS MITM inspection
type MITMPacketProcessor struct {
	pb.UnimplementedPacketProcessingServiceServer
	dhcpMonitor *integration.DHCPMonitorClient
	injector    *injector.HTTPRedirectInjector
	mitmHandler *mitm_handler.DualTLSHandler
	certCache   *certcache.CertificateCache
	policyMode  string
	allowOnce   bool
	enableMITM  bool
}

// NewMITMPacketProcessor creates MITM-enabled packet processor
func NewMITMPacketProcessor(
	dhcpMonitor *integration.DHCPMonitorClient,
	stepCA *integration.StepCAClient,
	redirectURL, policyMode string,
	allowOnce, enableMITM bool,
) *MITMPacketProcessor {

	// Create certificate cache
	certCache := certcache.NewCertificateCache(stepCA, 24*3600000000000, 1000)

	// Create traffic inspector
	inspector := mitm_handler.NewTrafficInspector(true, false, 1024)

	// Create MITM handler
	mitmHandler := mitm_handler.NewDualTLSHandler(certCache, inspector)

	return &MITMPacketProcessor{
		dhcpMonitor: dhcpMonitor,
		injector:    injector.NewHTTPRedirectInjector(redirectURL),
		mitmHandler: mitmHandler,
		certCache:   certCache,
		policyMode:  policyMode,
		allowOnce:   allowOnce,
		enableMITM:  enableMITM,
	}
}

// ProcessPacket handles packet with MITM capabilities (HTTP + HTTPS inspection)
func (p *MITMPacketProcessor) ProcessPacket(ctx context.Context, req *pb.PacketRequest) (*pb.PacketResponse, error) {
	log.Printf("[MITM Processor] Packet: src=%s:%d dst=%s:%d proto=%s",
		req.SourceIp, req.SourcePort, req.DestIp, req.DestPort, req.Protocol)

	// Parse packet
	info, err := packet.ParsePacket(
		req.RawPacket,
		req.SourceIp,
		req.DestIp,
		req.SourcePort,
		req.DestPort,
		req.Protocol,
	)
	if err != nil {
		log.Printf("[MITM] Parse error: %v", err)
		return &pb.PacketResponse{Action: pb.PacketAction_FORWARD, Reason: "Parse error"}, nil
	}

	packetType := packet.ClassifyPacket(info)

	// Check if this is TLS ClientHello (for MITM)
	if packetType == "TLS" && sni_parser.IsClientHello(req.RawPacket) {
		return p.handleTLSClientHello(ctx, req, info)
	}

	// Handle HTTP
	if packet.ShouldIntercept(info) {
		return p.handleHTTP(ctx, req, info)
	}

	// Forward everything else
	return &pb.PacketResponse{
		Action: pb.PacketAction_FORWARD,
		Reason: "Not HTTP/HTTPS",
	}, nil
}

// handleTLSClientHello handles TLS ClientHello for MITM inspection
func (p *MITMPacketProcessor) handleTLSClientHello(ctx context.Context, req *pb.PacketRequest, info *packet.PacketInfo) (*pb.PacketResponse, error) {
	_ = info // Reserved for future use (packet metadata)
	// Extract SNI
	sniInfo, err := sni_parser.ExtractSNI(req.RawPacket)
	if err != nil || !sniInfo.Found {
		log.Printf("[MITM] No SNI found, forwarding")
		return &pb.PacketResponse{Action: pb.PacketAction_FORWARD, Reason: "No SNI"}, nil
	}

	domain := sniInfo.Domain
	log.Printf("[MITM] TLS ClientHello for domain: %s", domain)

	// Check device trust
	deviceInfo, err := p.dhcpMonitor.GetDeviceByIP(ctx, req.SourceIp)
	if err != nil {
		log.Printf("[MITM] DHCP query failed: %v", err)
		return &pb.PacketResponse{Action: pb.PacketAction_FORWARD, Reason: "DHCP unavailable"}, nil
	}

	log.Printf("[MITM] Device %s trust: %s, CA cert installed: %v", req.SourceIp, deviceInfo.TrustStatus, deviceInfo.CaCertInstalled)

	// Phase 3B: Only perform MITM if device has installed CA certificate
	if !deviceInfo.CaCertInstalled {
		// Device hasn't installed CA cert - don't intercept HTTPS
		log.Printf("[MITM] ⚠️  Device %s has NOT installed CA cert - forwarding without MITM", req.SourceIp)
		return &pb.PacketResponse{Action: pb.PacketAction_FORWARD, Reason: "CA cert not installed"}, nil
	}

	// Also check trust status (defense in depth)
	if deviceInfo.TrustStatus != "TRUSTED" {
		// Untrusted devices - don't intercept HTTPS, just forward
		log.Printf("[MITM] Device untrusted, not intercepting HTTPS")
		return &pb.PacketResponse{Action: pb.PacketAction_FORWARD, Reason: "Device untrusted"}, nil
	}

	// Check if MITM is enabled
	if !p.enableMITM {
		log.Printf("[MITM] MITM disabled, forwarding")
		return &pb.PacketResponse{Action: pb.PacketAction_FORWARD, Reason: "MITM disabled"}, nil
	}

	// Perform MITM inspection
	// Note: In real implementation, this would establish dual TLS connection
	log.Printf("[MITM] ✓ MITM inspection enabled for %s (trusted device)", domain)

	// Get or generate certificate for this domain
	_, err = p.certCache.GetOrGenerate(domain)
	if err != nil {
		log.Printf("[MITM] Certificate generation failed: %v", err)
		return &pb.PacketResponse{Action: pb.PacketAction_FORWARD, Reason: "Cert gen failed"}, nil
	}

	log.Printf("[MITM] Certificate ready for %s - would establish dual TLS", domain)

	// In full implementation, we would:
	// 1. Establish TLS connection with client using generated cert
	// 2. Establish TLS connection with real server
	// 3. Proxy and inspect decrypted traffic
	// For now, we just forward (MITM logic is in mitm_handler for direct connections)

	return &pb.PacketResponse{
		Action: pb.PacketAction_FORWARD,
		Reason: fmt.Sprintf("MITM ready for %s (cert cached)", domain),
	}, nil
}

// handleHTTP handles HTTP packets
func (p *MITMPacketProcessor) handleHTTP(ctx context.Context, req *pb.PacketRequest, info *packet.PacketInfo) (*pb.PacketResponse, error) {
	// Check device trust
	deviceInfo, err := p.dhcpMonitor.GetDeviceByIP(ctx, req.SourceIp)
	if err != nil {
		return &pb.PacketResponse{Action: pb.PacketAction_FORWARD, Reason: "DHCP unavailable"}, nil
	}

	if deviceInfo.TrustStatus == "UNTRUSTED" && p.policyMode == "ALLOW_ONCE" && p.allowOnce {
		// Phase 3A: Check if portal was already shown
		if deviceInfo.PortalShown {
			log.Printf("[MITM] ALLOW_ONCE: Portal already shown → FORWARD")
			return &pb.PacketResponse{
				Action: pb.PacketAction_FORWARD,
				Reason: "Portal already shown (ALLOW_ONCE)",
			}, nil
		}

		// First time → redirect to captive portal
		log.Printf("[MITM] ALLOW_ONCE: First visit → Redirect to captive portal")
		redirectPacket, err := p.injector.BuildHTTP302Redirect(info)
		if err != nil {
			return &pb.PacketResponse{Action: pb.PacketAction_FORWARD, Reason: "Redirect failed"}, nil
		}

		return &pb.PacketResponse{
			Action:         pb.PacketAction_INJECT,
			ModifiedPacket: redirectPacket,
			Reason:         "Redirect to captive portal",
		}, nil
	}

	return &pb.PacketResponse{Action: pb.PacketAction_FORWARD, Reason: "Device trusted"}, nil
}
