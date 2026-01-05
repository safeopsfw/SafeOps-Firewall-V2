package grpc

import (
	"context"
	"log"
	"net"

	"google.golang.org/grpc"

	"tls_proxy/internal/integration"
	"tls_proxy/internal/packet"
	pb "tls_proxy/proto"
)

// PacketProcessingServer implements the PacketProcessingService gRPC server
// SIMPLIFIED: No redirect logic, users manually access portal
type PacketProcessingServer struct {
	pb.UnimplementedPacketProcessingServiceServer
	dhcpMonitor *integration.DHCPMonitorClient
	policyMode  string
	allowOnce   bool
}

// NewPacketProcessingServer creates a new packet processing gRPC server
func NewPacketProcessingServer(dhcpMonitor *integration.DHCPMonitorClient, redirectURL, policyMode string, allowOnce bool) *PacketProcessingServer {
	_ = redirectURL // No longer used - manual portal access
	return &PacketProcessingServer{
		dhcpMonitor: dhcpMonitor,
		policyMode:  policyMode,
		allowOnce:   allowOnce,
	}
}

// ProcessPacket handles packet processing requests from Packet Capture Engine
// SIMPLIFIED: No auto-redirect. Users manually access captive portal to download cert.
func (s *PacketProcessingServer) ProcessPacket(ctx context.Context, req *pb.PacketRequest) (*pb.PacketResponse, error) {
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
		return &pb.PacketResponse{
			Action: pb.PacketAction_FORWARD,
			Reason: "Parse error - forwarding",
		}, nil
	}

	_ = packet.ClassifyPacket(info)

	// ═══════════════════════════════════════════════════════════════════════
	// FAST-PATH: Gaming, VoIP, SSH, RDP get immediate FORWARD (low latency)
	// ═══════════════════════════════════════════════════════════════════════
	if isFastPathPort(req.DestPort) {
		return &pb.PacketResponse{
			Action: pb.PacketAction_FORWARD,
			Reason: "Fast-path port",
		}, nil
	}

	// ═══════════════════════════════════════════════════════════════════════
	// MANUAL PORTAL ACCESS: No auto-redirect
	// ═══════════════════════════════════════════════════════════════════════
	// Users manually navigate to portal URL (http://gateway:8080) or scan QR
	// to download CA certificate. No forced redirect, no DNS poisoning.
	// Internet works immediately for all devices.
	// ═══════════════════════════════════════════════════════════════════════

	// Forward all traffic - no redirect logic
	return &pb.PacketResponse{
		Action: pb.PacketAction_FORWARD,
		Reason: "Manual portal access - no redirect",
	}, nil
}

// PacketProcessingGRPCServer manages the gRPC server lifecycle
type PacketProcessingGRPCServer struct {
	server   *grpc.Server
	listener net.Listener
	address  string
}

// NewPacketProcessingGRPCServer creates a new gRPC server for packet processing
func NewPacketProcessingGRPCServer(address string, dhcpMonitor *integration.DHCPMonitorClient, redirectURL, policyMode string, allowOnce bool) (*PacketProcessingGRPCServer, error) {
	listener, err := net.Listen("tcp", address)
	if err != nil {
		return nil, err
	}

	grpcServer := grpc.NewServer()
	packetService := NewPacketProcessingServer(dhcpMonitor, redirectURL, policyMode, allowOnce)
	pb.RegisterPacketProcessingServiceServer(grpcServer, packetService)

	log.Printf("[Packet Processing gRPC] Server created on %s", address)

	return &PacketProcessingGRPCServer{
		server:   grpcServer,
		listener: listener,
		address:  address,
	}, nil
}

// Start starts the gRPC server (blocking)
func (s *PacketProcessingGRPCServer) Start() error {
	log.Printf("[Packet Processing gRPC] Starting server on %s", s.address)
	return s.server.Serve(s.listener)
}

// Stop gracefully stops the gRPC server
func (s *PacketProcessingGRPCServer) Stop() {
	log.Println("[Packet Processing gRPC] Stopping server...")
	s.server.GracefulStop()
}

// isFastPathPort returns true for ports that need low-latency processing
// These are gaming, VoIP, SSH, RDP - they get quick FORWARD without deep inspection
func isFastPathPort(port uint32) bool {
	// Gaming ports
	if port >= 27000 && port <= 27050 { // Steam
		return true
	}
	if port == 7777 || port == 7778 { // Unreal Engine, many games
		return true
	}
	if port == 25565 { // Minecraft
		return true
	}
	if port >= 3478 && port <= 3480 { // STUN/TURN (WebRTC, gaming)
		return true
	}

	// VoIP ports
	if port >= 50000 && port <= 65535 { // Discord, VoIP, high ports
		return true
	}
	if port >= 8801 && port <= 8810 { // Zoom
		return true
	}

	// Remote access (need responsiveness)
	if port == 22 { // SSH
		return true
	}
	if port == 3389 { // RDP
		return true
	}

	// HTTP/HTTPS are NOT fast-path (need captive portal + MITM logic)
	// Port 80, 443 fall through to full processing

	return false
}
