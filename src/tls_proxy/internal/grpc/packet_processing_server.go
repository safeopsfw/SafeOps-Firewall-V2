package grpc

import (
	"context"
	"log"
	"net"

	"google.golang.org/grpc"

	"tls_proxy/internal/injector"
	"tls_proxy/internal/integration"
	"tls_proxy/internal/packet"
	pb "tls_proxy/proto"
)

// PacketProcessingServer implements the PacketProcessingService gRPC server
type PacketProcessingServer struct {
	pb.UnimplementedPacketProcessingServiceServer
	dhcpMonitor *integration.DHCPMonitorClient
	injector    *injector.HTTPRedirectInjector
	policyMode  string
	allowOnce   bool
}

// NewPacketProcessingServer creates a new packet processing gRPC server
func NewPacketProcessingServer(dhcpMonitor *integration.DHCPMonitorClient, redirectURL, policyMode string, allowOnce bool) *PacketProcessingServer {
	return &PacketProcessingServer{
		dhcpMonitor: dhcpMonitor,
		injector:    injector.NewHTTPRedirectInjector(redirectURL),
		policyMode:  policyMode,
		allowOnce:   allowOnce,
	}
}

// ProcessPacket handles packet processing requests from Packet Capture Engine
func (s *PacketProcessingServer) ProcessPacket(ctx context.Context, req *pb.PacketRequest) (*pb.PacketResponse, error) {
	// Verbose packet logging removed to prevent terminal flooding

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
		log.Printf("[Packet Processing] Failed to parse packet: %v", err)
		return &pb.PacketResponse{
			Action: pb.PacketAction_FORWARD,
			Reason: "Parse error - forwarding",
		}, nil
	}

	_ = packet.ClassifyPacket(info)

	// Phase 3A: Only intercept HTTP packets (not HTTPS)
	if !packet.ShouldIntercept(info) {
		return &pb.PacketResponse{
			Action: pb.PacketAction_FORWARD,
			Reason: "Not HTTP GET request",
		}, nil
	}

	// Check device trust status
	// CRITICAL: Check if dhcpMonitor is nil to prevent panic when DHCP Monitor is not running
	if s.dhcpMonitor == nil {
		// Silent forward when DHCP Monitor unavailable (no logging to prevent flood)
		return &pb.PacketResponse{
			Action: pb.PacketAction_FORWARD,
			Reason: "No DHCP Monitor - forwarding",
		}, nil
	}

	deviceInfo, err := s.dhcpMonitor.GetDeviceByIP(ctx, req.SourceIp)
	if err != nil {
		// Silent forward on error (no logging to prevent flood)
		return &pb.PacketResponse{
			Action: pb.PacketAction_FORWARD,
			Reason: "DHCP Monitor unavailable",
		}, nil
	}

	// Decision based on trust status and policy
	switch deviceInfo.TrustStatus {
	case "TRUSTED":
		// Trusted device → forward normally
		log.Printf("[Packet Processing] Device trusted → FORWARD")
		return &pb.PacketResponse{
			Action: pb.PacketAction_FORWARD,
			Reason: "Device trusted",
		}, nil

	case "UNTRUSTED":
		// Untrusted device → apply policy
		if s.policyMode == "ALLOW_ONCE" && s.allowOnce {
			// ALLOW_ONCE: Check if portal was already shown
			if deviceInfo.PortalShown {
				// Portal already shown → allow internet access
				log.Printf("[Packet Processing] ALLOW_ONCE: Portal already shown → FORWARD")
				return &pb.PacketResponse{
					Action: pb.PacketAction_FORWARD,
					Reason: "Portal already shown (ALLOW_ONCE)",
				}, nil
			}

			// First time → redirect to captive portal
			// Note: Captive Portal will call MarkPortalShown when page loads
			log.Printf("[Packet Processing] ALLOW_ONCE: First visit → Inject redirect to captive portal")

			// Build HTTP 302 redirect
			redirectPacket, err := s.injector.BuildHTTP302Redirect(info)
			if err != nil {
				log.Printf("[Packet Processing] Failed to build redirect: %v", err)
				return &pb.PacketResponse{
					Action: pb.PacketAction_FORWARD,
					Reason: "Failed to build redirect",
				}, nil
			}

			return &pb.PacketResponse{
				Action:         pb.PacketAction_INJECT,
				ModifiedPacket: redirectPacket,
				Reason:         "Redirect to captive portal (ALLOW_ONCE)",
			}, nil

		} else if s.policyMode == "STRICT" {
			// STRICT: Block untrusted devices
			log.Printf("[Packet Processing] STRICT policy → BLOCK")

			blockPacket, _ := s.injector.BuildHTTP403Blocked(info, "Device not trusted. Please install SafeOps CA certificate.")
			return &pb.PacketResponse{
				Action:         pb.PacketAction_INJECT,
				ModifiedPacket: blockPacket,
				Reason:         "Device untrusted - strict mode",
			}, nil

		} else {
			// PERMISSIVE: Allow but log
			log.Printf("[Packet Processing] PERMISSIVE policy → FORWARD")
			return &pb.PacketResponse{
				Action: pb.PacketAction_FORWARD,
				Reason: "Device untrusted - permissive mode",
			}, nil
		}

	case "BLOCKED":
		// Blocked device → always block
		log.Printf("[Packet Processing] Device blocked → BLOCK")
		blockPacket, _ := s.injector.BuildHTTP403Blocked(info, "Device blocked by administrator.")
		return &pb.PacketResponse{
			Action:         pb.PacketAction_INJECT,
			ModifiedPacket: blockPacket,
			Reason:         "Device blocked",
		}, nil

	default:
		// Unknown status → fail safe based on policy
		log.Printf("[Packet Processing] Unknown trust status → Default policy")
		if s.policyMode == "STRICT" {
			return &pb.PacketResponse{
				Action: pb.PacketAction_DROP,
				Reason: "Unknown trust status",
			}, nil
		}
		return &pb.PacketResponse{
			Action: pb.PacketAction_FORWARD,
			Reason: "Unknown trust status - permissive fallback",
		}, nil
	}
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
