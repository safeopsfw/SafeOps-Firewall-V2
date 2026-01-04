package grpc

import (
	"context"
	"log"
	"net"

	"google.golang.org/grpc"

	"tls_proxy/internal/brain"
	pb "tls_proxy/proto"
)

// DNSDecisionServer implements the DNSDecisionService gRPC server
type DNSDecisionServer struct {
	pb.UnimplementedDNSDecisionServiceServer
	engine *brain.DecisionEngine
}

// NewDNSDecisionServer creates a new DNS decision gRPC server
func NewDNSDecisionServer(engine *brain.DecisionEngine) *DNSDecisionServer {
	return &DNSDecisionServer{
		engine: engine,
	}
}

// GetDNSDecision handles DNS decision requests from DNS Server
func (s *DNSDecisionServer) GetDNSDecision(ctx context.Context, req *pb.DNSDecisionRequest) (*pb.DNSDecisionResponse, error) {
	log.Printf("[DNS Decision Server] Request: domain=%s, client=%s, type=%s",
		req.Domain, req.ClientIp, req.QueryType)

	// Delegate to decision engine
	resp, err := s.engine.GetDNSDecision(ctx, req.Domain, req.ClientIp, req.QueryType)
	if err != nil {
		log.Printf("[DNS Decision Server] Decision error: %v", err)
		// Return fail-safe response
		return &pb.DNSDecisionResponse{
			Decision: pb.DecisionType_FORWARD_UPSTREAM,
			Ttl:      300,
			Reason:   "Decision engine error",
		}, nil
	}

	log.Printf("[DNS Decision Server] Response: decision=%v, ip=%s, reason=%s",
		resp.Decision, resp.IpAddress, resp.Reason)

	return resp, nil
}

// DNSDecisionGRPCServer manages the gRPC server lifecycle
type DNSDecisionGRPCServer struct {
	server   *grpc.Server
	listener net.Listener
	address  string
}

// NewDNSDecisionGRPCServer creates a new gRPC server for DNS decisions
func NewDNSDecisionGRPCServer(address string, engine *brain.DecisionEngine) (*DNSDecisionGRPCServer, error) {
	listener, err := net.Listen("tcp", address)
	if err != nil {
		return nil, err
	}

	grpcServer := grpc.NewServer()
	dnsService := NewDNSDecisionServer(engine)
	pb.RegisterDNSDecisionServiceServer(grpcServer, dnsService)

	log.Printf("[DNS Decision gRPC] Server created on %s", address)

	return &DNSDecisionGRPCServer{
		server:   grpcServer,
		listener: listener,
		address:  address,
	}, nil
}

// Start starts the gRPC server (blocking)
func (s *DNSDecisionGRPCServer) Start() error {
	log.Printf("[DNS Decision gRPC] Starting server on %s", s.address)
	return s.server.Serve(s.listener)
}

// Stop gracefully stops the gRPC server
func (s *DNSDecisionGRPCServer) Stop() {
	log.Println("[DNS Decision gRPC] Stopping server...")
	s.server.GracefulStop()
}
