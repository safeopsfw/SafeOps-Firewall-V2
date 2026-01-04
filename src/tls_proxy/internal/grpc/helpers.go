package grpc

import (
	"net"

	"google.golang.org/grpc"

	"tls_proxy/internal/integration"
	pb "tls_proxy/proto"
)

// NewPacketProcessingGRPCServerWithMITM creates packet processing server with MITM support
func NewPacketProcessingGRPCServerWithMITM(
	address string,
	dhcpMonitor *integration.DHCPMonitorClient,
	stepCA *integration.StepCAClient,
	redirectURL, policyMode string,
	allowOnce, enableMITM bool,
) (*PacketProcessingGRPCServer, error) {

	listener, err := net.Listen("tcp", address)
	if err != nil {
		return nil, err
	}

	grpcServer := grpc.NewServer()

	// Use MITM-enabled processor
	packetService := NewMITMPacketProcessor(
		dhcpMonitor,
		stepCA,
		redirectURL,
		policyMode,
		allowOnce,
		enableMITM,
	)

	pb.RegisterPacketProcessingServiceServer(grpcServer, packetService)

	return &PacketProcessingGRPCServer{
		server:   grpcServer,
		listener: listener,
		address:  address,
	}, nil
}
