package integration

import (
	"context"
	"fmt"

	grpcclient "firewall_engine/pkg/grpc"
	"safeops-engine/pkg/grpc/pb"
)

// SafeOpsGRPCClient provides gRPC-based connection to SafeOps Engine
type SafeOpsGRPCClient struct {
	grpcClient *grpcclient.Client
}

// NewSafeOpsGRPCClient creates a new gRPC-based SafeOps client
func NewSafeOpsGRPCClient(subscriberID, serverAddr string) *SafeOpsGRPCClient {
	return &SafeOpsGRPCClient{
		grpcClient: grpcclient.NewClient(subscriberID, serverAddr),
	}
}

// Connect establishes gRPC connection to SafeOps Engine
func (c *SafeOpsGRPCClient) Connect(ctx context.Context) error {
	if err := c.grpcClient.Connect(ctx); err != nil {
		return fmt.Errorf("gRPC connection failed: %w", err)
	}

	// Subscribe to metadata stream (no filters = all packets)
	if err := c.grpcClient.Subscribe(ctx, nil); err != nil {
		return fmt.Errorf("subscription failed: %w", err)
	}

	return nil
}

// StartCapture starts receiving packets from gRPC stream
func (c *SafeOpsGRPCClient) StartCapture(ctx context.Context, handler func(*pb.PacketMetadata)) error {
	return c.grpcClient.StartReceiving(ctx, handler)
}

// SendVerdict sends a firewall verdict back to SafeOps Engine
func (c *SafeOpsGRPCClient) SendVerdict(ctx context.Context, pktID uint64, verdict pb.VerdictType, reason, ruleID string, ttl uint32, cacheKey string) error {
	return c.grpcClient.SendVerdict(ctx, pktID, verdict, reason, ruleID, ttl, cacheKey)
}

// GetStats returns client statistics
func (c *SafeOpsGRPCClient) GetStats() (packetsReceived, verdictsApplied uint64) {
	return c.grpcClient.GetClientStats()
}

// GetEngineStats retrieves SafeOps Engine statistics
func (c *SafeOpsGRPCClient) GetEngineStats(ctx context.Context) (*pb.StatsResponse, error) {
	return c.grpcClient.GetEngineStats(ctx)
}

// IsConnected returns connection status
func (c *SafeOpsGRPCClient) IsConnected() bool {
	return c.grpcClient.IsConnected()
}

// Disconnect closes the gRPC connection
func (c *SafeOpsGRPCClient) Disconnect() error {
	return c.grpcClient.Disconnect()
}
