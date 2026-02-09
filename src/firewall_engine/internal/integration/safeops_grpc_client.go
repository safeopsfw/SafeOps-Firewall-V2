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
	filters    []string
}

// NewSafeOpsGRPCClient creates a new gRPC-based SafeOps client
func NewSafeOpsGRPCClient(subscriberID, serverAddr string, filters []string) *SafeOpsGRPCClient {
	if len(filters) == 0 {
		filters = []string{"tcp", "udp"} // Default: TCP+UDP only, skip ICMP/other
	}
	return &SafeOpsGRPCClient{
		grpcClient: grpcclient.NewClient(subscriberID, serverAddr),
		filters:    filters,
	}
}

// Connect establishes gRPC connection and subscribes with filters
func (c *SafeOpsGRPCClient) Connect(ctx context.Context) error {
	if err := c.grpcClient.Connect(ctx); err != nil {
		return fmt.Errorf("gRPC connection failed: %w", err)
	}

	// Subscribe with filters (tcp+udp by default, not all packets)
	if err := c.grpcClient.Subscribe(ctx, c.filters); err != nil {
		return fmt.Errorf("subscription failed: %w", err)
	}

	return nil
}

// StartCapture starts receiving packets with worker pool
func (c *SafeOpsGRPCClient) StartCapture(ctx context.Context, handler func(*pb.PacketMetadata), numWorkers int) error {
	if numWorkers < 1 {
		numWorkers = 8
	}
	return c.grpcClient.StartReceiving(ctx, handler, numWorkers)
}

// SendVerdict sends a firewall verdict back to SafeOps Engine
func (c *SafeOpsGRPCClient) SendVerdict(ctx context.Context, pktID uint64, verdict pb.VerdictType, reason, ruleID string, ttl uint32, cacheKey string) error {
	return c.grpcClient.SendVerdict(ctx, pktID, verdict, reason, ruleID, ttl, cacheKey)
}

// GetStats returns client statistics (received, dropped, verdicts)
func (c *SafeOpsGRPCClient) GetStats() (packetsReceived, packetsDropped, verdictsApplied uint64) {
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

// SetStopping marks the client as shutting down, suppressing reconnect attempts.
func (c *SafeOpsGRPCClient) SetStopping() {
	c.grpcClient.SetStopping()
}

// Disconnect closes the gRPC connection
func (c *SafeOpsGRPCClient) Disconnect() error {
	return c.grpcClient.Disconnect()
}
