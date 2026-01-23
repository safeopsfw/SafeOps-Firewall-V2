// Package grpc provides gRPC client for metadata streaming
package grpc

import (
	"context"
	"fmt"
	"io"
	"sync/atomic"
	"time"

	"safeops-engine/pkg/grpc/pb"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

// Client represents a gRPC client for SafeOps Engine
type Client struct {
	conn   *grpc.ClientConn
	client pb.MetadataStreamServiceClient
	stream pb.MetadataStreamService_StreamMetadataClient

	subscriberID string
	serverAddr   string
	connected    bool

	// Statistics
	packetsReceived uint64
	verdictsApplied uint64
}

// PacketHandler is called for each packet received from the stream
type PacketHandler func(*pb.PacketMetadata)

// NewClient creates a new gRPC client
func NewClient(subscriberID, serverAddr string) *Client {
	return &Client{
		subscriberID: subscriberID,
		serverAddr:   serverAddr,
	}
}

// Connect establishes connection to SafeOps Engine gRPC server
func (c *Client) Connect(ctx context.Context) error {
	if c.connected {
		return nil
	}

	// Connect to gRPC server with retry
	var conn *grpc.ClientConn
	var err error

	for retries := 0; retries < 5; retries++ {
		conn, err = grpc.NewClient(
			c.serverAddr,
			grpc.WithTransportCredentials(insecure.NewCredentials()),
			grpc.WithBlock(),
		)

		if err == nil {
			break
		}

		if retries < 4 {
			fmt.Printf("[gRPC Client] Connection failed, retrying in 2s... (%d/5)\n", retries+1)
			time.Sleep(2 * time.Second)
		}
	}

	if err != nil {
		return fmt.Errorf("failed to connect to SafeOps Engine at %s: %w", c.serverAddr, err)
	}

	c.conn = conn
	c.client = pb.NewMetadataStreamServiceClient(conn)
	c.connected = true

	fmt.Printf("[gRPC Client] Connected to SafeOps Engine at %s\n", c.serverAddr)
	return nil
}

// Subscribe subscribes to the metadata stream
func (c *Client) Subscribe(ctx context.Context, filters []string) error {
	if !c.connected {
		return fmt.Errorf("not connected to SafeOps Engine")
	}

	req := &pb.SubscribeRequest{
		SubscriberId: c.subscriberID,
		Filters:      filters,
	}

	stream, err := c.client.StreamMetadata(ctx, req)
	if err != nil {
		return fmt.Errorf("failed to subscribe to metadata stream: %w", err)
	}

	c.stream = stream
	fmt.Printf("[gRPC Client] Subscribed to metadata stream (ID: %s)\n", c.subscriberID)

	return nil
}

// StartReceiving starts receiving packets from the stream
func (c *Client) StartReceiving(ctx context.Context, handler PacketHandler) error {
	if c.stream == nil {
		return fmt.Errorf("not subscribed to metadata stream")
	}

	fmt.Println("[gRPC Client] Started receiving metadata stream")

	go func() {
		for {
			select {
			case <-ctx.Done():
				fmt.Println("[gRPC Client] Stream receiving stopped (context canceled)")
				return
			default:
				pkt, err := c.stream.Recv()
				if err == io.EOF {
					fmt.Println("[gRPC Client] Stream ended (EOF)")
					return
				}
				if err != nil {
					fmt.Printf("[gRPC Client] Stream receive error: %v\n", err)
					// Try to reconnect
					c.handleReconnect(ctx, handler)
					return
				}

				atomic.AddUint64(&c.packetsReceived, 1)
				handler(pkt)
			}
		}
	}()

	return nil
}

// SendVerdict sends a verdict decision to SafeOps Engine
func (c *Client) SendVerdict(ctx context.Context, pktID uint64, verdict pb.VerdictType, reason, ruleID string, ttl uint32, cacheKey string) error {
	if !c.connected {
		return fmt.Errorf("not connected to SafeOps Engine")
	}

	req := &pb.VerdictRequest{
		PacketId:   pktID,
		Verdict:    verdict,
		Reason:     reason,
		RuleId:     ruleID,
		TtlSeconds: ttl,
		CacheKey:   cacheKey,
	}

	resp, err := c.client.ApplyVerdict(ctx, req)
	if err != nil {
		return fmt.Errorf("failed to send verdict: %w", err)
	}

	if !resp.Success {
		return fmt.Errorf("verdict application failed: %s", resp.Message)
	}

	atomic.AddUint64(&c.verdictsApplied, 1)
	return nil
}

// GetEngineStats retrieves statistics from SafeOps Engine
func (c *Client) GetEngineStats(ctx context.Context) (*pb.StatsResponse, error) {
	if !c.connected {
		return nil, fmt.Errorf("not connected to SafeOps Engine")
	}

	req := &pb.StatsRequest{}
	resp, err := c.client.GetStats(ctx, req)
	if err != nil {
		return nil, fmt.Errorf("failed to get engine stats: %w", err)
	}

	return resp, nil
}

// GetClientStats returns client-side statistics
func (c *Client) GetClientStats() (packetsReceived, verdictsApplied uint64) {
	return atomic.LoadUint64(&c.packetsReceived), atomic.LoadUint64(&c.verdictsApplied)
}

// IsConnected returns connection status
func (c *Client) IsConnected() bool {
	return c.connected
}

// Disconnect closes the gRPC connection
func (c *Client) Disconnect() error {
	if !c.connected {
		return nil
	}

	fmt.Println("[gRPC Client] Disconnecting from SafeOps Engine")

	if c.conn != nil {
		if err := c.conn.Close(); err != nil {
			return fmt.Errorf("failed to close connection: %w", err)
		}
	}

	c.connected = false
	c.stream = nil
	c.client = nil

	fmt.Println("[gRPC Client] Disconnected from SafeOps Engine")
	return nil
}

// handleReconnect attempts to reconnect to the gRPC server
func (c *Client) handleReconnect(ctx context.Context, handler PacketHandler) {
	fmt.Println("[gRPC Client] Attempting to reconnect...")

	// Mark as disconnected
	c.connected = false
	if c.conn != nil {
		c.conn.Close()
	}

	// Wait a bit before reconnecting
	time.Sleep(5 * time.Second)

	// Try to reconnect
	if err := c.Connect(ctx); err != nil {
		fmt.Printf("[gRPC Client] Reconnection failed: %v\n", err)
		return
	}

	// Re-subscribe
	if err := c.Subscribe(ctx, nil); err != nil {
		fmt.Printf("[gRPC Client] Re-subscription failed: %v\n", err)
		return
	}

	// Restart receiving
	if err := c.StartReceiving(ctx, handler); err != nil {
		fmt.Printf("[gRPC Client] Failed to restart receiving: %v\n", err)
		return
	}

	fmt.Println("[gRPC Client] Reconnected successfully")
}
