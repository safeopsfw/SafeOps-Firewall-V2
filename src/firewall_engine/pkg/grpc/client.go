// Package grpc provides gRPC client for metadata streaming
package grpc

import (
	"context"
	"fmt"
	"io"
	"sync"
	"sync/atomic"
	"time"

	"safeops-engine/pkg/grpc/pb"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/keepalive"
)

// Client represents a gRPC client for SafeOps Engine
type Client struct {
	conn   *grpc.ClientConn
	client pb.MetadataStreamServiceClient
	stream pb.MetadataStreamService_StreamMetadataClient

	subscriberID string
	serverAddr   string
	connected    atomic.Bool
	stopping     atomic.Bool // set true during graceful shutdown to suppress reconnect

	// Reconnect configuration
	maxRetries    int           // 0 = unlimited
	baseBackoff   time.Duration // initial backoff (doubles each retry)

	// Async packet processing
	packetChan chan *pb.PacketMetadata // Buffered channel for async processing
	workerWg   sync.WaitGroup

	// Statistics
	packetsReceived uint64
	packetsDropped  uint64
	verdictsApplied uint64
	reconnects      uint64
}

// PacketHandler is called for each packet received from the stream
type PacketHandler func(*pb.PacketMetadata)

// NewClient creates a new gRPC client
func NewClient(subscriberID, serverAddr string) *Client {
	return &Client{
		subscriberID: subscriberID,
		serverAddr:   serverAddr,
		packetChan:   make(chan *pb.PacketMetadata, 100000), // 100K buffer
		maxRetries:   5,
		baseBackoff:  2 * time.Second,
	}
}

// WithReconnectConfig sets the max retry count and base backoff for reconnects.
// maxRetries=0 means unlimited retries. baseBackoff doubles each attempt.
func (c *Client) WithReconnectConfig(maxRetries int, baseBackoff time.Duration) *Client {
	c.maxRetries = maxRetries
	c.baseBackoff = baseBackoff
	return c
}

// GetReconnectCount returns the total number of successful reconnects.
func (c *Client) GetReconnectCount() uint64 {
	return atomic.LoadUint64(&c.reconnects)
}

// Connect establishes connection to SafeOps Engine gRPC server
func (c *Client) Connect(ctx context.Context) error {
	if c.connected.Load() {
		return nil
	}

	var conn *grpc.ClientConn
	var err error

	for retries := 0; retries < 5; retries++ {
		conn, err = grpc.NewClient(
			c.serverAddr,
			grpc.WithTransportCredentials(insecure.NewCredentials()),
			grpc.WithDefaultCallOptions(
				grpc.MaxCallRecvMsgSize(10*1024*1024), // 10MB receive
			),
			grpc.WithKeepaliveParams(keepalive.ClientParameters{
				Time:                10 * time.Second,
				Timeout:             3 * time.Second,
				PermitWithoutStream: true,
			}),
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
	c.connected.Store(true)

	fmt.Printf("[gRPC Client] Connected to SafeOps Engine at %s\n", c.serverAddr)
	return nil
}

// Subscribe subscribes to the metadata stream with optional filters
func (c *Client) Subscribe(ctx context.Context, filters []string) error {
	if !c.connected.Load() {
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
	fmt.Printf("[gRPC Client] Subscribed to metadata stream (ID: %s, filters: %v)\n", c.subscriberID, filters)

	return nil
}

// StartReceiving starts the receive loop and worker pool
// numWorkers controls how many goroutines process packets concurrently
func (c *Client) StartReceiving(ctx context.Context, handler PacketHandler, numWorkers int) error {
	if c.stream == nil {
		return fmt.Errorf("not subscribed to metadata stream")
	}

	if numWorkers < 1 {
		numWorkers = 8
	}

	fmt.Printf("[gRPC Client] Starting %d workers for packet processing\n", numWorkers)

	// Start worker pool - each worker reads from shared channel
	for i := 0; i < numWorkers; i++ {
		c.workerWg.Add(1)
		go func() {
			defer c.workerWg.Done()
			for pkt := range c.packetChan {
				handler(pkt)
			}
		}()
	}

	// Start receive goroutine - reads from gRPC stream into channel
	go func() {
		defer close(c.packetChan)

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
					// Don't reconnect if shutting down
					if c.stopping.Load() || !c.connected.Load() {
						return
					}
					select {
					case <-ctx.Done():
						return
					default:
					}
					fmt.Printf("[gRPC Client] Stream receive error: %v\n", err)
					c.handleReconnect(ctx, handler, numWorkers)
					return
				}

				atomic.AddUint64(&c.packetsReceived, 1)

				// Non-blocking send to worker pool
				select {
				case c.packetChan <- pkt:
					// Dispatched to worker
				default:
					// Channel full - drop packet instead of blocking network
					atomic.AddUint64(&c.packetsDropped, 1)
				}
			}
		}
	}()

	return nil
}

// SendVerdict sends a verdict decision to SafeOps Engine
func (c *Client) SendVerdict(ctx context.Context, pktID uint64, verdict pb.VerdictType, reason, ruleID string, ttl uint32, cacheKey string) error {
	if !c.connected.Load() {
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
	if !c.connected.Load() {
		return nil, fmt.Errorf("not connected to SafeOps Engine")
	}

	resp, err := c.client.GetStats(ctx, &pb.StatsRequest{})
	if err != nil {
		return nil, fmt.Errorf("failed to get engine stats: %w", err)
	}

	return resp, nil
}

// GetClientStats returns client-side statistics
func (c *Client) GetClientStats() (packetsReceived, packetsDropped, verdictsApplied uint64) {
	return atomic.LoadUint64(&c.packetsReceived),
		atomic.LoadUint64(&c.packetsDropped),
		atomic.LoadUint64(&c.verdictsApplied)
}

// IsConnected returns connection status
func (c *Client) IsConnected() bool {
	return c.connected.Load()
}

// SetStopping marks the client as shutting down, suppressing reconnect attempts.
// Call this at the start of graceful shutdown, before canceling the context.
func (c *Client) SetStopping() {
	c.stopping.Store(true)
}

// Disconnect closes the gRPC connection and waits for workers to finish
func (c *Client) Disconnect() error {
	if !c.connected.Load() {
		return nil
	}

	fmt.Println("[gRPC Client] Disconnecting from SafeOps Engine")

	c.stopping.Store(true) // suppress reconnect attempts
	c.connected.Store(false)

	// Wait for workers to drain
	c.workerWg.Wait()

	if c.conn != nil {
		if err := c.conn.Close(); err != nil {
			return fmt.Errorf("failed to close connection: %w", err)
		}
	}

	c.stream = nil
	c.client = nil

	fmt.Println("[gRPC Client] Disconnected from SafeOps Engine")
	return nil
}

// handleReconnect attempts to reconnect to the gRPC server with exponential backoff.
// When maxRetries is 0 it retries indefinitely until ctx is cancelled.
func (c *Client) handleReconnect(ctx context.Context, handler PacketHandler, numWorkers int) {
	fmt.Println("[gRPC Client] Attempting to reconnect...")

	c.connected.Store(false)
	if c.conn != nil {
		c.conn.Close()
	}

	maxAttempts := c.maxRetries
	if maxAttempts <= 0 {
		maxAttempts = 1<<31 - 1 // unlimited
	}
	baseBackoff := c.baseBackoff
	if baseBackoff <= 0 {
		baseBackoff = 2 * time.Second
	}
	// Cap backoff at 60 seconds
	const maxBackoff = 60 * time.Second

	for attempt := 0; attempt < maxAttempts; attempt++ {
		backoff := baseBackoff * time.Duration(1<<uint(attempt))
		if backoff > maxBackoff {
			backoff = maxBackoff
		}

		fmt.Printf("[gRPC Client] Reconnection attempt %d — waiting %s...\n", attempt+1, backoff)
		select {
		case <-ctx.Done():
			return
		case <-time.After(backoff):
		}

		if c.stopping.Load() {
			return
		}

		if err := c.Connect(ctx); err != nil {
			fmt.Printf("[gRPC Client] Connect attempt %d failed: %v\n", attempt+1, err)
			continue
		}

		if err := c.Subscribe(ctx, []string{"tcp", "udp"}); err != nil {
			fmt.Printf("[gRPC Client] Subscribe attempt %d failed: %v\n", attempt+1, err)
			c.conn.Close()
			c.connected.Store(false)
			continue
		}

		// Create new packet channel for reconnected stream
		c.packetChan = make(chan *pb.PacketMetadata, 100000)
		if err := c.StartReceiving(ctx, handler, numWorkers); err != nil {
			fmt.Printf("[gRPC Client] StartReceiving attempt %d failed: %v\n", attempt+1, err)
			continue
		}

		atomic.AddUint64(&c.reconnects, 1)
		fmt.Printf("[gRPC Client] Reconnected successfully (attempt %d)\n", attempt+1)
		return
	}

	fmt.Println("[gRPC Client] All reconnection attempts exhausted")
}
