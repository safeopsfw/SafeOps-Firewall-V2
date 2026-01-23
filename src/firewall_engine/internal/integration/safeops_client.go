package integration

import (
	"context"
	"fmt"
	"sync/atomic"

	"safeops-engine/pkg/engine"
	"safeops-engine/pkg/stream"
)

// SafeOpsClient subscribes to SafeOps Engine's metadata stream
type SafeOpsClient struct {
	engine      *engine.Engine
	subscriber  *stream.Subscriber
	connected   bool

	// Statistics
	packetsReceived uint64
}

// NewSafeOpsClient creates a new SafeOps Engine client
func NewSafeOpsClient() *SafeOpsClient {
	return &SafeOpsClient{}
}

// Connect subscribes to SafeOps Engine's metadata stream
func (c *SafeOpsClient) Connect(ctx context.Context, subscriberID string) error {
	if c.connected {
		return nil
	}

	// Get the global SafeOps Engine instance
	eng := engine.GetEngine()

	// If engine not initialized, initialize it
	// This allows Firewall to run standalone (it will start SafeOps internally)
	if eng == nil {
		fmt.Println("[SafeOpsClient] SafeOps Engine not running, initializing...")
		initEng, err := engine.Initialize()
		if err != nil {
			return fmt.Errorf("failed to initialize SafeOps Engine: %w", err)
		}
		eng = initEng
		fmt.Println("[SafeOpsClient] SafeOps Engine initialized successfully")
	}

	// Subscribe to metadata stream
	sub := eng.SubscribeToMetadata(subscriberID)
	if sub == nil {
		return fmt.Errorf("failed to subscribe to metadata stream")
	}

	c.engine = eng
	c.subscriber = sub
	c.connected = true

	fmt.Printf("[SafeOpsClient] Connected to SafeOps Engine metadata stream\n")
	fmt.Printf("[SafeOpsClient] Subscriber ID: %s\n", subscriberID)
	return nil
}

// Disconnect unsubscribes from the metadata stream
func (c *SafeOpsClient) Disconnect(subscriberID string) error {
	if !c.connected {
		return nil
	}

	if c.engine != nil {
		c.engine.UnsubscribeFromMetadata(subscriberID)
	}

	c.connected = false
	fmt.Println("[SafeOpsClient] Disconnected from SafeOps Engine")
	return nil
}

// IsConnected returns connection status
func (c *SafeOpsClient) IsConnected() bool {
	return c.connected
}

// StartCapture starts receiving packets from SafeOps metadata stream
func (c *SafeOpsClient) StartCapture(ctx context.Context, handler func(*PacketMetadata)) error {
	if !c.IsConnected() {
		return fmt.Errorf("not connected to SafeOps Engine")
	}

	fmt.Println("[SafeOpsClient] Started receiving metadata stream")

	// Start receiving packets from metadata stream
	go func() {
		for {
			select {
			case <-ctx.Done():
				return
			case pkt, ok := <-c.subscriber.Chan:
				if !ok {
					// Channel closed
					return
				}
				atomic.AddUint64(&c.packetsReceived, 1)
				handler(pkt)
			}
		}
	}()

	return nil
}

// GetStats returns client statistics
func (c *SafeOpsClient) GetStats() (packetsReceived, verdictsApplied uint64) {
	// For now, just return packets received
	// Verdicts will be implemented in Phase 2
	return atomic.LoadUint64(&c.packetsReceived), 0
}
