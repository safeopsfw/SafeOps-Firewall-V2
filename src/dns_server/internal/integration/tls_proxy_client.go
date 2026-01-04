package integration

import (
	"context"
	"fmt"
	"log"
	"sync"
	"time"

	pb "dns_server/proto"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

// TLSProxyClient manages gRPC connection to TLS Proxy's DNS Decision Service
type TLSProxyClient struct {
	address string
	conn    *grpc.ClientConn
	client  pb.DNSDecisionServiceClient
	mu      sync.RWMutex
	timeout time.Duration
}

// NewTLSProxyClient creates a new TLS Proxy gRPC client
func NewTLSProxyClient(address string, timeout time.Duration) (*TLSProxyClient, error) {
	if address == "" {
		return nil, fmt.Errorf("TLS Proxy address cannot be empty")
	}

	client := &TLSProxyClient{
		address: address,
		timeout: timeout,
	}

	if err := client.Connect(); err != nil {
		return nil, fmt.Errorf("failed to connect to TLS Proxy: %w", err)
	}

	log.Printf("[TLS Proxy Client] Connected to TLS Proxy at %s", address)
	return client, nil
}

// Connect establishes gRPC connection to TLS Proxy
func (c *TLSProxyClient) Connect() error {
	c.mu.Lock()
	defer c.mu.Unlock()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	conn, err := grpc.DialContext(
		ctx,
		c.address,
		grpc.WithTransportCredentials(insecure.NewCredentials()),
		grpc.WithBlock(),
	)
	if err != nil {
		return fmt.Errorf("failed to dial TLS Proxy: %w", err)
	}

	c.conn = conn
	c.client = pb.NewDNSDecisionServiceClient(conn)
	return nil
}

// GetDNSDecision asks TLS Proxy what IP to return for a domain
func (c *TLSProxyClient) GetDNSDecision(ctx context.Context, domain, clientIP, queryType string) (*pb.DNSDecisionResponse, error) {
	c.mu.RLock()
	client := c.client
	c.mu.RUnlock()

	if client == nil {
		return nil, fmt.Errorf("TLS Proxy client not connected")
	}

	// Create request
	req := &pb.DNSDecisionRequest{
		Domain:    domain,
		ClientIp:  clientIP,
		QueryType: queryType,
	}

	// Call with timeout
	callCtx, cancel := context.WithTimeout(ctx, c.timeout)
	defer cancel()

	resp, err := client.GetDNSDecision(callCtx, req)
	if err != nil {
		return nil, fmt.Errorf("failed to get DNS decision from TLS Proxy: %w", err)
	}

	return resp, nil
}

// Close closes the gRPC connection
func (c *TLSProxyClient) Close() error {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.conn != nil {
		err := c.conn.Close()
		c.conn = nil
		c.client = nil
		return err
	}
	return nil
}

// IsConnected returns whether the client is connected
func (c *TLSProxyClient) IsConnected() bool {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.client != nil
}

// Reconnect attempts to reconnect to TLS Proxy
func (c *TLSProxyClient) Reconnect() error {
	c.Close()
	return c.Connect()
}
