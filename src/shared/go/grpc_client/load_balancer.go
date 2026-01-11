// Package grpc_client provides load balancing utilities.
package grpc_client

import (
	"context"
	"fmt"
	"math/rand"
	"os"
	"sync"
	"sync/atomic"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/connectivity"
)

// LoadBalancingStrategy defines the load balancing algorithm
type LoadBalancingStrategy int

const (
	// RoundRobin distributes requests evenly across endpoints
	RoundRobin LoadBalancingStrategy = iota
	// Random selects endpoints randomly
	Random
	// WeightedRoundRobin distributes based on endpoint weights
	WeightedRoundRobin
	// LeastConnections routes to endpoint with fewest active connections
	LeastConnections
	// HealthBased only routes to healthy endpoints
	HealthBased
)

// Endpoint represents a service endpoint
type Endpoint struct {
	Address     string
	Weight      int
	conn        *grpc.ClientConn
	activeConns int64
	healthy     atomic.Bool
}

// LoadBalancer manages multiple service endpoints
type LoadBalancer struct {
	endpoints []*Endpoint
	strategy  LoadBalancingStrategy
	index     uint64
	mu        sync.RWMutex
	cfg       Config
}

// LoadBalancerConfig configures the load balancer
type LoadBalancerConfig struct {
	Strategy  LoadBalancingStrategy
	Endpoints []EndpointConfig
	Config    Config // gRPC client config
}

// EndpointConfig configures an endpoint
type EndpointConfig struct {
	Address string
	Weight  int // Only used for WeightedRoundRobin
}

// NewLoadBalancer creates a new load balancer
func NewLoadBalancer(ctx context.Context, cfg LoadBalancerConfig) (*LoadBalancer, error) {
	if len(cfg.Endpoints) == 0 {
		return nil, fmt.Errorf("no endpoints provided")
	}

	lb := &LoadBalancer{
		endpoints: make([]*Endpoint, 0, len(cfg.Endpoints)),
		strategy:  cfg.Strategy,
		cfg:       cfg.Config,
	}

	// Create connections to all endpoints
	for _, epCfg := range cfg.Endpoints {
		endpoint := &Endpoint{
			Address: epCfg.Address,
			Weight:  epCfg.Weight,
		}

		if endpoint.Weight <= 0 {
			endpoint.Weight = 1
		}

		// Create connection
		clientCfg := cfg.Config
		clientCfg.Target = epCfg.Address

		client, err := NewClient(ctx, clientCfg)
		if err != nil {
			// Cleanup already created connections
			lb.Close()
			return nil, fmt.Errorf("failed to connect to %s: %w", epCfg.Address, err)
		}

		endpoint.conn = client.ClientConn
		endpoint.healthy.Store(true)
		lb.endpoints = append(lb.endpoints, endpoint)
	}

	// Start health checking
	go lb.healthCheck(ctx)

	return lb, nil
}

// GetConnection returns a connection based on the load balancing strategy
func (lb *LoadBalancer) GetConnection() (*grpc.ClientConn, error) {
	lb.mu.RLock()
	defer lb.mu.RUnlock()

	if len(lb.endpoints) == 0 {
		return nil, fmt.Errorf("no endpoints available")
	}

	switch lb.strategy {
	case RoundRobin:
		return lb.roundRobin()
	case Random:
		return lb.random()
	case WeightedRoundRobin:
		return lb.weightedRoundRobin()
	case LeastConnections:
		return lb.leastConnections()
	case HealthBased:
		return lb.healthBased()
	default:
		return lb.roundRobin()
	}
}

// roundRobin returns the next endpoint in round-robin fashion
func (lb *LoadBalancer) roundRobin() (*grpc.ClientConn, error) {
	idx := atomic.AddUint64(&lb.index, 1)
	endpoint := lb.endpoints[int(idx)%len(lb.endpoints)]
	return endpoint.conn, nil
}

// random returns a random endpoint
func (lb *LoadBalancer) random() (*grpc.ClientConn, error) {
	idx := rand.Intn(len(lb.endpoints))
	return lb.endpoints[idx].conn, nil
}

// weightedRoundRobin returns endpoint based on weights
func (lb *LoadBalancer) weightedRoundRobin() (*grpc.ClientConn, error) {
	// Calculate total weight
	totalWeight := 0
	for _, ep := range lb.endpoints {
		if ep.healthy.Load() {
			totalWeight += ep.Weight
		}
	}

	if totalWeight == 0 {
		return nil, fmt.Errorf("no healthy endpoints")
	}

	// Get weighted index
	idx := atomic.AddUint64(&lb.index, 1)
	target := int(idx) % totalWeight

	// Find the endpoint
	sum := 0
	for _, ep := range lb.endpoints {
		if !ep.healthy.Load() {
			continue
		}
		sum += ep.Weight
		if target < sum {
			return ep.conn, nil
		}
	}

	// Fallback to first healthy endpoint
	for _, ep := range lb.endpoints {
		if ep.healthy.Load() {
			return ep.conn, nil
		}
	}

	return nil, fmt.Errorf("no healthy endpoints")
}

// leastConnections returns endpoint with fewest active connections
func (lb *LoadBalancer) leastConnections() (*grpc.ClientConn, error) {
	var selectedEndpoint *Endpoint
	minConns := int64(^uint64(0) >> 1) // Max int64

	for _, ep := range lb.endpoints {
		if !ep.healthy.Load() {
			continue
		}

		conns := atomic.LoadInt64(&ep.activeConns)
		if conns < minConns {
			minConns = conns
			selectedEndpoint = ep
		}
	}

	if selectedEndpoint == nil {
		return nil, fmt.Errorf("no healthy endpoints")
	}

	atomic.AddInt64(&selectedEndpoint.activeConns, 1)
	return selectedEndpoint.conn, nil
}

// healthBased returns only healthy endpoints (round-robin)
func (lb *LoadBalancer) healthBased() (*grpc.ClientConn, error) {
	// Find healthy endpoints
	var healthyEndpoints []*Endpoint
	for _, ep := range lb.endpoints {
		if ep.healthy.Load() {
			healthyEndpoints = append(healthyEndpoints, ep)
		}
	}

	if len(healthyEndpoints) == 0 {
		return nil, fmt.Errorf("no healthy endpoints")
	}

	// Round-robin among healthy endpoints
	idx := atomic.AddUint64(&lb.index, 1)
	endpoint := healthyEndpoints[int(idx)%len(healthyEndpoints)]
	return endpoint.conn, nil
}

// ReleaseConnection decrements the active connection count (for LeastConnections)
func (lb *LoadBalancer) ReleaseConnection(conn *grpc.ClientConn) {
	lb.mu.RLock()
	defer lb.mu.RUnlock()

	for _, ep := range lb.endpoints {
		if ep.conn == conn {
			atomic.AddInt64(&ep.activeConns, -1)
			break
		}
	}
}

// healthCheck periodically checks endpoint health
func (lb *LoadBalancer) healthCheck(ctx context.Context) {
	ticker := time.NewTicker(10 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			lb.mu.RLock()
			for _, ep := range lb.endpoints {
				state := ep.conn.GetState()
				isHealthy := state == connectivity.Ready || state == connectivity.Idle
				ep.healthy.Store(isHealthy)
			}
			lb.mu.RUnlock()
		}
	}
}

// Close closes all endpoint connections
func (lb *LoadBalancer) Close() error {
	lb.mu.Lock()
	defer lb.mu.Unlock()

	var lastErr error
	for _, ep := range lb.endpoints {
		if ep.conn != nil {
			if err := ep.conn.Close(); err != nil {
				lastErr = err
			}
		}
	}
	return lastErr
}

// Endpoint returns the list of endpoints
func (lb *LoadBalancer) Endpoints() []*Endpoint {
	lb.mu.RLock()
	defer lb.mu.RUnlock()
	return append([]*Endpoint(nil), lb.endpoints...)
}

// HealthyEndpoints returns only healthy endpoints
func (lb *LoadBalancer) HealthyEndpoints() []*Endpoint {
	lb.mu.RLock()
	defer lb.mu.RUnlock()

	var healthy []*Endpoint
	for _, ep := range lb.endpoints {
		if ep.healthy.Load() {
			healthy = append(healthy, ep)
		}
	}
	return healthy
}

// AddEndpoint adds a new endpoint dynamically
func (lb *LoadBalancer) AddEndpoint(ctx context.Context, epCfg EndpointConfig) error {
	lb.mu.Lock()
	defer lb.mu.Unlock()

	endpoint := &Endpoint{
		Address: epCfg.Address,
		Weight:  epCfg.Weight,
	}

	if endpoint.Weight <= 0 {
		endpoint.Weight = 1
	}

	// Create connection
	clientCfg := lb.cfg
	clientCfg.Target = epCfg.Address

	client, err := NewClient(ctx, clientCfg)
	if err != nil {
		return fmt.Errorf("failed to connect to %s: %w", epCfg.Address, err)
	}

	endpoint.conn = client.ClientConn
	endpoint.healthy.Store(true)
	lb.endpoints = append(lb.endpoints, endpoint)

	return nil
}

// RemoveEndpoint removes an endpoint by address
func (lb *LoadBalancer) RemoveEndpoint(address string) error {
	lb.mu.Lock()
	defer lb.mu.Unlock()

	for i, ep := range lb.endpoints {
		if ep.Address == address {
			ep.conn.Close()
			lb.endpoints = append(lb.endpoints[:i], lb.endpoints[i+1:]...)
			return nil
		}
	}

	return fmt.Errorf("endpoint not found: %s", address)
}

// Stats returns load balancer statistics
func (lb *LoadBalancer) Stats() LoadBalancerStats {
	lb.mu.RLock()
	defer lb.mu.RUnlock()

	stats := LoadBalancerStats{
		TotalEndpoints:   len(lb.endpoints),
		HealthyEndpoints: 0,
		Strategy:         lb.strategy.String(),
	}

	for _, ep := range lb.endpoints {
		if ep.healthy.Load() {
			stats.HealthyEndpoints++
		}
	}

	return stats
}

// LoadBalancerStats holds load balancer statistics
type LoadBalancerStats struct {
	TotalEndpoints   int
	HealthyEndpoints int
	Strategy         string
}

// String returns the strategy name
func (s LoadBalancingStrategy) String() string {
	switch s {
	case RoundRobin:
		return "RoundRobin"
	case Random:
		return "Random"
	case WeightedRoundRobin:
		return "WeightedRoundRobin"
	case LeastConnections:
		return "LeastConnections"
	case HealthBased:
		return "HealthBased"
	default:
		return "Unknown"
	}
}

// NewLoadBalancerFromEnv creates load balancer from environment variables
func NewLoadBalancerFromEnv(ctx context.Context, endpoints []EndpointConfig) (*LoadBalancer, error) {
	strategy := RoundRobin
	if policy := os.Getenv("GRPC_LB_POLICY"); policy != "" {
		switch policy {
		case "round_robin":
			strategy = RoundRobin
		case "random":
			strategy = Random
		case "weighted":
			strategy = WeightedRoundRobin
		case "least_connections":
			strategy = LeastConnections
		}
	}

	cfg := LoadBalancerConfig{
		Strategy:  strategy,
		Endpoints: endpoints,
		Config:    Config{}, // Use defaults
	}

	return NewLoadBalancer(ctx, cfg)
}
