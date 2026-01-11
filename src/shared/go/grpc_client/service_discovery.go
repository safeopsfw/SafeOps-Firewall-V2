// Package grpc_client provides service discovery integration.
package grpc_client

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/connectivity"
	"google.golang.org/grpc/resolver"
)

// ServiceDiscovery manages service endpoint discovery
type ServiceDiscovery struct {
	mu        sync.RWMutex
	endpoints map[string][]string // service -> endpoints
	watchers  map[string][]chan []string
}

// NewServiceDiscovery creates a new service discovery manager
func NewServiceDiscovery() *ServiceDiscovery {
	return &ServiceDiscovery{
		endpoints: make(map[string][]string),
		watchers:  make(map[string][]chan []string),
	}
}

// Register registers endpoints for a service
func (sd *ServiceDiscovery) Register(service string, endpoints []string) {
	sd.mu.Lock()
	defer sd.mu.Unlock()

	sd.endpoints[service] = endpoints
	sd.notifyWatchers(service, endpoints)
}

// Deregister removes a service
func (sd *ServiceDiscovery) Deregister(service string) {
	sd.mu.Lock()
	defer sd.mu.Unlock()

	delete(sd.endpoints, service)
	sd.notifyWatchers(service, nil)
}

// Resolve returns current endpoints for a service
func (sd *ServiceDiscovery) Resolve(service string) ([]string, error) {
	sd.mu.RLock()
	defer sd.mu.RUnlock()

	endpoints, ok := sd.endpoints[service]
	if !ok || len(endpoints) == 0 {
		return nil, fmt.Errorf("service not found: %s", service)
	}

	return append([]string(nil), endpoints...), nil
}

// Watch watches for service endpoint changes
func (sd *ServiceDiscovery) Watch(service string) <-chan []string {
	sd.mu.Lock()
	defer sd.mu.Unlock()

	ch := make(chan []string, 10)
	sd.watchers[service] = append(sd.watchers[service], ch)

	// Send current endpoints
	if endpoints, ok := sd.endpoints[service]; ok {
		ch <- endpoints
	}

	return ch
}

// notifyWatchers notifies all watchers of a service
func (sd *ServiceDiscovery) notifyWatchers(service string, endpoints []string) {
	watchers := sd.watchers[service]
	for _, ch := range watchers {
		select {
		case ch <- endpoints:
		default:
			// Don't block on slow watchers
		}
	}
}

// StaticResolver creates a resolver for static endpoints
type StaticResolver struct {
	endpoints []string
}

// NewStaticResolver creates a static resolver
func NewStaticResolver(endpoints []string) *StaticResolver {
	return &StaticResolver{
		endpoints: endpoints,
	}
}

// Build implements resolver.Builder
func (r *StaticResolver) Build(target resolver.Target, cc resolver.ClientConn, opts resolver.BuildOptions) (resolver.Resolver, error) {
	addrs := make([]resolver.Address, len(r.endpoints))
	for i, endpoint := range r.endpoints {
		addrs[i] = resolver.Address{Addr: endpoint}
	}

	err := cc.UpdateState(resolver.State{Addresses: addrs})
	if err != nil {
		return nil, err
	}

	return &staticResolverInstance{}, nil
}

// Scheme returns the resolver scheme
func (r *StaticResolver) Scheme() string {
	return "static"
}

type staticResolverInstance struct{}

func (r *staticResolverInstance) ResolveNow(resolver.ResolveNowOptions) {}
func (r *staticResolverInstance) Close()                                {}

// DialWithServiceDiscovery creates a connection using service discovery
func DialWithServiceDiscovery(ctx context.Context, sd *ServiceDiscovery, serviceName string, opts ...grpc.DialOption) (*grpc.ClientConn, error) {
	endpoints, err := sd.Resolve(serviceName)
	if err != nil {
		return nil, err
	}

	if len(endpoints) == 0 {
		return nil, fmt.Errorf("no endpoints available for service: %s", serviceName)
	}

	// Use first endpoint for now (can enhance with load balancing)
	return grpc.DialContext(ctx, endpoints[0], opts...)
}

// DialWithStaticDiscovery creates a connection with static endpoints
func DialWithStaticDiscovery(ctx context.Context, endpoints []string, opts ...grpc.DialOption) (*grpc.ClientConn, error) {
	if len(endpoints) == 0 {
		return nil, fmt.Errorf("no endpoints provided")
	}

	// Register static resolver
	resolver.Register(NewStaticResolver(endpoints))

	// Create target with static scheme
	target := fmt.Sprintf("static:///%s", strings.Join(endpoints, ","))

	// Add load balancing
	opts = append(opts, grpc.WithDefaultServiceConfig(`{"loadBalancingPolicy":"round_robin"}`))

	return grpc.DialContext(ctx, target, opts...)
}

// ConsulConfig configures Consul service discovery
type ConsulConfig struct {
	Address      string
	ServiceName  string
	HealthyOnly  bool
	WaitTime     time.Duration
	QueryOptions map[string]string
}

// DefaultConsulConfig returns default Consul configuration
func DefaultConsulConfig(serviceName string) ConsulConfig {
	return ConsulConfig{
		Address:     "127.0.0.1:8500",
		ServiceName: serviceName,
		HealthyOnly: true,
		WaitTime:    10 * time.Second,
	}
}

// DialWithConsul creates a connection using Consul service discovery
// NOTE: Requires github.com/mbobakov/grpc-consul-resolver
func DialWithConsul(ctx context.Context, cfg ConsulConfig, opts ...grpc.DialOption) (*grpc.ClientConn, error) {
	// Build Consul target
	target := fmt.Sprintf("consul://%s/%s", cfg.Address, cfg.ServiceName)

	if cfg.HealthyOnly {
		target += "?healthy=true"
	}

	// Add load balancing
	opts = append(opts, grpc.WithDefaultServiceConfig(`{"loadBalancingPolicy":"round_robin"}`))

	return grpc.DialContext(ctx, target, opts...)
}

// KubernetesConfig configures Kubernetes service discovery
type KubernetesConfig struct {
	ServiceName string
	Namespace   string
	Port        int
}

// DialWithKubernetes creates a connection using Kubernetes DNS
func DialWithKubernetes(ctx context.Context, cfg KubernetesConfig, opts ...grpc.DialOption) (*grpc.ClientConn, error) {
	// Build Kubernetes DNS target (headless service)
	target := fmt.Sprintf("dns:///%s.%s.svc.cluster.local:%d",
		cfg.ServiceName, cfg.Namespace, cfg.Port)

	// Configure DNS resolver with health checking
	serviceConfig := fmt.Sprintf(`{
		"loadBalancingPolicy":"round_robin",
		"healthCheckConfig": {
			"serviceName": "%s"
		}
	}`, cfg.ServiceName)

	opts = append(opts, grpc.WithDefaultServiceConfig(serviceConfig))

	return grpc.DialContext(ctx, target, opts...)
}

// DiscoveryStats holds service discovery statistics
type DiscoveryStats struct {
	Services  int
	Endpoints map[string]int
	Watchers  int
}

// Stats returns service discovery statistics
func (sd *ServiceDiscovery) Stats() DiscoveryStats {
	sd.mu.RLock()
	defer sd.mu.RUnlock()

	endpoints := make(map[string]int)
	for service, eps := range sd.endpoints {
		endpoints[service] = len(eps)
	}

	totalWatchers := 0
	for _, watchers := range sd.watchers {
		totalWatchers += len(watchers)
	}

	return DiscoveryStats{
		Services:  len(sd.endpoints),
		Endpoints: endpoints,
		Watchers:  totalWatchers,
	}
}

// HealthCheck performs health check on an endpoint
func HealthCheck(ctx context.Context, endpoint string, opts ...grpc.DialOption) error {
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()

	conn, err := grpc.DialContext(ctx, endpoint, opts...)
	if err != nil {
		return err
	}
	defer conn.Close()

	// Check connection state
	state := conn.GetState()
	if state == connectivity.Ready || state == connectivity.Idle {
		return nil
	}

	return fmt.Errorf("endpoint unhealthy: %s (state: %s)", endpoint, state)
}
