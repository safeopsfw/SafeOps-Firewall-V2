// Package client provides a high-level gRPC client library for communicating
// with the NIC Management service. It wraps the generated gRPC stubs with
// type-safe methods, connection management, retry logic, and error handling.
//
// NOTE: This client requires the generated protobuf/gRPC stubs from
// safeops/build/proto/go/nic_management. Run `make proto` to generate them.
package client

import (
	"context"
	"fmt"
	"sync"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/backoff"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/keepalive"
	"google.golang.org/grpc/status"
)

// =============================================================================
// Proto Stub Types (placeholder until proto is generated)
// These will be replaced with the actual generated types from:
// safeops/build/proto/go/nic_management
// =============================================================================

// The following interfaces and types are placeholders that match the expected
// proto-generated types. They allow the client to compile before proto generation.
// In production, import: pb "safeops/build/proto/go/nic_management"

// NICManagementServiceClient is the interface for the generated gRPC client.
// Replace with: pb.NICManagementClient when proto is generated.
type NICManagementServiceClient interface {
	ListNetworkInterfaces(ctx context.Context, req *InterfaceListRequest, opts ...grpc.CallOption) (*InterfaceListResponse, error)
	GetInterfaceDetails(ctx context.Context, req *InterfaceDetailsRequest, opts ...grpc.CallOption) (*InterfaceDetailsResponse, error)
	GetInterfaceStats(ctx context.Context, req *InterfaceStatsRequest, opts ...grpc.CallOption) (*InterfaceStatsResponse, error)
	ConfigureInterface(ctx context.Context, req *ConfigureInterfaceRequest, opts ...grpc.CallOption) (*ConfigureInterfaceResponse, error)
	EnableInterface(ctx context.Context, req *InterfaceActionRequest, opts ...grpc.CallOption) (*InterfaceActionResponse, error)
	DisableInterface(ctx context.Context, req *InterfaceActionRequest, opts ...grpc.CallOption) (*InterfaceActionResponse, error)
	GetRoutingTable(ctx context.Context, req *RoutingTableRequest, opts ...grpc.CallOption) (*RoutingTableResponse, error)
	GetNATMappings(ctx context.Context, req *NATMappingsRequest, opts ...grpc.CallOption) (*NATMappingsResponse, error)
	GetConnectionTracking(ctx context.Context, req *ConnectionTrackingRequest, opts ...grpc.CallOption) (*ConnectionTrackingResponse, error)
	GetWANHealth(ctx context.Context, req *WANHealthRequest, opts ...grpc.CallOption) (*WANHealthResponse, error)
	TriggerFailover(ctx context.Context, req *FailoverRequest, opts ...grpc.CallOption) (*FailoverResponse, error)
	GetLoadBalancerStats(ctx context.Context, req *LoadBalancerStatsRequest, opts ...grpc.CallOption) (*LoadBalancerStatsResponse, error)
	HealthCheck(ctx context.Context, req *HealthCheckRequest, opts ...grpc.CallOption) (*HealthCheckResponse, error)
}

// Request/Response placeholder types - these match the proto definitions
type InterfaceListRequest struct{}
type InterfaceListResponse struct {
	Interfaces []*NetworkInterfaceInfo `json:"interfaces"`
	TotalCount int32                   `json:"total_count"`
}
type NetworkInterfaceInfo struct {
	Name       string `json:"name"`
	Alias      string `json:"alias"`
	Type       string `json:"type"`
	State      string `json:"state"`
	MacAddress string `json:"mac_address"`
	IpAddress  string `json:"ip_address"`
	SpeedMbps  int32  `json:"speed_mbps"`
}

type InterfaceDetailsRequest struct{ InterfaceName string }
type InterfaceDetailsResponse struct {
	Interface    *NetworkInterfaceInfo  `json:"interface"`
	Capabilities *InterfaceCapabilities `json:"capabilities"`
	DriverInfo   *DriverInfo            `json:"driver_info"`
}
type InterfaceCapabilities struct {
	MaxSpeedMbps int32 `json:"max_speed_mbps"`
	VlanSupport  bool  `json:"vlan_support"`
}
type DriverInfo struct {
	Name    string `json:"name"`
	Version string `json:"version"`
}

type InterfaceStatsRequest struct{ InterfaceName string }
type InterfaceStatsResponse struct {
	RxBytes    uint64  `json:"rx_bytes"`
	TxBytes    uint64  `json:"tx_bytes"`
	RxPackets  uint64  `json:"rx_packets"`
	TxPackets  uint64  `json:"tx_packets"`
	RxErrors   uint64  `json:"rx_errors"`
	TxErrors   uint64  `json:"tx_errors"`
	Throughput float64 `json:"throughput_mbps"`
}

type ConfigureInterfaceRequest struct {
	InterfaceName string   `json:"interface_name"`
	IpAddress     string   `json:"ip_address"`
	Netmask       string   `json:"netmask"`
	Gateway       string   `json:"gateway"`
	DnsServers    []string `json:"dns_servers"`
	Mtu           int32    `json:"mtu"`
}
type ConfigureInterfaceResponse struct {
	Success bool   `json:"success"`
	Message string `json:"message"`
}

type InterfaceActionRequest struct{ InterfaceName string }
type InterfaceActionResponse struct {
	Success bool   `json:"success"`
	Message string `json:"message"`
}

type RoutingTableRequest struct{}
type RoutingTableResponse struct {
	Routes         []*RouteEntry `json:"routes"`
	DefaultGateway string        `json:"default_gateway"`
}
type RouteEntry struct {
	Destination   string `json:"destination"`
	Gateway       string `json:"gateway"`
	InterfaceName string `json:"interface_name"`
	Metric        int32  `json:"metric"`
	IsDefault     bool   `json:"is_default"`
}

type NATMappingsRequest struct {
	Protocol     string `json:"protocol"`
	WanInterface string `json:"wan_interface"`
	Limit        int32  `json:"limit"`
	Offset       int32  `json:"offset"`
}
type NATMappingsResponse struct {
	Mappings   []*NATMapping `json:"mappings"`
	TotalCount int32         `json:"total_count"`
}
type NATMapping struct {
	MappingId    string `json:"mapping_id"`
	InternalIp   string `json:"internal_ip"`
	InternalPort int32  `json:"internal_port"`
	ExternalIp   string `json:"external_ip"`
	ExternalPort int32  `json:"external_port"`
	Protocol     string `json:"protocol"`
}

type ConnectionTrackingRequest struct {
	State    string `json:"state"`
	Protocol string `json:"protocol"`
	Limit    int32  `json:"limit"`
	Offset   int32  `json:"offset"`
}
type ConnectionTrackingResponse struct {
	Connections []*Connection `json:"connections"`
	TotalCount  int32         `json:"total_count"`
}
type Connection struct {
	ConnectionId  string `json:"connection_id"`
	SrcIp         string `json:"src_ip"`
	SrcPort       int32  `json:"src_port"`
	DstIp         string `json:"dst_ip"`
	DstPort       int32  `json:"dst_port"`
	Protocol      string `json:"protocol"`
	State         string `json:"state"`
	BytesSent     uint64 `json:"bytes_sent"`
	BytesReceived uint64 `json:"bytes_received"`
}

type WANHealthRequest struct{}
type WANHealthResponse struct {
	WanInterfaces []*WANHealthInfo `json:"wan_interfaces"`
}
type WANHealthInfo struct {
	InterfaceName     string  `json:"interface_name"`
	State             string  `json:"state"`
	LatencyMs         float64 `json:"latency_ms"`
	PacketLossPercent float64 `json:"packet_loss_percent"`
	UptimePercent     float64 `json:"uptime_percent"`
}

type FailoverRequest struct {
	FromWan string `json:"from_wan"`
	ToWan   string `json:"to_wan"`
	Force   bool   `json:"force"`
}
type FailoverResponse struct {
	Success             bool   `json:"success"`
	Message             string `json:"message"`
	AffectedConnections int64  `json:"affected_connections"`
	DurationMs          int32  `json:"duration_ms"`
}

type LoadBalancerStatsRequest struct{}
type LoadBalancerStatsResponse struct {
	Mode     string         `json:"mode"`
	WanStats []*WANStatInfo `json:"wan_stats"`
}
type WANStatInfo struct {
	InterfaceName     string  `json:"interface_name"`
	TrafficPercentage float64 `json:"traffic_percentage"`
	ActiveConnections int64   `json:"active_connections"`
	TotalBytesSent    uint64  `json:"total_bytes_sent"`
	TotalBytesRecv    uint64  `json:"total_bytes_received"`
}

type HealthCheckRequest struct{}
type HealthCheckResponse struct {
	Status        string `json:"status"`
	Version       string `json:"version"`
	UptimeSeconds int64  `json:"uptime_seconds"`
}

// =============================================================================
// Client Configuration
// =============================================================================

// ClientConfig holds configuration for the NIC Management client.
type ClientConfig struct {
	Endpoint           string
	Timeout            time.Duration
	TLSEnabled         bool
	TLSCertFile        string
	TLSKeyFile         string
	TLSCAFile          string
	InsecureSkipVerify bool
	MaxRetries         int
	RetryBackoff       time.Duration
}

// DefaultConfig returns a default client configuration.
func DefaultConfig(endpoint string) *ClientConfig {
	return &ClientConfig{
		Endpoint:     endpoint,
		Timeout:      30 * time.Second,
		TLSEnabled:   false,
		MaxRetries:   3,
		RetryBackoff: 1 * time.Second,
	}
}

// =============================================================================
// Client Options
// =============================================================================

// ClientOption is a functional option for configuring the client.
type ClientOption func(*ClientConfig)

// WithTimeout sets the default request timeout.
func WithTimeout(timeout time.Duration) ClientOption {
	return func(c *ClientConfig) {
		c.Timeout = timeout
	}
}

// WithTLS enables TLS with the specified certificate files.
func WithTLS(certFile, keyFile, caFile string) ClientOption {
	return func(c *ClientConfig) {
		c.TLSEnabled = true
		c.TLSCertFile = certFile
		c.TLSKeyFile = keyFile
		c.TLSCAFile = caFile
	}
}

// WithInsecure disables TLS for development environments.
func WithInsecure() ClientOption {
	return func(c *ClientConfig) {
		c.TLSEnabled = false
	}
}

// WithMaxRetries sets the maximum number of retry attempts.
func WithMaxRetries(maxRetries int) ClientOption {
	return func(c *ClientConfig) {
		c.MaxRetries = maxRetries
	}
}

// WithRetryBackoff sets the backoff duration between retries.
func WithRetryBackoff(backoffDuration time.Duration) ClientOption {
	return func(c *ClientConfig) {
		c.RetryBackoff = backoffDuration
	}
}

// =============================================================================
// NIC Management Client
// =============================================================================

// NICManagementClient provides methods for interacting with the NIC Management service.
type NICManagementClient struct {
	conn   *grpc.ClientConn
	config *ClientConfig

	mu     sync.RWMutex
	closed bool
}

// NewClient creates a new NIC Management client with the specified endpoint and options.
func NewClient(endpoint string, opts ...ClientOption) (*NICManagementClient, error) {
	config := DefaultConfig(endpoint)
	for _, opt := range opts {
		opt(config)
	}

	client := &NICManagementClient{
		config: config,
	}

	if err := client.Connect(); err != nil {
		return nil, err
	}

	return client, nil
}

// Connect establishes a gRPC connection to the NIC Management service.
func (c *NICManagementClient) Connect() error {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.conn != nil {
		return nil // Already connected
	}

	dialOpts := []grpc.DialOption{
		grpc.WithKeepaliveParams(keepalive.ClientParameters{
			Time:                30 * time.Second,
			Timeout:             10 * time.Second,
			PermitWithoutStream: true,
		}),
		grpc.WithConnectParams(grpc.ConnectParams{
			Backoff: backoff.Config{
				BaseDelay:  1.0 * time.Second,
				Multiplier: 1.6,
				Jitter:     0.2,
				MaxDelay:   30 * time.Second,
			},
			MinConnectTimeout: 5 * time.Second,
		}),
		grpc.WithDefaultCallOptions(
			grpc.MaxCallRecvMsgSize(16*1024*1024), // 16 MB
			grpc.MaxCallSendMsgSize(16*1024*1024), // 16 MB
		),
	}

	// Configure TLS or insecure credentials
	if c.config.TLSEnabled {
		creds, err := credentials.NewClientTLSFromFile(c.config.TLSCertFile, "")
		if err != nil {
			return fmt.Errorf("failed to load TLS credentials: %w", err)
		}
		dialOpts = append(dialOpts, grpc.WithTransportCredentials(creds))
	} else {
		dialOpts = append(dialOpts, grpc.WithTransportCredentials(insecure.NewCredentials()))
	}

	// Dial the service
	conn, err := grpc.Dial(c.config.Endpoint, dialOpts...)
	if err != nil {
		return fmt.Errorf("failed to connect to NIC Management service at %s: %w", c.config.Endpoint, err)
	}

	c.conn = conn
	c.closed = false

	return nil
}

// Close closes the gRPC connection.
func (c *NICManagementClient) Close() error {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.closed || c.conn == nil {
		return nil
	}

	c.closed = true
	return c.conn.Close()
}

// IsConnected returns true if the client is connected.
func (c *NICManagementClient) IsConnected() bool {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.conn != nil && !c.closed
}

// Connection returns the underlying gRPC connection.
// Use this to create the actual proto client once generated:
//
//	pb.NewNICManagementClient(client.Connection())
func (c *NICManagementClient) Connection() *grpc.ClientConn {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.conn
}

// =============================================================================
// Context Helpers
// =============================================================================

// createContext creates a context with the default timeout if the parent doesn't have a deadline.
func (c *NICManagementClient) createContext(ctx context.Context) (context.Context, context.CancelFunc) {
	if _, hasDeadline := ctx.Deadline(); hasDeadline {
		return context.WithCancel(ctx)
	}
	return context.WithTimeout(ctx, c.config.Timeout)
}

// =============================================================================
// Error Handling
// =============================================================================

// Error types for client operations.
var (
	ErrNotConnected       = fmt.Errorf("client not connected")
	ErrConnectionFailed   = fmt.Errorf("connection failed")
	ErrTimeout            = fmt.Errorf("request timeout")
	ErrNotFound           = fmt.Errorf("resource not found")
	ErrInvalidArgument    = fmt.Errorf("invalid argument")
	ErrPermissionDenied   = fmt.Errorf("permission denied")
	ErrServiceUnavailable = fmt.Errorf("service unavailable")
	ErrInternal           = fmt.Errorf("internal error")
)

// HandleError translates gRPC errors to client errors.
func HandleError(method string, err error) error {
	if err == nil {
		return nil
	}

	st, ok := status.FromError(err)
	if !ok {
		return fmt.Errorf("%s: %w", method, err)
	}

	switch st.Code() {
	case codes.OK:
		return nil
	case codes.NotFound:
		return fmt.Errorf("%s: %w: %s", method, ErrNotFound, st.Message())
	case codes.InvalidArgument:
		return fmt.Errorf("%s: %w: %s", method, ErrInvalidArgument, st.Message())
	case codes.DeadlineExceeded:
		return fmt.Errorf("%s: %w", method, ErrTimeout)
	case codes.PermissionDenied:
		return fmt.Errorf("%s: %w: %s", method, ErrPermissionDenied, st.Message())
	case codes.Unavailable:
		return fmt.Errorf("%s: %w: %s", method, ErrServiceUnavailable, st.Message())
	case codes.Internal:
		return fmt.Errorf("%s: %w: %s", method, ErrInternal, st.Message())
	case codes.Canceled:
		return fmt.Errorf("%s: request canceled", method)
	default:
		return fmt.Errorf("%s: gRPC error (code=%s): %s", method, st.Code(), st.Message())
	}
}

// =============================================================================
// Convenience Functions
// =============================================================================

// MustNewClient creates a new client and panics on error.
// Useful for initialization in main() or tests.
func MustNewClient(endpoint string, opts ...ClientOption) *NICManagementClient {
	client, err := NewClient(endpoint, opts...)
	if err != nil {
		panic(fmt.Sprintf("failed to create NIC Management client: %v", err))
	}
	return client
}

// QuickConnect creates a client with insecure credentials for development.
func QuickConnect(endpoint string) (*NICManagementClient, error) {
	return NewClient(endpoint, WithInsecure(), WithTimeout(10*time.Second))
}

// =============================================================================
// Usage Example (when proto is generated)
// =============================================================================
//
// Once the proto is generated, update this file to:
// 1. Import: pb "safeops/build/proto/go/nic_management"
// 2. Add client field: client pb.NICManagementClient
// 3. Initialize in Connect(): c.client = pb.NewNICManagementClient(conn)
// 4. Implement methods using c.client.ListNetworkInterfaces(ctx, req), etc.
//
// Example usage:
//   client, _ := client.QuickConnect("localhost:50054")
//   defer client.Close()
//
//   protoClient := pb.NewNICManagementClient(client.Connection())
//   resp, _ := protoClient.ListNetworkInterfaces(ctx, &pb.InterfaceListRequest{})
