// Package management provides gRPC management API for the firewall engine.
package management

import (
	"context"
	"errors"
	"fmt"
	"net"
	"sync"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/reflection"
	"google.golang.org/protobuf/types/known/timestamppb"

	"firewall_engine/internal/health"
	"firewall_engine/internal/logging"
	"firewall_engine/internal/metrics"
)

// ============================================================================
// Server Configuration
// ============================================================================

// ServerConfig configures the management gRPC server.
type ServerConfig struct {
	// Address is the listen address (e.g., ":50054").
	Address string `json:"address" toml:"address"`

	// MaxConnections is the maximum concurrent connections.
	MaxConnections int `json:"max_connections" toml:"max_connections"`

	// EnableReflection enables gRPC reflection for debugging.
	EnableReflection bool `json:"enable_reflection" toml:"enable_reflection"`

	// MaxRecvMsgSize is the max receive message size in bytes.
	MaxRecvMsgSize int `json:"max_recv_msg_size" toml:"max_recv_msg_size"`

	// MaxSendMsgSize is the max send message size in bytes.
	MaxSendMsgSize int `json:"max_send_msg_size" toml:"max_send_msg_size"`
}

// DefaultServerConfig returns a config with sensible defaults.
func DefaultServerConfig() ServerConfig {
	return ServerConfig{
		Address:          ":50054",
		MaxConnections:   100,
		EnableReflection: true,
		MaxRecvMsgSize:   4 * 1024 * 1024, // 4MB
		MaxSendMsgSize:   4 * 1024 * 1024, // 4MB
	}
}

// Validate validates the configuration.
func (c *ServerConfig) Validate() error {
	if c.Address == "" {
		return errors.New("address is required")
	}
	if c.MaxConnections <= 0 {
		c.MaxConnections = 100
	}
	if c.MaxRecvMsgSize <= 0 {
		c.MaxRecvMsgSize = 4 * 1024 * 1024
	}
	if c.MaxSendMsgSize <= 0 {
		c.MaxSendMsgSize = 4 * 1024 * 1024
	}
	return nil
}

// ============================================================================
// Dependencies
// ============================================================================

// Dependencies holds all dependencies for the management server.
type Dependencies struct {
	// Metrics
	MetricsCollector *metrics.MetricsCollector
	RollingStats     *metrics.RollingStats

	// Health
	HealthAggregator *health.Aggregator

	// Logging
	Logger logging.Logger

	// Interfaces for components (will be injected)
	RuleManager       RuleManagerInterface
	CacheManager      CacheManagerInterface
	ConnectionTracker ConnectionTrackerInterface
	EngineController  EngineControllerInterface
}

// RuleManagerInterface defines methods for rule management.
type RuleManagerInterface interface {
	GetRuleCount() int
	GetRules() []RuleInfo
	GetRuleByID(id string) (RuleInfo, bool)
	Reload() error
	HasErrors() bool
	GetLastLoadTime() time.Time
}

// RuleInfo contains rule information.
type RuleInfo struct {
	ID         string
	Name       string
	Action     string
	Priority   int
	Conditions []string
	HitCount   uint64
	CreatedAt  time.Time
	LastHit    time.Time
	Enabled    bool
}

// CacheManagerInterface defines methods for cache management.
type CacheManagerInterface interface {
	GetSize() int
	GetCapacity() int
	GetHitRate() float64
	GetHits() uint64
	GetMisses() uint64
	GetEvictions() uint64
	Flush() int
}

// ConnectionTrackerInterface defines methods for connection tracking.
type ConnectionTrackerInterface interface {
	GetActiveConnectionCount() int
	GetConnections(limit int) []ConnectionInfo
	GetConnectionByFlowID(flowID string) (ConnectionInfo, bool)
}

// ConnectionInfo contains connection information.
type ConnectionInfo struct {
	FlowID       string
	SrcIP        string
	SrcPort      int
	DstIP        string
	DstPort      int
	Protocol     string
	State        string
	CreatedAt    time.Time
	LastActivity time.Time
	PacketsIn    uint64
	PacketsOut   uint64
	BytesIn      uint64
	BytesOut     uint64
	Application  string
}

// EngineControllerInterface defines methods for engine control.
type EngineControllerInterface interface {
	GetVersion() string
	GetBuildTime() string
	GetGoVersion() string
	GetGitCommit() string
	GetStartTime() time.Time
	GetMode() string
	IsSafeOpsEnabled() bool
	IsWFPEnabled() bool
	SetLogLevel(level string) (string, error)
	GetLogLevel() string
}

// ============================================================================
// Management Server
// ============================================================================

// Server is the gRPC management server.
type Server struct {
	config ServerConfig
	deps   Dependencies

	grpcServer *grpc.Server
	listener   net.Listener

	mu        sync.Mutex
	isRunning bool
	startTime time.Time
}

// NewServer creates a new management server.
func NewServer(config ServerConfig, deps Dependencies) (*Server, error) {
	if err := config.Validate(); err != nil {
		return nil, fmt.Errorf("invalid config: %w", err)
	}

	return &Server{
		config:    config,
		deps:      deps,
		startTime: time.Now(),
	}, nil
}

// Start starts the gRPC server.
func (s *Server) Start(ctx context.Context) error {
	s.mu.Lock()
	if s.isRunning {
		s.mu.Unlock()
		return errors.New("server already running")
	}
	s.mu.Unlock()

	// Create listener
	listener, err := net.Listen("tcp", s.config.Address)
	if err != nil {
		return fmt.Errorf("failed to listen on %s: %w", s.config.Address, err)
	}
	s.listener = listener

	// Create gRPC server with options
	opts := []grpc.ServerOption{
		grpc.MaxRecvMsgSize(s.config.MaxRecvMsgSize),
		grpc.MaxSendMsgSize(s.config.MaxSendMsgSize),
	}

	s.grpcServer = grpc.NewServer(opts...)

	// Register our service
	RegisterFirewallManagementServer(s.grpcServer, s)

	// Enable reflection for debugging
	if s.config.EnableReflection {
		reflection.Register(s.grpcServer)
	}

	s.mu.Lock()
	s.isRunning = true
	s.startTime = time.Now()
	s.mu.Unlock()

	// Log startup
	if s.deps.Logger != nil {
		s.deps.Logger.Info().
			Str("address", s.config.Address).
			Bool("reflection", s.config.EnableReflection).
			Msg("Management gRPC server started")
	}

	// Start serving
	errCh := make(chan error, 1)
	go func() {
		if err := s.grpcServer.Serve(listener); err != nil {
			errCh <- err
		}
		close(errCh)
	}()

	// Wait for context cancellation or error
	select {
	case <-ctx.Done():
		return s.Stop()
	case err := <-errCh:
		return err
	}
}

// StartAsync starts the server without blocking.
func (s *Server) StartAsync() error {
	s.mu.Lock()
	if s.isRunning {
		s.mu.Unlock()
		return errors.New("server already running")
	}
	s.mu.Unlock()

	// Create listener
	listener, err := net.Listen("tcp", s.config.Address)
	if err != nil {
		return fmt.Errorf("failed to listen on %s: %w", s.config.Address, err)
	}
	s.listener = listener

	// Create gRPC server
	opts := []grpc.ServerOption{
		grpc.MaxRecvMsgSize(s.config.MaxRecvMsgSize),
		grpc.MaxSendMsgSize(s.config.MaxSendMsgSize),
	}
	s.grpcServer = grpc.NewServer(opts...)

	// Register service
	RegisterFirewallManagementServer(s.grpcServer, s)

	// Enable reflection
	if s.config.EnableReflection {
		reflection.Register(s.grpcServer)
	}

	s.mu.Lock()
	s.isRunning = true
	s.startTime = time.Now()
	s.mu.Unlock()

	// Log startup
	if s.deps.Logger != nil {
		s.deps.Logger.Info().
			Str("address", s.config.Address).
			Bool("reflection", s.config.EnableReflection).
			Msg("Management gRPC server started (async)")
	}

	// Start serving in background
	go func() {
		if err := s.grpcServer.Serve(listener); err != nil {
			if s.deps.Logger != nil {
				s.deps.Logger.Error().Err(err).Msg("gRPC server error")
			}
		}
	}()

	return nil
}

// Stop stops the gRPC server gracefully.
func (s *Server) Stop() error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if !s.isRunning {
		return nil
	}

	s.isRunning = false

	if s.grpcServer != nil {
		s.grpcServer.GracefulStop()
	}

	if s.deps.Logger != nil {
		s.deps.Logger.Info().Msg("Management gRPC server stopped")
	}

	return nil
}

// Address returns the listen address.
func (s *Server) Address() string {
	return s.config.Address
}

// IsRunning returns true if the server is running.
func (s *Server) IsRunning() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.isRunning
}

// ============================================================================
// Service Registration (placeholder until proto is generated)
// ============================================================================

// FirewallManagementServer is the interface for the management service.
// This will be replaced by the generated interface from proto.
type FirewallManagementServer interface {
	// Statistics
	GetStatistics(ctx context.Context, req *GetStatisticsRequest) (*GetStatisticsResponse, error)
	GetRuleStats(ctx context.Context, req *GetRuleStatsRequest) (*GetRuleStatsResponse, error)
	GetTopBlockedDomains(ctx context.Context, req *GetTopBlockedDomainsRequest) (*GetTopBlockedDomainsResponse, error)

	// Health
	GetHealth(ctx context.Context, req *GetHealthRequest) (*GetHealthResponse, error)
	GetComponentHealth(ctx context.Context, req *GetComponentHealthRequest) (*GetComponentHealthResponse, error)

	// Rules
	ListRules(ctx context.Context, req *ListRulesRequest) (*ListRulesResponse, error)
	GetRule(ctx context.Context, req *GetRuleRequest) (*GetRuleResponse, error)
	ReloadRules(ctx context.Context, req *ReloadRulesRequest) (*ReloadRulesResponse, error)

	// Cache
	GetCacheStats(ctx context.Context, req *GetCacheStatsRequest) (*GetCacheStatsResponse, error)
	FlushCache(ctx context.Context, req *FlushCacheRequest) (*FlushCacheResponse, error)

	// Connections
	GetActiveConnections(ctx context.Context, req *GetActiveConnectionsRequest) (*GetActiveConnectionsResponse, error)
	GetConnectionByFlowID(ctx context.Context, req *GetConnectionByFlowIDRequest) (*GetConnectionByFlowIDResponse, error)

	// Engine
	SetLogLevel(ctx context.Context, req *SetLogLevelRequest) (*SetLogLevelResponse, error)
	GetEngineInfo(ctx context.Context, req *GetEngineInfoRequest) (*GetEngineInfoResponse, error)
}

// RegisterFirewallManagementServer registers the service with gRPC server.
// This is a placeholder - will be replaced by generated code.
func RegisterFirewallManagementServer(s *grpc.Server, srv FirewallManagementServer) {
	// Will be implemented when proto is generated
}

// ============================================================================
// Placeholder request/response types (will be replaced by generated code)
// ============================================================================

type GetStatisticsRequest struct {
	WindowSeconds int32
}
type GetStatisticsResponse struct {
	TotalPackets      uint64
	AllowedPackets    uint64
	DeniedPackets     uint64
	ThroughputPps     float64
	CacheHitRate      float64
	TotalBytes        uint64
	BytesIn           uint64
	BytesOut          uint64
	Latency           *LatencyStats
	PacketsByProtocol map[string]uint64
	PacketsByAction   map[string]uint64
}

type GetRuleStatsRequest struct {
	RuleID string
	Limit  int32
}
type GetRuleStatsResponse struct {
	Rules      []*RuleStat
	TotalCount int32
}

type GetTopBlockedDomainsRequest struct {
	Limit int32
}
type GetTopBlockedDomainsResponse struct {
	Domains []*BlockedDomain
}

type GetHealthRequest struct{}
type GetHealthResponse struct {
	Status         string
	Components     []*ComponentHealth
	Timestamp      *timestamppb.Timestamp
	CheckLatencyMs float64
}

type GetComponentHealthRequest struct {
	ComponentName string
}
type GetComponentHealthResponse struct {
	Component *ComponentHealth
}

type ListRulesRequest struct {
	Action string
	Limit  int32
	Offset int32
}
type ListRulesResponse struct {
	Rules      []*Rule
	TotalCount int32
	HasMore    bool
}

type GetRuleRequest struct {
	RuleID string
}
type GetRuleResponse struct {
	Rule  *Rule
	Found bool
}

type ReloadRulesRequest struct{}
type ReloadRulesResponse struct {
	Success           bool
	RulesLoaded       int32
	ReloadTimeSeconds float64
	Errors            []string
	PreviousRuleCount int32
}

type GetCacheStatsRequest struct{}
type GetCacheStatsResponse struct {
	Size      uint64
	Capacity  uint64
	HitRate   float64
	Hits      uint64
	Misses    uint64
	Evictions uint64
}

type FlushCacheRequest struct {
	Pattern string
}
type FlushCacheResponse struct {
	Success        bool
	EntriesFlushed uint64
}

type GetActiveConnectionsRequest struct {
	Limit    int32
	Protocol string
	State    string
}
type GetActiveConnectionsResponse struct {
	Connections      []*Connection
	TotalConnections uint64
}

type GetConnectionByFlowIDRequest struct {
	FlowID string
}
type GetConnectionByFlowIDResponse struct {
	Connection *Connection
	Found      bool
}

type SetLogLevelRequest struct {
	Level string
}
type SetLogLevelResponse struct {
	Success       bool
	PreviousLevel string
	NewLevel      string
	Error         string
}

type GetEngineInfoRequest struct{}
type GetEngineInfoResponse struct {
	Version       string
	BuildTime     string
	GoVersion     string
	GitCommit     string
	StartTime     *timestamppb.Timestamp
	UptimeSeconds float64
	Config        *EngineConfig
	Stats         *EngineStats
}
