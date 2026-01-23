// Package integration provides integration with SafeOps Engine for verdict enforcement.
package integration

import (
	"context"
	"errors"
	"fmt"
	"log"
	"sync"
	"sync/atomic"
	"time"

	"firewall_engine/pkg/models"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/keepalive"
	"google.golang.org/grpc/status"
)

// ============================================================================
// Error Definitions
// ============================================================================

var (
	// ErrClientClosed is returned when operations are attempted on a closed client.
	ErrClientClosed = errors.New("verdict client is closed")

	// ErrNotConnected is returned when the client is not connected.
	ErrNotConnected = errors.New("client not connected to SafeOps")

	// ErrSendFailed is returned when sending a verdict fails.
	ErrSendFailed = errors.New("failed to send verdict")

	// ErrTimeout is returned when an operation times out.
	ErrTimeout = errors.New("operation timed out")

	// ErrInvalidResponse is returned when SafeOps returns an invalid response.
	ErrInvalidResponse = errors.New("invalid response from SafeOps")
)

// ============================================================================
// Verdict Client
// ============================================================================

// VerdictClient is a gRPC client for communicating verdicts to SafeOps Engine.
// It handles verdict reporting, rule fetching, and hot-reload notifications.
//
// Usage:
//
//	client, _ := NewVerdictClient(config)
//	client.Connect(ctx)
//	defer client.Close()
//
//	client.SendVerdict(ctx, packet, verdict)
type VerdictClient struct {
	// Configuration
	config *VerdictClientConfig

	// gRPC connection
	conn *grpc.ClientConn

	// Hot-reload callbacks
	hotReloadCallbacks []HotReloadCallback
	callbacksMu        sync.RWMutex

	// Statistics
	stats *VerdictClientStats

	// Logging
	logger *log.Logger

	// Lifecycle
	ctx       context.Context
	cancel    context.CancelFunc
	wg        sync.WaitGroup
	connected atomic.Bool
	closed    atomic.Bool
	closeMu   sync.Mutex
	closeOnce sync.Once

	// Reconnection
	reconnectAttempts atomic.Int32
	lastConnectTime   atomic.Int64
}

// VerdictClientConfig contains configuration for the verdict client.
type VerdictClientConfig struct {
	// SafeOps server address
	SafeOpsAddress string `json:"safeops_address" toml:"safeops_address"`

	// Connection settings
	ConnectTimeout time.Duration `json:"connect_timeout" toml:"connect_timeout"`
	RequestTimeout time.Duration `json:"request_timeout" toml:"request_timeout"`

	// Reconnection settings
	ReconnectInitialDelay time.Duration `json:"reconnect_initial_delay" toml:"reconnect_initial_delay"`
	ReconnectMaxDelay     time.Duration `json:"reconnect_max_delay" toml:"reconnect_max_delay"`
	ReconnectMaxAttempts  int           `json:"reconnect_max_attempts" toml:"reconnect_max_attempts"`

	// Keepalive settings
	KeepaliveTime    time.Duration `json:"keepalive_time" toml:"keepalive_time"`
	KeepaliveTimeout time.Duration `json:"keepalive_timeout" toml:"keepalive_timeout"`

	// Retry settings
	MaxRetries    int           `json:"max_retries" toml:"max_retries"`
	RetryInterval time.Duration `json:"retry_interval" toml:"retry_interval"`

	// Batching settings
	EnableBatching     bool          `json:"enable_batching" toml:"enable_batching"`
	BatchSize          int           `json:"batch_size" toml:"batch_size"`
	BatchFlushInterval time.Duration `json:"batch_flush_interval" toml:"batch_flush_interval"`
}

// DefaultVerdictClientConfig returns the default configuration.
func DefaultVerdictClientConfig() *VerdictClientConfig {
	return &VerdictClientConfig{
		SafeOpsAddress:        "127.0.0.1:50053",
		ConnectTimeout:        10 * time.Second,
		RequestTimeout:        5 * time.Second,
		ReconnectInitialDelay: 1 * time.Second,
		ReconnectMaxDelay:     60 * time.Second,
		ReconnectMaxAttempts:  0, // Unlimited
		KeepaliveTime:         30 * time.Second,
		KeepaliveTimeout:      10 * time.Second,
		MaxRetries:            3,
		RetryInterval:         100 * time.Millisecond,
		EnableBatching:        false,
		BatchSize:             100,
		BatchFlushInterval:    10 * time.Millisecond,
	}
}

// Validate checks the configuration for errors.
func (c *VerdictClientConfig) Validate() error {
	if c.SafeOpsAddress == "" {
		return fmt.Errorf("safeops_address is required")
	}
	if c.ConnectTimeout < time.Second {
		return fmt.Errorf("connect_timeout must be >= 1s")
	}
	if c.RequestTimeout < 100*time.Millisecond {
		return fmt.Errorf("request_timeout must be >= 100ms")
	}
	return nil
}

// HotReloadCallback is called when rules are hot-reloaded.
type HotReloadCallback func(changedRules []string) error

// VerdictClientStats contains client statistics.
type VerdictClientStats struct {
	VerdictsSent       atomic.Uint64
	VerdictsFailed     atomic.Uint64
	ReconnectAttempts  atomic.Uint64
	ReconnectSuccesses atomic.Uint64
	HotReloadsReceived atomic.Uint64
	TotalLatencyNs     atomic.Uint64
}

// ============================================================================
// Constructor
// ============================================================================

// NewVerdictClient creates a new verdict client.
func NewVerdictClient(config *VerdictClientConfig) (*VerdictClient, error) {
	if config == nil {
		config = DefaultVerdictClientConfig()
	}

	if err := config.Validate(); err != nil {
		return nil, fmt.Errorf("invalid config: %w", err)
	}

	ctx, cancel := context.WithCancel(context.Background())

	return &VerdictClient{
		config:             config,
		hotReloadCallbacks: make([]HotReloadCallback, 0),
		stats:              &VerdictClientStats{},
		logger:             log.New(log.Writer(), "[VERDICT-CLIENT] ", log.LstdFlags|log.Lmicroseconds),
		ctx:                ctx,
		cancel:             cancel,
	}, nil
}

// ============================================================================
// Connection Management
// ============================================================================

// Connect establishes connection to SafeOps Engine.
func (c *VerdictClient) Connect(ctx context.Context) error {
	if c.closed.Load() {
		return ErrClientClosed
	}

	c.logger.Printf("Connecting to SafeOps at %s...", c.config.SafeOpsAddress)

	// Create connection with timeout
	connectCtx, cancel := context.WithTimeout(ctx, c.config.ConnectTimeout)
	defer cancel()

	// gRPC dial options
	opts := []grpc.DialOption{
		grpc.WithTransportCredentials(insecure.NewCredentials()),
		grpc.WithKeepaliveParams(keepalive.ClientParameters{
			Time:                c.config.KeepaliveTime,
			Timeout:             c.config.KeepaliveTimeout,
			PermitWithoutStream: true,
		}),
		grpc.WithBlock(),
	}

	conn, err := grpc.DialContext(connectCtx, c.config.SafeOpsAddress, opts...)
	if err != nil {
		return fmt.Errorf("failed to connect: %w", err)
	}

	c.conn = conn
	c.connected.Store(true)
	c.lastConnectTime.Store(time.Now().UnixNano())
	c.reconnectAttempts.Store(0)

	c.logger.Printf("Connected to SafeOps at %s", c.config.SafeOpsAddress)
	return nil
}

// Disconnect closes the connection.
func (c *VerdictClient) Disconnect() error {
	c.connected.Store(false)

	if c.conn != nil {
		err := c.conn.Close()
		c.conn = nil
		return err
	}

	return nil
}

// IsConnected returns true if connected to SafeOps.
func (c *VerdictClient) IsConnected() bool {
	return c.connected.Load()
}

// reconnect attempts to reconnect with exponential backoff.
func (c *VerdictClient) reconnect() error {
	if c.closed.Load() {
		return ErrClientClosed
	}

	backoff := c.config.ReconnectInitialDelay
	maxAttempts := c.config.ReconnectMaxAttempts
	if maxAttempts == 0 {
		maxAttempts = 1000000 // Effectively unlimited
	}

	for attempt := 1; attempt <= maxAttempts; attempt++ {
		c.stats.ReconnectAttempts.Add(1)
		c.reconnectAttempts.Add(1)

		c.logger.Printf("Reconnection attempt %d...", attempt)

		if err := c.Connect(c.ctx); err == nil {
			c.stats.ReconnectSuccesses.Add(1)
			c.logger.Printf("Reconnected after %d attempts", attempt)
			return nil
		}

		// Exponential backoff
		select {
		case <-c.ctx.Done():
			return c.ctx.Err()
		case <-time.After(backoff):
		}

		backoff *= 2
		if backoff > c.config.ReconnectMaxDelay {
			backoff = c.config.ReconnectMaxDelay
		}
	}

	return fmt.Errorf("reconnection failed after %d attempts", maxAttempts)
}

// ============================================================================
// Verdict Operations
// ============================================================================

// SendVerdict sends a verdict to SafeOps Engine.
func (c *VerdictClient) SendVerdict(ctx context.Context, packet *models.PacketMetadata, verdict *models.VerdictResult) error {
	if c.closed.Load() {
		return ErrClientClosed
	}

	if !c.connected.Load() {
		return ErrNotConnected
	}

	startTime := time.Now()

	// Create request context with timeout
	reqCtx, cancel := context.WithTimeout(ctx, c.config.RequestTimeout)
	defer cancel()

	// Retry logic
	var lastErr error
	for attempt := 0; attempt <= c.config.MaxRetries; attempt++ {
		err := c.sendVerdictOnce(reqCtx, packet, verdict)
		if err == nil {
			// Success
			c.stats.VerdictsSent.Add(1)
			c.stats.TotalLatencyNs.Add(uint64(time.Since(startTime).Nanoseconds()))
			return nil
		}

		lastErr = err

		// Check if retryable
		if !c.isRetryableError(err) {
			break
		}

		// Wait before retry
		if attempt < c.config.MaxRetries {
			select {
			case <-reqCtx.Done():
				return reqCtx.Err()
			case <-time.After(c.config.RetryInterval):
			}
		}
	}

	c.stats.VerdictsFailed.Add(1)
	return fmt.Errorf("%w: %v", ErrSendFailed, lastErr)
}

// sendVerdictOnce attempts to send a verdict once.
func (c *VerdictClient) sendVerdictOnce(_ context.Context, packet *models.PacketMetadata, verdict *models.VerdictResult) error {
	// This is a placeholder - in production, this would call the gRPC service
	// For now, we just log the verdict
	c.logger.Printf("Verdict: %s:%d -> %s:%d [%s] %s",
		packet.SrcIP, packet.SrcPort,
		packet.DstIP, packet.DstPort,
		verdict.Verdict, verdict.RuleName)

	return nil
}

// isRetryableError checks if an error is retryable.
func (c *VerdictClient) isRetryableError(err error) bool {
	if err == nil {
		return false
	}

	// gRPC status codes that are retryable
	code := status.Code(err)
	switch code {
	case codes.Unavailable, codes.ResourceExhausted, codes.Aborted:
		return true
	default:
		return false
	}
}

// ============================================================================
// Batch Operations
// ============================================================================

// VerdictBatch contains a batch of verdicts to send.
type VerdictBatch struct {
	Packets  []*models.PacketMetadata
	Verdicts []*models.VerdictResult
}

// SendVerdictBatch sends multiple verdicts in a batch.
func (c *VerdictClient) SendVerdictBatch(ctx context.Context, batch *VerdictBatch) error {
	if c.closed.Load() {
		return ErrClientClosed
	}

	if !c.connected.Load() {
		return ErrNotConnected
	}

	if batch == nil || len(batch.Packets) == 0 {
		return nil
	}

	if len(batch.Packets) != len(batch.Verdicts) {
		return fmt.Errorf("packets and verdicts count mismatch")
	}

	// Send each verdict
	var errs []error
	for i := range batch.Packets {
		if err := c.SendVerdict(ctx, batch.Packets[i], batch.Verdicts[i]); err != nil {
			errs = append(errs, err)
		}
	}

	if len(errs) > 0 {
		return fmt.Errorf("batch send failed with %d errors", len(errs))
	}

	return nil
}

// ============================================================================
// Hot-Reload
// ============================================================================

// OnHotReload registers a callback for rule hot-reload events.
func (c *VerdictClient) OnHotReload(callback HotReloadCallback) {
	c.callbacksMu.Lock()
	defer c.callbacksMu.Unlock()
	c.hotReloadCallbacks = append(c.hotReloadCallbacks, callback)
}

// notifyHotReload notifies all registered callbacks of a hot-reload.
func (c *VerdictClient) notifyHotReload(changedRules []string) {
	c.callbacksMu.RLock()
	callbacks := make([]HotReloadCallback, len(c.hotReloadCallbacks))
	copy(callbacks, c.hotReloadCallbacks)
	c.callbacksMu.RUnlock()

	c.stats.HotReloadsReceived.Add(1)

	for _, callback := range callbacks {
		if err := callback(changedRules); err != nil {
			c.logger.Printf("Hot-reload callback error: %v", err)
		}
	}
}

// TriggerHotReload manually triggers a hot-reload notification.
// This is useful for testing or when rules are changed via API.
func (c *VerdictClient) TriggerHotReload(changedRules []string) {
	c.logger.Printf("Hot-reload triggered, %d rules changed", len(changedRules))
	c.notifyHotReload(changedRules)
}

// ============================================================================
// Health Check
// ============================================================================

// HealthCheck checks the connection health.
func (c *VerdictClient) HealthCheck(ctx context.Context) error {
	if c.closed.Load() {
		return ErrClientClosed
	}

	if !c.connected.Load() {
		return ErrNotConnected
	}

	// Check connection state
	if c.conn == nil {
		return ErrNotConnected
	}

	// In production, this would call a gRPC health check endpoint
	return nil
}

// ============================================================================
// Statistics
// ============================================================================

// GetStats returns client statistics.
func (c *VerdictClient) GetStats() map[string]uint64 {
	sent := c.stats.VerdictsSent.Load()
	totalLatency := c.stats.TotalLatencyNs.Load()
	avgLatency := uint64(0)
	if sent > 0 {
		avgLatency = totalLatency / sent
	}

	return map[string]uint64{
		"verdicts_sent":        sent,
		"verdicts_failed":      c.stats.VerdictsFailed.Load(),
		"reconnect_attempts":   c.stats.ReconnectAttempts.Load(),
		"reconnect_successes":  c.stats.ReconnectSuccesses.Load(),
		"hot_reloads_received": c.stats.HotReloadsReceived.Load(),
		"avg_latency_ns":       avgLatency,
	}
}

// ============================================================================
// Lifecycle
// ============================================================================

// Close gracefully closes the client.
func (c *VerdictClient) Close() error {
	var err error

	c.closeOnce.Do(func() {
		c.closeMu.Lock()
		defer c.closeMu.Unlock()

		c.logger.Println("Closing verdict client...")
		c.closed.Store(true)

		// Cancel context
		c.cancel()

		// Wait for goroutines
		c.wg.Wait()

		// Disconnect
		if disconnectErr := c.Disconnect(); disconnectErr != nil {
			err = disconnectErr
		}

		// Log final stats
		stats := c.GetStats()
		c.logger.Printf("Client closed. Stats: sent=%d, failed=%d",
			stats["verdicts_sent"],
			stats["verdicts_failed"],
		)
	})

	return err
}

// SetLogger sets a custom logger.
func (c *VerdictClient) SetLogger(logger *log.Logger) {
	if logger != nil {
		c.logger = logger
	}
}

// GetConfig returns the current configuration.
func (c *VerdictClient) GetConfig() *VerdictClientConfig {
	return c.config
}
