// Package health provides health monitoring for the firewall engine.
package health

import (
	"context"
	"fmt"
	"net"
	"os"
	"sync"
	"time"
)

// ============================================================================
// Dependency Check Types
// ============================================================================

// DependencyType represents the type of external dependency.
type DependencyType int

const (
	// DependencyTypeGRPC is a gRPC service dependency.
	DependencyTypeGRPC DependencyType = iota

	// DependencyTypeTCP is a TCP service dependency.
	DependencyTypeTCP

	// DependencyTypeFile is a file dependency.
	DependencyTypeFile

	// DependencyTypeDirectory is a directory dependency.
	DependencyTypeDirectory

	// DependencyTypeCustom is a custom dependency check.
	DependencyTypeCustom
)

// String returns the string representation.
func (t DependencyType) String() string {
	switch t {
	case DependencyTypeGRPC:
		return "grpc"
	case DependencyTypeTCP:
		return "tcp"
	case DependencyTypeFile:
		return "file"
	case DependencyTypeDirectory:
		return "directory"
	case DependencyTypeCustom:
		return "custom"
	default:
		return "unknown"
	}
}

// ============================================================================
// Dependency Configuration
// ============================================================================

// DependencyConfig configures a dependency check.
type DependencyConfig struct {
	// Name is the dependency name.
	Name string `json:"name" toml:"name"`

	// Type is the dependency type.
	Type DependencyType `json:"type" toml:"type"`

	// Address is the network address (for TCP/gRPC).
	Address string `json:"address" toml:"address"`

	// Path is the file/directory path.
	Path string `json:"path" toml:"path"`

	// Timeout is the check timeout.
	Timeout time.Duration `json:"timeout" toml:"timeout"`

	// Critical marks this as a critical dependency.
	Critical bool `json:"critical" toml:"critical"`

	// Optional marks this dependency as optional (won't affect overall status).
	Optional bool `json:"optional" toml:"optional"`
}

// ============================================================================
// Dependency Checker
// ============================================================================

// DependencyChecker checks external dependencies.
type DependencyChecker struct {
	configs  []DependencyConfig
	checkers map[string]func(ctx context.Context, cfg DependencyConfig) CheckResult
	mu       sync.RWMutex
}

// NewDependencyChecker creates a new dependency checker.
func NewDependencyChecker() *DependencyChecker {
	dc := &DependencyChecker{
		configs:  make([]DependencyConfig, 0),
		checkers: make(map[string]func(ctx context.Context, cfg DependencyConfig) CheckResult),
	}

	// Register default checkers
	dc.registerDefaultCheckers()

	return dc
}

// registerDefaultCheckers registers the built-in checkers.
func (dc *DependencyChecker) registerDefaultCheckers() {
	dc.checkers["tcp"] = dc.checkTCP
	dc.checkers["grpc"] = dc.checkGRPC
	dc.checkers["file"] = dc.checkFile
	dc.checkers["directory"] = dc.checkDirectory
}

// AddDependency adds a dependency to check.
func (dc *DependencyChecker) AddDependency(cfg DependencyConfig) {
	dc.mu.Lock()
	defer dc.mu.Unlock()

	// Set default timeout
	if cfg.Timeout <= 0 {
		cfg.Timeout = 5 * time.Second
	}

	dc.configs = append(dc.configs, cfg)
}

// AddTCP adds a TCP dependency.
func (dc *DependencyChecker) AddTCP(name, address string, critical bool) {
	dc.AddDependency(DependencyConfig{
		Name:     name,
		Type:     DependencyTypeTCP,
		Address:  address,
		Timeout:  5 * time.Second,
		Critical: critical,
	})
}

// AddFile adds a file dependency.
func (dc *DependencyChecker) AddFile(name, path string, critical bool) {
	dc.AddDependency(DependencyConfig{
		Name:     name,
		Type:     DependencyTypeFile,
		Path:     path,
		Timeout:  1 * time.Second,
		Critical: critical,
	})
}

// AddDirectory adds a directory dependency.
func (dc *DependencyChecker) AddDirectory(name, path string, critical bool) {
	dc.AddDependency(DependencyConfig{
		Name:     name,
		Type:     DependencyTypeDirectory,
		Path:     path,
		Timeout:  1 * time.Second,
		Critical: critical,
	})
}

// AddCustom adds a custom dependency check.
func (dc *DependencyChecker) AddCustom(name string, critical bool, checkFunc func(ctx context.Context) CheckResult) {
	dc.mu.Lock()
	defer dc.mu.Unlock()

	// Store custom checker
	dc.checkers[name] = func(ctx context.Context, cfg DependencyConfig) CheckResult {
		return checkFunc(ctx)
	}

	dc.configs = append(dc.configs, DependencyConfig{
		Name:     name,
		Type:     DependencyTypeCustom,
		Timeout:  5 * time.Second,
		Critical: critical,
	})
}

// ============================================================================
// Check Methods
// ============================================================================

// CheckAll checks all dependencies.
func (dc *DependencyChecker) CheckAll(ctx context.Context) []CheckResult {
	dc.mu.RLock()
	configs := make([]DependencyConfig, len(dc.configs))
	copy(configs, dc.configs)
	dc.mu.RUnlock()

	if len(configs) == 0 {
		return nil
	}

	return dc.checkParallel(ctx, configs)
}

// checkParallel checks all dependencies in parallel.
func (dc *DependencyChecker) checkParallel(ctx context.Context, configs []DependencyConfig) []CheckResult {
	results := make([]CheckResult, len(configs))
	var wg sync.WaitGroup

	for i, cfg := range configs {
		wg.Add(1)
		go func(idx int, config DependencyConfig) {
			defer wg.Done()

			// Create timeout context
			checkCtx, cancel := context.WithTimeout(ctx, config.Timeout)
			defer cancel()

			result := dc.checkDependency(checkCtx, config)
			results[idx] = result
		}(i, cfg)
	}

	wg.Wait()
	return results
}

// checkDependency checks a single dependency.
func (dc *DependencyChecker) checkDependency(ctx context.Context, cfg DependencyConfig) CheckResult {
	start := time.Now()

	// Find checker
	var checkerFunc func(ctx context.Context, cfg DependencyConfig) CheckResult
	var checkerKey string

	switch cfg.Type {
	case DependencyTypeTCP:
		checkerKey = "tcp"
	case DependencyTypeGRPC:
		checkerKey = "grpc"
	case DependencyTypeFile:
		checkerKey = "file"
	case DependencyTypeDirectory:
		checkerKey = "directory"
	case DependencyTypeCustom:
		checkerKey = cfg.Name
	default:
		return Unhealthy(fmt.Sprintf("Unknown dependency type: %v", cfg.Type))
	}

	dc.mu.RLock()
	checkerFunc = dc.checkers[checkerKey]
	dc.mu.RUnlock()

	if checkerFunc == nil {
		return Unhealthy(fmt.Sprintf("No checker for dependency: %s", cfg.Name))
	}

	// Run check
	result := checkerFunc(ctx, cfg)
	result.Latency = time.Since(start)
	result.LatencyMs = float64(result.Latency.Microseconds()) / 1000.0
	result.Timestamp = time.Now()

	// Add dependency info
	result = result.WithDetails("dependency", cfg.Name)
	result = result.WithDetails("type", cfg.Type.String())

	return result
}

// ============================================================================
// Built-in Checkers
// ============================================================================

// checkTCP checks TCP connectivity.
func (dc *DependencyChecker) checkTCP(ctx context.Context, cfg DependencyConfig) CheckResult {
	if cfg.Address == "" {
		return Unhealthy("TCP address not configured")
	}

	// Use dialer with context timeout
	dialer := &net.Dialer{
		Timeout: cfg.Timeout,
	}

	conn, err := dialer.DialContext(ctx, "tcp", cfg.Address)
	if err != nil {
		return Unhealthy(fmt.Sprintf("TCP connection failed: %v", err))
	}
	defer conn.Close()

	return Healthy(fmt.Sprintf("TCP connected to %s", cfg.Address))
}

// checkGRPC checks gRPC connectivity (same as TCP for basic check).
func (dc *DependencyChecker) checkGRPC(ctx context.Context, cfg DependencyConfig) CheckResult {
	if cfg.Address == "" {
		return Unhealthy("gRPC address not configured")
	}

	// Basic TCP check (full gRPC health check would require client)
	dialer := &net.Dialer{
		Timeout: cfg.Timeout,
	}

	conn, err := dialer.DialContext(ctx, "tcp", cfg.Address)
	if err != nil {
		return Unhealthy(fmt.Sprintf("gRPC connection failed: %v", err))
	}
	defer conn.Close()

	return Healthy(fmt.Sprintf("gRPC reachable at %s", cfg.Address))
}

// checkFile checks if a file exists and is readable.
func (dc *DependencyChecker) checkFile(ctx context.Context, cfg DependencyConfig) CheckResult {
	if cfg.Path == "" {
		return Unhealthy("File path not configured")
	}

	info, err := os.Stat(cfg.Path)
	if err != nil {
		if os.IsNotExist(err) {
			return Unhealthy(fmt.Sprintf("File not found: %s", cfg.Path))
		}
		return Unhealthy(fmt.Sprintf("File access error: %v", err))
	}

	if info.IsDir() {
		return Unhealthy(fmt.Sprintf("Path is a directory, not a file: %s", cfg.Path))
	}

	// Try to open file to check readability
	f, err := os.Open(cfg.Path)
	if err != nil {
		return Unhealthy(fmt.Sprintf("File not readable: %v", err))
	}
	f.Close()

	return Healthy(fmt.Sprintf("File accessible: %s", cfg.Path)).
		WithDetails("size", info.Size()).
		WithDetails("modified", info.ModTime().Format(time.RFC3339))
}

// checkDirectory checks if a directory exists and is accessible.
func (dc *DependencyChecker) checkDirectory(ctx context.Context, cfg DependencyConfig) CheckResult {
	if cfg.Path == "" {
		return Unhealthy("Directory path not configured")
	}

	info, err := os.Stat(cfg.Path)
	if err != nil {
		if os.IsNotExist(err) {
			return Unhealthy(fmt.Sprintf("Directory not found: %s", cfg.Path))
		}
		return Unhealthy(fmt.Sprintf("Directory access error: %v", err))
	}

	if !info.IsDir() {
		return Unhealthy(fmt.Sprintf("Path is a file, not a directory: %s", cfg.Path))
	}

	return Healthy(fmt.Sprintf("Directory accessible: %s", cfg.Path))
}

// ============================================================================
// As Health Checker (implements Checker interface)
// ============================================================================

// DependencyHealthChecker wraps DependencyChecker as a Checker.
type DependencyHealthChecker struct {
	*BaseChecker
	depChecker *DependencyChecker
}

// NewDependencyHealthChecker creates a health checker for dependencies.
func NewDependencyHealthChecker(depChecker *DependencyChecker) *DependencyHealthChecker {
	c := &DependencyHealthChecker{
		depChecker: depChecker,
	}

	c.BaseChecker = NewBaseChecker("dependencies", true, c.check)
	return c
}

func (c *DependencyHealthChecker) check(ctx context.Context) CheckResult {
	if c.depChecker == nil {
		return Healthy("No dependencies configured")
	}

	results := c.depChecker.CheckAll(ctx)
	if len(results) == 0 {
		return Healthy("No dependencies configured")
	}

	// Check for failures
	unhealthyCount := 0
	degradedCount := 0
	var messages []string

	for _, result := range results {
		switch result.Status {
		case StatusUnhealthy:
			unhealthyCount++
			messages = append(messages, result.Message)
		case StatusDegraded:
			degradedCount++
		}
	}

	if unhealthyCount > 0 {
		return Unhealthy(fmt.Sprintf("%d dependencies unhealthy", unhealthyCount)).
			WithDetails("unhealthy_count", unhealthyCount).
			WithDetails("degraded_count", degradedCount)
	}

	if degradedCount > 0 {
		return Degraded(fmt.Sprintf("%d dependencies degraded", degradedCount))
	}

	return Healthy(fmt.Sprintf("All %d dependencies healthy", len(results)))
}

// ============================================================================
// Quick Setup
// ============================================================================

// SetupDefaultDependencies creates a dependency checker with common dependencies.
func SetupDefaultDependencies() *DependencyChecker {
	dc := NewDependencyChecker()

	// SafeOps Engine (gRPC)
	dc.AddTCP("safeops_engine", "127.0.0.1:50053", true)

	return dc
}
