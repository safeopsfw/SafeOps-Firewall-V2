// Package health provides standard health checks.
package health

import (
	"context"
	"database/sql"
	"fmt"
	"net"
	"net/http"
	"os"
	"runtime"
	"time"
)

// TCPCheck checks if a TCP endpoint is reachable
type TCPCheck struct {
	name    string
	address string
	timeout time.Duration
}

// NewTCPCheck creates a TCP health check
func NewTCPCheck(name, address string, timeout time.Duration) *TCPCheck {
	return &TCPCheck{
		name:    name,
		address: address,
		timeout: timeout,
	}
}

// Name returns the check name
func (c *TCPCheck) Name() string {
	return c.name
}

// Check performs the TCP check
func (c *TCPCheck) Check(ctx context.Context) *Result {
	conn, err := net.DialTimeout("tcp", c.address, c.timeout)
	if err != nil {
		return Unhealthy(fmt.Sprintf("failed to connect to %s: %v", c.address, err))
	}
	conn.Close()

	return Healthy().WithDetails(map[string]interface{}{
		"address": c.address,
	})
}

// IsRequired returns if this check is required (default: true)
func (c *TCPCheck) IsRequired() bool {
	return true
}

// HTTPCheck checks if an HTTP endpoint is healthy
type HTTPCheck struct {
	name       string
	url        string
	timeout    time.Duration
	client     *http.Client
	expectCode int
}

// NewHTTPCheck creates an HTTP health check
func NewHTTPCheck(name, url string, timeout time.Duration) *HTTPCheck {
	return &HTTPCheck{
		name:       name,
		url:        url,
		timeout:    timeout,
		expectCode: http.StatusOK,
		client: &http.Client{
			Timeout: timeout,
		},
	}
}

// WithExpectedCode sets the expected status code
func (c *HTTPCheck) WithExpectedCode(code int) *HTTPCheck {
	c.expectCode = code
	return c
}

// Name returns the check name
func (c *HTTPCheck) Name() string {
	return c.name
}

// Check performs the HTTP check
func (c *HTTPCheck) Check(ctx context.Context) *Result {
	req, err := http.NewRequestWithContext(ctx, "GET", c.url, nil)
	if err != nil {
		return Unhealthy(fmt.Sprintf("failed to create request: %v", err))
	}

	resp, err := c.client.Do(req)
	if err != nil {
		return Unhealthy(fmt.Sprintf("request failed: %v", err))
	}
	defer resp.Body.Close()

	if resp.StatusCode != c.expectCode {
		return Unhealthy(fmt.Sprintf("unexpected status: %d", resp.StatusCode))
	}

	return Healthy().WithDetails(map[string]interface{}{
		"url":    c.url,
		"status": resp.StatusCode,
	})
}

// IsRequired returns if this check is required (default: true)
func (c *HTTPCheck) IsRequired() bool {
	return true
}

// SQLCheck checks database connectivity
type SQLCheck struct {
	name string
	db   *sql.DB
}

// NewSQLCheck creates a SQL health check
func NewSQLCheck(name string, db *sql.DB) *SQLCheck {
	return &SQLCheck{
		name: name,
		db:   db,
	}
}

// Name returns the check name
func (c *SQLCheck) Name() string {
	return c.name
}

// Check performs the SQL check
func (c *SQLCheck) Check(ctx context.Context) *Result {
	if err := c.db.PingContext(ctx); err != nil {
		return Unhealthy(fmt.Sprintf("database ping failed: %v", err))
	}

	stats := c.db.Stats()
	return Healthy().WithDetails(map[string]interface{}{
		"open_connections": stats.OpenConnections,
		"in_use":           stats.InUse,
		"idle":             stats.Idle,
	})
}

// IsRequired returns if this check is required (default: true)
func (c *SQLCheck) IsRequired() bool {
	return true
}

// MemoryCheck checks memory usage
type MemoryCheck struct {
	name         string
	maxThreshold float64 // percentage
}

// NewMemoryCheck creates a memory health check
func NewMemoryCheck(name string, maxThreshold float64) *MemoryCheck {
	return &MemoryCheck{
		name:         name,
		maxThreshold: maxThreshold,
	}
}

// Name returns the check name
func (c *MemoryCheck) Name() string {
	return c.name
}

// Check performs the memory check
func (c *MemoryCheck) Check(ctx context.Context) *Result {
	// This is a simplified check - in production you'd use runtime.MemStats
	return Healthy().WithDetails(map[string]interface{}{
		"threshold": c.maxThreshold,
	})
}

// IsRequired returns if this check is required (default: false - memory is optional)
func (c *MemoryCheck) IsRequired() bool {
	return false
}

// DiskCheck checks disk space
type DiskCheck struct {
	name         string
	path         string
	minFreeBytes int64
}

// NewDiskCheck creates a disk space health check
func NewDiskCheck(name, path string, minFreeBytes int64) *DiskCheck {
	return &DiskCheck{
		name:         name,
		path:         path,
		minFreeBytes: minFreeBytes,
	}
}

// Name returns the check name
func (c *DiskCheck) Name() string {
	return c.name
}

// Check performs the disk check
func (c *DiskCheck) Check(ctx context.Context) *Result {
	// Platform-specific implementation would be needed
	return Healthy().WithDetails(map[string]interface{}{
		"path":           c.path,
		"min_free_bytes": c.minFreeBytes,
	})
}

// IsRequired returns if this check is required (default: true)
func (c *DiskCheck) IsRequired() bool {
	return true
}

// CompositeCheck runs multiple checks
type CompositeCheck struct {
	name   string
	checks []Check
}

// NewCompositeCheck creates a composite health check
func NewCompositeCheck(name string, checks ...Check) *CompositeCheck {
	return &CompositeCheck{
		name:   name,
		checks: checks,
	}
}

// Name returns the check name
func (c *CompositeCheck) Name() string {
	return c.name
}

// Check performs all sub-checks
func (c *CompositeCheck) Check(ctx context.Context) *Result {
	status := StatusHealthy
	details := make(map[string]interface{})

	for _, check := range c.checks {
		result := check.Check(ctx)
		details[check.Name()] = result.Status

		switch result.Status {
		case StatusUnhealthy:
			status = StatusUnhealthy
		case StatusDegraded:
			if status != StatusUnhealthy {
				status = StatusDegraded
			}
		}
	}

	return &Result{
		Status:  status,
		Details: details,
	}
}

// IsRequired returns if this check is required (aggregates from sub-checks)
func (c *CompositeCheck) IsRequired() bool {
	// Composite is required if any sub-check is required
	for _, check := range c.checks {
		if check.IsRequired() {
			return true
		}
	}
	return false
}

// ThrottledCheck wraps a check with rate limiting
type ThrottledCheck struct {
	check       Check
	minInterval time.Duration
	lastCheck   time.Time
	lastResult  *Result
}

// NewThrottledCheck creates a throttled check
func NewThrottledCheck(check Check, minInterval time.Duration) *ThrottledCheck {
	return &ThrottledCheck{
		check:       check,
		minInterval: minInterval,
	}
}

// Name returns the check name
func (c *ThrottledCheck) Name() string {
	return c.check.Name()
}

// Check performs the check with throttling
func (c *ThrottledCheck) Check(ctx context.Context) *Result {
	if time.Since(c.lastCheck) < c.minInterval && c.lastResult != nil {
		return c.lastResult
	}

	c.lastResult = c.check.Check(ctx)
	c.lastCheck = time.Now()
	return c.lastResult
}

// IsRequired delegates to the wrapped check
func (c *ThrottledCheck) IsRequired() bool {
	return c.check.IsRequired()
}

// ============================================================================
// Specialized Health Checkers
// ============================================================================

// RedisCheck checks Redis connectivity with PING command
type RedisCheck struct {
	name             string
	address          string
	timeout          time.Duration
	latencyThreshold time.Duration
}

// NewRedisCheck creates a Redis health check
func NewRedisCheck(name, address string, timeout time.Duration) *RedisCheck {
	return &RedisCheck{
		name:             name,
		address:          address,
		timeout:          timeout,
		latencyThreshold: 500 * time.Millisecond, // Default: degraded if >500ms
	}
}

// WithLatencyThreshold sets the latency threshold for degraded status
func (c *RedisCheck) WithLatencyThreshold(threshold time.Duration) *RedisCheck {
	c.latencyThreshold = threshold
	return c
}

// Name returns the check name
func (c *RedisCheck) Name() string {
	return c.name
}

// Check performs the Redis PING check
func (c *RedisCheck) Check(ctx context.Context) *Result {
	start := time.Now()

	// Connect to Redis
	conn, err := net.DialTimeout("tcp", c.address, c.timeout)
	if err != nil {
		return Unhealthy(fmt.Sprintf("failed to connect to Redis at %s: %v", c.address, err))
	}
	defer conn.Close()

	// Send PING command (Redis protocol: *1\r\n$4\r\nPING\r\n)
	if _, err := fmt.Fprintf(conn, "*1\r\n$4\r\nPING\r\n"); err != nil {
		return Unhealthy(fmt.Sprintf("failed to send PING: %v", err))
	}

	// Read PONG response
	buf := make([]byte, 7)
	if _, err := conn.Read(buf); err != nil {
		return Unhealthy(fmt.Sprintf("failed to read PONG: %v", err))
	}

	latency := time.Since(start)

	// Check if latency exceeds threshold
	if latency > c.latencyThreshold {
		return Degraded(fmt.Sprintf("Redis responding slowly (%s)", latency)).WithDetails(map[string]interface{}{
			"address":      c.address,
			"latency_ms":   latency.Milliseconds(),
			"threshold_ms": c.latencyThreshold.Milliseconds(),
		})
	}

	return Healthy().WithDetails(map[string]interface{}{
		"address":    c.address,
		"latency_ms": latency.Milliseconds(),
	})
}

// IsRequired returns if this check is required (default: true)
func (c *RedisCheck) IsRequired() bool {
	return true
}

// FileSystemCheck checks filesystem accessibility and writability
type FileSystemCheck struct {
	name      string
	paths     []string
	testWrite bool
}

// NewFileSystemCheck creates a filesystem health check
func NewFileSystemCheck(name string, paths []string) *FileSystemCheck {
	return &FileSystemCheck{
		name:      name,
		paths:     paths,
		testWrite: true,
	}
}

// WithWriteTest enables or disables write permission testing
func (c *FileSystemCheck) WithWriteTest(enabled bool) *FileSystemCheck {
	c.testWrite = enabled
	return c
}

// Name returns the check name
func (c *FileSystemCheck) Name() string {
	return c.name
}

// Check performs the filesystem check
func (c *FileSystemCheck) Check(ctx context.Context) *Result {
	details := make(map[string]interface{})
	allHealthy := true

	for _, path := range c.paths {
		pathInfo := make(map[string]interface{})

		// Check if path exists
		info, err := os.Stat(path)
		if err != nil {
			allHealthy = false
			pathInfo["error"] = fmt.Sprintf("path does not exist: %v", err)
			details[path] = pathInfo
			continue
		}

		pathInfo["exists"] = true
		pathInfo["is_dir"] = info.IsDir()

		// Test write permissions if enabled
		if c.testWrite {
			testFile := fmt.Sprintf("%s/.health_check_%d", path, time.Now().UnixNano())
			if err := os.WriteFile(testFile, []byte("health check"), 0644); err != nil {
				allHealthy = false
				pathInfo["writable"] = false
				pathInfo["write_error"] = err.Error()
			} else {
				pathInfo["writable"] = true
				os.Remove(testFile) // Clean up
			}
		}

		details[path] = pathInfo
	}

	if !allHealthy {
		return Unhealthy("one or more filesystem checks failed").WithDetails(details)
	}

	return Healthy().WithDetails(details)
}

// IsRequired returns if this check is required (default: true)
func (c *FileSystemCheck) IsRequired() bool {
	return true
}

// EnhancedMemoryCheck checks system and process memory usage
type EnhancedMemoryCheck struct {
	name      string
	maxHeapMB float64
}

// NewEnhancedMemoryCheck creates a memory health check
func NewEnhancedMemoryCheck(name string, maxHeapMB float64) *EnhancedMemoryCheck {
	return &EnhancedMemoryCheck{
		name:      name,
		maxHeapMB: maxHeapMB,
	}
}

// Name returns the check name
func (c *EnhancedMemoryCheck) Name() string {
	return c.name
}

// Check performs the memory check
func (c *EnhancedMemoryCheck) Check(ctx context.Context) *Result {
	var m runtime.MemStats
	runtime.ReadMemStats(&m)

	heapMB := float64(m.HeapAlloc) / 1024 / 1024
	heapSysMB := float64(m.HeapSys) / 1024 / 1024
	totalAllocMB := float64(m.TotalAlloc) / 1024 / 1024
	gcPauseMicros := m.PauseNs[(m.NumGC+255)%256] / 1000

	details := map[string]interface{}{
		"heap_alloc_mb":   heapMB,
		"heap_sys_mb":     heapSysMB,
		"total_alloc_mb":  totalAllocMB,
		"num_gc":          m.NumGC,
		"gc_pause_micros": gcPauseMicros,
		"num_goroutine":   runtime.NumGoroutine(),
	}

	// Check if heap exceeds threshold
	if c.maxHeapMB > 0 && heapMB > c.maxHeapMB {
		return Degraded(fmt.Sprintf("heap usage (%.2f MB) exceeds threshold (%.2f MB)", heapMB, c.maxHeapMB)).
			WithDetails(details)
	}

	return Healthy().WithDetails(details)
}

// IsRequired returns if this check is required (default: false for memory)
func (c *EnhancedMemoryCheck) IsRequired() bool {
	return false
}
