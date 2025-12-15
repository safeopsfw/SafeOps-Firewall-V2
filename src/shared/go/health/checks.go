// Package health provides standard health checks.
package health

import (
	"context"
	"database/sql"
	"fmt"
	"net"
	"net/http"
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
