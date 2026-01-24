// Package health provides health monitoring for the firewall engine.
package health

import (
	"context"
	"fmt"
	"runtime"
	"sync"
	"time"
)

// ============================================================================
// Component Names
// ============================================================================

const (
	// ComponentSafeOps is the SafeOps client component.
	ComponentSafeOps = "safeops"

	// ComponentWFP is the Windows Filtering Platform component.
	ComponentWFP = "wfp"

	// ComponentRules is the rule manager component.
	ComponentRules = "rules"

	// ComponentCache is the verdict cache component.
	ComponentCache = "cache"

	// ComponentProcess is the process health component.
	ComponentProcess = "process"

	// ComponentDualEngine is the dual engine coordinator.
	ComponentDualEngine = "dual_engine"
)

// ============================================================================
// SafeOps Client Checker
// ============================================================================

// SafeOpsClientInfo provides SafeOps client status information.
type SafeOpsClientInfo interface {
	IsConnected() bool
	GetLastPacketTime() time.Time
	GetConnectionState() string
}

// SafeOpsChecker checks the health of the SafeOps client connection.
type SafeOpsChecker struct {
	*BaseChecker
	client       SafeOpsClientInfo
	staleTimeout time.Duration
}

// NewSafeOpsChecker creates a new SafeOps client health checker.
func NewSafeOpsChecker(client SafeOpsClientInfo) *SafeOpsChecker {
	c := &SafeOpsChecker{
		client:       client,
		staleTimeout: 5 * time.Second,
	}

	c.BaseChecker = NewBaseChecker(ComponentSafeOps, true, c.check)
	return c
}

// SetStaleTimeout sets the timeout for considering the connection stale.
func (c *SafeOpsChecker) SetStaleTimeout(d time.Duration) {
	c.staleTimeout = d
}

func (c *SafeOpsChecker) check(ctx context.Context) CheckResult {
	if c.client == nil {
		return Unhealthy("SafeOps client not configured")
	}

	// Check connection state
	if !c.client.IsConnected() {
		state := c.client.GetConnectionState()
		return Unhealthy(fmt.Sprintf("SafeOps disconnected (state: %s)", state))
	}

	// Check for stale connection
	lastPacket := c.client.GetLastPacketTime()
	if !lastPacket.IsZero() && time.Since(lastPacket) > c.staleTimeout {
		return Degraded(fmt.Sprintf("SafeOps stream stale (last packet: %s ago)",
			time.Since(lastPacket).Round(time.Second)))
	}

	return Healthy("SafeOps connected")
}

// ============================================================================
// WFP Engine Checker
// ============================================================================

// WFPEngineInfo provides WFP engine status information.
type WFPEngineInfo interface {
	IsOpen() bool
	GetFilterCount() int
	GetErrorCount() int64
}

// WFPChecker checks the health of the WFP engine.
type WFPChecker struct {
	*BaseChecker
	engine              WFPEngineInfo
	expectedFilterCount int
	errorThreshold      int64
}

// NewWFPChecker creates a new WFP engine health checker.
func NewWFPChecker(engine WFPEngineInfo) *WFPChecker {
	c := &WFPChecker{
		engine:              engine,
		expectedFilterCount: 0, // Will be set after initialization
		errorThreshold:      10,
	}

	c.BaseChecker = NewBaseChecker(ComponentWFP, true, c.check)
	return c
}

// SetExpectedFilterCount sets the expected number of WFP filters.
func (c *WFPChecker) SetExpectedFilterCount(count int) {
	c.expectedFilterCount = count
}

// SetErrorThreshold sets the error threshold for degraded status.
func (c *WFPChecker) SetErrorThreshold(threshold int64) {
	c.errorThreshold = threshold
}

func (c *WFPChecker) check(ctx context.Context) CheckResult {
	if c.engine == nil {
		return Unhealthy("WFP engine not configured")
	}

	// Check if WFP session is open
	if !c.engine.IsOpen() {
		return Unhealthy("WFP session not open")
	}

	// Check filter count
	filterCount := c.engine.GetFilterCount()
	if filterCount == 0 {
		return Unhealthy("No WFP filters installed")
	}

	// Check for filter count mismatch (if expected is set)
	if c.expectedFilterCount > 0 && filterCount != c.expectedFilterCount {
		return Degraded(fmt.Sprintf("WFP filter mismatch (expected: %d, actual: %d)",
			c.expectedFilterCount, filterCount))
	}

	// Check error rate
	errorCount := c.engine.GetErrorCount()
	if errorCount > c.errorThreshold {
		return Degraded(fmt.Sprintf("WFP experiencing errors (count: %d)", errorCount))
	}

	return Healthy(fmt.Sprintf("WFP active (%d filters)", filterCount))
}

// ============================================================================
// Rules Manager Checker
// ============================================================================

// RulesManagerInfo provides rule manager status information.
type RulesManagerInfo interface {
	GetRuleCount() int
	HasErrors() bool
	GetLastLoadTime() time.Time
}

// RulesChecker checks the health of the rule manager.
type RulesChecker struct {
	*BaseChecker
	manager RulesManagerInfo
}

// NewRulesChecker creates a new rule manager health checker.
func NewRulesChecker(manager RulesManagerInfo) *RulesChecker {
	c := &RulesChecker{
		manager: manager,
	}

	c.BaseChecker = NewBaseChecker(ComponentRules, true, c.check)
	return c
}

func (c *RulesChecker) check(ctx context.Context) CheckResult {
	if c.manager == nil {
		return Unhealthy("Rule manager not configured")
	}

	// Check rule count
	ruleCount := c.manager.GetRuleCount()
	if ruleCount == 0 {
		return Unhealthy("No rules loaded")
	}

	// Check for parse errors
	if c.manager.HasErrors() {
		return Degraded(fmt.Sprintf("Rule parse errors present (%d rules loaded)", ruleCount))
	}

	lastLoad := c.manager.GetLastLoadTime()
	result := Healthy(fmt.Sprintf("%d rules loaded", ruleCount))

	if !lastLoad.IsZero() {
		result = result.WithDetails("last_load", lastLoad.Format(time.RFC3339))
	}

	return result
}

// ============================================================================
// Verdict Cache Checker
// ============================================================================

// VerdictCacheInfo provides verdict cache status information.
type VerdictCacheInfo interface {
	GetSize() int
	GetCapacity() int
	GetHitRate() float64
}

// CacheChecker checks the health of the verdict cache.
type CacheChecker struct {
	*BaseChecker
	cache            VerdictCacheInfo
	hitRateThreshold float64
}

// NewCacheChecker creates a new verdict cache health checker.
func NewCacheChecker(cache VerdictCacheInfo) *CacheChecker {
	c := &CacheChecker{
		cache:            cache,
		hitRateThreshold: 0.90, // 90% hit rate threshold
	}

	c.BaseChecker = NewBaseChecker(ComponentCache, false, c.check)
	return c
}

// SetHitRateThreshold sets the minimum acceptable hit rate.
func (c *CacheChecker) SetHitRateThreshold(threshold float64) {
	c.hitRateThreshold = threshold
}

func (c *CacheChecker) check(ctx context.Context) CheckResult {
	if c.cache == nil {
		return Unhealthy("Verdict cache not configured")
	}

	size := c.cache.GetSize()
	capacity := c.cache.GetCapacity()
	hitRate := c.cache.GetHitRate()

	// Check if cache is at capacity
	if capacity > 0 && size >= capacity {
		return Degraded(fmt.Sprintf("Cache at capacity (%d/%d)", size, capacity))
	}

	// Check hit rate
	if hitRate < c.hitRateThreshold && size > 100 { // Only check if cache has data
		return Degraded(fmt.Sprintf("Low cache hit rate: %.1f%%", hitRate*100))
	}

	return Healthy(fmt.Sprintf("Cache operational (%.1f%% hit rate, %d entries)", hitRate*100, size))
}

// ============================================================================
// Process Health Checker
// ============================================================================

// ProcessChecker checks the health of the firewall process.
type ProcessChecker struct {
	*BaseChecker
	maxMemoryMB        int64
	maxGoroutines      int
	lastGoroutineCount int
	mu                 sync.Mutex
}

// NewProcessChecker creates a new process health checker.
func NewProcessChecker() *ProcessChecker {
	c := &ProcessChecker{
		maxMemoryMB:   1024, // 1GB default
		maxGoroutines: 10000,
	}

	c.BaseChecker = NewBaseChecker(ComponentProcess, false, c.check)
	return c
}

// SetMaxMemoryMB sets the maximum memory threshold in MB.
func (c *ProcessChecker) SetMaxMemoryMB(mb int64) {
	c.maxMemoryMB = mb
}

// SetMaxGoroutines sets the maximum goroutine threshold.
func (c *ProcessChecker) SetMaxGoroutines(count int) {
	c.maxGoroutines = count
}

func (c *ProcessChecker) check(ctx context.Context) CheckResult {
	var memStats runtime.MemStats
	runtime.ReadMemStats(&memStats)

	allocMB := int64(memStats.Alloc / 1024 / 1024)
	goroutines := runtime.NumGoroutine()

	c.mu.Lock()
	lastCount := c.lastGoroutineCount
	c.lastGoroutineCount = goroutines
	c.mu.Unlock()

	// Check memory usage
	if allocMB > c.maxMemoryMB {
		return Unhealthy(fmt.Sprintf("High memory usage: %dMB (limit: %dMB)", allocMB, c.maxMemoryMB))
	}

	// Check for goroutine leak (significant increase)
	if lastCount > 0 && goroutines > lastCount*2 && goroutines > 1000 {
		return Degraded(fmt.Sprintf("Possible goroutine leak: %d (was: %d)", goroutines, lastCount))
	}

	// Check goroutine count
	if goroutines > c.maxGoroutines {
		return Degraded(fmt.Sprintf("High goroutine count: %d", goroutines))
	}

	return Healthy(fmt.Sprintf("Process healthy (mem: %dMB, goroutines: %d)", allocMB, goroutines)).
		WithDetails("memory_mb", allocMB).
		WithDetails("goroutines", goroutines)
}

// ============================================================================
// Dual Engine Checker
// ============================================================================

// DualEngineInfo provides dual engine coordinator status.
type DualEngineInfo interface {
	GetMode() string
	IsPrimaryHealthy() bool
	IsSecondaryHealthy() bool
}

// DualEngineChecker checks the health of the dual engine coordinator.
type DualEngineChecker struct {
	*BaseChecker
	coordinator DualEngineInfo
}

// NewDualEngineChecker creates a new dual engine health checker.
func NewDualEngineChecker(coordinator DualEngineInfo) *DualEngineChecker {
	c := &DualEngineChecker{
		coordinator: coordinator,
	}

	c.BaseChecker = NewBaseChecker(ComponentDualEngine, true, c.check)
	return c
}

func (c *DualEngineChecker) check(ctx context.Context) CheckResult {
	if c.coordinator == nil {
		return Unhealthy("Dual engine coordinator not configured")
	}

	mode := c.coordinator.GetMode()
	primaryOK := c.coordinator.IsPrimaryHealthy()
	secondaryOK := c.coordinator.IsSecondaryHealthy()

	// Both healthy
	if primaryOK && secondaryOK {
		return Healthy(fmt.Sprintf("Dual engine (%s mode): both engines healthy", mode))
	}

	// Only primary healthy
	if primaryOK && !secondaryOK {
		return Degraded(fmt.Sprintf("Dual engine (%s mode): secondary unhealthy", mode))
	}

	// Only secondary healthy
	if !primaryOK && secondaryOK {
		return Degraded(fmt.Sprintf("Dual engine (%s mode): primary unhealthy", mode))
	}

	// Both unhealthy
	return Unhealthy(fmt.Sprintf("Dual engine (%s mode): both engines unhealthy", mode))
}

// ============================================================================
// Generic Func Checker
// ============================================================================

// FuncChecker is a checker that uses a function to perform the check.
type FuncChecker struct {
	*BaseChecker
}

// NewFuncChecker creates a new function-based health checker.
func NewFuncChecker(name string, critical bool, checkFunc func(ctx context.Context) CheckResult) *FuncChecker {
	return &FuncChecker{
		BaseChecker: NewBaseChecker(name, critical, checkFunc),
	}
}

// ============================================================================
// Always Healthy Checker (for testing)
// ============================================================================

// AlwaysHealthyChecker always returns healthy status.
type AlwaysHealthyChecker struct {
	*BaseChecker
}

// NewAlwaysHealthyChecker creates a checker that always returns healthy.
func NewAlwaysHealthyChecker(name string) *AlwaysHealthyChecker {
	return &AlwaysHealthyChecker{
		BaseChecker: NewBaseChecker(name, false, func(ctx context.Context) CheckResult {
			return Healthy("OK")
		}),
	}
}
