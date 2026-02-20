package health

import (
	"context"
	"fmt"
	"runtime"
	"sync/atomic"
	"time"
)

// ============================================================================
// Memory Monitor
// ============================================================================

// MemoryMonitorConfig configures the memory monitor.
type MemoryMonitorConfig struct {
	// SoftLimitMB triggers a warning log when exceeded (default 512 MB).
	SoftLimitMB int64

	// HardLimitMB triggers GC + alert when exceeded (default 1024 MB).
	HardLimitMB int64

	// CheckInterval controls how often memory is sampled (default 30s).
	CheckInterval time.Duration
}

// DefaultMemoryMonitorConfig returns sane defaults.
func DefaultMemoryMonitorConfig() MemoryMonitorConfig {
	return MemoryMonitorConfig{
		SoftLimitMB:   512,
		HardLimitMB:   1024,
		CheckInterval: 30 * time.Second,
	}
}

// MemoryStats holds the most recently sampled memory statistics.
type MemoryStats struct {
	AllocMB      float64
	TotalAllocMB float64
	SysMB        float64
	GCCycles     uint32
	Goroutines   int
	SoftBreaches uint64
	HardBreaches uint64
}

// MemoryMonitor periodically samples runtime.MemStats and fires warnings or GC
// when configured thresholds are exceeded.
//
// OnSoftLimit and OnHardLimit are optional callbacks — set them from main.go
// to emit alerts or fire WebSocket events.
type MemoryMonitor struct {
	cfg MemoryMonitorConfig

	// Callbacks (may be nil)
	OnSoftLimit func(allocMB int64)
	OnHardLimit func(allocMB int64)

	// Counters
	softBreaches atomic.Uint64
	hardBreaches atomic.Uint64

	// Last snapshot (for status endpoint)
	lastStats atomic.Value // *MemoryStats
}

// NewMemoryMonitor creates a new memory monitor with the given config.
func NewMemoryMonitor(cfg MemoryMonitorConfig) *MemoryMonitor {
	return &MemoryMonitor{cfg: cfg}
}

// Run starts the memory monitoring loop. It blocks until ctx is cancelled.
func (m *MemoryMonitor) Run(ctx context.Context) {
	ticker := time.NewTicker(m.cfg.CheckInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			m.check()
		}
	}
}

// Stats returns the most recently sampled memory statistics.
func (m *MemoryMonitor) Stats() MemoryStats {
	if v := m.lastStats.Load(); v != nil {
		return *v.(*MemoryStats)
	}
	return MemoryStats{}
}

func (m *MemoryMonitor) check() {
	var ms runtime.MemStats
	runtime.ReadMemStats(&ms)

	allocMB := int64(ms.Alloc / 1024 / 1024)

	stats := &MemoryStats{
		AllocMB:      float64(ms.Alloc) / 1024 / 1024,
		TotalAllocMB: float64(ms.TotalAlloc) / 1024 / 1024,
		SysMB:        float64(ms.Sys) / 1024 / 1024,
		GCCycles:     ms.NumGC,
		Goroutines:   runtime.NumGoroutine(),
		SoftBreaches: m.softBreaches.Load(),
		HardBreaches: m.hardBreaches.Load(),
	}
	m.lastStats.Store(stats)

	if allocMB > m.cfg.HardLimitMB {
		m.hardBreaches.Add(1)
		stats.HardBreaches = m.hardBreaches.Load()
		// Force a GC cycle to reclaim memory
		runtime.GC()
		if m.OnHardLimit != nil {
			m.OnHardLimit(allocMB)
		}
	} else if allocMB > m.cfg.SoftLimitMB {
		m.softBreaches.Add(1)
		stats.SoftBreaches = m.softBreaches.Load()
		if m.OnSoftLimit != nil {
			m.OnSoftLimit(allocMB)
		}
	}
}

// ============================================================================
// Goroutine Monitor
// ============================================================================

// GoroutineMonitorConfig configures the goroutine leak detector.
type GoroutineMonitorConfig struct {
	// LeakThreshold fires an alert when goroutine count exceeds this value (default 10000).
	LeakThreshold int

	// DoubleThreshold fires a warning when count more than doubles between checks (default true).
	DoubleAlert bool

	// CheckInterval controls how often goroutines are counted (default 30s).
	CheckInterval time.Duration
}

// DefaultGoroutineMonitorConfig returns sane defaults.
func DefaultGoroutineMonitorConfig() GoroutineMonitorConfig {
	return GoroutineMonitorConfig{
		LeakThreshold: 10000,
		DoubleAlert:   true,
		CheckInterval: 30 * time.Second,
	}
}

// GoroutineMonitor periodically checks the goroutine count and fires warnings
// when a potential leak is detected.
type GoroutineMonitor struct {
	cfg GoroutineMonitorConfig

	// Callbacks (may be nil)
	OnLeak   func(count int, msg string)
	OnDouble func(count, prev int)

	lastCount int
}

// NewGoroutineMonitor creates a new goroutine monitor.
func NewGoroutineMonitor(cfg GoroutineMonitorConfig) *GoroutineMonitor {
	return &GoroutineMonitor{cfg: cfg}
}

// Run starts the goroutine monitoring loop. It blocks until ctx is cancelled.
func (g *GoroutineMonitor) Run(ctx context.Context) {
	ticker := time.NewTicker(g.cfg.CheckInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			g.check()
		}
	}
}

func (g *GoroutineMonitor) check() {
	count := runtime.NumGoroutine()

	if count > g.cfg.LeakThreshold {
		msg := fmt.Sprintf("GOROUTINE LEAK — count %d exceeds threshold %d", count, g.cfg.LeakThreshold)
		if g.OnLeak != nil {
			g.OnLeak(count, msg)
		}
	}

	if g.cfg.DoubleAlert && g.lastCount > 0 && count > g.lastCount*2 {
		if g.OnDouble != nil {
			g.OnDouble(count, g.lastCount)
		}
	}

	g.lastCount = count
}
