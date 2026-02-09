package security

import (
	"fmt"
	"math"
	"sync"
	"sync/atomic"
	"time"

	"firewall_engine/internal/alerting"
	"firewall_engine/internal/config"
)

// TrafficBaseline tracks per-minute traffic using an exponential moving average (EMA).
// When current traffic deviates significantly from the baseline, an alert is fired.
// Separate baselines are maintained for total traffic, per-protocol, and top ports.
type TrafficBaseline struct {
	cfg      config.BaselineConfig
	alertMgr *alerting.Manager

	// Total traffic baseline
	totalEMA     float64
	totalEMAVar  float64 // EMA of squared deviations (for stddev)
	totalMu      sync.Mutex

	// Per-protocol baselines: "TCP", "UDP", "ICMP" -> *emaTracker
	protocolEMAs sync.Map

	// Current minute counters (atomics for lock-free hot path)
	currentTotal  atomic.Int64
	currentTCP    atomic.Int64
	currentUDP    atomic.Int64
	currentICMP   atomic.Int64
	currentMinute atomic.Int64

	warmupUntil  int64 // unix timestamp when warmup ends
	deviations   atomic.Int64

	cancel chan struct{}
	wg     sync.WaitGroup
}

// emaTracker holds EMA state for a single metric
type emaTracker struct {
	mu      sync.Mutex
	ema     float64
	emaVar  float64
	samples int64
}

// BaselineStats holds baseline statistics
type BaselineStats struct {
	TotalEMA        float64 `json:"total_ema"`
	TotalStdDev     float64 `json:"total_stddev"`
	Deviations      int64   `json:"deviations"`
	IsWarmedUp      bool    `json:"is_warmed_up"`
	MinutesSampled  int64   `json:"minutes_sampled"`
}

// BaselineDeviation is returned when traffic deviates from baseline
type BaselineDeviation struct {
	Detected  bool
	Metric    string  // "total", "tcp", "udp", "icmp"
	Current   float64
	Baseline  float64
	StdDev    float64
	ZScore    float64 // how many stddevs from baseline
	Threshold float64
}

// NewTrafficBaseline creates a new traffic baseline tracker
func NewTrafficBaseline(cfg config.BaselineConfig, alertMgr *alerting.Manager) *TrafficBaseline {
	b := &TrafficBaseline{
		cfg:         cfg,
		alertMgr:    alertMgr,
		warmupUntil: time.Now().Unix() + int64(cfg.WarmupMinutes*60),
		cancel:      make(chan struct{}),
	}
	b.currentMinute.Store(time.Now().Unix() / 60)

	// Update goroutine
	interval := time.Duration(cfg.UpdateIntervalSeconds) * time.Second
	if interval < time.Second {
		interval = 10 * time.Second
	}

	b.wg.Add(1)
	go func() {
		defer b.wg.Done()
		b.updateLoop(interval)
	}()

	return b
}

// RecordPacket records a single packet for baseline tracking.
// This is the hot-path function — uses only atomic operations.
func (b *TrafficBaseline) RecordPacket(protocol string) {
	if !b.cfg.Enabled {
		return
	}

	b.currentTotal.Add(1)

	switch protocol {
	case "TCP":
		b.currentTCP.Add(1)
	case "UDP":
		b.currentUDP.Add(1)
	case "ICMP":
		b.currentICMP.Add(1)
	}
}

// CheckDeviation checks if current traffic rates deviate from baseline.
// Should be called periodically (e.g., every update interval), not per-packet.
func (b *TrafficBaseline) CheckDeviation() []BaselineDeviation {
	if !b.cfg.Enabled {
		return nil
	}

	// Don't check during warmup
	if time.Now().Unix() < b.warmupUntil {
		return nil
	}

	var results []BaselineDeviation

	// Check total traffic
	if dev := b.checkMetric("total", &b.totalEMA, &b.totalEMAVar, &b.totalMu); dev.Detected {
		results = append(results, dev)
	}

	// Check per-protocol
	for _, proto := range []string{"TCP", "UDP", "ICMP"} {
		val, ok := b.protocolEMAs.Load(proto)
		if !ok {
			continue
		}
		tracker := val.(*emaTracker)
		currentVal := b.getProtocolCount(proto)
		if dev := b.checkEMATracker(proto, tracker, float64(currentVal)); dev.Detected {
			results = append(results, dev)
		}
	}

	return results
}

// Stats returns baseline statistics
func (b *TrafficBaseline) Stats() BaselineStats {
	b.totalMu.Lock()
	ema := b.totalEMA
	emaVar := b.totalEMAVar
	b.totalMu.Unlock()

	var minutesSampled int64
	b.protocolEMAs.Range(func(key, value interface{}) bool {
		tracker := value.(*emaTracker)
		tracker.mu.Lock()
		if tracker.samples > minutesSampled {
			minutesSampled = tracker.samples
		}
		tracker.mu.Unlock()
		return true
	})

	return BaselineStats{
		TotalEMA:       ema,
		TotalStdDev:    math.Sqrt(emaVar),
		Deviations:     b.deviations.Load(),
		IsWarmedUp:     time.Now().Unix() >= b.warmupUntil,
		MinutesSampled: minutesSampled,
	}
}

// Stop halts the update goroutine
func (b *TrafficBaseline) Stop() {
	close(b.cancel)
	b.wg.Wait()
}

func (b *TrafficBaseline) updateLoop(interval time.Duration) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	for {
		select {
		case <-b.cancel:
			return
		case <-ticker.C:
			b.updateBaselines()
		}
	}
}

// updateBaselines takes a snapshot of current counters and updates EMAs
func (b *TrafficBaseline) updateBaselines() {
	// Swap counters atomically
	total := float64(b.currentTotal.Swap(0))
	tcp := float64(b.currentTCP.Swap(0))
	udp := float64(b.currentUDP.Swap(0))
	icmp := float64(b.currentICMP.Swap(0))

	// EMA smoothing factor: alpha = 2 / (windowMinutes + 1)
	// Since we update every UpdateIntervalSeconds, we adjust:
	// effective_alpha = alpha * (UpdateIntervalSeconds / 60)
	windowSamples := float64(b.cfg.WindowMinutes) * 60.0 / float64(b.cfg.UpdateIntervalSeconds)
	alpha := 2.0 / (windowSamples + 1.0)

	// Update total EMA
	b.totalMu.Lock()
	b.totalEMA = emaUpdate(b.totalEMA, total, alpha)
	diff := total - b.totalEMA
	b.totalEMAVar = emaUpdate(b.totalEMAVar, diff*diff, alpha)
	b.totalMu.Unlock()

	// Update per-protocol EMAs
	b.updateProtocolEMA("TCP", tcp, alpha)
	b.updateProtocolEMA("UDP", udp, alpha)
	b.updateProtocolEMA("ICMP", icmp, alpha)
}

func (b *TrafficBaseline) updateProtocolEMA(protocol string, value float64, alpha float64) {
	val, _ := b.protocolEMAs.LoadOrStore(protocol, &emaTracker{})
	tracker := val.(*emaTracker)

	tracker.mu.Lock()
	tracker.ema = emaUpdate(tracker.ema, value, alpha)
	diff := value - tracker.ema
	tracker.emaVar = emaUpdate(tracker.emaVar, diff*diff, alpha)
	tracker.samples++
	tracker.mu.Unlock()
}

func (b *TrafficBaseline) checkMetric(name string, ema, emaVar *float64, mu *sync.Mutex) BaselineDeviation {
	mu.Lock()
	baselineVal := *ema
	varianceVal := *emaVar
	mu.Unlock()

	stddev := math.Sqrt(varianceVal)
	current := float64(b.currentTotal.Load())

	if baselineVal == 0 || stddev == 0 {
		return BaselineDeviation{}
	}

	zScore := (current - baselineVal) / stddev

	if math.Abs(zScore) >= b.cfg.DeviationThreshold {
		b.deviations.Add(1)
		dev := BaselineDeviation{
			Detected:  true,
			Metric:    name,
			Current:   current,
			Baseline:  baselineVal,
			StdDev:    stddev,
			ZScore:    zScore,
			Threshold: b.cfg.DeviationThreshold,
		}
		b.fireDeviationAlert(dev)
		return dev
	}

	return BaselineDeviation{}
}

func (b *TrafficBaseline) checkEMATracker(name string, tracker *emaTracker, current float64) BaselineDeviation {
	tracker.mu.Lock()
	baselineVal := tracker.ema
	varianceVal := tracker.emaVar
	tracker.mu.Unlock()

	stddev := math.Sqrt(varianceVal)

	if baselineVal == 0 || stddev == 0 {
		return BaselineDeviation{}
	}

	zScore := (current - baselineVal) / stddev

	if math.Abs(zScore) >= b.cfg.DeviationThreshold {
		b.deviations.Add(1)
		dev := BaselineDeviation{
			Detected:  true,
			Metric:    name,
			Current:   current,
			Baseline:  baselineVal,
			StdDev:    stddev,
			ZScore:    zScore,
			Threshold: b.cfg.DeviationThreshold,
		}
		b.fireDeviationAlert(dev)
		return dev
	}

	return BaselineDeviation{}
}

func (b *TrafficBaseline) getProtocolCount(protocol string) int64 {
	switch protocol {
	case "TCP":
		return b.currentTCP.Load()
	case "UDP":
		return b.currentUDP.Load()
	case "ICMP":
		return b.currentICMP.Load()
	default:
		return 0
	}
}

func (b *TrafficBaseline) fireDeviationAlert(dev BaselineDeviation) {
	if b.alertMgr == nil {
		return
	}

	severity := alerting.SeverityMedium
	if math.Abs(dev.ZScore) >= b.cfg.DeviationThreshold*2 {
		severity = alerting.SeverityHigh
	}

	direction := "spike"
	if dev.ZScore < 0 {
		direction = "drop"
	}

	alert := alerting.NewAlert(alerting.AlertAnomaly, severity).
		WithDetails(fmt.Sprintf("Traffic %s in %s: current=%.0f baseline=%.0f stddev=%.1f z-score=%.2f",
			direction, dev.Metric, dev.Current, dev.Baseline, dev.StdDev, dev.ZScore)).
		WithAction(alerting.ActionLogged).
		WithMeta("metric", dev.Metric).
		WithMeta("z_score", fmt.Sprintf("%.2f", dev.ZScore)).
		WithMeta("direction", direction).
		Build()

	b.alertMgr.Alert(alert)
}

// emaUpdate computes new EMA value: ema = alpha*value + (1-alpha)*ema
func emaUpdate(ema, value, alpha float64) float64 {
	if ema == 0 {
		return value // Initialize on first sample
	}
	return alpha*value + (1-alpha)*ema
}
