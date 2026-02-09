package security

import (
	"fmt"
	"sync"
	"sync/atomic"
	"time"

	"firewall_engine/internal/alerting"
	"firewall_engine/internal/config"
)

// BruteForceDetector tracks failed connection attempts per IP per service port.
// When failures exceed the service-specific threshold within the configured window,
// the IP is flagged for banning.
type BruteForceDetector struct {
	cfg      config.BruteForceConfig
	alertMgr *alerting.Manager

	// portMap maps port -> service config for fast lookup
	portMap map[int]config.BruteForceService
	// serviceNames maps port -> service name for alerts
	serviceNames map[int]string

	// trackers: "ip:port" -> *failureTracker
	trackers sync.Map

	detections atomic.Int64
	cancel     chan struct{}
	wg         sync.WaitGroup
}

// failureTracker uses a circular buffer of timestamps to count failures in a window
type failureTracker struct {
	mu        sync.Mutex
	failures  []int64 // unix timestamps of failures
	writeIdx  int
	ip        string
	port      int
	lastSeen  atomic.Int64
}

// BruteForceStats holds detection statistics
type BruteForceStats struct {
	Detections int64 `json:"detections"`
	TrackedIPs int64 `json:"tracked_ips"`
}

// BruteForceResult is returned when a brute force attack is detected
type BruteForceResult struct {
	Detected    bool
	ServiceName string
	Port        int
	Failures    int
	Threshold   int
	WindowSec   int
}

// NewBruteForceDetector creates a new brute force detector
func NewBruteForceDetector(cfg config.BruteForceConfig, alertMgr *alerting.Manager) *BruteForceDetector {
	d := &BruteForceDetector{
		cfg:          cfg,
		alertMgr:     alertMgr,
		portMap:      make(map[int]config.BruteForceService),
		serviceNames: make(map[int]string),
		cancel:       make(chan struct{}),
	}

	// Build port -> service lookup
	for name, svc := range cfg.Services {
		d.portMap[svc.Port] = svc
		d.serviceNames[svc.Port] = name
	}

	// Cleanup goroutine every 60s
	d.wg.Add(1)
	go func() {
		defer d.wg.Done()
		d.cleanupLoop()
	}()

	return d
}

// RecordFailure records a failed connection attempt to a service port.
// Returns a BruteForceResult indicating whether the threshold has been exceeded.
func (d *BruteForceDetector) RecordFailure(srcIP string, dstPort int) BruteForceResult {
	if !d.cfg.Enabled {
		return BruteForceResult{}
	}

	svc, monitored := d.portMap[dstPort]
	if !monitored {
		return BruteForceResult{}
	}

	serviceName := d.serviceNames[dstPort]
	key := fmt.Sprintf("%s:%d", srcIP, dstPort)
	now := time.Now().Unix()

	val, _ := d.trackers.LoadOrStore(key, &failureTracker{
		failures: make([]int64, 0, svc.MaxFailures+1),
		ip:       srcIP,
		port:     dstPort,
	})
	tracker := val.(*failureTracker)
	tracker.lastSeen.Store(now)

	tracker.mu.Lock()
	// Append failure timestamp
	tracker.failures = append(tracker.failures, now)

	// Count failures within window
	windowStart := now - int64(svc.WindowSeconds)
	count := 0
	for _, ts := range tracker.failures {
		if ts >= windowStart {
			count++
		}
	}

	// Compact: remove old entries if buffer is getting large
	if len(tracker.failures) > svc.MaxFailures*3 {
		kept := make([]int64, 0, svc.MaxFailures+1)
		for _, ts := range tracker.failures {
			if ts >= windowStart {
				kept = append(kept, ts)
			}
		}
		tracker.failures = kept
	}
	tracker.mu.Unlock()

	if count >= svc.MaxFailures {
		d.detections.Add(1)
		d.fireAlert(srcIP, serviceName, dstPort, count, svc.MaxFailures, svc.WindowSeconds)

		// Reset tracker after detection to avoid repeated alerts
		tracker.mu.Lock()
		tracker.failures = tracker.failures[:0]
		tracker.mu.Unlock()

		return BruteForceResult{
			Detected:    true,
			ServiceName: serviceName,
			Port:        dstPort,
			Failures:    count,
			Threshold:   svc.MaxFailures,
			WindowSec:   svc.WindowSeconds,
		}
	}

	return BruteForceResult{
		Detected:    false,
		ServiceName: serviceName,
		Port:        dstPort,
		Failures:    count,
		Threshold:   svc.MaxFailures,
		WindowSec:   svc.WindowSeconds,
	}
}

// IsMonitoredPort checks if a destination port is a monitored service
func (d *BruteForceDetector) IsMonitoredPort(dstPort int) bool {
	_, ok := d.portMap[dstPort]
	return ok
}

// Stats returns detection statistics
func (d *BruteForceDetector) Stats() BruteForceStats {
	var tracked int64
	d.trackers.Range(func(_, _ interface{}) bool {
		tracked++
		return true
	})
	return BruteForceStats{
		Detections: d.detections.Load(),
		TrackedIPs: tracked,
	}
}

// Stop halts the cleanup goroutine
func (d *BruteForceDetector) Stop() {
	close(d.cancel)
	d.wg.Wait()
}

func (d *BruteForceDetector) fireAlert(srcIP, serviceName string, port, failures, threshold, windowSec int) {
	if d.alertMgr == nil {
		return
	}

	alert := alerting.NewAlert(alerting.AlertBruteForce, alerting.SeverityHigh).
		WithSource(srcIP, 0).
		WithDestination("", uint16(port)).
		WithDetails(fmt.Sprintf("Brute force on %s (port %d): %d failures in %ds (threshold: %d)",
			serviceName, port, failures, windowSec, threshold)).
		WithAction(alerting.ActionBanned).
		WithMeta("service", serviceName).
		WithMeta("port", fmt.Sprintf("%d", port)).
		WithMeta("failures", fmt.Sprintf("%d", failures)).
		WithMeta("threshold", fmt.Sprintf("%d", threshold)).
		Build()

	d.alertMgr.Alert(alert)
}

func (d *BruteForceDetector) cleanupLoop() {
	ticker := time.NewTicker(60 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-d.cancel:
			return
		case <-ticker.C:
			// Remove trackers with no activity for 5 minutes
			cutoff := time.Now().Unix() - 300

			d.trackers.Range(func(key, value interface{}) bool {
				tracker := value.(*failureTracker)
				if tracker.lastSeen.Load() < cutoff {
					d.trackers.Delete(key)
				}
				return true
			})
		}
	}
}
