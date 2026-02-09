package security

import (
	"fmt"
	"sort"
	"sync"
	"sync/atomic"
	"time"

	"firewall_engine/internal/alerting"
	"firewall_engine/internal/config"
)

// PortScanDetector detects port scanning activity by tracking unique destination
// ports accessed per source IP within a time window. Detects both random scanning
// (many unique ports) and sequential scanning (incrementing port numbers).
type PortScanDetector struct {
	cfg      config.PortScanConfig
	alertMgr *alerting.Manager

	// scanners: srcIP -> *portScanTracker
	scanners sync.Map

	detections atomic.Int64
	cancel     chan struct{}
	wg         sync.WaitGroup
}

// portScanTracker tracks unique ports per IP using a time-windowed approach
type portScanTracker struct {
	mu       sync.Mutex
	ports    map[uint16]int64 // port -> first seen timestamp
	lastSeen atomic.Int64
}

// PortScanStats holds detection statistics
type PortScanStats struct {
	Detections int64 `json:"detections"`
	TrackedIPs int64 `json:"tracked_ips"`
}

// PortScanResult is returned when port scanning is detected
type PortScanResult struct {
	Detected    bool
	ScanType    string // "random" or "sequential"
	UniquePorts int
	Threshold   int
}

// NewPortScanDetector creates a new port scan detector
func NewPortScanDetector(cfg config.PortScanConfig, alertMgr *alerting.Manager) *PortScanDetector {
	d := &PortScanDetector{
		cfg:      cfg,
		alertMgr: alertMgr,
		cancel:   make(chan struct{}),
	}

	// Cleanup goroutine every 30s
	d.wg.Add(1)
	go func() {
		defer d.wg.Done()
		d.cleanupLoop()
	}()

	return d
}

// RecordPort records access to a destination port from a source IP.
// Returns a PortScanResult indicating whether scanning has been detected.
func (d *PortScanDetector) RecordPort(srcIP string, dstPort uint16) PortScanResult {
	if !d.cfg.Enabled {
		return PortScanResult{}
	}

	now := time.Now().Unix()
	windowStart := now - int64(d.cfg.WindowSeconds)

	val, _ := d.scanners.LoadOrStore(srcIP, &portScanTracker{
		ports: make(map[uint16]int64),
	})
	tracker := val.(*portScanTracker)
	tracker.lastSeen.Store(now)

	tracker.mu.Lock()

	// Record port access
	if _, exists := tracker.ports[dstPort]; !exists {
		tracker.ports[dstPort] = now
	}

	// Evict ports outside window
	for port, ts := range tracker.ports {
		if ts < windowStart {
			delete(tracker.ports, port)
		}
	}

	uniqueCount := len(tracker.ports)

	// Check for sequential scan
	isSequential := false
	if d.cfg.SequentialThreshold > 0 && uniqueCount >= d.cfg.SequentialThreshold {
		isSequential = d.checkSequential(tracker.ports)
	}

	tracker.mu.Unlock()

	// Random scan: too many unique ports
	if uniqueCount >= d.cfg.PortThreshold {
		d.detections.Add(1)
		d.fireAlert(srcIP, "random", uniqueCount)

		// Reset after detection
		tracker.mu.Lock()
		tracker.ports = make(map[uint16]int64)
		tracker.mu.Unlock()

		return PortScanResult{
			Detected:    true,
			ScanType:    "random",
			UniquePorts: uniqueCount,
			Threshold:   d.cfg.PortThreshold,
		}
	}

	// Sequential scan: ports are incrementing
	if isSequential {
		d.detections.Add(1)
		d.fireAlert(srcIP, "sequential", uniqueCount)

		tracker.mu.Lock()
		tracker.ports = make(map[uint16]int64)
		tracker.mu.Unlock()

		return PortScanResult{
			Detected:    true,
			ScanType:    "sequential",
			UniquePorts: uniqueCount,
			Threshold:   d.cfg.SequentialThreshold,
		}
	}

	return PortScanResult{}
}

// checkSequential looks for runs of consecutive port numbers.
// Returns true if a sequential run >= threshold is found.
// Caller must hold tracker.mu.
func (d *PortScanDetector) checkSequential(ports map[uint16]int64) bool {
	if len(ports) < d.cfg.SequentialThreshold {
		return false
	}

	// Extract and sort port numbers
	sorted := make([]int, 0, len(ports))
	for p := range ports {
		sorted = append(sorted, int(p))
	}
	sort.Ints(sorted)

	// Find longest consecutive run
	runLen := 1
	for i := 1; i < len(sorted); i++ {
		if sorted[i] == sorted[i-1]+1 {
			runLen++
			if runLen >= d.cfg.SequentialThreshold {
				return true
			}
		} else {
			runLen = 1
		}
	}

	return false
}

// Stats returns detection statistics
func (d *PortScanDetector) Stats() PortScanStats {
	var tracked int64
	d.scanners.Range(func(_, _ interface{}) bool {
		tracked++
		return true
	})
	return PortScanStats{
		Detections: d.detections.Load(),
		TrackedIPs: tracked,
	}
}

// Stop halts the cleanup goroutine
func (d *PortScanDetector) Stop() {
	close(d.cancel)
	d.wg.Wait()
}

func (d *PortScanDetector) fireAlert(srcIP, scanType string, uniquePorts int) {
	if d.alertMgr == nil {
		return
	}

	severity := alerting.SeverityMedium
	if uniquePorts >= d.cfg.PortThreshold*2 {
		severity = alerting.SeverityHigh
	}

	alert := alerting.NewAlert(alerting.AlertPortScan, severity).
		WithSource(srcIP, 0).
		WithDetails(fmt.Sprintf("Port scan detected (%s): %d unique ports in %ds (threshold: %d)",
			scanType, uniquePorts, d.cfg.WindowSeconds, d.cfg.PortThreshold)).
		WithAction(alerting.ActionBanned).
		WithMeta("scan_type", scanType).
		WithMeta("unique_ports", fmt.Sprintf("%d", uniquePorts)).
		WithMeta("threshold", fmt.Sprintf("%d", d.cfg.PortThreshold)).
		Build()

	d.alertMgr.Alert(alert)
}

func (d *PortScanDetector) cleanupLoop() {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-d.cancel:
			return
		case <-ticker.C:
			// Remove scanners with no activity for 2x window
			cutoff := time.Now().Unix() - int64(d.cfg.WindowSeconds*2)
			if cutoff < time.Now().Unix()-120 {
				cutoff = time.Now().Unix() - 120
			}

			d.scanners.Range(func(key, value interface{}) bool {
				tracker := value.(*portScanTracker)
				if tracker.lastSeen.Load() < cutoff {
					d.scanners.Delete(key)
				}
				return true
			})
		}
	}
}
