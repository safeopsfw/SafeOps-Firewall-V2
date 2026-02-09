package alerting

import (
	"sync"
	"sync/atomic"
	"time"
)

// throttleEntry tracks a deduplicated alert within a time window
type throttleEntry struct {
	firstSeen time.Time
	lastSeen  time.Time
	count     int64
	lastAlert *Alert // most recent alert for aggregation
}

// Throttle deduplicates alerts by (alertType + srcIP) within a configurable window.
// When the window expires, it emits a single aggregated alert with the total count.
type Throttle struct {
	mu       sync.Mutex
	entries  map[string]*throttleEntry
	window   time.Duration
	suppressed atomic.Int64
}

// NewThrottle creates a new alert throttle
// windowSeconds: how long to suppress duplicate alerts (e.g., 60s)
func NewThrottle(windowSeconds int) *Throttle {
	if windowSeconds <= 0 {
		windowSeconds = 60
	}
	return &Throttle{
		entries: make(map[string]*throttleEntry),
		window:  time.Duration(windowSeconds) * time.Second,
	}
}

// Check determines whether an alert should be emitted or suppressed.
// Returns:
//   - emit: true if this alert should be written (first occurrence or window expired)
//   - aggregated: if non-nil, the alert has been updated with aggregation data
func (t *Throttle) Check(alert *Alert) (emit bool, aggregated *Alert) {
	key := alert.ThrottleKey()
	now := time.Now()

	t.mu.Lock()
	defer t.mu.Unlock()

	entry, exists := t.entries[key]
	if !exists {
		// First time seeing this alert type+src — emit immediately
		t.entries[key] = &throttleEntry{
			firstSeen: now,
			lastSeen:  now,
			count:     1,
			lastAlert: alert,
		}
		alert.Count = 1
		return true, alert
	}

	// Window expired — emit aggregated alert and reset
	if now.Sub(entry.firstSeen) >= t.window {
		aggregated := entry.lastAlert
		aggregated.Count = entry.count
		aggregated.WindowStart = entry.firstSeen.Format(time.RFC3339)
		aggregated.WindowEnd = entry.lastSeen.Format(time.RFC3339)
		aggregated.Timestamp = now

		// Reset for next window
		t.entries[key] = &throttleEntry{
			firstSeen: now,
			lastSeen:  now,
			count:     1,
			lastAlert: alert,
		}

		// Emit the aggregated summary if count > 1, else just the new one
		if aggregated.Count > 1 {
			return true, aggregated
		}
		alert.Count = 1
		return true, alert
	}

	// Within window — suppress and increment counter
	entry.count++
	entry.lastSeen = now
	entry.lastAlert = alert
	t.suppressed.Add(1)
	return false, nil
}

// Cleanup removes expired entries. Call periodically from a background goroutine.
func (t *Throttle) Cleanup() {
	now := time.Now()
	t.mu.Lock()
	defer t.mu.Unlock()

	for key, entry := range t.entries {
		if now.Sub(entry.lastSeen) > t.window*2 {
			delete(t.entries, key)
		}
	}
}

// FlushAll emits aggregated alerts for all active entries and resets.
// Used during shutdown to ensure no suppressed alerts are lost.
func (t *Throttle) FlushAll() []*Alert {
	t.mu.Lock()
	defer t.mu.Unlock()

	var alerts []*Alert
	for key, entry := range t.entries {
		if entry.count > 1 {
			a := entry.lastAlert
			a.Count = entry.count
			a.WindowStart = entry.firstSeen.Format(time.RFC3339)
			a.WindowEnd = entry.lastSeen.Format(time.RFC3339)
			alerts = append(alerts, a)
		}
		delete(t.entries, key)
	}
	return alerts
}

// Stats returns throttle statistics
func (t *Throttle) Stats() (activeEntries int, totalSuppressed int64) {
	t.mu.Lock()
	activeEntries = len(t.entries)
	t.mu.Unlock()
	totalSuppressed = t.suppressed.Load()
	return
}
