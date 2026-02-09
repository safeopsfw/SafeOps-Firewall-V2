package rate_limiting

import (
	"fmt"
	"sync"
	"sync/atomic"
	"time"

	"firewall_engine/internal/alerting"
	"firewall_engine/internal/config"
)

// FloodType identifies the kind of flood attack
type FloodType string

const (
	FloodSYN  FloodType = "SYN_FLOOD"
	FloodUDP  FloodType = "UDP_FLOOD"
	FloodICMP FloodType = "ICMP_FLOOD"
)

// ipFloodCounter tracks packets per second for a single IP using a sliding window
type ipFloodCounter struct {
	slots    [60]atomic.Int64 // 60-second sliding window
	lastSlot atomic.Int64
}

func (c *ipFloodCounter) increment() {
	now := time.Now().Unix()
	slot := now % 60
	lastSlot := c.lastSlot.Swap(now)

	// Clear stale slots if we've moved forward
	if now > lastSlot {
		for i := lastSlot + 1; i <= now && i <= lastSlot+60; i++ {
			c.slots[i%60].Store(0)
		}
	}

	c.slots[slot].Add(1)
}

func (c *ipFloodCounter) rate(windowSeconds int) int64 {
	if windowSeconds <= 0 || windowSeconds > 60 {
		windowSeconds = 10
	}
	now := time.Now().Unix()
	var total int64
	for i := int64(0); i < int64(windowSeconds); i++ {
		slot := (now - i) % 60
		if slot < 0 {
			slot += 60
		}
		total += c.slots[slot].Load()
	}
	return total
}

// DDoSProtection detects SYN floods, UDP floods, and ICMP floods.
// Uses per-IP sliding window counters for packet rate tracking.
type DDoSProtection struct {
	cfg      config.DDoSConfig
	alertMgr *alerting.Manager

	synCounters  sync.Map // ip -> *ipFloodCounter
	udpCounters  sync.Map // ip -> *ipFloodCounter
	icmpCounters sync.Map // ip -> *ipFloodCounter

	synDetections  atomic.Int64
	udpDetections  atomic.Int64
	icmpDetections atomic.Int64

	cancel chan struct{}
	wg     sync.WaitGroup
}

// DDoSStats holds detection statistics
type DDoSStats struct {
	SYNDetections  int64 `json:"syn_detections"`
	UDPDetections  int64 `json:"udp_detections"`
	ICMPDetections int64 `json:"icmp_detections"`
}

// NewDDoSProtection creates a new DDoS detector
func NewDDoSProtection(cfg config.DDoSConfig, alertMgr *alerting.Manager) *DDoSProtection {
	d := &DDoSProtection{
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

// CheckSYN records a SYN packet and checks if the IP exceeds the SYN rate threshold.
// Returns (isFlood, currentRate).
func (d *DDoSProtection) CheckSYN(srcIP string) (bool, int64) {
	if !d.cfg.Enabled {
		return false, 0
	}

	counter := d.getOrCreate(&d.synCounters, srcIP)
	counter.increment()

	rate := counter.rate(d.cfg.WindowSeconds)
	threshold := int64(d.cfg.SYNRateThreshold)

	if rate >= threshold {
		d.synDetections.Add(1)
		d.fireAlert(srcIP, FloodSYN, rate, threshold)
		return true, rate
	}
	return false, rate
}

// CheckUDP records a UDP packet and checks for UDP flood.
func (d *DDoSProtection) CheckUDP(srcIP string) (bool, int64) {
	if !d.cfg.Enabled {
		return false, 0
	}

	counter := d.getOrCreate(&d.udpCounters, srcIP)
	counter.increment()

	rate := counter.rate(d.cfg.WindowSeconds)
	threshold := int64(d.cfg.UDPRateThreshold)

	if rate >= threshold {
		d.udpDetections.Add(1)
		d.fireAlert(srcIP, FloodUDP, rate, threshold)
		return true, rate
	}
	return false, rate
}

// CheckICMP records an ICMP packet and checks for ICMP flood.
func (d *DDoSProtection) CheckICMP(srcIP string) (bool, int64) {
	if !d.cfg.Enabled {
		return false, 0
	}

	counter := d.getOrCreate(&d.icmpCounters, srcIP)
	counter.increment()

	rate := counter.rate(d.cfg.WindowSeconds)
	threshold := int64(d.cfg.ICMPRateThreshold)

	if rate >= threshold {
		d.icmpDetections.Add(1)
		d.fireAlert(srcIP, FloodICMP, rate, threshold)
		return true, rate
	}
	return false, rate
}

// Stats returns detection statistics
func (d *DDoSProtection) Stats() DDoSStats {
	return DDoSStats{
		SYNDetections:  d.synDetections.Load(),
		UDPDetections:  d.udpDetections.Load(),
		ICMPDetections: d.icmpDetections.Load(),
	}
}

// Stop halts the cleanup goroutine
func (d *DDoSProtection) Stop() {
	close(d.cancel)
	d.wg.Wait()
}

func (d *DDoSProtection) getOrCreate(m *sync.Map, ip string) *ipFloodCounter {
	val, loaded := m.LoadOrStore(ip, &ipFloodCounter{})
	if !loaded {
		entry := val.(*ipFloodCounter)
		entry.lastSlot.Store(time.Now().Unix())
	}
	return val.(*ipFloodCounter)
}

func (d *DDoSProtection) fireAlert(srcIP string, floodType FloodType, rate, threshold int64) {
	if d.alertMgr == nil {
		return
	}

	alert := alerting.NewAlert(alerting.AlertDDoS, alerting.SeverityCritical).
		WithSource(srcIP, 0).
		WithDetails(fmt.Sprintf("%s detected: %d packets/%ds (threshold: %d)",
			floodType, rate, d.cfg.WindowSeconds, threshold)).
		WithAction(alerting.ActionBanned).
		WithMeta("flood_type", string(floodType)).
		WithMeta("rate", fmt.Sprintf("%d", rate)).
		WithMeta("threshold", fmt.Sprintf("%d", threshold)).
		Build()

	d.alertMgr.Alert(alert)
}

func (d *DDoSProtection) cleanupLoop() {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-d.cancel:
			return
		case <-ticker.C:
			// Clean counters with no recent activity
			cutoff := time.Now().Unix() - 120 // 2 minutes stale

			cleanup := func(m *sync.Map) {
				m.Range(func(key, value interface{}) bool {
					counter := value.(*ipFloodCounter)
					if counter.lastSlot.Load() < cutoff {
						m.Delete(key)
					}
					return true
				})
			}

			cleanup(&d.synCounters)
			cleanup(&d.udpCounters)
			cleanup(&d.icmpCounters)
		}
	}
}
