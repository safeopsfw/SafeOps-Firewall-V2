package rate_limiting

import (
	"sync"
	"sync/atomic"
	"time"
)

// PerIPLimiter manages one token bucket per source IP.
// Buckets are created on first access and cleaned up periodically.
type PerIPLimiter struct {
	buckets     sync.Map // ip_string -> *ipEntry
	defaultRate float64
	defaultBurst int
	activeCount  atomic.Int64

	cancel chan struct{}
	wg     sync.WaitGroup
}

type ipEntry struct {
	bucket   *TokenBucket
	lastSeen atomic.Int64 // unix nanos
}

// NewPerIPLimiter creates a per-IP rate limiter with cleanup.
// rate: default tokens/sec per IP, burst: default burst capacity
// cleanupSeconds: how often to remove stale buckets (0 = no cleanup)
func NewPerIPLimiter(rate float64, burst int, cleanupSeconds int) *PerIPLimiter {
	l := &PerIPLimiter{
		defaultRate:  rate,
		defaultBurst: burst,
		cancel:       make(chan struct{}),
	}

	if cleanupSeconds > 0 {
		l.wg.Add(1)
		go func() {
			defer l.wg.Done()
			l.cleanupLoop(time.Duration(cleanupSeconds) * time.Second)
		}()
	}

	return l
}

// CheckRate checks if the IP is within its rate limit.
// Returns (allowed, currentRate). Creates a new bucket if the IP is new.
func (l *PerIPLimiter) CheckRate(ip string) (allowed bool, currentRate float64) {
	now := time.Now().UnixNano()

	val, loaded := l.buckets.LoadOrStore(ip, &ipEntry{
		bucket: NewTokenBucket(l.defaultRate, l.defaultBurst),
	})
	if !loaded {
		l.activeCount.Add(1)
	}

	entry := val.(*ipEntry)
	entry.lastSeen.Store(now)

	allowed = entry.bucket.Allow()
	currentRate = l.defaultRate - entry.bucket.Tokens()

	return allowed, currentRate
}

// Allow is a simple allow/deny check for the IP.
func (l *PerIPLimiter) Allow(ip string) bool {
	allowed, _ := l.CheckRate(ip)
	return allowed
}

// ActiveCount returns the number of tracked IPs
func (l *PerIPLimiter) ActiveCount() int64 {
	return l.activeCount.Load()
}

// Stop halts the cleanup goroutine
func (l *PerIPLimiter) Stop() {
	close(l.cancel)
	l.wg.Wait()
}

func (l *PerIPLimiter) cleanupLoop(interval time.Duration) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	// Remove IPs not seen for 5x the cleanup interval
	staleThreshold := interval * 5

	for {
		select {
		case <-l.cancel:
			return
		case <-ticker.C:
			now := time.Now().UnixNano()
			threshold := now - staleThreshold.Nanoseconds()

			l.buckets.Range(func(key, value interface{}) bool {
				entry := value.(*ipEntry)
				if entry.lastSeen.Load() < threshold {
					l.buckets.Delete(key)
					l.activeCount.Add(-1)
				}
				return true
			})
		}
	}
}
