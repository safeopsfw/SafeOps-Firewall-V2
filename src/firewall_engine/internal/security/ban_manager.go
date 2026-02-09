package security

import (
	"fmt"
	"sync"
	"sync/atomic"
	"time"

	"firewall_engine/internal/alerting"
)

// BanManager tracks active bans with exponential escalation.
// Ban durations escalate: base → base*mult → base*mult^2 → ... up to max.
// After max is reached, the ban becomes permanent.
type BanManager struct {
	alertMgr *alerting.Manager

	// Active bans: IP -> *BanEntry
	bans sync.Map

	// Ban history: IP -> *banHistory (tracks escalation level)
	history sync.Map

	// Escalation config
	baseDurationMin    int
	escalationMult     int
	maxDurationHours   int

	activeBans  atomic.Int64
	totalBans   atomic.Int64
	totalUnbans atomic.Int64

	cancel chan struct{}
	wg     sync.WaitGroup
}

// BanEntry represents an active ban
type BanEntry struct {
	IP        string    `json:"ip"`
	Reason    string    `json:"reason"`
	BannedAt  time.Time `json:"banned_at"`
	ExpiresAt time.Time `json:"expires_at"` // zero = permanent
	Duration  time.Duration `json:"duration"`
	Level     int       `json:"level"` // escalation level (0 = first ban)
	Permanent bool      `json:"permanent"`
}

// banHistory tracks how many times an IP has been banned (for escalation)
type banHistory struct {
	mu    sync.Mutex
	level int       // current escalation level
	lastBan time.Time
}

// BanManagerStats holds ban statistics
type BanManagerStats struct {
	ActiveBans int64 `json:"active_bans"`
	TotalBans  int64 `json:"total_bans"`
	TotalUnbans int64 `json:"total_unbans"`
}

// BanCallback is called when a ban is applied or removed.
// The caller (security manager) can use this to invoke SafeOps API.
type BanCallback func(ip string, banned bool, reason string, duration time.Duration)

// NewBanManager creates a new ban manager with escalation config.
// baseDurationMin: initial ban duration in minutes (e.g., 30)
// escalationMult: multiplier per escalation (e.g., 4 → 30m, 2h, 8h, 32h)
// maxDurationHours: maximum ban before permanent (e.g., 720 = 30 days)
func NewBanManager(baseDurationMin, escalationMult, maxDurationHours int, alertMgr *alerting.Manager) *BanManager {
	bm := &BanManager{
		alertMgr:         alertMgr,
		baseDurationMin:  baseDurationMin,
		escalationMult:   escalationMult,
		maxDurationHours: maxDurationHours,
		cancel:           make(chan struct{}),
	}

	// Expiry checker goroutine every 30s
	bm.wg.Add(1)
	go func() {
		defer bm.wg.Done()
		bm.expiryLoop()
	}()

	return bm
}

// Ban bans an IP with reason. Duration is automatically escalated based on history.
// Returns the BanEntry created.
func (bm *BanManager) Ban(ip, reason string) *BanEntry {
	// Get or create ban history
	val, _ := bm.history.LoadOrStore(ip, &banHistory{})
	hist := val.(*banHistory)

	hist.mu.Lock()
	level := hist.level
	hist.level++
	hist.lastBan = time.Now()
	hist.mu.Unlock()

	// Calculate duration with escalation
	duration := bm.calculateDuration(level)
	permanent := false

	entry := &BanEntry{
		IP:        ip,
		Reason:    reason,
		BannedAt:  time.Now(),
		Duration:  duration,
		Level:     level,
	}

	if duration == 0 {
		permanent = true
		entry.Permanent = true
	} else {
		entry.ExpiresAt = time.Now().Add(duration)
	}

	// Store or update ban
	if _, loaded := bm.bans.LoadOrStore(ip, entry); loaded {
		// Already banned — update with new entry (escalated)
		bm.bans.Store(ip, entry)
	} else {
		bm.activeBans.Add(1)
	}
	bm.totalBans.Add(1)

	// Alert
	if bm.alertMgr != nil {
		durStr := duration.String()
		if permanent {
			durStr = "PERMANENT"
		}

		alert := alerting.NewAlert(alerting.AlertIPBlock, alerting.SeverityHigh).
			WithSource(ip, 0).
			WithDetails(fmt.Sprintf("IP banned: %s (level %d, duration: %s)", reason, level, durStr)).
			WithAction(alerting.ActionBanned).
			WithBanDuration(duration).
			WithMeta("ban_level", fmt.Sprintf("%d", level)).
			WithMeta("reason", reason).
			Build()

		bm.alertMgr.Alert(alert)
	}

	return entry
}

// BanWithDuration bans an IP with a specific duration (bypasses escalation).
func (bm *BanManager) BanWithDuration(ip, reason string, duration time.Duration) *BanEntry {
	entry := &BanEntry{
		IP:        ip,
		Reason:    reason,
		BannedAt:  time.Now(),
		Duration:  duration,
		ExpiresAt: time.Now().Add(duration),
	}

	if _, loaded := bm.bans.LoadOrStore(ip, entry); loaded {
		bm.bans.Store(ip, entry)
	} else {
		bm.activeBans.Add(1)
	}
	bm.totalBans.Add(1)

	return entry
}

// Unban removes a ban for an IP
func (bm *BanManager) Unban(ip string) bool {
	if _, loaded := bm.bans.LoadAndDelete(ip); loaded {
		bm.activeBans.Add(-1)
		bm.totalUnbans.Add(1)
		return true
	}
	return false
}

// IsBanned checks if an IP is currently banned
func (bm *BanManager) IsBanned(ip string) (*BanEntry, bool) {
	val, ok := bm.bans.Load(ip)
	if !ok {
		return nil, false
	}
	entry := val.(*BanEntry)

	// Check expiry
	if !entry.Permanent && !entry.ExpiresAt.IsZero() && time.Now().After(entry.ExpiresAt) {
		bm.bans.Delete(ip)
		bm.activeBans.Add(-1)
		bm.totalUnbans.Add(1)
		return nil, false
	}

	return entry, true
}

// GetActiveBans returns all active bans
func (bm *BanManager) GetActiveBans() []*BanEntry {
	var bans []*BanEntry
	bm.bans.Range(func(_, value interface{}) bool {
		entry := value.(*BanEntry)
		if entry.Permanent || time.Now().Before(entry.ExpiresAt) {
			bans = append(bans, entry)
		}
		return true
	})
	return bans
}

// ResetHistory clears ban history for an IP (resets escalation)
func (bm *BanManager) ResetHistory(ip string) {
	bm.history.Delete(ip)
}

// Stats returns ban statistics
func (bm *BanManager) Stats() BanManagerStats {
	return BanManagerStats{
		ActiveBans:  bm.activeBans.Load(),
		TotalBans:   bm.totalBans.Load(),
		TotalUnbans: bm.totalUnbans.Load(),
	}
}

// UpdateEscalation updates ban escalation parameters without clearing active bans.
func (bm *BanManager) UpdateEscalation(baseDurationMin, escalationMult, maxDurationHours int) {
	bm.baseDurationMin = baseDurationMin
	bm.escalationMult = escalationMult
	bm.maxDurationHours = maxDurationHours
}

// Stop halts the expiry goroutine
func (bm *BanManager) Stop() {
	close(bm.cancel)
	bm.wg.Wait()
}

// calculateDuration returns the ban duration for a given escalation level.
// Level 0: base minutes
// Level 1: base * mult
// Level N: base * mult^N
// If exceeds max, returns 0 (permanent)
func (bm *BanManager) calculateDuration(level int) time.Duration {
	if level < 0 {
		level = 0
	}

	minutes := bm.baseDurationMin
	for i := 0; i < level; i++ {
		minutes *= bm.escalationMult
		// Check if we've exceeded max
		if minutes >= bm.maxDurationHours*60 {
			return 0 // permanent
		}
	}

	return time.Duration(minutes) * time.Minute
}

func (bm *BanManager) expiryLoop() {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-bm.cancel:
			return
		case <-ticker.C:
			now := time.Now()
			bm.bans.Range(func(key, value interface{}) bool {
				entry := value.(*BanEntry)
				if !entry.Permanent && !entry.ExpiresAt.IsZero() && now.After(entry.ExpiresAt) {
					bm.bans.Delete(key)
					bm.activeBans.Add(-1)
					bm.totalUnbans.Add(1)
				}
				return true
			})

			// Clean old history entries (no ban in 24 hours → reset escalation)
			cutoff := now.Add(-24 * time.Hour)
			bm.history.Range(func(key, value interface{}) bool {
				hist := value.(*banHistory)
				hist.mu.Lock()
				if hist.lastBan.Before(cutoff) {
					hist.mu.Unlock()
					bm.history.Delete(key)
				} else {
					hist.mu.Unlock()
				}
				return true
			})
		}
	}
}
