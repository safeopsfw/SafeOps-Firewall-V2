// Package models defines all core data structures used throughout the firewall engine.
package models

import (
	"encoding/json"
	"fmt"
	"sync/atomic"
	"time"
)

// ============================================================================
// Rule Statistics - Per-rule performance tracking
// ============================================================================

// RuleStats contains performance statistics for a single rule.
type RuleStats struct {
	// RuleID is the rule this statistics belong to.
	RuleID string `json:"rule_id"`

	// RuleName is the human-readable rule name.
	RuleName string `json:"rule_name"`

	// HitCount is the total number of times this rule matched.
	HitCount atomic.Uint64 `json:"-"`

	// BytesMatched is the total bytes matched by this rule.
	BytesMatched atomic.Uint64 `json:"-"`

	// PacketsMatched is the total packets matched by this rule.
	PacketsMatched atomic.Uint64 `json:"-"`

	// LastMatchTime is when this rule last matched a packet.
	LastMatchTime atomic.Int64 `json:"-"`

	// AverageMatchTimeNs is the average time to match this rule.
	AverageMatchTimeNs atomic.Int64 `json:"-"`

	// MatchTimeCount is the count for averaging.
	MatchTimeCount atomic.Uint64 `json:"-"`

	// JSON serialization fields
	HitCountJSON           uint64 `json:"hit_count"`
	BytesMatchedJSON       uint64 `json:"bytes_matched"`
	PacketsMatchedJSON     uint64 `json:"packets_matched"`
	LastMatchTimeJSON      string `json:"last_match_time,omitempty"`
	AverageMatchTimeNsJSON int64  `json:"average_match_time_ns"`
}

// NewRuleStats creates a new rule stats instance.
func NewRuleStats(ruleID, ruleName string) *RuleStats {
	return &RuleStats{
		RuleID:   ruleID,
		RuleName: ruleName,
	}
}

// RecordMatch records a rule match with timing information.
func (rs *RuleStats) RecordMatch(packetBytes uint32, matchTimeNs int64) {
	rs.HitCount.Add(1)
	rs.PacketsMatched.Add(1)
	rs.BytesMatched.Add(uint64(packetBytes))
	rs.LastMatchTime.Store(time.Now().UnixNano())

	// Update running average of match time
	if matchTimeNs > 0 {
		count := rs.MatchTimeCount.Add(1)
		currentAvg := rs.AverageMatchTimeNs.Load()
		// Exponential moving average
		newAvg := currentAvg + (matchTimeNs-currentAvg)/int64(count)
		rs.AverageMatchTimeNs.Store(newAvg)
	}
}

// PrepareForJSON prepares the stats for JSON serialization.
func (rs *RuleStats) PrepareForJSON() {
	rs.HitCountJSON = rs.HitCount.Load()
	rs.BytesMatchedJSON = rs.BytesMatched.Load()
	rs.PacketsMatchedJSON = rs.PacketsMatched.Load()
	rs.AverageMatchTimeNsJSON = rs.AverageMatchTimeNs.Load()

	lastMatch := rs.LastMatchTime.Load()
	if lastMatch > 0 {
		rs.LastMatchTimeJSON = time.Unix(0, lastMatch).Format(time.RFC3339)
	}
}

// GetHitCount returns the current hit count.
func (rs *RuleStats) GetHitCount() uint64 {
	return rs.HitCount.Load()
}

// GetLastMatchTime returns the last match time.
func (rs *RuleStats) GetLastMatchTime() time.Time {
	ns := rs.LastMatchTime.Load()
	if ns == 0 {
		return time.Time{}
	}
	return time.Unix(0, ns)
}

// Reset clears all statistics.
func (rs *RuleStats) Reset() {
	rs.HitCount.Store(0)
	rs.BytesMatched.Store(0)
	rs.PacketsMatched.Store(0)
	rs.LastMatchTime.Store(0)
	rs.AverageMatchTimeNs.Store(0)
	rs.MatchTimeCount.Store(0)
}

// ============================================================================
// Engine Statistics - Overall firewall performance
// ============================================================================

// EngineStats contains overall firewall engine statistics.
type EngineStats struct {
	// === Packet Counters ===

	// PacketsReceived is total packets received from SafeOps Engine.
	PacketsReceived atomic.Uint64 `json:"-"`

	// PacketsProcessed is total packets that completed rule evaluation.
	PacketsProcessed atomic.Uint64 `json:"-"`

	// PacketsAllowed is total packets that were allowed through.
	PacketsAllowed atomic.Uint64 `json:"-"`

	// PacketsBlocked is total packets that were blocked/dropped.
	PacketsBlocked atomic.Uint64 `json:"-"`

	// PacketsDropped is total packets silently dropped.
	PacketsDropped atomic.Uint64 `json:"-"`

	// PacketsRedirected is total packets redirected.
	PacketsRedirected atomic.Uint64 `json:"-"`

	// === Byte Counters ===

	// BytesReceived is total bytes received.
	BytesReceived atomic.Uint64 `json:"-"`

	// BytesAllowed is total bytes allowed through.
	BytesAllowed atomic.Uint64 `json:"-"`

	// BytesBlocked is total bytes blocked.
	BytesBlocked atomic.Uint64 `json:"-"`

	// === Rule Matching Stats ===

	// RulesEvaluated is total rule evaluations performed.
	RulesEvaluated atomic.Uint64 `json:"-"`

	// RuleMatches is total rules that matched a packet.
	RuleMatches atomic.Uint64 `json:"-"`

	// DefaultPolicyHits is times default policy was applied.
	DefaultPolicyHits atomic.Uint64 `json:"-"`

	// === Cache Stats ===

	// CacheHits is times a cached verdict was used (fast lane).
	CacheHits atomic.Uint64 `json:"-"`

	// CacheMisses is times full rule evaluation was needed (slow lane).
	CacheMisses atomic.Uint64 `json:"-"`

	// CacheSize is current number of cached verdicts.
	CacheSize atomic.Uint64 `json:"-"`

	// CacheEvictions is times a cache entry was evicted.
	CacheEvictions atomic.Uint64 `json:"-"`

	// === Connection Tracking Stats ===

	// ActiveConnections is current tracked connections.
	ActiveConnections atomic.Uint64 `json:"-"`

	// TotalConnections is total connections tracked since start.
	TotalConnections atomic.Uint64 `json:"-"`

	// ConnectionTimeouts is connections expired due to timeout.
	ConnectionTimeouts atomic.Uint64 `json:"-"`

	// === Performance Timing ===

	// TotalMatchTimeNs is cumulative rule matching time.
	TotalMatchTimeNs atomic.Int64 `json:"-"`

	// MaxMatchTimeNs is max single rule matching time.
	MaxMatchTimeNs atomic.Int64 `json:"-"`

	// MinMatchTimeNs is min single rule matching time.
	MinMatchTimeNs atomic.Int64 `json:"-"`

	// MatchCount is count for averaging.
	MatchCount atomic.Uint64 `json:"-"`

	// === Error Counters ===

	// Errors is total errors encountered.
	Errors atomic.Uint64 `json:"-"`

	// VerdictErrors is failed verdict applications.
	VerdictErrors atomic.Uint64 `json:"-"`

	// ParseErrors is packet parsing errors.
	ParseErrors atomic.Uint64 `json:"-"`

	// === Timestamps ===

	// StartTime is when the engine started.
	StartTime time.Time `json:"start_time"`

	// LastResetTime is when stats were last reset.
	LastResetTime time.Time `json:"last_reset_time"`

	// LastPacketTime is when the last packet was processed.
	LastPacketTime atomic.Int64 `json:"-"`
}

// NewEngineStats creates a new engine stats instance.
func NewEngineStats() *EngineStats {
	now := time.Now()
	stats := &EngineStats{
		StartTime:     now,
		LastResetTime: now,
	}
	// Initialize min to max int64 so first value always wins
	stats.MinMatchTimeNs.Store(int64(^uint64(0) >> 1))
	return stats
}

// RecordPacket records a processed packet.
func (es *EngineStats) RecordPacket(verdict Verdict, packetBytes uint32, matchTimeNs int64) {
	es.PacketsReceived.Add(1)
	es.PacketsProcessed.Add(1)
	es.BytesReceived.Add(uint64(packetBytes))
	es.LastPacketTime.Store(time.Now().UnixNano())

	switch verdict {
	case VerdictAllow, VerdictLog:
		es.PacketsAllowed.Add(1)
		es.BytesAllowed.Add(uint64(packetBytes))
	case VerdictBlock, VerdictReject:
		es.PacketsBlocked.Add(1)
		es.BytesBlocked.Add(uint64(packetBytes))
	case VerdictDrop:
		es.PacketsDropped.Add(1)
		es.BytesBlocked.Add(uint64(packetBytes))
	case VerdictRedirect:
		es.PacketsRedirected.Add(1)
	}

	// Update timing stats
	if matchTimeNs > 0 {
		es.TotalMatchTimeNs.Add(matchTimeNs)
		es.MatchCount.Add(1)

		// Update max
		for {
			current := es.MaxMatchTimeNs.Load()
			if matchTimeNs <= current || es.MaxMatchTimeNs.CompareAndSwap(current, matchTimeNs) {
				break
			}
		}

		// Update min
		for {
			current := es.MinMatchTimeNs.Load()
			if matchTimeNs >= current || es.MinMatchTimeNs.CompareAndSwap(current, matchTimeNs) {
				break
			}
		}
	}
}

// RecordCacheHit records a cache hit (fast lane).
func (es *EngineStats) RecordCacheHit() {
	es.CacheHits.Add(1)
}

// RecordCacheMiss records a cache miss (slow lane).
func (es *EngineStats) RecordCacheMiss() {
	es.CacheMisses.Add(1)
}

// RecordRuleMatch records a rule match.
func (es *EngineStats) RecordRuleMatch(rulesEvaluated int) {
	es.RulesEvaluated.Add(uint64(rulesEvaluated))
	es.RuleMatches.Add(1)
}

// RecordDefaultPolicy records a default policy hit.
func (es *EngineStats) RecordDefaultPolicy(rulesEvaluated int) {
	es.RulesEvaluated.Add(uint64(rulesEvaluated))
	es.DefaultPolicyHits.Add(1)
}

// RecordError records an error.
func (es *EngineStats) RecordError() {
	es.Errors.Add(1)
}

// SetConnectionCount updates the active connection count.
func (es *EngineStats) SetConnectionCount(count uint64) {
	es.ActiveConnections.Store(count)
}

// SetCacheSize updates the cache size.
func (es *EngineStats) SetCacheSize(size uint64) {
	es.CacheSize.Store(size)
}

// GetAverageMatchTimeNs returns the average match time in nanoseconds.
func (es *EngineStats) GetAverageMatchTimeNs() float64 {
	count := es.MatchCount.Load()
	if count == 0 {
		return 0
	}
	return float64(es.TotalMatchTimeNs.Load()) / float64(count)
}

// GetUptime returns how long the engine has been running.
func (es *EngineStats) GetUptime() time.Duration {
	return time.Since(es.StartTime)
}

// GetPacketsPerSecond returns the current packets per second rate.
func (es *EngineStats) GetPacketsPerSecond() float64 {
	uptime := es.GetUptime().Seconds()
	if uptime <= 0 {
		return 0
	}
	return float64(es.PacketsProcessed.Load()) / uptime
}

// GetCacheHitRate returns the cache hit rate (0-1).
func (es *EngineStats) GetCacheHitRate() float64 {
	hits := es.CacheHits.Load()
	misses := es.CacheMisses.Load()
	total := hits + misses
	if total == 0 {
		return 0
	}
	return float64(hits) / float64(total)
}

// Reset clears all statistics except start time.
func (es *EngineStats) Reset() {
	es.PacketsReceived.Store(0)
	es.PacketsProcessed.Store(0)
	es.PacketsAllowed.Store(0)
	es.PacketsBlocked.Store(0)
	es.PacketsDropped.Store(0)
	es.PacketsRedirected.Store(0)
	es.BytesReceived.Store(0)
	es.BytesAllowed.Store(0)
	es.BytesBlocked.Store(0)
	es.RulesEvaluated.Store(0)
	es.RuleMatches.Store(0)
	es.DefaultPolicyHits.Store(0)
	es.CacheHits.Store(0)
	es.CacheMisses.Store(0)
	es.CacheEvictions.Store(0)
	es.TotalMatchTimeNs.Store(0)
	es.MaxMatchTimeNs.Store(0)
	es.MinMatchTimeNs.Store(int64(^uint64(0) >> 1))
	es.MatchCount.Store(0)
	es.Errors.Store(0)
	es.VerdictErrors.Store(0)
	es.ParseErrors.Store(0)
	es.LastResetTime = time.Now()
}

// ToJSON returns a JSON-serializable snapshot of the stats.
func (es *EngineStats) ToJSON() *EngineStatsSnapshot {
	return &EngineStatsSnapshot{
		PacketsReceived:    es.PacketsReceived.Load(),
		PacketsProcessed:   es.PacketsProcessed.Load(),
		PacketsAllowed:     es.PacketsAllowed.Load(),
		PacketsBlocked:     es.PacketsBlocked.Load(),
		PacketsDropped:     es.PacketsDropped.Load(),
		PacketsRedirected:  es.PacketsRedirected.Load(),
		BytesReceived:      es.BytesReceived.Load(),
		BytesAllowed:       es.BytesAllowed.Load(),
		BytesBlocked:       es.BytesBlocked.Load(),
		RulesEvaluated:     es.RulesEvaluated.Load(),
		RuleMatches:        es.RuleMatches.Load(),
		DefaultPolicyHits:  es.DefaultPolicyHits.Load(),
		CacheHits:          es.CacheHits.Load(),
		CacheMisses:        es.CacheMisses.Load(),
		CacheSize:          es.CacheSize.Load(),
		CacheHitRate:       es.GetCacheHitRate(),
		ActiveConnections:  es.ActiveConnections.Load(),
		TotalConnections:   es.TotalConnections.Load(),
		AverageMatchTimeNs: es.GetAverageMatchTimeNs(),
		MaxMatchTimeNs:     es.MaxMatchTimeNs.Load(),
		MinMatchTimeNs:     es.MinMatchTimeNs.Load(),
		PacketsPerSecond:   es.GetPacketsPerSecond(),
		Errors:             es.Errors.Load(),
		Uptime:             es.GetUptime().String(),
		StartTime:          es.StartTime.Format(time.RFC3339),
		LastResetTime:      es.LastResetTime.Format(time.RFC3339),
	}
}

// EngineStatsSnapshot is a JSON-serializable snapshot of EngineStats.
type EngineStatsSnapshot struct {
	// Packet counters
	PacketsReceived   uint64 `json:"packets_received"`
	PacketsProcessed  uint64 `json:"packets_processed"`
	PacketsAllowed    uint64 `json:"packets_allowed"`
	PacketsBlocked    uint64 `json:"packets_blocked"`
	PacketsDropped    uint64 `json:"packets_dropped"`
	PacketsRedirected uint64 `json:"packets_redirected"`

	// Byte counters
	BytesReceived uint64 `json:"bytes_received"`
	BytesAllowed  uint64 `json:"bytes_allowed"`
	BytesBlocked  uint64 `json:"bytes_blocked"`

	// Rule stats
	RulesEvaluated    uint64 `json:"rules_evaluated"`
	RuleMatches       uint64 `json:"rule_matches"`
	DefaultPolicyHits uint64 `json:"default_policy_hits"`

	// Cache stats
	CacheHits    uint64  `json:"cache_hits"`
	CacheMisses  uint64  `json:"cache_misses"`
	CacheSize    uint64  `json:"cache_size"`
	CacheHitRate float64 `json:"cache_hit_rate"`

	// Connection stats
	ActiveConnections uint64 `json:"active_connections"`
	TotalConnections  uint64 `json:"total_connections"`

	// Performance
	AverageMatchTimeNs float64 `json:"average_match_time_ns"`
	MaxMatchTimeNs     int64   `json:"max_match_time_ns"`
	MinMatchTimeNs     int64   `json:"min_match_time_ns"`
	PacketsPerSecond   float64 `json:"packets_per_second"`

	// Errors
	Errors uint64 `json:"errors"`

	// Timestamps
	Uptime        string `json:"uptime"`
	StartTime     string `json:"start_time"`
	LastResetTime string `json:"last_reset_time"`
}

// MarshalJSON implements json.Marshaler for EngineStats.
func (es *EngineStats) MarshalJSON() ([]byte, error) {
	return json.Marshal(es.ToJSON())
}

// String returns a human-readable summary of the stats.
func (es *EngineStats) String() string {
	return fmt.Sprintf(
		"Packets: %d processed, %d allowed, %d blocked | "+
			"Cache: %.1f%% hit rate | "+
			"Avg match: %.2fμs | "+
			"Rate: %.0f pps",
		es.PacketsProcessed.Load(),
		es.PacketsAllowed.Load(),
		es.PacketsBlocked.Load(),
		es.GetCacheHitRate()*100,
		es.GetAverageMatchTimeNs()/1000,
		es.GetPacketsPerSecond(),
	)
}
