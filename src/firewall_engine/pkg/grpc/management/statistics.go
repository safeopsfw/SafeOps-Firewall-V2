// Package management provides gRPC management API for the firewall engine.
package management

import (
	"context"
	"sort"
	"sync"
	"time"

	"google.golang.org/protobuf/types/known/timestamppb"
)

// ============================================================================
// Statistics RPC Implementations
// ============================================================================

// GetStatistics returns firewall statistics for a time window.
func (s *Server) GetStatistics(ctx context.Context, req *GetStatisticsRequest) (*GetStatisticsResponse, error) {
	// Default to 60 seconds window
	windowSeconds := int32(60)
	if req != nil && req.WindowSeconds > 0 {
		windowSeconds = req.WindowSeconds
	}

	// Get stats from rolling stats if available
	if s.deps.RollingStats != nil {
		stats := s.deps.RollingStats.GetStats(time.Duration(windowSeconds) * time.Second)

		return &GetStatisticsResponse{
			TotalPackets:   stats.PacketsTotal,
			AllowedPackets: stats.PacketsAllow,
			DeniedPackets:  stats.PacketsDeny,
			ThroughputPps:  stats.PacketsPerSec,
			CacheHitRate:   stats.CacheHitRate,
			TotalBytes:     stats.BytesTotal,
			BytesIn:        stats.BytesIn,
			BytesOut:       stats.BytesOut,
			Latency: &LatencyStats{
				AvgSeconds: float64(stats.LatencyAvg.Nanoseconds()) / 1e9,
				MinSeconds: float64(stats.LatencyMin.Nanoseconds()) / 1e9,
				MaxSeconds: float64(stats.LatencyMax.Nanoseconds()) / 1e9,
			},
			PacketsByProtocol: make(map[string]uint64),
			PacketsByAction:   make(map[string]uint64),
		}, nil
	}

	// Return empty stats if no collector available
	return &GetStatisticsResponse{
		PacketsByProtocol: make(map[string]uint64),
		PacketsByAction:   make(map[string]uint64),
	}, nil
}

// GetRuleStats returns per-rule statistics.
func (s *Server) GetRuleStats(ctx context.Context, req *GetRuleStatsRequest) (*GetRuleStatsResponse, error) {
	limit := int32(100)
	if req != nil && req.Limit > 0 {
		limit = req.Limit
	}

	// Check if rule manager available
	if s.deps.RuleManager == nil {
		return &GetRuleStatsResponse{
			Rules:      []*RuleStat{},
			TotalCount: 0,
		}, nil
	}

	rules := s.deps.RuleManager.GetRules()

	// Filter by rule ID if specified
	if req != nil && req.RuleID != "" {
		var filtered []RuleInfo
		for _, r := range rules {
			if r.ID == req.RuleID {
				filtered = append(filtered, r)
			}
		}
		rules = filtered
	}

	// Sort by hit count (descending)
	sort.Slice(rules, func(i, j int) bool {
		return rules[i].HitCount > rules[j].HitCount
	})

	// Apply limit
	if int32(len(rules)) > limit {
		rules = rules[:limit]
	}

	// Convert to response
	ruleStats := make([]*RuleStat, len(rules))
	for i, r := range rules {
		var lastHit *timestamppb.Timestamp
		if !r.LastHit.IsZero() {
			lastHit = timestamppb.New(r.LastHit)
		}

		ruleStats[i] = &RuleStat{
			ID:       r.ID,
			Name:     r.Name,
			Action:   r.Action,
			HitCount: r.HitCount,
			LastHit:  lastHit,
			Priority: int32(r.Priority),
		}
	}

	return &GetRuleStatsResponse{
		Rules:      ruleStats,
		TotalCount: int32(s.deps.RuleManager.GetRuleCount()),
	}, nil
}

// GetTopBlockedDomains returns top blocked domains by count.
func (s *Server) GetTopBlockedDomains(ctx context.Context, req *GetTopBlockedDomainsRequest) (*GetTopBlockedDomainsResponse, error) {
	limit := int32(10)
	if req != nil && req.Limit > 0 {
		limit = req.Limit
	}

	// Get from blocked domains tracker if available
	domains := getTopBlockedDomains(int(limit))

	return &GetTopBlockedDomainsResponse{
		Domains: domains,
	}, nil
}

// ============================================================================
// Blocked Domains Tracker
// ============================================================================

// BlockedDomainTracker tracks blocked domains for statistics.
type BlockedDomainTracker struct {
	mu      sync.RWMutex
	domains map[string]*blockedDomainEntry
	maxSize int
}

type blockedDomainEntry struct {
	Domain      string
	Count       uint64
	RuleID      string
	LastBlocked time.Time
}

var (
	globalBlockedDomains     *BlockedDomainTracker
	globalBlockedDomainsOnce sync.Once
)

// GetBlockedDomainTracker returns the global blocked domain tracker.
func GetBlockedDomainTracker() *BlockedDomainTracker {
	globalBlockedDomainsOnce.Do(func() {
		globalBlockedDomains = &BlockedDomainTracker{
			domains: make(map[string]*blockedDomainEntry),
			maxSize: 10000,
		}
	})
	return globalBlockedDomains
}

// RecordBlock records a blocked domain.
func (t *BlockedDomainTracker) RecordBlock(domain, ruleID string) {
	t.mu.Lock()
	defer t.mu.Unlock()

	entry, exists := t.domains[domain]
	if exists {
		entry.Count++
		entry.LastBlocked = time.Now()
		if ruleID != "" {
			entry.RuleID = ruleID
		}
	} else {
		// Check size limit
		if len(t.domains) >= t.maxSize {
			// Remove least recently blocked
			t.evictOldest()
		}

		t.domains[domain] = &blockedDomainEntry{
			Domain:      domain,
			Count:       1,
			RuleID:      ruleID,
			LastBlocked: time.Now(),
		}
	}
}

// evictOldest removes the oldest entry (must be called with lock held).
func (t *BlockedDomainTracker) evictOldest() {
	var oldestDomain string
	var oldestTime time.Time

	for domain, entry := range t.domains {
		if oldestDomain == "" || entry.LastBlocked.Before(oldestTime) {
			oldestDomain = domain
			oldestTime = entry.LastBlocked
		}
	}

	if oldestDomain != "" {
		delete(t.domains, oldestDomain)
	}
}

// GetTopDomains returns top N blocked domains.
func (t *BlockedDomainTracker) GetTopDomains(limit int) []*BlockedDomain {
	t.mu.RLock()
	defer t.mu.RUnlock()

	// Collect all entries
	entries := make([]*blockedDomainEntry, 0, len(t.domains))
	for _, entry := range t.domains {
		entries = append(entries, entry)
	}

	// Sort by count (descending)
	sort.Slice(entries, func(i, j int) bool {
		return entries[i].Count > entries[j].Count
	})

	// Apply limit
	if limit > len(entries) {
		limit = len(entries)
	}

	// Convert to response type
	result := make([]*BlockedDomain, limit)
	for i := 0; i < limit; i++ {
		result[i] = &BlockedDomain{
			Domain:      entries[i].Domain,
			BlockCount:  entries[i].Count,
			RuleID:      entries[i].RuleID,
			LastBlocked: timestamppb.New(entries[i].LastBlocked),
		}
	}

	return result
}

// getTopBlockedDomains is a helper to get top blocked domains.
func getTopBlockedDomains(limit int) []*BlockedDomain {
	return GetBlockedDomainTracker().GetTopDomains(limit)
}

// ============================================================================
// Placeholder types (will be replaced by generated proto code)
// ============================================================================

// LatencyStats holds latency percentiles.
type LatencyStats struct {
	P50Seconds float64
	P95Seconds float64
	P99Seconds float64
	AvgSeconds float64
	MaxSeconds float64
	MinSeconds float64
}

// RuleStat holds per-rule statistics.
type RuleStat struct {
	ID                string
	Name              string
	Action            string
	HitCount          uint64
	LastHit           *timestamppb.Timestamp
	AvgLatencySeconds float64
	Priority          int32
}

// BlockedDomain holds blocked domain info.
type BlockedDomain struct {
	Domain      string
	BlockCount  uint64
	RuleID      string
	LastBlocked *timestamppb.Timestamp
}
