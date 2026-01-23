// Package cache provides high-performance verdict caching for the firewall engine.
package cache

import (
	"context"
	"errors"
	"fmt"
	"log"
	"net"
	"regexp"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"firewall_engine/pkg/models"
)

// ============================================================================
// Error Definitions
// ============================================================================

var (
	// ErrInvalidatorClosed is returned when operations are attempted on a closed invalidator.
	ErrInvalidatorClosed = errors.New("invalidator is closed")

	// ErrInvalidPattern is returned when a regex pattern is invalid.
	ErrInvalidPattern = errors.New("invalid invalidation pattern")

	// ErrInvalidationFailed is returned when invalidation fails.
	ErrInvalidationFailed = errors.New("invalidation failed")

	// ErrNoCache is returned when no cache is configured.
	ErrNoCache = errors.New("no cache configured")

	// ErrHookNotFound is returned when a hook is not found.
	ErrHookNotFound = errors.New("hook not found")
)

// ============================================================================
// Invalidation Manager
// ============================================================================

// InvalidationManager handles cache invalidation strategies and hot-reload hooks.
// It provides multiple ways to invalidate cache entries and integrates with
// rule hot-reload for automatic cache clearing.
//
// Invalidation Strategies:
//   - Full Invalidation: Clear entire cache (safest, but cold-start)
//   - Selective by IP: Clear entries matching IP (minimal disruption)
//   - Selective by Rule: Clear entries matched by specific rule
//   - Selective by Pattern: Clear entries matching regex pattern
//   - Expired Only: Clear only expired entries
type InvalidationManager struct {
	// Configuration
	config *InvalidationConfig

	// Cache reference
	cache *VerdictCache

	// Hot-reload hooks
	hooks   map[string]InvalidationHook
	hooksMu sync.RWMutex

	// Event listeners
	listeners   []InvalidationListener
	listenersMu sync.RWMutex

	// Statistics
	stats *InvalidationStats

	// Logging
	logger *log.Logger

	// Lifecycle
	closed    atomic.Bool
	closeMu   sync.Mutex
	closeOnce sync.Once
}

// InvalidationConfig contains configuration for the invalidation manager.
type InvalidationConfig struct {
	// DefaultStrategy is the default invalidation strategy.
	DefaultStrategy InvalidationStrategy `json:"default_strategy" toml:"default_strategy"`

	// LogInvalidations enables logging of invalidation events.
	LogInvalidations bool `json:"log_invalidations" toml:"log_invalidations"`

	// AsyncInvalidation performs invalidation asynchronously.
	AsyncInvalidation bool `json:"async_invalidation" toml:"async_invalidation"`

	// InvalidationTimeout is the timeout for invalidation operations.
	InvalidationTimeout time.Duration `json:"invalidation_timeout" toml:"invalidation_timeout"`

	// MaxConcurrentInvalidations limits concurrent selective invalidations.
	MaxConcurrentInvalidations int `json:"max_concurrent_invalidations" toml:"max_concurrent_invalidations"`

	// EnableHotReloadHook enables automatic invalidation on rule hot-reload.
	EnableHotReloadHook bool `json:"enable_hot_reload_hook" toml:"enable_hot_reload_hook"`
}

// DefaultInvalidationConfig returns the default configuration.
func DefaultInvalidationConfig() *InvalidationConfig {
	return &InvalidationConfig{
		DefaultStrategy:            InvalidateAll,
		LogInvalidations:           true,
		AsyncInvalidation:          false,
		InvalidationTimeout:        10 * time.Second,
		MaxConcurrentInvalidations: 4,
		EnableHotReloadHook:        true,
	}
}

// InvalidationHook is called when cache invalidation is needed.
type InvalidationHook func(ctx context.Context, event *InvalidationEvent) error

// InvalidationListener receives invalidation events.
type InvalidationListener func(event *InvalidationEvent)

// InvalidationEvent contains information about an invalidation event.
type InvalidationEvent struct {
	// Type is the type of invalidation event.
	Type InvalidationEventType `json:"type"`

	// Strategy is the strategy used.
	Strategy InvalidationStrategy `json:"strategy"`

	// Params contains invalidation parameters.
	Params *InvalidationParams `json:"params,omitempty"`

	// EntriesInvalidated is the number of entries removed.
	EntriesInvalidated int `json:"entries_invalidated"`

	// Duration is how long the invalidation took.
	Duration time.Duration `json:"duration"`

	// Timestamp is when the invalidation occurred.
	Timestamp time.Time `json:"timestamp"`

	// Source describes what triggered the invalidation.
	Source string `json:"source,omitempty"`

	// Error contains any error that occurred.
	Error error `json:"error,omitempty"`
}

// InvalidationEventType identifies the type of invalidation event.
type InvalidationEventType int

const (
	// EventTypeManual is a manually triggered invalidation.
	EventTypeManual InvalidationEventType = iota

	// EventTypeHotReload is triggered by rule hot-reload.
	EventTypeHotReload

	// EventTypeTTLExpiry is triggered by TTL expiration.
	EventTypeTTLExpiry

	// EventTypeRuleChange is triggered by a rule change.
	EventTypeRuleChange

	// EventTypeEmergency is an emergency invalidation.
	EventTypeEmergency
)

// String returns the event type name.
func (t InvalidationEventType) String() string {
	switch t {
	case EventTypeManual:
		return "MANUAL"
	case EventTypeHotReload:
		return "HOT_RELOAD"
	case EventTypeTTLExpiry:
		return "TTL_EXPIRY"
	case EventTypeRuleChange:
		return "RULE_CHANGE"
	case EventTypeEmergency:
		return "EMERGENCY"
	default:
		return "UNKNOWN"
	}
}

// InvalidationStats contains invalidation statistics.
type InvalidationStats struct {
	TotalInvalidations      atomic.Uint64 `json:"total_invalidations"`
	FullInvalidations       atomic.Uint64 `json:"full_invalidations"`
	SelectiveInvalidations  atomic.Uint64 `json:"selective_invalidations"`
	HotReloadInvalidations  atomic.Uint64 `json:"hot_reload_invalidations"`
	FailedInvalidations     atomic.Uint64 `json:"failed_invalidations"`
	TotalEntriesInvalidated atomic.Uint64 `json:"total_entries_invalidated"`
	TotalDurationNs         atomic.Uint64 `json:"total_duration_ns"`
}

// ============================================================================
// Constructor
// ============================================================================

// NewInvalidationManager creates a new invalidation manager.
func NewInvalidationManager(config *InvalidationConfig, cache *VerdictCache) (*InvalidationManager, error) {
	if config == nil {
		config = DefaultInvalidationConfig()
	}

	if cache == nil {
		return nil, ErrNoCache
	}

	return &InvalidationManager{
		config:    config,
		cache:     cache,
		hooks:     make(map[string]InvalidationHook),
		listeners: make([]InvalidationListener, 0),
		stats:     &InvalidationStats{},
		logger:    log.New(log.Writer(), "[INVALIDATOR] ", log.LstdFlags|log.Lmicroseconds),
	}, nil
}

// ============================================================================
// Invalidation Methods
// ============================================================================

// InvalidateAll clears the entire cache.
func (m *InvalidationManager) InvalidateAll(source string) (*InvalidationEvent, error) {
	return m.invalidate(InvalidateAll, nil, source)
}

// InvalidateByIP clears entries matching the IP (source or destination).
func (m *InvalidationManager) InvalidateByIP(ip string, source string) (*InvalidationEvent, error) {
	// Validate IP
	if net.ParseIP(ip) == nil {
		return nil, fmt.Errorf("%w: invalid IP %s", ErrInvalidPattern, ip)
	}

	params := &InvalidationParams{IP: ip}
	return m.invalidate(InvalidateByIP, params, source)
}

// InvalidateBySrcIP clears entries with matching source IP.
func (m *InvalidationManager) InvalidateBySrcIP(ip string, source string) (*InvalidationEvent, error) {
	if net.ParseIP(ip) == nil {
		return nil, fmt.Errorf("%w: invalid IP %s", ErrInvalidPattern, ip)
	}

	params := &InvalidationParams{IP: ip}
	return m.invalidate(InvalidateBySrcIP, params, source)
}

// InvalidateByDstIP clears entries with matching destination IP.
func (m *InvalidationManager) InvalidateByDstIP(ip string, source string) (*InvalidationEvent, error) {
	if net.ParseIP(ip) == nil {
		return nil, fmt.Errorf("%w: invalid IP %s", ErrInvalidPattern, ip)
	}

	params := &InvalidationParams{IP: ip}
	return m.invalidate(InvalidateByDstIP, params, source)
}

// InvalidateByRuleID clears entries matched by the rule ID.
func (m *InvalidationManager) InvalidateByRuleID(ruleID string, source string) (*InvalidationEvent, error) {
	if ruleID == "" {
		return nil, fmt.Errorf("%w: rule ID is empty", ErrInvalidPattern)
	}

	params := &InvalidationParams{RuleID: ruleID}
	return m.invalidate(InvalidateByRuleID, params, source)
}

// InvalidateByRuleName clears entries matched by rule name.
func (m *InvalidationManager) InvalidateByRuleName(ruleName string, source string) (*InvalidationEvent, error) {
	if ruleName == "" {
		return nil, fmt.Errorf("%w: rule name is empty", ErrInvalidPattern)
	}

	params := &InvalidationParams{RuleName: ruleName}
	return m.invalidate(InvalidateByRuleName, params, source)
}

// InvalidateByVerdict clears entries with the specified verdict.
func (m *InvalidationManager) InvalidateByVerdict(verdict models.Verdict, source string) (*InvalidationEvent, error) {
	params := &InvalidationParams{Verdict: verdict}
	return m.invalidate(InvalidateByVerdict, params, source)
}

// InvalidateExpired clears only expired entries.
func (m *InvalidationManager) InvalidateExpired(source string) (*InvalidationEvent, error) {
	return m.invalidate(InvalidateExpired, nil, source)
}

// InvalidateByPattern clears entries matching a regex pattern.
func (m *InvalidationManager) InvalidateByPattern(pattern string, source string) (*InvalidationEvent, error) {
	// Compile regex to validate
	re, err := regexp.Compile(pattern)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrInvalidPattern, err)
	}

	return m.invalidateByPattern(re, source)
}

// InvalidateByCIDR clears entries matching a CIDR range.
func (m *InvalidationManager) InvalidateByCIDR(cidr string, source string) (*InvalidationEvent, error) {
	_, ipnet, err := net.ParseCIDR(cidr)
	if err != nil {
		return nil, fmt.Errorf("%w: invalid CIDR %s: %v", ErrInvalidPattern, cidr, err)
	}

	return m.invalidateByCIDR(ipnet, source)
}

// ============================================================================
// Internal Invalidation
// ============================================================================

// invalidate performs the actual invalidation.
func (m *InvalidationManager) invalidate(strategy InvalidationStrategy, params *InvalidationParams, source string) (*InvalidationEvent, error) {
	if m.closed.Load() {
		return nil, ErrInvalidatorClosed
	}

	startTime := time.Now()

	// Perform invalidation
	count := m.cache.Invalidate(strategy, params)

	duration := time.Since(startTime)

	// Create event
	event := &InvalidationEvent{
		Type:               EventTypeManual,
		Strategy:           strategy,
		Params:             params,
		EntriesInvalidated: count,
		Duration:           duration,
		Timestamp:          startTime,
		Source:             source,
	}

	// Update stats
	m.stats.TotalInvalidations.Add(1)
	m.stats.TotalEntriesInvalidated.Add(uint64(count))
	m.stats.TotalDurationNs.Add(uint64(duration.Nanoseconds()))

	if strategy == InvalidateAll {
		m.stats.FullInvalidations.Add(1)
	} else {
		m.stats.SelectiveInvalidations.Add(1)
	}

	// Log if enabled
	if m.config.LogInvalidations {
		m.logger.Printf("Invalidation: strategy=%s, entries=%d, duration=%v, source=%s",
			strategy, count, duration, source)
	}

	// Notify listeners
	m.notifyListeners(event)

	return event, nil
}

// invalidateByPattern performs pattern-based invalidation.
func (m *InvalidationManager) invalidateByPattern(pattern *regexp.Regexp, source string) (*InvalidationEvent, error) {
	if m.closed.Load() {
		return nil, ErrInvalidatorClosed
	}

	startTime := time.Now()

	// Get all keys and filter by pattern
	keys := m.cache.Keys()
	var toInvalidate []string

	for _, key := range keys {
		if pattern.MatchString(key) {
			toInvalidate = append(toInvalidate, key)
		}
	}

	// Remove matching entries
	count := 0
	for _, key := range toInvalidate {
		if m.cache.Delete(key) {
			count++
		}
	}

	duration := time.Since(startTime)

	event := &InvalidationEvent{
		Type:               EventTypeManual,
		Strategy:           InvalidateByIP, // Pattern is a variant
		EntriesInvalidated: count,
		Duration:           duration,
		Timestamp:          startTime,
		Source:             source,
	}

	m.stats.TotalInvalidations.Add(1)
	m.stats.SelectiveInvalidations.Add(1)
	m.stats.TotalEntriesInvalidated.Add(uint64(count))

	if m.config.LogInvalidations {
		m.logger.Printf("Pattern invalidation: pattern=%s, entries=%d, duration=%v",
			pattern.String(), count, duration)
	}

	m.notifyListeners(event)
	return event, nil
}

// invalidateByCIDR performs CIDR-based invalidation.
func (m *InvalidationManager) invalidateByCIDR(ipnet *net.IPNet, source string) (*InvalidationEvent, error) {
	if m.closed.Load() {
		return nil, ErrInvalidatorClosed
	}

	startTime := time.Now()

	// Get all cache entries and check IP containment
	entries := m.cache.lru.Entries()
	count := 0

	for _, entry := range entries {
		// Check source IP
		if entry.SrcIP != "" {
			if ip := net.ParseIP(entry.SrcIP); ip != nil && ipnet.Contains(ip) {
				m.cache.Delete(entry.Key)
				count++
				continue
			}
		}

		// Check destination IP
		if entry.DstIP != "" {
			if ip := net.ParseIP(entry.DstIP); ip != nil && ipnet.Contains(ip) {
				m.cache.Delete(entry.Key)
				count++
			}
		}
	}

	duration := time.Since(startTime)

	event := &InvalidationEvent{
		Type:               EventTypeManual,
		Strategy:           InvalidateByIP,
		EntriesInvalidated: count,
		Duration:           duration,
		Timestamp:          startTime,
		Source:             source,
	}

	m.stats.TotalInvalidations.Add(1)
	m.stats.SelectiveInvalidations.Add(1)
	m.stats.TotalEntriesInvalidated.Add(uint64(count))

	if m.config.LogInvalidations {
		m.logger.Printf("CIDR invalidation: cidr=%s, entries=%d, duration=%v",
			ipnet.String(), count, duration)
	}

	m.notifyListeners(event)
	return event, nil
}

// ============================================================================
// Hot-Reload Integration
// ============================================================================

// RegisterHook registers a named invalidation hook.
func (m *InvalidationManager) RegisterHook(name string, hook InvalidationHook) error {
	if m.closed.Load() {
		return ErrInvalidatorClosed
	}

	m.hooksMu.Lock()
	defer m.hooksMu.Unlock()

	m.hooks[name] = hook
	m.logger.Printf("Registered invalidation hook: %s", name)
	return nil
}

// UnregisterHook removes a named hook.
func (m *InvalidationManager) UnregisterHook(name string) error {
	m.hooksMu.Lock()
	defer m.hooksMu.Unlock()

	if _, ok := m.hooks[name]; !ok {
		return ErrHookNotFound
	}

	delete(m.hooks, name)
	m.logger.Printf("Unregistered invalidation hook: %s", name)
	return nil
}

// OnHotReload is called when rules are hot-reloaded.
// This is the main integration point for rule changes.
func (m *InvalidationManager) OnHotReload(ctx context.Context, changedRules []string) error {
	if m.closed.Load() {
		return ErrInvalidatorClosed
	}

	if !m.config.EnableHotReloadHook {
		return nil
	}

	startTime := time.Now()
	m.logger.Printf("Hot-reload triggered, %d rules changed", len(changedRules))

	// Decide strategy based on number of changed rules
	var event *InvalidationEvent
	var err error

	if len(changedRules) == 0 || len(changedRules) > 10 {
		// Full invalidation for major changes
		event, err = m.InvalidateAll("hot-reload")
	} else {
		// Selective invalidation for minor changes
		totalInvalidated := 0
		for _, ruleID := range changedRules {
			e, _ := m.InvalidateByRuleID(ruleID, "hot-reload")
			if e != nil {
				totalInvalidated += e.EntriesInvalidated
			}
		}
		event = &InvalidationEvent{
			Type:               EventTypeHotReload,
			Strategy:           InvalidateByRuleID,
			EntriesInvalidated: totalInvalidated,
			Duration:           time.Since(startTime),
			Timestamp:          startTime,
			Source:             "hot-reload",
		}
	}

	if err != nil {
		m.stats.FailedInvalidations.Add(1)
		return fmt.Errorf("%w: %v", ErrInvalidationFailed, err)
	}

	m.stats.HotReloadInvalidations.Add(1)

	// Call registered hooks
	m.hooksMu.RLock()
	hooks := make(map[string]InvalidationHook, len(m.hooks))
	for name, hook := range m.hooks {
		hooks[name] = hook
	}
	m.hooksMu.RUnlock()

	for name, hook := range hooks {
		if err := hook(ctx, event); err != nil {
			m.logger.Printf("Hook %s failed: %v", name, err)
		}
	}

	return nil
}

// ============================================================================
// Event Listeners
// ============================================================================

// AddListener adds an invalidation event listener.
func (m *InvalidationManager) AddListener(listener InvalidationListener) {
	m.listenersMu.Lock()
	defer m.listenersMu.Unlock()
	m.listeners = append(m.listeners, listener)
}

// notifyListeners notifies all registered listeners.
func (m *InvalidationManager) notifyListeners(event *InvalidationEvent) {
	m.listenersMu.RLock()
	listeners := make([]InvalidationListener, len(m.listeners))
	copy(listeners, m.listeners)
	m.listenersMu.RUnlock()

	for _, listener := range listeners {
		listener(event)
	}
}

// ============================================================================
// Statistics
// ============================================================================

// GetStats returns invalidation statistics.
func (m *InvalidationManager) GetStats() map[string]uint64 {
	totalInv := m.stats.TotalInvalidations.Load()
	totalDur := m.stats.TotalDurationNs.Load()
	avgDur := uint64(0)
	if totalInv > 0 {
		avgDur = totalDur / totalInv
	}

	return map[string]uint64{
		"total_invalidations":       totalInv,
		"full_invalidations":        m.stats.FullInvalidations.Load(),
		"selective_invalidations":   m.stats.SelectiveInvalidations.Load(),
		"hot_reload_invalidations":  m.stats.HotReloadInvalidations.Load(),
		"failed_invalidations":      m.stats.FailedInvalidations.Load(),
		"total_entries_invalidated": m.stats.TotalEntriesInvalidated.Load(),
		"avg_invalidation_time_ns":  avgDur,
	}
}

// ============================================================================
// Lifecycle
// ============================================================================

// Close shuts down the invalidation manager.
func (m *InvalidationManager) Close() error {
	m.closeOnce.Do(func() {
		m.closeMu.Lock()
		defer m.closeMu.Unlock()

		m.closed.Store(true)

		// Log final stats
		stats := m.GetStats()
		m.logger.Printf("Invalidation manager closed. Stats: total=%d, full=%d, selective=%d, entries=%d",
			stats["total_invalidations"],
			stats["full_invalidations"],
			stats["selective_invalidations"],
			stats["total_entries_invalidated"],
		)
	})

	return nil
}

// SetLogger sets a custom logger.
func (m *InvalidationManager) SetLogger(logger *log.Logger) {
	if logger != nil {
		m.logger = logger
	}
}

// ============================================================================
// Helpers
// ============================================================================

// ParseCacheKeyIP extracts IP addresses from a cache key.
// Key format: protocol:srcIP:srcPort-dstIP:dstPort
func ParseCacheKeyIP(key string) (srcIP, dstIP string) {
	parts := strings.Split(key, "-")
	if len(parts) != 2 {
		return "", ""
	}

	// Parse source
	srcParts := strings.Split(parts[0], ":")
	if len(srcParts) >= 2 {
		srcIP = srcParts[1]
	}

	// Parse destination
	dstParts := strings.Split(parts[1], ":")
	if len(dstParts) >= 1 {
		dstIP = dstParts[0]
	}

	return srcIP, dstIP
}
