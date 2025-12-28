// Package loadbalancer provides multi-WAN load balancing functionality for the NIC Management service.
package loadbalancer

import (
	"context"
	"errors"
	"hash/fnv"
	"sync"
	"sync/atomic"
	"time"
)

// =============================================================================
// Error Types
// =============================================================================

var (
	// ErrSessionNotFound indicates flow not in cache.
	ErrSessionNotFound = errors.New("session not found")
	// ErrNotStickySession indicates attempted to remove non-sticky as sticky.
	ErrNotStickySession = errors.New("not a sticky session")
	// ErrPersistenceQueueFull indicates async queue at capacity.
	ErrPersistenceQueueFull = errors.New("persistence queue full")
	// ErrInvalidHashAlgorithm indicates unknown hash function.
	ErrInvalidHashAlgorithm = errors.New("invalid hash algorithm")
	// ErrImportFailed indicates session import validation failed.
	ErrImportFailed = errors.New("session import failed")
)

// =============================================================================
// Session Binding
// =============================================================================

// SessionBinding represents a flow-to-WAN binding.
type SessionBinding struct {
	// FlowHash is the flow identifier hash.
	FlowHash uint64 `json:"flow_hash"`
	// FiveTuple is the original flow.
	FiveTuple FiveTuple `json:"five_tuple"`
	// AssignedWAN is the WAN ID for this flow.
	AssignedWAN string `json:"assigned_wan"`
	// CreatedAt is when binding was created.
	CreatedAt time.Time `json:"created_at"`
	// LastHit is the last cache access timestamp.
	LastHit time.Time `json:"last_hit"`
	// HitCount is the total cache hits for this binding.
	HitCount uint64 `json:"hit_count"`
	// ExpiresAt is the TTL expiration timestamp.
	ExpiresAt time.Time `json:"expires_at"`
	// Sticky indicates binding never expires.
	Sticky bool `json:"sticky"`
	// Reason is the binding reason.
	Reason string `json:"reason"`
}

// =============================================================================
// Affinity Statistics
// =============================================================================

// AffinityStatistics contains cache performance metrics.
type AffinityStatistics struct {
	// TotalBindings is total bindings created since startup.
	TotalBindings uint64 `json:"total_bindings"`
	// CurrentBindings is active bindings in cache.
	CurrentBindings int `json:"current_bindings"`
	// CacheHits is total cache hits.
	CacheHits uint64 `json:"cache_hits"`
	// CacheMisses is total cache misses.
	CacheMisses uint64 `json:"cache_misses"`
	// HitRate is cache hit percentage.
	HitRate float64 `json:"hit_rate"`
	// Evictions is total evicted bindings.
	Evictions uint64 `json:"evictions"`
	// ManualInvalidations is total manual cache invalidations.
	ManualInvalidations uint64 `json:"manual_invalidations"`
	// PersistenceQueueDepth is current async queue size.
	PersistenceQueueDepth int `json:"persistence_queue_depth"`
	// AverageLookupLatency is mean lookup time.
	AverageLookupLatency time.Duration `json:"average_lookup_latency"`
	// LastEviction is when last eviction occurred.
	LastEviction time.Time `json:"last_eviction"`
	// LastPersistence is when last batch persisted.
	LastPersistence time.Time `json:"last_persistence"`
}

// =============================================================================
// Affinity Configuration
// =============================================================================

// AffinityConfig contains configuration for session affinity.
type AffinityConfig struct {
	// CacheCapacity is max cached sessions.
	CacheCapacity int `json:"cache_capacity"`
	// SessionTTL is session expiration time.
	SessionTTL time.Duration `json:"session_ttl"`
	// EnablePersistence saves sessions to database.
	EnablePersistence bool `json:"enable_persistence"`
	// PersistenceInterval is batch persistence frequency.
	PersistenceInterval time.Duration `json:"persistence_interval"`
	// PersistenceQueueSize is async queue capacity.
	PersistenceQueueSize int `json:"persistence_queue_size"`
	// EnableStickySourceIP pins source IP to WAN.
	EnableStickySourceIP bool `json:"enable_sticky_source_ip"`
	// EnableStickyDestination pins destination IP to WAN.
	EnableStickyDestination bool `json:"enable_sticky_destination"`
	// HashAlgorithm is the hash function (fnv64, xxhash, murmur3).
	HashAlgorithm string `json:"hash_algorithm"`
	// EvictionPolicy is cache eviction policy (lru, lfu).
	EvictionPolicy string `json:"eviction_policy"`
	// ExtendTTLOnHit resets TTL on cache hit.
	ExtendTTLOnHit bool `json:"extend_ttl_on_hit"`
}

// DefaultAffinityConfig returns the default configuration.
func DefaultAffinityConfig() *AffinityConfig {
	return &AffinityConfig{
		CacheCapacity:           100000,
		SessionTTL:              300 * time.Second,
		EnablePersistence:       true,
		PersistenceInterval:     30 * time.Second,
		PersistenceQueueSize:    10000,
		EnableStickySourceIP:    true,
		EnableStickyDestination: false,
		HashAlgorithm:           "fnv64",
		EvictionPolicy:          "lru",
		ExtendTTLOnHit:          true,
	}
}

// =============================================================================
// Database Interface
// =============================================================================

// AffinityDB defines the database interface for session persistence.
type AffinityDB interface {
	// LoadSessions loads active sessions from database.
	LoadSessions(ctx context.Context) ([]*SessionBinding, error)
	// SaveSessions saves sessions to database.
	SaveSessions(ctx context.Context, sessions []*SessionBinding) error
	// DeleteSession removes a session from database.
	DeleteSession(ctx context.Context, flowHash uint64) error
	// DeleteWANSessions removes all sessions for a WAN.
	DeleteWANSessions(ctx context.Context, wanID string) error
	// ClearAllSessions removes all sessions.
	ClearAllSessions(ctx context.Context) error
}

// =============================================================================
// No-Op Database
// =============================================================================

type noOpAffinityDB struct{}

func (n *noOpAffinityDB) LoadSessions(ctx context.Context) ([]*SessionBinding, error) {
	return nil, nil
}

func (n *noOpAffinityDB) SaveSessions(ctx context.Context, sessions []*SessionBinding) error {
	return nil
}

func (n *noOpAffinityDB) DeleteSession(ctx context.Context, flowHash uint64) error {
	return nil
}

func (n *noOpAffinityDB) DeleteWANSessions(ctx context.Context, wanID string) error {
	return nil
}

func (n *noOpAffinityDB) ClearAllSessions(ctx context.Context) error {
	return nil
}

// =============================================================================
// Session Affinity Manager
// =============================================================================

// SessionAffinityManager manages session-to-WAN mappings.
type SessionAffinityManager struct {
	// Cache storage (key: flowHash, value: binding).
	cache map[uint64]*SessionBinding
	// Database for persistence.
	db AffinityDB
	// Configuration.
	config *AffinityConfig
	// Protects cache.
	mu sync.RWMutex
	// Statistics counters.
	totalBindings       uint64
	cacheHits           uint64
	cacheMisses         uint64
	evictions           uint64
	manualInvalidations uint64
	stickySessionsCount int64
	lookupLatencySum    int64
	lookupLatencyCount  int64
	lastEviction        time.Time
	lastPersistence     time.Time
	// Persistence queue.
	persistQueue chan *SessionBinding
	// Control.
	stopChan  chan struct{}
	wg        sync.WaitGroup
	running   bool
	runningMu sync.Mutex
}

// NewSessionAffinityManager creates a new session affinity manager.
func NewSessionAffinityManager(db AffinityDB, config *AffinityConfig) *SessionAffinityManager {
	if config == nil {
		config = DefaultAffinityConfig()
	}

	if db == nil {
		db = &noOpAffinityDB{}
	}

	return &SessionAffinityManager{
		cache:        make(map[uint64]*SessionBinding, config.CacheCapacity),
		db:           db,
		config:       config,
		persistQueue: make(chan *SessionBinding, config.PersistenceQueueSize),
		stopChan:     make(chan struct{}),
	}
}

// =============================================================================
// Lifecycle Management
// =============================================================================

// Start starts the session affinity manager.
func (sam *SessionAffinityManager) Start(ctx context.Context) error {
	sam.runningMu.Lock()
	defer sam.runningMu.Unlock()

	if sam.running {
		return nil
	}

	// Load persisted sessions.
	if sam.config.EnablePersistence {
		sessions, _ := sam.db.LoadSessions(ctx)
		now := time.Now()
		for _, session := range sessions {
			// Skip expired sessions.
			if !session.ExpiresAt.IsZero() && session.ExpiresAt.Before(now) {
				continue
			}
			sam.cache[session.FlowHash] = session
		}
	}

	// Start persistence worker.
	if sam.config.EnablePersistence {
		sam.wg.Add(1)
		go sam.persistenceWorker()
	}

	// Start statistics updater.
	sam.wg.Add(1)
	go sam.statsLoop()

	// Start eviction checker.
	sam.wg.Add(1)
	go sam.evictionLoop()

	sam.running = true
	return nil
}

// Stop stops the session affinity manager.
func (sam *SessionAffinityManager) Stop() error {
	sam.runningMu.Lock()
	if !sam.running {
		sam.runningMu.Unlock()
		return nil
	}
	sam.running = false
	sam.runningMu.Unlock()

	close(sam.stopChan)
	sam.wg.Wait()

	// Final persistence.
	if sam.config.EnablePersistence {
		sam.persistAllSessions()
	}

	return nil
}

// =============================================================================
// Background Loops
// =============================================================================

// persistenceWorker handles async persistence.
func (sam *SessionAffinityManager) persistenceWorker() {
	defer sam.wg.Done()

	batch := make([]*SessionBinding, 0, 1000)
	ticker := time.NewTicker(sam.config.PersistenceInterval)
	defer ticker.Stop()

	for {
		select {
		case <-sam.stopChan:
			// Drain queue.
			sam.drainPersistQueue(batch)
			return
		case session := <-sam.persistQueue:
			batch = append(batch, session)
			if len(batch) >= 1000 {
				sam.persistBatch(batch)
				batch = batch[:0]
			}
		case <-ticker.C:
			if len(batch) > 0 {
				sam.persistBatch(batch)
				batch = batch[:0]
			}
		}
	}
}

// persistBatch saves a batch of sessions.
func (sam *SessionAffinityManager) persistBatch(batch []*SessionBinding) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	_ = sam.db.SaveSessions(ctx, batch)
	sam.lastPersistence = time.Now()
}

// drainPersistQueue drains remaining items from queue.
func (sam *SessionAffinityManager) drainPersistQueue(batch []*SessionBinding) {
	for {
		select {
		case session := <-sam.persistQueue:
			batch = append(batch, session)
			if len(batch) >= 1000 {
				sam.persistBatch(batch)
				batch = batch[:0]
			}
		default:
			if len(batch) > 0 {
				sam.persistBatch(batch)
			}
			return
		}
	}
}

// persistAllSessions saves all sessions.
func (sam *SessionAffinityManager) persistAllSessions() {
	sam.mu.RLock()
	sessions := make([]*SessionBinding, 0, len(sam.cache))
	for _, session := range sam.cache {
		copy := *session
		sessions = append(sessions, &copy)
	}
	sam.mu.RUnlock()

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	_ = sam.db.SaveSessions(ctx, sessions)
	sam.lastPersistence = time.Now()
}

// statsLoop periodically updates statistics.
func (sam *SessionAffinityManager) statsLoop() {
	defer sam.wg.Done()

	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-sam.stopChan:
			return
		case <-ticker.C:
			// Stats are calculated on-demand in GetStatistics().
		}
	}
}

// evictionLoop periodically checks for expired sessions.
func (sam *SessionAffinityManager) evictionLoop() {
	defer sam.wg.Done()

	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-sam.stopChan:
			return
		case <-ticker.C:
			sam.evictExpired()
		}
	}
}

// evictExpired removes expired sessions.
func (sam *SessionAffinityManager) evictExpired() {
	now := time.Now()
	expired := make([]uint64, 0)

	sam.mu.RLock()
	for hash, session := range sam.cache {
		if session.Sticky {
			continue // Never evict sticky sessions.
		}
		if !session.ExpiresAt.IsZero() && session.ExpiresAt.Before(now) {
			expired = append(expired, hash)
		}
	}
	sam.mu.RUnlock()

	if len(expired) == 0 {
		return
	}

	sam.mu.Lock()
	for _, hash := range expired {
		delete(sam.cache, hash)
	}
	sam.mu.Unlock()

	atomic.AddUint64(&sam.evictions, uint64(len(expired)))
	sam.lastEviction = now
}

// =============================================================================
// Session Lookup
// =============================================================================

// LookupSession looks up a session binding.
func (sam *SessionAffinityManager) LookupSession(flow FiveTuple) (string, bool) {
	start := time.Now()
	defer func() {
		latency := time.Since(start)
		atomic.AddInt64(&sam.lookupLatencySum, int64(latency))
		atomic.AddInt64(&sam.lookupLatencyCount, 1)
	}()

	flowHash := sam.computeFlowHash(flow)

	sam.mu.RLock()
	session, exists := sam.cache[flowHash]
	sam.mu.RUnlock()

	if !exists {
		atomic.AddUint64(&sam.cacheMisses, 1)
		return "", false
	}

	// Check if expired.
	if !session.Sticky && !session.ExpiresAt.IsZero() && session.ExpiresAt.Before(time.Now()) {
		atomic.AddUint64(&sam.cacheMisses, 1)
		return "", false
	}

	// Update hit stats.
	atomic.AddUint64(&sam.cacheHits, 1)

	sam.mu.Lock()
	session.LastHit = time.Now()
	session.HitCount++
	if sam.config.ExtendTTLOnHit && !session.Sticky {
		session.ExpiresAt = time.Now().Add(sam.config.SessionTTL)
	}
	sam.mu.Unlock()

	return session.AssignedWAN, true
}

// =============================================================================
// Session Binding
// =============================================================================

// BindSession creates a new session binding.
func (sam *SessionAffinityManager) BindSession(flow FiveTuple, wanID, reason string) error {
	flowHash := sam.computeFlowHash(flow)
	now := time.Now()

	binding := &SessionBinding{
		FlowHash:    flowHash,
		FiveTuple:   flow,
		AssignedWAN: wanID,
		CreatedAt:   now,
		LastHit:     now,
		HitCount:    0,
		ExpiresAt:   now.Add(sam.config.SessionTTL),
		Sticky:      reason == "MANUAL",
		Reason:      reason,
	}

	// Check capacity and evict if needed.
	sam.mu.Lock()
	if len(sam.cache) >= sam.config.CacheCapacity {
		sam.evictOldest()
	}
	sam.cache[flowHash] = binding
	sam.mu.Unlock()

	atomic.AddUint64(&sam.totalBindings, 1)

	if binding.Sticky {
		atomic.AddInt64(&sam.stickySessionsCount, 1)
	}

	// Queue for persistence (non-blocking).
	if sam.config.EnablePersistence {
		select {
		case sam.persistQueue <- binding:
		default:
			// Queue full, skip persistence.
		}
	}

	return nil
}

// evictOldest removes the oldest non-sticky session.
func (sam *SessionAffinityManager) evictOldest() {
	var oldestHash uint64
	var oldestTime time.Time

	for hash, session := range sam.cache {
		if session.Sticky {
			continue
		}
		if oldestTime.IsZero() || session.LastHit.Before(oldestTime) {
			oldestTime = session.LastHit
			oldestHash = hash
		}
	}

	if oldestHash != 0 {
		delete(sam.cache, oldestHash)
		atomic.AddUint64(&sam.evictions, 1)
		sam.lastEviction = time.Now()
	}
}

// =============================================================================
// Session Invalidation
// =============================================================================

// InvalidateSession removes a session binding.
func (sam *SessionAffinityManager) InvalidateSession(flow FiveTuple) error {
	flowHash := sam.computeFlowHash(flow)

	sam.mu.Lock()
	session, exists := sam.cache[flowHash]
	if !exists {
		sam.mu.Unlock()
		return ErrSessionNotFound
	}

	if session.Sticky {
		atomic.AddInt64(&sam.stickySessionsCount, -1)
	}

	delete(sam.cache, flowHash)
	sam.mu.Unlock()

	atomic.AddUint64(&sam.manualInvalidations, 1)

	// Delete from database.
	if sam.config.EnablePersistence {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = sam.db.DeleteSession(ctx, flowHash)
	}

	return nil
}

// InvalidateWANSessions removes all sessions for a WAN.
func (sam *SessionAffinityManager) InvalidateWANSessions(wanID string) (int, error) {
	toRemove := make([]uint64, 0)

	sam.mu.RLock()
	for hash, session := range sam.cache {
		if session.AssignedWAN == wanID {
			toRemove = append(toRemove, hash)
		}
	}
	sam.mu.RUnlock()

	sam.mu.Lock()
	for _, hash := range toRemove {
		session := sam.cache[hash]
		if session != nil && session.Sticky {
			atomic.AddInt64(&sam.stickySessionsCount, -1)
		}
		delete(sam.cache, hash)
	}
	sam.mu.Unlock()

	atomic.AddUint64(&sam.manualInvalidations, uint64(len(toRemove)))

	// Delete from database.
	if sam.config.EnablePersistence && len(toRemove) > 0 {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		_ = sam.db.DeleteWANSessions(ctx, wanID)
	}

	return len(toRemove), nil
}

// =============================================================================
// Sticky Sessions
// =============================================================================

// CreateStickySession creates a permanent session binding.
func (sam *SessionAffinityManager) CreateStickySession(flow FiveTuple, wanID string) error {
	flowHash := sam.computeFlowHash(flow)
	now := time.Now()

	binding := &SessionBinding{
		FlowHash:    flowHash,
		FiveTuple:   flow,
		AssignedWAN: wanID,
		CreatedAt:   now,
		LastHit:     now,
		HitCount:    0,
		ExpiresAt:   time.Time{}, // Never expires.
		Sticky:      true,
		Reason:      "MANUAL",
	}

	sam.mu.Lock()
	// Check if replacing existing sticky session.
	existing := sam.cache[flowHash]
	if existing != nil && existing.Sticky {
		// Already sticky, just update WAN.
		existing.AssignedWAN = wanID
		sam.mu.Unlock()
	} else {
		if len(sam.cache) >= sam.config.CacheCapacity {
			sam.evictOldest()
		}
		sam.cache[flowHash] = binding
		atomic.AddInt64(&sam.stickySessionsCount, 1)
		sam.mu.Unlock()
	}

	atomic.AddUint64(&sam.totalBindings, 1)

	// Persist immediately.
	if sam.config.EnablePersistence {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = sam.db.SaveSessions(ctx, []*SessionBinding{binding})
	}

	return nil
}

// RemoveStickySession removes a permanent session binding.
func (sam *SessionAffinityManager) RemoveStickySession(flow FiveTuple) error {
	flowHash := sam.computeFlowHash(flow)

	sam.mu.RLock()
	session, exists := sam.cache[flowHash]
	sam.mu.RUnlock()

	if !exists {
		return ErrSessionNotFound
	}

	if !session.Sticky {
		return ErrNotStickySession
	}

	return sam.InvalidateSession(flow)
}

// =============================================================================
// Flow Hash Computation
// =============================================================================

// computeFlowHash computes a deterministic hash from 5-tuple.
func (sam *SessionAffinityManager) computeFlowHash(flow FiveTuple) uint64 {
	// Use standard FNV-64a hash.
	h := fnv.New64a()

	// Normalize for bidirectional flows if needed.
	srcIP := flow.SrcIP
	dstIP := flow.DstIP
	srcPort := flow.SrcPort
	dstPort := flow.DstPort

	// For consistent hashing, ensure srcIP < dstIP.
	if sam.config.EnableStickySourceIP {
		// Keep source-based.
	} else if srcIP > dstIP {
		srcIP, dstIP = dstIP, srcIP
		srcPort, dstPort = dstPort, srcPort
	}

	h.Write([]byte(srcIP))
	h.Write([]byte(dstIP))
	h.Write([]byte{byte(srcPort >> 8), byte(srcPort)})
	h.Write([]byte{byte(dstPort >> 8), byte(dstPort)})
	h.Write([]byte{flow.Protocol})

	return h.Sum64()
}

// =============================================================================
// Query Methods
// =============================================================================

// GetAllSessions returns all active bindings.
func (sam *SessionAffinityManager) GetAllSessions() []*SessionBinding {
	sam.mu.RLock()
	defer sam.mu.RUnlock()

	result := make([]*SessionBinding, 0, len(sam.cache))
	for _, session := range sam.cache {
		copy := *session
		result = append(result, &copy)
	}
	return result
}

// GetSessionsByWAN returns bindings for a WAN.
func (sam *SessionAffinityManager) GetSessionsByWAN(wanID string) []*SessionBinding {
	sam.mu.RLock()
	defer sam.mu.RUnlock()

	result := make([]*SessionBinding, 0)
	for _, session := range sam.cache {
		if session.AssignedWAN == wanID {
			copy := *session
			result = append(result, &copy)
		}
	}
	return result
}

// GetSessionCount returns current cache size.
func (sam *SessionAffinityManager) GetSessionCount() int {
	sam.mu.RLock()
	defer sam.mu.RUnlock()
	return len(sam.cache)
}

// GetStickySessionCount returns sticky session count.
func (sam *SessionAffinityManager) GetStickySessionCount() int64 {
	return atomic.LoadInt64(&sam.stickySessionsCount)
}

// =============================================================================
// Cache Management
// =============================================================================

// ClearAllSessions removes all bindings.
func (sam *SessionAffinityManager) ClearAllSessions() error {
	sam.mu.Lock()
	sam.cache = make(map[uint64]*SessionBinding, sam.config.CacheCapacity)
	sam.mu.Unlock()

	atomic.StoreInt64(&sam.stickySessionsCount, 0)

	if sam.config.EnablePersistence {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		_ = sam.db.ClearAllSessions(ctx)
	}

	return nil
}

// =============================================================================
// Statistics
// =============================================================================

// GetStatistics returns current statistics.
func (sam *SessionAffinityManager) GetStatistics() AffinityStatistics {
	sam.mu.RLock()
	currentBindings := len(sam.cache)
	sam.mu.RUnlock()

	hits := atomic.LoadUint64(&sam.cacheHits)
	misses := atomic.LoadUint64(&sam.cacheMisses)
	var hitRate float64
	if hits+misses > 0 {
		hitRate = float64(hits) / float64(hits+misses) * 100.0
	}

	var avgLookupLatency time.Duration
	count := atomic.LoadInt64(&sam.lookupLatencyCount)
	if count > 0 {
		avgLookupLatency = time.Duration(atomic.LoadInt64(&sam.lookupLatencySum) / count)
	}

	return AffinityStatistics{
		TotalBindings:         atomic.LoadUint64(&sam.totalBindings),
		CurrentBindings:       currentBindings,
		CacheHits:             hits,
		CacheMisses:           misses,
		HitRate:               hitRate,
		Evictions:             atomic.LoadUint64(&sam.evictions),
		ManualInvalidations:   atomic.LoadUint64(&sam.manualInvalidations),
		PersistenceQueueDepth: len(sam.persistQueue),
		AverageLookupLatency:  avgLookupLatency,
		LastEviction:          sam.lastEviction,
		LastPersistence:       sam.lastPersistence,
	}
}

// =============================================================================
// Health Check
// =============================================================================

// HealthCheck verifies the manager is operational.
func (sam *SessionAffinityManager) HealthCheck() error {
	sam.runningMu.Lock()
	running := sam.running
	sam.runningMu.Unlock()

	if !running {
		return errors.New("session affinity manager not running")
	}

	// Check persistence queue not full.
	queueDepth := len(sam.persistQueue)
	queueCapacity := sam.config.PersistenceQueueSize
	if queueDepth >= int(float64(queueCapacity)*0.9) {
		return ErrPersistenceQueueFull
	}

	return nil
}

// =============================================================================
// Utility
// =============================================================================

// GetConfig returns the current configuration.
func (sam *SessionAffinityManager) GetConfig() *AffinityConfig {
	return sam.config
}

// IsRunning returns whether the manager is running.
func (sam *SessionAffinityManager) IsRunning() bool {
	sam.runningMu.Lock()
	defer sam.runningMu.Unlock()
	return sam.running
}
