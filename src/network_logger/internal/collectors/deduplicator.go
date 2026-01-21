package collectors

import (
	"crypto/md5"
	"encoding/hex"
	"sync"
	"time"
)

// DuplicateFilter provides multi-layer deduplication for IDS logs
// Ported from Python's EnhancedDuplicateFilter
type DuplicateFilter struct {
	// Connection cache: flowID -> ConnectionState
	connectionCache map[string]*ConnectionState
	// Per-connection payload hashes to avoid logging duplicate payloads
	payloadHashes map[string]map[string]bool
	mu            sync.RWMutex

	maxCacheSize      int
	suppressSeconds   float64
	connectionTimeout float64
	lastCleanup       time.Time

	stats DedupStats
}

// ConnectionState tracks a connection for deduplication
type ConnectionState struct {
	FirstSeen time.Time
	LastSeen  time.Time
	Count     int64
	AppType   string
}

// DedupStats tracks deduplication statistics
type DedupStats struct {
	TotalPackets       int64
	PayloadDuplicates  int64
	UniqueLogged       int64
	ExpiredConnections int64
}

// NewDuplicateFilter creates a new deduplication filter
func NewDuplicateFilter() *DuplicateFilter {
	return &DuplicateFilter{
		connectionCache:   make(map[string]*ConnectionState),
		payloadHashes:     make(map[string]map[string]bool),
		maxCacheSize:      50000,
		suppressSeconds:   600.0,  // 10 minutes
		connectionTimeout: 1800.0, // 30 minutes
		lastCleanup:       time.Now(),
	}
}

// IsDuplicate checks if an IDS log entry is a duplicate
// Returns (isDuplicate, reason)
func (f *DuplicateFilter) IsDuplicate(log *IDSLog) (bool, string) {
	now := time.Now()
	connKey := f.generateConnectionKey(log)
	payloadHash := f.generatePayloadHash(log)

	if connKey == "" || payloadHash == "" {
		return false, "no_key"
	}

	f.mu.Lock()
	defer f.mu.Unlock()

	f.stats.TotalPackets++

	// Check if payload already seen in this connection
	if hashes, exists := f.payloadHashes[connKey]; exists {
		if hashes[payloadHash] {
			f.stats.PayloadDuplicates++
			return true, "payload_dup"
		}
	}

	// Check connection state
	conn, connExists := f.connectionCache[connKey]

	if connExists {
		elapsed := now.Sub(conn.LastSeen).Seconds()

		if elapsed < f.suppressSeconds {
			// Connection active, check if new payload
			if f.payloadHashes[connKey] == nil {
				f.payloadHashes[connKey] = make(map[string]bool)
			}
			f.payloadHashes[connKey][payloadHash] = true
			conn.LastSeen = now
			conn.Count++
			f.stats.UniqueLogged++
			return false, "unique"
		}

		// Connection expired - reset
		f.stats.ExpiredConnections++
		f.connectionCache[connKey] = &ConnectionState{
			FirstSeen: now,
			LastSeen:  now,
			Count:     1,
			AppType:   log.Protocol,
		}
		f.payloadHashes[connKey] = map[string]bool{payloadHash: true}
		f.stats.UniqueLogged++
		return false, "unique"
	}

	// New connection
	f.connectionCache[connKey] = &ConnectionState{
		FirstSeen: now,
		LastSeen:  now,
		Count:     1,
		AppType:   log.Protocol,
	}
	f.payloadHashes[connKey] = map[string]bool{payloadHash: true}
	f.stats.UniqueLogged++

	// Cleanup if cache too large
	if len(f.connectionCache) > f.maxCacheSize {
		f.cleanupUnsafe(now)
	}

	return false, "unique"
}

// generateConnectionKey creates a normalized 5-tuple key
func (f *DuplicateFilter) generateConnectionKey(log *IDSLog) string {
	// Use same normalization as flow_id for consistency
	return log.FlowID
}

// generatePayloadHash creates a hash of the significant payload
func (f *DuplicateFilter) generatePayloadHash(log *IDSLog) string {
	var parts []string

	// DNS: query + type
	if log.DNS != nil && len(log.DNS.Queries) > 0 {
		for _, q := range log.DNS.Queries {
			parts = append(parts, q.Name, q.Type)
		}
	}

	// HTTP: method + host + uri
	if log.HTTP != nil {
		parts = append(parts, log.HTTP.Method, log.HTTP.Host, log.HTTP.URI)
	}

	// TLS: SNI
	if log.TLS != nil && log.TLS.SNI != "" {
		parts = append(parts, log.TLS.SNI)
	}

	if len(parts) == 0 {
		return ""
	}

	// Generate short hash
	h := md5.New()
	for _, p := range parts {
		h.Write([]byte(p))
	}
	return hex.EncodeToString(h.Sum(nil))[:16]
}

// cleanupUnsafe removes expired connections (must hold lock)
func (f *DuplicateFilter) cleanupUnsafe(now time.Time) {
	cutoff := now.Add(-time.Duration(f.connectionTimeout) * time.Second)

	// Remove expired connections
	for key, conn := range f.connectionCache {
		if conn.LastSeen.Before(cutoff) {
			delete(f.connectionCache, key)
			delete(f.payloadHashes, key)
		}
	}

	// If still too large, remove oldest 20%
	if len(f.connectionCache) > f.maxCacheSize {
		removeCount := len(f.connectionCache) / 5
		removed := 0
		for key := range f.connectionCache {
			delete(f.connectionCache, key)
			delete(f.payloadHashes, key)
			removed++
			if removed >= removeCount {
				break
			}
		}
	}
}

// GetStats returns deduplication statistics
func (f *DuplicateFilter) GetStats() DedupStats {
	f.mu.RLock()
	defer f.mu.RUnlock()
	return f.stats
}
