// Package connection provides stateful connection tracking for the firewall engine.
package connection

import (
	"sync"
	"sync/atomic"
)

// ============================================================================
// Connection Table - High-Performance sync.Map Wrapper
// ============================================================================

// ConnectionTable is a high-performance, thread-safe connection table.
// It uses sync.Map for lock-free reads and provides O(1) lookups.
//
// Design Goals:
//   - Lock-free reads (most common operation)
//   - Minimal lock contention on writes
//   - O(1) lookup by connection key
//   - Capacity limits with LRU eviction
//   - Safe concurrent iteration
type ConnectionTable struct {
	// Primary storage - sync.Map for lock-free reads
	// Key: string (ConnectionKey.Hash()), Value: *ConnectionEntry
	entries sync.Map

	// Count of entries (atomic for thread-safety)
	count atomic.Int64

	// Maximum capacity
	maxCapacity int

	// Eviction tracking (simple counter-based LRU approximation)
	evictionCounter atomic.Uint64
}

// NewConnectionTable creates a new connection table with the given capacity.
func NewConnectionTable(maxCapacity int) *ConnectionTable {
	if maxCapacity < 100 {
		maxCapacity = 100
	}

	return &ConnectionTable{
		maxCapacity: maxCapacity,
	}
}

// ============================================================================
// Core Operations
// ============================================================================

// Add adds a new connection to the table.
// Returns true if added successfully, false if at capacity.
func (t *ConnectionTable) Add(key ConnectionKey, entry *ConnectionEntry) bool {
	hash := key.Hash()

	// Check if already exists
	if _, exists := t.entries.Load(hash); exists {
		// Update existing
		t.entries.Store(hash, entry)
		return true
	}

	// Check capacity
	if t.count.Load() >= int64(t.maxCapacity) {
		return false
	}

	// Add new entry
	t.entries.Store(hash, entry)
	t.count.Add(1)

	return true
}

// Get retrieves a connection by key.
func (t *ConnectionTable) Get(key ConnectionKey) (*ConnectionEntry, bool) {
	hash := key.Hash()

	if val, exists := t.entries.Load(hash); exists {
		entry := val.(*ConnectionEntry)

		// Don't return marked-for-deletion entries
		if entry.IsMarkedForDeletion() {
			return nil, false
		}

		return entry, true
	}

	return nil, false
}

// GetOrCreate retrieves an existing connection or creates a new one.
func (t *ConnectionTable) GetOrCreate(key ConnectionKey, createFn func() *ConnectionEntry) (*ConnectionEntry, bool) {
	hash := key.Hash()

	// Fast path: check if exists
	if val, exists := t.entries.Load(hash); exists {
		entry := val.(*ConnectionEntry)
		if !entry.IsMarkedForDeletion() {
			return entry, false // existed
		}
	}

	// Slow path: need to create
	// Check capacity before creating
	if t.count.Load() >= int64(t.maxCapacity) {
		return nil, false
	}

	// Create new entry
	entry := createFn()

	// Use LoadOrStore for atomic creation
	actual, loaded := t.entries.LoadOrStore(hash, entry)
	if loaded {
		// Someone beat us to it
		return actual.(*ConnectionEntry), false
	}

	// We added it
	t.count.Add(1)
	return entry, true
}

// Delete removes a connection from the table.
func (t *ConnectionTable) Delete(key ConnectionKey) bool {
	hash := key.Hash()

	if _, exists := t.entries.LoadAndDelete(hash); exists {
		t.count.Add(-1)
		return true
	}

	return false
}

// ============================================================================
// Bulk Operations
// ============================================================================

// Range iterates over all connections in the table.
// The callback should return true to continue iteration, false to stop.
func (t *ConnectionTable) Range(fn func(key ConnectionKey, entry *ConnectionEntry) bool) {
	t.entries.Range(func(k, v interface{}) bool {
		entry := v.(*ConnectionEntry)
		return fn(entry.Key, entry)
	})
}

// DeleteIf deletes all connections matching the predicate.
// Returns the number of connections deleted.
func (t *ConnectionTable) DeleteIf(predicate func(key ConnectionKey, entry *ConnectionEntry) bool) int {
	deleted := 0

	var toDelete []string

	t.entries.Range(func(k, v interface{}) bool {
		hash := k.(string)
		entry := v.(*ConnectionEntry)

		if predicate(entry.Key, entry) {
			toDelete = append(toDelete, hash)
		}
		return true
	})

	for _, hash := range toDelete {
		if _, existed := t.entries.LoadAndDelete(hash); existed {
			t.count.Add(-1)
			deleted++
		}
	}

	return deleted
}

// Clear removes all connections from the table.
func (t *ConnectionTable) Clear() {
	// Create new empty map to replace existing
	t.entries = sync.Map{}
	t.count.Store(0)
}

// ============================================================================
// Statistics
// ============================================================================

// Count returns the number of connections in the table.
func (t *ConnectionTable) Count() int {
	return int(t.count.Load())
}

// Capacity returns the maximum capacity of the table.
func (t *ConnectionTable) Capacity() int {
	return t.maxCapacity
}

// IsFull returns true if the table is at capacity.
func (t *ConnectionTable) IsFull() bool {
	return t.count.Load() >= int64(t.maxCapacity)
}

// Utilization returns the table utilization as a percentage (0-100).
func (t *ConnectionTable) Utilization() float64 {
	if t.maxCapacity == 0 {
		return 0
	}
	return float64(t.count.Load()) / float64(t.maxCapacity) * 100
}

// ============================================================================
// Eviction
// ============================================================================

// EvictOldest removes the N oldest connections.
// Uses a simple counter-based LRU approximation.
func (t *ConnectionTable) EvictOldest(n int) int {
	if n <= 0 {
		return 0
	}

	type candidate struct {
		hash     string
		lastSeen int64
	}

	var candidates []candidate

	// Collect all entries with their last-seen timestamps
	t.entries.Range(func(k, v interface{}) bool {
		hash := k.(string)
		entry := v.(*ConnectionEntry)

		entry.mu.RLock()
		lastSeen := entry.LastSeen.UnixNano()
		entry.mu.RUnlock()

		candidates = append(candidates, candidate{hash: hash, lastSeen: lastSeen})
		return true
	})

	// Sort by last seen (oldest first) - simple selection sort for small n
	for i := 0; i < len(candidates) && i < n; i++ {
		oldest := i
		for j := i + 1; j < len(candidates); j++ {
			if candidates[j].lastSeen < candidates[oldest].lastSeen {
				oldest = j
			}
		}
		candidates[i], candidates[oldest] = candidates[oldest], candidates[i]
	}

	// Delete oldest n
	evicted := 0
	for i := 0; i < len(candidates) && evicted < n; i++ {
		if _, existed := t.entries.LoadAndDelete(candidates[i].hash); existed {
			t.count.Add(-1)
			evicted++
		}
	}

	return evicted
}

// EvictExpired removes all expired connections.
func (t *ConnectionTable) EvictExpired() int {
	return t.DeleteIf(func(key ConnectionKey, entry *ConnectionEntry) bool {
		return entry.IsExpired()
	})
}

// EvictMarked removes all connections marked for deletion.
func (t *ConnectionTable) EvictMarked() int {
	return t.DeleteIf(func(key ConnectionKey, entry *ConnectionEntry) bool {
		return entry.IsMarkedForDeletion()
	})
}

// ============================================================================
// Lookup Helpers
// ============================================================================

// Contains returns true if the key exists in the table.
func (t *ConnectionTable) Contains(key ConnectionKey) bool {
	_, exists := t.Get(key)
	return exists
}

// Keys returns all connection keys in the table.
func (t *ConnectionTable) Keys() []ConnectionKey {
	var keys []ConnectionKey

	t.entries.Range(func(k, v interface{}) bool {
		entry := v.(*ConnectionEntry)
		keys = append(keys, entry.Key)
		return true
	})

	return keys
}

// Entries returns all connection entries in the table.
func (t *ConnectionTable) Entries() []*ConnectionEntry {
	var entries []*ConnectionEntry

	t.entries.Range(func(k, v interface{}) bool {
		entry := v.(*ConnectionEntry)
		if !entry.IsMarkedForDeletion() {
			entries = append(entries, entry)
		}
		return true
	})

	return entries
}

// ============================================================================
// Protocol-Specific Queries
// ============================================================================

// GetByProtocol returns all connections for a specific protocol.
func (t *ConnectionTable) GetByProtocol(protocol uint8) []*ConnectionEntry {
	var entries []*ConnectionEntry

	t.entries.Range(func(k, v interface{}) bool {
		entry := v.(*ConnectionEntry)
		if entry.Key.Protocol == protocol && !entry.IsMarkedForDeletion() {
			entries = append(entries, entry)
		}
		return true
	})

	return entries
}

// CountByProtocol returns the count of connections for a specific protocol.
func (t *ConnectionTable) CountByProtocol(protocol uint8) int {
	count := 0

	t.entries.Range(func(k, v interface{}) bool {
		entry := v.(*ConnectionEntry)
		if entry.Key.Protocol == protocol && !entry.IsMarkedForDeletion() {
			count++
		}
		return true
	})

	return count
}

// GetByState returns all TCP connections in a specific state.
func (t *ConnectionTable) GetByState(state TCPState) []*ConnectionEntry {
	var entries []*ConnectionEntry

	t.entries.Range(func(k, v interface{}) bool {
		entry := v.(*ConnectionEntry)
		if entry.TCPState == state && !entry.IsMarkedForDeletion() {
			entries = append(entries, entry)
		}
		return true
	})

	return entries
}
