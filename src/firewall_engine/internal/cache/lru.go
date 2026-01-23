// Package cache provides high-performance verdict caching for the firewall engine.
package cache

import (
	"sync"
)

// ============================================================================
// LRU (Least Recently Used) Cache Implementation
// ============================================================================

// LRU implements a Least Recently Used cache using a doubly-linked list
// and a hash map for O(1) operations.
//
// Data Structure:
//
//	Doubly-Linked List (LRU Order):
//	┌──────────────────────────────────────────────────────────┐
//	│ [Most Recent] ↔ [Entry 2] ↔ ... ↔ [Least Recent]        │
//	│      HEAD                              TAIL              │
//	└──────────────────────────────────────────────────────────┘
//
//	Hash Map (O(1) Lookup):
//	  key → pointer to node in linked list
//
// Operations:
//   - Get: O(1) lookup + move to front
//   - Put: O(1) insert at front + evict tail if full
//   - Remove: O(1) delete from list and map
type LRU struct {
	// Maximum capacity
	capacity int

	// Hash map for O(1) lookup: key → *lruNode
	items map[string]*lruNode

	// Doubly-linked list for LRU ordering
	head *lruNode // Most recently used
	tail *lruNode // Least recently used

	// Thread safety
	mu sync.RWMutex
}

// lruNode represents a node in the doubly-linked list.
type lruNode struct {
	key   string
	entry *CacheEntry
	prev  *lruNode
	next  *lruNode
}

// ============================================================================
// Constructor
// ============================================================================

// NewLRU creates a new LRU cache with the given capacity.
func NewLRU(capacity int) *LRU {
	if capacity < 1 {
		capacity = 1
	}

	return &LRU{
		capacity: capacity,
		items:    make(map[string]*lruNode, capacity),
	}
}

// ============================================================================
// Core Operations
// ============================================================================

// Get retrieves an entry from the cache.
// If found, the entry is moved to the front (most recently used).
// Returns nil if not found.
func (l *LRU) Get(key string) *CacheEntry {
	l.mu.Lock()
	defer l.mu.Unlock()

	node, exists := l.items[key]
	if !exists {
		return nil
	}

	// Move to front (most recently used)
	l.moveToFront(node)

	// Update access info
	node.entry.Touch()

	return node.entry
}

// Put adds or updates an entry in the cache.
// If the cache is full, the least recently used entry is evicted.
// Returns the evicted entry (if any) or nil.
func (l *LRU) Put(key string, entry *CacheEntry) *CacheEntry {
	l.mu.Lock()
	defer l.mu.Unlock()

	// Check if key already exists
	if node, exists := l.items[key]; exists {
		// Update existing entry
		node.entry = entry
		l.moveToFront(node)
		return nil
	}

	// Check if we need to evict
	var evicted *CacheEntry
	if len(l.items) >= l.capacity {
		evicted = l.evictTail()
	}

	// Create new node
	node := &lruNode{
		key:   key,
		entry: entry,
	}

	// Add to front
	l.addToFront(node)

	// Add to map
	l.items[key] = node

	return evicted
}

// Remove removes an entry from the cache.
// Returns true if the entry was found and removed.
func (l *LRU) Remove(key string) bool {
	l.mu.Lock()
	defer l.mu.Unlock()

	node, exists := l.items[key]
	if !exists {
		return false
	}

	l.removeNode(node)
	delete(l.items, key)

	return true
}

// Contains returns true if the key exists in the cache.
// Does NOT update LRU ordering (peek operation).
func (l *LRU) Contains(key string) bool {
	l.mu.RLock()
	defer l.mu.RUnlock()
	_, exists := l.items[key]
	return exists
}

// Peek retrieves an entry without updating LRU ordering.
func (l *LRU) Peek(key string) *CacheEntry {
	l.mu.RLock()
	defer l.mu.RUnlock()

	node, exists := l.items[key]
	if !exists {
		return nil
	}
	return node.entry
}

// ============================================================================
// Bulk Operations
// ============================================================================

// Clear removes all entries from the cache.
func (l *LRU) Clear() {
	l.mu.Lock()
	defer l.mu.Unlock()

	l.items = make(map[string]*lruNode, l.capacity)
	l.head = nil
	l.tail = nil
}

// Keys returns all keys in the cache (most recent first).
func (l *LRU) Keys() []string {
	l.mu.RLock()
	defer l.mu.RUnlock()

	keys := make([]string, 0, len(l.items))
	for node := l.head; node != nil; node = node.next {
		keys = append(keys, node.key)
	}
	return keys
}

// Entries returns all entries in the cache (most recent first).
func (l *LRU) Entries() []*CacheEntry {
	l.mu.RLock()
	defer l.mu.RUnlock()

	entries := make([]*CacheEntry, 0, len(l.items))
	for node := l.head; node != nil; node = node.next {
		entries = append(entries, node.entry)
	}
	return entries
}

// RemoveIf removes all entries matching the predicate.
// Returns the number of entries removed.
func (l *LRU) RemoveIf(predicate func(key string, entry *CacheEntry) bool) int {
	l.mu.Lock()
	defer l.mu.Unlock()

	var toRemove []*lruNode

	for node := l.head; node != nil; node = node.next {
		if predicate(node.key, node.entry) {
			toRemove = append(toRemove, node)
		}
	}

	for _, node := range toRemove {
		l.removeNode(node)
		delete(l.items, node.key)
	}

	return len(toRemove)
}

// ============================================================================
// Size and Capacity
// ============================================================================

// Size returns the current number of entries.
func (l *LRU) Size() int {
	l.mu.RLock()
	defer l.mu.RUnlock()
	return len(l.items)
}

// Capacity returns the maximum capacity.
func (l *LRU) Capacity() int {
	return l.capacity
}

// IsFull returns true if the cache is at capacity.
func (l *LRU) IsFull() bool {
	l.mu.RLock()
	defer l.mu.RUnlock()
	return len(l.items) >= l.capacity
}

// Utilization returns the cache utilization as a percentage (0-100).
func (l *LRU) Utilization() float64 {
	if l.capacity == 0 {
		return 0
	}
	l.mu.RLock()
	defer l.mu.RUnlock()
	return float64(len(l.items)) / float64(l.capacity) * 100
}

// ============================================================================
// LRU Helpers (Internal)
// ============================================================================

// addToFront adds a node to the front of the list (most recently used).
func (l *LRU) addToFront(node *lruNode) {
	node.prev = nil
	node.next = l.head

	if l.head != nil {
		l.head.prev = node
	}
	l.head = node

	if l.tail == nil {
		l.tail = node
	}
}

// moveToFront moves an existing node to the front.
func (l *LRU) moveToFront(node *lruNode) {
	if node == l.head {
		return // Already at front
	}

	// Remove from current position
	l.removeNode(node)

	// Add to front
	l.addToFront(node)
}

// removeNode removes a node from the list (but not from map).
func (l *LRU) removeNode(node *lruNode) {
	if node.prev != nil {
		node.prev.next = node.next
	} else {
		l.head = node.next
	}

	if node.next != nil {
		node.next.prev = node.prev
	} else {
		l.tail = node.prev
	}

	node.prev = nil
	node.next = nil
}

// evictTail removes and returns the least recently used entry.
func (l *LRU) evictTail() *CacheEntry {
	if l.tail == nil {
		return nil
	}

	evicted := l.tail.entry
	key := l.tail.key

	l.removeNode(l.tail)
	delete(l.items, key)

	return evicted
}

// ============================================================================
// Iteration
// ============================================================================

// ForEach iterates over all entries (most recent first).
// The callback should return true to continue, false to stop.
func (l *LRU) ForEach(fn func(key string, entry *CacheEntry) bool) {
	l.mu.RLock()
	defer l.mu.RUnlock()

	for node := l.head; node != nil; node = node.next {
		if !fn(node.key, node.entry) {
			break
		}
	}
}

// ForEachReverse iterates over all entries (least recent first).
func (l *LRU) ForEachReverse(fn func(key string, entry *CacheEntry) bool) {
	l.mu.RLock()
	defer l.mu.RUnlock()

	for node := l.tail; node != nil; node = node.prev {
		if !fn(node.key, node.entry) {
			break
		}
	}
}

// ============================================================================
// LRU Order Access
// ============================================================================

// GetMostRecent returns the most recently used entry.
func (l *LRU) GetMostRecent() *CacheEntry {
	l.mu.RLock()
	defer l.mu.RUnlock()

	if l.head == nil {
		return nil
	}
	return l.head.entry
}

// GetLeastRecent returns the least recently used entry.
func (l *LRU) GetLeastRecent() *CacheEntry {
	l.mu.RLock()
	defer l.mu.RUnlock()

	if l.tail == nil {
		return nil
	}
	return l.tail.entry
}

// EvictN evicts up to N least recently used entries.
// Returns the number of entries actually evicted.
func (l *LRU) EvictN(n int) int {
	l.mu.Lock()
	defer l.mu.Unlock()

	evicted := 0
	for i := 0; i < n && l.tail != nil; i++ {
		key := l.tail.key
		l.removeNode(l.tail)
		delete(l.items, key)
		evicted++
	}

	return evicted
}
