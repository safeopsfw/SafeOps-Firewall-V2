// Package buffer provides in-memory packet storage for the TLS Proxy.
package buffer

import (
	"errors"
	"sync"
	"time"

	"tls_proxy/internal/config"
	"tls_proxy/internal/models"
)

// =============================================================================
// ERROR DEFINITIONS
// =============================================================================

var (
	ErrEntryNotFound = errors.New("buffer entry not found")
	ErrEntryExpired  = errors.New("buffer entry expired")
	ErrBufferFull    = errors.New("buffer at maximum capacity")
)

// =============================================================================
// STATISTICS
// =============================================================================

// BufferStats tracks buffer operation metrics.
type BufferStats struct {
	// TotalStored is the count of all Store() operations
	TotalStored uint64

	// CurrentCount is the number of entries currently in buffer
	CurrentCount int

	// EvictionCount is entries removed due to capacity limits
	EvictionCount uint64

	// ExpirationCount is entries removed due to TTL expiration
	ExpirationCount uint64

	// RetrieveHits is successful Retrieve() calls
	RetrieveHits uint64

	// RetrieveMisses is failed Retrieve() calls
	RetrieveMisses uint64
}

// HitRate returns the percentage of successful retrieval operations.
func (s *BufferStats) HitRate() float64 {
	total := s.RetrieveHits + s.RetrieveMisses
	if total == 0 {
		return 0
	}
	return float64(s.RetrieveHits) / float64(total) * 100
}

// =============================================================================
// PACKET BUFFER
// =============================================================================

// PacketBuffer provides thread-safe in-memory packet storage.
type PacketBuffer struct {
	// entries stores BufferEntry pointers indexed by ConnectionID
	entries map[string]*models.BufferEntry

	// mutex provides concurrent access control (RWMutex for read/write)
	mutex sync.RWMutex

	// maxCapacity is the maximum number of entries buffer can hold
	maxCapacity int

	// bufferTTL is how long entries remain valid before expiration
	bufferTTL time.Duration

	// stats tracks buffer operation metrics
	stats BufferStats
}

// =============================================================================
// CONSTRUCTOR
// =============================================================================

// NewPacketBuffer creates a new packet buffer with configuration.
func NewPacketBuffer(cfg *config.Config) *PacketBuffer {
	return &PacketBuffer{
		entries:     make(map[string]*models.BufferEntry, cfg.PacketBufferSize),
		maxCapacity: cfg.PacketBufferSize,
		bufferTTL:   cfg.BufferTTL,
		stats:       BufferStats{},
	}
}

// NewPacketBufferWithCapacity creates a buffer with explicit capacity.
func NewPacketBufferWithCapacity(maxCapacity int, bufferTTL time.Duration) *PacketBuffer {
	return &PacketBuffer{
		entries:     make(map[string]*models.BufferEntry, maxCapacity),
		maxCapacity: maxCapacity,
		bufferTTL:   bufferTTL,
		stats:       BufferStats{},
	}
}

// =============================================================================
// STORE OPERATIONS
// =============================================================================

// Store adds or updates a packet in the buffer.
// If buffer is at capacity, evicts the oldest entry using LRU policy.
func (pb *PacketBuffer) Store(entry *models.BufferEntry) {
	pb.mutex.Lock()
	defer pb.mutex.Unlock()

	// Set expiration time
	entry.ExpiresAt = time.Now().Add(pb.bufferTTL)

	// Check if entry already exists (update case)
	connectionID := entry.Packet.ConnectionID
	if _, exists := pb.entries[connectionID]; exists {
		pb.entries[connectionID] = entry
		return
	}

	// Evict oldest entry if at capacity
	if len(pb.entries) >= pb.maxCapacity {
		pb.evictOldest()
	}

	// Store new entry
	pb.entries[connectionID] = entry
	pb.stats.TotalStored++
	pb.stats.CurrentCount = len(pb.entries)
}

// StorePacket is a convenience method that creates a BufferEntry and stores it.
func (pb *PacketBuffer) StorePacket(packet models.Packet) *models.BufferEntry {
	entry := models.NewBufferEntry(packet, pb.bufferTTL)
	pb.Store(entry)
	return entry
}

// =============================================================================
// RETRIEVE OPERATIONS
// =============================================================================

// Retrieve fetches a packet from the buffer by ConnectionID.
// Returns the entry and nil error on success.
// Returns nil and error if entry not found or expired.
func (pb *PacketBuffer) Retrieve(connectionID string) (*models.BufferEntry, error) {
	pb.mutex.RLock()
	entry, exists := pb.entries[connectionID]
	pb.mutex.RUnlock()

	if !exists {
		pb.mutex.Lock()
		pb.stats.RetrieveMisses++
		pb.mutex.Unlock()
		return nil, ErrEntryNotFound
	}

	// Check expiration
	if entry.IsExpired() {
		pb.mutex.Lock()
		delete(pb.entries, connectionID)
		pb.stats.ExpirationCount++
		pb.stats.CurrentCount = len(pb.entries)
		pb.stats.RetrieveMisses++
		pb.mutex.Unlock()
		return nil, ErrEntryExpired
	}

	pb.mutex.Lock()
	pb.stats.RetrieveHits++
	pb.mutex.Unlock()

	return entry, nil
}

// Exists checks if an entry exists in the buffer (without expiration check).
func (pb *PacketBuffer) Exists(connectionID string) bool {
	pb.mutex.RLock()
	defer pb.mutex.RUnlock()
	_, exists := pb.entries[connectionID]
	return exists
}

// =============================================================================
// UPDATE OPERATIONS
// =============================================================================

// Update modifies an existing entry using the provided update function.
// Returns error if entry not found.
func (pb *PacketBuffer) Update(connectionID string, updateFunc func(*models.BufferEntry)) error {
	pb.mutex.Lock()
	defer pb.mutex.Unlock()

	entry, exists := pb.entries[connectionID]
	if !exists {
		return ErrEntryNotFound
	}

	// Call update function to modify entry
	updateFunc(entry)
	return nil
}

// SetSNI updates the SNI field for an entry.
func (pb *PacketBuffer) SetSNI(connectionID string, sni string) error {
	return pb.Update(connectionID, func(entry *models.BufferEntry) {
		entry.SNI = sni
		entry.SetDNSResolving()
	})
}

// SetResolvedIP updates the resolved IP for an entry.
func (pb *PacketBuffer) SetResolvedIP(connectionID string, ip string) error {
	return pb.Update(connectionID, func(entry *models.BufferEntry) {
		entry.ResolvedIP = ip
		entry.SetResolved()
	})
}

// SetError marks an entry as failed with the given error.
func (pb *PacketBuffer) SetError(connectionID string, err error) error {
	return pb.Update(connectionID, func(entry *models.BufferEntry) {
		entry.SetError(err)
	})
}

// =============================================================================
// REMOVE OPERATIONS
// =============================================================================

// Remove deletes a packet from the buffer.
// Returns true if entry was removed, false if not found.
func (pb *PacketBuffer) Remove(connectionID string) bool {
	pb.mutex.Lock()
	defer pb.mutex.Unlock()

	if _, exists := pb.entries[connectionID]; !exists {
		return false
	}

	delete(pb.entries, connectionID)
	pb.stats.CurrentCount = len(pb.entries)
	return true
}

// Clear removes all entries from the buffer.
func (pb *PacketBuffer) Clear() {
	pb.mutex.Lock()
	defer pb.mutex.Unlock()

	pb.entries = make(map[string]*models.BufferEntry, pb.maxCapacity)
	pb.stats.CurrentCount = 0
}

// =============================================================================
// QUERY OPERATIONS
// =============================================================================

// List returns entries matching the filter function.
func (pb *PacketBuffer) List(filter func(*models.BufferEntry) bool) []*models.BufferEntry {
	pb.mutex.RLock()
	defer pb.mutex.RUnlock()

	results := make([]*models.BufferEntry, 0)
	for _, entry := range pb.entries {
		if filter == nil || filter(entry) {
			results = append(results, entry)
		}
	}
	return results
}

// ListByState returns entries with the specified processing state.
func (pb *PacketBuffer) ListByState(state string) []*models.BufferEntry {
	return pb.List(func(entry *models.BufferEntry) bool {
		return entry.ProcessingState == state
	})
}

// ListPending returns entries in PENDING state.
func (pb *PacketBuffer) ListPending() []*models.BufferEntry {
	return pb.ListByState(models.StatePending)
}

// =============================================================================
// CLEANUP OPERATIONS
// =============================================================================

// Cleanup removes expired entries from the buffer.
// Returns the number of entries removed.
func (pb *PacketBuffer) Cleanup() int {
	pb.mutex.Lock()
	defer pb.mutex.Unlock()

	removed := 0
	for connectionID, entry := range pb.entries {
		if entry.IsExpired() {
			delete(pb.entries, connectionID)
			pb.stats.ExpirationCount++
			removed++
		}
	}
	pb.stats.CurrentCount = len(pb.entries)
	return removed
}

// evictOldest removes the entry with the earliest BufferTimestamp.
// Must be called with write lock held.
func (pb *PacketBuffer) evictOldest() {
	if len(pb.entries) == 0 {
		return
	}

	var oldestID string
	var oldestTime time.Time
	first := true

	for id, entry := range pb.entries {
		if first || entry.BufferTimestamp.Before(oldestTime) {
			oldestID = id
			oldestTime = entry.BufferTimestamp
			first = false
		}
	}

	if oldestID != "" {
		delete(pb.entries, oldestID)
		pb.stats.EvictionCount++
	}
}

// =============================================================================
// STATISTICS
// =============================================================================

// GetStats returns a copy of buffer statistics.
func (pb *PacketBuffer) GetStats() BufferStats {
	pb.mutex.RLock()
	defer pb.mutex.RUnlock()

	return BufferStats{
		TotalStored:     pb.stats.TotalStored,
		CurrentCount:    pb.stats.CurrentCount,
		EvictionCount:   pb.stats.EvictionCount,
		ExpirationCount: pb.stats.ExpirationCount,
		RetrieveHits:    pb.stats.RetrieveHits,
		RetrieveMisses:  pb.stats.RetrieveMisses,
	}
}

// Size returns the current number of entries in the buffer.
func (pb *PacketBuffer) Size() int {
	pb.mutex.RLock()
	defer pb.mutex.RUnlock()
	return len(pb.entries)
}

// Capacity returns the maximum buffer capacity.
func (pb *PacketBuffer) Capacity() int {
	return pb.maxCapacity
}

// TTL returns the configured buffer TTL.
func (pb *PacketBuffer) TTL() time.Duration {
	return pb.bufferTTL
}
