// Package management provides gRPC management API for the firewall engine.
package management

import (
	"context"
)

// ============================================================================
// Cache RPC Implementations
// ============================================================================

// GetCacheStats returns verdict cache statistics.
func (s *Server) GetCacheStats(ctx context.Context, req *GetCacheStatsRequest) (*GetCacheStatsResponse, error) {
	// Check if cache manager available
	if s.deps.CacheManager == nil {
		return &GetCacheStatsResponse{
			Size:      0,
			Capacity:  0,
			HitRate:   0,
			Hits:      0,
			Misses:    0,
			Evictions: 0,
		}, nil
	}

	return &GetCacheStatsResponse{
		Size:      uint64(s.deps.CacheManager.GetSize()),
		Capacity:  uint64(s.deps.CacheManager.GetCapacity()),
		HitRate:   s.deps.CacheManager.GetHitRate(),
		Hits:      s.deps.CacheManager.GetHits(),
		Misses:    s.deps.CacheManager.GetMisses(),
		Evictions: s.deps.CacheManager.GetEvictions(),
	}, nil
}

// FlushCache clears the verdict cache.
func (s *Server) FlushCache(ctx context.Context, req *FlushCacheRequest) (*FlushCacheResponse, error) {
	// Check if cache manager available
	if s.deps.CacheManager == nil {
		return &FlushCacheResponse{
			Success:        false,
			EntriesFlushed: 0,
		}, nil
	}

	// Get current size before flush
	sizeBefore := s.deps.CacheManager.GetSize()

	// Flush the cache
	flushed := s.deps.CacheManager.Flush()

	// Log the operation
	if s.deps.Logger != nil {
		s.deps.Logger.Info().
			Int("entries_flushed", flushed).
			Int("size_before", sizeBefore).
			Msg("Cache flushed via gRPC API")
	}

	return &FlushCacheResponse{
		Success:        true,
		EntriesFlushed: uint64(flushed),
	}, nil
}

// ============================================================================
// Default Cache Manager (for when no cache is injected)
// ============================================================================

// NoopCacheManager is a no-op cache manager implementation.
type NoopCacheManager struct{}

// NewNoopCacheManager creates a no-op cache manager.
func NewNoopCacheManager() *NoopCacheManager {
	return &NoopCacheManager{}
}

// GetSize returns 0.
func (m *NoopCacheManager) GetSize() int {
	return 0
}

// GetCapacity returns 0.
func (m *NoopCacheManager) GetCapacity() int {
	return 0
}

// GetHitRate returns 0.
func (m *NoopCacheManager) GetHitRate() float64 {
	return 0
}

// GetHits returns 0.
func (m *NoopCacheManager) GetHits() uint64 {
	return 0
}

// GetMisses returns 0.
func (m *NoopCacheManager) GetMisses() uint64 {
	return 0
}

// GetEvictions returns 0.
func (m *NoopCacheManager) GetEvictions() uint64 {
	return 0
}

// Flush returns 0.
func (m *NoopCacheManager) Flush() int {
	return 0
}
