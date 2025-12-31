// Package api implements gRPC API handlers for DNS server management.
package api

import (
	"context"
	"log"
	"safeops/dns_server/internal/cache"
	"safeops/dns_server/internal/captive"
	"safeops/dns_server/internal/filtering"
	"safeops/dns_server/internal/metrics"
	"safeops/dns_server/internal/storage"
)

// ============================================================================
// API Server
// ============================================================================

// Server implements the DNS Server gRPC API
type Server struct {
	zoneStore *storage.ZoneStore
	filter    *filtering.Filter
	cache     *cache.Cache
	captive   *captive.Manager
	metrics   *metrics.Collector
}

// NewServer creates a new API server
func NewServer(
	zoneStore *storage.ZoneStore,
	filter *filtering.Filter,
	cache *cache.Cache,
	captive *captive.Manager,
	metrics *metrics.Collector,
) *Server {
	return &Server{
		zoneStore: zoneStore,
		filter:    filter,
		cache:     cache,
		captive:   captive,
		metrics:   metrics,
	}
}

// ============================================================================
// Zone Management
// ============================================================================

// AddZone creates a new DNS zone
func (s *Server) AddZone(ctx context.Context, name, zoneType string) error {
	zone := &storage.Zone{
		Name: name,
		Type: zoneType,
	}
	return s.zoneStore.SaveZone(ctx, zone)
}

// DeleteZone removes a DNS zone
func (s *Server) DeleteZone(ctx context.Context, name string) error {
	return s.zoneStore.DeleteZone(ctx, name)
}

// ListZones returns all zones
func (s *Server) ListZones(ctx context.Context) ([]*storage.Zone, error) {
	return s.zoneStore.ListZones(ctx)
}

// GetZone retrieves a zone by name
func (s *Server) GetZone(ctx context.Context, name string) (*storage.Zone, error) {
	return s.zoneStore.LoadZone(ctx, name)
}

// ============================================================================
// Record Management
// ============================================================================

// AddRecord adds a DNS record
func (s *Server) AddRecord(ctx context.Context, zoneName string, record *storage.Record) (string, error) {
	return s.zoneStore.AddRecord(ctx, zoneName, record)
}

// DeleteRecord removes a DNS record
func (s *Server) DeleteRecord(ctx context.Context, recordID string) error {
	return s.zoneStore.DeleteRecord(ctx, recordID)
}

// UpdateRecord modifies a DNS record
func (s *Server) UpdateRecord(ctx context.Context, recordID string, record *storage.Record) error {
	return s.zoneStore.UpdateRecord(ctx, recordID, record)
}

// ListRecords returns records for a zone
func (s *Server) ListRecords(ctx context.Context, zoneName string, recordType *string) ([]*storage.Record, error) {
	return s.zoneStore.ListRecords(ctx, zoneName, recordType)
}

// ============================================================================
// Filtering
// ============================================================================

// AddBlockDomain adds a domain to blocklist
func (s *Server) AddBlockDomain(domain, reason, category string) {
	if s.filter != nil {
		s.filter.AddBlock(domain, reason, category, "api")
		log.Printf("Blocked domain added via API: %s", domain)
	}
}

// RemoveBlockDomain removes a domain from blocklist
func (s *Server) RemoveBlockDomain(domain string) {
	if s.filter != nil {
		s.filter.RemoveBlock(domain)
	}
}

// AddAllowDomain adds a domain to allowlist
func (s *Server) AddAllowDomain(domain string) {
	if s.filter != nil {
		s.filter.AddAllow(domain)
		log.Printf("Allowed domain added via API: %s", domain)
	}
}

// RemoveAllowDomain removes a domain from allowlist
func (s *Server) RemoveAllowDomain(domain string) {
	if s.filter != nil {
		s.filter.RemoveAllow(domain)
	}
}

// ============================================================================
// Cache Management
// ============================================================================

// FlushCache clears the DNS cache
func (s *Server) FlushCache() {
	if s.cache != nil {
		s.cache.Flush()
		log.Printf("DNS cache flushed via API")
	}
}

// GetCacheStats returns cache statistics
func (s *Server) GetCacheStats() cache.Stats {
	if s.cache != nil {
		return s.cache.GetStats()
	}
	return cache.Stats{}
}

// ============================================================================
// Captive Portal
// ============================================================================

// MarkDeviceEnrolled marks a device as enrolled
func (s *Server) MarkDeviceEnrolled(ctx context.Context, ipAddress, macAddress, osType, method, fingerprint string) error {
	if s.captive != nil {
		return s.captive.OnDeviceEnrolled(ctx, ipAddress, macAddress, osType, method, fingerprint)
	}
	return nil
}

// ListPendingDevices returns devices awaiting enrollment
func (s *Server) ListPendingDevices(ctx context.Context) ([]*captive.TrackedDevice, error) {
	if s.captive != nil {
		return s.captive.ListPendingDevices(ctx)
	}
	return nil, nil
}

// GetCaptiveStats returns captive portal statistics
func (s *Server) GetCaptiveStats(ctx context.Context) (*captive.TrackerStats, error) {
	if s.captive != nil {
		return s.captive.GetStats(ctx)
	}
	return nil, nil
}

// SetCaptiveEnabled enables or disables captive portal
func (s *Server) SetCaptiveEnabled(enabled bool) {
	if s.captive != nil {
		s.captive.SetEnabled(enabled)
	}
}

// ============================================================================
// Statistics
// ============================================================================

// GetStats returns server statistics
func (s *Server) GetStats() metrics.Stats {
	if s.metrics != nil {
		return s.metrics.GetStats()
	}
	return metrics.Stats{}
}
