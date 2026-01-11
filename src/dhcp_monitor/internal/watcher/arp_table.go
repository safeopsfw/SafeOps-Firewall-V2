// Package watcher provides ARP table queries and caching
package watcher

import (
	"context"
	"fmt"
	"net"
	"regexp"
	"strings"
	"sync"
	"time"

	"dhcp_monitor/internal/platform"
)

// =============================================================================
// ARP ENTRY STRUCT
// =============================================================================

// ARPEntry represents a parsed ARP table entry
type ARPEntry struct {
	IPAddress      net.IP    `json:"ip_address"`
	MACAddress     string    `json:"mac_address"`
	InterfaceIndex uint32    `json:"interface_index"`
	InterfaceName  string    `json:"interface_name"`
	State          string    `json:"state"` // REACHABLE, STALE, PERMANENT
	Type           string    `json:"type"`  // DYNAMIC, STATIC, OTHER
	LastUpdated    time.Time `json:"last_updated"`
}

// ToDeviceInfo converts ARPEntry to DeviceInfo for event creation
func (e *ARPEntry) ToDeviceInfo(detectionSource string) *DeviceInfo {
	return &DeviceInfo{
		MACAddress:      e.MACAddress,
		IPAddress:       e.IPAddress,
		InterfaceName:   e.InterfaceName,
		InterfaceIndex:  e.InterfaceIndex,
		Hostname:        "", // ARP table doesn't contain hostnames
		DetectionMethod: detectionSource,
	}
}

// =============================================================================
// ARP TABLE STRUCT
// =============================================================================

// ARPTable manages ARP table queries with caching
type ARPTable struct {
	entries         map[string]*ARPEntry // Keyed by IP address string
	mutex           sync.RWMutex
	lastRefresh     time.Time
	refreshInterval time.Duration
}

// NewARPTable creates a new ARPTable manager
func NewARPTable(refreshInterval time.Duration) *ARPTable {
	if refreshInterval <= 0 {
		refreshInterval = 5 * time.Second // Default refresh interval
	}

	return &ARPTable{
		entries:         make(map[string]*ARPEntry),
		refreshInterval: refreshInterval,
	}
}

// =============================================================================
// QUERY METHODS
// =============================================================================

// Query retrieves the current ARP table from Windows API
func (t *ARPTable) Query(ctx context.Context) ([]ARPEntry, error) {
	// Get raw ARP entries from Windows API
	rawEntries, err := platform.GetARPTable()
	if err != nil {
		return nil, fmt.Errorf("failed to query ARP table: %w", err)
	}

	t.mutex.Lock()
	defer t.mutex.Unlock()

	// Clear existing cache
	t.entries = make(map[string]*ARPEntry)
	t.lastRefresh = time.Now()

	result := make([]ARPEntry, 0, len(rawEntries))

	for _, raw := range rawEntries {
		// Parse IP address
		ip := net.ParseIP(raw.IPAddress)
		if ip == nil {
			continue
		}

		// Skip invalid states
		if !isValidARPState(raw.State) && raw.Type != "static" {
			continue
		}

		// Skip multicast addresses (224.0.0.0/4)
		if ip[0] >= 224 && ip[0] <= 239 {
			continue
		}

		// Skip broadcast (255.255.255.255)
		if ip.Equal(net.IPv4bcast) {
			continue
		}

		// Get interface name
		interfaceName, _ := platform.GetInterfaceName(raw.InterfaceIndex)

		entry := ARPEntry{
			IPAddress:      ip,
			MACAddress:     raw.MACAddress,
			InterfaceIndex: raw.InterfaceIndex,
			InterfaceName:  interfaceName,
			State:          raw.State,
			Type:           raw.Type,
			LastUpdated:    time.Now(),
		}

		// Add to cache and results
		t.entries[ip.String()] = &entry
		result = append(result, entry)
	}

	return result, nil
}

// QueryCached returns cached results if fresh, otherwise queries
func (t *ARPTable) QueryCached(ctx context.Context) ([]ARPEntry, error) {
	t.mutex.RLock()
	isFresh := time.Since(t.lastRefresh) < t.refreshInterval
	t.mutex.RUnlock()

	if isFresh {
		t.mutex.RLock()
		defer t.mutex.RUnlock()

		result := make([]ARPEntry, 0, len(t.entries))
		for _, entry := range t.entries {
			result = append(result, *entry)
		}
		return result, nil
	}

	return t.Query(ctx)
}

// =============================================================================
// LOOKUP METHODS
// =============================================================================

// LookupIP finds MAC address for a specific IP (O(1) lookup)
func (t *ARPTable) LookupIP(ctx context.Context, ip net.IP) (*ARPEntry, error) {
	// Ensure cache is fresh
	_, err := t.QueryCached(ctx)
	if err != nil {
		return nil, err
	}

	t.mutex.RLock()
	defer t.mutex.RUnlock()

	entry, exists := t.entries[ip.String()]
	if !exists {
		return nil, fmt.Errorf("ARP entry not found for IP: %s", ip.String())
	}

	// Return copy to prevent external modification
	result := *entry
	return &result, nil
}

// LookupMAC finds IP address for a specific MAC (O(n) iteration)
func (t *ARPTable) LookupMAC(ctx context.Context, mac string) (*ARPEntry, error) {
	// Ensure cache is fresh
	_, err := t.QueryCached(ctx)
	if err != nil {
		return nil, err
	}

	// Normalize input MAC for comparison
	normalizedMAC := normalizeMACAddress(mac)

	t.mutex.RLock()
	defer t.mutex.RUnlock()

	for _, entry := range t.entries {
		if entry.MACAddress == normalizedMAC {
			result := *entry
			return &result, nil
		}
	}

	return nil, fmt.Errorf("ARP entry not found for MAC: %s", mac)
}

// =============================================================================
// FILTER AND DIFF METHODS
// =============================================================================

// FilterByInterface returns entries matching interface name pattern
func (t *ARPTable) FilterByInterface(entries []ARPEntry, interfaceNamePattern string) []ARPEntry {
	if interfaceNamePattern == "" || interfaceNamePattern == ".*" {
		return entries // Return all if no filter
	}

	re, err := regexp.Compile(interfaceNamePattern)
	if err != nil {
		return entries // Return all if invalid regex
	}

	result := make([]ARPEntry, 0)
	for _, entry := range entries {
		if re.MatchString(entry.InterfaceName) {
			result = append(result, entry)
		}
	}

	return result
}

// Diff compares two ARP table snapshots and returns changes
func (t *ARPTable) Diff(old, new []ARPEntry) (added, changed, removed []ARPEntry) {
	oldMap := make(map[string]*ARPEntry)
	for i := range old {
		oldMap[old[i].IPAddress.String()] = &old[i]
	}

	newMap := make(map[string]*ARPEntry)
	for i := range new {
		newMap[new[i].IPAddress.String()] = &new[i]
	}

	added = make([]ARPEntry, 0)
	changed = make([]ARPEntry, 0)
	removed = make([]ARPEntry, 0)

	// Find added and changed entries
	for ip, newEntry := range newMap {
		oldEntry, exists := oldMap[ip]
		if !exists {
			added = append(added, *newEntry)
		} else if oldEntry.MACAddress != newEntry.MACAddress {
			changed = append(changed, *newEntry)
		}
	}

	// Find removed entries
	for ip, oldEntry := range oldMap {
		if _, exists := newMap[ip]; !exists {
			removed = append(removed, *oldEntry)
		}
	}

	return added, changed, removed
}

// =============================================================================
// HELPER METHODS
// =============================================================================

// GetEntryCount returns the number of cached entries
func (t *ARPTable) GetEntryCount() int {
	t.mutex.RLock()
	defer t.mutex.RUnlock()
	return len(t.entries)
}

// GetLastRefresh returns when the cache was last refreshed
func (t *ARPTable) GetLastRefresh() time.Time {
	t.mutex.RLock()
	defer t.mutex.RUnlock()
	return t.lastRefresh
}

// InvalidateCache forces a refresh on next query
func (t *ARPTable) InvalidateCache() {
	t.mutex.Lock()
	defer t.mutex.Unlock()
	t.lastRefresh = time.Time{} // Zero time forces refresh
}

// isValidARPState returns true for usable ARP states
// Note: Windows returns states with capital letters (Permanent, Stale, Reachable)
func isValidARPState(state string) bool {
	switch strings.ToLower(state) {
	case "reachable", "permanent", "stale":
		return true
	default:
		return false
	}
}

// ARPEntryToNetworkEvent creates a detection event from ARP entry
func ARPEntryToNetworkEvent(entry *ARPEntry, eventType string) *NetworkEvent {
	return &NetworkEvent{
		EventType:       eventType,
		Timestamp:       time.Now(),
		MACAddress:      entry.MACAddress,
		IPAddress:       entry.IPAddress,
		InterfaceName:   entry.InterfaceName,
		InterfaceIndex:  entry.InterfaceIndex,
		DetectionSource: DetectionSourceARPTable,
		Metadata:        make(map[string]string),
	}
}
