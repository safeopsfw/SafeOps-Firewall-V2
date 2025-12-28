// DHCP Management REST API
// Provides endpoints for DHCP lease management and statistics
package api

import (
	"encoding/json"
	"net/http"
	"strconv"
	"strings"
	"time"
)

// ============================================================================
// DHCP Types
// ============================================================================

// DHCPLease represents a DHCP lease
type DHCPLease struct {
	MAC        string    `json:"mac"`
	IP         string    `json:"ip"`
	Hostname   string    `json:"hostname"`
	State      string    `json:"state"` // ACTIVE, EXPIRED, RELEASED
	LeaseStart time.Time `json:"leaseStart"`
	LeaseEnd   time.Time `json:"leaseEnd"`
	PoolName   string    `json:"poolName"`
	VendorID   string    `json:"vendorId,omitempty"`
}

// DHCPPool represents a DHCP pool
type DHCPPool struct {
	Name        string  `json:"name"`
	StartIP     string  `json:"startIP"`
	EndIP       string  `json:"endIP"`
	Subnet      string  `json:"subnet"`
	Gateway     string  `json:"gateway"`
	DNS         string  `json:"dns"`
	LeaseTime   int     `json:"leaseTime"`
	TotalIPs    int     `json:"totalIPs"`
	UsedIPs     int     `json:"usedIPs"`
	Utilization float64 `json:"utilization"`
}

// DHCPStats represents DHCP server statistics
type DHCPStats struct {
	TotalLeases   int        `json:"totalLeases"`
	ActiveLeases  int        `json:"activeLeases"`
	ExpiredLeases int        `json:"expiredLeases"`
	Pools         []DHCPPool `json:"pools"`
	Uptime        string     `json:"uptime"`
	Timestamp     string     `json:"timestamp"`
}

// DHCPAPIServer provides REST API for DHCP management
type DHCPAPIServer struct {
	port int
	// In real implementation, would connect to actual DHCP server
	mockLeases []DHCPLease
	mockPools  []DHCPPool
}

// NewDHCPAPIServer creates a new DHCP API server
func NewDHCPAPIServer(port int) *DHCPAPIServer {
	s := &DHCPAPIServer{port: port}
	s.initMockData()
	return s
}

// initMockData creates sample data for testing
func (s *DHCPAPIServer) initMockData() {
	now := time.Now()

	s.mockLeases = []DHCPLease{
		{MAC: "AA:BB:CC:DD:EE:01", IP: "192.168.1.101", Hostname: "desktop-pc", State: "ACTIVE", LeaseStart: now.Add(-2 * time.Hour), LeaseEnd: now.Add(22 * time.Hour), PoolName: "LAN-Pool"},
		{MAC: "AA:BB:CC:DD:EE:02", IP: "192.168.1.102", Hostname: "laptop-work", State: "ACTIVE", LeaseStart: now.Add(-1 * time.Hour), LeaseEnd: now.Add(23 * time.Hour), PoolName: "LAN-Pool"},
		{MAC: "AA:BB:CC:DD:EE:03", IP: "192.168.1.103", Hostname: "phone-android", State: "ACTIVE", LeaseStart: now.Add(-30 * time.Minute), LeaseEnd: now.Add(23 * time.Hour), PoolName: "LAN-Pool"},
		{MAC: "AA:BB:CC:DD:EE:04", IP: "192.168.1.104", Hostname: "tablet-ipad", State: "ACTIVE", LeaseStart: now.Add(-15 * time.Minute), LeaseEnd: now.Add(23 * time.Hour), PoolName: "LAN-Pool"},
		{MAC: "AA:BB:CC:DD:EE:05", IP: "192.168.1.105", Hostname: "smart-tv", State: "ACTIVE", LeaseStart: now.Add(-5 * time.Hour), LeaseEnd: now.Add(19 * time.Hour), PoolName: "LAN-Pool"},
		{MAC: "AA:BB:CC:DD:EE:06", IP: "192.168.1.106", Hostname: "printer-hp", State: "ACTIVE", LeaseStart: now.Add(-12 * time.Hour), LeaseEnd: now.Add(12 * time.Hour), PoolName: "LAN-Pool"},
		{MAC: "AA:BB:CC:DD:EE:07", IP: "192.168.1.107", Hostname: "camera-nest", State: "EXPIRED", LeaseStart: now.Add(-25 * time.Hour), LeaseEnd: now.Add(-1 * time.Hour), PoolName: "LAN-Pool"},
		{MAC: "AA:BB:CC:DD:EE:08", IP: "192.168.1.108", Hostname: "router-mesh", State: "ACTIVE", LeaseStart: now.Add(-6 * time.Hour), LeaseEnd: now.Add(18 * time.Hour), PoolName: "LAN-Pool"},
		{MAC: "AA:BB:CC:DD:EE:09", IP: "192.168.1.109", Hostname: "alexa-echo", State: "ACTIVE", LeaseStart: now.Add(-3 * time.Hour), LeaseEnd: now.Add(21 * time.Hour), PoolName: "LAN-Pool"},
		{MAC: "AA:BB:CC:DD:EE:10", IP: "192.168.1.110", Hostname: "gaming-pc", State: "ACTIVE", LeaseStart: now.Add(-45 * time.Minute), LeaseEnd: now.Add(23 * time.Hour), PoolName: "LAN-Pool"},
	}

	s.mockPools = []DHCPPool{
		{
			Name:        "LAN-Pool",
			StartIP:     "192.168.1.100",
			EndIP:       "192.168.1.200",
			Subnet:      "255.255.255.0",
			Gateway:     "192.168.1.1",
			DNS:         "192.168.1.1",
			LeaseTime:   86400,
			TotalIPs:    101,
			UsedIPs:     9,
			Utilization: 8.9,
		},
	}
}

// ============================================================================
// DHCP API Handlers (for NIC API integration)
// ============================================================================

// HandleDHCPLeases handles GET /api/dhcp/leases
func (s *NICAPIServer) HandleDHCPLeases(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Get limit parameter
	limit := 10
	if limitStr := r.URL.Query().Get("limit"); limitStr != "" {
		if l, err := strconv.Atoi(limitStr); err == nil && l > 0 {
			limit = l
		}
	}

	// Get mock data
	dhcp := NewDHCPAPIServer(0)
	leases := dhcp.mockLeases

	// Apply limit
	if limit < len(leases) {
		leases = leases[:limit]
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"leases":    leases,
		"total":     len(dhcp.mockLeases),
		"timestamp": time.Now().Format(time.RFC3339),
	})
}

// HandleDHCPSearch handles GET /api/dhcp/leases/search
func (s *NICAPIServer) HandleDHCPSearch(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	query := strings.ToLower(r.URL.Query().Get("q"))
	if query == "" {
		http.Error(w, "Query parameter 'q' required", http.StatusBadRequest)
		return
	}

	dhcp := NewDHCPAPIServer(0)
	var results []DHCPLease

	for _, lease := range dhcp.mockLeases {
		if strings.Contains(strings.ToLower(lease.MAC), query) ||
			strings.Contains(strings.ToLower(lease.IP), query) ||
			strings.Contains(strings.ToLower(lease.Hostname), query) {
			results = append(results, lease)
		}
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"results":   results,
		"count":     len(results),
		"query":     query,
		"timestamp": time.Now().Format(time.RFC3339),
	})
}

// HandleDHCPStats handles GET /api/dhcp/stats
func (s *NICAPIServer) HandleDHCPStats(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	dhcp := NewDHCPAPIServer(0)

	activeCount := 0
	expiredCount := 0
	for _, lease := range dhcp.mockLeases {
		if lease.State == "ACTIVE" {
			activeCount++
		} else {
			expiredCount++
		}
	}

	stats := DHCPStats{
		TotalLeases:   len(dhcp.mockLeases),
		ActiveLeases:  activeCount,
		ExpiredLeases: expiredCount,
		Pools:         dhcp.mockPools,
		Uptime:        "2d 5h 30m",
		Timestamp:     time.Now().Format(time.RFC3339),
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(stats)
}

// HandleDHCPRelease handles POST /api/dhcp/leases/:mac/release
func (s *NICAPIServer) HandleDHCPRelease(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Extract MAC from URL
	parts := strings.Split(r.URL.Path, "/")
	if len(parts) < 5 {
		http.Error(w, "Invalid URL", http.StatusBadRequest)
		return
	}
	mac := parts[4]

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"success": true,
		"message": "Lease released",
		"mac":     mac,
	})
}

// HandleDHCPPools handles GET /api/dhcp/pools
func (s *NICAPIServer) HandleDHCPPools(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	dhcp := NewDHCPAPIServer(0)

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"pools":     dhcp.mockPools,
		"timestamp": time.Now().Format(time.RFC3339),
	})
}
