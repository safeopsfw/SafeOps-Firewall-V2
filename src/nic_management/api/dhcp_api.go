// DHCP Management REST API
// Provides endpoints for DHCP lease management from Windows Mobile Hotspot
package api

import (
	"encoding/json"
	"net/http"
	"os/exec"
	"runtime"
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
	Source     string    `json:"source"` // "hotspot", "dhcp-server", "arp"
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
	HotspotActive bool       `json:"hotspotActive"`
	Timestamp     string     `json:"timestamp"`
}

// ============================================================================
// Real Data Functions (Windows Hotspot Integration)
// ============================================================================

// getHotspotLeases gets clients connected to Windows Mobile Hotspot as DHCP leases
func getHotspotLeases() []DHCPLease {
	if runtime.GOOS != "windows" {
		return []DHCPLease{}
	}

	leases := []DHCPLease{}
	now := time.Now()

	// Use PowerShell TetheringManager to get connected clients
	psScript := "Add-Type -AssemblyName System.Runtime.WindowsRuntime\n" +
		"\n" +
		"$asTaskGeneric = ([System.WindowsRuntimeSystemExtensions].GetMethods() | Where-Object { $_.Name -eq 'AsTask' -and $_.GetParameters().Count -eq 1 -and $_.GetParameters()[0].ParameterType.Name -eq 'IAsyncOperation" + "`" + "1' })[0]\n" +
		"\n" +
		"Function Await($WinRtTask, $ResultType) {\n" +
		"    $asTask = $asTaskGeneric.MakeGenericMethod($ResultType)\n" +
		"    $netTask = $asTask.Invoke($null, @($WinRtTask))\n" +
		"    $netTask.Wait(-1) | Out-Null\n" +
		"    $netTask.Result\n" +
		"}\n" +
		"\n" +
		"[Windows.Networking.NetworkOperators.NetworkOperatorTetheringManager,Windows.Networking.NetworkOperators,ContentType=WindowsRuntime] | Out-Null\n" +
		"[Windows.Networking.Connectivity.NetworkInformation,Windows.Networking.Connectivity,ContentType=WindowsRuntime] | Out-Null\n" +
		"\n" +
		"try {\n" +
		"    $connectionProfile = [Windows.Networking.Connectivity.NetworkInformation]::GetInternetConnectionProfile()\n" +
		"    if ($null -eq $connectionProfile) {\n" +
		"        $profiles = [Windows.Networking.Connectivity.NetworkInformation]::GetConnectionProfiles()\n" +
		"        if ($profiles.Count -gt 0) { $connectionProfile = $profiles[0] }\n" +
		"    }\n" +
		"    \n" +
		"    if ($null -ne $connectionProfile) {\n" +
		"        $tetheringManager = [Windows.Networking.NetworkOperators.NetworkOperatorTetheringManager]::CreateFromConnectionProfile($connectionProfile)\n" +
		"        \n" +
		"        if ($null -ne $tetheringManager -and $tetheringManager.TetheringOperationalState -eq 1) {\n" +
		"            $clients = $tetheringManager.GetTetheringClients()\n" +
		"            foreach ($client in $clients) {\n" +
		"                $hostNames = $client.HostNames\n" +
		"                $hostname = ''\n" +
		"                if ($hostNames.Count -gt 0) { $hostname = $hostNames[0].DisplayName }\n" +
		"                Write-Host \"CLIENT:$($client.MacAddress)|$hostname\"\n" +
		"            }\n" +
		"        }\n" +
		"    }\n" +
		"}\n" +
		"catch {\n" +
		"    # Silently fail\n" +
		"}\n"

	cmd := exec.Command("powershell", "-NoProfile", "-ExecutionPolicy", "Bypass", "-Command", psScript)
	output, err := cmd.Output()
	if err == nil {
		lines := strings.Split(string(output), "\n")
		for _, line := range lines {
			line = strings.TrimSpace(line)
			if strings.HasPrefix(line, "CLIENT:") {
				parts := strings.SplitN(strings.TrimPrefix(line, "CLIENT:"), "|", 2)
				if len(parts) >= 1 {
					mac := normalizeMACAddress(parts[0])
					hostname := ""
					if len(parts) >= 2 {
						hostname = strings.TrimSpace(parts[1])
					}
					if mac != "" && mac != "FF:FF:FF:FF:FF:FF" {
						lease := DHCPLease{
							MAC:        mac,
							IP:         "", // Will be filled by ARP
							Hostname:   hostname,
							State:      "ACTIVE",
							LeaseStart: now.Add(-1 * time.Hour), // Approximate
							LeaseEnd:   now.Add(23 * time.Hour),
							PoolName:   "Hotspot",
							VendorID:   getVendorFromMAC(mac),
							Source:     "hotspot",
						}
						leases = append(leases, lease)
					}
				}
			}
		}
	}

	// Also check ARP table for hotspot subnet (192.168.137.x)
	arpCmd := exec.Command("arp", "-a")
	arpOutput, err := arpCmd.Output()
	if err == nil {
		arpLines := strings.Split(string(arpOutput), "\n")
		inHotspotInterface := false

		for _, line := range arpLines {
			line = strings.TrimSpace(line)

			// Detect hotspot interface section
			if strings.Contains(line, "Interface:") {
				inHotspotInterface = strings.Contains(line, "192.168.137") ||
					strings.Contains(line, "192.168.2.") ||
					strings.Contains(line, "192.168.43.")
				continue
			}

			// Parse ARP entries in hotspot interface
			if inHotspotInterface {
				fields := strings.Fields(line)
				if len(fields) >= 3 {
					ip := fields[0]
					mac := normalizeMACAddress(fields[1])

					// Skip gateway and broadcast
					if mac != "" && mac != "FF:FF:FF:FF:FF:FF" &&
						!strings.HasSuffix(ip, ".1") && !strings.HasSuffix(ip, ".255") {

						// Check if we already have this MAC from PowerShell
						found := false
						for i := range leases {
							if leases[i].MAC == mac {
								leases[i].IP = ip
								found = true
								break
							}
						}

						// Add new entry if not found
						if !found {
							lease := DHCPLease{
								MAC:        mac,
								IP:         ip,
								Hostname:   "",
								State:      "ACTIVE",
								LeaseStart: now.Add(-30 * time.Minute),
								LeaseEnd:   now.Add(23 * time.Hour),
								PoolName:   "Hotspot",
								VendorID:   getVendorFromMAC(mac),
								Source:     "arp",
							}
							leases = append(leases, lease)
						}
					}
				}
			}
		}
	}

	return leases
}

// getHotspotPool returns the Windows Mobile Hotspot pool configuration
func getHotspotPool() DHCPPool {
	// Windows Mobile Hotspot default configuration
	return DHCPPool{
		Name:        "Windows Hotspot",
		StartIP:     "192.168.137.2",
		EndIP:       "192.168.137.254",
		Subnet:      "255.255.255.0",
		Gateway:     "192.168.137.1",
		DNS:         "192.168.137.1",
		LeaseTime:   86400,
		TotalIPs:    253,
		UsedIPs:     0, // Will be updated
		Utilization: 0,
	}
}

// isHotspotActive checks if Windows Mobile Hotspot is enabled
func isHotspotActive() bool {
	status := getHotspotStatus()
	return status.Enabled
}

// ============================================================================
// DHCP API Handlers (Real Data)
// ============================================================================

// HandleDHCPLeases handles GET /api/dhcp/leases
func (s *NICAPIServer) HandleDHCPLeases(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Get limit parameter
	limit := 100
	if limitStr := r.URL.Query().Get("limit"); limitStr != "" {
		if l, err := strconv.Atoi(limitStr); err == nil && l > 0 {
			limit = l
		}
	}

	// Get real hotspot leases
	leases := getHotspotLeases()

	// Apply limit
	if limit < len(leases) {
		leases = leases[:limit]
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"leases":        leases,
		"total":         len(leases),
		"hotspotActive": isHotspotActive(),
		"timestamp":     time.Now().Format(time.RFC3339),
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

	leases := getHotspotLeases()
	var results []DHCPLease

	for _, lease := range leases {
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

	leases := getHotspotLeases()
	pool := getHotspotPool()

	// Update pool usage
	pool.UsedIPs = len(leases)
	if pool.TotalIPs > 0 {
		pool.Utilization = float64(pool.UsedIPs) / float64(pool.TotalIPs) * 100
	}

	activeCount := 0
	for _, lease := range leases {
		if lease.State == "ACTIVE" {
			activeCount++
		}
	}

	stats := DHCPStats{
		TotalLeases:   len(leases),
		ActiveLeases:  activeCount,
		ExpiredLeases: len(leases) - activeCount,
		Pools:         []DHCPPool{pool},
		Uptime:        getHotspotUptime(),
		HotspotActive: isHotspotActive(),
		Timestamp:     time.Now().Format(time.RFC3339),
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(stats)
}

// HandleDHCPRelease handles POST /api/dhcp/leases/:mac/release
func (s *NICAPIServer) HandleDHCPRelease(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost && r.Method != http.MethodDelete {
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

	// Note: Windows doesn't provide an API to disconnect individual hotspot clients
	// This is a known limitation
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"success": false,
		"message": "Disconnecting individual clients from Mobile Hotspot is not supported by Windows API",
		"mac":     mac,
	})
}

// HandleDHCPPools handles GET /api/dhcp/pools
func (s *NICAPIServer) HandleDHCPPools(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	leases := getHotspotLeases()
	pool := getHotspotPool()
	pool.UsedIPs = len(leases)
	if pool.TotalIPs > 0 {
		pool.Utilization = float64(pool.UsedIPs) / float64(pool.TotalIPs) * 100
	}

	pools := []DHCPPool{}
	if isHotspotActive() {
		pools = append(pools, pool)
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"pools":         pools,
		"hotspotActive": isHotspotActive(),
		"timestamp":     time.Now().Format(time.RFC3339),
	})
}

// getHotspotUptime returns how long the hotspot has been active
func getHotspotUptime() string {
	if !isHotspotActive() {
		return "Hotspot Inactive"
	}
	// Windows doesn't provide hotspot start time via API
	return "Active"
}
