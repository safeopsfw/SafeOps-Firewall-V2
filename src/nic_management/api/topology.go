// Network Topology and System Stats API
// Provides endpoints for network topology visualization and system statistics
package api

import (
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"time"
)

// ============================================================================
// Topology Types
// ============================================================================

// TopologyNode represents a node in the network topology
type TopologyNode struct {
	ID      string                 `json:"id"`
	Type    string                 `json:"type"` // internet, router, device, nic
	Label   string                 `json:"label"`
	Status  string                 `json:"status"` // online, offline, unknown
	IP      string                 `json:"ip,omitempty"`
	MAC     string                 `json:"mac,omitempty"`
	Details map[string]interface{} `json:"details,omitempty"`
}

// TopologyEdge represents a connection between nodes
type TopologyEdge struct {
	Source string `json:"source"`
	Target string `json:"target"`
	Type   string `json:"type"` // wired, wireless
	Speed  string `json:"speed,omitempty"`
}

// TopologyResponse represents the full network topology
type TopologyResponse struct {
	Nodes     []TopologyNode `json:"nodes"`
	Edges     []TopologyEdge `json:"edges"`
	Timestamp string         `json:"timestamp"`
}

// SystemStats represents system statistics
type SystemStats struct {
	Hostname      string        `json:"hostname"`
	OS            string        `json:"os"`
	Platform      string        `json:"platform"`
	Uptime        string        `json:"uptime"`
	CPUUsage      float64       `json:"cpuUsage"`
	MemoryTotal   uint64        `json:"memoryTotal"`
	MemoryUsed    uint64        `json:"memoryUsed"`
	MemoryPercent float64       `json:"memoryPercent"`
	Services      []ServiceInfo `json:"services"`
	Timestamp     string        `json:"timestamp"`
}

// ServiceInfo represents a SafeOps service status
type ServiceInfo struct {
	Name   string `json:"name"`
	Status string `json:"status"` // running, stopped, unknown
	Port   int    `json:"port,omitempty"`
	Uptime string `json:"uptime,omitempty"`
}

// ============================================================================
// Topology Handler
// ============================================================================

// HandleTopology handles GET /api/topology
func (s *NICAPIServer) HandleTopology(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	nics, _ := s.detectNICs()

	nodes := []TopologyNode{
		{
			ID:     "internet",
			Type:   "internet",
			Label:  "Internet",
			Status: "online",
		},
	}
	edges := []TopologyEdge{}

	// Find primary gateway/router
	gatewayIP := getDefaultGatewayIP()
	if gatewayIP != "" {
		nodes = append(nodes, TopologyNode{
			ID:     "router",
			Type:   "router",
			Label:  "Gateway/Router",
			Status: "online",
			IP:     gatewayIP,
		})
		edges = append(edges, TopologyEdge{
			Source: "internet",
			Target: "router",
			Type:   "wired",
		})
	}

	// Add SafeOps device
	hostname, _ := os.Hostname()
	nodes = append(nodes, TopologyNode{
		ID:     "safeops",
		Type:   "device",
		Label:  hostname,
		Status: "online",
		Details: map[string]interface{}{
			"role": "SafeOps Server",
			"os":   runtime.GOOS,
		},
	})

	if gatewayIP != "" {
		edges = append(edges, TopologyEdge{
			Source: "router",
			Target: "safeops",
			Type:   "wired",
		})
	} else {
		edges = append(edges, TopologyEdge{
			Source: "internet",
			Target: "safeops",
			Type:   "wired",
		})
	}

	// Add NICs as nodes
	for _, nic := range nics {
		if nic.Type == "LOOPBACK" {
			continue // Skip loopback
		}

		status := "offline"
		if nic.Status == "UP" {
			status = "online"
		}

		connType := "wired"
		isWiFi := strings.Contains(strings.ToLower(nic.Name), "wi-fi") ||
			strings.Contains(strings.ToLower(nic.Name), "wireless")
		if isWiFi {
			connType = "wireless"
		}

		ipAddr := ""
		if len(nic.IPv4) > 0 {
			ipAddr = strings.Split(nic.IPv4[0], "/")[0]
		}

		nodes = append(nodes, TopologyNode{
			ID:     fmt.Sprintf("nic-%d", nic.Index),
			Type:   "nic",
			Label:  nic.Alias,
			Status: status,
			IP:     ipAddr,
			MAC:    nic.MAC,
			Details: map[string]interface{}{
				"type":      nic.Type,
				"isPrimary": nic.IsPrimary,
				"speed":     nic.Speed,
			},
		})

		edges = append(edges, TopologyEdge{
			Source: "safeops",
			Target: fmt.Sprintf("nic-%d", nic.Index),
			Type:   connType,
		})
	}

	// Add hotspot connected clients
	hotspotClients := getHotspotClients()
	for i, client := range hotspotClients {
		clientID := fmt.Sprintf("hotspot-client-%d", i)
		label := client.Hostname
		if label == "" {
			label = client.Vendor
			if label == "" {
				label = "Unknown Device"
			}
		}

		nodes = append(nodes, TopologyNode{
			ID:     clientID,
			Type:   "device",
			Label:  label,
			Status: "online",
			IP:     client.IP,
			MAC:    client.MAC,
			Details: map[string]interface{}{
				"vendor":     client.Vendor,
				"type":       "hotspot-client",
				"connection": "wireless",
			},
		})

		// Connect to WiFi/hotspot interface
		// Find the WiFi interface to connect to
		targetNIC := "safeops" // Default to safeops if no WiFi found
		for _, nic := range nics {
			if strings.Contains(strings.ToLower(nic.Name), "wi-fi") ||
				strings.Contains(strings.ToLower(nic.Name), "wireless") ||
				strings.Contains(strings.ToLower(nic.Name), "local area connection") {
				if len(nic.IPv4) > 0 && strings.Contains(nic.IPv4[0], "192.168.137") {
					targetNIC = fmt.Sprintf("nic-%d", nic.Index)
					break
				}
			}
		}

		edges = append(edges, TopologyEdge{
			Source: targetNIC,
			Target: clientID,
			Type:   "wireless",
		})
	}

	resp := TopologyResponse{
		Nodes:     nodes,
		Edges:     edges,
		Timestamp: time.Now().Format(time.RFC3339),
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(resp)
}

// HandleSystemStats handles GET /api/system/stats
func (s *NICAPIServer) HandleSystemStats(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	hostname, _ := os.Hostname()

	stats := SystemStats{
		Hostname:  hostname,
		OS:        runtime.GOOS,
		Platform:  runtime.GOARCH,
		Uptime:    getSystemUptime(),
		CPUUsage:  getCPUUsage(),
		Timestamp: time.Now().Format(time.RFC3339),
	}

	// Get memory info
	memTotal, memUsed := getMemoryInfo()
	stats.MemoryTotal = memTotal
	stats.MemoryUsed = memUsed
	if memTotal > 0 {
		stats.MemoryPercent = float64(memUsed) / float64(memTotal) * 100
	}

	// Check SafeOps services
	stats.Services = []ServiceInfo{
		{Name: "NIC Management", Status: "running", Port: 8081},
		{Name: "DHCP Server", Status: checkPortOpen(67), Port: 67},
		{Name: "DNS Server", Status: checkPortOpen(53), Port: 53},
		{Name: "Firewall", Status: "running"},
		{Name: "Threat Intel", Status: checkPortOpen(8080), Port: 8080},
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(stats)
}

// ============================================================================
// Helper Functions
// ============================================================================

func getDefaultGatewayIP() string {
	if runtime.GOOS == "windows" {
		cmd := exec.Command("cmd", "/c", "route", "print", "0.0.0.0")
		output, err := cmd.Output()
		if err != nil {
			return ""
		}
		lines := strings.Split(string(output), "\n")
		for _, line := range lines {
			fields := strings.Fields(line)
			if len(fields) >= 3 && fields[0] == "0.0.0.0" {
				return fields[2]
			}
		}
	}
	return ""
}

func getSystemUptime() string {
	if runtime.GOOS == "windows" {
		cmd := exec.Command("powershell", "-Command",
			"(get-date) - (gcim Win32_OperatingSystem).LastBootUpTime | Select-Object -ExpandProperty TotalMinutes")
		output, err := cmd.Output()
		if err == nil {
			minutes := strings.TrimSpace(string(output))
			return fmt.Sprintf("%s minutes", minutes)
		}
	}
	return "unknown"
}

func getCPUUsage() float64 {
	if runtime.GOOS == "windows" {
		cmd := exec.Command("powershell", "-Command",
			"(Get-Counter '\\Processor(_Total)\\% Processor Time').CounterSamples.CookedValue")
		output, err := cmd.Output()
		if err == nil {
			var cpu float64
			fmt.Sscanf(strings.TrimSpace(string(output)), "%f", &cpu)
			return cpu
		}
	}
	return 0
}

func getMemoryInfo() (uint64, uint64) {
	if runtime.GOOS == "windows" {
		cmd := exec.Command("powershell", "-Command",
			"$os = Get-CimInstance Win32_OperatingSystem; Write-Output \"$($os.TotalVisibleMemorySize),$($os.FreePhysicalMemory)\"")
		output, err := cmd.Output()
		if err == nil {
			parts := strings.Split(strings.TrimSpace(string(output)), ",")
			if len(parts) == 2 {
				var total, free uint64
				fmt.Sscanf(parts[0], "%d", &total)
				fmt.Sscanf(parts[1], "%d", &free)
				return total * 1024, (total - free) * 1024
			}
		}
	}
	return 0, 0
}

func checkPortOpen(port int) string {
	// Simple check - in real implementation would check actual process
	return "unknown"
}
