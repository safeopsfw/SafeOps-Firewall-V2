// NIC Control - Enable/Disable NICs and Hotspot Management
// Provides API endpoints for controlling network interfaces on Windows
package api

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os/exec"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"time"
)

// ============================================================================
// NIC Control Types
// ============================================================================

// NICControlRequest represents a control action request
type NICControlRequest struct {
	Action string `json:"action"` // enable, disable
}

// HotspotConfig represents hotspot configuration
type HotspotConfig struct {
	SSID     string `json:"ssid"`
	Password string `json:"password"`
	Band     string `json:"band"` // 2.4GHz, 5GHz, Any
}

// HotspotStatus represents current hotspot state
type HotspotStatus struct {
	Enabled      bool     `json:"enabled"`
	SSID         string   `json:"ssid,omitempty"`
	Password     string   `json:"password,omitempty"`
	ClientCount  int      `json:"clientCount"`
	Clients      []string `json:"clients,omitempty"`
	Band         string   `json:"band,omitempty"`
	HostedIP     string   `json:"hostedIP,omitempty"`
	LastModified string   `json:"lastModified,omitempty"`
}

// NICController manages NIC and hotspot operations
type NICController struct {
	mu           sync.RWMutex
	hotspotState HotspotStatus
}

// NewNICController creates a new controller instance
func NewNICController() *NICController {
	return &NICController{}
}

// ============================================================================
// API Handlers
// ============================================================================

// HandleNICControl handles POST /api/nics/:id/control
func (s *NICAPIServer) HandleNICControl(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Extract NIC index from URL
	parts := strings.Split(r.URL.Path, "/")
	if len(parts) < 5 {
		http.Error(w, "Invalid URL", http.StatusBadRequest)
		return
	}

	indexStr := parts[3]
	index, err := strconv.Atoi(indexStr)
	if err != nil {
		http.Error(w, "Invalid NIC index", http.StatusBadRequest)
		return
	}

	var req NICControlRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	// Get NIC name
	nics, _ := s.detectNICs()
	var nicName string
	for _, nic := range nics {
		if nic.Index == index {
			nicName = nic.Name
			break
		}
	}

	if nicName == "" {
		http.Error(w, "NIC not found", http.StatusNotFound)
		return
	}

	var cmdErr error
	switch req.Action {
	case "enable":
		cmdErr = enableNIC(nicName)
	case "disable":
		cmdErr = disableNIC(nicName)
	default:
		http.Error(w, "Invalid action", http.StatusBadRequest)
		return
	}

	if cmdErr != nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(map[string]interface{}{
			"success": false,
			"error":   cmdErr.Error(),
			"message": "Operation requires administrator privileges",
		})
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"success": true,
		"action":  req.Action,
		"nic":     nicName,
	})
}

// HandleHotspotStatus handles GET /api/hotspot/status
func (s *NICAPIServer) HandleHotspotStatus(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	status := getHotspotStatus()
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(status)
}

// HandleHotspotStart handles POST /api/hotspot/start
func (s *NICAPIServer) HandleHotspotStart(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var config HotspotConfig
	if err := json.NewDecoder(r.Body).Decode(&config); err != nil {
		// Use defaults
		config.SSID = "SafeOps-Hotspot"
		config.Password = "SafeOps123"
	}

	err := startHotspot(config)
	if err != nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(map[string]interface{}{
			"success": false,
			"error":   err.Error(),
		})
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"success": true,
		"message": "Hotspot started",
		"ssid":    config.SSID,
	})
}

// HandleHotspotStop handles POST /api/hotspot/stop
func (s *NICAPIServer) HandleHotspotStop(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	err := stopHotspot()
	if err != nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(map[string]interface{}{
			"success": false,
			"error":   err.Error(),
		})
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"success": true,
		"message": "Hotspot stopped",
	})
}

// ============================================================================
// Windows NIC Control Functions
// ============================================================================

func enableNIC(nicName string) error {
	if runtime.GOOS != "windows" {
		return fmt.Errorf("NIC control only supported on Windows")
	}

	log.Printf("Enabling NIC: %s", nicName)
	cmd := exec.Command("netsh", "interface", "set", "interface", nicName, "admin=enable")
	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("failed to enable NIC: %s - %v", string(output), err)
	}
	return nil
}

func disableNIC(nicName string) error {
	if runtime.GOOS != "windows" {
		return fmt.Errorf("NIC control only supported on Windows")
	}

	log.Printf("Disabling NIC: %s", nicName)
	cmd := exec.Command("netsh", "interface", "set", "interface", nicName, "admin=disable")
	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("failed to disable NIC: %s - %v", string(output), err)
	}
	return nil
}

// ============================================================================
// Windows Hotspot Control Functions
// ============================================================================

func getHotspotStatus() HotspotStatus {
	if runtime.GOOS != "windows" {
		return HotspotStatus{Enabled: false}
	}

	status := HotspotStatus{
		LastModified: time.Now().Format(time.RFC3339),
	}

	// Check if mobile hotspot is enabled via netsh
	cmd := exec.Command("netsh", "wlan", "show", "hostednetwork")
	output, err := cmd.Output()
	if err == nil {
		outStr := string(output)
		if strings.Contains(outStr, "Status") && strings.Contains(outStr, "Started") {
			status.Enabled = true
		}
		// Parse SSID
		for _, line := range strings.Split(outStr, "\n") {
			if strings.Contains(line, "SSID name") {
				parts := strings.Split(line, ":")
				if len(parts) > 1 {
					status.SSID = strings.TrimSpace(strings.Trim(parts[1], "\""))
				}
			}
			if strings.Contains(line, "Number of clients") {
				parts := strings.Split(line, ":")
				if len(parts) > 1 {
					fmt.Sscanf(strings.TrimSpace(parts[1]), "%d", &status.ClientCount)
				}
			}
		}
	}

	return status
}

func startHotspot(config HotspotConfig) error {
	if runtime.GOOS != "windows" {
		return fmt.Errorf("hotspot control only supported on Windows")
	}

	log.Printf("Starting hotspot: SSID=%s", config.SSID)

	// Configure the hosted network
	configCmd := exec.Command("netsh", "wlan", "set", "hostednetwork",
		"mode=allow",
		fmt.Sprintf("ssid=%s", config.SSID),
		fmt.Sprintf("key=%s", config.Password))
	if output, err := configCmd.CombinedOutput(); err != nil {
		return fmt.Errorf("failed to configure hotspot: %s - %v", string(output), err)
	}

	// Start the hosted network
	startCmd := exec.Command("netsh", "wlan", "start", "hostednetwork")
	if output, err := startCmd.CombinedOutput(); err != nil {
		return fmt.Errorf("failed to start hotspot: %s - %v", string(output), err)
	}

	return nil
}

func stopHotspot() error {
	if runtime.GOOS != "windows" {
		return fmt.Errorf("hotspot control only supported on Windows")
	}

	log.Printf("Stopping hotspot")

	cmd := exec.Command("netsh", "wlan", "stop", "hostednetwork")
	if output, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("failed to stop hotspot: %s - %v", string(output), err)
	}

	return nil
}
