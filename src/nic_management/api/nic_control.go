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

	// Try to get Mobile Hotspot status via PowerShell API first
	psScript := `
		[Windows.Networking.NetworkOperators.NetworkOperatorTetheringManager,Windows.Networking.NetworkOperators,ContentType=WindowsRuntime] | Out-Null
		[Windows.Networking.Connectivity.NetworkInformation,Windows.Networking.Connectivity,ContentType=WindowsRuntime] | Out-Null

		try {
			$connectionProfile = [Windows.Networking.Connectivity.NetworkInformation]::GetInternetConnectionProfile()
			if ($null -eq $connectionProfile) {
				$profiles = [Windows.Networking.Connectivity.NetworkInformation]::GetConnectionProfiles()
				if ($profiles.Count -gt 0) {
					$connectionProfile = $profiles[0]
				}
			}

			if ($null -ne $connectionProfile) {
				$tetheringManager = [Windows.Networking.NetworkOperators.NetworkOperatorTetheringManager]::CreateFromConnectionProfile($connectionProfile)

				if ($null -ne $tetheringManager) {
					$state = $tetheringManager.TetheringOperationalState
					$clientCount = $tetheringManager.ClientCount

					Write-Output "State:$state"
					Write-Output "ClientCount:$clientCount"
					exit 0
				}
			}
			exit 1
		}
		catch {
			exit 1
		}
	`

	cmd := exec.Command("powershell", "-NoProfile", "-ExecutionPolicy", "Bypass", "-Command", psScript)
	output, err := cmd.Output()

	if err == nil {
		outStr := string(output)
		// Parse PowerShell output
		for _, line := range strings.Split(outStr, "\n") {
			line = strings.TrimSpace(line)
			if strings.HasPrefix(line, "State:") {
				state := strings.TrimPrefix(line, "State:")
				// TetheringOperationalState: Off=0, On=1, InTransition=2
				if strings.Contains(state, "1") || strings.Contains(state, "On") {
					status.Enabled = true
				}
			}
			if strings.HasPrefix(line, "ClientCount:") {
				countStr := strings.TrimPrefix(line, "ClientCount:")
				fmt.Sscanf(countStr, "%d", &status.ClientCount)
			}
		}

		// Get SSID from Windows registry or settings if available
		if status.Enabled {
			status.SSID = "SafeOps-Hotspot" // Default - would need registry access to get actual
		}

		return status
	}

	// Fallback to netsh method
	cmd = exec.Command("netsh", "wlan", "show", "hostednetwork")
	output, err = cmd.Output()
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

// checkMobileHotspotSupport checks if Windows Mobile Hotspot is available
func checkMobileHotspotSupport() error {
	// Check if we can access the Mobile Hotspot settings
	// This is more reliable than netsh hosted network
	cmd := exec.Command("powershell", "-Command",
		"Get-NetAdapter | Where-Object {$_.Status -eq 'Up' -and ($_.InterfaceDescription -match 'Wi-Fi|Wireless|802.11')} | Select-Object -First 1 Name")
	output, err := cmd.Output()
	if err != nil {
		return fmt.Errorf("no active WiFi adapter found for Mobile Hotspot")
	}

	outputStr := strings.TrimSpace(string(output))
	if len(outputStr) < 10 { // Just headers, no actual adapter
		return fmt.Errorf("no WiFi adapter available for Mobile Hotspot")
	}

	return nil
}

func startHotspot(config HotspotConfig) error {
	if runtime.GOOS != "windows" {
		return fmt.Errorf("hotspot control only supported on Windows")
	}

	log.Printf("Starting Windows Mobile Hotspot...")

	// Use defaults if not provided
	if config.SSID == "" {
		config.SSID = "SafeOps-Hotspot"
	}
	if config.Password == "" {
		config.Password = "SafeOps123"
	}

	// Validate password length
	if len(config.Password) < 8 {
		return fmt.Errorf("password must be at least 8 characters long")
	}

	// Simplified PowerShell script that works better with async operations
	// Note: Using string concatenation to handle the backtick character
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
		"    \n" +
		"    if ($null -eq $connectionProfile) {\n" +
		"        Write-Host 'ERROR:No internet connection available'\n" +
		"        exit 1\n" +
		"    }\n" +
		"    \n" +
		"    $tetheringManager = [Windows.Networking.NetworkOperators.NetworkOperatorTetheringManager]::CreateFromConnectionProfile($connectionProfile)\n" +
		"    \n" +
		"    if ($null -eq $tetheringManager) {\n" +
		"        Write-Host 'ERROR:Mobile Hotspot not available'\n" +
		"        exit 1\n" +
		"    }\n" +
		"    \n" +
		"    $state = $tetheringManager.TetheringOperationalState\n" +
		"    if ($state -eq 1) {\n" +
		"        Write-Host 'SUCCESS:Hotspot is already running'\n" +
		"        exit 0\n" +
		"    }\n" +
		"    \n" +
		"    $result = Await ($tetheringManager.StartTetheringAsync()) ([Windows.Networking.NetworkOperators.NetworkOperatorTetheringOperationResult])\n" +
		"    \n" +
		"    if ($result.Status -eq 0) {\n" +
		"        Write-Host 'SUCCESS:Mobile Hotspot started'\n" +
		"        exit 0\n" +
		"    } else {\n" +
		"        Write-Host \"ERROR:Failed to start - Status: $($result.Status)\"\n" +
		"        exit 1\n" +
		"    }\n" +
		"}\n" +
		"catch {\n" +
		"    Write-Host \"ERROR:$_\"\n" +
		"    exit 1\n" +
		"}\n"

	// Execute PowerShell script
	cmd := exec.Command("powershell", "-NoProfile", "-ExecutionPolicy", "Bypass", "-Command", psScript)
	output, err := cmd.CombinedOutput()
	outputStr := strings.TrimSpace(string(output))

	log.Printf("PowerShell output: %s", outputStr)

	if err == nil && strings.HasPrefix(outputStr, "SUCCESS:") {
		log.Printf("Mobile Hotspot started successfully via PowerShell API")
		return nil
	}

	// If PowerShell method fails, try opening Windows Settings as fallback
	log.Printf("PowerShell method failed, opening Windows Settings...")

	// Open Mobile Hotspot settings page
	settingsCmd := exec.Command("cmd", "/c", "start", "ms-settings:network-mobilehotspot")
	if settingsErr := settingsCmd.Run(); settingsErr != nil {
		log.Printf("Failed to open settings: %v", settingsErr)
	}

	// Return a user-friendly message
	if strings.Contains(outputStr, "ERROR:") {
		errorMsg := strings.TrimPrefix(outputStr, "ERROR:")
		return fmt.Errorf("hotspot start failed: %s. Windows Settings has been opened - please enable Mobile Hotspot manually", errorMsg)
	}

	return fmt.Errorf("hotspot start failed. Windows Settings has been opened - please enable Mobile Hotspot manually")
}

// startHotspotNetsh is a fallback method using netsh (legacy)
func startHotspotNetsh(config HotspotConfig) error {
	log.Printf("Using legacy netsh hosted network method...")

	// Step 1: Configure the hosted network
	log.Printf("Configuring hotspot: SSID=%s", config.SSID)
	configCmd := exec.Command("netsh", "wlan", "set", "hostednetwork",
		"mode=allow",
		fmt.Sprintf("ssid=%s", config.SSID),
		fmt.Sprintf("key=%s", config.Password))

	output, err := configCmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("failed to configure hotspot (requires admin rights): %s - %v", string(output), err)
	}

	log.Printf("Configure output: %s", string(output))

	// Step 2: Start the hosted network
	log.Printf("Starting hosted network...")
	startCmd := exec.Command("netsh", "wlan", "start", "hostednetwork")
	startOutput, startErr := startCmd.CombinedOutput()

	if startErr != nil {
		startOutputStr := string(startOutput)
		log.Printf("Start error: %s", startOutputStr)

		// Provide helpful error messages
		if strings.Contains(startOutputStr, "not in the correct state") {
			return fmt.Errorf("wireless adapter is not ready. Please ensure:\n1. WiFi adapter is enabled\n2. Running with administrator privileges\n3. Try enabling Mobile Hotspot from Windows Settings\n\nError: %s", startOutputStr)
		}
		if strings.Contains(startOutputStr, "group or resource") {
			return fmt.Errorf("WiFi adapter does not support hosted networks.\nPlease use Windows Settings > Network & Internet > Mobile hotspot instead")
		}
		if strings.Contains(startOutputStr, "radio") {
			return fmt.Errorf("WiFi radio is turned off. Please enable WiFi and try again")
		}

		return fmt.Errorf("failed to start hotspot: %s", startOutputStr)
	}

	log.Printf("Hotspot started successfully")
	return nil
}

func stopHotspot() error {
	if runtime.GOOS != "windows" {
		return fmt.Errorf("hotspot control only supported on Windows")
	}

	log.Printf("Stopping Windows Mobile Hotspot...")

	// PowerShell script to stop Mobile Hotspot with proper async handling
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
		"    if ($null -eq $connectionProfile) {\n" +
		"        Write-Host 'SUCCESS:No active connection'\n" +
		"        exit 0\n" +
		"    }\n" +
		"    \n" +
		"    $tetheringManager = [Windows.Networking.NetworkOperators.NetworkOperatorTetheringManager]::CreateFromConnectionProfile($connectionProfile)\n" +
		"    \n" +
		"    $state = $tetheringManager.TetheringOperationalState\n" +
		"    if ($state -eq 0) {\n" +
		"        Write-Host 'SUCCESS:Hotspot is already stopped'\n" +
		"        exit 0\n" +
		"    }\n" +
		"    \n" +
		"    $result = Await ($tetheringManager.StopTetheringAsync()) ([Windows.Networking.NetworkOperators.NetworkOperatorTetheringOperationResult])\n" +
		"    \n" +
		"    if ($result.Status -eq 0) {\n" +
		"        Write-Host 'SUCCESS:Mobile Hotspot stopped'\n" +
		"        exit 0\n" +
		"    } else {\n" +
		"        Write-Host \"ERROR:Failed to stop - Status: $($result.Status)\"\n" +
		"        exit 1\n" +
		"    }\n" +
		"}\n" +
		"catch {\n" +
		"    Write-Host \"ERROR:$_\"\n" +
		"    exit 1\n" +
		"}\n"

	// Execute PowerShell script
	cmd := exec.Command("powershell", "-NoProfile", "-ExecutionPolicy", "Bypass", "-Command", psScript)
	output, err := cmd.CombinedOutput()
	outputStr := strings.TrimSpace(string(output))

	log.Printf("PowerShell output: %s", outputStr)

	if err == nil && strings.HasPrefix(outputStr, "SUCCESS:") {
		log.Printf("Mobile Hotspot stopped successfully")
		return nil
	}

	// Fallback to netsh
	log.Printf("Falling back to netsh method...")
	netshCmd := exec.Command("netsh", "wlan", "stop", "hostednetwork")
	if netshOutput, netshErr := netshCmd.CombinedOutput(); netshErr != nil {
		return fmt.Errorf("failed to stop hotspot: %s", string(netshOutput))
	}

	return nil
}
