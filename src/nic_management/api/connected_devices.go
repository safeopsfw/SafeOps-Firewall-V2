// Connected Devices Discovery
// Combines ARP table + DHCP leases for comprehensive device listing
package api

import (
	"encoding/json"
	"net/http"
	"os/exec"
	"runtime"
	"strings"
	"time"
)

// ConnectedDevice represents a device on the network
type ConnectedDevice struct {
	IP       string `json:"ip"`
	MAC      string `json:"mac"`
	Hostname string `json:"hostname"`
	Vendor   string `json:"vendor,omitempty"`
	Type     string `json:"type"` // "static", "dhcp", "arp-only"
	LastSeen string `json:"lastSeen"`
	Active   bool   `json:"active"`
}

// HandleConnectedDevices handles GET /api/devices
func (s *NICAPIServer) HandleConnectedDevices(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	devices, err := getConnectedDevices()
	if err != nil {
		http.Error(w, "Failed to get devices", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"devices":   devices,
		"count":     len(devices),
		"timestamp": time.Now().Format(time.RFC3339),
	})
}

// getConnectedDevices combines ARP table, DHCP leases, and hotspot clients
func getConnectedDevices() ([]ConnectedDevice, error) {
	// Get ARP table entries
	arpDevices, err := parseARPTable()
	if err != nil {
		return nil, err
	}

	// Get DHCP leases (if DHCP server is available)
	dhcpDevices := getDHCPDevices()

	// Get hotspot clients (if hotspot is enabled)
	hotspotClients := getHotspotClients()

	// Merge ARP, DHCP, and Hotspot data
	deviceMap := make(map[string]*ConnectedDevice)

	// Add hotspot clients first (highest priority)
	for _, device := range hotspotClients {
		normalizedMAC := normalizeMACAddress(device.MAC)
		deviceMap[normalizedMAC] = &device
	}

	// Add ARP entries
	for _, arp := range arpDevices {
		deviceMap[arp.MAC] = &arp
	}

	// Enhance with DHCP data (hostnames, lease info)
	for _, dhcp := range dhcpDevices {
		if device, exists := deviceMap[dhcp.MAC]; exists {
			// Update existing entry with DHCP info
			device.Hostname = dhcp.Hostname
			device.Type = "dhcp"
		} else {
			// Add DHCP-only entry (not in ARP yet)
			deviceMap[dhcp.MAC] = &dhcp
		}
	}

	// Convert map to slice
	devices := make([]ConnectedDevice, 0, len(deviceMap))
	for _, device := range deviceMap {
		devices = append(devices, *device)
	}

	return devices, nil
}

// parseARPTable parses the system ARP table
func parseARPTable() ([]ConnectedDevice, error) {
	if runtime.GOOS != "windows" {
		return []ConnectedDevice{}, nil // TODO: Linux support
	}

	// Run "arp -a" command
	cmd := exec.Command("arp", "-a")
	output, err := cmd.Output()
	if err != nil {
		return nil, err
	}

	lines := strings.Split(string(output), "\n")
	devices := []ConnectedDevice{}

	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" || strings.Contains(line, "Interface:") || strings.Contains(line, "Internet Address") {
			continue
		}

		fields := strings.Fields(line)
		if len(fields) < 3 {
			continue
		}

		// Parse format: "IP  MAC  Type"
		// Example: "192.168.1.100   aa-bb-cc-dd-ee-ff   dynamic"
		ip := fields[0]
		mac := normalizeMACAddress(fields[1])
		arpType := ""
		if len(fields) >= 3 {
			arpType = fields[2]
		}

		// Skip invalid/incomplete entries
		if mac == "" || mac == "ff-ff-ff-ff-ff-ff" || strings.Contains(mac, "incomplete") {
			continue
		}

		device := ConnectedDevice{
			IP:       ip,
			MAC:      mac,
			Hostname: "", // Will be filled by DHCP
			Vendor:   getVendorFromMAC(mac),
			Type:     "arp-only",
			LastSeen: time.Now().Format(time.RFC3339),
			Active:   arpType == "dynamic",
		}

		devices = append(devices, device)
	}

	return devices, nil
}

// getDHCPDevices fetches devices from hotspot leases
func getDHCPDevices() []ConnectedDevice {
	// Get real hotspot leases
	dhcpLeases := getHotspotLeases()

	devices := make([]ConnectedDevice, 0, len(dhcpLeases))
	for _, lease := range dhcpLeases {
		if lease.State != "ACTIVE" {
			continue
		}

		device := ConnectedDevice{
			IP:       lease.IP,
			MAC:      lease.MAC,
			Hostname: lease.Hostname,
			Vendor:   getVendorFromMAC(lease.MAC),
			Type:     "dhcp",
			LastSeen: lease.LeaseEnd.Format(time.RFC3339),
			Active:   true,
		}
		devices = append(devices, device)
	}

	return devices
}

// normalizeMACAddress converts MAC address to standard format
func normalizeMACAddress(mac string) string {
	// Convert "aa-bb-cc-dd-ee-ff" to "AA:BB:CC:DD:EE:FF"
	mac = strings.ToUpper(mac)
	mac = strings.ReplaceAll(mac, "-", ":")
	return mac
}

// getHotspotClients retrieves devices connected to Windows Mobile Hotspot
func getHotspotClients() []ConnectedDevice {
	if runtime.GOOS != "windows" {
		return []ConnectedDevice{}
	}

	devices := []ConnectedDevice{}

	// Method 1: Use PowerShell TetheringManager to get connected clients
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
		"    # Silently fail - will use ARP fallback\n" +
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
						hostname = parts[1]
					}
					if mac != "" && mac != "FF:FF:FF:FF:FF:FF" {
						device := ConnectedDevice{
							IP:       "", // Will be filled by ARP merge
							MAC:      mac,
							Hostname: hostname,
							Vendor:   getVendorFromMAC(mac),
							Type:     "hotspot",
							LastSeen: time.Now().Format(time.RFC3339),
							Active:   true,
						}
						devices = append(devices, device)
					}
				}
			}
		}
	}

	// Method 2 (Fallback): Parse ARP table for hotspot subnet
	// Windows Mobile Hotspot typically uses 192.168.137.x subnet
	arpCmd := exec.Command("arp", "-a")
	arpOutput, err := arpCmd.Output()
	if err == nil {
		arpLines := strings.Split(string(arpOutput), "\n")
		inHotspotInterface := false

		for _, line := range arpLines {
			line = strings.TrimSpace(line)

			// Detect hotspot interface section (usually shows 192.168.137.1)
			if strings.Contains(line, "Interface:") && strings.Contains(line, "192.168.137") {
				inHotspotInterface = true
				continue
			}

			// Also check for other common hotspot subnets (192.168.2.x, 192.168.43.x on Android)
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

					// Skip gateway and invalid entries
					if mac != "" && mac != "FF:FF:FF:FF:FF:FF" && !strings.HasSuffix(ip, ".1") && !strings.HasSuffix(ip, ".255") {
						// Check if we already have this device from PowerShell
						exists := false
						for i := range devices {
							if devices[i].MAC == mac {
								exists = true
								// Update IP if missing
								if devices[i].IP == "" {
									devices[i].IP = ip
								}
								break
							}
						}

						if !exists {
							device := ConnectedDevice{
								IP:       ip,
								MAC:      mac,
								Hostname: "",
								Vendor:   getVendorFromMAC(mac),
								Type:     "hotspot",
								LastSeen: time.Now().Format(time.RFC3339),
								Active:   true,
							}
							devices = append(devices, device)
						}
					}
				}
			}
		}
	}

	return devices
}

// getVendorFromMAC returns vendor name from MAC OUI (first 3 bytes)
func getVendorFromMAC(mac string) string {
	if len(mac) < 8 {
		return ""
	}

	// Simple vendor mapping (in production, use IEEE OUI database)
	oui := strings.ToUpper(mac[:8])
	vendors := map[string]string{
		// Virtual machines
		"00:50:56": "VMware",
		"08:00:27": "VirtualBox",
		"00:15:5D": "Microsoft Hyper-V",
		"00:1C:42": "Parallels",
		"52:54:00": "QEMU/KVM",
		"00:0C:29": "VMware",

		// Apple devices (iPhone, iPad, MacBook)
		"00:23:24": "Apple",
		"00:1B:63": "Apple",
		"00:15:C5": "Apple",
		"A4:83:E7": "Apple",
		"B8:E8:56": "Apple",
		"C8:B5:AD": "Apple",
		"D0:25:98": "Apple",
		"F0:DB:E2": "Apple",
		"AC:87:A3": "Apple",

		// Samsung (Galaxy phones/tablets)
		"00:1A:8A": "Samsung",
		"34:AA:8B": "Samsung",
		"38:AA:3C": "Samsung",
		"54:88:0E": "Samsung",
		"5C:0A:5B": "Samsung",
		"C8:19:F7": "Samsung",
		"E8:50:8B": "Samsung",

		// Other major mobile vendors
		"28:6D:CD": "Xiaomi",
		"34:CE:00": "Xiaomi",
		"F8:A4:5F": "Xiaomi",
		"64:09:80": "Huawei",
		"00:1E:10": "Huawei",
		"AC:E2:D3": "OnePlus",
		"30:D6:C9": "Google (Pixel)",

		// PC manufacturers
		"AC:DE:48": "Dell",
		"00:50:F2": "Microsoft",

		// IoT devices
		"B8:27:EB": "Raspberry Pi",
		"DC:A6:32": "Raspberry Pi",
		"E4:5F:01": "Raspberry Pi",
	}

	if vendor, exists := vendors[oui]; exists {
		return vendor
	}

	return ""
}
