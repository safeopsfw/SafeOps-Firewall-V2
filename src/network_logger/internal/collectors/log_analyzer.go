package collectors

import (
	"bufio"
	"encoding/json"
	"os"
	"sort"
	"strings"
	"sync"
	"time"
)

// LogAnalyzer analyzes packet master logs to extract device information
type LogAnalyzer struct {
	masterLogPath string
	devices       map[string]*AnalyzedDevice // key: MAC address
	mu            sync.RWMutex
	macVendor     *MACVendorDB
	lastPosition  int64 // For incremental reading
}

// AnalyzedDevice represents a device detected from packet logs
type AnalyzedDevice struct {
	MAC          string             `json:"mac"`
	Vendor       string             `json:"vendor"`
	DeviceType   string             `json:"device_type"`
	Category     string             `json:"category"`
	IPs          []string           `json:"ips"`
	Interfaces   []string           `json:"interfaces"`
	Traffic      DeviceTraffic      `json:"traffic"`
	FirstSeen    time.Time          `json:"first_seen"`
	LastSeen     time.Time          `json:"last_seen"`
	Processes    []ProcessSummary   `json:"processes,omitempty"`
	Destinations DestinationSummary `json:"destinations"`
	Sessions     int                `json:"sessions"`
	IsLocal      bool               `json:"is_local"`
}

// DeviceTraffic contains traffic statistics
type DeviceTraffic struct {
	PacketsSent int64    `json:"packets_sent"`
	PacketsRecv int64    `json:"packets_recv"`
	BytesSent   int64    `json:"bytes_sent"`
	BytesRecv   int64    `json:"bytes_recv"`
	Protocols   []string `json:"protocols"`
}

// ProcessSummary represents a process associated with device traffic
type ProcessSummary struct {
	Name        string `json:"name"`
	PID         int32  `json:"pid"`
	Connections int    `json:"connections"`
}

// DestinationSummary contains destination analysis
type DestinationSummary struct {
	TopIPs    []string `json:"top_ips"`
	TopPorts  []uint16 `json:"top_ports"`
	Countries []string `json:"countries"`
}

// PacketLogEntry represents a single packet log entry (simplified for parsing)
type PacketLogEntry struct {
	PacketID  string `json:"packet_id"`
	Timestamp struct {
		Epoch   float64 `json:"epoch"`
		ISO8601 string  `json:"iso8601"`
	} `json:"timestamp"`
	CaptureInfo struct {
		Interface     string `json:"interface"`
		CaptureLength int    `json:"capture_length"`
		WireLength    int    `json:"wire_length"`
	} `json:"capture_info"`
	Layers struct {
		Datalink *struct {
			SrcMAC string `json:"src_mac"`
			DstMAC string `json:"dst_mac"`
		} `json:"datalink"`
		Network *struct {
			SrcIP    string `json:"src_ip"`
			DstIP    string `json:"dst_ip"`
			Protocol uint8  `json:"protocol"`
		} `json:"network"`
		Transport *struct {
			SrcPort uint16 `json:"src_port"`
			DstPort uint16 `json:"dst_port"`
		} `json:"transport"`
	} `json:"layers"`
	ParsedApplication struct {
		DetectedProtocol string `json:"detected_protocol"`
	} `json:"parsed_application"`
	FlowContext *struct {
		FlowID      string `json:"flow_id"`
		ProcessInfo *struct {
			PID  int32  `json:"pid"`
			Name string `json:"name"`
		} `json:"process"`
	} `json:"flow_context"`
	SrcGeo *struct {
		Country     string `json:"country"`
		CountryName string `json:"country_name"`
	} `json:"src_geo"`
	DstGeo *struct {
		Country     string `json:"country"`
		CountryName string `json:"country_name"`
	} `json:"dst_geo"`
}

// NewLogAnalyzer creates a new log analyzer
func NewLogAnalyzer(masterLogPath string) *LogAnalyzer {
	return &LogAnalyzer{
		masterLogPath: masterLogPath,
		devices:       make(map[string]*AnalyzedDevice),
		macVendor:     NewMACVendorDB(),
	}
}

// Analyze reads the master log and extracts device information
func (a *LogAnalyzer) Analyze() error {
	a.mu.Lock()
	defer a.mu.Unlock()

	file, err := os.Open(a.masterLogPath)
	if err != nil {
		return err
	}
	defer file.Close()

	// Reset devices for fresh analysis
	a.devices = make(map[string]*AnalyzedDevice)

	// Track additional data
	macToIPs := make(map[string]map[string]bool)
	macToIfaces := make(map[string]map[string]bool)
	macToProtos := make(map[string]map[string]bool)
	macToProcesses := make(map[string]map[string]*ProcessSummary)
	macToDstIPs := make(map[string]map[string]int)
	macToDstPorts := make(map[string]map[uint16]int)
	macToCountries := make(map[string]map[string]bool)
	macToFlows := make(map[string]map[string]bool)

	scanner := bufio.NewScanner(file)
	// Increase buffer size for large JSON lines
	buf := make([]byte, 0, 1024*1024)
	scanner.Buffer(buf, 10*1024*1024)

	for scanner.Scan() {
		var entry PacketLogEntry
		if err := json.Unmarshal(scanner.Bytes(), &entry); err != nil {
			continue
		}

		// Process source MAC
		if entry.Layers.Datalink != nil && entry.Layers.Datalink.SrcMAC != "" {
			srcMAC := strings.ToUpper(entry.Layers.Datalink.SrcMAC)
			if !isBroadcastMAC(srcMAC) {
				a.processDevice(srcMAC, &entry, true,
					macToIPs, macToIfaces, macToProtos, macToProcesses,
					macToDstIPs, macToDstPorts, macToCountries, macToFlows)
			}
		}

		// Process destination MAC
		if entry.Layers.Datalink != nil && entry.Layers.Datalink.DstMAC != "" {
			dstMAC := strings.ToUpper(entry.Layers.Datalink.DstMAC)
			if !isBroadcastMAC(dstMAC) {
				a.processDevice(dstMAC, &entry, false,
					macToIPs, macToIfaces, macToProtos, macToProcesses,
					macToDstIPs, macToDstPorts, macToCountries, macToFlows)
			}
		}
	}

	// Finalize device data
	for mac, device := range a.devices {
		// Set IPs
		if ips, ok := macToIPs[mac]; ok {
			for ip := range ips {
				device.IPs = append(device.IPs, ip)
			}
		}
		// Set Interfaces
		if ifaces, ok := macToIfaces[mac]; ok {
			for iface := range ifaces {
				device.Interfaces = append(device.Interfaces, iface)
			}
		}
		// Set Protocols
		if protos, ok := macToProtos[mac]; ok {
			for proto := range protos {
				device.Traffic.Protocols = append(device.Traffic.Protocols, proto)
			}
		}
		// Set Processes
		if procs, ok := macToProcesses[mac]; ok {
			for _, proc := range procs {
				device.Processes = append(device.Processes, *proc)
			}
		}
		// Set Top Destinations (top 5)
		if dstIPs, ok := macToDstIPs[mac]; ok {
			device.Destinations.TopIPs = getTopN(dstIPs, 5)
		}
		if dstPorts, ok := macToDstPorts[mac]; ok {
			device.Destinations.TopPorts = getTopPorts(dstPorts, 5)
		}
		// Set Countries
		if countries, ok := macToCountries[mac]; ok {
			for country := range countries {
				if country != "" && country != "XX" {
					device.Destinations.Countries = append(device.Destinations.Countries, country)
				}
			}
		}
		// Set Sessions (unique flows)
		if flows, ok := macToFlows[mac]; ok {
			device.Sessions = len(flows)
		}
	}

	return scanner.Err()
}

// processDevice processes a device entry
func (a *LogAnalyzer) processDevice(mac string, entry *PacketLogEntry, isSrc bool,
	macToIPs, macToIfaces, macToProtos map[string]map[string]bool,
	macToProcesses map[string]map[string]*ProcessSummary,
	macToDstIPs map[string]map[string]int,
	macToDstPorts map[string]map[uint16]int,
	macToCountries, macToFlows map[string]map[string]bool) {

	device, exists := a.devices[mac]
	if !exists {
		vendor := a.macVendor.Lookup(mac)
		deviceType, category := a.macVendor.GetDeviceType(vendor)

		device = &AnalyzedDevice{
			MAC:        mac,
			Vendor:     vendor,
			DeviceType: deviceType,
			Category:   category,
			FirstSeen:  time.Now(),
			IsLocal:    isLocalMAC(mac),
		}
		a.devices[mac] = device

		// Initialize tracking maps
		macToIPs[mac] = make(map[string]bool)
		macToIfaces[mac] = make(map[string]bool)
		macToProtos[mac] = make(map[string]bool)
		macToProcesses[mac] = make(map[string]*ProcessSummary)
		macToDstIPs[mac] = make(map[string]int)
		macToDstPorts[mac] = make(map[uint16]int)
		macToCountries[mac] = make(map[string]bool)
		macToFlows[mac] = make(map[string]bool)
	}

	// Parse timestamp
	if ts, err := time.Parse(time.RFC3339, entry.Timestamp.ISO8601); err == nil {
		if ts.Before(device.FirstSeen) {
			device.FirstSeen = ts
		}
		if ts.After(device.LastSeen) {
			device.LastSeen = ts
		}
	}

	// Track IP
	if entry.Layers.Network != nil {
		if isSrc {
			macToIPs[mac][entry.Layers.Network.SrcIP] = true
		} else {
			macToIPs[mac][entry.Layers.Network.DstIP] = true
		}
	}

	// Track Interface
	macToIfaces[mac][entry.CaptureInfo.Interface] = true

	// Track Protocol
	proto := strings.ToUpper(entry.ParsedApplication.DetectedProtocol)
	if proto != "" && proto != "UNKNOWN" && proto != "DATA" {
		macToProtos[mac][proto] = true
	}

	// Track traffic
	bytes := entry.CaptureInfo.WireLength
	if isSrc {
		device.Traffic.PacketsSent++
		device.Traffic.BytesSent += int64(bytes)
	} else {
		device.Traffic.PacketsRecv++
		device.Traffic.BytesRecv += int64(bytes)
	}

	// Track Process
	if entry.FlowContext != nil && entry.FlowContext.ProcessInfo != nil {
		proc := entry.FlowContext.ProcessInfo
		if proc.Name != "" {
			key := proc.Name
			if p, ok := macToProcesses[mac][key]; ok {
				p.Connections++
			} else {
				macToProcesses[mac][key] = &ProcessSummary{
					Name:        proc.Name,
					PID:         proc.PID,
					Connections: 1,
				}
			}
		}
	}

	// Track Destinations (for source MAC)
	if isSrc && entry.Layers.Network != nil {
		macToDstIPs[mac][entry.Layers.Network.DstIP]++
	}
	if isSrc && entry.Layers.Transport != nil {
		macToDstPorts[mac][entry.Layers.Transport.DstPort]++
	}

	// Track Countries
	if entry.DstGeo != nil && entry.DstGeo.Country != "" {
		macToCountries[mac][entry.DstGeo.Country] = true
	}

	// Track Flows
	if entry.FlowContext != nil && entry.FlowContext.FlowID != "" {
		macToFlows[mac][entry.FlowContext.FlowID] = true
	}
}

// GetDevices returns all analyzed devices
func (a *LogAnalyzer) GetDevices() []*AnalyzedDevice {
	a.mu.RLock()
	defer a.mu.RUnlock()

	devices := make([]*AnalyzedDevice, 0, len(a.devices))
	for _, device := range a.devices {
		devices = append(devices, device)
	}

	// Sort by traffic (most active first)
	sort.Slice(devices, func(i, j int) bool {
		totalI := devices[i].Traffic.BytesSent + devices[i].Traffic.BytesRecv
		totalJ := devices[j].Traffic.BytesSent + devices[j].Traffic.BytesRecv
		return totalI > totalJ
	})

	return devices
}

// Helper functions

func isBroadcastMAC(mac string) bool {
	mac = strings.ToUpper(mac)
	return mac == "FF:FF:FF:FF:FF:FF" ||
		strings.HasPrefix(mac, "01:00:5E") || // IPv4 multicast
		strings.HasPrefix(mac, "33:33") // IPv6 multicast
}

func isLocalMAC(mac string) bool {
	// Check if it's a locally administered address (bit 1 of first byte is set)
	mac = strings.ReplaceAll(mac, ":", "")
	if len(mac) < 2 {
		return false
	}
	// Second hex char represents bits 0-3, if bit 1 is set it's local
	secondChar := mac[1]
	switch secondChar {
	case '2', '3', '6', '7', 'A', 'B', 'E', 'F', 'a', 'b', 'e', 'f':
		return true
	}
	return false
}

func getTopN(counts map[string]int, n int) []string {
	type kv struct {
		Key   string
		Value int
	}
	var sorted []kv
	for k, v := range counts {
		sorted = append(sorted, kv{k, v})
	}
	sort.Slice(sorted, func(i, j int) bool {
		return sorted[i].Value > sorted[j].Value
	})

	result := make([]string, 0, n)
	for i := 0; i < len(sorted) && i < n; i++ {
		result = append(result, sorted[i].Key)
	}
	return result
}

func getTopPorts(counts map[uint16]int, n int) []uint16 {
	type kv struct {
		Key   uint16
		Value int
	}
	var sorted []kv
	for k, v := range counts {
		sorted = append(sorted, kv{k, v})
	}
	sort.Slice(sorted, func(i, j int) bool {
		return sorted[i].Value > sorted[j].Value
	})

	result := make([]uint16, 0, n)
	for i := 0; i < len(sorted) && i < n; i++ {
		result = append(result, sorted[i].Key)
	}
	return result
}
