// NIC Detection and Configuration Utility
// Run: go run cmd/nic_detect/main.go
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"net"
	"os"
	"sort"
	"strings"
	"text/tabwriter"

	"gopkg.in/yaml.v3"
)

// NICInfo represents detected network interface information
type NICInfo struct {
	Index        int      `json:"index" yaml:"index"`
	Name         string   `json:"name" yaml:"name"`
	FriendlyName string   `json:"friendly_name" yaml:"friendly_name"`
	Alias        string   `json:"alias,omitempty" yaml:"alias,omitempty"`
	Type         string   `json:"type" yaml:"type"` // WAN, LAN, LOOPBACK, VIRTUAL
	Status       string   `json:"status" yaml:"status"`
	MACAddress   string   `json:"mac_address" yaml:"mac_address"`
	IPv4         []string `json:"ipv4_addresses" yaml:"ipv4_addresses"`
	IPv6         []string `json:"ipv6_addresses" yaml:"ipv6_addresses"`
	Gateway      string   `json:"gateway,omitempty" yaml:"gateway,omitempty"`
	MTU          int      `json:"mtu" yaml:"mtu"`
	IsPhysical   bool     `json:"is_physical" yaml:"is_physical"`
	HasInternet  bool     `json:"has_internet" yaml:"has_internet"`
}

// ConfigOutput represents the auto-generated config
type ConfigOutput struct {
	WANInterfaces []WANConfig `yaml:"wan_interfaces"`
	LANInterfaces []LANConfig `yaml:"lan_interfaces"`
}

type WANConfig struct {
	Name        string       `yaml:"name"`
	Alias       string       `yaml:"alias"`
	Priority    int          `yaml:"priority"`
	Weight      int          `yaml:"weight"`
	Enabled     bool         `yaml:"enabled"`
	HealthCheck *HealthCheck `yaml:"health_check,omitempty"`
}

type LANConfig struct {
	Name    string  `yaml:"name"`
	Alias   string  `yaml:"alias"`
	Enabled bool    `yaml:"enabled"`
	Network *NetCfg `yaml:"network,omitempty"`
}

type HealthCheck struct {
	Targets      []string `yaml:"targets"`
	CheckGateway bool     `yaml:"check_gateway"`
}

type NetCfg struct {
	Subnet  string `yaml:"subnet"`
	Gateway string `yaml:"gateway"`
}

func main() {
	outputFormat := flag.String("format", "table", "Output format: table, json, yaml, config")
	generateConfig := flag.Bool("generate-config", false, "Generate config.yaml with detected NICs")
	outputFile := flag.String("output", "", "Output file path (default: stdout)")
	flag.Parse()

	// Detect all NICs
	nics, err := detectAllNICs()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error detecting NICs: %v\n", err)
		os.Exit(1)
	}

	// Sort by index
	sort.Slice(nics, func(i, j int) bool {
		return nics[i].Index < nics[j].Index
	})

	// Output based on format
	var output string
	switch *outputFormat {
	case "json":
		data, _ := json.MarshalIndent(nics, "", "  ")
		output = string(data)
	case "yaml":
		data, _ := yaml.Marshal(nics)
		output = string(data)
	case "config":
		*generateConfig = true
		fallthrough
	default:
		output = formatTable(nics)
	}

	// Generate config if requested
	if *generateConfig {
		cfg := generateAutoConfig(nics)
		data, _ := yaml.Marshal(cfg)
		output = "# Auto-Generated NIC Configuration\n" +
			"# Generated from detected network interfaces\n" +
			"# Edit 'alias' fields to rename interfaces\n\n" +
			string(data)
	}

	// Write output
	if *outputFile != "" {
		err := os.WriteFile(*outputFile, []byte(output), 0644)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error writing file: %v\n", err)
			os.Exit(1)
		}
		fmt.Printf("Output written to %s\n", *outputFile)
	} else {
		fmt.Println(output)
	}
}

func detectAllNICs() ([]*NICInfo, error) {
	interfaces, err := net.Interfaces()
	if err != nil {
		return nil, err
	}

	var nics []*NICInfo

	for _, iface := range interfaces {
		nic := &NICInfo{
			Index:        iface.Index,
			Name:         iface.Name,
			FriendlyName: iface.Name, // Will be same on non-Windows, different on Windows
			MACAddress:   iface.HardwareAddr.String(),
			MTU:          iface.MTU,
			IPv4:         []string{},
			IPv6:         []string{},
		}

		// Get status
		if iface.Flags&net.FlagUp != 0 {
			nic.Status = "UP"
		} else {
			nic.Status = "DOWN"
		}

		// Detect if physical
		nic.IsPhysical = isPhysicalInterface(iface)

		// Get addresses
		addrs, err := iface.Addrs()
		if err == nil {
			for _, addr := range addrs {
				ip, _, err := net.ParseCIDR(addr.String())
				if err != nil {
					continue
				}
				if ip.To4() != nil {
					nic.IPv4 = append(nic.IPv4, addr.String())
				} else {
					nic.IPv6 = append(nic.IPv6, addr.String())
				}
			}
		}

		// Classify interface type
		nic.Type = classifyInterface(nic, iface)

		// Check for gateway (indicates WAN)
		nic.Gateway = detectGateway(nic)
		if nic.Gateway != "" {
			nic.HasInternet = true
		}

		nics = append(nics, nic)
	}

	return nics, nil
}

func isPhysicalInterface(iface net.Interface) bool {
	name := strings.ToLower(iface.Name)

	// Virtual interface patterns
	virtualPatterns := []string{
		"loopback", "lo", "veth", "docker", "br-", "virbr",
		"vmnet", "vboxnet", "vmware", "hyper-v", "wsl",
		"isatap", "teredo", "6to4", "tunnel",
	}

	for _, pattern := range virtualPatterns {
		if strings.Contains(name, pattern) {
			return false
		}
	}

	// Must have MAC address for physical
	if len(iface.HardwareAddr) == 0 {
		return false
	}

	return true
}

func classifyInterface(nic *NICInfo, iface net.Interface) string {
	// Loopback
	if iface.Flags&net.FlagLoopback != 0 {
		return "LOOPBACK"
	}

	// Virtual check
	if !nic.IsPhysical {
		return "VIRTUAL"
	}

	// Check if has public IPs or gateway (WAN)
	for _, ipStr := range nic.IPv4 {
		ip, _, _ := net.ParseCIDR(ipStr)
		if ip != nil && !isPrivateIP(ip) {
			return "WAN"
		}
	}

	// Check for gateway
	if nic.Gateway != "" {
		return "WAN"
	}

	// Check if has private IP (LAN)
	for _, ipStr := range nic.IPv4 {
		ip, _, _ := net.ParseCIDR(ipStr)
		if ip != nil && isPrivateIP(ip) {
			return "LAN"
		}
	}

	// Default based on having IPs
	if len(nic.IPv4) > 0 {
		return "LAN"
	}

	return "UNKNOWN"
}

func isPrivateIP(ip net.IP) bool {
	private := []string{
		"10.0.0.0/8",
		"172.16.0.0/12",
		"192.168.0.0/16",
		"169.254.0.0/16",
	}

	for _, cidr := range private {
		_, network, _ := net.ParseCIDR(cidr)
		if network.Contains(ip) {
			return true
		}
	}
	return false
}

func detectGateway(nic *NICInfo) string {
	// On Windows, we'd use the iphlpapi to get gateway
	// For cross-platform, we check if interface has route to internet

	// Simple heuristic: if has private IP with common gateway pattern
	for _, ipStr := range nic.IPv4 {
		ip, ipnet, _ := net.ParseCIDR(ipStr)
		if ip == nil || ipnet == nil {
			continue
		}

		// Check common gateway pattern (x.x.x.1)
		ip4 := ip.To4()
		if ip4 != nil {
			gatewayIP := net.IPv4(ip4[0], ip4[1], ip4[2], 1)
			return gatewayIP.String()
		}
	}
	return ""
}

func formatTable(nics []*NICInfo) string {
	var buf strings.Builder
	w := tabwriter.NewWriter(&buf, 0, 0, 2, ' ', 0)

	fmt.Fprintln(w, "")
	fmt.Fprintln(w, "╔══════════════════════════════════════════════════════════════════════════════════════════╗")
	fmt.Fprintln(w, "║                           DETECTED NETWORK INTERFACES                                    ║")
	fmt.Fprintln(w, "╠══════════════════════════════════════════════════════════════════════════════════════════╣")
	fmt.Fprintln(w, "")

	fmt.Fprintln(w, "INDEX\tNAME\tTYPE\tSTATUS\tIPv4\tMAC\tGATEWAY")
	fmt.Fprintln(w, "─────\t────\t────\t──────\t────\t───\t───────")

	for _, nic := range nics {
		ipv4 := "-"
		if len(nic.IPv4) > 0 {
			ipv4 = nic.IPv4[0]
		}

		mac := nic.MACAddress
		if mac == "" {
			mac = "-"
		}

		gw := nic.Gateway
		if gw == "" {
			gw = "-"
		}

		fmt.Fprintf(w, "%d\t%s\t%s\t%s\t%s\t%s\t%s\n",
			nic.Index,
			nic.Name,
			nic.Type,
			nic.Status,
			ipv4,
			mac,
			gw,
		)
	}

	fmt.Fprintln(w, "")
	fmt.Fprintln(w, "╚══════════════════════════════════════════════════════════════════════════════════════════╝")

	// Summary
	wanCount := 0
	lanCount := 0
	for _, nic := range nics {
		if nic.Type == "WAN" {
			wanCount++
		} else if nic.Type == "LAN" {
			lanCount++
		}
	}

	fmt.Fprintf(w, "\nSummary: %d WAN interfaces, %d LAN interfaces, %d total\n", wanCount, lanCount, len(nics))
	fmt.Fprintln(w, "\nTo generate config: go run . -generate-config -output config.yaml")

	w.Flush()
	return buf.String()
}

func generateAutoConfig(nics []*NICInfo) *ConfigOutput {
	cfg := &ConfigOutput{
		WANInterfaces: []WANConfig{},
		LANInterfaces: []LANConfig{},
	}

	wanPriority := 1
	for _, nic := range nics {
		if nic.Status != "UP" {
			continue
		}

		switch nic.Type {
		case "WAN":
			wan := WANConfig{
				Name:     nic.Name,
				Alias:    fmt.Sprintf("WAN-%d (%s)", wanPriority, nic.Name),
				Priority: wanPriority,
				Weight:   100 / wanPriority, // First WAN gets more weight
				Enabled:  true,
				HealthCheck: &HealthCheck{
					Targets:      []string{"8.8.8.8", "1.1.1.1"},
					CheckGateway: true,
				},
			}
			cfg.WANInterfaces = append(cfg.WANInterfaces, wan)
			wanPriority++

		case "LAN":
			lan := LANConfig{
				Name:    nic.Name,
				Alias:   fmt.Sprintf("LAN (%s)", nic.Name),
				Enabled: true,
			}

			// Extract network info from IP
			if len(nic.IPv4) > 0 {
				ip, ipnet, err := net.ParseCIDR(nic.IPv4[0])
				if err == nil && ipnet != nil {
					lan.Network = &NetCfg{
						Subnet:  ipnet.String(),
						Gateway: ip.String(),
					}
				}
			}

			cfg.LANInterfaces = append(cfg.LANInterfaces, lan)
		}
	}

	// Ensure at least one WAN
	if len(cfg.WANInterfaces) == 0 {
		// Find any interface with gateway
		for _, nic := range nics {
			if nic.Gateway != "" && nic.Status == "UP" {
				cfg.WANInterfaces = append(cfg.WANInterfaces, WANConfig{
					Name:     nic.Name,
					Alias:    "Primary WAN",
					Priority: 1,
					Weight:   100,
					Enabled:  true,
					HealthCheck: &HealthCheck{
						Targets:      []string{"8.8.8.8", "1.1.1.1"},
						CheckGateway: true,
					},
				})
				break
			}
		}
	}

	return cfg
}
