package sysconfig

import (
	"fmt"
	"os/exec"
	"strings"

	"safeops-engine/internal/logger"
)

// DNSConfigurator manages DNS settings for all network interfaces
type DNSConfigurator struct {
	log             *logger.Logger
	dnsProxyAddress string
	originalDNS     map[string][]string // interface -> original DNS servers
}

// NewDNSConfigurator creates a DNS configuration manager
func NewDNSConfigurator(log *logger.Logger, dnsProxyAddress string) *DNSConfigurator {
	return &DNSConfigurator{
		log:             log,
		dnsProxyAddress: dnsProxyAddress,
		originalDNS:     make(map[string][]string),
	}
}

// GetAllPhysicalInterfaces returns all physical network interfaces
func (d *DNSConfigurator) GetAllPhysicalInterfaces() ([]string, error) {
	// Get all interfaces using netsh
	cmd := exec.Command("netsh", "interface", "show", "interface")
	output, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("failed to list interfaces: %w", err)
	}

	interfaces := []string{}
	lines := strings.Split(string(output), "\n")

	for _, line := range lines {
		// Skip header and empty lines
		if !strings.Contains(line, "Connected") && !strings.Contains(line, "Disconnected") {
			continue
		}

		// Parse interface name (last column)
		fields := strings.Fields(line)
		if len(fields) < 4 {
			continue
		}

		interfaceName := strings.Join(fields[3:], " ")

		// Skip virtual/loopback interfaces
		if d.isVirtualInterface(interfaceName) {
			continue
		}

		interfaces = append(interfaces, interfaceName)
	}

	return interfaces, nil
}

// isVirtualInterface checks if an interface is virtual
func (d *DNSConfigurator) isVirtualInterface(name string) bool {
	virtualPrefixes := []string{
		"Loopback",
		"vEthernet",
		"VMware",
		"VirtualBox",
		"Hyper-V",
	}

	nameLower := strings.ToLower(name)
	for _, prefix := range virtualPrefixes {
		if strings.Contains(nameLower, strings.ToLower(prefix)) {
			return true
		}
	}

	return false
}

// GetInterfaceDNS gets current DNS servers for an interface
func (d *DNSConfigurator) GetInterfaceDNS(interfaceName string) ([]string, error) {
	cmd := exec.Command("netsh", "interface", "ipv4", "show", "dnsservers", interfaceName)
	output, err := cmd.Output()
	if err != nil {
		// Interface might not have DNS configured or doesn't exist
		return []string{}, nil
	}

	servers := []string{}
	lines := strings.Split(string(output), "\n")

	for _, line := range lines {
		line = strings.TrimSpace(line)
		// Look for IP addresses (simple pattern match)
		if strings.Count(line, ".") == 3 && !strings.Contains(line, ":") {
			servers = append(servers, line)
		}
	}

	return servers, nil
}

// SetInterfaceDNS sets DNS server for a specific interface
func (d *DNSConfigurator) SetInterfaceDNS(interfaceName string, dnsServer string) error {
	// Set primary DNS
	cmd := exec.Command("netsh", "interface", "ipv4", "set", "dnsservers",
		interfaceName, "static", dnsServer, "primary")

	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("failed to set DNS on %s: %w (output: %s)", interfaceName, err, string(output))
	}

	d.log.Info("DNS configured", map[string]interface{}{
		"interface": interfaceName,
		"dns":       dnsServer,
	})

	return nil
}

// ResetInterfaceDNS resets DNS to DHCP for an interface
func (d *DNSConfigurator) ResetInterfaceDNS(interfaceName string) error {
	cmd := exec.Command("netsh", "interface", "ipv4", "set", "dnsservers",
		interfaceName, "dhcp")

	if err := cmd.Run(); err != nil {
		return fmt.Errorf("failed to reset DNS on %s: %w", interfaceName, err)
	}

	d.log.Info("DNS reset to DHCP", map[string]interface{}{
		"interface": interfaceName,
	})

	return nil
}

// ConfigureAllInterfaces configures DNS for all physical interfaces
func (d *DNSConfigurator) ConfigureAllInterfaces() error {
	interfaces, err := d.GetAllPhysicalInterfaces()
	if err != nil {
		return fmt.Errorf("failed to get interfaces: %w", err)
	}

	d.log.Info("Configuring DNS for all interfaces", map[string]interface{}{
		"count":   len(interfaces),
		"dns":     d.dnsProxyAddress,
	})

	successCount := 0
	for _, iface := range interfaces {
		// Backup original DNS
		originalDNS, _ := d.GetInterfaceDNS(iface)
		if len(originalDNS) > 0 {
			d.originalDNS[iface] = originalDNS
		}

		// Set our DNS proxy
		if err := d.SetInterfaceDNS(iface, d.dnsProxyAddress); err != nil {
			d.log.Warn("Failed to configure DNS", map[string]interface{}{
				"interface": iface,
				"error":     err.Error(),
			})
			continue
		}

		successCount++
	}

	if successCount == 0 {
		return fmt.Errorf("failed to configure DNS on any interface")
	}

	d.log.Info("DNS configuration complete", map[string]interface{}{
		"configured": successCount,
		"total":      len(interfaces),
	})

	return nil
}

// RestoreAllInterfaces restores original DNS settings for all interfaces
func (d *DNSConfigurator) RestoreAllInterfaces() error {
	d.log.Info("Restoring DNS settings...", nil)

	interfaces, err := d.GetAllPhysicalInterfaces()
	if err != nil {
		return err
	}

	for _, iface := range interfaces {
		// If we have original DNS, restore it
		if originalDNS, exists := d.originalDNS[iface]; exists && len(originalDNS) > 0 {
			// Set primary
			if err := d.SetInterfaceDNS(iface, originalDNS[0]); err != nil {
				d.log.Warn("Failed to restore DNS", map[string]interface{}{
					"interface": iface,
					"error":     err.Error(),
				})
			}
		} else {
			// No original DNS, reset to DHCP
			if err := d.ResetInterfaceDNS(iface); err != nil {
				d.log.Warn("Failed to reset DNS", map[string]interface{}{
					"interface": iface,
					"error":     err.Error(),
				})
			}
		}
	}

	d.log.Info("DNS restoration complete", nil)
	return nil
}

// WatchForNewInterfaces monitors for new network interfaces and configures them
// This is useful for hotplugged adapters or VPN connections
func (d *DNSConfigurator) WatchForNewInterfaces() error {
	// TODO: Implement interface change detection using Windows API
	// For now, this is a placeholder for future enhancement
	return nil
}
