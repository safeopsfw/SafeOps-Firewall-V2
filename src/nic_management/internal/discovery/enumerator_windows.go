//go:build windows
// +build windows

// Package discovery provides network interface enumeration and discovery capabilities.
// This file contains Windows-specific enumeration implementation using NDIS and IP Helper APIs.
// Note: WinPcap/Npcap integration is optional and requires CGO with Npcap SDK installed.
package discovery

import (
	"context"
	"fmt"
	"strings"
	"time"

	"safeops/nic_management/internal/driver"
	"safeops/nic_management/pkg/types"
)

// =============================================================================
// Windows Enumeration Implementation
// =============================================================================

// enumerateWindows discovers interfaces on Windows systems using NDIS and IP Helper APIs.
func (e *Enumerator) enumerateWindows(ctx context.Context) ([]*types.NetworkInterface, error) {
	// Get NDIS interfaces (provides config/status info).
	adapters, err := driver.EnumerateNDISInterfaces()
	if err != nil {
		return nil, fmt.Errorf("NDIS enumeration failed: %w", err)
	}

	interfaces := e.convertNDISToNetworkInterfaces(adapters)

	// Enrich with IP Helper API data.
	enriched, err := e.enrichWithIPHelper(interfaces)
	if err != nil {
		// Log warning but continue with what we have.
		_ = err
	}

	return enriched, nil
}

// convertNDISToNetworkInterfaces converts NDIS adapter info to NetworkInterface.
func (e *Enumerator) convertNDISToNetworkInterfaces(adapters []*driver.NDISInterface) []*types.NetworkInterface {
	interfaces := make([]*types.NetworkInterface, 0, len(adapters))

	for _, adapter := range adapters {
		iface := &types.NetworkInterface{
			ID:          fmt.Sprintf("ndis-%d", adapter.Index),
			Name:        adapter.Name,
			Description: adapter.Description,
			MACAddress:  adapter.MACAddress,
			MTU:         int(adapter.MTU),
			SpeedMbps:   int(adapter.Speed / 1000000),
			IsVirtual:   !adapter.IsPhysical,
			IsEnabled:   adapter.IsEnabled,
			CreatedAt:   time.Now(),
			UpdatedAt:   time.Now(),
		}

		// Set operational state.
		iface.State = e.mapOperationalStatus(adapter.OperStatus)

		// Set interface type.
		iface.Type = e.mapInterfaceType(adapter.Type, adapter.Name, adapter.Description)

		// Check if wireless.
		if adapter.Type == 71 { // IF_TYPE_IEEE80211
			iface.IsWireless = true
			iface.Type = types.InterfaceTypeWIFI
		}

		// Set duplex based on speed (heuristic).
		if adapter.Speed >= 1000000000 {
			iface.Duplex = types.DuplexFull
		} else {
			iface.Duplex = types.DuplexAuto
		}

		interfaces = append(interfaces, iface)
	}

	return interfaces
}

// enrichWithIPHelper adds IP Helper API data to interfaces.
func (e *Enumerator) enrichWithIPHelper(interfaces []*types.NetworkInterface) ([]*types.NetworkInterface, error) {
	adapters, err := driver.GetAdaptersList()
	if err != nil {
		return interfaces, fmt.Errorf("IP Helper enumeration failed: %w", err)
	}

	// Create a map by MAC address for matching.
	adapterMap := make(map[string]*driver.NICInfo)
	for _, adapter := range adapters {
		if adapter.MACAddress != "" {
			adapterMap[strings.ToUpper(adapter.MACAddress)] = adapter
		}
	}

	for _, iface := range interfaces {
		macKey := strings.ToUpper(iface.MACAddress)
		if adapter, ok := adapterMap[macKey]; ok {
			// Enrich with IP Helper data.
			if len(adapter.IPv4Addresses) > 0 && iface.IPAddress == "" {
				iface.IPAddress = adapter.IPv4Addresses[0]
			}
			if len(adapter.IPv6Addresses) > 0 && iface.IPv6Address == "" {
				iface.IPv6Address = adapter.IPv6Addresses[0]
			}
			if len(adapter.Gateways) > 0 && iface.Gateway == "" {
				iface.Gateway = adapter.Gateways[0]
			}
			if len(adapter.DNSServers) > 0 && len(iface.DNSServers) == 0 {
				iface.DNSServers = adapter.DNSServers
			}
			if iface.Description == "" && adapter.Description != "" {
				iface.Description = adapter.Description
			}
			// If friendly name is available, prefer it.
			if adapter.FriendlyName != "" {
				iface.Alias = adapter.FriendlyName
			}
		}
	}

	return interfaces, nil
}

// mapOperationalStatus maps Windows operational status to InterfaceState.
func (e *Enumerator) mapOperationalStatus(operStatus uint32) types.InterfaceState {
	switch operStatus {
	case 1: // IF_OPER_STATUS_UP
		return types.InterfaceStateUP
	case 2: // IF_OPER_STATUS_DOWN
		return types.InterfaceStateDOWN
	case 5: // IF_OPER_STATUS_DORMANT
		return types.InterfaceStateDORMANT
	case 6: // IF_OPER_STATUS_NOT_PRESENT
		return types.InterfaceStateNotPresent
	case 7: // IF_OPER_STATUS_LOWER_DOWN
		return types.InterfaceStateLowerLayerDown
	default:
		return types.InterfaceStateUnknown
	}
}

// mapInterfaceType determines the interface type based on Windows type code and name patterns.
func (e *Enumerator) mapInterfaceType(typeCode uint32, name, description string) types.InterfaceType {
	// Check for loopback.
	if typeCode == 24 { // IF_TYPE_LOOPBACK
		return types.InterfaceTypeLOOPBACK
	}

	// Check for wireless.
	if typeCode == 71 { // IF_TYPE_IEEE80211
		return types.InterfaceTypeWIFI
	}

	// Check for tunnel/virtual.
	if typeCode == 131 { // IF_TYPE_TUNNEL
		return types.InterfaceTypeVIRTUAL
	}

	// Check name patterns for virtual adapters.
	combined := strings.ToLower(name + " " + description)
	virtualPatterns := []string{"virtual", "hyper-v", "vmware", "virtualbox", "docker", "wsl", "vpn", "tunnel"}
	for _, pattern := range virtualPatterns {
		if strings.Contains(combined, pattern) {
			return types.InterfaceTypeVIRTUAL
		}
	}

	// Default to LAN for Ethernet (type 6).
	if typeCode == 6 { // IF_TYPE_ETHERNET
		return types.InterfaceTypeLAN
	}

	return types.InterfaceTypeUNKNOWN
}

// =============================================================================
// Windows Statistics
// =============================================================================

// GetInterfaceStatistics retrieves statistics for an interface by index (Windows implementation).
func (e *Enumerator) GetInterfaceStatistics(interfaceIndex uint32) (*types.InterfaceStatistics, error) {
	return driver.GetIPHLPInterfaceStats(interfaceIndex)
}

// =============================================================================
// Linux Stub (required for compilation on Windows)
// =============================================================================

// enumerateLinux is a stub for Windows builds - Linux enumeration not available.
func (e *Enumerator) enumerateLinux(ctx context.Context) ([]*types.NetworkInterface, error) {
	return nil, fmt.Errorf("Linux enumeration not available on Windows")
}
