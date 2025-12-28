//go:build linux
// +build linux

// Package discovery provides network interface enumeration and discovery capabilities.
// This file contains Linux-specific enumeration implementation using netlink.
package discovery

import (
	"context"
	"fmt"

	"safeops/nic_management/pkg/types"
)

// =============================================================================
// Linux Enumeration Implementation
// =============================================================================

// enumerateLinux discovers interfaces on Linux systems using netlink.
// NOTE: Full implementation requires github.com/vishvananda/netlink library.
func (e *Enumerator) enumerateLinux(ctx context.Context) ([]*types.NetworkInterface, error) {
	// TODO: Implement using netlink library
	// Example implementation:
	// links, err := netlink.LinkList()
	// if err != nil {
	//     return nil, fmt.Errorf("netlink.LinkList failed: %w", err)
	// }
	// for _, link := range links {
	//     attrs := link.Attrs()
	//     // Extract interface properties from attrs
	// }

	return nil, fmt.Errorf("Linux enumeration not yet implemented - requires netlink library (github.com/vishvananda/netlink)")
}

// =============================================================================
// Linux Statistics
// =============================================================================

// GetInterfaceStatistics retrieves statistics for an interface by index (Linux implementation).
func (e *Enumerator) GetInterfaceStatistics(interfaceIndex uint32) (*types.InterfaceStatistics, error) {
	// TODO: Implement using netlink or /sys/class/net/<iface>/statistics
	return nil, fmt.Errorf("Linux statistics not yet implemented")
}

// =============================================================================
// Windows Stub (required for compilation on Linux)
// =============================================================================

// enumerateWindows is a stub for Linux builds - Windows enumeration not available.
func (e *Enumerator) enumerateWindows(ctx context.Context) ([]*types.NetworkInterface, error) {
	return nil, fmt.Errorf("Windows enumeration not available on Linux")
}
