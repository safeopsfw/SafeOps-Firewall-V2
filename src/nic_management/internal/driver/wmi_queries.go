//go:build windows
// +build windows

// Package driver provides low-level network driver interactions.
// This file implements a comprehensive wrapper around Windows Management Instrumentation (WMI)
// for querying detailed network adapter information on Windows systems.
package driver

import (
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/StackExchange/wmi"
)

// =============================================================================
// WMI Structure Definitions - MSNdis Classes
// =============================================================================

// MSNdis_LinkSpeed represents NDIS link speed information.
type MSNdis_LinkSpeed struct {
	InstanceName  string
	Active        bool
	NdisLinkSpeed uint64
}

// MSNdis_MediaDuplexState represents NDIS duplex mode information.
type MSNdis_MediaDuplexState struct {
	InstanceName         string
	Active               bool
	NdisMediaDuplexState uint32
}

// MSNdis_VlanIdentifier represents VLAN configuration.
type MSNdis_VlanIdentifier struct {
	InstanceName string
	Active       bool
	NdisVlanId   uint32
}

// MSNdis_RSSCapabilities represents Receive Side Scaling capabilities.
type MSNdis_RSSCapabilities struct {
	InstanceName          string
	Active                bool
	NumberOfReceiveQueues uint32
	RSSCapabilities       uint32
}

// =============================================================================
// WMI Structure Definitions - Win32_PnPEntity
// =============================================================================

// Win32_PnPEntity maps to the Win32_PnPEntity WMI class.
type Win32_PnPEntity struct {
	DeviceID     string
	Name         string
	Description  string
	Manufacturer string
	Service      string
	Status       string
	PNPDeviceID  string
	ClassGuid    string
}

// Win32_PnPSignedDriver provides driver information.
type Win32_PnPSignedDriver struct {
	DeviceID           string
	DeviceName         string
	DriverVersion      string
	DriverDate         time.Time
	DriverProviderName string
	Manufacturer       string
	InfName            string
}

// =============================================================================
// RSS Information
// =============================================================================

// RSSInfo contains Receive Side Scaling information.
type RSSInfo struct {
	QueueCount uint32 `json:"queue_count"`
	Enabled    bool   `json:"enabled"`
}

// =============================================================================
// Adapter Details (Combined Information)
// =============================================================================

// WMIAdapterDetails contains combined adapter information from multiple WMI queries.
type WMIAdapterDetails struct {
	Adapter       *Win32_NetworkAdapter
	Configuration *Win32_NetworkAdapterConfiguration
	LinkSpeed     uint64
	DuplexMode    string
	RSSQueues     uint32
	DriverVersion string
}

// =============================================================================
// WMI Client Structure
// =============================================================================

// WMIClient is the WMI query client with connection management.
type WMIClient struct {
	namespace string
	timeout   time.Duration
	mu        sync.Mutex
}

// =============================================================================
// Constructor
// =============================================================================

// NewWMIClient creates a new WMI client instance.
func NewWMIClient() (*WMIClient, error) {
	return &WMIClient{
		namespace: `root\cimv2`,
		timeout:   30 * time.Second,
	}, nil
}

// =============================================================================
// Configuration Methods
// =============================================================================

// SetNamespace sets the WMI namespace for queries.
func (c *WMIClient) SetNamespace(namespace string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.namespace = namespace
}

// SetTimeout sets the query timeout.
func (c *WMIClient) SetTimeout(timeout time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.timeout = timeout
}

// GetNamespace returns the current WMI namespace.
func (c *WMIClient) GetNamespace() string {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.namespace
}

// =============================================================================
// Core Query Method
// =============================================================================

// Query executes a WMI query and populates the destination slice.
func (c *WMIClient) Query(dst interface{}, query string) error {
	c.mu.Lock()
	namespace := c.namespace
	c.mu.Unlock()

	err := wmi.QueryNamespace(query, dst, namespace)
	if err != nil {
		return c.handleWMIError(err, query)
	}
	return nil
}

// QueryWithNamespace executes a query in a specific namespace.
func (c *WMIClient) QueryWithNamespace(dst interface{}, query string, namespace string) error {
	err := wmi.QueryNamespace(query, dst, namespace)
	if err != nil {
		return c.handleWMIError(err, query)
	}
	return nil
}

// =============================================================================
// Network Adapter Queries
// =============================================================================

// GetAllNetworkAdapters retrieves all network adapters.
func (c *WMIClient) GetAllNetworkAdapters() ([]Win32_NetworkAdapter, error) {
	var adapters []Win32_NetworkAdapter
	query := "SELECT * FROM Win32_NetworkAdapter"
	err := c.Query(&adapters, query)
	if err != nil {
		return nil, fmt.Errorf("failed to query network adapters: %w", err)
	}
	return adapters, nil
}

// GetPhysicalNetworkAdapters retrieves only physical network adapters.
func (c *WMIClient) GetPhysicalNetworkAdapters() ([]Win32_NetworkAdapter, error) {
	var adapters []Win32_NetworkAdapter
	query := "SELECT * FROM Win32_NetworkAdapter WHERE PhysicalAdapter=TRUE"
	err := c.Query(&adapters, query)
	if err != nil {
		return nil, fmt.Errorf("failed to query physical adapters: %w", err)
	}
	return adapters, nil
}

// GetConnectedNetworkAdapters retrieves only connected adapters.
func (c *WMIClient) GetConnectedNetworkAdapters() ([]Win32_NetworkAdapter, error) {
	var adapters []Win32_NetworkAdapter
	query := "SELECT * FROM Win32_NetworkAdapter WHERE NetConnectionStatus=2"
	err := c.Query(&adapters, query)
	if err != nil {
		return nil, fmt.Errorf("failed to query connected adapters: %w", err)
	}
	return adapters, nil
}

// GetNetworkAdapterByIndex retrieves an adapter by its index.
func (c *WMIClient) GetNetworkAdapterByIndex(index uint32) (*Win32_NetworkAdapter, error) {
	var adapters []Win32_NetworkAdapter
	query := fmt.Sprintf("SELECT * FROM Win32_NetworkAdapter WHERE Index=%d", index)
	err := c.Query(&adapters, query)
	if err != nil {
		return nil, fmt.Errorf("failed to query adapter by index: %w", err)
	}
	if len(adapters) == 0 {
		return nil, fmt.Errorf("adapter with index %d not found", index)
	}
	return &adapters[0], nil
}

// GetNetworkAdapterByGUID retrieves an adapter by its GUID.
func (c *WMIClient) GetNetworkAdapterByGUID(guid string) (*Win32_NetworkAdapter, error) {
	var adapters []Win32_NetworkAdapter
	sanitizedGUID := c.sanitizeWQLString(guid)
	query := fmt.Sprintf("SELECT * FROM Win32_NetworkAdapter WHERE GUID='%s'", sanitizedGUID)
	err := c.Query(&adapters, query)
	if err != nil {
		return nil, fmt.Errorf("failed to query adapter by GUID: %w", err)
	}
	if len(adapters) == 0 {
		return nil, fmt.Errorf("adapter with GUID %s not found", guid)
	}
	return &adapters[0], nil
}

// GetNetworkAdapterByName retrieves an adapter by its connection name.
func (c *WMIClient) GetNetworkAdapterByName(name string) (*Win32_NetworkAdapter, error) {
	var adapters []Win32_NetworkAdapter
	sanitizedName := c.sanitizeWQLString(name)
	query := fmt.Sprintf("SELECT * FROM Win32_NetworkAdapter WHERE NetConnectionID='%s'", sanitizedName)
	err := c.Query(&adapters, query)
	if err != nil {
		return nil, fmt.Errorf("failed to query adapter by name: %w", err)
	}
	if len(adapters) == 0 {
		return nil, fmt.Errorf("adapter with name %s not found", name)
	}
	return &adapters[0], nil
}

// =============================================================================
// Adapter Configuration Queries
// =============================================================================

// GetAdapterConfiguration retrieves IP configuration for an adapter by index.
func (c *WMIClient) GetAdapterConfiguration(index uint32) (*Win32_NetworkAdapterConfiguration, error) {
	var configs []Win32_NetworkAdapterConfiguration
	query := fmt.Sprintf("SELECT * FROM Win32_NetworkAdapterConfiguration WHERE Index=%d", index)
	err := c.Query(&configs, query)
	if err != nil {
		return nil, fmt.Errorf("failed to query adapter configuration: %w", err)
	}
	if len(configs) == 0 {
		return nil, fmt.Errorf("configuration for adapter index %d not found", index)
	}
	return &configs[0], nil
}

// GetAllAdapterConfigurations retrieves all IP-enabled adapter configurations.
func (c *WMIClient) GetAllAdapterConfigurations() ([]Win32_NetworkAdapterConfiguration, error) {
	var configs []Win32_NetworkAdapterConfiguration
	query := "SELECT * FROM Win32_NetworkAdapterConfiguration WHERE IPEnabled=TRUE"
	err := c.Query(&configs, query)
	if err != nil {
		return nil, fmt.Errorf("failed to query adapter configurations: %w", err)
	}
	return configs, nil
}

// GetAdapterConfigurationByMAC retrieves configuration by MAC address.
func (c *WMIClient) GetAdapterConfigurationByMAC(macAddress string) (*Win32_NetworkAdapterConfiguration, error) {
	var configs []Win32_NetworkAdapterConfiguration
	sanitizedMAC := c.sanitizeWQLString(macAddress)
	query := fmt.Sprintf("SELECT * FROM Win32_NetworkAdapterConfiguration WHERE MACAddress='%s'", sanitizedMAC)
	err := c.Query(&configs, query)
	if err != nil {
		return nil, fmt.Errorf("failed to query adapter configuration by MAC: %w", err)
	}
	if len(configs) == 0 {
		return nil, fmt.Errorf("configuration for MAC %s not found", macAddress)
	}
	return &configs[0], nil
}

// =============================================================================
// NDIS Capability Queries
// =============================================================================

// GetNDISLinkSpeed retrieves link speed from NDIS for an adapter.
func (c *WMIClient) GetNDISLinkSpeed(instanceName string) (uint64, error) {
	var results []MSNdis_LinkSpeed
	sanitizedName := c.sanitizeWQLString(instanceName)
	query := fmt.Sprintf("SELECT * FROM MSNdis_LinkSpeed WHERE InstanceName='%s'", sanitizedName)

	err := c.QueryWithNamespace(&results, query, `root\wmi`)
	if err != nil {
		return 0, fmt.Errorf("failed to query link speed: %w", err)
	}
	if len(results) == 0 {
		return 0, fmt.Errorf("link speed for %s not found", instanceName)
	}

	// NdisLinkSpeed is in units of 100 bps, convert to bps.
	return results[0].NdisLinkSpeed * 100, nil
}

// GetNDISDuplexState retrieves duplex mode from NDIS for an adapter.
func (c *WMIClient) GetNDISDuplexState(instanceName string) (string, error) {
	var results []MSNdis_MediaDuplexState
	sanitizedName := c.sanitizeWQLString(instanceName)
	query := fmt.Sprintf("SELECT * FROM MSNdis_MediaDuplexState WHERE InstanceName='%s'", sanitizedName)

	err := c.QueryWithNamespace(&results, query, `root\wmi`)
	if err != nil {
		return "UNKNOWN", fmt.Errorf("failed to query duplex state: %w", err)
	}
	if len(results) == 0 {
		return "UNKNOWN", fmt.Errorf("duplex state for %s not found", instanceName)
	}

	return c.convertDuplexState(results[0].NdisMediaDuplexState), nil
}

// GetNDISVLANId retrieves VLAN ID from NDIS for an adapter.
func (c *WMIClient) GetNDISVLANId(instanceName string) (uint32, error) {
	var results []MSNdis_VlanIdentifier
	sanitizedName := c.sanitizeWQLString(instanceName)
	query := fmt.Sprintf("SELECT * FROM MSNdis_VlanIdentifier WHERE InstanceName='%s'", sanitizedName)

	err := c.QueryWithNamespace(&results, query, `root\wmi`)
	if err != nil {
		return 0, nil // VLAN not configured is not an error.
	}
	if len(results) == 0 {
		return 0, nil
	}

	return results[0].NdisVlanId, nil
}

// GetNDISRSSCapabilities retrieves RSS capabilities from NDIS for an adapter.
func (c *WMIClient) GetNDISRSSCapabilities(instanceName string) (*RSSInfo, error) {
	var results []MSNdis_RSSCapabilities
	sanitizedName := c.sanitizeWQLString(instanceName)
	query := fmt.Sprintf("SELECT * FROM MSNdis_RSSCapabilities WHERE InstanceName='%s'", sanitizedName)

	err := c.QueryWithNamespace(&results, query, `root\wmi`)
	if err != nil {
		return &RSSInfo{Enabled: false}, nil
	}
	if len(results) == 0 {
		return &RSSInfo{Enabled: false}, nil
	}

	return &RSSInfo{
		QueueCount: results[0].NumberOfReceiveQueues,
		Enabled:    results[0].NumberOfReceiveQueues > 0,
	}, nil
}

// =============================================================================
// Hardware Information Queries
// =============================================================================

// GetPnPDeviceInfo retrieves Plug and Play device information.
func (c *WMIClient) GetPnPDeviceInfo(pnpDeviceID string) (*Win32_PnPEntity, error) {
	var entities []Win32_PnPEntity
	sanitizedID := c.sanitizeWQLString(pnpDeviceID)
	// PNPDeviceID contains backslashes which need special escaping.
	sanitizedID = strings.ReplaceAll(sanitizedID, `\`, `\\`)
	query := fmt.Sprintf("SELECT * FROM Win32_PnPEntity WHERE PNPDeviceID='%s'", sanitizedID)

	err := c.Query(&entities, query)
	if err != nil {
		return nil, fmt.Errorf("failed to query PnP device: %w", err)
	}
	if len(entities) == 0 {
		return nil, fmt.Errorf("PnP device %s not found", pnpDeviceID)
	}

	return &entities[0], nil
}

// GetDriverVersion retrieves driver version for a device.
func (c *WMIClient) GetDriverVersion(pnpDeviceID string) (string, error) {
	var drivers []Win32_PnPSignedDriver
	sanitizedID := c.sanitizeWQLString(pnpDeviceID)
	sanitizedID = strings.ReplaceAll(sanitizedID, `\`, `\\`)
	query := fmt.Sprintf("SELECT * FROM Win32_PnPSignedDriver WHERE DeviceID='%s'", sanitizedID)

	err := c.Query(&drivers, query)
	if err != nil {
		return "", fmt.Errorf("failed to query driver version: %w", err)
	}
	if len(drivers) == 0 {
		return "", fmt.Errorf("driver for device %s not found", pnpDeviceID)
	}

	return drivers[0].DriverVersion, nil
}

// GetDriverInfo retrieves detailed driver information.
func (c *WMIClient) GetDriverInfo(pnpDeviceID string) (*Win32_PnPSignedDriver, error) {
	var drivers []Win32_PnPSignedDriver
	sanitizedID := c.sanitizeWQLString(pnpDeviceID)
	sanitizedID = strings.ReplaceAll(sanitizedID, `\`, `\\`)
	query := fmt.Sprintf("SELECT * FROM Win32_PnPSignedDriver WHERE DeviceID='%s'", sanitizedID)

	err := c.Query(&drivers, query)
	if err != nil {
		return nil, fmt.Errorf("failed to query driver info: %w", err)
	}
	if len(drivers) == 0 {
		return nil, fmt.Errorf("driver for device %s not found", pnpDeviceID)
	}

	return &drivers[0], nil
}

// =============================================================================
// Batch Query Optimization
// =============================================================================

// GetAllAdapterDetails retrieves complete adapter information in optimized batch.
func (c *WMIClient) GetAllAdapterDetails() ([]*WMIAdapterDetails, error) {
	// Get all physical adapters.
	adapters, err := c.GetPhysicalNetworkAdapters()
	if err != nil {
		return nil, err
	}

	// Get all configurations.
	configs, err := c.GetAllAdapterConfigurations()
	if err != nil {
		// Continue without configurations.
		configs = nil
	}

	// Build configuration map by index.
	configMap := make(map[uint32]*Win32_NetworkAdapterConfiguration)
	for i := range configs {
		configMap[configs[i].Index] = &configs[i]
	}

	// Build result list.
	results := make([]*WMIAdapterDetails, 0, len(adapters))
	for i := range adapters {
		adapter := &adapters[i]
		details := &WMIAdapterDetails{
			Adapter: adapter,
		}

		// Add configuration if available.
		if config, ok := configMap[adapter.Index]; ok {
			details.Configuration = config
		}

		// Try to get NDIS information.
		instanceName := c.instanceNameFromGUID(adapter.GUID)
		if instanceName != "" {
			if speed, err := c.GetNDISLinkSpeed(instanceName); err == nil {
				details.LinkSpeed = speed
			}
			if duplex, err := c.GetNDISDuplexState(instanceName); err == nil {
				details.DuplexMode = duplex
			}
			if rss, err := c.GetNDISRSSCapabilities(instanceName); err == nil && rss != nil {
				details.RSSQueues = rss.QueueCount
			}
		}

		// Try to get driver version.
		if adapter.PNPDeviceID != "" {
			if version, err := c.GetDriverVersion(adapter.PNPDeviceID); err == nil {
				details.DriverVersion = version
			}
		}

		results = append(results, details)
	}

	return results, nil
}

// =============================================================================
// Helper Methods
// =============================================================================

// instanceNameFromGUID converts a GUID to an NDIS instance name.
func (c *WMIClient) instanceNameFromGUID(guid string) string {
	if guid == "" {
		return ""
	}
	// NDIS instance names are typically the GUID itself.
	return guid
}

// sanitizeWQLString escapes special characters in WQL queries.
func (c *WMIClient) sanitizeWQLString(input string) string {
	// Escape single quotes.
	result := strings.ReplaceAll(input, "'", "''")
	return result
}

// ConvertConnectionStatus converts WMI connection status to string.
func ConvertConnectionStatus(status uint16) string {
	switch status {
	case 0:
		return "Disconnected"
	case 1:
		return "Connecting"
	case 2:
		return "Connected"
	case 3:
		return "Disconnecting"
	case 4:
		return "Hardware Not Present"
	case 5:
		return "Hardware Disabled"
	case 6:
		return "Hardware Malfunction"
	case 7:
		return "Media Disconnected"
	case 8:
		return "Authenticating"
	case 9:
		return "Authentication Succeeded"
	case 10:
		return "Authentication Failed"
	case 11:
		return "Invalid Address"
	case 12:
		return "Credentials Required"
	default:
		return "Unknown"
	}
}

// convertDuplexState converts NDIS duplex state to string.
func (c *WMIClient) convertDuplexState(state uint32) string {
	switch state {
	case 0:
		return "HALF"
	case 1:
		return "FULL"
	default:
		return "UNKNOWN"
	}
}

// =============================================================================
// Error Handling
// =============================================================================

// handleWMIError converts WMI errors to descriptive Go errors.
func (c *WMIClient) handleWMIError(err error, query string) error {
	if err == nil {
		return nil
	}

	errStr := err.Error()

	// Check for common WMI errors.
	if strings.Contains(errStr, "access denied") || strings.Contains(errStr, "Access is denied") {
		return fmt.Errorf("WMI access denied (requires administrator privileges): %w", err)
	}
	if strings.Contains(errStr, "Invalid class") || strings.Contains(errStr, "not found") {
		return fmt.Errorf("WMI class not found (query: %s): %w", query, err)
	}
	if strings.Contains(errStr, "timeout") || strings.Contains(errStr, "Timeout") {
		return fmt.Errorf("WMI query timeout: %w", err)
	}
	if strings.Contains(errStr, "RPC") || strings.Contains(errStr, "unavailable") {
		return fmt.Errorf("WMI service unavailable: %w", err)
	}

	return fmt.Errorf("WMI query failed: %w", err)
}

// IsWMIAvailable checks if WMI is accessible.
func IsWMIAvailable() bool {
	var adapters []Win32_NetworkAdapter
	query := "SELECT Index FROM Win32_NetworkAdapter WHERE Index=0"
	err := wmi.Query(query, &adapters)
	return err == nil
}

// =============================================================================
// Cleanup
// =============================================================================

// Close releases WMI client resources.
func (c *WMIClient) Close() error {
	// The go-ole/wmi library handles cleanup automatically.
	return nil
}
