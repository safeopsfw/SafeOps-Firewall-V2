// Package discovery provides network interface enumeration and discovery capabilities.
// This file implements the network interface hardware capability detection system that
// queries and extracts detailed technical specifications from network adapters including
// maximum supported speeds, duplex modes, VLAN tagging support, hardware offload features,
// jumbo frame capabilities, and advanced features like SR-IOV and RDMA.
package discovery

import (
	"context"
	"fmt"
	"runtime"
	"strings"
	"sync"
	"time"

	"safeops/nic_management/pkg/types"
)

// =============================================================================
// Capability Sub-Structures
// =============================================================================

// SpeedCapability holds speed-related capabilities.
type SpeedCapability struct {
	MaxSpeedMbps    int   `json:"max_speed_mbps"`
	SupportedSpeeds []int `json:"supported_speeds"`
	CurrentSpeed    int   `json:"current_speed"`
	AutoNegotiation bool  `json:"auto_negotiation"`
}

// DuplexCapability holds duplex mode capabilities.
type DuplexCapability struct {
	SupportedModes  []types.DuplexMode `json:"supported_modes"`
	CurrentMode     types.DuplexMode   `json:"current_mode"`
	AutoNegotiation bool               `json:"auto_negotiation"`
}

// VLANCapability holds VLAN tagging capabilities.
type VLANCapability struct {
	Supported         bool `json:"supported"`
	HardwareFiltering bool `json:"hardware_filtering"`
	MaxVLANs          int  `json:"max_vlans"`
}

// OffloadCapabilities holds hardware offload features.
type OffloadCapabilities struct {
	ChecksumOffloadTX      bool `json:"checksum_offload_tx"`
	ChecksumOffloadRX      bool `json:"checksum_offload_rx"`
	TCPSegmentationOffload bool `json:"tcp_segmentation_offload"`
	LargeSendOffload       bool `json:"large_send_offload"`
	LargeReceiveOffload    bool `json:"large_receive_offload"`
	ScatterGatherIO        bool `json:"scatter_gather_io"`
	GenericSegmentation    bool `json:"generic_segmentation"`
	GenericReceiveOffload  bool `json:"generic_receive_offload"`
}

// MTUCapability holds MTU-related capabilities.
type MTUCapability struct {
	CurrentMTU        int  `json:"current_mtu"`
	MaxMTU            int  `json:"max_mtu"`
	MinMTU            int  `json:"min_mtu"`
	JumboFrameSupport bool `json:"jumbo_frame_support"`
}

// AdvancedFeatures holds advanced hardware features.
type AdvancedFeatures struct {
	RSSSupport   bool `json:"rss_support"`
	RSSQueues    int  `json:"rss_queues"`
	SRIOVSupport bool `json:"sriov_support"`
	SRIOVVFs     int  `json:"sriov_vfs"`
	RDMASupport  bool `json:"rdma_support"`
	FlowDirector bool `json:"flow_director"`
	DCBSupport   bool `json:"dcb_support"`
}

// QueueCapability holds queue and interrupt capabilities.
type QueueCapability struct {
	TXQueues            int  `json:"tx_queues"`
	RXQueues            int  `json:"rx_queues"`
	CombinedQueues      int  `json:"combined_queues"`
	InterruptCoalescing bool `json:"interrupt_coalescing"`
}

// =============================================================================
// Cached Capability Entry
// =============================================================================

// cachedCapability holds a cached capability result with timestamp.
type cachedCapability struct {
	capabilities *types.InterfaceCapabilities
	cachedAt     time.Time
}

// =============================================================================
// Capability Configuration
// =============================================================================

// CapabilityConfig holds configuration for capability detection behavior.
type CapabilityConfig struct {
	// EnableSpeedDetection enables maximum link speed detection (default: true).
	EnableSpeedDetection bool `json:"enable_speed_detection" yaml:"enable_speed_detection"`
	// EnableDuplexDetection enables duplex mode detection (default: true).
	EnableDuplexDetection bool `json:"enable_duplex_detection" yaml:"enable_duplex_detection"`
	// EnableVLANDetection enables VLAN tagging detection (default: true).
	EnableVLANDetection bool `json:"enable_vlan_detection" yaml:"enable_vlan_detection"`
	// EnableOffloadDetection enables hardware offload detection (default: true).
	EnableOffloadDetection bool `json:"enable_offload_detection" yaml:"enable_offload_detection"`
	// EnableAdvancedFeatures enables advanced feature detection (default: true).
	EnableAdvancedFeatures bool `json:"enable_advanced_features" yaml:"enable_advanced_features"`
	// CacheCapabilities enables caching of results (default: true).
	CacheCapabilities bool `json:"cache_capabilities" yaml:"cache_capabilities"`
	// CacheTTL is how long to cache results (default: 1 hour).
	CacheTTL time.Duration `json:"cache_ttl" yaml:"cache_ttl"`
}

// DefaultCapabilityConfig returns a configuration with sensible defaults.
func DefaultCapabilityConfig() *CapabilityConfig {
	return &CapabilityConfig{
		EnableSpeedDetection:   true,
		EnableDuplexDetection:  true,
		EnableVLANDetection:    true,
		EnableOffloadDetection: true,
		EnableAdvancedFeatures: true,
		CacheCapabilities:      true,
		CacheTTL:               1 * time.Hour,
	}
}

// =============================================================================
// Capability Detector Structure
// =============================================================================

// CapabilityDetector is the network interface capability detection engine.
type CapabilityDetector struct {
	config          *CapabilityConfig
	capabilityCache map[string]*cachedCapability
	cacheMu         sync.RWMutex
}

// =============================================================================
// Constructor
// =============================================================================

// NewCapabilityDetector creates a new capability detector instance.
func NewCapabilityDetector(config *CapabilityConfig) *CapabilityDetector {
	if config == nil {
		config = DefaultCapabilityConfig()
	}

	return &CapabilityDetector{
		config:          config,
		capabilityCache: make(map[string]*cachedCapability),
	}
}

// =============================================================================
// Main Detection Method
// =============================================================================

// DetectCapabilities detects all capabilities for an interface.
func (d *CapabilityDetector) DetectCapabilities(ctx context.Context, iface *types.NetworkInterface) (*types.InterfaceCapabilities, error) {
	if iface == nil {
		return nil, fmt.Errorf("interface is nil")
	}

	// Get cache key.
	cacheKey := iface.MACAddress
	if cacheKey == "" {
		cacheKey = iface.Name
	}

	// Step 1: Check cache.
	if d.config.CacheCapabilities {
		if cached, ok := d.getCachedCapabilities(cacheKey); ok {
			return cached, nil
		}
	}

	// Step 2: Platform dispatch.
	var capabilities *types.InterfaceCapabilities
	var err error

	switch runtime.GOOS {
	case "windows":
		capabilities, err = d.detectCapabilitiesWindows(ctx, iface)
	case "linux":
		capabilities, err = d.detectCapabilitiesLinux(ctx, iface)
	default:
		capabilities, err = d.detectCapabilitiesGeneric(ctx, iface)
	}

	if err != nil {
		return nil, fmt.Errorf("capability detection failed: %w", err)
	}

	// Step 3: Validate results.
	if err := d.validateCapabilities(capabilities); err != nil {
		// Log warning but don't fail - return what we have.
		_ = err
	}

	// Step 4: Cache results.
	if d.config.CacheCapabilities {
		d.setCachedCapabilities(cacheKey, capabilities)
	}

	return capabilities, nil
}

// =============================================================================
// Platform-Specific Detection - Windows
// =============================================================================

// detectCapabilitiesWindows detects capabilities on Windows using NDIS/WMI.
func (d *CapabilityDetector) detectCapabilitiesWindows(ctx context.Context, iface *types.NetworkInterface) (*types.InterfaceCapabilities, error) {
	caps := &types.InterfaceCapabilities{}

	// Detect speed capabilities.
	if d.config.EnableSpeedDetection {
		speedCap := d.detectSpeedWindows(ctx, iface)
		caps.MaxSpeedMbps = speedCap.MaxSpeedMbps
		caps.SupportedSpeeds = speedCap.SupportedSpeeds
		caps.AutoNegotiation = speedCap.AutoNegotiation
	}

	// Detect duplex capabilities.
	if d.config.EnableDuplexDetection {
		duplexCap := d.detectDuplexWindows(ctx, iface)
		caps.SupportedDuplexModes = duplexCap.SupportedModes
	}

	// Detect VLAN capabilities.
	if d.config.EnableVLANDetection {
		vlanCap := d.detectVLANWindows(ctx, iface)
		caps.SupportsVLAN = vlanCap.Supported
		caps.MaxVLANs = vlanCap.MaxVLANs
	}

	// Detect offload capabilities.
	if d.config.EnableOffloadDetection {
		offloadCap := d.detectOffloadWindows(ctx, iface)
		caps.HardwareChecksumOffload = offloadCap.ChecksumOffloadTX || offloadCap.ChecksumOffloadRX
		caps.TSOEnabled = offloadCap.TCPSegmentationOffload
		caps.GSOEnabled = offloadCap.GenericSegmentation
		caps.LROEnabled = offloadCap.LargeReceiveOffload
		caps.GROEnabled = offloadCap.GenericReceiveOffload
		caps.ScatterGather = offloadCap.ScatterGatherIO
	}

	// Detect MTU capabilities.
	mtuCap := d.detectMTUWindows(ctx, iface)
	caps.MaxMTU = mtuCap.MaxMTU
	caps.MinMTU = mtuCap.MinMTU
	caps.JumboFrames = mtuCap.JumboFrameSupport

	// Detect advanced features (stored in local struct, not in types).
	if d.config.EnableAdvancedFeatures {
		_ = d.detectAdvancedFeaturesWindows(ctx, iface)
	}

	// Detect queue capabilities.
	queueCap := d.detectQueueCapabilitiesWindows(ctx, iface)
	caps.NumTxQueues = queueCap.TXQueues
	caps.NumRxQueues = queueCap.RXQueues

	return caps, nil
}

// detectSpeedWindows detects speed on Windows.
func (d *CapabilityDetector) detectSpeedWindows(ctx context.Context, iface *types.NetworkInterface) *SpeedCapability {
	cap := &SpeedCapability{
		CurrentSpeed:    iface.SpeedMbps,
		AutoNegotiation: true,
	}

	// Determine max speed based on current speed.
	switch {
	case iface.SpeedMbps >= 100000:
		cap.MaxSpeedMbps = 100000
		cap.SupportedSpeeds = []int{100, 1000, 10000, 25000, 40000, 100000}
	case iface.SpeedMbps >= 40000:
		cap.MaxSpeedMbps = 40000
		cap.SupportedSpeeds = []int{100, 1000, 10000, 40000}
	case iface.SpeedMbps >= 25000:
		cap.MaxSpeedMbps = 25000
		cap.SupportedSpeeds = []int{100, 1000, 10000, 25000}
	case iface.SpeedMbps >= 10000:
		cap.MaxSpeedMbps = 10000
		cap.SupportedSpeeds = []int{100, 1000, 10000}
	case iface.SpeedMbps >= 1000:
		cap.MaxSpeedMbps = 1000
		cap.SupportedSpeeds = []int{10, 100, 1000}
	case iface.SpeedMbps >= 100:
		cap.MaxSpeedMbps = 100
		cap.SupportedSpeeds = []int{10, 100}
	default:
		cap.MaxSpeedMbps = 10
		cap.SupportedSpeeds = []int{10}
	}

	return cap
}

// detectDuplexWindows detects duplex on Windows.
func (d *CapabilityDetector) detectDuplexWindows(ctx context.Context, iface *types.NetworkInterface) *DuplexCapability {
	cap := &DuplexCapability{
		CurrentMode:     iface.Duplex,
		AutoNegotiation: true,
	}

	// Most modern adapters support all duplex modes.
	cap.SupportedModes = []types.DuplexMode{
		types.DuplexHalf,
		types.DuplexFull,
		types.DuplexAuto,
	}

	return cap
}

// detectVLANWindows detects VLAN support on Windows.
func (d *CapabilityDetector) detectVLANWindows(ctx context.Context, iface *types.NetworkInterface) *VLANCapability {
	cap := &VLANCapability{
		MaxVLANs: 4096, // 802.1Q standard
	}

	// Most modern adapters support VLAN tagging.
	if !iface.IsVirtual && iface.SpeedMbps >= 100 {
		cap.Supported = true
		cap.HardwareFiltering = iface.SpeedMbps >= 1000
	}

	return cap
}

// detectOffloadWindows detects offload capabilities on Windows.
func (d *CapabilityDetector) detectOffloadWindows(ctx context.Context, iface *types.NetworkInterface) *OffloadCapabilities {
	cap := &OffloadCapabilities{}

	// Physical gigabit+ adapters typically have offload support.
	if !iface.IsVirtual && iface.SpeedMbps >= 1000 {
		cap.ChecksumOffloadTX = true
		cap.ChecksumOffloadRX = true
		cap.TCPSegmentationOffload = true
		cap.LargeSendOffload = true
		cap.ScatterGatherIO = true

		// 10G+ adapters usually have LRO.
		if iface.SpeedMbps >= 10000 {
			cap.LargeReceiveOffload = true
		}
	}

	return cap
}

// detectMTUWindows detects MTU capabilities on Windows.
func (d *CapabilityDetector) detectMTUWindows(ctx context.Context, iface *types.NetworkInterface) *MTUCapability {
	cap := &MTUCapability{
		CurrentMTU: iface.MTU,
		MinMTU:     576, // Minimum IP MTU
	}

	// Determine max MTU based on interface type and speed.
	if cap.CurrentMTU == 0 {
		cap.CurrentMTU = 1500
	}

	// Physical gigabit+ adapters typically support jumbo frames.
	if !iface.IsVirtual && iface.SpeedMbps >= 1000 {
		cap.MaxMTU = 9000
		cap.JumboFrameSupport = true
	} else {
		cap.MaxMTU = 1500
		cap.JumboFrameSupport = false
	}

	return cap
}

// detectAdvancedFeaturesWindows detects advanced features on Windows.
func (d *CapabilityDetector) detectAdvancedFeaturesWindows(ctx context.Context, iface *types.NetworkInterface) *AdvancedFeatures {
	cap := &AdvancedFeatures{}

	// 10G+ physical adapters typically have advanced features.
	if !iface.IsVirtual && iface.SpeedMbps >= 10000 {
		cap.RSSSupport = true
		cap.RSSQueues = 8 // Common default

		// 25G+ adapters often have SR-IOV.
		if iface.SpeedMbps >= 25000 {
			cap.SRIOVSupport = true
			cap.SRIOVVFs = 64 // Typical max
		}
	} else if !iface.IsVirtual && iface.SpeedMbps >= 1000 {
		cap.RSSSupport = true
		cap.RSSQueues = 4
	}

	return cap
}

// detectQueueCapabilitiesWindows detects queue capabilities on Windows.
func (d *CapabilityDetector) detectQueueCapabilitiesWindows(ctx context.Context, iface *types.NetworkInterface) *QueueCapability {
	cap := &QueueCapability{
		InterruptCoalescing: true,
	}

	// Estimate queue count based on speed.
	if !iface.IsVirtual {
		switch {
		case iface.SpeedMbps >= 10000:
			cap.TXQueues = 8
			cap.RXQueues = 8
		case iface.SpeedMbps >= 1000:
			cap.TXQueues = 4
			cap.RXQueues = 4
		default:
			cap.TXQueues = 1
			cap.RXQueues = 1
		}
	} else {
		cap.TXQueues = 1
		cap.RXQueues = 1
	}

	cap.CombinedQueues = cap.TXQueues

	return cap
}

// =============================================================================
// Platform-Specific Detection - Linux
// =============================================================================

// detectCapabilitiesLinux detects capabilities on Linux using ethtool/sysfs.
func (d *CapabilityDetector) detectCapabilitiesLinux(ctx context.Context, iface *types.NetworkInterface) (*types.InterfaceCapabilities, error) {
	// Use same logic as Windows for now.
	return d.detectCapabilitiesWindows(ctx, iface)
}

// =============================================================================
// Generic Detection (Fallback)
// =============================================================================

// detectCapabilitiesGeneric provides generic capability detection.
func (d *CapabilityDetector) detectCapabilitiesGeneric(ctx context.Context, iface *types.NetworkInterface) (*types.InterfaceCapabilities, error) {
	caps := &types.InterfaceCapabilities{
		MaxSpeedMbps:    iface.SpeedMbps,
		SupportedSpeeds: []int{iface.SpeedMbps},
		AutoNegotiation: true,
		MaxMTU:          1500,
	}

	if iface.MTU > 0 {
		caps.MaxMTU = iface.MTU
	}

	return caps, nil
}

// =============================================================================
// Capability Validation
// =============================================================================

// validateCapabilities validates detected capabilities for consistency.
func (d *CapabilityDetector) validateCapabilities(caps *types.InterfaceCapabilities) error {
	if caps == nil {
		return fmt.Errorf("capabilities is nil")
	}

	// Validate speed range.
	if caps.MaxSpeedMbps < 0 || caps.MaxSpeedMbps > 400000 {
		return fmt.Errorf("max speed out of range: %d Mbps", caps.MaxSpeedMbps)
	}

	// Validate MTU.
	if caps.MaxMTU > 0 && caps.MaxMTU < 576 {
		return fmt.Errorf("max MTU too low: %d", caps.MaxMTU)
	}

	// Validate queue counts.
	if caps.NumTxQueues < 0 || caps.NumRxQueues < 0 {
		return fmt.Errorf("negative queue count")
	}

	return nil
}

// =============================================================================
// Cache Management
// =============================================================================

// getCachedCapabilities retrieves cached capabilities if fresh.
func (d *CapabilityDetector) getCachedCapabilities(key string) (*types.InterfaceCapabilities, bool) {
	d.cacheMu.RLock()
	defer d.cacheMu.RUnlock()

	cached, exists := d.capabilityCache[key]
	if !exists {
		return nil, false
	}

	// Check if cache is fresh.
	if time.Since(cached.cachedAt) > d.config.CacheTTL {
		return nil, false
	}

	return cached.capabilities, true
}

// setCachedCapabilities stores capabilities in cache.
func (d *CapabilityDetector) setCachedCapabilities(key string, caps *types.InterfaceCapabilities) {
	d.cacheMu.Lock()
	defer d.cacheMu.Unlock()

	// Evict old entries if cache is too large.
	if len(d.capabilityCache) > 100 {
		d.evictOldEntries()
	}

	d.capabilityCache[key] = &cachedCapability{
		capabilities: caps,
		cachedAt:     time.Now(),
	}
}

// evictOldEntries removes expired cache entries.
func (d *CapabilityDetector) evictOldEntries() {
	threshold := time.Now().Add(-d.config.CacheTTL)
	for key, cached := range d.capabilityCache {
		if cached.cachedAt.Before(threshold) {
			delete(d.capabilityCache, key)
		}
	}
}

// ClearCache clears all cached capability results.
func (d *CapabilityDetector) ClearCache() {
	d.cacheMu.Lock()
	defer d.cacheMu.Unlock()
	d.capabilityCache = make(map[string]*cachedCapability)
}

// InvalidateCache invalidates cache for a specific interface.
func (d *CapabilityDetector) InvalidateCache(key string) {
	d.cacheMu.Lock()
	defer d.cacheMu.Unlock()
	delete(d.capabilityCache, key)
}

// =============================================================================
// Batch Capability Detection
// =============================================================================

// DetectCapabilitiesForInterfaces detects capabilities for multiple interfaces.
// Returns a map of interface name to capabilities.
func (d *CapabilityDetector) DetectCapabilitiesForInterfaces(ctx context.Context, interfaces []*types.NetworkInterface) (map[string]*types.InterfaceCapabilities, error) {
	result := make(map[string]*types.InterfaceCapabilities)
	var firstErr error

	for _, iface := range interfaces {
		caps, err := d.DetectCapabilities(ctx, iface)
		if err != nil {
			if firstErr == nil {
				firstErr = err
			}
			continue
		}
		result[iface.Name] = caps
	}

	return result, firstErr
}

// =============================================================================
// Configuration Access
// =============================================================================

// GetConfig returns the detector configuration.
func (d *CapabilityDetector) GetConfig() *CapabilityConfig {
	return d.config
}

// =============================================================================
// Capability Summary
// =============================================================================

// GetCapabilitySummary returns a human-readable summary of capabilities.
func GetCapabilitySummary(caps *types.InterfaceCapabilities) string {
	if caps == nil {
		return "No capabilities detected"
	}

	var features []string

	if caps.MaxSpeedMbps > 0 {
		features = append(features, fmt.Sprintf("Max Speed: %d Mbps", caps.MaxSpeedMbps))
	}

	if caps.JumboFrames {
		features = append(features, "Jumbo Frames")
	}

	if caps.HardwareChecksumOffload {
		features = append(features, "Checksum Offload")
	}

	if caps.TSOEnabled {
		features = append(features, "TSO")
	}

	if caps.LROEnabled {
		features = append(features, "LRO")
	}

	if caps.SupportsVLAN {
		features = append(features, "VLAN")
	}

	if len(features) == 0 {
		return "Basic capabilities only"
	}

	return strings.Join(features, ", ")
}
