// Package manager provides business logic for device management
package manager

import (
	"context"
	"database/sql"
	"fmt"
	"log"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"

	"dhcp_monitor/internal/database"
	"dhcp_monitor/internal/watcher"
)

// =============================================================================
// POLICY CONSTANTS
// =============================================================================

const (
	PolicyAutoCreate     = "auto-create"     // Default: auto-create all valid devices
	PolicyManualApproval = "manual-approval" // Queue for admin approval
	PolicyReject         = "reject"          // Reject all unknown devices (lockdown)
)

// =============================================================================
// VALIDATION INTERFACE
// =============================================================================

// ValidationRule interface for pluggable validation
type ValidationRule interface {
	Name() string
	Validate(event *watcher.NetworkEvent) error
}

// =============================================================================
// CREATION STATISTICS
// =============================================================================

// CreationStatistics contains handler metrics
type CreationStatistics struct {
	TotalCreated       int64     `json:"total_created"`
	ValidationFailures int64     `json:"validation_failures"`
	PolicyRejections   int64     `json:"policy_rejections"`
	DuplicatePrevented int64     `json:"duplicate_prevented"`
	LastCreation       time.Time `json:"last_creation"`
}

// =============================================================================
// UNKNOWN DEVICE HANDLER
// =============================================================================

// UnknownDeviceHandler manages creation of new device records
type UnknownDeviceHandler struct {
	db              *database.DatabaseClient
	policy          string
	validationRules []ValidationRule

	// Statistics
	stats      CreationStatistics
	statsMutex sync.RWMutex
}

// NewUnknownDeviceHandler creates a new handler
func NewUnknownDeviceHandler(db *database.DatabaseClient, policy string) *UnknownDeviceHandler {
	if policy == "" {
		policy = PolicyAutoCreate
	}

	handler := &UnknownDeviceHandler{
		db:              db,
		policy:          policy,
		validationRules: make([]ValidationRule, 0),
	}

	// Register default validation rules
	handler.AddValidationRule(&MACFormatValidator{})
	handler.AddValidationRule(&IPAddressValidator{})
	handler.AddValidationRule(&InterfaceNameValidator{
		blacklist: []string{"vEthernet (WSL)", "Hyper-V Virtual"},
	})
	handler.AddValidationRule(NewRateLimitValidator(100)) // 100 devices/minute max

	return handler
}

// =============================================================================
// MAIN HANDLER METHOD
// =============================================================================

// HandleUnknownDevice processes a detection for a device not in database
func (h *UnknownDeviceHandler) HandleUnknownDevice(ctx context.Context, event *watcher.NetworkEvent) (*database.Device, error) {
	// Run validation checks
	if err := h.runValidations(event); err != nil {
		h.statsMutex.Lock()
		h.stats.ValidationFailures++
		h.statsMutex.Unlock()
		return nil, fmt.Errorf("validation failed: %w", err)
	}

	// Check policy
	switch h.policy {
	case PolicyAutoCreate:
		return h.createDevice(ctx, event)

	case PolicyManualApproval:
		h.statsMutex.Lock()
		h.stats.PolicyRejections++
		h.statsMutex.Unlock()
		return nil, fmt.Errorf("device requires manual approval (MAC=%s)", event.MACAddress)

	case PolicyReject:
		h.statsMutex.Lock()
		h.stats.PolicyRejections++
		h.statsMutex.Unlock()
		log.Printf("[UNKNOWN_DEVICE] Rejected device (lockdown mode): MAC=%s", event.MACAddress)
		return nil, fmt.Errorf("unknown devices rejected (lockdown mode)")

	default:
		return nil, fmt.Errorf("unknown policy: %s", h.policy)
	}
}

// =============================================================================
// DEVICE CREATION
// =============================================================================

// createDevice creates a new device record in the database
func (h *UnknownDeviceHandler) createDevice(ctx context.Context, event *watcher.NetworkEvent) (*database.Device, error) {
	// Double-check for race condition
	if h.checkForDuplicate(ctx, event.MACAddress) {
		h.statsMutex.Lock()
		h.stats.DuplicatePrevented++
		h.statsMutex.Unlock()

		// Fetch and return existing device
		existing, err := h.db.GetDeviceByMAC(ctx, event.MACAddress)
		if err == nil {
			return existing, nil
		}
		return nil, fmt.Errorf("race condition detected but device fetch failed: %w", err)
	}

	// Create Device struct with UNTRUSTED status
	device := &database.Device{
		DeviceID:        uuid.New(),
		MACAddress:      event.MACAddress,
		CurrentIP:       event.IPAddress,
		Hostname:        sql.NullString{String: event.Hostname, Valid: event.Hostname != ""},
		TrustStatus:     "UNTRUSTED", // CRITICAL: Default to UNTRUSTED
		InterfaceName:   event.InterfaceName,
		InterfaceIndex:  int32(event.InterfaceIndex),
		Status:          "ACTIVE", // Must be ACTIVE/OFFLINE/EXPIRED (uppercase)
		IsOnline:        true,
		DetectionMethod: database.DetectionMethod(event.DetectionSource),
		FirstSeen:       time.Now(),
		LastSeen:        time.Now(),
	}

	// Lookup MAC vendor (optional)
	vendorName := h.lookupMACVendor(event.MACAddress)
	device.Vendor = sql.NullString{String: vendorName, Valid: vendorName != ""}

	// Create device in database
	if err := h.db.CreateDevice(ctx, device); err != nil {
		return nil, fmt.Errorf("database create failed: %w", err)
	}

	// Create initial IP history record (non-critical)
	if err := h.createInitialIPHistory(ctx, device); err != nil {
		log.Printf("[UNKNOWN_DEVICE] Warning: IP history creation failed: %v", err)
	}

	// Update statistics
	h.statsMutex.Lock()
	h.stats.TotalCreated++
	h.stats.LastCreation = time.Now()
	h.statsMutex.Unlock()

	log.Printf("[UNKNOWN_DEVICE] Created new device: MAC=%s IP=%s Interface=%s Trust=%s",
		device.MACAddress, device.CurrentIP.String(), device.InterfaceName, device.TrustStatus)

	return device, nil
}

// createInitialIPHistory creates audit trail for first IP assignment
func (h *UnknownDeviceHandler) createInitialIPHistory(ctx context.Context, device *database.Device) error {
	history := &database.IPHistory{
		HistoryID:      uuid.New(),
		DeviceID:       device.DeviceID,
		IPAddress:      device.CurrentIP,
		InterfaceName:  device.InterfaceName,
		InterfaceIndex: device.InterfaceIndex,
		ChangeReason:   "INITIAL_DETECTION",
		AssignedAt:     device.FirstSeen,
	}

	return h.db.CreateIPHistory(ctx, history)
}

// =============================================================================
// VALIDATION METHODS
// =============================================================================

// AddValidationRule adds a validation rule
func (h *UnknownDeviceHandler) AddValidationRule(rule ValidationRule) {
	h.validationRules = append(h.validationRules, rule)
}

// runValidations executes all validation rules
func (h *UnknownDeviceHandler) runValidations(event *watcher.NetworkEvent) error {
	for _, rule := range h.validationRules {
		if err := rule.Validate(event); err != nil {
			return fmt.Errorf("%s: %w", rule.Name(), err)
		}
	}
	return nil
}

// =============================================================================
// HELPER METHODS
// =============================================================================

// checkForDuplicate verifies device doesn't exist (race condition check)
func (h *UnknownDeviceHandler) checkForDuplicate(ctx context.Context, mac string) bool {
	_, err := h.db.GetDeviceByMAC(ctx, mac)
	return err == nil // Device exists if no error
}

// lookupMACVendor resolves MAC OUI to vendor name
func (h *UnknownDeviceHandler) lookupMACVendor(mac string) string {
	// Extract first 3 octets (OUI)
	parts := strings.Split(mac, ":")
	if len(parts) < 3 {
		return ""
	}
	oui := strings.ToUpper(parts[0] + parts[1] + parts[2])

	// Common OUI prefixes (basic lookup table)
	vendors := map[string]string{
		"ACDE48": "Apple, Inc.",
		"3C06A7": "Apple, Inc.",
		"D4619D": "Samsung Electronics",
		"9C5A44": "Samsung Electronics",
		"B4A9FC": "Samsung Electronics",
		"FC1A11": "Motorola Mobility",
		"A4C494": "Intel Corporate",
		"3C7C3F": "ASUSTek Computer",
		"2C549D": "HP Inc.",
		"001A2B": "Hewlett Packard",
		"D89D67": "Xiaomi Communications",
		"8C8590": "Xiaomi Communications",
		"D4B16C": "Google, Inc.",
		"A47B2C": "Google, Inc.",
		"A4FC77": "Microsoft Corporation",
		"7C1E52": "Microsoft Corporation",
	}

	if vendor, ok := vendors[oui]; ok {
		return vendor
	}
	return ""
}

// GetStatistics returns handler metrics
func (h *UnknownDeviceHandler) GetStatistics() *CreationStatistics {
	h.statsMutex.RLock()
	defer h.statsMutex.RUnlock()

	stats := h.stats // Copy
	return &stats
}

// SetPolicy updates the handling policy
func (h *UnknownDeviceHandler) SetPolicy(policy string) error {
	switch policy {
	case PolicyAutoCreate, PolicyManualApproval, PolicyReject:
		h.policy = policy
		log.Printf("[UNKNOWN_DEVICE] Policy changed to: %s", policy)
		return nil
	default:
		return fmt.Errorf("invalid policy: %s", policy)
	}
}

// GetPolicy returns current policy
func (h *UnknownDeviceHandler) GetPolicy() string {
	return h.policy
}

// =============================================================================
// VALIDATION RULE IMPLEMENTATIONS
// =============================================================================

// MACFormatValidator validates MAC address format
type MACFormatValidator struct{}

func (v *MACFormatValidator) Name() string { return "MACFormatValidator" }

func (v *MACFormatValidator) Validate(event *watcher.NetworkEvent) error {
	if event.MACAddress == "" {
		return fmt.Errorf("MAC address is empty")
	}

	// Check format: AA:BB:CC:DD:EE:FF
	macRegex := regexp.MustCompile(`^([0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}$`)
	if !macRegex.MatchString(event.MACAddress) {
		return fmt.Errorf("invalid MAC format: %s", event.MACAddress)
	}

	// Check for broadcast/multicast
	if event.MACAddress == "FF:FF:FF:FF:FF:FF" {
		return fmt.Errorf("broadcast MAC not allowed")
	}

	return nil
}

// IPAddressValidator validates IP address
type IPAddressValidator struct{}

func (v *IPAddressValidator) Name() string { return "IPAddressValidator" }

func (v *IPAddressValidator) Validate(event *watcher.NetworkEvent) error {
	if event.IPAddress == nil {
		return fmt.Errorf("IP address is nil")
	}

	ip := event.IPAddress

	if ip.IsLoopback() {
		return fmt.Errorf("loopback IP not allowed")
	}

	if ip.IsMulticast() {
		return fmt.Errorf("multicast IP not allowed")
	}

	if ip.IsUnspecified() {
		return fmt.Errorf("unspecified IP (0.0.0.0) not allowed")
	}

	// Check link-local (169.254.x.x)
	if ip4 := ip.To4(); ip4 != nil {
		if ip4[0] == 169 && ip4[1] == 254 {
			return fmt.Errorf("link-local IP not allowed")
		}
	}

	return nil
}

// InterfaceNameValidator validates interface name
type InterfaceNameValidator struct {
	blacklist []string
}

func (v *InterfaceNameValidator) Name() string { return "InterfaceNameValidator" }

func (v *InterfaceNameValidator) Validate(event *watcher.NetworkEvent) error {
	if event.InterfaceName == "" {
		return fmt.Errorf("interface name is empty")
	}

	for _, bl := range v.blacklist {
		if strings.Contains(event.InterfaceName, bl) {
			return fmt.Errorf("interface blacklisted: %s", event.InterfaceName)
		}
	}

	return nil
}

// RateLimitValidator prevents creation flood
type RateLimitValidator struct {
	maxPerMinute    int
	recentCreations []time.Time
	mutex           sync.Mutex
}

func NewRateLimitValidator(maxPerMinute int) *RateLimitValidator {
	return &RateLimitValidator{
		maxPerMinute:    maxPerMinute,
		recentCreations: make([]time.Time, 0),
	}
}

func (v *RateLimitValidator) Name() string { return "RateLimitValidator" }

func (v *RateLimitValidator) Validate(event *watcher.NetworkEvent) error {
	v.mutex.Lock()
	defer v.mutex.Unlock()

	now := time.Now()
	cutoff := now.Add(-time.Minute)

	// Remove old timestamps
	filtered := make([]time.Time, 0)
	for _, t := range v.recentCreations {
		if t.After(cutoff) {
			filtered = append(filtered, t)
		}
	}
	v.recentCreations = filtered

	if len(v.recentCreations) >= v.maxPerMinute {
		return fmt.Errorf("rate limit exceeded: %d devices/min", v.maxPerMinute)
	}

	v.recentCreations = append(v.recentCreations, now)
	return nil
}
