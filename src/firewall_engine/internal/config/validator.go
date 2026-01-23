// Package config provides configuration loading, parsing, and validation.
package config

import (
	"fmt"
	"net"
	"strings"

	"firewall_engine/pkg/models"
)

// ============================================================================
// Validation Result
// ============================================================================

// Severity represents the severity level of a validation issue.
type Severity int

const (
	// SeverityInfo is informational (not a problem).
	SeverityInfo Severity = iota

	// SeverityWarning is a potential issue that doesn't prevent loading.
	SeverityWarning

	// SeverityError is a critical issue that prevents loading.
	SeverityError
)

func (s Severity) String() string {
	switch s {
	case SeverityInfo:
		return "INFO"
	case SeverityWarning:
		return "WARNING"
	case SeverityError:
		return "ERROR"
	default:
		return "UNKNOWN"
	}
}

// ValidationIssue represents a single validation problem.
type ValidationIssue struct {
	Severity Severity
	Path     string // Config path (e.g., "rules[0].action")
	Message  string
	Value    interface{} // The problematic value
}

func (vi *ValidationIssue) Error() string {
	return fmt.Sprintf("[%s] %s: %s", vi.Severity, vi.Path, vi.Message)
}

// ValidationResult contains all validation issues.
type ValidationResult struct {
	Issues []ValidationIssue
	Valid  bool // True if no errors (warnings are allowed)
}

// NewValidationResult creates an empty validation result.
func NewValidationResult() *ValidationResult {
	return &ValidationResult{
		Issues: make([]ValidationIssue, 0),
		Valid:  true,
	}
}

// AddInfo adds an informational message.
func (vr *ValidationResult) AddInfo(path, message string) {
	vr.Issues = append(vr.Issues, ValidationIssue{
		Severity: SeverityInfo,
		Path:     path,
		Message:  message,
	})
}

// AddWarning adds a warning.
func (vr *ValidationResult) AddWarning(path, message string, value interface{}) {
	vr.Issues = append(vr.Issues, ValidationIssue{
		Severity: SeverityWarning,
		Path:     path,
		Message:  message,
		Value:    value,
	})
}

// AddError adds an error (marks result as invalid).
func (vr *ValidationResult) AddError(path, message string, value interface{}) {
	vr.Issues = append(vr.Issues, ValidationIssue{
		Severity: SeverityError,
		Path:     path,
		Message:  message,
		Value:    value,
	})
	vr.Valid = false
}

// HasErrors returns true if there are any errors.
func (vr *ValidationResult) HasErrors() bool {
	return !vr.Valid
}

// HasWarnings returns true if there are any warnings.
func (vr *ValidationResult) HasWarnings() bool {
	for _, issue := range vr.Issues {
		if issue.Severity == SeverityWarning {
			return true
		}
	}
	return false
}

// Errors returns only error issues.
func (vr *ValidationResult) Errors() []ValidationIssue {
	var errors []ValidationIssue
	for _, issue := range vr.Issues {
		if issue.Severity == SeverityError {
			errors = append(errors, issue)
		}
	}
	return errors
}

// Warnings returns only warning issues.
func (vr *ValidationResult) Warnings() []ValidationIssue {
	var warnings []ValidationIssue
	for _, issue := range vr.Issues {
		if issue.Severity == SeverityWarning {
			warnings = append(warnings, issue)
		}
	}
	return warnings
}

// Merge combines another ValidationResult into this one.
func (vr *ValidationResult) Merge(other *ValidationResult) {
	if other == nil {
		return
	}
	vr.Issues = append(vr.Issues, other.Issues...)
	if !other.Valid {
		vr.Valid = false
	}
}

// String returns a human-readable summary.
func (vr *ValidationResult) String() string {
	var sb strings.Builder
	errorCount := 0
	warningCount := 0

	for _, issue := range vr.Issues {
		switch issue.Severity {
		case SeverityError:
			errorCount++
		case SeverityWarning:
			warningCount++
		}
		sb.WriteString(issue.Error())
		sb.WriteString("\n")
	}

	summary := fmt.Sprintf("Validation: %d errors, %d warnings", errorCount, warningCount)
	if vr.Valid {
		summary += " (PASSED)"
	} else {
		summary += " (FAILED)"
	}

	return summary + "\n" + sb.String()
}

// ============================================================================
// Validator
// ============================================================================

// Validator validates firewall configuration.
type Validator struct {
	// Limits for performance validation
	MaxRules          int
	MaxRulesPerGroup  int
	MaxObjectEntries  int
	MaxDomainPatterns int
	WarnRuleThreshold int

	// Known object names (populated during validation)
	addressObjects map[string]bool
	portObjects    map[string]bool
	domainObjects  map[string]bool
	serviceObjects map[string]bool
	ruleGroups     map[string]bool
}

// NewValidator creates a validator with default limits.
func NewValidator() *Validator {
	return &Validator{
		MaxRules:          10000,
		MaxRulesPerGroup:  100,
		MaxObjectEntries:  1000,
		MaxDomainPatterns: 50,
		WarnRuleThreshold: 5000,
		addressObjects:    make(map[string]bool),
		portObjects:       make(map[string]bool),
		domainObjects:     make(map[string]bool),
		serviceObjects:    make(map[string]bool),
		ruleGroups:        make(map[string]bool),
	}
}

// Validate performs complete validation of a configuration.
func (v *Validator) Validate(cfg *Config) *ValidationResult {
	result := NewValidationResult()

	if cfg == nil {
		result.AddError("", "configuration is nil", nil)
		return result
	}

	// Collect object names first
	v.collectObjectNames(cfg)

	// Validate each section
	v.validateDefaultPolicies(cfg.DefaultPolicies, result)
	v.validateConnectionTracking(cfg.ConnectionTracking, result)
	v.validateSecurityZones(cfg.SecurityZones, result)
	v.validateAddressObjects(cfg.AddressObjects, result)
	v.validatePortObjects(cfg.PortObjects, result)
	v.validateDomainObjects(cfg.DomainObjects, result)
	v.validateRuleGroups(cfg.RuleGroups, result)
	v.validateRules(cfg.Rules, result)
	v.validateAdvanced(cfg.Advanced, result)

	// Performance validation
	v.validatePerformance(cfg, result)

	return result
}

// collectObjectNames populates object name maps for reference validation.
func (v *Validator) collectObjectNames(cfg *Config) {
	for _, obj := range cfg.AddressObjects {
		v.addressObjects[obj.ObjectName] = true
	}
	for _, obj := range cfg.PortObjects {
		v.portObjects[obj.ObjectName] = true
	}
	for _, obj := range cfg.DomainObjects {
		v.domainObjects[obj.ObjectName] = true
	}
	for _, obj := range cfg.ServiceObjects {
		v.serviceObjects[obj.ObjectName] = true
	}
	for _, grp := range cfg.RuleGroups {
		v.ruleGroups[grp.GroupName] = true
	}
}

// ============================================================================
// Section Validators
// ============================================================================

func (v *Validator) validateDefaultPolicies(dp *DefaultPoliciesConfig, result *ValidationResult) {
	if dp == nil {
		result.AddWarning("default_policies", "missing, using defaults", nil)
		return
	}

	// Validate inbound policy
	if _, err := models.VerdictFromString(dp.DefaultInboundPolicy); err != nil {
		result.AddError("default_policies.default_inbound_policy",
			fmt.Sprintf("invalid policy: %s", dp.DefaultInboundPolicy), dp.DefaultInboundPolicy)
	}

	// Validate outbound policy
	if _, err := models.VerdictFromString(dp.DefaultOutboundPolicy); err != nil {
		result.AddError("default_policies.default_outbound_policy",
			fmt.Sprintf("invalid policy: %s", dp.DefaultOutboundPolicy), dp.DefaultOutboundPolicy)
	}

	// Validate forward policy
	if dp.DefaultForwardPolicy != "" {
		if _, err := models.VerdictFromString(dp.DefaultForwardPolicy); err != nil {
			result.AddError("default_policies.default_forward_policy",
				fmt.Sprintf("invalid policy: %s", dp.DefaultForwardPolicy), dp.DefaultForwardPolicy)
		}
	}
}

func (v *Validator) validateConnectionTracking(ct *ConnectionTrackingConfig, result *ValidationResult) {
	if ct == nil {
		return
	}

	// Validate timeout values
	if ct.ConnectionTimeoutTCP < 0 {
		result.AddError("connection_tracking.connection_timeout_tcp",
			"timeout cannot be negative", ct.ConnectionTimeoutTCP)
	}

	if ct.ConnectionTimeoutUDP < 0 {
		result.AddError("connection_tracking.connection_timeout_udp",
			"timeout cannot be negative", ct.ConnectionTimeoutUDP)
	}

	if ct.ConnectionTimeoutICMP < 0 {
		result.AddError("connection_tracking.connection_timeout_icmp",
			"timeout cannot be negative", ct.ConnectionTimeoutICMP)
	}

	// Validate max connections
	if ct.MaxConnections < 0 {
		result.AddError("connection_tracking.max_connections",
			"max connections cannot be negative", ct.MaxConnections)
	} else if ct.MaxConnections > 10000000 {
		result.AddWarning("connection_tracking.max_connections",
			"very high value may cause memory issues", ct.MaxConnections)
	}
}

func (v *Validator) validateSecurityZones(sz *SecurityZonesConfig, result *ValidationResult) {
	if sz == nil {
		return
	}

	seenZones := make(map[string]bool)
	for i, zone := range sz.Zones {
		path := fmt.Sprintf("security_zones.zones[%d]", i)

		if zone.ZoneName == "" {
			result.AddError(path+".zone_name", "zone name is required", nil)
		} else if seenZones[zone.ZoneName] {
			result.AddError(path+".zone_name",
				fmt.Sprintf("duplicate zone name: %s", zone.ZoneName), zone.ZoneName)
		} else {
			seenZones[zone.ZoneName] = true
		}

		if len(zone.Interfaces) == 0 {
			result.AddWarning(path+".interfaces", "no interfaces defined", nil)
		}
	}
}

func (v *Validator) validateAddressObjects(objects []*AddressObjectConfig, result *ValidationResult) {
	seenNames := make(map[string]bool)

	for i, obj := range objects {
		path := fmt.Sprintf("address_objects[%d]", i)

		// Check name
		if obj.ObjectName == "" {
			result.AddError(path+".object_name", "object name is required", nil)
			continue
		}

		if seenNames[obj.ObjectName] {
			result.AddError(path+".object_name",
				fmt.Sprintf("duplicate object name: %s", obj.ObjectName), obj.ObjectName)
		}
		seenNames[obj.ObjectName] = true

		// Check addresses
		addrs := obj.Addresses
		if len(addrs) == 0 {
			addrs = obj.Values
		}

		if len(addrs) == 0 {
			result.AddWarning(path+".addresses", "no addresses defined", nil)
			continue
		}

		// Validate each address
		for j, addr := range addrs {
			addrPath := fmt.Sprintf("%s.addresses[%d]", path, j)
			v.validateAddress(addr, addrPath, result)
		}

		// Check entry count
		if len(addrs) > v.MaxObjectEntries {
			result.AddWarning(path,
				fmt.Sprintf("too many entries: %d (max %d)", len(addrs), v.MaxObjectEntries),
				len(addrs))
		}
	}
}

func (v *Validator) validateAddress(addr, path string, result *ValidationResult) {
	addr = strings.TrimSpace(addr)

	// Check for CIDR
	if strings.Contains(addr, "/") {
		_, _, err := net.ParseCIDR(addr)
		if err != nil {
			result.AddError(path, fmt.Sprintf("invalid CIDR: %s", addr), addr)
		}
		return
	}

	// Check for IP range
	if strings.Contains(addr, "-") {
		parts := strings.SplitN(addr, "-", 2)
		if len(parts) == 2 {
			startIP := net.ParseIP(strings.TrimSpace(parts[0]))
			endIP := net.ParseIP(strings.TrimSpace(parts[1]))
			if startIP == nil {
				result.AddError(path, fmt.Sprintf("invalid range start IP: %s", parts[0]), parts[0])
			}
			if endIP == nil {
				result.AddError(path, fmt.Sprintf("invalid range end IP: %s", parts[1]), parts[1])
			}
		}
		return
	}

	// Check single IP
	ip := net.ParseIP(addr)
	if ip == nil {
		result.AddError(path, fmt.Sprintf("invalid IP address: %s", addr), addr)
	}
}

func (v *Validator) validatePortObjects(objects []*PortObjectConfig, result *ValidationResult) {
	seenNames := make(map[string]bool)

	for i, obj := range objects {
		path := fmt.Sprintf("port_objects[%d]", i)

		if obj.ObjectName == "" {
			result.AddError(path+".object_name", "object name is required", nil)
			continue
		}

		if seenNames[obj.ObjectName] {
			result.AddError(path+".object_name",
				fmt.Sprintf("duplicate object name: %s", obj.ObjectName), obj.ObjectName)
		}
		seenNames[obj.ObjectName] = true

		// Validate ports
		for j, port := range obj.Ports {
			if port < 1 || port > 65535 {
				result.AddError(fmt.Sprintf("%s.ports[%d]", path, j),
					fmt.Sprintf("invalid port number: %d (must be 1-65535)", port), port)
			}
		}

		// Validate port ranges
		for j, rangeStr := range obj.PortRanges {
			rangePath := fmt.Sprintf("%s.port_ranges[%d]", path, j)
			v.validatePortRange(rangeStr, rangePath, result)
		}

		// Validate protocol
		if obj.Protocol != "" {
			upper := strings.ToUpper(obj.Protocol)
			if upper != "TCP" && upper != "UDP" && upper != "BOTH" && upper != "ANY" {
				result.AddError(path+".protocol",
					fmt.Sprintf("invalid protocol: %s", obj.Protocol), obj.Protocol)
			}
		}
	}
}

func (v *Validator) validatePortRange(rangeStr, path string, result *ValidationResult) {
	parts := strings.SplitN(rangeStr, "-", 2)
	if len(parts) != 2 {
		result.AddError(path, fmt.Sprintf("invalid port range format: %s", rangeStr), rangeStr)
		return
	}

	var start, end int
	_, err1 := fmt.Sscanf(strings.TrimSpace(parts[0]), "%d", &start)
	_, err2 := fmt.Sscanf(strings.TrimSpace(parts[1]), "%d", &end)

	if err1 != nil || err2 != nil {
		result.AddError(path, fmt.Sprintf("invalid port range: %s", rangeStr), rangeStr)
		return
	}

	if start < 1 || start > 65535 || end < 1 || end > 65535 {
		result.AddError(path, fmt.Sprintf("port out of range: %s", rangeStr), rangeStr)
	}

	if start > end {
		result.AddError(path, fmt.Sprintf("start > end in range: %s", rangeStr), rangeStr)
	}
}

func (v *Validator) validateDomainObjects(objects []*DomainObjectConfig, result *ValidationResult) {
	seenNames := make(map[string]bool)

	for i, obj := range objects {
		path := fmt.Sprintf("domain_objects[%d]", i)

		if obj.ObjectName == "" {
			result.AddError(path+".object_name", "object name is required", nil)
			continue
		}

		if seenNames[obj.ObjectName] {
			result.AddError(path+".object_name",
				fmt.Sprintf("duplicate object name: %s", obj.ObjectName), obj.ObjectName)
		}
		seenNames[obj.ObjectName] = true

		if len(obj.Values) > v.MaxDomainPatterns {
			result.AddWarning(path,
				fmt.Sprintf("too many patterns: %d (max %d)", len(obj.Values), v.MaxDomainPatterns),
				len(obj.Values))
		}
	}
}

func (v *Validator) validateRuleGroups(groups []*RuleGroupConfig, result *ValidationResult) {
	seenNames := make(map[string]bool)
	seenPriorities := make(map[int]string)

	for i, grp := range groups {
		path := fmt.Sprintf("rule_groups[%d]", i)

		if grp.GroupName == "" {
			result.AddError(path+".group_name", "group name is required", nil)
			continue
		}

		if seenNames[grp.GroupName] {
			result.AddError(path+".group_name",
				fmt.Sprintf("duplicate group name: %s", grp.GroupName), grp.GroupName)
		}
		seenNames[grp.GroupName] = true

		if existing, ok := seenPriorities[grp.Priority]; ok {
			result.AddWarning(path+".priority",
				fmt.Sprintf("priority %d conflicts with group %s", grp.Priority, existing),
				grp.Priority)
		}
		seenPriorities[grp.Priority] = grp.GroupName

		if grp.Priority < 0 {
			result.AddError(path+".priority", "priority cannot be negative", grp.Priority)
		}
	}
}

func (v *Validator) validateRules(rules []*RuleConfig, result *ValidationResult) {
	seenIDs := make(map[int]bool)
	groupRuleCounts := make(map[string]int)

	for i, rule := range rules {
		path := fmt.Sprintf("rules[%d]", i)

		// Validate rule ID
		if seenIDs[rule.RuleID] {
			result.AddError(path+".rule_id",
				fmt.Sprintf("duplicate rule ID: %d", rule.RuleID), rule.RuleID)
		}
		seenIDs[rule.RuleID] = true

		// Validate rule name
		if rule.RuleName == "" {
			result.AddError(path+".rule_name", "rule name is required", nil)
		}

		// Validate action
		if _, err := models.VerdictFromString(rule.Action); err != nil {
			result.AddError(path+".action",
				fmt.Sprintf("invalid action: %s", rule.Action), rule.Action)
		}

		// Validate direction
		if rule.Direction != "" {
			if _, err := models.DirectionFromString(rule.Direction); err != nil {
				result.AddError(path+".direction",
					fmt.Sprintf("invalid direction: %s", rule.Direction), rule.Direction)
			}
		}

		// Validate protocol
		if rule.Protocol != "" {
			if _, err := models.ProtocolFromString(rule.Protocol); err != nil {
				result.AddError(path+".protocol",
					fmt.Sprintf("invalid protocol: %s", rule.Protocol), rule.Protocol)
			}
		}

		// Validate group reference
		if rule.Group != "" && !v.ruleGroups[rule.Group] {
			result.AddWarning(path+".group",
				fmt.Sprintf("unknown group: %s", rule.Group), rule.Group)
		}
		groupRuleCounts[rule.Group]++

		// Validate address references
		if rule.SourceAddress != "" {
			v.validateAddressReference(rule.SourceAddress, path+".source_address", result)
		}
		if rule.DestinationAddress != "" {
			v.validateAddressReference(rule.DestinationAddress, path+".destination_address", result)
		}

		// Validate ports
		for j, port := range rule.SourcePort {
			if port < 1 || port > 65535 {
				result.AddError(fmt.Sprintf("%s.source_port[%d]", path, j),
					fmt.Sprintf("invalid port: %d", port), port)
			}
		}
		for j, port := range rule.DestinationPort {
			if port < 1 || port > 65535 {
				result.AddError(fmt.Sprintf("%s.destination_port[%d]", path, j),
					fmt.Sprintf("invalid port: %d", port), port)
			}
		}

		// Validate redirect configuration
		if strings.ToUpper(rule.Action) == "REDIRECT" {
			if rule.RedirectIP == "" {
				result.AddError(path+".redirect_ip",
					"REDIRECT action requires redirect_ip", nil)
			}
		}
	}

	// Check rules per group
	for group, count := range groupRuleCounts {
		if count > v.MaxRulesPerGroup {
			result.AddWarning(fmt.Sprintf("group[%s]", group),
				fmt.Sprintf("too many rules: %d (max %d)", count, v.MaxRulesPerGroup), count)
		}
	}
}

func (v *Validator) validateAddressReference(ref, path string, result *ValidationResult) {
	// Skip validation for special values
	upper := strings.ToUpper(ref)
	if upper == "ANY" || upper == "0.0.0.0/0" {
		return
	}

	// Handle negation - always trim prefix (no-op if not present)
	ref = strings.TrimPrefix(ref, "!")

	// Check if it's an object reference or direct address
	if v.addressObjects[ref] {
		return // Valid object reference
	}

	// Try to parse as direct address/CIDR
	if strings.Contains(ref, "/") {
		_, _, err := net.ParseCIDR(ref)
		if err != nil {
			result.AddError(path,
				fmt.Sprintf("invalid CIDR or unknown object: %s", ref), ref)
		}
	} else if net.ParseIP(ref) == nil {
		// Not a valid IP, might be an unknown object
		result.AddWarning(path,
			fmt.Sprintf("unknown object or invalid IP: %s", ref), ref)
	}
}

func (v *Validator) validateAdvanced(adv *AdvancedConfig, result *ValidationResult) {
	if adv == nil {
		return
	}

	if adv.FragmentHandling != "" {
		upper := strings.ToUpper(adv.FragmentHandling)
		if upper != "DROP" && upper != "ALLOW" && upper != "REASSEMBLE" {
			result.AddError("advanced.fragment_handling",
				fmt.Sprintf("invalid value: %s", adv.FragmentHandling), adv.FragmentHandling)
		}
	}

	if adv.InvalidPacketAction != "" {
		upper := strings.ToUpper(adv.InvalidPacketAction)
		if upper != "DROP" && upper != "LOG_AND_DROP" {
			result.AddError("advanced.invalid_packet_action",
				fmt.Sprintf("invalid value: %s", adv.InvalidPacketAction), adv.InvalidPacketAction)
		}
	}

	if adv.RPFCheck != "" {
		upper := strings.ToUpper(adv.RPFCheck)
		if upper != "STRICT" && upper != "LOOSE" && upper != "DISABLED" {
			result.AddError("advanced.rpf_check",
				fmt.Sprintf("invalid value: %s", adv.RPFCheck), adv.RPFCheck)
		}
	}

	if adv.ICMPRateLimit < 0 {
		result.AddError("advanced.icmp_rate_limit",
			"rate limit cannot be negative", adv.ICMPRateLimit)
	}
}

func (v *Validator) validatePerformance(cfg *Config, result *ValidationResult) {
	ruleCount := len(cfg.Rules)

	if ruleCount > v.MaxRules {
		result.AddError("rules",
			fmt.Sprintf("too many rules: %d (max %d)", ruleCount, v.MaxRules), ruleCount)
	} else if ruleCount > v.WarnRuleThreshold {
		result.AddWarning("rules",
			fmt.Sprintf("high rule count: %d (performance may degrade beyond %d)",
				ruleCount, v.WarnRuleThreshold), ruleCount)
	}

	objectCount := len(cfg.AddressObjects) + len(cfg.PortObjects) +
		len(cfg.DomainObjects) + len(cfg.ServiceObjects)

	if objectCount > 1000 {
		result.AddWarning("objects",
			fmt.Sprintf("high object count: %d", objectCount), objectCount)
	}
}

// ============================================================================
// Convenience Functions
// ============================================================================

// Validate is a convenience function for validating a configuration.
func Validate(cfg *Config) *ValidationResult {
	return NewValidator().Validate(cfg)
}

// ValidateAndLoad loads and validates a configuration file.
func ValidateAndLoad(path string) (*Config, *ValidationResult, error) {
	cfg, err := LoadConfig(path)
	if err != nil {
		return nil, nil, err
	}

	result := Validate(cfg)
	return cfg, result, nil
}
