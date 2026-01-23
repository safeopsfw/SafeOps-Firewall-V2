// Package validation provides comprehensive validation for firewall rules.
package validation

import (
	"fmt"
	"net"
	"regexp"
	"strconv"
	"strings"

	"firewall_engine/internal/config"
	"firewall_engine/pkg/models"
)

// ============================================================================
// Syntax Validator - IP, Port, Protocol, Enum Validation
// ============================================================================

// SyntaxValidator validates the syntax of configuration values.
type SyntaxValidator struct {
	// Compiled regex patterns
	domainPattern  *regexp.Regexp
	interfaceRegex *regexp.Regexp
}

// NewSyntaxValidator creates a new syntax validator.
func NewSyntaxValidator() *SyntaxValidator {
	return &SyntaxValidator{
		// Domain pattern: allows wildcards like *.facebook.com
		domainPattern: regexp.MustCompile(`^(\*\.)?[a-zA-Z0-9]([a-zA-Z0-9\-]*[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9\-]*[a-zA-Z0-9])?)*(\.\*)?$`),
		// Interface pattern: alphanumeric with spaces (Windows style)
		interfaceRegex: regexp.MustCompile(`^[a-zA-Z0-9\s\-_\.]+$`),
	}
}

// ValidateConfig validates the syntax of the entire configuration.
func (v *SyntaxValidator) ValidateConfig(cfg *config.Config) *ValidationResult {
	result := NewValidationResult()

	// Validate default policies
	v.validateDefaultPolicies(cfg.DefaultPolicies, result)

	// Validate address objects
	for i, obj := range cfg.AddressObjects {
		v.validateAddressObject(obj, i, result)
	}

	// Validate port objects
	for i, obj := range cfg.PortObjects {
		v.validatePortObject(obj, i, result)
	}

	// Validate domain objects
	for i, obj := range cfg.DomainObjects {
		v.validateDomainObject(obj, i, result)
	}

	// Validate rules
	for i, ruleCfg := range cfg.Rules {
		v.validateRuleConfig(ruleCfg, i, result)
	}

	return result
}

// ValidateRule validates the syntax of a single rule.
func (v *SyntaxValidator) ValidateRule(rule *models.FirewallRule) *ValidationResult {
	result := NewValidationResult()
	path := fmt.Sprintf("rules[%d]", rule.RuleID)

	// Validate rule name
	if rule.Name == "" {
		result.AddError("syntax", path+".rule_name", "rule name is required")
	}

	// Validate action
	if !rule.Action.IsValid() {
		result.AddErrorWithValue("syntax", path+".action",
			fmt.Sprintf("invalid action: %s", rule.Action), rule.Action)
	}

	// Validate direction
	if !rule.Direction.IsValid() {
		result.AddErrorWithValue("syntax", path+".direction",
			fmt.Sprintf("invalid direction: %s", rule.Direction), rule.Direction)
	}

	// Validate protocol
	if !rule.Protocol.IsValid() {
		result.AddErrorWithValue("syntax", path+".protocol",
			fmt.Sprintf("invalid protocol: %s", rule.Protocol), rule.Protocol)
	}

	// Validate source address
	if rule.SourceAddress != "" {
		if err := v.ValidateAddressSpec(rule.SourceAddress); err != nil {
			result.AddError("syntax", path+".source_address", err.Error())
		}
	}

	// Validate destination address
	if rule.DestinationAddress != "" {
		if err := v.ValidateAddressSpec(rule.DestinationAddress); err != nil {
			result.AddError("syntax", path+".destination_address", err.Error())
		}
	}

	// Validate ports
	for j, port := range rule.SourcePort {
		if err := v.ValidatePort(port); err != nil {
			result.AddError("syntax", fmt.Sprintf("%s.source_port[%d]", path, j), err.Error())
		}
	}
	for j, port := range rule.DestinationPort {
		if err := v.ValidatePort(port); err != nil {
			result.AddError("syntax", fmt.Sprintf("%s.destination_port[%d]", path, j), err.Error())
		}
	}

	// Validate domain
	if rule.Domain != "" {
		if err := v.ValidateDomainPattern(rule.Domain); err != nil {
			result.AddError("syntax", path+".domain", err.Error())
		}
	}

	// Validate state
	if rule.State != "" {
		if err := v.ValidateStateSpec(rule.State); err != nil {
			result.AddError("syntax", path+".state", err.Error())
		}
	}

	// Validate redirect configuration
	if rule.Action == models.VerdictRedirect {
		if rule.RedirectIP == "" {
			result.AddError("syntax", path+".redirect_ip",
				"REDIRECT action requires redirect_ip")
		} else if err := v.ValidateIP(rule.RedirectIP); err != nil {
			result.AddError("syntax", path+".redirect_ip", err.Error())
		}
	}

	return result
}

// ============================================================================
// Individual Validation Functions
// ============================================================================

// ValidateIP validates a single IP address.
func (v *SyntaxValidator) ValidateIP(ip string) error {
	ip = strings.TrimSpace(ip)
	if ip == "" {
		return fmt.Errorf("IP address is empty")
	}

	parsed := net.ParseIP(ip)
	if parsed == nil {
		return fmt.Errorf("invalid IP address: %s", ip)
	}
	return nil
}

// ValidateCIDR validates a CIDR notation.
func (v *SyntaxValidator) ValidateCIDR(cidr string) error {
	cidr = strings.TrimSpace(cidr)
	if cidr == "" {
		return fmt.Errorf("CIDR is empty")
	}

	_, _, err := net.ParseCIDR(cidr)
	if err != nil {
		return fmt.Errorf("invalid CIDR: %s", cidr)
	}
	return nil
}

// ValidateAddressSpec validates an address specification.
// Supports: IP, CIDR, object reference, ANY, negation (!)
func (v *SyntaxValidator) ValidateAddressSpec(spec string) error {
	spec = strings.TrimSpace(spec)
	if spec == "" {
		return nil // Empty is valid (means any)
	}

	// Handle negation - always trim prefix (no-op if not present)
	spec = strings.TrimPrefix(spec, "!")

	// Check for special values
	upper := strings.ToUpper(spec)
	if upper == "ANY" || upper == "0.0.0.0/0" || upper == "::/0" {
		return nil
	}

	// Check for CIDR
	if strings.Contains(spec, "/") {
		return v.ValidateCIDR(spec)
	}

	// Check for IP range (192.168.1.1-192.168.1.100)
	if strings.Contains(spec, "-") && !strings.Contains(spec, "/") {
		parts := strings.SplitN(spec, "-", 2)
		if len(parts) == 2 {
			if err := v.ValidateIP(strings.TrimSpace(parts[0])); err != nil {
				return fmt.Errorf("invalid range start: %w", err)
			}
			if err := v.ValidateIP(strings.TrimSpace(parts[1])); err != nil {
				return fmt.Errorf("invalid range end: %w", err)
			}
			return nil
		}
	}

	// Try as single IP
	if net.ParseIP(spec) != nil {
		return nil
	}

	// Assume it's an object reference (will be validated semantically)
	if isValidObjectName(spec) {
		return nil
	}

	return fmt.Errorf("invalid address specification: %s", spec)
}

// ValidatePort validates a port number.
func (v *SyntaxValidator) ValidatePort(port int) error {
	if port < 1 || port > 65535 {
		return fmt.Errorf("invalid port number: %d (must be 1-65535)", port)
	}
	return nil
}

// ValidatePortRange validates a port range string.
func (v *SyntaxValidator) ValidatePortRange(portRange string) error {
	parts := strings.SplitN(portRange, "-", 2)
	if len(parts) != 2 {
		return fmt.Errorf("invalid port range format: %s (expected start-end)", portRange)
	}

	start, err := strconv.Atoi(strings.TrimSpace(parts[0]))
	if err != nil {
		return fmt.Errorf("invalid port range start: %s", parts[0])
	}

	end, err := strconv.Atoi(strings.TrimSpace(parts[1]))
	if err != nil {
		return fmt.Errorf("invalid port range end: %s", parts[1])
	}

	if start < 1 || start > 65535 || end < 1 || end > 65535 {
		return fmt.Errorf("port out of range (1-65535): %s", portRange)
	}

	if start > end {
		return fmt.Errorf("port range start > end: %s", portRange)
	}

	return nil
}

// ValidateDomainPattern validates a domain pattern.
func (v *SyntaxValidator) ValidateDomainPattern(pattern string) error {
	pattern = strings.TrimSpace(strings.ToLower(pattern))
	if pattern == "" {
		return nil
	}

	// Allow wildcards at start or end
	if !v.domainPattern.MatchString(pattern) {
		return fmt.Errorf("invalid domain pattern: %s", pattern)
	}
	return nil
}

// ValidateStateSpec validates a connection state specification.
func (v *SyntaxValidator) ValidateStateSpec(state string) error {
	state = strings.ToUpper(strings.TrimSpace(state))
	if state == "" {
		return nil
	}

	validStates := map[string]bool{
		"NEW":          true,
		"ESTABLISHED":  true,
		"RELATED":      true,
		"INVALID":      true,
		"SYN_SENT":     true,
		"SYN_RECEIVED": true,
		"CLOSING":      true,
		"TIME_WAIT":    true,
		"CLOSED":       true,
	}

	// Handle comma-separated states
	parts := strings.Split(state, ",")
	for _, part := range parts {
		part = strings.TrimSpace(part)
		if part != "" && !validStates[part] {
			return fmt.Errorf("invalid connection state: %s", part)
		}
	}

	return nil
}

// ValidateProtocol validates a protocol string.
func (v *SyntaxValidator) ValidateProtocol(proto string) error {
	proto = strings.ToUpper(strings.TrimSpace(proto))
	if proto == "" || proto == "ANY" {
		return nil
	}

	_, err := models.ProtocolFromString(proto)
	return err
}

// ValidateAction validates an action string.
func (v *SyntaxValidator) ValidateAction(action string) error {
	action = strings.ToUpper(strings.TrimSpace(action))
	if action == "" {
		return fmt.Errorf("action is required")
	}

	_, err := models.VerdictFromString(action)
	return err
}

// ValidateDirection validates a direction string.
func (v *SyntaxValidator) ValidateDirection(direction string) error {
	direction = strings.ToUpper(strings.TrimSpace(direction))
	if direction == "" || direction == "ANY" {
		return nil
	}

	_, err := models.DirectionFromString(direction)
	return err
}

// ============================================================================
// Config Section Validators
// ============================================================================

func (v *SyntaxValidator) validateDefaultPolicies(dp *config.DefaultPoliciesConfig, result *ValidationResult) {
	if dp == nil {
		return
	}

	if err := v.ValidateAction(dp.DefaultInboundPolicy); err != nil {
		result.AddError("syntax", "default_policies.default_inbound_policy", err.Error())
	}

	if err := v.ValidateAction(dp.DefaultOutboundPolicy); err != nil {
		result.AddError("syntax", "default_policies.default_outbound_policy", err.Error())
	}

	if dp.DefaultForwardPolicy != "" {
		if err := v.ValidateAction(dp.DefaultForwardPolicy); err != nil {
			result.AddError("syntax", "default_policies.default_forward_policy", err.Error())
		}
	}
}

func (v *SyntaxValidator) validateAddressObject(obj *config.AddressObjectConfig, index int, result *ValidationResult) {
	path := fmt.Sprintf("address_objects[%d]", index)

	if obj.ObjectName == "" {
		result.AddError("syntax", path+".object_name", "object name is required")
	} else if !isValidObjectName(obj.ObjectName) {
		result.AddError("syntax", path+".object_name",
			fmt.Sprintf("invalid object name: %s (use alphanumeric and underscores)", obj.ObjectName))
	}

	addrs := obj.Addresses
	if len(addrs) == 0 {
		addrs = obj.Values
	}

	for i, addr := range addrs {
		if err := v.ValidateAddressSpec(addr); err != nil {
			result.AddError("syntax", fmt.Sprintf("%s.addresses[%d]", path, i), err.Error())
		}
	}
}

func (v *SyntaxValidator) validatePortObject(obj *config.PortObjectConfig, index int, result *ValidationResult) {
	path := fmt.Sprintf("port_objects[%d]", index)

	if obj.ObjectName == "" {
		result.AddError("syntax", path+".object_name", "object name is required")
	} else if !isValidObjectName(obj.ObjectName) {
		result.AddError("syntax", path+".object_name",
			fmt.Sprintf("invalid object name: %s", obj.ObjectName))
	}

	for i, port := range obj.Ports {
		if err := v.ValidatePort(port); err != nil {
			result.AddError("syntax", fmt.Sprintf("%s.ports[%d]", path, i), err.Error())
		}
	}

	for i, rangeStr := range obj.PortRanges {
		if err := v.ValidatePortRange(rangeStr); err != nil {
			result.AddError("syntax", fmt.Sprintf("%s.port_ranges[%d]", path, i), err.Error())
		}
	}

	if obj.Protocol != "" {
		if err := v.ValidateProtocol(obj.Protocol); err != nil {
			result.AddError("syntax", path+".protocol", err.Error())
		}
	}
}

func (v *SyntaxValidator) validateDomainObject(obj *config.DomainObjectConfig, index int, result *ValidationResult) {
	path := fmt.Sprintf("domain_objects[%d]", index)

	if obj.ObjectName == "" {
		result.AddError("syntax", path+".object_name", "object name is required")
	} else if !isValidObjectName(obj.ObjectName) {
		result.AddError("syntax", path+".object_name",
			fmt.Sprintf("invalid object name: %s", obj.ObjectName))
	}

	for i, pattern := range obj.Values {
		if err := v.ValidateDomainPattern(pattern); err != nil {
			result.AddError("syntax", fmt.Sprintf("%s.values[%d]", path, i), err.Error())
		}
	}
}

func (v *SyntaxValidator) validateRuleConfig(ruleCfg *config.RuleConfig, index int, result *ValidationResult) {
	path := fmt.Sprintf("rules[%d]", index)

	if ruleCfg.RuleName == "" {
		result.AddError("syntax", path+".rule_name", "rule name is required")
	}

	if err := v.ValidateAction(ruleCfg.Action); err != nil {
		result.AddError("syntax", path+".action", err.Error())
	}

	if ruleCfg.Direction != "" {
		if err := v.ValidateDirection(ruleCfg.Direction); err != nil {
			result.AddError("syntax", path+".direction", err.Error())
		}
	}

	if ruleCfg.Protocol != "" {
		if err := v.ValidateProtocol(ruleCfg.Protocol); err != nil {
			result.AddError("syntax", path+".protocol", err.Error())
		}
	}

	if ruleCfg.SourceAddress != "" {
		if err := v.ValidateAddressSpec(ruleCfg.SourceAddress); err != nil {
			result.AddError("syntax", path+".source_address", err.Error())
		}
	}

	if ruleCfg.DestinationAddress != "" {
		if err := v.ValidateAddressSpec(ruleCfg.DestinationAddress); err != nil {
			result.AddError("syntax", path+".destination_address", err.Error())
		}
	}

	for i, port := range ruleCfg.SourcePort {
		if err := v.ValidatePort(port); err != nil {
			result.AddError("syntax", fmt.Sprintf("%s.source_port[%d]", path, i), err.Error())
		}
	}

	for i, port := range ruleCfg.DestinationPort {
		if err := v.ValidatePort(port); err != nil {
			result.AddError("syntax", fmt.Sprintf("%s.destination_port[%d]", path, i), err.Error())
		}
	}

	if ruleCfg.Domain != "" {
		if err := v.ValidateDomainPattern(ruleCfg.Domain); err != nil {
			result.AddError("syntax", path+".domain", err.Error())
		}
	}

	if ruleCfg.State != "" {
		if err := v.ValidateStateSpec(ruleCfg.State); err != nil {
			result.AddError("syntax", path+".state", err.Error())
		}
	}
}

// ============================================================================
// Helper Functions
// ============================================================================

// isValidObjectName checks if an object name is valid.
func isValidObjectName(name string) bool {
	if name == "" || len(name) > 64 {
		return false
	}

	// Must start with letter or underscore
	first := name[0]
	if !((first >= 'a' && first <= 'z') || (first >= 'A' && first <= 'Z') || first == '_') {
		return false
	}

	// Rest can be alphanumeric or underscore
	for _, c := range name[1:] {
		if !((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '_') {
			return false
		}
	}

	return true
}
