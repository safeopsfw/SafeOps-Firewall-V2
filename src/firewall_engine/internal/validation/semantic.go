// Package validation provides comprehensive validation for firewall rules.
package validation

import (
	"fmt"
	"strings"

	"firewall_engine/internal/config"
	"firewall_engine/internal/objects"
	"firewall_engine/pkg/models"
)

// ============================================================================
// Semantic Validator - Object References, Rule Conflicts
// ============================================================================

// SemanticValidator validates object references and rule semantics.
type SemanticValidator struct {
	objectManager *objects.Manager

	// Collected object names during validation
	addressObjects map[string]bool
	portObjects    map[string]bool
	domainObjects  map[string]bool
	serviceObjects map[string]bool
	ruleGroups     map[string]int // name -> priority
}

// NewSemanticValidator creates a new semantic validator.
func NewSemanticValidator() *SemanticValidator {
	return &SemanticValidator{
		addressObjects: make(map[string]bool),
		portObjects:    make(map[string]bool),
		domainObjects:  make(map[string]bool),
		serviceObjects: make(map[string]bool),
		ruleGroups:     make(map[string]int),
	}
}

// SetObjectManager sets the object manager for validation.
func (v *SemanticValidator) SetObjectManager(om *objects.Manager) {
	v.objectManager = om
}

// ValidateConfig validates the semantic correctness of the entire configuration.
func (v *SemanticValidator) ValidateConfig(cfg *config.Config) *ValidationResult {
	result := NewValidationResult()

	// First pass: collect all object names
	v.collectObjectNames(cfg)

	// Validate object name uniqueness across types
	v.validateObjectNameUniqueness(cfg, result)

	// Validate rule groups
	v.validateRuleGroups(cfg.RuleGroups, result)

	// Validate rules
	for i, ruleCfg := range cfg.Rules {
		// Convert to model for validation
		rule, err := ruleCfg.ToModel()
		if err != nil {
			result.AddError("semantic", fmt.Sprintf("rules[%d]", i),
				fmt.Sprintf("failed to parse rule: %v", err))
			continue
		}
		v.validateRuleSemantics(rule, ruleCfg, i, result)
	}

	// Validate rule conflicts
	v.validateRuleConflicts(cfg.Rules, result)

	return result
}

// ValidateRule validates the semantics of a single rule.
func (v *SemanticValidator) ValidateRule(rule *models.FirewallRule) *ValidationResult {
	result := NewValidationResult()
	path := fmt.Sprintf("rules[%d]", rule.RuleID)

	// Validate object references
	v.validateAddressReference(rule.SourceAddress, path+".source_address", result)
	v.validateAddressReference(rule.DestinationAddress, path+".destination_address", result)
	v.validatePortReference(rule.SourcePortObject, path+".source_port_object", result)
	v.validatePortReference(rule.DestinationPortObject, path+".destination_port_object", result)
	v.validateDomainReference(rule.DomainObject, path+".domain_object", result)

	// Validate rule group reference
	if rule.GroupName != "" {
		if _, ok := v.ruleGroups[rule.GroupName]; !ok {
			// Check if we have an object manager to verify
			if v.objectManager == nil && len(v.ruleGroups) == 0 {
				// Can't validate without object info - just warn
				result.AddWarning("semantic", path+".group",
					fmt.Sprintf("unknown group reference: %s (validation incomplete)", rule.GroupName))
			}
		}
	}

	// Validate protocol-specific rules
	v.validateProtocolSemantics(rule, path, result)

	// Validate redirect rules
	if rule.Action == models.VerdictRedirect {
		v.validateRedirectSemantics(rule, path, result)
	}

	return result
}

// ============================================================================
// Collection Methods
// ============================================================================

func (v *SemanticValidator) collectObjectNames(cfg *config.Config) {
	// Reset collections
	v.addressObjects = make(map[string]bool)
	v.portObjects = make(map[string]bool)
	v.domainObjects = make(map[string]bool)
	v.serviceObjects = make(map[string]bool)
	v.ruleGroups = make(map[string]int)

	// Collect address objects
	for _, obj := range cfg.AddressObjects {
		v.addressObjects[obj.ObjectName] = true
	}

	// Collect port objects
	for _, obj := range cfg.PortObjects {
		v.portObjects[obj.ObjectName] = true
	}

	// Collect domain objects
	for _, obj := range cfg.DomainObjects {
		v.domainObjects[obj.ObjectName] = true
	}

	// Collect service objects
	for _, obj := range cfg.ServiceObjects {
		v.serviceObjects[obj.ObjectName] = true
	}

	// Collect rule groups
	for _, grp := range cfg.RuleGroups {
		v.ruleGroups[grp.GroupName] = grp.Priority
	}
}

// ============================================================================
// Validation Methods
// ============================================================================

func (v *SemanticValidator) validateObjectNameUniqueness(cfg *config.Config, result *ValidationResult) {
	seenNames := make(map[string]string) // name -> type

	// Check address objects
	for i, obj := range cfg.AddressObjects {
		if existing, ok := seenNames[obj.ObjectName]; ok {
			result.AddError("semantic", fmt.Sprintf("address_objects[%d].object_name", i),
				fmt.Sprintf("duplicate object name '%s' (also defined as %s)", obj.ObjectName, existing))
		} else {
			seenNames[obj.ObjectName] = "address_object"
		}
	}

	// Check port objects
	for i, obj := range cfg.PortObjects {
		if existing, ok := seenNames[obj.ObjectName]; ok {
			result.AddError("semantic", fmt.Sprintf("port_objects[%d].object_name", i),
				fmt.Sprintf("duplicate object name '%s' (also defined as %s)", obj.ObjectName, existing))
		} else {
			seenNames[obj.ObjectName] = "port_object"
		}
	}

	// Check domain objects
	for i, obj := range cfg.DomainObjects {
		if existing, ok := seenNames[obj.ObjectName]; ok {
			result.AddError("semantic", fmt.Sprintf("domain_objects[%d].object_name", i),
				fmt.Sprintf("duplicate object name '%s' (also defined as %s)", obj.ObjectName, existing))
		} else {
			seenNames[obj.ObjectName] = "domain_object"
		}
	}

	// Check service objects
	for i, obj := range cfg.ServiceObjects {
		if existing, ok := seenNames[obj.ObjectName]; ok {
			result.AddError("semantic", fmt.Sprintf("service_objects[%d].object_name", i),
				fmt.Sprintf("duplicate object name '%s' (also defined as %s)", obj.ObjectName, existing))
		} else {
			seenNames[obj.ObjectName] = "service_object"
		}
	}
}

func (v *SemanticValidator) validateRuleGroups(groups []*config.RuleGroupConfig, result *ValidationResult) {
	seenNames := make(map[string]int)      // name -> index
	seenPriorities := make(map[int]string) // priority -> name

	for i, grp := range groups {
		path := fmt.Sprintf("rule_groups[%d]", i)

		// Check for duplicate names
		if existingIdx, ok := seenNames[grp.GroupName]; ok {
			result.AddError("semantic", path+".group_name",
				fmt.Sprintf("duplicate group name '%s' (first defined at index %d)", grp.GroupName, existingIdx))
		} else {
			seenNames[grp.GroupName] = i
		}

		// Check for priority conflicts
		if existingName, ok := seenPriorities[grp.Priority]; ok {
			result.AddWarningWithSuggestion("semantic", path+".priority",
				fmt.Sprintf("priority %d conflicts with group '%s'", grp.Priority, existingName),
				"Consider using unique priorities to ensure consistent rule ordering")
		} else {
			seenPriorities[grp.Priority] = grp.GroupName
		}

		// Validate priority is positive
		if grp.Priority < 0 {
			result.AddError("semantic", path+".priority", "priority cannot be negative")
		}
	}
}

func (v *SemanticValidator) validateRuleSemantics(_ *models.FirewallRule, ruleCfg *config.RuleConfig, index int, result *ValidationResult) {
	path := fmt.Sprintf("rules[%d]", index)

	// Validate group reference
	if ruleCfg.Group != "" {
		if _, ok := v.ruleGroups[ruleCfg.Group]; !ok {
			result.AddWarningWithSuggestion("semantic", path+".group",
				fmt.Sprintf("unknown group '%s'", ruleCfg.Group),
				"Define the group in rule_groups section or remove the reference")
		}
	}

	// Validate address references
	v.validateAddressReference(ruleCfg.SourceAddress, path+".source_address", result)
	v.validateAddressReference(ruleCfg.DestinationAddress, path+".destination_address", result)

	// Validate protocol-port consistency
	if ruleCfg.Protocol == "ICMP" {
		if len(ruleCfg.SourcePort) > 0 || len(ruleCfg.DestinationPort) > 0 {
			result.AddError("semantic", path,
				"ICMP protocol does not use ports (remove source_port/destination_port)")
		}
	}

	// Validate domain matching requirements
	if ruleCfg.Domain != "" && ruleCfg.Protocol != "" {
		upper := strings.ToUpper(ruleCfg.Protocol)
		if upper != "TCP" && upper != "UDP" && upper != "ANY" {
			result.AddWarning("semantic", path+".domain",
				"domain matching only works with TCP/UDP protocols (for DNS/TLS SNI extraction)")
		}
	}

	// Validate state filtering with protocol
	if ruleCfg.State != "" {
		upper := strings.ToUpper(ruleCfg.Protocol)
		if upper == "UDP" || upper == "ICMP" {
			// States like ESTABLISHED work differently for non-TCP
			if strings.Contains(strings.ToUpper(ruleCfg.State), "SYN") {
				result.AddWarning("semantic", path+".state",
					fmt.Sprintf("TCP state '%s' may not work as expected with %s protocol", ruleCfg.State, upper))
			}
		}
	}
}

func (v *SemanticValidator) validateAddressReference(addr, path string, result *ValidationResult) {
	if addr == "" {
		return
	}

	// Handle negation
	addr = strings.TrimPrefix(addr, "!")

	// Skip special values
	upper := strings.ToUpper(addr)
	if upper == "ANY" || upper == "0.0.0.0/0" || upper == "::/0" {
		return
	}

	// Skip direct IPs/CIDRs
	if strings.Contains(addr, "/") || strings.Contains(addr, ".") || strings.Contains(addr, ":") {
		return
	}

	// Check if it's a known object
	if v.addressObjects[addr] {
		return
	}

	// Check with object manager if available
	if v.objectManager != nil && v.objectManager.Addresses().Exists(addr) {
		return
	}

	result.AddWarningWithSuggestion("semantic", path,
		fmt.Sprintf("unknown address object '%s'", addr),
		"Define the object in address_objects section or use a direct IP/CIDR")
}

func (v *SemanticValidator) validatePortReference(portObj, path string, result *ValidationResult) {
	if portObj == "" {
		return
	}

	if v.portObjects[portObj] {
		return
	}

	if v.objectManager != nil && v.objectManager.Ports().Exists(portObj) {
		return
	}

	result.AddWarningWithSuggestion("semantic", path,
		fmt.Sprintf("unknown port object '%s'", portObj),
		"Define the object in port_objects section")
}

func (v *SemanticValidator) validateDomainReference(domainObj, path string, result *ValidationResult) {
	if domainObj == "" {
		return
	}

	if v.domainObjects[domainObj] {
		return
	}

	if v.objectManager != nil && v.objectManager.Domains().Exists(domainObj) {
		return
	}

	result.AddWarningWithSuggestion("semantic", path,
		fmt.Sprintf("unknown domain object '%s'", domainObj),
		"Define the object in domain_objects section")
}

func (v *SemanticValidator) validateProtocolSemantics(rule *models.FirewallRule, path string, result *ValidationResult) {
	// ICMP should not have ports
	if rule.Protocol == models.ProtocolICMP {
		if len(rule.SourcePort) > 0 || len(rule.DestinationPort) > 0 ||
			rule.SourcePortObject != "" || rule.DestinationPortObject != "" {
			result.AddError("semantic", path,
				"ICMP protocol does not support port matching")
		}
	}

	// TCP/UDP should specify ports for security
	if rule.Protocol == models.ProtocolTCP || rule.Protocol == models.ProtocolUDP {
		if len(rule.DestinationPort) == 0 && rule.DestinationPortObject == "" {
			if rule.Action == models.VerdictAllow {
				result.AddWarning("semantic", path+".destination_port",
					"ALLOW rule for TCP/UDP without destination port - consider being more specific")
			}
		}
	}
}

func (v *SemanticValidator) validateRedirectSemantics(rule *models.FirewallRule, path string, result *ValidationResult) {
	// Redirect requires an IP
	if rule.RedirectIP == "" {
		result.AddError("semantic", path+".redirect_ip",
			"REDIRECT action requires redirect_ip")
		return
	}

	// Redirect with port should specify destination port
	if rule.RedirectPort > 0 {
		if len(rule.DestinationPort) == 0 && rule.DestinationPortObject == "" {
			result.AddWarning("semantic", path,
				"REDIRECT with redirect_port but no destination_port filter - will redirect all ports")
		}
	}

	// Direction check
	if rule.Direction == models.DirectionOutbound {
		result.AddWarning("semantic", path,
			"REDIRECT for OUTBOUND traffic may not work as expected")
	}
}

func (v *SemanticValidator) validateRuleConflicts(rules []*config.RuleConfig, result *ValidationResult) {
	// Check for potentially overlapping rules
	for i := 0; i < len(rules); i++ {
		for j := i + 1; j < len(rules); j++ {
			if v.rulesOverlap(rules[i], rules[j]) {
				// Only warn if actions differ
				if rules[i].Action != rules[j].Action {
					result.AddWarningWithSuggestion("semantic",
						fmt.Sprintf("rules[%d] vs rules[%d]", i, j),
						fmt.Sprintf("potentially overlapping rules '%s' and '%s' with different actions (%s vs %s)",
							rules[i].RuleName, rules[j].RuleName, rules[i].Action, rules[j].Action),
						"Review rule priorities to ensure correct ordering")
				}
			}
		}
	}
}

// rulesOverlap checks if two rules might match the same traffic.
func (v *SemanticValidator) rulesOverlap(r1, r2 *config.RuleConfig) bool {
	// Different directions don't overlap
	if r1.Direction != "" && r2.Direction != "" &&
		r1.Direction != r2.Direction && r1.Direction != "ANY" && r2.Direction != "ANY" {
		return false
	}

	// Different protocols don't overlap
	if r1.Protocol != "" && r2.Protocol != "" &&
		r1.Protocol != r2.Protocol && r1.Protocol != "ANY" && r2.Protocol != "ANY" {
		return false
	}

	// If source/destination are completely different, they don't overlap
	// This is a simplified check - full overlap detection would be more complex
	if r1.SourceAddress != "" && r2.SourceAddress != "" &&
		r1.SourceAddress != r2.SourceAddress {
		// Could still overlap if one is a subset of the other
		// For now, we just check exact matches
		return false
	}

	if r1.DestinationAddress != "" && r2.DestinationAddress != "" &&
		r1.DestinationAddress != r2.DestinationAddress {
		return false
	}

	// If both have ports and they don't match, they don't overlap
	if len(r1.DestinationPort) > 0 && len(r2.DestinationPort) > 0 {
		overlap := false
		for _, p1 := range r1.DestinationPort {
			for _, p2 := range r2.DestinationPort {
				if p1 == p2 {
					overlap = true
					break
				}
			}
		}
		if !overlap {
			return false
		}
	}

	return true
}
