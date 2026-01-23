// Package validation provides comprehensive validation for firewall rules.
package validation

import (
	"fmt"

	"firewall_engine/internal/config"
)

// ============================================================================
// Performance Validator - Rule/Object Limits
// ============================================================================

// PerformanceValidator validates performance-related limits.
type PerformanceValidator struct {
	config *ValidatorConfig
}

// NewPerformanceValidator creates a new performance validator.
func NewPerformanceValidator(cfg *ValidatorConfig) *PerformanceValidator {
	if cfg == nil {
		cfg = DefaultValidatorConfig()
	}
	return &PerformanceValidator{config: cfg}
}

// Validate validates performance limits for the configuration.
func (v *PerformanceValidator) Validate(cfg *config.Config) *ValidationResult {
	result := NewValidationResult()

	// Validate total rule count
	v.validateRuleCount(cfg, result)

	// Validate rules per group
	v.validateRulesPerGroup(cfg, result)

	// Validate object counts
	v.validateObjectCounts(cfg, result)

	// Validate object entry counts
	v.validateObjectEntries(cfg, result)

	// Check for inefficient patterns
	v.checkInefficiencies(cfg, result)

	return result
}

// ============================================================================
// Limit Validations
// ============================================================================

func (v *PerformanceValidator) validateRuleCount(cfg *config.Config, result *ValidationResult) {
	ruleCount := len(cfg.Rules)

	if ruleCount > v.config.MaxRules {
		result.AddError("performance", "rules",
			fmt.Sprintf("too many rules: %d (maximum: %d)", ruleCount, v.config.MaxRules))
	} else if ruleCount > v.config.WarnRuleThreshold {
		result.AddWarningWithSuggestion("performance", "rules",
			fmt.Sprintf("high rule count: %d (warning threshold: %d)", ruleCount, v.config.WarnRuleThreshold),
			"Consider consolidating rules or using object groups to reduce rule count")
	}

	// Info about rule count
	if ruleCount > 0 {
		result.AddInfo("performance", "rules",
			fmt.Sprintf("total rules: %d", ruleCount))
	}
}

func (v *PerformanceValidator) validateRulesPerGroup(cfg *config.Config, result *ValidationResult) {
	groupCounts := make(map[string]int)

	for _, rule := range cfg.Rules {
		groupCounts[rule.Group]++
	}

	for group, count := range groupCounts {
		if count > v.config.MaxRulesPerGroup {
			groupName := group
			if groupName == "" {
				groupName = "(ungrouped)"
			}
			result.AddWarningWithSuggestion("performance", fmt.Sprintf("group[%s]", groupName),
				fmt.Sprintf("too many rules in group: %d (maximum: %d)", count, v.config.MaxRulesPerGroup),
				"Consider splitting into multiple groups for better organization and performance")
		}
	}
}

func (v *PerformanceValidator) validateObjectCounts(cfg *config.Config, result *ValidationResult) {
	totalObjects := len(cfg.AddressObjects) + len(cfg.PortObjects) +
		len(cfg.DomainObjects) + len(cfg.ServiceObjects)

	if totalObjects > v.config.MaxObjects {
		result.AddError("performance", "objects",
			fmt.Sprintf("too many objects: %d (maximum: %d)", totalObjects, v.config.MaxObjects))
	} else if totalObjects > v.config.MaxObjects/2 {
		result.AddWarning("performance", "objects",
			fmt.Sprintf("high object count: %d (maximum: %d)", totalObjects, v.config.MaxObjects))
	}

	// Specific object type warnings
	if len(cfg.AddressObjects) > 500 {
		result.AddInfo("performance", "address_objects",
			fmt.Sprintf("high address object count: %d", len(cfg.AddressObjects)))
	}

	if len(cfg.DomainObjects) > 100 {
		result.AddWarning("performance", "domain_objects",
			fmt.Sprintf("high domain object count: %d - domain matching is expensive", len(cfg.DomainObjects)))
	}
}

func (v *PerformanceValidator) validateObjectEntries(cfg *config.Config, result *ValidationResult) {
	// Check address object entries
	for i, obj := range cfg.AddressObjects {
		addrs := obj.Addresses
		if len(addrs) == 0 {
			addrs = obj.Values
		}
		if len(addrs) > v.config.MaxObjectEntries {
			result.AddError("performance", fmt.Sprintf("address_objects[%d]", i),
				fmt.Sprintf("object '%s' has too many entries: %d (maximum: %d)",
					obj.ObjectName, len(addrs), v.config.MaxObjectEntries))
		} else if len(addrs) > v.config.MaxObjectEntries/2 {
			result.AddWarning("performance", fmt.Sprintf("address_objects[%d]", i),
				fmt.Sprintf("object '%s' has many entries: %d", obj.ObjectName, len(addrs)))
		}
	}

	// Check domain object entries (domain matching is expensive)
	for i, obj := range cfg.DomainObjects {
		if len(obj.Values) > 50 {
			result.AddWarningWithSuggestion("performance", fmt.Sprintf("domain_objects[%d]", i),
				fmt.Sprintf("object '%s' has many domain patterns: %d", obj.ObjectName, len(obj.Values)),
				"Domain pattern matching is expensive - consider using fewer patterns or blocklists")
		}
	}
}

// ============================================================================
// Inefficiency Detection
// ============================================================================

func (v *PerformanceValidator) checkInefficiencies(cfg *config.Config, result *ValidationResult) {
	// Check for wildcard-heavy rules
	wildcardRules := 0
	anyDstRules := 0
	anySrcRules := 0

	for _, rule := range cfg.Rules {
		if rule.DestinationAddress == "" || rule.DestinationAddress == "ANY" {
			anyDstRules++
		}
		if rule.SourceAddress == "" || rule.SourceAddress == "ANY" {
			anySrcRules++
		}
		if rule.Protocol == "" || rule.Protocol == "ANY" {
			wildcardRules++
		}
	}

	ruleCount := len(cfg.Rules)
	if ruleCount > 0 {
		// Warn if too many "any destination" rules
		if anyDstRules > ruleCount/2 {
			result.AddWarning("performance", "rules",
				fmt.Sprintf("%d of %d rules have ANY destination - consider being more specific for security",
					anyDstRules, ruleCount))
		}

		// Warn if too many "any protocol" rules
		if wildcardRules > ruleCount/3 {
			result.AddWarning("performance", "rules",
				fmt.Sprintf("%d of %d rules have ANY protocol - this may slow matching",
					wildcardRules, ruleCount))
		}
	}

	// Check for disabled rules
	disabledRules := 0
	for _, rule := range cfg.Rules {
		if !rule.Enabled {
			disabledRules++
		}
	}
	if disabledRules > 10 {
		result.AddInfoWithSuggestion("performance", "rules",
			fmt.Sprintf("%d disabled rules in configuration", disabledRules),
			"Consider removing disabled rules to reduce configuration size")
	}

	// Check for duplicate-looking rules
	v.checkDuplicatePatterns(cfg, result)

	// Check for logging overhead
	loggingRules := 0
	for _, rule := range cfg.Rules {
		if rule.LogEnabled {
			loggingRules++
		}
	}
	if loggingRules > ruleCount/2 && loggingRules > 50 {
		result.AddWarning("performance", "rules",
			fmt.Sprintf("%d of %d rules have logging enabled - may impact performance",
				loggingRules, ruleCount))
	}
}

func (v *PerformanceValidator) checkDuplicatePatterns(cfg *config.Config, result *ValidationResult) {
	// Simple check for rules that look identical
	type ruleKey struct {
		action  string
		dir     string
		proto   string
		srcAddr string
		dstAddr string
		dstPort string
	}

	seen := make(map[ruleKey][]int)

	for i, rule := range cfg.Rules {
		dstPortStr := fmt.Sprintf("%v", rule.DestinationPort)
		key := ruleKey{
			action:  rule.Action,
			dir:     rule.Direction,
			proto:   rule.Protocol,
			srcAddr: rule.SourceAddress,
			dstAddr: rule.DestinationAddress,
			dstPort: dstPortStr,
		}
		seen[key] = append(seen[key], i)
	}

	for _, indices := range seen {
		if len(indices) > 1 {
			result.AddWarning("performance", fmt.Sprintf("rules[%d]", indices[0]),
				fmt.Sprintf("potentially duplicate rule pattern found at indices: %v", indices))
		}
	}
}

// ============================================================================
// Helper for info with suggestion
// ============================================================================

// AddInfoWithSuggestion adds info with a suggestion.
func (r *ValidationResult) AddInfoWithSuggestion(category, path, message, suggestion string) {
	r.Info = append(r.Info, ValidationIssue{
		Severity:   SeverityInfo,
		Category:   category,
		Path:       path,
		Message:    message,
		Suggestion: suggestion,
	})
	r.Stats.InfoCount++
}
