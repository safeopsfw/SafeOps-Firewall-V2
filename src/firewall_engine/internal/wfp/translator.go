// Package wfp provides rule-to-filter translation for WFP integration.
// Converts firewall rules into WFP filter structures.
package wfp

import (
	"fmt"
	"strings"

	"firewall_engine/internal/wfp/bindings"
	"firewall_engine/pkg/models"
)

// ============================================================================
// Translator
// ============================================================================

// Translator converts firewall rules to WFP filters.
type Translator struct {
	layerSelector *LayerSelector
	appResolver   *AppResolver
}

// NewTranslator creates a new rule-to-filter translator.
func NewTranslator() *Translator {
	return &Translator{
		layerSelector: NewLayerSelector(),
		appResolver:   DefaultAppResolver(),
	}
}

// NewTranslatorWithResolver creates a translator with a custom app resolver.
func NewTranslatorWithResolver(resolver *AppResolver) *Translator {
	return &Translator{
		layerSelector: NewLayerSelector(),
		appResolver:   resolver,
	}
}

// ============================================================================
// Translation Result
// ============================================================================

// TranslationResult contains the result of translating a rule.
type TranslationResult struct {
	// Filters are the WFP filters generated from the rule.
	// Multiple filters may be generated for rules that span multiple layers.
	Filters []*bindings.FWPM_FILTER0

	// Warnings are non-fatal issues encountered during translation.
	Warnings []string

	// Supported indicates if the rule can be fully translated to WFP.
	// If false, the rule may be partially supported or unsupported.
	Supported bool

	// UnsupportedReason explains why the rule is not fully supported.
	UnsupportedReason string
}

// ============================================================================
// Rule Translation
// ============================================================================

// TranslateRule converts a FirewallRule to WFP filter(s).
// Returns multiple filters if the rule needs to be installed on multiple layers.
func (t *Translator) TranslateRule(rule *models.FirewallRule) (*TranslationResult, error) {
	if rule == nil {
		return nil, fmt.Errorf("nil rule")
	}

	result := &TranslationResult{
		Filters:   make([]*bindings.FWPM_FILTER0, 0),
		Warnings:  make([]string, 0),
		Supported: true,
	}

	// Check for unsupported features
	if !t.SupportsRule(rule) {
		result.Supported = false
		result.UnsupportedReason = t.getUnsupportedReason(rule)
		result.Warnings = append(result.Warnings, result.UnsupportedReason)
	}

	// Get appropriate layers for this rule
	layers := t.layerSelector.GetLayerForRule(rule)
	if len(layers) == 0 {
		return nil, fmt.Errorf("no suitable WFP layer for rule: %s", rule.Name)
	}

	// Create filter for each layer
	for _, layer := range layers {
		filter, err := t.buildFilter(rule, layer)
		if err != nil {
			return nil, fmt.Errorf("failed to build filter for layer %s: %w", layer.Name, err)
		}
		result.Filters = append(result.Filters, filter)
	}

	return result, nil
}

// SupportsRule checks if a rule can be fully translated to WFP.
func (t *Translator) SupportsRule(rule *models.FirewallRule) bool {
	// WFP doesn't support domain matching (SNI, DNS, HTTP Host)
	if rule.Domain != "" || rule.DomainObject != "" {
		return false
	}

	// WFP can't do TCP RST injection or DNS redirection
	if rule.Action == models.VerdictRedirect {
		return false
	}

	return true
}

// getUnsupportedReason returns the reason why a rule is not supported.
func (t *Translator) getUnsupportedReason(rule *models.FirewallRule) string {
	if rule.Domain != "" || rule.DomainObject != "" {
		return "WFP does not support domain matching - SafeOps will handle this rule"
	}
	if rule.Action == models.VerdictRedirect {
		return "WFP does not support redirect actions - SafeOps will handle this rule"
	}
	return "Unknown unsupported feature"
}

// ============================================================================
// Action Translation
// ============================================================================

// translateAction converts a verdict to WFP action type.
func (t *Translator) translateAction(verdict models.Verdict) bindings.FWP_ACTION_TYPE {
	switch verdict {
	case models.VerdictAllow:
		return bindings.FWP_ACTION_PERMIT
	case models.VerdictBlock, models.VerdictDrop:
		return bindings.FWP_ACTION_BLOCK
	case models.VerdictReject:
		// WFP can't send ICMP unreachable, just block
		return bindings.FWP_ACTION_BLOCK
	default:
		return bindings.FWP_ACTION_BLOCK
	}
}

// ============================================================================
// Priority Translation
// ============================================================================

// translatePriority converts rule priority to WFP weight.
// WFP weight range: 0-255 (as uint8, higher = evaluated first).
// Rule priority range: 1-65535 (lower = evaluated first).
func (t *Translator) translatePriority(priority int) uint8 {
	// Invert priority (higher rule priority = lower weight value)
	// Scale to WFP weight range (0-255)
	switch {
	case priority <= 10:
		return 250 // Highest priority
	case priority <= 100:
		return 200
	case priority <= 500:
		return 150
	case priority <= 1000:
		return 128
	case priority <= 5000:
		return 80
	case priority <= 10000:
		return 50
	default:
		return 20 // Lowest priority
	}
}

// ============================================================================
// Filter Building
// ============================================================================

// buildFilter creates a WFP filter from a rule for a specific layer.
func (t *Translator) buildFilter(rule *models.FirewallRule, layer *LayerInfo) (*bindings.FWPM_FILTER0, error) {
	// Create base filter using bindings helper
	actionType := t.translateAction(rule.Action)
	filter := bindings.NewFilter(
		fmt.Sprintf("SafeOps: %s", rule.Name),
		layer.GUID,
		actionType,
	)

	// Set description
	filter.DisplayData.Description = rule.Description

	// Set weight based on priority
	weight := t.translatePriority(rule.Priority)
	filter.SetWeight(weight)

	// Set rule ID for tracking
	filter.SetRuleID(rule.ID.String())

	// Add conditions

	// Source IP condition
	if rule.SourceAddress != "" && !isAnyAddress(rule.SourceAddress) {
		cond, err := bindings.NewLocalIPCondition(rule.SourceAddress)
		if err != nil {
			return nil, fmt.Errorf("invalid source address %s: %w", rule.SourceAddress, err)
		}
		filter.AddCondition(cond)
	}

	// Destination IP condition
	if rule.DestinationAddress != "" && !isAnyAddress(rule.DestinationAddress) {
		cond, err := bindings.NewRemoteIPCondition(rule.DestinationAddress)
		if err != nil {
			return nil, fmt.Errorf("invalid destination address %s: %w", rule.DestinationAddress, err)
		}
		filter.AddCondition(cond)
	}

	// Protocol condition
	if rule.Protocol != models.ProtocolAny {
		switch rule.Protocol {
		case models.ProtocolTCP:
			filter.AddTCP()
		case models.ProtocolUDP:
			filter.AddUDP()
		case models.ProtocolICMP:
			filter.AddICMP()
		default:
			filter.AddCondition(bindings.NewProtocolExactCondition(uint8(rule.Protocol)))
		}
	}

	// Source port condition(s) - use local port
	for _, port := range rule.SourcePort {
		filter.AddLocalPort(uint16(port))
	}

	// Destination port condition(s) - use remote port
	for _, port := range rule.DestinationPort {
		filter.AddRemotePort(uint16(port))
	}

	return filter, nil
}

// ============================================================================
// Helper Functions
// ============================================================================

// isAnyAddress checks if an address represents "any" address.
func isAnyAddress(addr string) bool {
	upper := strings.ToUpper(strings.TrimSpace(addr))
	return upper == "" || upper == "ANY" || upper == "*" || upper == "0.0.0.0" || upper == "0.0.0.0/0"
}

// ============================================================================
// Batch Translation
// ============================================================================

// TranslateRules translates multiple rules to WFP filters.
func (t *Translator) TranslateRules(rules []*models.FirewallRule) ([]*TranslationResult, error) {
	results := make([]*TranslationResult, 0, len(rules))

	for _, rule := range rules {
		if rule == nil || !rule.Enabled {
			continue
		}

		result, err := t.TranslateRule(rule)
		if err != nil {
			// Log warning but continue with other rules
			results = append(results, &TranslationResult{
				Supported:         false,
				UnsupportedReason: err.Error(),
				Warnings:          []string{fmt.Sprintf("Failed to translate rule %s: %v", rule.Name, err)},
			})
			continue
		}

		results = append(results, result)
	}

	return results, nil
}

// GetAllFilters extracts all filters from translation results.
func GetAllFilters(results []*TranslationResult) []*bindings.FWPM_FILTER0 {
	var filters []*bindings.FWPM_FILTER0
	for _, result := range results {
		if result.Filters != nil {
			filters = append(filters, result.Filters...)
		}
	}
	return filters
}

// CountFilters counts total filters across all translation results.
func CountFilters(results []*TranslationResult) int {
	count := 0
	for _, result := range results {
		count += len(result.Filters)
	}
	return count
}
