// Package validation provides comprehensive validation for firewall rules and configuration.
// It checks for syntax errors, semantic issues, circular references, and performance concerns.
//
// The validation process consists of multiple phases:
// 1. Syntax validation - IP addresses, ports, protocols, enums
// 2. Semantic validation - Object references, rule conflicts
// 3. Circular reference detection - Objects referencing each other
// 4. Performance validation - Rule/object limits
package validation

import (
	"fmt"
	"strings"
	"sync"
	"time"

	"firewall_engine/internal/config"
	"firewall_engine/internal/objects"
	"firewall_engine/pkg/models"
)

// ============================================================================
// Validator - Main Orchestrator
// ============================================================================

// Validator orchestrates all validation phases for firewall configuration.
type Validator struct {
	mu sync.RWMutex

	// Validators for each phase
	syntaxValidator      *SyntaxValidator
	semanticValidator    *SemanticValidator
	circularDetector     *CircularDetector
	performanceValidator *PerformanceValidator

	// Object manager for reference resolution
	objectManager *objects.Manager

	// Configuration
	config *ValidatorConfig
}

// ValidatorConfig contains configuration for the validator.
type ValidatorConfig struct {
	// MaxRules is the maximum number of rules allowed.
	MaxRules int

	// MaxRulesPerGroup is the maximum rules per group.
	MaxRulesPerGroup int

	// MaxObjects is the maximum number of objects allowed.
	MaxObjects int

	// MaxObjectEntries is the maximum entries per object.
	MaxObjectEntries int

	// WarnRuleThreshold triggers a warning above this count.
	WarnRuleThreshold int

	// StrictMode fails on warnings.
	StrictMode bool

	// SkipPerformanceCheck skips performance validation.
	SkipPerformanceCheck bool
}

// DefaultValidatorConfig returns default validation configuration.
func DefaultValidatorConfig() *ValidatorConfig {
	return &ValidatorConfig{
		MaxRules:             10000,
		MaxRulesPerGroup:     500,
		MaxObjects:           1000,
		MaxObjectEntries:     10000,
		WarnRuleThreshold:    5000,
		StrictMode:           false,
		SkipPerformanceCheck: false,
	}
}

// NewValidator creates a new validator with the given configuration.
func NewValidator(cfg *ValidatorConfig) *Validator {
	if cfg == nil {
		cfg = DefaultValidatorConfig()
	}

	return &Validator{
		syntaxValidator:      NewSyntaxValidator(),
		semanticValidator:    NewSemanticValidator(),
		circularDetector:     NewCircularDetector(),
		performanceValidator: NewPerformanceValidator(cfg),
		config:               cfg,
	}
}

// SetObjectManager sets the object manager for reference validation.
func (v *Validator) SetObjectManager(om *objects.Manager) {
	v.mu.Lock()
	defer v.mu.Unlock()
	v.objectManager = om
	v.semanticValidator.SetObjectManager(om)
}

// ============================================================================
// Validation Results
// ============================================================================

// ValidationResult contains the complete validation output.
type ValidationResult struct {
	// Valid is true if no errors were found.
	Valid bool `json:"valid"`

	// Errors contains all validation errors.
	Errors []ValidationIssue `json:"errors,omitempty"`

	// Warnings contains all validation warnings.
	Warnings []ValidationIssue `json:"warnings,omitempty"`

	// Info contains informational messages.
	Info []ValidationIssue `json:"info,omitempty"`

	// Stats contains validation statistics.
	Stats ValidationStats `json:"stats"`

	// Duration is how long validation took.
	Duration time.Duration `json:"duration"`
}

// ValidationIssue represents a single validation problem.
type ValidationIssue struct {
	// Severity is ERROR, WARNING, or INFO.
	Severity Severity `json:"severity"`

	// Category is the validation phase that found this issue.
	Category string `json:"category"`

	// Path is the config path (e.g., "rules[0].source_address").
	Path string `json:"path"`

	// RuleID is the rule ID if applicable.
	RuleID int `json:"rule_id,omitempty"`

	// RuleName is the rule name if applicable.
	RuleName string `json:"rule_name,omitempty"`

	// Message is the human-readable error message.
	Message string `json:"message"`

	// Value is the problematic value.
	Value interface{} `json:"value,omitempty"`

	// Suggestion is a recommended fix.
	Suggestion string `json:"suggestion,omitempty"`
}

// Severity levels for validation issues.
type Severity string

const (
	SeverityError   Severity = "ERROR"
	SeverityWarning Severity = "WARNING"
	SeverityInfo    Severity = "INFO"
)

// ValidationStats contains validation statistics.
type ValidationStats struct {
	RulesValidated    int `json:"rules_validated"`
	ObjectsValidated  int `json:"objects_validated"`
	ErrorCount        int `json:"error_count"`
	WarningCount      int `json:"warning_count"`
	InfoCount         int `json:"info_count"`
	SyntaxErrors      int `json:"syntax_errors"`
	SemanticErrors    int `json:"semantic_errors"`
	CircularRefs      int `json:"circular_refs"`
	PerformanceIssues int `json:"performance_issues"`
}

// NewValidationResult creates an empty validation result.
func NewValidationResult() *ValidationResult {
	return &ValidationResult{
		Valid:    true,
		Errors:   make([]ValidationIssue, 0),
		Warnings: make([]ValidationIssue, 0),
		Info:     make([]ValidationIssue, 0),
	}
}

// AddError adds an error to the result.
func (r *ValidationResult) AddError(category, path, message string) {
	r.Valid = false
	r.Errors = append(r.Errors, ValidationIssue{
		Severity: SeverityError,
		Category: category,
		Path:     path,
		Message:  message,
	})
	r.Stats.ErrorCount++
}

// AddErrorWithValue adds an error with the problematic value.
func (r *ValidationResult) AddErrorWithValue(category, path, message string, value interface{}) {
	r.Valid = false
	r.Errors = append(r.Errors, ValidationIssue{
		Severity: SeverityError,
		Category: category,
		Path:     path,
		Message:  message,
		Value:    value,
	})
	r.Stats.ErrorCount++
}

// AddRuleError adds an error for a specific rule.
func (r *ValidationResult) AddRuleError(category string, rule *models.FirewallRule, field, message string) {
	r.Valid = false
	path := fmt.Sprintf("rules[%d].%s", rule.RuleID, field)
	r.Errors = append(r.Errors, ValidationIssue{
		Severity: SeverityError,
		Category: category,
		Path:     path,
		RuleID:   rule.RuleID,
		RuleName: rule.Name,
		Message:  message,
	})
	r.Stats.ErrorCount++
}

// AddWarning adds a warning to the result.
func (r *ValidationResult) AddWarning(category, path, message string) {
	r.Warnings = append(r.Warnings, ValidationIssue{
		Severity: SeverityWarning,
		Category: category,
		Path:     path,
		Message:  message,
	})
	r.Stats.WarningCount++
}

// AddWarningWithSuggestion adds a warning with a fix suggestion.
func (r *ValidationResult) AddWarningWithSuggestion(category, path, message, suggestion string) {
	r.Warnings = append(r.Warnings, ValidationIssue{
		Severity:   SeverityWarning,
		Category:   category,
		Path:       path,
		Message:    message,
		Suggestion: suggestion,
	})
	r.Stats.WarningCount++
}

// AddInfo adds an informational message.
func (r *ValidationResult) AddInfo(category, path, message string) {
	r.Info = append(r.Info, ValidationIssue{
		Severity: SeverityInfo,
		Category: category,
		Path:     path,
		Message:  message,
	})
	r.Stats.InfoCount++
}

// Merge combines another result into this one.
func (r *ValidationResult) Merge(other *ValidationResult) {
	if other == nil {
		return
	}
	if !other.Valid {
		r.Valid = false
	}
	r.Errors = append(r.Errors, other.Errors...)
	r.Warnings = append(r.Warnings, other.Warnings...)
	r.Info = append(r.Info, other.Info...)
	r.Stats.ErrorCount += other.Stats.ErrorCount
	r.Stats.WarningCount += other.Stats.WarningCount
	r.Stats.InfoCount += other.Stats.InfoCount
}

// HasErrors returns true if there are any errors.
func (r *ValidationResult) HasErrors() bool {
	return len(r.Errors) > 0
}

// HasWarnings returns true if there are any warnings.
func (r *ValidationResult) HasWarnings() bool {
	return len(r.Warnings) > 0
}

// ============================================================================
// Main Validation Methods
// ============================================================================

// ValidateConfig performs complete validation of a configuration.
func (v *Validator) ValidateConfig(cfg *config.Config) *ValidationResult {
	startTime := time.Now()
	result := NewValidationResult()

	if cfg == nil {
		result.AddError("config", "", "configuration is nil")
		result.Duration = time.Since(startTime)
		return result
	}

	// Phase 1: Syntax validation
	syntaxResult := v.syntaxValidator.ValidateConfig(cfg)
	result.Merge(syntaxResult)
	result.Stats.SyntaxErrors = syntaxResult.Stats.ErrorCount

	// Phase 2: Semantic validation (object references, etc.)
	semanticResult := v.semanticValidator.ValidateConfig(cfg)
	result.Merge(semanticResult)
	result.Stats.SemanticErrors = semanticResult.Stats.ErrorCount

	// Phase 3: Circular reference detection
	circularResult := v.circularDetector.DetectAll(cfg)
	result.Merge(circularResult)
	result.Stats.CircularRefs = circularResult.Stats.ErrorCount

	// Phase 4: Performance validation
	if !v.config.SkipPerformanceCheck {
		perfResult := v.performanceValidator.Validate(cfg)
		result.Merge(perfResult)
		result.Stats.PerformanceIssues = perfResult.Stats.WarningCount + perfResult.Stats.ErrorCount
	}

	// Update stats
	result.Stats.RulesValidated = len(cfg.Rules)
	result.Stats.ObjectsValidated = len(cfg.AddressObjects) + len(cfg.PortObjects) +
		len(cfg.DomainObjects) + len(cfg.ServiceObjects)

	// Apply strict mode
	if v.config.StrictMode && result.HasWarnings() {
		result.Valid = false
	}

	result.Duration = time.Since(startTime)
	return result
}

// ValidateRules validates a slice of rules.
func (v *Validator) ValidateRules(rules []*models.FirewallRule) *ValidationResult {
	startTime := time.Now()
	result := NewValidationResult()

	for _, rule := range rules {
		ruleResult := v.ValidateRule(rule)
		result.Merge(ruleResult)
	}

	result.Stats.RulesValidated = len(rules)
	result.Duration = time.Since(startTime)
	return result
}

// ValidateRule validates a single rule.
func (v *Validator) ValidateRule(rule *models.FirewallRule) *ValidationResult {
	result := NewValidationResult()

	if rule == nil {
		result.AddError("rule", "", "rule is nil")
		return result
	}

	// Syntax validation
	result.Merge(v.syntaxValidator.ValidateRule(rule))

	// Semantic validation
	result.Merge(v.semanticValidator.ValidateRule(rule))

	return result
}

// ValidateRuleConfig validates a rule from configuration.
func (v *Validator) ValidateRuleConfig(ruleCfg *config.RuleConfig) *ValidationResult {
	result := NewValidationResult()

	if ruleCfg == nil {
		result.AddError("rule", "", "rule config is nil")
		return result
	}

	// Convert to model and validate
	rule, err := ruleCfg.ToModel()
	if err != nil {
		result.AddError("rule", fmt.Sprintf("rules[%d]", ruleCfg.RuleID),
			fmt.Sprintf("failed to parse rule: %v", err))
		return result
	}

	return v.ValidateRule(rule)
}

// ============================================================================
// Quick Validation Helpers
// ============================================================================

// QuickValidate performs fast validation without performance checks.
func (v *Validator) QuickValidate(cfg *config.Config) bool {
	v.config.SkipPerformanceCheck = true
	result := v.ValidateConfig(cfg)
	v.config.SkipPerformanceCheck = false
	return result.Valid
}

// ValidateAndReport validates and returns a formatted report.
func (v *Validator) ValidateAndReport(cfg *config.Config) (bool, string) {
	result := v.ValidateConfig(cfg)
	reporter := NewReporter()
	report := reporter.FormatResult(result)
	return result.Valid, report
}

// ============================================================================
// Convenience Functions
// ============================================================================

// Validate is a convenience function for validating configuration.
func Validate(cfg *config.Config) *ValidationResult {
	return NewValidator(nil).ValidateConfig(cfg)
}

// ValidateWithStrictMode validates with warnings treated as errors.
func ValidateWithStrictMode(cfg *config.Config) *ValidationResult {
	config := DefaultValidatorConfig()
	config.StrictMode = true
	return NewValidator(config).ValidateConfig(cfg)
}

// IsValid returns true if the configuration is valid.
func IsValid(cfg *config.Config) bool {
	return Validate(cfg).Valid
}

// GetErrors returns only errors from validation.
func GetErrors(cfg *config.Config) []string {
	result := Validate(cfg)
	errors := make([]string, 0, len(result.Errors))
	for _, err := range result.Errors {
		errors = append(errors, fmt.Sprintf("[%s] %s: %s", err.Category, err.Path, err.Message))
	}
	return errors
}

// ============================================================================
// Summary String Methods
// ============================================================================

// String returns a human-readable summary of the validation result.
func (r *ValidationResult) String() string {
	var sb strings.Builder

	if r.Valid {
		sb.WriteString("✓ Validation PASSED")
	} else {
		sb.WriteString("✗ Validation FAILED")
	}

	sb.WriteString(fmt.Sprintf(" (%d errors, %d warnings, validated %d rules, %d objects in %v)\n",
		r.Stats.ErrorCount, r.Stats.WarningCount,
		r.Stats.RulesValidated, r.Stats.ObjectsValidated, r.Duration.Round(time.Millisecond)))

	return sb.String()
}
