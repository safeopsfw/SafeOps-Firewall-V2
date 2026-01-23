// Package validation provides comprehensive validation for firewall rules.
package validation

import (
	"encoding/json"
	"fmt"
	"strings"
	"time"
)

// ============================================================================
// Reporter - Validation Result Formatting
// ============================================================================

// Reporter formats validation results for output.
type Reporter struct {
	// ShowInfo includes informational messages in output.
	ShowInfo bool

	// ColorOutput enables ANSI color codes (for terminal).
	ColorOutput bool

	// MaxIssues limits the number of issues shown per category.
	MaxIssues int
}

// NewReporter creates a new reporter with default settings.
func NewReporter() *Reporter {
	return &Reporter{
		ShowInfo:    false,
		ColorOutput: false,
		MaxIssues:   20,
	}
}

// FormatResult formats a validation result as a human-readable string.
func (r *Reporter) FormatResult(result *ValidationResult) string {
	var sb strings.Builder

	// Header
	sb.WriteString(r.formatHeader(result))

	// Errors
	if len(result.Errors) > 0 {
		sb.WriteString("\n")
		sb.WriteString(r.formatSection("ERRORS", result.Errors, r.MaxIssues))
	}

	// Warnings
	if len(result.Warnings) > 0 {
		sb.WriteString("\n")
		sb.WriteString(r.formatSection("WARNINGS", result.Warnings, r.MaxIssues))
	}

	// Info (optional)
	if r.ShowInfo && len(result.Info) > 0 {
		sb.WriteString("\n")
		sb.WriteString(r.formatSection("INFO", result.Info, r.MaxIssues))
	}

	// Summary
	sb.WriteString("\n")
	sb.WriteString(r.formatSummary(result))

	return sb.String()
}

func (r *Reporter) formatHeader(result *ValidationResult) string {
	var status string
	if result.Valid {
		status = "✓ VALIDATION PASSED"
		if r.ColorOutput {
			status = "\033[32m" + status + "\033[0m" // Green
		}
	} else {
		status = "✗ VALIDATION FAILED"
		if r.ColorOutput {
			status = "\033[31m" + status + "\033[0m" // Red
		}
	}

	return fmt.Sprintf("═══════════════════════════════════════════════════════════════\n"+
		" %s\n"+
		"═══════════════════════════════════════════════════════════════\n",
		status)
}

func (r *Reporter) formatSection(title string, issues []ValidationIssue, maxIssues int) string {
	var sb strings.Builder

	icon := ""
	switch title {
	case "ERRORS":
		icon = "✗"
		if r.ColorOutput {
			title = "\033[31m" + title + "\033[0m"
		}
	case "WARNINGS":
		icon = "⚠"
		if r.ColorOutput {
			title = "\033[33m" + title + "\033[0m"
		}
	case "INFO":
		icon = "ℹ"
		if r.ColorOutput {
			title = "\033[36m" + title + "\033[0m"
		}
	}

	sb.WriteString(fmt.Sprintf("%s %s (%d)\n", icon, title, len(issues)))
	sb.WriteString("───────────────────────────────────────────────────────────────\n")

	displayed := 0
	for _, issue := range issues {
		if maxIssues > 0 && displayed >= maxIssues {
			sb.WriteString(fmt.Sprintf("  ... and %d more\n", len(issues)-displayed))
			break
		}

		sb.WriteString(r.formatIssue(issue))
		displayed++
	}

	return sb.String()
}

func (r *Reporter) formatIssue(issue ValidationIssue) string {
	var sb strings.Builder

	// Category and path
	path := issue.Path
	if path == "" {
		path = "(global)"
	}

	sb.WriteString(fmt.Sprintf("  [%s] %s\n", issue.Category, path))

	// Message
	sb.WriteString(fmt.Sprintf("    └─ %s\n", issue.Message))

	// Value if present
	if issue.Value != nil {
		sb.WriteString(fmt.Sprintf("       Value: %v\n", issue.Value))
	}

	// Suggestion if present
	if issue.Suggestion != "" {
		suggestion := issue.Suggestion
		if r.ColorOutput {
			suggestion = "\033[90m" + suggestion + "\033[0m" // Gray
		}
		sb.WriteString(fmt.Sprintf("       Suggestion: %s\n", suggestion))
	}

	// Rule info if present
	if issue.RuleID > 0 || issue.RuleName != "" {
		sb.WriteString(fmt.Sprintf("       Rule: %s (ID: %d)\n", issue.RuleName, issue.RuleID))
	}

	return sb.String()
}

func (r *Reporter) formatSummary(result *ValidationResult) string {
	var sb strings.Builder

	sb.WriteString("═══════════════════════════════════════════════════════════════\n")
	sb.WriteString(" SUMMARY\n")
	sb.WriteString("───────────────────────────────────────────────────────────────\n")

	sb.WriteString(fmt.Sprintf("  Rules validated:   %d\n", result.Stats.RulesValidated))
	sb.WriteString(fmt.Sprintf("  Objects validated: %d\n", result.Stats.ObjectsValidated))
	sb.WriteString(fmt.Sprintf("  Errors:            %d\n", result.Stats.ErrorCount))
	sb.WriteString(fmt.Sprintf("  Warnings:          %d\n", result.Stats.WarningCount))

	if r.ShowInfo {
		sb.WriteString(fmt.Sprintf("  Info:              %d\n", result.Stats.InfoCount))
	}

	if result.Stats.SyntaxErrors > 0 {
		sb.WriteString(fmt.Sprintf("    - Syntax errors:      %d\n", result.Stats.SyntaxErrors))
	}
	if result.Stats.SemanticErrors > 0 {
		sb.WriteString(fmt.Sprintf("    - Semantic errors:    %d\n", result.Stats.SemanticErrors))
	}
	if result.Stats.CircularRefs > 0 {
		sb.WriteString(fmt.Sprintf("    - Circular refs:      %d\n", result.Stats.CircularRefs))
	}
	if result.Stats.PerformanceIssues > 0 {
		sb.WriteString(fmt.Sprintf("    - Performance issues: %d\n", result.Stats.PerformanceIssues))
	}

	sb.WriteString(fmt.Sprintf("  Duration:          %v\n", result.Duration.Round(time.Millisecond)))
	sb.WriteString("═══════════════════════════════════════════════════════════════\n")

	return sb.String()
}

// ============================================================================
// JSON Formatting
// ============================================================================

// FormatJSON returns the validation result as JSON.
func (r *Reporter) FormatJSON(result *ValidationResult) (string, error) {
	data, err := json.MarshalIndent(result, "", "  ")
	if err != nil {
		return "", err
	}
	return string(data), nil
}

// FormatJSONCompact returns compact JSON.
func (r *Reporter) FormatJSONCompact(result *ValidationResult) (string, error) {
	data, err := json.Marshal(result)
	if err != nil {
		return "", err
	}
	return string(data), nil
}

// ============================================================================
// Markdown Formatting
// ============================================================================

// FormatMarkdown returns the validation result as Markdown.
func (r *Reporter) FormatMarkdown(result *ValidationResult) string {
	var sb strings.Builder

	// Header
	if result.Valid {
		sb.WriteString("# ✅ Validation Passed\n\n")
	} else {
		sb.WriteString("# ❌ Validation Failed\n\n")
	}

	// Summary table
	sb.WriteString("## Summary\n\n")
	sb.WriteString("| Metric | Value |\n")
	sb.WriteString("|--------|-------|\n")
	sb.WriteString(fmt.Sprintf("| Rules Validated | %d |\n", result.Stats.RulesValidated))
	sb.WriteString(fmt.Sprintf("| Objects Validated | %d |\n", result.Stats.ObjectsValidated))
	sb.WriteString(fmt.Sprintf("| Errors | %d |\n", result.Stats.ErrorCount))
	sb.WriteString(fmt.Sprintf("| Warnings | %d |\n", result.Stats.WarningCount))
	sb.WriteString(fmt.Sprintf("| Duration | %v |\n", result.Duration.Round(time.Millisecond)))

	// Errors
	if len(result.Errors) > 0 {
		sb.WriteString("\n## ❌ Errors\n\n")
		for _, issue := range result.Errors {
			sb.WriteString(fmt.Sprintf("- **[%s]** `%s`: %s\n", issue.Category, issue.Path, issue.Message))
			if issue.Suggestion != "" {
				sb.WriteString(fmt.Sprintf("  - 💡 *%s*\n", issue.Suggestion))
			}
		}
	}

	// Warnings
	if len(result.Warnings) > 0 {
		sb.WriteString("\n## ⚠️ Warnings\n\n")
		for _, issue := range result.Warnings {
			sb.WriteString(fmt.Sprintf("- **[%s]** `%s`: %s\n", issue.Category, issue.Path, issue.Message))
			if issue.Suggestion != "" {
				sb.WriteString(fmt.Sprintf("  - 💡 *%s*\n", issue.Suggestion))
			}
		}
	}

	return sb.String()
}

// ============================================================================
// Error-Only Formatting
// ============================================================================

// FormatErrors returns just the errors as a simple list.
func (r *Reporter) FormatErrors(result *ValidationResult) []string {
	errors := make([]string, 0, len(result.Errors))
	for _, issue := range result.Errors {
		errors = append(errors, fmt.Sprintf("[%s] %s: %s", issue.Category, issue.Path, issue.Message))
	}
	return errors
}

// FormatWarnings returns just the warnings as a simple list.
func (r *Reporter) FormatWarnings(result *ValidationResult) []string {
	warnings := make([]string, 0, len(result.Warnings))
	for _, issue := range result.Warnings {
		warnings = append(warnings, fmt.Sprintf("[%s] %s: %s", issue.Category, issue.Path, issue.Message))
	}
	return warnings
}

// ============================================================================
// One-Line Summary
// ============================================================================

// FormatOneLine returns a single-line summary.
func (r *Reporter) FormatOneLine(result *ValidationResult) string {
	if result.Valid {
		return fmt.Sprintf("✓ Valid (%d rules, %d objects, %d warnings, %v)",
			result.Stats.RulesValidated, result.Stats.ObjectsValidated,
			result.Stats.WarningCount, result.Duration.Round(time.Millisecond))
	}
	return fmt.Sprintf("✗ Invalid (%d errors, %d warnings)",
		result.Stats.ErrorCount, result.Stats.WarningCount)
}
