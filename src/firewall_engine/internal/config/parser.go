// Package config provides configuration loading, parsing, and validation.
package config

import (
	"bytes"
	"fmt"
	"strings"

	"github.com/BurntSushi/toml"
)

// ============================================================================
// TOML Parsing
// ============================================================================

// ParseError represents a TOML parsing error with context.
type ParseError struct {
	Line    int
	Column  int
	Message string
	Err     error
}

func (e *ParseError) Error() string {
	if e.Line > 0 {
		return fmt.Sprintf("line %d, column %d: %s", e.Line, e.Column, e.Message)
	}
	return e.Message
}

func (e *ParseError) Unwrap() error {
	return e.Err
}

// Parse parses TOML data into a Config.
func Parse(data []byte) (*Config, error) {
	cfg := NewConfig()

	decoder := toml.NewDecoder(bytes.NewReader(data))
	_, err := decoder.Decode(cfg)
	if err != nil {
		return nil, wrapTOMLError(err)
	}

	return cfg, nil
}

// ParseString parses a TOML string into a Config.
func ParseString(tomlStr string) (*Config, error) {
	return Parse([]byte(tomlStr))
}

// wrapTOMLError wraps TOML library errors with better context.
func wrapTOMLError(err error) error {
	if err == nil {
		return nil
	}

	errStr := err.Error()

	// Try to extract line/column from error message
	// TOML errors are usually in format "line X, column Y: message"
	var line, column int
	var message string

	_, parseErr := fmt.Sscanf(errStr, "line %d, column %d:", &line, &column)
	if parseErr == nil {
		// Extract the message after the location
		parts := strings.SplitN(errStr, ":", 2)
		if len(parts) > 1 {
			message = strings.TrimSpace(parts[1])
		} else {
			message = errStr
		}
	} else {
		line = 0
		column = 0
		message = errStr
	}

	return &ParseError{
		Line:    line,
		Column:  column,
		Message: message,
		Err:     err,
	}
}

// ============================================================================
// Partial Parsing (for specific sections)
// ============================================================================

// ParseRulesOnly parses only the rules section from TOML.
func ParseRulesOnly(data []byte) ([]*RuleConfig, error) {
	type RulesContainer struct {
		Rules []*RuleConfig `toml:"rules"`
	}

	var container RulesContainer
	_, err := toml.Decode(string(data), &container)
	if err != nil {
		return nil, wrapTOMLError(err)
	}

	return container.Rules, nil
}

// ParseAddressObjectsOnly parses only address objects from TOML.
func ParseAddressObjectsOnly(data []byte) ([]*AddressObjectConfig, error) {
	type ObjectsContainer struct {
		AddressObjects []*AddressObjectConfig `toml:"address_objects"`
	}

	var container ObjectsContainer
	_, err := toml.Decode(string(data), &container)
	if err != nil {
		return nil, wrapTOMLError(err)
	}

	return container.AddressObjects, nil
}

// ParsePortObjectsOnly parses only port objects from TOML.
func ParsePortObjectsOnly(data []byte) ([]*PortObjectConfig, error) {
	type ObjectsContainer struct {
		PortObjects []*PortObjectConfig `toml:"port_objects"`
	}

	var container ObjectsContainer
	_, err := toml.Decode(string(data), &container)
	if err != nil {
		return nil, wrapTOMLError(err)
	}

	return container.PortObjects, nil
}

// ParseRuleGroupsOnly parses only rule groups from TOML.
func ParseRuleGroupsOnly(data []byte) ([]*RuleGroupConfig, error) {
	type GroupsContainer struct {
		RuleGroups []*RuleGroupConfig `toml:"rule_groups"`
	}

	var container GroupsContainer
	_, err := toml.Decode(string(data), &container)
	if err != nil {
		return nil, wrapTOMLError(err)
	}

	return container.RuleGroups, nil
}

// ============================================================================
// TOML Serialization
// ============================================================================

// ToTOML serializes a Config to TOML format.
func (c *Config) ToTOML() ([]byte, error) {
	var buf bytes.Buffer
	encoder := toml.NewEncoder(&buf)

	if err := encoder.Encode(c); err != nil {
		return nil, fmt.Errorf("failed to encode config to TOML: %w", err)
	}

	return buf.Bytes(), nil
}

// ToTOMLString serializes a Config to a TOML string.
func (c *Config) ToTOMLString() (string, error) {
	data, err := c.ToTOML()
	if err != nil {
		return "", err
	}
	return string(data), nil
}

// RuleToTOML serializes a single rule to TOML format.
func RuleToTOML(rule *RuleConfig) (string, error) {
	var buf bytes.Buffer
	encoder := toml.NewEncoder(&buf)

	type RuleWrapper struct {
		Rules []*RuleConfig `toml:"rules"`
	}

	wrapper := RuleWrapper{Rules: []*RuleConfig{rule}}
	if err := encoder.Encode(wrapper); err != nil {
		return "", fmt.Errorf("failed to encode rule to TOML: %w", err)
	}

	return buf.String(), nil
}

// ============================================================================
// TOML Validation Helpers
// ============================================================================

// ValidateTOMLSyntax checks if the TOML syntax is valid without full parsing.
func ValidateTOMLSyntax(data []byte) error {
	var generic interface{}
	_, err := toml.Decode(string(data), &generic)
	if err != nil {
		return wrapTOMLError(err)
	}
	return nil
}

// ExtractTOMLKeys extracts top-level keys from TOML data.
func ExtractTOMLKeys(data []byte) ([]string, error) {
	var generic map[string]interface{}
	_, err := toml.Decode(string(data), &generic)
	if err != nil {
		return nil, wrapTOMLError(err)
	}

	keys := make([]string, 0, len(generic))
	for key := range generic {
		keys = append(keys, key)
	}

	return keys, nil
}

// ============================================================================
// TOML Formatting
// ============================================================================

// FormatTOML formats TOML data with proper indentation.
// This is useful for pretty-printing configuration.
func FormatTOML(data []byte) ([]byte, error) {
	// Parse and re-encode to normalize formatting
	var generic interface{}
	_, err := toml.Decode(string(data), &generic)
	if err != nil {
		return nil, wrapTOMLError(err)
	}

	var buf bytes.Buffer
	encoder := toml.NewEncoder(&buf)

	if err := encoder.Encode(generic); err != nil {
		return nil, fmt.Errorf("failed to format TOML: %w", err)
	}

	return buf.Bytes(), nil
}

// ============================================================================
// TOML Comment Preservation
// ============================================================================

// TOMLWithComments represents TOML data with preserved comments.
type TOMLWithComments struct {
	Data     *Config
	Comments map[string]string // path -> comment
}

// ParseWithComments parses TOML while preserving comments.
// Note: This is a simplified implementation. Full comment preservation
// would require a custom TOML parser.
func ParseWithComments(data []byte) (*TOMLWithComments, error) {
	cfg, err := Parse(data)
	if err != nil {
		return nil, err
	}

	// Extract comments (lines starting with #)
	comments := make(map[string]string)
	lines := strings.Split(string(data), "\n")
	var currentComment strings.Builder
	var currentSection string

	for _, line := range lines {
		trimmed := strings.TrimSpace(line)

		if strings.HasPrefix(trimmed, "#") {
			// Accumulate comment
			currentComment.WriteString(trimmed)
			currentComment.WriteString("\n")
		} else if strings.HasPrefix(trimmed, "[") {
			// New section
			if currentComment.Len() > 0 {
				comments[currentSection] = currentComment.String()
				currentComment.Reset()
			}
			// Extract section name
			endIdx := strings.Index(trimmed, "]")
			if endIdx > 1 {
				currentSection = trimmed[1:endIdx]
			}
		} else if currentComment.Len() > 0 && trimmed != "" {
			// Key with preceding comment
			eqIdx := strings.Index(trimmed, "=")
			if eqIdx > 0 {
				key := strings.TrimSpace(trimmed[:eqIdx])
				path := currentSection
				if path != "" {
					path += "."
				}
				path += key
				comments[path] = currentComment.String()
				currentComment.Reset()
			}
		}
	}

	return &TOMLWithComments{
		Data:     cfg,
		Comments: comments,
	}, nil
}
