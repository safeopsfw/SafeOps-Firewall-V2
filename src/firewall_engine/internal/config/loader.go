// Package config provides configuration loading, parsing, and validation.
package config

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// ============================================================================
// Configuration Loading
// ============================================================================

// LoadError represents an error that occurred during configuration loading.
type LoadError struct {
	File    string
	Phase   string
	Message string
	Err     error
}

func (e *LoadError) Error() string {
	if e.Err != nil {
		return fmt.Sprintf("%s: %s: %s: %v", e.Phase, e.File, e.Message, e.Err)
	}
	return fmt.Sprintf("%s: %s: %s", e.Phase, e.File, e.Message)
}

func (e *LoadError) Unwrap() error {
	return e.Err
}

// newLoadError creates a new LoadError.
func newLoadError(file, phase, message string, err error) *LoadError {
	return &LoadError{
		File:    file,
		Phase:   phase,
		Message: message,
		Err:     err,
	}
}

// Loader handles configuration file loading with caching and hot-reload support.
type Loader struct {
	// configPaths are the directories to search for config files.
	configPaths []string

	// lastLoaded tracks when files were last loaded for hot-reload.
	lastLoaded map[string]time.Time

	// cache stores loaded configurations.
	cache map[string]*Config
}

// NewLoader creates a new configuration loader.
func NewLoader(configPaths ...string) *Loader {
	if len(configPaths) == 0 {
		// Default search paths
		configPaths = []string{
			".",
			"config",
			"../config",
			"../../config",
			"config/firewall",
			"../../config/firewall",
			"configs",
			"../configs",
		}
	}

	return &Loader{
		configPaths: configPaths,
		lastLoaded:  make(map[string]time.Time),
		cache:       make(map[string]*Config),
	}
}

// Load loads a configuration from file.
// It searches configPaths for the file if not an absolute path.
func (l *Loader) Load(filename string) (*Config, error) {
	path, err := l.resolvePath(filename)
	if err != nil {
		return nil, err
	}

	return l.loadFile(path)
}

// LoadWithDefaults loads a configuration and merges with defaults.
func (l *Loader) LoadWithDefaults(filename string) (*Config, error) {
	cfg, err := l.Load(filename)
	if err != nil {
		// If file not found, return defaults
		if os.IsNotExist(err) {
			defaults := Defaults()
			defaults.SourceFile = filename
			return defaults, nil
		}
		return nil, err
	}

	return MergeWithDefaults(cfg), nil
}

// LoadMultiple loads multiple configuration files and merges them.
// Later files override earlier ones.
func (l *Loader) LoadMultiple(filenames ...string) (*Config, error) {
	if len(filenames) == 0 {
		return Defaults(), nil
	}

	// Start with defaults
	merged := Defaults()

	for _, filename := range filenames {
		cfg, err := l.Load(filename)
		if err != nil {
			if os.IsNotExist(err) {
				continue // Skip missing optional files
			}
			return nil, err
		}

		// Merge this config into merged
		merged = mergeConfigs(merged, cfg)
	}

	return merged, nil
}

// resolvePath finds the file in the search paths.
func (l *Loader) resolvePath(filename string) (string, error) {
	// If absolute path, check directly
	if filepath.IsAbs(filename) {
		if _, err := os.Stat(filename); err != nil {
			return "", newLoadError(filename, "resolve", "file not found", err)
		}
		return filename, nil
	}

	// Search in config paths
	for _, dir := range l.configPaths {
		path := filepath.Join(dir, filename)
		if _, err := os.Stat(path); err == nil {
			return path, nil
		}
	}

	// Try without extension
	if !strings.HasSuffix(filename, ".toml") {
		return l.resolvePath(filename + ".toml")
	}

	return "", newLoadError(filename, "resolve",
		fmt.Sprintf("file not found in search paths: %v", l.configPaths), nil)
}

// loadFile loads a single configuration file.
func (l *Loader) loadFile(path string) (*Config, error) {
	// Read file
	data, err := l.readFile(path)
	if err != nil {
		return nil, err
	}

	// Parse TOML
	cfg, err := Parse(data)
	if err != nil {
		return nil, newLoadError(path, "parse", "TOML parsing failed", err)
	}

	// Set metadata
	cfg.SourceFile = path
	cfg.LoadedAt = time.Now()

	// Track for hot-reload
	l.lastLoaded[path] = time.Now()

	return cfg, nil
}

// readFile reads the file contents.
func (l *Loader) readFile(path string) ([]byte, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, newLoadError(path, "read", "failed to open file", err)
	}
	defer file.Close()

	// Check file size (max 10MB)
	info, err := file.Stat()
	if err != nil {
		return nil, newLoadError(path, "read", "failed to stat file", err)
	}

	if info.Size() > 10*1024*1024 {
		return nil, newLoadError(path, "read", "file too large (max 10MB)", nil)
	}

	data, err := io.ReadAll(file)
	if err != nil {
		return nil, newLoadError(path, "read", "failed to read file", err)
	}

	return data, nil
}

// HasChanged checks if a configuration file has changed since last load.
func (l *Loader) HasChanged(filename string) (bool, error) {
	path, err := l.resolvePath(filename)
	if err != nil {
		return false, err
	}

	info, err := os.Stat(path)
	if err != nil {
		return false, newLoadError(path, "check", "failed to stat file", err)
	}

	lastLoad, ok := l.lastLoaded[path]
	if !ok {
		return true, nil // Never loaded
	}

	return info.ModTime().After(lastLoad), nil
}

// Reload reloads a configuration file if it has changed.
func (l *Loader) Reload(filename string) (*Config, bool, error) {
	changed, err := l.HasChanged(filename)
	if err != nil {
		return nil, false, err
	}

	if !changed {
		// Return cached if available
		path, _ := l.resolvePath(filename)
		if cached, ok := l.cache[path]; ok {
			return cached, false, nil
		}
	}

	cfg, err := l.LoadWithDefaults(filename)
	if err != nil {
		return nil, false, err
	}

	// Update cache
	l.cache[cfg.SourceFile] = cfg

	return cfg, true, nil
}

// ClearCache clears the configuration cache.
func (l *Loader) ClearCache() {
	l.cache = make(map[string]*Config)
	l.lastLoaded = make(map[string]time.Time)
}

// ============================================================================
// Simple Loading Functions
// ============================================================================

// LoadConfig loads a configuration file with defaults.
// This is the main entry point for loading firewall configuration.
func LoadConfig(path string) (*Config, error) {
	loader := NewLoader()
	return loader.LoadWithDefaults(path)
}

// LoadConfigFromPaths loads configuration from multiple paths.
func LoadConfigFromPaths(paths ...string) (*Config, error) {
	loader := NewLoader()
	return loader.LoadMultiple(paths...)
}

// LoadFirewallConfig loads the standard firewall configuration.
// It looks for firewall.toml in standard locations.
func LoadFirewallConfig() (*Config, error) {
	return LoadConfig("firewall.toml")
}

// LoadFromReader loads configuration from an io.Reader.
func LoadFromReader(r io.Reader) (*Config, error) {
	data, err := io.ReadAll(r)
	if err != nil {
		return nil, newLoadError("reader", "read", "failed to read", err)
	}

	cfg, err := Parse(data)
	if err != nil {
		return nil, newLoadError("reader", "parse", "TOML parsing failed", err)
	}

	cfg.LoadedAt = time.Now()
	return MergeWithDefaults(cfg), nil
}

// LoadFromString loads configuration from a TOML string.
func LoadFromString(tomlData string) (*Config, error) {
	return LoadFromReader(strings.NewReader(tomlData))
}

// ============================================================================
// Config Merging
// ============================================================================

// mergeConfigs merges two configurations.
// Values from 'override' take precedence over 'base'.
func mergeConfigs(base, override *Config) *Config {
	if override == nil {
		return base
	}
	if base == nil {
		return override
	}

	// Create new config to avoid mutex copy issues
	result := &Config{
		DefaultPolicies:    base.DefaultPolicies,
		ConnectionTracking: base.ConnectionTracking,
		SecurityZones:      base.SecurityZones,
		AddressObjects:     base.AddressObjects,
		PortObjects:        base.PortObjects,
		ServiceObjects:     base.ServiceObjects,
		DomainObjects:      base.DomainObjects,
		RuleGroups:         base.RuleGroups,
		Rules:              base.Rules,
		NAT:                base.NAT,
		PortForwarding:     base.PortForwarding,
		Advanced:           base.Advanced,
		Version:            base.Version,
		SourceFile:         base.SourceFile,
	}

	if override.DefaultPolicies != nil {
		result.DefaultPolicies = override.DefaultPolicies
	}

	if override.ConnectionTracking != nil {
		result.ConnectionTracking = override.ConnectionTracking
	}

	if override.SecurityZones != nil && len(override.SecurityZones.Zones) > 0 {
		result.SecurityZones = override.SecurityZones
	}

	if override.Advanced != nil {
		result.Advanced = override.Advanced
	}

	if override.NAT != nil {
		result.NAT = override.NAT
	}

	if override.PortForwarding != nil {
		result.PortForwarding = override.PortForwarding
	}

	// Append collections
	if len(override.AddressObjects) > 0 {
		result.AddressObjects = append(result.AddressObjects, override.AddressObjects...)
	}

	if len(override.PortObjects) > 0 {
		result.PortObjects = append(result.PortObjects, override.PortObjects...)
	}

	if len(override.ServiceObjects) > 0 {
		result.ServiceObjects = append(result.ServiceObjects, override.ServiceObjects...)
	}

	if len(override.DomainObjects) > 0 {
		result.DomainObjects = append(result.DomainObjects, override.DomainObjects...)
	}

	if len(override.RuleGroups) > 0 {
		result.RuleGroups = override.RuleGroups
	}

	if len(override.Rules) > 0 {
		result.Rules = append(result.Rules, override.Rules...)
	}

	result.LoadedAt = time.Now()

	return result
}

// ============================================================================
// File Path Utilities
// ============================================================================

// FindConfigFile finds a configuration file in common locations.
func FindConfigFile(filename string, additionalPaths ...string) (string, error) {
	loader := NewLoader(additionalPaths...)
	return loader.resolvePath(filename)
}

// ConfigExists checks if a configuration file exists.
func ConfigExists(filename string) bool {
	_, err := FindConfigFile(filename)
	return err == nil
}
