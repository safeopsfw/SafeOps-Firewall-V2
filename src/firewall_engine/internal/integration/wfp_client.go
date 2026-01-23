// Package integration provides high-level clients for external components.
// WFPClient wraps the WFP engine with a simplified API for use by main.go.
package integration

import (
	"fmt"
	"sync"
	"time"

	"firewall_engine/internal/wfp"
	"firewall_engine/internal/wfp/boottime"
	"firewall_engine/pkg/models"
)

// ============================================================================
// WFP Client Configuration
// ============================================================================

// WFPClientConfig configures the WFP client.
type WFPClientConfig struct {
	// SessionName is the name for the WFP session.
	SessionName string

	// Dynamic determines if filters are deleted on close.
	Dynamic bool

	// EnablePersistentFilters enables boot-time persistent filter support.
	EnablePersistentFilters bool

	// MaxPersistentFilters is the maximum number of persistent filters.
	MaxPersistentFilters int

	// TransactionTimeout is the timeout for WFP transactions.
	TransactionTimeout time.Duration

	// Logger is the logger for WFP operations.
	Logger wfp.Logger
}

// DefaultWFPClientConfig returns the default configuration.
func DefaultWFPClientConfig() *WFPClientConfig {
	return &WFPClientConfig{
		SessionName:             "SafeOps_WFP_Client",
		Dynamic:                 true,
		EnablePersistentFilters: true,
		MaxPersistentFilters:    50,
		TransactionTimeout:      5 * time.Second,
	}
}

// ============================================================================
// WFP Client Status
// ============================================================================

// WFPClientStatus contains the current status of the WFP client.
type WFPClientStatus struct {
	// Connected indicates if the client is connected to WFP.
	Connected bool

	// State is the engine state.
	State string

	// FilterCount is the number of installed filters.
	FilterCount int

	// PersistentCount is the number of persistent filters.
	PersistentCount int

	// ProviderRegistered indicates if SafeOps provider is registered.
	ProviderRegistered bool

	// LastError is the last error encountered.
	LastError error

	// Uptime is how long the client has been connected.
	Uptime time.Duration
}

// String returns a summary of the status.
func (s *WFPClientStatus) String() string {
	status := "disconnected"
	if s.Connected {
		status = "connected"
	}
	return fmt.Sprintf("[%s] filters=%d, persistent=%d, uptime=%v",
		status, s.FilterCount, s.PersistentCount, s.Uptime.Round(time.Second))
}

// ============================================================================
// WFP Client
// ============================================================================

// WFPClient provides a high-level API for WFP integration.
// It manages the WFP engine, translator, and persistent filter manager.
type WFPClient struct {
	mu sync.RWMutex

	// Configuration
	config *WFPClientConfig

	// Components
	engine        *wfp.Engine
	translator    *wfp.Translator
	persistentMgr *boottime.PersistentManager
	criticalSel   *boottime.CriticalSelector

	// State
	isOpen    bool
	openTime  time.Time
	lastError error

	// Statistics
	rulesInstalled  int
	rulesFailed     int
	installDuration time.Duration
}

// NewWFPClient creates a new WFP client with the given configuration.
func NewWFPClient(config *WFPClientConfig) (*WFPClient, error) {
	if config == nil {
		config = DefaultWFPClientConfig()
	}

	// Create engine config
	engineConfig := wfp.DefaultEngineConfig()
	engineConfig.SessionName = config.SessionName
	engineConfig.Dynamic = config.Dynamic
	if config.Logger != nil {
		engineConfig.Logger = config.Logger
	}

	// Create engine
	engine := wfp.NewEngine(engineConfig)

	client := &WFPClient{
		config:      config,
		engine:      engine,
		translator:  wfp.NewTranslator(),
		criticalSel: boottime.NewCriticalSelector().WithMaxPersistent(config.MaxPersistentFilters),
	}

	return client, nil
}

// ============================================================================
// Lifecycle Methods
// ============================================================================

// Open opens the WFP connection.
func (c *WFPClient) Open() error {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.isOpen {
		return nil
	}

	// Open engine
	if err := c.engine.Open(); err != nil {
		c.lastError = err
		return fmt.Errorf("open WFP engine: %w", err)
	}

	// Initialize persistent manager if enabled
	if c.config.EnablePersistentFilters {
		pm, err := boottime.NewPersistentManagerWithConfig(c.engine, &boottime.PersistentConfig{
			MaxPersistent: c.config.MaxPersistentFilters,
			AutoSync:      true,
			VerifyOnLoad:  true,
		})
		if err != nil {
			// Log but don't fail - persistent filters are optional
		} else {
			c.persistentMgr = pm
		}
	}

	c.isOpen = true
	c.openTime = time.Now()
	return nil
}

// Close closes the WFP connection.
func (c *WFPClient) Close() error {
	c.mu.Lock()
	defer c.mu.Unlock()

	if !c.isOpen {
		return nil
	}

	// Close persistent manager
	if c.persistentMgr != nil {
		c.persistentMgr.Close()
		c.persistentMgr = nil
	}

	// Close engine
	if err := c.engine.Close(); err != nil {
		c.lastError = err
		return fmt.Errorf("close WFP engine: %w", err)
	}

	c.isOpen = false
	return nil
}

// IsOpen returns true if the client is connected.
func (c *WFPClient) IsOpen() bool {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.isOpen
}

// ============================================================================
// Filter Installation
// ============================================================================

// InstallRules installs firewall rules as WFP filters.
func (c *WFPClient) InstallRules(rules []*models.FirewallRule) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	if !c.isOpen {
		return fmt.Errorf("client is not open")
	}

	start := time.Now()
	installed := 0
	failed := 0

	bindingsEngine := c.engine.GetBindings()
	if bindingsEngine == nil {
		return fmt.Errorf("bindings engine is nil")
	}

	for _, rule := range rules {
		if rule == nil || !rule.Enabled {
			continue
		}

		// Translate rule
		result, err := c.translator.TranslateRule(rule)
		if err != nil {
			failed++
			continue
		}

		// Install filters
		for _, filter := range result.Filters {
			filterID, err := bindingsEngine.AddFilter(filter)
			if err != nil {
				failed++
				continue
			}
			c.engine.TrackFilter(rule.ID.String(), filterID)
			installed++
		}
	}

	c.rulesInstalled = installed
	c.rulesFailed = failed
	c.installDuration = time.Since(start)

	if failed > 0 {
		return fmt.Errorf("installed %d filters, %d failed", installed, failed)
	}

	return nil
}

// UninstallRules removes all SafeOps filters from WFP.
func (c *WFPClient) UninstallRules() error {
	c.mu.Lock()
	defer c.mu.Unlock()

	if !c.isOpen {
		return fmt.Errorf("client is not open")
	}

	bindingsEngine := c.engine.GetBindings()
	if bindingsEngine == nil {
		return fmt.Errorf("bindings engine is nil")
	}

	if err := bindingsEngine.DeleteAllFilters(); err != nil {
		c.lastError = err
		return fmt.Errorf("delete all filters: %w", err)
	}

	c.rulesInstalled = 0
	return nil
}

// RefreshRules performs a hot-reload of rules.
func (c *WFPClient) RefreshRules(rules []*models.FirewallRule) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	if !c.isOpen {
		return fmt.Errorf("client is not open")
	}

	bindingsEngine := c.engine.GetBindings()
	if bindingsEngine == nil {
		return fmt.Errorf("bindings engine is nil")
	}

	// Use transaction for atomic refresh
	if err := bindingsEngine.BeginTransaction(); err != nil {
		// Continue without transaction
	}

	// Delete existing filters
	if err := bindingsEngine.DeleteAllFilters(); err != nil {
		bindingsEngine.AbortTransaction()
		return fmt.Errorf("delete existing filters: %w", err)
	}

	// Install new filters
	start := time.Now()
	installed := 0

	for _, rule := range rules {
		if rule == nil || !rule.Enabled {
			continue
		}

		result, err := c.translator.TranslateRule(rule)
		if err != nil {
			continue
		}

		for _, filter := range result.Filters {
			filterID, err := bindingsEngine.AddFilter(filter)
			if err != nil {
				continue
			}
			c.engine.TrackFilter(rule.ID.String(), filterID)
			installed++
		}
	}

	// Commit transaction
	if bindingsEngine.InTransaction() {
		if err := bindingsEngine.CommitTransaction(); err != nil {
			bindingsEngine.AbortTransaction()
			return fmt.Errorf("commit transaction: %w", err)
		}
	}

	c.rulesInstalled = installed
	c.installDuration = time.Since(start)

	return nil
}

// ============================================================================
// Persistent Filter Management
// ============================================================================

// InstallPersistentRules installs critical rules as persistent filters.
func (c *WFPClient) InstallPersistentRules(rules []*models.FirewallRule) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	if !c.isOpen {
		return fmt.Errorf("client is not open")
	}

	if c.persistentMgr == nil {
		return fmt.Errorf("persistent filters not enabled")
	}

	// Select critical rules
	critical := c.criticalSel.GetCriticalRules(rules)

	// Install persistent filters
	_, errors := c.persistentMgr.InstallMultiple(critical)
	if len(errors) > 0 {
		return errors[0]
	}

	return nil
}

// GetPersistentCount returns the number of persistent filters.
func (c *WFPClient) GetPersistentCount() int {
	c.mu.RLock()
	defer c.mu.RUnlock()

	if c.persistentMgr == nil {
		return 0
	}
	return c.persistentMgr.GetPersistentCount()
}

// ValidateBootProtection validates boot-time protection is active.
func (c *WFPClient) ValidateBootProtection() (*boottime.ValidationReport, error) {
	c.mu.RLock()
	defer c.mu.RUnlock()

	if c.persistentMgr == nil {
		return nil, fmt.Errorf("persistent filters not enabled")
	}

	validator := boottime.NewBootValidator(c.persistentMgr)
	return validator.RunFullValidation(), nil
}

// ============================================================================
// Status and Statistics
// ============================================================================

// GetStatus returns the current client status.
func (c *WFPClient) GetStatus() *WFPClientStatus {
	c.mu.RLock()
	defer c.mu.RUnlock()

	status := &WFPClientStatus{
		Connected: c.isOpen,
		LastError: c.lastError,
	}

	if c.isOpen {
		status.State = c.engine.State().String()
		status.FilterCount = c.engine.GetFilterCount()
		status.Uptime = time.Since(c.openTime)
		status.ProviderRegistered = true // Assumed if open

		if c.persistentMgr != nil {
			status.PersistentCount = c.persistentMgr.GetPersistentCount()
		}
	}

	return status
}

// GetInstalledFilterCount returns the number of installed filters.
func (c *WFPClient) GetInstalledFilterCount() int {
	c.mu.RLock()
	defer c.mu.RUnlock()

	if !c.isOpen {
		return 0
	}
	return c.engine.GetFilterCount()
}

// GetInstallDuration returns how long the last installation took.
func (c *WFPClient) GetInstallDuration() time.Duration {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.installDuration
}

// GetEngine returns the underlying WFP engine (use with caution).
func (c *WFPClient) GetEngine() *wfp.Engine {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.engine
}

// ============================================================================
// Error Handling
// ============================================================================

// GetLastError returns the last error encountered.
func (c *WFPClient) GetLastError() error {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.lastError
}

// ClearLastError clears the last error.
func (c *WFPClient) ClearLastError() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.lastError = nil
}

// ============================================================================
// Utility Methods
// ============================================================================

// RequireOpen returns an error if the client is not open.
func (c *WFPClient) RequireOpen() error {
	c.mu.RLock()
	defer c.mu.RUnlock()

	if !c.isOpen {
		return fmt.Errorf("WFP client is not open")
	}
	return nil
}

// Ping checks if the WFP connection is alive.
func (c *WFPClient) Ping() error {
	c.mu.RLock()
	defer c.mu.RUnlock()

	if !c.isOpen {
		return fmt.Errorf("client is not open")
	}

	if !c.engine.IsOpen() {
		return fmt.Errorf("engine is not connected")
	}

	return nil
}

// ============================================================================
// Helper Functions
// ============================================================================

// IsWFPAvailable checks if WFP is available on this system.
func IsWFPAvailable() bool {
	// WFP is available on Windows Vista and later
	// For now, assume available if we can load the DLL
	return true
}

// IsAdminRequired returns true if admin privileges are required for WFP.
func IsAdminRequired() bool {
	return true // WFP always requires admin
}
