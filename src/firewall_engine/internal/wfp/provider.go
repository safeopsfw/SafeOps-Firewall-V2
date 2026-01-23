// Package wfp provides provider and sublayer management for WFP filter organization.
// Providers identify the source of filters, while sublayers group related filters.
package wfp

import (
	"fmt"
	"sync"

	"firewall_engine/internal/wfp/bindings"
)

// ============================================================================
// Provider Manager
// ============================================================================

// ProviderManager handles WFP provider and sublayer registration.
// Providers give identity to filters (e.g., "SafeOps Firewall").
// Sublayers group filters and affect evaluation order.
type ProviderManager struct {
	engine *Engine
	mu     sync.RWMutex

	// Provider state
	providerRegistered bool
	providerKey        bindings.GUID

	// Sublayer state
	sublayerRegistered bool
	sublayerKey        bindings.GUID
}

// NewProviderManager creates a new provider manager.
func NewProviderManager(engine *Engine) *ProviderManager {
	return &ProviderManager{
		engine:      engine,
		providerKey: bindings.SAFEOPS_PROVIDER_GUID,
		sublayerKey: bindings.SAFEOPS_SUBLAYER_GUID,
	}
}

// ============================================================================
// Provider Registration
// ============================================================================

// RegisterProvider registers the SafeOps provider with WFP.
// This should be called once after opening the engine.
// It's safe to call multiple times - subsequent calls are no-ops.
func (pm *ProviderManager) RegisterProvider() error {
	pm.mu.Lock()
	defer pm.mu.Unlock()

	if pm.providerRegistered {
		return nil // Already registered
	}

	if err := pm.engine.RequireOpen(); err != nil {
		return fmt.Errorf("cannot register provider: %w", err)
	}

	provider := bindings.NewSafeOpsProvider()
	if err := pm.engine.GetBindings().AddProvider(provider); err != nil {
		// Check if already exists (from a previous session)
		if !bindings.IsAlreadyExists(err) {
			return fmt.Errorf("failed to register provider: %w", err)
		}
		// Already exists is okay
	}

	pm.providerRegistered = true
	pm.engine.logger.Info("SafeOps provider registered: %s", pm.providerKey.String())

	return nil
}

// UnregisterProvider removes the SafeOps provider from WFP.
// All filters using this provider should be deleted first.
func (pm *ProviderManager) UnregisterProvider() error {
	pm.mu.Lock()
	defer pm.mu.Unlock()

	if !pm.providerRegistered {
		return nil // Not registered
	}

	if err := pm.engine.RequireOpen(); err != nil {
		return fmt.Errorf("cannot unregister provider: %w", err)
	}

	if err := pm.engine.GetBindings().DeleteProvider(pm.providerKey); err != nil {
		// Check if not found (already deleted)
		if !bindings.IsNotFound(err) {
			return fmt.Errorf("failed to unregister provider: %w", err)
		}
	}

	pm.providerRegistered = false
	pm.engine.logger.Info("SafeOps provider unregistered")

	return nil
}

// IsProviderRegistered returns true if the provider is registered.
func (pm *ProviderManager) IsProviderRegistered() bool {
	pm.mu.RLock()
	defer pm.mu.RUnlock()
	return pm.providerRegistered
}

// GetProviderKey returns the provider GUID.
func (pm *ProviderManager) GetProviderKey() bindings.GUID {
	return pm.providerKey
}

// ============================================================================
// Sublayer Registration
// ============================================================================

// RegisterSublayer registers the SafeOps sublayer with WFP.
// Sublayers group filters and determine evaluation priority.
// Call after RegisterProvider().
func (pm *ProviderManager) RegisterSublayer() error {
	pm.mu.Lock()
	defer pm.mu.Unlock()

	if pm.sublayerRegistered {
		return nil // Already registered
	}

	if err := pm.engine.RequireOpen(); err != nil {
		return fmt.Errorf("cannot register sublayer: %w", err)
	}

	sublayer := bindings.NewSafeOpsSublayer()
	if err := pm.engine.GetBindings().AddSublayer(sublayer); err != nil {
		// Check if already exists (from a previous session)
		if !bindings.IsAlreadyExists(err) {
			return fmt.Errorf("failed to register sublayer: %w", err)
		}
		// Already exists is okay
	}

	pm.sublayerRegistered = true
	pm.engine.logger.Info("SafeOps sublayer registered: %s", pm.sublayerKey.String())

	return nil
}

// UnregisterSublayer removes the SafeOps sublayer from WFP.
// All filters in this sublayer are automatically deleted.
func (pm *ProviderManager) UnregisterSublayer() error {
	pm.mu.Lock()
	defer pm.mu.Unlock()

	if !pm.sublayerRegistered {
		return nil // Not registered
	}

	if err := pm.engine.RequireOpen(); err != nil {
		return fmt.Errorf("cannot unregister sublayer: %w", err)
	}

	if err := pm.engine.GetBindings().DeleteSublayer(pm.sublayerKey); err != nil {
		// Check if not found (already deleted)
		if !bindings.IsNotFound(err) {
			return fmt.Errorf("failed to unregister sublayer: %w", err)
		}
	}

	pm.sublayerRegistered = false
	pm.engine.logger.Info("SafeOps sublayer unregistered")

	return nil
}

// IsSublayerRegistered returns true if the sublayer is registered.
func (pm *ProviderManager) IsSublayerRegistered() bool {
	pm.mu.RLock()
	defer pm.mu.RUnlock()
	return pm.sublayerRegistered
}

// GetSublayerKey returns the sublayer GUID.
func (pm *ProviderManager) GetSublayerKey() bindings.GUID {
	return pm.sublayerKey
}

// ============================================================================
// Convenience Methods
// ============================================================================

// Initialize registers both provider and sublayer.
// This is the recommended way to set up WFP for use.
func (pm *ProviderManager) Initialize() error {
	if err := pm.RegisterProvider(); err != nil {
		return err
	}
	return pm.RegisterSublayer()
}

// Cleanup unregisters sublayer and provider in correct order.
// Sublayer must be removed before provider.
func (pm *ProviderManager) Cleanup() error {
	var errs []error

	if err := pm.UnregisterSublayer(); err != nil {
		errs = append(errs, err)
	}

	if err := pm.UnregisterProvider(); err != nil {
		errs = append(errs, err)
	}

	if len(errs) > 0 {
		return fmt.Errorf("cleanup errors: %v", errs)
	}
	return nil
}

// IsInitialized returns true if both provider and sublayer are registered.
func (pm *ProviderManager) IsInitialized() bool {
	pm.mu.RLock()
	defer pm.mu.RUnlock()
	return pm.providerRegistered && pm.sublayerRegistered
}

// ============================================================================
// Custom Provider Support
// ============================================================================

// RegisterCustomProvider registers a custom provider with WFP.
// Use this for advanced scenarios where you need multiple providers.
func (pm *ProviderManager) RegisterCustomProvider(key bindings.GUID, name, description string) error {
	pm.mu.Lock()
	defer pm.mu.Unlock()

	if err := pm.engine.RequireOpen(); err != nil {
		return fmt.Errorf("cannot register custom provider: %w", err)
	}

	provider := bindings.NewProvider(key, name, description)
	if err := pm.engine.GetBindings().AddProvider(provider); err != nil {
		if !bindings.IsAlreadyExists(err) {
			return fmt.Errorf("failed to register custom provider: %w", err)
		}
	}

	pm.engine.logger.Info("Custom provider registered: %s (%s)", name, key.String())
	return nil
}

// RegisterCustomSublayer registers a custom sublayer with WFP.
// Weight determines evaluation order (higher = evaluated first).
func (pm *ProviderManager) RegisterCustomSublayer(key bindings.GUID, name, description string, weight uint16) error {
	pm.mu.Lock()
	defer pm.mu.Unlock()

	if err := pm.engine.RequireOpen(); err != nil {
		return fmt.Errorf("cannot register custom sublayer: %w", err)
	}

	sublayer := bindings.NewSublayer(key, name, description, weight)
	// Link to SafeOps provider
	sublayer.ProviderKey = &pm.providerKey

	if err := pm.engine.GetBindings().AddSublayer(sublayer); err != nil {
		if !bindings.IsAlreadyExists(err) {
			return fmt.Errorf("failed to register custom sublayer: %w", err)
		}
	}

	pm.engine.logger.Info("Custom sublayer registered: %s (weight=%d)", name, weight)
	return nil
}

// ============================================================================
// Status
// ============================================================================

// ProviderStatus contains the current state of provider management.
type ProviderStatus struct {
	ProviderRegistered bool
	ProviderKey        string
	SublayerRegistered bool
	SublayerKey        string
}

// GetStatus returns the current provider/sublayer status.
func (pm *ProviderManager) GetStatus() ProviderStatus {
	pm.mu.RLock()
	defer pm.mu.RUnlock()

	return ProviderStatus{
		ProviderRegistered: pm.providerRegistered,
		ProviderKey:        pm.providerKey.String(),
		SublayerRegistered: pm.sublayerRegistered,
		SublayerKey:        pm.sublayerKey.String(),
	}
}
