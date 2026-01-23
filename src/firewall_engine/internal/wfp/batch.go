// Package wfp provides batch operations for efficient filter management.
// Supports transactional batching for performance.
package wfp

import (
	"fmt"
	"sync"

	"firewall_engine/internal/wfp/bindings"
	"firewall_engine/pkg/models"
)

// ============================================================================
// Batch Configuration
// ============================================================================

const (
	// DefaultBatchSize is the default number of filters per batch.
	DefaultBatchSize = 100

	// MaxBatchSize is the maximum allowed batch size.
	MaxBatchSize = 1000
)

// ============================================================================
// Batch Context
// ============================================================================

// BatchContext manages a batch of filter operations.
type BatchContext struct {
	mu        sync.Mutex
	engine    *Engine
	filters   []*bindings.FWPM_FILTER0
	filterIDs []uint64
	committed bool
	aborted   bool
}

// NewBatchContext creates a new batch context.
func NewBatchContext(engine *Engine) *BatchContext {
	return &BatchContext{
		engine:    engine,
		filters:   make([]*bindings.FWPM_FILTER0, 0, DefaultBatchSize),
		filterIDs: make([]uint64, 0, DefaultBatchSize),
	}
}

// Add adds a filter to the batch (not yet committed).
func (bc *BatchContext) Add(filter *bindings.FWPM_FILTER0) {
	bc.mu.Lock()
	defer bc.mu.Unlock()
	bc.filters = append(bc.filters, filter)
}

// Size returns the number of filters in the batch.
func (bc *BatchContext) Size() int {
	bc.mu.Lock()
	defer bc.mu.Unlock()
	return len(bc.filters)
}

// IsCommitted returns true if the batch has been committed.
func (bc *BatchContext) IsCommitted() bool {
	bc.mu.Lock()
	defer bc.mu.Unlock()
	return bc.committed
}

// IsAborted returns true if the batch has been aborted.
func (bc *BatchContext) IsAborted() bool {
	bc.mu.Lock()
	defer bc.mu.Unlock()
	return bc.aborted
}

// FilterIDs returns the IDs of successfully installed filters.
func (bc *BatchContext) FilterIDs() []uint64 {
	bc.mu.Lock()
	defer bc.mu.Unlock()
	ids := make([]uint64, len(bc.filterIDs))
	copy(ids, bc.filterIDs)
	return ids
}

// ============================================================================
// Batch Manager
// ============================================================================

// BatchManager handles batch filter operations with transaction support.
type BatchManager struct {
	engine     *Engine
	filterMgr  *FilterManager
	translator *Translator
	batchSize  int
}

// NewBatchManager creates a new batch manager.
func NewBatchManager(engine *Engine, filterMgr *FilterManager) *BatchManager {
	return &BatchManager{
		engine:     engine,
		filterMgr:  filterMgr,
		translator: NewTranslator(),
		batchSize:  DefaultBatchSize,
	}
}

// SetBatchSize sets the batch size for operations.
func (bm *BatchManager) SetBatchSize(size int) {
	if size < 1 {
		size = 1
	}
	if size > MaxBatchSize {
		size = MaxBatchSize
	}
	bm.batchSize = size
}

// GetBatchSize returns the current batch size.
func (bm *BatchManager) GetBatchSize() int {
	return bm.batchSize
}

// ============================================================================
// Transaction Operations
// ============================================================================

// BeginBatch starts a new batch context.
func (bm *BatchManager) BeginBatch() (*BatchContext, error) {
	if err := bm.engine.RequireOpen(); err != nil {
		return nil, fmt.Errorf("cannot begin batch: %w", err)
	}

	ctx := NewBatchContext(bm.engine)
	return ctx, nil
}

// CommitBatch commits all filters in the batch within a transaction.
func (bm *BatchManager) CommitBatch(ctx *BatchContext) error {
	if ctx.IsCommitted() || ctx.IsAborted() {
		return fmt.Errorf("batch already finalized")
	}

	ctx.mu.Lock()
	defer ctx.mu.Unlock()

	if len(ctx.filters) == 0 {
		ctx.committed = true
		return nil
	}

	// Use transaction for atomic commit
	err := bm.engine.GetBindings().WithTransaction(func() error {
		for _, filter := range ctx.filters {
			id, err := bm.engine.GetBindings().AddFilter(filter)
			if err != nil {
				return fmt.Errorf("failed to add filter: %w", err)
			}
			ctx.filterIDs = append(ctx.filterIDs, id)

			// Track in filter manager
			if filter.RuleID != "" {
				bm.engine.TrackFilter(filter.RuleID, id)
			}
		}
		return nil
	})

	if err != nil {
		ctx.aborted = true
		return err
	}

	ctx.committed = true
	return nil
}

// AbortBatch discards the batch without committing.
func (bm *BatchManager) AbortBatch(ctx *BatchContext) {
	ctx.mu.Lock()
	defer ctx.mu.Unlock()

	if !ctx.committed && !ctx.aborted {
		ctx.aborted = true
		ctx.filters = nil
	}
}

// ============================================================================
// High-Level Batch Operations
// ============================================================================

// AddFiltersInBatch adds multiple filters using batching and transactions.
func (bm *BatchManager) AddFiltersInBatch(rules []*models.FirewallRule) ([]uint64, error) {
	if err := bm.engine.RequireOpen(); err != nil {
		return nil, fmt.Errorf("cannot add filters: %w", err)
	}

	if len(rules) == 0 {
		return nil, nil
	}

	// Translate all rules first
	var allFilters []*bindings.FWPM_FILTER0
	for _, rule := range rules {
		if rule == nil || !rule.Enabled {
			continue
		}

		result, err := bm.translator.TranslateRule(rule)
		if err != nil {
			// Log warning but continue
			continue
		}

		allFilters = append(allFilters, result.Filters...)
	}

	if len(allFilters) == 0 {
		return nil, nil
	}

	// Process in batches
	var allIDs []uint64
	for i := 0; i < len(allFilters); i += bm.batchSize {
		end := i + bm.batchSize
		if end > len(allFilters) {
			end = len(allFilters)
		}
		batch := allFilters[i:end]

		ctx, err := bm.BeginBatch()
		if err != nil {
			return allIDs, err
		}

		for _, filter := range batch {
			ctx.Add(filter)
		}

		if err := bm.CommitBatch(ctx); err != nil {
			// Try individual adds as fallback
			for _, filter := range batch {
				id, _ := bm.engine.GetBindings().AddFilter(filter)
				if id > 0 {
					allIDs = append(allIDs, id)
				}
			}
			continue
		}

		allIDs = append(allIDs, ctx.FilterIDs()...)
	}

	return allIDs, nil
}

// DeleteAllFilters removes all filters from this provider in a batch.
func (bm *BatchManager) DeleteAllFilters() error {
	if err := bm.engine.RequireOpen(); err != nil {
		return fmt.Errorf("cannot delete filters: %w", err)
	}

	return bm.engine.GetBindings().DeleteAllFilters()
}

// ============================================================================
// Sync Operations
// ============================================================================

// SyncRules synchronizes WFP filters with the provided rules.
// Efficiently adds new rules and removes stale ones.
func (bm *BatchManager) SyncRules(rules []*models.FirewallRule) error {
	if err := bm.engine.RequireOpen(); err != nil {
		return fmt.Errorf("cannot sync: %w", err)
	}

	// Get current filter state
	currentFilters := bm.filterMgr.GetAllFilters()
	currentIDs := make(map[string]bool)
	for _, f := range currentFilters {
		currentIDs[f.RuleID] = true
	}

	// Determine what to add and remove
	wantedIDs := make(map[string]*models.FirewallRule)
	for _, rule := range rules {
		if rule != nil && rule.Enabled {
			wantedIDs[rule.ID.String()] = rule
		}
	}

	// Rules to add
	var toAdd []*models.FirewallRule
	for id, rule := range wantedIDs {
		if !currentIDs[id] {
			toAdd = append(toAdd, rule)
		}
	}

	// Rules to remove
	var toRemove []string
	for id := range currentIDs {
		if _, wanted := wantedIDs[id]; !wanted {
			toRemove = append(toRemove, id)
		}
	}

	// Remove stale filters
	for _, ruleID := range toRemove {
		_ = bm.filterMgr.DeleteFilter(ruleID)
	}

	// Add new filters in batch
	if len(toAdd) > 0 {
		_, err := bm.AddFiltersInBatch(toAdd)
		if err != nil {
			return fmt.Errorf("failed to add filters: %w", err)
		}
	}

	return nil
}

// ============================================================================
// Statistics
// ============================================================================

// BatchStats contains batch operation statistics.
type BatchStats struct {
	BatchSize      int
	TotalFilters   int
	PendingFilters int
}

// GetStats returns current batch statistics.
func (bm *BatchManager) GetStats() BatchStats {
	return BatchStats{
		BatchSize:    bm.batchSize,
		TotalFilters: bm.filterMgr.GetFilterCount(),
	}
}
