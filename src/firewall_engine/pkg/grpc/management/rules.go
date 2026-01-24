// Package management provides gRPC management API for the firewall engine.
package management

import (
	"context"
	"time"

	"google.golang.org/protobuf/types/known/timestamppb"
)

// ============================================================================
// Rules RPC Implementations
// ============================================================================

// ListRules returns a paginated list of rules.
func (s *Server) ListRules(ctx context.Context, req *ListRulesRequest) (*ListRulesResponse, error) {
	// Default values
	limit := int32(100)
	offset := int32(0)
	var actionFilter string

	if req != nil {
		if req.Limit > 0 {
			limit = req.Limit
		}
		if req.Offset >= 0 {
			offset = req.Offset
		}
		actionFilter = req.Action
	}

	// Check if rule manager available
	if s.deps.RuleManager == nil {
		return &ListRulesResponse{
			Rules:      []*Rule{},
			TotalCount: 0,
			HasMore:    false,
		}, nil
	}

	// Get all rules
	allRules := s.deps.RuleManager.GetRules()

	// Filter by action if specified
	if actionFilter != "" {
		var filtered []RuleInfo
		for _, r := range allRules {
			if r.Action == actionFilter {
				filtered = append(filtered, r)
			}
		}
		allRules = filtered
	}

	totalCount := int32(len(allRules))

	// Apply pagination
	startIdx := int(offset)
	if startIdx >= len(allRules) {
		return &ListRulesResponse{
			Rules:      []*Rule{},
			TotalCount: totalCount,
			HasMore:    false,
		}, nil
	}

	endIdx := startIdx + int(limit)
	if endIdx > len(allRules) {
		endIdx = len(allRules)
	}

	pagedRules := allRules[startIdx:endIdx]
	hasMore := endIdx < len(allRules)

	// Convert to response
	rules := make([]*Rule, len(pagedRules))
	for i, r := range pagedRules {
		var createdAt, lastHit *timestamppb.Timestamp
		if !r.CreatedAt.IsZero() {
			createdAt = timestamppb.New(r.CreatedAt)
		}
		if !r.LastHit.IsZero() {
			lastHit = timestamppb.New(r.LastHit)
		}

		rules[i] = &Rule{
			ID:         r.ID,
			Name:       r.Name,
			Action:     r.Action,
			Priority:   int32(r.Priority),
			Conditions: r.Conditions,
			HitCount:   r.HitCount,
			CreatedAt:  createdAt,
			LastHit:    lastHit,
			Enabled:    r.Enabled,
		}
	}

	return &ListRulesResponse{
		Rules:      rules,
		TotalCount: totalCount,
		HasMore:    hasMore,
	}, nil
}

// GetRule returns a single rule by ID.
func (s *Server) GetRule(ctx context.Context, req *GetRuleRequest) (*GetRuleResponse, error) {
	if req == nil || req.RuleID == "" {
		return &GetRuleResponse{
			Rule:  nil,
			Found: false,
		}, nil
	}

	// Check if rule manager available
	if s.deps.RuleManager == nil {
		return &GetRuleResponse{
			Rule:  nil,
			Found: false,
		}, nil
	}

	// Get rule by ID
	ruleInfo, found := s.deps.RuleManager.GetRuleByID(req.RuleID)
	if !found {
		return &GetRuleResponse{
			Rule:  nil,
			Found: false,
		}, nil
	}

	// Convert to response
	var createdAt, lastHit *timestamppb.Timestamp
	if !ruleInfo.CreatedAt.IsZero() {
		createdAt = timestamppb.New(ruleInfo.CreatedAt)
	}
	if !ruleInfo.LastHit.IsZero() {
		lastHit = timestamppb.New(ruleInfo.LastHit)
	}

	rule := &Rule{
		ID:         ruleInfo.ID,
		Name:       ruleInfo.Name,
		Action:     ruleInfo.Action,
		Priority:   int32(ruleInfo.Priority),
		Conditions: ruleInfo.Conditions,
		HitCount:   ruleInfo.HitCount,
		CreatedAt:  createdAt,
		LastHit:    lastHit,
		Enabled:    ruleInfo.Enabled,
	}

	return &GetRuleResponse{
		Rule:  rule,
		Found: true,
	}, nil
}

// ReloadRules triggers a hot-reload of rules from the config file.
func (s *Server) ReloadRules(ctx context.Context, req *ReloadRulesRequest) (*ReloadRulesResponse, error) {
	start := time.Now()

	// Check if rule manager available
	if s.deps.RuleManager == nil {
		return &ReloadRulesResponse{
			Success:           false,
			RulesLoaded:       0,
			ReloadTimeSeconds: 0,
			Errors:            []string{"rule manager not available"},
		}, nil
	}

	// Get previous rule count
	previousCount := int32(s.deps.RuleManager.GetRuleCount())

	// Trigger reload
	err := s.deps.RuleManager.Reload()
	reloadTime := time.Since(start)

	if err != nil {
		// Log the error
		if s.deps.Logger != nil {
			s.deps.Logger.Error().Err(err).Msg("Rule reload failed via gRPC API")
		}

		return &ReloadRulesResponse{
			Success:           false,
			RulesLoaded:       int32(s.deps.RuleManager.GetRuleCount()),
			ReloadTimeSeconds: reloadTime.Seconds(),
			Errors:            []string{err.Error()},
			PreviousRuleCount: previousCount,
		}, nil
	}

	newCount := int32(s.deps.RuleManager.GetRuleCount())

	// Log success
	if s.deps.Logger != nil {
		s.deps.Logger.Info().
			Int32("previous_count", previousCount).
			Int32("new_count", newCount).
			Dur("reload_time", reloadTime).
			Msg("Rules reloaded via gRPC API")
	}

	// Check for errors in the loaded rules
	var errors []string
	if s.deps.RuleManager.HasErrors() {
		errors = append(errors, "some rules have parse errors")
	}

	return &ReloadRulesResponse{
		Success:           true,
		RulesLoaded:       newCount,
		ReloadTimeSeconds: reloadTime.Seconds(),
		Errors:            errors,
		PreviousRuleCount: previousCount,
	}, nil
}

// ============================================================================
// Placeholder types (will be replaced by generated proto code)
// ============================================================================

// Rule holds rule information.
type Rule struct {
	ID         string
	Name       string
	Action     string
	Priority   int32
	Conditions []string
	HitCount   uint64
	CreatedAt  *timestamppb.Timestamp
	LastHit    *timestamppb.Timestamp
	Enabled    bool
}
