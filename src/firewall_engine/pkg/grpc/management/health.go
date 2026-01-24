// Package management provides gRPC management API for the firewall engine.
package management

import (
	"context"
	"time"

	"google.golang.org/protobuf/types/known/timestamppb"

	"firewall_engine/internal/health"
)

// ============================================================================
// Health RPC Implementations
// ============================================================================

// GetHealth returns overall health status with component breakdown.
func (s *Server) GetHealth(ctx context.Context, req *GetHealthRequest) (*GetHealthResponse, error) {
	start := time.Now()

	// Check if health aggregator available
	if s.deps.HealthAggregator == nil {
		return &GetHealthResponse{
			Status:         "unknown",
			Components:     []*ComponentHealth{},
			Timestamp:      timestamppb.Now(),
			CheckLatencyMs: 0,
		}, nil
	}

	// Perform health check
	result := s.deps.HealthAggregator.Check(ctx)

	// Convert components
	components := make([]*ComponentHealth, len(result.Components))
	for i, comp := range result.Components {
		components[i] = &ComponentHealth{
			Name:      comp.Name,
			Status:    comp.Status.String(),
			Message:   comp.Message,
			LatencyMs: comp.LatencyMs,
			Critical:  comp.Critical,
			Details:   make(map[string]string),
		}
	}

	latencyMs := float64(time.Since(start).Microseconds()) / 1000.0

	return &GetHealthResponse{
		Status:         result.Status.String(),
		Components:     components,
		Timestamp:      timestamppb.Now(),
		CheckLatencyMs: latencyMs,
	}, nil
}

// GetComponentHealth returns health status for a specific component.
func (s *Server) GetComponentHealth(ctx context.Context, req *GetComponentHealthRequest) (*GetComponentHealthResponse, error) {
	if req == nil || req.ComponentName == "" {
		return &GetComponentHealthResponse{
			Component: &ComponentHealth{
				Name:    "unknown",
				Status:  "error",
				Message: "component name is required",
			},
		}, nil
	}

	// Check if health aggregator available
	if s.deps.HealthAggregator == nil {
		return &GetComponentHealthResponse{
			Component: &ComponentHealth{
				Name:    req.ComponentName,
				Status:  "unknown",
				Message: "health aggregator not available",
			},
		}, nil
	}

	// Get component status
	status, err := s.deps.HealthAggregator.GetComponentStatus(req.ComponentName)
	if err != nil {
		if err == health.ErrCheckerNotFound {
			return &GetComponentHealthResponse{
				Component: &ComponentHealth{
					Name:    req.ComponentName,
					Status:  "not_found",
					Message: "component not found",
				},
			}, nil
		}
		return &GetComponentHealthResponse{
			Component: &ComponentHealth{
				Name:    req.ComponentName,
				Status:  "error",
				Message: err.Error(),
			},
		}, nil
	}

	return &GetComponentHealthResponse{
		Component: &ComponentHealth{
			Name:   req.ComponentName,
			Status: status.String(),
		},
	}, nil
}

// ============================================================================
// Placeholder types (will be replaced by generated proto code)
// ============================================================================

// ComponentHealth holds component health info.
type ComponentHealth struct {
	Name      string
	Status    string
	Message   string
	LatencyMs float64
	Critical  bool
	Details   map[string]string
}
