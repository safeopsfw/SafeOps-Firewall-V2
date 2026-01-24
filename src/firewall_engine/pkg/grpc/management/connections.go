// Package management provides gRPC management API for the firewall engine.
package management

import (
	"context"

	"google.golang.org/protobuf/types/known/timestamppb"
)

// ============================================================================
// Connection RPC Implementations
// ============================================================================

// GetActiveConnections returns a list of active connections.
func (s *Server) GetActiveConnections(ctx context.Context, req *GetActiveConnectionsRequest) (*GetActiveConnectionsResponse, error) {
	// Default limit
	limit := int32(100)
	if req != nil && req.Limit > 0 {
		limit = req.Limit
	}

	// Check if connection tracker available
	if s.deps.ConnectionTracker == nil {
		return &GetActiveConnectionsResponse{
			Connections:      []*Connection{},
			TotalConnections: 0,
		}, nil
	}

	// Get connections
	conns := s.deps.ConnectionTracker.GetConnections(int(limit))

	// Filter by protocol if specified
	if req != nil && req.Protocol != "" {
		var filtered []ConnectionInfo
		for _, c := range conns {
			if c.Protocol == req.Protocol {
				filtered = append(filtered, c)
			}
		}
		conns = filtered
	}

	// Filter by state if specified
	if req != nil && req.State != "" {
		var filtered []ConnectionInfo
		for _, c := range conns {
			if c.State == req.State {
				filtered = append(filtered, c)
			}
		}
		conns = filtered
	}

	// Convert to response
	connections := make([]*Connection, len(conns))
	for i, c := range conns {
		var createdAt, lastActivity *timestamppb.Timestamp
		if !c.CreatedAt.IsZero() {
			createdAt = timestamppb.New(c.CreatedAt)
		}
		if !c.LastActivity.IsZero() {
			lastActivity = timestamppb.New(c.LastActivity)
		}

		connections[i] = &Connection{
			FlowID:       c.FlowID,
			SrcIP:        c.SrcIP,
			SrcPort:      int32(c.SrcPort),
			DstIP:        c.DstIP,
			DstPort:      int32(c.DstPort),
			Protocol:     c.Protocol,
			State:        c.State,
			CreatedAt:    createdAt,
			LastActivity: lastActivity,
			PacketsIn:    c.PacketsIn,
			PacketsOut:   c.PacketsOut,
			BytesIn:      c.BytesIn,
			BytesOut:     c.BytesOut,
			Application:  c.Application,
		}
	}

	totalConnections := uint64(s.deps.ConnectionTracker.GetActiveConnectionCount())

	return &GetActiveConnectionsResponse{
		Connections:      connections,
		TotalConnections: totalConnections,
	}, nil
}

// GetConnectionByFlowID returns a single connection by flow ID.
func (s *Server) GetConnectionByFlowID(ctx context.Context, req *GetConnectionByFlowIDRequest) (*GetConnectionByFlowIDResponse, error) {
	if req == nil || req.FlowID == "" {
		return &GetConnectionByFlowIDResponse{
			Connection: nil,
			Found:      false,
		}, nil
	}

	// Check if connection tracker available
	if s.deps.ConnectionTracker == nil {
		return &GetConnectionByFlowIDResponse{
			Connection: nil,
			Found:      false,
		}, nil
	}

	// Get connection by flow ID
	connInfo, found := s.deps.ConnectionTracker.GetConnectionByFlowID(req.FlowID)
	if !found {
		return &GetConnectionByFlowIDResponse{
			Connection: nil,
			Found:      false,
		}, nil
	}

	// Convert to response
	var createdAt, lastActivity *timestamppb.Timestamp
	if !connInfo.CreatedAt.IsZero() {
		createdAt = timestamppb.New(connInfo.CreatedAt)
	}
	if !connInfo.LastActivity.IsZero() {
		lastActivity = timestamppb.New(connInfo.LastActivity)
	}

	connection := &Connection{
		FlowID:       connInfo.FlowID,
		SrcIP:        connInfo.SrcIP,
		SrcPort:      int32(connInfo.SrcPort),
		DstIP:        connInfo.DstIP,
		DstPort:      int32(connInfo.DstPort),
		Protocol:     connInfo.Protocol,
		State:        connInfo.State,
		CreatedAt:    createdAt,
		LastActivity: lastActivity,
		PacketsIn:    connInfo.PacketsIn,
		PacketsOut:   connInfo.PacketsOut,
		BytesIn:      connInfo.BytesIn,
		BytesOut:     connInfo.BytesOut,
		Application:  connInfo.Application,
	}

	return &GetConnectionByFlowIDResponse{
		Connection: connection,
		Found:      true,
	}, nil
}

// ============================================================================
// Default Connection Tracker (for when no tracker is injected)
// ============================================================================

// NoopConnectionTracker is a no-op connection tracker implementation.
type NoopConnectionTracker struct{}

// NewNoopConnectionTracker creates a no-op connection tracker.
func NewNoopConnectionTracker() *NoopConnectionTracker {
	return &NoopConnectionTracker{}
}

// GetActiveConnectionCount returns 0.
func (t *NoopConnectionTracker) GetActiveConnectionCount() int {
	return 0
}

// GetConnections returns empty slice.
func (t *NoopConnectionTracker) GetConnections(limit int) []ConnectionInfo {
	return nil
}

// GetConnectionByFlowID returns not found.
func (t *NoopConnectionTracker) GetConnectionByFlowID(flowID string) (ConnectionInfo, bool) {
	return ConnectionInfo{}, false
}

// ============================================================================
// Placeholder types (will be replaced by generated proto code)
// ============================================================================

// Connection holds connection information.
type Connection struct {
	FlowID       string
	SrcIP        string
	SrcPort      int32
	DstIP        string
	DstPort      int32
	Protocol     string
	State        string
	CreatedAt    *timestamppb.Timestamp
	LastActivity *timestamppb.Timestamp
	PacketsIn    uint64
	PacketsOut   uint64
	BytesIn      uint64
	BytesOut     uint64
	Application  string
}
