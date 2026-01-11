package flow

import (
	"context"
	"crypto/md5"
	"fmt"
	"sync"
	"time"

	"github.com/safeops/network_logger/pkg/models"
)

// Tracker manages bidirectional flow tracking
type Tracker struct {
	flows           map[string]*models.FlowContext
	mu              sync.RWMutex
	cleanupInterval time.Duration
	flowTimeout     time.Duration
}

// NewTracker creates a new flow tracker
func NewTracker(cleanupInterval, flowTimeout time.Duration) *Tracker {
	return &Tracker{
		flows:           make(map[string]*models.FlowContext),
		cleanupInterval: cleanupInterval,
		flowTimeout:     flowTimeout,
	}
}

// UpdateFlow updates or creates a flow entry
func (t *Tracker) UpdateFlow(srcIP, dstIP string, srcPort, dstPort uint16, proto string, pktSize int, flags *models.TCPFlags) *models.FlowContext {
	flowID, direction := GenerateFlowKey(srcIP, dstIP, srcPort, dstPort, proto)

	t.mu.Lock()
	defer t.mu.Unlock()

	flow, exists := t.flows[flowID]
	if !exists {
		// Create new flow
		flow = &models.FlowContext{
			FlowID:        flowID,
			Direction:     direction,
			FlowStartTime: float64(time.Now().UnixNano()) / 1e9,
			FlowState:     "NEW",
		}
		t.flows[flowID] = flow
	}

	// Update flow statistics
	if direction == "forward" {
		flow.PacketsForward++
		flow.BytesForward += int64(pktSize)
	} else {
		flow.PacketsBackward++
		flow.BytesBackward += int64(pktSize)
	}

	// Update flow duration
	flow.FlowDuration = (float64(time.Now().UnixNano()) / 1e9) - flow.FlowStartTime

	// Update TCP state if applicable
	if flags != nil {
		flow.TCPState = getTCPState(flags)
		flow.FlowState = getFlowState(flags, flow.PacketsForward, flow.PacketsBackward)
	} else {
		flow.FlowState = "ESTABLISHED"
	}

	flow.Direction = direction

	return flow
}

// GetFlow retrieves a flow by ID
func (t *Tracker) GetFlow(flowID string) *models.FlowContext {
	t.mu.RLock()
	defer t.mu.RUnlock()

	return t.flows[flowID]
}

// CleanupStaleFlows removes flows older than timeout
func (t *Tracker) CleanupStaleFlows() {
	t.mu.Lock()
	defer t.mu.Unlock()

	now := float64(time.Now().UnixNano()) / 1e9

	for flowID, flow := range t.flows {
		age := now - flow.FlowStartTime
		if age > t.flowTimeout.Seconds() {
			delete(t.flows, flowID)
		}
	}
}

// StartCleanup begins periodic flow cleanup
func (t *Tracker) StartCleanup(ctx context.Context) {
	ticker := time.NewTicker(t.cleanupInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			t.CleanupStaleFlows()
		}
	}
}

// GetStats returns flow statistics
func (t *Tracker) GetStats() map[string]interface{} {
	t.mu.RLock()
	defer t.mu.RUnlock()

	return map[string]interface{}{
		"active_flows": len(t.flows),
	}
}

// GenerateFlowKey generates a normalized flow key for bidirectional tracking
func GenerateFlowKey(srcIP, dstIP string, srcPort, dstPort uint16, proto string) (flowID, direction string) {
	var key string

	// Normalize: smaller IP/port combination goes first
	if srcIP < dstIP || (srcIP == dstIP && srcPort < dstPort) {
		key = fmt.Sprintf("%s:%d-%s:%d/%s", srcIP, srcPort, dstIP, dstPort, proto)
		direction = "forward"
	} else {
		key = fmt.Sprintf("%s:%d-%s:%d/%s", dstIP, dstPort, srcIP, srcPort, proto)
		direction = "reverse"
	}

	// Generate flow ID hash
	hash := md5.Sum([]byte(key))
	flowID = fmt.Sprintf("flow_%x", hash[:8])

	return
}

// getTCPState returns TCP state string
func getTCPState(flags *models.TCPFlags) string {
	if flags.SYN && !flags.ACK {
		return "SYN"
	}
	if flags.SYN && flags.ACK {
		return "SYN-ACK"
	}
	if flags.FIN {
		return "FIN"
	}
	if flags.RST {
		return "RST"
	}
	if flags.ACK {
		return "ESTABLISHED"
	}
	return "UNKNOWN"
}

// getFlowState determines overall flow state
func getFlowState(flags *models.TCPFlags, pktsForward, pktsBackward int) string {
	if flags.SYN && !flags.ACK && pktsForward == 1 && pktsBackward == 0 {
		return "NEW"
	}
	if flags.SYN && flags.ACK {
		return "ESTABLISHING"
	}
	if flags.FIN || flags.RST {
		return "CLOSING"
	}
	if pktsForward > 0 && pktsBackward > 0 {
		return "ESTABLISHED"
	}
	return "NEW"
}
