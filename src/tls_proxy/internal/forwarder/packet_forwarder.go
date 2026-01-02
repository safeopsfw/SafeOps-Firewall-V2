// Package forwarder implements packet forwarding response generation.
package forwarder

import (
	"errors"
	"sync"
	"time"

	"tls_proxy/internal/buffer"
	"tls_proxy/internal/config"
	"tls_proxy/internal/models"
)

// =============================================================================
// ERROR DEFINITIONS
// =============================================================================

var (
	ErrNilResult     = errors.New("processing result is nil")
	ErrNilPacket     = errors.New("original packet is nil")
	ErrUnknownAction = errors.New("unexpected action type")
)

// =============================================================================
// gRPC RESPONSE ACTIONS
// =============================================================================

const (
	// GRPCActionForward indicates packet should be forwarded
	GRPCActionForward = "FORWARD"
	// GRPCActionDrop indicates packet should be dropped (Phase 2+)
	GRPCActionDrop = "DROP"
	// GRPCActionModify indicates packet was modified (Phase 2+)
	GRPCActionModify = "MODIFY"
)

// =============================================================================
// STATISTICS
// =============================================================================

// ForwarderStats tracks forwarding operation metrics.
type ForwarderStats struct {
	// TotalForwarded is the count of all Forward() invocations
	TotalForwarded uint64

	// ForwardedUnchanged is packets forwarded without modification
	ForwardedUnchanged uint64

	// ForwardedModified is packets forwarded with modifications (Phase 2+)
	ForwardedModified uint64

	// Dropped is packets dropped by policy (Phase 2+)
	Dropped uint64

	// ResponseErrors is errors during response construction
	ResponseErrors uint64

	// TotalResponseTime is cumulative response construction time
	TotalResponseTime time.Duration

	// LastForwardedTime is timestamp of last forwarded packet
	LastForwardedTime time.Time
}

// AverageResponseTime returns the mean duration to construct gRPC response.
func (s *ForwarderStats) AverageResponseTime() time.Duration {
	if s.TotalForwarded == 0 {
		return 0
	}
	return s.TotalResponseTime / time.Duration(s.TotalForwarded)
}

// SuccessRate returns the percentage of successful forwarding operations.
func (s *ForwarderStats) SuccessRate() float64 {
	total := s.TotalForwarded + s.ResponseErrors
	if total == 0 {
		return 0
	}
	return float64(s.TotalForwarded) / float64(total) * 100
}

// =============================================================================
// FORWARD RESPONSE STRUCTURE
// =============================================================================

// ForwardResponse represents the response to be sent back to NIC Management.
// This structure mirrors the gRPC InterceptPacketResponse message.
type ForwardResponse struct {
	// Action indicates the forwarding decision ("FORWARD", "DROP", "MODIFY")
	Action string

	// PacketData contains the packet bytes to forward
	PacketData []byte

	// Success indicates if processing succeeded
	Success bool

	// ErrorMessage contains error description if Success is false
	ErrorMessage string

	// ProcessingTimeMs is the processing duration in milliseconds
	ProcessingTimeMs int64

	// SNIHostname is the extracted SNI (for metadata enrichment)
	SNIHostname string

	// ResolvedIP is the DNS-resolved IP (for metadata enrichment)
	ResolvedIP string
}

// =============================================================================
// PACKET FORWARDER
// =============================================================================

// PacketForwarder translates ProcessingResult into gRPC responses.
type PacketForwarder struct {
	// config contains forwarding-specific settings
	config *config.Config

	// buffer provides packet retrieval and cleanup
	buffer *buffer.PacketBuffer

	// stats tracks forwarding metrics
	stats ForwarderStats
	mutex sync.RWMutex
}

// =============================================================================
// CONSTRUCTOR
// =============================================================================

// NewPacketForwarder creates a new forwarder with dependencies.
func NewPacketForwarder(cfg *config.Config, buf *buffer.PacketBuffer) *PacketForwarder {
	return &PacketForwarder{
		config: cfg,
		buffer: buf,
		stats:  ForwarderStats{},
	}
}

// =============================================================================
// MAIN FORWARD FUNCTION
// =============================================================================

// Forward creates a gRPC response from the processing result.
// Returns a ForwardResponse structure that can be used to construct gRPC message.
// Phase 1: Always returns Action="FORWARD" with original packet data.
func (f *PacketForwarder) Forward(result *models.ProcessingResult, packet *models.Packet) (*ForwardResponse, error) {
	startTime := time.Now()

	// Step 1: Validate Inputs
	if result == nil {
		f.incrementErrors()
		return nil, ErrNilResult
	}

	if packet == nil {
		f.incrementErrors()
		return nil, ErrNilPacket
	}

	// Step 2: Process Action Type
	var response *ForwardResponse
	var err error

	switch result.Action {
	case models.ActionForwardUnchanged:
		response = f.buildForwardUnchangedResponse(result, packet)
		f.incrementUnchanged()

	case models.ActionForwardModified:
		// Phase 2+: Forward modified packet
		response = f.buildForwardModifiedResponse(result, packet)
		f.incrementModified()

	case models.ActionDrop:
		// Phase 2+: Drop packet
		response = f.buildDropResponse(result)
		f.incrementDropped()

	default:
		f.incrementErrors()
		return nil, ErrUnknownAction
	}

	// Step 3: Buffer Cleanup
	if f.buffer != nil && packet.ConnectionID != "" {
		f.buffer.Remove(packet.ConnectionID)
	}

	// Step 4: Update Statistics
	f.recordForward(time.Since(startTime))

	return response, err
}

// =============================================================================
// RESPONSE BUILDERS
// =============================================================================

// buildForwardUnchangedResponse creates response for pass-through forwarding.
func (f *PacketForwarder) buildForwardUnchangedResponse(result *models.ProcessingResult, packet *models.Packet) *ForwardResponse {
	return &ForwardResponse{
		Action:           GRPCActionForward,
		PacketData:       packet.RawData, // Use original data unchanged
		Success:          true,
		ErrorMessage:     "",
		ProcessingTimeMs: result.ProcessingDuration.Milliseconds(),
		SNIHostname:      result.SNIHostname,
		ResolvedIP:       result.ResolvedIP,
	}
}

// buildForwardModifiedResponse creates response with modified packet (Phase 2+).
func (f *PacketForwarder) buildForwardModifiedResponse(result *models.ProcessingResult, packet *models.Packet) *ForwardResponse {
	packetData := result.ModifiedPacket
	if packetData == nil {
		// Fallback to original if no modification provided
		packetData = packet.RawData
	}

	return &ForwardResponse{
		Action:           GRPCActionModify,
		PacketData:       packetData,
		Success:          true,
		ErrorMessage:     "",
		ProcessingTimeMs: result.ProcessingDuration.Milliseconds(),
		SNIHostname:      result.SNIHostname,
		ResolvedIP:       result.ResolvedIP,
	}
}

// buildDropResponse creates response indicating packet should be dropped (Phase 2+).
func (f *PacketForwarder) buildDropResponse(result *models.ProcessingResult) *ForwardResponse {
	return &ForwardResponse{
		Action:           GRPCActionDrop,
		PacketData:       nil, // No data for dropped packets
		Success:          true,
		ErrorMessage:     result.DropReason,
		ProcessingTimeMs: result.ProcessingDuration.Milliseconds(),
	}
}

// BuildErrorResponse creates response for processing failures.
func (f *PacketForwarder) BuildErrorResponse(err error, processingTime time.Duration) *ForwardResponse {
	return &ForwardResponse{
		Action:           GRPCActionForward,
		PacketData:       nil,
		Success:          false,
		ErrorMessage:     err.Error(),
		ProcessingTimeMs: processingTime.Milliseconds(),
	}
}

// =============================================================================
// STATISTICS
// =============================================================================

// incrementUnchanged safely increments unchanged forward count.
func (f *PacketForwarder) incrementUnchanged() {
	f.mutex.Lock()
	defer f.mutex.Unlock()
	f.stats.ForwardedUnchanged++
}

// incrementModified safely increments modified forward count.
func (f *PacketForwarder) incrementModified() {
	f.mutex.Lock()
	defer f.mutex.Unlock()
	f.stats.ForwardedModified++
}

// incrementDropped safely increments dropped count.
func (f *PacketForwarder) incrementDropped() {
	f.mutex.Lock()
	defer f.mutex.Unlock()
	f.stats.Dropped++
}

// incrementErrors safely increments error count.
func (f *PacketForwarder) incrementErrors() {
	f.mutex.Lock()
	defer f.mutex.Unlock()
	f.stats.ResponseErrors++
}

// recordForward records a successful forward operation.
func (f *PacketForwarder) recordForward(duration time.Duration) {
	f.mutex.Lock()
	defer f.mutex.Unlock()
	f.stats.TotalForwarded++
	f.stats.TotalResponseTime += duration
	f.stats.LastForwardedTime = time.Now()
}

// GetStats returns a copy of forwarder statistics.
func (f *PacketForwarder) GetStats() ForwarderStats {
	f.mutex.RLock()
	defer f.mutex.RUnlock()

	return ForwarderStats{
		TotalForwarded:     f.stats.TotalForwarded,
		ForwardedUnchanged: f.stats.ForwardedUnchanged,
		ForwardedModified:  f.stats.ForwardedModified,
		Dropped:            f.stats.Dropped,
		ResponseErrors:     f.stats.ResponseErrors,
		TotalResponseTime:  f.stats.TotalResponseTime,
		LastForwardedTime:  f.stats.LastForwardedTime,
	}
}
