// Package models defines all core data structures used throughout the firewall engine.
package models

import (
	"encoding/json"
	"fmt"
	"sync/atomic"
	"time"
)

// ============================================================================
// Flow Statistics - Network flow tracking for logging and analysis
// ============================================================================

// FlowStatistics represents aggregated statistics for a network flow.
// A flow is identified by the 5-tuple (proto, src_ip, src_port, dst_ip, dst_port).
// Used for flow-based logging instead of per-packet logging.
type FlowStatistics struct {
	// === Flow Identification ===

	// FlowID is a unique identifier for this flow (hash of 5-tuple).
	FlowID string `json:"flow_id"`

	// FlowKey is the normalized 5-tuple key.
	FlowKey string `json:"flow_key,omitempty"`

	// === Endpoint Information ===

	// Protocol is the IP protocol (TCP, UDP, ICMP).
	Protocol Protocol `json:"protocol"`

	// SrcIP is the source IP address.
	SrcIP string `json:"src_ip"`

	// SrcPort is the source port.
	SrcPort uint16 `json:"src_port"`

	// DstIP is the destination IP address.
	DstIP string `json:"dst_ip"`

	// DstPort is the destination port.
	DstPort uint16 `json:"dst_port"`

	// === Domain Information ===

	// Domain is the associated domain name (if extracted).
	Domain string `json:"domain,omitempty"`

	// DomainSource indicates how the domain was extracted.
	DomainSource DomainSource `json:"domain_source,omitempty"`

	// === Timestamps ===

	// StartTime is when the flow was first seen.
	StartTime time.Time `json:"start_time"`

	// EndTime is when the flow was last seen.
	EndTime time.Time `json:"end_time"`

	// Duration is the flow duration.
	Duration time.Duration `json:"duration"`

	// === Packet/Byte Counters ===

	// TotalPackets is total packets in both directions.
	TotalPackets atomic.Uint64 `json:"-"`

	// TotalBytes is total bytes in both directions.
	TotalBytes atomic.Uint64 `json:"-"`

	// ForwardPackets is packets in the original direction.
	ForwardPackets atomic.Uint64 `json:"-"`

	// ForwardBytes is bytes in the original direction.
	ForwardBytes atomic.Uint64 `json:"-"`

	// ReversePackets is packets in the reverse direction.
	ReversePackets atomic.Uint64 `json:"-"`

	// ReverseBytes is bytes in the reverse direction.
	ReverseBytes atomic.Uint64 `json:"-"`

	// === Flow State ===

	// State is the current connection state.
	State ConnectionState `json:"state"`

	// Verdict is the firewall verdict applied to this flow.
	Verdict Verdict `json:"verdict"`

	// RuleID is the rule that matched this flow.
	RuleID string `json:"rule_id,omitempty"`

	// RuleName is the name of the matched rule.
	RuleName string `json:"rule_name,omitempty"`

	// === TCP State (if applicable) ===

	// TCPState tracks TCP connection state.
	TCPState *FlowTCPState `json:"tcp_state,omitempty"`

	// === Network Information ===

	// Direction is the original flow direction.
	Direction Direction `json:"direction"`

	// AdapterName is the network interface.
	AdapterName string `json:"adapter_name,omitempty"`

	// SourceZone is the security zone of the source.
	SourceZone string `json:"source_zone,omitempty"`

	// DestinationZone is the security zone of the destination.
	DestinationZone string `json:"destination_zone,omitempty"`

	// === Flags ===

	// IsActive indicates if the flow is still active.
	IsActive bool `json:"is_active"`

	// IsLogged indicates if this flow has been logged.
	IsLogged bool `json:"-"`

	// === JSON Serialization Fields ===
	TotalPacketsJSON   uint64 `json:"total_packets"`
	TotalBytesJSON     uint64 `json:"total_bytes"`
	ForwardPacketsJSON uint64 `json:"forward_packets"`
	ForwardBytesJSON   uint64 `json:"forward_bytes"`
	ReversePacketsJSON uint64 `json:"reverse_packets"`
	ReverseBytesJSON   uint64 `json:"reverse_bytes"`
	DurationJSON       string `json:"duration_str,omitempty"`
}

// FlowTCPState tracks TCP-specific flow state.
type FlowTCPState struct {
	// SYNSent indicates if SYN was seen.
	SYNSent bool `json:"syn_sent"`

	// SYNACKSeen indicates if SYN-ACK was seen.
	SYNACKSeen bool `json:"syn_ack_seen"`

	// Established indicates if connection was established.
	Established bool `json:"established"`

	// ClientFIN indicates if client sent FIN.
	ClientFIN bool `json:"client_fin"`

	// ServerFIN indicates if server sent FIN.
	ServerFIN bool `json:"server_fin"`

	// RSTSeen indicates if RST was seen.
	RSTSeen bool `json:"rst_seen"`

	// HandshakeTime is the 3-way handshake completion time.
	HandshakeTime time.Time `json:"handshake_time,omitempty"`

	// ClosingTime is when teardown started.
	ClosingTime time.Time `json:"closing_time,omitempty"`
}

// NewFlowStatistics creates a new flow statistics entry from a packet.
func NewFlowStatistics(pkt *PacketMetadata) *FlowStatistics {
	now := time.Now()

	flow := &FlowStatistics{
		FlowID:       pkt.GenerateFlowKey(),
		FlowKey:      pkt.GenerateFlowKey(),
		Protocol:     pkt.Protocol,
		SrcIP:        pkt.SrcIP,
		SrcPort:      pkt.SrcPort,
		DstIP:        pkt.DstIP,
		DstPort:      pkt.DstPort,
		Domain:       pkt.Domain,
		DomainSource: pkt.DomainSource,
		StartTime:    now,
		EndTime:      now,
		State:        StateNew,
		Direction:    pkt.Direction,
		AdapterName:  pkt.AdapterName,
		IsActive:     true,
	}

	// Initialize TCP state if TCP
	if pkt.Protocol == ProtocolTCP {
		flow.TCPState = &FlowTCPState{}
		if pkt.IsSYN && !pkt.IsACK {
			flow.TCPState.SYNSent = true
		}
	}

	// Record first packet
	flow.TotalPackets.Store(1)
	flow.TotalBytes.Store(uint64(pkt.PacketSize))

	if pkt.Direction == DirectionOutbound {
		flow.ForwardPackets.Store(1)
		flow.ForwardBytes.Store(uint64(pkt.PacketSize))
	} else {
		flow.ReversePackets.Store(1)
		flow.ReverseBytes.Store(uint64(pkt.PacketSize))
	}

	return flow
}

// Update updates the flow with new packet information.
func (fs *FlowStatistics) Update(pkt *PacketMetadata) {
	fs.EndTime = time.Now()
	fs.Duration = fs.EndTime.Sub(fs.StartTime)

	// Update counters
	fs.TotalPackets.Add(1)
	fs.TotalBytes.Add(uint64(pkt.PacketSize))

	// Determine packet direction relative to flow
	isForward := (pkt.SrcIP == fs.SrcIP && pkt.DstIP == fs.DstIP)

	if isForward {
		fs.ForwardPackets.Add(1)
		fs.ForwardBytes.Add(uint64(pkt.PacketSize))
	} else {
		fs.ReversePackets.Add(1)
		fs.ReverseBytes.Add(uint64(pkt.PacketSize))
	}

	// Update domain if found
	if pkt.Domain != "" && fs.Domain == "" {
		fs.Domain = pkt.Domain
		fs.DomainSource = pkt.DomainSource
	}

	// Update TCP state
	if fs.Protocol == ProtocolTCP && fs.TCPState != nil {
		fs.updateTCPState(pkt, isForward)
	}
}

// updateTCPState updates TCP flow state based on flags.
func (fs *FlowStatistics) updateTCPState(pkt *PacketMetadata, isForward bool) {
	if pkt.IsSYN && !pkt.IsACK {
		fs.TCPState.SYNSent = true
		fs.State = StateSYNSent
	} else if pkt.IsSYN && pkt.IsACK {
		fs.TCPState.SYNACKSeen = true
		fs.State = StateSYNReceived
	} else if pkt.IsACK && !pkt.IsSYN && !pkt.IsFIN && !pkt.IsRST {
		if fs.TCPState.SYNSent && fs.TCPState.SYNACKSeen && !fs.TCPState.Established {
			fs.TCPState.Established = true
			fs.TCPState.HandshakeTime = time.Now()
			fs.State = StateEstablished
		}
	}

	if pkt.IsFIN {
		if isForward {
			fs.TCPState.ClientFIN = true
		} else {
			fs.TCPState.ServerFIN = true
		}
		if fs.TCPState.ClosingTime.IsZero() {
			fs.TCPState.ClosingTime = time.Now()
		}
		fs.State = StateClosing
	}

	if pkt.IsRST {
		fs.TCPState.RSTSeen = true
		fs.State = StateClosed
		fs.IsActive = false
	}

	// Check for complete teardown
	if fs.TCPState.ClientFIN && fs.TCPState.ServerFIN {
		fs.State = StateClosed
		fs.IsActive = false
	}
}

// SetVerdict sets the firewall verdict for this flow.
func (fs *FlowStatistics) SetVerdict(verdict *VerdictResult) {
	fs.Verdict = verdict.Verdict
	fs.RuleID = verdict.RuleID
	fs.RuleName = verdict.RuleName
}

// Close marks the flow as closed.
func (fs *FlowStatistics) Close() {
	fs.IsActive = false
	fs.EndTime = time.Now()
	fs.Duration = fs.EndTime.Sub(fs.StartTime)
	if fs.State != StateClosed {
		fs.State = StateClosed
	}
}

// PrepareForJSON prepares the flow for JSON serialization.
func (fs *FlowStatistics) PrepareForJSON() {
	fs.TotalPacketsJSON = fs.TotalPackets.Load()
	fs.TotalBytesJSON = fs.TotalBytes.Load()
	fs.ForwardPacketsJSON = fs.ForwardPackets.Load()
	fs.ForwardBytesJSON = fs.ForwardBytes.Load()
	fs.ReversePacketsJSON = fs.ReversePackets.Load()
	fs.ReverseBytesJSON = fs.ReverseBytes.Load()
	fs.Duration = fs.EndTime.Sub(fs.StartTime)
	fs.DurationJSON = fs.Duration.String()
}

// GetDuration returns the flow duration.
func (fs *FlowStatistics) GetDuration() time.Duration {
	if fs.IsActive {
		return time.Since(fs.StartTime)
	}
	return fs.EndTime.Sub(fs.StartTime)
}

// GetPacketRate returns the packets per second for this flow.
func (fs *FlowStatistics) GetPacketRate() float64 {
	duration := fs.GetDuration().Seconds()
	if duration <= 0 {
		return 0
	}
	return float64(fs.TotalPackets.Load()) / duration
}

// GetByteRate returns the bytes per second for this flow.
func (fs *FlowStatistics) GetByteRate() float64 {
	duration := fs.GetDuration().Seconds()
	if duration <= 0 {
		return 0
	}
	return float64(fs.TotalBytes.Load()) / duration
}

// IsBidirectional returns true if traffic was seen in both directions.
func (fs *FlowStatistics) IsBidirectional() bool {
	return fs.ForwardPackets.Load() > 0 && fs.ReversePackets.Load() > 0
}

// IsExpired checks if the flow has been idle too long.
func (fs *FlowStatistics) IsExpired(timeout time.Duration) bool {
	return time.Since(fs.EndTime) > timeout
}

// ToLogEntry creates a log-friendly representation of the flow.
func (fs *FlowStatistics) ToLogEntry() map[string]interface{} {
	fs.PrepareForJSON()

	entry := map[string]interface{}{
		"flow_id":         fs.FlowID,
		"protocol":        fs.Protocol.String(),
		"src_ip":          fs.SrcIP,
		"src_port":        fs.SrcPort,
		"dst_ip":          fs.DstIP,
		"dst_port":        fs.DstPort,
		"direction":       fs.Direction.String(),
		"state":           fs.State.String(),
		"verdict":         fs.Verdict.String(),
		"total_packets":   fs.TotalPacketsJSON,
		"total_bytes":     fs.TotalBytesJSON,
		"forward_packets": fs.ForwardPacketsJSON,
		"reverse_packets": fs.ReversePacketsJSON,
		"start_time":      fs.StartTime.Format(time.RFC3339),
		"end_time":        fs.EndTime.Format(time.RFC3339),
		"duration_ms":     fs.GetDuration().Milliseconds(),
	}

	if fs.Domain != "" {
		entry["domain"] = fs.Domain
	}

	if fs.RuleName != "" {
		entry["rule_name"] = fs.RuleName
	}

	if fs.AdapterName != "" {
		entry["adapter"] = fs.AdapterName
	}

	return entry
}

// String returns a human-readable summary of the flow.
func (fs *FlowStatistics) String() string {
	return fmt.Sprintf("[%s] %s:%d → %s:%d | %s | %d pkts, %d bytes, %s",
		fs.Protocol, fs.SrcIP, fs.SrcPort, fs.DstIP, fs.DstPort,
		fs.Verdict, fs.TotalPackets.Load(), fs.TotalBytes.Load(),
		fs.GetDuration().Round(time.Millisecond))
}

// MarshalJSON implements json.Marshaler.
func (fs *FlowStatistics) MarshalJSON() ([]byte, error) {
	fs.PrepareForJSON()
	type Alias FlowStatistics
	return json.Marshal((*Alias)(fs))
}

// ============================================================================
// Flow Summary - Aggregated flow information for reporting
// ============================================================================

// FlowSummary provides summarized flow statistics for reporting.
type FlowSummary struct {
	// TotalFlows is the total number of flows tracked.
	TotalFlows int `json:"total_flows"`

	// ActiveFlows is the current number of active flows.
	ActiveFlows int `json:"active_flows"`

	// CompletedFlows is flows that have been closed.
	CompletedFlows int `json:"completed_flows"`

	// AllowedFlows is flows with ALLOW verdict.
	AllowedFlows int `json:"allowed_flows"`

	// BlockedFlows is flows with BLOCK/DROP verdict.
	BlockedFlows int `json:"blocked_flows"`

	// TotalPackets is total packets across all flows.
	TotalPackets uint64 `json:"total_packets"`

	// TotalBytes is total bytes across all flows.
	TotalBytes uint64 `json:"total_bytes"`

	// TopDomains lists most frequent domains.
	TopDomains []DomainCount `json:"top_domains,omitempty"`

	// TopRules lists most hit rules.
	TopRules []RuleCount `json:"top_rules,omitempty"`

	// ProtocolBreakdown shows traffic by protocol.
	ProtocolBreakdown map[string]int `json:"protocol_breakdown,omitempty"`
}

// DomainCount represents a domain and its occurrence count.
type DomainCount struct {
	Domain string `json:"domain"`
	Count  int    `json:"count"`
	Bytes  uint64 `json:"bytes"`
}

// RuleCount represents a rule and its hit count.
type RuleCount struct {
	RuleID   string `json:"rule_id"`
	RuleName string `json:"rule_name"`
	HitCount int    `json:"hit_count"`
}
