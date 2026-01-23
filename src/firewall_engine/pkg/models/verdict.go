// Package models defines all core data structures used throughout the firewall engine.
// These structures provide type safety, JSON/protobuf serialization support, and
// consistent interfaces across all components.
package models

import (
	"encoding/json"
	"fmt"
	"strings"

	pb "safeops-engine/pkg/grpc/pb"
)

// ============================================================================
// Verdict Types - Firewall Decision Actions
// ============================================================================

// Verdict represents the action to take on a packet after rule evaluation.
// It aligns with the proto VerdictType but extends it with additional actions
// needed for comprehensive firewall functionality.
type Verdict int32

const (
	// VerdictAllow forwards the packet normally through the network stack.
	// This is the default action for traffic that matches an allow rule
	// or when no rule matches and the default policy is ALLOW.
	VerdictAllow Verdict = 0

	// VerdictDrop silently discards the packet without sending any response.
	// The sender will experience a timeout. Use for security-sensitive blocks
	// where revealing firewall presence is undesirable.
	VerdictDrop Verdict = 1

	// VerdictBlock drops the packet and sends a rejection response:
	// - TCP: Sends TCP RST to immediately close the connection
	// - UDP: Sends ICMP port unreachable
	// - ICMP: Drops without response
	// Use when you want immediate feedback to the sender.
	VerdictBlock Verdict = 2

	// VerdictRedirect redirects the traffic to a different destination.
	// Primarily used for:
	// - DNS sinkholing (redirect to captive portal)
	// - Transparent proxy redirection
	// - Load balancing
	VerdictRedirect Verdict = 3

	// VerdictReject is similar to Block but specifically sends ICMP
	// administratively prohibited message, indicating policy-based rejection.
	VerdictReject Verdict = 4

	// VerdictLog allows the packet but marks it for detailed logging.
	// Useful for debugging and traffic analysis without blocking.
	VerdictLog Verdict = 5

	// VerdictQueue sends the packet to a user-space queue for further
	// inspection by IDS/IPS or DPI engines. Used for slow-lane processing.
	VerdictQueue Verdict = 6

	// VerdictMark marks the packet for QoS or routing purposes without
	// affecting forwarding. Can be combined with other verdicts.
	VerdictMark Verdict = 7
)

// verdictNames maps verdict values to human-readable strings.
var verdictNames = map[Verdict]string{
	VerdictAllow:    "ALLOW",
	VerdictDrop:     "DROP",
	VerdictBlock:    "BLOCK",
	VerdictRedirect: "REDIRECT",
	VerdictReject:   "REJECT",
	VerdictLog:      "LOG",
	VerdictQueue:    "QUEUE",
	VerdictMark:     "MARK",
}

// verdictValues maps string names to verdict values for parsing.
var verdictValues = map[string]Verdict{
	"ALLOW":    VerdictAllow,
	"DROP":     VerdictDrop,
	"BLOCK":    VerdictBlock,
	"REDIRECT": VerdictRedirect,
	"REJECT":   VerdictReject,
	"LOG":      VerdictLog,
	"QUEUE":    VerdictQueue,
	"MARK":     VerdictMark,
	// Aliases for compatibility
	"DENY":   VerdictBlock, // DENY is commonly used synonym for BLOCK
	"ACCEPT": VerdictAllow, // ACCEPT is iptables terminology
	"PASS":   VerdictAllow, // PASS is pf terminology
}

// String returns the human-readable name of the verdict.
// Implements fmt.Stringer interface.
func (v Verdict) String() string {
	if name, ok := verdictNames[v]; ok {
		return name
	}
	return fmt.Sprintf("UNKNOWN(%d)", v)
}

// IsValid checks if the verdict is a recognized value.
func (v Verdict) IsValid() bool {
	_, ok := verdictNames[v]
	return ok
}

// IsBlocking returns true if this verdict prevents packet forwarding.
func (v Verdict) IsBlocking() bool {
	switch v {
	case VerdictDrop, VerdictBlock, VerdictReject:
		return true
	default:
		return false
	}
}

// IsAllowing returns true if this verdict permits packet forwarding.
func (v Verdict) IsAllowing() bool {
	switch v {
	case VerdictAllow, VerdictLog:
		return true
	default:
		return false
	}
}

// RequiresResponse returns true if this verdict needs to send a response packet.
func (v Verdict) RequiresResponse() bool {
	switch v {
	case VerdictBlock, VerdictReject:
		return true
	default:
		return false
	}
}

// VerdictFromString parses a string into a Verdict.
// The parsing is case-insensitive.
// Returns an error if the string doesn't match any known verdict.
func VerdictFromString(s string) (Verdict, error) {
	upper := strings.ToUpper(strings.TrimSpace(s))
	if v, ok := verdictValues[upper]; ok {
		return v, nil
	}
	return VerdictAllow, fmt.Errorf("unknown verdict: %q", s)
}

// MustVerdictFromString parses a string into a Verdict, panicking on error.
// Use only in initialization code or tests.
func MustVerdictFromString(s string) Verdict {
	v, err := VerdictFromString(s)
	if err != nil {
		panic(err)
	}
	return v
}

// ToProto converts the Verdict to the protobuf VerdictType.
// This is used when sending verdicts back to SafeOps Engine via gRPC.
func (v Verdict) ToProto() pb.VerdictType {
	switch v {
	case VerdictAllow, VerdictLog:
		return pb.VerdictType_ALLOW
	case VerdictDrop:
		return pb.VerdictType_DROP
	case VerdictBlock, VerdictReject:
		return pb.VerdictType_BLOCK
	case VerdictRedirect:
		return pb.VerdictType_REDIRECT
	default:
		// Default to DROP for safety
		return pb.VerdictType_DROP
	}
}

// VerdictFromProto converts a protobuf VerdictType to the internal Verdict.
func VerdictFromProto(v pb.VerdictType) Verdict {
	switch v {
	case pb.VerdictType_ALLOW:
		return VerdictAllow
	case pb.VerdictType_DROP:
		return VerdictDrop
	case pb.VerdictType_BLOCK:
		return VerdictBlock
	case pb.VerdictType_REDIRECT:
		return VerdictRedirect
	default:
		return VerdictAllow
	}
}

// MarshalJSON implements json.Marshaler for JSON serialization.
func (v Verdict) MarshalJSON() ([]byte, error) {
	return json.Marshal(v.String())
}

// UnmarshalJSON implements json.Unmarshaler for JSON deserialization.
func (v *Verdict) UnmarshalJSON(data []byte) error {
	var s string
	if err := json.Unmarshal(data, &s); err != nil {
		// Try unmarshaling as integer
		var i int32
		if err2 := json.Unmarshal(data, &i); err2 != nil {
			return fmt.Errorf("verdict must be string or integer: %w", err)
		}
		*v = Verdict(i)
		return nil
	}
	parsed, err := VerdictFromString(s)
	if err != nil {
		return err
	}
	*v = parsed
	return nil
}

// ============================================================================
// VerdictResult - Complete verdict with metadata
// ============================================================================

// VerdictResult contains the complete result of a rule evaluation,
// including the verdict, the matched rule, and additional metadata
// for logging, caching, and enforcement.
type VerdictResult struct {
	// Verdict is the action to take on the packet.
	Verdict Verdict `json:"verdict"`

	// RuleID is the UUID of the rule that matched (empty if default policy).
	RuleID string `json:"rule_id,omitempty"`

	// RuleName is the human-readable name of the matched rule.
	RuleName string `json:"rule_name,omitempty"`

	// Reason provides human-readable explanation for the verdict.
	// Examples: "Blocked by rule: Block_Facebook", "Default policy: DENY"
	Reason string `json:"reason"`

	// LogEnabled indicates whether this match should be logged.
	LogEnabled bool `json:"log_enabled"`

	// CacheTTL is how long (in seconds) this verdict can be cached.
	// 0 means apply once, don't cache.
	CacheTTL uint32 `json:"cache_ttl"`

	// CacheKey is the key for caching this verdict decision.
	// Format: "src_ip:dst_ip:proto:port"
	CacheKey string `json:"cache_key,omitempty"`

	// RedirectIP is the destination IP for REDIRECT verdicts.
	RedirectIP string `json:"redirect_ip,omitempty"`

	// RedirectPort is the destination port for REDIRECT verdicts.
	RedirectPort uint16 `json:"redirect_port,omitempty"`

	// MatchDuration is how long the rule matching took (nanoseconds).
	// Used for performance monitoring.
	MatchDuration int64 `json:"match_duration_ns,omitempty"`

	// FastLane indicates if this verdict came from cache (fast lane)
	// or required full rule evaluation (slow lane).
	FastLane bool `json:"fast_lane"`

	// Priority is the priority of the matched rule (lower = higher priority).
	Priority int `json:"priority,omitempty"`

	// GroupName is the name of the rule group that contained the matched rule.
	GroupName string `json:"group_name,omitempty"`
}

// NewAllowVerdict creates a VerdictResult for allowing traffic.
func NewAllowVerdict(reason string) *VerdictResult {
	return &VerdictResult{
		Verdict: VerdictAllow,
		Reason:  reason,
	}
}

// NewDenyVerdict creates a VerdictResult for blocking traffic with response.
func NewDenyVerdict(reason string) *VerdictResult {
	return &VerdictResult{
		Verdict: VerdictBlock,
		Reason:  reason,
	}
}

// NewDropVerdict creates a VerdictResult for silently dropping traffic.
func NewDropVerdict(reason string) *VerdictResult {
	return &VerdictResult{
		Verdict: VerdictDrop,
		Reason:  reason,
	}
}

// NewRedirectVerdict creates a VerdictResult for redirecting traffic.
func NewRedirectVerdict(reason, redirectIP string, redirectPort uint16) *VerdictResult {
	return &VerdictResult{
		Verdict:      VerdictRedirect,
		Reason:       reason,
		RedirectIP:   redirectIP,
		RedirectPort: redirectPort,
	}
}

// NewDefaultPolicyVerdict creates a VerdictResult for the default policy.
func NewDefaultPolicyVerdict(verdict Verdict) *VerdictResult {
	return &VerdictResult{
		Verdict:  verdict,
		RuleName: "Default Policy",
		Reason:   fmt.Sprintf("No rule matched, applying default policy: %s", verdict),
	}
}

// WithCaching adds caching parameters to the verdict.
func (vr *VerdictResult) WithCaching(cacheKey string, ttlSeconds uint32) *VerdictResult {
	vr.CacheKey = cacheKey
	vr.CacheTTL = ttlSeconds
	return vr
}

// WithRule adds rule information to the verdict.
func (vr *VerdictResult) WithRule(ruleID, ruleName, groupName string, priority int) *VerdictResult {
	vr.RuleID = ruleID
	vr.RuleName = ruleName
	vr.GroupName = groupName
	vr.Priority = priority
	return vr
}

// WithLogging enables logging for this verdict.
func (vr *VerdictResult) WithLogging() *VerdictResult {
	vr.LogEnabled = true
	return vr
}

// WithMatchDuration records how long rule matching took.
func (vr *VerdictResult) WithMatchDuration(duration int64) *VerdictResult {
	vr.MatchDuration = duration
	return vr
}

// MarkFastLane marks this verdict as coming from cache.
func (vr *VerdictResult) MarkFastLane() *VerdictResult {
	vr.FastLane = true
	return vr
}

// String returns a human-readable representation of the verdict result.
func (vr *VerdictResult) String() string {
	if vr.RuleName != "" {
		return fmt.Sprintf("%s (Rule: %s)", vr.Verdict, vr.RuleName)
	}
	return vr.Verdict.String()
}

// ToProtoRequest converts the VerdictResult to a proto VerdictRequest
// for sending back to SafeOps Engine.
func (vr *VerdictResult) ToProtoRequest(packetID uint64) *pb.VerdictRequest {
	return &pb.VerdictRequest{
		PacketId:   packetID,
		Verdict:    vr.Verdict.ToProto(),
		Reason:     vr.Reason,
		RuleId:     vr.RuleID,
		TtlSeconds: vr.CacheTTL,
		CacheKey:   vr.CacheKey,
	}
}
