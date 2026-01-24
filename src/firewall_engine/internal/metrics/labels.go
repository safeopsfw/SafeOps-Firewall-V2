// Package metrics provides Prometheus metrics collection for the firewall engine.
package metrics

import (
	"errors"
	"fmt"
	"strings"
)

// ============================================================================
// Label Name Constants
// ============================================================================

const (
	// LabelAction is the packet action (allow, deny, drop).
	LabelAction = "action"

	// LabelProtocol is the network protocol (tcp, udp, icmp).
	LabelProtocol = "protocol"

	// LabelDirection is the traffic direction (inbound, outbound).
	LabelDirection = "direction"

	// LabelEngine is the processing engine (safeops, wfp, dual).
	LabelEngine = "engine"

	// LabelComponent is the system component (cache, rules, wfp, etc).
	LabelComponent = "component"

	// LabelLayer is the WFP layer (inbound, outbound, ale).
	LabelLayer = "layer"

	// LabelRule is the rule name for rule-specific metrics.
	LabelRule = "rule"

	// LabelErrorType is the error type for error metrics.
	LabelErrorType = "type"
)

// ============================================================================
// Label Value Constants - Action
// ============================================================================

const (
	// ActionAllow indicates traffic was allowed.
	ActionAllow = "allow"

	// ActionDeny indicates traffic was denied (logged).
	ActionDeny = "deny"

	// ActionDrop indicates traffic was silently dropped.
	ActionDrop = "drop"

	// ActionReject indicates traffic was rejected with response.
	ActionReject = "reject"

	// ActionRedirect indicates traffic was redirected.
	ActionRedirect = "redirect"
)

// ValidActions is the list of valid action label values.
var ValidActions = []string{ActionAllow, ActionDeny, ActionDrop, ActionReject, ActionRedirect}

// ============================================================================
// Label Value Constants - Protocol
// ============================================================================

const (
	// ProtocolTCP is the TCP protocol.
	ProtocolTCP = "tcp"

	// ProtocolUDP is the UDP protocol.
	ProtocolUDP = "udp"

	// ProtocolICMP is the ICMP protocol.
	ProtocolICMP = "icmp"

	// ProtocolOther is for other protocols.
	ProtocolOther = "other"
)

// ValidProtocols is the list of valid protocol label values.
var ValidProtocols = []string{ProtocolTCP, ProtocolUDP, ProtocolICMP, ProtocolOther}

// ============================================================================
// Label Value Constants - Direction
// ============================================================================

const (
	// DirectionInbound is incoming traffic.
	DirectionInbound = "inbound"

	// DirectionOutbound is outgoing traffic.
	DirectionOutbound = "outbound"
)

// ValidDirections is the list of valid direction label values.
var ValidDirections = []string{DirectionInbound, DirectionOutbound}

// ============================================================================
// Label Value Constants - Engine
// ============================================================================

const (
	// EngineSafeOps is the SafeOps kernel packet engine.
	EngineSafeOps = "safeops"

	// EngineWFP is the Windows Filtering Platform engine.
	EngineWFP = "wfp"

	// EngineDual is the dual-engine coordinator.
	EngineDual = "dual"

	// EngineCache is the verdict cache (for latency metrics).
	EngineCache = "cache"
)

// ValidEngines is the list of valid engine label values.
var ValidEngines = []string{EngineSafeOps, EngineWFP, EngineDual, EngineCache}

// ============================================================================
// Label Value Constants - Component
// ============================================================================

const (
	// ComponentCache is the verdict cache component.
	ComponentCache = "cache"

	// ComponentRules is the rule manager component.
	ComponentRules = "rules"

	// ComponentWFP is the WFP engine component.
	ComponentWFP = "wfp"

	// ComponentInspector is the packet inspector component.
	ComponentInspector = "inspector"

	// ComponentConnTracker is the connection tracker component.
	ComponentConnTracker = "conntracker"

	// ComponentTotal is for total/all components.
	ComponentTotal = "total"
)

// ValidComponents is the list of valid component label values.
var ValidComponents = []string{ComponentCache, ComponentRules, ComponentWFP, ComponentInspector, ComponentConnTracker, ComponentTotal}

// ============================================================================
// Label Value Constants - WFP Layer
// ============================================================================

const (
	// LayerInboundV4 is the WFP inbound IPv4 layer.
	LayerInboundV4 = "inbound_v4"

	// LayerOutboundV4 is the WFP outbound IPv4 layer.
	LayerOutboundV4 = "outbound_v4"

	// LayerALEAuthRecv is the WFP ALE auth receive layer.
	LayerALEAuthRecv = "ale_auth_recv"

	// LayerALEAuthConnect is the WFP ALE auth connect layer.
	LayerALEAuthConnect = "ale_auth_connect"
)

// ValidLayers is the list of valid WFP layer label values.
var ValidLayers = []string{LayerInboundV4, LayerOutboundV4, LayerALEAuthRecv, LayerALEAuthConnect}

// ============================================================================
// Label Value Constants - Error Types
// ============================================================================

const (
	// ErrorTypeTimeout is a timeout error.
	ErrorTypeTimeout = "timeout"

	// ErrorTypeConnection is a connection error.
	ErrorTypeConnection = "connection"

	// ErrorTypeParsing is a packet parsing error.
	ErrorTypeParsing = "parsing"

	// ErrorTypeRule is a rule evaluation error.
	ErrorTypeRule = "rule"

	// ErrorTypeWFP is a WFP error.
	ErrorTypeWFP = "wfp"

	// ErrorTypeInternal is an internal error.
	ErrorTypeInternal = "internal"
)

// ValidErrorTypes is the list of valid error type label values.
var ValidErrorTypes = []string{ErrorTypeTimeout, ErrorTypeConnection, ErrorTypeParsing, ErrorTypeRule, ErrorTypeWFP, ErrorTypeInternal}

// ============================================================================
// Label Builders
// ============================================================================

// Labels is a type alias for label key-value pairs.
type Labels map[string]string

// NewLabels creates an empty labels map.
func NewLabels() Labels {
	return make(Labels)
}

// WithAction adds the action label.
func (l Labels) WithAction(action string) Labels {
	l[LabelAction] = action
	return l
}

// WithProtocol adds the protocol label.
func (l Labels) WithProtocol(protocol string) Labels {
	l[LabelProtocol] = protocol
	return l
}

// WithDirection adds the direction label.
func (l Labels) WithDirection(direction string) Labels {
	l[LabelDirection] = direction
	return l
}

// WithEngine adds the engine label.
func (l Labels) WithEngine(engine string) Labels {
	l[LabelEngine] = engine
	return l
}

// WithComponent adds the component label.
func (l Labels) WithComponent(component string) Labels {
	l[LabelComponent] = component
	return l
}

// WithRule adds the rule label.
func (l Labels) WithRule(rule string) Labels {
	l[LabelRule] = rule
	return l
}

// WithLayer adds the layer label.
func (l Labels) WithLayer(layer string) Labels {
	l[LabelLayer] = layer
	return l
}

// WithErrorType adds the error type label.
func (l Labels) WithErrorType(errType string) Labels {
	l[LabelErrorType] = errType
	return l
}

// Values returns label values in the order of the given label names.
func (l Labels) Values(names ...string) []string {
	values := make([]string, len(names))
	for i, name := range names {
		values[i] = l[name]
	}
	return values
}

// ============================================================================
// Cardinality Validation
// ============================================================================

// Cardinality limits to prevent metric explosion.
const (
	// MaxLabelCardinality is the max number of unique values per label.
	MaxLabelCardinality = 100

	// MaxRuleLabels is the max number of unique rule labels.
	// Rules can have many unique names, so we limit this.
	MaxRuleLabels = 200

	// WarningCardinality triggers a warning when exceeded.
	WarningCardinality = 50
)

// Cardinality errors.
var (
	// ErrHighCardinality is returned when cardinality is too high.
	ErrHighCardinality = errors.New("high cardinality label detected")

	// ErrForbiddenLabel is returned for forbidden label values (IPs, UUIDs).
	ErrForbiddenLabel = errors.New("forbidden label value")
)

// CardinalityValidator tracks label cardinality to prevent metric explosion.
type CardinalityValidator struct {
	labelCounts map[string]map[string]struct{} // label -> value -> exists
	limits      map[string]int                 // label -> max values
}

// NewCardinalityValidator creates a new cardinality validator.
func NewCardinalityValidator() *CardinalityValidator {
	cv := &CardinalityValidator{
		labelCounts: make(map[string]map[string]struct{}),
		limits:      make(map[string]int),
	}

	// Set default limits
	cv.limits[LabelAction] = 10
	cv.limits[LabelProtocol] = 10
	cv.limits[LabelDirection] = 5
	cv.limits[LabelEngine] = 10
	cv.limits[LabelComponent] = 20
	cv.limits[LabelLayer] = 10
	cv.limits[LabelErrorType] = 20
	cv.limits[LabelRule] = MaxRuleLabels // Rules can have more values

	return cv
}

// ValidateLabels checks if the labels are within cardinality limits.
func (cv *CardinalityValidator) ValidateLabels(labels Labels) error {
	for name, value := range labels {
		if err := cv.ValidateLabel(name, value); err != nil {
			return err
		}
	}
	return nil
}

// ValidateLabel checks a single label value.
func (cv *CardinalityValidator) ValidateLabel(name, value string) error {
	// Check for forbidden patterns (high cardinality)
	if isForbiddenValue(value) {
		return fmt.Errorf("%w: %s=%s looks like IP/UUID", ErrForbiddenLabel, name, value)
	}

	// Get or create value set for this label
	if cv.labelCounts[name] == nil {
		cv.labelCounts[name] = make(map[string]struct{})
	}

	// Add value
	cv.labelCounts[name][value] = struct{}{}

	// Check limit
	limit := cv.limits[name]
	if limit == 0 {
		limit = MaxLabelCardinality
	}

	if len(cv.labelCounts[name]) > limit {
		return fmt.Errorf("%w: label %s has %d unique values (limit: %d)",
			ErrHighCardinality, name, len(cv.labelCounts[name]), limit)
	}

	return nil
}

// GetCardinality returns the current cardinality for a label.
func (cv *CardinalityValidator) GetCardinality(name string) int {
	if values := cv.labelCounts[name]; values != nil {
		return len(values)
	}
	return 0
}

// GetStats returns cardinality stats for all labels.
func (cv *CardinalityValidator) GetStats() map[string]int {
	stats := make(map[string]int)
	for name, values := range cv.labelCounts {
		stats[name] = len(values)
	}
	return stats
}

// isForbiddenValue checks if a value looks like high-cardinality data.
func isForbiddenValue(value string) bool {
	// Check for IP address patterns
	if looksLikeIP(value) {
		return true
	}

	// Check for UUID patterns
	if looksLikeUUID(value) {
		return true
	}

	return false
}

// looksLikeIP checks if value looks like an IP address.
func looksLikeIP(value string) bool {
	// Simple check: contains dots and digits
	parts := strings.Split(value, ".")
	if len(parts) == 4 {
		for _, p := range parts {
			if len(p) > 0 && p[0] >= '0' && p[0] <= '9' {
				return true
			}
		}
	}

	// Check for IPv6 (contains colons and hex)
	if strings.Count(value, ":") >= 2 {
		return true
	}

	return false
}

// looksLikeUUID checks if value looks like a UUID.
func looksLikeUUID(value string) bool {
	// UUID format: 8-4-4-4-12 (36 chars with dashes)
	if len(value) == 36 && strings.Count(value, "-") == 4 {
		return true
	}

	// UUID without dashes (32 hex chars)
	if len(value) == 32 && isHexString(value) {
		return true
	}

	return false
}

// isHexString checks if a string is all hex characters.
func isHexString(s string) bool {
	for _, c := range s {
		if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')) {
			return false
		}
	}
	return true
}

// ============================================================================
// Protocol Helpers
// ============================================================================

// ProtocolFromNumber converts protocol number to label value.
func ProtocolFromNumber(proto uint8) string {
	switch proto {
	case 6:
		return ProtocolTCP
	case 17:
		return ProtocolUDP
	case 1:
		return ProtocolICMP
	default:
		return ProtocolOther
	}
}

// DirectionFromBool converts bool to direction label.
func DirectionFromBool(inbound bool) string {
	if inbound {
		return DirectionInbound
	}
	return DirectionOutbound
}

// SanitizeRuleName sanitizes a rule name for use as a label value.
// Prometheus label values can contain any Unicode characters.
func SanitizeRuleName(name string) string {
	if len(name) > 64 {
		name = name[:64]
	}
	return name
}
