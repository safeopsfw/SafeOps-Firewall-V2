// Package wfp provides WFP layer management for filter placement.
// WFP layers determine WHERE in the network stack filters are applied.
package wfp

import (
	"firewall_engine/internal/wfp/bindings"
	"firewall_engine/pkg/models"
)

// ============================================================================
// Layer Types
// ============================================================================

// LayerType categorizes WFP layers by their position in the network stack.
type LayerType int

const (
	// LayerTypeIPPacket filters at the IP packet level (raw packets).
	LayerTypeIPPacket LayerType = iota
	// LayerTypeTransport filters at the transport level (TCP/UDP headers available).
	LayerTypeTransport
	// LayerTypeALEConnect filters outbound connection attempts (application-aware).
	LayerTypeALEConnect
	// LayerTypeALERecvAccept filters inbound connection acceptance (application-aware).
	LayerTypeALERecvAccept
	// LayerTypeALEFlow filters established flows (bidirectional).
	LayerTypeALEFlow
	// LayerTypeStream filters at the stream level (reassembled data).
	LayerTypeStream
)

// String returns the string representation of the layer type.
func (lt LayerType) String() string {
	switch lt {
	case LayerTypeIPPacket:
		return "IP_PACKET"
	case LayerTypeTransport:
		return "TRANSPORT"
	case LayerTypeALEConnect:
		return "ALE_CONNECT"
	case LayerTypeALERecvAccept:
		return "ALE_RECV_ACCEPT"
	case LayerTypeALEFlow:
		return "ALE_FLOW"
	case LayerTypeStream:
		return "STREAM"
	default:
		return "UNKNOWN"
	}
}

// ============================================================================
// Layer Information
// ============================================================================

// LayerInfo contains metadata about a WFP layer.
type LayerInfo struct {
	// GUID is the unique identifier for this layer.
	GUID bindings.GUID

	// Name is the human-readable name.
	Name string

	// Description describes what the layer does.
	Description string

	// Type categorizes the layer.
	Type LayerType

	// IsIPv6 indicates if this is an IPv6 layer.
	IsIPv6 bool

	// IsInbound indicates if this is for inbound traffic.
	IsInbound bool

	// IsApplicationAware indicates if this layer provides process info.
	IsApplicationAware bool
}

// ============================================================================
// Predefined Layers
// ============================================================================

// Layer GUID wrappers for clean API usage.
var (
	// IPv4 Packet Layers
	LayerInboundIPPacketV4 = &LayerInfo{
		GUID:        bindings.FWPM_LAYER_INBOUND_IPPACKET_V4,
		Name:        "FWPM_LAYER_INBOUND_IPPACKET_V4",
		Description: "IPv4 inbound packets at IP layer",
		Type:        LayerTypeIPPacket,
		IsIPv6:      false,
		IsInbound:   true,
	}

	LayerOutboundIPPacketV4 = &LayerInfo{
		GUID:        bindings.FWPM_LAYER_OUTBOUND_IPPACKET_V4,
		Name:        "FWPM_LAYER_OUTBOUND_IPPACKET_V4",
		Description: "IPv4 outbound packets at IP layer",
		Type:        LayerTypeIPPacket,
		IsIPv6:      false,
		IsInbound:   false,
	}

	// IPv6 Packet Layers
	LayerInboundIPPacketV6 = &LayerInfo{
		GUID:        bindings.FWPM_LAYER_INBOUND_IPPACKET_V6,
		Name:        "FWPM_LAYER_INBOUND_IPPACKET_V6",
		Description: "IPv6 inbound packets at IP layer",
		Type:        LayerTypeIPPacket,
		IsIPv6:      true,
		IsInbound:   true,
	}

	LayerOutboundIPPacketV6 = &LayerInfo{
		GUID:        bindings.FWPM_LAYER_OUTBOUND_IPPACKET_V6,
		Name:        "FWPM_LAYER_OUTBOUND_IPPACKET_V6",
		Description: "IPv6 outbound packets at IP layer",
		Type:        LayerTypeIPPacket,
		IsIPv6:      true,
		IsInbound:   false,
	}

	// IPv4 Transport Layers
	LayerInboundTransportV4 = &LayerInfo{
		GUID:        bindings.FWPM_LAYER_INBOUND_TRANSPORT_V4,
		Name:        "FWPM_LAYER_INBOUND_TRANSPORT_V4",
		Description: "IPv4 inbound at transport layer (TCP/UDP headers)",
		Type:        LayerTypeTransport,
		IsIPv6:      false,
		IsInbound:   true,
	}

	LayerOutboundTransportV4 = &LayerInfo{
		GUID:        bindings.FWPM_LAYER_OUTBOUND_TRANSPORT_V4,
		Name:        "FWPM_LAYER_OUTBOUND_TRANSPORT_V4",
		Description: "IPv4 outbound at transport layer (TCP/UDP headers)",
		Type:        LayerTypeTransport,
		IsIPv6:      false,
		IsInbound:   false,
	}

	// IPv6 Transport Layers
	LayerInboundTransportV6 = &LayerInfo{
		GUID:        bindings.FWPM_LAYER_INBOUND_TRANSPORT_V6,
		Name:        "FWPM_LAYER_INBOUND_TRANSPORT_V6",
		Description: "IPv6 inbound at transport layer (TCP/UDP headers)",
		Type:        LayerTypeTransport,
		IsIPv6:      true,
		IsInbound:   true,
	}

	LayerOutboundTransportV6 = &LayerInfo{
		GUID:        bindings.FWPM_LAYER_OUTBOUND_TRANSPORT_V6,
		Name:        "FWPM_LAYER_OUTBOUND_TRANSPORT_V6",
		Description: "IPv6 outbound at transport layer (TCP/UDP headers)",
		Type:        LayerTypeTransport,
		IsIPv6:      true,
		IsInbound:   false,
	}

	// ALE Connect Layers (Outbound Connection Attempts - Application Aware)
	LayerALEAuthConnectV4 = &LayerInfo{
		GUID:               bindings.FWPM_LAYER_ALE_AUTH_CONNECT_V4,
		Name:               "FWPM_LAYER_ALE_AUTH_CONNECT_V4",
		Description:        "IPv4 outbound connection authorization (application-aware)",
		Type:               LayerTypeALEConnect,
		IsIPv6:             false,
		IsInbound:          false,
		IsApplicationAware: true,
	}

	LayerALEAuthConnectV6 = &LayerInfo{
		GUID:               bindings.FWPM_LAYER_ALE_AUTH_CONNECT_V6,
		Name:               "FWPM_LAYER_ALE_AUTH_CONNECT_V6",
		Description:        "IPv6 outbound connection authorization (application-aware)",
		Type:               LayerTypeALEConnect,
		IsIPv6:             true,
		IsInbound:          false,
		IsApplicationAware: true,
	}

	// ALE Recv/Accept Layers (Inbound Connection Acceptance - Application Aware)
	LayerALEAuthRecvAcceptV4 = &LayerInfo{
		GUID:               bindings.FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V4,
		Name:               "FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V4",
		Description:        "IPv4 inbound connection acceptance (application-aware)",
		Type:               LayerTypeALERecvAccept,
		IsIPv6:             false,
		IsInbound:          true,
		IsApplicationAware: true,
	}

	LayerALEAuthRecvAcceptV6 = &LayerInfo{
		GUID:               bindings.FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V6,
		Name:               "FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V6",
		Description:        "IPv6 inbound connection acceptance (application-aware)",
		Type:               LayerTypeALERecvAccept,
		IsIPv6:             true,
		IsInbound:          true,
		IsApplicationAware: true,
	}

	// Stream Layers (Reassembled data)
	LayerStreamV4 = &LayerInfo{
		GUID:        bindings.FWPM_LAYER_STREAM_V4,
		Name:        "FWPM_LAYER_STREAM_V4",
		Description: "IPv4 TCP stream data (reassembled)",
		Type:        LayerTypeStream,
		IsIPv6:      false,
		IsInbound:   false, // bidirectional
	}

	LayerStreamV6 = &LayerInfo{
		GUID:        bindings.FWPM_LAYER_STREAM_V6,
		Name:        "FWPM_LAYER_STREAM_V6",
		Description: "IPv6 TCP stream data (reassembled)",
		Type:        LayerTypeStream,
		IsIPv6:      true,
		IsInbound:   false, // bidirectional
	}
)

// AllLayers returns a list of all available WFP layers.
func AllLayers() []*LayerInfo {
	return []*LayerInfo{
		// IP Packet layers
		LayerInboundIPPacketV4,
		LayerOutboundIPPacketV4,
		LayerInboundIPPacketV6,
		LayerOutboundIPPacketV6,
		// Transport layers
		LayerInboundTransportV4,
		LayerOutboundTransportV4,
		LayerInboundTransportV6,
		LayerOutboundTransportV6,
		// ALE layers
		LayerALEAuthConnectV4,
		LayerALEAuthConnectV6,
		LayerALEAuthRecvAcceptV4,
		LayerALEAuthRecvAcceptV6,
		// Stream layers
		LayerStreamV4,
		LayerStreamV6,
	}
}

// ============================================================================
// Layer Selection
// ============================================================================

// LayerSelector provides methods to select appropriate WFP layers for rules.
type LayerSelector struct{}

// NewLayerSelector creates a new layer selector.
func NewLayerSelector() *LayerSelector {
	return &LayerSelector{}
}

// GetLayerForRule returns the appropriate WFP layer(s) for a firewall rule.
// Returns multiple layers if the rule requires both inbound and outbound filtering.
func (s *LayerSelector) GetLayerForRule(rule *models.FirewallRule) []*LayerInfo {
	var layers []*LayerInfo

	// Determine if this is an application-aware rule
	// Note: Current FirewallRule doesn't have an Application field,
	// so we always use non-ALE layers for now. Application-aware filtering
	// will be added in Sub-Task 4.3.
	hasApplication := false

	// Determine address type (IPv4, IPv6, or both)
	isIPv6 := s.isIPv6Rule(rule)
	isIPv4 := s.isIPv4Rule(rule)

	// Determine direction
	switch rule.Direction {
	case models.DirectionInbound:
		if hasApplication {
			// Use ALE layer for application-aware filtering
			if isIPv4 {
				layers = append(layers, LayerALEAuthRecvAcceptV4)
			}
			if isIPv6 {
				layers = append(layers, LayerALEAuthRecvAcceptV6)
			}
		} else {
			// Use transport layer for port-based filtering
			if isIPv4 {
				layers = append(layers, LayerInboundTransportV4)
			}
			if isIPv6 {
				layers = append(layers, LayerInboundTransportV6)
			}
		}

	case models.DirectionOutbound:
		if hasApplication {
			// Use ALE layer for application-aware filtering
			if isIPv4 {
				layers = append(layers, LayerALEAuthConnectV4)
			}
			if isIPv6 {
				layers = append(layers, LayerALEAuthConnectV6)
			}
		} else {
			// Use transport layer for port-based filtering
			if isIPv4 {
				layers = append(layers, LayerOutboundTransportV4)
			}
			if isIPv6 {
				layers = append(layers, LayerOutboundTransportV6)
			}
		}

	case models.DirectionAny, models.DirectionForward:
		// Install filters in both directions
		if hasApplication {
			if isIPv4 {
				layers = append(layers, LayerALEAuthConnectV4, LayerALEAuthRecvAcceptV4)
			}
			if isIPv6 {
				layers = append(layers, LayerALEAuthConnectV6, LayerALEAuthRecvAcceptV6)
			}
		} else {
			if isIPv4 {
				layers = append(layers, LayerInboundTransportV4, LayerOutboundTransportV4)
			}
			if isIPv6 {
				layers = append(layers, LayerInboundTransportV6, LayerOutboundTransportV6)
			}
		}

	default:
		// Default to outbound transport layers
		if isIPv4 {
			layers = append(layers, LayerOutboundTransportV4)
		}
		if isIPv6 {
			layers = append(layers, LayerOutboundTransportV6)
		}
	}

	return layers
}

// GetIPPacketLayers returns IP packet layer(s) for basic IP filtering.
func (s *LayerSelector) GetIPPacketLayers(direction models.Direction, ipv6 bool) []*LayerInfo {
	var layers []*LayerInfo

	switch direction {
	case models.DirectionInbound:
		if ipv6 {
			layers = append(layers, LayerInboundIPPacketV6)
		} else {
			layers = append(layers, LayerInboundIPPacketV4)
		}
	case models.DirectionOutbound:
		if ipv6 {
			layers = append(layers, LayerOutboundIPPacketV6)
		} else {
			layers = append(layers, LayerOutboundIPPacketV4)
		}
	case models.DirectionAny, models.DirectionForward:
		if ipv6 {
			layers = append(layers, LayerInboundIPPacketV6, LayerOutboundIPPacketV6)
		} else {
			layers = append(layers, LayerInboundIPPacketV4, LayerOutboundIPPacketV4)
		}
	}

	return layers
}

// GetTransportLayers returns transport layer(s) for port-based filtering.
func (s *LayerSelector) GetTransportLayers(direction models.Direction, ipv6 bool) []*LayerInfo {
	var layers []*LayerInfo

	switch direction {
	case models.DirectionInbound:
		if ipv6 {
			layers = append(layers, LayerInboundTransportV6)
		} else {
			layers = append(layers, LayerInboundTransportV4)
		}
	case models.DirectionOutbound:
		if ipv6 {
			layers = append(layers, LayerOutboundTransportV6)
		} else {
			layers = append(layers, LayerOutboundTransportV4)
		}
	case models.DirectionAny, models.DirectionForward:
		if ipv6 {
			layers = append(layers, LayerInboundTransportV6, LayerOutboundTransportV6)
		} else {
			layers = append(layers, LayerInboundTransportV4, LayerOutboundTransportV4)
		}
	}

	return layers
}

// GetALELayers returns ALE layer(s) for application-aware filtering.
func (s *LayerSelector) GetALELayers(direction models.Direction, ipv6 bool) []*LayerInfo {
	var layers []*LayerInfo

	switch direction {
	case models.DirectionInbound:
		if ipv6 {
			layers = append(layers, LayerALEAuthRecvAcceptV6)
		} else {
			layers = append(layers, LayerALEAuthRecvAcceptV4)
		}
	case models.DirectionOutbound:
		if ipv6 {
			layers = append(layers, LayerALEAuthConnectV6)
		} else {
			layers = append(layers, LayerALEAuthConnectV4)
		}
	case models.DirectionAny, models.DirectionForward:
		if ipv6 {
			layers = append(layers, LayerALEAuthConnectV6, LayerALEAuthRecvAcceptV6)
		} else {
			layers = append(layers, LayerALEAuthConnectV4, LayerALEAuthRecvAcceptV4)
		}
	}

	return layers
}

// isIPv6Rule checks if a rule targets IPv6 addresses.
func (s *LayerSelector) isIPv6Rule(rule *models.FirewallRule) bool {
	// Check source address
	if isIPv6Address(rule.SourceAddress) {
		return true
	}
	// Check destination address
	if isIPv6Address(rule.DestinationAddress) {
		return true
	}
	return false
}

// isIPv4Rule checks if a rule targets IPv4 addresses (or is address-agnostic).
func (s *LayerSelector) isIPv4Rule(rule *models.FirewallRule) bool {
	// If no addresses specified, default to IPv4
	if rule.SourceAddress == "" && rule.DestinationAddress == "" {
		return true
	}

	// Check source address
	if isIPv4Address(rule.SourceAddress) {
		return true
	}
	// Check destination address
	if isIPv4Address(rule.DestinationAddress) {
		return true
	}

	// If somehow no match, default to IPv4
	return true
}

// ============================================================================
// Helper Functions
// ============================================================================

// isIPv6Address checks if a string represents an IPv6 address or CIDR.
func isIPv6Address(addr string) bool {
	if addr == "" || addr == "any" || addr == "*" {
		return false
	}
	// Simple check: IPv6 contains colons
	for _, c := range addr {
		if c == ':' {
			return true
		}
	}
	return false
}

// isIPv4Address checks if a string represents an IPv4 address or CIDR.
func isIPv4Address(addr string) bool {
	if addr == "" || addr == "any" || addr == "*" {
		return true // Default to IPv4 for any/empty
	}
	// Simple check: IPv4 contains dots and no colons
	hasDot := false
	for _, c := range addr {
		if c == ':' {
			return false // IPv6
		}
		if c == '.' {
			hasDot = true
		}
	}
	return hasDot
}

// GetLayerByGUID returns the LayerInfo for a given GUID, or nil if not found.
func GetLayerByGUID(guid bindings.GUID) *LayerInfo {
	for _, layer := range AllLayers() {
		if layer.GUID == guid {
			return layer
		}
	}
	return nil
}

// GetLayersByType returns all layers of a specific type.
func GetLayersByType(layerType LayerType) []*LayerInfo {
	var result []*LayerInfo
	for _, layer := range AllLayers() {
		if layer.Type == layerType {
			result = append(result, layer)
		}
	}
	return result
}

// GetApplicationAwareLayers returns all layers that support application identification.
func GetApplicationAwareLayers() []*LayerInfo {
	var result []*LayerInfo
	for _, layer := range AllLayers() {
		if layer.IsApplicationAware {
			result = append(result, layer)
		}
	}
	return result
}
