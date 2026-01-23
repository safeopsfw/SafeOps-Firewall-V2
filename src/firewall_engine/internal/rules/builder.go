// Package rules provides rule matching and management for the firewall engine.
package rules

import (
	"firewall_engine/pkg/models"
)

// ============================================================================
// Rule Builder - Fluent Interface for Creating Rules
// ============================================================================

// Builder provides a fluent interface for constructing firewall rules.
type Builder struct {
	rule *models.FirewallRule
}

// NewBuilder creates a new rule builder.
func NewBuilder() *Builder {
	return &Builder{
		rule: &models.FirewallRule{
			Enabled:   true,
			Direction: models.DirectionAny,
			Protocol:  models.ProtocolAny,
			Priority:  100,
		},
	}
}

// NewBuilderFrom creates a builder from an existing rule (for copying).
func NewBuilderFrom(rule *models.FirewallRule) *Builder {
	return &Builder{
		rule: rule.Clone(),
	}
}

// ============================================================================
// Basic Properties
// ============================================================================

// ID sets the rule ID.
func (b *Builder) ID(id int) *Builder {
	b.rule.RuleID = id
	return b
}

// Name sets the rule name.
func (b *Builder) Name(name string) *Builder {
	b.rule.Name = name
	return b
}

// Description sets the rule description.
func (b *Builder) Description(desc string) *Builder {
	b.rule.Description = desc
	return b
}

// Priority sets the rule priority (lower = higher priority).
func (b *Builder) Priority(priority int) *Builder {
	b.rule.Priority = priority
	return b
}

// Group sets the rule group.
func (b *Builder) Group(groupName string) *Builder {
	b.rule.GroupName = groupName
	return b
}

// Enabled sets whether the rule is enabled.
func (b *Builder) Enabled(enabled bool) *Builder {
	b.rule.Enabled = enabled
	return b
}

// ============================================================================
// Direction and Protocol
// ============================================================================

// Direction sets the traffic direction.
func (b *Builder) Direction(dir models.Direction) *Builder {
	b.rule.Direction = dir
	return b
}

// Inbound sets direction to inbound.
func (b *Builder) Inbound() *Builder {
	b.rule.Direction = models.DirectionInbound
	return b
}

// Outbound sets direction to outbound.
func (b *Builder) Outbound() *Builder {
	b.rule.Direction = models.DirectionOutbound
	return b
}

// BothDirections sets direction to any (matches both).
func (b *Builder) BothDirections() *Builder {
	b.rule.Direction = models.DirectionAny
	return b
}

// Protocol sets the protocol.
func (b *Builder) Protocol(proto models.Protocol) *Builder {
	b.rule.Protocol = proto
	return b
}

// TCP sets protocol to TCP.
func (b *Builder) TCP() *Builder {
	b.rule.Protocol = models.ProtocolTCP
	return b
}

// UDP sets protocol to UDP.
func (b *Builder) UDP() *Builder {
	b.rule.Protocol = models.ProtocolUDP
	return b
}

// ICMP sets protocol to ICMP.
func (b *Builder) ICMP() *Builder {
	b.rule.Protocol = models.ProtocolICMP
	return b
}

// AnyProtocol sets protocol to ANY.
func (b *Builder) AnyProtocol() *Builder {
	b.rule.Protocol = models.ProtocolAny
	return b
}

// ============================================================================
// Address Matching
// ============================================================================

// SourceAddress sets the source address specification.
func (b *Builder) SourceAddress(addr string) *Builder {
	b.rule.SourceAddress = addr
	return b
}

// DestinationAddress sets the destination address specification.
func (b *Builder) DestinationAddress(addr string) *Builder {
	b.rule.DestinationAddress = addr
	return b
}

// FromAddress is an alias for SourceAddress.
func (b *Builder) FromAddress(addr string) *Builder {
	return b.SourceAddress(addr)
}

// ToAddress is an alias for DestinationAddress.
func (b *Builder) ToAddress(addr string) *Builder {
	return b.DestinationAddress(addr)
}

// FromAny sets source address to match any.
func (b *Builder) FromAny() *Builder {
	b.rule.SourceAddress = "ANY"
	return b
}

// ToAny sets destination address to match any.
func (b *Builder) ToAny() *Builder {
	b.rule.DestinationAddress = "ANY"
	return b
}

// ============================================================================
// Port Matching
// ============================================================================

// SourcePort sets the source port(s).
func (b *Builder) SourcePort(ports ...int) *Builder {
	b.rule.SourcePort = ports
	return b
}

// DestinationPort sets the destination port(s).
func (b *Builder) DestinationPort(ports ...int) *Builder {
	b.rule.DestinationPort = ports
	return b
}

// SourcePortObject sets the source port object reference.
func (b *Builder) SourcePortObject(objName string) *Builder {
	b.rule.SourcePortObject = objName
	return b
}

// DestinationPortObject sets the destination port object reference.
func (b *Builder) DestinationPortObject(objName string) *Builder {
	b.rule.DestinationPortObject = objName
	return b
}

// Port is a shorthand for DestinationPort.
func (b *Builder) Port(ports ...int) *Builder {
	return b.DestinationPort(ports...)
}

// ============================================================================
// Domain Matching
// ============================================================================

// Domain sets the domain pattern.
func (b *Builder) Domain(domain string) *Builder {
	b.rule.Domain = domain
	return b
}

// DomainObject sets the domain object reference.
func (b *Builder) DomainObject(objName string) *Builder {
	b.rule.DomainObject = objName
	return b
}

// ============================================================================
// State and Interface
// ============================================================================

// State sets the connection state requirement.
func (b *Builder) State(state string) *Builder {
	b.rule.State = state
	return b
}

// NewState sets state to NEW.
func (b *Builder) NewState() *Builder {
	b.rule.State = "NEW"
	return b
}

// EstablishedState sets state to ESTABLISHED.
func (b *Builder) EstablishedState() *Builder {
	b.rule.State = "ESTABLISHED"
	return b
}

// Interface sets the network interface.
func (b *Builder) Interface(iface string) *Builder {
	b.rule.Interface = iface
	return b
}

// ============================================================================
// Action
// ============================================================================

// Action sets the rule action.
func (b *Builder) Action(action models.Verdict) *Builder {
	b.rule.Action = action
	return b
}

// Allow sets the action to ALLOW.
func (b *Builder) Allow() *Builder {
	b.rule.Action = models.VerdictAllow
	return b
}

// Deny sets the action to BLOCK (DENY is alias for BLOCK).
func (b *Builder) Deny() *Builder {
	b.rule.Action = models.VerdictBlock
	return b
}

// Drop sets the action to DROP.
func (b *Builder) Drop() *Builder {
	b.rule.Action = models.VerdictDrop
	return b
}

// Log sets the action to LOG (log and accept).
func (b *Builder) Log() *Builder {
	b.rule.Action = models.VerdictLog
	return b
}

// Redirect sets the action to REDIRECT.
func (b *Builder) Redirect(ip string, port int) *Builder {
	b.rule.Action = models.VerdictRedirect
	b.rule.RedirectIP = ip
	b.rule.RedirectPort = uint16(port)
	return b
}

// ============================================================================
// Logging
// ============================================================================

// WithLogging enables logging for this rule.
func (b *Builder) WithLogging() *Builder {
	b.rule.LogEnabled = true
	return b
}

// LogPrefix sets the log prefix (stored in description for now).
func (b *Builder) LogPrefix(prefix string) *Builder {
	// LogPrefix not in model, using description
	b.rule.Description = "[LOG: " + prefix + "] " + b.rule.Description
	return b
}

// ============================================================================
// Build
// ============================================================================

// Build finalizes and returns the rule.
func (b *Builder) Build() *models.FirewallRule {
	return b.rule
}

// BuildWithID builds the rule with the specified ID.
func (b *Builder) BuildWithID(id int) *models.FirewallRule {
	b.rule.RuleID = id
	return b.rule
}

// ============================================================================
// Convenience Functions
// ============================================================================

// AllowTCPPort creates a rule to allow TCP traffic on a port.
func AllowTCPPort(id int, name string, port int) *models.FirewallRule {
	return NewBuilder().
		ID(id).
		Name(name).
		TCP().
		DestinationPort(port).
		Allow().
		Build()
}

// BlockIP creates a rule to block an IP address.
func BlockIP(id int, name string, ip string) *models.FirewallRule {
	return NewBuilder().
		ID(id).
		Name(name).
		SourceAddress(ip).
		Drop().
		Build()
}

// AllowDomain creates a rule to allow a domain pattern.
func AllowDomain(id int, name string, domain string) *models.FirewallRule {
	return NewBuilder().
		ID(id).
		Name(name).
		Domain(domain).
		Allow().
		Build()
}

// BlockDomain creates a rule to block a domain pattern.
func BlockDomain(id int, name string, domain string) *models.FirewallRule {
	return NewBuilder().
		ID(id).
		Name(name).
		Domain(domain).
		Drop().
		Build()
}
