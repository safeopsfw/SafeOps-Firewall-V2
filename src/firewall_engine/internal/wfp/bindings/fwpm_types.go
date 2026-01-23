// Package bindings provides low-level Go bindings to Windows Filtering Platform (WFP) APIs.
package bindings

import (
	"fmt"
	"net"
	"time"
)

// ============================================================================
// FWPM_DISPLAY_DATA0 - Human-readable name and description
// ============================================================================

// FWPM_DISPLAY_DATA0 contains human-readable display information.
// Used by sessions, providers, sublayers, filters, and other WFP objects.
type FWPM_DISPLAY_DATA0 struct {
	Name        string `json:"name,omitempty" toml:"name,omitempty"`
	Description string `json:"description,omitempty" toml:"description,omitempty"`
}

// NewDisplayData creates a new display data with name and description.
func NewDisplayData(name, description string) FWPM_DISPLAY_DATA0 {
	return FWPM_DISPLAY_DATA0{
		Name:        name,
		Description: description,
	}
}

// IsEmpty returns true if both name and description are empty.
func (d FWPM_DISPLAY_DATA0) IsEmpty() bool {
	return d.Name == "" && d.Description == ""
}

// String returns a string representation.
func (d FWPM_DISPLAY_DATA0) String() string {
	if d.Description != "" {
		return fmt.Sprintf("%s: %s", d.Name, d.Description)
	}
	return d.Name
}

// ============================================================================
// FWPM_SESSION0 - WFP Session Configuration
// ============================================================================

// FWPM_SESSION0 contains configuration for a WFP engine session.
// A session is required before any filter operations can be performed.
type FWPM_SESSION0 struct {
	// SessionKey is the unique identifier for this session.
	// If empty, Windows generates one automatically.
	SessionKey GUID `json:"session_key,omitempty"`

	// DisplayData contains the session name and description.
	DisplayData FWPM_DISPLAY_DATA0 `json:"display_data,omitempty"`

	// Flags control session behavior.
	// FWPM_SESSION_FLAG_DYNAMIC: Filters are deleted when session closes.
	Flags FWPM_SESSION_FLAG `json:"flags,omitempty"`

	// TransactionWaitTimeoutMs is the maximum time to wait for transactions.
	// 0 = infinite wait.
	TransactionWaitTimeoutMs uint32 `json:"txn_wait_timeout_ms,omitempty"`

	// ProcessID is the ID of the process that created this session.
	// Set automatically by Windows.
	ProcessID uint32 `json:"process_id,omitempty"`

	// SID is the Security Identifier of the user who created this session.
	// Set automatically by Windows.
	SID []byte `json:"-"`

	// Username is the name of the user who created the session.
	// Set automatically by Windows (for display purposes).
	Username string `json:"username,omitempty"`

	// KernelMode indicates if this is a kernel-mode session.
	// Always false for user-mode applications.
	KernelMode bool `json:"kernel_mode,omitempty"`
}

// NewSession creates a new session configuration with sensible defaults.
func NewSession(name, description string) *FWPM_SESSION0 {
	return &FWPM_SESSION0{
		DisplayData:              NewDisplayData(name, description),
		Flags:                    FWPM_SESSION_FLAG_DYNAMIC, // Auto-cleanup on close
		TransactionWaitTimeoutMs: SESSION_TXN_WAIT_TIMEOUT_DEFAULT,
	}
}

// NewDynamicSession creates a session where all filters are deleted on close.
func NewDynamicSession() *FWPM_SESSION0 {
	return NewSession("SafeOps Firewall", "SafeOps Firewall Engine dynamic session")
}

// NewPersistentSession creates a session where filters can be persistent.
func NewPersistentSession() *FWPM_SESSION0 {
	s := NewSession("SafeOps Firewall", "SafeOps Firewall Engine persistent session")
	s.Flags = 0 // No DYNAMIC flag = filters can be persistent
	return s
}

// IsDynamic returns true if all filters will be deleted when session closes.
func (s *FWPM_SESSION0) IsDynamic() bool {
	return s.Flags&FWPM_SESSION_FLAG_DYNAMIC != 0
}

// String returns a string representation.
func (s *FWPM_SESSION0) String() string {
	if s == nil {
		return "<nil session>"
	}
	return fmt.Sprintf("Session[%s, flags=0x%X, pid=%d]",
		s.DisplayData.Name, s.Flags, s.ProcessID)
}

// ============================================================================
// FWPM_PROVIDER0 - Provider Registration
// ============================================================================

// FWPM_PROVIDER0 represents a firewall provider registration.
// Providers group filters together for identification and management.
type FWPM_PROVIDER0 struct {
	// ProviderKey is the unique identifier for this provider.
	ProviderKey GUID `json:"provider_key"`

	// DisplayData contains the provider name and description.
	DisplayData FWPM_DISPLAY_DATA0 `json:"display_data"`

	// Flags control provider behavior.
	// FWPM_PROVIDER_FLAG_PERSISTENT: Provider survives reboot.
	Flags FWPM_PROVIDER_FLAG `json:"flags,omitempty"`

	// ProviderData contains optional provider-specific data.
	ProviderData *FWP_BYTE_BLOB `json:"-"`

	// ServiceName is the name of the service associated with this provider.
	ServiceName string `json:"service_name,omitempty"`
}

// NewProvider creates a new provider configuration.
func NewProvider(key GUID, name, description string) *FWPM_PROVIDER0 {
	return &FWPM_PROVIDER0{
		ProviderKey: key,
		DisplayData: NewDisplayData(name, description),
		Flags:       0,
	}
}

// NewSafeOpsProvider creates the SafeOps provider configuration.
func NewSafeOpsProvider() *FWPM_PROVIDER0 {
	return &FWPM_PROVIDER0{
		ProviderKey: SAFEOPS_PROVIDER_GUID,
		DisplayData: NewDisplayData(SAFEOPS_PROVIDER_NAME, SAFEOPS_PROVIDER_DESCRIPTION),
		Flags:       0,
		ServiceName: "firewall_engine",
	}
}

// IsPersistent returns true if the provider survives reboot.
func (p *FWPM_PROVIDER0) IsPersistent() bool {
	return p.Flags&FWPM_PROVIDER_FLAG_PERSISTENT != 0
}

// String returns a string representation.
func (p *FWPM_PROVIDER0) String() string {
	if p == nil {
		return "<nil provider>"
	}
	return fmt.Sprintf("Provider[%s, key=%s]", p.DisplayData.Name, p.ProviderKey.String())
}

// ============================================================================
// FWPM_SUBLAYER0 - Sublayer Registration
// ============================================================================

// FWPM_SUBLAYER0 represents a sublayer for grouping filters.
// Sublayers affect filter evaluation order and can provide isolation.
type FWPM_SUBLAYER0 struct {
	// SublayerKey is the unique identifier for this sublayer.
	SublayerKey GUID `json:"sublayer_key"`

	// DisplayData contains the sublayer name and description.
	DisplayData FWPM_DISPLAY_DATA0 `json:"display_data"`

	// Flags control sublayer behavior.
	Flags uint16 `json:"flags,omitempty"`

	// ProviderKey links this sublayer to a provider.
	// Optional - if null, sublayer has no provider.
	ProviderKey *GUID `json:"provider_key,omitempty"`

	// ProviderData contains optional provider-specific data.
	ProviderData *FWP_BYTE_BLOB `json:"-"`

	// Weight determines evaluation order relative to other sublayers.
	// Higher weight = evaluated first.
	Weight uint16 `json:"weight,omitempty"`
}

// NewSublayer creates a new sublayer configuration.
func NewSublayer(key GUID, name, description string, weight uint16) *FWPM_SUBLAYER0 {
	return &FWPM_SUBLAYER0{
		SublayerKey: key,
		DisplayData: NewDisplayData(name, description),
		Weight:      weight,
	}
}

// NewSafeOpsSublayer creates the SafeOps sublayer configuration.
func NewSafeOpsSublayer() *FWPM_SUBLAYER0 {
	providerKey := SAFEOPS_PROVIDER_GUID
	return &FWPM_SUBLAYER0{
		SublayerKey: SAFEOPS_SUBLAYER_GUID,
		DisplayData: NewDisplayData("SafeOps Sublayer", "SafeOps Firewall filter sublayer"),
		ProviderKey: &providerKey,
		Weight:      0x8000, // Middle priority
	}
}

// String returns a string representation.
func (s *FWPM_SUBLAYER0) String() string {
	if s == nil {
		return "<nil sublayer>"
	}
	return fmt.Sprintf("Sublayer[%s, key=%s, weight=%d]",
		s.DisplayData.Name, s.SublayerKey.String(), s.Weight)
}

// ============================================================================
// FWPM_FILTER_CONDITION0 - Filter Match Condition
// ============================================================================

// FWPM_FILTER_CONDITION0 specifies a single match condition for a filter.
// Multiple conditions in a filter are ANDed together.
type FWPM_FILTER_CONDITION0 struct {
	// FieldKey identifies what field to match (e.g., remote IP, port, protocol).
	FieldKey GUID `json:"field_key"`

	// MatchType specifies how to compare (EQUAL, RANGE, PREFIX, etc.).
	MatchType FWP_MATCH_TYPE `json:"match_type"`

	// ConditionValue is the value to match against.
	ConditionValue FWP_CONDITION_VALUE0 `json:"condition_value"`
}

// NewFilterCondition creates a new filter condition.
func NewFilterCondition(fieldKey GUID, matchType FWP_MATCH_TYPE, value FWP_VALUE0) *FWPM_FILTER_CONDITION0 {
	return &FWPM_FILTER_CONDITION0{
		FieldKey:       fieldKey,
		MatchType:      matchType,
		ConditionValue: value,
	}
}

// NewRemoteIPCondition creates a condition for matching remote IP address.
func NewRemoteIPCondition(ip string) (*FWPM_FILTER_CONDITION0, error) {
	// Parse as CIDR or plain IP
	if _, _, err := parseIPMask(ip); err == nil {
		// CIDR notation
		mask, err := NewV4AddrAndMaskFromCIDR(ip)
		if err != nil {
			return nil, err
		}
		return NewFilterCondition(
			FWPM_CONDITION_IP_REMOTE_ADDRESS,
			FWP_MATCH_PREFIX,
			NewV4AddrMaskValue(mask),
		), nil
	}

	// Plain IP (exact match)
	mask := NewV4AddrAndMask(parseIP(ip), 32)
	return NewFilterCondition(
		FWPM_CONDITION_IP_REMOTE_ADDRESS,
		FWP_MATCH_EQUAL,
		NewV4AddrMaskValue(mask),
	), nil
}

// NewLocalIPCondition creates a condition for matching local IP address.
func NewLocalIPCondition(ip string) (*FWPM_FILTER_CONDITION0, error) {
	// Similar to NewRemoteIPCondition but for local address
	mask := NewV4AddrAndMask(parseIP(ip), 32)
	return NewFilterCondition(
		FWPM_CONDITION_IP_LOCAL_ADDRESS,
		FWP_MATCH_EQUAL,
		NewV4AddrMaskValue(mask),
	), nil
}

// NewRemotePortExactCondition creates a condition for exact port match.
func NewRemotePortExactCondition(port uint16) *FWPM_FILTER_CONDITION0 {
	return NewFilterCondition(
		FWPM_CONDITION_IP_REMOTE_PORT,
		FWP_MATCH_EQUAL,
		NewPortValue(port),
	)
}

// NewRemotePortRangeCondition creates a condition for port range match.
func NewRemotePortRangeCondition(lowPort, highPort uint16) *FWPM_FILTER_CONDITION0 {
	return NewFilterCondition(
		FWPM_CONDITION_IP_REMOTE_PORT,
		FWP_MATCH_RANGE,
		NewRangeValue(NewUint16Range(lowPort, highPort)),
	)
}

// NewLocalPortExactCondition creates a condition for exact local port match.
func NewLocalPortExactCondition(port uint16) *FWPM_FILTER_CONDITION0 {
	return NewFilterCondition(
		FWPM_CONDITION_IP_LOCAL_PORT,
		FWP_MATCH_EQUAL,
		NewPortValue(port),
	)
}

// NewProtocolExactCondition creates a condition for protocol match.
func NewProtocolExactCondition(protocol uint8) *FWPM_FILTER_CONDITION0 {
	return NewFilterCondition(
		FWPM_CONDITION_IP_PROTOCOL,
		FWP_MATCH_EQUAL,
		NewProtocolValue(protocol),
	)
}

// NewTCPProtocolCondition creates a condition for TCP protocol.
func NewTCPProtocolCondition() *FWPM_FILTER_CONDITION0 {
	return NewProtocolExactCondition(IPPROTO_TCP)
}

// NewUDPProtocolCondition creates a condition for UDP protocol.
func NewUDPProtocolCondition() *FWPM_FILTER_CONDITION0 {
	return NewProtocolExactCondition(IPPROTO_UDP)
}

// NewICMPProtocolCondition creates a condition for ICMP protocol.
func NewICMPProtocolCondition() *FWPM_FILTER_CONDITION0 {
	return NewProtocolExactCondition(IPPROTO_ICMP)
}

// String returns a string representation.
func (c *FWPM_FILTER_CONDITION0) String() string {
	if c == nil {
		return "<nil condition>"
	}
	return fmt.Sprintf("Condition[field=%s, match=%s, value=%s]",
		c.FieldKey.String(), c.MatchType.String(), c.ConditionValue.String())
}

// ============================================================================
// FWPM_FILTER0 - WFP Filter Definition
// ============================================================================

// FWPM_FILTER0 represents a complete WFP filter definition.
// This is the Go version of the Windows FWPM_FILTER0 structure.
type FWPM_FILTER0 struct {
	// FilterKey is the unique identifier for this filter.
	// If empty, Windows generates one automatically.
	FilterKey GUID `json:"filter_key"`

	// DisplayData contains the filter name and description.
	DisplayData FWPM_DISPLAY_DATA0 `json:"display_data"`

	// Flags control filter behavior.
	// FWPM_FILTER_FLAG_PERSISTENT: Filter survives reboot.
	// FWPM_FILTER_FLAG_BOOTTIME: Filter active during boot.
	Flags FWPM_FILTER_FLAG `json:"flags,omitempty"`

	// ProviderKey links this filter to a provider.
	// Should be SAFEOPS_PROVIDER_GUID for SafeOps filters.
	ProviderKey *GUID `json:"provider_key,omitempty"`

	// ProviderData contains optional provider-specific data.
	ProviderData *FWP_BYTE_BLOB `json:"-"`

	// LayerKey specifies which layer this filter applies to.
	// Example: FWPM_LAYER_OUTBOUND_IPPACKET_V4 for outbound IPv4.
	LayerKey GUID `json:"layer_key"`

	// SublayerKey specifies which sublayer this filter belongs to.
	// Optional - if empty, uses default sublayer.
	SublayerKey GUID `json:"sublayer_key,omitempty"`

	// Weight determines evaluation order within the sublayer.
	// Higher weight = evaluated first.
	Weight FilterWeight `json:"weight,omitempty"`

	// Conditions is the list of match conditions (ANDed together).
	Conditions []*FWPM_FILTER_CONDITION0 `json:"conditions,omitempty"`

	// Action specifies what happens when all conditions match.
	Action FWP_ACTION0 `json:"action"`

	// EffectiveWeight is the actual weight used by Windows.
	// Set automatically by Windows; not used for input.
	EffectiveWeight uint64 `json:"effective_weight,omitempty"`

	// FilterID is the unique ID assigned by Windows after installation.
	// Set automatically; not used for input.
	FilterID uint64 `json:"filter_id,omitempty"`

	// === Metadata (not sent to Windows) ===

	// RuleID is the SafeOps rule ID this filter was created from.
	// Used for correlation during hot-reload.
	RuleID string `json:"rule_id,omitempty"`

	// CreatedAt is when this filter was created.
	CreatedAt time.Time `json:"created_at,omitempty"`

	// Enabled indicates if the filter is active.
	Enabled bool `json:"enabled"`
}

// NewFilter creates a new filter with default values.
func NewFilter(name string, layerKey GUID, action FWP_ACTION_TYPE) *FWPM_FILTER0 {
	providerKey := SAFEOPS_PROVIDER_GUID
	return &FWPM_FILTER0{
		DisplayData: NewDisplayData(name, ""),
		Flags:       FWPM_FILTER_FLAG_NONE,
		ProviderKey: &providerKey,
		LayerKey:    layerKey,
		SublayerKey: SAFEOPS_SUBLAYER_GUID,
		Weight:      NewUint8Weight(128), // Medium priority
		Conditions:  make([]*FWPM_FILTER_CONDITION0, 0),
		Action:      FWP_ACTION0{Type: action},
		Enabled:     true,
		CreatedAt:   time.Now(),
	}
}

// NewBlockFilter creates a filter that blocks matching traffic.
func NewBlockFilter(name string, layerKey GUID) *FWPM_FILTER0 {
	return NewFilter(name, layerKey, FWP_ACTION_BLOCK)
}

// NewPermitFilter creates a filter that permits matching traffic.
func NewPermitFilter(name string, layerKey GUID) *FWPM_FILTER0 {
	return NewFilter(name, layerKey, FWP_ACTION_PERMIT)
}

// AddCondition adds a condition to the filter.
func (f *FWPM_FILTER0) AddCondition(c *FWPM_FILTER_CONDITION0) *FWPM_FILTER0 {
	if c != nil {
		f.Conditions = append(f.Conditions, c)
	}
	return f
}

// AddRemoteIP adds a remote IP condition.
func (f *FWPM_FILTER0) AddRemoteIP(ip string) *FWPM_FILTER0 {
	c, err := NewRemoteIPCondition(ip)
	if err == nil {
		f.AddCondition(c)
	}
	return f
}

// AddRemotePort adds a remote port condition.
func (f *FWPM_FILTER0) AddRemotePort(port uint16) *FWPM_FILTER0 {
	return f.AddCondition(NewRemotePortExactCondition(port))
}

// AddRemotePortRange adds a remote port range condition.
func (f *FWPM_FILTER0) AddRemotePortRange(lowPort, highPort uint16) *FWPM_FILTER0 {
	return f.AddCondition(NewRemotePortRangeCondition(lowPort, highPort))
}

// AddLocalPort adds a local port condition.
func (f *FWPM_FILTER0) AddLocalPort(port uint16) *FWPM_FILTER0 {
	return f.AddCondition(NewLocalPortExactCondition(port))
}

// AddTCP adds a TCP protocol condition.
func (f *FWPM_FILTER0) AddTCP() *FWPM_FILTER0 {
	return f.AddCondition(NewTCPProtocolCondition())
}

// AddUDP adds a UDP protocol condition.
func (f *FWPM_FILTER0) AddUDP() *FWPM_FILTER0 {
	return f.AddCondition(NewUDPProtocolCondition())
}

// AddICMP adds an ICMP protocol condition.
func (f *FWPM_FILTER0) AddICMP() *FWPM_FILTER0 {
	return f.AddCondition(NewICMPProtocolCondition())
}

// SetWeight sets the filter weight.
func (f *FWPM_FILTER0) SetWeight(w uint8) *FWPM_FILTER0 {
	f.Weight = NewUint8Weight(w)
	return f
}

// SetPersistent makes the filter persistent (survives reboot).
func (f *FWPM_FILTER0) SetPersistent(persistent bool) *FWPM_FILTER0 {
	if persistent {
		f.Flags |= FWPM_FILTER_FLAG_PERSISTENT
	} else {
		f.Flags &^= FWPM_FILTER_FLAG_PERSISTENT
	}
	return f
}

// SetBoottime makes the filter active during boot.
func (f *FWPM_FILTER0) SetBoottime(boottime bool) *FWPM_FILTER0 {
	if boottime {
		f.Flags |= FWPM_FILTER_FLAG_BOOTTIME
	} else {
		f.Flags &^= FWPM_FILTER_FLAG_BOOTTIME
	}
	return f
}

// SetRuleID sets the SafeOps rule ID for correlation.
func (f *FWPM_FILTER0) SetRuleID(ruleID string) *FWPM_FILTER0 {
	f.RuleID = ruleID
	return f
}

// IsPersistent returns true if filter survives reboot.
func (f *FWPM_FILTER0) IsPersistent() bool {
	return f.Flags&FWPM_FILTER_FLAG_PERSISTENT != 0
}

// IsBoottime returns true if filter is active during boot.
func (f *FWPM_FILTER0) IsBoottime() bool {
	return f.Flags&FWPM_FILTER_FLAG_BOOTTIME != 0
}

// IsBlock returns true if this is a block filter.
func (f *FWPM_FILTER0) IsBlock() bool {
	return f.Action.IsBlock()
}

// IsPermit returns true if this is a permit filter.
func (f *FWPM_FILTER0) IsPermit() bool {
	return f.Action.IsPermit()
}

// NumConditions returns the number of conditions.
func (f *FWPM_FILTER0) NumConditions() int {
	return len(f.Conditions)
}

// Validate checks if the filter is valid for installation.
func (f *FWPM_FILTER0) Validate() error {
	if f == nil {
		return fmt.Errorf("filter is nil")
	}
	if f.LayerKey.IsNull() {
		return fmt.Errorf("layer key is required")
	}
	if f.DisplayData.Name == "" {
		return fmt.Errorf("filter name is required")
	}
	return nil
}

// String returns a string representation.
func (f *FWPM_FILTER0) String() string {
	if f == nil {
		return "<nil filter>"
	}
	return fmt.Sprintf("Filter[%s, layer=%s, action=%s, conditions=%d]",
		f.DisplayData.Name, f.LayerKey.String(), f.Action.String(), len(f.Conditions))
}

// ============================================================================
// Helper Functions
// ============================================================================

// parseIP parses an IP address string.
func parseIP(ip string) net.IP {
	return net.ParseIP(ip)
}

// parseIPMask attempts to parse a CIDR notation.
func parseIPMask(cidr string) (net.IP, net.IPMask, error) {
	_, ipNet, err := net.ParseCIDR(cidr)
	if err != nil {
		return nil, nil, err
	}
	return ipNet.IP, ipNet.Mask, nil
}

// ============================================================================
// Filter Builder (Convenience)
// ============================================================================

// FilterBuilder provides a fluent interface for building filters.
type FilterBuilder struct {
	filter *FWPM_FILTER0
	errors []error
}

// NewFilterBuilder creates a new filter builder.
func NewFilterBuilder(name string) *FilterBuilder {
	return &FilterBuilder{
		filter: NewFilter(name, FWPM_LAYER_OUTBOUND_IPPACKET_V4, FWP_ACTION_BLOCK),
		errors: nil,
	}
}

// Layer sets the filter layer.
func (b *FilterBuilder) Layer(key GUID) *FilterBuilder {
	b.filter.LayerKey = key
	return b
}

// OutboundIPv4 sets layer to outbound IPv4.
func (b *FilterBuilder) OutboundIPv4() *FilterBuilder {
	return b.Layer(FWPM_LAYER_OUTBOUND_IPPACKET_V4)
}

// InboundIPv4 sets layer to inbound IPv4.
func (b *FilterBuilder) InboundIPv4() *FilterBuilder {
	return b.Layer(FWPM_LAYER_INBOUND_IPPACKET_V4)
}

// OutboundTransport sets layer to outbound transport (TCP/UDP).
func (b *FilterBuilder) OutboundTransport() *FilterBuilder {
	return b.Layer(FWPM_LAYER_OUTBOUND_TRANSPORT_V4)
}

// InboundTransport sets layer to inbound transport.
func (b *FilterBuilder) InboundTransport() *FilterBuilder {
	return b.Layer(FWPM_LAYER_INBOUND_TRANSPORT_V4)
}

// ALEConnect sets layer to ALE outbound connect (app-aware).
func (b *FilterBuilder) ALEConnect() *FilterBuilder {
	return b.Layer(FWPM_LAYER_ALE_AUTH_CONNECT_V4)
}

// ALEAccept sets layer to ALE inbound accept (app-aware).
func (b *FilterBuilder) ALEAccept() *FilterBuilder {
	return b.Layer(FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V4)
}

// Block sets action to block.
func (b *FilterBuilder) Block() *FilterBuilder {
	b.filter.Action = NewBlockAction()
	return b
}

// Permit sets action to permit.
func (b *FilterBuilder) Permit() *FilterBuilder {
	b.filter.Action = NewPermitAction()
	return b
}

// RemoteIP adds a remote IP condition.
func (b *FilterBuilder) RemoteIP(ip string) *FilterBuilder {
	c, err := NewRemoteIPCondition(ip)
	if err != nil {
		b.errors = append(b.errors, err)
	} else {
		b.filter.AddCondition(c)
	}
	return b
}

// RemotePort adds a remote port condition.
func (b *FilterBuilder) RemotePort(port uint16) *FilterBuilder {
	b.filter.AddRemotePort(port)
	return b
}

// RemotePorts adds a remote port range condition.
func (b *FilterBuilder) RemotePorts(low, high uint16) *FilterBuilder {
	b.filter.AddRemotePortRange(low, high)
	return b
}

// LocalPort adds a local port condition.
func (b *FilterBuilder) LocalPort(port uint16) *FilterBuilder {
	b.filter.AddLocalPort(port)
	return b
}

// TCP adds a TCP protocol condition.
func (b *FilterBuilder) TCP() *FilterBuilder {
	b.filter.AddTCP()
	return b
}

// UDP adds a UDP protocol condition.
func (b *FilterBuilder) UDP() *FilterBuilder {
	b.filter.AddUDP()
	return b
}

// ICMP adds an ICMP protocol condition.
func (b *FilterBuilder) ICMP() *FilterBuilder {
	b.filter.AddICMP()
	return b
}

// Weight sets the filter weight.
func (b *FilterBuilder) Weight(w uint8) *FilterBuilder {
	b.filter.SetWeight(w)
	return b
}

// Persistent makes the filter persistent.
func (b *FilterBuilder) Persistent() *FilterBuilder {
	b.filter.SetPersistent(true)
	return b
}

// Boottime makes the filter active at boot.
func (b *FilterBuilder) Boottime() *FilterBuilder {
	b.filter.SetBoottime(true)
	return b
}

// RuleID sets the SafeOps rule ID.
func (b *FilterBuilder) RuleID(id string) *FilterBuilder {
	b.filter.SetRuleID(id)
	return b
}

// Description sets the filter description.
func (b *FilterBuilder) Description(desc string) *FilterBuilder {
	b.filter.DisplayData.Description = desc
	return b
}

// Build returns the constructed filter and any errors.
func (b *FilterBuilder) Build() (*FWPM_FILTER0, error) {
	if len(b.errors) > 0 {
		return nil, b.errors[0]
	}
	if err := b.filter.Validate(); err != nil {
		return nil, err
	}
	return b.filter, nil
}

// MustBuild returns the filter or panics on error.
func (b *FilterBuilder) MustBuild() *FWPM_FILTER0 {
	f, err := b.Build()
	if err != nil {
		panic(err)
	}
	return f
}
