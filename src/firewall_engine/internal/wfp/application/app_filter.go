// Package application provides a fluent API for building application-aware filters.
// The AppFilterBuilder allows easy construction of complex ALE filters with a
// chainable method interface.
package application

import (
	"fmt"
	"time"

	"firewall_engine/internal/wfp"
	"firewall_engine/internal/wfp/bindings"
)

// ============================================================================
// Filter Target Configuration
// ============================================================================

// FilterTarget specifies a network target to filter.
type FilterTarget struct {
	// Address is an IP address or CIDR to match.
	// Examples: "192.168.1.1", "10.0.0.0/8", "2001:db8::/32"
	Address string

	// Port is a single port to match (0 = any port).
	Port uint16

	// PortRangeLow is the low end of a port range (0 = unused).
	PortRangeLow uint16

	// PortRangeHigh is the high end of a port range (0 = unused).
	PortRangeHigh uint16

	// Protocol is the IP protocol to match (0 = any).
	// Common values: 6 (TCP), 17 (UDP), 1 (ICMP)
	Protocol uint8
}

// HasAddress returns true if an address is specified.
func (t *FilterTarget) HasAddress() bool {
	return t.Address != ""
}

// HasPort returns true if a port is specified.
func (t *FilterTarget) HasPort() bool {
	return t.Port > 0 || (t.PortRangeLow > 0 && t.PortRangeHigh > 0)
}

// HasProtocol returns true if a protocol is specified.
func (t *FilterTarget) HasProtocol() bool {
	return t.Protocol > 0
}

// IsPortRange returns true if this is a port range.
func (t *FilterTarget) IsPortRange() bool {
	return t.PortRangeLow > 0 && t.PortRangeHigh > 0
}

// ============================================================================
// App Filter Result
// ============================================================================

// AppFilterResult contains the result of building/installing app filters.
type AppFilterResult struct {
	// FilterIDs are the WFP filter IDs after installation.
	FilterIDs []uint64

	// Filters are the created filter objects.
	Filters []*bindings.FWPM_FILTER0

	// Application is the resolved application identity.
	Application *AppIdentity

	// RuleID is the SafeOps rule ID (if specified).
	RuleID string

	// Success indicates if the operation succeeded.
	Success bool

	// Errors contains any errors encountered.
	Errors []error

	// Warnings contains non-fatal warnings.
	Warnings []string

	// CreatedAt is when the filters were created.
	CreatedAt time.Time

	// InstalledAt is when the filters were installed (if applicable).
	InstalledAt time.Time
}

// AddError adds an error to the result.
func (r *AppFilterResult) AddError(err error) {
	r.Errors = append(r.Errors, err)
	r.Success = false
}

// AddWarning adds a warning to the result.
func (r *AppFilterResult) AddWarning(msg string) {
	r.Warnings = append(r.Warnings, msg)
}

// HasErrors returns true if there are any errors.
func (r *AppFilterResult) HasErrors() bool {
	return len(r.Errors) > 0
}

// Error returns the first error, or nil.
func (r *AppFilterResult) Error() error {
	if len(r.Errors) > 0 {
		return r.Errors[0]
	}
	return nil
}

// FilterCount returns the number of filters created.
func (r *AppFilterResult) FilterCount() int {
	return len(r.Filters)
}

// String returns a summary of the result.
func (r *AppFilterResult) String() string {
	if r.HasErrors() {
		return fmt.Sprintf("AppFilterResult[FAILED: %v]", r.Errors[0])
	}
	appName := "<unknown>"
	if r.Application != nil {
		appName = r.Application.ProcessName
	}
	return fmt.Sprintf("AppFilterResult[%s, filters=%d, success=%v]",
		appName, r.FilterCount(), r.Success)
}

// ============================================================================
// App Filter Builder
// ============================================================================

// AppFilterBuilder provides a fluent interface for building application filters.
type AppFilterBuilder struct {
	// Dependencies
	engine   *wfp.Engine
	resolver *Resolver
	factory  *ALEFilterFactory

	// Configuration
	appName     string
	appPath     string
	appIdentity *AppIdentity

	action     bindings.FWP_ACTION_TYPE
	directions []ALEDirection
	ipv4       bool
	ipv6       bool

	targets []FilterTarget
	weight  uint8
	ruleID  string
	name    string
	desc    string

	persistent bool

	// State
	errors []error
	built  bool
}

// NewAppFilterBuilder creates a new application filter builder.
func NewAppFilterBuilder(engine *wfp.Engine) *AppFilterBuilder {
	resolver := NewResolver()
	return &AppFilterBuilder{
		engine:     engine,
		resolver:   resolver,
		factory:    NewALEFilterFactory(resolver),
		action:     bindings.FWP_ACTION_BLOCK, // Default to block
		directions: []ALEDirection{},
		ipv4:       true,  // Default to IPv4
		ipv6:       false, // IPv6 opt-in
		targets:    make([]FilterTarget, 0),
		weight:     200, // High-ish default priority
		errors:     make([]error, 0),
	}
}

// NewAppFilterBuilderWithResolver creates a builder with a custom resolver.
func NewAppFilterBuilderWithResolver(engine *wfp.Engine, resolver *Resolver) *AppFilterBuilder {
	if resolver == nil {
		resolver = NewResolver()
	}
	return &AppFilterBuilder{
		engine:     engine,
		resolver:   resolver,
		factory:    NewALEFilterFactory(resolver),
		action:     bindings.FWP_ACTION_BLOCK,
		directions: []ALEDirection{},
		ipv4:       true,
		ipv6:       false,
		targets:    make([]FilterTarget, 0),
		weight:     200,
		errors:     make([]error, 0),
	}
}

// ============================================================================
// Application Specification
// ============================================================================

// ForApp sets the target application by name (e.g., "chrome.exe").
// The application will be resolved to its full path.
func (b *AppFilterBuilder) ForApp(name string) *AppFilterBuilder {
	if name == "" {
		b.errors = append(b.errors, fmt.Errorf("application name cannot be empty"))
		return b
	}
	b.appName = name
	b.appPath = ""
	b.appIdentity = nil
	return b
}

// ForAppPath sets the target application by full path.
func (b *AppFilterBuilder) ForAppPath(path string) *AppFilterBuilder {
	if path == "" {
		b.errors = append(b.errors, fmt.Errorf("application path cannot be empty"))
		return b
	}
	b.appPath = path
	b.appName = ""
	b.appIdentity = nil
	return b
}

// ForAppIdentity sets the target application using a pre-resolved identity.
func (b *AppFilterBuilder) ForAppIdentity(identity *AppIdentity) *AppFilterBuilder {
	if identity == nil {
		b.errors = append(b.errors, fmt.Errorf("application identity cannot be nil"))
		return b
	}
	b.appIdentity = identity
	b.appName = ""
	b.appPath = ""
	return b
}

// ============================================================================
// Action Specification
// ============================================================================

// Block sets the action to block matching traffic.
func (b *AppFilterBuilder) Block() *AppFilterBuilder {
	b.action = bindings.FWP_ACTION_BLOCK
	return b
}

// Permit sets the action to permit matching traffic.
func (b *AppFilterBuilder) Permit() *AppFilterBuilder {
	b.action = bindings.FWP_ACTION_PERMIT
	return b
}

// ============================================================================
// Direction Specification
// ============================================================================

// Outbound filters only outbound connections (ALE Connect layer).
func (b *AppFilterBuilder) Outbound() *AppFilterBuilder {
	b.addDirection(ALEConnect)
	return b
}

// Inbound filters only inbound connections (ALE RecvAccept layer).
func (b *AppFilterBuilder) Inbound() *AppFilterBuilder {
	b.addDirection(ALERecvAccept)
	return b
}

// Listen filters server listen operations.
func (b *AppFilterBuilder) Listen() *AppFilterBuilder {
	b.addDirection(ALEListen)
	return b
}

// Both filters both inbound and outbound traffic.
func (b *AppFilterBuilder) Both() *AppFilterBuilder {
	b.addDirection(ALEConnect)
	b.addDirection(ALERecvAccept)
	return b
}

// All filters all directions including listen.
func (b *AppFilterBuilder) All() *AppFilterBuilder {
	b.addDirection(ALEConnect)
	b.addDirection(ALERecvAccept)
	b.addDirection(ALEListen)
	return b
}

func (b *AppFilterBuilder) addDirection(dir ALEDirection) {
	for _, d := range b.directions {
		if d == dir {
			return // Already added
		}
	}
	b.directions = append(b.directions, dir)
}

// ============================================================================
// IP Version Specification
// ============================================================================

// IPv4Only generates only IPv4 filters (default).
func (b *AppFilterBuilder) IPv4Only() *AppFilterBuilder {
	b.ipv4 = true
	b.ipv6 = false
	return b
}

// IPv6Only generates only IPv6 filters.
func (b *AppFilterBuilder) IPv6Only() *AppFilterBuilder {
	b.ipv4 = false
	b.ipv6 = true
	return b
}

// BothIPVersions generates both IPv4 and IPv6 filters.
func (b *AppFilterBuilder) BothIPVersions() *AppFilterBuilder {
	b.ipv4 = true
	b.ipv6 = true
	return b
}

// ============================================================================
// Target Specification
// ============================================================================

// ToAddress adds a target address (IP or CIDR).
func (b *AppFilterBuilder) ToAddress(addr string) *AppFilterBuilder {
	b.targets = append(b.targets, FilterTarget{Address: addr})
	return b
}

// ToPort adds a target port.
func (b *AppFilterBuilder) ToPort(port uint16) *AppFilterBuilder {
	if port == 0 {
		b.errors = append(b.errors, fmt.Errorf("port cannot be 0"))
		return b
	}
	b.targets = append(b.targets, FilterTarget{Port: port})
	return b
}

// ToPortRange adds a target port range.
func (b *AppFilterBuilder) ToPortRange(low, high uint16) *AppFilterBuilder {
	if low == 0 || high == 0 || low > high {
		b.errors = append(b.errors, fmt.Errorf("invalid port range: %d-%d", low, high))
		return b
	}
	b.targets = append(b.targets, FilterTarget{
		PortRangeLow:  low,
		PortRangeHigh: high,
	})
	return b
}

// ToAddressAndPort adds a target with both address and port.
func (b *AppFilterBuilder) ToAddressAndPort(addr string, port uint16) *AppFilterBuilder {
	b.targets = append(b.targets, FilterTarget{
		Address: addr,
		Port:    port,
	})
	return b
}

// ============================================================================
// Protocol Specification
// ============================================================================

// TCP filters only TCP traffic.
func (b *AppFilterBuilder) TCP() *AppFilterBuilder {
	// Add TCP protocol to existing targets or create new one
	if len(b.targets) == 0 {
		b.targets = append(b.targets, FilterTarget{Protocol: bindings.IPPROTO_TCP})
	} else {
		// Add TCP to last target if it doesn't have a protocol
		last := &b.targets[len(b.targets)-1]
		if last.Protocol == 0 {
			last.Protocol = bindings.IPPROTO_TCP
		} else {
			b.targets = append(b.targets, FilterTarget{Protocol: bindings.IPPROTO_TCP})
		}
	}
	return b
}

// UDP filters only UDP traffic.
func (b *AppFilterBuilder) UDP() *AppFilterBuilder {
	if len(b.targets) == 0 {
		b.targets = append(b.targets, FilterTarget{Protocol: bindings.IPPROTO_UDP})
	} else {
		last := &b.targets[len(b.targets)-1]
		if last.Protocol == 0 {
			last.Protocol = bindings.IPPROTO_UDP
		} else {
			b.targets = append(b.targets, FilterTarget{Protocol: bindings.IPPROTO_UDP})
		}
	}
	return b
}

// ICMP filters only ICMP traffic.
func (b *AppFilterBuilder) ICMP() *AppFilterBuilder {
	if len(b.targets) == 0 {
		b.targets = append(b.targets, FilterTarget{Protocol: bindings.IPPROTO_ICMP})
	} else {
		last := &b.targets[len(b.targets)-1]
		if last.Protocol == 0 {
			last.Protocol = bindings.IPPROTO_ICMP
		} else {
			b.targets = append(b.targets, FilterTarget{Protocol: bindings.IPPROTO_ICMP})
		}
	}
	return b
}

// ============================================================================
// Metadata Specification
// ============================================================================

// WithWeight sets the filter weight (priority).
func (b *AppFilterBuilder) WithWeight(w uint8) *AppFilterBuilder {
	b.weight = w
	return b
}

// WithRuleID sets the SafeOps rule ID for tracking.
func (b *AppFilterBuilder) WithRuleID(id string) *AppFilterBuilder {
	b.ruleID = id
	return b
}

// WithName sets a custom filter name.
func (b *AppFilterBuilder) WithName(name string) *AppFilterBuilder {
	b.name = name
	return b
}

// WithDescription sets the filter description.
func (b *AppFilterBuilder) WithDescription(desc string) *AppFilterBuilder {
	b.desc = desc
	return b
}

// Persistent makes the filters survive reboot.
func (b *AppFilterBuilder) Persistent() *AppFilterBuilder {
	b.persistent = true
	return b
}

// ============================================================================
// Build Methods
// ============================================================================

// Build creates the filters without installing them.
func (b *AppFilterBuilder) Build() (*AppFilterResult, error) {
	result := &AppFilterResult{
		Filters:   make([]*bindings.FWPM_FILTER0, 0),
		FilterIDs: make([]uint64, 0),
		Success:   true,
		CreatedAt: time.Now(),
	}

	// Check for accumulated errors
	if len(b.errors) > 0 {
		result.Errors = b.errors
		result.Success = false
		return result, b.errors[0]
	}

	// Resolve application
	identity, err := b.resolveApp()
	if err != nil {
		result.AddError(fmt.Errorf("resolve application: %w", err))
		return result, result.Error()
	}
	result.Application = identity

	// Set defaults if not specified
	if len(b.directions) == 0 {
		b.directions = []ALEDirection{ALEConnect} // Default to outbound
	}

	// Build filters
	filters, err := b.buildFilters(identity)
	if err != nil {
		result.AddError(err)
		return result, result.Error()
	}

	result.Filters = filters
	result.RuleID = b.ruleID
	b.built = true

	return result, nil
}

// resolveApp resolves the application to an identity.
func (b *AppFilterBuilder) resolveApp() (*AppIdentity, error) {
	// Use pre-resolved identity if available
	if b.appIdentity != nil {
		return b.appIdentity, nil
	}

	// Resolve by path
	if b.appPath != "" {
		return b.resolver.ResolveApplication(b.appPath)
	}

	// Resolve by name
	if b.appName != "" {
		return b.resolver.ResolveApplication(b.appName)
	}

	return nil, fmt.Errorf("no application specified")
}

// buildFilters creates all the filter objects.
func (b *AppFilterBuilder) buildFilters(identity *AppIdentity) ([]*bindings.FWPM_FILTER0, error) {
	filters := make([]*bindings.FWPM_FILTER0, 0)

	// Determine IP versions to create
	ipVersions := make([]bool, 0, 2) // bool = isIPv6
	if b.ipv4 {
		ipVersions = append(ipVersions, false)
	}
	if b.ipv6 {
		ipVersions = append(ipVersions, true)
	}
	if len(ipVersions) == 0 {
		ipVersions = append(ipVersions, false) // Default IPv4
	}

	// Create filters for each combination
	for _, dir := range b.directions {
		for _, ipv6 := range ipVersions {
			if len(b.targets) == 0 {
				// No specific targets - block/permit all traffic
				cfg := b.buildConfig(identity, dir, ipv6, nil)
				filter, err := b.factory.NewALEFilter(cfg)
				if err != nil {
					return nil, fmt.Errorf("create filter for %s %s: %w",
						dir.String(), ipVersionStr(ipv6), err)
				}
				filters = append(filters, filter)
			} else {
				// Create filter for each target
				for i := range b.targets {
					target := &b.targets[i]
					cfg := b.buildConfig(identity, dir, ipv6, target)
					filter, err := b.factory.NewALEFilter(cfg)
					if err != nil {
						return nil, fmt.Errorf("create filter for %s %s target %d: %w",
							dir.String(), ipVersionStr(ipv6), i, err)
					}
					filters = append(filters, filter)
				}
			}
		}
	}

	return filters, nil
}

// buildConfig creates an ALEFilterConfig from builder settings.
func (b *AppFilterBuilder) buildConfig(
	identity *AppIdentity,
	dir ALEDirection,
	ipv6 bool,
	target *FilterTarget,
) *ALEFilterConfig {
	cfg := &ALEFilterConfig{
		Application: identity,
		Direction:   dir,
		IPv6:        ipv6,
		Action:      b.action,
		Weight:      b.weight,
		FilterName:  b.name,
		Description: b.desc,
		RuleID:      b.ruleID,
		Persistent:  b.persistent,
	}

	if target != nil {
		cfg.RemoteAddress = target.Address
		cfg.Protocol = target.Protocol

		if target.Port > 0 {
			cfg.RemotePort = target.Port
		}
		// Note: Port ranges would need additional handling in ALEFilterConfig
	}

	return cfg
}

// Install builds and installs the filters.
func (b *AppFilterBuilder) Install() (*AppFilterResult, error) {
	// Build first
	result, err := b.Build()
	if err != nil {
		return result, err
	}

	// Check engine
	if b.engine == nil {
		result.AddError(fmt.Errorf("engine is nil - cannot install"))
		return result, result.Error()
	}

	if err := b.engine.RequireOpen(); err != nil {
		result.AddError(fmt.Errorf("engine not open: %w", err))
		return result, result.Error()
	}

	// Install each filter
	result.InstalledAt = time.Now()
	result.FilterIDs = make([]uint64, 0, len(result.Filters))

	for i, filter := range result.Filters {
		filterID, err := b.engine.GetBindings().AddFilter(filter)
		if err != nil {
			result.AddError(fmt.Errorf("install filter %d: %w", i, err))
			// Continue with other filters
			continue
		}
		result.FilterIDs = append(result.FilterIDs, filterID)

		// Track in engine
		if filter.RuleID != "" {
			b.engine.TrackFilter(filter.RuleID, filterID)
		}
	}

	// Success if at least one filter was installed
	if len(result.FilterIDs) > 0 {
		result.Success = true
	}

	return result, nil
}

// ============================================================================
// Helper Functions
// ============================================================================

func ipVersionStr(ipv6 bool) string {
	if ipv6 {
		return "IPv6"
	}
	return "IPv4"
}

// ============================================================================
// Convenience Constructors
// ============================================================================

// BlockApp creates a simple app blocking filter builder.
func BlockApp(engine *wfp.Engine, appName string) *AppFilterBuilder {
	return NewAppFilterBuilder(engine).ForApp(appName).Block()
}

// PermitApp creates a simple app permitting filter builder.
func PermitApp(engine *wfp.Engine, appName string) *AppFilterBuilder {
	return NewAppFilterBuilder(engine).ForApp(appName).Permit()
}

// BlockAppToIP creates a filter blocking an app from connecting to an IP.
func BlockAppToIP(engine *wfp.Engine, appName, remoteIP string) *AppFilterBuilder {
	return NewAppFilterBuilder(engine).
		ForApp(appName).
		Block().
		Outbound().
		ToAddress(remoteIP)
}

// BlockAppToPort creates a filter blocking an app from connecting to a port.
func BlockAppToPort(engine *wfp.Engine, appName string, port uint16) *AppFilterBuilder {
	return NewAppFilterBuilder(engine).
		ForApp(appName).
		Block().
		Outbound().
		ToPort(port)
}

// BlockAppHTTPS creates a filter blocking an app from HTTPS connections.
func BlockAppHTTPS(engine *wfp.Engine, appName string) *AppFilterBuilder {
	return NewAppFilterBuilder(engine).
		ForApp(appName).
		Block().
		Outbound().
		ToPort(443).
		TCP()
}

// BlockAppAll creates a filter blocking all network access for an app.
func BlockAppAll(engine *wfp.Engine, appName string) *AppFilterBuilder {
	return NewAppFilterBuilder(engine).
		ForApp(appName).
		Block().
		Both().
		BothIPVersions()
}

// ============================================================================
// Bulk Operations
// ============================================================================

// AppFilterBulkBuilder builds filters for multiple applications.
type AppFilterBulkBuilder struct {
	engine   *wfp.Engine
	builders []*AppFilterBuilder
	errors   []error
}

// NewAppFilterBulkBuilder creates a new bulk builder.
func NewAppFilterBulkBuilder(engine *wfp.Engine) *AppFilterBulkBuilder {
	return &AppFilterBulkBuilder{
		engine:   engine,
		builders: make([]*AppFilterBuilder, 0),
		errors:   make([]error, 0),
	}
}

// Add adds a builder to the bulk operation.
func (bb *AppFilterBulkBuilder) Add(builder *AppFilterBuilder) *AppFilterBulkBuilder {
	if builder == nil {
		bb.errors = append(bb.errors, fmt.Errorf("nil builder"))
		return bb
	}
	bb.builders = append(bb.builders, builder)
	return bb
}

// AddBlockApp adds a block filter for an app.
func (bb *AppFilterBulkBuilder) AddBlockApp(appName string) *AppFilterBulkBuilder {
	return bb.Add(BlockApp(bb.engine, appName).Outbound())
}

// AddPermitApp adds a permit filter for an app.
func (bb *AppFilterBulkBuilder) AddPermitApp(appName string) *AppFilterBulkBuilder {
	return bb.Add(PermitApp(bb.engine, appName).Outbound())
}

// Build builds all filters without installing.
func (bb *AppFilterBulkBuilder) Build() ([]*AppFilterResult, error) {
	results := make([]*AppFilterResult, 0, len(bb.builders))

	for _, builder := range bb.builders {
		result, _ := builder.Build()
		results = append(results, result)
	}

	if len(bb.errors) > 0 {
		return results, bb.errors[0]
	}

	return results, nil
}

// Install builds and installs all filters.
func (bb *AppFilterBulkBuilder) Install() ([]*AppFilterResult, error) {
	results := make([]*AppFilterResult, 0, len(bb.builders))

	for _, builder := range bb.builders {
		result, _ := builder.Install()
		results = append(results, result)
	}

	if len(bb.errors) > 0 {
		return results, bb.errors[0]
	}

	return results, nil
}

// Size returns the number of builders.
func (bb *AppFilterBulkBuilder) Size() int {
	return len(bb.builders)
}
