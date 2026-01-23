// Package application provides ALE (Application Layer Enforcement) filter creation.
// ALE layers enable application-aware filtering where filters can match based on
// the application that is generating or receiving network traffic.
package application

import (
	"fmt"
	"time"

	"firewall_engine/internal/wfp/bindings"
)

// ============================================================================
// ALE Direction Types
// ============================================================================

// ALEDirection specifies which type of ALE layer to use.
type ALEDirection int

const (
	// ALEConnect is for outbound connection attempts.
	// Used when an application tries to establish an outgoing connection.
	ALEConnect ALEDirection = iota

	// ALERecvAccept is for inbound connection acceptance.
	// Used when an application receives and accepts an incoming connection.
	ALERecvAccept

	// ALEListen is for server listen operations.
	// Used when an application binds to a port to listen for connections.
	ALEListen
)

// String returns the string representation of the direction.
func (d ALEDirection) String() string {
	switch d {
	case ALEConnect:
		return "CONNECT"
	case ALERecvAccept:
		return "RECV_ACCEPT"
	case ALEListen:
		return "LISTEN"
	default:
		return "UNKNOWN"
	}
}

// IsInbound returns true if this is an inbound direction.
func (d ALEDirection) IsInbound() bool {
	return d == ALERecvAccept || d == ALEListen
}

// IsOutbound returns true if this is an outbound direction.
func (d ALEDirection) IsOutbound() bool {
	return d == ALEConnect
}

// ============================================================================
// ALE Filter Configuration
// ============================================================================

// ALEFilterConfig contains all configuration for creating an ALE filter.
type ALEFilterConfig struct {
	// Application is the resolved application identity.
	// Required - the filter will match traffic from/to this application.
	Application *AppIdentity

	// Direction specifies which ALE layer to use.
	Direction ALEDirection

	// IPv6 indicates whether to create IPv6 filters (default: IPv4).
	IPv6 bool

	// Action specifies whether to permit or block matching traffic.
	Action bindings.FWP_ACTION_TYPE

	// RemoteAddress is an optional remote IP/CIDR to match.
	// Empty means match any remote address.
	RemoteAddress string

	// RemotePort is an optional remote port to match.
	// 0 means match any port.
	RemotePort uint16

	// LocalPort is an optional local port to match.
	// 0 means match any port.
	LocalPort uint16

	// Protocol is an optional IP protocol to match (TCP=6, UDP=17).
	// 0 means match any protocol.
	Protocol uint8

	// Weight determines filter evaluation priority (0-255, higher = first).
	Weight uint8

	// FilterName is the display name for the filter.
	// If empty, auto-generated from application name.
	FilterName string

	// Description is the filter description.
	Description string

	// RuleID is the SafeOps rule ID for tracking.
	RuleID string

	// Persistent indicates if the filter should survive reboot.
	Persistent bool
}

// Validate checks if the configuration is valid.
func (c *ALEFilterConfig) Validate() error {
	if c.Application == nil {
		return fmt.Errorf("application identity is required")
	}
	if !c.Application.IsValid() {
		return fmt.Errorf("application identity is invalid: missing NT path or blob")
	}
	if c.Action != bindings.FWP_ACTION_PERMIT && c.Action != bindings.FWP_ACTION_BLOCK {
		return fmt.Errorf("action must be PERMIT or BLOCK, got %d", c.Action)
	}
	return nil
}

// ============================================================================
// ALE Layer Selection
// ============================================================================

// GetALELayer returns the appropriate ALE layer GUID for the given direction.
func GetALELayer(direction ALEDirection, ipv6 bool) bindings.GUID {
	switch direction {
	case ALEConnect:
		if ipv6 {
			return bindings.FWPM_LAYER_ALE_AUTH_CONNECT_V6
		}
		return bindings.FWPM_LAYER_ALE_AUTH_CONNECT_V4

	case ALERecvAccept:
		if ipv6 {
			return bindings.FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V6
		}
		return bindings.FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V4

	case ALEListen:
		if ipv6 {
			return bindings.FWPM_LAYER_ALE_AUTH_LISTEN_V6
		}
		return bindings.FWPM_LAYER_ALE_AUTH_LISTEN_V4

	default:
		// Default to connect layer
		if ipv6 {
			return bindings.FWPM_LAYER_ALE_AUTH_CONNECT_V6
		}
		return bindings.FWPM_LAYER_ALE_AUTH_CONNECT_V4
	}
}

// GetALELayerName returns a human-readable name for the layer.
func GetALELayerName(direction ALEDirection, ipv6 bool) string {
	proto := "IPv4"
	if ipv6 {
		proto = "IPv6"
	}

	switch direction {
	case ALEConnect:
		return fmt.Sprintf("ALE Auth Connect %s", proto)
	case ALERecvAccept:
		return fmt.Sprintf("ALE Auth Recv/Accept %s", proto)
	case ALEListen:
		return fmt.Sprintf("ALE Auth Listen %s", proto)
	default:
		return fmt.Sprintf("ALE Unknown %s", proto)
	}
}

// ============================================================================
// ALE Filter Factory
// ============================================================================

// ALEFilterFactory creates ALE-based application filters.
type ALEFilterFactory struct {
	resolver *Resolver
}

// NewALEFilterFactory creates a new ALE filter factory.
func NewALEFilterFactory(resolver *Resolver) *ALEFilterFactory {
	if resolver == nil {
		resolver = NewResolver()
	}
	return &ALEFilterFactory{
		resolver: resolver,
	}
}

// ============================================================================
// Filter Creation
// ============================================================================

// NewALEFilter creates a WFP filter from the given configuration.
func (f *ALEFilterFactory) NewALEFilter(cfg *ALEFilterConfig) (*bindings.FWPM_FILTER0, error) {
	if err := cfg.Validate(); err != nil {
		return nil, fmt.Errorf("invalid config: %w", err)
	}

	// Get appropriate layer
	layerGUID := GetALELayer(cfg.Direction, cfg.IPv6)

	// Generate filter name if not provided
	filterName := cfg.FilterName
	if filterName == "" {
		action := "Block"
		if cfg.Action == bindings.FWP_ACTION_PERMIT {
			action = "Permit"
		}
		filterName = fmt.Sprintf("SafeOps: %s %s (%s)",
			action, cfg.Application.ProcessName, cfg.Direction.String())
	}

	// Create base filter
	filter := bindings.NewFilter(filterName, layerGUID, cfg.Action)
	filter.DisplayData.Description = cfg.Description
	if cfg.RuleID != "" {
		filter.SetRuleID(cfg.RuleID)
	}

	// Set weight
	if cfg.Weight > 0 {
		filter.SetWeight(cfg.Weight)
	}

	// Set persistence
	if cfg.Persistent {
		filter.SetPersistent(true)
	}

	// Add application condition
	appCondition, err := f.NewAppCondition(cfg.Application)
	if err != nil {
		return nil, fmt.Errorf("create app condition: %w", err)
	}
	filter.AddCondition(appCondition)

	// Add remote address condition if specified
	if cfg.RemoteAddress != "" {
		// Use the bindings helper for remote IP
		ipCondition, err := bindings.NewRemoteIPCondition(cfg.RemoteAddress)
		if err != nil {
			return nil, fmt.Errorf("create remote IP condition for %s: %w", cfg.RemoteAddress, err)
		}
		filter.AddCondition(ipCondition)
	}

	// Add remote port condition if specified
	if cfg.RemotePort > 0 {
		filter.AddRemotePort(cfg.RemotePort)
	}

	// Add local port condition if specified
	if cfg.LocalPort > 0 {
		filter.AddLocalPort(cfg.LocalPort)
	}

	// Add protocol condition if specified
	if cfg.Protocol > 0 {
		switch cfg.Protocol {
		case bindings.IPPROTO_TCP:
			filter.AddTCP()
		case bindings.IPPROTO_UDP:
			filter.AddUDP()
		case bindings.IPPROTO_ICMP:
			filter.AddICMP()
		default:
			filter.AddCondition(bindings.NewProtocolExactCondition(cfg.Protocol))
		}
	}

	return filter, nil
}

// NewAppCondition creates a WFP filter condition for an application.
// This uses FWPM_CONDITION_ALE_APP_ID with the application's blob.
func (f *ALEFilterFactory) NewAppCondition(app *AppIdentity) (*bindings.FWPM_FILTER_CONDITION0, error) {
	if app == nil {
		return nil, fmt.Errorf("application identity is nil")
	}
	if len(app.AppIDBlob) == 0 {
		return nil, fmt.Errorf("application blob is empty")
	}

	// Create blob from application's AppIDBlob using bindings helper
	blob := bindings.NewByteBlob(app.AppIDBlob)

	// Create condition for ALE_APP_ID
	condition := &bindings.FWPM_FILTER_CONDITION0{
		FieldKey:       bindings.FWPM_CONDITION_ALE_APP_ID,
		MatchType:      bindings.FWP_MATCH_EQUAL,
		ConditionValue: bindings.NewByteBlobValue(blob),
	}

	return condition, nil
}

// ============================================================================
// Convenience Filter Creators
// ============================================================================

// NewAppBlockFilter creates a filter that blocks all network traffic for an application.
func (f *ALEFilterFactory) NewAppBlockFilter(app *AppIdentity, direction ALEDirection) (*bindings.FWPM_FILTER0, error) {
	cfg := &ALEFilterConfig{
		Application: app,
		Direction:   direction,
		Action:      bindings.FWP_ACTION_BLOCK,
		Weight:      200, // High priority
	}
	return f.NewALEFilter(cfg)
}

// NewAppPermitFilter creates a filter that permits all network traffic for an application.
func (f *ALEFilterFactory) NewAppPermitFilter(app *AppIdentity, direction ALEDirection) (*bindings.FWPM_FILTER0, error) {
	cfg := &ALEFilterConfig{
		Application: app,
		Direction:   direction,
		Action:      bindings.FWP_ACTION_PERMIT,
		Weight:      200, // High priority
	}
	return f.NewALEFilter(cfg)
}

// NewAppBlockToIPFilter blocks an application from connecting to a specific IP/CIDR.
func (f *ALEFilterFactory) NewAppBlockToIPFilter(app *AppIdentity, remoteIP string) (*bindings.FWPM_FILTER0, error) {
	cfg := &ALEFilterConfig{
		Application:   app,
		Direction:     ALEConnect,
		Action:        bindings.FWP_ACTION_BLOCK,
		RemoteAddress: remoteIP,
		Weight:        200,
	}
	return f.NewALEFilter(cfg)
}

// NewAppBlockToPortFilter blocks an application from connecting to a specific port.
func (f *ALEFilterFactory) NewAppBlockToPortFilter(app *AppIdentity, port uint16, protocol uint8) (*bindings.FWPM_FILTER0, error) {
	cfg := &ALEFilterConfig{
		Application: app,
		Direction:   ALEConnect,
		Action:      bindings.FWP_ACTION_BLOCK,
		RemotePort:  port,
		Protocol:    protocol,
		Weight:      200,
	}
	return f.NewALEFilter(cfg)
}

// NewBlockHTTPSFilter blocks an application from making HTTPS connections.
func (f *ALEFilterFactory) NewBlockHTTPSFilter(app *AppIdentity) (*bindings.FWPM_FILTER0, error) {
	return f.NewAppBlockToPortFilter(app, 443, bindings.IPPROTO_TCP)
}

// NewBlockHTTPFilter blocks an application from making HTTP connections.
func (f *ALEFilterFactory) NewBlockHTTPFilter(app *AppIdentity) (*bindings.FWPM_FILTER0, error) {
	return f.NewAppBlockToPortFilter(app, 80, bindings.IPPROTO_TCP)
}

// NewBlockDNSFilter blocks an application from making DNS queries.
func (f *ALEFilterFactory) NewBlockDNSFilter(app *AppIdentity) ([]*bindings.FWPM_FILTER0, error) {
	filters := make([]*bindings.FWPM_FILTER0, 0, 2)

	// Block UDP DNS
	udpFilter, err := f.NewAppBlockToPortFilter(app, 53, bindings.IPPROTO_UDP)
	if err != nil {
		return nil, fmt.Errorf("create UDP DNS block filter: %w", err)
	}
	filters = append(filters, udpFilter)

	// Block TCP DNS
	tcpFilter, err := f.NewAppBlockToPortFilter(app, 53, bindings.IPPROTO_TCP)
	if err != nil {
		return nil, fmt.Errorf("create TCP DNS block filter: %w", err)
	}
	filters = append(filters, tcpFilter)

	return filters, nil
}

// ============================================================================
// Batch Filter Creation
// ============================================================================

// ALEFilterBatch holds multiple ALE filter configurations.
type ALEFilterBatch struct {
	factory *ALEFilterFactory
	configs []*ALEFilterConfig
	errors  []error
}

// NewALEFilterBatch creates a new batch for building multiple filters.
func (f *ALEFilterFactory) NewBatch() *ALEFilterBatch {
	return &ALEFilterBatch{
		factory: f,
		configs: make([]*ALEFilterConfig, 0),
		errors:  make([]error, 0),
	}
}

// Add adds a filter configuration to the batch.
func (b *ALEFilterBatch) Add(cfg *ALEFilterConfig) *ALEFilterBatch {
	if err := cfg.Validate(); err != nil {
		b.errors = append(b.errors, err)
	} else {
		b.configs = append(b.configs, cfg)
	}
	return b
}

// AddBlock adds a block filter for an application.
func (b *ALEFilterBatch) AddBlock(app *AppIdentity, direction ALEDirection) *ALEFilterBatch {
	return b.Add(&ALEFilterConfig{
		Application: app,
		Direction:   direction,
		Action:      bindings.FWP_ACTION_BLOCK,
	})
}

// AddPermit adds a permit filter for an application.
func (b *ALEFilterBatch) AddPermit(app *AppIdentity, direction ALEDirection) *ALEFilterBatch {
	return b.Add(&ALEFilterConfig{
		Application: app,
		Direction:   direction,
		Action:      bindings.FWP_ACTION_PERMIT,
	})
}

// Build creates all filters in the batch.
func (b *ALEFilterBatch) Build() ([]*bindings.FWPM_FILTER0, []error) {
	filters := make([]*bindings.FWPM_FILTER0, 0, len(b.configs))
	errors := make([]error, 0)

	// Include any validation errors
	errors = append(errors, b.errors...)

	for _, cfg := range b.configs {
		filter, err := b.factory.NewALEFilter(cfg)
		if err != nil {
			errors = append(errors, err)
			continue
		}
		filters = append(filters, filter)
	}

	return filters, errors
}

// Size returns the number of configurations in the batch.
func (b *ALEFilterBatch) Size() int {
	return len(b.configs)
}

// HasErrors returns true if there are any errors.
func (b *ALEFilterBatch) HasErrors() bool {
	return len(b.errors) > 0
}

// ============================================================================
// ALE Filter Result
// ============================================================================

// ALEFilterResult contains the result of creating/installing an ALE filter.
type ALEFilterResult struct {
	// Filter is the created filter (nil if failed).
	Filter *bindings.FWPM_FILTER0

	// FilterID is the ID assigned by WFP after installation (0 if not installed).
	FilterID uint64

	// Application is the resolved application identity.
	Application *AppIdentity

	// Direction is the ALE direction used.
	Direction ALEDirection

	// Success indicates if the operation succeeded.
	Success bool

	// Error contains any error that occurred.
	Error error

	// CreatedAt is when the filter was created.
	CreatedAt time.Time
}

// String returns a human-readable representation.
func (r *ALEFilterResult) String() string {
	if r.Error != nil {
		return fmt.Sprintf("ALEFilterResult[FAILED: %v]", r.Error)
	}
	return fmt.Sprintf("ALEFilterResult[%s, direction=%s, filterID=%d]",
		r.Application.ProcessName, r.Direction, r.FilterID)
}

// ============================================================================
// Helper Functions
// ============================================================================

// ResolveAndCreateFilter resolves an application by name and creates a filter.
// This is a convenience function that combines resolution and filter creation.
func (f *ALEFilterFactory) ResolveAndCreateFilter(
	appName string,
	action bindings.FWP_ACTION_TYPE,
	direction ALEDirection,
) (*ALEFilterResult, error) {
	result := &ALEFilterResult{
		Direction: direction,
		CreatedAt: time.Now(),
	}

	// Resolve application
	app, err := f.resolver.ResolveApplication(appName)
	if err != nil {
		result.Error = fmt.Errorf("resolve application %q: %w", appName, err)
		return result, result.Error
	}
	result.Application = app

	// Create filter
	cfg := &ALEFilterConfig{
		Application: app,
		Direction:   direction,
		Action:      action,
		Weight:      200,
	}

	filter, err := f.NewALEFilter(cfg)
	if err != nil {
		result.Error = fmt.Errorf("create filter: %w", err)
		return result, result.Error
	}

	result.Filter = filter
	result.Success = true
	return result, nil
}

// CreateBothDirectionFilters creates filters for both inbound and outbound directions.
func (f *ALEFilterFactory) CreateBothDirectionFilters(
	app *AppIdentity,
	action bindings.FWP_ACTION_TYPE,
) ([]*bindings.FWPM_FILTER0, error) {
	filters := make([]*bindings.FWPM_FILTER0, 0, 4)

	// Create IPv4 filters
	outboundV4, err := f.NewALEFilter(&ALEFilterConfig{
		Application: app,
		Direction:   ALEConnect,
		IPv6:        false,
		Action:      action,
	})
	if err != nil {
		return nil, fmt.Errorf("create outbound IPv4 filter: %w", err)
	}
	filters = append(filters, outboundV4)

	inboundV4, err := f.NewALEFilter(&ALEFilterConfig{
		Application: app,
		Direction:   ALERecvAccept,
		IPv6:        false,
		Action:      action,
	})
	if err != nil {
		return nil, fmt.Errorf("create inbound IPv4 filter: %w", err)
	}
	filters = append(filters, inboundV4)

	// Create IPv6 filters
	outboundV6, err := f.NewALEFilter(&ALEFilterConfig{
		Application: app,
		Direction:   ALEConnect,
		IPv6:        true,
		Action:      action,
	})
	if err != nil {
		return nil, fmt.Errorf("create outbound IPv6 filter: %w", err)
	}
	filters = append(filters, outboundV6)

	inboundV6, err := f.NewALEFilter(&ALEFilterConfig{
		Application: app,
		Direction:   ALERecvAccept,
		IPv6:        true,
		Action:      action,
	})
	if err != nil {
		return nil, fmt.Errorf("create inbound IPv6 filter: %w", err)
	}
	filters = append(filters, inboundV6)

	return filters, nil
}

// GetAllALELayers returns all ALE layer GUIDs for iteration.
func GetAllALELayers() []bindings.GUID {
	return []bindings.GUID{
		bindings.FWPM_LAYER_ALE_AUTH_CONNECT_V4,
		bindings.FWPM_LAYER_ALE_AUTH_CONNECT_V6,
		bindings.FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V4,
		bindings.FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V6,
		bindings.FWPM_LAYER_ALE_AUTH_LISTEN_V4,
		bindings.FWPM_LAYER_ALE_AUTH_LISTEN_V6,
	}
}

// IsALELayer checks if a layer GUID is an ALE layer.
func IsALELayer(layer bindings.GUID) bool {
	aleLayers := GetAllALELayers()
	for _, ale := range aleLayers {
		if layer == ale {
			return true
		}
	}
	return false
}
