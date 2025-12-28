// Package discovery handles DHCP message processing.
// This file implements DHCP ACK packet construction with CA certificate integration.
package discovery

import (
	"context"
	"encoding/binary"
	"errors"
	"net"
	"sync"
	"time"
)

// ============================================================================
// ACK Builder Configuration
// ============================================================================

// ACKBuilderConfig holds ACK construction settings.
type ACKBuilderConfig struct {
	IncludeCAOptions      bool
	CAIntegrationTimeout  time.Duration
	RetryCAOnFailure      bool
	RequireCAOptions      bool
	IncludeRevocationURLs bool
	ACKTimeout            time.Duration
	ServerIP              net.IP
	DefaultLeaseTime      time.Duration
}

// DefaultACKBuilderConfig returns sensible defaults.
func DefaultACKBuilderConfig() *ACKBuilderConfig {
	return &ACKBuilderConfig{
		IncludeCAOptions:      true,
		CAIntegrationTimeout:  2 * time.Second,
		RetryCAOnFailure:      true,
		RequireCAOptions:      false,
		IncludeRevocationURLs: true,
		ACKTimeout:            200 * time.Millisecond,
		DefaultLeaseTime:      24 * time.Hour,
	}
}

// ============================================================================
// ACK Build Request
// ============================================================================

// ACKBuildRequest contains parameters for ACK construction.
type ACKBuildRequest struct {
	TransactionID uint32
	HType         byte
	HLen          byte
	Flags         uint16
	CIAddr        net.IP
	YIAddr        net.IP
	GIAddr        net.IP
	ClientMAC     net.HardwareAddr
	Pool          *PoolInfo
	LeaseTime     time.Duration
	Hostname      string
	IsRenewal     bool
}

// ACKBuildResult contains the result of ACK construction.
type ACKBuildResult struct {
	Packet         *DHCPPacket
	IncludedCAOpts bool
	CAOptionsCount int
	Error          error
}

// ============================================================================
// CA Certificate Provider Interface
// ============================================================================

// CACertProviderInterface defines CA certificate retrieval.
type CACertProviderInterface interface {
	GetCertificateInfo(ctx context.Context, gatewayIP net.IP) (*CACertInfo, error)
}

// CACertInfo contains CA certificate distribution information.
type CACertInfo struct {
	CAURL             string
	InstallScriptURLs []string
	WPADURL           string
	CRLURL            string
	OCSPURL           string
}

// CAOptionBuilderInterface defines CA option encoding.
type CAOptionBuilderInterface interface {
	BuildCAOptions(ctx context.Context, info *CACertInfo) ([]DHCPOption, error)
}

// ============================================================================
// ACK Builder
// ============================================================================

// ACKBuilder constructs DHCP ACK packets.
type ACKBuilder struct {
	mu     sync.RWMutex
	config *ACKBuilderConfig

	// Dependencies
	caProvider      CACertProviderInterface
	caOptionBuilder CAOptionBuilderInterface

	// Statistics
	stats ACKBuilderStats
}

// ACKBuilderStats tracks ACK construction metrics.
type ACKBuilderStats struct {
	TotalBuilt          int64
	SuccessfulBuilds    int64
	FailedBuilds        int64
	WithCompleteCA      int64
	WithPartialCA       int64
	WithoutCA           int64
	CAIntegrationErrors int64
	Option224Count      int64
	Option225Count      int64
	Option252Count      int64
	AvgBuildTimeMs      float64
}

// NewACKBuilder creates a new ACK builder.
func NewACKBuilder(config *ACKBuilderConfig) *ACKBuilder {
	if config == nil {
		config = DefaultACKBuilderConfig()
	}

	return &ACKBuilder{
		config: config,
	}
}

// ============================================================================
// Dependency Setters
// ============================================================================

// SetCAProvider sets the CA certificate provider.
func (b *ACKBuilder) SetCAProvider(provider CACertProviderInterface) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.caProvider = provider
}

// SetCAOptionBuilder sets the CA option builder.
func (b *ACKBuilder) SetCAOptionBuilder(builder CAOptionBuilderInterface) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.caOptionBuilder = builder
}

// SetServerIP sets the server IP address.
func (b *ACKBuilder) SetServerIP(ip net.IP) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.config.ServerIP = ip
}

// ============================================================================
// Main Build Function
// ============================================================================

// BuildACK constructs a DHCP ACK packet with CA certificate options.
func (b *ACKBuilder) BuildACK(ctx context.Context, req *ACKBuildRequest) (*ACKBuildResult, error) {
	startTime := time.Now()
	b.stats.TotalBuilt++

	result := &ACKBuildResult{}

	// Validate request
	if err := b.validateRequest(req); err != nil {
		b.stats.FailedBuilds++
		result.Error = err
		return result, err
	}

	// Create base packet
	packet := b.createBasePacket(req)

	// Build standard options
	standardOpts := b.buildStandardOptions(req)

	// Build CA options if enabled
	var caOpts []DHCPOption
	if b.config.IncludeCAOptions {
		caOpts = b.buildCAOptions(ctx, req)
		result.CAOptionsCount = len(caOpts)
		result.IncludedCAOpts = len(caOpts) > 0

		// Track CA option coverage
		b.trackCAOptions(caOpts)
	}

	// Combine all options
	packet.Options = b.combineOptions(standardOpts, caOpts)

	// Validate packet
	if err := ValidatePacket(packet); err != nil {
		b.stats.FailedBuilds++
		result.Error = err
		return result, err
	}

	result.Packet = packet
	b.stats.SuccessfulBuilds++

	// Update timing stats
	elapsed := float64(time.Since(startTime).Milliseconds())
	b.updateAvgBuildTime(elapsed)

	return result, nil
}

// ============================================================================
// Base Packet Construction
// ============================================================================

func (b *ACKBuilder) createBasePacket(req *ACKBuildRequest) *DHCPPacket {
	packet := &DHCPPacket{
		Op:     BootReply,
		HType:  req.HType,
		HLen:   req.HLen,
		Hops:   0,
		XID:    req.TransactionID,
		Secs:   0,
		Flags:  req.Flags,
		YIAddr: req.YIAddr,
		SIAddr: b.config.ServerIP,
		CHAddr: req.ClientMAC,
	}

	// Set CIAddr for renewals
	if req.IsRenewal && req.CIAddr != nil {
		packet.CIAddr = req.CIAddr
	} else {
		packet.CIAddr = net.IPv4zero
	}

	// Set GIAddr if relayed
	if req.GIAddr != nil && !req.GIAddr.IsUnspecified() {
		packet.GIAddr = req.GIAddr
	} else {
		packet.GIAddr = net.IPv4zero
	}

	return packet
}

// ============================================================================
// Standard Options Building
// ============================================================================

func (b *ACKBuilder) buildStandardOptions(req *ACKBuildRequest) []DHCPOption {
	options := make([]DHCPOption, 0, 16)

	// Option 53: DHCP Message Type (ACK)
	options = append(options, DHCPOption{
		Code:   OptMessageType,
		Length: 1,
		Data:   []byte{DHCPAck},
	})

	// Option 54: Server Identifier
	if b.config.ServerIP != nil {
		options = append(options, DHCPOption{
			Code:   OptServerID,
			Length: 4,
			Data:   b.config.ServerIP.To4(),
		})
	}

	// Option 51: IP Address Lease Time
	leaseTime := req.LeaseTime
	if leaseTime == 0 {
		leaseTime = b.config.DefaultLeaseTime
	}
	leaseSeconds := uint32(leaseTime.Seconds())
	options = append(options, b.encodeUint32Option(OptLeaseTime, leaseSeconds))

	// Option 58: Renewal Time (T1) - 50% of lease
	t1 := leaseSeconds / 2
	options = append(options, b.encodeUint32Option(OptRenewalTime, t1))

	// Option 59: Rebinding Time (T2) - 87.5% of lease
	t2 := (leaseSeconds * 7) / 8
	options = append(options, b.encodeUint32Option(OptRebindingTime, t2))

	// Pool-specific options
	if req.Pool != nil {
		// Option 1: Subnet Mask
		if len(req.Pool.SubnetMask) >= 4 {
			options = append(options, DHCPOption{
				Code:   OptSubnetMask,
				Length: 4,
				Data:   []byte(req.Pool.SubnetMask[:4]),
			})
		}

		// Option 3: Router (Default Gateway)
		if req.Pool.Gateway != nil && !req.Pool.Gateway.IsUnspecified() {
			options = append(options, DHCPOption{
				Code:   OptRouter,
				Length: 4,
				Data:   req.Pool.Gateway.To4(),
			})
		}

		// Option 6: DNS Servers
		if len(req.Pool.DNSServers) > 0 {
			dnsData := make([]byte, 0, len(req.Pool.DNSServers)*4)
			for _, dns := range req.Pool.DNSServers {
				if dns4 := dns.To4(); dns4 != nil {
					dnsData = append(dnsData, dns4...)
				}
			}
			if len(dnsData) > 0 {
				options = append(options, DHCPOption{
					Code:   OptDNS,
					Length: byte(len(dnsData)),
					Data:   dnsData,
				})
			}
		}

		// Option 28: Broadcast Address
		if req.YIAddr != nil && req.Pool.SubnetMask != nil {
			broadcast := b.calculateBroadcast(req.YIAddr, req.Pool.SubnetMask)
			if broadcast != nil {
				options = append(options, DHCPOption{
					Code:   OptBroadcastAddr,
					Length: 4,
					Data:   broadcast.To4(),
				})
			}
		}
	}

	// Option 12: Hostname (echo back)
	if req.Hostname != "" && len(req.Hostname) <= 255 {
		options = append(options, DHCPOption{
			Code:   OptHostname,
			Length: byte(len(req.Hostname)),
			Data:   []byte(req.Hostname),
		})
	}

	return options
}

// ============================================================================
// CA Options Building
// ============================================================================

func (b *ACKBuilder) buildCAOptions(ctx context.Context, req *ACKBuildRequest) []DHCPOption {
	options := make([]DHCPOption, 0, 5)

	// Get gateway IP for CA URL generation
	var gatewayIP net.IP
	if req.Pool != nil && req.Pool.Gateway != nil {
		gatewayIP = req.Pool.Gateway
	} else if b.config.ServerIP != nil {
		gatewayIP = b.config.ServerIP
	}

	if gatewayIP == nil {
		return options
	}

	// Get CA certificate info
	b.mu.RLock()
	provider := b.caProvider
	b.mu.RUnlock()

	if provider == nil {
		b.stats.WithoutCA++
		return options
	}

	caCtx, cancel := context.WithTimeout(ctx, b.config.CAIntegrationTimeout)
	defer cancel()

	certInfo, err := provider.GetCertificateInfo(caCtx, gatewayIP)
	if err != nil {
		b.stats.CAIntegrationErrors++

		// Retry once if configured
		if b.config.RetryCAOnFailure {
			certInfo, err = provider.GetCertificateInfo(caCtx, gatewayIP)
			if err != nil {
				b.stats.WithoutCA++
				return options
			}
		} else {
			b.stats.WithoutCA++
			return options
		}
	}

	// Build Option 224: CA Certificate URL
	if certInfo.CAURL != "" {
		opt := b.buildURLOption(224, certInfo.CAURL)
		if opt != nil {
			options = append(options, *opt)
			b.stats.Option224Count++
		}
	}

	// Build Option 225: Install Script URLs
	if len(certInfo.InstallScriptURLs) > 0 {
		opt := b.buildScriptURLsOption(certInfo.InstallScriptURLs)
		if opt != nil {
			options = append(options, *opt)
			b.stats.Option225Count++
		}
	}

	// Build Option 252: WPAD URL
	if certInfo.WPADURL != "" {
		opt := b.buildURLOption(252, certInfo.WPADURL)
		if opt != nil {
			options = append(options, *opt)
			b.stats.Option252Count++
		}
	}

	// Build revocation options if enabled
	if b.config.IncludeRevocationURLs {
		// Option 226: CRL URL
		if certInfo.CRLURL != "" {
			opt := b.buildURLOption(226, certInfo.CRLURL)
			if opt != nil {
				options = append(options, *opt)
			}
		}

		// Option 227: OCSP URL
		if certInfo.OCSPURL != "" {
			opt := b.buildURLOption(227, certInfo.OCSPURL)
			if opt != nil {
				options = append(options, *opt)
			}
		}
	}

	// Track CA coverage
	if len(options) >= 3 {
		b.stats.WithCompleteCA++
	} else if len(options) > 0 {
		b.stats.WithPartialCA++
	} else {
		b.stats.WithoutCA++
	}

	return options
}

func (b *ACKBuilder) buildURLOption(code byte, urlStr string) *DHCPOption {
	if urlStr == "" || len(urlStr) > 255 {
		return nil
	}

	return &DHCPOption{
		Code:   code,
		Length: byte(len(urlStr)),
		Data:   []byte(urlStr),
	}
}

func (b *ACKBuilder) buildScriptURLsOption(urls []string) *DHCPOption {
	if len(urls) == 0 {
		return nil
	}

	// Join URLs with comma
	combined := ""
	for i, u := range urls {
		if i > 0 {
			combined += ","
		}
		combined += u

		// Truncate if too long
		if len(combined) > 255 {
			combined = combined[:255]
			break
		}
	}

	if combined == "" {
		return nil
	}

	return &DHCPOption{
		Code:   225,
		Length: byte(len(combined)),
		Data:   []byte(combined),
	}
}

// ============================================================================
// Options Combination
// ============================================================================

func (b *ACKBuilder) combineOptions(standard, ca []DHCPOption) []DHCPOption {
	// Calculate total capacity
	totalLen := len(standard) + len(ca) + 1 // +1 for End option

	options := make([]DHCPOption, 0, totalLen)

	// Add standard options first
	options = append(options, standard...)

	// Add CA options
	options = append(options, ca...)

	// Add End option
	options = append(options, DHCPOption{
		Code:   OptEnd,
		Length: 0,
		Data:   nil,
	})

	return options
}

func (b *ACKBuilder) trackCAOptions(caOpts []DHCPOption) {
	for _, opt := range caOpts {
		switch opt.Code {
		case 224:
			// Already tracked in buildCAOptions
		case 225:
			// Already tracked in buildCAOptions
		case 252:
			// Already tracked in buildCAOptions
		}
	}
}

// ============================================================================
// Helper Functions
// ============================================================================

func (b *ACKBuilder) validateRequest(req *ACKBuildRequest) error {
	if req == nil {
		return ErrNilACKRequest
	}

	if len(req.ClientMAC) == 0 {
		return ErrMissingClientMAC
	}

	if req.YIAddr == nil || req.YIAddr.IsUnspecified() {
		return ErrMissingLeasedIP
	}

	if req.TransactionID == 0 {
		return ErrMissingXID
	}

	return nil
}

func (b *ACKBuilder) encodeUint32Option(code byte, value uint32) DHCPOption {
	data := make([]byte, 4)
	binary.BigEndian.PutUint32(data, value)
	return DHCPOption{
		Code:   code,
		Length: 4,
		Data:   data,
	}
}

func (b *ACKBuilder) calculateBroadcast(ip net.IP, mask net.IPMask) net.IP {
	ip4 := ip.To4()
	if ip4 == nil || len(mask) < 4 {
		return nil
	}

	broadcast := make(net.IP, 4)
	for i := 0; i < 4; i++ {
		broadcast[i] = ip4[i] | ^mask[i]
	}
	return broadcast
}

func (b *ACKBuilder) updateAvgBuildTime(elapsed float64) {
	b.mu.Lock()
	defer b.mu.Unlock()

	if b.stats.SuccessfulBuilds <= 1 {
		b.stats.AvgBuildTimeMs = elapsed
	} else {
		b.stats.AvgBuildTimeMs = (b.stats.AvgBuildTimeMs + elapsed) / 2
	}
}

// ============================================================================
// Statistics
// ============================================================================

// GetStats returns ACK builder statistics.
func (b *ACKBuilder) GetStats() ACKBuilderStats {
	b.mu.RLock()
	defer b.mu.RUnlock()
	return b.stats
}

// GetCAInclusionRate returns percentage of ACKs with CA options.
func (b *ACKBuilder) GetCAInclusionRate() float64 {
	total := b.stats.WithCompleteCA + b.stats.WithPartialCA + b.stats.WithoutCA
	if total == 0 {
		return 0
	}
	caTotal := b.stats.WithCompleteCA + b.stats.WithPartialCA
	return float64(caTotal) / float64(total) * 100
}

// GetCompleteCARate returns percentage of ACKs with all CA options.
func (b *ACKBuilder) GetCompleteCARate() float64 {
	total := b.stats.WithCompleteCA + b.stats.WithPartialCA + b.stats.WithoutCA
	if total == 0 {
		return 0
	}
	return float64(b.stats.WithCompleteCA) / float64(total) * 100
}

// ============================================================================
// Errors
// ============================================================================

var (
	// ErrNilACKRequest is returned when request is nil
	ErrNilACKRequest = errors.New("ACK build request is nil")

	// ErrMissingLeasedIP is returned when leased IP missing
	ErrMissingLeasedIP = errors.New("leased IP address is required")

	// ErrCAIntegrationFailed is returned when CA integration fails
	ErrCAIntegrationFailed = errors.New("CA certificate integration failed")
)
