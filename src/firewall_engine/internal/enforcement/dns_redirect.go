// Package enforcement provides verdict enforcement functionality for the firewall engine.
package enforcement

import (
	"context"
	"fmt"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// ============================================================================
// DNS Redirect Handler - DNS Spoofing for Captive Portal
// ============================================================================

// DNSRedirectHandler implements DNS response spoofing for domain redirection.
// When a DNS query matches a REDIRECT rule, this handler intercepts the query
// and injects a fake DNS response pointing to a captive portal IP.
//
// DNS Spoofing Flow:
//
//	User's Browser
//	  ↓ (Query: What is facebook.com's IP?)
//	Firewall Intercepts Query
//	  ↓ (Inject fake response: 192.168.1.1)
//	User's Browser
//	  ↓ (Connect to 192.168.1.1:80)
//	Captive Portal
//	  ↓ (Display: "This site is blocked by IT policy")
//
// Critical Details:
//   - Transaction ID must match (DNS clients reject mismatched responses)
//   - Response must arrive before real DNS server response
//   - SafeOps kernel-level injection is faster than network round-trip
//   - Short TTL (60s) prevents long-term caching
//
// Use Cases:
//   - Blocking gambling websites with user-friendly block page
//   - Blocking adult content with warning message
//   - Blocking malware domains with security warning
//   - Guest network captive portal (redirect to login page)
type DNSRedirectHandler struct {
	// Configuration
	config *DNSRedirectConfig

	// SafeOps verdict engine for DNS injection
	verdictEngine DNSRedirectEngineInterface

	// Domain to redirect IP cache
	redirects     sync.Map // domain → net.IP
	redirectCount atomic.Int64

	// Statistics
	stats *DNSRedirectStats

	// Shutdown
	closed atomic.Bool
}

// DNSRedirectConfig contains configuration for the DNS redirect handler.
type DNSRedirectConfig struct {
	// CaptivePortalIP is the default IP to redirect blocked domains to.
	CaptivePortalIP string `json:"captive_portal_ip" toml:"captive_portal_ip"`

	// CaptivePortalPort is the port for the captive portal.
	CaptivePortalPort int `json:"captive_portal_port" toml:"captive_portal_port"`

	// ResponseTTL is the TTL for injected DNS responses (seconds).
	ResponseTTL int `json:"response_ttl" toml:"response_ttl"`

	// PreserveCase preserves original domain case in response.
	PreserveCase bool `json:"preserve_case" toml:"preserve_case"`

	// EnableDomainCache caches domain→IP mappings for faster lookups.
	EnableDomainCache bool `json:"enable_domain_cache" toml:"enable_domain_cache"`
}

// DefaultDNSRedirectConfig returns the default configuration.
func DefaultDNSRedirectConfig() *DNSRedirectConfig {
	return &DNSRedirectConfig{
		CaptivePortalIP:   "192.168.1.1",
		CaptivePortalPort: 80,
		ResponseTTL:       60, // 1 minute - short TTL for quick policy changes
		PreserveCase:      false,
		EnableDomainCache: true,
	}
}

// Validate checks the configuration.
func (c *DNSRedirectConfig) Validate() error {
	if c.CaptivePortalIP == "" {
		return fmt.Errorf("captive_portal_ip is required")
	}
	if ip := net.ParseIP(c.CaptivePortalIP); ip == nil {
		return fmt.Errorf("invalid captive_portal_ip: %s", c.CaptivePortalIP)
	}
	if c.CaptivePortalPort < 0 || c.CaptivePortalPort > 65535 {
		return fmt.Errorf("captive_portal_port must be 0-65535, got %d", c.CaptivePortalPort)
	}
	if c.ResponseTTL < 1 {
		return fmt.Errorf("response_ttl must be >= 1, got %d", c.ResponseTTL)
	}
	return nil
}

// DNSRedirectStats tracks DNS redirect handler statistics.
type DNSRedirectStats struct {
	RedirectsAttempted atomic.Uint64
	RedirectsSucceeded atomic.Uint64
	RedirectsFailed    atomic.Uint64
	ResponsesInjected  atomic.Uint64
	DomainCacheHits    atomic.Uint64
	DomainCacheMisses  atomic.Uint64
	InvalidDNSQueries  atomic.Uint64
	ProtocolMismatch   atomic.Uint64
}

// DNSRedirectEngineInterface abstracts the SafeOps verdict engine for DNS injection.
type DNSRedirectEngineInterface interface {
	// InjectDNSResponse injects a fake DNS response for the given query.
	InjectDNSResponse(
		adapterHandle interface{},
		queryPacket []byte,
		domain string,
		fakeIP net.IP,
		srcMAC, dstMAC [6]byte,
	) error

	// AddDNSRedirect adds a domain to the redirect list.
	AddDNSRedirect(domain string, redirectIP net.IP)

	// RemoveDNSRedirect removes a domain from the redirect list.
	RemoveDNSRedirect(domain string)
}

// NewDNSRedirectHandler creates a new DNS redirect handler.
func NewDNSRedirectHandler(config *DNSRedirectConfig, engine DNSRedirectEngineInterface) (*DNSRedirectHandler, error) {
	if config == nil {
		config = DefaultDNSRedirectConfig()
	}

	if err := config.Validate(); err != nil {
		return nil, fmt.Errorf("invalid dns redirect config: %w", err)
	}

	return &DNSRedirectHandler{
		config:        config,
		verdictEngine: engine,
		stats:         &DNSRedirectStats{},
	}, nil
}

// ============================================================================
// ActionHandler Interface Implementation
// ============================================================================

// Name returns the handler name.
func (h *DNSRedirectHandler) Name() string {
	return "DNSRedirectHandler"
}

// SupportedActions returns the actions this handler supports.
func (h *DNSRedirectHandler) SupportedActions() []EnforcementAction {
	return []EnforcementAction{ActionRedirect}
}

// CanHandle checks if this handler can process the given context.
func (h *DNSRedirectHandler) CanHandle(ctx *PacketContext) bool {
	if ctx == nil || ctx.Packet == nil {
		return false
	}

	// Only handle DNS queries
	if !ctx.IsDNS() {
		return false
	}

	// Must be a DNS query (not a response)
	if !ctx.Packet.IsDNSQuery {
		return false
	}

	// Need the raw query packet for injection
	if len(ctx.RawPacket) < 42 { // Min: Eth(14) + IP(20) + UDP(8)
		// Can still handle if we have domain info for redirect rule setup
		return ctx.DNSQueryName != "" || ctx.Packet.Domain != ""
	}

	return true
}

// Handle executes the DNS redirect by injecting a fake DNS response.
func (h *DNSRedirectHandler) Handle(ctx context.Context, pktCtx *PacketContext) *EnforcementResult {
	startTime := time.Now()

	// Check if handler is closed
	if h.closed.Load() {
		return NewFailureResult(ActionRedirect, pktCtx.GetPacketID(),
			fmt.Errorf("dns redirect handler is closed"), ErrCodeDisabled)
	}

	h.stats.RedirectsAttempted.Add(1)

	// Validate this is a DNS query
	if !h.CanHandle(pktCtx) {
		h.stats.ProtocolMismatch.Add(1)
		return NewFailureResult(ActionRedirect, pktCtx.GetPacketID(),
			ErrDNSQueryRequired, ErrCodeProtocolMismatch).
			WithHandler(h.Name())
	}

	// Get the domain to redirect
	domain := h.getDomain(pktCtx)
	if domain == "" {
		h.stats.InvalidDNSQueries.Add(1)
		return NewFailureResult(ActionRedirect, pktCtx.GetPacketID(),
			fmt.Errorf("no domain found in DNS query"), ErrCodeInvalidPacket).
			WithHandler(h.Name())
	}

	// Get redirect IP (from verdict, cache, or default)
	redirectIP := h.getRedirectIP(pktCtx, domain)
	if redirectIP == nil {
		h.stats.RedirectsFailed.Add(1)
		return NewFailureResult(ActionRedirect, pktCtx.GetPacketID(),
			fmt.Errorf("no redirect IP configured"), ErrCodeMissingContext).
			WithHandler(h.Name())
	}

	// Check if we can inject the response
	if h.verdictEngine == nil {
		// No engine - just record the redirect rule for later
		h.addRedirectRule(domain, redirectIP)
		h.stats.RedirectsSucceeded.Add(1)
		return NewSuccessResult(ActionRedirect, pktCtx.GetPacketID(), time.Since(startTime)).
			WithHandler(h.Name()).
			WithMetadata("domain", domain).
			WithMetadata("redirect_ip", redirectIP.String()).
			WithMetadata("mode", "rule_only")
	}

	// Check if we have raw packet for injection
	if len(pktCtx.RawPacket) < 42 {
		// No raw packet - just set up the redirect rule
		h.addRedirectRule(domain, redirectIP)
		h.stats.RedirectsSucceeded.Add(1)
		return NewSuccessResult(ActionRedirect, pktCtx.GetPacketID(), time.Since(startTime)).
			WithHandler(h.Name()).
			WithMetadata("domain", domain).
			WithMetadata("redirect_ip", redirectIP.String()).
			WithMetadata("mode", "rule_setup")
	}

	// Validate context for injection
	if err := pktCtx.ValidateForInjection(); err != nil {
		// Fallback to rule-only mode
		h.addRedirectRule(domain, redirectIP)
		h.stats.RedirectsSucceeded.Add(1)
		return NewSuccessResult(ActionRedirect, pktCtx.GetPacketID(), time.Since(startTime)).
			WithHandler(h.Name()).
			WithMetadata("domain", domain).
			WithMetadata("redirect_ip", redirectIP.String()).
			WithMetadata("mode", "rule_only").
			WithMetadata("injection_skipped", err.Error())
	}

	// Check context cancellation
	select {
	case <-ctx.Done():
		h.stats.RedirectsFailed.Add(1)
		return NewFailureResult(ActionRedirect, pktCtx.GetPacketID(),
			ctx.Err(), ErrCodeTimeout).
			WithHandler(h.Name())
	default:
	}

	// Inject the fake DNS response
	err := h.verdictEngine.InjectDNSResponse(
		pktCtx.AdapterHandle,
		pktCtx.RawPacket,
		domain,
		redirectIP,
		pktCtx.SrcMAC,
		pktCtx.DstMAC,
	)

	if err != nil {
		h.stats.RedirectsFailed.Add(1)
		return NewFailureResult(ActionRedirect, pktCtx.GetPacketID(),
			fmt.Errorf("DNS response injection failed: %w", err),
			ErrCodeInjectionFailed).
			WithHandler(h.Name())
	}

	h.stats.RedirectsSucceeded.Add(1)
	h.stats.ResponsesInjected.Add(1)

	// Also set up the redirect rule for future queries
	h.addRedirectRule(domain, redirectIP)

	return NewSuccessResult(ActionRedirect, pktCtx.GetPacketID(), time.Since(startTime)).
		WithHandler(h.Name()).
		WithMetadata("domain", domain).
		WithMetadata("redirect_ip", redirectIP.String()).
		WithMetadata("mode", "injected")
}

// ============================================================================
// Domain and IP Resolution
// ============================================================================

// getDomain extracts the domain from the packet context.
func (h *DNSRedirectHandler) getDomain(ctx *PacketContext) string {
	// Prefer explicit DNS query name
	if ctx.DNSQueryName != "" {
		return h.normalizeDomain(ctx.DNSQueryName)
	}

	// Fall back to packet domain
	if ctx.Packet != nil && ctx.Packet.Domain != "" {
		return h.normalizeDomain(ctx.Packet.Domain)
	}

	return ""
}

// normalizeDomain normalizes a domain name for consistent handling.
func (h *DNSRedirectHandler) normalizeDomain(domain string) string {
	// Remove trailing dot (FQDN format)
	domain = strings.TrimSuffix(domain, ".")

	// Optionally lowercase
	if !h.config.PreserveCase {
		domain = strings.ToLower(domain)
	}

	return domain
}

// getRedirectIP determines the IP to redirect to.
func (h *DNSRedirectHandler) getRedirectIP(ctx *PacketContext, domain string) net.IP {
	// 1. Check if verdict has explicit redirect IP
	if ctx.RedirectIP != nil {
		return ctx.RedirectIP
	}

	if ctx.Verdict != nil && ctx.Verdict.RedirectIP != "" {
		if ip := net.ParseIP(ctx.Verdict.RedirectIP); ip != nil {
			return ip
		}
	}

	// 2. Check domain-specific redirect cache
	if h.config.EnableDomainCache {
		if ip, ok := h.getRedirectFromCache(domain); ok {
			h.stats.DomainCacheHits.Add(1)
			return ip
		}
		h.stats.DomainCacheMisses.Add(1)
	}

	// 3. Use default captive portal IP
	return net.ParseIP(h.config.CaptivePortalIP)
}

// getRedirectFromCache looks up a domain-specific redirect IP.
func (h *DNSRedirectHandler) getRedirectFromCache(domain string) (net.IP, bool) {
	if val, ok := h.redirects.Load(domain); ok {
		return val.(net.IP), true
	}
	return nil, false
}

// addRedirectRule adds a domain→IP redirect rule.
func (h *DNSRedirectHandler) addRedirectRule(domain string, ip net.IP) {
	if h.config.EnableDomainCache {
		h.redirects.Store(domain, ip)
		h.redirectCount.Add(1)
	}

	// Also add to SafeOps engine for kernel-level handling
	if h.verdictEngine != nil {
		h.verdictEngine.AddDNSRedirect(domain, ip)
	}
}

// ============================================================================
// Public API for Redirect Management
// ============================================================================

// AddDomainRedirect adds a domain redirect rule.
func (h *DNSRedirectHandler) AddDomainRedirect(domain string, redirectIP string) error {
	domain = h.normalizeDomain(domain)
	if domain == "" {
		return fmt.Errorf("domain cannot be empty")
	}

	ip := net.ParseIP(redirectIP)
	if ip == nil {
		return fmt.Errorf("invalid redirect IP: %s", redirectIP)
	}

	h.addRedirectRule(domain, ip)
	return nil
}

// RemoveDomainRedirect removes a domain redirect rule.
func (h *DNSRedirectHandler) RemoveDomainRedirect(domain string) {
	domain = h.normalizeDomain(domain)

	if _, loaded := h.redirects.LoadAndDelete(domain); loaded {
		h.redirectCount.Add(-1)
	}

	if h.verdictEngine != nil {
		h.verdictEngine.RemoveDNSRedirect(domain)
	}
}

// GetRedirectedDomains returns all domains with active redirects.
func (h *DNSRedirectHandler) GetRedirectedDomains() []string {
	var domains []string
	h.redirects.Range(func(key, value interface{}) bool {
		domains = append(domains, key.(string))
		return true
	})
	return domains
}

// GetRedirectCount returns the number of active redirect rules.
func (h *DNSRedirectHandler) GetRedirectCount() int {
	return int(h.redirectCount.Load())
}

// ClearRedirects removes all domain redirect rules.
func (h *DNSRedirectHandler) ClearRedirects() {
	h.redirects.Range(func(key, value interface{}) bool {
		h.redirects.Delete(key)
		if h.verdictEngine != nil {
			h.verdictEngine.RemoveDNSRedirect(key.(string))
		}
		return true
	})
	h.redirectCount.Store(0)
}

// SetCaptivePortalIP updates the default captive portal IP.
func (h *DNSRedirectHandler) SetCaptivePortalIP(ip string) error {
	if net.ParseIP(ip) == nil {
		return fmt.Errorf("invalid IP address: %s", ip)
	}
	h.config.CaptivePortalIP = ip
	return nil
}

// GetCaptivePortalIP returns the current captive portal IP.
func (h *DNSRedirectHandler) GetCaptivePortalIP() string {
	return h.config.CaptivePortalIP
}

// ============================================================================
// Statistics and Lifecycle
// ============================================================================

// GetStats returns the DNS redirect handler statistics.
func (h *DNSRedirectHandler) GetStats() map[string]uint64 {
	return map[string]uint64{
		"redirects_attempted": h.stats.RedirectsAttempted.Load(),
		"redirects_succeeded": h.stats.RedirectsSucceeded.Load(),
		"redirects_failed":    h.stats.RedirectsFailed.Load(),
		"responses_injected":  h.stats.ResponsesInjected.Load(),
		"domain_cache_hits":   h.stats.DomainCacheHits.Load(),
		"domain_cache_misses": h.stats.DomainCacheMisses.Load(),
		"invalid_dns_queries": h.stats.InvalidDNSQueries.Load(),
		"protocol_mismatch":   h.stats.ProtocolMismatch.Load(),
		"active_redirects":    uint64(h.redirectCount.Load()),
	}
}

// Close shuts down the DNS redirect handler.
func (h *DNSRedirectHandler) Close() error {
	h.closed.Store(true)
	// Note: We keep redirect rules active for now
	// Caller can call ClearRedirects() if needed
	return nil
}

// SetVerdictEngine sets the verdict engine reference.
func (h *DNSRedirectHandler) SetVerdictEngine(engine DNSRedirectEngineInterface) {
	h.verdictEngine = engine
}

// GetConfig returns the current configuration.
func (h *DNSRedirectHandler) GetConfig() *DNSRedirectConfig {
	return h.config
}
