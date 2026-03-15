// Package domain provides domain-based filtering for the firewall engine.
// It loads domains from the config file (domains.txt), supports category blocking
// (social media, streaming, gaming, ads, trackers), integrates with threat intel
// domain cache, enforces CDN-aware verdicts (DNS→REDIRECT, SNI/HTTP→BLOCK),
// and returns protocol-aware results so SafeOps Engine can enforce correctly.
//
// Thread-safe for concurrent packet pipeline access.
package domain

import (
	"bufio"
	"errors"
	"fmt"
	"os"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"firewall_engine/internal/alerting"
	"firewall_engine/internal/rules"
	"firewall_engine/internal/threatintel"
)

// ============================================================================
// Error types
// ============================================================================

var (
	// ErrFilterNotInitialized indicates the filter was not properly created.
	ErrFilterNotInitialized = errors.New("domain filter not initialized")

	// ErrNilAlertManager indicates the alert manager was nil during init.
	ErrNilAlertManager = errors.New("alert manager is nil")

	// ErrDomainFileUnreadable indicates the domains.txt file could not be read.
	ErrDomainFileUnreadable = errors.New("domains file is unreadable")
)

// ============================================================================
// Verdict actions
// ============================================================================

// VerdictAction tells SafeOps Engine how to enforce a domain block.
type VerdictAction int

const (
	ActionAllow    VerdictAction = iota // No action, domain is clean
	ActionRedirect                      // DNS query → respond with redirect IP (127.0.0.1)
	ActionBlock                         // TLS SNI / HTTP → TCP RST
	ActionDrop                          // Silent drop (unknown protocol)
)

func (a VerdictAction) String() string {
	switch a {
	case ActionAllow:
		return "ALLOW"
	case ActionRedirect:
		return "REDIRECT"
	case ActionBlock:
		return "BLOCK"
	case ActionDrop:
		return "DROP"
	default:
		return fmt.Sprintf("UNKNOWN(%d)", a)
	}
}

// ============================================================================
// Filter result
// ============================================================================

// FilterResult is returned when a domain check is performed.
type FilterResult struct {
	Blocked       bool          // true if domain should be blocked
	Domain        string        // normalized domain that was checked
	MatchedBy     string        // "config_list", "category:social_media", "threat_intel", "cdn_protected"
	Action        VerdictAction // protocol-aware enforcement action
	Category      string        // category name if matched by category
	ThreatScore   int           // threat intel score (0-100), only set for threat intel matches
	IsCDN         bool          // true if domain belongs to a CDN (affects enforcement strategy)
	CDNProvider   string        // CDN provider name if IsCDN is true
	DomainSource  string        // the protocol source ("DNS", "SNI", "HTTP") that detected this domain
}

// ============================================================================
// Filter stats
// ============================================================================

// FilterStats holds domain filter statistics.
type FilterStats struct {
	ConfigDomains    int   `json:"config_domains"`
	CategoriesActive int   `json:"categories_active"`
	CDNProviders     int   `json:"cdn_providers"`
	ThreatIntelAvail bool  `json:"threat_intel_available"`
	TotalChecks      int64 `json:"total_checks"`
	TotalBlocks      int64 `json:"total_blocks"`
	DNSBlocks        int64 `json:"dns_blocks"`
	SNIBlocks        int64 `json:"sni_blocks"`
	HTTPBlocks       int64 `json:"http_blocks"`
	ThreatIntelHits  int64 `json:"threat_intel_hits"`
	CDNProtected     int64 `json:"cdn_protected"`
	ConfigListHits   int64 `json:"config_list_hits"`
	CategoryHits     int64 `json:"category_hits"`
	AutoBlockedCount int64 `json:"auto_blocked_count"`
	VisitThreshold   int64 `json:"visit_threshold"`
	Errors           int64 `json:"errors"`
}

// ============================================================================
// Auto-block tracking types
// ============================================================================

// autoBlockEntry holds internal state for a runtime-auto-blocked domain.
type autoBlockEntry struct {
	Domain      string    `json:"domain"`
	VisitCount  int64     `json:"visit_count"`
	BlockedAt   time.Time `json:"blocked_at"`
	ThreatScore int       `json:"threat_score"`
	Source      string    `json:"source"` // DNS / SNI / HTTP
}

// AutoBlockEntry is the public view exposed via API and GetAutoBlockedDomains().
type AutoBlockEntry struct {
	Domain      string    `json:"domain"`
	VisitCount  int64     `json:"visit_count"`
	BlockedAt   time.Time `json:"blocked_at"`
	ThreatScore int       `json:"threat_score"`
	Source      string    `json:"source"`
}

// MaliciousVisitEntry describes a threat-intel-flagged domain and its visit count.
type MaliciousVisitEntry struct {
	Domain      string `json:"domain"`
	VisitCount  int64  `json:"visit_count"`
	AutoBlocked bool   `json:"auto_blocked"`
	ThreatScore int    `json:"threat_score"`
}

// ============================================================================
// Filter
// ============================================================================

// Filter checks domains against config blocklist, categories, threat intel,
// and CDN allowlist. It returns protocol-aware enforcement actions.
//
// Check pipeline order:
//  1. CDN check (if CDN, restrict to DNS redirect only — never IP block)
//  2. Config file blocklist (domains.txt)
//  3. Category blocklists (social_media, ads, trackers, etc.)
//  4. Threat intel database cache (malicious domains)
//
// Thread-safe: all lookups use RWMutex for config data, atomics for stats.
type Filter struct {
	alertMgr *alerting.Manager

	// Config file domain matcher (from domains.txt)
	configMatcher *rules.DomainMatcher
	configMu      sync.RWMutex
	configPath    string
	configLoaded  atomic.Bool // true if domains.txt was loaded at least once

	// Category matchers (from detection config / web UI)
	categoryMatchers map[string]*rules.DomainMatcher
	categoryMu       sync.RWMutex

	// CDN allowlist (prevents collateral IP blocking)
	cdnAllowlist *CDNAllowlist

	// Threat intel integration (nil if threat intel DB is unavailable)
	threatDecision *threatintel.Decision
	threatMu       sync.RWMutex

	// Malicious visit tracking and auto-block (threat intel domain escalation)
	// maliciousVisits: domain → *atomic.Int64 (visit counter)
	// autoBlocked: domain → autoBlockEntry (promoted to config blocklist)
	maliciousVisits  sync.Map     // domain → *atomic.Int64
	autoBlocked      sync.Map     // domain → autoBlockEntry
	visitThreshold   atomic.Int64 // 0 = disabled; default 10

	// Stats (all atomic for lock-free hot-path access)
	totalChecks      atomic.Int64
	totalBlocks      atomic.Int64
	dnsBlocks        atomic.Int64
	sniBlocks        atomic.Int64
	httpBlocks       atomic.Int64
	threatIntelHits  atomic.Int64
	cdnProtected     atomic.Int64
	configListHits   atomic.Int64
	categoryHits     atomic.Int64
	autoBlockedCount atomic.Int64
	errors           atomic.Int64

	// Lifecycle
	initialized atomic.Bool
	lastReload  atomic.Value // stores time.Time of last successful reload
}

// NewFilter creates a new domain filter.
//
// Parameters:
//   - domainsFilePath: path to domains.txt config file. If empty or file
//     doesn't exist, the filter starts with an empty blocklist (no error).
//   - blockedCategories: list of category names to block (e.g., ["ads", "trackers"]).
//     Unknown categories are silently skipped.
//   - alertMgr: alert manager for firing DOMAIN_BLOCK alerts. May be nil (alerts disabled).
//
// The CDN allowlist is always initialized with default providers.
// Threat intel is not connected at creation time; call SetThreatDecision() separately.
func NewFilter(domainsFilePath string, blockedCategories []string, alertMgr *alerting.Manager) (*Filter, error) {
	f := &Filter{
		alertMgr:         alertMgr,
		configPath:       domainsFilePath,
		categoryMatchers: make(map[string]*rules.DomainMatcher),
		cdnAllowlist:     NewCDNAllowlist(),
	}
	f.visitThreshold.Store(10) // default: auto-block after 10 malicious visits

	// Load config domains (non-fatal if file missing)
	if loadErr := f.loadConfigDomains(domainsFilePath); loadErr != nil {
		// File doesn't exist = OK (empty blocklist). Other errors are warnings.
		if !os.IsNotExist(loadErr) && !errors.Is(loadErr, ErrDomainFileUnreadable) {
			f.errors.Add(1)
			return nil, fmt.Errorf("failed to load domains file %q: %w", domainsFilePath, loadErr)
		}
		// File missing — initialize empty matcher
		f.configMu.Lock()
		f.configMatcher = rules.NewDomainMatcher(nil)
		f.configMu.Unlock()
	}

	// Build category matchers (skip unknown categories gracefully)
	validCategories := 0
	for _, cat := range blockedCategories {
		cat = strings.TrimSpace(strings.ToLower(cat))
		if cat == "" {
			continue
		}
		patterns := rules.GetCategoryPatterns(cat)
		if len(patterns) == 0 {
			// Unknown category — skip silently (user might have a typo)
			continue
		}
		f.categoryMatchers[cat] = rules.NewDomainMatcher(patterns)
		validCategories++
	}

	f.lastReload.Store(time.Now())
	f.initialized.Store(true)

	return f, nil
}

// ============================================================================
// Core check pipeline
// ============================================================================

// Check checks a domain against all blocklists and threat intel.
//
// Pipeline order:
//  1. Empty domain → immediate ALLOW (no-op)
//  2. CDN detection (flags domain for DNS-only enforcement)
//  3. Config file blocklist (domains.txt)
//  4. Category blocklists
//  5. Threat intel cache
//
// Parameters:
//   - domain: the domain name extracted from the packet (e.g., "evil.com")
//   - domainSource: protocol that extracted it ("DNS", "SNI", "HTTP", or "")
//
// Returns FilterResult with blocking decision and enforcement action.
// Thread-safe for concurrent calls from multiple worker goroutines.
func (f *Filter) Check(domain, domainSource string) FilterResult {
	// Guard: filter not initialized
	if !f.initialized.Load() {
		f.errors.Add(1)
		return FilterResult{}
	}

	// Guard: empty domain — nothing to check
	if domain == "" {
		return FilterResult{}
	}

	f.totalChecks.Add(1)
	domain = rules.NormalizeDomain(domain)

	// Guard: domain still empty after normalization (was all whitespace/dots)
	if domain == "" {
		return FilterResult{}
	}

	// Step 1: CDN detection — determines enforcement strategy
	cdnResult := f.cdnAllowlist.Check(domain)

	// Step 2: Config file blocklist (domains.txt)
	f.configMu.RLock()
	configMatch := f.configMatcher != nil && f.configMatcher.Match(domain)
	f.configMu.RUnlock()

	if configMatch {
		f.configListHits.Add(1)
		action := f.resolveAction(domainSource, cdnResult.IsCDN)
		f.recordBlock(domainSource)

		if cdnResult.IsCDN {
			f.cdnProtected.Add(1)
		}

		f.fireConfigAlert(domain, domainSource, cdnResult)
		return FilterResult{
			Blocked:      true,
			Domain:       domain,
			MatchedBy:    "config_list",
			Action:       action,
			IsCDN:        cdnResult.IsCDN,
			CDNProvider:  cdnResult.Provider,
			DomainSource: domainSource,
		}
	}

	// Step 3: Category blocklists
	f.categoryMu.RLock()
	for cat, matcher := range f.categoryMatchers {
		if matcher.Match(domain) {
			f.categoryMu.RUnlock()

			f.categoryHits.Add(1)
			action := f.resolveAction(domainSource, cdnResult.IsCDN)
			f.recordBlock(domainSource)

			if cdnResult.IsCDN {
				f.cdnProtected.Add(1)
			}

			f.fireCategoryAlert(domain, domainSource, cat, cdnResult)
			return FilterResult{
				Blocked:      true,
				Domain:       domain,
				MatchedBy:    "category:" + cat,
				Action:       action,
				Category:     cat,
				IsCDN:        cdnResult.IsCDN,
				CDNProvider:  cdnResult.Provider,
				DomainSource: domainSource,
			}
		}
	}
	f.categoryMu.RUnlock()

	// Step 4: Threat intel database cache
	// Visits 1 to (threshold-1) → ALERT ONLY (security team review).
	// At threshold → AUTO-BLOCK: domain promoted to runtime config blocklist.
	// If threshold is 0 (disabled) → always alert-only regardless of visit count.
	f.threatMu.RLock()
	td := f.threatDecision
	f.threatMu.RUnlock()

	if td != nil {
		threatResult := td.CheckDomain(domain)
		if threatResult != nil && threatResult.IsBlocked {
			f.threatIntelHits.Add(1)

			// Track visit and potentially auto-block
			if blocked, result := f.trackMaliciousVisit(domain, domainSource, cdnResult, threatResult.ThreatScore); blocked {
				return result
			}

			// Under threshold (or threshold disabled) — alert only, no verdict sent
			return FilterResult{
				Blocked:      false,
				Domain:       domain,
				MatchedBy:    "threat_intel_alert",
				ThreatScore:  threatResult.ThreatScore,
				IsCDN:        cdnResult.IsCDN,
				CDNProvider:  cdnResult.Provider,
				DomainSource: domainSource,
			}
		}
	}

	// Domain is clean
	return FilterResult{
		Domain:       domain,
		DomainSource: domainSource,
	}
}

// CheckDomainOnly checks a domain without threat intel (config list + categories only).
// Useful when threat intel has already been checked separately in the pipeline.
func (f *Filter) CheckDomainOnly(domain, domainSource string) FilterResult {
	if !f.initialized.Load() || domain == "" {
		return FilterResult{}
	}

	f.totalChecks.Add(1)
	domain = rules.NormalizeDomain(domain)
	if domain == "" {
		return FilterResult{}
	}

	cdnResult := f.cdnAllowlist.Check(domain)

	// Config file blocklist
	f.configMu.RLock()
	configMatch := f.configMatcher != nil && f.configMatcher.Match(domain)
	f.configMu.RUnlock()

	if configMatch {
		f.configListHits.Add(1)
		action := f.resolveAction(domainSource, cdnResult.IsCDN)
		f.recordBlock(domainSource)
		if cdnResult.IsCDN {
			f.cdnProtected.Add(1)
		}
		f.fireConfigAlert(domain, domainSource, cdnResult)
		return FilterResult{
			Blocked:      true,
			Domain:       domain,
			MatchedBy:    "config_list",
			Action:       action,
			IsCDN:        cdnResult.IsCDN,
			CDNProvider:  cdnResult.Provider,
			DomainSource: domainSource,
		}
	}

	// Category blocklists
	f.categoryMu.RLock()
	for cat, matcher := range f.categoryMatchers {
		if matcher.Match(domain) {
			f.categoryMu.RUnlock()
			f.categoryHits.Add(1)
			action := f.resolveAction(domainSource, cdnResult.IsCDN)
			f.recordBlock(domainSource)
			if cdnResult.IsCDN {
				f.cdnProtected.Add(1)
			}
			f.fireCategoryAlert(domain, domainSource, cat, cdnResult)
			return FilterResult{
				Blocked:      true,
				Domain:       domain,
				MatchedBy:    "category:" + cat,
				Action:       action,
				Category:     cat,
				IsCDN:        cdnResult.IsCDN,
				CDNProvider:  cdnResult.Provider,
				DomainSource: domainSource,
			}
		}
	}
	f.categoryMu.RUnlock()

	return FilterResult{Domain: domain, DomainSource: domainSource}
}

// ============================================================================
// Configuration management
// ============================================================================

// Reload reloads the domains.txt file from disk.
// Called by hot-reload file watcher when domains.txt changes.
// Returns nil on success, error on failure (old data is preserved on error).
func (f *Filter) Reload() error {
	if !f.initialized.Load() {
		return ErrFilterNotInitialized
	}

	if err := f.loadConfigDomains(f.configPath); err != nil {
		f.errors.Add(1)
		return fmt.Errorf("domain filter reload failed for %q: %w", f.configPath, err)
	}

	f.lastReload.Store(time.Now())
	return nil
}

// SetBlockedCategories updates which categories are blocked at runtime.
// Unknown category names are silently skipped.
// Thread-safe; takes effect immediately for subsequent Check() calls.
func (f *Filter) SetBlockedCategories(categories []string) {
	if !f.initialized.Load() {
		return
	}

	newMatchers := make(map[string]*rules.DomainMatcher)
	for _, cat := range categories {
		cat = strings.TrimSpace(strings.ToLower(cat))
		if cat == "" {
			continue
		}
		patterns := rules.GetCategoryPatterns(cat)
		if len(patterns) > 0 {
			newMatchers[cat] = rules.NewDomainMatcher(patterns)
		}
	}

	f.categoryMu.Lock()
	f.categoryMatchers = newMatchers
	f.categoryMu.Unlock()
}

// AddDomain adds a domain to the config blocklist at runtime.
// The domain is auto-wildcarded: "evil.com" also blocks "*.evil.com".
// Thread-safe; takes effect immediately for subsequent Check() calls.
func (f *Filter) AddDomain(domain string) error {
	if !f.initialized.Load() {
		return ErrFilterNotInitialized
	}

	domain = strings.TrimSpace(strings.ToLower(domain))
	if domain == "" {
		return fmt.Errorf("cannot add empty domain")
	}

	f.configMu.Lock()
	defer f.configMu.Unlock()

	if f.configMatcher == nil {
		f.configMatcher = rules.NewDomainMatcher(nil)
	}

	// Add exact + wildcard (same logic as loadConfigDomains)
	f.configMatcher.AddPattern(domain)
	if !strings.HasPrefix(domain, "*.") && !strings.Contains(domain, "*") {
		f.configMatcher.AddPattern("*." + domain)
	}

	return nil
}

// RemoveDomain is a no-op placeholder. DomainMatcher doesn't support removal;
// to remove a domain, edit domains.txt and call Reload().
// Returns an error explaining this limitation.
func (f *Filter) RemoveDomain(domain string) error {
	return fmt.Errorf("domain removal requires editing domains.txt and calling Reload(); "+
		"in-memory removal not supported (domain: %q)", domain)
}

// SetThreatDecision connects the threat intel decision engine.
// If decision is nil, threat intel checks are disabled.
// Thread-safe; can be called at any time.
func (f *Filter) SetThreatDecision(decision *threatintel.Decision) {
	f.threatMu.Lock()
	f.threatDecision = decision
	f.threatMu.Unlock()
}

// GetCDNAllowlist returns the CDN allowlist for external use (e.g., by main.go
// to check if an IP block should be suppressed for CDN domains).
func (f *Filter) GetCDNAllowlist() *CDNAllowlist {
	return f.cdnAllowlist
}

// ============================================================================
// Statistics
// ============================================================================

// Stats returns domain filter statistics. Thread-safe.
func (f *Filter) Stats() FilterStats {
	configCount := 0
	f.configMu.RLock()
	if f.configMatcher != nil {
		configCount = f.configMatcher.Count()
	}
	f.configMu.RUnlock()

	f.categoryMu.RLock()
	catCount := len(f.categoryMatchers)
	f.categoryMu.RUnlock()

	f.threatMu.RLock()
	hasThreat := f.threatDecision != nil
	f.threatMu.RUnlock()

	return FilterStats{
		ConfigDomains:    configCount,
		CategoriesActive: catCount,
		CDNProviders:     f.cdnAllowlist.ProviderCount(),
		ThreatIntelAvail: hasThreat,
		TotalChecks:      f.totalChecks.Load(),
		TotalBlocks:      f.totalBlocks.Load(),
		DNSBlocks:        f.dnsBlocks.Load(),
		SNIBlocks:        f.sniBlocks.Load(),
		HTTPBlocks:       f.httpBlocks.Load(),
		ThreatIntelHits:  f.threatIntelHits.Load(),
		CDNProtected:     f.cdnProtected.Load(),
		ConfigListHits:   f.configListHits.Load(),
		CategoryHits:     f.categoryHits.Load(),
		AutoBlockedCount: f.autoBlockedCount.Load(),
		VisitThreshold:   f.visitThreshold.Load(),
		Errors:           f.errors.Load(),
	}
}

// LastReload returns the time of the last successful config reload.
func (f *Filter) LastReload() time.Time {
	if v := f.lastReload.Load(); v != nil {
		return v.(time.Time)
	}
	return time.Time{}
}

// GetAllBlockedDomains returns all domains from the config blocklist.
// This is used by BlocklistSync to push domains to SafeOps Engine.
// Note: threat intel domains are ALERT ONLY and not included here.
func (f *Filter) GetAllBlockedDomains() []string {
	f.configMu.RLock()
	defer f.configMu.RUnlock()

	if f.configMatcher == nil {
		return nil
	}

	return f.configMatcher.GetExactDomains()
}

// ============================================================================
// Internal helpers
// ============================================================================

// loadConfigDomains parses domains.txt into a DomainMatcher.
// If the file doesn't exist, returns nil (empty matcher is created).
// The old matcher is only replaced on successful parse (atomic swap).
func (f *Filter) loadConfigDomains(path string) error {
	if path == "" {
		// No domains file configured — create empty matcher
		f.configMu.Lock()
		f.configMatcher = rules.NewDomainMatcher(nil)
		f.configLoaded.Store(true)
		f.configMu.Unlock()
		return nil
	}

	file, err := os.Open(path)
	if err != nil {
		if os.IsNotExist(err) {
			// File doesn't exist — empty matcher, not an error
			f.configMu.Lock()
			f.configMatcher = rules.NewDomainMatcher(nil)
			f.configLoaded.Store(true)
			f.configMu.Unlock()
			return nil
		}
		return fmt.Errorf("%w: %v", ErrDomainFileUnreadable, err)
	}
	defer file.Close()

	// Validate file is readable (stat check)
	info, err := file.Stat()
	if err != nil {
		return fmt.Errorf("cannot stat domains file: %w", err)
	}
	if info.IsDir() {
		return fmt.Errorf("domains path is a directory, not a file: %s", path)
	}

	var patterns []string
	var lineNum int
	var parseErrors int

	scanner := bufio.NewScanner(file)
	// Increase scanner buffer for very long lines (shouldn't happen, but defensive)
	scanner.Buffer(make([]byte, 0, 64*1024), 256*1024)

	for scanner.Scan() {
		lineNum++
		line := strings.TrimSpace(scanner.Text())

		// Skip empty lines and comments
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, "//") {
			continue
		}

		// Basic domain validation: must contain at least one dot, no spaces
		if strings.ContainsAny(line, " \t\r") {
			parseErrors++
			continue
		}

		// Sanitize: remove any trailing dots, lowercase
		line = strings.ToLower(line)
		line = strings.TrimSuffix(line, ".")

		if line == "" {
			continue
		}

		// Auto-wildcard: blocking "evil.com" also blocks "*.evil.com"
		if !strings.HasPrefix(line, "*.") && !strings.Contains(line, "*") {
			patterns = append(patterns, line)
			patterns = append(patterns, "*."+line)
		} else {
			patterns = append(patterns, line)
		}
	}

	if err := scanner.Err(); err != nil {
		return fmt.Errorf("error reading domains file at line %d: %w", lineNum, err)
	}

	// Build new matcher and swap atomically
	newMatcher := rules.NewDomainMatcher(patterns)

	f.configMu.Lock()
	f.configMatcher = newMatcher
	f.configLoaded.Store(true)
	f.configMu.Unlock()

	return nil
}

// resolveAction determines the enforcement action based on the protocol source
// and whether the domain belongs to a CDN.
//
// CDN domains are ALWAYS restricted to DNS redirect (ActionRedirect) regardless
// of protocol, because blocking CDN IPs via RST causes collateral damage to
// thousands of unrelated sites sharing the same CDN IP.
func (f *Filter) resolveAction(domainSource string, isCDN bool) VerdictAction {
	if isCDN {
		// CDN domains: ONLY use DNS redirect. Never send RST to CDN IPs.
		// If the packet is not a DNS query (i.e., SNI/HTTP), we still block
		// but must use REDIRECT so SafeOps Engine handles it at DNS level
		// on subsequent requests.
		return ActionRedirect
	}

	// Non-CDN domains: protocol-aware enforcement
	switch strings.ToUpper(domainSource) {
	case "DNS":
		return ActionRedirect // DNS → redirect to 127.0.0.1
	case "SNI":
		return ActionBlock // TLS → TCP RST
	case "HTTP":
		return ActionBlock // HTTP → block page + RST
	default:
		return ActionDrop // Unknown protocol → silent drop
	}
}

// recordBlock increments per-protocol block counters.
func (f *Filter) recordBlock(domainSource string) {
	f.totalBlocks.Add(1)
	switch strings.ToUpper(domainSource) {
	case "DNS":
		f.dnsBlocks.Add(1)
	case "SNI":
		f.sniBlocks.Add(1)
	case "HTTP":
		f.httpBlocks.Add(1)
	}
}

// ============================================================================
// Alert firing
// ============================================================================

// fireConfigAlert fires a DOMAIN_BLOCK alert for config list matches.
func (f *Filter) fireConfigAlert(domain, source string, cdn CDNCheckResult) {
	if f.alertMgr == nil {
		return
	}

	action := f.resolveAction(source, cdn.IsCDN)
	severity := alerting.SeverityMedium
	actionStr := actionToAlertAction(action)

	details := fmt.Sprintf("Domain blocked (config_list): %s via %s → %s", domain, source, action)
	if cdn.IsCDN {
		details = fmt.Sprintf("Domain blocked (config_list, CDN: %s): %s via %s → %s (DNS-only enforcement)",
			cdn.Provider, domain, source, action)
	}

	builder := alerting.NewAlert(alerting.AlertDomainBlock, severity).
		WithDomain(domain).
		WithDetails(details).
		WithAction(actionStr).
		WithMeta("domain_source", source).
		WithMeta("matched_by", "config_list")

	if cdn.IsCDN {
		builder = builder.
			WithMeta("is_cdn", "true").
			WithMeta("cdn_provider", cdn.Provider)
	}

	f.alertMgr.Alert(builder.Build())
}

// fireCategoryAlert fires a DOMAIN_BLOCK alert for category matches.
func (f *Filter) fireCategoryAlert(domain, source, category string, cdn CDNCheckResult) {
	if f.alertMgr == nil {
		return
	}

	action := f.resolveAction(source, cdn.IsCDN)
	severity := alerting.SeverityLow // Category blocks are policy, not threats
	actionStr := actionToAlertAction(action)

	details := fmt.Sprintf("Domain blocked (category:%s): %s via %s → %s", category, domain, source, action)
	if cdn.IsCDN {
		details = fmt.Sprintf("Domain blocked (category:%s, CDN: %s): %s via %s → %s (DNS-only enforcement)",
			category, cdn.Provider, domain, source, action)
	}

	builder := alerting.NewAlert(alerting.AlertDomainBlock, severity).
		WithDomain(domain).
		WithDetails(details).
		WithAction(actionStr).
		WithMeta("domain_source", source).
		WithMeta("matched_by", "category:"+category).
		WithMeta("category", category)

	if cdn.IsCDN {
		builder = builder.
			WithMeta("is_cdn", "true").
			WithMeta("cdn_provider", cdn.Provider)
	}

	f.alertMgr.Alert(builder.Build())
}

// fireCDNThreatAlert fires an additional alert when a threat intel domain
// also belongs to a CDN (noteworthy because enforcement is restricted).
func (f *Filter) fireCDNThreatAlert(domain, source string, cdn CDNCheckResult, threatScore int) {
	if f.alertMgr == nil {
		return
	}

	severity := alerting.SeverityHigh
	if threatScore >= 90 {
		severity = alerting.SeverityCritical
	}

	details := fmt.Sprintf("Threat intel domain on CDN (%s): %s (score=%d) — enforcement restricted to DNS redirect only",
		cdn.Provider, domain, threatScore)

	builder := alerting.NewAlert(alerting.AlertDomainBlock, severity).
		WithDomain(domain).
		WithDetails(details).
		WithThreatScore(float64(threatScore)).
		WithAction(alerting.ActionRedirected).
		WithMeta("domain_source", source).
		WithMeta("matched_by", "threat_intel").
		WithMeta("is_cdn", "true").
		WithMeta("cdn_provider", cdn.Provider).
		WithMeta("cdn_restricted", "true")

	f.alertMgr.Alert(builder.Build())
}

// fireThreatIntelAlert fires an alert-only event for threat intel domain hits.
// The domain is NOT blocked — security team must review and manually add to
// config blocklist or use control API. Alert severity scales with threat score.
func (f *Filter) fireThreatIntelAlert(domain, source string, cdn CDNCheckResult, threatScore int) {
	if f.alertMgr == nil {
		return
	}

	severity := alerting.SeverityMedium
	if threatScore >= 80 {
		severity = alerting.SeverityHigh
	}
	if threatScore >= 95 {
		severity = alerting.SeverityCritical
	}

	details := fmt.Sprintf("Threat intel alert (NOT blocked): %s (score=%d, source=%s) — review required",
		domain, threatScore, source)
	if cdn.IsCDN {
		details = fmt.Sprintf("Threat intel alert (NOT blocked, CDN: %s): %s (score=%d, source=%s) — review required",
			cdn.Provider, domain, threatScore, source)
	}

	builder := alerting.NewAlert(alerting.AlertDomainBlock, severity).
		WithDomain(domain).
		WithDetails(details).
		WithThreatScore(float64(threatScore)).
		WithAction(alerting.ActionLogged).
		WithMeta("domain_source", source).
		WithMeta("matched_by", "threat_intel").
		WithMeta("auto_blocked", "false").
		WithMeta("review_required", "true")

	if cdn.IsCDN {
		builder = builder.
			WithMeta("is_cdn", "true").
			WithMeta("cdn_provider", cdn.Provider)
	}

	f.alertMgr.Alert(builder.Build())
}

// ============================================================================
// Malicious visit tracking and auto-block
// ============================================================================

// trackMaliciousVisit increments the visit counter for a threat-intel-flagged domain.
// If the counter reaches the visit threshold, the domain is auto-blocked (promoted
// to the runtime config blocklist in-memory). Returns (true, result) when the domain
// should be blocked, (false, {}) when it is still alert-only.
//
// Thread-safe: uses sync.Map atomic operations for counters.
func (f *Filter) trackMaliciousVisit(domain, domainSource string, cdn CDNCheckResult, threatScore int) (bool, FilterResult) {
	threshold := f.visitThreshold.Load()

	// Already in autoBlocked set? The domain is in configMatcher on subsequent calls
	// (from when it was promoted), but this covers the rare race where autoBlocked is
	// set but configMatcher hasn't been updated yet.
	if entry, alreadyBlocked := f.autoBlocked.Load(domain); alreadyBlocked {
		ae := entry.(autoBlockEntry)
		action := f.resolveAction(domainSource, cdn.IsCDN)
		f.recordBlock(domainSource)
		return true, FilterResult{
			Blocked:      true,
			Domain:       domain,
			MatchedBy:    "auto_blocked_threat_intel",
			Action:       action,
			ThreatScore:  ae.ThreatScore,
			IsCDN:        cdn.IsCDN,
			CDNProvider:  cdn.Provider,
			DomainSource: domainSource,
		}
	}

	// Load or create atomic counter for this domain
	counterIface, _ := f.maliciousVisits.LoadOrStore(domain, new(atomic.Int64))
	counter := counterIface.(*atomic.Int64)
	count := counter.Add(1)

	// threshold == 0 means disabled (alert-only forever)
	if threshold <= 0 || count < threshold {
		// Under threshold — fire standard alert, do not block
		f.fireThreatIntelAlert(domain, domainSource, cdn, threatScore)
		return false, FilterResult{}
	}

	// Reached threshold — auto-block this domain
	entry := autoBlockEntry{
		Domain:      domain,
		VisitCount:  count,
		BlockedAt:   time.Now(),
		ThreatScore: threatScore,
		Source:      domainSource,
	}

	// Store in autoBlocked set (idempotent: LoadOrStore prevents double-blocking)
	if _, existed := f.autoBlocked.LoadOrStore(domain, entry); !existed {
		// We won the race — actually add to configMatcher
		_ = f.AddDomain(domain) // also adds wildcard *.domain
		f.autoBlockedCount.Add(1)
		f.fireAutoBlockAlert(domain, domainSource, cdn, threatScore, count, threshold)
	}

	action := f.resolveAction(domainSource, cdn.IsCDN)
	f.recordBlock(domainSource)
	return true, FilterResult{
		Blocked:      true,
		Domain:       domain,
		MatchedBy:    "auto_blocked_threat_intel",
		Action:       action,
		ThreatScore:  threatScore,
		IsCDN:        cdn.IsCDN,
		CDNProvider:  cdn.Provider,
		DomainSource: domainSource,
	}
}

// SetVisitThreshold sets the malicious-visit auto-block threshold at runtime.
// 0 disables auto-blocking (alert-only mode).
// Thread-safe.
func (f *Filter) SetVisitThreshold(threshold int64) {
	if threshold < 0 {
		threshold = 0
	}
	f.visitThreshold.Store(threshold)
}

// GetVisitThreshold returns the current auto-block threshold. 0 = disabled.
func (f *Filter) GetVisitThreshold() int64 {
	return f.visitThreshold.Load()
}

// GetAutoBlockedDomains returns all domains that have been auto-blocked due to
// exceeding the malicious visit threshold. Sorted by blocked_at descending.
func (f *Filter) GetAutoBlockedDomains() []AutoBlockEntry {
	var entries []AutoBlockEntry
	f.autoBlocked.Range(func(k, v interface{}) bool {
		ae := v.(autoBlockEntry)
		entries = append(entries, AutoBlockEntry{
			Domain:      ae.Domain,
			VisitCount:  ae.VisitCount,
			BlockedAt:   ae.BlockedAt,
			ThreatScore: ae.ThreatScore,
			Source:      ae.Source,
		})
		return true
	})
	sort.Slice(entries, func(i, j int) bool {
		return entries[i].BlockedAt.After(entries[j].BlockedAt)
	})
	return entries
}

// GetMaliciousVisitCounts returns all domains that have been seen by threat intel,
// along with their visit counts and whether they are auto-blocked.
// Sorted by visit count descending.
func (f *Filter) GetMaliciousVisitCounts() []MaliciousVisitEntry {
	var entries []MaliciousVisitEntry
	f.maliciousVisits.Range(func(k, v interface{}) bool {
		domain := k.(string)
		count := v.(*atomic.Int64).Load()
		_, blocked := f.autoBlocked.Load(domain)
		entries = append(entries, MaliciousVisitEntry{
			Domain:      domain,
			VisitCount:  count,
			AutoBlocked: blocked,
		})
		return true
	})
	sort.Slice(entries, func(i, j int) bool {
		return entries[i].VisitCount > entries[j].VisitCount
	})
	return entries
}

// RemoveAutoBlock removes a domain from the auto-block set.
// The domain remains in configMatcher until the next Reload() is called.
// Use this to manually un-block a domain that was auto-blocked incorrectly.
// Thread-safe.
func (f *Filter) RemoveAutoBlock(domain string) {
	domain = strings.TrimSpace(strings.ToLower(domain))
	if domain == "" {
		return
	}
	f.autoBlocked.Delete(domain)
	// Also reset the visit counter so it starts fresh
	f.maliciousVisits.Delete(domain)
}

// ============================================================================
// Auto-block alert
// ============================================================================

// fireAutoBlockAlert fires a high-severity alert when a domain is auto-blocked.
func (f *Filter) fireAutoBlockAlert(domain, source string, cdn CDNCheckResult, threatScore int, visitCount, threshold int64) {
	if f.alertMgr == nil {
		return
	}

	severity := alerting.SeverityHigh
	if threatScore >= 80 {
		severity = alerting.SeverityCritical
	}

	details := fmt.Sprintf(
		"Domain AUTO-BLOCKED after %d malicious visits (threshold=%d): %s (threat_score=%d, source=%s)",
		visitCount, threshold, domain, threatScore, source,
	)
	if cdn.IsCDN {
		details = fmt.Sprintf(
			"Domain AUTO-BLOCKED after %d malicious visits (threshold=%d, CDN:%s): %s (threat_score=%d, source=%s) — DNS-only enforcement",
			visitCount, threshold, cdn.Provider, domain, threatScore, source,
		)
	}

	builder := alerting.NewAlert(alerting.AlertDomainBlock, severity).
		WithDomain(domain).
		WithDetails(details).
		WithThreatScore(float64(threatScore)).
		WithAction(alerting.ActionBlocked).
		WithMeta("domain_source", source).
		WithMeta("matched_by", "auto_blocked_threat_intel").
		WithMeta("visit_count", fmt.Sprintf("%d", visitCount)).
		WithMeta("threshold", fmt.Sprintf("%d", threshold)).
		WithMeta("auto_blocked", "true")

	if cdn.IsCDN {
		builder = builder.
			WithMeta("is_cdn", "true").
			WithMeta("cdn_provider", cdn.Provider)
	}

	f.alertMgr.Alert(builder.Build())
}

// actionToAlertAction maps VerdictAction to alerting.ActionTaken.
func actionToAlertAction(action VerdictAction) alerting.ActionTaken {
	switch action {
	case ActionRedirect:
		return alerting.ActionRedirected
	case ActionBlock:
		return alerting.ActionBlocked
	case ActionDrop:
		return alerting.ActionDropped
	default:
		return alerting.ActionLogged
	}
}
