package hotreload

import (
	"context"
	"fmt"
	"sync"
	"sync/atomic"
	"time"

	"firewall_engine/internal/alerting"
	"firewall_engine/internal/config"
	"firewall_engine/internal/domain"
	"firewall_engine/internal/geoip"
	"firewall_engine/internal/integration"
	"firewall_engine/internal/logging"
	"firewall_engine/internal/rules"
	"firewall_engine/internal/security"
)

// Reloader orchestrates hot-reload of all config files.
// It validates new configs before applying them and rolls back on error.
type Reloader struct {
	watcher   *Watcher
	logger    logging.Logger
	configDir string

	// Components that can be reloaded
	domainFilter  *domain.Filter
	geoChecker    *geoip.Checker
	securityMgr   *security.Manager
	alertMgr      *alerting.Manager
	ruleEngine    *rules.Engine
	blocklistSync *integration.BlocklistSync

	// Current parsed blocklist (atomic swap)
	parsedBlocklist atomic.Pointer[config.ParsedBlocklist]

	// Callback for main.go to receive updated ParsedBlocklist
	onBlocklistReload func(*config.ParsedBlocklist)

	// Stats
	successCount atomic.Int64
	failCount    atomic.Int64
	lastReload   atomic.Value // time.Time
	lastError    atomic.Value // string

	mu sync.RWMutex
}

// ReloaderConfig holds dependencies for the reloader.
type ReloaderConfig struct {
	ConfigDir    string
	Logger       logging.Logger
	AlertMgr     *alerting.Manager
	DomainFilter *domain.Filter
	GeoChecker   *geoip.Checker
	SecurityMgr  *security.Manager

	// Initial parsed blocklist
	InitialBlocklist *config.ParsedBlocklist

	// Called when blocklist.toml is reloaded with the new ParsedBlocklist.
	// The callback should update the packet handler's reference.
	OnBlocklistReload func(*config.ParsedBlocklist)

	// Rule engine for hot-reload of rules.toml
	RuleEngine *rules.Engine

	// BlocklistSync for pushing domain changes to SafeOps Engine
	BlocklistSync *integration.BlocklistSync
}

// NewReloader creates a hot-reload orchestrator.
func NewReloader(cfg ReloaderConfig) (*Reloader, error) {
	watcher, err := NewWatcher(cfg.Logger, 500*time.Millisecond)
	if err != nil {
		return nil, fmt.Errorf("create watcher: %w", err)
	}

	r := &Reloader{
		watcher:           watcher,
		logger:            cfg.Logger,
		configDir:         cfg.ConfigDir,
		domainFilter:      cfg.DomainFilter,
		geoChecker:        cfg.GeoChecker,
		securityMgr:       cfg.SecurityMgr,
		alertMgr:          cfg.AlertMgr,
		onBlocklistReload: cfg.OnBlocklistReload,
		ruleEngine:        cfg.RuleEngine,
		blocklistSync:     cfg.BlocklistSync,
	}

	if cfg.InitialBlocklist != nil {
		r.parsedBlocklist.Store(cfg.InitialBlocklist)
	}

	return r, nil
}

// Start registers file watchers and begins monitoring.
// Call this after all components are initialized.
func (r *Reloader) Start(ctx context.Context) error {
	// Register handlers for each config file
	files := map[string]FileChangeHandler{
		"domains.txt":           r.reloadDomains,
		"blocklist.toml":        r.reloadBlocklist,
		"geoip.toml":            r.reloadGeoIP,
		"detection.toml":        r.reloadDetection,
		"rules.toml":            r.reloadRules,
		"blocked_ips.txt":       r.reloadBlocklist, // IP file changes trigger full blocklist reload
		"whitelist_domains.txt": r.reloadBlocklist, // whitelist file changes trigger full blocklist reload
	}

	for filename, handler := range files {
		path := r.configDir + "/" + filename
		if err := r.watcher.Watch(path, handler); err != nil {
			r.logger.Warn().Str("file", filename).Err(err).Msg("Failed to watch config file")
			// Non-fatal: continue watching others
		}
	}

	// Run watcher in background
	go r.watcher.Start(ctx)

	r.logger.Info().
		Int("files", len(files)).
		Str("config_dir", r.configDir).
		Msg("Hot-reload started")

	return nil
}

// Stop shuts down the file watcher.
func (r *Reloader) Stop() error {
	return r.watcher.Close()
}

// GetParsedBlocklist returns the current ParsedBlocklist (thread-safe).
func (r *Reloader) GetParsedBlocklist() *config.ParsedBlocklist {
	return r.parsedBlocklist.Load()
}

// reloadDomains handles changes to domains.txt
func (r *Reloader) reloadDomains(path string) {
	r.mu.RLock()
	filter := r.domainFilter
	r.mu.RUnlock()

	if filter == nil {
		r.logger.Warn().Msg("Hot-reload: domain filter not initialized, skipping domains.txt reload")
		return
	}

	if err := filter.Reload(); err != nil {
		r.failCount.Add(1)
		r.lastError.Store(fmt.Sprintf("domains.txt: %v", err))
		r.logger.Error().Err(err).Msg("Hot-reload: domains.txt reload failed")

		r.fireAlert("domains.txt", false, err.Error())
		return
	}

	r.successCount.Add(1)
	r.lastReload.Store(time.Now())

	stats := filter.Stats()
	r.logger.Info().
		Int("domains", stats.ConfigDomains).
		Msg("Hot-reload: domains.txt reloaded successfully")

	// Push updated domain list to SafeOps Engine (in-process, zero-latency)
	if r.blocklistSync != nil {
		domains := filter.GetAllBlockedDomains()
		synced := r.blocklistSync.SyncDomains(domains)
		r.logger.Info().Int("synced", synced).Msg("Hot-reload: domain blocklist synced to SafeOps Engine")
	}

	r.fireAlert("domains.txt", true, fmt.Sprintf("%d domains loaded", stats.ConfigDomains))
}

// reloadBlocklist handles changes to blocklist.toml
func (r *Reloader) reloadBlocklist(path string) {
	// Step 1: Load and validate new config
	newBL, err := config.LoadBlocklistConfigFromFile(path)
	if err != nil {
		r.failCount.Add(1)
		r.lastError.Store(fmt.Sprintf("blocklist.toml: %v", err))
		r.logger.Error().Err(err).Msg("Hot-reload: blocklist.toml parse failed — keeping old config")
		r.fireAlert("blocklist.toml", false, err.Error())
		return
	}

	// Step 2: Parse into runtime structures (validates IPs, CIDRs, etc.)
	parsed, err := newBL.Parse(r.configDir)
	if err != nil {
		r.failCount.Add(1)
		r.lastError.Store(fmt.Sprintf("blocklist.toml validation: %v", err))
		r.logger.Error().Err(err).Msg("Hot-reload: blocklist.toml validation failed — keeping old config")
		r.fireAlert("blocklist.toml", false, err.Error())
		return
	}

	// Step 3: Atomic swap
	r.parsedBlocklist.Store(parsed)

	// Step 4: Update domain filter categories
	r.mu.RLock()
	filter := r.domainFilter
	r.mu.RUnlock()

	if filter != nil {
		filter.SetBlockedCategories(parsed.BlockedCategories)
		r.logger.Info().
			Strs("categories", parsed.BlockedCategories).
			Msg("Hot-reload: domain filter categories updated")

		// Re-sync domain blocklist to SafeOps Engine after category change
		if r.blocklistSync != nil {
			domains := filter.GetAllBlockedDomains()
			synced := r.blocklistSync.SyncDomains(domains)
			r.logger.Info().Int("synced", synced).Msg("Hot-reload: domain blocklist re-synced to SafeOps Engine (blocklist.toml change)")
		}
	}

	// Step 5: Update GeoIP extra countries/ASNs
	r.mu.RLock()
	geo := r.geoChecker
	r.mu.RUnlock()

	if geo != nil && (len(parsed.ExtraBlockedCountries) > 0 || len(parsed.ExtraBlockedASNs) > 0) {
		r.logger.Info().
			Int("extra_countries", len(parsed.ExtraBlockedCountries)).
			Int("extra_asns", len(parsed.ExtraBlockedASNs)).
			Msg("Hot-reload: GeoIP overrides updated from blocklist")
	}

	// Step 6: Notify main.go callback
	if r.onBlocklistReload != nil {
		r.onBlocklistReload(parsed)
	}

	r.successCount.Add(1)
	r.lastReload.Store(time.Now())
	r.logger.Info().
		Bool("domains_enabled", parsed.DomainsEnabled).
		Bool("ips_enabled", parsed.IPsEnabled).
		Bool("threat_intel", parsed.ThreatIntelEnabled).
		Bool("geo_enabled", parsed.GeoEnabled).
		Int("manual_ips", len(parsed.ManualIPs)).
		Int("whitelist_ips", len(parsed.WhitelistIPs)).
		Int("categories", len(parsed.BlockedCategories)).
		Msg("Hot-reload: blocklist.toml reloaded successfully")

	r.fireAlert("blocklist.toml", true, fmt.Sprintf(
		"domains=%v ips=%v threat_intel=%v geo=%v",
		parsed.DomainsEnabled, parsed.IPsEnabled, parsed.ThreatIntelEnabled, parsed.GeoEnabled))
}

// reloadGeoIP handles changes to geoip.toml
func (r *Reloader) reloadGeoIP(path string) {
	r.mu.RLock()
	geo := r.geoChecker
	r.mu.RUnlock()

	if geo == nil {
		r.logger.Warn().Msg("Hot-reload: GeoIP checker not initialized, skipping geoip.toml reload")
		return
	}

	// Load new config
	newGeo, err := config.LoadGeoIPConfigFromFile(path)
	if err != nil {
		r.failCount.Add(1)
		r.lastError.Store(fmt.Sprintf("geoip.toml: %v", err))
		r.logger.Error().Err(err).Msg("Hot-reload: geoip.toml parse failed — keeping old config")
		r.fireAlert("geoip.toml", false, err.Error())
		return
	}

	// Parse into runtime policy
	policy, err := newGeo.Parse()
	if err != nil {
		r.failCount.Add(1)
		r.lastError.Store(fmt.Sprintf("geoip.toml validation: %v", err))
		r.logger.Error().Err(err).Msg("Hot-reload: geoip.toml validation failed — keeping old config")
		r.fireAlert("geoip.toml", false, err.Error())
		return
	}

	// Merge extra countries/ASNs from current blocklist
	bl := r.parsedBlocklist.Load()
	if bl != nil {
		for _, cc := range bl.ExtraBlockedCountries {
			policy.Countries[cc] = true
		}
		for _, asn := range bl.ExtraBlockedASNs {
			policy.BlockedASNs[asn] = true
		}
	}

	// Apply — checker.UpdatePolicy is mutex-protected
	geo.UpdatePolicy(policy)

	r.successCount.Add(1)
	r.lastReload.Store(time.Now())

	stats := geo.Stats()
	r.logger.Info().
		Int("countries", stats.CountriesCount).
		Int("asns", stats.ASNsBlocked).
		Str("mode", stats.Mode).
		Msg("Hot-reload: geoip.toml reloaded successfully")

	r.fireAlert("geoip.toml", true, fmt.Sprintf(
		"mode=%s countries=%d asns=%d", stats.Mode, stats.CountriesCount, stats.ASNsBlocked))
}

// reloadDetection handles changes to detection.toml
func (r *Reloader) reloadDetection(path string) {
	r.mu.RLock()
	secMgr := r.securityMgr
	r.mu.RUnlock()

	if secMgr == nil {
		r.logger.Warn().Msg("Hot-reload: security manager not initialized, skipping detection.toml reload")
		return
	}

	// Load new config
	newDet, err := config.LoadDetectionConfigFromFile(path)
	if err != nil {
		r.failCount.Add(1)
		r.lastError.Store(fmt.Sprintf("detection.toml: %v", err))
		r.logger.Error().Err(err).Msg("Hot-reload: detection.toml parse failed — keeping old config")
		r.fireAlert("detection.toml", false, err.Error())
		return
	}

	// Apply new config to security manager
	secMgr.UpdateConfig(newDet)

	r.successCount.Add(1)
	r.lastReload.Store(time.Now())
	r.logger.Info().
		Bool("rate_limit", newDet.RateLimit.Enabled).
		Bool("ddos", newDet.DDoS.Enabled).
		Bool("brute_force", newDet.BruteForce.Enabled).
		Bool("port_scan", newDet.PortScan.Enabled).
		Msg("Hot-reload: detection.toml reloaded successfully")

	r.fireAlert("detection.toml", true, fmt.Sprintf(
		"rate_limit=%v ddos=%v brute_force=%v port_scan=%v",
		newDet.RateLimit.Enabled, newDet.DDoS.Enabled,
		newDet.BruteForce.Enabled, newDet.PortScan.Enabled))
}

// reloadRules handles changes to rules.toml
func (r *Reloader) reloadRules(path string) {
	if r.ruleEngine == nil {
		r.logger.Warn().Msg("Hot-reload: rule engine not initialized, skipping rules.toml reload")
		return
	}

	if err := r.ruleEngine.Reload(path); err != nil {
		r.failCount.Add(1)
		r.lastError.Store(fmt.Sprintf("rules.toml: %v", err))
		r.logger.Error().Err(err).Msg("Hot-reload: rules.toml reload failed — keeping old rules")
		r.fireAlert("rules.toml", false, err.Error())
		return
	}

	r.successCount.Add(1)
	r.lastReload.Store(time.Now())
	r.logger.Info().
		Int("rules", r.ruleEngine.RuleCount()).
		Msg("Hot-reload: rules.toml reloaded successfully")

	r.fireAlert("rules.toml", true, fmt.Sprintf("%d rules loaded", r.ruleEngine.RuleCount()))
}

// fireAlert sends a reload event as an alert.
func (r *Reloader) fireAlert(filename string, success bool, details string) {
	if r.alertMgr == nil {
		return
	}

	severity := alerting.SeverityInfo
	action := alerting.ActionLogged
	if !success {
		severity = alerting.SeverityHigh
	}

	builder := alerting.NewAlert(alerting.AlertConfigChange, severity).
		WithDetails(fmt.Sprintf("Hot-reload %s: %s — %s",
			map[bool]string{true: "SUCCESS", false: "FAILED"}[success],
			filename, details)).
		WithAction(action).
		WithMeta("config_file", filename).
		WithMeta("success", fmt.Sprintf("%v", success)).
		WithMeta("reload_count", fmt.Sprintf("%d", r.successCount.Load()+r.failCount.Load()))

	r.alertMgr.Alert(builder.Build())
}

// Stats returns reload statistics.
func (r *Reloader) Stats() ReloaderStats {
	var lastReload time.Time
	if v := r.lastReload.Load(); v != nil {
		lastReload = v.(time.Time)
	}
	var lastErr string
	if v := r.lastError.Load(); v != nil {
		lastErr = v.(string)
	}

	return ReloaderStats{
		Successes:   r.successCount.Load(),
		Failures:    r.failCount.Load(),
		LastReload:  lastReload,
		LastError:   lastErr,
		Watcher:     r.watcher.Stats(),
	}
}

// ReloaderStats holds reload statistics.
type ReloaderStats struct {
	Successes  int64        `json:"successes"`
	Failures   int64        `json:"failures"`
	LastReload time.Time    `json:"last_reload"`
	LastError  string       `json:"last_error,omitempty"`
	Watcher    WatcherStats `json:"watcher"`
}
