// Package main is the entry point for the SafeOps Firewall Engine.
// All configuration is loaded from configs/ directory (soft-coded path resolution).
package main

import (
	"context"
	"fmt"
	"log"
	"os"
	"os/signal"
	"strings"
	"sync/atomic"
	"syscall"
	"time"

	"firewall_engine/internal/alerting"
	"firewall_engine/internal/cache"
	"firewall_engine/internal/config"
	"firewall_engine/internal/connection"
	"firewall_engine/internal/domain"
	"firewall_engine/internal/enforcement"
	"firewall_engine/internal/geoip"
	"firewall_engine/internal/health"
	"firewall_engine/internal/hotreload"
	"firewall_engine/internal/inspector"
	"firewall_engine/internal/integration"
	"firewall_engine/internal/logging"
	"firewall_engine/internal/metrics"
	"firewall_engine/internal/objects"
	"firewall_engine/internal/security"
	"firewall_engine/internal/threatintel"
	"firewall_engine/internal/wfp"
	"firewall_engine/pkg/grpc/management"
	"firewall_engine/pkg/models"

	"safeops-engine/pkg/grpc/pb"
)

func main() {
	fmt.Println("=== SafeOps Firewall Engine ===")
	fmt.Println("Initializing...")

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// ========================================================================
	// 0. Load Configuration (soft-coded path resolution)
	// ========================================================================
	configDir, err := config.ResolveConfigDir()
	if err != nil {
		fmt.Printf("Config error: %v\n", err)
		fmt.Println("Expected configs/ directory with firewall.toml alongside the binary")
		os.Exit(1)
	}

	cfg, err := config.LoadAll(configDir)
	if err != nil {
		fmt.Printf("Failed to load config from %s: %v\n", configDir, err)
		os.Exit(1)
	}

	fmt.Printf("Config loaded from: %s\n", cfg.ConfigDir)
	fmt.Printf("Data directory:     %s\n", cfg.DataDir)

	// Parse blocklist config into runtime structures
	parsedBlocklist, err := cfg.ParsedBlocklistPolicy()
	if err != nil {
		fmt.Printf("Failed to parse blocklist config: %v\n", err)
		os.Exit(1)
	}
	fmt.Printf("Blocklist loaded:   %s\n", cfg.BlocklistFilePath())

	// Atomic pointer for hot-reloadable blocklist config.
	// The packet handler reads this atomically; the hot-reloader swaps it.
	var liveBlocklist atomic.Pointer[config.ParsedBlocklist]
	liveBlocklist.Store(parsedBlocklist)

	// ========================================================================
	// 1. Initialize Structured Logging
	// ========================================================================
	logConfig := logging.LogConfig{
		Level:          logging.LevelFromEnvironment(),
		Format:         logging.FormatConsole,
		Output:         logging.OutputStdout,
		EnableCaller:   true,
		EnableTimestamp: true,
		TimestampFormat: "rfc3339",
	}

	logger, err := logging.NewLogger(logConfig)
	if err != nil {
		fmt.Printf("Failed to initialize logger: %v\n", err)
		os.Exit(1)
	}
	logging.SetGlobal(logger)
	defer logger.Sync()

	logger.Info().
		Str(logging.FieldVersion, cfg.Firewall.Engine.Version).
		Str("config_dir", cfg.ConfigDir).
		Msg("Configuration loaded")

	legacyLogger := log.New(os.Stdout, "[FIREWALL] ", log.LstdFlags|log.Lmicroseconds)
	_ = legacyLogger

	// ========================================================================
	// 2. Initialize Alert Manager
	// ========================================================================
	alertDir, err := cfg.AlertLogDir()
	if err != nil {
		logger.Fatal().Err(err).Msg("Failed to resolve alert log directory")
	}

	// DB logger is nil for now — wired in Phase 2B when threat intel DB is added
	alertMgr, err := alerting.NewManager(
		alertDir,
		cfg.Firewall.Logging.MaxFileSizeMB,
		60, // throttle window seconds
		nil, // dbLogger - wired later with threat intel DB
	)
	if err != nil {
		logger.Fatal().Err(err).Msg("Failed to create alert manager")
	}
	alertMgr.Start(ctx)
	logger.Info().Str("dir", alertDir).Msg("Alert Manager started")

	// ========================================================================
	// 2b. Initialize Threat Intel DB + Caches
	// ========================================================================
	var threatDecision *threatintel.Decision
	var threatRefresher *threatintel.Refresher

	// Respect blocklist master switch for threat intel
	if !parsedBlocklist.ThreatIntelEnabled {
		logger.Info().Msg("Threat intel disabled by blocklist.toml [threat_intel].enabled = false")
	}

	threatDB, err := threatintel.NewDB(cfg.Firewall.Database)
	if err != nil {
		logger.Warn().Err(err).Msg("Threat intel DB unavailable - running without threat intel")
	} else if !parsedBlocklist.ThreatIntelEnabled {
		logger.Info().Msg("Threat intel DB connected but blocking disabled by blocklist config")
	} else {
		logger.Info().Str("dsn_host", cfg.Firewall.Database.Host).Str("db", cfg.Firewall.Database.DBName).Msg("Threat intel DB connected")

		ipCache := threatintel.NewIPCache()
		domainCache := threatintel.NewDomainCache()

		// Initial load
		loadCtx, loadCancel := context.WithTimeout(ctx, 60*time.Second)
		if err := ipCache.Load(loadCtx, threatDB.Pool()); err != nil {
			logger.Error().Err(err).Msg("Failed to load IP blacklist")
		} else {
			logger.Info().Int64("count", ipCache.Count()).Msg("IP blacklist loaded")
		}

		if err := ipCache.LoadVPNIPs(loadCtx, threatDB.Pool()); err != nil {
			logger.Error().Err(err).Msg("Failed to load VPN IPs")
		} else {
			logger.Info().Int64("count", ipCache.VPNCount()).Msg("VPN/anonymizer IPs loaded")
		}

		if err := domainCache.Load(loadCtx, threatDB.Pool()); err != nil {
			logger.Error().Err(err).Msg("Failed to load domain blocklist")
		} else {
			logger.Info().Int64("count", domainCache.Count()).Msg("Domain blocklist loaded")
		}
		loadCancel()

		// Background refresher
		threatRefresher = threatintel.NewRefresher(threatDB, ipCache, domainCache,
			cfg.Firewall.Performance.ThreatIntelRefreshMinutes)
		threatRefresher.Start(ctx)

		// Decision engine
		threatDecision = threatintel.NewDecision(ipCache, domainCache, alertMgr)

		logger.Info().
			Int64("ips", ipCache.Count()).
			Int64("vpns", ipCache.VPNCount()).
			Int64("domains", domainCache.Count()).
			Int("refresh_min", cfg.Firewall.Performance.ThreatIntelRefreshMinutes).
			Msg("Threat intel pipeline ready")
	}

	// ========================================================================
	// 2c. Initialize Security Manager (rate limiting, DDoS, brute force, etc.)
	// ========================================================================
	securityMgr := security.NewManager(cfg.Detection, alertMgr)
	logger.Info().
		Bool("rate_limit", cfg.Detection.RateLimit.Enabled).
		Bool("ddos", cfg.Detection.DDoS.Enabled).
		Bool("brute_force", cfg.Detection.BruteForce.Enabled).
		Bool("port_scan", cfg.Detection.PortScan.Enabled).
		Bool("anomaly", cfg.Detection.Anomaly.Enabled).
		Bool("baseline", cfg.Detection.Baseline.Enabled).
		Msg("Security Manager initialized")

	// ========================================================================
	// 2d. Initialize Domain Filter (domains.txt + category blocking)
	// ========================================================================
	var domainFilter *domain.Filter

	if !parsedBlocklist.DomainsEnabled {
		logger.Info().Msg("Domain blocking disabled by blocklist.toml [domains].enabled = false")
	} else {
		// Categories from blocklist.toml (toggleable per-category)
		blockedCategories := parsedBlocklist.BlockedCategories

		domainFilter, err = domain.NewFilter(parsedBlocklist.DomainsFilePath, blockedCategories, alertMgr)
		if err != nil {
			logger.Warn().Err(err).Msg("Domain filter init failed - domain blocking from config disabled")
			domainFilter = nil
		} else {
			// Connect threat intel to domain filter so Check() also queries the domain cache
			if threatDecision != nil {
				domainFilter.SetThreatDecision(threatDecision)
				logger.Info().Msg("Domain filter: threat intel domain cache connected")
			}

			// Add custom CDN domains from blocklist config
			if len(parsedBlocklist.CustomCDNDomains) > 0 {
				cdnList := domainFilter.GetCDNAllowlist()
				if cdnList != nil {
					cdnList.AddProvider(domain.CDNProvider{
						Name:    "custom",
						Domains: parsedBlocklist.CustomCDNDomains,
					})
					logger.Info().Int("count", len(parsedBlocklist.CustomCDNDomains)).Msg("Custom CDN domains added from blocklist config")
				}
			}

			stats := domainFilter.Stats()
			logger.Info().
				Int("config_domains", stats.ConfigDomains).
				Int("categories", stats.CategoriesActive).
				Strs("enabled_categories", blockedCategories).
				Int("cdn_providers", stats.CDNProviders).
				Bool("threat_intel", stats.ThreatIntelAvail).
				Str("file", parsedBlocklist.DomainsFilePath).
				Msg("Domain Filter initialized")
		}
	}

	// ========================================================================
	// 2e. Initialize GeoIP Checker (country/ASN blocking)
	// ========================================================================
	var geoChecker *geoip.Checker

	if !parsedBlocklist.GeoEnabled {
		logger.Info().Msg("GeoIP blocking disabled by blocklist.toml [geo].enabled = false")
	}

	geoPolicy, err := cfg.GeoIP.Parse()
	if err != nil {
		logger.Warn().Err(err).Msg("GeoIP policy parse failed - geo blocking disabled")
	} else if !geoPolicy.Enabled || !parsedBlocklist.GeoEnabled {
		if !parsedBlocklist.GeoEnabled {
			logger.Info().Msg("GeoIP policy disabled by blocklist config")
		} else {
			logger.Info().Msg("GeoIP policy disabled in geoip.toml")
		}
	} else if threatDB == nil {
		logger.Warn().Msg("GeoIP requires database - no threat intel DB, geo blocking disabled")
	} else {
		// Merge extra blocked countries from blocklist.toml into geo policy
		for _, cc := range parsedBlocklist.ExtraBlockedCountries {
			if !geoPolicy.Countries[cc] {
				geoPolicy.Countries[cc] = true
				logger.Info().Str("country", cc).Msg("Extra blocked country added from blocklist config")
			}
		}

		// Merge extra blocked ASNs from blocklist.toml into geo policy
		for _, asn := range parsedBlocklist.ExtraBlockedASNs {
			if !geoPolicy.BlockedASNs[asn] {
				geoPolicy.BlockedASNs[asn] = true
				logger.Info().Uint32("asn", asn).Msg("Extra blocked ASN added from blocklist config")
			}
		}
		// Create PostgreSQL-backed GeoIP resolver
		geoResolver, geoErr := objects.NewPostgresGeoResolver(&objects.PostgresGeoConfig{
			DB:       threatDB.Pool(),
			CacheTTL: time.Hour,
		})
		if geoErr != nil {
			logger.Warn().Err(geoErr).Msg("GeoIP resolver init failed - geo blocking disabled")
		} else {
			geoChecker, err = geoip.NewChecker(geoip.CheckerConfig{
				Resolver: geoResolver,
				Policy:   geoPolicy,
				AlertMgr: alertMgr,
				CacheTTL: time.Hour,
				CacheMax: 100_000,
			})
			if err != nil {
				logger.Warn().Err(err).Msg("GeoIP checker init failed - geo blocking disabled")
			} else {
				gs := geoChecker.Stats()
				mode := "deny_list"
				if !geoPolicy.IsDenyMode {
					mode = "allow_list"
				}
				logger.Info().
					Str("mode", mode).
					Int("countries", gs.CountriesCount).
					Int("blocked_asns", gs.ASNsBlocked).
					Bool("enrich_alerts", geoPolicy.EnrichAlerts).
					Msg("GeoIP Checker initialized")
			}
		}
	}

	// ========================================================================
	// 3. Initialize Verdict Cache (config-driven)
	// ========================================================================
	cacheConfig := cache.DefaultCacheConfig()
	cacheConfig.Capacity = cfg.Firewall.Performance.VerdictCacheSize
	cacheConfig.DefaultTTL = time.Duration(cfg.Firewall.Performance.VerdictCacheTTLSeconds) * time.Second
	cacheConfig.CleanupInterval = time.Duration(cfg.Firewall.Performance.VerdictCacheCleanupSeconds) * time.Second

	verdictCache, err := cache.NewVerdictCache(cacheConfig)
	if err != nil {
		logger.Fatal().Err(err).Msg("Failed to create verdict cache")
	}
	logger.Info().
		Int("capacity", cfg.Firewall.Performance.VerdictCacheSize).
		Dur("ttl", cacheConfig.DefaultTTL).
		Msg("Verdict Cache initialized")

	if err := verdictCache.Start(ctx); err != nil {
		logger.Fatal().Err(err).Msg("Failed to start verdict cache")
	}

	// ========================================================================
	// 4. Initialize Connection Tracker (config-driven)
	// ========================================================================
	connConfig := connection.DefaultTrackerConfig()
	connConfig.MaxConnections = cfg.Firewall.Performance.MaxConnections

	connTracker, err := connection.NewTracker(connConfig)
	if err != nil {
		logger.Fatal().Err(err).Msg("Failed to create connection tracker")
	}
	logger.Info().Int("capacity", cfg.Firewall.Performance.MaxConnections).Msg("Connection Tracker initialized")

	// ========================================================================
	// 5. Initialize Fast-Path Evaluator
	// ========================================================================
	fastPathConfig := inspector.DefaultFastPathConfig()
	fastPathConfig.BypassGaming = true
	fastPathConfig.BypassVoIP = true
	fastPathConfig.EnableBlocklist = true
	fastPathConfig.EnableEstablished = true

	fastPath := inspector.NewFastPath(fastPathConfig)
	logger.Info().Bool("gaming_bypass", true).Bool("voip_bypass", true).Msg("Fast-Path Evaluator initialized")

	// ========================================================================
	// 6. Initialize Enforcement Handler
	// ========================================================================
	enfConfig := enforcement.DefaultEnforcementConfig()
	enfConfig.FailOpen = cfg.Firewall.Engine.FailOpen
	enfConfig.MaxRetries = 2
	enfConfig.EnableMetrics = true

	enforcementHandler, err := enforcement.NewVerdictHandler(enfConfig)
	if err != nil {
		logger.Fatal().Err(err).Msg("Failed to create enforcement handler")
	}
	logger.Info().Bool("fail_open", cfg.Firewall.Engine.FailOpen).Msg("Enforcement Handler initialized")

	// ========================================================================
	// 7. Initialize Packet Inspector (config-driven worker count)
	// ========================================================================
	inspConfig := inspector.DefaultInspectorConfig()
	inspConfig.WorkerCount = cfg.Firewall.Engine.WorkerCount
	inspConfig.EnableCache = true
	inspConfig.EnableFastPath = true
	inspConfig.EnableEnforcement = true
	inspConfig.EnableLogging = true
	inspConfig.FailOpen = cfg.Firewall.Engine.FailOpen

	packetInspector, err := inspector.NewInspector(inspConfig)
	if err != nil {
		logger.Fatal().Err(err).Msg("Failed to create packet inspector")
	}

	packetInspector.SetConnectionTracker(connTracker)
	packetInspector.SetEnforcementHandler(enforcementHandler)
	packetInspector.SetFastPathEvaluator(fastPath)

	logger.Info().Int("workers", cfg.Firewall.Engine.WorkerCount).Bool("fail_open", cfg.Firewall.Engine.FailOpen).Msg("Packet Inspector initialized")

	if err := packetInspector.Start(ctx); err != nil {
		logger.Fatal().Err(err).Msg("Failed to start packet inspector")
	}

	// ========================================================================
	// 8. Initialize WFP Engine
	// ========================================================================
	var dualEngine *enforcement.DualEngineCoordinator
	var wfpEngine *wfp.Engine

	wfpConfig := wfp.DefaultEngineConfig()
	wfpConfig.SessionName = "SafeOps_Firewall_V5"
	wfpConfig.Dynamic = true

	wfpEngine = wfp.NewEngine(wfpConfig)
	if err := wfpEngine.Open(); err != nil {
		logger.Warn().Err(err).Msg("WFP initialization failed - running in SafeOps-only mode")
		wfpEngine = nil
	} else {
		logger.Info().Msg("WFP Engine initialized")
	}

	// ========================================================================
	// 9. Initialize Dual-Engine Coordinator
	// ========================================================================
	dualEngineConfig := enforcement.DefaultDualEngineConfig()
	if wfpEngine == nil {
		dualEngineConfig.Mode = enforcement.DualModeSafeOpsOnly
	} else {
		dualEngineConfig.Mode = enforcement.DualModeBoth
	}

	dualEngine, err = enforcement.NewDualEngineCoordinatorWithConfig(wfpEngine, dualEngineConfig)
	if err != nil {
		logger.Warn().Err(err).Msg("Dual-engine init failed")
	} else {
		if err := dualEngine.Start(ctx); err != nil {
			logger.Warn().Err(err).Msg("Dual-engine start failed")
		} else {
			logger.Info().Str("mode", dualEngine.GetMode().String()).Msg("Dual-Engine Coordinator started")
		}
	}

	// ========================================================================
	// 10. Initialize gRPC Client (config-driven address + filters)
	// ========================================================================
	grpcClient := integration.NewSafeOpsGRPCClient(
		cfg.Firewall.SafeOps.SubscriberID,
		cfg.Firewall.SafeOps.GRPCAddress,
		cfg.Firewall.SafeOps.Filters,
	)

	if err := grpcClient.Connect(ctx); err != nil {
		logger.Warn().Err(err).Str("address", cfg.Firewall.SafeOps.GRPCAddress).Msg("Failed to connect to SafeOps Engine - standalone mode")
	} else {
		logger.Info().
			Str("address", cfg.Firewall.SafeOps.GRPCAddress).
			Strs("filters", cfg.Firewall.SafeOps.Filters).
			Msg("Connected to SafeOps Engine")
	}
	defer grpcClient.Disconnect()

	// ========================================================================
	// 11. Start Packet Capture Stream (config-driven worker count)
	// ========================================================================
	if grpcClient.IsConnected() {
		numWorkers := cfg.Firewall.Engine.WorkerCount
		if err := grpcClient.StartCapture(ctx, func(pkt *pb.PacketMetadata) {
			packet := convertPacket(pkt)

			// Load current blocklist config (hot-reloadable via atomic pointer)
			bl := liveBlocklist.Load()
			blockCacheTTL := uint32(bl.BlockCacheTTLSeconds)

			// Step 0: Global whitelist bypass (blocklist.toml [whitelist])
			// Whitelisted IPs bypass ALL blocking checks (manual, threat intel, geo).
			if bl.IsIPWhitelisted(pkt.SrcIp) || bl.IsIPWhitelisted(pkt.DstIp) {
				// Skip all blocking — go straight to packet inspector
				goto inspectPacket
			}

			{
				// Security check (O(1) ban check + rate limit + DDoS — fastest)
				protocol := protocolName(pkt.Protocol)
				verdict := securityMgr.Check(pkt.SrcIp, protocol, uint8(pkt.TcpFlags), int(pkt.PacketSize))
				if !verdict.Allowed {
					go grpcClient.SendVerdict(ctx, pkt.PacketId, pb.VerdictType_DROP,
						verdict.Reason, verdict.DetectorName, 60, pkt.CacheKey)
					return
				}

				// Port scan check (for SYN packets to new destinations)
				if protocol == "TCP" && pkt.TcpFlags&0x02 != 0 && pkt.TcpFlags&0x10 == 0 {
					scanVerdict := securityMgr.CheckPortScan(pkt.SrcIp, uint16(pkt.DstPort))
					if !scanVerdict.Allowed {
						go grpcClient.SendVerdict(ctx, pkt.PacketId, pb.VerdictType_DROP,
							scanVerdict.Reason, scanVerdict.DetectorName, 300, pkt.CacheKey)
						return
					}
				}

				// Manual IP blocklist check (blocklist.toml [ips])
				if bl.IPsEnabled {
					if bl.IsIPManuallyBlocked(pkt.SrcIp) {
						reason := fmt.Sprintf("Source IP %s in manual blocklist (blocklist.toml)", pkt.SrcIp)
						go grpcClient.SendVerdict(ctx, pkt.PacketId, pb.VerdictType_DROP,
							reason, "manual_blocklist", blockCacheTTL, pkt.CacheKey)
						return
					}
					if bl.IsIPManuallyBlocked(pkt.DstIp) {
						reason := fmt.Sprintf("Destination IP %s in manual blocklist (blocklist.toml)", pkt.DstIp)
						go grpcClient.SendVerdict(ctx, pkt.PacketId, pb.VerdictType_DROP,
							reason, "manual_blocklist", blockCacheTTL, pkt.CacheKey)
						return
					}
				}

				// GeoIP check (country/ASN blocking — cached, fast after first lookup)
				if geoChecker != nil {
					geoResult := geoChecker.Check(pkt.SrcIp)
					if geoResult.Blocked {
						go grpcClient.SendVerdict(ctx, pkt.PacketId, pb.VerdictType_DROP,
							geoResult.Reason, "geoip", 600, pkt.CacheKey)
						return
					}
				}

				// Threat intel IP check (O(1) in-memory — IP only, domain handled by domain filter)
				if threatDecision != nil {
					ipResult := threatDecision.CheckIP(pkt.SrcIp, pkt.DstIp)
					if ipResult != nil && ipResult.IsBlocked {
						go grpcClient.SendVerdict(ctx, pkt.PacketId, pb.VerdictType_DROP,
							ipResult.Reason, "threat_intel", 300, pkt.CacheKey)
						return
					}
				}

				// Domain whitelist check (blocklist.toml [whitelist].domains)
				// If domain is whitelisted, skip domain filter entirely.
				domainWhitelisted := false
				if pkt.Domain != "" && bl.IsDomainWhitelisted(pkt.Domain) {
					domainWhitelisted = true
				}

				// Domain filter check: config blocklist + categories + threat intel domains + CDN awareness
				// The domain filter combines all domain-level blocking and returns protocol-aware verdicts.
				if domainFilter != nil && pkt.Domain != "" && !domainWhitelisted {
					domResult := domainFilter.Check(pkt.Domain, pkt.DomainSource)
					if domResult.Blocked {
						verdictType := domainActionToVerdict(domResult.Action)
						reason := fmt.Sprintf("Domain blocked: %s (matched: %s, source: %s, action: %s)",
							domResult.Domain, domResult.MatchedBy, domResult.DomainSource, domResult.Action)

						// CDN-protected domains get REDIRECT only (never RST CDN IPs)
						if domResult.IsCDN {
							verdictType = pb.VerdictType_REDIRECT
							reason = fmt.Sprintf("Domain blocked (CDN %s): %s (matched: %s, DNS redirect only)",
								domResult.CDNProvider, domResult.Domain, domResult.MatchedBy)
						}

						go grpcClient.SendVerdict(ctx, pkt.PacketId, verdictType,
							reason, "domain_filter", blockCacheTTL, pkt.CacheKey)
						return
					}
				}
			}

		inspectPacket:
			result, err := packetInspector.Inspect(ctx, packet)
			if err != nil {
				logger.Error().Err(err).Msg("Inspection failed")
				return
			}

			if result.CacheHit {
				return
			}

			verdictType := convertVerdictType(result.Verdict)
			cacheTTL := uint32(cfg.Firewall.Performance.VerdictCacheTTLSeconds)

			go grpcClient.SendVerdict(ctx, pkt.PacketId, verdictType, result.Reason,
				result.RuleID, cacheTTL, pkt.CacheKey)

		}, numWorkers); err != nil {
			logger.Error().Err(err).Msg("Failed to start capture")
		} else {
			logger.Info().Int("workers", numWorkers).Msg("Packet capture stream started")
		}
	}

	// ========================================================================
	// 12. Initialize Prometheus Metrics Exporter (config-driven)
	// ========================================================================
	metricsConfig := metrics.DefaultExporterConfig()
	metricsConfig.Address = cfg.Firewall.Servers.MetricsAddress
	metricsConfig.Path = cfg.Firewall.Servers.MetricsPath

	metricsRegistry := metrics.NewDefaultRegistry()
	if err := metricsRegistry.Register(); err != nil {
		logger.Error().Err(err).Msg("Failed to register metrics")
	} else {
		metricsExporter, err := metrics.NewExporter(metricsConfig, metricsRegistry)
		if err != nil {
			logger.Error().Err(err).Msg("Failed to create metrics exporter")
		} else {
			if err := metricsExporter.StartAsync(); err != nil {
				logger.Error().Err(err).Msg("Failed to start metrics exporter")
			} else {
				logger.Info().Str("address", cfg.Firewall.Servers.MetricsAddress).Msg("Prometheus metrics started")
			}
		}
	}

	// ========================================================================
	// 13. Initialize Health Server (config-driven)
	// ========================================================================
	healthAggregator := health.NewAggregator()

	healthAggregator.Register(health.NewFuncChecker("verdict_cache", true, func(ctx context.Context) health.CheckResult {
		if verdictCache == nil {
			return health.Unhealthy("Cache not initialized")
		}
		size := verdictCache.Size()
		cap90 := cfg.Firewall.Performance.VerdictCacheSize * 9 / 10
		if size > cap90 {
			return health.Degraded(fmt.Sprintf("Cache near capacity: %d/%d", size, cfg.Firewall.Performance.VerdictCacheSize))
		}
		return health.Healthy(fmt.Sprintf("Cache healthy: %d entries", size))
	}))

	healthAggregator.Register(health.NewFuncChecker("connection_tracker", true, func(ctx context.Context) health.CheckResult {
		if connTracker == nil {
			return health.Unhealthy("Tracker not initialized")
		}
		count := connTracker.Count()
		cap90 := cfg.Firewall.Performance.MaxConnections * 9 / 10
		if count > cap90 {
			return health.Degraded(fmt.Sprintf("Connections near limit: %d/%d", count, cfg.Firewall.Performance.MaxConnections))
		}
		return health.Healthy(fmt.Sprintf("Tracking %d connections", count))
	}))

	healthAggregator.Register(health.NewFuncChecker("safeops_connection", true, func(ctx context.Context) health.CheckResult {
		if grpcClient == nil || !grpcClient.IsConnected() {
			return health.Degraded("SafeOps Engine not connected")
		}
		return health.Healthy("Connected to SafeOps Engine")
	}))

	healthAggregator.Register(health.NewFuncChecker("wfp_engine", false, func(ctx context.Context) health.CheckResult {
		if wfpEngine == nil || !wfpEngine.IsOpen() {
			return health.Degraded("WFP Engine not available")
		}
		return health.Healthy("WFP Engine active")
	}))

	if threatDB != nil {
		healthAggregator.Register(health.NewFuncChecker("threat_intel_db", true, func(ctx context.Context) health.CheckResult {
			if err := threatDB.Ping(ctx); err != nil {
				return health.Unhealthy(fmt.Sprintf("DB ping failed: %v", err))
			}
			if threatRefresher != nil {
				stats := threatRefresher.Stats()
				return health.Healthy(fmt.Sprintf("IPs=%d VPNs=%d Domains=%d refresh=%dms",
					stats.IPCount, stats.VPNCount, stats.DomainCount, stats.RefreshDurMs))
			}
			return health.Healthy("Connected")
		}))
	}

	healthConfig := health.DefaultHTTPConfig()
	healthConfig.Address = cfg.Firewall.Servers.HealthAddress

	healthServer, err := health.NewServer(healthConfig, healthAggregator)
	if err != nil {
		logger.Error().Err(err).Msg("Failed to create health server")
	} else {
		if err := healthServer.StartAsync(); err != nil {
			logger.Error().Err(err).Msg("Failed to start health server")
		} else {
			healthServer.SetStarted(true)
			logger.Info().Str("address", cfg.Firewall.Servers.HealthAddress).Msg("Health server started")
		}
	}

	// ========================================================================
	// 14. Initialize gRPC Management Server (config-driven)
	// ========================================================================
	mgmtConfig := management.DefaultServerConfig()
	mgmtConfig.Address = cfg.Firewall.Servers.ManagementAddress

	mgmtDeps := management.Dependencies{
		Logger:           logger,
		HealthAggregator: healthAggregator,
		RollingStats:     metrics.GlobalStats(),
	}

	mgmtServer, err := management.NewServer(mgmtConfig, mgmtDeps)
	if err != nil {
		logger.Error().Err(err).Msg("Failed to create management server")
	} else {
		if err := mgmtServer.StartAsync(); err != nil {
			logger.Error().Err(err).Msg("Failed to start management server")
		} else {
			logger.Info().Str("address", cfg.Firewall.Servers.ManagementAddress).Msg("gRPC management server started")
		}
	}

	// ========================================================================
	// 15. Statistics Reporter
	// ========================================================================
	go func() {
		ticker := time.NewTicker(30 * time.Second)
		defer ticker.Stop()

		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				printStats(packetInspector, verdictCache, connTracker, grpcClient, alertMgr, securityMgr, domainFilter, geoChecker, legacyLogger)
			}
		}
	}()

	// ========================================================================
	// Ready Message
	// ========================================================================
	printBanner(cfg, dualEngine, wfpEngine, alertDir, threatRefresher, securityMgr, domainFilter, geoChecker, parsedBlocklist)

	// ========================================================================
	// 16. Initialize Hot-Reload Watcher
	// ========================================================================
	reloader, err := hotreload.NewReloader(hotreload.ReloaderConfig{
		ConfigDir:        cfg.ConfigDir,
		Logger:           logger,
		AlertMgr:         alertMgr,
		DomainFilter:     domainFilter,
		GeoChecker:       geoChecker,
		SecurityMgr:      securityMgr,
		InitialBlocklist: parsedBlocklist,
		OnBlocklistReload: func(newBL *config.ParsedBlocklist) {
			liveBlocklist.Store(newBL)
		},
	})
	if err != nil {
		logger.Error().Err(err).Msg("Failed to create hot-reload watcher")
	} else {
		if err := reloader.Start(ctx); err != nil {
			logger.Error().Err(err).Msg("Failed to start hot-reload watcher")
		} else {
			logger.Info().Str("config_dir", cfg.ConfigDir).Msg("Hot-reload watcher active")
		}
	}

	// ========================================================================
	// Wait for Shutdown Signal
	// ========================================================================
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	<-sigCh

	fmt.Println("\n\nShutting down Firewall Engine...")
	grpcClient.SetStopping() // suppress gRPC reconnect attempts before cancel
	cancel()

	// Graceful shutdown in reverse order
	if reloader != nil {
		if err := reloader.Stop(); err != nil {
			logger.Error().Err(err).Msg("Error stopping hot-reload watcher")
		}
	}
	if geoChecker != nil {
		geoChecker.Stop()
	}
	securityMgr.Stop()
	if threatRefresher != nil {
		threatRefresher.Stop()
	}
	alertMgr.Stop()
	if threatDB != nil {
		threatDB.Close()
	}
	if mgmtServer != nil {
		if err := mgmtServer.Stop(); err != nil {
			logger.Error().Err(err).Msg("Error stopping management server")
		}
	}
	if healthServer != nil {
		if err := healthServer.Stop(); err != nil {
			logger.Error().Err(err).Msg("Error stopping health server")
		}
	}
	if dualEngine != nil {
		if err := dualEngine.Stop(); err != nil {
			logger.Error().Err(err).Msg("Error stopping dual-engine")
		}
	}
	if err := packetInspector.Stop(); err != nil {
		logger.Error().Err(err).Msg("Error stopping inspector")
	}
	if err := verdictCache.Stop(); err != nil {
		logger.Error().Err(err).Msg("Error stopping cache")
	}

	printFinalStats(packetInspector, verdictCache, connTracker, grpcClient, alertMgr, securityMgr, domainFilter, geoChecker)

	fmt.Println("Firewall Engine stopped.")
}

// ============================================================================
// Helper Functions
// ============================================================================

func convertPacket(pkt *pb.PacketMetadata) *models.PacketMetadata {
	return &models.PacketMetadata{
		SrcIP:    pkt.SrcIp,
		DstIP:    pkt.DstIp,
		SrcPort:  uint16(pkt.SrcPort),
		DstPort:  uint16(pkt.DstPort),
		Protocol: models.Protocol(pkt.Protocol),
	}
}

func convertVerdictType(verdict models.Verdict) pb.VerdictType {
	switch verdict {
	case models.VerdictAllow:
		return pb.VerdictType_ALLOW
	case models.VerdictDrop:
		return pb.VerdictType_DROP
	case models.VerdictBlock:
		return pb.VerdictType_BLOCK
	case models.VerdictRedirect:
		return pb.VerdictType_REDIRECT
	default:
		return pb.VerdictType_ALLOW
	}
}

// domainActionToVerdict maps domain filter VerdictAction to protobuf VerdictType.
func domainActionToVerdict(action domain.VerdictAction) pb.VerdictType {
	switch action {
	case domain.ActionRedirect:
		return pb.VerdictType_REDIRECT
	case domain.ActionBlock:
		return pb.VerdictType_BLOCK
	case domain.ActionDrop:
		return pb.VerdictType_DROP
	default:
		return pb.VerdictType_ALLOW
	}
}

func protocolName(proto uint32) string {
	switch proto {
	case 6:
		return "TCP"
	case 17:
		return "UDP"
	case 1:
		return "ICMP"
	default:
		return fmt.Sprintf("PROTO_%d", proto)
	}
}

func printBanner(cfg *config.AllConfig, dualEngine *enforcement.DualEngineCoordinator, wfpEngine *wfp.Engine, alertDir string, refresher *threatintel.Refresher, secMgr *security.Manager, domFilter *domain.Filter, geoCheck *geoip.Checker, bl *config.ParsedBlocklist) {
	sep := strings.Repeat("=", 60)
	fmt.Println("\n" + sep)
	fmt.Printf("Firewall Engine %s is RUNNING\n", cfg.Firewall.Engine.Version)
	fmt.Println(sep)
	fmt.Printf("  Config:             %s\n", cfg.ConfigDir)
	fmt.Printf("  Data:               %s\n", cfg.DataDir)
	fmt.Printf("  Alerts:             %s\n", alertDir)
	fmt.Println(sep)
	fmt.Println("Dual-Engine Mode:")
	if dualEngine != nil {
		fmt.Printf("  Mode:               %s\n", dualEngine.GetMode())
		if wfpEngine != nil && wfpEngine.IsOpen() {
			fmt.Println("  SafeOps Engine:     ACTIVE (kernel-level)")
			fmt.Println("  WFP Engine:         ACTIVE (OS-level)")
		} else {
			fmt.Println("  SafeOps Engine:     ACTIVE (kernel-level)")
			fmt.Println("  WFP Engine:         INACTIVE (run as Admin)")
		}
	} else {
		fmt.Println("  SafeOps Engine:     ACTIVE")
		fmt.Println("  WFP Engine:         DISABLED")
	}
	fmt.Println(sep)
	fmt.Println("Components:")
	fmt.Printf("  Verdict Cache:      %dK entries, %ds TTL\n",
		cfg.Firewall.Performance.VerdictCacheSize/1000,
		cfg.Firewall.Performance.VerdictCacheTTLSeconds)
	fmt.Printf("  Connection Tracker: %dK connections\n",
		cfg.Firewall.Performance.MaxConnections/1000)
	fmt.Println("  Fast-Path:          Gaming/VoIP bypass enabled")
	fmt.Printf("  Inspector:          %d workers, fail-%s\n",
		cfg.Firewall.Engine.WorkerCount,
		map[bool]string{true: "open", false: "closed"}[cfg.Firewall.Engine.FailOpen])
	fmt.Println("  Enforcement:        DROP/BLOCK/REDIRECT/REJECT")
	fmt.Println(sep)
	fmt.Println("gRPC Pipeline:")
	fmt.Printf("  SafeOps Engine:     %s\n", cfg.Firewall.SafeOps.GRPCAddress)
	fmt.Printf("  Filters:            %s\n", strings.Join(cfg.Firewall.SafeOps.Filters, " + "))
	fmt.Printf("  Worker Pool:        %d async workers\n", cfg.Firewall.Engine.WorkerCount)
	fmt.Printf("  Packet Buffer:      %dK non-blocking\n", cfg.Firewall.Performance.PacketBufferSize/1000)
	fmt.Println(sep)
	if refresher != nil {
		stats := refresher.Stats()
		fmt.Println("Threat Intel:")
		fmt.Printf("  Malicious IPs:      %d\n", stats.IPCount)
		fmt.Printf("  VPN/Anonymizers:    %d\n", stats.VPNCount)
		fmt.Printf("  Malicious Domains:  %d\n", stats.DomainCount)
		fmt.Printf("  Refresh Interval:   %d min\n", cfg.Firewall.Performance.ThreatIntelRefreshMinutes)
		fmt.Println(sep)
	}
	if domFilter != nil {
		ds := domFilter.Stats()
		fmt.Println("Domain Filtering:")
		fmt.Printf("  Config Blocklist:   %d domains\n", ds.ConfigDomains)
		fmt.Printf("  Categories Active:  %d\n", ds.CategoriesActive)
		fmt.Printf("  CDN Providers:      %d (IP-block protected)\n", ds.CDNProviders)
		fmt.Printf("  Threat Intel:       %v\n", ds.ThreatIntelAvail)
		fmt.Printf("  Enforcement:        DNS→REDIRECT, SNI→BLOCK, HTTP→BLOCK\n")
		fmt.Println(sep)
	}
	if geoCheck != nil {
		gs := geoCheck.Stats()
		fmt.Println("GeoIP Blocking:")
		fmt.Printf("  Mode:               %s\n", gs.Mode)
		fmt.Printf("  Countries:          %d configured\n", gs.CountriesCount)
		fmt.Printf("  Blocked ASNs:       %d\n", gs.ASNsBlocked)
		fmt.Printf("  Alert Enrichment:   %v\n", cfg.GeoIP.Policy.EnrichAlerts)
		fmt.Println(sep)
	}
	if bl != nil {
		fmt.Println("Blocklist Config (blocklist.toml):")
		fmt.Printf("  Domain Blocking:    %v\n", bl.DomainsEnabled)
		fmt.Printf("  IP Blocking:        %v (manual IPs: %d, CIDRs: %d)\n",
			bl.IPsEnabled, len(bl.ManualIPs), len(bl.ManualCIDRs))
		fmt.Printf("  Threat Intel:       %v (IP threshold: %d, domain: %d)\n",
			bl.ThreatIntelEnabled, bl.IPBlockThreshold, bl.DomainBlockThreshold)
		fmt.Printf("  Block Anonymizers:  %v (threshold: %d)\n",
			bl.BlockAnonymizers, bl.AnonymizerBlockThreshold)
		fmt.Printf("  GeoIP Override:     %v (extra countries: %d, extra ASNs: %d)\n",
			bl.GeoEnabled, len(bl.ExtraBlockedCountries), len(bl.ExtraBlockedASNs))
		fmt.Printf("  Categories:         %d enabled (%s)\n",
			len(bl.BlockedCategories), strings.Join(bl.BlockedCategories, ", "))
		fmt.Printf("  DNS Redirect:       %s\n", bl.DNSRedirectIP)
		fmt.Printf("  Block Cache TTL:    %ds\n", bl.BlockCacheTTLSeconds)
		fmt.Printf("  Whitelist IPs:      %d, CIDRs: %d, Domains: %d\n",
			len(bl.WhitelistIPs), len(bl.WhitelistCIDRs), len(bl.WhitelistDomains))
		fmt.Println(sep)
	}
	if secMgr != nil {
		fmt.Println("Security:")
		fmt.Printf("  Rate Limiting:      %v (per-IP: %d/s, global: %d/s)\n",
			cfg.Detection.RateLimit.Enabled, cfg.Detection.RateLimit.DefaultRate, cfg.Detection.RateLimit.GlobalRate)
		fmt.Printf("  DDoS Protection:    %v (SYN:%d UDP:%d ICMP:%d /%ds)\n",
			cfg.Detection.DDoS.Enabled, cfg.Detection.DDoS.SYNRateThreshold, cfg.Detection.DDoS.UDPRateThreshold,
			cfg.Detection.DDoS.ICMPRateThreshold, cfg.Detection.DDoS.WindowSeconds)
		fmt.Printf("  Brute Force:        %v (%d services monitored)\n",
			cfg.Detection.BruteForce.Enabled, len(cfg.Detection.BruteForce.Services))
		fmt.Printf("  Port Scan:          %v (threshold: %d ports/%ds)\n",
			cfg.Detection.PortScan.Enabled, cfg.Detection.PortScan.PortThreshold, cfg.Detection.PortScan.WindowSeconds)
		fmt.Printf("  Anomaly Detection:  %v (protocol/size/beaconing)\n", cfg.Detection.Anomaly.Enabled)
		fmt.Printf("  Traffic Baseline:   %v (EMA window: %d min)\n",
			cfg.Detection.Baseline.Enabled, cfg.Detection.Baseline.WindowMinutes)
		fmt.Printf("  Ban Escalation:     %dm → %dm → %dm → ... (max %dh)\n",
			cfg.Detection.DDoS.BanDurationMinutes,
			cfg.Detection.DDoS.BanDurationMinutes*cfg.Detection.DDoS.EscalationMultiplier,
			cfg.Detection.DDoS.BanDurationMinutes*cfg.Detection.DDoS.EscalationMultiplier*cfg.Detection.DDoS.EscalationMultiplier,
			cfg.Detection.DDoS.MaxBanDurationHours)
		fmt.Println(sep)
	}
	fmt.Println("Servers:")
	fmt.Printf("  Metrics:            http://localhost%s%s\n", cfg.Firewall.Servers.MetricsAddress, cfg.Firewall.Servers.MetricsPath)
	fmt.Printf("  Health:             http://localhost%s/health\n", cfg.Firewall.Servers.HealthAddress)
	fmt.Printf("  gRPC Management:    grpc://localhost%s\n", cfg.Firewall.Servers.ManagementAddress)
	fmt.Println(sep)
	fmt.Println("\nPress Ctrl+C to stop...")
}

func printStats(insp *inspector.Inspector, cache *cache.VerdictCache,
	conn *connection.Tracker, grpc *integration.SafeOpsGRPCClient,
	alertMgr *alerting.Manager, secMgr *security.Manager, domFilter *domain.Filter, geoCheck *geoip.Checker, logger *log.Logger) {

	inspStats := insp.GetStats()
	cacheStats := cache.GetStats()
	connCount := conn.Count()
	grpcRecv, grpcDropped, grpcVerdicts := grpc.GetStats()
	alertStats := alertMgr.GetStats()
	secStats := secMgr.Stats()

	// Domain filter stats (nil-safe)
	var domChecks, domBlocks, domDNS, domSNI, domHTTP, domThreat, domCDN int64
	if domFilter != nil {
		ds := domFilter.Stats()
		domChecks = ds.TotalChecks
		domBlocks = ds.TotalBlocks
		domDNS = ds.DNSBlocks
		domSNI = ds.SNIBlocks
		domHTTP = ds.HTTPBlocks
		domThreat = ds.ThreatIntelHits
		domCDN = ds.CDNProtected
	}

	// GeoIP stats (nil-safe)
	var geoChecks, geoBlocks, geoCacheH int64
	if geoCheck != nil {
		gs := geoCheck.Stats()
		geoChecks = gs.TotalChecks
		geoBlocks = gs.TotalBlocks
		geoCacheH = gs.CacheHits
	}

	logger.Printf("[STATS] Packets: recv=%d proc=%d | Cache: hit=%.1f%% size=%d | Conn: %d | gRPC: recv=%d drop=%d verdict=%d | Alerts: total=%d written=%d throttled=%d | Security: bans=%d rl=%d/%d ddos=%d/%d/%d bf=%d ps=%d | Domain: checks=%d blocks=%d dns=%d sni=%d http=%d threat=%d cdn=%d | Geo: checks=%d blocks=%d cache=%d",
		inspStats.PacketsReceived.Load(),
		inspStats.PacketsProcessed.Load(),
		cacheStats.GetHitRate(),
		cache.Size(),
		connCount,
		grpcRecv,
		grpcDropped,
		grpcVerdicts,
		alertStats.TotalAlerts,
		alertStats.Written,
		alertStats.Throttled,
		secStats.Bans.ActiveBans,
		secStats.RateLimiter.Allowed,
		secStats.RateLimiter.Denied,
		secStats.DDoS.SYNDetections,
		secStats.DDoS.UDPDetections,
		secStats.DDoS.ICMPDetections,
		secStats.BruteForce.Detections,
		secStats.PortScan.Detections,
		domChecks,
		domBlocks,
		domDNS,
		domSNI,
		domHTTP,
		domThreat,
		domCDN,
		geoChecks,
		geoBlocks,
		geoCacheH,
	)
}

func printFinalStats(insp *inspector.Inspector, cache *cache.VerdictCache,
	conn *connection.Tracker, grpc *integration.SafeOpsGRPCClient,
	alertMgr *alerting.Manager, secMgr *security.Manager, domFilter *domain.Filter, geoCheck *geoip.Checker) {

	inspStats := insp.GetStats()
	cacheStats := cache.GetStats()
	connCount := conn.Count()
	grpcRecv, grpcDropped, grpcVerdicts := grpc.GetStats()
	alertStats := alertMgr.GetStats()
	secStats := secMgr.Stats()

	sep := strings.Repeat("=", 60)
	fmt.Println("\n" + sep)
	fmt.Println("Final Statistics")
	fmt.Println(sep)
	fmt.Printf("Packets Received:    %d\n", inspStats.PacketsReceived.Load())
	fmt.Printf("Packets Processed:   %d\n", inspStats.PacketsProcessed.Load())
	fmt.Printf("Packets Dropped:     %d\n", inspStats.PacketsDropped.Load())
	fmt.Printf("Cache Hits:          %d\n", cacheStats.Hits.Load())
	fmt.Printf("Cache Misses:        %d\n", cacheStats.Misses.Load())
	fmt.Printf("Cache Hit Rate:      %.2f%%\n", cacheStats.GetHitRate())
	fmt.Printf("Active Connections:  %d\n", connCount)
	fmt.Printf("gRPC Received:       %d\n", grpcRecv)
	fmt.Printf("gRPC Dropped:        %d\n", grpcDropped)
	fmt.Printf("gRPC Verdicts Sent:  %d\n", grpcVerdicts)
	fmt.Printf("Alerts Total:        %d\n", alertStats.TotalAlerts)
	fmt.Printf("Alerts Written:      %d\n", alertStats.Written)
	fmt.Printf("Alerts Throttled:    %d\n", alertStats.Throttled)
	fmt.Println(sep)
	fmt.Println("Security")
	fmt.Println(sep)
	fmt.Printf("Active Bans:         %d\n", secStats.Bans.ActiveBans)
	fmt.Printf("Total Bans:          %d\n", secStats.Bans.TotalBans)
	fmt.Printf("Rate Limit Allow:    %d\n", secStats.RateLimiter.Allowed)
	fmt.Printf("Rate Limit Deny:     %d\n", secStats.RateLimiter.Denied)
	fmt.Printf("DDoS SYN:            %d\n", secStats.DDoS.SYNDetections)
	fmt.Printf("DDoS UDP:            %d\n", secStats.DDoS.UDPDetections)
	fmt.Printf("DDoS ICMP:           %d\n", secStats.DDoS.ICMPDetections)
	fmt.Printf("Brute Force:         %d\n", secStats.BruteForce.Detections)
	fmt.Printf("Port Scans:          %d\n", secStats.PortScan.Detections)
	fmt.Printf("Protocol Violations: %d\n", secStats.Anomaly.ProtocolViolations)
	fmt.Printf("Size Anomalies:      %d\n", secStats.Anomaly.SizeAnomalies)
	fmt.Printf("Beaconing Alerts:    %d\n", secStats.Anomaly.BeaconingAlerts)
	fmt.Printf("Baseline Deviations: %d\n", secStats.Baseline.Deviations)
	fmt.Println(sep)
	if domFilter != nil {
		ds := domFilter.Stats()
		fmt.Println("Domain Filtering")
		fmt.Println(sep)
		fmt.Printf("Total Checks:        %d\n", ds.TotalChecks)
		fmt.Printf("Total Blocks:        %d\n", ds.TotalBlocks)
		fmt.Printf("  DNS Redirects:     %d\n", ds.DNSBlocks)
		fmt.Printf("  SNI Blocks (RST):  %d\n", ds.SNIBlocks)
		fmt.Printf("  HTTP Blocks:       %d\n", ds.HTTPBlocks)
		fmt.Printf("Threat Intel Hits:   %d\n", ds.ThreatIntelHits)
		fmt.Printf("Config List Hits:    %d\n", ds.ConfigListHits)
		fmt.Printf("Category Hits:       %d\n", ds.CategoryHits)
		fmt.Printf("CDN Protected:       %d\n", ds.CDNProtected)
		fmt.Printf("Errors:              %d\n", ds.Errors)
		fmt.Println(sep)
	}
	if geoCheck != nil {
		gs := geoCheck.Stats()
		fmt.Println("GeoIP Blocking")
		fmt.Println(sep)
		fmt.Printf("Total Checks:        %d\n", gs.TotalChecks)
		fmt.Printf("Total Blocks:        %d\n", gs.TotalBlocks)
		fmt.Printf("  Country Blocks:    %d\n", gs.CountryBlocks)
		fmt.Printf("  ASN Blocks:        %d\n", gs.ASNBlocks)
		fmt.Printf("Whitelisted:         %d\n", gs.Whitelisted)
		fmt.Printf("Private IPs:         %d\n", gs.PrivateIPs)
		fmt.Printf("Foreign Datacenter:  %d\n", gs.ForeignDC)
		fmt.Printf("Cache Hits:          %d\n", gs.CacheHits)
		fmt.Printf("Cache Misses:        %d\n", gs.CacheMisses)
		fmt.Printf("Lookup Errors:       %d\n", gs.LookupErrors)
		fmt.Printf("Alert Enrichments:   %d\n", gs.Enrichments)
		fmt.Println(sep)
	}
}
