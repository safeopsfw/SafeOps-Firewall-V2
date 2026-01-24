// Package main is the entry point for the SafeOps Firewall Engine.
// It wires all Phase 3 components together: enforcement, connection tracking,
// packet inspection, verdict caching, and the gRPC integration with SafeOps Engine.
package main

import (
	"context"
	"fmt"
	"log"
	oldlog "log"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"firewall_engine/internal/cache"
	"firewall_engine/internal/connection"
	"firewall_engine/internal/enforcement"
	"firewall_engine/internal/health"
	"firewall_engine/internal/inspector"
	"firewall_engine/internal/integration"
	"firewall_engine/internal/logging"
	"firewall_engine/internal/metrics"
	"firewall_engine/internal/wfp"
	"firewall_engine/pkg/grpc/management"
	"firewall_engine/pkg/models"

	"safeops-engine/pkg/grpc/pb"
)

// ============================================================================
// Main Entry Point
// ============================================================================

func main() {
	fmt.Println("=== SafeOps Firewall Engine V5 ===")
	fmt.Println("Version: 5.0.0 (Dual-Engine + WFP + Structured Logging)")
	fmt.Println("Initializing Phase 5 components...")

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// ========================================================================
	// 0. Initialize Structured Logging (Phase 5)
	// ========================================================================
	logConfig := logging.LogConfig{
		Level:           logging.LevelFromEnvironment(),
		Format:          logging.FormatConsole, // Console output for engine ops
		Output:          logging.OutputStdout,  // Console only - firewall.log is for network flows
		EnableCaller:    true,
		EnableTimestamp: true,
		TimestampFormat: "rfc3339",
	}

	log, err := logging.NewLogger(logConfig)
	if err != nil {
		fmt.Printf("Failed to initialize logger: %v\n", err)
		os.Exit(1)
	}
	logging.SetGlobal(log)
	defer log.Sync()

	log.Info().
		Str(logging.FieldVersion, "5.0.0").
		Str("level", logConfig.Level.String()).
		Msg("Structured logging initialized")

	// Create legacy logger for components that still need *log.Logger
	legacyLogger := oldlog.New(os.Stdout, "[FIREWALL] ", oldlog.LstdFlags|oldlog.Lmicroseconds)
	_ = legacyLogger // Keep for backward compatibility

	// ========================================================================
	// 1. Initialize Verdict Cache
	// ========================================================================
	cacheConfig := cache.DefaultCacheConfig()
	cacheConfig.Capacity = 100000 // 100K entries
	cacheConfig.DefaultTTL = 60 * time.Second
	cacheConfig.CleanupInterval = 10 * time.Second

	verdictCache, err := cache.NewVerdictCache(cacheConfig)
	if err != nil {
		log.Fatal().Err(err).Msg("Failed to create verdict cache")
	}
	log.Info().Int("capacity", 100000).Dur("ttl", 60*time.Second).Msg("Verdict Cache initialized")

	// Start cache background cleanup
	if err := verdictCache.Start(ctx); err != nil {
		log.Fatal().Err(err).Msg("Failed to start verdict cache")
	}

	// ========================================================================
	// 2. Initialize Connection Tracker
	// ========================================================================
	connConfig := connection.DefaultTrackerConfig()
	connConfig.MaxConnections = 500000 // 500K concurrent connections

	connTracker, err := connection.NewTracker(connConfig)
	if err != nil {
		log.Fatal().Err(err).Msg("Failed to create connection tracker")
	}
	log.Info().Int("capacity", 500000).Msg("Connection Tracker initialized")

	// ========================================================================
	// 3. Initialize Fast-Path Evaluator
	// ========================================================================
	fastPathConfig := inspector.DefaultFastPathConfig()
	fastPathConfig.BypassGaming = true // Gaming traffic → kernel fast lane
	fastPathConfig.BypassVoIP = true   // VoIP → kernel fast lane
	fastPathConfig.EnableBlocklist = true
	fastPathConfig.EnableEstablished = true

	fastPath := inspector.NewFastPath(fastPathConfig)
	log.Info().Bool("gaming_bypass", true).Bool("voip_bypass", true).Msg("Fast-Path Evaluator initialized")

	// ========================================================================
	// 4. Initialize Enforcement Handler
	// ========================================================================
	enfConfig := enforcement.DefaultEnforcementConfig()
	enfConfig.FailOpen = true // Fail-open for safety
	enfConfig.MaxRetries = 2
	enfConfig.EnableMetrics = true

	enforcementHandler, err := enforcement.NewVerdictHandler(enfConfig)
	if err != nil {
		log.Fatal().Err(err).Msg("Failed to create enforcement handler")
	}
	log.Info().Bool("fail_open", true).Msg("Enforcement Handler initialized")

	// ========================================================================
	// 5. Initialize Packet Inspector
	// ========================================================================
	inspConfig := inspector.DefaultInspectorConfig()
	inspConfig.WorkerCount = 8 // 8 parallel workers
	inspConfig.EnableCache = true
	inspConfig.EnableFastPath = true
	inspConfig.EnableEnforcement = true
	inspConfig.EnableLogging = true
	inspConfig.FailOpen = true

	packetInspector, err := inspector.NewInspector(inspConfig)
	if err != nil {
		log.Fatal().Err(err).Msg("Failed to create packet inspector")
	}

	// Wire dependencies
	packetInspector.SetConnectionTracker(connTracker)
	packetInspector.SetEnforcementHandler(enforcementHandler)
	packetInspector.SetFastPathEvaluator(fastPath)
	// Note: VerdictCache interface mismatch - using adapter pattern if needed

	log.Info().Int("workers", 8).Bool("fail_open", true).Msg("Packet Inspector initialized")

	// Start inspector
	if err := packetInspector.Start(ctx); err != nil {
		log.Fatal().Err(err).Msg("Failed to start packet inspector")
	}

	// ========================================================================
	// 6. Initialize WFP Engine (Phase 4)
	// ========================================================================
	var dualEngine *enforcement.DualEngineCoordinator
	var wfpEngine *wfp.Engine

	// Try to initialize WFP (requires admin privileges)
	wfpConfig := wfp.DefaultEngineConfig()
	wfpConfig.SessionName = "SafeOps_Firewall_V5"
	wfpConfig.Dynamic = true

	wfpEngine = wfp.NewEngine(wfpConfig)
	if err := wfpEngine.Open(); err != nil {
		log.Warn().Err(err).Msg("WFP initialization failed - running in SafeOps-only mode")
		log.Info().Msg("Make sure you're running as Administrator for WFP support")
		wfpEngine = nil
	} else {
		log.Info().Msg("WFP Engine initialized (Windows Filtering Platform)")
	}

	// ========================================================================
	// 7. Initialize Dual-Engine Coordinator (Phase 4)
	// ========================================================================
	dualEngineConfig := enforcement.DefaultDualEngineConfig()
	if wfpEngine == nil {
		dualEngineConfig.Mode = enforcement.DualModeSafeOpsOnly
	} else {
		dualEngineConfig.Mode = enforcement.DualModeBoth
	}

	dualEngine, err = enforcement.NewDualEngineCoordinatorWithConfig(wfpEngine, dualEngineConfig)
	if err != nil {
		log.Warn().Err(err).Msg("Dual-engine init failed")
	} else {
		if err := dualEngine.Start(ctx); err != nil {
			log.Warn().Err(err).Msg("Dual-engine start failed")
		} else {
			log.Info().Str("mode", dualEngine.GetMode().String()).Msg("Dual-Engine Coordinator started")
		}
	}

	// ========================================================================
	// 8. Initialize gRPC Client (connect to SafeOps Engine)
	// ========================================================================
	grpcClient := integration.NewSafeOpsGRPCClient("firewall-engine", "127.0.0.1:50051")

	if err := grpcClient.Connect(ctx); err != nil {
		log.Warn().Err(err).Msg("Failed to connect to SafeOps Engine - running in standalone mode")
		log.Info().Msg("Make sure SafeOps Engine is running on 127.0.0.1:50051")
	} else {
		log.Info().Str("address", "127.0.0.1:50051").Msg("Connected to SafeOps Engine")
	}
	defer grpcClient.Disconnect()

	// ========================================================================
	// 7. Start Packet Capture Stream
	// ========================================================================
	if grpcClient.IsConnected() {
		if err := grpcClient.StartCapture(ctx, func(pkt *pb.PacketMetadata) {
			// Convert protobuf packet to internal model
			packet := convertPacket(pkt)

			// Process through inspection pipeline
			result, err := packetInspector.Inspect(ctx, packet)
			if err != nil {
				log.Error().Err(err).Msg("Inspection failed")
				return
			}

			// Send verdict back to SafeOps Engine
			verdictType := convertVerdictType(result.Verdict)
			cacheTTL := uint32(60) // Default 60s cache TTL

			if result.CacheHit {
				// Already cached, don't need to send again
				return
			}

			go grpcClient.SendVerdict(ctx, pkt.PacketId, verdictType, result.Reason,
				result.RuleID, cacheTTL, pkt.CacheKey)
		}); err != nil {
			log.Error().Err(err).Msg("Failed to start capture")
		} else {
			log.Info().Msg("Packet capture stream started")
		}
	}

	// ========================================================================
	// 9. Initialize Prometheus Metrics Exporter (Phase 5)
	// ========================================================================
	metricsConfig := metrics.DefaultExporterConfig()
	metricsConfig.Address = ":9090"
	metricsConfig.Path = "/metrics"

	metricsRegistry := metrics.NewDefaultRegistry()
	if err := metricsRegistry.Register(); err != nil {
		log.Error().Err(err).Msg("Failed to register metrics - continuing without metrics")
	} else {
		metricsExporter, err := metrics.NewExporter(metricsConfig, metricsRegistry)
		if err != nil {
			log.Error().Err(err).Msg("Failed to create metrics exporter")
		} else {
			if err := metricsExporter.StartAsync(); err != nil {
				log.Error().Err(err).Msg("Failed to start metrics exporter")
			} else {
				log.Info().Str("address", ":9090").Str("path", "/metrics").Msg("Prometheus metrics exporter started")
			}
		}
	}

	// ========================================================================
	// 10. Initialize Health Server (Phase 5)
	// ========================================================================
	healthAggregator := health.NewAggregator()

	// Register health checkers for all components
	healthAggregator.Register(health.NewFuncChecker("verdict_cache", true, func(ctx context.Context) health.CheckResult {
		if verdictCache == nil {
			return health.Unhealthy("Cache not initialized")
		}
		size := verdictCache.Size()
		if size > 90000 {
			return health.Degraded(fmt.Sprintf("Cache near capacity: %d/100000", size))
		}
		return health.Healthy(fmt.Sprintf("Cache healthy: %d entries", size))
	}))

	healthAggregator.Register(health.NewFuncChecker("connection_tracker", true, func(ctx context.Context) health.CheckResult {
		if connTracker == nil {
			return health.Unhealthy("Tracker not initialized")
		}
		count := connTracker.Count()
		if count > 450000 {
			return health.Degraded(fmt.Sprintf("Connections near limit: %d/500000", count))
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

	// Start health HTTP server
	healthConfig := health.DefaultHTTPConfig()
	healthConfig.Address = ":8085"

	healthServer, err := health.NewServer(healthConfig, healthAggregator)
	if err != nil {
		log.Error().Err(err).Msg("Failed to create health server")
	} else {
		if err := healthServer.StartAsync(); err != nil {
			log.Error().Err(err).Msg("Failed to start health server")
		} else {
			healthServer.SetStarted(true)
			log.Info().Str("address", ":8085").Msg("Health server started")
		}
	}

	// ========================================================================
	// 11. Initialize gRPC Management Server (Phase 5)
	// ========================================================================
	mgmtConfig := management.DefaultServerConfig()
	mgmtConfig.Address = ":50054"

	mgmtDeps := management.Dependencies{
		Logger:           log,
		HealthAggregator: healthAggregator,
		RollingStats:     metrics.GlobalStats(),
	}

	mgmtServer, err := management.NewServer(mgmtConfig, mgmtDeps)
	if err != nil {
		log.Error().Err(err).Msg("Failed to create management server")
	} else {
		if err := mgmtServer.StartAsync(); err != nil {
			log.Error().Err(err).Msg("Failed to start management server")
		} else {
			log.Info().Str("address", ":50054").Msg("gRPC management server started")
		}
	}

	// ========================================================================
	// 12. Statistics Reporter
	// ========================================================================
	go func() {
		ticker := time.NewTicker(30 * time.Second)
		defer ticker.Stop()

		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				printStats(packetInspector, verdictCache, connTracker, grpcClient, legacyLogger)
			}
		}
	}()

	// ========================================================================
	// Ready Message
	// ========================================================================
	separator := strings.Repeat("=", 60)
	fmt.Println("\n" + separator)
	fmt.Println("Firewall Engine V5 is RUNNING")
	fmt.Println(separator)
	fmt.Println("Dual-Engine Mode:")
	if dualEngine != nil {
		fmt.Printf("  • Mode:               %s\n", dualEngine.GetMode())
		if wfpEngine != nil && wfpEngine.IsOpen() {
			fmt.Println("  • SafeOps Engine:     ACTIVE (kernel-level packet filtering)")
			fmt.Println("  • WFP Engine:         ACTIVE (OS-level persistent filtering)")
		} else {
			fmt.Println("  • SafeOps Engine:     ACTIVE (kernel-level packet filtering)")
			fmt.Println("  • WFP Engine:         INACTIVE (run as Administrator)")
		}
	} else {
		fmt.Println("  • SafeOps Engine:     ACTIVE")
		fmt.Println("  • WFP Engine:         DISABLED")
	}
	fmt.Println(separator)
	fmt.Println("Components:")
	fmt.Println("  • Verdict Cache:      100K entries, 60s TTL")
	fmt.Println("  • Connection Tracker: 500K connections")
	fmt.Println("  • Fast-Path:          Gaming/VoIP bypass enabled")
	fmt.Println("  • Inspector:          8 workers, fail-open")
	fmt.Println("  • Enforcement:        DROP/BLOCK/REDIRECT/REJECT")
	fmt.Println(separator)
	fmt.Println("Phase 5 Servers:")
	fmt.Println("  • Metrics:            http://localhost:9090/metrics")
	fmt.Println("  • Health:             http://localhost:8085/health")
	fmt.Println("  • gRPC Management:    grpc://localhost:50054")
	fmt.Println(separator)
	fmt.Println("Performance Targets:")
	fmt.Println("  • Throughput:         100K+ pps")
	fmt.Println("  • Cache Hit Latency:  ~10-15μs")
	fmt.Println("  • Full Match Latency: ~50μs")
	fmt.Println(separator)
	fmt.Println("\nPress Ctrl+C to stop...")

	// ========================================================================
	// 11. Wait for Shutdown Signal
	// ========================================================================
	// ========================================================================
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	<-sigCh

	fmt.Println("\n\nShutting down Firewall Engine...")

	// Cancel context
	cancel()

	// Graceful shutdown - stop components in reverse order

	// Stop Phase 5 servers first
	if mgmtServer != nil {
		if err := mgmtServer.Stop(); err != nil {
			log.Error().Err(err).Msg("Error stopping management server")
		}
	}

	if healthServer != nil {
		if err := healthServer.Stop(); err != nil {
			log.Error().Err(err).Msg("Error stopping health server")
		}
	}

	if dualEngine != nil {
		if err := dualEngine.Stop(); err != nil {
			log.Error().Err(err).Msg("Error stopping dual-engine")
		}
	}

	if err := packetInspector.Stop(); err != nil {
		log.Error().Err(err).Msg("Error stopping inspector")
	}

	if err := verdictCache.Stop(); err != nil {
		log.Error().Err(err).Msg("Error stopping cache")
	}

	// Print final statistics
	printFinalStats(packetInspector, verdictCache, connTracker, legacyLogger)

	fmt.Println("Firewall Engine stopped.")
}

// ============================================================================
// Helper Functions
// ============================================================================

// convertPacket converts protobuf packet to internal model.
func convertPacket(pkt *pb.PacketMetadata) *models.PacketMetadata {
	return &models.PacketMetadata{
		SrcIP:    pkt.SrcIp,
		DstIP:    pkt.DstIp,
		SrcPort:  uint16(pkt.SrcPort),
		DstPort:  uint16(pkt.DstPort),
		Protocol: models.Protocol(pkt.Protocol),
	}
}

// convertVerdictType converts internal verdict to protobuf.
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

// printStats prints periodic statistics.
func printStats(insp *inspector.Inspector, cache *cache.VerdictCache,
	conn *connection.Tracker, _ *integration.SafeOpsGRPCClient, logger *log.Logger) {

	inspStats := insp.GetStats()
	cacheStats := cache.GetStats()
	connCount := conn.Count()

	logger.Printf("[STATS] Packets: recv=%d proc=%d | Cache: hit=%.1f%% size=%d | Conn: %d",
		inspStats.PacketsReceived.Load(),
		inspStats.PacketsProcessed.Load(),
		cacheStats.GetHitRate(),
		cache.Size(),
		connCount,
	)
}

// printFinalStats prints final statistics on shutdown.
func printFinalStats(insp *inspector.Inspector, cache *cache.VerdictCache,
	conn *connection.Tracker, _ *log.Logger) {

	inspStats := insp.GetStats()
	cacheStats := cache.GetStats()
	connCount := conn.Count()

	separator := strings.Repeat("=", 60)
	fmt.Println("\n" + separator)
	fmt.Println("Final Statistics")
	fmt.Println(separator)
	fmt.Printf("Packets Received:    %d\n", inspStats.PacketsReceived.Load())
	fmt.Printf("Packets Processed:   %d\n", inspStats.PacketsProcessed.Load())
	fmt.Printf("Packets Dropped:     %d\n", inspStats.PacketsDropped.Load())
	fmt.Printf("Cache Hits:          %d\n", cacheStats.Hits.Load())
	fmt.Printf("Cache Misses:        %d\n", cacheStats.Misses.Load())
	fmt.Printf("Cache Hit Rate:      %.2f%%\n", cacheStats.GetHitRate())
	fmt.Printf("Active Connections:  %d\n", connCount)
	fmt.Println(separator)
}
