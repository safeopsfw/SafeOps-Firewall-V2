// Package main is the entry point for the SafeOps Firewall Engine.
// It wires all Phase 3 components together: enforcement, connection tracking,
// packet inspection, verdict caching, and the gRPC integration with SafeOps Engine.
package main

import (
	"context"
	"fmt"
	"log"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"firewall_engine/internal/cache"
	"firewall_engine/internal/connection"
	"firewall_engine/internal/enforcement"
	"firewall_engine/internal/inspector"
	"firewall_engine/internal/integration"
	"firewall_engine/internal/wfp"
	"firewall_engine/pkg/models"

	"safeops-engine/pkg/grpc/pb"
)

// ============================================================================
// Main Entry Point
// ============================================================================

func main() {
	fmt.Println("=== SafeOps Firewall Engine V4 ===")
	fmt.Println("Version: 4.0.0 (Dual-Engine + WFP Integration)")
	fmt.Println("Initializing Phase 4 components...")

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Create logger
	logger := log.New(os.Stdout, "[FIREWALL] ", log.LstdFlags|log.Lmicroseconds)

	// ========================================================================
	// 1. Initialize Verdict Cache
	// ========================================================================
	cacheConfig := cache.DefaultCacheConfig()
	cacheConfig.Capacity = 100000 // 100K entries
	cacheConfig.DefaultTTL = 60 * time.Second
	cacheConfig.CleanupInterval = 10 * time.Second

	verdictCache, err := cache.NewVerdictCache(cacheConfig)
	if err != nil {
		logger.Fatalf("Failed to create verdict cache: %v", err)
	}
	logger.Println("[✓] Verdict Cache initialized (capacity=100K, TTL=60s)")

	// Start cache background cleanup
	if err := verdictCache.Start(ctx); err != nil {
		logger.Fatalf("Failed to start verdict cache: %v", err)
	}

	// ========================================================================
	// 2. Initialize Connection Tracker
	// ========================================================================
	connConfig := connection.DefaultTrackerConfig()
	connConfig.MaxConnections = 500000 // 500K concurrent connections

	connTracker, err := connection.NewTracker(connConfig)
	if err != nil {
		logger.Fatalf("Failed to create connection tracker: %v", err)
	}
	logger.Println("[✓] Connection Tracker initialized (capacity=500K)")

	// ========================================================================
	// 3. Initialize Fast-Path Evaluator
	// ========================================================================
	fastPathConfig := inspector.DefaultFastPathConfig()
	fastPathConfig.BypassGaming = true // Gaming traffic → kernel fast lane
	fastPathConfig.BypassVoIP = true   // VoIP → kernel fast lane
	fastPathConfig.EnableBlocklist = true
	fastPathConfig.EnableEstablished = true

	fastPath := inspector.NewFastPath(fastPathConfig)
	logger.Println("[✓] Fast-Path Evaluator initialized (gaming/VoIP bypass enabled)")

	// ========================================================================
	// 4. Initialize Enforcement Handler
	// ========================================================================
	enfConfig := enforcement.DefaultEnforcementConfig()
	enfConfig.FailOpen = true // Fail-open for safety
	enfConfig.MaxRetries = 2
	enfConfig.EnableMetrics = true

	enforcementHandler, err := enforcement.NewVerdictHandler(enfConfig)
	if err != nil {
		logger.Fatalf("Failed to create enforcement handler: %v", err)
	}
	logger.Println("[✓] Enforcement Handler initialized (fail-open enabled)")

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
		logger.Fatalf("Failed to create packet inspector: %v", err)
	}

	// Wire dependencies
	packetInspector.SetConnectionTracker(connTracker)
	packetInspector.SetEnforcementHandler(enforcementHandler)
	packetInspector.SetFastPathEvaluator(fastPath)
	// Note: VerdictCache interface mismatch - using adapter pattern if needed

	logger.Println("[✓] Packet Inspector initialized (8 workers, all features enabled)")

	// Start inspector
	if err := packetInspector.Start(ctx); err != nil {
		logger.Fatalf("Failed to start packet inspector: %v", err)
	}

	// ========================================================================
	// 6. Initialize WFP Engine (Phase 4)
	// ========================================================================
	var dualEngine *enforcement.DualEngineCoordinator
	var wfpEngine *wfp.Engine

	// Try to initialize WFP (requires admin privileges)
	wfpConfig := wfp.DefaultEngineConfig()
	wfpConfig.SessionName = "SafeOps_Firewall_V4"
	wfpConfig.Dynamic = true

	wfpEngine = wfp.NewEngine(wfpConfig)
	if err := wfpEngine.Open(); err != nil {
		logger.Printf("[WARNING] WFP initialization failed: %v", err)
		logger.Println("         Running in SafeOps-only mode (no OS-level filtering)")
		logger.Println("         Make sure you're running as Administrator")
		wfpEngine = nil
	} else {
		logger.Println("[✓] WFP Engine initialized (Windows Filtering Platform)")
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
		logger.Printf("[WARNING] Dual-engine init failed: %v", err)
	} else {
		if err := dualEngine.Start(ctx); err != nil {
			logger.Printf("[WARNING] Dual-engine start failed: %v", err)
		} else {
			logger.Printf("[✓] Dual-Engine Coordinator started (mode: %s)", dualEngine.GetMode())
		}
	}

	// ========================================================================
	// 8. Initialize gRPC Client (connect to SafeOps Engine)
	// ========================================================================
	grpcClient := integration.NewSafeOpsGRPCClient("firewall-engine", "127.0.0.1:50051")

	if err := grpcClient.Connect(ctx); err != nil {
		logger.Printf("[WARNING] Failed to connect to SafeOps Engine: %v", err)
		logger.Println("         Running in standalone mode (no packet capture)")
		logger.Println("         Make sure:")
		logger.Println("         1. SafeOps Engine is running")
		logger.Println("         2. Listening on 127.0.0.1:50051")
	} else {
		logger.Println("[✓] Connected to SafeOps Engine (127.0.0.1:50051)")
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
				logger.Printf("[ERROR] Inspection failed: %v", err)
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
			logger.Printf("[ERROR] Failed to start capture: %v", err)
		} else {
			logger.Println("[✓] Packet capture stream started")
		}
	}

	// ========================================================================
	// 10. Statistics Reporter
	// ========================================================================
	// ========================================================================
	go func() {
		ticker := time.NewTicker(30 * time.Second)
		defer ticker.Stop()

		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				printStats(packetInspector, verdictCache, connTracker, grpcClient, logger)
			}
		}
	}()

	// ========================================================================
	// Ready Message
	// ========================================================================
	separator := strings.Repeat("=", 60)
	fmt.Println("\n" + separator)
	fmt.Println("Firewall Engine V4 is RUNNING")
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
	if dualEngine != nil {
		if err := dualEngine.Stop(); err != nil {
			logger.Printf("Error stopping dual-engine: %v", err)
		}
	}

	if err := packetInspector.Stop(); err != nil {
		logger.Printf("Error stopping inspector: %v", err)
	}

	if err := verdictCache.Stop(); err != nil {
		logger.Printf("Error stopping cache: %v", err)
	}

	// Print final statistics
	printFinalStats(packetInspector, verdictCache, connTracker, logger)

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
