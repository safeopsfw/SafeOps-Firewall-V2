package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"github.com/google/gopacket/pcap"
	"github.com/safeops/network_logger/internal/capture"
	"github.com/safeops/network_logger/internal/collectors"
	"github.com/safeops/network_logger/internal/config"
	"github.com/safeops/network_logger/internal/dedup"
	"github.com/safeops/network_logger/internal/flow"
	"github.com/safeops/network_logger/internal/geoip"
	"github.com/safeops/network_logger/internal/hotspot"
	"github.com/safeops/network_logger/internal/process"
	"github.com/safeops/network_logger/internal/stats"
	"github.com/safeops/network_logger/internal/tls"
	"github.com/safeops/network_logger/internal/writer"
)

func main() {
	// Parse command-line flags
	listInterfaces := flag.Bool("list-interfaces", false, "List available network interfaces and exit")
	flag.Parse()

	// List interfaces mode
	if *listInterfaces {
		listAvailableInterfaces()
		return
	}

	// Print banner
	stats.PrintBanner()

	// Load configuration (hardcoded defaults)
	cfg := config.LoadDefault()

	log.Println("✅ Using embedded default configuration")

	// Create context for graceful shutdown
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Initialize components
	log.Println("🔧 Initializing components...")

	// 1. Interface scanner
	ifScanner := capture.NewInterfaceScanner(10 * time.Second)
	ifScanner.Start(ctx)

	// Wait for interfaces to be discovered
	time.Sleep(1 * time.Second)

	// 2. Stats collector
	statsCollector := stats.NewCollector()

	// 3. Flow tracker
	flowTracker := flow.NewTracker(
		cfg.GetFlowCleanupInterval(),
		cfg.GetFlowTimeout(),
	)
	go flowTracker.StartCleanup(ctx)

	// 4. Deduplication engine
	dedupEngine := dedup.NewEngine(
		cfg.Deduplication.CacheSize,
		cfg.Deduplication.WindowSeconds,
	)

	// 5. Process correlator
	processCorr := process.NewCorrelator(cfg.GetProcessCacheTTL())

	// 6. Hotspot device tracker
	hotspotTracker := hotspot.NewDeviceTracker()

	// 7. TLS key logger
	absKeylogPath, _ := filepath.Abs(cfg.TLS.KeylogFile)
	tlsKeyLogger := tls.NewKeyLogger(absKeylogPath)
	if cfg.TLS.Enabled {
		tlsKeyLogger.Start(ctx)
		log.Printf("🔐 TLS key logger monitoring: %s", absKeylogPath)
	}

	// 8. TLS decryptor
	tlsDecryptor := tls.NewDecryptor(tlsKeyLogger)

	// 9. GeoIP lookup (PostgreSQL)
	geoLookup := geoip.NewLookup(geoip.DefaultConfig())
	defer geoLookup.Close()

	// 10. Packet processor
	processor := capture.NewPacketProcessor(
		flowTracker,
		dedupEngine,
		processCorr,
		hotspotTracker,
		tlsDecryptor,
		statsCollector,
		geoLookup,
	)

	// 10. JSON writer
	absLogPath, _ := filepath.Abs(cfg.Logging.LogPath)

	// Ensure logs directory exists
	logDir := filepath.Dir(absLogPath)
	if err := os.MkdirAll(logDir, 0755); err != nil {
		log.Fatalf("❌ Failed to create logs directory: %v", err)
	}

	// Unknown IP tracker (tracks public IPs not in GeoIP database)
	unknownIPPath := filepath.Join(logDir, "unknown_ips.csv")
	unknownTracker := geoip.NewUnknownIPTracker(unknownIPPath)
	geoLookup.SetUnknownTracker(unknownTracker)
	log.Printf("📍 Unknown IP Tracker: %s", unknownIPPath)

	jsonWriter := writer.NewJSONWriter(
		absLogPath,
		cfg.Logging.BatchSize,
		cfg.GetLogCycleInterval(),
	)
	jsonWriter.Start(ctx)
	log.Printf("💾 Master log: %s (5-min cycle)", absLogPath)

	// 12. IDS Collector (Suricata EVE JSON, rotating 50MB)
	idsLogPath := filepath.Join(logDir, "ids_ips.jsonl")
	idsCollector := collectors.NewIDSCollector(idsLogPath, cfg.GetLogRotationInterval())
	idsCollector.Start(ctx)
	log.Printf("🛡️  IDS/IPS log: %s (EVE JSON, 50MB rotation)", idsLogPath)

	// 13. BiFlow Collector (NetFlow E-W / N-S, rotating 50MB)
	netflowDir := filepath.Join(logDir, "netflow")
	os.MkdirAll(netflowDir, 0755)
	ewLogPath := filepath.Join(netflowDir, "east_west.jsonl")
	nsLogPath := filepath.Join(netflowDir, "north_south.jsonl")
	biflowCollector := collectors.NewBiflowCollector(ewLogPath, nsLogPath, 50*1024*1024, 3)
	if err := biflowCollector.Start(ctx); err != nil {
		log.Fatalf("Failed to start NetFlow collector: %v", err)
	}
	log.Printf("🌐 NetFlow: %s, %s (IPFIX, 50MB rotation)", ewLogPath, nsLogPath)

	// 14. IP Summary Collector (5-min per-IP aggregation, rotating 50MB)
	ipSummaryPath := filepath.Join(logDir, "ip_summary.jsonl")
	ipSummaryCollector := collectors.NewIPSummaryCollector(ipSummaryPath, 5, 50*1024*1024, 3)
	if err := ipSummaryCollector.Start(ctx); err != nil {
		log.Fatalf("Failed to start IP Summary collector: %v", err)
	}
	log.Printf("📊 IP Summary: %s (5-min aggregation, 50MB rotation)", ipSummaryPath)

	// 11. Capture engine
	captureConfig := capture.CaptureConfig{
		Promiscuous:    cfg.Capture.Promiscuous,
		SnapshotLength: cfg.Capture.SnapshotLength,
		BPFFilter:      cfg.Capture.BPFFilter,
	}

	captureEngine := capture.NewCaptureEngine(captureConfig)

	// Get interfaces to capture from
	var interfaces []string
	if len(cfg.Capture.Interfaces) > 0 {
		interfaces = cfg.Capture.Interfaces
	} else {
		interfaces = ifScanner.GetActiveInterfaces()
	}

	if len(interfaces) == 0 {
		log.Fatal("❌ No network interfaces available for capture")
	}

	log.Printf("📡 Starting capture on %d interface(s)...", len(interfaces))

	// Start capture
	if err := captureEngine.Start(ctx, interfaces); err != nil {
		log.Fatalf("❌ Failed to start capture: %v", err)
	}

	// Packet processing pipeline
	go func() {
		for {
			select {
			case <-ctx.Done():
				return
			case rawPkt, ok := <-captureEngine.GetPacketQueue():
				if !ok {
					return
				}

				// Process packet
				pktLog, err := processor.ProcessPacket(rawPkt)
				if err != nil || pktLog == nil {
					continue
				}

				// Write to master log
				jsonWriter.Write(pktLog)

				// Route to collectors
				idsCollector.Process(pktLog)
				biflowCollector.Process(pktLog)
				ipSummaryCollector.Process(pktLog)
			}
		}
	}()

	// Stats display loop
	go func() {
		ticker := time.NewTicker(cfg.GetStatsDisplayInterval())
		defer ticker.Stop()

		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				writerStats := jsonWriter.GetStats()
				dedupStats := dedupEngine.GetStats()
				tlsStats := stats.TLSStats{
					TotalKeys:  tlsKeyLogger.GetStats().TotalKeys,
					RecentKeys: tlsKeyLogger.GetStats().RecentKeys,
				}

				statsCollector.DisplayStats(writerStats, dedupStats, tlsStats)
			}
		}
	}()

	log.Println("✅ SafeOps Network Logger is running!")
	log.Println("📊 Live statistics will appear every 2 minutes")
	log.Println("🛑 Press Ctrl+C to stop")
	fmt.Println()

	// Wait for interrupt signal
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM)
	<-sigChan

	// Graceful shutdown
	fmt.Println("\n\n🛑 Shutting down...")
	cancel()

	// Give time for goroutines to finish
	time.Sleep(2 * time.Second)

	// Stop capture
	captureEngine.Stop()

	// Print final statistics
	writerStats := jsonWriter.GetStats()
	statsCollector.PrintShutdownStats(writerStats)

	log.Println("✅ SafeOps Network Logger stopped cleanly")
}

// listAvailableInterfaces lists all network interfaces
func listAvailableInterfaces() {
	devices, err := pcap.FindAllDevs()
	if err != nil {
		log.Fatalf("Error finding devices: %v", err)
	}

	fmt.Println("\n📡 Available Network Interfaces:")
	fmt.Println("═══════════════════════════════════════════════════════════")

	for i, device := range devices {
		fmt.Printf("\n[%d] %s\n", i+1, device.Name)
		if device.Description != "" {
			fmt.Printf("    Description: %s\n", device.Description)
		}

		if len(device.Addresses) > 0 {
			fmt.Println("    Addresses:")
			for _, addr := range device.Addresses {
				fmt.Printf("      - %s\n", addr.IP.String())
			}
		} else {
			fmt.Println("    Status: No addresses (disconnected)")
		}
	}

	fmt.Println("\n═══════════════════════════════════════════════════════════")
	fmt.Printf("Total interfaces found: %d\n\n", len(devices))
}
