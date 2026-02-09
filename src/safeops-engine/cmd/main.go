package main

import (
	"fmt"
	"os"
	"os/signal"
	"syscall"
	"time"

	"safeops-engine/pkg/engine"
)

func main() {
	fmt.Println("=== SafeOps Network Pipeline ===")
	fmt.Println("Version: 5.0.0 (Enterprise Domain Blocking + VPN/DoH Defense)")
	fmt.Println("Starting...")

	// Initialize SafeOps Engine
	eng, err := engine.Initialize()
	if err != nil {
		fmt.Printf("[ERROR] Failed to initialize SafeOps Engine: %v\n", err)
		os.Exit(1)
	}
	defer eng.Shutdown()

	fmt.Println("\nSafeOps Engine is running")
	fmt.Println("  gRPC metadata stream: 127.0.0.1:50051")
	fmt.Println("  Control API:          127.0.0.1:50052")
	fmt.Println("\nReady for subscribers (Firewall, IDS, IPS, etc.)")
	fmt.Println("Press Ctrl+C to stop...")
	fmt.Println()

	// Stats logging every 30 seconds
	go func() {
		ticker := time.NewTicker(30 * time.Second)
		defer ticker.Stop()
		for {
			<-ticker.C
			stats := eng.GetEnhancedStats()
			fmt.Printf("\n[STATS] Read=%v Written=%v Dropped=%v | Domains blocked=%v DoH blocked=%v VPN blocked=%v\n\n",
				stats["packets_read"], stats["packets_written"], stats["packets_dropped"],
				stats["domains_blocked"], stats["doh_blocked"], stats["vpn_blocked"])
		}
	}()

	// Wait for shutdown
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM)
	<-sigChan

	fmt.Println("\n\nShutting down SafeOps Engine...")
	time.Sleep(1 * time.Second)

	// Final stats
	stats := eng.GetEnhancedStats()
	fmt.Printf("\nFinal Statistics:\n")
	fmt.Printf("  Packets Read:     %v\n", stats["packets_read"])
	fmt.Printf("  Packets Written:  %v\n", stats["packets_written"])
	fmt.Printf("  Packets Dropped:  %v\n", stats["packets_dropped"])
	fmt.Printf("  Fast Path:        %v\n", stats["fast_path_packets"])
	fmt.Printf("  Slow Path:        %v\n", stats["slow_path_packets"])
	fmt.Printf("  Domains Blocked:  %v\n", stats["domains_blocked"])
	fmt.Printf("  DoH Blocked:      %v\n", stats["doh_blocked"])
	fmt.Printf("  VPN Blocked:      %v\n", stats["vpn_blocked"])

	fmt.Println("\nSafeOps Engine stopped.")
}
