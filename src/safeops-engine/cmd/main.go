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
	fmt.Println("Version: 4.0.0 (Fast/Slow Path + Control API)")
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
			read, written, dropped := eng.GetStats()
			fmt.Printf("\n[STATS] Read=%d Written=%d Dropped=%d\n\n", read, written, dropped)
		}
	}()

	// Wait for shutdown
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM)
	<-sigChan

	fmt.Println("\n\nShutting down SafeOps Engine...")
	time.Sleep(1 * time.Second)

	// Final stats
	read, written, dropped := eng.GetStats()
	fmt.Printf("\nFinal Statistics:\n")
	fmt.Printf("  Packets Read: %d\n", read)
	fmt.Printf("  Packets Written: %d\n", written)
	fmt.Printf("  Packets Dropped: %d\n", dropped)

	fmt.Println("\nSafeOps Engine stopped.")
}
