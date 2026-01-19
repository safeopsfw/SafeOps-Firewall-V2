package main

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"sync/atomic"
	"syscall"
	"time"

	"safeops-engine/internal/config"
	"safeops-engine/internal/driver"
	"safeops-engine/internal/logger"
)

func main() {
	fmt.Println("=== SafeOps Network Pipeline ===")
	fmt.Println("Version: 3.0.0 (Pure Passthrough)")
	fmt.Println("Starting...")

	// Load configuration
	cfg, err := config.Load("configs/engine.yaml")
	if err != nil {
		cfg, err = config.Load("src/safeops-engine/configs/engine.yaml")
		if err != nil {
			fmt.Printf("Failed to load config: %v\n", err)
			os.Exit(1)
		}
		fmt.Println("Loaded config from: src/safeops-engine/configs/engine.yaml")
	}

	// Initialize logger
	log := logger.New(cfg.Logging)
	log.Info("SafeOps Engine starting", map[string]interface{}{
		"version": "3.0.0",
		"mode":    "pure-passthrough",
	})

	// Context for graceful shutdown
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Initialize WinpkFilter driver
	log.Info("Initializing WinpkFilter driver...", nil)
	drv, err := driver.Open(log)
	if err != nil {
		log.Error("Failed to open WinpkFilter driver", map[string]interface{}{"error": err.Error()})
		os.Exit(1)
	}
	defer drv.Close()

	// List adapters
	adapters, _ := drv.GetAdapters()
	log.Info("Found adapters", map[string]interface{}{"count": len(adapters)})

	// Set tunnel mode on all physical adapters
	if err := drv.SetTunnelModeAll(); err != nil {
		log.Error("Failed to set tunnel mode", map[string]interface{}{"error": err.Error()})
		os.Exit(1)
	}

	log.Info("Pipeline ready - All packets captured and forwarded immediately", nil)

	// Packet counter
	var packetCount uint64

	// Packet handler: PURE PASSTHROUGH - No inspection, no modification
	drv.SetHandler(func(pkt *driver.ParsedPacket) bool {
		atomic.AddUint64(&packetCount, 1)
		return true // Always forward immediately
	})

	// Start packet processing
	log.Info("Starting packet processing...", nil)
	go drv.ProcessPacketsAll(ctx)

	// Stats logging every 30 seconds
	go func() {
		ticker := time.NewTicker(30 * time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				read, written, dropped := drv.GetStats()
				log.Info("Stats", map[string]interface{}{
					"packets_read":    read,
					"packets_written": written,
					"packets_dropped": dropped,
					"total_processed": atomic.LoadUint64(&packetCount),
				})
			}
		}
	}()

	// Wait for shutdown
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM)
	<-sigChan

	log.Info("Shutting down...", nil)
	cancel()
	time.Sleep(2 * time.Second)

	// Final stats
	read, written, dropped := drv.GetStats()
	log.Info("Final stats", map[string]interface{}{
		"total_processed": atomic.LoadUint64(&packetCount),
		"packets_read":    read,
		"packets_written": written,
		"packets_dropped": dropped,
	})

	log.Info("SafeOps Engine stopped", nil)
}
