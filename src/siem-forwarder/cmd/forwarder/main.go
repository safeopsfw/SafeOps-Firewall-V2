package main

import (
	"flag"
	"log"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"

	"github.com/safeops/siem-forwarder/internal/config"
	"github.com/safeops/siem-forwarder/internal/shipper"
	"github.com/safeops/siem-forwarder/internal/tailer"
)

func main() {
	// Parse command line flags
	configPath := flag.String("config", "configs/config.yaml", "Path to configuration file")
	flag.Parse()

	log.SetFlags(log.LstdFlags | log.Lshortfile)
	log.Println("SafeOps SIEM Log Forwarder starting...")

	// Load configuration
	cfg, err := config.Load(*configPath)
	if err != nil {
		log.Fatalf("Failed to load config: %v", err)
	}

	log.Printf("Loaded configuration with %d log files to monitor", len(cfg.LogFiles))

	// Resolve log base path relative to executable
	exePath, err := os.Executable()
	if err != nil {
		log.Fatalf("Failed to get executable path: %v", err)
	}
	exeDir := filepath.Dir(exePath)
	basePath := filepath.Join(exeDir, cfg.LogBasePath)

	// Also resolve position DB path
	posDBPath := filepath.Join(exeDir, cfg.PositionDB.Path)

	// Initialize position database
	posDB, err := tailer.NewPositionDB(posDBPath)
	if err != nil {
		log.Fatalf("Failed to initialize position database: %v", err)
	}

	// Create shared channel for log entries
	logChannel := make(chan tailer.LogEntry, 1000)

	// Create and start the Elasticsearch shipper
	ship := shipper.New(shipper.Config{
		Hosts:         cfg.Elasticsearch.Hosts,
		Username:      cfg.Elasticsearch.Username,
		Password:      cfg.Elasticsearch.Password,
		BulkSize:      cfg.Elasticsearch.BulkSize,
		FlushInterval: cfg.Elasticsearch.FlushInterval,
		Input:         logChannel,
	})
	ship.Start()
	log.Println("Elasticsearch shipper started")

	// Create and start tailers for each log file
	var tailers []*tailer.Tailer
	for _, logFile := range cfg.LogFiles {
		fullPath := filepath.Join(basePath, logFile.Path)
		t := tailer.NewTailer(tailer.TailerConfig{
			Path:         fullPath,
			IndexPrefix:  logFile.IndexPrefix,
			LogType:      logFile.Type,
			PollInterval: cfg.Tailer.PollInterval,
			MaxLineSize:  cfg.Tailer.MaxLineSize,
			PositionDB:   posDB,
			Output:       logChannel,
		})
		if err := t.Start(); err != nil {
			log.Printf("Warning: Failed to start tailer for %s: %v", fullPath, err)
			continue
		}
		tailers = append(tailers, t)
		log.Printf("Started tailing: %s -> %s", logFile.Path, logFile.IndexPrefix)
	}

	// Start position database auto-save
	stopSave := make(chan struct{})
	posDB.StartAutoSave(cfg.PositionDB.SaveInterval, stopSave)

	log.Printf("SIEM Forwarder running. Monitoring %d files. Press Ctrl+C to stop.", len(tailers))

	// Wait for shutdown signal
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)
	<-sigChan

	log.Println("Shutting down...")

	// Stop all tailers
	for _, t := range tailers {
		t.Stop()
	}

	// Close the log channel to signal shipper
	close(logChannel)

	// Stop the shipper (will flush remaining)
	ship.Stop()

	// Stop position saving and save final positions
	close(stopSave)

	sent, errors := ship.Stats()
	log.Printf("Shutdown complete. Total documents sent: %d, errors: %d", sent, errors)
}
