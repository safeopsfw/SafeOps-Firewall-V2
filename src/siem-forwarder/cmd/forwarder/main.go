package main

import (
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

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

	// Wait for Elasticsearch to be available before proceeding
	if err := waitForElasticsearch(cfg.Elasticsearch.Hosts, cfg.Elasticsearch.Username, cfg.Elasticsearch.Password); err != nil {
		log.Fatalf("Elasticsearch not available: %v", err)
	}

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

	// Start retention manager if enabled
	var retMgr *shipper.RetentionManager
	if cfg.Retention.Enabled {
		retMgr = shipper.NewRetentionManager(shipper.RetentionConfig{
			Hosts:         cfg.Elasticsearch.Hosts,
			Username:      cfg.Elasticsearch.Username,
			Password:      cfg.Elasticsearch.Password,
			MaxDays:       cfg.Retention.MaxDays,
			CheckInterval: cfg.Retention.CheckInterval,
		})
		retMgr.Start()
		log.Printf("Retention manager started (max_days=%d, check_interval=%s)",
			cfg.Retention.MaxDays, cfg.Retention.CheckInterval)
	}

	log.Printf("SIEM Forwarder running. Monitoring %d files. Press Ctrl+C to stop.", len(tailers))

	// Wait for shutdown signal
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)
	<-sigChan

	log.Println("Shutting down...")

	// Stop retention manager
	if retMgr != nil {
		retMgr.Stop()
	}

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

// waitForElasticsearch blocks until at least one ES host responds with a healthy cluster status.
// Retries indefinitely with backoff (2s → 5s → 10s → 10s...), logging each attempt.
// This ensures log shipping doesn't start (and lose data) before ES is ready.
func waitForElasticsearch(hosts []string, username, password string) error {
	if len(hosts) == 0 {
		return fmt.Errorf("no Elasticsearch hosts configured")
	}

	client := &http.Client{Timeout: 5 * time.Second}
	backoffs := []time.Duration{2 * time.Second, 5 * time.Second, 10 * time.Second}
	attempt := 0

	log.Println("[SIEM] Waiting for Elasticsearch to be available...")

	for {
		for _, host := range hosts {
			url := host + "/_cluster/health?timeout=3s"
			req, err := http.NewRequest("GET", url, nil)
			if err != nil {
				continue
			}
			if username != "" {
				req.SetBasicAuth(username, password)
			}

			resp, err := client.Do(req)
			if err != nil {
				continue
			}
			resp.Body.Close()

			if resp.StatusCode >= 200 && resp.StatusCode < 300 {
				log.Printf("[SIEM] Elasticsearch is ready at %s (status: %d)", host, resp.StatusCode)
				return nil
			}
		}

		// Pick backoff duration (cap at last value)
		delay := backoffs[len(backoffs)-1]
		if attempt < len(backoffs) {
			delay = backoffs[attempt]
		}
		attempt++

		log.Printf("[SIEM] Elasticsearch not ready (attempt %d), retrying in %s...", attempt, delay)
		time.Sleep(delay)
	}
}
