// Package main is the entry point for the Threat Intelligence Service
// It starts both the REST API server and the background worker for feed processing
package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"threat_intel/config"
	"threat_intel/src/api"
	"threat_intel/src/storage"
	"threat_intel/src/ui"
	"threat_intel/src/worker"
)

var (
	configPath = flag.String("config", "config/config.yaml", "Path to configuration file")
	version    = "2.0.0"
	buildTime  = "unknown"
)

func main() {
	flag.Parse()

	// Banner
	printBanner()

	// Load configuration
	cfg, err := config.LoadConfig(*configPath)
	if err != nil {
		log.Fatalf("Failed to load configuration: %v", err)
	}

	log.Printf("Loaded configuration from: %s", *configPath)

	// Initialize database connection
	db, err := storage.NewDB(cfg.Database)
	if err != nil {
		log.Fatalf("Failed to connect to database: %v", err)
	}
	defer db.Close()

	log.Println("Database connection established")

	// Create context for graceful shutdown
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Initialize background worker
	w := worker.NewWorker(cfg, db)
	go w.Start(ctx)

	log.Println("Background worker started")

	// Initialize API server
	apiServer := api.NewServer(cfg, db)
	apiRouter := apiServer.SetupRoutes()

	// Initialize UI server
	uiServer, err := ui.NewServer(cfg, db)
	if err != nil {
		log.Fatalf("Failed to initialize UI server: %v", err)
	}

	// Get UI routes
	uiRouter := uiServer.SetupRoutes()

	// Create combined HTTP server
	mainMux := http.NewServeMux()

	// API routes (/api/*)
	// Strip prefix so API handler receives path from root
	mainMux.Handle("/api/", http.StripPrefix("/api", apiRouter))

	// Health check endpoint
	mainMux.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		fmt.Fprintf(w, `{"status":"healthy","version":"%s","build":"%s"}`, version, buildTime)
	})

	// UI routes (everything else)
	// Note: UI router handles static assets too
	mainMux.Handle("/", uiRouter)

	// Determine port
	port := cfg.API.Port
	if port == 0 {
		port = 8080 // Fallback
	}

	// HTTP Server configuration
	server := &http.Server{
		Addr:         fmt.Sprintf(":%d", port),
		Handler:      mainMux,
		ReadTimeout:  15 * time.Second,
		WriteTimeout: 15 * time.Second,
		IdleTimeout:  60 * time.Second,
	}

	// Start server in goroutine
	go func() {
		log.Printf("Server starting on port %d", port)
		log.Printf("API endpoints: http://localhost:%d/api/v1/", port)
		log.Printf("Web UI: http://localhost:%d/", port)

		if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatalf("Server failed: %v", err)
		}
	}()

	// Wait for interrupt signal
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	<-quit

	log.Println("Shutdown signal received, gracefully shutting down...")

	// Shutdown context with timeout
	shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer shutdownCancel()

	// Stop worker
	cancel()

	// Shutdown HTTP server
	if err := server.Shutdown(shutdownCtx); err != nil {
		log.Printf("Server shutdown error: %v", err)
	}

	log.Println("Server stopped gracefully")
}

func printBanner() {
	banner := `
╔══════════════════════════════════════════════════════════════╗
║                   THREAT INTELLIGENCE SERVICE                 ║
║                         SafeOps v2.0                          ║
╚══════════════════════════════════════════════════════════════╝
`
	fmt.Println(banner)
	fmt.Printf("Version: %s | Build: %s\n\n", version, buildTime)
}
