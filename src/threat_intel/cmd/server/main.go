package main

import (
	"context"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"threat_intel/config"
	"threat_intel/src/api"
	"threat_intel/src/worker"
)

func main() {
	// Load configuration
	cfg, err := config.LoadConfig(config.GetDefaultConfigPath())
	if err != nil {
		log.Fatalf("Failed to load configuration: %v", err)
	}

	// Initialize API server
	apiHandler := api.NewRouter(cfg)
	server := &http.Server{
		Addr:         fmt.Sprintf(":%d", cfg.API.Port),
		Handler:      apiHandler,
		ReadTimeout:  time.Duration(cfg.API.ReadTimeout) * time.Second,
		WriteTimeout: time.Duration(cfg.API.WriteTimeout) * time.Second,
		IdleTimeout:  time.Duration(cfg.API.IdleTimeout) * time.Second,
	}

	// Start worker pool
	workerPool := worker.NewWorkerPool(cfg)
	go workerPool.Start()

	// Start API server
	go func() {
		log.Printf("Starting Threat Intel API server on port %d", cfg.API.Port)
		if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatalf("Server failed to start: %v", err)
		}
	}()

	// Graceful shutdown
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	<-quit

	log.Println("Shutting down server...")
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	workerPool.Stop()
	if err := server.Shutdown(ctx); err != nil {
		log.Fatalf("Server forced to shutdown: %v", err)
	}

	log.Println("Server exited")
}
