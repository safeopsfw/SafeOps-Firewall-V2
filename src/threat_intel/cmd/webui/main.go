// Package main implements the threat intelligence web UI
package main

import (
	"context"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"
)

func main() {
	log.Println("Starting Threat Intelligence Web UI...")

	// TODO: Load configuration
	// TODO: Initialize database connection
	// TODO: Setup web server with routes
	// TODO: Serve static assets and templates

	server := &http.Server{
		Addr:         ":8080",
		ReadTimeout:  15 * time.Second,
		WriteTimeout: 15 * time.Second,
		IdleTimeout:  60 * time.Second,
	}

	// TODO: Configure routes
	// http.HandleFunc("/", dashboardHandler)
	// http.HandleFunc("/api/feeds", feedsHandler)
	// http.HandleFunc("/api/iocs", iocsHandler)

	// Start server in goroutine
	go func() {
		log.Printf("Web UI listening on %s", server.Addr)
		if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatalf("Server error: %v", err)
		}
	}()

	// Setup graceful shutdown
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM)
	<-sigChan

	log.Println("Shutdown signal received, gracefully stopping...")
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	if err := server.Shutdown(ctx); err != nil {
		log.Printf("Server shutdown error: %v", err)
	}

	log.Println("Web UI shutdown complete")
}
