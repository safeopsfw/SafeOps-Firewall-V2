// NIC API Server - Standalone executable
// Provides REST API for NIC management with real-time traffic stats

package main

import (
	"log"
	"os"
	"os/signal"
	"syscall"

	"safeops/nic_management/api"
)

func main() {
	log.Println("Starting NIC Management API Server...")

	// Start API server on port 8081
	server, err := api.StartNICAPI(8081, "config.yaml")
	if err != nil {
		log.Fatalf("Failed to start API server: %v", err)
	}

	log.Println("NIC API server running on http://localhost:8081")
	log.Println("Endpoints:")
	log.Println("  GET  /api/nics       - List all NICs")
	log.Println("  GET  /api/nics/:id   - Get NIC by index")
	log.Println("  PATCH /api/nics/:id  - Update NIC alias/type")
	log.Println("  POST /api/nics/refresh - Force refresh")
	log.Println("  GET  /api/health     - Health check")

	// Wait for interrupt signal
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	<-quit

	log.Println("Shutting down...")
	server.Stop()
}
