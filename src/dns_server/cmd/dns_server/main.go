// Package main provides the DNS Server entry point.
package main

import (
	"context"
	"flag"
	"log"
	"os"
	"os/signal"
	"syscall"
	"time"

	"safeops/dns_server/internal/captive"
	"safeops/dns_server/internal/protocol"
	"safeops/dns_server/internal/server"
	"safeops/dns_server/internal/storage"
)

var (
	// Configuration flags
	listenAddr = flag.String("addr", ":53", "DNS server listen address")
	dbHost     = flag.String("db-host", "localhost", "PostgreSQL host")
	dbPort     = flag.Int("db-port", 5432, "PostgreSQL port")
	dbUser     = flag.String("db-user", "dns_server", "PostgreSQL username")
	dbName     = flag.String("db-name", "safeops_network", "PostgreSQL database name")
	dbPass     = flag.String("db-pass", "", "PostgreSQL password (or use DNS_DB_PASSWORD env)")

	// Captive portal flags
	captiveEnabled = flag.Bool("captive", true, "Enable captive portal redirect")
	portalIP       = flag.String("portal-ip", "192.168.1.1", "Captive portal IP address")
	portalPort     = flag.Int("portal-port", 80, "Captive portal port")

	// Feature flags
	recursion = flag.Bool("recursion", true, "Enable recursive DNS resolution")
)

func main() {
	flag.Parse()

	log.Printf("SafeOps DNS Server starting...")
	log.Printf("  Listen: %s", *listenAddr)
	log.Printf("  Captive Portal: %v (IP: %s)", *captiveEnabled, *portalIP)

	// Get password from environment if not provided
	password := *dbPass
	if password == "" {
		password = os.Getenv("DNS_DB_PASSWORD")
	}

	// Initialize database (optional - runs without DB for basic DNS)
	var db *storage.Database
	var err error

	if password != "" {
		dbConfig := &storage.DatabaseConfig{
			Host:              *dbHost,
			Port:              *dbPort,
			Database:          *dbName,
			Username:          *dbUser,
			Password:          password,
			SSLMode:           "disable",
			MaxConnections:    20,
			MinConnections:    5,
			ConnectionTimeout: 10 * time.Second,
		}

		db, err = storage.InitDatabase(dbConfig)
		if err != nil {
			log.Printf("Warning: Database connection failed: %v", err)
			log.Printf("Running in standalone mode (no persistent storage)")
		} else {
			log.Printf("Database connected")

			// Run migrations
			ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			if err := storage.RunMigrations(ctx, db); err != nil {
				log.Printf("Warning: Migration failed: %v", err)
			}
			cancel()
		}
	}

	// Create DNS handler
	handlerConfig := &protocol.HandlerConfig{
		RecursionEnabled: *recursion,
		CacheEnabled:     true,
		FilterEnabled:    true,
		CaptiveEnabled:   *captiveEnabled,
		AuthoritativeZones: []string{
			"safeops.local",
		},
	}
	handler := protocol.NewHandler(handlerConfig)

	// Initialize captive portal
	var captiveManager *captive.Manager
	if *captiveEnabled {
		captiveConfig := &captive.Config{
			Enabled:     true,
			PortalIP:    *portalIP,
			PortalPort:  *portalPort,
			PortalURL:   "http://" + *portalIP + "/install",
			CacheTTL:    5 * time.Minute,
			RedirectTTL: 60,
		}

		var dbConn interface{} = nil
		if db != nil {
			dbConn = db.GetPool()
		}
		_ = dbConn // Will be used when we integrate with tracker

		captiveManager = captive.NewManager(captiveConfig, nil)
		log.Printf("Captive portal enabled: redirect to %s", *portalIP)
	}

	// Create DNS server
	dnsServer := server.NewDNSServer(*listenAddr, handler)

	// Start server
	if err := dnsServer.Start(); err != nil {
		log.Fatalf("Failed to start DNS server: %v", err)
	}

	log.Printf("DNS Server running on %s", *listenAddr)

	// Wait for shutdown signal
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	<-sigCh

	log.Printf("Shutting down...")

	// Cleanup
	if captiveManager != nil {
		captiveManager.Stop()
	}
	dnsServer.Stop()
	if db != nil {
		db.Close()
	}

	log.Printf("DNS Server stopped")
}
