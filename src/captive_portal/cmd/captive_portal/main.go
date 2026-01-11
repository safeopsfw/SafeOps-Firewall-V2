// ============================================================================
// SafeOps Captive Portal - Main Entry Point
// ============================================================================
// File: D:\SafeOpsFV2\src\captive_portal\cmd\captive_portal\main.go
// Purpose: Application entry point - loads config, initializes services, starts server
//
// Usage:
//   go run cmd/captive_portal/main.go
//   go run cmd/captive_portal/main.go -config path/to/config.yaml
//   captive_portal.exe -config config/captive_portal.yaml
//
// Environment Variables:
//   CAPTIVE_PORTAL_CONFIG - Path to configuration file
//
// Author: SafeOps Phase 3A
// Date: 2026-01-03
// ============================================================================

package main

import (
	"flag"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"runtime"
	"time"

	"captive_portal/internal/config"
	"captive_portal/internal/server"
)

// ============================================================================
// Version Information
// ============================================================================

var (
	version   = "1.0.0"
	buildTime = "2026-01-03"
	gitCommit = "unknown"
)

// ============================================================================
// Configuration
// ============================================================================

var (
	configPath  string
	showVersion bool
	showHelp    bool
)

func init() {
	// Command-line flags
	flag.StringVar(&configPath, "config", "", "Path to configuration file")
	flag.StringVar(&configPath, "c", "", "Path to configuration file (shorthand)")
	flag.BoolVar(&showVersion, "version", false, "Show version information")
	flag.BoolVar(&showVersion, "v", false, "Show version (shorthand)")
	flag.BoolVar(&showHelp, "help", false, "Show help message")
	flag.BoolVar(&showHelp, "h", false, "Show help (shorthand)")
}

// ============================================================================
// Main Entry Point
// ============================================================================

func main() {
	// Parse command-line flags
	flag.Parse()

	// Handle version flag
	if showVersion {
		printVersion()
		os.Exit(0)
	}

	// Handle help flag
	if showHelp {
		printHelp()
		os.Exit(0)
	}

	// Print startup banner
	printBanner()

	// Determine configuration path
	configPath = resolveConfigPath(configPath)
	log.Printf("[Main] Using configuration: %s", configPath)

	// Load configuration
	cfg, err := config.LoadConfig(configPath)
	if err != nil {
		log.Fatalf("[Main] Failed to load configuration: %v", err)
	}
	log.Printf("[Main] Configuration loaded successfully")

	// Create and start server
	srv, err := server.NewServer(cfg)
	if err != nil {
		log.Fatalf("[Main] Failed to create server: %v", err)
	}

	// Start server
	if err := srv.Start(); err != nil {
		log.Fatalf("[Main] Failed to start server: %v", err)
	}

	log.Printf("[Main] Server started successfully")
	log.Printf("[Main] Portal URL: https://localhost:%d", cfg.Server.HTTPSPort)
	log.Printf("[Main] Press Ctrl+C to stop")

	// Wait for shutdown
	if err := srv.Wait(); err != nil {
		log.Printf("[Main] Server shutdown error: %v", err)
		os.Exit(1)
	}

	log.Printf("[Main] Server stopped")
}

// ============================================================================
// Helper Functions
// ============================================================================

// resolveConfigPath determines the configuration file path
func resolveConfigPath(provided string) string {
	// 1. Use provided path if given
	if provided != "" {
		return provided
	}

	// 2. Check environment variable
	if envPath := os.Getenv("CAPTIVE_PORTAL_CONFIG"); envPath != "" {
		return envPath
	}

	// 3. Check common locations
	commonPaths := []string{
		"config/captive_portal.yaml",
		"captive_portal.yaml",
		"config.yaml",
		filepath.Join(os.Getenv("USERPROFILE"), ".safeops", "captive_portal.yaml"),
		"D:\\SafeOpsFV2\\src\\captive_portal\\config\\captive_portal.yaml",
	}

	for _, path := range commonPaths {
		if _, err := os.Stat(path); err == nil {
			return path
		}
	}

	// 4. Default fallback
	return "config/captive_portal.yaml"
}

// printBanner prints the startup banner
func printBanner() {
	banner := `
╔═══════════════════════════════════════════════════════════════╗
║                 SafeOps Captive Portal                        ║
║               CA Certificate Distribution                      ║
╠═══════════════════════════════════════════════════════════════╣
║  Version: %-10s                                           ║
║  Build:   %-10s                                           ║
║  Runtime: %-10s                                           ║
╚═══════════════════════════════════════════════════════════════╝
`
	fmt.Printf(banner, version, buildTime, runtime.Version())
	fmt.Println()
}

// printVersion prints version information
func printVersion() {
	fmt.Printf("SafeOps Captive Portal v%s\n", version)
	fmt.Printf("Build Time: %s\n", buildTime)
	fmt.Printf("Git Commit: %s\n", gitCommit)
	fmt.Printf("Go Version: %s\n", runtime.Version())
	fmt.Printf("OS/Arch:    %s/%s\n", runtime.GOOS, runtime.GOARCH)
}

// printHelp prints help message
func printHelp() {
	fmt.Println("SafeOps Captive Portal - CA Certificate Distribution Server")
	fmt.Println()
	fmt.Println("Usage:")
	fmt.Println("  captive_portal [options]")
	fmt.Println()
	fmt.Println("Options:")
	fmt.Println("  -c, -config string   Path to configuration file")
	fmt.Println("  -v, -version         Show version information")
	fmt.Println("  -h, -help            Show this help message")
	fmt.Println()
	fmt.Println("Environment Variables:")
	fmt.Println("  CAPTIVE_PORTAL_CONFIG   Path to configuration file")
	fmt.Println()
	fmt.Println("Examples:")
	fmt.Println("  captive_portal")
	fmt.Println("  captive_portal -c /path/to/config.yaml")
	fmt.Println("  CAPTIVE_PORTAL_CONFIG=config.yaml captive_portal")
	fmt.Println()
	fmt.Println("Default Configuration Paths (checked in order):")
	fmt.Println("  1. config/captive_portal.yaml")
	fmt.Println("  2. captive_portal.yaml")
	fmt.Println("  3. config.yaml")
	fmt.Println("  4. $USERPROFILE/.safeops/captive_portal.yaml")
	fmt.Println("  5. D:\\SafeOpsFV2\\src\\captive_portal\\config\\captive_portal.yaml")
}

// ============================================================================
// Initialization Logging
// ============================================================================

func init() {
	// Configure structured logging
	log.SetFlags(log.Ldate | log.Ltime | log.Lmicroseconds | log.Lshortfile)
	log.SetPrefix("[CaptivePortal] ")

	// Log startup time
	log.Printf("[Init] Application starting at %s", time.Now().Format(time.RFC3339))
}
