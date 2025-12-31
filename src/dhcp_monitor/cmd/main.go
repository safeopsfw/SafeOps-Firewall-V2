// Package main is the entry point for DHCP Monitor service
package main

import (
	"context"
	"dhcp_monitor/internal/arp_monitor"
	"dhcp_monitor/internal/captive_portal"
	"dhcp_monitor/internal/config"
	"dhcp_monitor/internal/dns_hijack"
	"dhcp_monitor/internal/nic_integration"
	"dhcp_monitor/internal/storage"
	"dhcp_monitor/internal/windows_dhcp"
	"flag"
	"fmt"
	"net"
	"os"
	"os/signal"
	"strings"
	"sync"
	"syscall"
	"time"
)

var (
	configPath = flag.String("config", "config/config.yaml", "Path to configuration file")
	version    = flag.Bool("version", false, "Print version and exit")
)

const (
	serviceName    = "DHCP Monitor"
	serviceVersion = "1.0.0"
)

func main() {
	flag.Parse()

	if *version {
		fmt.Printf("%s v%s\n", serviceName, serviceVersion)
		os.Exit(0)
	}

	logInfo("Starting %s v%s", serviceName, serviceVersion)

	// Load configuration
	cfg, err := config.Load(*configPath)
	if err != nil {
		logError("Failed to load configuration: %v", err)
		os.Exit(1)
	}

	logInfo("Configuration loaded successfully")

	// Create application
	app, err := NewApplication(cfg)
	if err != nil {
		logError("Failed to create application: %v", err)
		os.Exit(1)
	}

	// Start application
	if err := app.Start(); err != nil {
		logError("Failed to start application: %v", err)
		os.Exit(1)
	}

	// Wait for termination signal
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM)
	<-sigChan

	logInfo("Shutdown signal received, stopping services...")

	// Graceful shutdown
	if err := app.Stop(); err != nil {
		logError("Shutdown error: %v", err)
		os.Exit(1)
	}

	logInfo("DHCP Monitor stopped successfully")
}

// Application holds all service components
type Application struct {
	cfg    *config.Config
	ctx    context.Context
	cancel context.CancelFunc
	wg     sync.WaitGroup

	// Components
	db           *storage.Database
	arpMonitor   *arp_monitor.Monitor
	dnsServer    *dns_hijack.Server
	portalServer *captive_portal.Server
	nicDetector  *nic_integration.NICDetector
}

// NewApplication creates a new application instance
func NewApplication(cfg *config.Config) (*Application, error) {
	ctx, cancel := context.WithCancel(context.Background())

	app := &Application{
		cfg:    cfg,
		ctx:    ctx,
		cancel: cancel,
	}

	// Initialize database
	logInfo("Initializing device tracking database...")
	db, err := storage.NewDatabase(cfg.Database.Path)
	if err != nil {
		cancel()
		return nil, fmt.Errorf("database initialization failed: %w", err)
	}
	app.db = db

	// Initialize ARP monitor for universal device detection (works on Windows 10/11)
	// This replaces Windows DHCP Server polling which only works on Windows Server
	logInfo("Initializing ARP monitor for universal device detection...")
	app.arpMonitor = arp_monitor.New(arp_monitor.Config{
		PollInterval: 10 * time.Second,
		Database:     db,
	})

	// Initialize DNS hijacking server
	if cfg.DNS.Enabled {
		logInfo("Initializing DNS hijacking server...")

		// Auto-detect portal IP if needed
		portalIP := cfg.Portal.IP
		if portalIP == "" || portalIP == "auto" {
			portalIP = getLocalIP()
			logInfo("Auto-detected portal IP: %s", portalIP)
		}

		dnsServer, err := dns_hijack.New(dns_hijack.Config{
			Port:        cfg.DNS.Port,
			PortalIP:    portalIP,
			UpstreamDNS: cfg.DNS.Upstream + ":53",
			HijackTTL:   cfg.DNS.HijackTTL,
			Enabled:     cfg.DNS.Enabled,
		}, db)
		if err != nil {
			cancel()
			return nil, fmt.Errorf("DNS server creation failed: %w", err)
		}
		app.dnsServer = dnsServer
	}

	// Initialize NIC detector
	logInfo("Initializing NIC detector...")
	nicDetector, err := nic_integration.New()
	if err != nil {
		cancel()
		return nil, fmt.Errorf("NIC detector creation failed: %w", err)
	}
	app.nicDetector = nicDetector

	// Initialize captive portal
	logInfo("Initializing captive portal...")
	portalServer, err := captive_portal.New(captive_portal.Config{
		PortalIP:          cfg.Portal.IP,
		HTTPPort:          cfg.Portal.HTTPPort,
		HTTPSPort:         cfg.Portal.HTTPSPort,
		EnableHTTPS:       cfg.Portal.HTTPSEnabled,
		TLSCertPath:       cfg.Portal.CertPath,
		TLSKeyPath:        cfg.Portal.KeyPath,
		RootCACertPath:    cfg.StepCA.RootCertPath,
		SessionTimeout:    cfg.Portal.SessionTimeout,
		VerifyClientCerts: cfg.StepCA.VerifyClientCerts,
	}, db)
	if err != nil {
		cancel()
		return nil, fmt.Errorf("captive portal creation failed: %w", err)
	}
	app.portalServer = portalServer

	logInfo("All components initialized successfully")
	return app, nil
}

// Start starts all application services
func (app *Application) Start() error {
	// Start NIC detector
	if app.nicDetector != nil {
		logInfo("Starting NIC detector...")
		if err := app.nicDetector.Start(app.ctx); err != nil {
			return fmt.Errorf("NIC detector start failed: %w", err)
		}
	}

	// Start ARP monitor (universal device detection for Windows 10/11)
	logInfo("Starting ARP monitor for all NICs...")
	if err := app.arpMonitor.Start(app.ctx); err != nil {
		logError("ARP monitor start failed: %v", err)
	}

	// Process ARP events
	app.wg.Add(1)
	go app.processARPEvents()

	// Start DNS server
	if app.dnsServer != nil {
		logInfo("Starting DNS hijacking server on port %d...", app.cfg.DNS.Port)
		app.wg.Add(1)
		go func() {
			defer app.wg.Done()
			if err := app.dnsServer.Start(app.ctx); err != nil {
				logError("DNS server error: %v", err)
			}
		}()
	}

	// Start captive portal
	logInfo("Starting captive portal on port %d...", app.cfg.Portal.HTTPPort)
	app.wg.Add(1)
	go func() {
		defer app.wg.Done()
		if err := app.portalServer.Start(app.ctx); err != nil {
			logError("Captive portal error: %v", err)
		}
	}()

	// Print status
	app.printStatus()

	logInfo("DHCP Monitor started successfully")
	return nil
}

// Stop stops all application services
func (app *Application) Stop() error {
	logInfo("Stopping DHCP Monitor...")

	// Cancel context to stop all services
	app.cancel()

	// Stop NIC detector
	if app.nicDetector != nil {
		logInfo("Stopping NIC detector...")
		app.nicDetector.Stop()
	}

	// Stop ARP monitor
	if app.arpMonitor != nil {
		logInfo("Stopping ARP monitor...")
		app.arpMonitor.Stop()
	}

	// Stop DNS server
	if app.dnsServer != nil {
		logInfo("Stopping DNS server...")
		app.dnsServer.Stop()
	}

	// Stop portal server
	if app.portalServer != nil {
		logInfo("Stopping captive portal...")
		app.portalServer.Stop()
	}

	// Wait for all goroutines
	app.wg.Wait()

	// Close database
	if app.db != nil {
		logInfo("Closing database...")
		app.db.Close()
	}

	return nil
}

// processARPEvents processes ARP events from the ARP monitor
func (app *Application) processARPEvents() {
	defer app.wg.Done()

	eventChan := app.arpMonitor.Events()
	for event := range eventChan {
		switch event.Type {
		case arp_monitor.EventDeviceConnected:
			logInfo("ARP: Device connected via %s: IP=%s, MAC=%s",
				event.Device.InterfaceName, event.Device.IP, event.Device.MAC)
		case arp_monitor.EventDeviceDisconnected:
			logInfo("ARP: Device disconnected: IP=%s, MAC=%s",
				event.Device.IP, event.Device.MAC)
		}
	}
}

// printStatus prints service status
func (app *Application) printStatus() {
	fmt.Println("\n" + strings.Repeat("=", 60))
	fmt.Printf("  %s v%s - Running\n", serviceName, serviceVersion)
	fmt.Println(strings.Repeat("=", 60))
	fmt.Printf("  Portal IP:       %s\n", getLocalIP())
	fmt.Printf("  HTTP Portal:     http://%s:%d\n", getLocalIP(), app.cfg.Portal.HTTPPort)
	fmt.Printf("  DNS Server:      %s:%d\n", getLocalIP(), app.cfg.DNS.Port)
	fmt.Printf("  Database:        %s\n", app.cfg.Database.Path)
	fmt.Printf("  Step-CA Root:    %s\n", app.cfg.StepCA.RootCertPath)
	fmt.Println(strings.Repeat("=", 60))

	// Show statistics
	stats, _ := app.db.GetStats()
	fmt.Printf("  Total Devices:   %d\n", stats.TotalDevices)
	fmt.Printf("  Enrolled:        %d\n", stats.EnrolledDevices)
	fmt.Printf("  Unenrolled:      %d\n", stats.UnenrolledDevices)
	fmt.Println(strings.Repeat("=", 60) + "\n")
}

// createDHCPClient creates a Windows DHCP client based on config
func createDHCPClient(cfg config.WindowsDHCPConfig) (windows_dhcp.Client, error) {
	switch cfg.Method {
	case "powershell":
		return windows_dhcp.NewPowerShellClient(cfg.Server)
	default:
		return nil, fmt.Errorf("unsupported DHCP monitoring method: %s", cfg.Method)
	}
}

// getLocalIP returns the local machine's IP address
func getLocalIP() string {
	addrs, err := net.InterfaceAddrs()
	if err != nil {
		return ""
	}

	for _, addr := range addrs {
		if ipnet, ok := addr.(*net.IPNet); ok && !ipnet.IP.IsLoopback() {
			if ipnet.IP.To4() != nil {
				return ipnet.IP.String()
			}
		}
	}

	return ""
}

// Logging functions
func logInfo(format string, args ...interface{}) {
	fmt.Printf("[INFO] %s\n", fmt.Sprintf(format, args...))
}

func logError(format string, args ...interface{}) {
	fmt.Fprintf(os.Stderr, "[ERROR] %s\n", fmt.Sprintf(format, args...))
}
