package main

import (
	"database/sql"
	"fmt"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	_ "github.com/lib/pq"
)

// Service represents a background service to start
type Service struct {
	Name         string
	ExePath      string
	WorkDir      string
	Args         []string
	RequireAdmin bool
	Delay        time.Duration
}

// Database configuration for threat intel
const (
	dbHost     = "localhost"
	dbPort     = 5432
	dbUser     = "postgres"
	dbPassword = "postgres"
	dbName     = "threat_intel_db"
)

var startedProcesses []*os.Process

func main() {
	// Setup signal handling for graceful shutdown
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM)

	go func() {
		<-sigChan
		fmt.Println("\nReceived shutdown signal. Cleaning up...")
		cleanup()
		os.Exit(0)
	}()

	fmt.Println("╔═══════════════════════════════════════════════════════════════╗")
	fmt.Println("║           SafeOps Launcher - Starting All Services            ║")
	fmt.Println("╚═══════════════════════════════════════════════════════════════╝")
	fmt.Println("Press Ctrl+C to stop all services and exit.")
	fmt.Println()

	// Detect project root and bin directory
	projectRoot, binDir := detectPaths()

	fmt.Printf("[INFO] Project Root: %s\n", projectRoot)
	fmt.Printf("[INFO] Bin Directory: %s\n", binDir)
	fmt.Println()

	// Initialize Threat Intel Database
	initThreatIntelDB()

	// Define services
	services := []Service{
		{
			Name:    "Threat Intel API",
			ExePath: filepath.Join(binDir, "threat_intel", "threat_intel_api.exe"),
			WorkDir: filepath.Join(binDir, "threat_intel"),
			Delay:   1 * time.Second,
		},
		{
			Name:    "NIC Management",
			ExePath: filepath.Join(binDir, "nic_management", "nic_management.exe"),
			WorkDir: filepath.Join(binDir, "nic_management"),
			Delay:   1 * time.Second,
		},
		{
			Name:    "DHCP Monitor",
			ExePath: filepath.Join(binDir, "dhcp_monitor", "dhcp_monitor.exe"),
			WorkDir: filepath.Join(binDir, "dhcp_monitor"),
			Delay:   1 * time.Second,
		},
		{
			Name:    "Step-CA",
			ExePath: filepath.Join(binDir, "step-ca", "bin", "step-ca.exe"),
			WorkDir: filepath.Join(binDir, "step-ca"),
			Args:    []string{"config/ca.json", "--password-file", "secrets/password.txt"},
			Delay:   2 * time.Second,
		},
		{
			Name:    "Captive Portal",
			ExePath: filepath.Join(binDir, "captive_portal", "captive_portal.exe"),
			WorkDir: filepath.Join(binDir, "captive_portal"),
			Delay:   1 * time.Second,
		},
		{
			Name:         "SafeOps Engine",
			ExePath:      filepath.Join(binDir, "safeops-engine", "safeops-engine.exe"),
			WorkDir:      filepath.Join(binDir, "safeops-engine"),
			RequireAdmin: true,
			Delay:        1 * time.Second,
		},
		{
			Name:    "Network Logger",
			ExePath: filepath.Join(binDir, "network_logger", "network_logger.exe"),
			WorkDir: filepath.Join(binDir, "network_logger"),
			Delay:   1 * time.Second,
		},
		{
			Name:    "Threat Intel Pipeline",
			ExePath: filepath.Join(binDir, "threat_intel", "threat_intel.exe"),
			WorkDir: filepath.Join(binDir, "threat_intel"),
			Args:    []string{"-scheduler"},
			Delay:   1 * time.Second,
		},
	}

	// Start each service
	for _, svc := range services {
		startService(svc)
	}

	// Start UI Dev Server and Backend API
	startUIAndBackend(projectRoot)

	fmt.Println()
	fmt.Println("╔═══════════════════════════════════════════════════════════════╗")
	fmt.Println("║           All Services Started Successfully!                  ║")
	fmt.Println("╠═══════════════════════════════════════════════════════════════╣")
	fmt.Println("║  Service              │ Port/Info                             ║")
	fmt.Println("║  ─────────────────────────────────────────────────────────────║")
	fmt.Println("║  Threat Intel DB      │ PostgreSQL :5432                      ║")
	fmt.Println("║  Threat Intel API     │ :5050 (REST API via Node)             ║")
	fmt.Println("║  NIC Management       │ :8081 (REST API + SSE)                ║")
	fmt.Println("║  DHCP Monitor         │ :50055 (gRPC)                         ║")
	fmt.Println("║  Step-CA              │ :9000 (HTTPS)                         ║")
	fmt.Println("║  Captive Portal       │ :8445 (HTTPS) / :8090 (HTTP)          ║")
	fmt.Println("║  SafeOps Engine       │ Admin Mode (Packet Capture)           ║")
	fmt.Println("║  Network Logger       │ Packet Logging                        ║")
	fmt.Println("║  Threat Intel         │ Threat Feed Pipeline (-scheduler)     ║")
	fmt.Println("║  UI Frontend          │ :3001 (Vite)                          ║")
	fmt.Println("║  Backend API          │ :5050 (Node.js + Step-CA Proxy)       ║")
	fmt.Println("╚═══════════════════════════════════════════════════════════════╝")
	fmt.Println()
	fmt.Println("╔═══════════════════════════════════════════════════════════════╗")
	fmt.Println("║              Expected CPU Load (Idle/Active)                  ║")
	fmt.Println("╠═══════════════════════════════════════════════════════════════╣")
	fmt.Println("║  DHCP Monitor         │ ~1-3% (polling ARP table)             ║")
	fmt.Println("║  Step-CA              │ ~0-1% (idle), ~3% (issuing certs)     ║")
	fmt.Println("║  Captive Portal       │ ~0-1% (idle), ~2% (serving pages)     ║")
	fmt.Println("║  SafeOps Engine       │ ~2-5% (packet capture)                ║")
	fmt.Println("║  Network Logger       │ ~1-3% (logging packets)               ║")
	fmt.Println("║  Threat Intel         │ ~0% (idle), ~10-20% (fetching feeds)  ║")
	fmt.Println("║  NIC Management       │ ~0-1% (idle)                          ║")
	fmt.Println("║  UI + Backend         │ ~2-5% (Vite HMR + Node)               ║")
	fmt.Println("║  ─────────────────────────────────────────────────────────────║")
	fmt.Println("║  TOTAL (Idle)         │ ~5-15% CPU                            ║")
	fmt.Println("║  TOTAL (Active)       │ ~15-35% CPU                           ║")
	fmt.Println("║  RAM Usage            │ ~500MB - 1GB                          ║")
	fmt.Println("╚═══════════════════════════════════════════════════════════════╝")
	fmt.Println()

	// Open browser to SafeOps UI
	fmt.Println("[Opening] SafeOps Dashboard in browser...")
	time.Sleep(3 * time.Second)
	exec.Command("cmd", "/c", "start", "http://localhost:3001").Start()

	fmt.Println()
	fmt.Println("Services are running. Press Enter to stop all services and exit...")
	fmt.Scanln()
	cleanup()
}

// detectPaths finds project root and bin directory based on launcher location
func detectPaths() (projectRoot, binDir string) {
	exePath, err := os.Executable()
	if err != nil {
		fmt.Printf("Error getting executable path: %v\n", err)
		os.Exit(1)
	}

	exeDir := filepath.Dir(exePath)
	exeName := filepath.Base(exeDir)

	// Check if running from bin/ folder
	if exeName == "bin" {
		// Launcher is in bin/, project root is parent
		projectRoot = filepath.Dir(exeDir)
		binDir = exeDir
		fmt.Println("[INFO] Launcher detected in bin/ folder")
	} else if _, err := os.Stat(filepath.Join(exeDir, "bin")); err == nil {
		// Launcher is in project root, bin/ exists
		projectRoot = exeDir
		binDir = filepath.Join(exeDir, "bin")
		fmt.Println("[INFO] Launcher detected in project root")
	} else if _, err := os.Stat(filepath.Join(exeDir, "..", "bin")); err == nil {
		// Launcher might be in some subfolder, check parent for bin/
		projectRoot = filepath.Join(exeDir, "..")
		binDir = filepath.Join(projectRoot, "bin")
		fmt.Println("[INFO] Launcher detected in subfolder, using parent as root")
	} else {
		// Default: assume exeDir is project root
		projectRoot = exeDir
		binDir = filepath.Join(exeDir, "bin")
		fmt.Println("[WARN] Could not detect folder structure, assuming project root")
	}

	// Resolve absolute paths
	projectRoot, _ = filepath.Abs(projectRoot)
	binDir, _ = filepath.Abs(binDir)

	return projectRoot, binDir
}

func initThreatIntelDB() {
	fmt.Println("[Initializing] Threat Intel Database...")

	connStr := fmt.Sprintf("host=%s port=%d user=%s password=%s dbname=%s sslmode=disable",
		dbHost, dbPort, dbUser, dbPassword, dbName)

	db, err := sql.Open("postgres", connStr)
	if err != nil {
		fmt.Printf("  [WARN] Could not connect to database: %v\n", err)
		return
	}
	defer db.Close()

	// Test connection
	if err := db.Ping(); err != nil {
		fmt.Printf("  [WARN] Database ping failed: %v\n", err)
		return
	}

	fmt.Println("  [OK] Database connection verified")
}

func startUIAndBackend(projectRoot string) {
	fmt.Println("[Starting] UI Frontend and Backend API...")

	uiDir := filepath.Join(projectRoot, "src", "ui", "dev")

	if _, err := os.Stat(uiDir); os.IsNotExist(err) {
		fmt.Printf("  [SKIP] UI directory not found: %s\n", uiDir)
		return
	}

	// Start npm run dev (UI Frontend) in a new window
	cmd := exec.Command("cmd", "/c", "start", "SafeOps-UI", "cmd", "/k", fmt.Sprintf("cd /d %s && npm run dev", uiDir))
	err := cmd.Start()
	if err != nil {
		fmt.Printf("  [ERROR] Failed to start UI: %v\n", err)
	} else {
		fmt.Println("  [OK] UI Frontend starting on http://localhost:3001")
	}
	time.Sleep(2 * time.Second)

	// Start npm run server (Backend API) in a new window
	cmdServer := exec.Command("cmd", "/c", "start", "SafeOps-Backend", "cmd", "/k", fmt.Sprintf("cd /d %s && npm run server", uiDir))
	errServer := cmdServer.Start()
	if errServer != nil {
		fmt.Printf("  [ERROR] Failed to start Backend API: %v\n", errServer)
	} else {
		fmt.Println("  [OK] Backend API starting on http://localhost:5050 (with Step-CA proxy)")
	}
	time.Sleep(1 * time.Second)
}

func startService(svc Service) {
	fmt.Printf("[Starting] %s...\n", svc.Name)

	// Check if executable exists
	if _, err := os.Stat(svc.ExePath); os.IsNotExist(err) {
		fmt.Printf("  [SKIP] Executable not found: %s\n", svc.ExePath)
		return
	}

	cmd := exec.Command(svc.ExePath, svc.Args...)
	cmd.Dir = svc.WorkDir

	// Start the process
	if err := cmd.Start(); err != nil {
		fmt.Printf("  [ERROR] Failed to start %s: %v\n", svc.Name, err)
		return
	}

	// Track the process for cleanup
	if cmd.Process != nil {
		startedProcesses = append(startedProcesses, cmd.Process)
	}

	fmt.Printf("  [OK] %s started (PID: %d)\n", svc.Name, cmd.Process.Pid)
	time.Sleep(svc.Delay)
}

func cleanup() {
	fmt.Println("\n[Cleanup] Stopping all services...")

	// Kill tracked processes
	for _, proc := range startedProcesses {
		if proc != nil {
			fmt.Printf("  Stopping PID %d...\n", proc.Pid)
			proc.Kill()
		}
	}

	// Kill known service executables
	services := []string{
		"threat_intel_api.exe",
		"threat_intel.exe",
		"nic_management.exe",
		"dhcp_monitor.exe",
		"step-ca.exe",
		"captive_portal.exe",
		"safeops-engine.exe",
		"network_logger.exe",
	}

	for _, svc := range services {
		exec.Command("taskkill", "/IM", svc, "/F").Run()
	}

	fmt.Println("  [OK] Background services stopped")
	fmt.Println("  [NOTE] UI and Backend windows may still be open - close them manually if needed")
}
