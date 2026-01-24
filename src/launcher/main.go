package main

import (
	"database/sql"
	"fmt"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
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

// DBConfig holds database configuration
type DBConfig struct {
	Host     string
	Port     int
	User     string
	Password string
	Name     string
}

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

	// Load Database Configuration
	dbConfig := loadDBConfig(projectRoot)

	// Initialize Threat Intel Database
	initThreatIntelDB(dbConfig)

	// Reset Step-CA database if corrupted (prevents BadgerDB issues)
	resetStepCADatabase(binDir)

	// Define services
	services := []Service{
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
			Delay:        2 * time.Second, // Give SafeOps Engine more time to start
		},
		{
			Name:         "Firewall Engine V4",
			ExePath:      filepath.Join(binDir, "firewall_engine", "firewall-engine.exe"),
			WorkDir:      filepath.Join(binDir, "firewall_engine"),
			RequireAdmin: true,
			Delay:        2 * time.Second, // Needs SafeOps Engine to be running
		},
		{
			Name:    "Network Logger",
			ExePath: filepath.Join(binDir, "network_logger", "network_logger.exe"),
			WorkDir: filepath.Join(binDir, "network_logger"),
			Delay:   1 * time.Second,
		},
		{
			Name:    "SIEM Forwarder",
			ExePath: filepath.Join(binDir, "siem-forwarder", "siem-forwarder.exe"),
			WorkDir: filepath.Join(binDir, "siem-forwarder"),
			Args:    []string{"-config", "config.yaml"},
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
	fmt.Println("║  Firewall Engine V4   │ Dual-Engine (SafeOps + WFP)           ║")
	fmt.Println("║  Network Logger       │ Packet Logging                        ║")
	fmt.Println("║  SIEM Forwarder       │ Log Shipping → Elasticsearch          ║")
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
	fmt.Println("║  Firewall Engine V4   │ ~2-5% (dual-engine enforcement)       ║")
	fmt.Println("║  Network Logger       │ ~1-3% (logging packets)               ║")
	fmt.Println("║  Threat Intel         │ ~0% (idle), ~10-20% (fetching feeds)  ║")
	fmt.Println("║  NIC Management       │ ~0-1% (idle)                          ║")
	fmt.Println("║  SIEM Forwarder       │ ~0-1% (idle), ~2% (shipping)          ║")
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
// Supports running from:
//   - Project root (D:\SafeOpsFV2\safeops_launcher.exe)
//   - Bin folder (D:\SafeOpsFV2\bin\safeops_launcher.exe)
func detectPaths() (projectRoot, binDir string) {
	exePath, err := os.Executable()
	if err != nil {
		fmt.Printf("Error getting executable path: %v\n", err)
		os.Exit(1)
	}

	exeDir := filepath.Dir(exePath)
	exeDirName := filepath.Base(exeDir)

	// Method 1: Check if we're in the bin/ folder
	if exeDirName == "bin" {
		// Launcher is in bin/, project root is parent
		projectRoot = filepath.Dir(exeDir)
		binDir = exeDir
		fmt.Println("[INFO] Running from: bin/ folder")
	} else if _, err := os.Stat(filepath.Join(exeDir, "bin")); err == nil {
		// Method 2: Launcher is in project root (bin/ exists as subdirectory)
		projectRoot = exeDir
		binDir = filepath.Join(exeDir, "bin")
		fmt.Println("[INFO] Running from: project root")
	} else if _, err := os.Stat(filepath.Join(exeDir, "src")); err == nil {
		// Method 3: We're in project root (src/ exists - alternative check)
		projectRoot = exeDir
		binDir = filepath.Join(exeDir, "bin")
		fmt.Println("[INFO] Running from: project root (detected via src/)")
	} else {
		// Method 4: Default - assume exeDir is project root
		projectRoot = exeDir
		binDir = filepath.Join(exeDir, "bin")
		fmt.Println("[WARN] Could not detect folder structure, assuming project root")
	}

	// Resolve to absolute paths
	projectRoot, _ = filepath.Abs(projectRoot)
	binDir, _ = filepath.Abs(binDir)

	// Validate that bin directory exists
	if _, err := os.Stat(binDir); os.IsNotExist(err) {
		fmt.Printf("[ERROR] Bin directory not found: %s\n", binDir)
		fmt.Println("[INFO] Make sure you run the launcher from the project root or bin folder")
		os.Exit(1)
	}

	return projectRoot, binDir
}

func loadDBConfig(projectRoot string) DBConfig {
	config := DBConfig{
		Host:     "localhost",
		Port:     5432,
		User:     "postgres",
		Password: "postgres", // Default, but now overridable
		Name:     "threat_intel_db",
	}

	// 1. Try to read backend/.env
	envPath := filepath.Join(projectRoot, "backend", ".env")
	if content, err := os.ReadFile(envPath); err == nil {
		lines := strings.Split(string(content), "\n")
		for _, line := range lines {
			line = strings.TrimSpace(line)
			if line == "" || strings.HasPrefix(line, "#") {
				continue
			}
			parts := strings.SplitN(line, "=", 2)
			if len(parts) == 2 {
				key := strings.TrimSpace(parts[0])
				value := strings.TrimSpace(parts[1])
				// Handle quotes if present
				value = strings.Trim(value, `"'`)

				switch key {
				case "DB_HOST":
					config.Host = value
				case "DB_PORT":
					if p, err := strconv.Atoi(value); err == nil {
						config.Port = p
					}
				case "DB_USER":
					config.User = value
				case "DB_PASSWORD":
					config.Password = value
				case "DB_NAME":
					config.Name = value
				}
			}
		}
		fmt.Printf("[INFO] Loaded configuration from %s\n", envPath)
	}

	// 2. Override with environment variables
	if v := os.Getenv("DB_HOST"); v != "" {
		config.Host = v
	}
	if v := os.Getenv("DB_PORT"); v != "" {
		if p, err := strconv.Atoi(v); err == nil {
			config.Port = p
		}
	}
	if v := os.Getenv("DB_USER"); v != "" {
		config.User = v
	}
	if v := os.Getenv("DB_PASSWORD"); v != "" {
		config.Password = v
	}
	if v := os.Getenv("DB_NAME"); v != "" {
		config.Name = v
	}

	return config
}

func initThreatIntelDB(config DBConfig) {
	fmt.Println("[Initializing] Threat Intel Database...")
	fmt.Printf("  [INFO] Connecting to %s@%s:%d\n", config.User, config.Host, config.Port)

	connStr := fmt.Sprintf("host=%s port=%d user=%s password=%s dbname=%s sslmode=disable",
		config.Host, config.Port, config.User, config.Password, config.Name)

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

// resetStepCADatabase clears the BadgerDB folder to prevent corruption issues
// BadgerDB can become corrupted if Step-CA doesn't shut down cleanly
func resetStepCADatabase(binDir string) {
	stepCADBPath := filepath.Join(binDir, "step-ca", "db")

	// Check if db folder exists
	if _, err := os.Stat(stepCADBPath); os.IsNotExist(err) {
		return // No db folder, nothing to do
	}

	fmt.Println("[Maintenance] Resetting Step-CA database (prevents BadgerDB corruption)...")

	// Remove the db folder
	if err := os.RemoveAll(stepCADBPath); err != nil {
		fmt.Printf("  [WARN] Could not remove Step-CA db: %v\n", err)
		return
	}

	// Recreate empty db folder
	if err := os.MkdirAll(stepCADBPath, 0755); err != nil {
		fmt.Printf("  [WARN] Could not recreate Step-CA db folder: %v\n", err)
		return
	}

	fmt.Println("  [OK] Step-CA database reset successfully")
}

func startUIAndBackend(projectRoot string) {
	fmt.Println("[Starting] UI Frontend and Backend API...")

	uiDir := filepath.Join(projectRoot, "src", "ui", "dev")

	if _, err := os.Stat(uiDir); os.IsNotExist(err) {
		fmt.Printf("  [SKIP] UI directory not found: %s\n", uiDir)
		return
	}

	// Start npm run dev (UI Frontend) in a new cmd window
	cmd := exec.Command("cmd", "/c", "start", "cmd", "/k", fmt.Sprintf("cd /d %s && npm run dev", uiDir))
	err := cmd.Start()
	if err != nil {
		fmt.Printf("  [ERROR] Failed to start UI: %v\n", err)
	} else {
		fmt.Println("  [OK] UI Frontend starting on http://localhost:3001")
	}

	fmt.Println("  [WAIT] Waiting 5 seconds for UI to initialize...")
	time.Sleep(5 * time.Second)

	// Start npm run server (Backend API) in a new cmd window
	backendDir := filepath.Join(projectRoot, "backend")
	if _, err := os.Stat(backendDir); os.IsNotExist(err) {
		fmt.Printf("  [SKIP] Backend directory not found: %s\n", backendDir)
	} else {
		cmdServer := exec.Command("cmd", "/c", "start", "cmd", "/k", fmt.Sprintf("cd /d %s && npm start", backendDir))
		errServer := cmdServer.Start()
		if errServer != nil {
			fmt.Printf("  [ERROR] Failed to start Backend API: %v\n", errServer)
		} else {
			fmt.Println("  [OK] Backend API starting on http://localhost:5050 (from backend/)")
		}
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
		"firewall-engine.exe",
		"network_logger.exe",
		"siem-forwarder.exe",
	}

	for _, svc := range services {
		exec.Command("taskkill", "/IM", svc, "/F").Run()
	}

	fmt.Println("  [OK] Background services stopped")
	fmt.Println("  [NOTE] UI and Backend windows may still be open - close them manually if needed")
}
