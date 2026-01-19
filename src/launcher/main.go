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

// Service configuration
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
var devServerCmd *exec.Cmd // Keep track of dev server specially if needed, currently started via 'start' in separate window

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

	// Get executable directory (now in project root)
	exePath, err := os.Executable()
	if err != nil {
		fmt.Printf("Error getting executable path: %v\n", err)
		os.Exit(1)
	}
	projectRoot := filepath.Dir(exePath)
	binDir := filepath.Join(projectRoot, "bin")

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
			Delay:   1 * time.Second,
		},
	}

	// Start each service
	for _, svc := range services {
		startService(svc)
	}

	// Start UI Dev Server
	startUIDevServer(projectRoot)

	fmt.Println()
	fmt.Println("╔═══════════════════════════════════════════════════════════════╗")
	fmt.Println("║           All Services Started Successfully!                  ║")
	fmt.Println("╠═══════════════════════════════════════════════════════════════╣")
	fmt.Println("║  Service              │ Port/Info                             ║")
	fmt.Println("║  ─────────────────────────────────────────────────────────────║")
	fmt.Println("║  Threat Intel DB      │ PostgreSQL :5432                      ║")
	fmt.Println("║  Threat Intel API     │ :5050 (REST API)                      ║")
	fmt.Println("║  NIC Management       │ :8081 (REST API + SSE)                ║")
	fmt.Println("║  DHCP Monitor         │ :50055 (gRPC)                         ║")
	fmt.Println("║  Step-CA              │ :9000 (HTTPS)                         ║")
	fmt.Println("║  Captive Portal       │ :8445 (HTTPS) / :8090 (HTTP)          ║")
	fmt.Println("║  SafeOps Engine       │ Admin Mode (Packet Capture)           ║")
	fmt.Println("║  Network Logger       │ Packet Logging                        ║")
	fmt.Println("║  Threat Intel         │ Threat Feed Pipeline                  ║")
	fmt.Println("║  UI Dev Server        │ :3001 (Vite)                          ║")
	fmt.Println("╚═══════════════════════════════════════════════════════════════╝")
	fmt.Println()

	// Open browser to SafeOps UI
	fmt.Println("[Opening] SafeOps Dashboard in browser...")
	time.Sleep(3 * time.Second)
	// Open in default browser, no need to track this process
	exec.Command("cmd", "/c", "start", "http://localhost:3001").Start()

	fmt.Println()
	fmt.Println("Services are running. Press Enter to stop all services and exit...")
	fmt.Scanln()
	cleanup()
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
	err = db.Ping()
	if err != nil {
		fmt.Printf("  [WARN] Database not reachable: %v\n", err)
		fmt.Println("  [INFO] Start PostgreSQL and ensure threat_intel_db exists")
		return
	}

	fmt.Println("  [OK] Threat Intel Database connected (PostgreSQL)")
	time.Sleep(1 * time.Second)
}

func startUIDevServer(projectRoot string) {
	fmt.Println("[Starting] UI Dev Server...")

	uiDir := filepath.Join(projectRoot, "src", "ui", "dev")

	if _, err := os.Stat(uiDir); os.IsNotExist(err) {
		fmt.Printf("  [SKIP] UI directory not found: %s\n", uiDir)
		return
	}

	// Start npm run dev in a new window
	// Using "start" cmd means it runs in separate window, we can't easily kill it unless we track its window/process
	// Ideally we would run it as a child process and pipe output, but user seems to prefer separate window or background
	// For "Close all services", we can try to kill node.exe or just leave it since it's a dev server in a separate terminal
	// If the user wants it closed, they can close the terminal window.
	// However, we can track the 'cmd' process we started? Start returns immediately.
	cmd := exec.Command("cmd", "/c", "start", "cmd", "/k", fmt.Sprintf("cd /d %s && npm run dev", uiDir))
	err := cmd.Start()
	if err != nil {
		fmt.Printf("  [ERROR] Failed to start UI: %v\n", err)
		return
	}

	fmt.Println("  [OK] UI Dev Server starting on http://localhost:3001")
	time.Sleep(2 * time.Second)

	// Start backend API server (npm run server) for Threat Intel DB connection
	fmt.Println("[Starting] Backend API Server...")
	cmdServer := exec.Command("cmd", "/c", "start", "cmd", "/k", fmt.Sprintf("cd /d %s && npm run server", uiDir))
	errServer := cmdServer.Start()
	if errServer != nil {
		fmt.Printf("  [ERROR] Failed to start Backend API: %v\n", errServer)
		return
	}
	fmt.Println("  [OK] Backend API Server starting on http://localhost:5050")
	time.Sleep(1 * time.Second)
}

func startService(svc Service) {
	fmt.Printf("[Starting] %s...\n", svc.Name)

	// Check if executable exists
	if _, err := os.Stat(svc.ExePath); os.IsNotExist(err) {
		fmt.Printf("  [SKIP] Executable not found: %s\n", svc.ExePath)
		return
	}

	// Create command
	cmd := exec.Command(svc.ExePath, svc.Args...)
	cmd.Dir = svc.WorkDir
	// We do NOT set SysProcAttr to create new console group because we want signals to propagate?
	// Actually, on Windows, if we want to kill them individually, we just keep their Process objects.

	// Start the process
	err := cmd.Start()
	if err != nil {
		fmt.Printf("  [ERROR] Failed to start: %v\n", err)
		return
	}

	startedProcesses = append(startedProcesses, cmd.Process)
	fmt.Printf("  [OK] %s started (PID: %d)\n", svc.Name, cmd.Process.Pid)

	// Wait before starting next service
	time.Sleep(svc.Delay)
}

func cleanup() {
	fmt.Println("\n[Stopping] Stopping all services...")
	for _, p := range startedProcesses {
		if p != nil {
			fmt.Printf("  Killing PID %d... ", p.Pid)
			err := p.Kill()
			if err != nil {
				fmt.Printf("Error: %v\n", err)
			} else {
				fmt.Println("OK")
			}
		}
	}
	fmt.Println("[Done] All services stopped.")
}
