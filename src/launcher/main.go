package main

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"time"
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

func main() {
	fmt.Println("╔═══════════════════════════════════════════════════════════════╗")
	fmt.Println("║           SafeOps Launcher - Starting All Services            ║")
	fmt.Println("╚═══════════════════════════════════════════════════════════════╝")
	fmt.Println()

	// Get executable directory
	exePath, err := os.Executable()
	if err != nil {
		fmt.Printf("Error getting executable path: %v\n", err)
		os.Exit(1)
	}
	binDir := filepath.Dir(exePath)

	// Define services
	services := []Service{
		{
			Name:    "NIC Management",
			ExePath: filepath.Join(binDir, "nic_management", "nic_management.exe"),
			WorkDir: filepath.Join(binDir, "nic_management"),
			Delay:   2 * time.Second,
		},
		{
			Name:    "DHCP Monitor",
			ExePath: filepath.Join(binDir, "dhcp_monitor", "dhcp_monitor.exe"),
			WorkDir: filepath.Join(binDir, "dhcp_monitor"),
			Delay:   2 * time.Second,
		},
		{
			Name:    "Step-CA",
			ExePath: filepath.Join(binDir, "step-ca", "bin", "step-ca.exe"),
			WorkDir: filepath.Join(binDir, "step-ca"),
			Args:    []string{"config/ca.json", "--password-file", "secrets/password.txt"},
			Delay:   3 * time.Second,
		},
		{
			Name:    "Captive Portal",
			ExePath: filepath.Join(binDir, "captive_portal", "captive_portal.exe"),
			WorkDir: filepath.Join(binDir, "captive_portal"),
			Delay:   2 * time.Second,
		},
		{
			Name:         "SafeOps Engine",
			ExePath:      filepath.Join(binDir, "safeops-engine", "safeops-engine.exe"),
			WorkDir:      filepath.Join(binDir, "safeops-engine"),
			RequireAdmin: true,
			Delay:        2 * time.Second,
		},
		{
			Name:    "Network Logger",
			ExePath: filepath.Join(binDir, "network_logger", "network_logger.exe"),
			WorkDir: filepath.Join(binDir, "network_logger"),
			Delay:   2 * time.Second,
		},
		{
			Name:    "Threat Intel",
			ExePath: filepath.Join(binDir, "threat_intel", "threat_intel.exe"),
			WorkDir: filepath.Join(binDir, "threat_intel"),
			Delay:   2 * time.Second,
		},
	}

	// Start each service
	for _, svc := range services {
		startService(svc)
	}

	// Start UI Dev Server
	startUIDevServer(binDir)

	fmt.Println()
	fmt.Println("╔═══════════════════════════════════════════════════════════════╗")
	fmt.Println("║           All Services Started Successfully!                  ║")
	fmt.Println("╠═══════════════════════════════════════════════════════════════╣")
	fmt.Println("║  Service              │ Port/Info                             ║")
	fmt.Println("║  ─────────────────────────────────────────────────────────────║")
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
	fmt.Println("Press Enter to exit...")
	fmt.Scanln()
}

func startUIDevServer(binDir string) {
	fmt.Println("[Starting] UI Dev Server...")

	// UI is in src/ui/dev relative to bin's parent (project root)
	projectRoot := filepath.Dir(binDir)
	uiDir := filepath.Join(projectRoot, "src", "ui", "dev")

	if _, err := os.Stat(uiDir); os.IsNotExist(err) {
		fmt.Printf("  [SKIP] UI directory not found: %s\n", uiDir)
		return
	}

	// Start npm run dev
	cmd := exec.Command("cmd", "/c", "start", "cmd", "/k", "cd /d", uiDir, "&&", "npm", "run", "dev")
	err := cmd.Start()
	if err != nil {
		fmt.Printf("  [ERROR] Failed to start UI: %v\n", err)
		return
	}

	fmt.Println("  [OK] UI Dev Server starting on http://localhost:3001")
	time.Sleep(2 * time.Second)
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

	// Start the process
	err := cmd.Start()
	if err != nil {
		fmt.Printf("  [ERROR] Failed to start: %v\n", err)
		return
	}

	fmt.Printf("  [OK] %s started (PID: %d)\n", svc.Name, cmd.Process.Pid)

	// Wait before starting next service
	time.Sleep(svc.Delay)
}
