// SafeOps Unified Launcher
// Starts all SafeOps services with a single command
package main

import (
	"context"
	"fmt"
	"log"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"sync"
	"syscall"
	"time"
)

const (
	appName    = "SafeOps Development Server"
	appVersion = "1.0.0"
)

// Service represents a runnable service
type Service struct {
	Name      string
	Dir       string
	Command   string
	Args      []string
	Port      int
	Env       []string
	Process   *exec.Cmd
	IsRunning bool
}

var services = []Service{
	{
		Name:    "PostgreSQL Database",
		Dir:     ".",
		Command: "pg_ctl",
		Args:    []string{"start", "-D", "C:/Program Files/PostgreSQL/16/data", "-l", "postgres.log"},
		Port:    5432,
	},
	{
		Name:    "NIC Management API",
		Dir:     "src/nic_management",
		Command: "go",
		Args:    []string{"run", "./cmd/..."},
		Port:    8081,
	},
	{
		Name:    "DHCP Server",
		Dir:     "src/dhcp_server",
		Command: "go",
		Args:    []string{"run", "./cmd/main.go"},
		Port:    67,
	},
	{
		Name:    "Threat Intel API",
		Dir:     "src/threat_intel",
		Command: "go",
		Args:    []string{"run", "./cmd/server/main.go"},
		Port:    8080,
	},
	{
		Name:    "Frontend Dev Server",
		Dir:     "src/ui/dev",
		Command: "npm",
		Args:    []string{"run", "dev"},
		Port:    3003,
	},
}

func main() {
	printBanner()

	// Get project root
	projectRoot := getProjectRoot()
	log.Printf("Project root: %s\n", projectRoot)

	// Create context for graceful shutdown
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Handle shutdown signals
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM)

	var wg sync.WaitGroup

	// Start all services
	log.Println("🚀 Starting SafeOps services...")

	for i := range services {
		svc := &services[i]
		svc.Dir = filepath.Join(projectRoot, svc.Dir)
		wg.Add(1)
		go func(s *Service) {
			defer wg.Done()
			startService(ctx, s)
		}(svc)
		time.Sleep(500 * time.Millisecond) // Stagger starts
	}

	// Print status
	time.Sleep(2 * time.Second)
	printStatus()

	// Wait for shutdown signal
	<-sigChan
	log.Println("\n\n🛑 Shutting down SafeOps services...")
	cancel()

	// Stop all services
	for i := range services {
		stopService(&services[i])
	}

	wg.Wait()
	log.Println("✅ All services stopped. Goodbye!")
}

func startService(ctx context.Context, svc *Service) {
	log.Printf("▶️  Starting %s on port %d...\n", svc.Name, svc.Port)

	cmd := exec.CommandContext(ctx, svc.Command, svc.Args...)
	cmd.Dir = svc.Dir
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	cmd.Env = append(os.Environ(), svc.Env...)

	svc.Process = cmd

	if err := cmd.Start(); err != nil {
		log.Printf("❌ Failed to start %s: %v\n", svc.Name, err)
		return
	}

	svc.IsRunning = true
	log.Printf("✅ %s started (PID: %d)\n", svc.Name, cmd.Process.Pid)

	// Wait for it to finish
	cmd.Wait()
	svc.IsRunning = false
}

func stopService(svc *Service) {
	if svc.Process != nil && svc.IsRunning {
		log.Printf("⏹️  Stopping %s...\n", svc.Name)
		if svc.Process.Process != nil {
			svc.Process.Process.Kill()
		}
	}
}

func printBanner() {
	banner := `
╔═══════════════════════════════════════════════════════════╗
║                                                           ║
║   ███████╗ █████╗ ███████╗███████╗ ██████╗ ██████╗ ███████╗║
║   ██╔════╝██╔══██╗██╔════╝██╔════╝██╔═══██╗██╔══██╗██╔════╝║
║   ███████╗███████║█████╗  █████╗  ██║   ██║██████╔╝███████╗║
║   ╚════██║██╔══██║██╔══╝  ██╔══╝  ██║   ██║██╔═══╝ ╚════██║║
║   ███████║██║  ██║██║     ███████╗╚██████╔╝██║     ███████║║
║   ╚══════╝╚═╝  ╚═╝╚═╝     ╚══════╝ ╚═════╝ ╚═╝     ╚══════╝║
║                                                           ║
║          Development Server v1.0.0                        ║
║          All-in-One Service Launcher                      ║
║                                                           ║
╚═══════════════════════════════════════════════════════════╝
`
	fmt.Println(banner)
}

func printStatus() {
	divider := "════════════════════════════════════════════════════════════"
	fmt.Println("\n" + divider)
	fmt.Println("  📊 SERVICE STATUS")
	fmt.Println(divider)
	for _, svc := range services {
		status := "🔴 Stopped"
		if svc.IsRunning {
			status = "🟢 Running"
		}
		fmt.Printf("  %-25s %s (Port %d)\n", svc.Name, status, svc.Port)
	}
	fmt.Println(divider)
	fmt.Println("\n  📱 Access Points:")
	fmt.Println("     • NIC Management API: http://localhost:8081/api/nics")
	fmt.Println("     • Frontend Dev UI:    http://localhost:3003")
	fmt.Println("     • DHCP Server:        UDP port 67")
	fmt.Println("\n  Press Ctrl+C to stop all services")
	fmt.Println(divider + "\n")
}

func getProjectRoot() string {
	// Try to find SafeOpsFV2 in current or parent directories
	dir, _ := os.Getwd()
	for {
		if filepath.Base(dir) == "SafeOpsFV2" {
			return dir
		}
		// Check if go.work exists (indicates project root)
		if _, err := os.Stat(filepath.Join(dir, "go.work")); err == nil {
			return dir
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			break
		}
		dir = parent
	}
	// Fallback: assume D:\SafeOpsFV2
	return "D:\\SafeOpsFV2"
}
