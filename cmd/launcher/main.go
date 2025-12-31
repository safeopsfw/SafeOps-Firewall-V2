// SafeOps Unified Launcher
// Starts all SafeOps services from a single executable

package main

import (
	"fmt"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"
)

type Service struct {
	Name    string
	Dir     string
	Command string
	Args    []string
	Env     []string
	Port    int
	Process *exec.Cmd
}

func main() {
	fmt.Println("╔═══════════════════════════════════════════════════════════════╗")
	fmt.Println("║              SafeOps Unified Launcher v1.0                    ║")
	fmt.Println("║     Network Security & Device Management Platform             ║")
	fmt.Println("╚═══════════════════════════════════════════════════════════════╝")
	fmt.Println()

	// Get the base directory (where this exe is located)
	exePath, err := os.Executable()
	if err != nil {
		fmt.Printf("[ERROR] Cannot determine executable path: %v\n", err)
		os.Exit(1)
	}
	baseDir := filepath.Dir(exePath)

	// Define all services
	services := []Service{
		{
			Name:    "Backend API",
			Dir:     filepath.Join(baseDir, "backend"),
			Command: "node",
			Args:    []string{"server.js"},
			Env:     []string{"DB_PASSWORD=safeops123"},
			Port:    5050,
		},
		{
			Name:    "NIC Management",
			Dir:     filepath.Join(baseDir, "src", "nic_management"),
			Command: filepath.Join(baseDir, "src", "nic_management", "nic_management.exe"),
			Args:    []string{},
			Port:    8081,
		},
		{
			Name:    "Threat Intel API",
			Dir:     filepath.Join(baseDir, "src", "threat_intel"),
			Command: filepath.Join(baseDir, "src", "threat_intel", "threat_intel_api.exe"),
			Args:    []string{},
			Env:     []string{"DB_PASSWORD=safeops123"},
			Port:    8080,
		},
		{
			Name:    "Step-CA",
			Dir:     filepath.Join(baseDir, "certs", "step-ca"),
			Command: filepath.Join(baseDir, "certs", "step-ca", "step-ca.exe"),
			Args:    []string{"ca/config/ca.json", "--password-file", "ca/secrets/password.txt"},
			Port:    9000,
		},
		{
			Name:    "Network Monitor",
			Dir:     filepath.Join(baseDir, "src", "dhcp_monitor"),
			Command: filepath.Join(baseDir, "src", "dhcp_monitor", "dhcp_monitor.exe"),
			Args:    []string{},
			Port:    80,
		},
	}

	// Start all services
	fmt.Println("[INFO] Starting services...")
	fmt.Println()

	var runningServices []*exec.Cmd

	for i, svc := range services {
		fmt.Printf("[%d/%d] Starting %s (Port %d)...\n", i+1, len(services), svc.Name, svc.Port)

		cmd := exec.Command(svc.Command, svc.Args...)
		cmd.Dir = svc.Dir
		cmd.Env = append(os.Environ(), svc.Env...)
		cmd.Stdout = os.Stdout
		cmd.Stderr = os.Stderr

		err := cmd.Start()
		if err != nil {
			fmt.Printf("     ✗ Failed to start: %v\n", err)
			continue
		}

		services[i].Process = cmd
		runningServices = append(runningServices, cmd)
		fmt.Printf("     ✓ Started (PID: %d)\n", cmd.Process.Pid)

		// Small delay between service starts
		time.Sleep(500 * time.Millisecond)
	}

	fmt.Println()
	fmt.Println("═══════════════════════════════════════════════════════════════")
	fmt.Println("  All services started! Access the dashboard at:")
	fmt.Println()
	fmt.Println("    Frontend:        http://localhost:3001")
	fmt.Println("    Backend API:     http://localhost:5050")
	fmt.Println("    NIC Management:  http://localhost:8081")
	fmt.Println("    Threat Intel:    http://localhost:8080")
	fmt.Println("    Step-CA:         https://localhost:9000")
	fmt.Println("    Captive Portal:  http://192.168.137.1")
	fmt.Println()
	fmt.Println("  Press Ctrl+C to stop all services")
	fmt.Println("═══════════════════════════════════════════════════════════════")

	// Handle shutdown
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)

	<-sigChan

	fmt.Println()
	fmt.Println("[INFO] Shutting down all services...")

	for _, cmd := range runningServices {
		if cmd.Process != nil {
			cmd.Process.Kill()
		}
	}

	fmt.Println("[INFO] All services stopped. Goodbye!")
}
