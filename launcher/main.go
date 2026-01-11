// SafeOps Launcher - Single Executable Runner
// Starts NIC Management API + DHCP Server + Dev UI + Opens Browser
package main

import (
	"fmt"
	"log"
	"os"
	"os/exec"
	"os/signal"
	"runtime"
	"syscall"
	"time"
)

const (
	NIC_API_PORT  = "8081"
	DHCP_PORT     = "50054"
	DEV_UI_PORT   = "5173"
	BROWSER_URL   = "http://localhost:5173/nic-management"
	STARTUP_DELAY = 3 // seconds to wait before opening browser
)

var (
	processes []*exec.Cmd
)

func main() {
	fmt.Println("╔═══════════════════════════════════════════════════════╗")
	fmt.Println("║           SafeOps - Network Management Suite         ║")
	fmt.Println("║              Starting All Services...                ║")
	fmt.Println("╚═══════════════════════════════════════════════════════╝")
	fmt.Println()

	// Setup signal handler for graceful shutdown
	setupSignalHandler()

	// Start services in order
	startDHCPServer()
	time.Sleep(1 * time.Second)

	startNICAPI()
	time.Sleep(1 * time.Second)

	startDevUI()

	// Wait for services to start
	fmt.Printf("\n⏳ Waiting %d seconds for services to initialize...\n", STARTUP_DELAY)
	time.Sleep(time.Duration(STARTUP_DELAY) * time.Second)

	// Open browser
	openBrowser(BROWSER_URL)

	fmt.Println("\n✅ All services running!")
	fmt.Println()
	fmt.Println("📋 Service Status:")
	fmt.Printf("   • DHCP Server:       http://localhost:%s (gRPC)\n", DHCP_PORT)
	fmt.Printf("   • NIC Management:    http://localhost:%s/api\n", NIC_API_PORT)
	fmt.Printf("   • Dev UI:            http://localhost:%s\n", DEV_UI_PORT)
	fmt.Println()
	fmt.Println("🌐 Opening browser at: " + BROWSER_URL)
	fmt.Println()
	fmt.Println("Press Ctrl+C to stop all services...")

	// Wait for interrupt
	select {}
}

// startDHCPServer starts the DHCP server
func startDHCPServer() {
	fmt.Println("🔧 Starting DHCP Server...")

	cmd := exec.Command("go", "run", "cmd/main.go")
	cmd.Dir = "D:\\SafeOpsFV2\\src\\dhcp_server"
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	if err := cmd.Start(); err != nil {
		log.Printf("⚠️  Warning: Could not start DHCP server: %v\n", err)
		log.Println("   Continuing with mock DHCP data...")
	} else {
		processes = append(processes, cmd)
		fmt.Printf("   ✅ DHCP Server started (PID: %d)\n", cmd.Process.Pid)
	}
}

// startNICAPI starts the NIC Management API
func startNICAPI() {
	fmt.Println("🔧 Starting NIC Management API...")

	cmd := exec.Command("go", "run", "cmd/main.go")
	cmd.Dir = "D:\\SafeOpsFV2\\src\\nic_management\\api"
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	if err := cmd.Start(); err != nil {
		log.Fatalf("❌ Failed to start NIC API: %v\n", err)
	}

	processes = append(processes, cmd)
	fmt.Printf("   ✅ NIC API started (PID: %d)\n", cmd.Process.Pid)
}

// startDevUI starts the React development server
func startDevUI() {
	fmt.Println("🔧 Starting React Dev UI...")

	var cmd *exec.Cmd
	if runtime.GOOS == "windows" {
		cmd = exec.Command("cmd", "/C", "npm", "run", "dev")
	} else {
		cmd = exec.Command("npm", "run", "dev")
	}

	cmd.Dir = "D:\\SafeOpsFV2\\src\\ui\\dev"
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	if err := cmd.Start(); err != nil {
		log.Fatalf("❌ Failed to start Dev UI: %v\n", err)
	}

	processes = append(processes, cmd)
	fmt.Printf("   ✅ Dev UI started (PID: %d)\n", cmd.Process.Pid)
}

// openBrowser opens the default browser
func openBrowser(url string) {
	var cmd *exec.Cmd

	switch runtime.GOOS {
	case "windows":
		cmd = exec.Command("cmd", "/c", "start", url)
	case "darwin":
		cmd = exec.Command("open", url)
	case "linux":
		cmd = exec.Command("xdg-open", url)
	default:
		log.Println("⚠️  Cannot open browser on this platform")
		return
	}

	if err := cmd.Run(); err != nil {
		log.Printf("⚠️  Warning: Could not open browser: %v\n", err)
		fmt.Printf("   Please manually open: %s\n", url)
	}
}

// setupSignalHandler handles Ctrl+C gracefully
func setupSignalHandler() {
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM)

	go func() {
		<-sigChan
		fmt.Println("\n\n🛑 Shutting down all services...")

		// Kill all processes
		for i, cmd := range processes {
			if cmd.Process != nil {
				fmt.Printf("   Stopping process %d (PID: %d)...\n", i+1, cmd.Process.Pid)
				cmd.Process.Kill()
			}
		}

		fmt.Println("✅ All services stopped. Goodbye!")
		os.Exit(0)
	}()
}
