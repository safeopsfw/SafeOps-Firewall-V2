//go:build ignore

package main

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
)

func main() {
	printBuildBanner()

	// Check if we're in the right directory
	if _, err := os.Stat("main.go"); os.IsNotExist(err) {
		fmt.Println("[ERROR] build.go must be run from src/SIEM directory")
		os.Exit(1)
	}

	// Check Go installation
	if err := checkGo(); err != nil {
		fmt.Printf("[ERROR] %v\n", err)
		os.Exit(1)
	}

	// Download dependencies
	fmt.Println("\n[STEP 1/4] Downloading dependencies...")
	if err := runCommand("go", "mod", "download"); err != nil {
		fmt.Printf("[ERROR] Failed to download dependencies: %v\n", err)
		os.Exit(1)
	}
	fmt.Println("[SUCCESS] Dependencies downloaded")

	// Create output directory
	fmt.Println("\n[STEP 2/4] Creating output directory...")
	outputDir := filepath.Join("..", "..", "bin", "siem")
	if err := os.MkdirAll(outputDir, 0755); err != nil {
		fmt.Printf("[ERROR] Failed to create output directory: %v\n", err)
		os.Exit(1)
	}
	fmt.Println("[SUCCESS] Output directory created")

	// Build the executable
	fmt.Println("\n[STEP 3/4] Building executable...")
	outputExe := filepath.Join(outputDir, "safeops-siem-setup.exe")
	if runtime.GOOS != "windows" {
		outputExe = filepath.Join(outputDir, "safeops-siem-setup")
	}

	buildArgs := []string{"build", "-o", outputExe, "main.go"}
	if err := runCommand("go", buildArgs...); err != nil {
		fmt.Printf("[ERROR] Build failed: %v\n", err)
		os.Exit(1)
	}
	fmt.Println("[SUCCESS] Executable built successfully")

	// Copy config file
	fmt.Println("\n[STEP 4/4] Copying configuration file...")
	configSrc := "config.yaml"
	configDest := filepath.Join(outputDir, "config.yaml")
	if err := copyFile(configSrc, configDest); err != nil {
		fmt.Printf("[ERROR] Failed to copy config: %v\n", err)
		os.Exit(1)
	}
	fmt.Println("[SUCCESS] Configuration file copied")

	// Print completion
	printCompletionBanner(outputExe, configDest)
}

func printBuildBanner() {
	fmt.Println("╔═══════════════════════════════════════════════════════════════╗")
	fmt.Println("║           SafeOps SIEM Installer - Build Tool                ║")
	fmt.Println("╚═══════════════════════════════════════════════════════════════╝")
	fmt.Println()
}

func checkGo() error {
	cmd := exec.Command("go", "version")
	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("Go is not installed or not in PATH. Install from: https://go.dev/dl/")
	}
	fmt.Printf("[INFO] %s", output)
	return nil
}

func runCommand(name string, args ...string) error {
	cmd := exec.Command(name, args...)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	return cmd.Run()
}

func copyFile(src, dst string) error {
	data, err := os.ReadFile(src)
	if err != nil {
		return err
	}
	return os.WriteFile(dst, data, 0644)
}

func printCompletionBanner(exePath, configPath string) {
	fmt.Println("\n╔═══════════════════════════════════════════════════════════════╗")
	fmt.Println("║                    Build Complete!                            ║")
	fmt.Println("╚═══════════════════════════════════════════════════════════════╝")
	fmt.Println()
	fmt.Println("Output files:")
	fmt.Printf("  Executable: %s\n", exePath)
	fmt.Printf("  Config:     %s\n", configPath)
	fmt.Println()
	fmt.Println("To run the installer:")
	fmt.Printf("  cd %s\n", filepath.Dir(exePath))
	if runtime.GOOS == "windows" {
		fmt.Println("  .\\safeops-siem-setup.exe")
	} else {
		fmt.Println("  ./safeops-siem-setup")
	}
	fmt.Println()
	fmt.Println("IMPORTANT: Run as Administrator!")
	fmt.Println()
}
