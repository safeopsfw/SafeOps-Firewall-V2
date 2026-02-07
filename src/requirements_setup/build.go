// +build ignore

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
		fmt.Println("[ERROR] build.go must be run from src/requirements_setup directory")
		os.Exit(1)
	}

	// Check Go installation
	if err := checkGo(); err != nil {
		fmt.Printf("[ERROR] %v\n", err)
		os.Exit(1)
	}

	// Download dependencies
	fmt.Println("\n[STEP 1/6] Downloading dependencies...")
	if err := runCommand("go", "mod", "download"); err != nil {
		fmt.Printf("[ERROR] Failed to download dependencies: %v\n", err)
		os.Exit(1)
	}
	fmt.Println("[SUCCESS] Dependencies downloaded")

	// Create embedded schemas directory structure
	fmt.Println("\n[STEP 2/6] Creating embedded schemas directory...")
	dirs := []string{
		"embedded/schemas/threat_intel",
		"embedded/schemas/safeops_network",
		"embedded/schemas/dhcp_migrations",
		"embedded/schemas/patches",
		"embedded/schemas/seeds",
	}
	for _, dir := range dirs {
		if err := os.MkdirAll(dir, 0755); err != nil {
			fmt.Printf("[ERROR] Failed to create directory %s: %v\n", dir, err)
			os.Exit(1)
		}
	}
	fmt.Println("[SUCCESS] Embedded directories created")

	// Copy SQL schemas
	fmt.Println("\n[STEP 3/6] Copying SQL schema files...")
	if err := copySchemas(); err != nil {
		fmt.Printf("[ERROR] Failed to copy schemas: %v\n", err)
		os.Exit(1)
	}
	fmt.Println("[SUCCESS] SQL schemas copied")

	// Create output directory
	fmt.Println("\n[STEP 4/6] Creating output directory...")
	outputDir := filepath.Join("..", "..", "bin", "requirements_setup")
	if err := os.MkdirAll(outputDir, 0755); err != nil {
		fmt.Printf("[ERROR] Failed to create output directory: %v\n", err)
		os.Exit(1)
	}
	fmt.Println("[SUCCESS] Output directory created")

	// Build the executable
	fmt.Println("\n[STEP 5/6] Building executable...")
	outputExe := filepath.Join(outputDir, "safeops-requirements-setup.exe")
	if runtime.GOOS != "windows" {
		outputExe = filepath.Join(outputDir, "safeops-requirements-setup")
	}

	buildArgs := []string{"build", "-o", outputExe, "main.go"}
	if err := runCommand("go", buildArgs...); err != nil {
		fmt.Printf("[ERROR] Build failed: %v\n", err)
		os.Exit(1)
	}
	fmt.Println("[SUCCESS] Executable built successfully")

	// Copy config file
	fmt.Println("\n[STEP 6/6] Copying configuration file...")
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
	fmt.Println("║      SafeOps Requirements Installer - Build Tool             ║")
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

func copySchemas() error {
	// Threat Intel schemas
	threatIntelSchemas := []string{
		"001_initial_setup.sql",
		"002_ip_reputation.sql",
		"003_domain_reputation.sql",
		"004_hash_reputation.sql",
		"007_geolocation.sql",
		"008_threat_feeds.sql",
		"010_whitelist_filters.sql",
		"016_firewall_engine.sql",
		"017_ids_ips.sql",
		"021_threat_intel.sql",
		"users.sql",
	}

	schemaBaseDir := filepath.Join("..", "..", "database", "schemas")
	for _, schema := range threatIntelSchemas {
		src := filepath.Join(schemaBaseDir, schema)
		dest := filepath.Join("embedded", "schemas", "threat_intel", schema)
		if err := copyFile(src, dest); err != nil {
			return fmt.Errorf("failed to copy %s: %w", schema, err)
		}
		fmt.Printf("  Copied: %s\n", schema)
	}

	// SafeOps Network schemas
	networkSchemas := []string{
		"013_dhcp_server.sql",
		"020_nic_management.sql",
		"022_step_ca.sql",
	}

	for _, schema := range networkSchemas {
		src := filepath.Join(schemaBaseDir, schema)
		dest := filepath.Join("embedded", "schemas", "safeops_network", schema)
		if err := copyFile(src, dest); err != nil {
			return fmt.Errorf("failed to copy %s: %w", schema, err)
		}
		fmt.Printf("  Copied: %s\n", schema)
	}

	// DHCP migrations
	dhcpMigrations := []string{
		"002_add_portal_tracking.sql",
		"003_add_ca_cert_tracking.sql",
		"004_add_device_fingerprint.sql",
		"005_fix_missing_columns.sql",
	}

	migrationBaseDir := filepath.Join("..", "..", "src", "dhcp_monitor", "migrations")
	for _, migration := range dhcpMigrations {
		src := filepath.Join(migrationBaseDir, migration)
		dest := filepath.Join("embedded", "schemas", "dhcp_migrations", migration)
		if err := copyFile(src, dest); err != nil {
			return fmt.Errorf("failed to copy %s: %w", migration, err)
		}
		fmt.Printf("  Copied: %s\n", migration)
	}

	// Schema patches (fixes for threat_intel pipeline binary)
	patches := []string{
		"001_threat_intel_patches.sql",
		"002_views_and_functions.sql",
	}

	patchBaseDir := filepath.Join("..", "..", "database", "patches")
	for _, patch := range patches {
		src := filepath.Join(patchBaseDir, patch)
		dest := filepath.Join("embedded", "schemas", "patches", patch)
		if err := copyFile(src, dest); err != nil {
			return fmt.Errorf("failed to copy %s: %w", patch, err)
		}
		fmt.Printf("  Copied: %s\n", patch)
	}

	// Seed data
	seeds := []string{
		"feed_sources_config.sql",
		"initial_threat_categories.sql",
	}

	seedBaseDir := filepath.Join("..", "..", "database", "seeds")
	for _, seed := range seeds {
		src := filepath.Join(seedBaseDir, seed)
		dest := filepath.Join("embedded", "schemas", "seeds", seed)
		if err := copyFile(src, dest); err != nil {
			return fmt.Errorf("failed to copy %s: %w", seed, err)
		}
		fmt.Printf("  Copied: %s\n", seed)
	}

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
		fmt.Println("  .\\safeops-requirements-setup.exe")
	} else {
		fmt.Println("  ./safeops-requirements-setup")
	}
	fmt.Println()
	fmt.Println("IMPORTANT: Run as Administrator!")
	fmt.Println()
}
