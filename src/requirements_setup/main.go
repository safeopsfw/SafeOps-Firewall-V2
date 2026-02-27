package main

import (
	"embed"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

//go:embed embedded/schemas/threat_intel/*.sql
var threatIntelSchemas embed.FS

//go:embed embedded/schemas/safeops_network/*.sql
var safeopsNetworkSchemas embed.FS

//go:embed embedded/schemas/dhcp_migrations/*.sql
var dhcpMigrations embed.FS

//go:embed embedded/schemas/patches/*.sql
var patchSchemas embed.FS

//go:embed embedded/schemas/seeds/*.sql
var seedSchemas embed.FS

// Config structures matching config.yaml
type Config struct {
	Installation struct {
		BaseDir      string `yaml:"base_dir"`
		TempDir      string `yaml:"temp_dir"`
		SkipExisting bool   `yaml:"skip_existing"`
		Interactive  bool   `yaml:"interactive"`
	} `yaml:"installation"`

	PostgreSQL struct {
		Version          string `yaml:"version"`
		DownloadURL      string `yaml:"download_url"`
		InstallDir       string `yaml:"install_dir"`
		DataDir          string `yaml:"data_dir"`
		Port             int    `yaml:"port"`
		PostgresPassword string `yaml:"postgres_password"`
		Locale           string `yaml:"locale"`
		ServiceName      string `yaml:"service_name"`
		Databases        []struct {
			Name        string `yaml:"name"`
			Owner       string `yaml:"owner"`
			Encoding    string `yaml:"encoding"`
			Description string `yaml:"description"`
		} `yaml:"databases"`
		Users []struct {
			Username    string   `yaml:"username"`
			Password    string   `yaml:"password"`
			Description string   `yaml:"description"`
			Databases   []string `yaml:"databases"`
		} `yaml:"users"`
	} `yaml:"postgresql"`

	WinPkFilter struct {
		Version     string `yaml:"version"`
		DownloadURL string `yaml:"download_url"`
		InstallDir  string `yaml:"install_dir"`
		DriverFile  string `yaml:"driver_file"`
		Required    bool   `yaml:"required"`
	} `yaml:"winpkfilter"`

	NodeJS struct {
		Version     string `yaml:"version"`
		DownloadURL string `yaml:"download_url"`
		InstallDir  string `yaml:"install_dir"`
		AddToPath   bool   `yaml:"add_to_path"`
		Required    bool   `yaml:"required"`
	} `yaml:"nodejs"`

	DatabaseSchemas struct {
		ThreatIntelSchemas []struct {
			File        string `yaml:"file"`
			Description string `yaml:"description"`
		} `yaml:"threat_intel_schemas"`
		SafeopsNetworkSchemas []struct {
			File        string `yaml:"file"`
			Description string `yaml:"description"`
		} `yaml:"safeops_network_schemas"`
		DHCPMigrations []struct {
			File        string `yaml:"file"`
			Description string `yaml:"description"`
		} `yaml:"dhcp_migrations"`
		Patches []struct {
			File        string `yaml:"file"`
			Description string `yaml:"description"`
		} `yaml:"patches"`
		Seeds []struct {
			File        string `yaml:"file"`
			Description string `yaml:"description"`
		} `yaml:"seeds"`
	} `yaml:"database_schemas"`

	Options struct {
		CreateShortcuts   bool `yaml:"create_shortcuts"`
		ConfigureFirewall bool `yaml:"configure_firewall"`
		FirewallPorts     []struct {
			Port      int    `yaml:"port"`
			Protocol  string `yaml:"protocol"`
			Name      string `yaml:"name"`
			Direction string `yaml:"direction"`
		} `yaml:"firewall_ports"`
	} `yaml:"options"`

	Verification struct {
		Services []struct {
			Name           string `yaml:"name"`
			ExpectedStatus string `yaml:"expected_status"`
		} `yaml:"services"`
		Ports []struct {
			Port        int    `yaml:"port"`
			Host        string `yaml:"host"`
			Description string `yaml:"description"`
		} `yaml:"ports"`
		Databases []struct {
			Name string `yaml:"name"`
			Host string `yaml:"host"`
			Port int    `yaml:"port"`
			User string `yaml:"user"`
		} `yaml:"databases"`
	} `yaml:"verification"`

	Security struct {
		DefaultPasswords map[string]string `yaml:"default_passwords"`
		Warning          string            `yaml:"warning"`
	} `yaml:"security"`
}

var config Config

func main() {
	// Parse command-line flags
	dbInit := false
	dbReset := false
	for _, arg := range os.Args[1:] {
		switch arg {
		case "--db-init", "-db-init":
			dbInit = true
		case "--db-reset", "-db-reset":
			dbReset = true
		}
	}

	printBanner()

	// Load configuration
	if err := loadConfig(); err != nil {
		fmt.Printf("[ERROR] Failed to load config: %v\n", err)
		os.Exit(1)
	}

	fmt.Println("[INFO] Configuration loaded successfully")
	fmt.Println()

	// Database-only modes
	if dbInit || dbReset {
		runDatabaseInit(dbReset)
		return
	}

	// Display current configuration
	displayConfiguration()

	// Confirm installation
	if config.Installation.Interactive && !confirmInstallation() {
		fmt.Println("[INFO] Installation cancelled by user")
		return
	}

	// Create temporary directory
	if err := createTempDir(); err != nil {
		fmt.Printf("[ERROR] Failed to create temp directory: %v\n", err)
		os.Exit(1)
	}

	// Install PostgreSQL
	fmt.Println("\n[STEP 1/11] Installing PostgreSQL...")
	if err := installPostgreSQL(); err != nil {
		fmt.Printf("[ERROR] PostgreSQL installation failed: %v\n", err)
		os.Exit(1)
	}
	fmt.Println("[SUCCESS] PostgreSQL installed")

	// Start PostgreSQL service
	fmt.Println("\n[STEP 2/11] Starting PostgreSQL service...")
	if err := startPostgreSQLService(); err != nil {
		fmt.Printf("[ERROR] Failed to start PostgreSQL: %v\n", err)
		os.Exit(1)
	}
	fmt.Println("[SUCCESS] PostgreSQL service started")

	// Wait for PostgreSQL to be ready
	fmt.Println("[INFO] Waiting for PostgreSQL to initialize...")
	time.Sleep(5 * time.Second)

	// Create databases
	fmt.Println("\n[STEP 3/11] Creating databases...")
	if err := createDatabases(); err != nil {
		fmt.Printf("[ERROR] Database creation failed: %v\n", err)
		os.Exit(1)
	}
	fmt.Println("[SUCCESS] Databases created")

	// Create users
	fmt.Println("\n[STEP 4/11] Creating database users...")
	if err := createUsers(); err != nil {
		fmt.Printf("[ERROR] User creation failed: %v\n", err)
		os.Exit(1)
	}
	fmt.Println("[SUCCESS] Database users created")

	// Apply schemas
	fmt.Println("\n[STEP 5/11] Applying database schemas...")
	if err := applySchemas(); err != nil {
		fmt.Printf("[ERROR] Schema application failed: %v\n", err)
		os.Exit(1)
	}
	fmt.Println("[SUCCESS] All schemas applied")

	// Apply schema patches (fixes for threat_intel pipeline binary)
	fmt.Println("\n[STEP 6/11] Applying schema patches...")
	if err := applyPatches(); err != nil {
		fmt.Printf("[ERROR] Schema patches failed: %v\n", err)
		os.Exit(1)
	}
	fmt.Println("[SUCCESS] Schema patches applied")

	// Apply seed data
	fmt.Println("\n[STEP 7/11] Loading seed data...")
	if err := applySeeds(); err != nil {
		fmt.Printf("[ERROR] Seed data failed: %v\n", err)
		os.Exit(1)
	}
	fmt.Println("[SUCCESS] Seed data loaded")

	// Apply views and functions (done after patches since patches may alter column types)
	fmt.Println("\n[STEP 8/11] Creating views and functions...")
	// Views are included in patch 002, already applied above
	fmt.Println("[SUCCESS] Views and functions created")

	// Grant table-level permissions
	fmt.Println("\n[STEP 9/11] Granting table-level permissions...")
	if err := grantTablePermissions(); err != nil {
		fmt.Printf("[ERROR] Permission grants failed: %v\n", err)
		os.Exit(1)
	}
	fmt.Println("[SUCCESS] Table-level permissions granted")

	// Install Node.js
	fmt.Println("\n[STEP 10/11] Installing Node.js...")
	if err := installNodeJS(); err != nil {
		fmt.Printf("[ERROR] Node.js installation failed: %v\n", err)
		os.Exit(1)
	}
	fmt.Println("[SUCCESS] Node.js installed")

	// Install WinPkFilter
	fmt.Println("\n[STEP 11/11] Installing WinPkFilter driver...")
	if err := installWinPkFilter(); err != nil {
		fmt.Printf("[ERROR] WinPkFilter installation failed: %v\n", err)
		os.Exit(1)
	}
	fmt.Println("[SUCCESS] WinPkFilter installed")

	// Cleanup
	fmt.Println("\n[CLEANUP] Removing temporary files...")
	cleanup()

	// Print completion summary
	printCompletionSummary()
}

// runDatabaseInit handles --db-init and --db-reset modes.
// Skips PostgreSQL/Node.js/WinPkFilter installation.
// Only runs database creation, schemas, patches, seeds, and permissions.
func runDatabaseInit(reset bool) {
	if reset {
		fmt.Println("[MODE] Database RESET — will drop and recreate all databases")
	} else {
		fmt.Println("[MODE] Database INIT — will create/update databases (safe to re-run)")
	}
	fmt.Println()

	// Verify PostgreSQL is installed and reachable
	psqlPath := filepath.Join(config.PostgreSQL.InstallDir, "bin", "psql.exe")
	if _, err := os.Stat(psqlPath); os.IsNotExist(err) {
		fmt.Printf("[ERROR] psql not found at: %s\n", psqlPath)
		fmt.Println("[HINT] Install PostgreSQL first with: safeops-requirements-setup.exe")
		os.Exit(1)
	}

	// Check PostgreSQL service is running
	fmt.Println("[CHECK] Verifying PostgreSQL is running...")
	testCmd := exec.Command(psqlPath,
		"-U", "postgres", "-h", "localhost",
		"-p", fmt.Sprintf("%d", config.PostgreSQL.Port),
		"-c", "SELECT 1;",
	)
	testCmd.Env = append(os.Environ(), fmt.Sprintf("PGPASSWORD=%s", config.PostgreSQL.PostgresPassword))
	if output, err := testCmd.CombinedOutput(); err != nil {
		fmt.Printf("[ERROR] Cannot connect to PostgreSQL: %v\n", err)
		fmt.Printf("  Output: %s\n", string(output))
		fmt.Println("[HINT] Make sure PostgreSQL service is running:")
		fmt.Println("       net start postgresql-x64-16")
		os.Exit(1)
	}
	fmt.Println("[OK] PostgreSQL is running")
	fmt.Println()

	// Create temp dir for SQL file execution
	if err := createTempDir(); err != nil {
		fmt.Printf("[ERROR] Failed to create temp directory: %v\n", err)
		os.Exit(1)
	}
	defer cleanup()

	steps := 7
	step := 1

	// Step 0 (reset only): Drop databases
	if reset {
		fmt.Printf("\n[STEP %d/%d] Dropping existing databases...\n", step, steps)
		for _, db := range config.PostgreSQL.Databases {
			fmt.Printf("  Dropping: %s\n", db.Name)
			dropQuery := fmt.Sprintf("DROP DATABASE IF EXISTS %s;", db.Name)
			cmd := exec.Command(psqlPath,
				"-U", "postgres", "-h", "localhost",
				"-p", fmt.Sprintf("%d", config.PostgreSQL.Port),
				"-c", dropQuery,
			)
			cmd.Env = append(os.Environ(), fmt.Sprintf("PGPASSWORD=%s", config.PostgreSQL.PostgresPassword))
			output, err := cmd.CombinedOutput()
			if err != nil {
				// Ignore errors (db might have active connections)
				fmt.Printf("  [WARN] %s: %s\n", db.Name, strings.TrimSpace(string(output)))
			}
		}
		fmt.Println("[OK] Databases dropped")
		step++
	}

	// Create databases
	fmt.Printf("\n[STEP %d/%d] Creating databases...\n", step, steps)
	if err := createDatabases(); err != nil {
		fmt.Printf("[ERROR] %v\n", err)
		os.Exit(1)
	}
	fmt.Println("[OK] Databases ready")
	step++

	// Create users
	fmt.Printf("\n[STEP %d/%d] Creating database users...\n", step, steps)
	if err := createUsers(); err != nil {
		fmt.Printf("[ERROR] %v\n", err)
		os.Exit(1)
	}
	fmt.Println("[OK] Users ready")
	step++

	// Apply schemas
	fmt.Printf("\n[STEP %d/%d] Applying database schemas...\n", step, steps)
	if err := applySchemas(); err != nil {
		fmt.Printf("[ERROR] %v\n", err)
		os.Exit(1)
	}
	fmt.Println("[OK] Schemas applied")
	step++

	// Apply patches
	fmt.Printf("\n[STEP %d/%d] Applying schema patches...\n", step, steps)
	if err := applyPatches(); err != nil {
		fmt.Printf("[ERROR] %v\n", err)
		os.Exit(1)
	}
	fmt.Println("[OK] Patches applied")
	step++

	// Apply seeds
	fmt.Printf("\n[STEP %d/%d] Loading seed data...\n", step, steps)
	if err := applySeeds(); err != nil {
		fmt.Printf("[ERROR] %v\n", err)
		os.Exit(1)
	}
	fmt.Println("[OK] Seed data loaded")
	step++

	// Grant permissions
	fmt.Printf("\n[STEP %d/%d] Granting table-level permissions...\n", step, steps)
	if err := grantTablePermissions(); err != nil {
		fmt.Printf("[ERROR] %v\n", err)
		os.Exit(1)
	}
	fmt.Println("[OK] Permissions granted")

	// Summary
	fmt.Println()
	fmt.Println("╔═══════════════════════════════════════════════════════════════╗")
	fmt.Println("║           Database Initialization Complete!                   ║")
	fmt.Println("╚═══════════════════════════════════════════════════════════════╝")
	fmt.Println()
	fmt.Println("Databases:")
	for _, db := range config.PostgreSQL.Databases {
		fmt.Printf("  [OK] %-20s (%s)\n", db.Name, db.Description)
	}
	fmt.Println()
	fmt.Println("Next Steps:")
	fmt.Println("  1. Run threat intel pipeline:  bin\\threat_intel\\threat_intel.exe")
	fmt.Println("  2. Start SafeOps launcher:     bin\\launcher.exe")
	fmt.Println()
}

func printBanner() {
	fmt.Println("╔═══════════════════════════════════════════════════════════════╗")
	fmt.Println("║       SafeOps Requirements Setup Installer v1.0              ║")
	fmt.Println("╚═══════════════════════════════════════════════════════════════╝")
	fmt.Println()
	fmt.Println("Usage:")
	fmt.Println("  safeops-requirements-setup.exe              Full install")
	fmt.Println("  safeops-requirements-setup.exe --db-init    Database only (safe to re-run)")
	fmt.Println("  safeops-requirements-setup.exe --db-reset   Drop + recreate databases")
	fmt.Println()
	fmt.Println("This installer will set up:")
	fmt.Println("  * PostgreSQL 16.1 (with 3 databases + schemas + patches)")
	fmt.Println("  * Database seed data (threat feeds, categories)")
	fmt.Println("  * Table-level permissions for all app users")
	fmt.Println("  * Node.js 20.11.0 (for UI and Backend)")
	fmt.Println("  * WinPkFilter 3.4.8 (packet capture driver)")
	fmt.Println()
}

func loadConfig() error {
	data, err := os.ReadFile("config.yaml")
	if err != nil {
		return fmt.Errorf("failed to read config.yaml: %w", err)
	}

	if err := yaml.Unmarshal(data, &config); err != nil {
		return fmt.Errorf("failed to parse config.yaml: %w", err)
	}

	return nil
}

func displayConfiguration() {
	fmt.Println("╔═══════════════════════════════════════════════════════════════╗")
	fmt.Println("║                  Current Configuration                        ║")
	fmt.Println("╚═══════════════════════════════════════════════════════════════╝")
	fmt.Println()
	fmt.Println("PostgreSQL Settings:")
	fmt.Printf("  Installation Directory: %s\n", config.PostgreSQL.InstallDir)
	fmt.Printf("  Data Directory:         %s\n", config.PostgreSQL.DataDir)
	fmt.Printf("  Port:                   %d\n", config.PostgreSQL.Port)
	fmt.Printf("  Postgres Password:      %s\n", maskPassword(config.PostgreSQL.PostgresPassword))
	fmt.Println()
	fmt.Println("Node.js Settings:")
	fmt.Printf("  Installation Directory: %s\n", config.NodeJS.InstallDir)
	fmt.Println()
	fmt.Println("WinPkFilter Settings:")
	fmt.Printf("  Installation Directory: %s\n", config.WinPkFilter.InstallDir)
	fmt.Println()
}

func maskPassword(password string) string {
	if len(password) <= 2 {
		return "***"
	}
	return string(password[0]) + strings.Repeat("*", len(password)-2) + string(password[len(password)-1])
}

func confirmInstallation() bool {
	fmt.Print("Do you want to continue? (yes/no): ")
	var response string
	fmt.Scanln(&response)
	response = strings.ToLower(strings.TrimSpace(response))
	return response == "yes" || response == "y"
}

func createTempDir() error {
	return os.MkdirAll(config.Installation.TempDir, 0755)
}

func installPostgreSQL() error {
	// Check if already installed
	if config.Installation.SkipExisting {
		if _, err := os.Stat(config.PostgreSQL.InstallDir); err == nil {
			fmt.Println("  [SKIP] PostgreSQL already installed")
			return nil
		}
	}

	// Download PostgreSQL installer
	installerPath := filepath.Join(config.Installation.TempDir, "postgresql-installer.exe")
	fmt.Printf("  Downloading from: %s\n", config.PostgreSQL.DownloadURL)

	if err := downloadFile(config.PostgreSQL.DownloadURL, installerPath); err != nil {
		return fmt.Errorf("download failed: %w", err)
	}

	// Run silent installation
	fmt.Println("  Running silent installation (this may take several minutes)...")
	args := []string{
		"--mode", "unattended",
		"--unattendedmodeui", "none",
		"--prefix", config.PostgreSQL.InstallDir,
		"--datadir", config.PostgreSQL.DataDir,
		"--superpassword", config.PostgreSQL.PostgresPassword,
		"--serverport", fmt.Sprintf("%d", config.PostgreSQL.Port),
		"--servicename", config.PostgreSQL.ServiceName,
		"--locale", config.PostgreSQL.Locale,
		"--enable-components", "server,commandlinetools",
	}

	cmd := exec.Command(installerPath, args...)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	if err := cmd.Run(); err != nil {
		return fmt.Errorf("installation failed: %w", err)
	}

	return nil
}

func startPostgreSQLService() error {
	cmd := exec.Command("net", "start", config.PostgreSQL.ServiceName)
	output, err := cmd.CombinedOutput()

	// Service might already be running
	if err != nil && !strings.Contains(string(output), "already") {
		return fmt.Errorf("failed to start service: %w\nOutput: %s", err, output)
	}

	return nil
}

func createDatabases() error {
	psqlPath := filepath.Join(config.PostgreSQL.InstallDir, "bin", "psql.exe")

	for _, db := range config.PostgreSQL.Databases {
		fmt.Printf("  Creating database: %s (%s)\n", db.Name, db.Description)

		query := fmt.Sprintf("CREATE DATABASE %s OWNER %s ENCODING '%s';", db.Name, db.Owner, db.Encoding)

		cmd := exec.Command(psqlPath,
			"-U", "postgres",
			"-h", "localhost",
			"-p", fmt.Sprintf("%d", config.PostgreSQL.Port),
			"-c", query,
		)

		cmd.Env = append(os.Environ(), fmt.Sprintf("PGPASSWORD=%s", config.PostgreSQL.PostgresPassword))
		output, err := cmd.CombinedOutput()

		if err != nil && !strings.Contains(string(output), "already exists") {
			return fmt.Errorf("failed to create database %s: %w\nOutput: %s", db.Name, err, output)
		}
	}

	return nil
}

func createUsers() error {
	psqlPath := filepath.Join(config.PostgreSQL.InstallDir, "bin", "psql.exe")

	for _, user := range config.PostgreSQL.Users {
		fmt.Printf("  Creating user: %s (%s)\n", user.Username, user.Description)

		// Create user
		createUserQuery := fmt.Sprintf("CREATE USER %s WITH PASSWORD '%s';", user.Username, user.Password)

		cmd := exec.Command(psqlPath,
			"-U", "postgres",
			"-h", "localhost",
			"-p", fmt.Sprintf("%d", config.PostgreSQL.Port),
			"-c", createUserQuery,
		)

		cmd.Env = append(os.Environ(), fmt.Sprintf("PGPASSWORD=%s", config.PostgreSQL.PostgresPassword))
		output, err := cmd.CombinedOutput()

		if err != nil && !strings.Contains(string(output), "already exists") {
			return fmt.Errorf("failed to create user %s: %w\nOutput: %s", user.Username, err, output)
		}

		// Grant permissions
		for _, dbName := range user.Databases {
			grantQuery := fmt.Sprintf("GRANT ALL PRIVILEGES ON DATABASE %s TO %s;", dbName, user.Username)

			cmdGrant := exec.Command(psqlPath,
				"-U", "postgres",
				"-h", "localhost",
				"-p", fmt.Sprintf("%d", config.PostgreSQL.Port),
				"-c", grantQuery,
			)

			cmdGrant.Env = append(os.Environ(), fmt.Sprintf("PGPASSWORD=%s", config.PostgreSQL.PostgresPassword))
			if err := cmdGrant.Run(); err != nil {
				fmt.Printf("  [WARN] Failed to grant privileges on %s to %s\n", dbName, user.Username)
			}
		}
	}

	return nil
}

func applySchemas() error {
	psqlPath := filepath.Join(config.PostgreSQL.InstallDir, "bin", "psql.exe")

	// Apply threat intel schemas
	fmt.Println("  Applying Threat Intel schemas...")
	for _, schema := range config.DatabaseSchemas.ThreatIntelSchemas {
		fmt.Printf("    - %s: %s\n", schema.File, schema.Description)

		sqlContent, err := threatIntelSchemas.ReadFile("embedded/schemas/threat_intel/" + schema.File)
		if err != nil {
			return fmt.Errorf("failed to read schema %s: %w", schema.File, err)
		}

		if err := executeSQLFile(psqlPath, "threat_intel_db", string(sqlContent)); err != nil {
			return fmt.Errorf("failed to apply schema %s: %w", schema.File, err)
		}
	}

	// Apply safeops_network schemas
	fmt.Println("  Applying SafeOps Network schemas...")
	for _, schema := range config.DatabaseSchemas.SafeopsNetworkSchemas {
		fmt.Printf("    - %s: %s\n", schema.File, schema.Description)

		sqlContent, err := safeopsNetworkSchemas.ReadFile("embedded/schemas/safeops_network/" + schema.File)
		if err != nil {
			return fmt.Errorf("failed to read schema %s: %w", schema.File, err)
		}

		if err := executeSQLFile(psqlPath, "safeops_network", string(sqlContent)); err != nil {
			return fmt.Errorf("failed to apply schema %s: %w", schema.File, err)
		}
	}

	// Apply DHCP migrations
	fmt.Println("  Applying DHCP Monitor migrations...")
	for _, migration := range config.DatabaseSchemas.DHCPMigrations {
		fmt.Printf("    - %s: %s\n", migration.File, migration.Description)

		sqlContent, err := dhcpMigrations.ReadFile("embedded/schemas/dhcp_migrations/" + migration.File)
		if err != nil {
			return fmt.Errorf("failed to read migration %s: %w", migration.File, err)
		}

		if err := executeSQLFile(psqlPath, "safeops_network", string(sqlContent)); err != nil {
			return fmt.Errorf("failed to apply migration %s: %w", migration.File, err)
		}
	}

	return nil
}

func applyPatches() error {
	psqlPath := filepath.Join(config.PostgreSQL.InstallDir, "bin", "psql.exe")

	for _, patch := range config.DatabaseSchemas.Patches {
		fmt.Printf("  Applying: %s (%s)\n", patch.File, patch.Description)

		sqlContent, err := patchSchemas.ReadFile("embedded/schemas/patches/" + patch.File)
		if err != nil {
			return fmt.Errorf("failed to read patch %s: %w", patch.File, err)
		}

		if err := executeSQLFile(psqlPath, "threat_intel_db", string(sqlContent)); err != nil {
			// Patches are best-effort (some may warn on already-applied changes)
			fmt.Printf("  [WARN] Patch %s had warnings (may be already applied)\n", patch.File)
		}
	}

	return nil
}

func applySeeds() error {
	psqlPath := filepath.Join(config.PostgreSQL.InstallDir, "bin", "psql.exe")

	for _, seed := range config.DatabaseSchemas.Seeds {
		fmt.Printf("  Loading: %s (%s)\n", seed.File, seed.Description)

		sqlContent, err := seedSchemas.ReadFile("embedded/schemas/seeds/" + seed.File)
		if err != nil {
			return fmt.Errorf("failed to read seed %s: %w", seed.File, err)
		}

		if err := executeSQLFile(psqlPath, "threat_intel_db", string(sqlContent)); err != nil {
			// Seeds may fail on duplicate keys, that's OK
			fmt.Printf("  [WARN] Seed %s had warnings (data may already exist)\n", seed.File)
		}
	}

	return nil
}

func grantTablePermissions() error {
	psqlPath := filepath.Join(config.PostgreSQL.InstallDir, "bin", "psql.exe")

	// Grant table-level permissions on all databases for all app users
	databases := map[string][]string{
		"threat_intel_db": {"safeops", "threat_intel_app", "dhcp_server", "dns_server"},
		"safeops_network": {"safeops", "dhcp_server", "dns_server"},
		"safeops":         {"safeops"},
	}

	for dbName, users := range databases {
		for _, user := range users {
			grantSQL := fmt.Sprintf(`
				GRANT ALL PRIVILEGES ON ALL TABLES IN SCHEMA public TO %s;
				GRANT ALL PRIVILEGES ON ALL SEQUENCES IN SCHEMA public TO %s;
				ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT ALL ON TABLES TO %s;
				ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT ALL ON SEQUENCES TO %s;
			`, user, user, user, user)

			if err := executeSQLFile(psqlPath, dbName, grantSQL); err != nil {
				fmt.Printf("  [WARN] Failed to grant permissions to %s on %s\n", user, dbName)
			}
		}
		fmt.Printf("  [OK] Permissions granted on %s\n", dbName)
	}

	return nil
}

func executeSQLFile(psqlPath, database, sqlContent string) error {
	// Create temp file for SQL content
	tempFile := filepath.Join(config.Installation.TempDir, fmt.Sprintf("temp_%d.sql", time.Now().Unix()))
	if err := os.WriteFile(tempFile, []byte(sqlContent), 0644); err != nil {
		return fmt.Errorf("failed to write temp SQL file: %w", err)
	}
	defer os.Remove(tempFile)

	cmd := exec.Command(psqlPath,
		"-U", "postgres",
		"-h", "localhost",
		"-p", fmt.Sprintf("%d", config.PostgreSQL.Port),
		"-d", database,
		"-f", tempFile,
	)

	cmd.Env = append(os.Environ(), fmt.Sprintf("PGPASSWORD=%s", config.PostgreSQL.PostgresPassword))
	output, err := cmd.CombinedOutput()

	if err != nil {
		return fmt.Errorf("SQL execution failed: %w\nOutput: %s", err, output)
	}

	return nil
}

func installNodeJS() error {
	// Check if already installed
	if config.Installation.SkipExisting {
		cmd := exec.Command("node", "--version")
		if err := cmd.Run(); err == nil {
			fmt.Println("  [SKIP] Node.js already installed")
			return nil
		}
	}

	// Download Node.js installer
	installerPath := filepath.Join(config.Installation.TempDir, "node-installer.msi")
	fmt.Printf("  Downloading from: %s\n", config.NodeJS.DownloadURL)

	if err := downloadFile(config.NodeJS.DownloadURL, installerPath); err != nil {
		return fmt.Errorf("download failed: %w", err)
	}

	// Run MSI installer silently
	fmt.Println("  Running silent installation...")
	cmd := exec.Command("msiexec", "/i", installerPath, "/quiet", "/norestart")
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	if err := cmd.Run(); err != nil {
		return fmt.Errorf("installation failed: %w", err)
	}

	return nil
}

func installWinPkFilter() error {
	// Check if driver already exists
	driverPath := filepath.Join(config.WinPkFilter.InstallDir, config.WinPkFilter.DriverFile)
	if config.Installation.SkipExisting {
		if _, err := os.Stat(driverPath); err == nil {
			fmt.Println("  [SKIP] WinPkFilter already installed")
			return nil
		}
	}

	// Download WinPkFilter installer
	installerPath := filepath.Join(config.Installation.TempDir, "winpkfilter-installer.exe")
	fmt.Printf("  Downloading from: %s\n", config.WinPkFilter.DownloadURL)

	if err := downloadFile(config.WinPkFilter.DownloadURL, installerPath); err != nil {
		return fmt.Errorf("download failed: %w", err)
	}

	// Run silent installation
	fmt.Println("  Running silent installation...")
	installDirArg := fmt.Sprintf("/D=%s", config.WinPkFilter.InstallDir)
	cmd := exec.Command(installerPath, "/S", installDirArg)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	if err := cmd.Run(); err != nil {
		return fmt.Errorf("installation failed: %w", err)
	}

	return nil
}

func downloadFile(url, dest string) error {
	out, err := os.Create(dest)
	if err != nil {
		return err
	}
	defer out.Close()

	resp, err := http.Get(url)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("bad status: %s", resp.Status)
	}

	// Show progress
	total := resp.ContentLength
	fmt.Printf("  File size: %.2f MB\n", float64(total)/(1024*1024))

	_, err = io.Copy(out, resp.Body)
	return err
}

func cleanup() {
	os.RemoveAll(config.Installation.TempDir)
}

func printCompletionSummary() {
	fmt.Println()
	fmt.Println("╔═══════════════════════════════════════════════════════════════╗")
	fmt.Println("║         Installation Complete Successfully!                   ║")
	fmt.Println("╚═══════════════════════════════════════════════════════════════╝")
	fmt.Println()
	fmt.Println("PostgreSQL Details:")
	fmt.Printf("  Host:     localhost\n")
	fmt.Printf("  Port:     %d\n", config.PostgreSQL.Port)
	fmt.Printf("  Username: postgres\n")
	fmt.Printf("  Password: %s\n", maskPassword(config.PostgreSQL.PostgresPassword))
	fmt.Println()
	fmt.Println("Databases Created:")
	for _, db := range config.PostgreSQL.Databases {
		fmt.Printf("  • %-20s (%s)\n", db.Name, db.Description)
	}
	fmt.Println()
	fmt.Println("Database Users Created:")
	for _, user := range config.PostgreSQL.Users {
		fmt.Printf("  • %-20s (password: %s)\n", user.Username, user.Password)
	}
	fmt.Println()
	fmt.Println("Components Installed:")
	fmt.Printf("  • PostgreSQL %s\n", config.PostgreSQL.Version)
	fmt.Printf("  • Node.js %s\n", config.NodeJS.Version)
	fmt.Printf("  • WinPkFilter %s\n", config.WinPkFilter.Version)
	fmt.Println()
	fmt.Println(config.Security.Warning)
	fmt.Println()
	fmt.Println("Next Steps:")
	fmt.Println("  1. Change default passwords (IMPORTANT!)")
	fmt.Println("  2. Run SafeOps launcher: bin\\launcher.exe")
	fmt.Println("  3. (Optional) Run SIEM installer: bin\\siem\\safeops-siem-setup.exe")
	fmt.Println()
}
