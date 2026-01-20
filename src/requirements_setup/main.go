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
	printBanner()

	// Load configuration
	if err := loadConfig(); err != nil {
		fmt.Printf("[ERROR] Failed to load config: %v\n", err)
		os.Exit(1)
	}

	fmt.Println("[INFO] Configuration loaded successfully")
	fmt.Println()

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
	fmt.Println("\n[STEP 1/7] Installing PostgreSQL...")
	if err := installPostgreSQL(); err != nil {
		fmt.Printf("[ERROR] PostgreSQL installation failed: %v\n", err)
		os.Exit(1)
	}
	fmt.Println("[SUCCESS] PostgreSQL installed")

	// Start PostgreSQL service
	fmt.Println("\n[STEP 2/7] Starting PostgreSQL service...")
	if err := startPostgreSQLService(); err != nil {
		fmt.Printf("[ERROR] Failed to start PostgreSQL: %v\n", err)
		os.Exit(1)
	}
	fmt.Println("[SUCCESS] PostgreSQL service started")

	// Wait for PostgreSQL to be ready
	fmt.Println("[INFO] Waiting for PostgreSQL to initialize...")
	time.Sleep(5 * time.Second)

	// Create databases
	fmt.Println("\n[STEP 3/7] Creating databases...")
	if err := createDatabases(); err != nil {
		fmt.Printf("[ERROR] Database creation failed: %v\n", err)
		os.Exit(1)
	}
	fmt.Println("[SUCCESS] Databases created")

	// Create users
	fmt.Println("\n[STEP 4/7] Creating database users...")
	if err := createUsers(); err != nil {
		fmt.Printf("[ERROR] User creation failed: %v\n", err)
		os.Exit(1)
	}
	fmt.Println("[SUCCESS] Database users created")

	// Apply schemas
	fmt.Println("\n[STEP 5/7] Applying database schemas...")
	if err := applySchemas(); err != nil {
		fmt.Printf("[ERROR] Schema application failed: %v\n", err)
		os.Exit(1)
	}
	fmt.Println("[SUCCESS] All schemas applied")

	// Install Node.js
	fmt.Println("\n[STEP 6/7] Installing Node.js...")
	if err := installNodeJS(); err != nil {
		fmt.Printf("[ERROR] Node.js installation failed: %v\n", err)
		os.Exit(1)
	}
	fmt.Println("[SUCCESS] Node.js installed")

	// Install WinPkFilter
	fmt.Println("\n[STEP 7/7] Installing WinPkFilter driver...")
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

func printBanner() {
	fmt.Println("╔═══════════════════════════════════════════════════════════════╗")
	fmt.Println("║       SafeOps Requirements Setup Installer v1.0              ║")
	fmt.Println("╚═══════════════════════════════════════════════════════════════╝")
	fmt.Println()
	fmt.Println("This installer will set up:")
	fmt.Println("  • PostgreSQL 16.1 (with 3 databases)")
	fmt.Println("  • Node.js 20.11.0 (for UI and Backend)")
	fmt.Println("  • WinPkFilter 3.4.8 (packet capture driver)")
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
