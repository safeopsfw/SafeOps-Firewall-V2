package main

import (
	"archive/zip"
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

// Config structures matching config.yaml
type Config struct {
	Installation struct {
		InstallDir string `yaml:"install_dir"`
		TempDir    string `yaml:"temp_dir"`
		DataDir    string `yaml:"data_dir"`
		LogsDir    string `yaml:"logs_dir"`
	} `yaml:"installation"`

	ElkStack struct {
		Elasticsearch struct {
			Version     string `yaml:"version"`
			DownloadURL string `yaml:"download_url"`
			Port        int    `yaml:"port"`
			HeapSize    string `yaml:"heap_size"`
		} `yaml:"elasticsearch"`
		Kibana struct {
			Version     string `yaml:"version"`
			DownloadURL string `yaml:"download_url"`
			Port        int    `yaml:"port"`
		} `yaml:"kibana"`
		Logstash struct {
			Version     string `yaml:"version"`
			DownloadURL string `yaml:"download_url"`
			Port        int    `yaml:"port"`
		} `yaml:"logstash"`
	} `yaml:"elk_stack"`

	Credentials struct {
		ElasticsearchUsername string `yaml:"elasticsearch_username"`
		ElasticsearchPassword string `yaml:"elasticsearch_password"`
		KibanaEncryptionKey   string `yaml:"kibana_encryption_key"`
	} `yaml:"credentials"`

	SafeopsIntegration struct {
		LogSources    []string `yaml:"log_sources"`
		IndexPatterns []string `yaml:"index_patterns"`
	} `yaml:"safeops_integration"`

	WindowsService struct {
		CreateServices       bool   `yaml:"create_services"`
		AutoStart            bool   `yaml:"auto_start"`
		ElasticsearchService string `yaml:"elasticsearch_service"`
		KibanaService        string `yaml:"kibana_service"`
		LogstashService      string `yaml:"logstash_service"`
	} `yaml:"windows_service"`
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

	// Display current configuration and allow modifications
	displayAndModifyConfig()

	// Confirm installation
	if !confirmInstallation() {
		fmt.Println("[INFO] Installation cancelled by user")
		return
	}

	// Create directory structure
	fmt.Println("\n[STEP 1/7] Creating directory structure...")
	if err := createDirectories(); err != nil {
		fmt.Printf("[ERROR] Failed to create directories: %v\n", err)
		os.Exit(1)
	}
	fmt.Println("[SUCCESS] Directories created")

	// Download Elasticsearch
	fmt.Println("\n[STEP 2/7] Downloading Elasticsearch...")
	esZip := filepath.Join(config.Installation.TempDir, "elasticsearch.zip")
	if err := downloadFile(config.ElkStack.Elasticsearch.DownloadURL, esZip); err != nil {
		fmt.Printf("[ERROR] Failed to download Elasticsearch: %v\n", err)
		os.Exit(1)
	}
	fmt.Println("[SUCCESS] Elasticsearch downloaded")

	// Download Kibana
	fmt.Println("\n[STEP 3/7] Downloading Kibana...")
	kibanaZip := filepath.Join(config.Installation.TempDir, "kibana.zip")
	if err := downloadFile(config.ElkStack.Kibana.DownloadURL, kibanaZip); err != nil {
		fmt.Printf("[ERROR] Failed to download Kibana: %v\n", err)
		os.Exit(1)
	}
	fmt.Println("[SUCCESS] Kibana downloaded")

	// Download Logstash
	fmt.Println("\n[STEP 4/7] Downloading Logstash...")
	logstashZip := filepath.Join(config.Installation.TempDir, "logstash.zip")
	if err := downloadFile(config.ElkStack.Logstash.DownloadURL, logstashZip); err != nil {
		fmt.Printf("[ERROR] Failed to download Logstash: %v\n", err)
		os.Exit(1)
	}
	fmt.Println("[SUCCESS] Logstash downloaded")

	// Extract all components
	fmt.Println("\n[STEP 5/7] Extracting ELK Stack components...")
	if err := extractZip(esZip, filepath.Join(config.Installation.InstallDir, "elasticsearch")); err != nil {
		fmt.Printf("[ERROR] Failed to extract Elasticsearch: %v\n", err)
		os.Exit(1)
	}
	if err := extractZip(kibanaZip, filepath.Join(config.Installation.InstallDir, "kibana")); err != nil {
		fmt.Printf("[ERROR] Failed to extract Kibana: %v\n", err)
		os.Exit(1)
	}
	if err := extractZip(logstashZip, filepath.Join(config.Installation.InstallDir, "logstash")); err != nil {
		fmt.Printf("[ERROR] Failed to extract Logstash: %v\n", err)
		os.Exit(1)
	}
	fmt.Println("[SUCCESS] All components extracted")

	// Configure components
	fmt.Println("\n[STEP 6/7] Configuring ELK Stack...")
	if err := configureElasticsearch(); err != nil {
		fmt.Printf("[ERROR] Failed to configure Elasticsearch: %v\n", err)
		os.Exit(1)
	}
	if err := configureKibana(); err != nil {
		fmt.Printf("[ERROR] Failed to configure Kibana: %v\n", err)
		os.Exit(1)
	}
	if err := configureLogstash(); err != nil {
		fmt.Printf("[ERROR] Failed to configure Logstash: %v\n", err)
		os.Exit(1)
	}
	fmt.Println("[SUCCESS] Configuration completed")

	// Setup Windows services
	fmt.Println("\n[STEP 7/7] Setting up Windows services...")
	if config.WindowsService.CreateServices {
		if err := createWindowsServices(); err != nil {
			fmt.Printf("[WARNING] Failed to create Windows services: %v\n", err)
			fmt.Println("[INFO] You can start services manually using the provided scripts")
		} else {
			fmt.Println("[SUCCESS] Windows services created")
		}
	}

	// Cleanup temp files
	fmt.Println("\n[CLEANUP] Removing temporary files...")
	os.RemoveAll(config.Installation.TempDir)

	// Verify installation
	fmt.Println("\n[VERIFICATION] Checking services...")
	verifyInstallation()

	// Installation complete
	printCompletionBanner()
}

func displayAndModifyConfig() {
	fmt.Println("╔═══════════════════════════════════════════════════════════════╗")
	fmt.Println("║                 Current Configuration                         ║")
	fmt.Println("╚═══════════════════════════════════════════════════════════════╝")
	fmt.Println()

	fmt.Println("Installation Settings:")
	fmt.Printf("  [1] Installation Directory: %s\n", config.Installation.InstallDir)
	fmt.Printf("  [2] Data Directory:         %s\n", config.Installation.DataDir)
	fmt.Printf("  [3] Logs Directory:         %s\n", config.Installation.LogsDir)
	fmt.Println()

	fmt.Println("ELK Stack Components:")
	fmt.Printf("  [4] Elasticsearch Version: %s (Port: %d)\n", config.ElkStack.Elasticsearch.Version, config.ElkStack.Elasticsearch.Port)
	fmt.Printf("  [5] Elasticsearch Heap:    %s\n", config.ElkStack.Elasticsearch.HeapSize)
	fmt.Printf("  [6] Kibana Version:        %s (Port: %d)\n", config.ElkStack.Kibana.Version, config.ElkStack.Kibana.Port)
	fmt.Printf("  [7] Logstash Version:      %s (Port: %d)\n", config.ElkStack.Logstash.Version, config.ElkStack.Logstash.Port)
	fmt.Println()

	fmt.Println("Security Credentials:")
	fmt.Printf("  [8] Elasticsearch Username: %s\n", config.Credentials.ElasticsearchUsername)
	fmt.Printf("  [9] Elasticsearch Password: %s\n", maskPassword(config.Credentials.ElasticsearchPassword))
	fmt.Println()

	fmt.Println("Windows Service:")
	fmt.Printf("  [10] Create Windows Services: %t\n", config.WindowsService.CreateServices)
	fmt.Printf("  [11] Auto-start on Boot:     %t\n", config.WindowsService.AutoStart)
	fmt.Println()

	fmt.Print("Do you want to modify any settings? (yes/no): ")
	var response string
	fmt.Scanln(&response)
	response = strings.ToLower(strings.TrimSpace(response))

	if response == "yes" || response == "y" {
		modifyConfiguration()
	}
}

func maskPassword(password string) string {
	if len(password) <= 4 {
		return strings.Repeat("*", len(password))
	}
	return password[:2] + strings.Repeat("*", len(password)-4) + password[len(password)-2:]
}

func modifyConfiguration() {
	fmt.Println("\n╔═══════════════════════════════════════════════════════════════╗")
	fmt.Println("║              Modify Configuration                             ║")
	fmt.Println("╚═══════════════════════════════════════════════════════════════╝")
	fmt.Println()
	fmt.Println("Enter the number of the setting to change (or 0 to finish):")

	for {
		fmt.Print("\nOption number (0 to finish): ")
		var option int
		fmt.Scanln(&option)

		if option == 0 {
			break
		}

		switch option {
		case 1:
			fmt.Print("Enter new installation directory: ")
			var newPath string
			fmt.Scanln(&newPath)
			config.Installation.InstallDir = newPath
			config.Installation.DataDir = filepath.Join(newPath, "data")
			config.Installation.LogsDir = filepath.Join(newPath, "logs")
			config.Installation.TempDir = filepath.Join(newPath, "temp")
			fmt.Println("[✓] Installation directory updated")

		case 2:
			fmt.Print("Enter new data directory: ")
			var newPath string
			fmt.Scanln(&newPath)
			config.Installation.DataDir = newPath
			fmt.Println("[✓] Data directory updated")

		case 3:
			fmt.Print("Enter new logs directory: ")
			var newPath string
			fmt.Scanln(&newPath)
			config.Installation.LogsDir = newPath
			fmt.Println("[✓] Logs directory updated")

		case 4:
			fmt.Printf("Enter Elasticsearch port (current: %d): ", config.ElkStack.Elasticsearch.Port)
			var newPort int
			fmt.Scanln(&newPort)
			if newPort > 0 && newPort < 65536 {
				config.ElkStack.Elasticsearch.Port = newPort
				fmt.Println("[✓] Elasticsearch port updated")
			} else {
				fmt.Println("[✗] Invalid port number")
			}

		case 5:
			fmt.Print("Enter Elasticsearch heap size (e.g., 1g, 2g, 4g): ")
			var newHeap string
			fmt.Scanln(&newHeap)
			config.ElkStack.Elasticsearch.HeapSize = newHeap
			fmt.Println("[✓] Elasticsearch heap size updated")

		case 6:
			fmt.Printf("Enter Kibana port (current: %d): ", config.ElkStack.Kibana.Port)
			var newPort int
			fmt.Scanln(&newPort)
			if newPort > 0 && newPort < 65536 {
				config.ElkStack.Kibana.Port = newPort
				fmt.Println("[✓] Kibana port updated")
			} else {
				fmt.Println("[✗] Invalid port number")
			}

		case 7:
			fmt.Printf("Enter Logstash port (current: %d): ", config.ElkStack.Logstash.Port)
			var newPort int
			fmt.Scanln(&newPort)
			if newPort > 0 && newPort < 65536 {
				config.ElkStack.Logstash.Port = newPort
				fmt.Println("[✓] Logstash port updated")
			} else {
				fmt.Println("[✗] Invalid port number")
			}

		case 8:
			fmt.Print("Enter new Elasticsearch username: ")
			var newUsername string
			fmt.Scanln(&newUsername)
			config.Credentials.ElasticsearchUsername = newUsername
			fmt.Println("[✓] Username updated")

		case 9:
			fmt.Print("Enter new Elasticsearch password: ")
			var newPassword string
			fmt.Scanln(&newPassword)
			if len(newPassword) >= 8 {
				config.Credentials.ElasticsearchPassword = newPassword
				fmt.Println("[✓] Password updated")
			} else {
				fmt.Println("[✗] Password must be at least 8 characters")
			}

		case 10:
			fmt.Print("Create Windows services? (true/false): ")
			var createServices bool
			fmt.Scanln(&createServices)
			config.WindowsService.CreateServices = createServices
			fmt.Println("[✓] Windows service setting updated")

		case 11:
			fmt.Print("Enable auto-start on boot? (true/false): ")
			var autoStart bool
			fmt.Scanln(&autoStart)
			config.WindowsService.AutoStart = autoStart
			fmt.Println("[✓] Auto-start setting updated")

		default:
			fmt.Println("[✗] Invalid option")
		}
	}

	// Display updated configuration
	fmt.Println("\n╔═══════════════════════════════════════════════════════════════╗")
	fmt.Println("║              Updated Configuration                            ║")
	fmt.Println("╚═══════════════════════════════════════════════════════════════╝")
	displayConfigurationSummary()
}

func displayConfigurationSummary() {
	fmt.Println()
	fmt.Printf("  Installation Directory: %s\n", config.Installation.InstallDir)
	fmt.Printf("  Elasticsearch Port:     %d\n", config.ElkStack.Elasticsearch.Port)
	fmt.Printf("  Elasticsearch Heap:     %s\n", config.ElkStack.Elasticsearch.HeapSize)
	fmt.Printf("  Kibana Port:            %d\n", config.ElkStack.Kibana.Port)
	fmt.Printf("  Logstash Port:          %d\n", config.ElkStack.Logstash.Port)
	fmt.Printf("  Username:               %s\n", config.Credentials.ElasticsearchUsername)
	fmt.Printf("  Password:               %s\n", maskPassword(config.Credentials.ElasticsearchPassword))
	fmt.Printf("  Windows Services:       %t\n", config.WindowsService.CreateServices)
	fmt.Printf("  Auto-start:             %t\n", config.WindowsService.AutoStart)
	fmt.Println()
}

func printBanner() {
	fmt.Println("╔═══════════════════════════════════════════════════════════════╗")
	fmt.Println("║       SafeOps SIEM Integration Installer (ELK Stack)         ║")
	fmt.Println("╚═══════════════════════════════════════════════════════════════╝")
	fmt.Println()
	fmt.Println("This installer will set up the ELK Stack for SafeOps:")
	fmt.Println("  • Elasticsearch 8.11.3 - Search and analytics engine")
	fmt.Println("  • Kibana 8.11.3 - Data visualization dashboard")
	fmt.Println("  • Logstash 8.11.3 - Data processing pipeline")
	fmt.Println()
	fmt.Println("Alternative SIEM Options (if you prefer):")
	fmt.Println("  • Wazuh - Security-focused SIEM with better threat detection")
	fmt.Println("  • Graylog - Simpler, lightweight log management")
	fmt.Println("  • Security Onion - Complete security monitoring (requires Linux)")
	fmt.Println()
	fmt.Println("ELK Stack is recommended for SafeOps because:")
	fmt.Println("  ✓ Free and open-source")
	fmt.Println("  ✓ Excellent log aggregation and visualization")
	fmt.Println("  ✓ Powerful query language (KQL)")
	fmt.Println("  ✓ Large community and extensive documentation")
	fmt.Println()
}

func loadConfig() error {
	// Get executable directory
	exePath, err := os.Executable()
	if err != nil {
		return err
	}
	exeDir := filepath.Dir(exePath)

	// Try to load config from same directory as exe
	configPath := filepath.Join(exeDir, "config.yaml")

	// If not found, try src/SIEM directory
	if _, err := os.Stat(configPath); os.IsNotExist(err) {
		configPath = filepath.Join(exeDir, "..", "..", "src", "SIEM", "config.yaml")
	}

	data, err := os.ReadFile(configPath)
	if err != nil {
		return fmt.Errorf("config file not found: %w", err)
	}

	return yaml.Unmarshal(data, &config)
}

func confirmInstallation() bool {
	fmt.Printf("Installation will use approximately 2-3 GB of disk space on D:\\\n")
	fmt.Printf("Installation directory: %s\n\n", config.Installation.InstallDir)
	fmt.Print("Do you want to continue? (yes/no): ")

	var response string
	fmt.Scanln(&response)
	response = strings.ToLower(strings.TrimSpace(response))

	return response == "yes" || response == "y"
}

func createDirectories() error {
	dirs := []string{
		config.Installation.InstallDir,
		config.Installation.TempDir,
		config.Installation.DataDir,
		config.Installation.LogsDir,
		filepath.Join(config.Installation.InstallDir, "elasticsearch"),
		filepath.Join(config.Installation.InstallDir, "kibana"),
		filepath.Join(config.Installation.InstallDir, "logstash"),
		filepath.Join(config.Installation.InstallDir, "scripts"),
	}

	for _, dir := range dirs {
		if err := os.MkdirAll(dir, 0755); err != nil {
			return err
		}
	}

	return nil
}

func downloadFile(url, filepath string) error {
	fmt.Printf("  Downloading from: %s\n", url)
	fmt.Printf("  Saving to: %s\n", filepath)

	// Create the file
	out, err := os.Create(filepath)
	if err != nil {
		return err
	}
	defer out.Close()

	// Download the file
	resp, err := http.Get(url)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("bad status: %s", resp.Status)
	}

	// Create a progress indicator
	size := resp.ContentLength
	fmt.Printf("  File size: %.2f MB\n", float64(size)/1024/1024)

	// Copy with progress
	counter := &WriteCounter{Total: size}
	_, err = io.Copy(out, io.TeeReader(resp.Body, counter))
	fmt.Println()

	return err
}

// WriteCounter counts the number of bytes written to it
type WriteCounter struct {
	Total      int64
	Downloaded int64
}

func (wc *WriteCounter) Write(p []byte) (int, error) {
	n := len(p)
	wc.Downloaded += int64(n)
	wc.printProgress()
	return n, nil
}

func (wc *WriteCounter) printProgress() {
	fmt.Printf("\r  Progress: %.2f MB / %.2f MB (%.0f%%)",
		float64(wc.Downloaded)/1024/1024,
		float64(wc.Total)/1024/1024,
		float64(wc.Downloaded)/float64(wc.Total)*100)
}

func extractZip(src, dest string) error {
	fmt.Printf("  Extracting: %s\n", filepath.Base(src))

	r, err := zip.OpenReader(src)
	if err != nil {
		return err
	}
	defer r.Close()

	for _, f := range r.File {
		fpath := filepath.Join(dest, f.Name)

		if f.FileInfo().IsDir() {
			os.MkdirAll(fpath, os.ModePerm)
			continue
		}

		if err := os.MkdirAll(filepath.Dir(fpath), os.ModePerm); err != nil {
			return err
		}

		outFile, err := os.OpenFile(fpath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, f.Mode())
		if err != nil {
			return err
		}

		rc, err := f.Open()
		if err != nil {
			return err
		}

		_, err = io.Copy(outFile, rc)
		outFile.Close()
		rc.Close()

		if err != nil {
			return err
		}
	}

	return nil
}

func configureElasticsearch() error {
	// Find the actual elasticsearch directory (it includes version in name)
	esDir := filepath.Join(config.Installation.InstallDir, "elasticsearch")
	entries, err := os.ReadDir(esDir)
	if err != nil {
		return err
	}

	var actualESDir string
	for _, entry := range entries {
		if entry.IsDir() && strings.HasPrefix(entry.Name(), "elasticsearch") {
			actualESDir = filepath.Join(esDir, entry.Name())
			break
		}
	}

	if actualESDir == "" {
		return fmt.Errorf("elasticsearch directory not found")
	}

	// Create elasticsearch.yml configuration
	configFile := filepath.Join(actualESDir, "config", "elasticsearch.yml")

	configContent := fmt.Sprintf(`# SafeOps Elasticsearch Configuration
cluster.name: safeops-siem
node.name: safeops-node-1
path.data: %s
path.logs: %s
network.host: 127.0.0.1
http.port: %d
xpack.security.enabled: true
xpack.security.enrollment.enabled: false
`,
		filepath.Join(config.Installation.DataDir, "elasticsearch"),
		filepath.Join(config.Installation.LogsDir, "elasticsearch"),
		config.ElkStack.Elasticsearch.Port)

	return os.WriteFile(configFile, []byte(configContent), 0644)
}

func configureKibana() error {
	// Find the actual kibana directory
	kibanaDir := filepath.Join(config.Installation.InstallDir, "kibana")
	entries, err := os.ReadDir(kibanaDir)
	if err != nil {
		return err
	}

	var actualKibanaDir string
	for _, entry := range entries {
		if entry.IsDir() && strings.HasPrefix(entry.Name(), "kibana") {
			actualKibanaDir = filepath.Join(kibanaDir, entry.Name())
			break
		}
	}

	if actualKibanaDir == "" {
		return fmt.Errorf("kibana directory not found")
	}

	// Create kibana.yml configuration
	configFile := filepath.Join(actualKibanaDir, "config", "kibana.yml")

	configContent := fmt.Sprintf(`# SafeOps Kibana Configuration
server.port: %d
server.host: "127.0.0.1"
server.name: "safeops-kibana"
elasticsearch.hosts: ["http://127.0.0.1:%d"]
elasticsearch.username: "%s"
elasticsearch.password: "%s"
logging.dest: %s
xpack.encryptedSavedObjects.encryptionKey: "%s"
`,
		config.ElkStack.Kibana.Port,
		config.ElkStack.Elasticsearch.Port,
		config.Credentials.ElasticsearchUsername,
		config.Credentials.ElasticsearchPassword,
		filepath.Join(config.Installation.LogsDir, "kibana", "kibana.log"),
		config.Credentials.KibanaEncryptionKey)

	return os.WriteFile(configFile, []byte(configContent), 0644)
}

func configureLogstash() error {
	// Find the actual logstash directory
	logstashDir := filepath.Join(config.Installation.InstallDir, "logstash")
	entries, err := os.ReadDir(logstashDir)
	if err != nil {
		return err
	}

	var actualLogstashDir string
	for _, entry := range entries {
		if entry.IsDir() && strings.HasPrefix(entry.Name(), "logstash") {
			actualLogstashDir = filepath.Join(logstashDir, entry.Name())
			break
		}
	}

	if actualLogstashDir == "" {
		return fmt.Errorf("logstash directory not found")
	}

	// Create logstash pipeline configuration for SafeOps logs
	pipelineDir := filepath.Join(actualLogstashDir, "config", "pipeline")
	os.MkdirAll(pipelineDir, 0755)

	// SafeOps network logs pipeline
	networkPipeline := `input {
  file {
    path => "D:/SafeOpsFV2/bin/logs/netflow/*.log"
    start_position => "beginning"
    sincedb_path => "D:/SafeOps-SIEM-Integration/data/logstash/sincedb_netflow"
    codec => "json"
    tags => ["safeops", "network"]
  }
}

filter {
  if "safeops" in [tags] {
    mutate {
      add_field => { "[@metadata][index]" => "safeops-network" }
    }
  }
}

output {
  elasticsearch {
    hosts => ["http://127.0.0.1:9200"]
    index => "safeops-network-%{+YYYY.MM.dd}"
    user => "elastic"
    password => "SafeOps2026!"
  }
}
`
	pipelineFile := filepath.Join(pipelineDir, "safeops-network.conf")
	return os.WriteFile(pipelineFile, []byte(networkPipeline), 0644)
}

func createWindowsServices() error {
	// Create batch scripts directory
	scriptsDir := filepath.Join(config.Installation.InstallDir, "scripts")
	os.MkdirAll(scriptsDir, 0755)

	// Find actual directories
	esDir := findSubDir(filepath.Join(config.Installation.InstallDir, "elasticsearch"), "elasticsearch")
	kibanaDir := findSubDir(filepath.Join(config.Installation.InstallDir, "kibana"), "kibana")
	logstashDir := findSubDir(filepath.Join(config.Installation.InstallDir, "logstash"), "logstash")

	fmt.Println("  Installing Elasticsearch as Windows service...")

	// Install Elasticsearch service
	esServiceBat := filepath.Join(esDir, "bin", "elasticsearch-service.bat")
	if _, err := os.Stat(esServiceBat); err == nil {
		// Install the service
		cmd := exec.Command(esServiceBat, "install")
		cmd.Dir = filepath.Join(esDir, "bin")
		output, err := cmd.CombinedOutput()
		if err != nil && !strings.Contains(string(output), "already exists") {
			return fmt.Errorf("failed to install Elasticsearch service: %w\nOutput: %s", err, output)
		}
		fmt.Println("  [OK] Elasticsearch service installed")

		// Start the service
		fmt.Println("  Starting Elasticsearch service...")
		cmdStart := exec.Command("net", "start", config.WindowsService.ElasticsearchService)
		outputStart, errStart := cmdStart.CombinedOutput()
		if errStart != nil && !strings.Contains(string(outputStart), "already") {
			fmt.Printf("  [WARN] Failed to start Elasticsearch: %v\n", errStart)
		} else {
			fmt.Println("  [OK] Elasticsearch service started")
		}
	} else {
		return fmt.Errorf("elasticsearch-service.bat not found at: %s", esServiceBat)
	}

	// Wait for Elasticsearch to initialize
	fmt.Println("  Waiting 30 seconds for Elasticsearch to initialize...")
	time.Sleep(30 * time.Second)

	// Create batch scripts for Kibana and Logstash
	// Kibana startup script
	kibanaScript := fmt.Sprintf(`@echo off
echo Starting Kibana...
cd /d "%s"
bin\kibana.bat
`, kibanaDir)
	kibanaScriptPath := filepath.Join(scriptsDir, "start-kibana.bat")
	os.WriteFile(kibanaScriptPath, []byte(kibanaScript), 0644)

	// Logstash startup script
	logstashScript := fmt.Sprintf(`@echo off
echo Starting Logstash...
cd /d "%s"
bin\logstash.bat -f config\logstash.conf
`, logstashDir)
	logstashScriptPath := filepath.Join(scriptsDir, "start-logstash.bat")
	os.WriteFile(logstashScriptPath, []byte(logstashScript), 0644)

	// Start Kibana in background
	fmt.Println("  Starting Kibana...")
	cmdKibana := exec.Command("cmd", "/c", "start", "/min", "cmd", "/c", kibanaScriptPath)
	if err := cmdKibana.Start(); err != nil {
		fmt.Printf("  [WARN] Failed to start Kibana: %v\n", err)
	} else {
		fmt.Println("  [OK] Kibana started")
	}

	// Wait for Kibana
	time.Sleep(10 * time.Second)

	// Start Logstash in background
	fmt.Println("  Starting Logstash...")
	cmdLogstash := exec.Command("cmd", "/c", "start", "/min", "cmd", "/c", logstashScriptPath)
	if err := cmdLogstash.Start(); err != nil {
		fmt.Printf("  [WARN] Failed to start Logstash: %v\n", err)
	} else {
		fmt.Println("  [OK] Logstash started")
	}

	// Create master startup script
	startupScript := fmt.Sprintf(`@echo off
echo Starting SafeOps SIEM Stack...
echo.

echo [1/3] Starting Elasticsearch service...
net start %s
if %%errorlevel%% neq 0 (
    echo Failed to start Elasticsearch service
)
timeout /t 30 /nobreak

echo [2/3] Starting Kibana...
cd /d "%s"
start /min cmd /c bin\kibana.bat
timeout /t 10 /nobreak

echo [3/3] Starting Logstash...
cd /d "%s"
start /min cmd /c bin\logstash.bat -f config\logstash.conf

echo.
echo ========================================
echo SafeOps SIEM Stack Started!
echo ========================================
echo.
echo Elasticsearch: http://localhost:%d
echo Kibana:        http://localhost:%d
echo Logstash:      port %d
echo.
pause
`, config.WindowsService.ElasticsearchService, kibanaDir, logstashDir,
   config.ElkStack.Elasticsearch.Port, config.ElkStack.Kibana.Port, config.ElkStack.Logstash.Port)

	startAllPath := filepath.Join(scriptsDir, "start-all.bat")
	os.WriteFile(startAllPath, []byte(startupScript), 0644)
	fmt.Printf("  [OK] Created startup script: %s\n", startAllPath)

	// Create stop script
	stopScript := fmt.Sprintf(`@echo off
echo Stopping SafeOps SIEM Stack...
echo.

echo [1/3] Stopping Elasticsearch service...
net stop %s

echo [2/3] Stopping Kibana...
taskkill /FI "WINDOWTITLE eq *kibana*" /F

echo [3/3] Stopping Logstash...
taskkill /FI "WINDOWTITLE eq *logstash*" /F

echo.
echo SafeOps SIEM Stack Stopped!
pause
`, config.WindowsService.ElasticsearchService)

	stopAllPath := filepath.Join(scriptsDir, "stop-all.bat")
	os.WriteFile(stopAllPath, []byte(stopScript), 0644)
	fmt.Printf("  [OK] Created stop script: %s\n", stopAllPath)

	// Add to Windows startup if requested
	if config.WindowsService.AutoStart {
		fmt.Println("  Adding to Windows startup...")
		if err := addToStartup(startAllPath); err != nil {
			fmt.Printf("  [WARN] Failed to add to startup: %v\n", err)
		} else {
			fmt.Println("  [OK] Added to Windows startup")
		}
	}

	return nil
}

func findSubDir(baseDir, prefix string) string {
	entries, _ := os.ReadDir(baseDir)
	for _, entry := range entries {
		if entry.IsDir() && strings.HasPrefix(entry.Name(), prefix) {
			return filepath.Join(baseDir, entry.Name())
		}
	}
	return baseDir
}

func addToStartup(scriptPath string) error {
	// Get Windows startup folder
	startupDir := filepath.Join(os.Getenv("APPDATA"), "Microsoft", "Windows", "Start Menu", "Programs", "Startup")

	// Create a shortcut
	shortcutPath := filepath.Join(startupDir, "SafeOps-SIEM.lnk")

	// Use PowerShell to create shortcut
	psScript := fmt.Sprintf(`
$WshShell = New-Object -comObject WScript.Shell
$Shortcut = $WshShell.CreateShortcut("%s")
$Shortcut.TargetPath = "%s"
$Shortcut.Save()
`, shortcutPath, scriptPath)

	cmd := exec.Command("powershell", "-Command", psScript)
	return cmd.Run()
}

func verifyInstallation() {
	// Check Elasticsearch service
	fmt.Print("  Checking Elasticsearch service... ")
	cmd := exec.Command("sc", "query", config.WindowsService.ElasticsearchService)
	output, err := cmd.CombinedOutput()
	if err != nil || !strings.Contains(string(output), "RUNNING") {
		fmt.Println("[NOT RUNNING]")
	} else {
		fmt.Println("[RUNNING]")
	}

	// Check Elasticsearch HTTP endpoint
	fmt.Printf("  Checking Elasticsearch endpoint (localhost:%d)... ", config.ElkStack.Elasticsearch.Port)
	resp, err := http.Get(fmt.Sprintf("http://localhost:%d", config.ElkStack.Elasticsearch.Port))
	if err != nil {
		fmt.Println("[NOT ACCESSIBLE]")
	} else {
		resp.Body.Close()
		fmt.Println("[ACCESSIBLE]")
	}

	// Check Kibana endpoint (might take longer to start)
	fmt.Printf("  Checking Kibana endpoint (localhost:%d)... ", config.ElkStack.Kibana.Port)
	respKibana, errKibana := http.Get(fmt.Sprintf("http://localhost:%d", config.ElkStack.Kibana.Port))
	if errKibana != nil {
		fmt.Println("[NOT ACCESSIBLE - may still be starting]")
	} else {
		respKibana.Body.Close()
		fmt.Println("[ACCESSIBLE]")
	}

	fmt.Println()
	fmt.Println("  Note: Kibana and Logstash may take 1-2 minutes to fully start.")
}

func printCompletionBanner() {
	fmt.Println("\n╔═══════════════════════════════════════════════════════════════╗")
	fmt.Println("║              Installation Complete Successfully!              ║")
	fmt.Println("╚═══════════════════════════════════════════════════════════════╝")
	fmt.Println()
	fmt.Println("Installation Details:")
	fmt.Printf("  Installation Directory: %s\n", config.Installation.InstallDir)
	fmt.Printf("  Data Directory: %s\n", config.Installation.DataDir)
	fmt.Printf("  Logs Directory: %s\n", config.Installation.LogsDir)
	fmt.Println()
	fmt.Println("Access URLs:")
	fmt.Printf("  Elasticsearch: http://localhost:%d\n", config.ElkStack.Elasticsearch.Port)
	fmt.Printf("  Kibana: http://localhost:%d\n", config.ElkStack.Kibana.Port)
	fmt.Println()
	fmt.Println("Default Credentials:")
	fmt.Printf("  Username: %s\n", config.Credentials.ElasticsearchUsername)
	fmt.Printf("  Password: %s\n", config.Credentials.ElasticsearchPassword)
	fmt.Println()
	fmt.Println("IMPORTANT SECURITY NOTE:")
	fmt.Println("  Please change the default password after first login!")
	fmt.Println()
	fmt.Println("Next Steps:")
	fmt.Println("  1. Run the scripts in: " + filepath.Join(config.Installation.InstallDir, "scripts"))
	fmt.Println("  2. Start Elasticsearch: install-elasticsearch-service.bat")
	fmt.Println("  3. Start Kibana: start-kibana.bat")
	fmt.Println("  4. Start Logstash: start-logstash.bat")
	fmt.Println("  5. Access Kibana at http://localhost:5601")
	fmt.Println()

	if config.WindowsService.AutoStart {
		fmt.Println("Windows Startup: Enabled")
		fmt.Println("  SIEM components will start automatically on system boot")
	}

	fmt.Println()
	fmt.Println("For support and documentation, visit SafeOps documentation.")
	fmt.Println()

	// Wait for user to read
	fmt.Print("Press Enter to exit...")
	fmt.Scanln()
}
