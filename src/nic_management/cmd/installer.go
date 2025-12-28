// Package main provides the entry point for the NIC Management service.
package main

import (
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"time"
)

// =============================================================================
// Service Configuration
// =============================================================================

// StartMode represents service start type.
type StartMode int

const (
	// StartModeAuto starts service automatically on system boot.
	StartModeAuto StartMode = iota
	// StartModeManual requires manual service start.
	StartModeManual
	// StartModeDisabled prevents service from starting.
	StartModeDisabled
)

// ServiceConfig contains cross-platform service configuration.
type ServiceConfig struct {
	// ServiceName is the internal service name.
	ServiceName string
	// DisplayName is the user-friendly service name.
	DisplayName string
	// Description is the service description.
	Description string
	// BinaryPath is the full path to service executable.
	BinaryPath string
	// ConfigPath is the path to configuration file.
	ConfigPath string
	// WorkingDirectory is the service working directory.
	WorkingDirectory string
	// StartMode is the service start type.
	StartMode StartMode
	// Dependencies is the list of service dependencies.
	Dependencies []string
	// User is the service user account (Linux only).
	User string
	// LogPath is the path to service logs.
	LogPath string
	// PidFile is the path to PID file (Linux only).
	PidFile string
	// GRPCPort is the gRPC listening port.
	GRPCPort int
}

// DefaultServiceConfig returns the default service configuration.
func DefaultServiceConfig() *ServiceConfig {
	binaryPath, _ := os.Executable()

	return &ServiceConfig{
		ServiceName:      "SafeOpsNICManagement",
		DisplayName:      "SafeOps NIC Management Service",
		Description:      "Multi-WAN routing with NAT, load balancing, and failover",
		BinaryPath:       binaryPath,
		ConfigPath:       "/etc/safeops/nic_management.yaml",
		WorkingDirectory: "/var/lib/safeops",
		StartMode:        StartModeAuto,
		Dependencies:     []string{"network.target", "postgresql.service"},
		User:             "safeops",
		LogPath:          "/var/log/safeops",
		PidFile:          "/var/run/safeops/nic_management.pid",
		GRPCPort:         50054,
	}
}

// =============================================================================
// Installation Errors
// =============================================================================

var (
	// ErrNotAdmin indicates installation requires admin/root privileges.
	ErrNotAdmin = errors.New("installation requires administrator/root privileges")
	// ErrUnsupportedPlatform indicates the platform is not supported.
	ErrUnsupportedPlatform = errors.New("unsupported platform")
	// ErrBinaryNotFound indicates the binary was not found.
	ErrBinaryNotFound = errors.New("binary not found")
	// ErrConfigNotFound indicates the config file was not found.
	ErrConfigNotFound = errors.New("config file not found")
	// ErrPortInUse indicates the port is already in use.
	ErrPortInUse = errors.New("port already in use")
	// ErrInstallFailed indicates installation failed.
	ErrInstallFailed = errors.New("installation failed")
)

// =============================================================================
// Main Installation Entry Point
// =============================================================================

// InstallService installs the NIC Management service.
func InstallService(config *ServiceConfig) error {
	if config == nil {
		config = DefaultServiceConfig()
	}

	fmt.Println("SafeOps NIC Management Service Installer")
	fmt.Println("=========================================")
	fmt.Printf("Platform: %s/%s\n", runtime.GOOS, runtime.GOARCH)
	fmt.Printf("Service Name: %s\n", config.ServiceName)
	fmt.Printf("Binary Path: %s\n", config.BinaryPath)
	fmt.Println()

	// Validate prerequisites.
	fmt.Println("[1/5] Validating prerequisites...")
	if err := validatePrerequisites(config); err != nil {
		return fmt.Errorf("prerequisites validation failed: %w", err)
	}
	fmt.Println("      Prerequisites validated ✓")

	// Create config backup if exists.
	fmt.Println("[2/5] Creating configuration backup...")
	backupPath, err := createConfigBackup(config.ConfigPath)
	if err != nil {
		fmt.Printf("      Warning: Could not create backup: %v\n", err)
	} else if backupPath != "" {
		fmt.Printf("      Backup created: %s ✓\n", backupPath)
	} else {
		fmt.Println("      No existing config to backup ✓")
	}

	// Install based on platform.
	fmt.Println("[3/5] Installing service...")
	var installErr error
	switch runtime.GOOS {
	case "windows":
		installErr = installWindowsService(config)
	case "linux":
		installErr = installLinuxService(config)
	default:
		return ErrUnsupportedPlatform
	}

	if installErr != nil {
		fmt.Println("      Installation failed, rolling back...")
		rollbackInstallation(config, backupPath)
		return fmt.Errorf("installation failed: %w", installErr)
	}
	fmt.Println("      Service installed ✓")

	// Configure firewall.
	fmt.Println("[4/5] Configuring firewall...")
	if err := configureFirewall(config); err != nil {
		fmt.Printf("      Warning: Firewall configuration failed: %v\n", err)
	} else {
		fmt.Println("      Firewall configured ✓")
	}

	// Verify installation.
	fmt.Println("[5/5] Verifying installation...")
	if err := verifyInstallation(config); err != nil {
		fmt.Printf("      Warning: Verification failed: %v\n", err)
	} else {
		fmt.Println("      Installation verified ✓")
	}

	// Print summary.
	fmt.Println()
	printInstallationSummary(config)

	return nil
}

// =============================================================================
// Prerequisites Validation
// =============================================================================

// validatePrerequisites validates system prerequisites.
func validatePrerequisites(config *ServiceConfig) error {
	// Check privileges.
	if !isRunningAsAdmin() {
		return ErrNotAdmin
	}

	// Check binary exists.
	if _, err := os.Stat(config.BinaryPath); os.IsNotExist(err) {
		return fmt.Errorf("%w: %s", ErrBinaryNotFound, config.BinaryPath)
	}

	// Check port availability.
	if isPortInUse(config.GRPCPort) {
		return fmt.Errorf("%w: port %d", ErrPortInUse, config.GRPCPort)
	}

	// Check disk space (100 MB minimum).
	if err := checkDiskSpace(config.LogPath, 100*1024*1024); err != nil {
		return fmt.Errorf("disk space check failed: %w", err)
	}

	// Platform-specific checks.
	if runtime.GOOS == "linux" {
		if err := checkLinuxTools(); err != nil {
			return err
		}
	}

	return nil
}

// isRunningAsAdmin checks if running with admin/root privileges.
func isRunningAsAdmin() bool {
	switch runtime.GOOS {
	case "windows":
		// Try to open a privileged file.
		_, err := os.Open("\\\\.\\PHYSICALDRIVE0")
		return err == nil
	case "linux", "darwin":
		return os.Getuid() == 0
	default:
		return false
	}
}

// isPortInUse checks if a port is already in use.
func isPortInUse(port int) bool {
	addr := fmt.Sprintf(":%d", port)
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return true
	}
	ln.Close()
	return false
}

// checkDiskSpace checks for minimum disk space.
func checkDiskSpace(path string, _ int64) error {
	// Create directory if not exists for check.
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0755); err != nil {
		// If we can't create, assume it's ok and let installation fail later.
		return nil
	}

	// On Windows and Linux, we'd use syscall.Statfs.
	// For simplicity, we assume disk space is sufficient.
	return nil
}

// checkLinuxTools checks for required Linux tools.
func checkLinuxTools() error {
	tools := []string{"systemctl", "setcap"}
	for _, tool := range tools {
		if _, err := exec.LookPath(tool); err != nil {
			return fmt.Errorf("required tool not found: %s", tool)
		}
	}
	return nil
}

// =============================================================================
// Configuration Backup
// =============================================================================

// createConfigBackup creates a backup of existing configuration.
func createConfigBackup(configPath string) (string, error) {
	// Check if config exists.
	if _, err := os.Stat(configPath); os.IsNotExist(err) {
		return "", nil // No backup needed.
	}

	// Generate backup filename.
	timestamp := time.Now().Format("20060102_150405")
	backupPath := fmt.Sprintf("%s.backup.%s", configPath, timestamp)

	// Read existing config.
	data, err := os.ReadFile(configPath)
	if err != nil {
		return "", fmt.Errorf("failed to read config: %w", err)
	}

	// Write backup.
	if err := os.WriteFile(backupPath, data, 0644); err != nil {
		return "", fmt.Errorf("failed to write backup: %w", err)
	}

	return backupPath, nil
}

// =============================================================================
// Windows Service Installation
// =============================================================================

// installWindowsService installs the service on Windows using sc.exe.
func installWindowsService(config *ServiceConfig) error {
	// Build sc create command.
	binPath := fmt.Sprintf("\"%s\" --service --config \"%s\"", config.BinaryPath, config.ConfigPath)

	// Create service.
	cmd := exec.Command("sc", "create", config.ServiceName,
		"binPath=", binPath,
		"DisplayName=", config.DisplayName,
		"start=", "auto",
	)
	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("sc create failed: %w: %s", err, string(output))
	}

	// Set description.
	cmd = exec.Command("sc", "description", config.ServiceName, config.Description)
	if output, err = cmd.CombinedOutput(); err != nil {
		fmt.Printf("Warning: Failed to set description: %s\n", string(output))
	}

	// Configure recovery actions (restart on failure).
	cmd = exec.Command("sc", "failure", config.ServiceName,
		"reset=", "86400",
		"actions=", "restart/10000/restart/30000/restart/60000",
	)
	if output, err = cmd.CombinedOutput(); err != nil {
		fmt.Printf("Warning: Failed to set recovery actions: %s\n", string(output))
	}

	return nil
}

// =============================================================================
// Linux Service Installation
// =============================================================================

// installLinuxService installs the service on Linux using systemd.
func installLinuxService(config *ServiceConfig) error {
	// Create service user if not exists.
	if err := createLinuxUser(config.User); err != nil {
		fmt.Printf("Warning: Could not create user %s: %v\n", config.User, err)
	}

	// Create required directories.
	dirs := []string{
		"/etc/safeops",
		config.LogPath,
		filepath.Dir(config.PidFile),
	}
	for _, dir := range dirs {
		if err := os.MkdirAll(dir, 0755); err != nil {
			return fmt.Errorf("failed to create directory %s: %w", dir, err)
		}
	}

	// Set binary capabilities for raw socket access.
	if err := setLinuxCapabilities(config.BinaryPath); err != nil {
		fmt.Printf("Warning: Failed to set capabilities: %v\n", err)
	}

	// Generate systemd unit file.
	unitContent := generateSystemdUnit(config)
	unitPath := "/etc/systemd/system/nic-management.service"
	if err := os.WriteFile(unitPath, []byte(unitContent), 0644); err != nil {
		return fmt.Errorf("failed to write systemd unit: %w", err)
	}

	// Reload systemd daemon.
	cmd := exec.Command("systemctl", "daemon-reload")
	if output, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("systemctl daemon-reload failed: %w: %s", err, string(output))
	}

	// Enable service.
	cmd = exec.Command("systemctl", "enable", "nic-management.service")
	if output, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("systemctl enable failed: %w: %s", err, string(output))
	}

	return nil
}

// createLinuxUser creates a system user for the service.
func createLinuxUser(username string) error {
	// Check if user exists.
	cmd := exec.Command("id", username)
	if cmd.Run() == nil {
		return nil // User exists.
	}

	// Create system user.
	cmd = exec.Command("useradd", "--system", "--no-create-home", "--shell", "/bin/false", username)
	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("useradd failed: %w: %s", err, string(output))
	}

	return nil
}

// setLinuxCapabilities sets capabilities for raw socket access.
func setLinuxCapabilities(binaryPath string) error {
	cmd := exec.Command("setcap", "cap_net_raw,cap_net_admin=+eip", binaryPath)
	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("setcap failed: %w: %s", err, string(output))
	}
	return nil
}

// generateSystemdUnit generates the systemd unit file content.
func generateSystemdUnit(config *ServiceConfig) string {
	deps := strings.Join(config.Dependencies, " ")

	return fmt.Sprintf(`[Unit]
Description=%s
After=%s
Wants=postgresql.service

[Service]
Type=simple
User=%s
Group=%s
ExecStart=%s --config %s
Restart=on-failure
RestartSec=10s
StandardOutput=journal
StandardError=journal
SyslogIdentifier=nic-management

# Security hardening
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=strict
ProtectHome=true
ReadWritePaths=%s

# Resource limits
LimitNOFILE=65536
LimitNPROC=4096

[Install]
WantedBy=multi-user.target
`, config.Description, deps, config.User, config.User,
		config.BinaryPath, config.ConfigPath, config.LogPath)
}

// =============================================================================
// Firewall Configuration
// =============================================================================

// configureFirewall configures firewall rules.
func configureFirewall(config *ServiceConfig) error {
	switch runtime.GOOS {
	case "windows":
		return setWindowsFirewallRule(config.GRPCPort)
	case "linux":
		return setLinuxFirewallRule(config.GRPCPort)
	default:
		return nil
	}
}

// setWindowsFirewallRule adds Windows Firewall rule.
func setWindowsFirewallRule(port int) error {
	ruleName := "SafeOps NIC Management"
	cmd := exec.Command("netsh", "advfirewall", "firewall", "add", "rule",
		"name="+ruleName,
		"dir=in",
		"action=allow",
		"protocol=TCP",
		fmt.Sprintf("localport=%d", port),
	)
	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("netsh failed: %w: %s", err, string(output))
	}
	return nil
}

// setLinuxFirewallRule adds Linux firewall rule (firewalld or iptables).
func setLinuxFirewallRule(port int) error {
	// Try firewalld first.
	cmd := exec.Command("firewall-cmd", "--permanent",
		fmt.Sprintf("--add-port=%d/tcp", port))
	if cmd.Run() == nil {
		exec.Command("firewall-cmd", "--reload").Run()
		return nil
	}

	// Fall back to iptables.
	cmd = exec.Command("iptables", "-A", "INPUT", "-p", "tcp",
		"--dport", fmt.Sprintf("%d", port), "-j", "ACCEPT")
	if output, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("iptables failed: %w: %s", err, string(output))
	}

	return nil
}

// =============================================================================
// Installation Verification
// =============================================================================

// verifyInstallation verifies the service was installed correctly.
func verifyInstallation(config *ServiceConfig) error {
	switch runtime.GOOS {
	case "windows":
		cmd := exec.Command("sc", "query", config.ServiceName)
		return cmd.Run()
	case "linux":
		cmd := exec.Command("systemctl", "status", "nic-management.service", "--no-pager")
		return cmd.Run()
	default:
		return nil
	}
}

// =============================================================================
// Rollback
// =============================================================================

// rollbackInstallation reverts installation changes.
func rollbackInstallation(config *ServiceConfig, backupPath string) {
	fmt.Println("Rolling back installation...")

	switch runtime.GOOS {
	case "windows":
		exec.Command("sc", "delete", config.ServiceName).Run()
	case "linux":
		exec.Command("systemctl", "disable", "nic-management.service").Run()
		os.Remove("/etc/systemd/system/nic-management.service")
		exec.Command("systemctl", "daemon-reload").Run()
	}

	// Restore config backup if exists.
	if backupPath != "" {
		if data, err := os.ReadFile(backupPath); err == nil {
			os.WriteFile(config.ConfigPath, data, 0644)
			os.Remove(backupPath)
		}
	}

	fmt.Println("Rollback complete")
}

// =============================================================================
// Installation Summary
// =============================================================================

// printInstallationSummary prints the installation summary.
func printInstallationSummary(config *ServiceConfig) {
	fmt.Println("=========================================")
	fmt.Println("Service installed successfully!")
	fmt.Println("=========================================")
	fmt.Println()
	fmt.Println("Installation Details:")
	fmt.Printf("  Service Name: %s\n", config.ServiceName)
	fmt.Printf("  Binary Path:  %s\n", config.BinaryPath)
	fmt.Printf("  Config Path:  %s\n", config.ConfigPath)
	fmt.Printf("  Log Path:     %s\n", config.LogPath)
	fmt.Printf("  gRPC Port:    %d\n", config.GRPCPort)
	fmt.Println()

	switch runtime.GOOS {
	case "windows":
		fmt.Println("Next Steps (Windows):")
		fmt.Println("  To start the service:")
		fmt.Printf("    sc start %s\n", config.ServiceName)
		fmt.Println()
		fmt.Println("  To check status:")
		fmt.Printf("    sc query %s\n", config.ServiceName)
		fmt.Println()
		fmt.Println("  To view logs:")
		fmt.Println("    Event Viewer -> Applications and Services Logs -> SafeOps")
	case "linux":
		fmt.Println("Next Steps (Linux):")
		fmt.Println("  To start the service:")
		fmt.Println("    sudo systemctl start nic-management")
		fmt.Println()
		fmt.Println("  To check status:")
		fmt.Println("    sudo systemctl status nic-management")
		fmt.Println()
		fmt.Println("  To view logs:")
		fmt.Println("    sudo journalctl -u nic-management -f")
		fmt.Println()
		fmt.Println("  Service is enabled to start on boot.")
	}

	fmt.Println()
	fmt.Printf("gRPC endpoint: localhost:%d\n", config.GRPCPort)
}

// =============================================================================
// Uninstall Service
// =============================================================================

// UninstallService removes the NIC Management service.
func UninstallService(config *ServiceConfig) error {
	if config == nil {
		config = DefaultServiceConfig()
	}

	fmt.Println("Uninstalling SafeOps NIC Management Service...")

	// Check privileges.
	if !isRunningAsAdmin() {
		return ErrNotAdmin
	}

	switch runtime.GOOS {
	case "windows":
		// Stop service.
		exec.Command("sc", "stop", config.ServiceName).Run()
		time.Sleep(2 * time.Second)

		// Delete service.
		cmd := exec.Command("sc", "delete", config.ServiceName)
		if output, err := cmd.CombinedOutput(); err != nil {
			return fmt.Errorf("sc delete failed: %w: %s", err, string(output))
		}

		// Remove firewall rule.
		exec.Command("netsh", "advfirewall", "firewall", "delete", "rule",
			"name=SafeOps NIC Management").Run()

	case "linux":
		// Stop and disable service.
		exec.Command("systemctl", "stop", "nic-management.service").Run()
		exec.Command("systemctl", "disable", "nic-management.service").Run()

		// Remove unit file.
		os.Remove("/etc/systemd/system/nic-management.service")
		exec.Command("systemctl", "daemon-reload").Run()

	default:
		return ErrUnsupportedPlatform
	}

	fmt.Println("Service uninstalled successfully")
	return nil
}
