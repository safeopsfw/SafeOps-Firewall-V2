// Package main provides the entry point for the NIC Management service.
package main

import (
	"bufio"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"time"
)

// =============================================================================
// Uninstall Options
// =============================================================================

// UninstallOptions defines uninstallation behavior options.
type UninstallOptions struct {
	// PreserveConfig keeps configuration files.
	PreserveConfig bool
	// PreserveLogs keeps log files.
	PreserveLogs bool
	// PreserveData keeps database data (always true, manual cleanup required).
	PreserveData bool
	// Force forces uninstall even if service is running.
	Force bool
	// RemoveUser removes service user account (Linux only).
	RemoveUser bool
	// RemoveFirewallRule removes firewall rules.
	RemoveFirewallRule bool
	// Interactive prompts user for confirmation.
	Interactive bool
}

// DefaultUninstallOptions returns the default uninstallation options.
func DefaultUninstallOptions() *UninstallOptions {
	return &UninstallOptions{
		PreserveConfig:     false,
		PreserveLogs:       false,
		PreserveData:       true, // Always preserve database data by default.
		Force:              false,
		RemoveUser:         false,
		RemoveFirewallRule: true,
		Interactive:        true,
	}
}

// =============================================================================
// Main Uninstallation Entry Point
// =============================================================================

// UninstallServiceWithOptions uninstalls the NIC Management service.
func UninstallServiceWithOptions(options *UninstallOptions) error {
	if options == nil {
		options = DefaultUninstallOptions()
	}

	fmt.Println("SafeOps NIC Management Service Uninstaller")
	fmt.Println("===========================================")
	fmt.Printf("Platform: %s/%s\n", runtime.GOOS, runtime.GOARCH)
	fmt.Println()

	// Check privileges.
	if !isRunningAsAdmin() {
		return ErrNotAdmin
	}

	// Check if service exists.
	if !serviceExists() {
		fmt.Println("Service is not installed.")
		return nil
	}

	// Interactive confirmation.
	if options.Interactive {
		if !confirmUninstall(options) {
			fmt.Println("Uninstallation cancelled.")
			return nil
		}
	}

	// Stop service if running.
	fmt.Println("[1/4] Stopping service...")
	if err := stopServiceGracefully(options.Force); err != nil {
		return fmt.Errorf("failed to stop service: %w", err)
	}
	fmt.Println("      Service stopped ✓")

	// Uninstall based on platform.
	fmt.Println("[2/4] Removing service registration...")
	var uninstallErr error
	switch runtime.GOOS {
	case "windows":
		uninstallErr = uninstallWindowsServiceImpl(options)
	case "linux":
		uninstallErr = uninstallLinuxServiceImpl(options)
	default:
		return ErrUnsupportedPlatform
	}

	if uninstallErr != nil {
		return fmt.Errorf("uninstallation failed: %w", uninstallErr)
	}
	fmt.Println("      Service registration removed ✓")

	// Remove files.
	fmt.Println("[3/4] Cleaning up files...")
	cleanupFiles(options)
	fmt.Println("      Files cleaned up ✓")

	// Remove firewall rules.
	fmt.Println("[4/4] Removing firewall rules...")
	if options.RemoveFirewallRule {
		if err := removeFirewallRules(); err != nil {
			fmt.Printf("      Warning: %v\n", err)
		} else {
			fmt.Println("      Firewall rules removed ✓")
		}
	} else {
		fmt.Println("      Skipped (preserve firewall rules)")
	}

	// Print summary.
	fmt.Println()
	printUninstallSummary(options)

	return nil
}

// =============================================================================
// Service Status and Control
// =============================================================================

// serviceExists checks if the service is installed.
func serviceExists() bool {
	switch runtime.GOOS {
	case "windows":
		cmd := exec.Command("sc", "query", "SafeOpsNICManagement")
		return cmd.Run() == nil
	case "linux":
		_, err := os.Stat("/etc/systemd/system/nic-management.service")
		return err == nil
	default:
		return false
	}
}

// stopServiceGracefully stops the service with graceful shutdown.
func stopServiceGracefully(force bool) error {
	timeout := 30 * time.Second

	switch runtime.GOOS {
	case "windows":
		return stopWindowsService(timeout, force)
	case "linux":
		return stopLinuxService(timeout, force)
	default:
		return nil
	}
}

// stopWindowsService stops the Windows service.
func stopWindowsService(timeout time.Duration, force bool) error {
	// Query current status.
	cmd := exec.Command("sc", "query", "SafeOpsNICManagement")
	output, err := cmd.CombinedOutput()
	if err != nil {
		return nil // Service doesn't exist or already stopped.
	}

	// Check if running.
	if !strings.Contains(string(output), "RUNNING") {
		return nil // Already stopped.
	}

	// Send stop command.
	cmd = exec.Command("sc", "stop", "SafeOpsNICManagement")
	if _, err := cmd.CombinedOutput(); err != nil {
		// Ignore error, check status instead.
	}

	// Wait for service to stop.
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		cmd = exec.Command("sc", "query", "SafeOpsNICManagement")
		output, err := cmd.CombinedOutput()
		if err != nil || strings.Contains(string(output), "STOPPED") {
			return nil
		}
		time.Sleep(time.Second)
	}

	// Force kill if requested.
	if force {
		// Use taskkill to force terminate.
		cmd = exec.Command("taskkill", "/F", "/IM", "nic_management.exe")
		cmd.Run()
		time.Sleep(2 * time.Second)
		return nil
	}

	return fmt.Errorf("service did not stop within %v", timeout)
}

// stopLinuxService stops the Linux service.
func stopLinuxService(timeout time.Duration, force bool) error {
	// Check if active.
	cmd := exec.Command("systemctl", "is-active", "nic-management.service")
	if cmd.Run() != nil {
		return nil // Already stopped.
	}

	// Send stop command.
	cmd = exec.Command("systemctl", "stop", "nic-management.service")
	if _, err := cmd.CombinedOutput(); err != nil {
		// Ignore error, check status instead.
	}

	// Wait for service to stop.
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		cmd = exec.Command("systemctl", "is-active", "nic-management.service")
		if cmd.Run() != nil {
			return nil // Stopped.
		}
		time.Sleep(time.Second)
	}

	// Force kill if requested.
	if force {
		cmd = exec.Command("systemctl", "kill", "-s", "SIGKILL", "nic-management.service")
		cmd.Run()
		time.Sleep(2 * time.Second)
		return nil
	}

	return fmt.Errorf("service did not stop within %v", timeout)
}

// =============================================================================
// Windows Uninstallation
// =============================================================================

// uninstallWindowsServiceImpl removes the Windows service.
func uninstallWindowsServiceImpl(_ *UninstallOptions) error {
	// Delete service.
	cmd := exec.Command("sc", "delete", "SafeOpsNICManagement")
	output, err := cmd.CombinedOutput()
	if err != nil {
		// Check if already deleted.
		if strings.Contains(string(output), "DOES_NOT_EXIST") ||
			strings.Contains(string(output), "specified service does not exist") {
			return nil
		}
		return fmt.Errorf("sc delete failed: %s", string(output))
	}

	return nil
}

// =============================================================================
// Linux Uninstallation
// =============================================================================

// uninstallLinuxServiceImpl removes the Linux service.
func uninstallLinuxServiceImpl(options *UninstallOptions) error {
	// Disable service.
	cmd := exec.Command("systemctl", "disable", "nic-management.service")
	cmd.Run() // Ignore error.

	// Remove systemd unit file.
	unitPath := "/etc/systemd/system/nic-management.service"
	if err := os.Remove(unitPath); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("failed to remove systemd unit: %w", err)
	}

	// Reload systemd daemon.
	cmd = exec.Command("systemctl", "daemon-reload")
	cmd.Run()

	// Remove service user if requested.
	if options.RemoveUser {
		removeLinuxUser()
	}

	return nil
}

// removeLinuxUser removes the safeops user if no other services use it.
func removeLinuxUser() {
	// Check if other SafeOps services exist.
	if otherSafeOpsServicesExist() {
		fmt.Println("      Skipping user removal (other SafeOps services detected)")
		return
	}

	// Remove user.
	cmd := exec.Command("userdel", "safeops")
	if output, err := cmd.CombinedOutput(); err != nil {
		fmt.Printf("      Warning: Failed to remove user: %s\n", string(output))
	}
}

// otherSafeOpsServicesExist checks for other SafeOps services.
func otherSafeOpsServicesExist() bool {
	// Check for other SafeOps systemd services.
	matches, err := filepath.Glob("/etc/systemd/system/safeops-*.service")
	if err != nil || len(matches) == 0 {
		return false
	}

	// Exclude nic-management.
	for _, m := range matches {
		if !strings.Contains(m, "nic-management") {
			return true
		}
	}

	return false
}

// =============================================================================
// File Cleanup
// =============================================================================

// cleanupFiles removes configuration and log files.
func cleanupFiles(options *UninstallOptions) {
	switch runtime.GOOS {
	case "windows":
		cleanupWindowsFiles(options)
	case "linux":
		cleanupLinuxFiles(options)
	}
}

// cleanupWindowsFiles removes Windows files.
func cleanupWindowsFiles(options *UninstallOptions) {
	basePath := "C:\\ProgramData\\SafeOps"

	// Remove config.
	if !options.PreserveConfig {
		configPath := filepath.Join(basePath, "nic_management.yaml")
		if err := os.Remove(configPath); err != nil && !os.IsNotExist(err) {
			fmt.Printf("      Warning: Could not remove config: %v\n", err)
		}
	}

	// Remove logs.
	if !options.PreserveLogs {
		logsPath := filepath.Join(basePath, "Logs", "nic_management")
		if err := os.RemoveAll(logsPath); err != nil {
			fmt.Printf("      Warning: Could not remove logs: %v\n", err)
		}
	}

	// Remove binary from standard location.
	binaryPath := "C:\\Program Files\\SafeOps\\nic_management.exe"
	if err := os.Remove(binaryPath); err != nil && !os.IsNotExist(err) {
		// Try alternate location.
		os.Remove(filepath.Join(basePath, "nic_management.exe"))
	}
}

// cleanupLinuxFiles removes Linux files.
func cleanupLinuxFiles(options *UninstallOptions) {
	// Remove config.
	if !options.PreserveConfig {
		configPath := "/etc/safeops/nic_management.yaml"
		if err := os.Remove(configPath); err != nil && !os.IsNotExist(err) {
			fmt.Printf("      Warning: Could not remove config: %v\n", err)
		}

		// Remove config directory if empty.
		removeIfEmpty("/etc/safeops")
	}

	// Remove logs.
	if !options.PreserveLogs {
		logsPath := "/var/log/safeops"
		if err := os.RemoveAll(logsPath); err != nil && !os.IsNotExist(err) {
			fmt.Printf("      Warning: Could not remove logs: %v\n", err)
		}
	}

	// Remove binary.
	binaryPath := "/usr/local/bin/nic_management"
	if err := os.Remove(binaryPath); err != nil && !os.IsNotExist(err) {
		fmt.Printf("      Warning: Could not remove binary: %v\n", err)
	}

	// Remove PID file directory.
	removeIfEmpty("/var/run/safeops")
}

// removeIfEmpty removes a directory if it's empty.
func removeIfEmpty(dir string) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return
	}
	if len(entries) == 0 {
		os.Remove(dir)
	}
}

// =============================================================================
// Firewall Rules Cleanup
// =============================================================================

// removeFirewallRules removes firewall rules.
func removeFirewallRules() error {
	switch runtime.GOOS {
	case "windows":
		return removeWindowsFirewallRuleForUninstall()
	case "linux":
		return removeLinuxFirewallRuleForUninstall()
	default:
		return nil
	}
}

// removeWindowsFirewallRuleForUninstall removes Windows firewall rule.
func removeWindowsFirewallRuleForUninstall() error {
	cmd := exec.Command("netsh", "advfirewall", "firewall", "delete", "rule",
		"name=SafeOps NIC Management")
	output, err := cmd.CombinedOutput()
	if err != nil {
		// Check if rule doesn't exist.
		if strings.Contains(string(output), "No rules match") {
			return nil
		}
		return fmt.Errorf("netsh failed: %s", string(output))
	}
	return nil
}

// removeLinuxFirewallRuleForUninstall removes Linux firewall rule.
func removeLinuxFirewallRuleForUninstall() error {
	port := 50054

	// Try firewalld first.
	cmd := exec.Command("firewall-cmd", "--permanent",
		fmt.Sprintf("--remove-port=%d/tcp", port))
	if cmd.Run() == nil {
		exec.Command("firewall-cmd", "--reload").Run()
		return nil
	}

	// Fall back to iptables.
	cmd = exec.Command("iptables", "-D", "INPUT", "-p", "tcp",
		"--dport", fmt.Sprintf("%d", port), "-j", "ACCEPT")
	cmd.Run() // Ignore error - rule may not exist.

	return nil
}

// =============================================================================
// Interactive Confirmation
// =============================================================================

// confirmUninstall prompts user for confirmation.
func confirmUninstall(options *UninstallOptions) bool {
	fmt.Println("╔════════════════════════════════════════════════════╗")
	fmt.Println("║  WARNING: This will uninstall NIC Management       ║")
	fmt.Println("╚════════════════════════════════════════════════════╝")
	fmt.Println()

	fmt.Println("The following will be REMOVED:")
	fmt.Println("  ✓ Service registration")
	fmt.Println("  ✓ Service binary")
	if !options.PreserveConfig {
		fmt.Println("  ✓ Configuration files")
	}
	if !options.PreserveLogs {
		fmt.Println("  ✓ Log files")
	}
	if options.RemoveFirewallRule {
		fmt.Println("  ✓ Firewall rules")
	}
	if options.RemoveUser {
		fmt.Println("  ✓ Service user account (Linux)")
	}

	fmt.Println()
	fmt.Println("The following will be PRESERVED:")
	fmt.Println("  ⚠ Database data (manual cleanup required)")
	if options.PreserveConfig {
		fmt.Println("  ✓ Configuration files")
	}
	if options.PreserveLogs {
		fmt.Println("  ✓ Log files")
	}

	fmt.Println()
	fmt.Print("Proceed with uninstallation? [y/N]: ")

	reader := bufio.NewReader(os.Stdin)
	input, err := reader.ReadString('\n')
	if err != nil {
		return false
	}

	input = strings.TrimSpace(strings.ToLower(input))
	return input == "y" || input == "yes"
}

// =============================================================================
// Uninstall Summary
// =============================================================================

// printUninstallSummary prints the uninstallation summary.
func printUninstallSummary(options *UninstallOptions) {
	fmt.Println("═══════════════════════════════════════════════════════")
	fmt.Println("✓ NIC Management service uninstalled successfully")
	fmt.Println("═══════════════════════════════════════════════════════")
	fmt.Println()

	fmt.Println("Removed:")
	fmt.Println("  • Service registration")
	fmt.Println("  • Service binary")
	if !options.PreserveConfig {
		fmt.Println("  • Configuration files")
	}
	if !options.PreserveLogs {
		fmt.Println("  • Log files")
	}

	if options.PreserveConfig || options.PreserveLogs || options.PreserveData {
		fmt.Println()
		fmt.Println("Preserved:")
		if options.PreserveConfig {
			switch runtime.GOOS {
			case "windows":
				fmt.Println("  • Configuration: C:\\ProgramData\\SafeOps\\nic_management.yaml")
			case "linux":
				fmt.Println("  • Configuration: /etc/safeops/nic_management.yaml")
			}
		}
		if options.PreserveLogs {
			switch runtime.GOOS {
			case "windows":
				fmt.Println("  • Logs: C:\\ProgramData\\SafeOps\\Logs\\nic_management\\")
			case "linux":
				fmt.Println("  • Logs: /var/log/safeops/")
			}
		}
		if options.PreserveData {
			fmt.Println("  • Database tables (manual cleanup required)")
		}
	}

	fmt.Println()
	fmt.Println("Database Cleanup (manual):")
	fmt.Println("  To remove database tables:")
	fmt.Println("    psql -U postgres -d safeops -c \"DROP SCHEMA IF EXISTS nic_mgmt CASCADE;\"")

	fmt.Println()
	fmt.Println("Reinstallation:")
	switch runtime.GOOS {
	case "windows":
		fmt.Println("  nic_management.exe --install-service")
	case "linux":
		fmt.Println("  sudo ./nic_management --install-service")
	}
}

// =============================================================================
// CLI Entry Point
// =============================================================================

// runServiceUninstall runs the service uninstallation process.
func runServiceUninstall() {
	options := DefaultUninstallOptions()

	// Parse additional flags if needed (simplified for now).
	// In production, you'd use flag package for detailed options.

	if err := UninstallServiceWithOptions(options); err != nil {
		fmt.Printf("Error: %v\n", err)
		os.Exit(1)
	}
}
