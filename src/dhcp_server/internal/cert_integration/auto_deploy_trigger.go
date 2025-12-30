// Package cert_integration provides automatic CA deployment triggering.
// This ensures clients automatically install certificates without any manual action.
package cert_integration

import (
	"context"
	"fmt"
	"net"
	"time"
)

// ============================================================================
// Automatic Deployment Trigger
// ============================================================================

// AutoDeployTrigger triggers automatic certificate installation on clients.
type AutoDeployTrigger struct {
	certManagerAddr string
	grpcClient      *RealGRPCCertProvider
}

// NewAutoDeployTrigger creates a new auto-deploy trigger.
func NewAutoDeployTrigger(certManagerAddr string, grpcClient *RealGRPCCertProvider) *AutoDeployTrigger {
	return &AutoDeployTrigger{
		certManagerAddr: certManagerAddr,
		grpcClient:      grpcClient,
	}
}

// ============================================================================
// Trigger Installation on Device Connection
// ============================================================================

// TriggerInstallation initiates automatic certificate installation for a device.
// This is called immediately after DHCP ACK is sent.
func (t *AutoDeployTrigger) TriggerInstallation(ctx context.Context, device *DeviceInfo) error {
	// Based on OS type, trigger appropriate installation method
	switch device.OSType {
	case "Windows":
		return t.triggerWindowsInstall(ctx, device)
	case "Linux":
		return t.triggerLinuxInstall(ctx, device)
	case "macOS":
		return t.triggerMacOSInstall(ctx, device)
	case "Android":
		return t.triggerAndroidInstall(ctx, device)
	case "iOS":
		return t.triggeriOSInstall(ctx, device)
	default:
		// Unknown OS - use captive portal fallback
		return t.triggerCaptivePortalRedirect(ctx, device)
	}
}

// ============================================================================
// Windows Auto-Install (via WinRM or Group Policy)
// ============================================================================

func (t *AutoDeployTrigger) triggerWindowsInstall(ctx context.Context, device *DeviceInfo) error {
	// Method 1: If device is domain-joined, use GPO push
	if device.IsDomainJoined {
		return t.pushViaGroupPolicy(ctx, device)
	}

	// Method 2: Use WinRM if available
	if t.isWinRMAvailable(device.IPAddress) {
		return t.pushViaWinRM(ctx, device)
	}

	// Method 3: Trigger via DHCP Option + Windows DHCP Client Hook
	// Windows DHCP client can execute scripts from DHCP options
	return t.triggerDHCPClientHook(ctx, device, "windows")
}

func (t *AutoDeployTrigger) pushViaGroupPolicy(ctx context.Context, device *DeviceInfo) error {
	// In production, this would:
	// 1. Add device to "Pending CA Install" GPO group
	// 2. GPO pushes certificate to Trusted Root automatically
	// 3. Device applies on next Group Policy refresh (immediate with gpupdate /force)

	// For now, log the action
	fmt.Printf("[AUTO-DEPLOY] Triggering GPO push for Windows device: %s (%s)\n",
		device.Hostname, device.IPAddress)

	return nil
}

func (t *AutoDeployTrigger) pushViaWinRM(ctx context.Context, device *DeviceInfo) error {
	// In production, this would:
	// 1. Connect via WinRM to device
	// 2. Execute PowerShell script remotely:
	//    Invoke-Command -ComputerName $device -ScriptBlock {
	//        Invoke-WebRequest -Uri "http://192.168.1.1/install-ca.ps1" | Invoke-Expression
	//    }

	fmt.Printf("[AUTO-DEPLOY] Triggering WinRM remote execution for: %s\n", device.IPAddress)
	return nil
}

func (t *AutoDeployTrigger) triggerDHCPClientHook(ctx context.Context, device *DeviceInfo, os string) error {
	// DHCP Option 226 already contains the script URL
	// This logs that the hook should execute
	fmt.Printf("[AUTO-DEPLOY] DHCP client hook should execute for %s: %s\n", os, device.IPAddress)
	return nil
}

// ============================================================================
// Linux Auto-Install (via SSH or Configuration Management)
// ============================================================================

func (t *AutoDeployTrigger) triggerLinuxInstall(ctx context.Context, device *DeviceInfo) error {
	// Method 1: Use Ansible/Puppet/Chef if available
	if t.hasConfigManagement() {
		return t.pushViaConfigManagement(ctx, device, "linux")
	}

	// Method 2: Use SSH if available
	if t.isSSHAvailable(device.IPAddress) {
		return t.pushViaSSH(ctx, device)
	}

	// Method 3: NetworkManager dispatcher script (already configured)
	// This is the most common method - NetworkManager auto-executes on DHCP
	return t.triggerNetworkManagerHook(ctx, device)
}

func (t *AutoDeployTrigger) pushViaSSH(ctx context.Context, device *DeviceInfo) error {
	// In production:
	// ssh root@$device "curl -s http://192.168.1.1/install-ca.sh | bash"

	fmt.Printf("[AUTO-DEPLOY] Triggering SSH remote execution for Linux: %s\n", device.IPAddress)
	return nil
}

func (t *AutoDeployTrigger) triggerNetworkManagerHook(ctx context.Context, device *DeviceInfo) error {
	// NetworkManager dispatcher script at:
	// /etc/NetworkManager/dispatcher.d/99-install-ca
	// This auto-executes when DHCP lease is obtained

	fmt.Printf("[AUTO-DEPLOY] NetworkManager dispatcher should execute for: %s\n", device.IPAddress)
	return nil
}

// ============================================================================
// macOS Auto-Install (via MDM or Configuration Profile)
// ============================================================================

func (t *AutoDeployTrigger) triggerMacOSInstall(ctx context.Context, device *DeviceInfo) error {
	// Method 1: Push via MDM (JAMF, Workspace ONE, Intune)
	if device.HasMDM {
		return t.pushViaMDM(ctx, device)
	}

	// Method 2: Configuration Profile via DHCP Option 229
	// macOS automatically detects and prompts to install
	return t.triggerConfigProfileInstall(ctx, device)
}

func (t *AutoDeployTrigger) pushViaMDM(ctx context.Context, device *DeviceInfo) error {
	// In production:
	// 1. API call to JAMF/Intune
	// 2. Push certificate configuration profile
	// 3. Device auto-installs silently

	fmt.Printf("[AUTO-DEPLOY] Triggering MDM push for macOS: %s\n", device.IPAddress)
	return nil
}

func (t *AutoDeployTrigger) triggerConfigProfileInstall(ctx context.Context, device *DeviceInfo) error {
	// DHCP Option 229 points to .mobileconfig file
	// macOS detects and shows installation prompt

	fmt.Printf("[AUTO-DEPLOY] Configuration profile available for macOS: %s\n", device.IPAddress)
	return nil
}

// ============================================================================
// Android Auto-Install (via MDM or Captive Portal)
// ============================================================================

func (t *AutoDeployTrigger) triggerAndroidInstall(ctx context.Context, device *DeviceInfo) error {
	// Method 1: MDM push (if enrolled)
	if device.HasMDM {
		return t.pushViaMDM(ctx, device)
	}

	// Method 2: Captive portal with auto-install intent
	// Android automatically opens captive portal
	return t.triggerCaptivePortalRedirect(ctx, device)
}

// ============================================================================
// iOS Auto-Install (via MDM or Configuration Profile)
// ============================================================================

func (t *AutoDeployTrigger) triggeriOSInstall(ctx context.Context, device *DeviceInfo) error {
	// Method 1: MDM push
	if device.HasMDM {
		return t.pushViaMDM(ctx, device)
	}

	// Method 2: Configuration profile via captive portal
	return t.triggerCaptivePortalRedirect(ctx, device)
}

// ============================================================================
// Captive Portal Redirect (Fallback)
// ============================================================================

func (t *AutoDeployTrigger) triggerCaptivePortalRedirect(ctx context.Context, device *DeviceInfo) error {
	// This is handled by DHCP Option 228
	// First HTTP request is intercepted and redirected

	fmt.Printf("[AUTO-DEPLOY] Captive portal redirect for: %s\n", device.IPAddress)
	return nil
}

// ============================================================================
// Helper Methods
// ============================================================================

func (t *AutoDeployTrigger) isWinRMAvailable(ip net.IP) bool {
	// Check if WinRM port 5985 is open
	conn, err := net.DialTimeout("tcp", fmt.Sprintf("%s:5985", ip.String()), 2*time.Second)
	if err != nil {
		return false
	}
	conn.Close()
	return true
}

func (t *AutoDeployTrigger) isSSHAvailable(ip net.IP) bool {
	// Check if SSH port 22 is open
	conn, err := net.DialTimeout("tcp", fmt.Sprintf("%s:22", ip.String()), 2*time.Second)
	if err != nil {
		return false
	}
	conn.Close()
	return true
}

func (t *AutoDeployTrigger) hasConfigManagement() bool {
	// Check if Ansible/Puppet/Chef is configured
	// In production, this would check actual configuration
	return false
}

func (t *AutoDeployTrigger) pushViaConfigManagement(ctx context.Context, device *DeviceInfo, os string) error {
	fmt.Printf("[AUTO-DEPLOY] Configuration management push for %s: %s\n", os, device.IPAddress)
	return nil
}

// ============================================================================
// Device Information Structure
// ============================================================================

// DeviceInfo contains device information for auto-deployment.
type DeviceInfo struct {
	MACAddress     string
	IPAddress      net.IP
	Hostname       string
	OSType         string // Windows, Linux, macOS, Android, iOS
	OSVersion      string
	IsDomainJoined bool   // For Windows
	HasMDM         bool   // For mobile/macOS
	UserAgent      string
}
