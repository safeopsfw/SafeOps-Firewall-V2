<#
.SYNOPSIS
    Installs SafeOps NIC Management service on Windows
.DESCRIPTION
    Automated installation script for NIC Management service
    - Checks prerequisites (admin, Windows version, Npcap)
    - Installs service via service binary
    - Configures firewall rules
    - Verifies installation
.PARAMETER ConfigPath
    Path to configuration file (default: C:\ProgramData\SafeOps\nic_management.yaml)
.PARAMETER BinaryPath
    Path to service binary (default: current directory\nic_management.exe)
.PARAMETER StartService
    Start service after installation (default: true)
.PARAMETER InstallNpcap
    Automatically install Npcap if not found (default: true)
.PARAMETER SkipFirewall
    Skip firewall rule configuration (default: false)
.EXAMPLE
    .\install_service.ps1
.EXAMPLE
    .\install_service.ps1 -ConfigPath "C:\Custom\config.yaml" -StartService $false
.NOTES
    Author: SafeOps Team
    Requires: PowerShell 5.1+, Administrator privileges
#>

param(
    [string]$ConfigPath = "C:\ProgramData\SafeOps\nic_management.yaml",
    [string]$BinaryPath = ".\nic_management.exe",
    [bool]$StartService = $true,
    [bool]$InstallNpcap = $true,
    [bool]$SkipFirewall = $false
)

# =============================================================================
# Error Handling
# =============================================================================

$ErrorActionPreference = "Stop"

function Write-Success {
    param([string]$Message)
    Write-Host "✓ $Message" -ForegroundColor Green
}

function Write-Info {
    param([string]$Message)
    Write-Host "  $Message" -ForegroundColor Cyan
}

function Write-Step {
    param([string]$Message)
    Write-Host "`n$Message" -ForegroundColor Cyan
}

# =============================================================================
# Section 1: Check Administrator Privileges
# =============================================================================

function Test-AdminPrivileges {
    $currentPrincipal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
    return $currentPrincipal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

if (-not (Test-AdminPrivileges)) {
    Write-Error "This script requires Administrator privileges"
    Write-Host "Right-click PowerShell and select 'Run as Administrator'" -ForegroundColor Yellow
    exit 1
}

Write-Host "`n============================================================" -ForegroundColor Cyan
Write-Host "  SafeOps NIC Management Service - Windows Installer" -ForegroundColor White
Write-Host "============================================================" -ForegroundColor Cyan

# =============================================================================
# Section 2: Check Windows Version
# =============================================================================

Write-Step "[1/8] Checking Windows version..."

$osVersion = [System.Environment]::OSVersion.Version
$minVersion = [Version]"10.0.0.0"

if ($osVersion -lt $minVersion) {
    Write-Error "NIC Management requires Windows 10 or Windows Server 2016 or later"
    Write-Host "Current version: $($osVersion.ToString())" -ForegroundColor Red
    exit 1
}

Write-Success "Windows version check passed: $($osVersion.ToString())"

# =============================================================================
# Section 3: Check Npcap Installation
# =============================================================================

Write-Step "[2/8] Checking Npcap installation..."

function Test-NpcapInstalled {
    $npcapPath = "C:\Windows\System32\Npcap"
    $npcapDriver = "C:\Windows\System32\drivers\npcap.sys"
    
    return (Test-Path $npcapPath) -or (Test-Path $npcapDriver)
}

function Install-Npcap {
    $npcapUrl = "https://npcap.com/dist/npcap-1.79.exe"
    $installerPath = "$env:TEMP\npcap-installer.exe"
    
    try {
        Write-Info "Downloading Npcap from $npcapUrl..."
        [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
        Invoke-WebRequest -Uri $npcapUrl -OutFile $installerPath -UseBasicParsing
        
        Write-Info "Installing Npcap (this may take a minute)..."
        $installArgs = "/S /winpcap_mode=yes /loopback_support=yes /admin_only=no"
        $process = Start-Process -FilePath $installerPath -ArgumentList $installArgs -Wait -NoNewWindow -PassThru
        
        Start-Sleep -Seconds 5
        
        if (Test-NpcapInstalled) {
            Write-Success "Npcap installed successfully"
        }
        else {
            throw "Npcap installation verification failed"
        }
    }
    catch {
        Write-Error "Failed to install Npcap: $_"
        Write-Host "Please install manually from https://npcap.com/" -ForegroundColor Yellow
        exit 1
    }
    finally {
        if (Test-Path $installerPath) {
            Remove-Item $installerPath -Force -ErrorAction SilentlyContinue
        }
    }
}

if (-not (Test-NpcapInstalled)) {
    Write-Warning "Npcap not detected"
    
    if ($InstallNpcap) {
        Install-Npcap
    }
    else {
        Write-Error "Npcap is required for packet capture functionality"
        Write-Host "Download from: https://npcap.com/#download" -ForegroundColor Yellow
        Write-Host "Or run script with -InstallNpcap `$true" -ForegroundColor Yellow
        exit 1
    }
}
else {
    Write-Success "Npcap is installed"
}

# =============================================================================
# Section 4: Check Binary Exists
# =============================================================================

Write-Step "[3/8] Checking service binary..."

if (-not (Test-Path $BinaryPath)) {
    Write-Error "Service binary not found at: $BinaryPath"
    Write-Host "Current directory: $(Get-Location)" -ForegroundColor Yellow
    Write-Host "Please ensure nic_management.exe is in the current directory" -ForegroundColor Yellow
    exit 1
}

$BinaryPath = Resolve-Path $BinaryPath
Write-Success "Service binary found: $BinaryPath"

# =============================================================================
# Section 5: Create Configuration Directory
# =============================================================================

Write-Step "[4/8] Creating directories..."

$configDir = "C:\ProgramData\SafeOps"
$logDir = "C:\ProgramData\SafeOps\Logs\nic_management"

if (-not (Test-Path $configDir)) {
    New-Item -Path $configDir -ItemType Directory -Force | Out-Null
    Write-Success "Created configuration directory: $configDir"
}
else {
    Write-Info "Configuration directory exists: $configDir"
}

if (-not (Test-Path $logDir)) {
    New-Item -Path $logDir -ItemType Directory -Force | Out-Null
    Write-Success "Created log directory: $logDir"
}
else {
    Write-Info "Log directory exists: $logDir"
}

# =============================================================================
# Section 6: Copy Configuration File
# =============================================================================

Write-Step "[5/8] Configuring service..."

$defaultConfigPath = Join-Path (Split-Path $BinaryPath) "nic_management.yaml"

if (Test-Path $ConfigPath) {
    $backupPath = "$ConfigPath.backup.$(Get-Date -Format 'yyyyMMddHHmmss')"
    Copy-Item -Path $ConfigPath -Destination $backupPath
    Write-Success "Existing config backed up to: $backupPath"
}
elseif (Test-Path $defaultConfigPath) {
    Copy-Item -Path $defaultConfigPath -Destination $ConfigPath
    Write-Success "Configuration file copied to: $ConfigPath"
}
else {
    Write-Warning "No default config found at $defaultConfigPath"
    Write-Info "You may need to create configuration manually at: $ConfigPath"
}

# =============================================================================
# Section 7: Install Service via Binary
# =============================================================================

Write-Step "[6/8] Installing service..."

try {
    $installArgs = "--install-service"
    $process = Start-Process -FilePath $BinaryPath -ArgumentList $installArgs -Wait -NoNewWindow -PassThru
    
    if ($process.ExitCode -eq 0) {
        Write-Success "Service installed successfully"
    }
    else {
        throw "Service installation failed with exit code: $($process.ExitCode)"
    }
}
catch {
    Write-Error "Service installation failed: $_"
    exit 1
}

# =============================================================================
# Section 8: Configure Firewall Rule
# =============================================================================

Write-Step "[7/8] Configuring firewall..."

if (-not $SkipFirewall) {
    try {
        $ruleName = "SafeOps NIC Management"
        
        $existingRule = Get-NetFirewallRule -DisplayName $ruleName -ErrorAction SilentlyContinue
        if ($existingRule) {
            Remove-NetFirewallRule -DisplayName $ruleName -ErrorAction SilentlyContinue
        }
        
        New-NetFirewallRule -DisplayName $ruleName `
                            -Direction Inbound `
                            -Action Allow `
                            -Protocol TCP `
                            -LocalPort 50054 `
                            -Profile Any `
                            -Description "Allow gRPC connections to NIC Management service" | Out-Null
        
        Write-Success "Firewall rule created for port 50054"
    }
    catch {
        Write-Warning "Failed to configure firewall: $_"
        Write-Info "You may need to manually allow port 50054"
    }
}
else {
    Write-Info "Firewall configuration skipped"
}

# =============================================================================
# Section 9: Verify Service Installation
# =============================================================================

Write-Step "[8/8] Verifying installation..."

$service = Get-Service -Name "SafeOpsNICManagement" -ErrorAction SilentlyContinue

if ($null -eq $service) {
    Write-Error "Service verification failed - service not found"
    exit 1
}

Write-Success "Service registered: $($service.Name)"
Write-Info "Display Name: $($service.DisplayName)"
Write-Info "Status: $($service.Status)"
Write-Info "Start Type: $($service.StartType)"

# =============================================================================
# Section 10: Start Service (Optional)
# =============================================================================

if ($StartService) {
    Write-Host "`nStarting service..." -ForegroundColor Cyan
    
    try {
        Start-Service -Name "SafeOpsNICManagement"
        Start-Sleep -Seconds 3
        
        $service = Get-Service -Name "SafeOpsNICManagement"
        
        if ($service.Status -eq "Running") {
            Write-Success "Service started successfully"
            
            # Test connectivity
            Start-Sleep -Seconds 2
            $testConnection = Test-NetConnection -ComputerName localhost -Port 50054 -WarningAction SilentlyContinue -ErrorAction SilentlyContinue
            
            if ($testConnection.TcpTestSucceeded) {
                Write-Success "gRPC endpoint accessible on port 50054"
            }
            else {
                Write-Info "gRPC port may still be initializing..."
            }
        }
        else {
            Write-Warning "Service did not start. Status: $($service.Status)"
            Write-Info "Check Event Viewer for errors: eventvwr.msc"
        }
    }
    catch {
        Write-Warning "Failed to start service: $_"
        Write-Info "You can start manually: Start-Service SafeOpsNICManagement"
    }
}
else {
    Write-Info "Service not started (use -StartService `$true to start)"
}

# =============================================================================
# Section 11: Print Installation Summary
# =============================================================================

Write-Host "`n============================================================" -ForegroundColor Green
Write-Host "  NIC Management Service - Installation Complete" -ForegroundColor White
Write-Host "============================================================" -ForegroundColor Green

Write-Host "`nInstallation Details:" -ForegroundColor White
Write-Host "  Service Name:    SafeOpsNICManagement"
Write-Host "  Binary Path:     $BinaryPath"
Write-Host "  Config Path:     $ConfigPath"
Write-Host "  Log Path:        $logDir"
Write-Host "  gRPC Endpoint:   localhost:50054"

Write-Host "`nService Management Commands:" -ForegroundColor White
Write-Host "  Start:    Start-Service SafeOpsNICManagement"
Write-Host "  Stop:     Stop-Service SafeOpsNICManagement"
Write-Host "  Restart:  Restart-Service SafeOpsNICManagement"
Write-Host "  Status:   Get-Service SafeOpsNICManagement"

Write-Host "`nView Logs:" -ForegroundColor White
Write-Host "  Event Viewer: eventvwr.msc -> Windows Logs -> Application"
Write-Host "  Log Files:    $logDir"

Write-Host "`nConfiguration:" -ForegroundColor White
Write-Host "  Edit config:  notepad $ConfigPath"
Write-Host "  After edit:   Restart-Service SafeOpsNICManagement"

Write-Host "`n============================================================" -ForegroundColor Green
