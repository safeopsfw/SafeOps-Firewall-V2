<#
.SYNOPSIS
    Uninstalls SafeOps NIC Management service from Windows
.DESCRIPTION
    Automated uninstallation script for NIC Management service
    - Stops service gracefully
    - Removes service registration
    - Optionally removes configuration and logs
    - Removes firewall rules
.PARAMETER PreserveConfig
    Keep configuration files (default: false)
.PARAMETER PreserveLogs
    Keep log files (default: false)
.PARAMETER Force
    Force service stop if graceful shutdown fails (default: false)
.PARAMETER RemoveFirewallRule
    Remove firewall rule for port 50054 (default: true)
.PARAMETER NonInteractive
    Skip confirmation prompts (default: false)
.EXAMPLE
    .\uninstall_service.ps1
.EXAMPLE
    .\uninstall_service.ps1 -PreserveConfig -PreserveLogs
.EXAMPLE
    .\uninstall_service.ps1 -Force -NonInteractive
.NOTES
    Author: SafeOps Team
    Requires: PowerShell 5.1+, Administrator privileges
#>

param(
    [switch]$PreserveConfig,
    [switch]$PreserveLogs,
    [switch]$Force,
    [bool]$RemoveFirewallRule = $true,
    [switch]$NonInteractive
)

# =============================================================================
# Error Handling
# =============================================================================

$ErrorActionPreference = "Continue"

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
Write-Host "  SafeOps NIC Management Service - Windows Uninstaller" -ForegroundColor White
Write-Host "============================================================" -ForegroundColor Cyan

# =============================================================================
# Section 2: Check Service Exists
# =============================================================================

$service = Get-Service -Name "SafeOpsNICManagement" -ErrorAction SilentlyContinue

if ($null -eq $service) {
    Write-Warning "NIC Management service is not installed"
    exit 0
}

Write-Host "`nFound service: $($service.DisplayName)" -ForegroundColor Cyan
Write-Info "Status: $($service.Status)"
Write-Info "Start Type: $($service.StartType)"

# =============================================================================
# Section 3: Confirmation Prompt (Interactive)
# =============================================================================

if (-not $NonInteractive) {
    Write-Host "`n" -NoNewLine
    Write-Host ("=" * 60) -ForegroundColor Yellow
    Write-Host "  WARNING: This will uninstall NIC Management service" -ForegroundColor Yellow
    Write-Host ("=" * 60) -ForegroundColor Yellow
    
    Write-Host "`nThe following will be REMOVED:" -ForegroundColor White
    Write-Host "  ✓ Service registration"
    Write-Host "  ✓ Service binary"
    if (-not $PreserveConfig) {
        Write-Host "  ✓ Configuration files" -ForegroundColor Red
    }
    if (-not $PreserveLogs) {
        Write-Host "  ✓ Log files" -ForegroundColor Red
    }
    if ($RemoveFirewallRule) {
        Write-Host "  ✓ Firewall rule"
    }
    
    if ($PreserveConfig -or $PreserveLogs) {
        Write-Host "`nThe following will be PRESERVED:" -ForegroundColor White
        if ($PreserveConfig) {
            Write-Host "  • Configuration files" -ForegroundColor Green
        }
        if ($PreserveLogs) {
            Write-Host "  • Log files" -ForegroundColor Green
        }
    }
    
    Write-Host "`nNote: Database data will NOT be removed (manual cleanup required)" -ForegroundColor Gray
    
    $confirmation = Read-Host "`nProceed with uninstallation? [y/N]"
    if ($confirmation -ne 'y' -and $confirmation -ne 'Y') {
        Write-Host "Uninstallation cancelled" -ForegroundColor Yellow
        exit 0
    }
}

# =============================================================================
# Section 4: Stop Service
# =============================================================================

Write-Step "[1/6] Stopping service..."

if ($service.Status -eq "Running") {
    try {
        Stop-Service -Name "SafeOpsNICManagement" -Force:$Force -ErrorAction SilentlyContinue
        
        $timeout = 30
        $elapsed = 0
        
        while ($elapsed -lt $timeout) {
            $svc = Get-Service -Name "SafeOpsNICManagement" -ErrorAction SilentlyContinue
            if ($null -eq $svc -or $svc.Status -eq "Stopped") {
                break
            }
            Start-Sleep -Seconds 1
            $elapsed++
            Write-Progress -Activity "Stopping service" -Status "Waiting... ($elapsed sec)" -PercentComplete (($elapsed / $timeout) * 100)
        }
        
        Write-Progress -Activity "Stopping service" -Completed
        
        $svc = Get-Service -Name "SafeOpsNICManagement" -ErrorAction SilentlyContinue
        
        if ($null -eq $svc -or $svc.Status -eq "Stopped") {
            Write-Success "Service stopped"
        }
        else {
            if ($Force) {
                Write-Warning "Service did not stop gracefully, attempting force kill..."
                $servicePid = (Get-CimInstance Win32_Service | Where-Object { $_.Name -eq "SafeOpsNICManagement" }).ProcessId
                if ($servicePid -and $servicePid -ne 0) {
                    Stop-Process -Id $servicePid -Force -ErrorAction SilentlyContinue
                    Start-Sleep -Seconds 2
                    Write-Success "Service force-stopped"
                }
            }
            else {
                throw "Service did not stop within timeout. Use -Force to kill process."
            }
        }
    }
    catch {
        Write-Warning "Could not stop service: $_"
        if (-not $Force) {
            Write-Host "Try running with -Force parameter" -ForegroundColor Yellow
        }
    }
}
else {
    Write-Success "Service already stopped"
}

# =============================================================================
# Section 5: Remove Service Registration
# =============================================================================

Write-Step "[2/6] Removing service registration..."

try {
    $result = & sc.exe delete "SafeOpsNICManagement" 2>&1
    
    if ($LASTEXITCODE -eq 0) {
        Write-Success "Service registration removed"
    }
    elseif ($result -match "does not exist") {
        Write-Info "Service already removed from registry"
    }
    else {
        Write-Warning "sc.exe delete returned: $result"
    }
}
catch {
    Write-Warning "Failed to remove service: $_"
}

# =============================================================================
# Section 6: Remove Firewall Rule
# =============================================================================

Write-Step "[3/6] Removing firewall rule..."

if ($RemoveFirewallRule) {
    try {
        $ruleName = "SafeOps NIC Management"
        $existingRule = Get-NetFirewallRule -DisplayName $ruleName -ErrorAction SilentlyContinue
        
        if ($existingRule) {
            Remove-NetFirewallRule -DisplayName $ruleName -ErrorAction Stop
            Write-Success "Firewall rule removed"
        }
        else {
            Write-Info "Firewall rule not found (may have been removed manually)"
        }
    }
    catch {
        Write-Warning "Failed to remove firewall rule: $_"
    }
}
else {
    Write-Info "Firewall rule removal skipped"
}

# =============================================================================
# Section 7: Remove Service Binary
# =============================================================================

Write-Step "[4/6] Removing service binary..."

try {
    $binaryPaths = @(
        "C:\Program Files\SafeOps\nic_management.exe",
        "C:\ProgramData\SafeOps\nic_management.exe"
    )
    
    $removed = $false
    foreach ($path in $binaryPaths) {
        if (Test-Path $path) {
            Remove-Item -Path $path -Force -ErrorAction SilentlyContinue
            Write-Success "Binary removed: $path"
            $removed = $true
        }
    }
    
    if (-not $removed) {
        Write-Info "Binary not found in standard locations"
    }
}
catch {
    Write-Warning "Failed to remove binary: $_"
}

# =============================================================================
# Section 8: Remove Configuration Files (Optional)
# =============================================================================

Write-Step "[5/6] Cleaning configuration..."

if (-not $PreserveConfig) {
    $configPath = "C:\ProgramData\SafeOps\nic_management.yaml"
    
    if (Test-Path $configPath) {
        Remove-Item -Path $configPath -Force -ErrorAction SilentlyContinue
        Write-Success "Configuration removed: $configPath"
    }
    else {
        Write-Info "Configuration file not found"
    }
}
else {
    Write-Success "Configuration files preserved"
}

# =============================================================================
# Section 9: Remove Log Files (Optional)
# =============================================================================

Write-Step "[6/6] Cleaning logs..."

if (-not $PreserveLogs) {
    $logDir = "C:\ProgramData\SafeOps\Logs\nic_management"
    
    if (Test-Path $logDir) {
        Remove-Item -Path $logDir -Force -Recurse -ErrorAction SilentlyContinue
        Write-Success "Logs removed: $logDir"
    }
    else {
        Write-Info "Log directory not found"
    }
    
    # Remove parent directories if empty
    $parentLogDir = "C:\ProgramData\SafeOps\Logs"
    if ((Test-Path $parentLogDir) -and ((Get-ChildItem $parentLogDir -Recurse -ErrorAction SilentlyContinue | Measure-Object).Count -eq 0)) {
        Remove-Item -Path $parentLogDir -Force -Recurse -ErrorAction SilentlyContinue
    }
    
    $configDir = "C:\ProgramData\SafeOps"
    if ((Test-Path $configDir) -and ((Get-ChildItem $configDir -Recurse -ErrorAction SilentlyContinue | Measure-Object).Count -eq 0)) {
        Remove-Item -Path $configDir -Force -Recurse -ErrorAction SilentlyContinue
        Write-Info "Empty SafeOps directory removed"
    }
}
else {
    Write-Success "Log files preserved"
}

# =============================================================================
# Section 10: Print Uninstallation Summary
# =============================================================================

Write-Host "`n" -NoNewLine
Write-Host ("=" * 60) -ForegroundColor Green
Write-Host "  NIC Management Service - Uninstallation Complete" -ForegroundColor White
Write-Host ("=" * 60) -ForegroundColor Green

Write-Host "`nRemoved:" -ForegroundColor White
Write-Host "  ✓ Service registration"
Write-Host "  ✓ Service binary"
if (-not $PreserveConfig) {
    Write-Host "  ✓ Configuration files"
}
if (-not $PreserveLogs) {
    Write-Host "  ✓ Log files"
}
if ($RemoveFirewallRule) {
    Write-Host "  ✓ Firewall rule"
}

if ($PreserveConfig -or $PreserveLogs) {
    Write-Host "`nPreserved:" -ForegroundColor Yellow
    if ($PreserveConfig) {
        Write-Host "  • Configuration: C:\ProgramData\SafeOps\nic_management.yaml"
    }
    if ($PreserveLogs) {
        Write-Host "  • Logs: C:\ProgramData\SafeOps\Logs\nic_management\"
    }
}

Write-Host "`nManual Cleanup Required:" -ForegroundColor White
Write-Host "  Database tables still exist in PostgreSQL" -ForegroundColor Gray
Write-Host "  To remove database data, run:" -ForegroundColor Gray
Write-Host '    psql -U postgres -d safeops -c "DROP SCHEMA IF EXISTS nic_mgmt CASCADE;"' -ForegroundColor DarkGray

if ($PreserveConfig) {
    Write-Host "`n  To remove configuration manually:" -ForegroundColor Gray
    Write-Host "    Remove-Item 'C:\ProgramData\SafeOps\nic_management.yaml'" -ForegroundColor DarkGray
}

if ($PreserveLogs) {
    Write-Host "`n  To remove logs manually:" -ForegroundColor Gray
    Write-Host "    Remove-Item 'C:\ProgramData\SafeOps\Logs\nic_management\' -Recurse" -ForegroundColor DarkGray
}

Write-Host "`nTo reinstall:" -ForegroundColor White
Write-Host "  .\install_service.ps1" -ForegroundColor DarkGray

Write-Host "`n" -NoNewLine
Write-Host ("=" * 60) -ForegroundColor Green
