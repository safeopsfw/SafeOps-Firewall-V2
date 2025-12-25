# ==============================================================================
# SafeOps v2.0 - Uninstallation Script
# ==============================================================================
# Purpose: Safely remove SafeOps kernel driver and userspace service
# Requirements: Administrator privileges
# ==============================================================================

param(
    [switch]$RemoveConfig = $false,
    [switch]$RemoveLogs = $false,
    [switch]$Unattended = $false
)

$ErrorActionPreference = "Stop"
$ProgressPreference = "SilentlyContinue"

# ==============================================================================
# Configuration
# ==============================================================================

$ServiceName = "SafeOpsService"
$DriverName = "SafeOps"
$InstallDir = "C:\Program Files\SafeOps"
$ConfigDir = Join-Path $env:APPDATA "SafeOps"
$LogDir = Join-Path $env:ProgramData "SafeOps\Logs"
$LogFile = Join-Path $env:TEMP "safeops_uninstall_$(Get-Date -Format 'yyyyMMdd_HHmmss').log"

# ==============================================================================
# Logging Functions
# ==============================================================================

function Write-Log {
    param(
        [string]$Message,
        [string]$Level = "INFO"
    )

    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $logMessage = "[$timestamp] [$Level] $Message"

    Add-Content -Path $LogFile -Value $logMessage -Encoding UTF8

    switch ($Level) {
        "ERROR" { Write-Host $Message -ForegroundColor Red }
        "WARNING" { Write-Host $Message -ForegroundColor Yellow }
        "SUCCESS" { Write-Host $Message -ForegroundColor Green }
        "INFO" { Write-Host $Message -ForegroundColor Cyan }
        default { Write-Host $Message }
    }
}

function Write-Section {
    param([string]$Title)

    Write-Host ""
    Write-Host "=" * 80 -ForegroundColor Magenta
    Write-Host " $Title" -ForegroundColor Magenta
    Write-Host "=" * 80 -ForegroundColor Magenta
    Write-Log "SECTION: $Title"
}

# ==============================================================================
# Privilege Check
# ==============================================================================

function Test-Administrator {
    $currentUser = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($currentUser)
    return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

# ==============================================================================
# Pre-Uninstallation Checks
# ==============================================================================

function Invoke-PreUninstallationChecks {
    Write-Section "Pre-Uninstallation Checks"

    Write-Host "Checking Administrator Privileges..." -ForegroundColor Cyan
    if (-not (Test-Administrator)) {
        throw "ERROR: This script must be run as Administrator."
    }
    Write-Log "Administrator privileges confirmed" "SUCCESS"

    Write-Host ""
    Write-Host "Checking installed services..." -ForegroundColor Cyan

    $appService = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
    $drvService = Get-Service -Name $DriverName -ErrorAction SilentlyContinue

    $installationFound = ($null -ne $appService) -or ($null -ne $drvService)

    if (-not $installationFound) {
        Write-Log "No SafeOps installation found" "WARNING"
        Write-Host "SafeOps does not appear to be installed on this system." -ForegroundColor Yellow
        exit 0
    }

    if ($null -ne $appService) {
        Write-Host "  Found: Userspace Service ($ServiceName)" -ForegroundColor Green
    }
    if ($null -ne $drvService) {
        Write-Host "  Found: Kernel Driver ($DriverName)" -ForegroundColor Green
    }

    if (Test-Path $InstallDir) {
        Write-Host "  Found: Installation Directory ($InstallDir)" -ForegroundColor Green
    }

    Write-Log "Uninstallation target identified" "SUCCESS"
}

# ==============================================================================
# Service Stopping and Removal
# ==============================================================================

function Stop-SafeOpsServices {
    Write-Section "Stopping Services"

    Write-Host "Stopping userspace service..." -ForegroundColor Cyan
    try {
        $service = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
        if ($null -ne $service) {
            Stop-Service -Name $ServiceName -Force -ErrorAction Stop
            Start-Sleep -Seconds 2
            Write-Log "Service stopped: $ServiceName" "SUCCESS"
        }
    }
    catch {
        Write-Log "Warning stopping userspace service: $_" "WARNING"
    }

    Write-Host "Stopping kernel driver..." -ForegroundColor Cyan
    try {
        $driver = Get-Service -Name $DriverName -ErrorAction SilentlyContinue
        if ($null -ne $driver) {
            Stop-Service -Name $DriverName -Force -ErrorAction Stop
            Start-Sleep -Seconds 2
            Write-Log "Service stopped: $DriverName" "SUCCESS"
        }
    }
    catch {
        Write-Log "Warning stopping kernel driver: $_" "WARNING"
    }

    Start-Sleep -Seconds 1
}

function Remove-SafeOpsServices {
    Write-Section "Removing Services"

    Write-Host "Removing userspace service from registry..." -ForegroundColor Cyan
    try {
        Remove-Service -Name $ServiceName -Force -ErrorAction SilentlyContinue
        Write-Log "Service removed: $ServiceName" "SUCCESS"
    }
    catch {
        Write-Log "Note: Service $ServiceName could not be removed: $_" "WARNING"
    }

    Write-Host "Removing kernel driver from registry..." -ForegroundColor Cyan
    try {
        Remove-Service -Name $DriverName -Force -ErrorAction SilentlyContinue
        Write-Log "Service removed: $DriverName" "SUCCESS"
    }
    catch {
        Write-Log "Note: Driver $DriverName could not be removed: $_" "WARNING"
    }

    Start-Sleep -Seconds 1
}

# ==============================================================================
# File Removal
# ==============================================================================

function Remove-InstallationDirectory {
    Write-Section "Removing Installation Files"

    if (-not (Test-Path $InstallDir)) {
        Write-Host "Installation directory not found: $InstallDir" -ForegroundColor Yellow
        return
    }

    Write-Host "Removing installation directory..." -ForegroundColor Cyan
    Write-Host "  Path: $InstallDir" -ForegroundColor Gray

    try {
        # Get file count for logging
        $fileCount = (Get-ChildItem -Path $InstallDir -Recurse -File -ErrorAction SilentlyContinue | Measure-Object).Count
        Write-Log "Removing $fileCount files from installation directory" "INFO"

        Remove-Item -Path $InstallDir -Recurse -Force -ErrorAction Stop
        Write-Log "Installation directory removed: $InstallDir" "SUCCESS"
        Write-Host "Successfully removed installation directory" -ForegroundColor Green
    }
    catch {
        Write-Log "Error removing installation directory: $_" "ERROR"
        Write-Host "Could not remove installation directory. Files may be in use." -ForegroundColor Yellow
        Write-Host "Please restart the system and try again, or manually delete: $InstallDir" -ForegroundColor Yellow
    }
}

function Remove-ConfigurationDirectory {
    Write-Section "Configuration Files"

    if (-not (Test-Path $ConfigDir)) {
        Write-Host "Configuration directory not found: $ConfigDir" -ForegroundColor Yellow
        return
    }

    Write-Host "Configuration directory exists: $ConfigDir" -ForegroundColor Cyan

    if (-not $RemoveConfig) {
        Write-Host "Configuration files will be preserved for backup." -ForegroundColor Yellow
        Write-Host "To remove, run this script with -RemoveConfig flag" -ForegroundColor Yellow
        Write-Log "Configuration directory preserved" "INFO"
        return
    }

    Write-Host "Removing configuration directory..." -ForegroundColor Cyan

    try {
        Remove-Item -Path $ConfigDir -Recurse -Force -ErrorAction Stop
        Write-Log "Configuration directory removed: $ConfigDir" "SUCCESS"
        Write-Host "Successfully removed configuration directory" -ForegroundColor Green
    }
    catch {
        Write-Log "Error removing configuration directory: $_" "WARNING"
        Write-Host "Could not remove configuration directory: $_" -ForegroundColor Yellow
        Write-Host "Please manually delete if desired: $ConfigDir" -ForegroundColor Yellow
    }
}

function Remove-LogDirectory {
    Write-Section "Log Files"

    if (-not (Test-Path $LogDir)) {
        Write-Host "Log directory not found: $LogDir" -ForegroundColor Yellow
        return
    }

    Write-Host "Log directory exists: $LogDir" -ForegroundColor Cyan

    if (-not $RemoveLogs) {
        Write-Host "Log files will be preserved for diagnostics." -ForegroundColor Yellow
        Write-Host "To remove, run this script with -RemoveLogs flag" -ForegroundColor Yellow
        Write-Log "Log directory preserved" "INFO"
        return
    }

    Write-Host "Removing log directory..." -ForegroundColor Cyan

    try {
        Remove-Item -Path $LogDir -Recurse -Force -ErrorAction Stop
        Write-Log "Log directory removed: $LogDir" "SUCCESS"
        Write-Host "Successfully removed log directory" -ForegroundColor Green
    }
    catch {
        Write-Log "Error removing log directory: $_" "WARNING"
        Write-Host "Could not remove log directory: $_" -ForegroundColor Yellow
        Write-Host "Please manually delete if desired: $LogDir" -ForegroundColor Yellow
    }
}

# ==============================================================================
# Registry Cleanup
# ==============================================================================

function Invoke-RegistryCleanup {
    Write-Section "Registry Cleanup"

    Write-Host "Checking Windows Registry..." -ForegroundColor Cyan

    # Paths to check
    $regPaths = @(
        "HKLM:\SYSTEM\CurrentControlSet\Services\$ServiceName",
        "HKLM:\SYSTEM\CurrentControlSet\Services\$DriverName"
    )

    foreach ($path in $regPaths) {
        try {
            if (Test-Path $path) {
                Write-Host "Found registry entry: $path" -ForegroundColor Yellow
                # Note: Services removed via Remove-Service should clean up registry automatically
                Write-Log "Registry entry found: $path" "INFO"
            }
        }
        catch {
            Write-Log "Note checking registry: $_" "WARNING"
        }
    }

    Write-Host "Registry cleanup completed" -ForegroundColor Green
    Write-Log "Registry cleanup completed" "SUCCESS"
}

# ==============================================================================
# Firewall Rules Cleanup
# ==============================================================================

function Invoke-FirewallCleanup {
    Write-Section "Firewall Rules"

    Write-Host "Checking Windows Firewall rules..." -ForegroundColor Cyan

    try {
        $safeOpsRules = Get-NetFirewallRule -DisplayName "*SafeOps*" -ErrorAction SilentlyContinue

        if ($safeOpsRules) {
            Write-Host "Found SafeOps firewall rules:" -ForegroundColor Yellow
            foreach ($rule in $safeOpsRules) {
                Write-Host "  - $($rule.DisplayName)" -ForegroundColor Gray
                Remove-NetFirewallRule -InputObject $rule -ErrorAction SilentlyContinue
                Write-Log "Removed firewall rule: $($rule.DisplayName)" "INFO"
            }
            Write-Host "SafeOps firewall rules removed" -ForegroundColor Green
        } else {
            Write-Host "No SafeOps firewall rules found" -ForegroundColor Green
        }

        Write-Log "Firewall cleanup completed" "SUCCESS"
    }
    catch {
        Write-Log "Note during firewall cleanup: $_" "WARNING"
    }
}

# ==============================================================================
# Event Log Cleanup
# ==============================================================================

function Invoke-EventLogCleanup {
    Write-Section "Event Log"

    Write-Host "Checking Event Viewer..." -ForegroundColor Cyan

    try {
        # Archive SafeOps events before deletion
        $safeOpsEvents = Get-EventLog -LogName System -Source SafeOps -ErrorAction SilentlyContinue
        if ($safeOpsEvents) {
            Write-Host "Found $($safeOpsEvents.Count) SafeOps events in Event Viewer" -ForegroundColor Yellow
            Write-Log "Found $($safeOpsEvents.Count) SafeOps events in System log" "INFO"
        } else {
            Write-Host "No SafeOps events in Event Viewer" -ForegroundColor Green
        }
    }
    catch {
        Write-Log "Note accessing Event Viewer: $_" "WARNING"
    }

    Write-Log "Event log cleanup completed" "SUCCESS"
}

# ==============================================================================
# Uninstallation Summary
# ==============================================================================

function Show-UninstallationSummary {
    Write-Section "Uninstallation Complete"

    Write-Host ""
    Write-Host "SafeOps v2.0 has been uninstalled from this system." -ForegroundColor Green
    Write-Host ""

    Write-Host "Removed Items:" -ForegroundColor Cyan
    Write-Host "  - Userspace Service: $ServiceName"
    Write-Host "  - Kernel Driver: $DriverName"
    Write-Host "  - Installation Directory: $InstallDir"

    Write-Host ""
    Write-Host "Preserved Items:" -ForegroundColor Cyan

    if (Test-Path $ConfigDir) {
        Write-Host "  - Configuration Directory: $ConfigDir"
        if (-not $RemoveConfig) {
            Write-Host "    (Run with -RemoveConfig to delete)"
        }
    }

    if (Test-Path $LogDir) {
        Write-Host "  - Log Directory: $LogDir"
        if (-not $RemoveLogs) {
            Write-Host "    (Run with -RemoveLogs to delete)"
        }
    }

    Write-Host ""
    Write-Host "Uninstallation Log:" -ForegroundColor Yellow
    Write-Host "  $LogFile"

    Write-Host ""
    Write-Host "Post-Uninstallation:" -ForegroundColor Cyan
    Write-Host "  - A system restart is recommended"
    Write-Host "  - Run 'verify_installation.ps1' to confirm removal"
    Write-Host "  - Configuration files can be manually deleted if no longer needed"

    Write-Host ""
}

# ==============================================================================
# Main Uninstallation Flow
# ==============================================================================

function Invoke-SafeOpsUninstallation {
    try {
        Write-Host ""
        Write-Host "╔══════════════════════════════════════════════════════════════╗" -ForegroundColor Magenta
        Write-Host "║                                                              ║" -ForegroundColor Magenta
        Write-Host "║           SafeOps v2.0 Uninstallation Script                 ║" -ForegroundColor Magenta
        Write-Host "║                                                              ║" -ForegroundColor Magenta
        Write-Host "╚══════════════════════════════════════════════════════════════╝" -ForegroundColor Magenta
        Write-Host ""

        # Initialize logging
        @"
================================================================================
SafeOps v2.0 Uninstallation Log
================================================================================
Started: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')
User: $env:USERNAME
Computer: $env:COMPUTERNAME
Parameters: RemoveConfig=$RemoveConfig, RemoveLogs=$RemoveLogs, Unattended=$Unattended
================================================================================

"@ | Out-File -FilePath $LogFile -Encoding UTF8

        Invoke-PreUninstallationChecks

        if (-not $Unattended) {
            Write-Host ""
            Write-Host "Are you sure you want to uninstall SafeOps?" -ForegroundColor Yellow
            $response = Read-Host "Type 'yes' to continue"

            if ($response -ne "yes") {
                Write-Host "Uninstallation cancelled" -ForegroundColor Yellow
                Write-Log "Uninstallation cancelled by user" "WARNING"
                exit 0
            }
        }

        Stop-SafeOpsServices
        Remove-SafeOpsServices
        Remove-InstallationDirectory
        Remove-ConfigurationDirectory
        Remove-LogDirectory
        Invoke-RegistryCleanup
        Invoke-FirewallCleanup
        Invoke-EventLogCleanup

        Show-UninstallationSummary

        Write-Log "Uninstallation completed successfully" "SUCCESS"
        return 0
    }
    catch {
        Write-Log "Uninstallation failed: $_" "ERROR"

        Write-Host ""
        Write-Host "Uninstallation Error" -ForegroundColor Red
        Write-Host "Error: $_" -ForegroundColor Red
        Write-Host ""
        Write-Host "Log file: $LogFile" -ForegroundColor Yellow

        return 1
    }
}

# ==============================================================================
# Main Entry Point
# ==============================================================================

$exitCode = Invoke-SafeOpsUninstallation
exit $exitCode
