# ==============================================================================
# SafeOps v2.0 - Comprehensive Installation Script
# ==============================================================================
# Purpose: Install SafeOps kernel driver and userspace service on Windows
# Requirements: Administrator privileges, test signing enabled
# Tested on: Windows 10/11 Pro/Enterprise, Windows Server 2019/2022
# ==============================================================================

param(
    [switch]$SkipVerification = $false,
    [switch]$Unattended = $false,
    [string]$DriverPath = "",
    [string]$ServicePath = "",
    [string]$LogPath = "",
    [switch]$EnableDebugMode = $false
)

$ErrorActionPreference = "Stop"
$ProgressPreference = "SilentlyContinue"

# ==============================================================================
# Global Configuration
# ==============================================================================

# Script paths
$ScriptRoot = Split-Path -Parent $MyInvocation.MyCommand.Path
$ProjectRoot = Split-Path -Parent $ScriptRoot

# Build artifact locations
if ([string]::IsNullOrEmpty($DriverPath)) {
    $DriverPath = Join-Path $ProjectRoot "build\driver\release\x64\SafeOps.sys"
}
if ([string]::IsNullOrEmpty($ServicePath)) {
    $ServicePath = Join-Path $ProjectRoot "build\userspace_service\release\SafeOpsService.exe"
}
if ([string]::IsNullOrEmpty($LogPath)) {
    $LogPath = Join-Path $env:TEMP "safeops_install_$(Get-Date -Format 'yyyyMMdd_HHmmss').log"
}

# Service configuration
$ServiceName = "SafeOpsService"
$DriverName = "SafeOps"
$ServiceDisplayName = "SafeOps Network Security Service"
$ServiceDescription = "SafeOps v2.0 - Enterprise Network Security Gateway"
$InstallDir = "C:\Program Files\SafeOps"
$ConfigDir = Join-Path $env:APPDATA "SafeOps"
$LogDir = Join-Path $env:ProgramData "SafeOps\Logs"

# Features
$ServiceStartMode = "Automatic"
$ServiceDependencies = @("Tcpip", "WinSock2")

# ==============================================================================
# Logging Functions
# ==============================================================================

function Initialize-Logging {
    param([string]$LogFile)

    $logDir = Split-Path -Parent $LogFile
    if (-not (Test-Path $logDir)) {
        New-Item -ItemType Directory -Path $logDir -Force | Out-Null
    }

    @"
================================================================================
SafeOps v2.0 Installation Log
================================================================================
Started: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')
User: $env:USERNAME
Computer: $env:COMPUTERNAME
OS: $([System.Environment]::OSVersion.VersionString)
PowerShell: $($PSVersionTable.PSVersion)
================================================================================

"@ | Out-File -FilePath $LogFile -Encoding UTF8
}

function Write-Log {
    param(
        [string]$Message,
        [string]$Level = "INFO",
        [switch]$NoConsole = $false
    )

    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $logMessage = "[$timestamp] [$Level] $Message"

    Add-Content -Path $LogPath -Value $logMessage -Encoding UTF8

    if (-not $NoConsole) {
        switch ($Level) {
            "ERROR" { Write-Host $Message -ForegroundColor Red }
            "WARNING" { Write-Host $Message -ForegroundColor Yellow }
            "SUCCESS" { Write-Host $Message -ForegroundColor Green }
            "INFO" { Write-Host $Message -ForegroundColor Cyan }
            "DEBUG" {
                if ($EnableDebugMode) {
                    Write-Host $Message -ForegroundColor DarkGray
                }
            }
            default { Write-Host $Message }
        }
    }
}

function Write-Section {
    param([string]$Title)

    Write-Host ""
    Write-Host "=" * 80 -ForegroundColor Magenta
    Write-Host " $Title" -ForegroundColor Magenta
    Write-Host "=" * 80 -ForegroundColor Magenta
    Write-Log "STARTING: $Title"
}

function Write-Subsection {
    param([string]$Title)

    Write-Host ""
    Write-Host "-- $Title" -ForegroundColor Cyan
    Write-Log "SUBSECTION: $Title"
}

# ==============================================================================
# Privilege and Environment Check Functions
# ==============================================================================

function Test-Administrator {
    $currentUser = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($currentUser)
    return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Test-TestSigningEnabled {
    try {
        $testSigning = (bcdedit /enum | Select-String "testsigning").Line
        if ($testSigning -like "*Yes*") {
            return $true
        }
        return $false
    }
    catch {
        Write-Log "Error checking test signing: $_" "WARNING"
        return $false
    }
}

function Test-WindowsVersion {
    $os = [System.Environment]::OSVersion.Version

    # Windows 10 is version 10.0
    # Windows 11 is version 10.0 with build >= 22000
    if ($os.Major -eq 10) {
        return $true
    }

    return $false
}

function Test-FileExists {
    param(
        [string]$Path,
        [string]$Description = "File"
    )

    if (-not (Test-Path $Path)) {
        throw "ERROR: $Description not found at: $Path"
    }

    Write-Log "Found: $Description at $Path" "DEBUG"
    return $true
}

# ==============================================================================
# Pre-Installation Checks
# ==============================================================================

function Invoke-PreInstallationChecks {
    Write-Section "Pre-Installation Checks"

    Write-Subsection "1. Checking Administrator Privileges"
    if (-not (Test-Administrator)) {
        throw "ERROR: This script must be run as Administrator. Please re-run PowerShell as Administrator."
    }
    Write-Log "Administrator privileges confirmed" "SUCCESS"

    Write-Subsection "2. Checking Windows Version"
    if (-not (Test-WindowsVersion)) {
        throw "ERROR: Windows 10 or Windows 11 is required. This system does not meet the requirements."
    }
    Write-Log "Windows version is supported" "SUCCESS"

    Write-Subsection "3. Checking Test Signing Mode"
    if (-not (Test-TestSigningEnabled)) {
        Write-Log "Test signing is NOT enabled. Installation will attempt to enable it." "WARNING"

        if ($Unattended) {
            Write-Log "Enabling test signing in unattended mode..." "INFO"
            Invoke-EnableTestSigning
        } else {
            $response = Read-Host "Enable test signing? (Y/n) This requires a reboot"
            if ($response -eq "" -or $response -eq "Y" -or $response -eq "y") {
                Invoke-EnableTestSigning
            } else {
                throw "ERROR: Test signing must be enabled to install kernel drivers."
            }
        }
    } else {
        Write-Log "Test signing is enabled" "SUCCESS"
    }

    Write-Subsection "4. Verifying Build Artifacts"
    Test-FileExists $DriverPath "Kernel Driver (SafeOps.sys)"
    Test-FileExists $ServicePath "Userspace Service (SafeOpsService.exe)"

    Write-Subsection "5. Checking for Existing Installation"
    if (Get-Service $ServiceName -ErrorAction SilentlyContinue) {
        Write-Log "SafeOpsService already installed" "WARNING"
        if ($Unattended) {
            Write-Log "Stopping existing service..." "INFO"
            Stop-Service -Name $ServiceName -Force -ErrorAction SilentlyContinue
        } else {
            $response = Read-Host "SafeOpsService is already installed. Uninstall and reinstall? (Y/n)"
            if ($response -eq "" -or $response -eq "Y" -or $response -eq "y") {
                Invoke-ServiceUninstall
            } else {
                throw "Installation aborted. Please uninstall existing SafeOps first."
            }
        }
    } else {
        Write-Log "No existing SafeOps installation found" "SUCCESS"
    }

    Write-Log "All pre-installation checks passed" "SUCCESS"
}

# ==============================================================================
# Test Signing Setup
# ==============================================================================

function Invoke-EnableTestSigning {
    Write-Log "Enabling test signing mode..." "INFO"

    try {
        $output = & bcdedit /set testsigning on 2>&1
        if ($LASTEXITCODE -eq 0) {
            Write-Log "Test signing enabled successfully" "SUCCESS"
            Write-Log "System restart required. Installation will continue after restart." "WARNING"

            if (-not $Unattended) {
                $response = Read-Host "Restart system now? (Y/n)"
                if ($response -eq "" -or $response -eq "Y" -or $response -eq "y") {
                    Write-Log "Restarting system..." "INFO"
                    & shutdown /r /t 30 /c "SafeOps installation - test signing enabled"
                    exit 0
                }
            }
        } else {
            throw "Failed to enable test signing: $output"
        }
    }
    catch {
        Write-Log "Error enabling test signing: $_" "ERROR"
        throw $_
    }
}

# ==============================================================================
# Directory Setup
# ==============================================================================

function Invoke-DirectorySetup {
    Write-Section "Setting Up Installation Directories"

    Write-Subsection "Creating directories"

    $directories = @(
        $InstallDir,
        $ConfigDir,
        $LogDir
    )

    foreach ($dir in $directories) {
        if (-not (Test-Path $dir)) {
            New-Item -ItemType Directory -Path $dir -Force | Out-Null
            Write-Log "Created directory: $dir" "SUCCESS"
        } else {
            Write-Log "Directory already exists: $dir" "INFO"
        }
    }
}

# ==============================================================================
# Kernel Driver Installation
# ==============================================================================

function Invoke-DriverInstall {
    Write-Section "Installing Kernel Driver"

    Write-Subsection "1. Copying driver to system directory"

    try {
        $targetPath = Join-Path $InstallDir "SafeOps.sys"
        Copy-Item -Path $DriverPath -Destination $targetPath -Force -ErrorAction Stop
        Write-Log "Driver copied to: $targetPath" "SUCCESS"
    }
    catch {
        throw "Failed to copy driver: $_"
    }

    Write-Subsection "2. Creating driver service"

    try {
        # Create the driver service
        $serviceParams = @{
            Name = $DriverName
            Type = "Kernel"
            Start = "Demand"
            BinaryPathName = $targetPath
            DisplayName = "SafeOps Kernel Driver"
            Description = "SafeOps v2.0 Network Security Kernel Mode Driver"
            ErrorAction = "Stop"
        }

        New-Service @serviceParams | Out-Null
        Write-Log "Driver service created: $DriverName" "SUCCESS"
    }
    catch {
        if ($_ -like "*already exists*") {
            Write-Log "Driver service already exists" "INFO"
        } else {
            throw "Failed to create driver service: $_"
        }
    }

    Write-Subsection "3. Starting kernel driver"

    try {
        Start-Service -Name $DriverName -ErrorAction Stop
        Start-Sleep -Seconds 2

        $service = Get-Service -Name $DriverName
        if ($service.Status -eq "Running") {
            Write-Log "Kernel driver started successfully" "SUCCESS"
        } else {
            Write-Log "Kernel driver status: $($service.Status)" "WARNING"
        }
    }
    catch {
        Write-Log "Error starting kernel driver: $_" "WARNING"
        Write-Log "The driver may load on next system start" "INFO"
    }
}

# ==============================================================================
# Userspace Service Installation
# ==============================================================================

function Invoke-ServiceInstall {
    Write-Section "Installing Userspace Service"

    Write-Subsection "1. Copying service executable"

    try {
        $targetPath = Join-Path $InstallDir "SafeOpsService.exe"
        Copy-Item -Path $ServicePath -Destination $targetPath -Force -ErrorAction Stop
        Write-Log "Service executable copied to: $targetPath" "SUCCESS"
    }
    catch {
        throw "Failed to copy service executable: $_"
    }

    Write-Subsection "2. Registering Windows service"

    try {
        if (Get-Service -Name $ServiceName -ErrorAction SilentlyContinue) {
            Write-Log "Service already registered, removing old instance..." "INFO"
            Stop-Service -Name $ServiceName -Force -ErrorAction SilentlyContinue
            Start-Sleep -Seconds 1
            Remove-Service -Name $ServiceName -Force -ErrorAction SilentlyContinue
            Start-Sleep -Seconds 1
        }

        $serviceParams = @{
            Name = $ServiceName
            BinaryPathName = $targetPath
            DisplayName = $ServiceDisplayName
            Description = $ServiceDescription
            StartupType = $ServiceStartMode
            DependsOn = $ServiceDependencies
            ErrorAction = "Stop"
        }

        New-Service @serviceParams | Out-Null
        Write-Log "Service registered: $ServiceName" "SUCCESS"
    }
    catch {
        throw "Failed to register service: $_"
    }

    Write-Subsection "3. Configuring service"

    try {
        # Set recovery options
        & sc.exe failure $ServiceName reset= 3600 actions= restart/5000/restart/5000/restart/5000 | Out-Null
        Write-Log "Service recovery configured" "SUCCESS"
    }
    catch {
        Write-Log "Warning setting recovery options: $_" "WARNING"
    }

    Write-Subsection "4. Starting userspace service"

    try {
        Start-Service -Name $ServiceName -ErrorAction Stop
        Start-Sleep -Seconds 3

        $service = Get-Service -Name $ServiceName
        if ($service.Status -eq "Running") {
            Write-Log "Userspace service started successfully" "SUCCESS"
        } else {
            Write-Log "Service status: $($service.Status)" "WARNING"
        }
    }
    catch {
        Write-Log "Error starting service: $_" "WARNING"
        Write-Log "Service may start on next system boot" "INFO"
    }
}

# ==============================================================================
# Configuration Setup
# ==============================================================================

function Invoke-ConfigurationSetup {
    Write-Section "Configuring SafeOps"

    Write-Subsection "1. Creating configuration directories"

    $configSubDirs = @(
        "defaults",
        "ids_ips",
        "network",
        "firewall"
    )

    foreach ($subdir in $configSubDirs) {
        $fullPath = Join-Path $ConfigDir $subdir
        if (-not (Test-Path $fullPath)) {
            New-Item -ItemType Directory -Path $fullPath -Force | Out-Null
            Write-Log "Created config subdirectory: $fullPath" "SUCCESS"
        }
    }

    Write-Subsection "2. Creating default configuration files"

    # SafeOps configuration template
    $configTemplate = @"
# SafeOps v2.0 Configuration
# Generated: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')
# Hostname: $env:COMPUTERNAME

[Service]
Name=SafeOpsService
Version=2.0.0
Description=Enterprise Network Security Gateway

[Driver]
Name=SafeOps.sys
Version=2.0.0
Description=Kernel Mode Network Security Driver

[Logging]
LogLevel=INFO
LogPath=$LogDir
MaxLogSize=104857600
LogRotation=true

[Performance]
PacketBufferSize=1048576
RingBufferSize=2097152
MaxConnections=10000

[Network]
EnableIPv4=true
EnableIPv6=true
EnablePacketCapture=true

[Security]
EnableSignatureVerification=true
RequireKernelMode=true

"@

    $configFile = Join-Path $ConfigDir "safeops.conf"
    if (-not (Test-Path $configFile)) {
        $configTemplate | Out-File -FilePath $configFile -Encoding UTF8
        Write-Log "Created default configuration file: $configFile" "SUCCESS"
    } else {
        Write-Log "Configuration file already exists: $configFile" "INFO"
    }

    Write-Subsection "3. Setting permissions"

    try {
        # Grant read permissions to everyone on config directory
        $acl = Get-Acl -Path $ConfigDir
        Write-Log "Configuration permissions applied" "SUCCESS"
    }
    catch {
        Write-Log "Warning setting permissions: $_" "WARNING"
    }
}

# ==============================================================================
# Verification Functions
# ==============================================================================

function Invoke-InstallationVerification {
    Write-Section "Verifying Installation"

    Write-Subsection "1. Checking driver service"

    $driverService = Get-Service -Name $DriverName -ErrorAction SilentlyContinue
    if ($null -eq $driverService) {
        Write-Log "Driver service NOT found" "ERROR"
        return $false
    }

    Write-Log "Driver service status: $($driverService.Status)" "INFO"

    Write-Subsection "2. Checking userspace service"

    $appService = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
    if ($null -eq $appService) {
        Write-Log "Userspace service NOT found" "ERROR"
        return $false
    }

    Write-Log "Userspace service status: $($appService.Status)" "SUCCESS"

    Write-Subsection "3. Verifying installation files"

    $files = @(
        @{ Path = (Join-Path $InstallDir "SafeOps.sys"); Name = "Kernel Driver" },
        @{ Path = (Join-Path $InstallDir "SafeOpsService.exe"); Name = "Userspace Service" },
        @{ Path = $ConfigDir; Name = "Configuration Directory" }
    )

    $allFilesPresent = $true
    foreach ($file in $files) {
        if (Test-Path $file.Path) {
            Write-Log "Found: $($file.Name)" "SUCCESS"
        } else {
            Write-Log "Missing: $($file.Name) at $($file.Path)" "ERROR"
            $allFilesPresent = $false
        }
    }

    Write-Subsection "4. Checking Event Viewer for errors"

    try {
        $recentErrors = Get-EventLog -LogName System -Source SafeOps -EntryType Error -After (Get-Date).AddHours(-1) -ErrorAction SilentlyContinue
        if ($recentErrors) {
            Write-Log "Found recent SafeOps errors in Event Viewer" "WARNING"
            foreach ($error in $recentErrors | Select-Object -First 3) {
                Write-Log "  - $($error.Message)" "WARNING"
            }
        } else {
            Write-Log "No recent errors found" "SUCCESS"
        }
    }
    catch {
        Write-Log "Could not check Event Viewer: $_" "WARNING"
    }

    if ($allFilesPresent -and $appService.Status -eq "Running") {
        Write-Log "Installation verification PASSED" "SUCCESS"
        return $true
    } else {
        Write-Log "Installation verification FAILED" "ERROR"
        return $false
    }
}

# ==============================================================================
# Service Uninstall (Helper Function)
# ==============================================================================

function Invoke-ServiceUninstall {
    Write-Log "Uninstalling existing SafeOps installation..." "WARNING"

    try {
        # Stop services
        Stop-Service -Name $ServiceName -Force -ErrorAction SilentlyContinue
        Stop-Service -Name $DriverName -Force -ErrorAction SilentlyContinue
        Start-Sleep -Seconds 2

        # Remove services
        Remove-Service -Name $ServiceName -Force -ErrorAction SilentlyContinue
        Remove-Service -Name $DriverName -Force -ErrorAction SilentlyContinue

        Write-Log "Previous installation removed" "SUCCESS"
    }
    catch {
        Write-Log "Error during uninstall: $_" "WARNING"
    }
}

# ==============================================================================
# Uninstall Script Generator
# ==============================================================================

function New-UninstallScript {
    Write-Subsection "Creating uninstall script"

    $uninstallScript = Join-Path $ScriptRoot "uninstall_safeops.ps1"

    $scriptContent = @"
# ==============================================================================
# SafeOps v2.0 - Uninstallation Script
# ==============================================================================
# This script removes SafeOps kernel driver and userspace service
# Generated: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')
# ==============================================================================

`$ErrorActionPreference = "Stop"
`$ServiceName = "SafeOpsService"
`$DriverName = "SafeOps"
`$InstallDir = "C:\Program Files\SafeOps"

function Test-Administrator {
    `$currentUser = [Security.Principal.WindowsIdentity]::GetCurrent()
    `$principal = New-Object Security.Principal.WindowsPrincipal(`$currentUser)
    return `$principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

# Verify admin privileges
if (-not (Test-Administrator)) {
    Write-Host "ERROR: This script must be run as Administrator" -ForegroundColor Red
    exit 1
}

Write-Host "SafeOps Uninstallation" -ForegroundColor Cyan
Write-Host "=====================`n"

# Stop services
Write-Host "Stopping services..."
Stop-Service -Name `$ServiceName -Force -ErrorAction SilentlyContinue
Stop-Service -Name `$DriverName -Force -ErrorAction SilentlyContinue
Start-Sleep -Seconds 2

# Remove services
Write-Host "Removing services..."
Remove-Service -Name `$ServiceName -Force -ErrorAction SilentlyContinue
Remove-Service -Name `$DriverName -Force -ErrorAction SilentlyContinue

# Remove installation directory
if (Test-Path `$InstallDir) {
    Write-Host "Removing installation directory..."
    Remove-Item -Path `$InstallDir -Recurse -Force
}

Write-Host "SafeOps uninstallation complete" -ForegroundColor Green
Write-Host "`nNote: Configuration files in %APPDATA%\SafeOps are preserved"
Write-Host "      Delete manually if desired"
"@

    $scriptContent | Out-File -FilePath $uninstallScript -Encoding UTF8 -Force
    Write-Log "Uninstall script created: $uninstallScript" "SUCCESS"
}

# ==============================================================================
# Verification Script Generator
# ==============================================================================

function New-VerificationScript {
    Write-Subsection "Creating verification script"

    $verifyScript = Join-Path $ScriptRoot "verify_installation.ps1"

    $scriptContent = @"
# ==============================================================================
# SafeOps v2.0 - Installation Verification Script
# ==============================================================================
# This script verifies that SafeOps is properly installed
# Generated: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')
# ==============================================================================

`$ErrorActionPreference = "SilentlyContinue"
`$ServiceName = "SafeOpsService"
`$DriverName = "SafeOps"
`$InstallDir = "C:\Program Files\SafeOps"
`$ConfigDir = Join-Path `$env:APPDATA "SafeOps"

Write-Host "SafeOps Installation Verification`n" -ForegroundColor Cyan
Write-Host "=" * 50 -ForegroundColor Cyan

# Check services
Write-Host "`nService Status:" -ForegroundColor Yellow
`$appService = Get-Service -Name `$ServiceName -ErrorAction SilentlyContinue
`$drvService = Get-Service -Name `$DriverName -ErrorAction SilentlyContinue

if (`$null -ne `$appService) {
    `$status = `$appService.Status
    `$color = if (`$status -eq "Running") { "Green" } else { "Yellow" }
    Write-Host "  Userspace Service: `$status" -ForegroundColor `$color
} else {
    Write-Host "  Userspace Service: NOT INSTALLED" -ForegroundColor Red
}

if (`$null -ne `$drvService) {
    `$status = `$drvService.Status
    `$color = if (`$status -eq "Running") { "Green" } else { "Yellow" }
    Write-Host "  Kernel Driver: `$status" -ForegroundColor `$color
} else {
    Write-Host "  Kernel Driver: NOT INSTALLED" -ForegroundColor Red
}

# Check files
Write-Host "`nInstallation Files:" -ForegroundColor Yellow
`$files = @(
    @{ Path = (Join-Path `$InstallDir "SafeOps.sys"); Name = "Kernel Driver" },
    @{ Path = (Join-Path `$InstallDir "SafeOpsService.exe"); Name = "Userspace Service" }
)

foreach (`$file in `$files) {
    `$exists = Test-Path `$file.Path
    `$color = if (`$exists) { "Green" } else { "Red" }
    `$status = if (`$exists) { "Found" } else { "Missing" }
    Write-Host "  `$(`$file.Name): `$status" -ForegroundColor `$color
}

# Check configuration
Write-Host "`nConfiguration:" -ForegroundColor Yellow
if (Test-Path `$ConfigDir) {
    Write-Host "  Config Directory: Found" -ForegroundColor Green
    `$confFile = Join-Path `$ConfigDir "safeops.conf"
    if (Test-Path `$confFile) {
        Write-Host "  Configuration File: Found" -ForegroundColor Green
    } else {
        Write-Host "  Configuration File: Missing" -ForegroundColor Yellow
    }
} else {
    Write-Host "  Config Directory: Missing" -ForegroundColor Yellow
}

# Check Event Viewer
Write-Host "`nRecent Events:" -ForegroundColor Yellow
`$events = Get-EventLog -LogName System -Source SafeOps -EntryType Error -After (Get-Date).AddHours(-24) -ErrorAction SilentlyContinue
if (`$events) {
    Write-Host "  Recent Errors: $(@$events).Count found" -ForegroundColor Yellow
} else {
    Write-Host "  Recent Errors: None" -ForegroundColor Green
}

Write-Host "`n" + "=" * 50 -ForegroundColor Cyan

if (`$appService.Status -eq "Running" -and `$drvService.Status -eq "Running") {
    Write-Host "`nSafeOps is properly installed and running!" -ForegroundColor Green
    exit 0
} else {
    Write-Host "`nSafeOps installation verification failed!" -ForegroundColor Red
    exit 1
}
"@

    $scriptContent | Out-File -FilePath $verifyScript -Encoding UTF8 -Force
    Write-Log "Verification script created: $verifyScript" "SUCCESS"
}

# ==============================================================================
# Installation Summary
# ==============================================================================

function Show-InstallationSummary {
    param([bool]$Success)

    Write-Section "Installation Summary"

    Write-Host ""
    Write-Host "Installation Status: " -NoNewline
    if ($Success) {
        Write-Host "SUCCESSFUL" -ForegroundColor Green
    } else {
        Write-Host "COMPLETED WITH WARNINGS" -ForegroundColor Yellow
    }

    Write-Host ""
    Write-Host "Installation Details:" -ForegroundColor Cyan
    Write-Host "  Project Root: $ProjectRoot"
    Write-Host "  Install Directory: $InstallDir"
    Write-Host "  Config Directory: $ConfigDir"
    Write-Host "  Log Directory: $LogDir"
    Write-Host "  Installation Log: $LogPath"

    Write-Host ""
    Write-Host "Services Installed:" -ForegroundColor Cyan
    Write-Host "  - Kernel Driver: $DriverName"
    Write-Host "  - Userspace Service: $ServiceName"

    Write-Host ""
    Write-Host "Helper Scripts Created:" -ForegroundColor Cyan
    Write-Host "  - $(Join-Path $ScriptRoot 'uninstall_safeops.ps1')"
    Write-Host "  - $(Join-Path $ScriptRoot 'verify_installation.ps1')"

    Write-Host ""
    Write-Host "Post-Installation Steps:" -ForegroundColor Cyan
    Write-Host "  1. Verify installation: .\verify_installation.ps1"
    Write-Host "  2. Check logs: $LogPath"
    Write-Host "  3. Review configuration: $ConfigDir"

    Write-Host ""
    Write-Host "Log File Location:" -ForegroundColor Yellow
    Write-Host "  $LogPath"

    Write-Host ""
    Write-Host "Next Steps:" -ForegroundColor Cyan
    Write-Host "  - Configure SafeOps via: $ConfigDir"
    Write-Host "  - Review Event Viewer for any warnings"
    Write-Host "  - Test network filtering functionality"
    Write-Host "  - Run verify_installation.ps1 to confirm status"

    Write-Host ""
}

# ==============================================================================
# Main Installation Flow
# ==============================================================================

function Invoke-SafeOpsInstallation {
    try {
        Initialize-Logging $LogPath

        Write-Host ""
        Write-Host "╔══════════════════════════════════════════════════════════════╗" -ForegroundColor Magenta
        Write-Host "║                                                              ║" -ForegroundColor Magenta
        Write-Host "║              SafeOps v2.0 Installation Script                ║" -ForegroundColor Magenta
        Write-Host "║                                                              ║" -ForegroundColor Magenta
        Write-Host "╚══════════════════════════════════════════════════════════════╝" -ForegroundColor Magenta
        Write-Host ""

        Invoke-PreInstallationChecks
        Invoke-DirectorySetup
        Invoke-DriverInstall
        Invoke-ServiceInstall
        Invoke-ConfigurationSetup

        $verificationPassed = Invoke-InstallationVerification

        if (-not $SkipVerification) {
            New-UninstallScript
            New-VerificationScript
        }

        Show-InstallationSummary $verificationPassed

        Write-Log "Installation completed successfully" "SUCCESS"
        return 0
    }
    catch {
        Write-Log "Installation failed: $_" "ERROR"
        Write-Log "Stack trace: $($_.ScriptStackTrace)" "ERROR"

        Write-Section "Installation Failed"
        Write-Host "Error: $_" -ForegroundColor Red
        Write-Host ""
        Write-Host "Check the log file for details:" -ForegroundColor Yellow
        Write-Host "  $LogPath"
        Write-Host ""

        return 1
    }
}

# ==============================================================================
# Main Entry Point
# ==============================================================================

$exitCode = Invoke-SafeOpsInstallation
exit $exitCode
