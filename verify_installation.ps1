# ==============================================================================
# SafeOps v2.0 - Installation Verification Script
# ==============================================================================
# Purpose: Verify SafeOps installation and system health
# ==============================================================================

param(
    [switch]$Verbose = $false,
    [switch]$FullReport = $false
)

$ErrorActionPreference = "SilentlyContinue"
$ProgressPreference = "SilentlyContinue"

# ==============================================================================
# Configuration
# ==============================================================================

$ServiceName = "SafeOpsService"
$DriverName = "SafeOps"
$InstallDir = "C:\Program Files\SafeOps"
$ConfigDir = Join-Path $env:APPDATA "SafeOps"
$LogDir = Join-Path $env:ProgramData "SafeOps\Logs"

# Verification results tracking
$script:VerificationResults = @{
    Passed = @()
    Failed = @()
    Warnings = @()
}

# ==============================================================================
# Helper Functions
# ==============================================================================

function Write-Section {
    param([string]$Title)

    Write-Host ""
    Write-Host "=" * 80 -ForegroundColor Cyan
    Write-Host " $Title" -ForegroundColor Cyan
    Write-Host "=" * 80 -ForegroundColor Cyan
}

function Write-CheckResult {
    param(
        [string]$CheckName,
        [string]$Status,
        [string]$Message = "",
        [string]$Details = ""
    )

    $statusColor = switch ($Status) {
        "PASS" { "Green" }
        "FAIL" { "Red" }
        "WARN" { "Yellow" }
        default { "Gray" }
    }

    $statusSymbol = switch ($Status) {
        "PASS" { "[✓]" }
        "FAIL" { "[✗]" }
        "WARN" { "[!]" }
        default { "[?]" }
    }

    Write-Host "  $statusSymbol $CheckName" -ForegroundColor $statusColor -NoNewline

    if ($Message) {
        Write-Host " - $Message" -ForegroundColor $statusColor
    } else {
        Write-Host ""
    }

    if ($Details -and $Verbose) {
        Write-Host "      $Details" -ForegroundColor DarkGray
    }

    switch ($Status) {
        "PASS" { $script:VerificationResults.Passed += $CheckName }
        "FAIL" { $script:VerificationResults.Failed += $CheckName }
        "WARN" { $script:VerificationResults.Warnings += $CheckName }
    }
}

# ==============================================================================
# System Information
# ==============================================================================

function Get-SystemInfo {
    Write-Section "System Information"

    Write-Host ""
    Write-Host "Computer Information:" -ForegroundColor Yellow
    Write-Host "  Hostname: $env:COMPUTERNAME"
    Write-Host "  Username: $env:USERNAME"
    Write-Host "  OS Version: $([System.Environment]::OSVersion.VersionString)"
    Write-Host "  Architecture: $(if ([Environment]::Is64BitOperatingSystem) { 'x64' } else { 'x86' })"
    Write-Host "  PowerShell Version: $($PSVersionTable.PSVersion)"

    $osVersion = [System.Environment]::OSVersion.Version
    Write-Host ""
    Write-Host "OS Version Details:" -ForegroundColor Yellow
    Write-Host "  Major: $($osVersion.Major)"
    Write-Host "  Minor: $($osVersion.Minor)"
    Write-Host "  Build: $($osVersion.Build)"
    Write-Host "  Revision: $($osVersion.Revision)"

    # Check test signing
    Write-Host ""
    Write-Host "Security Settings:" -ForegroundColor Yellow
    try {
        $testSigning = (bcdedit /enum | Select-String "testsigning").Line
        if ($testSigning -like "*Yes*") {
            Write-Host "  Test Signing: ENABLED" -ForegroundColor Green
        } else {
            Write-Host "  Test Signing: DISABLED" -ForegroundColor Yellow
        }
    }
    catch {
        Write-Host "  Test Signing: [Unable to determine]" -ForegroundColor Yellow
    }
}

# ==============================================================================
# Service Verification
# ==============================================================================

function Verify-Services {
    Write-Section "Service Status"

    Write-Host ""
    Write-Host "Checking SafeOps Services:" -ForegroundColor Yellow
    Write-Host ""

    # Check userspace service
    $appService = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue

    if ($null -ne $appService) {
        $status = $appService.Status
        $statusColor = if ($status -eq "Running") { "Green" } else { "Yellow" }
        $statusIcon = if ($status -eq "Running") { "[✓]" } else { "[!]" }

        Write-Host "  $statusIcon Userspace Service ($ServiceName)" -ForegroundColor $statusColor
        Write-Host "      Status: $status"
        Write-Host "      Startup Type: $($appService.StartType)"
        Write-Host "      Display Name: $($appService.DisplayName)"

        if ($status -eq "Running") {
            Write-CheckResult "Userspace Service Running" "PASS" "Status is Running"
        } else {
            Write-CheckResult "Userspace Service Running" "WARN" "Status is $status"
        }
    } else {
        Write-Host "  [✗] Userspace Service ($ServiceName)" -ForegroundColor Red
        Write-Host "      Status: NOT INSTALLED"
        Write-CheckResult "Userspace Service Installed" "FAIL" "Service not found"
    }

    Write-Host ""

    # Check kernel driver
    $drvService = Get-Service -Name $DriverName -ErrorAction SilentlyContinue

    if ($null -ne $drvService) {
        $status = $drvService.Status
        $statusColor = if ($status -eq "Running") { "Green" } else { "Yellow" }
        $statusIcon = if ($status -eq "Running") { "[✓]" } else { "[!]" }

        Write-Host "  $statusIcon Kernel Driver ($DriverName)" -ForegroundColor $statusColor
        Write-Host "      Status: $status"
        Write-Host "      Startup Type: $($drvService.StartType)"
        Write-Host "      Display Name: $($drvService.DisplayName)"

        if ($status -eq "Running") {
            Write-CheckResult "Kernel Driver Running" "PASS" "Status is Running"
        } else {
            Write-CheckResult "Kernel Driver Running" "WARN" "Status is $status"
        }
    } else {
        Write-Host "  [✗] Kernel Driver ($DriverName)" -ForegroundColor Red
        Write-Host "      Status: NOT INSTALLED"
        Write-CheckResult "Kernel Driver Installed" "FAIL" "Driver not found"
    }

    Write-Host ""

    # Service dependencies
    if ($null -ne $appService) {
        Write-Host "Service Dependencies:" -ForegroundColor Yellow
        try {
            $deps = (Get-Service -Name $ServiceName -DependentServices -ErrorAction SilentlyContinue).Name
            if ($deps) {
                foreach ($dep in $deps) {
                    Write-Host "    - $dep" -ForegroundColor Gray
                }
            } else {
                Write-Host "    (No dependencies)" -ForegroundColor Gray
            }
        }
        catch {
            Write-Host "    [Unable to determine]" -ForegroundColor Gray
        }
    }
}

# ==============================================================================
# File System Verification
# ==============================================================================

function Verify-FileSystem {
    Write-Section "Installation Files"

    Write-Host ""
    Write-Host "Checking Installation Directory: $InstallDir" -ForegroundColor Yellow
    Write-Host ""

    if (Test-Path $InstallDir) {
        Write-Host "  [✓] Installation Directory Found" -ForegroundColor Green
        Write-CheckResult "Installation Directory Exists" "PASS" "Found at $InstallDir"

        Write-Host ""

        # Check individual files
        $files = @(
            @{ Path = (Join-Path $InstallDir "SafeOps.sys"); Name = "Kernel Driver"; Critical = $true },
            @{ Path = (Join-Path $InstallDir "SafeOpsService.exe"); Name = "Userspace Service"; Critical = $true }
        )

        foreach ($file in $files) {
            if (Test-Path $file.Path) {
                $fileInfo = Get-Item -Path $file.Path
                $size = $fileInfo.Length / 1MB
                Write-Host "  [✓] $($file.Name)" -ForegroundColor Green
                Write-Host "      Path: $($file.Path)"
                Write-Host "      Size: $([Math]::Round($size, 2)) MB"
                Write-Host "      Modified: $($fileInfo.LastWriteTime)"
                Write-CheckResult "$($file.Name) File" "PASS" "Found and accessible"
            } else {
                if ($file.Critical) {
                    Write-Host "  [✗] $($file.Name)" -ForegroundColor Red
                    Write-Host "      Path: $($file.Path)"
                    Write-Host "      Status: MISSING"
                    Write-CheckResult "$($file.Name) File" "FAIL" "Not found"
                } else {
                    Write-Host "  [!] $($file.Name)" -ForegroundColor Yellow
                    Write-Host "      Path: $($file.Path)"
                    Write-Host "      Status: NOT FOUND (optional)"
                    Write-CheckResult "$($file.Name) File" "WARN" "Not found (optional)"
                }
            }
            Write-Host ""
        }
    } else {
        Write-Host "  [✗] Installation Directory Not Found" -ForegroundColor Red
        Write-Host "      Expected: $InstallDir"
        Write-CheckResult "Installation Directory Exists" "FAIL" "Not found"
    }
}

# ==============================================================================
# Configuration Verification
# ==============================================================================

function Verify-Configuration {
    Write-Section "Configuration"

    Write-Host ""
    Write-Host "Checking Configuration Directory: $ConfigDir" -ForegroundColor Yellow
    Write-Host ""

    if (Test-Path $ConfigDir) {
        Write-Host "  [✓] Configuration Directory Found" -ForegroundColor Green
        Write-Host "      Path: $ConfigDir"
        Write-CheckResult "Configuration Directory Exists" "PASS" "Found at $ConfigDir"

        Write-Host ""

        # Check for configuration file
        $configFile = Join-Path $ConfigDir "safeops.conf"
        if (Test-Path $configFile) {
            Write-Host "  [✓] Configuration File Found" -ForegroundColor Green
            Write-Host "      Path: $configFile"
            Write-CheckResult "Configuration File Exists" "PASS" "Found safeops.conf"

            if ($Verbose) {
                Write-Host "      File size: $(((Get-Item $configFile).Length / 1KB))" -ForegroundColor Gray
            }
        } else {
            Write-Host "  [!] Configuration File Not Found" -ForegroundColor Yellow
            Write-Host "      Path: $configFile"
            Write-Host "      Status: Using defaults"
            Write-CheckResult "Configuration File Exists" "WARN" "Not found, defaults used"
        }

        Write-Host ""

        # List subdirectories
        Write-Host "Configuration Subdirectories:" -ForegroundColor Yellow
        try {
            $subDirs = Get-ChildItem -Path $ConfigDir -Directory -ErrorAction SilentlyContinue
            if ($subDirs) {
                foreach ($dir in $subDirs) {
                    $fileCount = (Get-ChildItem -Path $dir.FullName -File -Recurse -ErrorAction SilentlyContinue | Measure-Object).Count
                    Write-Host "    - $($dir.Name) [$fileCount files]" -ForegroundColor Gray
                }
            } else {
                Write-Host "    (Empty)" -ForegroundColor Gray
            }
        }
        catch {
            Write-Host "    [Unable to enumerate]" -ForegroundColor Gray
        }
    } else {
        Write-Host "  [!] Configuration Directory Not Found" -ForegroundColor Yellow
        Write-Host "      Path: $ConfigDir"
        Write-Host "      Status: Not yet created"
        Write-CheckResult "Configuration Directory Exists" "WARN" "Not created yet"
    }
}

# ==============================================================================
# Logging Verification
# ==============================================================================

function Verify-Logging {
    Write-Section "Logging"

    Write-Host ""
    Write-Host "Checking Log Directory: $LogDir" -ForegroundColor Yellow
    Write-Host ""

    if (Test-Path $LogDir) {
        Write-Host "  [✓] Log Directory Found" -ForegroundColor Green
        Write-Host "      Path: $LogDir"
        Write-CheckResult "Log Directory Exists" "PASS" "Found at $LogDir"

        Write-Host ""

        # Check for log files
        try {
            $logFiles = Get-ChildItem -Path $LogDir -Filter "*.log" -ErrorAction SilentlyContinue
            if ($logFiles) {
                Write-Host "Log Files ($($logFiles.Count) found):" -ForegroundColor Yellow
                foreach ($file in $logFiles | Select-Object -Last 5) {
                    $size = $file.Length / 1KB
                    Write-Host "    - $($file.Name) ($([Math]::Round($size, 2)) KB)" -ForegroundColor Gray
                }

                if ($logFiles.Count -gt 5) {
                    Write-Host "    ... and $($logFiles.Count - 5) more files" -ForegroundColor Gray
                }

                Write-CheckResult "Log Files Exist" "PASS" "Found $($logFiles.Count) log files"
            } else {
                Write-Host "  [!] No Log Files Found" -ForegroundColor Yellow
                Write-CheckResult "Log Files Exist" "WARN" "No log files yet"
            }
        }
        catch {
            Write-Host "  [!] Error accessing log files" -ForegroundColor Yellow
        }
    } else {
        Write-Host "  [!] Log Directory Not Found" -ForegroundColor Yellow
        Write-Host "      Path: $LogDir"
        Write-Host "      Status: Not yet created"
        Write-CheckResult "Log Directory Exists" "WARN" "Not created yet"
    }
}

# ==============================================================================
# Event Viewer Check
# ==============================================================================

function Verify-EventViewer {
    Write-Section "Event Viewer"

    Write-Host ""
    Write-Host "Checking System Event Log for SafeOps entries..." -ForegroundColor Yellow
    Write-Host ""

    try {
        # Get recent SafeOps events
        $allEvents = Get-EventLog -LogName System -Source SafeOps -ErrorAction SilentlyContinue | Sort-Object TimeGenerated -Descending

        if ($allEvents) {
            Write-Host "  [✓] SafeOps Events Found" -ForegroundColor Green
            Write-Host "      Total events: $($allEvents.Count)"
            Write-CheckResult "SafeOps Events in Event Viewer" "PASS" "Found $($allEvents.Count) events"

            Write-Host ""

            # Show recent events
            $recentEvents = $allEvents | Select-Object -First 5
            Write-Host "Recent Events (last 5):" -ForegroundColor Yellow

            foreach ($event in $recentEvents) {
                $eventType = $event.EntryType
                $color = switch ($eventType) {
                    "Error" { "Red" }
                    "Warning" { "Yellow" }
                    "Information" { "Green" }
                    default { "Gray" }
                }

                Write-Host "    [$($event.TimeGenerated.ToString('yyyy-MM-dd HH:mm:ss'))] $eventType" -ForegroundColor $color
                if ($Verbose) {
                    Write-Host "      $($event.Message.Substring(0, [Math]::Min(100, $event.Message.Length)))" -ForegroundColor DarkGray
                }
            }

            # Check for errors
            $errors = $allEvents | Where-Object { $_.EntryType -eq "Error" }
            if ($errors) {
                Write-Host ""
                Write-Host "  [!] Error Events Found" -ForegroundColor Yellow
                Write-Host "      Count: $($errors.Count)"
                Write-CheckResult "No SafeOps Errors" "WARN" "Found $($errors.Count) errors"
            } else {
                Write-CheckResult "No SafeOps Errors" "PASS" "No errors found"
            }
        } else {
            Write-Host "  [!] No SafeOps Events Found" -ForegroundColor Yellow
            Write-Host "      Status: Service may not have logged yet"
            Write-CheckResult "SafeOps Events in Event Viewer" "WARN" "No events found yet"
        }
    }
    catch {
        Write-Host "  [!] Error accessing Event Viewer" -ForegroundColor Yellow
        Write-Host "      Error: $_" -ForegroundColor Gray
        Write-CheckResult "Event Viewer Access" "WARN" "Could not access Event Viewer"
    }
}

# ==============================================================================
# Network Verification
# ==============================================================================

function Verify-Network {
    Write-Section "Network Configuration"

    Write-Host ""
    Write-Host "Checking network adapters and connectivity..." -ForegroundColor Yellow
    Write-Host ""

    try {
        $adapters = Get-NetAdapter -ErrorAction SilentlyContinue | Where-Object { $_.Status -eq "Up" }

        if ($adapters) {
            Write-Host "  [✓] Network Adapters Found" -ForegroundColor Green
            Write-Host "      Count: $($adapters.Count)"
            Write-CheckResult "Network Adapters" "PASS" "Found $($adapters.Count) active adapters"

            Write-Host ""
            Write-Host "Active Adapters:" -ForegroundColor Yellow

            foreach ($adapter in $adapters) {
                Write-Host "    - $($adapter.Name)" -ForegroundColor Gray
                Write-Host "      Status: $($adapter.Status)" -ForegroundColor Gray
                Write-Host "      Type: $($adapter.InterfaceDescription)" -ForegroundColor Gray
            }
        } else {
            Write-Host "  [!] No Active Network Adapters Found" -ForegroundColor Yellow
            Write-CheckResult "Network Adapters" "WARN" "No active adapters"
        }

        Write-Host ""

        # Check DNS resolution
        Write-Host "DNS Resolution:" -ForegroundColor Yellow
        try {
            $dnsCheck = [System.Net.Dns]::GetHostName()
            Write-Host "  [✓] DNS Lookup Successful" -ForegroundColor Green
            Write-Host "      Hostname: $dnsCheck" -ForegroundColor Gray
            Write-CheckResult "DNS Resolution" "PASS" "Hostname resolved"
        }
        catch {
            Write-Host "  [!] DNS Lookup Failed" -ForegroundColor Yellow
            Write-CheckResult "DNS Resolution" "WARN" "Could not resolve hostname"
        }
    }
    catch {
        Write-Host "  [!] Error checking network configuration" -ForegroundColor Yellow
        Write-CheckResult "Network Configuration" "WARN" "Could not check"
    }
}

# ==============================================================================
# Registry Check
# ==============================================================================

function Verify-Registry {
    Write-Section "Registry"

    Write-Host ""
    Write-Host "Checking Windows Registry for SafeOps entries..." -ForegroundColor Yellow
    Write-Host ""

    $regPaths = @(
        @{ Path = "HKLM:\SYSTEM\CurrentControlSet\Services\$ServiceName"; Name = "Userspace Service" },
        @{ Path = "HKLM:\SYSTEM\CurrentControlSet\Services\$DriverName"; Name = "Kernel Driver" }
    )

    foreach ($regItem in $regPaths) {
        if (Test-Path $regItem.Path) {
            Write-Host "  [✓] Registry Entry: $($regItem.Name)" -ForegroundColor Green
            Write-Host "      Path: $($regItem.Path)" -ForegroundColor Gray
            Write-CheckResult "Registry Entry - $($regItem.Name)" "PASS" "Found"
        } else {
            Write-Host "  [!] Registry Entry Not Found: $($regItem.Name)" -ForegroundColor Yellow
            Write-Host "      Path: $($regItem.Path)" -ForegroundColor Gray
            Write-CheckResult "Registry Entry - $($regItem.Name)" "WARN" "Not found"
        }
    }
}

# ==============================================================================
# Verification Report
# ==============================================================================

function Show-VerificationReport {
    Write-Host ""
    Write-Host "=" * 80 -ForegroundColor Cyan
    Write-Host " VERIFICATION REPORT" -ForegroundColor Cyan
    Write-Host "=" * 80 -ForegroundColor Cyan
    Write-Host ""

    $totalChecks = $script:VerificationResults.Passed.Count + $script:VerificationResults.Failed.Count + $script:VerificationResults.Warnings.Count
    $passRate = if ($totalChecks -gt 0) { [Math]::Round(($script:VerificationResults.Passed.Count / $totalChecks) * 100, 1) } else { 0 }

    Write-Host "Summary:" -ForegroundColor Yellow
    Write-Host "  Passed:  $($script:VerificationResults.Passed.Count)" -ForegroundColor Green
    Write-Host "  Failed:  $($script:VerificationResults.Failed.Count)" -ForegroundColor Red
    Write-Host "  Warnings: $($script:VerificationResults.Warnings.Count)" -ForegroundColor Yellow
    Write-Host "  Success Rate: $passRate%" -ForegroundColor Cyan

    Write-Host ""

    if ($script:VerificationResults.Failed.Count -eq 0) {
        Write-Host "Status: HEALTHY" -ForegroundColor Green
        Write-Host "SafeOps appears to be properly installed and configured." -ForegroundColor Green
    } elseif ($script:VerificationResults.Failed.Count -le 2) {
        Write-Host "Status: DEGRADED" -ForegroundColor Yellow
        Write-Host "Some components may not be functioning properly." -ForegroundColor Yellow
    } else {
        Write-Host "Status: UNHEALTHY" -ForegroundColor Red
        Write-Host "SafeOps installation has critical issues." -ForegroundColor Red
    }

    Write-Host ""

    if ($FullReport) {
        Write-Host "Detailed Results:" -ForegroundColor Yellow
        Write-Host ""

        if ($script:VerificationResults.Passed.Count -gt 0) {
            Write-Host "Passed Checks:" -ForegroundColor Green
            foreach ($check in $script:VerificationResults.Passed) {
                Write-Host "  [✓] $check" -ForegroundColor Green
            }
            Write-Host ""
        }

        if ($script:VerificationResults.Failed.Count -gt 0) {
            Write-Host "Failed Checks:" -ForegroundColor Red
            foreach ($check in $script:VerificationResults.Failed) {
                Write-Host "  [✗] $check" -ForegroundColor Red
            }
            Write-Host ""
        }

        if ($script:VerificationResults.Warnings.Count -gt 0) {
            Write-Host "Warnings:" -ForegroundColor Yellow
            foreach ($check in $script:VerificationResults.Warnings) {
                Write-Host "  [!] $check" -ForegroundColor Yellow
            }
            Write-Host ""
        }
    }
}

# ==============================================================================
# Main Verification Flow
# ==============================================================================

function Invoke-VerificationScript {
    Write-Host ""
    Write-Host "╔══════════════════════════════════════════════════════════════╗" -ForegroundColor Cyan
    Write-Host "║                                                              ║" -ForegroundColor Cyan
    Write-Host "║       SafeOps v2.0 Installation Verification Script          ║" -ForegroundColor Cyan
    Write-Host "║                                                              ║" -ForegroundColor Cyan
    Write-Host "╚══════════════════════════════════════════════════════════════╝" -ForegroundColor Cyan
    Write-Host ""

    Get-SystemInfo
    Verify-Services
    Verify-FileSystem
    Verify-Configuration
    Verify-Logging
    Verify-EventViewer
    Verify-Network
    Verify-Registry

    Show-VerificationReport

    Write-Host "Verification completed at $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')" -ForegroundColor Cyan
    Write-Host ""

    # Return appropriate exit code
    if ($script:VerificationResults.Failed.Count -eq 0) {
        return 0
    } else {
        return 1
    }
}

# ==============================================================================
# Main Entry Point
# ==============================================================================

$exitCode = Invoke-VerificationScript
exit $exitCode
