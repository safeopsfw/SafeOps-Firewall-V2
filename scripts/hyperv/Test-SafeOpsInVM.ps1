<#
.SYNOPSIS
    Runs SafeOps tests inside a Hyper-V VM from the host

.DESCRIPTION
    Uses PowerShell Direct to:
    - Copy SafeOps files to VM
    - Execute test scripts inside VM
    - Report results back to host
    - Optionally restore checkpoint after testing

.PARAMETER VMName
    Target VM name

.PARAMETER TestType
    Type of tests: scripts, build, driver, all

.PARAMETER AutoRestore
    Automatically restore to checkpoint after testing

.EXAMPLE
    .\Test-SafeOpsInVM.ps1 -VMName "SafeOps-Test" -TestType scripts

.EXAMPLE
    .\Test-SafeOpsInVM.ps1 -TestType all -AutoRestore
#>

#Requires -RunAsAdministrator
#Requires -Modules Hyper-V

[CmdletBinding()]
param(
    [Parameter()]
    [string]$VMName = "SafeOps-Test",
    
    [Parameter()]
    [ValidateSet("scripts", "build", "driver", "all")]
    [string]$TestType = "scripts",
    
    [Parameter()]
    [string]$SafeOpsPath = "D:\SafeOpsFV2",
    
    [Parameter()]
    [switch]$AutoRestore,
    
    [Parameter()]
    [PSCredential]$Credential
)

$ErrorActionPreference = "Stop"
$script:StartTime = Get-Date

function Write-Status {
    param([string]$Message, [string]$Type = "Info")
    $color = switch ($Type) {
        "Success" { "Green" }
        "Warning" { "Yellow" }
        "Error" { "Red" }
        "Test" { "Magenta" }
        default { "Cyan" }
    }
    Write-Host "[$Type] $Message" -ForegroundColor $color
}

# Validate SafeOps path
if (-not (Test-Path $SafeOpsPath)) {
    Write-Status "SafeOps not found at: $SafeOpsPath" "Error"
    exit 1
}

# Check VM
$vm = Get-VM -Name $VMName -ErrorAction SilentlyContinue
if (-not $vm) {
    Write-Status "VM '$VMName' not found" "Error"
    Write-Host "Available VMs:"
    Get-VM | ForEach-Object { Write-Host "  - $($_.Name)" }
    exit 1
}

# Start VM if needed
if ($vm.State -ne 'Running') {
    Write-Status "Starting VM '$VMName'..."
    Start-VM -Name $VMName
    Write-Status "Waiting for VM to boot (45 seconds)..."
    Start-Sleep -Seconds 45
}

# Get credentials
if (-not $Credential) {
    $Credential = Get-Credential -Message "Enter admin credentials for VM '$VMName'"
}

Write-Host ""
Write-Host "╔════════════════════════════════════════════════════════════╗" -ForegroundColor Blue
Write-Host "║           SAFEOPS VM TEST RUNNER                           ║" -ForegroundColor Blue
Write-Host "╚════════════════════════════════════════════════════════════╝" -ForegroundColor Blue
Write-Host ""
Write-Host "  VM:        $VMName"
Write-Host "  Test Type: $TestType"
Write-Host "  Source:    $SafeOpsPath"
Write-Host ""

# Create pre-test checkpoint
$checkpointName = "Pre-Test-$(Get-Date -Format 'yyyyMMdd-HHmmss')"
Write-Status "Creating checkpoint: $checkpointName"
Checkpoint-VM -VMName $VMName -SnapshotName $checkpointName

# Test connectivity
Write-Status "Testing PowerShell Direct connection..."
try {
    $vmHostname = Invoke-Command -VMName $VMName -Credential $Credential -ScriptBlock { hostname }
    Write-Status "Connected to: $vmHostname" "Success"
}
catch {
    Write-Status "Connection failed: $($_.Exception.Message)" "Error"
    exit 1
}

# Copy SafeOps to VM
Write-Status "Copying SafeOps files to VM..."
try {
    # Copy specific directories to minimize transfer
    $dirsToSync = @("config", "proto", "src", "scripts")
    
    Invoke-Command -VMName $VMName -Credential $Credential -ScriptBlock {
        if (Test-Path "C:\SafeOpsFV2") {
            Remove-Item "C:\SafeOpsFV2" -Recurse -Force
        }
        New-Item -ItemType Directory -Path "C:\SafeOpsFV2" -Force | Out-Null
    }
    
    foreach ($dir in $dirsToSync) {
        $srcPath = Join-Path $SafeOpsPath $dir
        if (Test-Path $srcPath) {
            Write-Host "  Copying $dir..." -ForegroundColor DarkGray
            Copy-VMFile -VMName $VMName -SourcePath $srcPath -DestinationPath "C:\SafeOpsFV2\" `
                -CreateFullPath -FileSource Host -Recurse -Force
        }
    }
    Write-Status "Files copied to C:\SafeOpsFV2" "Success"
}
catch {
    Write-Status "File copy failed: $($_.Exception.Message)" "Error"
    Write-Host "Ensure 'Guest Service Interface' is enabled in VM settings"
    exit 1
}

# Run tests inside VM
Write-Status "Running tests inside VM..." "Test"
Write-Host ""

$testResults = Invoke-Command -VMName $VMName -Credential $Credential -ScriptBlock {
    param($TestType)
    
    $results = @()
    Set-Location "C:\SafeOpsFV2"
    
    #region Script Tests
    if ($TestType -in "scripts", "all") {
        
        # Test 1: File Structure
        $requiredDirs = @("config", "proto", "src", "scripts")
        $missing = $requiredDirs | Where-Object { -not (Test-Path $_) }
        $results += @{
            Name    = "File Structure"
            Status  = if ($missing.Count -eq 0) { "PASS" } else { "FAIL" }
            Details = if ($missing.Count -eq 0) { "All directories present" } else { "Missing: $($missing -join ', ')" }
        }
        
        # Test 2: Config Validator
        if (Test-Path "config\config_validator.ps1") {
            try {
                Push-Location "config"
                $output = & .\config_validator.ps1 2>&1
                Pop-Location
                $results += @{
                    Name    = "Config Validator"
                    Status  = "PASS"
                    Details = "Executed successfully"
                }
            }
            catch {
                $results += @{
                    Name    = "Config Validator"
                    Status  = "FAIL"
                    Details = $_.Exception.Message
                }
            }
        }
        else {
            $results += @{
                Name    = "Config Validator"
                Status  = "SKIP"
                Details = "Script not found"
            }
        }
        
        # Test 3: Proto Build
        if (Test-Path "proto\build.ps1") {
            $protocExists = Get-Command protoc -ErrorAction SilentlyContinue
            if ($protocExists) {
                try {
                    Push-Location "proto"
                    $output = & .\build.ps1 2>&1
                    Pop-Location
                    $results += @{
                        Name    = "Proto Build"
                        Status  = "PASS"
                        Details = "Proto files generated"
                    }
                }
                catch {
                    $results += @{
                        Name    = "Proto Build"
                        Status  = "FAIL"
                        Details = $_.Exception.Message
                    }
                }
            }
            else {
                $results += @{
                    Name    = "Proto Build"
                    Status  = "SKIP"
                    Details = "protoc not installed"
                }
            }
        }
        
        # Test 4: Kernel Driver Files
        $driverFiles = @(
            "src\kernel_driver\driver.c",
            "src\kernel_driver\filter_engine.c",
            "src\kernel_driver\safeops.inf"
        )
        $driverMissing = $driverFiles | Where-Object { -not (Test-Path $_) }
        $results += @{
            Name    = "Kernel Driver Files"
            Status  = if ($driverMissing.Count -eq 0) { "PASS" } else { "FAIL" }
            Details = if ($driverMissing.Count -eq 0) { "Core files present" } else { "Missing: $($driverMissing.Count) files" }
        }
    }
    #endregion
    
    #region Build Tests
    if ($TestType -in "build", "all") {
        # Check for WDK/nmake
        $nmake = Get-Command nmake.exe -ErrorAction SilentlyContinue
        if ($nmake) {
            $results += @{
                Name    = "Build Tools"
                Status  = "PASS"
                Details = "nmake found: $($nmake.Source)"
            }
        }
        else {
            $results += @{
                Name    = "Build Tools"
                Status  = "SKIP"
                Details = "WDK/nmake not installed"
            }
        }
    }
    #endregion
    
    #region Driver Tests
    if ($TestType -in "driver", "all") {
        # Check test signing status
        $bcdOutput = bcdedit /enum | Select-String "testsigning"
        $testSigningOn = $bcdOutput -match "Yes"
        $results += @{
            Name    = "Test Signing"
            Status  = if ($testSigningOn) { "PASS" } else { "WARN" }
            Details = if ($testSigningOn) { "Test signing enabled" } else { "Test signing NOT enabled" }
        }
        
        # Check for SafeOps service
        $service = Get-Service -Name "SafeOps" -ErrorAction SilentlyContinue
        if ($service) {
            $results += @{
                Name    = "SafeOps Service"
                Status  = "PASS"
                Details = "Service status: $($service.Status)"
            }
        }
        else {
            $results += @{
                Name    = "SafeOps Service"
                Status  = "SKIP"
                Details = "Driver not installed"
            }
        }
    }
    #endregion
    
    return $results
} -ArgumentList $TestType

# Display results
Write-Host "╔════════════════════════════════════════════════════════════╗" -ForegroundColor Yellow
Write-Host "║                    TEST RESULTS                            ║" -ForegroundColor Yellow
Write-Host "╚════════════════════════════════════════════════════════════╝" -ForegroundColor Yellow
Write-Host ""

$passed = 0
$failed = 0
$skipped = 0

foreach ($result in $testResults) {
    $icon = switch ($result.Status) {
        "PASS" { "✓"; $passed++ }
        "FAIL" { "✗"; $failed++ }
        "SKIP" { "○"; $skipped++ }
        "WARN" { "!"; $skipped++ }
        default { "?"; $skipped++ }
    }
    $color = switch ($result.Status) {
        "PASS" { "Green" }
        "FAIL" { "Red" }
        "SKIP" { "Yellow" }
        "WARN" { "Yellow" }
        default { "White" }
    }
    Write-Host "  $icon $($result.Name)" -ForegroundColor $color -NoNewline
    Write-Host " - $($result.Details)" -ForegroundColor DarkGray
}

$duration = (Get-Date) - $script:StartTime
Write-Host ""
Write-Host "─" * 60 -ForegroundColor DarkGray
Write-Host ""
Write-Host "  Passed:  $passed" -ForegroundColor Green
Write-Host "  Failed:  $failed" -ForegroundColor $(if ($failed -gt 0) { "Red" } else { "DarkGray" })
Write-Host "  Skipped: $skipped" -ForegroundColor $(if ($skipped -gt 0) { "Yellow" } else { "DarkGray" })
Write-Host ""
Write-Host "  Duration: $($duration.TotalSeconds.ToString('F1'))s"
Write-Host ""

# Restore checkpoint if requested
if ($AutoRestore -or $failed -gt 0) {
    if (-not $AutoRestore) {
        $restore = Read-Host "Tests had failures. Restore VM to checkpoint? (y/N)"
        if ($restore -ne 'y') { exit $failed }
    }
    
    Write-Status "Restoring VM to checkpoint: $checkpointName"
    Stop-VM -Name $VMName -Force -ErrorAction SilentlyContinue
    Restore-VMSnapshot -VMName $VMName -Name $checkpointName -Confirm:$false
    Start-VM -Name $VMName
    Write-Status "VM restored to pre-test state" "Success"
}

exit $failed
