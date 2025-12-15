<#
.SYNOPSIS
    Configures a VM for SafeOps driver development and testing

.DESCRIPTION
    Runs inside the VM via PowerShell Direct to:
    - Enable test signing mode
    - Disable driver signature enforcement
    - Configure kernel debugging (optional)
    - Create a clean checkpoint

.PARAMETER VMName
    Name of the target VM

.PARAMETER EnableDebug
    Enable kernel debugging

.EXAMPLE
    .\Configure-VMForDriverDev.ps1 -VMName "SafeOps-Test"

.NOTES
    Requires admin credentials for the VM
    VM must be running with Windows installed
#>

#Requires -RunAsAdministrator
#Requires -Modules Hyper-V

[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string]$VMName,
    
    [Parameter()]
    [switch]$EnableDebug,
    
    [Parameter()]
    [PSCredential]$Credential
)

$ErrorActionPreference = "Stop"

function Write-Status {
    param([string]$Message, [string]$Type = "Info")
    $color = switch ($Type) {
        "Success" { "Green" }
        "Warning" { "Yellow" }
        "Error" { "Red" }
        default { "Cyan" }
    }
    Write-Host "[$Type] $Message" -ForegroundColor $color
}

# Check VM exists and is running
$vm = Get-VM -Name $VMName -ErrorAction SilentlyContinue
if (-not $vm) {
    Write-Status "VM '$VMName' not found" "Error"
    exit 1
}

if ($vm.State -ne 'Running') {
    Write-Status "Starting VM '$VMName'..."
    Start-VM -Name $VMName
    Write-Status "Waiting for VM to boot (60 seconds)..."
    Start-Sleep -Seconds 60
}

# Get credentials if not provided
if (-not $Credential) {
    Write-Status "Enter VM administrator credentials" "Warning"
    $Credential = Get-Credential -Message "Enter admin credentials for VM '$VMName'"
}

Write-Host ""
Write-Host "╔════════════════════════════════════════════════════════════╗" -ForegroundColor Blue
Write-Host "║           CONFIGURING VM FOR DRIVER DEVELOPMENT            ║" -ForegroundColor Blue
Write-Host "╚════════════════════════════════════════════════════════════╝" -ForegroundColor Blue
Write-Host ""

# Test PowerShell Direct connectivity
Write-Status "Testing PowerShell Direct connection..."
try {
    $hostname = Invoke-Command -VMName $VMName -Credential $Credential -ScriptBlock { hostname } -ErrorAction Stop
    Write-Status "Connected to: $hostname" "Success"
}
catch {
    Write-Status "Failed to connect via PowerShell Direct: $($_.Exception.Message)" "Error"
    Write-Host ""
    Write-Host "Troubleshooting:" -ForegroundColor Yellow
    Write-Host "  1. Ensure Windows is fully installed and booted"
    Write-Host "  2. Create a user account with admin privileges"
    Write-Host "  3. Enable 'Guest Services' in VM settings"
    Write-Host ""
    exit 1
}

# Configure VM for driver testing
Write-Status "Configuring test signing and driver settings..."

$configResult = Invoke-Command -VMName $VMName -Credential $Credential -ScriptBlock {
    param($EnableDebug)
    
    $results = @()
    
    # Enable test signing
    $output = bcdedit /set testsigning on 2>&1
    $results += @{ Command = "Test Signing"; Output = $output; Success = $LASTEXITCODE -eq 0 }
    
    # Disable integrity checks
    $output = bcdedit /set nointegritychecks on 2>&1
    $results += @{ Command = "Integrity Checks Off"; Output = $output; Success = $LASTEXITCODE -eq 0 }
    
    # Enable kernel debugging if requested
    if ($EnableDebug) {
        $output = bcdedit /debug on 2>&1
        $results += @{ Command = "Kernel Debug"; Output = $output; Success = $LASTEXITCODE -eq 0 }
    }
    
    # Create SafeOps directory
    $safeopsDir = "C:\SafeOps"
    if (-not (Test-Path $safeopsDir)) {
        New-Item -ItemType Directory -Path $safeopsDir -Force | Out-Null
    }
    $results += @{ Command = "Create C:\SafeOps"; Output = "Directory ready"; Success = $true }
    
    # Create Drivers directory
    $driversDir = "C:\Drivers"
    if (-not (Test-Path $driversDir)) {
        New-Item -ItemType Directory -Path $driversDir -Force | Out-Null
    }
    $results += @{ Command = "Create C:\Drivers"; Output = "Directory ready"; Success = $true }
    
    return $results
} -ArgumentList $EnableDebug

# Display results
foreach ($result in $configResult) {
    if ($result.Success) {
        Write-Status "$($result.Command): OK" "Success"
    }
    else {
        Write-Status "$($result.Command): FAILED - $($result.Output)" "Error"
    }
}

# Create checkpoint
Write-Status "Creating 'Ready-For-Testing' checkpoint..."
Checkpoint-VM -VMName $VMName -SnapshotName "Ready-For-Testing"
Write-Status "Checkpoint created" "Success"

# Restart VM to apply BCD changes
Write-Status "Restarting VM to apply settings..."
Invoke-Command -VMName $VMName -Credential $Credential -ScriptBlock {
    Restart-Computer -Force
}

Write-Host ""
Write-Host "╔════════════════════════════════════════════════════════════╗" -ForegroundColor Green
Write-Host "║           VM CONFIGURED SUCCESSFULLY                       ║" -ForegroundColor Green
Write-Host "╚════════════════════════════════════════════════════════════╝" -ForegroundColor Green
Write-Host ""
Write-Host "Configuration Applied:" -ForegroundColor White
Write-Host "  ✓ Test signing enabled"
Write-Host "  ✓ Driver signature enforcement disabled"
if ($EnableDebug) {
    Write-Host "  ✓ Kernel debugging enabled"
}
Write-Host "  ✓ C:\SafeOps directory created"
Write-Host "  ✓ C:\Drivers directory created"
Write-Host "  ✓ 'Ready-For-Testing' checkpoint saved"
Write-Host ""
Write-Host "Next Steps:" -ForegroundColor Yellow
Write-Host "  Wait for VM to reboot, then run:"
Write-Host "  .\Test-SafeOpsInVM.ps1 -VMName '$VMName' -TestType scripts"
Write-Host ""
