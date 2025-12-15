<#
.SYNOPSIS
    Creates a Hyper-V VM for SafeOps testing

.DESCRIPTION
    Automates creation of a Windows VM with optimal settings for driver development
    and testing. Uses minimum resources while supporting WDK compilation.

.PARAMETER VMName
    Name of the VM to create (default: SafeOps-Test)

.PARAMETER ISOPath
    Path to Windows ISO file for installation

.PARAMETER VHDXPath
    Path to existing VHDX file (alternative to ISO)

.PARAMETER VMPath
    Path to store VM files (default: C:\Hyper-V)

.EXAMPLE
    .\Create-SafeOpsTestVM.ps1 -ISOPath "C:\ISO\Windows10.iso"
    Creates VM and mounts ISO for installation

.EXAMPLE
    .\Create-SafeOpsTestVM.ps1 -VHDXPath "C:\VMs\Win10Dev.vhdx"
    Creates VM from existing VHDX

.NOTES
    Requires: Windows 10/11 Pro/Enterprise/Education with Hyper-V enabled
    Run as Administrator
#>

#Requires -RunAsAdministrator
#Requires -Modules Hyper-V

[CmdletBinding()]
param(
    [Parameter()]
    [string]$VMName = "SafeOps-Test",
    
    [Parameter()]
    [string]$ISOPath = "",
    
    [Parameter()]
    [string]$VHDXPath = "",
    
    [Parameter()]
    [string]$VMPath = "C:\Hyper-V",
    
    [Parameter()]
    [int64]$VHDSize = 60GB,
    
    [Parameter()]
    [int64]$MemoryStartup = 4GB,
    
    [Parameter()]
    [int]$ProcessorCount = 2
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

# Validate parameters
if (-not $ISOPath -and -not $VHDXPath) {
    Write-Status "Either -ISOPath or -VHDXPath must be specified" "Error"
    Write-Host @"

Usage Examples:
  .\Create-SafeOpsTestVM.ps1 -ISOPath "C:\ISO\Windows10.iso"
  .\Create-SafeOpsTestVM.ps1 -VHDXPath "C:\VMs\existing.vhdx"

Download Windows 10 Enterprise Evaluation (Free 90-day):
  https://www.microsoft.com/evalcenter/evaluate-windows-10-enterprise

"@
    exit 1
}

if ($ISOPath -and -not (Test-Path $ISOPath)) {
    Write-Status "ISO file not found: $ISOPath" "Error"
    exit 1
}

if ($VHDXPath -and -not (Test-Path $VHDXPath)) {
    Write-Status "VHDX file not found: $VHDXPath" "Error"
    exit 1
}

# Check if VM already exists
$existingVM = Get-VM -Name $VMName -ErrorAction SilentlyContinue
if ($existingVM) {
    Write-Status "VM '$VMName' already exists" "Warning"
    $confirm = Read-Host "Delete existing VM? (y/N)"
    if ($confirm -eq 'y') {
        Stop-VM -Name $VMName -Force -ErrorAction SilentlyContinue
        Remove-VM -Name $VMName -Force
        Remove-Item "$VMPath\$VMName" -Recurse -Force -ErrorAction SilentlyContinue
        Write-Status "Removed existing VM" "Success"
    }
    else {
        exit 0
    }
}

Write-Host ""
Write-Host "╔════════════════════════════════════════════════════════════╗" -ForegroundColor Blue
Write-Host "║           SAFEOPS TEST VM CREATION                         ║" -ForegroundColor Blue
Write-Host "╚════════════════════════════════════════════════════════════╝" -ForegroundColor Blue
Write-Host ""

# Create VM directory
$vmDir = "$VMPath\$VMName"
if (-not (Test-Path $vmDir)) {
    New-Item -ItemType Directory -Path $vmDir -Force | Out-Null
}

# Create internal switch if not exists
$switchName = "SafeOps-Internal"
$switch = Get-VMSwitch -Name $switchName -ErrorAction SilentlyContinue
if (-not $switch) {
    Write-Status "Creating virtual switch: $switchName"
    New-VMSwitch -Name $switchName -SwitchType Internal | Out-Null
    Write-Status "Virtual switch created" "Success"
}

# Create VM
Write-Status "Creating VM: $VMName"

if ($VHDXPath) {
    # Use existing VHDX - copy it
    $newVHDPath = "$vmDir\$VMName.vhdx"
    Write-Status "Copying VHDX to $newVHDPath"
    Copy-Item $VHDXPath $newVHDPath
    
    New-VM -Name $VMName `
        -MemoryStartupBytes $MemoryStartup `
        -Generation 2 `
        -VHDPath $newVHDPath `
        -Path $VMPath | Out-Null
}
else {
    # Create new VHDX
    $newVHDPath = "$vmDir\$VMName.vhdx"
    
    New-VM -Name $VMName `
        -MemoryStartupBytes $MemoryStartup `
        -Generation 2 `
        -NewVHDPath $newVHDPath `
        -NewVHDSizeBytes $VHDSize `
        -Path $VMPath | Out-Null
}

Write-Status "VM created" "Success"

# Configure processor
Write-Status "Configuring processor: $ProcessorCount vCPUs"
Set-VMProcessor -VMName $VMName -Count $ProcessorCount

# Configure memory (dynamic)
Write-Status "Configuring dynamic memory: 2GB - 8GB"
Set-VMMemory -VMName $VMName -DynamicMemoryEnabled $true -MinimumBytes 2GB -MaximumBytes 8GB

# Disable Secure Boot for driver testing
Write-Status "Disabling Secure Boot for driver testing"
Set-VMFirmware -VMName $VMName -EnableSecureBoot Off

# Connect network
Write-Status "Connecting to virtual switch: $switchName"
Connect-VMNetworkAdapter -VMName $VMName -SwitchName $switchName

# Mount ISO if provided
if ($ISOPath) {
    Write-Status "Mounting ISO: $ISOPath"
    Add-VMDvdDrive -VMName $VMName -Path $ISOPath
    $dvd = Get-VMDvdDrive -VMName $VMName
    Set-VMFirmware -VMName $VMName -FirstBootDevice $dvd
    Write-Status "ISO mounted as boot device" "Success"
}

# Enable guest services for file copy
Write-Status "Enabling guest services for PowerShell Direct"
Enable-VMIntegrationService -VMName $VMName -Name "Guest Service Interface"

# Create initial checkpoint
Write-Status "Creating initial checkpoint"
Checkpoint-VM -VMName $VMName -SnapshotName "Initial-Created"

# Summary
Write-Host ""
Write-Host "╔════════════════════════════════════════════════════════════╗" -ForegroundColor Green
Write-Host "║           VM CREATED SUCCESSFULLY                          ║" -ForegroundColor Green
Write-Host "╚════════════════════════════════════════════════════════════╝" -ForegroundColor Green
Write-Host ""
Write-Host "  VM Name:     $VMName"
Write-Host "  vCPUs:       $ProcessorCount"
Write-Host "  Memory:      2-8 GB (Dynamic)"
Write-Host "  Disk:        $([math]::Round($VHDSize/1GB))GB"
Write-Host "  Switch:      $switchName"
Write-Host "  Location:    $vmDir"
Write-Host ""
Write-Host "Next Steps:" -ForegroundColor Yellow
Write-Host "  1. Start VM:    Start-VM -Name '$VMName'"
Write-Host "  2. Connect:     vmconnect localhost $VMName"
Write-Host "  3. Install Windows (if using ISO)"
Write-Host "  4. Run: .\Configure-VMForDriverDev.ps1 -VMName '$VMName'"
Write-Host ""
