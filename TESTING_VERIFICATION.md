# SafeOps v2.0 - Testing and Verification Guide

**Document Version:** 1.0
**Last Updated:** 2025-12-25
**Status:** Production Ready

---

## Table of Contents

1. [Overview](#overview)
2. [Pre-Testing Requirements](#pre-testing-requirements)
3. [Kernel Driver Verification](#kernel-driver-verification)
4. [Service Verification](#service-verification)
5. [Driver-Service Communication Tests](#driver-service-communication-tests)
6. [Packet Capture Verification](#packet-capture-verification)
7. [Log Verification](#log-verification)
8. [System Integration Tests](#system-integration-tests)
9. [Performance Verification](#performance-verification)
10. [Troubleshooting Tests](#troubleshooting-tests)

---

## Overview

This guide provides step-by-step procedures to verify that the SafeOps kernel driver and userspace service are properly installed, configured, and functioning together. It includes:

- Kernel driver installation and loading verification
- Service startup and status checks
- Inter-process communication (IPC) verification
- Packet capture functionality testing
- Log file integrity checks
- Performance benchmarking
- Network monitoring capabilities

All tests can be performed manually or via automated scripts suitable for CI/CD integration and AI agent testing.

---

## Pre-Testing Requirements

### System Readiness Checklist

Before performing any tests, verify:

```powershell
# Run as Administrator

# 1. Check test signing is enabled
Write-Host "Checking test signing mode..."
bcdedit /enum {current} | findstr testsigning
# Expected: "testsigning             Yes"

# 2. Check Administrator privileges
$isAdmin = ([Security.Principal.WindowsIdentity]::GetCurrent()).Groups -contains 'S-1-5-32-544'
Write-Host "Administrator: $isAdmin"
# Expected: True

# 3. Verify WDK installation
Write-Host "Checking WDK installation..."
$wdkPath = "C:\Program Files (x86)\Windows Kits\10\Include"
if (Test-Path $wdkPath) { Write-Host "✓ WDK found" } else { Write-Host "✗ WDK not found" }

# 4. Check source files exist
$sourceDir = "C:\SafeOps-Firewall-V2\src"
Write-Host "Checking source files..."
if (Test-Path "$sourceDir\kernel_driver\driver.c") { Write-Host "✓ Kernel driver sources found" }
if (Test-Path "$sourceDir\userspace_service\service_main.c") { Write-Host "✓ Service sources found" }
```

### Environment Variables

```powershell
# Verify required paths are in system PATH
$paths = @("C:\Program Files\Git\cmd", "C:\Go\bin", "$env:USERPROFILE\.cargo\bin")
foreach ($path in $paths) {
    $inPath = $env:PATH -like "*$path*"
    Write-Host "$path : $inPath"
}
```

### Service Prerequisites

```powershell
# PostgreSQL must be running
Get-Service postgresql* | Format-Table Name, Status

# Redis must be running
Get-Service Redis | Format-Table Name, Status
```

---

## Kernel Driver Verification

### 1. Build Verification

#### Step 1: Build the Driver

Open x64 Native Tools Command Prompt for VS 2022 (as Administrator):

```cmd
cd C:\SafeOps-Firewall-V2\src\kernel_driver

REM Build in debug mode first
nmake BUILD=debug

REM Verify build succeeded
if exist "obj\amd64\SafeOps.sys" (
    echo ✓ Driver build successful
    dir "obj\amd64\SafeOps.sys"
    dir "obj\amd64\SafeOps.pdb"
) else (
    echo ✗ Driver build failed
    exit /b 1
)
```

**Expected Output:**
```
obj\amd64\SafeOps.sys     - Kernel driver binary (50-200 KB)
obj\amd64\SafeOps.pdb     - Debug symbols (1-5 MB)
obj\amd64\SafeOps.inf     - Driver information file
```

#### Verification Script (PowerShell)

```powershell
# verify_driver_build.ps1

$driverDir = "C:\SafeOps-Firewall-V2\src\kernel_driver"
$outputDir = "$driverDir\obj\amd64"

Write-Host "SafeOps Kernel Driver Build Verification" -ForegroundColor Green
Write-Host "========================================" -ForegroundColor Green

$requiredFiles = @(
    "SafeOps.sys",
    "SafeOps.pdb",
    "SafeOps.inf"
)

$allPresent = $true
foreach ($file in $requiredFiles) {
    $path = "$outputDir\$file"
    if (Test-Path $path) {
        $size = (Get-Item $path).Length / 1KB
        Write-Host "✓ $file ($('{0:F2}' -f $size) KB)" -ForegroundColor Green
    } else {
        Write-Host "✗ $file NOT FOUND" -ForegroundColor Red
        $allPresent = $false
    }
}

if ($allPresent) {
    Write-Host "`nBuild verification PASSED" -ForegroundColor Green
} else {
    Write-Host "`nBuild verification FAILED" -ForegroundColor Red
}
```

### 2. Driver Installation

#### Install the Driver

```cmd
REM Run as Administrator

cd C:\SafeOps-Firewall-V2\src\kernel_driver\obj\amd64

REM Install driver
sc create SafeOpsFilter binPath= "%cd%\SafeOps.sys" type= kernel start= boot

REM Expected output:
REM [SC] CreateService SUCCESS
```

**Verify Installation:**

```cmd
REM List installed driver
sc query SafeOpsFilter

REM Expected output shows:
REM SERVICE_NAME: SafeOpsFilter
REM TYPE        : 10  KERNEL_DRIVER
REM START_TYPE  : 2   BOOT
REM STATE       : 1   STOPPED (or RUNNING if auto-started)
```

#### Verify INF File

```cmd
REM Check driver information file
dir SafeOps.inf

REM View INF file contents (should contain driver metadata)
type SafeOps.inf
```

**Expected content in SafeOps.inf:**
```ini
[Version]
Signature="$WINDOWS NT$"
Class=NetService
ClassGuid={4D36E974-E325-11CE-BFC1-08002BE10318}
Provider=%CompanyName%
DriverVer=2025/12/25,2.0.0.0

[Manufacturer]
%CompanyName%=SafeOpsDriver,NT.6.3,NT.10.0

[SafeOpsDriver.NT.6.3]
%SafeOpsDriverDesc%=Install,SAFEOPS_FILTER

[Install]
CopyFiles=DriverFiles
```

### 3. Driver Loading

#### Load the Driver

```cmd
REM Load the driver into memory
sc start SafeOpsFilter

REM Should see:
REM SERVICE_START_PENDING
REM Then SERVICE_RUNNING
```

#### Verify Driver is Loaded

```powershell
# verify_driver_loaded.ps1

Write-Host "Verifying SafeOps Kernel Driver..." -ForegroundColor Green

# Check via service control
$service = Get-Service -Name SafeOpsFilter -ErrorAction SilentlyContinue
if ($null -ne $service) {
    Write-Host "✓ Service found: $($service.DisplayName)" -ForegroundColor Green
    Write-Host "  Status: $($service.Status)" -ForegroundColor Cyan
    Write-Host "  Start Type: $($service.StartType)" -ForegroundColor Cyan
} else {
    Write-Host "✗ Service not found" -ForegroundColor Red
}

# Check via sc query
$scOutput = sc query SafeOpsFilter 2>&1 | Out-String
if ($scOutput -like "*RUNNING*") {
    Write-Host "✓ Driver is RUNNING" -ForegroundColor Green
} elseif ($scOutput -like "*STOPPED*") {
    Write-Host "✗ Driver is STOPPED" -ForegroundColor Yellow
} else {
    Write-Host "✗ Driver not found in service list" -ForegroundColor Red
}

# Check device in Device Manager (if WMI accessible)
try {
    $device = Get-WmiObject -Class Win32_SystemDriver -Filter "Name='SafeOpsFilter'" -ErrorAction SilentlyContinue
    if ($device) {
        Write-Host "✓ Found in Device Manager: $($device.Description)" -ForegroundColor Green
    }
} catch {
    Write-Host "Note: Device Manager check skipped" -ForegroundColor Yellow
}
```

### 4. Driver Symbol Loading

```cmd
REM Verify debug symbols are available
REM This is important for kernel debugging

dir SafeOps.pdb

REM Copy to symbol cache (optional but recommended)
setx _NT_SYMBOL_PATH "srv*C:\symbols*https://msdl.microsoft.com/download/symbols"
setx _NT_SOURCE_PATH "C:\SafeOps-Firewall-V2\src\kernel_driver"
```

### 5. Kernel Debugger Check (Optional)

If you have WinDbg installed:

```cmd
REM Connect kernel debugger
REM In WinDbg:

REM Check driver is loaded
lm m SafeOps*

REM Expected output:
REM start             end                 module name
REM fffff801`........  fffff801`........   SafeOps    (deferred)

REM Dump driver information
!drvobj SafeOpsFilter

REM Check device objects
!devnode 0 1 SafeOpsFilter
```

---

## Service Verification

### 1. Build Verification

#### Build the Service

Open x64 Native Tools Command Prompt for VS 2022 (as Administrator):

```cmd
cd C:\SafeOps-Firewall-V2\src\userspace_service

REM Build in debug mode
build.cmd debug

REM Verify build succeeded
if exist "build\SafeOpsService.exe" (
    echo ✓ Service build successful
    dir "build\SafeOpsService.exe"
) else (
    echo ✗ Service build failed
    exit /b 1
)
```

**Expected Output:**
```
build\SafeOpsService.exe     - Service executable (500 KB - 2 MB)
build\SafeOpsService.pdb     - Debug symbols (2-10 MB)
```

#### Verification Script (PowerShell)

```powershell
# verify_service_build.ps1

$serviceDir = "C:\SafeOps-Firewall-V2\src\userspace_service"
$outputDir = "$serviceDir\build"

Write-Host "SafeOps Service Build Verification" -ForegroundColor Green
Write-Host "===================================" -ForegroundColor Green

$requiredFiles = @(
    "SafeOpsService.exe",
    "SafeOpsService.pdb"
)

$allPresent = $true
foreach ($file in $requiredFiles) {
    $path = "$outputDir\$file"
    if (Test-Path $path) {
        $size = (Get-Item $path).Length / 1KB
        Write-Host "✓ $file ($('{0:F2}' -f $size) KB)" -ForegroundColor Green
    } else {
        Write-Host "✗ $file NOT FOUND" -ForegroundColor Red
        $allPresent = $false
    }
}

if ($allPresent) {
    Write-Host "`nBuild verification PASSED" -ForegroundColor Green
} else {
    Write-Host "`nBuild verification FAILED" -ForegroundColor Red
}
```

### 2. Service Installation

#### Install the Service

```cmd
REM Run as Administrator

REM Install service
sc create SafeOpsCapture binPath= "C:\SafeOps-Firewall-V2\src\userspace_service\build\SafeOpsService.exe" type= own start= auto

REM Expected output:
REM [SC] CreateService SUCCESS

REM Set service description
sc description SafeOpsCapture "SafeOps packet capture and processing service"

REM Set service dependencies (depends on driver)
sc config SafeOpsCapture depend= SafeOpsFilter
```

**Verify Installation:**

```cmd
sc query SafeOpsCapture

REM Expected output shows:
REM SERVICE_NAME: SafeOpsCapture
REM TYPE        : 10  WIN32_OWN_PROCESS
REM START_TYPE  : 2   AUTOMATIC
REM STATE       : 1   STOPPED (or RUNNING)
```

### 3. Service Startup

#### Start the Service

```cmd
REM Start the service
sc start SafeOpsCapture

REM Monitor startup
timeout /t 2

REM Check status
sc query SafeOpsCapture
```

**Expected Output:**
```
SERVICE_NAME: SafeOpsCapture
        TYPE               : 10  WIN32_OWN_PROCESS
        STATE              : 4  RUNNING
        WIN32_EXIT_CODE    : 0  (0x0)
        SERVICE_EXIT_CODE  : 0  (0x0)
        CHECKPOINT         : 0x0
        WAIT_HINT          : 0x0
```

#### Stop the Service

```cmd
REM Stop the service gracefully
sc stop SafeOpsCapture

REM Verify it stopped
sc query SafeOpsCapture
```

### 4. Service Verification Script

```powershell
# verify_service_running.ps1

Write-Host "SafeOps Service Verification" -ForegroundColor Green
Write-Host "============================" -ForegroundColor Green

# Check via Get-Service
$service = Get-Service -Name SafeOpsCapture -ErrorAction SilentlyContinue
if ($null -ne $service) {
    Write-Host "✓ Service found: $($service.DisplayName)" -ForegroundColor Green
    Write-Host "  Status: $($service.Status)" -ForegroundColor Cyan
    Write-Host "  Start Type: $($service.StartType)" -ForegroundColor Cyan

    if ($service.Status -eq "Running") {
        Write-Host "✓ Service is RUNNING" -ForegroundColor Green
    } else {
        Write-Host "⚠ Service is not running (Status: $($service.Status))" -ForegroundColor Yellow
    }
} else {
    Write-Host "✗ Service not found" -ForegroundColor Red
}

# Check via sc query
$scOutput = sc query SafeOpsCapture 2>&1 | Out-String
if ($scOutput -like "*RUNNING*") {
    Write-Host "✓ Confirmed RUNNING via sc query" -ForegroundColor Green
}

# Check process
$process = Get-Process -Name SafeOpsService -ErrorAction SilentlyContinue
if ($process) {
    Write-Host "✓ Process running (PID: $($process.Id))" -ForegroundColor Green
    Write-Host "  Memory: $($process.WorkingSet / 1MB | Round) MB" -ForegroundColor Cyan
} else {
    Write-Host "⚠ Process not found" -ForegroundColor Yellow
}

# Check executable location
$exePath = "C:\SafeOps-Firewall-V2\src\userspace_service\build\SafeOpsService.exe"
if (Test-Path $exePath) {
    Write-Host "✓ Executable exists at: $exePath" -ForegroundColor Green
} else {
    Write-Host "✗ Executable not found at: $exePath" -ForegroundColor Red
}
```

---

## Driver-Service Communication Tests

### 1. IOCTL Command Testing

Test inter-process communication between driver and service.

```c
// Test IOCTL communication
// File: test_ioctl_communication.c

#include <windows.h>
#include <stdio.h>
#include <setupapi.h>

#pragma comment(lib, "setupapi.lib")
#pragma comment(lib, "kernel32.lib")

// Define IOCTL codes (must match kernel driver definitions)
#define IOCTL_SAFEOPS_GET_STATUS    CTL_CODE(FILE_DEVICE_UNKNOWN, 0x800, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_SAFEOPS_START_CAPTURE CTL_CODE(FILE_DEVICE_UNKNOWN, 0x801, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_SAFEOPS_STOP_CAPTURE  CTL_CODE(FILE_DEVICE_UNKNOWN, 0x802, METHOD_BUFFERED, FILE_ANY_ACCESS)

int main() {
    HANDLE deviceHandle = INVALID_HANDLE_VALUE;
    DWORD bytesReturned = 0;
    CHAR outBuffer[256];

    printf("SafeOps IOCTL Communication Test\n");
    printf("=================================\n\n");

    // Try to open device
    deviceHandle = CreateFileA(
        "\\\\.\\SafeOpsFilter",
        GENERIC_READ | GENERIC_WRITE,
        0,
        NULL,
        OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL,
        NULL
    );

    if (deviceHandle == INVALID_HANDLE_VALUE) {
        printf("FAILED: Could not open device\n");
        printf("Error: %ld\n", GetLastError());
        return 1;
    }

    printf("SUCCESS: Device handle obtained\n\n");

    // Test GET_STATUS IOCTL
    printf("Testing IOCTL_GET_STATUS...\n");
    if (DeviceIoControl(
        deviceHandle,
        IOCTL_SAFEOPS_GET_STATUS,
        NULL, 0,
        outBuffer, sizeof(outBuffer),
        &bytesReturned,
        NULL
    )) {
        printf("SUCCESS: GET_STATUS returned %ld bytes\n", bytesReturned);
    } else {
        printf("FAILED: GET_STATUS error %ld\n", GetLastError());
    }

    // Test START_CAPTURE IOCTL
    printf("\nTesting IOCTL_START_CAPTURE...\n");
    if (DeviceIoControl(
        deviceHandle,
        IOCTL_SAFEOPS_START_CAPTURE,
        NULL, 0,
        outBuffer, sizeof(outBuffer),
        &bytesReturned,
        NULL
    )) {
        printf("SUCCESS: START_CAPTURE returned %ld bytes\n", bytesReturned);
    } else {
        printf("FAILED: START_CAPTURE error %ld\n", GetLastError());
    }

    // Test STOP_CAPTURE IOCTL
    printf("\nTesting IOCTL_STOP_CAPTURE...\n");
    if (DeviceIoControl(
        deviceHandle,
        IOCTL_SAFEOPS_STOP_CAPTURE,
        NULL, 0,
        outBuffer, sizeof(outBuffer),
        &bytesReturned,
        NULL
    )) {
        printf("SUCCESS: STOP_CAPTURE returned %ld bytes\n", bytesReturned);
    } else {
        printf("FAILED: STOP_CAPTURE error %ld\n", GetLastError());
    }

    CloseHandle(deviceHandle);
    printf("\nTest completed\n");
    return 0;
}
```

**Compile and Run:**

```cmd
REM In VS developer command prompt
cl.exe test_ioctl_communication.c /link advapi32.lib kernel32.lib
test_ioctl_communication.exe
```

### 2. Shared Memory Ring Buffer Test

```powershell
# verify_ring_buffer.ps1

Write-Host "Ring Buffer Communication Test" -ForegroundColor Green
Write-Host "==============================" -ForegroundColor Green

# Check if shared memory is accessible
$ringBufferName = "Global\SafeOpsRingBuffer"

Write-Host "Attempting to access ring buffer: $ringBufferName" -ForegroundColor Cyan

# Use CreateFileMapping API indirectly through C# interop
Add-Type -TypeDefinition @"
using System;
using System.Runtime.InteropServices;

public class RingBufferTest {
    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern IntPtr OpenFileMapping(uint dwDesiredAccess, bool bInheritHandle, string lpName);

    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern IntPtr MapViewOfFile(IntPtr hFileMappingObject, uint dwDesiredAccess,
        uint dwFileOffsetHigh, uint dwFileOffsetLow, UIntPtr dwNumberOfBytesToMap);

    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern bool UnmapViewOfFile(IntPtr lpBaseAddress);

    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern bool CloseHandle(IntPtr hObject);

    public static bool TestRingBuffer(string bufferName) {
        try {
            const uint FILE_MAP_READ = 0x4;
            IntPtr fileMapping = OpenFileMapping(FILE_MAP_READ, false, bufferName);

            if (fileMapping == IntPtr.Zero) {
                return false;
            }

            IntPtr buffer = MapViewOfFile(fileMapping, FILE_MAP_READ, 0, 0, UIntPtr.Zero);
            if (buffer != IntPtr.Zero) {
                UnmapViewOfFile(buffer);
                CloseHandle(fileMapping);
                return true;
            }

            CloseHandle(fileMapping);
            return false;
        } catch {
            return false;
        }
    }
}
"@

if ([RingBufferTest]::TestRingBuffer($ringBufferName)) {
    Write-Host "✓ Ring buffer is accessible" -ForegroundColor Green
} else {
    Write-Host "✗ Ring buffer not accessible" -ForegroundColor Red
}
```

---

## Packet Capture Verification

### 1. Basic Packet Capture Test

```powershell
# verify_packet_capture.ps1

Write-Host "Packet Capture Verification" -ForegroundColor Green
Write-Host "===========================" -ForegroundColor Green

# Get network adapters
$adapters = Get-NetAdapter | Where-Object { $_.Status -eq "Up" }

Write-Host "`nNetwork Adapters:" -ForegroundColor Cyan
foreach ($adapter in $adapters) {
    Write-Host "  - $($adapter.Name): $($adapter.MacAddress)" -ForegroundColor Gray
}

# Start the service if not running
$service = Get-Service SafeOpsCapture -ErrorAction SilentlyContinue
if ($service.Status -ne "Running") {
    Write-Host "`nStarting SafeOpsCapture service..." -ForegroundColor Yellow
    Start-Service SafeOpsCapture
    Start-Sleep -Seconds 2
}

# Generate test traffic
Write-Host "`nGenerating test traffic..." -ForegroundColor Cyan
$testIPs = @("8.8.8.8", "1.1.1.1", "github.com")
foreach ($testIP in $testIPs) {
    Write-Host "  Pinging $testIP..."
    ping -n 1 -w 1000 $testIP | Out-Null
    Start-Sleep -Milliseconds 100
}

Write-Host "`nMonitoring network activity..." -ForegroundColor Cyan
Get-NetStat | Select-Object -First 20 | Format-Table

Write-Host "`n✓ Packet capture test completed" -ForegroundColor Green
```

### 2. WinDivert Packet Capture Test

If using WinDivert driver:

```c
// Simple packet capture using WinDivert
// Compile with: cl test_windivert.c /link WinDivert.lib advapi32.lib

#include <winsock2.h>
#include <iphlpapi.h>
#include <stdio.h>

#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "iphlpapi.lib")

int main() {
    PETH_HEADER pEthernetFrame = NULL;
    IPV4_HEADER_PROPERTY ipv4Header;
    TCP_HEADER_PROPERTY tcpHeader;
    HANDLE hDevice = NULL;

    printf("SafeOps Packet Capture Test\n");
    printf("===========================\n\n");

    // Capture a few packets
    printf("Capturing packets... Press Ctrl+C to stop\n\n");

    // This would use actual WinDivert or similar API
    // Implementation depends on packet capture library used

    printf("Packet capture test completed\n");
    return 0;
}
```

### 3. Performance Metrics

```powershell
# test_capture_performance.ps1

Write-Host "Packet Capture Performance Test" -ForegroundColor Green
Write-Host "================================" -ForegroundColor Green

# Get baseline metrics
$before = Get-NetAdapterStatistics | Select-Object -First 1
$beforeTime = Get-Date

Write-Host "`nBaseline network stats captured at $(Get-Date -Format 'HH:mm:ss')" -ForegroundColor Cyan

# Run intense traffic test
Write-Host "Running 30-second traffic test..." -ForegroundColor Yellow

for ($i = 1; $i -le 30; $i++) {
    # Send test packets
    ping -n 1 8.8.8.8 | Out-Null
    if ($i % 10 -eq 0) { Write-Host "  ${i}s..." -NoNewline }
}
Write-Host ""

# Get after metrics
Start-Sleep -Seconds 2
$after = Get-NetAdapterStatistics | Select-Object -First 1
$afterTime = Get-Date
$duration = ($afterTime - $beforeTime).TotalSeconds

Write-Host "`nPerformance Results:" -ForegroundColor Cyan
Write-Host "  Test Duration: $([Math]::Round($duration)) seconds"
Write-Host "  Packets Before: $($before.ReceivedPackets)"
Write-Host "  Packets After: $($after.ReceivedPackets)"
Write-Host "  Packets Captured: $($after.ReceivedPackets - $before.ReceivedPackets)"
Write-Host "  Rate: $([Math]::Round(($after.ReceivedPackets - $before.ReceivedPackets) / $duration)) packets/sec"

Write-Host "`n✓ Performance test completed" -ForegroundColor Green
```

---

## Log Verification

### 1. Check Log Files

```powershell
# verify_logs.ps1

Write-Host "Log File Verification" -ForegroundColor Green
Write-Host "=====================" -ForegroundColor Green

$logDirs = @(
    "C:\SafeOps-Dev\logs",
    "C:\ProgramData\SafeOps\logs",
    "$env:APPDATA\SafeOps\logs",
    "C:\Windows\System32\drivers\etc\SafeOps"
)

foreach ($logDir in $logDirs) {
    Write-Host "`nChecking: $logDir" -ForegroundColor Cyan

    if (Test-Path $logDir) {
        $files = Get-ChildItem $logDir -Filter "*.log" -ErrorAction SilentlyContinue
        if ($files) {
            Write-Host "  ✓ Log directory exists"
            Write-Host "  Files found: $($files.Count)"

            foreach ($file in $files | Select-Object -First 5) {
                $size = $file.Length / 1KB
                $modified = $file.LastWriteTime
                Write-Host "    - $($file.Name) ($([Math]::Round($size)) KB, Modified: $modified)"
            }
        } else {
            Write-Host "  ⚠ No log files found"
        }
    } else {
        Write-Host "  ✗ Directory not found"
    }
}
```

### 2. View Recent Kernel Logs

```powershell
# Get kernel events
Get-WinEvent -LogName System -FilterXPath "*[System[EventID=1000 or EventID=1001]]" -MaxEvents 10 |
    Format-Table TimeCreated, Id, Message
```

### 3. View Service Logs

```powershell
# Get application events for SafeOps
Get-WinEvent -LogName Application -FilterXPath "*[System[Provider[@Name='SafeOpsService'] or Provider[@Name='SafeOpsCapture']]]" -MaxEvents 20 |
    Format-Table TimeCreated, LevelDisplayName, Message
```

### 4. Real-Time Log Monitoring

```powershell
# monitor_logs.ps1

param(
    [int]$RefreshInterval = 5
)

Write-Host "SafeOps Real-Time Log Monitor" -ForegroundColor Green
Write-Host "=============================" -ForegroundColor Green
Write-Host "Refresh interval: ${RefreshInterval}s (Press Ctrl+C to stop)`n" -ForegroundColor Yellow

while ($true) {
    Clear-Host
    Write-Host "SafeOps Real-Time Log Monitor - $(Get-Date -Format 'HH:mm:ss')" -ForegroundColor Green
    Write-Host "======================================================`n"

    # Recent system events
    Write-Host "Recent System Events (SafeOps):" -ForegroundColor Cyan
    Get-WinEvent -LogName System -FilterXPath "*[System[Provider[@Name='SafeOpsDriver']]]" -MaxEvents 5 -ErrorAction SilentlyContinue |
        Format-Table TimeCreated, LevelDisplayName, Message | Out-Host

    # Service status
    Write-Host "`nService Status:" -ForegroundColor Cyan
    Get-Service SafeOpsCapture, SafeOpsFilter -ErrorAction SilentlyContinue | Format-Table Name, Status, StartType

    # Process info
    Write-Host "`nService Process:" -ForegroundColor Cyan
    Get-Process SafeOpsService -ErrorAction SilentlyContinue | Format-Table Name, Id, WorkingSet, CPU

    Write-Host "`nWaiting for next refresh in ${RefreshInterval}s..." -ForegroundColor Yellow
    Start-Sleep -Seconds $RefreshInterval
}
```

---

## System Integration Tests

### 1. Full System Boot Test

```powershell
# test_system_integration.ps1

Write-Host "Full System Integration Test" -ForegroundColor Green
Write-Host "============================" -ForegroundColor Green

$results = @{
    DriverLoaded = $false
    ServiceRunning = $false
    CommunicationWorking = $false
    PacketsCaptured = 0
}

# Test 1: Driver
Write-Host "`n[1/4] Testing kernel driver..." -ForegroundColor Cyan
$driver = Get-Service SafeOpsFilter -ErrorAction SilentlyContinue
if ($driver -and $driver.Status -eq "Running") {
    Write-Host "  ✓ Driver loaded and running"
    $results.DriverLoaded = $true
} else {
    Write-Host "  ✗ Driver not running"
}

# Test 2: Service
Write-Host "`n[2/4] Testing service..." -ForegroundColor Cyan
$service = Get-Service SafeOpsCapture -ErrorAction SilentlyContinue
if ($service -and $service.Status -eq "Running") {
    Write-Host "  ✓ Service running"
    $results.ServiceRunning = $true

    $proc = Get-Process SafeOpsService -ErrorAction SilentlyContinue
    if ($proc) {
        Write-Host "  ✓ Process active (PID: $($proc.Id), Memory: $($proc.WorkingSet / 1MB | Round) MB)"
    }
} else {
    Write-Host "  ✗ Service not running"
}

# Test 3: Communication
Write-Host "`n[3/4] Testing driver-service communication..." -ForegroundColor Cyan
if ($results.DriverLoaded -and $results.ServiceRunning) {
    Write-Host "  ✓ Communication prerequisites met"
    $results.CommunicationWorking = $true
} else {
    Write-Host "  ✗ Communication cannot be tested"
}

# Test 4: Packet capture
Write-Host "`n[4/4] Testing packet capture..." -ForegroundColor Cyan
if ($results.ServiceRunning) {
    Write-Host "  Sending test packets..."
    @("8.8.8.8", "1.1.1.1") | ForEach-Object { ping -n 1 -w 500 $_ | Out-Null }
    Write-Host "  ✓ Test packets sent"
}

# Summary
Write-Host "`n`n=== INTEGRATION TEST SUMMARY ===" -ForegroundColor Green
Write-Host "Driver Loaded:              $(if ($results.DriverLoaded) { 'PASS' } else { 'FAIL' })" -ForegroundColor $(if ($results.DriverLoaded) { 'Green' } else { 'Red' })
Write-Host "Service Running:            $(if ($results.ServiceRunning) { 'PASS' } else { 'FAIL' })" -ForegroundColor $(if ($results.ServiceRunning) { 'Green' } else { 'Red' })
Write-Host "Driver-Service Comm:        $(if ($results.CommunicationWorking) { 'PASS' } else { 'FAIL' })" -ForegroundColor $(if ($results.CommunicationWorking) { 'Green' } else { 'Red' })

$allPass = $results.DriverLoaded -and $results.ServiceRunning -and $results.CommunicationWorking
Write-Host "`nOverall Result:             $(if ($allPass) { 'PASSED' } else { 'FAILED' })" -ForegroundColor $(if ($allPass) { 'Green' } else { 'Red' })
```

---

## Performance Verification

### 1. CPU and Memory Usage

```powershell
# test_performance.ps1

Write-Host "Performance Verification Test" -ForegroundColor Green
Write-Host "=============================" -ForegroundColor Green

# Monitor service process
$service = Get-Process SafeOpsService -ErrorAction SilentlyContinue

if ($service) {
    Write-Host "`nInitial Metrics:" -ForegroundColor Cyan
    Write-Host "  Memory: $($service.WorkingSet / 1MB | Round) MB"
    Write-Host "  CPU Threads: $($service.Threads.Count)"
    Write-Host "  Handles: $($service.Handles)"

    # Load test: Send packets and monitor
    Write-Host "`nRunning load test (60 seconds)..." -ForegroundColor Yellow
    $startMem = $service.WorkingSet
    $startTime = Get-Date

    for ($i = 1; $i -le 6; $i++) {
        # Send traffic
        1..10 | ForEach-Object { ping -n 1 8.8.8.8 | Out-Null }

        # Check memory
        $service.Refresh()
        $currentMem = $service.WorkingSet / 1MB
        $elapsed = ((Get-Date) - $startTime).TotalSeconds

        Write-Host "  ${elapsed}s: Memory = ${currentMem} MB"
        Start-Sleep -Seconds 10
    }

    Write-Host "`nFinal Metrics:" -ForegroundColor Cyan
    $endMem = $service.WorkingSet / 1MB
    $startMemMB = $startMem / 1MB
    Write-Host "  Initial Memory: $([Math]::Round($startMemMB)) MB"
    Write-Host "  Final Memory: $([Math]::Round($endMem)) MB"
    Write-Host "  Memory Growth: $([Math]::Round($endMem - $startMemMB)) MB"
} else {
    Write-Host "✗ SafeOpsService process not found" -ForegroundColor Red
}
```

### 2. Network Performance

```powershell
# test_network_throughput.ps1

Write-Host "Network Throughput Test" -ForegroundColor Green
Write-Host "=======================" -ForegroundColor Green

$adapters = Get-NetAdapter | Where-Object { $_.Status -eq "Up" } | Select-Object -First 1

if ($adapters) {
    Write-Host "Testing on adapter: $($adapters.Name)`n" -ForegroundColor Cyan

    # Get baseline
    $stats1 = Get-NetAdapterStatistics -Name $adapters.Name
    $time1 = Get-Date

    # Send traffic
    Write-Host "Sending test traffic..." -ForegroundColor Yellow
    1..100 | ForEach-Object {
        ping -n 1 8.8.8.8 | Out-Null
    }

    # Get final stats
    Start-Sleep -Seconds 1
    $stats2 = Get-NetAdapterStatistics -Name $adapters.Name
    $time2 = Get-Date
    $duration = ($time2 - $time1).TotalSeconds

    $packetsSent = $stats2.SentPackets - $stats1.SentPackets
    $packetsRecv = $stats2.ReceivedPackets - $stats1.ReceivedPackets

    Write-Host "`nResults:" -ForegroundColor Cyan
    Write-Host "  Duration: $([Math]::Round($duration, 2)) seconds"
    Write-Host "  Packets Sent: $packetsSent"
    Write-Host "  Packets Received: $packetsRecv"
    Write-Host "  Send Rate: $([Math]::Round($packetsSent / $duration)) pps"
    Write-Host "  Receive Rate: $([Math]::Round($packetsRecv / $duration)) pps"
}
```

---

## Troubleshooting Tests

### 1. Driver Load Failure Diagnosis

```powershell
# diagnose_driver_failure.ps1

Write-Host "Driver Load Failure Diagnosis" -ForegroundColor Green
Write-Host "=============================" -ForegroundColor Green

# Check WDK installation
Write-Host "`nChecking WDK installation..." -ForegroundColor Cyan
$wdkPath = "C:\Program Files (x86)\Windows Kits\10"
if (Test-Path $wdkPath) {
    Write-Host "  ✓ WDK found at: $wdkPath"
} else {
    Write-Host "  ✗ WDK not found - reinstall Windows Driver Kit"
}

# Check test signing
Write-Host "`nChecking test signing mode..." -ForegroundColor Cyan
$testSigning = bcdedit /enum {current} | Select-String "testsigning"
if ($testSigning -like "*Yes*") {
    Write-Host "  ✓ Test signing enabled"
} else {
    Write-Host "  ✗ Test signing disabled - run: bcdedit /set testsigning on"
}

# Check driver file signature
Write-Host "`nChecking driver signature..." -ForegroundColor Cyan
$driverPath = "C:\SafeOps-Firewall-V2\src\kernel_driver\obj\amd64\SafeOps.sys"
if (Test-Path $driverPath) {
    $sig = (Get-AuthenticodeSignature $driverPath).Status
    Write-Host "  Signature Status: $sig"
    if ($sig -ne "Valid") {
        Write-Host "  ⚠ Driver is not properly signed"
    }
} else {
    Write-Host "  ✗ Driver file not found at: $driverPath"
}

# Check event log for driver errors
Write-Host "`nRecent kernel errors..." -ForegroundColor Cyan
Get-WinEvent -LogName System -FilterXPath "*[System[(EventID=1000 or EventID=1001 or EventID=7000 or EventID=7001) and TimeCreated[timediff(@SystemTime) <= 3600000]]]" -MaxEvents 5 -ErrorAction SilentlyContinue |
    Format-Table TimeCreated, Id, Message
```

### 2. Service Connectivity Test

```powershell
# diagnose_service_issues.ps1

Write-Host "Service Connectivity Diagnosis" -ForegroundColor Green
Write-Host "==============================" -ForegroundColor Green

# Check if service can communicate with driver
Write-Host "`nTesting service-driver communication..." -ForegroundColor Cyan

# Method 1: Check for open device handles
$proc = Get-Process SafeOpsService -ErrorAction SilentlyContinue
if ($proc) {
    Write-Host "  Process found (PID: $($proc.Id))"

    # Attempt to query service status
    Write-Host "  Querying service status..."

    $service = Get-Service SafeOpsCapture -ErrorAction SilentlyContinue
    if ($service.Status -eq "Running") {
        Write-Host "  ✓ Service is running"
    } else {
        Write-Host "  ✗ Service is not running"

        # Try to start and check for errors
        Write-Host "  Attempting to start service..."
        try {
            Start-Service SafeOpsCapture -ErrorAction Stop
            Write-Host "  ✓ Service started successfully"
        } catch {
            Write-Host "  ✗ Failed to start service: $_"
        }
    }
} else {
    Write-Host "  ✗ SafeOpsService process not found"
}

# Check for resource locks
Write-Host "`nChecking for resource locks..." -ForegroundColor Cyan
netstat -ano | Select-String SafeOpsService | Format-Table
```

---

## Expected Outputs and Behaviors

### Successful Driver Load

```
SERVICE_NAME: SafeOpsFilter
        TYPE               : 10  KERNEL_DRIVER
        STATE              : 4   RUNNING
        WIN32_EXIT_CODE    : 0   (0x0)
        SERVICE_EXIT_CODE  : 0   (0x0)
        CHECKPOINT         : 0x0
        WAIT_HINT          : 0x0
```

### Successful Service Start

```
SERVICE_NAME: SafeOpsCapture
        TYPE               : 10  WIN32_OWN_PROCESS
        STATE              : 4   RUNNING
        WIN32_EXIT_CODE    : 0   (0x0)
        SERVICE_EXIT_CODE  : 0   (0x0)
        CHECKPOINT         : 0x0
        WAIT_HINT          : 0x0
        PROCESS_ID         : 1234
        FLAGS              :
```

### Successful Packet Capture

- Network packets visible in monitoring tools
- Increasing packet counts in statistics
- Consistent memory usage (not growing unbounded)
- CPU usage < 20% at idle, < 80% under load

### Expected Log Entries

```
[INFO] SafeOps Kernel Driver loaded successfully
[INFO] SafeOps Service started at HH:MM:SS
[INFO] Connected to ring buffer at address 0xFFFFXXXX
[INFO] Packet capture enabled on adapter: {GUID}
[INFO] Packets processed: 1000, Dropped: 0
```

---

## Testing Checklist

Use this checklist to verify all components:

- [ ] Test signing mode enabled
- [ ] Driver file exists and is signed
- [ ] Driver installs without errors
- [ ] Driver loads and runs
- [ ] Service executable exists
- [ ] Service installs without errors
- [ ] Service starts successfully
- [ ] Service connects to driver
- [ ] IOCTL commands work
- [ ] Ring buffer accessible
- [ ] Packets captured successfully
- [ ] Log files created and updated
- [ ] Performance metrics acceptable
- [ ] No memory leaks detected
- [ ] All integration tests pass

---

For more detailed debugging, see BUILD_GUIDE.md and INSTALLATION_GUIDE.md.
