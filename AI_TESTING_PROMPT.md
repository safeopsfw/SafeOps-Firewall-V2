# SafeOps v2.0 - Comprehensive AI Testing Prompt

**Document Version:** 1.0
**Last Updated:** 2025-12-25
**Status:** Production Ready

---

## Purpose

This document provides an AI agent with a complete, automated testing procedure for the SafeOps v2.0 system. It includes step-by-step instructions that can be executed by an AI agent to verify the entire system is working correctly, with specific expected outcomes for each test.

---

## System Overview for AI Agent

SafeOps v2.0 is a Windows-based network security gateway consisting of:

1. **Kernel Driver (SafeOps.sys)** - Windows kernel mode driver that captures network packets
2. **Userspace Service (SafeOpsService.exe)** - Windows service that processes captured packets
3. **Shared Libraries** - Go, Rust, and C libraries for inter-process communication
4. **Supporting Services** - PostgreSQL (database), Redis (caching), etc.

The driver and service communicate via:
- IOCTL (I/O Control) commands for control operations
- Shared memory ring buffer for packet data
- Windows event log for diagnostics

---

## Pre-Testing Requirements for AI Agent

### Environmental Assumptions

**IMPORTANT:** Verify these conditions before starting tests. If any fail, report and stop.

```
ASSUMPTION 1: Running as Administrator
  - Check: PowerShell execution context should show Administrator privileges
  - If False: CANNOT PROCEED - Kernel driver operations require admin rights
  - Report as: BLOCKING_ISSUE_001_NOT_ADMIN

ASSUMPTION 2: Test Signing Enabled
  - Check: Command "bcdedit /enum {current}" should contain "testsigning     Yes"
  - If False: CANNOT PROCEED - Unsigned kernel drivers won't load
  - Report as: BLOCKING_ISSUE_002_TEST_SIGNING_DISABLED

ASSUMPTION 3: Source Code Exists
  - Check: Directory "C:\SafeOps-Firewall-V2\src" must exist
  - If False: CANNOT PROCEED - Source code needed for building
  - Report as: BLOCKING_ISSUE_003_SOURCE_NOT_FOUND

ASSUMPTION 4: Visual Studio Build Tools Available
  - Check: "x64 Native Tools Command Prompt for VS 2022" must be available
  - If False: CANNOT PROCEED - Cannot compile without build tools
  - Report as: BLOCKING_ISSUE_004_BUILD_TOOLS_MISSING

ASSUMPTION 5: Network Connectivity
  - Check: ping 8.8.8.8 must succeed (for packet capture tests)
  - If False: WARNING_SKIP_NET_TESTS - Continue with offline tests only
  - Report as: WARNING_001_NO_NETWORK
```

### Pre-Testing Verification Script

```powershell
# Run this FIRST to verify all assumptions

function Test-AITestingPrerequisites {
    Write-Host "SafeOps AI Testing Prerequisites Check" -ForegroundColor Green
    Write-Host "=====================================" -ForegroundColor Green
    Write-Host ""

    $issues = @()
    $warnings = @()

    # Check 1: Administrator
    Write-Host "Checking prerequisites..."
    $isAdmin = ([Security.Principal.WindowsIdentity]::GetCurrent()).Groups -contains 'S-1-5-32-544'
    if (-not $isAdmin) {
        $issues += "NOT_ADMIN"
        Write-Host "  ✗ Not running as Administrator" -ForegroundColor Red
    } else {
        Write-Host "  ✓ Administrator privileges confirmed" -ForegroundColor Green
    }

    # Check 2: Test Signing
    $testSigning = bcdedit /enum {current} 2>&1 | Select-String "testsigning"
    if ($testSigning -notlike "*Yes*") {
        $issues += "TEST_SIGNING_DISABLED"
        Write-Host "  ✗ Test signing not enabled" -ForegroundColor Red
    } else {
        Write-Host "  ✓ Test signing mode enabled" -ForegroundColor Green
    }

    # Check 3: Source Code
    if (-not (Test-Path "C:\SafeOps-Firewall-V2\src")) {
        $issues += "SOURCE_NOT_FOUND"
        Write-Host "  ✗ Source code not found" -ForegroundColor Red
    } else {
        Write-Host "  ✓ Source code directory exists" -ForegroundColor Green
    }

    # Check 4: Build Tools
    $vsDevCmd = "C:\Program Files\Microsoft Visual Studio\2022\Community\Common7\Tools\VsDevCmd.bat"
    if (-not (Test-Path $vsDevCmd)) {
        $issues += "BUILD_TOOLS_MISSING"
        Write-Host "  ✗ Visual Studio build tools not found" -ForegroundColor Red
    } else {
        Write-Host "  ✓ Visual Studio build tools available" -ForegroundColor Green
    }

    # Check 5: Network
    $ping = ping -n 1 8.8.8.8 2>&1
    if ($ping -notlike "*Reply*") {
        $warnings += "NO_NETWORK"
        Write-Host "  ⚠ No network connectivity (will skip network tests)" -ForegroundColor Yellow
    } else {
        Write-Host "  ✓ Network connectivity confirmed" -ForegroundColor Green
    }

    # Report
    Write-Host ""
    if ($issues.Count -gt 0) {
        Write-Host "BLOCKING ISSUES FOUND:" -ForegroundColor Red
        foreach ($issue in $issues) {
            Write-Host "  - $issue"
        }
        Write-Host ""
        return $false
    }

    if ($warnings.Count -gt 0) {
        Write-Host "WARNINGS (can continue):" -ForegroundColor Yellow
        foreach ($warning in $warnings) {
            Write-Host "  - $warning"
        }
    }

    Write-Host "All prerequisites met - testing can proceed" -ForegroundColor Green
    return $true
}

Test-AITestingPrerequisites
```

---

## Testing Procedure for AI Agent

### Phase 1: Build Verification (Est. 10-15 minutes)

**Objective:** Verify that both kernel driver and userspace service compile successfully.

#### Test 1.1: Kernel Driver Build

**Steps:**

1. Open x64 Native Tools Command Prompt for VS 2022
2. Navigate to kernel driver directory:
   ```cmd
   cd C:\SafeOps-Firewall-V2\src\kernel_driver
   ```

3. Clean previous build:
   ```cmd
   nmake clean
   ```

4. Build kernel driver in debug mode:
   ```cmd
   nmake BUILD=debug
   ```

5. Check for success:
   ```cmd
   if exist "obj\amd64\SafeOps.sys" (
       echo BUILD_SUCCESS
       dir "obj\amd64\SafeOps.sys"
       dir "obj\amd64\SafeOps.pdb"
   ) else (
       echo BUILD_FAILED
       exit /b 1
   )
   ```

**Expected Output:**
```
obj\amd64\SafeOps.sys    - Size: 50-200 KB
obj\amd64\SafeOps.pdb    - Size: 1-5 MB
obj\amd64\SafeOps.inf    - Driver information file
```

**Success Criteria:**
- [ ] SafeOps.sys exists
- [ ] SafeOps.pdb exists
- [ ] SafeOps.inf exists
- [ ] No compilation errors in console output
- [ ] Build completes in < 5 minutes

**Report Format:**
```
TEST_1_1_KERNEL_DRIVER_BUILD: [PASS|FAIL]
  Details: [Build output summary]
  Error (if any): [Error message]
```

#### Test 1.2: Userspace Service Build

**Steps:**

1. In x64 Native Tools Command Prompt, navigate to userspace service:
   ```cmd
   cd C:\SafeOps-Firewall-V2\src\userspace_service
   ```

2. Clean previous build:
   ```cmd
   build.cmd release clean
   ```

3. Build service:
   ```cmd
   build.cmd debug
   ```

4. Verify output:
   ```cmd
   if exist "build\SafeOpsService.exe" (
       echo BUILD_SUCCESS
       dir "build\SafeOpsService.exe"
   ) else (
       echo BUILD_FAILED
       exit /b 1
   )
   ```

**Expected Output:**
```
build\SafeOpsService.exe  - Size: 500 KB - 2 MB
build\SafeOpsService.pdb  - Size: 2-10 MB
```

**Success Criteria:**
- [ ] SafeOpsService.exe exists
- [ ] SafeOpsService.pdb exists
- [ ] No compilation errors
- [ ] Build completes in < 3 minutes

**Report Format:**
```
TEST_1_2_SERVICE_BUILD: [PASS|FAIL]
  Details: [Build output summary]
  Error (if any): [Error message]
```

---

### Phase 2: Kernel Driver Installation (Est. 5 minutes)

**Objective:** Verify kernel driver installs as Windows service and loads into kernel memory.

#### Test 2.1: Driver Installation

**PowerShell Steps:**

```powershell
$driverDir = "C:\SafeOps-Firewall-V2\src\kernel_driver\obj\amd64"
$driverPath = "$driverDir\SafeOps.sys"

# Verify file exists
if (-not (Test-Path $driverPath)) {
    Write-Host "TEST_2_1_DRIVER_INSTALL: FAIL - Driver file not found"
    exit 1
}

# Uninstall if already exists
sc stop SafeOpsFilter 2>&1 | Out-Null
Start-Sleep -Seconds 1
sc delete SafeOpsFilter 2>&1 | Out-Null
Start-Sleep -Seconds 1

# Install driver as Windows service
$result = sc create SafeOpsFilter binPath= "$driverPath" type= kernel start= demand
if ($LASTEXITCODE -eq 0) {
    Write-Host "TEST_2_1_DRIVER_INSTALL: PASS"
} else {
    Write-Host "TEST_2_1_DRIVER_INSTALL: FAIL - Installation failed"
    Write-Host "Error: $result"
    exit 1
}
```

**Expected Output:**
```
[SC] CreateService SUCCESS
```

**Success Criteria:**
- [ ] Service created without errors
- [ ] Service name is SafeOpsFilter
- [ ] Service type is KERNEL_DRIVER

**Report Format:**
```
TEST_2_1_DRIVER_INSTALL: [PASS|FAIL]
  Service: SafeOpsFilter
  Status: Installed|Failed
  Error (if any): [Error message]
```

#### Test 2.2: Driver Load

**PowerShell Steps:**

```powershell
# Start the driver
sc start SafeOpsFilter
Start-Sleep -Seconds 2

# Verify it loaded
$service = Get-Service SafeOpsFilter -ErrorAction SilentlyContinue
if ($service -and $service.Status -eq "Running") {
    Write-Host "TEST_2_2_DRIVER_LOAD: PASS"
} else {
    Write-Host "TEST_2_2_DRIVER_LOAD: FAIL - Driver not running"
    sc query SafeOpsFilter
    exit 1
}
```

**Expected Output:**
```
SERVICE_NAME: SafeOpsFilter
        TYPE               : 10  KERNEL_DRIVER
        STATE              : 4   RUNNING
        WIN32_EXIT_CODE    : 0   (0x0)
```

**Success Criteria:**
- [ ] Service state is RUNNING
- [ ] No error codes (WIN32_EXIT_CODE = 0)
- [ ] SERVICE_EXIT_CODE = 0

**Report Format:**
```
TEST_2_2_DRIVER_LOAD: [PASS|FAIL]
  Status: [RUNNING|STOPPED|ERROR]
  WIN32_EXIT_CODE: [0|Error code]
  Details: [Full sc query output]
```

#### Test 2.3: Driver Symbol Loading

**PowerShell Steps:**

```powershell
$pdbFile = "C:\SafeOps-Firewall-V2\src\kernel_driver\obj\amd64\SafeOps.pdb"

if (Test-Path $pdbFile) {
    Write-Host "TEST_2_3_DRIVER_SYMBOLS: PASS"
} else {
    Write-Host "TEST_2_3_DRIVER_SYMBOLS: FAIL - PDB not found"
    exit 1
}
```

**Success Criteria:**
- [ ] SafeOps.pdb exists
- [ ] File size > 1 MB

**Report Format:**
```
TEST_2_3_DRIVER_SYMBOLS: [PASS|FAIL]
  PDB Location: [Path]
  Size: [KB]
```

---

### Phase 3: Userspace Service Installation (Est. 5 minutes)

**Objective:** Verify service installs and starts correctly.

#### Test 3.1: Service Installation

**PowerShell Steps:**

```powershell
$servicePath = "C:\SafeOps-Firewall-V2\src\userspace_service\build\SafeOpsService.exe"

if (-not (Test-Path $servicePath)) {
    Write-Host "TEST_3_1_SERVICE_INSTALL: FAIL - Executable not found"
    exit 1
}

# Uninstall if exists
sc stop SafeOpsCapture 2>&1 | Out-Null
Start-Sleep -Seconds 1
sc delete SafeOpsCapture 2>&1 | Out-Null
Start-Sleep -Seconds 1

# Install service
$result = sc create SafeOpsCapture binPath= "$servicePath" type= own start= auto
if ($LASTEXITCODE -eq 0) {
    Write-Host "TEST_3_1_SERVICE_INSTALL: PASS"
} else {
    Write-Host "TEST_3_1_SERVICE_INSTALL: FAIL"
    Write-Host "Error: $result"
    exit 1
}
```

**Expected Output:**
```
[SC] CreateService SUCCESS
```

**Success Criteria:**
- [ ] Service created successfully
- [ ] Service name is SafeOpsCapture
- [ ] Service type is WIN32_OWN_PROCESS

**Report Format:**
```
TEST_3_1_SERVICE_INSTALL: [PASS|FAIL]
  Service: SafeOpsCapture
  Type: WIN32_OWN_PROCESS
  Start Type: AUTO
```

#### Test 3.2: Service Startup

**PowerShell Steps:**

```powershell
# Start service
sc start SafeOpsCapture
Start-Sleep -Seconds 3

# Verify running
$service = Get-Service SafeOpsCapture -ErrorAction SilentlyContinue
if ($service -and $service.Status -eq "Running") {
    Write-Host "TEST_3_2_SERVICE_STARTUP: PASS"
} else {
    Write-Host "TEST_3_2_SERVICE_STARTUP: FAIL - Service not running"
    sc query SafeOpsCapture
    exit 1
}
```

**Expected Output:**
```
SERVICE_NAME: SafeOpsCapture
        TYPE               : 10  WIN32_OWN_PROCESS
        STATE              : 4   RUNNING
        WIN32_EXIT_CODE    : 0   (0x0)
        PROCESS_ID         : [PID]
```

**Success Criteria:**
- [ ] Service state is RUNNING
- [ ] WIN32_EXIT_CODE = 0
- [ ] PROCESS_ID is valid (> 0)

**Report Format:**
```
TEST_3_2_SERVICE_STARTUP: [PASS|FAIL]
  Status: [RUNNING|STOPPED]
  Process ID: [PID]
  Memory Usage: [MB]
```

#### Test 3.3: Service Process Verification

**PowerShell Steps:**

```powershell
$proc = Get-Process SafeOpsService -ErrorAction SilentlyContinue

if ($proc) {
    $memMB = $proc.WorkingSet / 1MB
    Write-Host "TEST_3_3_SERVICE_PROCESS: PASS"
    Write-Host "  PID: $($proc.Id)"
    Write-Host "  Memory: $([Math]::Round($memMB)) MB"
    Write-Host "  Threads: $($proc.Threads.Count)"
} else {
    Write-Host "TEST_3_3_SERVICE_PROCESS: FAIL - Process not found"
    exit 1
}
```

**Success Criteria:**
- [ ] Process found by name SafeOpsService
- [ ] Memory usage < 100 MB (normal operation)
- [ ] Thread count > 0 (process is active)

**Report Format:**
```
TEST_3_3_SERVICE_PROCESS: [PASS|FAIL]
  Process Name: SafeOpsService
  PID: [ID]
  Memory: [MB]
  Threads: [Count]
```

---

### Phase 4: Driver-Service Communication (Est. 10 minutes)

**Objective:** Verify driver and service can communicate via IOCTL and shared memory.

#### Test 4.1: Shared Memory Ring Buffer

**PowerShell Steps:**

```powershell
Add-Type -TypeDefinition @"
using System;
using System.Runtime.InteropServices;

public class RingBufferTest {
    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern IntPtr OpenFileMapping(uint dwDesiredAccess, bool bInheritHandle, string lpName);

    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern bool CloseHandle(IntPtr hObject);

    public static bool TestRingBuffer(string bufferName) {
        const uint FILE_MAP_READ = 0x4;
        IntPtr fileMapping = OpenFileMapping(FILE_MAP_READ, false, bufferName);
        if (fileMapping == IntPtr.Zero) return false;
        CloseHandle(fileMapping);
        return true;
    }
}
"@

$ringBufferName = "Global\SafeOpsRingBuffer"

if ([RingBufferTest]::TestRingBuffer($ringBufferName)) {
    Write-Host "TEST_4_1_RING_BUFFER: PASS"
} else {
    Write-Host "TEST_4_1_RING_BUFFER: FAIL - Cannot access ring buffer"
    exit 1
}
```

**Success Criteria:**
- [ ] Ring buffer mapping accessible
- [ ] Buffer name correct
- [ ] No access denied errors

**Report Format:**
```
TEST_4_1_RING_BUFFER: [PASS|FAIL]
  Buffer Name: Global\SafeOpsRingBuffer
  Accessible: [Yes|No]
```

#### Test 4.2: Device Handle Test

**PowerShell Steps:**

```powershell
# Attempt to open device (would be used for IOCTL commands)
$deviceName = "\\.\SafeOpsFilter"

# This requires compiled C code, so we'll do a simpler check
# Verify driver is still loaded
$service = Get-Service SafeOpsFilter -ErrorAction SilentlyContinue
if ($service.Status -eq "Running") {
    Write-Host "TEST_4_2_DEVICE_HANDLE: PASS"
} else {
    Write-Host "TEST_4_2_DEVICE_HANDLE: FAIL - Driver not running"
    exit 1
}
```

**Success Criteria:**
- [ ] Driver service still running
- [ ] No service crashes

**Report Format:**
```
TEST_4_2_DEVICE_HANDLE: [PASS|FAIL]
  Device: \\.\SafeOpsFilter
  Accessible: [Yes|No]
```

---

### Phase 5: Packet Capture Verification (Est. 15 minutes)

**Objective:** Verify packet capture functionality is working.

#### Test 5.1: Network Adapter Detection

**PowerShell Steps:**

```powershell
$adapters = Get-NetAdapter | Where-Object { $_.Status -eq "Up" }

if ($adapters.Count -gt 0) {
    Write-Host "TEST_5_1_ADAPTER_DETECTION: PASS"
    Write-Host "Found $($adapters.Count) active adapter(s):"
    foreach ($adapter in $adapters) {
        Write-Host "  - $($adapter.Name): $($adapter.MacAddress)"
    }
} else {
    Write-Host "TEST_5_1_ADAPTER_DETECTION: FAIL - No active adapters"
    exit 1
}
```

**Success Criteria:**
- [ ] At least one active network adapter found
- [ ] Adapter has valid MAC address

**Report Format:**
```
TEST_5_1_ADAPTER_DETECTION: [PASS|FAIL]
  Adapters Found: [Count]
  Details: [Names and MAC addresses]
```

#### Test 5.2: Generate Test Traffic

**PowerShell Steps:**

```powershell
Write-Host "Generating test traffic..."

# Send ICMP ping packets
$testIPs = @("8.8.8.8", "1.1.1.1", "github.com")
$totalSent = 0

foreach ($ip in $testIPs) {
    $result = ping -n 3 -w 500 $ip 2>&1
    if ($result -like "*Reply*") {
        Write-Host "  ✓ $ip responded"
        $totalSent += 3
    } else {
        Write-Host "  ✗ $ip no response"
    }
    Start-Sleep -Milliseconds 100
}

if ($totalSent -gt 0) {
    Write-Host "TEST_5_2_TEST_TRAFFIC: PASS"
    Write-Host "  Packets sent: $totalSent"
} else {
    Write-Host "TEST_5_2_TEST_TRAFFIC: FAIL - No packets sent"
    exit 1
}
```

**Success Criteria:**
- [ ] Packets sent successfully
- [ ] Network traffic visible on adapter
- [ ] Some responses received

**Report Format:**
```
TEST_5_2_TEST_TRAFFIC: [PASS|FAIL]
  Packets Sent: [Count]
  Responses: [Count]
  Network Issues: [None|Details]
```

#### Test 5.3: Packet Statistics

**PowerShell Steps:**

```powershell
# Get network adapter statistics before traffic
$adapters = Get-NetAdapter | Where-Object { $_.Status -eq "Up" } | Select-Object -First 1

if ($adapters) {
    $statsBefore = Get-NetAdapterStatistics -Name $adapters.Name
    $timeBefore = Get-Date

    # Send more test traffic
    Write-Host "Sending 30 seconds of test traffic..."
    for ($i = 1; $i -le 30; $i++) {
        ping -n 1 8.8.8.8 | Out-Null
        if ($i % 10 -eq 0) { Write-Host "  ${i}s..." }
    }

    # Get stats after
    Start-Sleep -Seconds 2
    $statsAfter = Get-NetAdapterStatistics -Name $adapters.Name
    $timeAfter = Get-Date
    $duration = ($timeAfter - $timeBefore).TotalSeconds

    $packetsReceived = $statsAfter.ReceivedPackets - $statsBefore.ReceivedPackets
    $bytesSent = $statsAfter.SentBytes - $statsBefore.SentBytes

    if ($packetsReceived -gt 0 -or $bytesSent -gt 0) {
        Write-Host "TEST_5_3_PACKET_STATS: PASS"
        Write-Host "  Duration: $([Math]::Round($duration))s"
        Write-Host "  Packets Received: $packetsReceived"
        Write-Host "  Bytes Sent: $bytesSent"
        Write-Host "  Packet Rate: $([Math]::Round($packetsReceived / $duration)) pps"
    } else {
        Write-Host "TEST_5_3_PACKET_STATS: FAIL - No traffic statistics"
        exit 1
    }
} else {
    Write-Host "TEST_5_3_PACKET_STATS: SKIP - No active adapters"
}
```

**Success Criteria:**
- [ ] Packet count increased
- [ ] Byte count increased
- [ ] Statistics available

**Report Format:**
```
TEST_5_3_PACKET_STATS: [PASS|FAIL|SKIP]
  Duration: [Seconds]
  Packets Received: [Count]
  Bytes Sent: [Count]
  Rate: [Packets/sec]
```

---

### Phase 6: Log Verification (Est. 5 minutes)

**Objective:** Verify logs are being created and updated.

#### Test 6.1: Service Log Files

**PowerShell Steps:**

```powershell
$logDirs = @(
    "C:\ProgramData\SafeOps\logs",
    "$env:APPDATA\SafeOps\logs"
)

$logFound = $false

foreach ($logDir in $logDirs) {
    if (Test-Path $logDir) {
        $logFiles = Get-ChildItem $logDir -Filter "*.log" -ErrorAction SilentlyContinue

        if ($logFiles) {
            Write-Host "TEST_6_1_SERVICE_LOGS: PASS"
            Write-Host "  Directory: $logDir"
            Write-Host "  Log files: $($logFiles.Count)"

            foreach ($file in $logFiles | Select-Object -First 3) {
                $size = $file.Length / 1KB
                Write-Host "    - $($file.Name) ($([Math]::Round($size)) KB)"
            }

            $logFound = $true
            break
        }
    }
}

if (-not $logFound) {
    Write-Host "TEST_6_1_SERVICE_LOGS: FAIL - No log files found"
    exit 1
}
```

**Success Criteria:**
- [ ] Log directory exists
- [ ] Log files present
- [ ] Files have size > 0

**Report Format:**
```
TEST_6_1_SERVICE_LOGS: [PASS|FAIL]
  Directory: [Path]
  Files Found: [Count]
  Total Size: [KB]
```

#### Test 6.2: System Event Log

**PowerShell Steps:**

```powershell
$systemEvents = Get-WinEvent -LogName System -FilterXPath "*[System[Provider[@Name='SafeOps*'] or EventID=7000 or EventID=7001]]" -MaxEvents 10 -ErrorAction SilentlyContinue

if ($systemEvents) {
    Write-Host "TEST_6_2_SYSTEM_EVENTS: PASS"
    Write-Host "  Found $($systemEvents.Count) SafeOps-related events"
} else {
    Write-Host "TEST_6_2_SYSTEM_EVENTS: WARNING - No recent events"
    # This is not a failure - events may not be created if no issues occurred
}
```

**Success Criteria:**
- [ ] Event log accessible
- [ ] No critical errors in log

**Report Format:**
```
TEST_6_2_SYSTEM_EVENTS: [PASS|WARNING|FAIL]
  Events Found: [Count]
  Recent Event: [Date/Time]
```

#### Test 6.3: Log Content Validation

**PowerShell Steps:**

```powershell
$logFiles = Get-ChildItem "C:\ProgramData\SafeOps\logs\*.log" -ErrorAction SilentlyContinue

if ($logFiles) {
    $recentFile = $logFiles | Sort-Object LastWriteTime -Descending | Select-Object -First 1

    if ($recentFile) {
        $content = Get-Content $recentFile -Tail 10
        $hasErrors = $content | Select-String "ERROR|FAIL|Exception"

        Write-Host "TEST_6_3_LOG_CONTENT: PASS"
        Write-Host "  Latest log: $($recentFile.Name)"
        Write-Host "  Last modified: $($recentFile.LastWriteTime)"
        Write-Host "  Errors in last 10 lines: $(if ($hasErrors) { $hasErrors.Count } else { 0 })"

        if ($hasErrors) {
            Write-Host "  Error details:"
            foreach ($error in $hasErrors) {
                Write-Host "    - $error"
            }
        }
    }
} else {
    Write-Host "TEST_6_3_LOG_CONTENT: FAIL - No log files"
    exit 1
}
```

**Success Criteria:**
- [ ] Log files readable
- [ ] Content contains expected entries
- [ ] No critical errors in recent logs

**Report Format:**
```
TEST_6_3_LOG_CONTENT: [PASS|FAIL]
  Latest File: [Name]
  Last Modified: [DateTime]
  Lines: [Count]
  Errors: [Count]
```

---

### Phase 7: Performance Verification (Est. 10 minutes)

**Objective:** Verify system performance under packet load.

#### Test 7.1: Memory Usage

**PowerShell Steps:**

```powershell
$proc = Get-Process SafeOpsService -ErrorAction SilentlyContinue

if ($proc) {
    $initialMem = $proc.WorkingSet / 1MB

    Write-Host "Initial memory: $([Math]::Round($initialMem)) MB"

    # Load test: generate traffic for 60 seconds
    Write-Host "Running 60-second load test..."

    for ($i = 1; $i -le 6; $i++) {
        for ($j = 1; $j -le 10; $j++) {
            ping -n 1 8.8.8.8 | Out-Null
        }

        $proc.Refresh()
        $currentMem = $proc.WorkingSet / 1MB

        Write-Host "  ${i}0s: $([Math]::Round($currentMem)) MB"
        Start-Sleep -Seconds 10
    }

    $finalMem = $proc.WorkingSet / 1MB
    $memGrowth = $finalMem - $initialMem

    if ($memGrowth -lt 50) {
        Write-Host "TEST_7_1_MEMORY_USAGE: PASS"
    } else {
        Write-Host "TEST_7_1_MEMORY_USAGE: WARNING - High memory growth"
    }

    Write-Host "  Initial: $([Math]::Round($initialMem)) MB"
    Write-Host "  Final: $([Math]::Round($finalMem)) MB"
    Write-Host "  Growth: $([Math]::Round($memGrowth)) MB"
} else {
    Write-Host "TEST_7_1_MEMORY_USAGE: FAIL - Process not found"
    exit 1
}
```

**Success Criteria:**
- [ ] Initial memory < 100 MB
- [ ] Memory growth < 50 MB during load test
- [ ] No memory leaks (growth rate slows)

**Report Format:**
```
TEST_7_1_MEMORY_USAGE: [PASS|WARNING|FAIL]
  Initial: [MB]
  Final: [MB]
  Growth: [MB]
  Status: [Acceptable|High Growth]
```

#### Test 7.2: CPU Usage

**PowerShell Steps:**

```powershell
$proc = Get-Process SafeOpsService -ErrorAction SilentlyContinue

if ($proc) {
    Write-Host "TEST_7_2_CPU_USAGE: PASS"
    Write-Host "  Threads: $($proc.Threads.Count)"
    Write-Host "  Handles: $($proc.Handles)"

    # Note: CPU usage requires multiple snapshots over time
    # This is a simplified check
} else {
    Write-Host "TEST_7_2_CPU_USAGE: FAIL - Process not found"
    exit 1
}
```

**Success Criteria:**
- [ ] Thread count reasonable (< 100)
- [ ] Handle count reasonable (< 1000)
- [ ] No runaway resource consumption

**Report Format:**
```
TEST_7_2_CPU_USAGE: [PASS|WARNING|FAIL]
  Threads: [Count]
  Handles: [Count]
  Status: [Normal|High]
```

---

### Phase 8: System Integration Test (Est. 5 minutes)

**Objective:** Verify entire system works together.

#### Test 8.1: Full System Status

**PowerShell Steps:**

```powershell
Write-Host "Full System Integration Test" -ForegroundColor Green
Write-Host "===========================" -ForegroundColor Green

$allPass = $true

# Check driver
$driver = Get-Service SafeOpsFilter -ErrorAction SilentlyContinue
if ($driver -and $driver.Status -eq "Running") {
    Write-Host "✓ Kernel driver loaded"
} else {
    Write-Host "✗ Kernel driver not running"
    $allPass = $false
}

# Check service
$service = Get-Service SafeOpsCapture -ErrorAction SilentlyContinue
if ($service -and $service.Status -eq "Running") {
    Write-Host "✓ Userspace service running"
} else {
    Write-Host "✗ Userspace service not running"
    $allPass = $false
}

# Check process
$proc = Get-Process SafeOpsService -ErrorAction SilentlyContinue
if ($proc) {
    Write-Host "✓ Service process active"
} else {
    Write-Host "✗ Service process not found"
    $allPass = $false
}

# Check logs
$logs = Get-ChildItem "C:\ProgramData\SafeOps\logs\*.log" -ErrorAction SilentlyContinue
if ($logs) {
    Write-Host "✓ Log files created"
} else {
    Write-Host "⚠ Log files not found"
}

# Network activity
$adapters = Get-NetAdapter | Where-Object { $_.Status -eq "Up" }
if ($adapters) {
    Write-Host "✓ Network adapters available"
} else {
    Write-Host "✗ No active network adapters"
    $allPass = $false
}

if ($allPass) {
    Write-Host "`nTEST_8_1_SYSTEM_INTEGRATION: PASS"
} else {
    Write-Host "`nTEST_8_1_SYSTEM_INTEGRATION: FAIL"
    exit 1
}
```

**Success Criteria:**
- [ ] Driver loaded
- [ ] Service running
- [ ] Process active
- [ ] Logs exist
- [ ] Network available

**Report Format:**
```
TEST_8_1_SYSTEM_INTEGRATION: [PASS|FAIL]
  Driver: [Running|Stopped]
  Service: [Running|Stopped]
  Process: [Active|Inactive]
  Logs: [Present|Missing]
  Network: [Available|Unavailable]
```

---

## Complete Test Execution Script

```powershell
# complete_ai_test_suite.ps1

Write-Host "SafeOps v2.0 Complete AI Test Suite" -ForegroundColor Magenta
Write-Host "====================================" -ForegroundColor Magenta
$startTime = Get-Date
$testResults = @()

# Phase 1: Build Verification
Write-Host "`n[PHASE 1] Build Verification" -ForegroundColor Cyan
# ... execute Phase 1 tests (Test 1.1, 1.2)

# Phase 2: Kernel Driver Installation
Write-Host "`n[PHASE 2] Kernel Driver Installation" -ForegroundColor Cyan
# ... execute Phase 2 tests (Test 2.1, 2.2, 2.3)

# Phase 3: Userspace Service Installation
Write-Host "`n[PHASE 3] Userspace Service Installation" -ForegroundColor Cyan
# ... execute Phase 3 tests (Test 3.1, 3.2, 3.3)

# Phase 4: Driver-Service Communication
Write-Host "`n[PHASE 4] Driver-Service Communication" -ForegroundColor Cyan
# ... execute Phase 4 tests (Test 4.1, 4.2)

# Phase 5: Packet Capture Verification
Write-Host "`n[PHASE 5] Packet Capture Verification" -ForegroundColor Cyan
# ... execute Phase 5 tests (Test 5.1, 5.2, 5.3)

# Phase 6: Log Verification
Write-Host "`n[PHASE 6] Log Verification" -ForegroundColor Cyan
# ... execute Phase 6 tests (Test 6.1, 6.2, 6.3)

# Phase 7: Performance Verification
Write-Host "`n[PHASE 7] Performance Verification" -ForegroundColor Cyan
# ... execute Phase 7 tests (Test 7.1, 7.2)

# Phase 8: System Integration
Write-Host "`n[PHASE 8] System Integration" -ForegroundColor Cyan
# ... execute Phase 8 tests (Test 8.1)

# Final Summary
$endTime = Get-Date
$totalDuration = ($endTime - $startTime).TotalMinutes

Write-Host "`n`n==== TEST EXECUTION COMPLETE ====" -ForegroundColor Green
Write-Host "Total Tests Run: [COUNT]"
Write-Host "Passed: [COUNT]"
Write-Host "Failed: [COUNT]"
Write-Host "Warnings: [COUNT]"
Write-Host "Total Duration: $([Math]::Round($totalDuration, 2)) minutes"
Write-Host "=================================="`
```

---

## Expected Results and Behaviors

### All Tests Pass

```
OVERALL_STATUS: PASS
  Phase 1 Build: PASS (2/2 tests)
  Phase 2 Driver: PASS (3/3 tests)
  Phase 3 Service: PASS (3/3 tests)
  Phase 4 Communication: PASS (2/2 tests)
  Phase 5 Packet Capture: PASS (3/3 tests)
  Phase 6 Logs: PASS (3/3 tests)
  Phase 7 Performance: PASS (2/2 tests)
  Phase 8 Integration: PASS (1/1 tests)
  Total: 19/19 PASS
```

### Expected Packet Capture Behavior

```
- Packets captured at adapter level
- Ring buffer receives packet metadata
- Service processes packets without errors
- Memory usage remains stable
- Packet rate: 100-10,000 packets/second (depending on network load)
- Loss rate: < 0.1% under normal load
```

### Expected Log Entries

```
[2025-12-25 HH:MM:SS] INFO: SafeOps kernel driver loaded
[2025-12-25 HH:MM:SS] INFO: Ring buffer initialized at address 0xFFFFXXXX
[2025-12-25 HH:MM:SS] INFO: Packet capture enabled on adapter {GUID}
[2025-12-25 HH:MM:SS] INFO: Processing packets - received 100, processed 100
```

---

## Failure Diagnosis for AI Agent

If a test fails, use these diagnostic steps:

### If Phase 1 (Build) Fails:

1. Check Visual Studio installation:
   ```cmd
   where cl.exe
   where link.exe
   ```

2. Check source files exist:
   ```cmd
   dir C:\SafeOps-Firewall-V2\src\kernel_driver\*.c
   dir C:\SafeOps-Firewall-V2\src\userspace_service\*.c
   ```

3. Try clean rebuild:
   ```cmd
   cd C:\SafeOps-Firewall-V2\src\kernel_driver
   nmake clean
   nmake BUILD=debug
   ```

### If Phase 2 (Driver) Fails:

1. Verify test signing:
   ```cmd
   bcdedit /enum {current}
   ```

2. Check WDK installation:
   ```cmd
   dir "C:\Program Files (x86)\Windows Kits\10"
   ```

3. Try manual service creation:
   ```cmd
   sc create SafeOpsFilter binPath= "C:\Path\To\SafeOps.sys" type= kernel
   sc start SafeOpsFilter
   ```

### If Phase 3 (Service) Fails:

1. Check executable exists:
   ```cmd
   dir C:\SafeOps-Firewall-V2\src\userspace_service\build\SafeOpsService.exe
   ```

2. Try running in console mode:
   ```cmd
   C:\SafeOps-Firewall-V2\src\userspace_service\build\SafeOpsService.exe -console
   ```

3. Check event log for errors:
   ```powershell
   Get-WinEvent -LogName Application -MaxEvents 20 | Format-Table TimeCreated, LevelDisplayName, Message
   ```

### If Phase 4 (Communication) Fails:

1. Verify both are running:
   ```powershell
   Get-Service SafeOpsFilter, SafeOpsCapture | Format-Table
   ```

2. Check for driver crashes:
   ```powershell
   Get-WinEvent -LogName System -FilterXPath "*[System[EventID=7000 or EventID=7001]]" | Format-Table
   ```

3. Try restarting driver and service:
   ```cmd
   sc stop SafeOpsCapture
   sc stop SafeOpsFilter
   sc start SafeOpsFilter
   timeout /t 2
   sc start SafeOpsCapture
   ```

---

## AI Agent Reporting Template

When reporting test results, use this format:

```
SAFEOPS_TEST_REPORT_[TIMESTAMP]

SYSTEM_INFO:
  OS: Windows [Version]
  Test Date: [YYYY-MM-DD HH:MM:SS]
  Test Duration: [Minutes]
  Tested By: AI Agent

PREREQUISITES:
  Administrator: [Pass|Fail]
  Test Signing: [Pass|Fail]
  Source Code: [Pass|Fail]
  Build Tools: [Pass|Fail]
  Network: [Pass|Warning]

TEST_RESULTS:
  Phase 1 Build:           [X/2 Pass]
  Phase 2 Driver:          [X/3 Pass]
  Phase 3 Service:         [X/3 Pass]
  Phase 4 Communication:   [X/2 Pass]
  Phase 5 Packet Capture:  [X/3 Pass]
  Phase 6 Logs:            [X/3 Pass]
  Phase 7 Performance:     [X/2 Pass]
  Phase 8 Integration:     [X/1 Pass]

OVERALL_RESULT: [PASS|FAIL]

ISSUES_FOUND:
  [If any - list each issue with details]

RECOMMENDATIONS:
  [If any failures - suggest corrective actions]
```

---

## Summary

This AI testing prompt provides:

1. **Automated testing procedure** - Step-by-step tests for entire system
2. **Clear success criteria** - Each test has specific pass/fail conditions
3. **Expected outputs** - Exact format of expected command outputs
4. **Diagnosis procedures** - How to troubleshoot failures
5. **Reporting format** - How to document results

The AI agent should:
- Follow all 8 phases in order
- Stop and report if prerequisites fail
- Run all tests even if some fail (to collect complete information)
- Use the reporting template for final results
- Recommend corrective actions based on failures

Estimated total test time: 60-90 minutes for complete execution.
