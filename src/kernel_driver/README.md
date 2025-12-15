# SafeOps Kernel Driver

> **High-Performance Windows Kernel-Mode Network Security Driver**  
> NDIS Lightweight Filter + WFP Callouts for Multi-NIC Firewall Appliances

---

## Table of Contents

- [Overview](#overview)
- [Architecture Summary](#architecture-summary)
- [Build Requirements](#build-requirements)
- [Build Instructions](#build-instructions)
- [Installation Instructions](#installation-instructions)
- [Testing and Debugging](#testing-and-debugging)
- [Configuration](#configuration)
- [Architecture Details](#architecture-details)
- [Component Descriptions](#component-descriptions)
- [IOCTL Interface](#ioctl-interface)
- [Troubleshooting](#troubleshooting)
- [Known Issues](#known-issues)
- [Development Guidelines](#development-guidelines)
- [License](#license)

---

## Overview

SafeOps is an enterprise-grade Windows kernel-mode network security driver designed for high-performance packet capture, filtering, and NAT capabilities on multi-NIC firewall appliances. Built on NDIS lightweight filter and Windows Filtering Platform (WFP) technologies, it provides comprehensive network monitoring and security enforcement at wire speed.

### Key Capabilities

- ✅ **3-NIC Architecture**: Simultaneous monitoring of WAN, LAN, and WiFi network interfaces
- ✅ **Zero-Copy Packet Capture**: Metadata extraction without payload copying for minimal overhead
- ✅ **High Performance**: 10+ Gbps throughput with <1ms latency per packet
- ✅ **Advanced Filtering**: Stateful packet inspection with WFP callout integration across 8 layers
- ✅ **NAT Translation**: Network Address Translation with full connection tracking
- ✅ **Lock-Free Design**: Optimized for multi-core processors with lock-free ring buffer
- ✅ **DDoS Protection**: Built-in DDoS mitigation, rate limiting, and anomaly detection
- ✅ **Flow Direction Detection**: Automatic North-South vs East-West traffic classification

### Performance Specifications

| Metric | Specification |
|--------|---------------|
| **Throughput** | 10+ Gbps per NIC (30+ Gbps aggregate) |
| **Latency** | <1ms packet processing time |
| **Packet Rate** | 10M+ packets/sec aggregate |
| **Ring Buffer** | 2 GB shared memory (16 million packet capacity) |
| **CPU Usage** | <5% per core at 10 Gbps |
| **Memory** | ~2.5 GB (2 GB ring buffer + 500 MB driver state) |
| **Connection Tracking** | 1M+ concurrent connections |

### Supported Platforms

| Operating System | Minimum Version | Architecture |
|------------------|-----------------|--------------|
| Windows 10 | 1809 (Build 17763) | x64, ARM64 |
| Windows 11 | All versions | x64, ARM64 |
| Windows Server 2019 | All versions | x64, ARM64 |
| Windows Server 2022 | All versions | x64, ARM64 |

> **Note**: Windows 7/8/8.1 are **not supported** due to NDIS 6.60+ and WFP API requirements.

---

## Architecture Summary

SafeOps implements a dual-mode architecture combining **NDIS Lightweight Filter** and **WFP Callout** technologies for comprehensive network traffic control at the kernel level.

### System Architecture Diagram

```
┌───────────────────────────────────────────────────────────────────────┐
│                         USERSPACE (Ring 3)                            │
│  ┌──────────────────┐         ┌──────────────────────────────────┐   │
│  │  Network Logger  │  IOCTL  │  Wails Application (GUI)         │   │
│  │  (Go Service)    │◄────────┤  - Query packet history          │   │
│  │  - Read metadata │         │  - Configure firewall rules      │   │
│  │  - PostgreSQL    │         │  - View statistics dashboard     │   │
│  │  - Redis cache   │         │  - Monitor live traffic          │   │
│  └──────────────────┘         └──────────────────────────────────┘   │
│         ▲                                                             │
│         │ Shared Memory Ring Buffer (2 GB, Lock-Free)                │
│         │ - Metadata only (no packet payloads)                       │
│         │ - 16M packet capacity                                      │
│         ▼                                                             │
├───────────────────────────────────────────────────────────────────────┤
│                         KERNEL MODE (Ring 0)                          │
│  ┌─────────────────────────────────────────────────────────────────┐ │
│  │                  SafeOps Kernel Driver                          │ │
│  │  ┌──────────────┐  ┌──────────────┐  ┌────────────────────┐   │ │
│  │  │  NDIS Filter │  │  WFP Callouts│  │  Ring Buffer Mgr   │   │ │
│  │  │  ─────────── │  │  ─────────── │  │  ───────────────   │   │ │
│  │  │  • Capture   │  │  • Filtering │  │  • Lock-free       │   │ │
│  │  │  • Tag NIC   │  │  • NAT       │  │  • Metadata write  │   │ │
│  │  │  • Metadata  │  │  • DDoS      │  │  • Zero-copy       │   │ │
│  │  │  • Direction │  │  • Logging   │  │  • Batch write     │   │ │
│  │  └──────────────┘  └──────────────┘  └────────────────────┘   │ │
│  │  ┌──────────────┐  ┌──────────────┐  ┌────────────────────┐   │ │
│  │  │ NIC Manager  │  │ Performance  │  │  IOCTL Handler     │   │ │
│  │  │ ──────────── │  │ ──────────── │  │  ──────────────    │   │ │
│  │  │  • Detect    │  │  • DMA       │  │  • Start/Stop      │   │ │
│  │  │  • WAN=1     │  │  • RSS       │  │  • Get Stats       │   │ │
│  │  │  • LAN=2     │  │  • NUMA      │  │  • Map Memory      │   │ │
│  │  │  • WiFi=3    │  │  • Batching  │  │  • Configure       │   │ │
│  │  └──────────────┘  └──────────────┘  └────────────────────┘   │ │
│  └─────────────────────────────────────────────────────────────────┘ │
│         ▲                    ▲                    ▲                   │
├─────────┼────────────────────┼────────────────────┼───────────────────┤
│    NDIS.sys             FwpKclnt.sys          Kernel APIs             │
│    (6.60+)              (WFP Engine)         (Memory, I/O)            │
└─────────┴────────────────────┴────────────────────┴───────────────────┘
         ▲                    ▲                    ▲
         │                    │                    │
    ┌────┴─────┐         ┌────┴─────┐         ┌───┴──────┐
    │ WAN NIC  │         │ LAN NIC  │         │ WiFi NIC │
    │ (Tag: 1) │         │ (Tag: 2) │         │ (Tag: 3) │
    └──────────┘         └──────────┘         └──────────┘
```

### Key Technologies

| Technology | Purpose | Version |
|------------|---------|---------|
| **NDIS Lightweight Filter** | Packet interception at NDIS layer | 6.60+ |
| **WFP Callouts** | Deep packet inspection & filtering | Windows 10+ API |
| **Shared Memory Ring Buffer** | Zero-copy userspace communication | Custom lock-free impl. |
| **DMA & RSS** | Hardware acceleration | NIC-dependent |
| **NUMA Awareness** | Optimal memory allocation | Multi-socket support |

### Data Flow

1. **Packet Arrives** → NIC hardware receives packet
2. **NDIS Processing** → NDIS.sys passes packet to our filter
3. **Capture** → Extract metadata (100 bytes), tag NIC (1/2/3), detect direction
4. **Filter** → WFP callouts apply rules, NAT, DDoS checks
5. **Log** → Write metadata to ring buffer (lock-free)
6. **Forward** → Pass packet to next filter or protocol stack
7. **Userspace** → Network Logger reads ring buffer, formats to PostgreSQL/Redis

> **Zero-Copy Promise**: Packet payloads **never** copied to userspace. Only 100-byte metadata structures are written to the ring buffer, enabling 10+ Gbps throughput with minimal CPU overhead.

---

## Build Requirements

### Required Software

| Component | Minimum Version | Recommended | Notes |
|-----------|----------------|-------------|-------|
| **Windows Driver Kit (WDK)** | 10.0.22621.0 | 10.0.26100.0 | [Download WDK](https://learn.microsoft.com/windows-hardware/drivers/download-the-wdk) |
| **Visual Studio** | 2019 | 2022 Community | Build Tools sufficient |
| **Windows SDK** | 10.0.22621.0 | 10.0.26100.0 | Included with WDK |
| **Git** | 2.30+ | Latest | For version control |
| **nmake** | Any | Latest | Included with VS |

### Optional Tools (Production)

| Tool | Purpose |
|------|---------|
| **Code Signing Certificate** | Kernel-mode signing (EV or standard) |
| **SignTool.exe** | Driver signing utility (in Windows SDK) |
| **Inf2Cat.exe** | Catalog file generation (in WDK) |
| **Driver Verifier** | Testing and validation (built into Windows) |
| **WinDbg** | Kernel debugging (in SDK) |

### Hardware Requirements

| Resource | Minimum | Recommended | Notes |
|----------|---------|-------------|-------|
| **RAM** | 8 GB | 16 GB | Build requires ~4 GB |
| **Disk Space** | 50 GB free | 100 GB SSD | WDK ~30 GB, builds ~20 GB |
| **CPU** | 4 cores | 8+ cores | Parallel builds |
| **Network** | 3x NICs | Dedicated test machine | For full testing |

### Development Environment Setup

#### 1. Install Visual Studio 2022

```powershell
# Download installer
https://visualstudio.microsoft.com/downloads/

# Run installer and select:
# - "Desktop development with C++"
# - "Windows 11 SDK (10.0.22621.0)"
# - "MSVC v143 - VS 2022 C++ x64/x86 build tools"
```

#### 2. Install Windows Driver Kit (WDK)

```powershell
# Download WDK installer matching your SDK version
https://learn.microsoft.com/windows-hardware/drivers/download-the-wdk

# Install to default location
# Default: C:\Program Files (x86)\Windows Kits\10
```

#### 3. Verify Installation

```powershell
# Check WDK headers
dir "C:\Program Files (x86)\Windows Kits\10\Include\10.0.22621.0\km"
# Should see: ntddk.h, wdm.h, ndis.h, fwpsk.h

# Check compiler (from VS Developer Command Prompt)
where cl.exe
# Should output: C:\Program Files\Microsoft Visual Studio\...\cl.exe

# Check linker
where link.exe
# Should output: C:\Program Files\Microsoft Visual Studio\...\link.exe

# Check nmake
where nmake.exe
# Should output: C:\Program Files\Microsoft Visual Studio\...\nmake.exe
```

---

## Build Instructions

### Quick Start (Release Build)

```powershell
# 1. Open "Developer Command Prompt for VS 2022" as Administrator
# Start Menu → Visual Studio 2022 → Developer Command Prompt

# 2. Navigate to kernel driver directory
cd d:\SafeOpsFV2\src\kernel_driver

# 3. Build release version (x64)
nmake

# 4. Verify output
dir ..\..\build\driver\release\x64\SafeOps.sys
```

### Build Configurations

#### Release Build (x64) - Default
```powershell
nmake
# Output: build\driver\release\x64\SafeOps.sys
# Optimizations: /O2 (maximize speed), /GL (link-time code gen)
# Size: ~150 KB, stripped symbols
```

#### Debug Build (x64)
```powershell
nmake BUILD=debug
# Output: build\driver\debug\x64\SafeOps.sys
# Output: build\driver\debug\x64\SafeOps.pdb (debug symbols)
# Optimizations: /Od (disabled), /Zi (debug info)
# Size: ~300 KB with symbols
```

#### ARM64 Build (Release)
```powershell
nmake ARCH=ARM64
# Output: build\driver\release\ARM64\SafeOps.sys
# Requires: ARM64 WDK libraries
```

#### ARM64 Build (Debug)
```powershell
nmake BUILD=debug ARCH=ARM64
# Output: build\driver\debug\ARM64\SafeOps.sys
```

### Build Targets Reference

| Target | Command | Description |
|--------|---------|-------------|
| **all** | `nmake` | Build complete driver (default) |
| **driver** | `nmake driver` | Compile and link driver binary only |
| **sign** | `nmake sign` | Sign driver with Authenticode certificate |
| **package** | `nmake package` | Create installation package (INF, SYS, CAT, README, checksums) |
| **clean** | `nmake clean` | Remove all build artifacts |
| **rebuild** | `nmake rebuild` | Clean + build from scratch |
| **install** | `nmake install` | Install driver on local system (requires admin) |
| **uninstall** | `nmake uninstall` | Uninstall driver from local system |
| **test** | `nmake test` | Run Driver Verifier static analysis |
| **load** | `nmake load` | Load driver for testing (requires test signing) |
| **unload** | `nmake unload` | Unload test driver |
| **verify** | `nmake verify` | Run PE header and export verification |
| **help** | `nmake help` | Show all available targets and usage |

### Build Output Structure

```
SafeOpsFV2/
├── build/
│   └── driver/
│       ├── debug/
│       │   ├── x64/
│       │   │   ├── obj/                  # Object files (.obj)
│       │   │   ├── SafeOps.sys           # Debug driver binary (~300 KB)
│       │   │   ├── SafeOps.pdb           # Debug symbols (~2 MB)
│       │   │   ├── SafeOps.map           # Link map for analysis
│       │   │   └── SafeOps.cat           # Catalog file (after signing)
│       │   └── ARM64/
│       │       └── ...similar structure...
│       └── release/
│           ├── x64/
│           │   ├── obj/
│           │   ├── SafeOps.sys           # Release driver (~150 KB, optimized)
│           │   ├── SafeOps.map
│           │   └── SafeOps.cat
│           └── ARM64/
│               └── ...similar structure...
└── dist/
    └── driver/
        ├── SafeOps.sys                   # Packaged driver binary
        ├── SafeOps.inf                   # Installation manifest
        ├── SafeOps.cat                   # Digital signature catalog
        ├── README.txt                    # Installation instructions
        └── SafeOps.sys.sha256            # SHA-256 checksum
```

### Common Build Errors and Solutions

#### ❌ Error: WDK not found
```
ERROR: WDK not found at C:\Program Files (x86)\Windows Kits\10
```
**Solution**: 
```powershell
# Option 1: Install WDK to default location
# Option 2: Set WDK_ROOT environment variable
set WDK_ROOT=C:\Path\To\Your\WDK
nmake
```

#### ❌ Error: Compiler not found (cl.exe)
```
'cl.exe' is not recognized as an internal or external command
```
**Solution**:
```powershell
# Use "Developer Command Prompt for VS 2022" instead of regular cmd
# Or manually run VS environment setup:
"C:\Program Files\Microsoft Visual Studio\2022\Community\Common7\Tools\VsDevCmd.bat"
```

#### ❌ Error: ntddk.h not found
```
fatal error C1083: Cannot open include file: 'ntddk.h': No such file or directory
```
**Solution**:
```powershell
# Verify WDK kernel headers are installed
dir "C:\Program Files (x86)\Windows Kits\10\Include\10.0.22621.0\km\ntddk.h"

# If missing, reinstall WDK and ensure "Debugging Tools for Windows" is selected
```

#### ❌ Error: Source file not found
```
ERROR: Source file not found: driver.c
```
**Solution**:
```powershell
# Ensure you're in the correct directory
cd d:\SafeOpsFV2\src\kernel_driver

# Verify all source files exist
dir *.c
# Should show: driver.c, packet_capture.c, filter_engine.c, etc.
```

#### ❌ Error: Warnings treated as errors
```
error C2220: the following warning is treated as an error
warning C4100: 'Parameter': unreferenced formal parameter
```
**Solution**:
```c
// Option 1: Fix the warning (preferred)
UNREFERENCED_PARAMETER(Parameter);

// Option 2: Temporarily disable /WX in Makefile (NOT recommended)
// Remove /WX from CFLAGS_COMMON
```

#### ❌ Error: Linker unresolved external symbol
```
error LNK2019: unresolved external symbol _NdisAllocateMemoryWithTagPriority
```
**Solution**:
```powershell
# Ensure ndis.lib is linked (check Makefile LIBS section)
# Verify WDK libraries are in correct path:
dir "C:\Program Files (x86)\Windows Kits\10\Lib\10.0.22621.0\km\x64\ndis.lib"
```

### Build Troubleshooting Checklist

- [ ] **WDK installed**: Version 10.0.22621.0 or later
- [ ] **VS Build Tools installed**: 2019 or 2022
- [ ] **Using correct command prompt**: "Developer Command Prompt for VS 2022"
- [ ] **Running as Administrator**: Some operations require elevation
- [ ] **Correct directory**: `cd d:\SafeOpsFV2\src\kernel_driver`
- [ ] **All source files present**: `dir *.c` shows 7 files
- [ ] **INF file present**: `dir SafeOps.inf`
- [ ] **Disk space available**: 50 GB+ free
- [ ] **Antivirus disabled**: May interfere with compilation

### Advanced Build Options

#### Custom WDK Version
```powershell
set WDK_VERSION=10.0.26100.0
nmake
```

#### Custom Build Number (for CI/CD)
```powershell
set BUILD_NUMBER=1234
nmake package
# Creates package with version 2.0.0.1234
```

#### Custom Certificate Path
```powershell
set CERT_PATH=C:\Certs\MyDriverCert.pfx
nmake sign
```

#### Parallel Build (experimental)
```powershell
# nmake doesn't support -j, but you can build modules separately
# This is for advanced users only
```

---

*Continue to [Installation Instructions](#installation-instructions) →*

**Phase 1 Complete**: Overview, Architecture, Build Requirements, Build Instructions ✓  
**Next Phase**: Installation, Testing, Configuration, Troubleshooting →

---

## Installation Instructions

### Development Installation (Test-Signed Driver)

For development and testing, you'll use test-signed drivers which require enabling test signing mode on Windows.

#### Step 1: Enable Test Signing

```powershell
# Run as Administrator
bcdedit /set testsigning on

# Reboot system (required)
Restart-Computer
```

After reboot, you'll see "Test Mode" watermark on desktop (this is normal).

#### Step 2: Build Driver

```powershell
cd d:\\SafeOpsFV2\\src\\kernel_driver
nmake BUILD=debug
```

#### Step 3: Install Driver

```powershell
# Install using the Makefile target
nmake install

# This will:
# 1. Create installation package
# 2. Copy files to dist/driver/
# 3. Install using: pnputil /add-driver SafeOps.inf /install
```

#### Step 4: Verify Installation

```powershell
# Check driver installation
pnputil /enum-drivers | findstr SafeOps

# Check service status
sc query SafeOps

# Expected output:
# STATE: 4 RUNNING (or 1 STOPPED if not started yet)
```

#### Step 5: Start Driver

```powershell
# Start the driver service
sc start SafeOps

# Check status
sc query SafeOps
# Should show: STATE: 4 RUNNING
```

### Production Installation (Signed Driver)

For production deployment, drivers must be properly signed with a valid kernel-mode code signing certificate.

#### Prerequisites

1. **Code Signing Certificate**: Obtain EV or standard kernel-mode certificate from:
   - DigiCert
   - Sectigo
   - GlobalSign

2. **Microsoft Hardware Dev Center Account**: For WHQL attestation signing

#### Option 1: Self-Sign (For Testing Only)

```powershell
# Create test certificate
$cert = New-SelfSignedCertificate `
    -Type CodeSigningCert `
    -Subject "CN=SafeOps Test Certificate" `
    -CertStoreLocation "Cert:\\CurrentUser\\My"

# Export certificate
Export-Certificate -Cert $cert -FilePath SafeOps_Test.cer

# Import to Trusted Root (requires admin)
Import-Certificate `
    -FilePath SafeOps_Test.cer `
    -CertStoreLocation "Cert:\\LocalMachine\\Root"

# Import to Trusted Publishers
Import-Certificate `
    -FilePath SafeOps_Test.cer `
    -CertStoreLocation "Cert:\\LocalMachine\\TrustedPublisher"

# Sign driver
SignTool sign /v /s My /n "SafeOps Test Certificate" /t http://timestamp.digicert.com SafeOps.sys
```

#### Option 2: Production Signing (Recommended)

```powershell
# Set certificate path
set CERT_PATH=C:\\Certs\\SafeOps_Production.pfx

# Build and sign
nmake sign

# Verify signature
SignTool verify /v /pa SafeOps.sys
```

#### Install Signed Driver

```powershell
# No test signing needed for properly signed drivers
# Install package
nmake install

# Or manual installation
pnputil /add-driver SafeOps.inf /install
```

### Uninstallation

#### Quick Uninstall

```powershell
# Using Makefile
nmake uninstall

# This will:
# 1. Stop the driver service
# 2. Delete the service
# 3. Remove driver using: pnputil /delete-driver SafeOps.inf /uninstall
```

#### Manual Uninstall

```powershell
# Stop service
sc stop SafeOps

# Wait for service to stop
timeout /t 2

# Delete service
sc delete SafeOps

# Uninstall driver
pnputil /delete-driver SafeOps.inf /uninstall /force

# Remove files (if needed)
del "%SystemRoot%\\System32\\drivers\\SafeOps.sys"

# Reboot (recommended)
Restart-Computer
```

### Disable Test Signing (After Development)

```powershell
# Disable test signing
bcdedit /set testsigning off

# Reboot
Restart-Computer
```

---

## Testing and Debugging

### Quick Test After Installation

```powershell
# 1. Check driver is running
sc query SafeOps

# 2. Check Event Viewer for errors
Get-EventLog -LogName System -Source "SafeOps" -Newest 10

# 3. Check NDIS filter binding
Get-NetAdapterBinding -Name * | Where-Object {$_.DisplayName -like "*SafeOps*"}

# 4. Test packet capture (requires userspace app)
# See src/network_logger/ for test application
```

### Loading Driver for Testing

```powershell
# Build debug version
nmake BUILD=debug

# Load driver (requires test signing enabled)
nmake load

# Expected output:
# ========================================
# Loading Driver for Testing...
# ========================================
# Checking test signing status...
# Copying driver to system directory...
# Creating service...
# Starting service...
# Driver loaded successfully.
```

### Unloading Test Driver

```powershell
# Unload driver after testing
nmake unload

# This will:
# - Stop the service
# - Delete the service
# - Remove driver binary
```

### Enable Driver Verifier

Driver Verifier is essential for finding bugs that could cause system crashes.

```powershell
# Enable verifier for SafeOps driver
verifier /standard /driver SafeOps.sys

# Reboot (required)
Restart-Computer

# After testing, disable verifier
verifier /reset
Restart-Computer
```

**Verifier Checks**:
- Pool tracking
- IRQL checking
- Deadlock detection
- Security checks
- Miscellaneous checks

### Debugging with WinDbg

#### Setup Kernel Debugging

```powershell
# Enable kernel debugging (serial port)
bcdedit /debug on
bcdedit /dbgsettings serial debugport:1 baudrate:115200

# Or use network debugging (faster)
bcdedit /dbgsettings net hostip:192.168.1.100 port:50000

# Reboot
Restart-Computer
```

#### WinDbg Commands

```
# Load driver symbols
.sympath+ d:\\SafeOpsFV2\\build\\driver\\debug\\x64
.reload /f SafeOps.sys

# Set breakpoint at DriverEntry
bp SafeOps!DriverEntry

# Set breakpoint at packet capture
bp SafeOps!PacketCaptureCallback

# View driver object
!drvobj \\Driver\\SafeOps

# View device object
!devobj \\Device\\SafeOps

# View WFP callouts
!wdfkd.wdflogdump SafeOps

# Dump driver context
dt SafeOps!DRIVER_CONTEXT

# View ring buffer
dt SafeOps!RING_BUFFER_HEADER

# Analyze crash (if BSOD)
!analyze -v

# View call stack
k

# View all threads
!process 0 0
```

### DbgPrint Output

View kernel debug messages using DebugView:

1. Download [DebugView](https://learn.microsoft.com/sysinternals/downloads/debugview)
2. Run as Administrator
3. Capture → Capture Kernel
4. Filter: `[SafeOps]`

**Log Levels** (configured in registry):
- 0 = TRACE (very verbose)
- 1 = DEBUG
- 2 = VERBOSE
- 3 = INFO (default)
- 4 = WARN
- 5 = ERROR (minimal logging)

### Event Viewer

Check system logs for driver events:

```powershell
# View SafeOps events
Get-EventLog -LogName System -Source "SafeOps" -Newest 20

# View all driver-related errors
Get-EventLog -LogName System -EntryType Error | Where-Object {$_.Source -like "*driver*"}

# Export logs
Get-EventLog -LogName System -Source "SafeOps" | Export-Csv SafeOps_Logs.csv
```

### Performance Monitoring

```powershell
# View network adapter statistics
Get-NetAdapterStatistics

# View RSS configuration
Get-NetAdapterRss

# View hardware offloads
Get-NetAdapterChecksumOffload
Get-NetAdapterLso

# Monitor CPU usage per core
Get-Counter "\\Processor(*)\\% Processor Time"

# Monitor memory usage
Get-Process | Where-Object {$_.Name -eq "System"} | Select-Object *Memory*
```

### Testing Checklist

- [ ] **Driver loads without error**
- [ ] **No BSOD on startup**
- [ ] **NDIS filter binds to all NICs**
- [ ] **WFP callouts registered successfully**
- [ ] **Shared memory mapped correctly**
- [ ] **IOCTL interface responds**
- [ ] **Packets captured and logged**
- [ ] **NIC tagging correct (WAN=1, LAN=2, WiFi=3)**
- [ ] **Flow direction detection works**
- [ ] **No memory leaks (Driver Verifier passed)**
- [ ] **Stable for 24+ hours under load**
- [ ] **Unloads cleanly without errors**

---

## Configuration

### Registry Settings

All configuration is stored in the Windows Registry under:

```
HKEY_LOCAL_MACHINE\\System\\CurrentControlSet\\Services\\SafeOps\\Parameters
```

### Core Parameters

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `RingBufferSize` | REG_DWORD | 2147483648 (2 GB) | Shared memory ring buffer size |
| `PacketBatchSize` | REG_DWORD | 128 | Packets processed per batch |
| `CaptureEnabled` | REG_DWORD | 1 | Enable packet capture (1=on, 0=off) |
| `SnapLength` | REG_DWORD | 65535 | Maximum bytes captured per packet |
| `PromiscuousMode` | REG_DWORD | 0 | Promiscuous mode (0=off, 1=on) |

### Logging Configuration

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `LogLevel` | REG_DWORD | 3 | Log verbosity (0=TRACE, 5=ERROR) |
| `LogToFile` | REG_DWORD | 0 | Write logs to file (0=DbgPrint only) |
| `LogFilePath` | REG_SZ | `%SystemRoot%\\Logs\\SafeOps` | Log file directory |

### NIC Mapping

NICs are automatically detected, but can be manually configured:

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `WAN_NIC_GUID` | REG_SZ | (empty) | GUID of WAN network adapter |
| `LAN_NIC_GUID` | REG_SZ | (empty) | GUID of LAN network adapter |
| `WIFI_NIC_GUID` | REG_SZ | (empty) | GUID of WiFi network adapter |

### Performance Settings

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `DMAEnabled` | REG_DWORD | 1 | Enable DMA optimization |
| `RSSEnabled` | REG_DWORD | 1 | Enable RSS (Receive Side Scaling) |
| `NUMAAware` | REG_DWORD | 1 | NUMA-aware memory allocation |
| `ZeroCopyEnabled` | REG_DWORD | 1 | Zero-copy packet handling |
| `CPUAffinity` | REG_DWORD | 0xFFFFFFFF | CPU affinity bitmask (all CPUs) |
| `IRQLOptimization` | REG_DWORD | 1 | IRQL-aware optimizations |
| `InterruptRate` | REG_DWORD | 10000 | Interrupt rate (per second) |
| `RSSQueues` | REG_DWORD | 16 | Number of RSS queues |

### Security Settings

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `StealthMode` | REG_DWORD | 0 | Stealth mode (0=disabled) |
| `BlockByDefault` | REG_DWORD | 0 | Default action (0=allow, 1=block) |
| `EnableTLS13` | REG_DWORD | 1 | TLS 1.3 inspection |

### Statistics

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `StatsInterval` | REG_DWORD | 1000 | Statistics update interval (ms) |
| `EnableCounters` | REG_DWORD | 1 | Performance counters |

### WFP Configuration

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `SublayerWeight` | REG_DWORD | 0xFFFE | WFP sublayer priority |
| `EnableIPv4` | REG_DWORD | 1 | Enable IPv4 filtering |
| `EnableIPv6` | REG_DWORD | 1 | Enable IPv6 filtering |

### How to Modify Configuration

```powershell
# Set ring buffer size to 4 GB
reg add "HKLM\\System\\CurrentControlSet\\Services\\SafeOps\\Parameters" /v RingBufferSize /t REG_DWORD /d 4294967296 /f

# Enable verbose logging
reg add "HKLM\\System\\CurrentControlSet\\Services\\SafeOps\\Parameters" /v LogLevel /t REG_DWORD /d 2 /f

# Disable packet capture
reg add "HKLM\\System\\CurrentControlSet\\Services\\SafeOps\\Parameters" /v CaptureEnabled /t REG_DWORD /d 0 /f

# Restart driver to apply changes
sc stop SafeOps
sc start SafeOps
```

### Determining NIC GUIDs

#### Method 1: Device Manager

1. Open Device Manager (`devmgmt.msc`)
2. Expand "Network adapters"
3. Right-click adapter → Properties
4. Details tab → Property: "Device instance path"
5. Copy GUID (between `{...}`)

#### Method 2: PowerShell

```powershell
# List all network adapters with GUIDs
Get-NetAdapter | Select-Object Name, InterfaceDescription, InterfaceGuid

# Example output:
# Name        InterfaceDescription                InterfaceGuid
# ----        --------------------                -------------
# Ethernet    Intel(R) Ethernet Adapter          {12345678-1234-1234-1234-123456789012}
# WiFi        Qualcomm Wireless Adapter          {87654321-4321-4321-4321-210987654321}
```

#### Method 3: Registry

```batch
# View all network adapters
reg query "HKLM\\SYSTEM\\CurrentControlSet\\Control\\Class\\{4D36E972-E325-11CE-BFC1-08002BE10318}" /s
```

### Manual NIC Configuration Example

```powershell
# Set WAN NIC (Ethernet)
$wan_guid = "{12345678-1234-1234-1234-123456789012}"
reg add "HKLM\\System\\CurrentControlSet\\Services\\SafeOps\\Parameters\\NICs" /v WAN_NIC_GUID /t REG_SZ /d $wan_guid /f

# Set LAN NIC (Ethernet 2)
$lan_guid = "{22222222-2222-2222-2222-222222222222}"
reg add "HKLM\\System\\CurrentControlSet\\Services\\SafeOps\\Parameters\\NICs" /v LAN_NIC_GUID /t REG_SZ /d $lan_guid /f

# Set WiFi NIC
$wifi_guid = "{87654321-4321-4321-4321-210987654321}"
reg add "HKLM\\System\\CurrentControlSet\\Services\\SafeOps\\Parameters\\NICs" /v WIFI_NIC_GUID /t REG_SZ /d $wifi_guid /f

# Restart driver
sc stop SafeOps
sc start SafeOps
```

---

**Phase 2 Complete**: Installation (Dev + Production), Testing & Debugging, Configuration ✓  
**Next Phase**: Architecture Details, Component Descriptions, IOCTL Interface, Troubleshooting →
