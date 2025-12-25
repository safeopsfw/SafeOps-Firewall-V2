# SafeOps v2.0 - Complete Usage Guide

## Table of Contents
1. [Project Overview](#project-overview)
2. [Directory Structure](#directory-structure)
3. [Component Architecture](#component-architecture)
4. [Building the Project](#building-the-project)
5. [Installation and Deployment](#installation-and-deployment)
6. [Configuration](#configuration)
7. [Operation and Monitoring](#operation-and-monitoring)
8. [Troubleshooting](#troubleshooting)

---

## Project Overview

SafeOps v2.0 is a comprehensive network security monitoring system consisting of:
- **Kernel Driver** (SafeOps.sys) - High-performance packet capture using NDIS filters
- **Userspace Service** (SafeOpsService.exe) - Windows service for log management
- **Management Console** - Web-based UI for monitoring and configuration
- **Database Backend** - PostgreSQL for storing threats and analytics

**Key Capabilities:**
- Real-time network packet capture at kernel level
- Integration with Suricata IDS for threat detection
- Threat intelligence correlation and enrichment
- Comprehensive logging and rotation management
- RESTful API for external integrations

---

## Directory Structure

```
D:\SafeOpsFV2\
├── src\
│   ├── kernel_driver\          # Kernel mode driver (SafeOps.sys)
│   │   ├── driver.c            # Main driver entry point
│   │   ├── driver.h            # Master header with all definitions
│   │   ├── packet_capture.c    # NDIS filter implementation
│   │   ├── filter_engine.c     # WFP callout engine
│   │   ├── shared_memory.c     # Ring buffer for userspace communication
│   │   ├── ioctl_handler.c     # Device control interface
│   │   ├── nic_management.c    # Network adapter management
│   │   ├── performance.c       # Performance counters
│   │   ├── statistics.c        # Packet statistics
│   │   ├── makefile            # Build configuration
│   │   └── safeops.inf         # Driver installation file
│   │
│   └── userspace_service\      # Windows service (SafeOpsService.exe)
│       ├── service_main.c      # Service entry point and control
│       ├── service_main.h      # Service type definitions
│       ├── ring_reader.c       # Reads packets from kernel ring buffer
│       ├── ring_reader.h       # Ring reader interface
│       ├── log_writer.c        # Writes packets to PCAP files
│       ├── log_writer.h        # Log writer interface
│       ├── rotation_manager.c  # Log rotation and cleanup
│       ├── rotation_manager.h  # Rotation manager interface
│       ├── ioctl_client.c      # Driver communication
│       ├── packet_metadata.h   # Packet structure definitions
│       ├── build.cmd           # Primary build script
│       └── build.ps1           # PowerShell build script
│
├── management_console\         # Web UI (Node.js + React)
│   ├── backend\                # Express.js REST API
│   └── frontend\               # React dashboard
│
├── database\                   # PostgreSQL schema and migrations
│   ├── schema\
│   └── migrations\
│
├── config\                     # Configuration files
│   ├── suricata\              # IDS rules
│   ├── threat_intel\          # Threat feeds configuration
│   └── schemas\               # JSON validation schemas
│
├── threat_intel_fetcher\       # Go-based threat intel updater
│
└── installation\               # Installation scripts
    ├── scripts\               # PowerShell automation
    └── templates\             # Configuration templates
```

---

## Component Architecture

### 1. Kernel Driver (SafeOps.sys)

**Location:** `D:\SafeOpsFV2\src\kernel_driver\`

**Purpose:** Captures network packets at the kernel level using NDIS lightweight filter.

**Key Modules:**
- **driver.c/driver.h** - Driver initialization, lifecycle, and global state management
- **packet_capture.c** - NDIS 6.50 filter driver implementation
- **filter_engine.c** - Windows Filtering Platform (WFP) callouts
- **shared_memory.c** - Lock-free ring buffer for kernel-to-userspace communication
- **ioctl_handler.c** - Device control interface for configuration
- **nic_management.c** - Network adapter attachment and monitoring
- **performance.c** - Real-time performance metrics
- **statistics.c** - Packet and byte counters

**Build Output:** `SafeOps.sys` (placed in driver build directory)

**Dependencies:**
- Windows Driver Kit (WDK) 10
- NDIS 6.50 support (Windows 10+)
- WFP kernel API

---

### 2. Userspace Service (SafeOpsService.exe)

**Location:** `D:\SafeOpsFV2\src\userspace_service\`

**Purpose:** Windows service that reads captured packets and manages logging.

**Key Modules:**
- **service_main.c** - Service control manager interface and main loop
- **ring_reader.c** - Reads packets from kernel ring buffer via shared memory
- **log_writer.c** - Writes packets to PCAP files with compression
- **rotation_manager.c** - Manages log rotation, archival, and cleanup
- **ioctl_client.c** - Communicates with kernel driver via DeviceIoControl

**Build Output:** `SafeOpsService.exe` (in `build\` subdirectory)

**Configuration:**
- Service name: `SafeOpsCapture`
- Start type: Automatic
- Run as: Local System
- Log location: `C:\SafeOps\logs\`

---

### 3. Management Console

**Location:** `D:\SafeOpsFV2\management_console\`

**Purpose:** Web-based UI for monitoring, configuration, and threat analysis.

**Components:**
- **Backend** (Node.js/Express)
  - REST API for alerts, statistics, configuration
  - WebSocket support for real-time updates
  - Database queries and aggregation

- **Frontend** (React)
  - Dashboard with real-time statistics
  - Alert management interface
  - Threat intelligence viewer
  - Configuration editor

**Access:** `http://localhost:3000` (default)

---

### 4. Threat Intelligence Fetcher

**Location:** `D:\SafeOpsFV2\threat_intel_fetcher\`

**Purpose:** Automated fetcher for threat intelligence feeds (Go-based).

**Features:**
- Fetches IoCs from AlienVault OTX, AbuseIPDB, etc.
- Validates and normalizes threat data
- Updates PostgreSQL database
- Scheduled execution via Windows Task Scheduler

**Build Output:** `fetcher.exe`

---

## Building the Project

### Prerequisites

1. **For Kernel Driver:**
   - Visual Studio 2019 or 2022
   - Windows Driver Kit (WDK) 10.0.19041.0 or later
   - Windows SDK 10.0.19041.0 or later
   - Code signing certificate (for production deployment)

2. **For Userspace Service:**
   - Visual Studio 2019 or 2022 with C++ Desktop Development
   - Windows SDK 10.0.19041.0 or later

3. **For Management Console:**
   - Node.js 18+ and npm
   - PostgreSQL 14+

4. **For Threat Fetcher:**
   - Go 1.21+

---

### Build Instructions

#### 1. Build Kernel Driver (SafeOps.sys)

**Option A: Using Visual Studio**
```cmd
cd D:\SafeOpsFV2\src\kernel_driver
# Open SafeOps.sln in Visual Studio
# Select "Release" or "Debug" configuration
# Build -> Build Solution (Ctrl+Shift+B)
```

**Option B: Using nmake (Command Line)**
```cmd
cd D:\SafeOpsFV2\src\kernel_driver

# Open "x64 Native Tools Command Prompt for VS 2022"
nmake /f makefile clean
nmake /f makefile
```

**Output:** `SafeOps.sys` in build directory

---

#### 2. Build Userspace Service (SafeOpsService.exe)

**Option A: Using PowerShell**
```powershell
cd D:\SafeOpsFV2\src\userspace_service
.\build.ps1
```

**Option B: Using batch script**
```cmd
cd D:\SafeOpsFV2\src\userspace_service
build.cmd
```

**Output:** `SafeOpsService.exe` in `build\` subdirectory

**Current Status:** Already built successfully at:
- `D:\SafeOpsFV2\src\userspace_service\build\SafeOpsService.exe` (138 KB)

---

#### 3. Build Management Console

```bash
cd D:\SafeOpsFV2\management_console\backend
npm install
npm run build

cd ..\frontend
npm install
npm run build
```

---

#### 4. Build Threat Fetcher

```bash
cd D:\SafeOpsFV2\threat_intel_fetcher
go build -o fetcher.exe ./cmd/fetcher
```

---

## Installation and Deployment

### Driver Installation

1. **Test Signing (Development Only)**
```cmd
# Enable test signing mode (requires admin)
bcdedit /set testsigning on
# Reboot required
```

2. **Install Driver**
```cmd
cd D:\SafeOpsFV2\src\kernel_driver

# Copy driver to system directory
copy SafeOps.sys C:\Windows\System32\drivers\

# Install using INF file
pnputil /add-driver safeops.inf /install
```

3. **Start Driver**
```cmd
sc create SafeOps type= kernel binPath= C:\Windows\System32\drivers\SafeOps.sys
sc start SafeOps
```

---

### Service Installation

```cmd
cd D:\SafeOpsFV2\src\userspace_service\build

# Install service
sc create SafeOpsCapture binPath= "D:\SafeOpsFV2\src\userspace_service\build\SafeOpsService.exe" start= auto
sc description SafeOpsCapture "SafeOps Network Packet Capture Service"

# Start service
sc start SafeOpsCapture
```

**Service Verification:**
```cmd
sc query SafeOpsCapture
```

---

### Database Setup

```bash
cd D:\SafeOpsFV2\database

# Create database
psql -U postgres -c "CREATE DATABASE safeops;"

# Run schema migrations
psql -U postgres -d safeops -f schema/init.sql
```

---

### Management Console Deployment

```bash
cd D:\SafeOpsFV2\management_console\backend
npm start &

cd ..\frontend
npm start
```

Access at: `http://localhost:3000`

---

## Configuration

### Driver Configuration

**Registry Settings:** `HKLM\SYSTEM\CurrentControlSet\Services\SafeOps\Parameters`

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| RingBufferSize | DWORD | 33554432 | Ring buffer size (32 MB) |
| MaxPacketSize | DWORD | 65536 | Maximum packet size (64 KB) |
| EnableFiltering | DWORD | 1 | Enable packet filtering |
| CaptureMode | DWORD | 0 | 0=Promiscuous, 1=Selective |

---

### Service Configuration

**Config File:** `C:\SafeOps\config\service.json`

```json
{
  "logging": {
    "output_directory": "C:\\SafeOps\\logs",
    "format": "pcap",
    "compression": true,
    "max_file_size_mb": 100,
    "rotation_interval_hours": 1
  },
  "driver": {
    "device_name": "\\\\.\\SafeOps",
    "poll_interval_ms": 100
  },
  "performance": {
    "worker_threads": 4,
    "buffer_size": 8192
  }
}
```

---

### Suricata Integration

**Config:** `D:\SafeOpsFV2\config\suricata\suricata.yaml`

Point Suricata to read PCAP files:
```yaml
pcap-file:
  checksum-validation: no

inputs:
  - interface: default
    pcap-file: C:\SafeOps\logs\current.pcap
```

---

## Operation and Monitoring

### Viewing Logs

**Service Logs:**
```cmd
# Windows Event Viewer
eventvwr.msc
# Navigate to: Windows Logs -> Application
# Filter by Source: SafeOpsCapture
```

**Driver Logs (DebugView):**
- Download DebugView from Microsoft Sysinternals
- Capture -> Capture Kernel
- Filter: `SafeOps`

---

### Monitoring Performance

**Real-time Statistics:**
```powershell
# Query driver statistics via IOCTL
.\ioctl_client.exe --stats
```

**Management Console:**
- Navigate to `http://localhost:3000/dashboard`
- View real-time packet counts, bandwidth, alerts

---

### Log Files

**Location:** `C:\SafeOps\logs\`

**Structure:**
```
C:\SafeOps\logs\
├── current.pcap          # Active capture file
├── 2024-12-25_00.pcap.gz # Rotated archives
├── 2024-12-25_01.pcap.gz
└── metadata\
    └── rotation.log      # Rotation events
```

---

## Troubleshooting

### Driver Issues

**Driver Won't Start:**
```cmd
# Check driver status
sc query SafeOps

# View error details
driverquery /v | findstr SafeOps

# Check event logs
wevtutil qe System /q:"*[System[Provider[@Name='SafeOps']]]" /f:text /rd:true /c:10
```

**Common Errors:**
- `ERROR_FILE_NOT_FOUND` - Driver binary not in system32\drivers
- `ERROR_INVALID_PARAMETER` - INF file mismatch
- `STATUS_INVALID_IMAGE_HASH` - Test signing not enabled

---

### Service Issues

**Service Won't Start:**
```cmd
# Check service status
sc query SafeOpsCapture

# View service logs
Get-EventLog -LogName Application -Source SafeOpsCapture -Newest 20
```

**Common Errors:**
- `ERROR_SERVICE_DOES_NOT_EXIST` - Service not installed
- `ERROR_FAILED_SERVICE_CONTROLLER_CONNECT` - Running from wrong context
- Driver communication failure - Ensure SafeOps.sys is running

---

### Performance Issues

**High CPU Usage:**
- Reduce `poll_interval_ms` in service config
- Decrease ring buffer polling frequency
- Enable packet filtering to reduce volume

**Dropped Packets:**
- Increase ring buffer size (driver registry)
- Add more worker threads (service config)
- Optimize filter rules

---

### Build Errors

**Kernel Driver Build Failures:**
- Ensure WDK paths are correct in makefile
- Verify NDIS version compatibility
- Check for missing Windows headers

**Service Build Failures:**
- Ensure Visual Studio C++ tools are installed
- Verify Windows SDK version
- Check library paths in build scripts

---

## Component Communication Flow

```
[Network Packet]
      |
      v
[NDIS Filter - SafeOps.sys]
      |
      v
[Ring Buffer - Shared Memory]
      |
      v
[Ring Reader - SafeOpsService.exe]
      |
      v
[PCAP Writer - Log Files]
      |
      v
[Suricata IDS]
      |
      v
[PostgreSQL Database]
      |
      v
[Management Console - Web UI]
```

---

## File Organization Summary

### What's Been Cleaned Up
- Removed temporary build scripts (build_direct.bat, compile_simple.ps1, etc.)
- Removed minimal_main.c test file
- Removed duplicate documentation files
- Consolidated build processes

### What's Kept
- **Essential build files:**
  - `src/kernel_driver/makefile` - Driver build configuration
  - `src/userspace_service/build.cmd` - Service build script
  - `src/userspace_service/build.ps1` - PowerShell build alternative

- **Core documentation:**
  - `BUILD_GUIDE.md` - Comprehensive build instructions
  - `DOCUMENTATION_INDEX.md` - Central documentation reference
  - `INSTALLATION_GUIDE.md` - Installation procedures
  - Component-specific READMEs in each directory

- **Source code:**
  - All .c and .h files in both driver and service directories
  - All project files (.vcxproj, .sln)
  - Configuration files (.inf, .rc)

---

## Next Steps

1. **Complete Driver Build** - Fix remaining compilation issues (see Agent 4-6 tasks)
2. **Test Driver Loading** - Verify SafeOps.sys loads without errors
3. **Test Service Integration** - Confirm service can communicate with driver
4. **Verify Packet Capture** - Ensure packets flow from driver -> service -> PCAP
5. **Deploy Full Stack** - Start database, console, and integrate with Suricata

---

## Support and Documentation

- **Main README:** `D:\SafeOpsFV2\README.md`
- **Build Guide:** `D:\SafeOpsFV2\BUILD_GUIDE.md`
- **Installation Guide:** `D:\SafeOpsFV2\INSTALLATION_GUIDE.md`
- **API Documentation:** `D:\SafeOpsFV2\management_console\API.md`

---

**Version:** 2.0.0
**Last Updated:** 2024-12-25
**Status:** In Development - Driver compilation in progress
