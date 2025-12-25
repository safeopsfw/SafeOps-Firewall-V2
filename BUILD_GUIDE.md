# SafeOps v2.0 - Comprehensive Build Guide

**Document Version:** 1.0
**Last Updated:** 2025-12-25
**Status:** Production Ready

---

## Table of Contents

1. [Overview](#overview)
2. [System Requirements](#system-requirements)
3. [Prerequisites Installation](#prerequisites-installation)
4. [Build Environment Setup](#build-environment-setup)
5. [Component Build Instructions](#component-build-instructions)
6. [Build Order and Dependencies](#build-order-and-dependencies)
7. [Testing and Verification](#testing-and-verification)
8. [Deployment Instructions](#deployment-instructions)
9. [Troubleshooting](#troubleshooting)
10. [Appendices](#appendices)

---

## Overview

### Purpose

This guide provides comprehensive instructions for building the entire SafeOps v2.0 system from source code. SafeOps is an enterprise-grade network security gateway for Windows, consisting of multiple components built with different technologies.

### Build Scope

**Components to Build:**
- Kernel Driver (SafeOps.sys) - Windows kernel mode driver
- Userspace Service (SafeOpsService.exe) - Windows service for packet processing
- Shared Libraries - Rust, Go, and C libraries
- Service Components - Firewall, IDS/IPS, DNS, DHCP, WiFi AP, etc.
- Web UI - Management console (Wails + TypeScript)

**Estimated Build Time:**
- First-time setup: 2-3 hours
- Subsequent builds: 15-30 minutes

---

## System Requirements

### Hardware Requirements

**Minimum:**
- CPU: Intel/AMD x64, 4+ cores
- RAM: 16 GB
- Disk: 50 GB free space (SSD recommended)
- Network: Ethernet adapter for testing

**Recommended:**
- CPU: Intel/AMD x64, 8+ cores
- RAM: 32 GB
- Disk: 100 GB free space (NVMe SSD)
- Network: Multiple network adapters for WAN/LAN testing

### Operating System

**Required:**
- Windows 10 Pro/Enterprise (21H2 or later)
- Windows 11 Pro/Enterprise
- Windows Server 2019 or 2022

**Note:** Home editions are not supported due to kernel driver signing requirements.

### Build Machine Configuration

**Enable Test Signing:**
```cmd
bcdedit /set testsigning on
shutdown /r /t 0
```

**Verify Test Signing:**
```cmd
bcdedit /enum {current} | findstr testsigning
```

Expected output: `testsigning             Yes`

---

## Prerequisites Installation

### Development Tools

#### 1. Visual Studio 2022

**Required Components:**
- Desktop development with C++
- Windows Driver development
- .NET desktop development

**Installation:**
```powershell
# Download from: https://visualstudio.microsoft.com/downloads/
# Or use winget:
winget install Microsoft.VisualStudio.2022.Community

# During installation, select these workloads:
# - Desktop development with C++
# - .NET desktop development
# - Windows Driver Kit (from Individual Components)
```

#### 2. Windows Driver Kit (WDK)

**Version Required:** 10.0.22621.0 or later

**Installation:**
```powershell
# Download from: https://docs.microsoft.com/en-us/windows-hardware/drivers/download-the-wdk
# Must be installed AFTER Visual Studio

# Or use winget:
winget install Microsoft.WindowsDriverKit
```

**Verify Installation:**
```cmd
where nmake
where cl.exe
where link.exe
```

All three commands should return valid paths.

#### 3. Windows SDK

**Version Required:** 10.0.22621.0 or later

**Included with Visual Studio** or install separately:
```powershell
winget install Microsoft.WindowsSDK.10.0.22621
```

#### 4. Rust Toolchain

**Version Required:** 1.74 or later

**Installation:**
```powershell
# Download from: https://rustup.rs/
# Or use winget:
winget install Rustlang.Rustup

# After installation, configure:
rustup default stable-x86_64-pc-windows-msvc
rustup update
rustup component add clippy rustfmt
```

**Verify Installation:**
```cmd
rustc --version
cargo --version
```

#### 5. Go Toolchain

**Version Required:** 1.21 or later

**Installation:**
```powershell
# Download from: https://golang.org/dl/
# Or use winget:
winget install GoLang.Go

# Set GOPATH:
setx GOPATH "%USERPROFILE%\go"
setx PATH "%PATH%;%GOPATH%\bin"
```

**Verify Installation:**
```cmd
go version
```

#### 6. Protocol Buffers Compiler

**Version Required:** 3.21.0 or later

**Installation:**
```powershell
# Download from: https://github.com/protocolbuffers/protobuf/releases
# Extract protoc.exe to C:\protoc\bin\

# Or use Chocolatey:
choco install protoc

# Add to PATH:
setx PATH "%PATH%;C:\protoc\bin"
```

**Verify Installation:**
```cmd
protoc --version
```

#### 7. Node.js and npm (for Web UI)

**Version Required:** Node.js 18.x LTS or later

**Installation:**
```powershell
# Download from: https://nodejs.org/
# Or use winget:
winget install OpenJS.NodeJS.LTS

# Verify:
node --version
npm --version
```

#### 8. Git

**Installation:**
```powershell
winget install Git.Git

# Configure:
git config --global user.name "Your Name"
git config --global user.email "your.email@example.com"
```

### Additional Tools

#### PowerShell 7+

```powershell
winget install Microsoft.PowerShell
```

#### Process Explorer (for debugging)

```powershell
# Download from: https://docs.microsoft.com/en-us/sysinternals/downloads/process-explorer
```

#### DebugView (for kernel debugging)

```powershell
# Download from: https://docs.microsoft.com/en-us/sysinternals/downloads/debugview
```

---

## Build Environment Setup

### Environment Variables

**Required Environment Variables:**

```powershell
# Set these in System Environment Variables:
setx WDK_ROOT "C:\Program Files (x86)\Windows Kits\10"
setx WDK_VERSION "10.0.22621.0"
setx GOPATH "%USERPROFILE%\go"
setx RUST_BACKTRACE "1"

# Update PATH:
setx PATH "%PATH%;%GOPATH%\bin;C:\protoc\bin"
```

### Clone Repository

```bash
# Clone the repository:
git clone https://github.com/yourusername/SafeOps-FW.git
cd SafeOps-FW

# Verify all files present:
git status
```

### Directory Structure Verification

**Run this PowerShell script to verify structure:**

```powershell
# Verify critical directories exist:
$dirs = @(
    "src\kernel_driver",
    "src\userspace_service",
    "src\shared\rust",
    "src\shared\go",
    "src\shared\c",
    "config",
    "database",
    "proto",
    "docs"
)

foreach ($dir in $dirs) {
    if (Test-Path $dir) {
        Write-Host "[OK] $dir" -ForegroundColor Green
    } else {
        Write-Host "[MISSING] $dir" -ForegroundColor Red
    }
}
```

---

## Component Build Instructions

### Build Order

Build components in this order to satisfy dependencies:

1. Protocol Buffers (generates code for other components)
2. Shared C Headers (header-only, no build)
3. Shared Rust Library
4. Shared Go Packages
5. Kernel Driver
6. Userspace Service
7. Service Components (Firewall, IDS/IPS, etc.)
8. Web UI

---

### Step 1: Protocol Buffers

**Location:** `proto/`

**Build Commands:**

```powershell
cd proto

# Windows:
.\build.ps1

# Or manually:
protoc --go_out=. --go-grpc_out=. network_manager.proto
protoc --rust_out=. network_manager.proto
```

**Verification:**

```powershell
# Check generated files exist:
dir grpc\*.pb.go
dir rust\*.rs
```

**Expected Output:**
- `grpc/*.pb.go` - Go generated code
- `rust/*.rs` - Rust generated code

---

### Step 2: Shared C Headers

**Location:** `src/shared/c/`

**No Build Required** - Header-only library

**Verification:**

```powershell
cd src\shared\c

# Verify headers exist:
dir *.h
```

**Expected Files:**
- `packet_structs.h` (963 lines)
- `ring_buffer.h` (530 lines)
- `shared_constants.h`
- `ioctl_codes.h`
- `error_codes.h`

**Validation:**

```cmd
# Read the verification report:
type C_VERIFICATION_REPORT.md
```

---

### Step 3: Shared Rust Library

**Location:** `src/shared/rust/`

**Build Commands:**

```bash
cd src/shared/rust

# Debug build:
cargo build

# Release build (optimized):
cargo build --release

# Run tests:
cargo test

# Run benchmarks:
cargo bench

# Generate docs:
cargo doc --open
```

**Build Flags:**

```toml
# In Cargo.toml:
[profile.release]
opt-level = 3
lto = true
codegen-units = 1
```

**Verification:**

```bash
# Check binary exists:
ls target/release/libsafeops_shared.rlib

# Run tests:
cargo test --release

# Check documentation:
cargo doc --no-deps
```

**Expected Output:**
- Build completes without errors
- All tests pass
- Library file created: `target/release/libsafeops_shared.rlib`

**Troubleshooting:**

If build fails:
```bash
# Update dependencies:
cargo update

# Clean and rebuild:
cargo clean
cargo build --release
```

---

### Step 4: Shared Go Packages

**Location:** `src/shared/go/`

**Build Commands:**

```bash
cd src/shared/go

# Initialize module (first time only):
go mod init github.com/safeops/shared

# Download dependencies:
go mod download
go mod tidy

# Build all packages:
go build ./...

# Run tests:
go test ./...

# Run tests with coverage:
go test -v -coverprofile=coverage.out ./...
go tool cover -html=coverage.out
```

**Verification:**

```bash
# Verify all packages compile:
go build -v ./...

# Check for common issues:
go vet ./...

# Format code:
go fmt ./...
```

**Expected Output:**
- All packages compile successfully
- Tests pass with >80% coverage

---

### Step 5: Kernel Driver (SafeOps.sys)

**Location:** `src/kernel_driver/`

**Critical Documentation:**
- **BUILD_DOCUMENTATION.md** - Comprehensive build guide
- **TESTING_PLAN.md** - 70+ test cases
- **WORK_SUMMARY.md** - Build status

#### Prerequisites

1. **Enable Test Signing** (if not already done):
   ```cmd
   bcdedit /set testsigning on
   shutdown /r /t 0
   ```

2. **Verify WDK Environment:**
   ```cmd
   where nmake
   where cl.exe
   ```

#### Build Process

**Method 1: Using Makefile (Recommended)**

```cmd
# Open x64 Native Tools Command Prompt for VS 2022
# (Start Menu > Visual Studio 2022 > x64 Native Tools Command Prompt)

cd C:\Users\02arj\.claude-worktrees\SafeOpsFV2\pensive-swanson\src\kernel_driver

# Debug build:
nmake BUILD=debug

# Release build:
nmake BUILD=release

# Sign driver:
nmake sign

# Create installation package:
nmake package

# Clean build:
nmake clean

# Rebuild from scratch:
nmake rebuild
```

**Method 2: Using Visual Studio IDE**

1. Open Visual Studio 2022
2. File → New → Project From Existing Code
3. Select "Windows Driver" project type
4. Add all .c and .h files from `src/kernel_driver/`
5. Set Configuration to "Release" and Platform to "x64"
6. Build → Build Solution (Ctrl+Shift+B)

**Build Output Locations:**

```
Debug Build:
  build\driver\debug\x64\SafeOps.sys
  build\driver\debug\x64\SafeOps.pdb

Release Build:
  build\driver\release\x64\SafeOps.sys
  build\driver\release\x64\SafeOps.pdb

Package:
  dist\driver\SafeOps.sys
  dist\driver\SafeOps.inf
  dist\driver\SafeOps.cat
```

#### Verification

```cmd
# Check file exists and size:
dir build\driver\release\x64\SafeOps.sys

# Check PE header:
dumpbin /headers build\driver\release\x64\SafeOps.sys | findstr "SUBSYSTEM"
# Expected: SUBSYSTEM: Native

# Verify driver signature (if signed):
signtool verify /v build\driver\release\x64\SafeOps.sys
```

**Expected Output:**
- `SafeOps.sys` size: 100-500 KB
- PDB file created for debugging
- No critical compilation errors

#### Troubleshooting

**Error: "nmake not found"**
```cmd
# Solution: Use x64 Native Tools Command Prompt, not regular cmd
```

**Error: "Cannot open include file"**
```cmd
# Solution: Verify WDK installation:
nmake check-wdk
```

**See Full Troubleshooting Guide:**
- `src/kernel_driver/BUILD_DOCUMENTATION.md` (Section: "Troubleshooting Guide")

---

### Step 6: Userspace Service (SafeOpsService.exe)

**Location:** `src/userspace_service/`

**Critical Documentation:**
- **BUILD.md** - Complete build guide (787 lines)
- **TESTING_PLAN.md** - 102 test cases
- **WORK_SUMMARY.md** - Build status

#### Prerequisites

1. **Visual Studio C++ Build Tools** installed
2. **Windows SDK** 10.0.22621.0 or later

#### Build Process

**Method 1: Using Build Script (Recommended)**

```cmd
# Open x64 Native Tools Command Prompt for VS 2022

cd C:\Users\02arj\.claude-worktrees\SafeOpsFV2\pensive-swanson\src\userspace_service

# Release build:
build.cmd release

# Debug build:
build.cmd debug

# Clean and rebuild:
build.cmd release clean
```

**Method 2: Manual Compilation**

```cmd
# Open x64 Native Tools Command Prompt for VS 2022

cd src\userspace_service

# Release build:
cl.exe /O2 /W4 /MT /GL /D_WIN32_WINNT=0x0A00 /DUNICODE /D_UNICODE ^
    /DWIN32_LEAN_AND_MEAN ^
    /I. /I..\shared\c ^
    service_main.c ^
    ioctl_client.c ^
    ring_reader.c ^
    log_writer.c ^
    rotation_manager.c ^
    /Fe:SafeOpsService.exe ^
    /link /LTCG /OPT:REF /OPT:ICF advapi32.lib kernel32.lib user32.lib
```

**Build Output:**

```
build\SafeOpsService.exe
build\*.obj (object files)
build\*.pdb (debug symbols, if debug build)
```

#### Verification

```cmd
# Check file exists:
dir build\SafeOpsService.exe

# Check dependencies:
dumpbin /dependents build\SafeOpsService.exe

# Test console mode:
build\SafeOpsService.exe -console
# Press Ctrl+C to stop
```

**Expected Output:**
- `SafeOpsService.exe` size: 200-300 KB
- Console mode displays initialization logs
- No crashes on startup

#### Troubleshooting

**Error: "cl.exe not found"**
```cmd
# Solution: Use x64 Native Tools Command Prompt
# Start Menu > Visual Studio 2022 > x64 Native Tools Command Prompt
```

**Error: "Cannot open include file"**
```cmd
# Solution: Verify include paths:
# - Current directory: /I.
# - Shared headers: /I..\shared\c
```

**See Full Troubleshooting Guide:**
- `src/userspace_service/BUILD.md` (Section 7: "Troubleshooting")

---

### Step 7: Service Components

After building kernel driver and userspace service, build the individual service components.

#### Firewall Engine

```bash
cd src/firewall_engine
cargo build --release
```

#### IDS/IPS

```bash
cd src/ids_ips
cargo build --release
```

#### DNS Server

```bash
cd src/dns_server
cargo build --release
```

#### DHCP Server

```bash
cd src/dhcp_server
cargo build --release
```

#### WiFi AP

```bash
cd src/wifi_ap
cargo build --release
```

#### TLS Proxy

```bash
cd src/tls_proxy
cargo build --release
```

#### Threat Intelligence

```bash
cd src/threat_intel
cargo build --release
```

#### Orchestrator

```bash
cd src/orchestrator
cargo build --release
```

**Note:** Many services are currently skeletons awaiting Phase 2 implementation. Focus on kernel driver and userspace service first.

---

### Step 8: Web UI (Optional)

**Location:** `ui/`

**Prerequisites:**
- Node.js 18.x LTS or later
- Wails CLI

**Build Commands:**

```bash
cd ui

# Install dependencies:
npm install

# Development build:
npm run dev

# Production build:
npm run build

# Or use Wails:
wails build
```

---

## Build Order and Dependencies

### Dependency Graph

```
Protocol Buffers
    ↓
C Headers ──→ Rust Shared ──→ Kernel Driver
    ↓              ↓
    ↓         Go Shared ──→ Userspace Service
    ↓              ↓
    └──────→ Service Components ──→ Web UI
                    ↓
                Database
```

### Build Sequence

**Phase 1: Foundation (30 minutes)**
1. Protocol Buffers - 5 min
2. C Headers - No build (verification only)
3. Rust Shared Library - 10 min
4. Go Shared Packages - 5 min

**Phase 2: Core Components (45 minutes)**
5. Kernel Driver - 20 min (first build)
6. Userspace Service - 10 min

**Phase 3: Service Layer (30 minutes)**
7. Firewall Engine - 5 min
8. IDS/IPS - 5 min
9. DNS Server - 5 min
10. Other services - 15 min

**Phase 4: UI (15 minutes)**
11. Web UI - 15 min

**Total Time:** ~2 hours (first build), 30 minutes (subsequent builds)

---

## Testing and Verification

### Pre-Deployment Testing

#### Kernel Driver Testing

**Location:** `src/kernel_driver/TESTING_PLAN.md`

**Critical Tests:**

1. **Driver Load Test:**
   ```cmd
   sc create SafeOps type=kernel binPath=%SystemRoot%\System32\drivers\SafeOps.sys
   sc start SafeOps
   sc query SafeOps
   ```

2. **IOCTL Communication Test:**
   ```cmd
   # Run test harness (to be developed)
   ```

3. **Packet Capture Test:**
   ```cmd
   # Generate traffic and verify capture
   ping 8.8.8.8
   # Check logs
   ```

**Full Test Plan:** 70+ test cases in `TESTING_PLAN.md`

#### Userspace Service Testing

**Location:** `src/userspace_service/TESTING_PLAN.md`

**Critical Tests:**

1. **Service Installation:**
   ```cmd
   sc create SafeOpsCapture binPath="C:\SafeOps\bin\SafeOpsService.exe"
   sc start SafeOpsCapture
   sc query SafeOpsCapture
   ```

2. **Driver Communication:**
   ```cmd
   # Service should connect to driver
   # Check logs: C:\SafeOps\logs\service.log
   ```

3. **Console Mode Test:**
   ```cmd
   SafeOpsService.exe -console
   # Verify initialization logs
   # Press Ctrl+C to stop
   ```

**Full Test Plan:** 102 test cases in `TESTING_PLAN.md`

### Build Verification Checklist

**Kernel Driver:**
- [ ] SafeOps.sys created
- [ ] File size 100-500 KB
- [ ] PDB symbols present
- [ ] No critical errors in build log
- [ ] Driver signed (test or production)
- [ ] Driver loads without crash
- [ ] Device object created: `\\.\SafeOps`

**Userspace Service:**
- [ ] SafeOpsService.exe created
- [ ] File size 200-300 KB
- [ ] Dependencies correct (advapi32, kernel32, user32)
- [ ] Console mode starts successfully
- [ ] Service installs correctly
- [ ] Service connects to driver

**Shared Libraries:**
- [ ] Rust library compiled: `libsafeops_shared.rlib`
- [ ] All Rust tests pass
- [ ] Go packages compile: `go build ./...`
- [ ] All Go tests pass
- [ ] C headers validate

---

## Deployment Instructions

### Kernel Driver Installation

**Manual Installation:**

```cmd
# 1. Copy driver to system directory:
copy build\driver\release\x64\SafeOps.sys %SystemRoot%\System32\drivers\

# 2. Create service:
sc create SafeOps type=kernel binPath=%SystemRoot%\System32\drivers\SafeOps.sys start=demand

# 3. Start driver:
sc start SafeOps

# 4. Verify:
sc query SafeOps
```

**Using INF File:**

```cmd
# Install using PnP:
pnputil /add-driver src\kernel_driver\SafeOps.inf /install

# Start service:
sc start SafeOps
```

**Uninstallation:**

```cmd
# Stop driver:
sc stop SafeOps

# Delete service:
sc delete SafeOps

# Remove binary:
del %SystemRoot%\System32\drivers\SafeOps.sys
```

### Userspace Service Installation

**Installation:**

```cmd
# 1. Create installation directory:
mkdir C:\SafeOps\bin
mkdir C:\SafeOps\logs

# 2. Copy service binary:
copy build\SafeOpsService.exe C:\SafeOps\bin\

# 3. Create service:
sc create SafeOpsCapture binPath="C:\SafeOps\bin\SafeOpsService.exe" start=auto

# 4. Start service:
sc start SafeOpsCapture

# 5. Verify:
sc query SafeOpsCapture
```

**Uninstallation:**

```cmd
# Stop service:
sc stop SafeOpsCapture

# Delete service:
sc delete SafeOpsCapture

# Remove files:
rmdir /S /Q C:\SafeOps
```

### Database Setup

**PostgreSQL Installation:**

```powershell
# Install PostgreSQL:
winget install PostgreSQL.PostgreSQL

# Start service:
net start postgresql-x64-15

# Create database:
psql -U postgres -c "CREATE DATABASE safeops;"
psql -U postgres -c "CREATE USER safeops_user WITH PASSWORD 'changeme';"
psql -U postgres -c "GRANT ALL PRIVILEGES ON DATABASE safeops TO safeops_user;"

# Initialize schemas:
cd database
.\init_database.sh
```

**Redis Installation:**

```powershell
# Install Redis:
winget install Redis.Redis

# Start service:
net start redis
```

---

## Troubleshooting

### Common Build Issues

#### Issue: "nmake not found" or "cl.exe not found"

**Cause:** Not running from Developer Command Prompt

**Solution:**
```cmd
# Use x64 Native Tools Command Prompt for VS 2022
# Start Menu > Visual Studio 2022 > x64 Native Tools Command Prompt
```

#### Issue: "Cannot open include file"

**Cause:** Incorrect include paths or missing dependencies

**Solution:**
```cmd
# Verify WDK installation:
dir "C:\Program Files (x86)\Windows Kits\10"

# Verify include path in build command:
# For kernel driver: WDK headers should be auto-detected
# For userspace service: Include /I. /I..\shared\c
```

#### Issue: "Unresolved external symbol"

**Cause:** Missing library in linker input

**Solution:**
```cmd
# For userspace service, ensure these libs are linked:
# advapi32.lib kernel32.lib user32.lib

# Check linker command includes /link flag with libraries
```

#### Issue: Rust build fails

**Solution:**
```bash
# Update Rust:
rustup update

# Clean and rebuild:
cd src/shared/rust
cargo clean
cargo build --release

# If still fails, check Cargo.toml dependencies
```

#### Issue: Go build fails

**Solution:**
```bash
# Update dependencies:
cd src/shared/go
go mod tidy
go mod download

# If still fails, delete go.mod and reinitialize:
del go.mod go.sum
go mod init github.com/safeops/shared
go mod tidy
```

### Runtime Issues

#### Issue: Driver fails to load

**Symptom:** `sc start SafeOps` returns error

**Solutions:**

1. **Check test signing enabled:**
   ```cmd
   bcdedit /enum {current} | findstr testsigning
   ```

2. **Check Event Viewer:**
   ```cmd
   eventvwr.msc
   # Navigate to: Windows Logs > System
   # Filter by Source: SafeOps
   ```

3. **Check driver signature:**
   ```cmd
   signtool verify /v SafeOps.sys
   ```

#### Issue: Service fails to start

**Symptom:** `sc start SafeOpsCapture` returns error or service stops immediately

**Solutions:**

1. **Run in console mode for debugging:**
   ```cmd
   C:\SafeOps\bin\SafeOpsService.exe -console
   ```

2. **Check if driver is running:**
   ```cmd
   sc query SafeOps
   ```

3. **Check Event Viewer:**
   ```cmd
   eventvwr.msc
   # Navigate to: Windows Logs > Application
   # Filter by Source: SafeOpsCapture
   ```

4. **Verify log directory exists:**
   ```cmd
   dir C:\SafeOps\logs
   ```

### Getting Help

**Documentation:**
1. Kernel Driver: [`src/kernel_driver/BUILD_DOCUMENTATION.md`](src/kernel_driver/BUILD_DOCUMENTATION.md)
2. Userspace Service: [`src/userspace_service/BUILD.md`](src/userspace_service/BUILD.md)
3. Documentation Index: [`DOCUMENTATION_INDEX.md`](DOCUMENTATION_INDEX.md)

**Testing Plans:**
1. Kernel Driver: [`src/kernel_driver/TESTING_PLAN.md`](src/kernel_driver/TESTING_PLAN.md)
2. Userspace Service: [`src/userspace_service/TESTING_PLAN.md`](src/userspace_service/TESTING_PLAN.md)

---

## Appendices

### Appendix A: Complete Build Script

**File:** `build_all.ps1`

```powershell
# SafeOps v2.0 - Complete Build Script
# Run from project root

param(
    [switch]$Debug,
    [switch]$Clean
)

$ErrorActionPreference = "Stop"

Write-Host "========================================" -ForegroundColor Cyan
Write-Host "SafeOps v2.0 - Complete Build" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan
Write-Host ""

$config = if ($Debug) { "debug" } else { "release" }
Write-Host "Configuration: $config" -ForegroundColor Yellow
Write-Host ""

# Step 1: Protocol Buffers
Write-Host "[1/8] Building Protocol Buffers..." -ForegroundColor Green
cd proto
.\build.ps1
cd ..

# Step 2: Rust Shared Library
Write-Host "[2/8] Building Rust Shared Library..." -ForegroundColor Green
cd src\shared\rust
if ($Clean) { cargo clean }
cargo build $(if (-not $Debug) { "--release" })
cd ..\..\..

# Step 3: Go Shared Packages
Write-Host "[3/8] Building Go Shared Packages..." -ForegroundColor Green
cd src\shared\go
go build ./...
cd ..\..\..

# Step 4: Kernel Driver
Write-Host "[4/8] Building Kernel Driver..." -ForegroundColor Green
Write-Host "NOTE: Must run from x64 Native Tools Command Prompt" -ForegroundColor Yellow
# User must build manually from VS command prompt

# Step 5: Userspace Service
Write-Host "[5/8] Building Userspace Service..." -ForegroundColor Green
Write-Host "NOTE: Must run from x64 Native Tools Command Prompt" -ForegroundColor Yellow
# User must build manually from VS command prompt

# Step 6-8: Service Components
Write-Host "[6/8] Building Firewall Engine..." -ForegroundColor Green
cd src\firewall_engine
if (Test-Path Cargo.toml) {
    cargo build $(if (-not $Debug) { "--release" })
}
cd ..\..

Write-Host "[7/8] Building IDS/IPS..." -ForegroundColor Green
cd src\ids_ips
if (Test-Path Cargo.toml) {
    cargo build $(if (-not $Debug) { "--release" })
}
cd ..\..

Write-Host "[8/8] Building DNS Server..." -ForegroundColor Green
cd src\dns_server
if (Test-Path Cargo.toml) {
    cargo build $(if (-not $Debug) { "--release" })
}
cd ..\..

Write-Host ""
Write-Host "========================================" -ForegroundColor Cyan
Write-Host "Build Complete!" -ForegroundColor Green
Write-Host "========================================" -ForegroundColor Cyan
Write-Host ""
Write-Host "IMPORTANT: Kernel driver and userspace service must be built manually" -ForegroundColor Yellow
Write-Host "from x64 Native Tools Command Prompt for VS 2022" -ForegroundColor Yellow
Write-Host ""
Write-Host "See BUILD_GUIDE.md for detailed instructions." -ForegroundColor Cyan
```

### Appendix B: Pre-Build Checklist

**Complete this checklist before starting the build:**

**Environment Setup:**
- [ ] Windows 10/11 Pro or Server (Home edition not supported)
- [ ] Test signing enabled: `bcdedit /set testsigning on`
- [ ] System rebooted after enabling test signing
- [ ] Visual Studio 2022 installed with C++ workload
- [ ] WDK 10.0.22621.0 installed
- [ ] Windows SDK 10.0.22621.0 installed
- [ ] Rust toolchain installed (1.74+)
- [ ] Go toolchain installed (1.21+)
- [ ] Protocol Buffers compiler installed (3.21+)
- [ ] Git installed and configured

**Environment Variables:**
- [ ] WDK_ROOT set to WDK installation path
- [ ] WDK_VERSION set to installed version
- [ ] GOPATH set to Go workspace
- [ ] PATH includes Go bin, protoc bin

**Repository:**
- [ ] Repository cloned successfully
- [ ] All directories present (src, config, database, proto, docs)
- [ ] Git status clean

**Documentation:**
- [ ] Read: `BUILD_GUIDE.md` (this document)
- [ ] Read: `DOCUMENTATION_INDEX.md`
- [ ] Read: `src/kernel_driver/BUILD_DOCUMENTATION.md`
- [ ] Read: `src/userspace_service/BUILD.md`

### Appendix C: Post-Build Checklist

**Kernel Driver:**
- [ ] SafeOps.sys created in build directory
- [ ] File size between 100-500 KB
- [ ] PDB symbols file created
- [ ] No critical errors in build output
- [ ] Driver signed (test or production certificate)
- [ ] `dumpbin /headers` shows SUBSYSTEM: Native
- [ ] Driver loads successfully: `sc start SafeOps`
- [ ] Device object created: accessible via `\\.\SafeOps`
- [ ] No blue screen on load
- [ ] Event Log shows successful driver start

**Userspace Service:**
- [ ] SafeOpsService.exe created in build directory
- [ ] File size between 200-300 KB
- [ ] Correct dependencies (advapi32, kernel32, user32)
- [ ] No critical errors in build output
- [ ] Console mode runs: `SafeOpsService.exe -console`
- [ ] Service installs: `sc create SafeOpsCapture ...`
- [ ] Service starts: `sc start SafeOpsCapture`
- [ ] Service connects to driver (check logs)
- [ ] No crashes or immediate stops

**Shared Libraries:**
- [ ] Rust library compiled: `libsafeops_shared.rlib` exists
- [ ] All Rust tests pass: `cargo test --release`
- [ ] Go packages compile: `go build ./...` succeeds
- [ ] All Go tests pass: `go test ./...`
- [ ] C headers validate (see C_VERIFICATION_REPORT.md)

**Testing:**
- [ ] Review kernel driver testing plan
- [ ] Review userspace service testing plan
- [ ] Run critical tests before deployment
- [ ] Document any issues found

### Appendix D: Quick Reference Commands

**Kernel Driver:**
```cmd
cd src\kernel_driver
nmake BUILD=release        # Build
nmake sign                 # Sign
nmake package             # Package
nmake install             # Install
```

**Userspace Service:**
```cmd
cd src\userspace_service
build.cmd release         # Build
sc create SafeOpsCapture binPath="C:\SafeOps\bin\SafeOpsService.exe"  # Install
sc start SafeOpsCapture   # Start
```

**Rust Library:**
```bash
cd src/shared/rust
cargo build --release
cargo test --release
```

**Go Packages:**
```bash
cd src/shared/go
go build ./...
go test ./...
```

**Protocol Buffers:**
```powershell
cd proto
.\build.ps1
```

---

## Conclusion

This build guide provides comprehensive instructions for building all components of SafeOps v2.0 from source. Follow the steps in order, verify each component after building, and consult the troubleshooting section if issues arise.

**Key Success Factors:**
1. Use the correct build environment (x64 Native Tools Command Prompt)
2. Enable test signing before building kernel components
3. Build in the recommended order (dependencies first)
4. Verify each component before proceeding to the next
5. Read component-specific documentation for details
6. Test thoroughly before deployment

**Next Steps:**
1. Complete pre-build checklist (Appendix B)
2. Follow build instructions for each component
3. Complete post-build checklist (Appendix C)
4. Execute testing plans
5. Deploy to test environment

**For Support:**
- See: [`DOCUMENTATION_INDEX.md`](DOCUMENTATION_INDEX.md) for all documentation
- See: Component-specific build documentation
- See: Testing plans for verification procedures

---

**Document Version:** 1.0
**Last Updated:** 2025-12-25
**Status:** Production Ready

**End of Build Guide**
