# SafeOps v2.0 - Installation Guide

**Document Version:** 1.0
**Last Updated:** 2025-12-25
**Status:** Production Ready

---

## Table of Contents

1. [Prerequisites](#prerequisites)
2. [System Requirements](#system-requirements)
3. [Step-by-Step Installation](#step-by-step-installation)
4. [Using PowerShell Scripts](#using-powershell-scripts)
5. [Manual Installation Steps](#manual-installation-steps)
6. [Building Components](#building-components)
7. [Installation Verification](#installation-verification)
8. [Troubleshooting](#troubleshooting)
9. [Common Issues and Solutions](#common-issues-and-solutions)

---

## Prerequisites

### System Requirements

**Minimum Hardware:**
- CPU: Intel/AMD x64, 4+ cores
- RAM: 16 GB (32 GB recommended for full stack)
- Disk: 100 GB free space (SSD strongly recommended)
- Network: At least one Ethernet adapter

**Operating System:**
- Windows 10 Pro/Enterprise (version 21H2 or later)
- Windows 11 Pro/Enterprise
- Windows Server 2019 or 2022
- **Note:** Home editions are NOT supported (kernel driver signing requirements)

**Administrator Access:**
- You MUST have administrator privileges
- Scripts must be run as Administrator
- Kernel driver installation requires elevated privileges

### Required Software

All software listed below will be automatically installed by the installer script if you use the PowerShell approach. For manual installation, follow the individual component instructions.

#### Core Development Tools

1. **Visual Studio 2022 Community/Professional**
   - Desktop development with C++
   - Windows Driver Kit component
   - Windows SDK component

2. **Windows Driver Kit (WDK) 10.0.22621.0 or later**
   - Must be installed AFTER Visual Studio
   - Required for kernel driver compilation

3. **Windows SDK 10.0.22621.0 or later**
   - Included with Visual Studio or available separately

#### Language Runtimes

4. **Go 1.21.5 or later**
   - Required for service components
   - Add to system PATH

5. **Rust 1.74 or later**
   - Required for shared libraries
   - Includes Cargo package manager

6. **Protocol Buffers (protoc) 3.21.0 or later**
   - Required for gRPC communication
   - For Go and Rust code generation

#### Database and Caching

7. **PostgreSQL 16.x**
   - Default credentials: username=postgres, password=postgres
   - Port: 5432
   - Must be running as Windows service

8. **Redis 7.x or later**
   - Default port: 6379
   - Optional password in production

#### Optional Tools

9. **Docker Desktop** (Optional but recommended)
   - Required for containerized testing
   - Requires Windows Pro/Enterprise with Hyper-V

10. **Node.js 20.x LTS** (Optional for UI development)
    - Required only if building management console UI
    - Includes npm package manager

---

## System Requirements Check

### Enable Test Signing Mode

For kernel driver testing and installation:

```cmd
REM Run as Administrator
bcdedit /set testsigning on
shutdown /r /t 0
```

**Verify test signing is enabled:**

```cmd
bcdedit /enum {current} | findstr testsigning
```

Expected output: `testsigning             Yes`

### Verify Administrator Privileges

```powershell
$currentUser = [Security.Principal.WindowsIdentity]::GetCurrent()
$principal = New-Object Security.Principal.WindowsPrincipal($currentUser)
$isAdmin = $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
Write-Host "Is Administrator: $isAdmin"
```

---

## Step-by-Step Installation

### Option 1: Automated Installation (Recommended)

This is the quickest way to get SafeOps running on a clean machine.

#### Step 1: Download the Installer

Clone the SafeOps repository:

```powershell
cd C:\
git clone https://github.com/your-username/SafeOps-Firewall-V2.git
cd SafeOps-Firewall-V2
```

#### Step 2: Run the Installation Script

Run PowerShell as Administrator, then:

```powershell
# Navigate to the project root
cd C:\SafeOps-Firewall-V2

# Run the installer
.\Install-SafeOpsDev.ps1
```

**Installation Options:**

```powershell
# Full installation (includes all optional components)
.\Install-SafeOpsDev.ps1

# Skip optional components (Docker, Node.js, VS Code)
.\Install-SafeOpsDev.ps1 -SkipOptional

# Custom installation path
.\Install-SafeOpsDev.ps1 -InstallPath "D:\MyDev"

# Unattended mode (no prompts)
.\Install-SafeOpsDev.ps1 -Unattended
```

#### Step 3: Wait for Completion

The installation will take 15-30 minutes depending on internet speed and disk I/O.

**What gets installed:**
- Chocolatey package manager
- Visual Studio 2022 (with required workloads)
- Windows Driver Kit (WDK)
- Go toolchain
- Rust toolchain
- PostgreSQL 16
- Redis 7
- Protocol Buffers compiler
- Optional: Docker Desktop, Node.js, VS Code, Consul

#### Step 4: Restart Computer

After installation completes, restart your computer to update PATH environment variables and start services.

```powershell
shutdown /r /t 30
```

#### Step 5: Verify Installation

After restart, open PowerShell as Administrator and run:

```powershell
# Check all required tools are installed
go version
rustc --version
cargo --version
git --version
protoc --version
psql --version
redis-cli ping

# Expected outputs:
# go version go1.21.5 windows/amd64
# rustc 1.74.x
# cargo 1.74.x
# git version 2.x.x
# libprotoc 3.21.x
# psql (PostgreSQL) 16.x
# PONG
```

---

## Using PowerShell Scripts

### Main Installation Script: Install-SafeOpsDev.ps1

**Location:** `C:\SafeOps-Firewall-V2\Install-SafeOpsDev.ps1`

**Purpose:** Complete development environment installation

**Syntax:**

```powershell
.\Install-SafeOpsDev.ps1 [Options]
```

**Options:**

| Option | Type | Description |
|--------|------|-------------|
| `-SkipOptional` | Switch | Skip Docker, Node.js, VS Code, Consul |
| `-InstallPath` | String | Custom installation directory (default: C:\SafeOpsDev) |
| `-Unattended` | Switch | Run without user prompts |
| `-SkipChecks` | Switch | Skip system requirement checks |

**Examples:**

```powershell
# Full installation with progress prompts
.\Install-SafeOpsDev.ps1

# Fast installation, skipping optional tools
.\Install-SafeOpsDev.ps1 -SkipOptional

# Install to custom location without prompts
.\Install-SafeOpsDev.ps1 -InstallPath "D:\SafeOps" -Unattended

# Full installation, skipping system checks (assumes system is ready)
.\Install-SafeOpsDev.ps1 -SkipChecks
```

### Build Automation: safeops_installer.ps1

**Location:** `C:\SafeOps-Firewall-V2\safeops_installer.ps1`

**Purpose:** Build entire SafeOps system from source

**Syntax:**

```powershell
.\safeops_installer.ps1 [Options]
```

**Available Options:**

- `-BuildKernelDriver` - Build kernel driver (SafeOps.sys)
- `-BuildUserspace` - Build userspace service
- `-BuildSharedLibs` - Build shared libraries (Go, Rust, C)
- `-BuildAll` - Build all components
- `-Clean` - Clean build (rebuild from scratch)
- `-Release` - Build release configuration
- `-Debug` - Build debug configuration

**Examples:**

```powershell
# Build all components in debug mode
.\safeops_installer.ps1 -BuildAll -Debug

# Build only kernel driver in release mode
.\safeops_installer.ps1 -BuildKernelDriver -Release

# Clean build of everything
.\safeops_installer.ps1 -BuildAll -Clean -Release
```

### Configuration Script: config/config_validator.ps1

**Purpose:** Validate and set up configuration files

**Syntax:**

```powershell
.\config\config_validator.ps1
```

---

## Manual Installation Steps

If you prefer not to use automated scripts, follow these manual steps.

### Step 1: Install Visual Studio 2022

1. Download Visual Studio 2022 Community from https://visualstudio.microsoft.com/downloads/
2. Run the installer with administrator privileges
3. Choose "Desktop development with C++"
4. Under "Individual Components", search for and select:
   - Windows Driver Kit (any version)
   - Windows SDK (10.0.22621.0 or later)
5. Click "Install" and wait for completion (20-30 minutes)

**Verify Installation:**

```cmd
where cl.exe
where link.exe
where nmake.exe
```

All three commands should return valid paths in `C:\Program Files\Microsoft Visual Studio\2022\`.

### Step 2: Install Windows Driver Kit (WDK)

1. Download WDK from https://docs.microsoft.com/en-us/windows-hardware/drivers/download-the-wdk
2. Choose the version matching your Visual Studio version
3. Run the installer with administrator privileges
4. Choose "Install to local disk" and "Install the Windows Driver Kit"
5. Point to your Visual Studio 2022 installation when prompted

**Verify Installation:**

```cmd
where wdftemplates.exe
where wdfkd.dll
```

### Step 3: Install Go

1. Download Go from https://golang.org/dl/ (version 1.21.5 or later)
2. Run the MSI installer with administrator privileges
3. Accept default installation path (C:\Program Files\Go)
4. Close and reopen PowerShell to update PATH

**Verify Installation:**

```powershell
go version
go env GOPATH
```

### Step 4: Install Rust

1. Download Rustup from https://rustup.rs/
2. Run rustup-init.exe with administrator privileges
3. Choose option 1 (default) when prompted
4. Close and reopen PowerShell to update PATH

**Verify Installation:**

```powershell
rustc --version
cargo --version
rustup show
```

### Step 5: Install Protocol Buffers

1. Download protoc from https://github.com/protocolbuffers/protobuf/releases (Windows x64 version)
2. Extract to a permanent location (e.g., C:\Program Files\protobuf)
3. Add the bin folder to your PATH environment variable
4. Restart PowerShell

**Verify Installation:**

```powershell
protoc --version
```

### Step 6: Install PostgreSQL

1. Download PostgreSQL 16 from https://www.postgresql.org/download/windows/
2. Run the installer with administrator privileges
3. Set password for postgres user (remember this!)
4. Accept default port 5432
5. Choose to install as Windows service

**Verify Installation:**

```powershell
psql --version
psql -U postgres -c "SELECT version();"
```

### Step 7: Install Redis

**Option A: Using Memurai (Windows Redis)**

1. Download from https://www.memurai.com/
2. Run installer with administrator privileges
3. Install as Windows service

**Option B: Using Chocolatey**

```powershell
choco install redis-64 -y
```

**Verify Installation:**

```powershell
redis-cli ping
# Should return: PONG
```

### Step 8: Clone SafeOps Repository

```powershell
# Create workspace directory
mkdir C:\SafeOps-Dev
cd C:\SafeOps-Dev

# Clone the repository
git clone https://github.com/your-username/SafeOps-Firewall-V2.git
cd SafeOps-Firewall-V2

# Verify directory structure
ls
```

---

## Building Components

### Build Kernel Driver

The kernel driver must be built from the x64 Native Tools Command Prompt.

#### Step 1: Open Build Environment

1. Press Windows key and search for "x64 Native Tools Command Prompt for VS 2022"
2. Run as Administrator
3. Navigate to kernel driver directory:

```cmd
cd C:\SafeOps-Firewall-V2\src\kernel_driver
```

#### Step 2: Build Using Makefile

```cmd
REM Debug build
nmake BUILD=debug

REM Release build (default)
nmake BUILD=release

REM Clean build
nmake clean
nmake BUILD=release

REM Check for errors
echo Checking for SafeOps.sys...
dir obj\amd64\SafeOps.sys
```

#### Step 3: Verify Output

After successful build, you should see:

```
obj\amd64\SafeOps.sys              - Kernel driver
obj\amd64\SafeOps.pdb              - Debug symbols
obj\amd64\SafeOps.inf              - Installation info file
```

**Expected Build Time:** 2-5 minutes

### Build Userspace Service

The userspace service must be built from the x64 Native Tools Command Prompt.

#### Step 1: Open Build Environment

Same as above - open x64 Native Tools Command Prompt for VS 2022 as Administrator

#### Step 2: Navigate to Service Directory

```cmd
cd C:\SafeOps-Firewall-V2\src\userspace_service
```

#### Step 3: Build Using Script

```cmd
REM Debug build
build.cmd debug

REM Release build (default)
build.cmd release

REM Clean and rebuild
build.cmd release clean
```

#### Step 4: Verify Output

After successful build:

```
build\SafeOpsService.exe            - Service executable
build\SafeOpsService.pdb            - Debug symbols
```

**Expected Build Time:** 1-3 minutes

### Build Shared Libraries

Optional: Build shared libraries for other components.

#### Go Libraries

```powershell
cd C:\SafeOps-Firewall-V2\src\shared\go
go mod download
go build ./...
go test ./...
```

#### Rust Libraries

```powershell
cd C:\SafeOps-Firewall-V2\src\shared\rust
cargo build --release
cargo test
```

---

## Installation Verification

### Verify All Prerequisites

Create a verification script to test all requirements:

```powershell
# verify_installation.ps1

Write-Host "SafeOps Installation Verification" -ForegroundColor Green
Write-Host "=================================" -ForegroundColor Green
Write-Host ""

$checks = @(
    @{Name = "Go"; Command = "go version"; MinVersion = "1.21" },
    @{Name = "Rust"; Command = "rustc --version"; MinVersion = "1.74" },
    @{Name = "Cargo"; Command = "cargo --version"; MinVersion = "1.74" },
    @{Name = "Git"; Command = "git --version"; MinVersion = "2.0" },
    @{Name = "Protoc"; Command = "protoc --version"; MinVersion = "3.21" },
    @{Name = "PostgreSQL"; Command = "psql --version"; MinVersion = "16" }
)

$allGood = $true

foreach ($check in $checks) {
    try {
        $output = & cmd /c "$($check.Command)" 2>&1
        Write-Host "✓ $($check.Name): $($output[0])" -ForegroundColor Green
    } catch {
        Write-Host "✗ $($check.Name): NOT FOUND" -ForegroundColor Red
        $allGood = $false
    }
}

# Check services
Write-Host ""
Write-Host "Service Status:" -ForegroundColor Cyan

try {
    $pgService = Get-Service "postgresql*" -ErrorAction SilentlyContinue
    if ($pgService.Status -eq "Running") {
        Write-Host "✓ PostgreSQL: Running" -ForegroundColor Green
    } else {
        Write-Host "✗ PostgreSQL: Stopped" -ForegroundColor Yellow
    }
} catch {
    Write-Host "✗ PostgreSQL: Not installed" -ForegroundColor Red
}

try {
    $redisService = Get-Service "Redis" -ErrorAction SilentlyContinue
    if ($redisService.Status -eq "Running") {
        Write-Host "✓ Redis: Running" -ForegroundColor Green
    } else {
        Write-Host "✗ Redis: Stopped" -ForegroundColor Yellow
    }
} catch {
    Write-Host "✗ Redis: Not installed" -ForegroundColor Red
}

Write-Host ""
if ($allGood) {
    Write-Host "All checks passed! SafeOps is ready for development." -ForegroundColor Green
} else {
    Write-Host "Some checks failed. Please install missing components." -ForegroundColor Red
}
```

### Check Directory Structure

```powershell
# After cloning, verify the project structure
$expected = @(
    "src/kernel_driver",
    "src/userspace_service",
    "src/shared",
    "config",
    "database",
    "docs",
    "tests",
    "ui",
    "BUILD_GUIDE.md",
    "Install-SafeOpsDev.ps1"
)

foreach ($dir in $expected) {
    if (Test-Path $dir) {
        Write-Host "✓ $dir" -ForegroundColor Green
    } else {
        Write-Host "✗ $dir MISSING" -ForegroundColor Red
    }
}
```

---

## Troubleshooting

### Common Installation Issues

#### "Administrator privileges required"

**Symptom:** Script fails with permission denied error.

**Solution:**
1. Right-click PowerShell
2. Select "Run as Administrator"
3. Re-run the installation script

#### Test Signing Not Enabled

**Symptom:** Cannot install kernel driver - "driver not signed" error.

**Solution:**
```cmd
REM Run as Administrator
bcdedit /set testsigning on
shutdown /r /t 0

REM After restart, verify
bcdedit /enum {current} | findstr testsigning
```

#### Missing cl.exe or link.exe

**Symptom:** Build fails with "cl.exe not found" or "link.exe not found".

**Solution:**
1. Reinstall Visual Studio 2022
2. Ensure "Desktop development with C++" workload is selected
3. Run builds from x64 Native Tools Command Prompt for VS 2022 (NOT regular PowerShell)

#### PostgreSQL Won't Start

**Symptom:** PostgreSQL service fails to start or connects refused.

**Solution:**
```powershell
# Check service status
Get-Service "postgresql*" | Format-List Name, Status

# Start the service manually
Start-Service postgresql-x64-16

# Check if listening on port 5432
netstat -ano | findstr :5432

# Try connection
psql -U postgres -h localhost
```

#### Redis Connection Refused

**Symptom:** `redis-cli ping` returns "Could not connect to Redis".

**Solution:**
```powershell
# Check service status
Get-Service Redis | Format-List Name, Status

# Start Redis
Start-Service Redis

# Verify listening port
netstat -ano | findstr :6379

# Test connection again
redis-cli ping
```

#### PATH Not Updated

**Symptom:** Commands like `go`, `rustc`, `protoc` not found after installation.

**Solution:**
```powershell
# Reload PATH environment variables
$env:Path = [System.Environment]::GetEnvironmentVariable("Path","Machine") + ";" + [System.Environment]::GetEnvironmentVariable("Path","User")

# Verify
go version
rustc --version
```

Or restart PowerShell/Command Prompt completely.

#### Build Fails with "missing files"

**Symptom:** Build script reports missing header files or source files.

**Solution:**
1. Verify all files are present:
```cmd
dir src\kernel_driver\*.c
dir src\kernel_driver\*.h
dir src\userspace_service\*.c
dir src\userspace_service\*.h
```

2. If files are truly missing, rebuild from git:
```powershell
git status
git checkout -- .  # Restore all files
```

#### Cannot Find nmake

**Symptom:** "nmake: command not found" when building kernel driver.

**Solution:**
1. You MUST build from x64 Native Tools Command Prompt for VS 2022
2. This command prompt is NOT the same as regular PowerShell
3. Find it in Start Menu > Visual Studio 2022 > x64 Native Tools Command Prompt
4. Run as Administrator

---

## Common Issues and Solutions

### Issue: Installation Takes Too Long

**Cause:** Internet speed, disk I/O, or large file downloads

**Solution:**
- Ensure stable internet connection
- Use SSD for installation (much faster than HDD)
- Install to local drive (not network drive)
- If stuck, check C:\ProgramData\chocolatey\logs\ for progress

### Issue: PowerShell Execution Policy Error

**Error:** "cannot be loaded because running scripts is disabled on this system"

**Solution:**
```powershell
# Temporarily allow script execution for current session
Set-ExecutionPolicy -ExecutionPolicy Bypass -Scope Process

# Run the installer
.\Install-SafeOpsDev.ps1
```

### Issue: Chocolatey Installation Fails

**Error:** Chocolatey not found after installation

**Solution:**
```powershell
# Manual Chocolatey installation
Set-ExecutionPolicy Bypass -Scope Process -Force
[System.Net.ServicePointManager]::SecurityProtocol = [System.Net.ServicePointManager]::SecurityProtocol -bor 3072
iex ((New-Object System.Net.WebClient).DownloadString('https://community.chocolatey.org/install.ps1'))

# Restart PowerShell for changes to take effect
```

### Issue: WDK Installation Fails

**Error:** "Could not find Visual Studio installation"

**Solution:**
1. Reinstall in correct order: Visual Studio FIRST, then WDK
2. WDK must be installed to VS 2022, not earlier versions
3. Verify VS 2022 installation with:
```cmd
where devenv.exe
```

### Issue: PostgreSQL Startup Fails

**Error:** "The specified service does not exist as an installed service"

**Solution:**
1. Manually register PostgreSQL service:
```cmd
REM Run as Administrator
pg_ctl register -N postgresql-x64-16 -D "C:\Program Files\PostgreSQL\16\data"
```

2. Start the service:
```powershell
Start-Service postgresql-x64-16
```

### Issue: Kernel Driver Build Fails with WDK Errors

**Error:** "Cannot find WDK headers" or "Unknown directive"

**Solution:**
1. Verify WDK is installed in VS 2022 components
2. Build from x64 Native Tools Command Prompt (not PowerShell)
3. Verify environment variables:
```cmd
echo %WindowsSDKVersion%
echo %VCINSTALLDIR%
```

4. Clean and rebuild:
```cmd
cd src\kernel_driver
nmake clean
nmake BUILD=release
```

---

## Next Steps After Installation

1. **Restart Computer** (required for PATH variables and services to start)

2. **Verify Installation** - Run verification script:
   ```powershell
   # See "Installation Verification" section above
   ```

3. **Review Build Guide** - Read `BUILD_GUIDE.md` for detailed build instructions

4. **Start Development** - Begin developing components:
   - Modify kernel driver: `src/kernel_driver/`
   - Modify userspace service: `src/userspace_service/`
   - Develop services: `src/[service_name]/`

5. **Run Tests** - See `TESTING_VERIFICATION.md` for testing procedures

6. **Set Up IDE** - Configure Visual Studio or VS Code:
   - Open solution files in Visual Studio 2022
   - Or open project root in VS Code with C++ extension

---

## Getting Help

If you encounter issues not covered here:

1. Check the `BUILD_GUIDE.md` for component-specific issues
2. Check the `TESTING_VERIFICATION.md` for verification procedures
3. Review logs:
   - Installation logs: `C:\SafeOpsDev\logs\`
   - Build logs: Check console output or build directory
4. Check existing issues on GitHub
5. Review service configuration in `config/` directory

---

## Summary Checklist

Use this checklist to verify successful installation:

- [ ] Administrator privileges verified
- [ ] Test signing mode enabled
- [ ] Visual Studio 2022 installed with C++ workload
- [ ] Windows Driver Kit installed
- [ ] Go 1.21.5+ installed
- [ ] Rust 1.74+ installed
- [ ] Protocol Buffers compiler installed
- [ ] PostgreSQL 16 running as service
- [ ] Redis running as service
- [ ] SafeOps repository cloned
- [ ] Kernel driver builds successfully
- [ ] Userspace service builds successfully
- [ ] All verification checks pass
- [ ] Ready to start development

Once all items are checked, proceed to `BUILD_GUIDE.md` for detailed build instructions and then to `TESTING_VERIFICATION.md` for testing procedures.
