# SafeOps v2.0 Installation Scripts - Comprehensive Guide

**Document Version:** 1.0
**Created:** 2025-12-25
**Status:** Production Ready

---

## Overview

SafeOps v2.0 provides three comprehensive PowerShell scripts for complete installation, uninstallation, and verification of the kernel driver and userspace service on Windows systems.

### Script Files

| Script | Purpose | Lines | Size |
|--------|---------|-------|------|
| `install_safeops.ps1` | Complete installation with all setup steps | 882 | 31 KB |
| `uninstall_safeops.ps1` | Safe removal with configuration preservation | 474 | 18 KB |
| `verify_installation.ps1` | Comprehensive health check and diagnostics | 622 | 25 KB |

---

## Installation Script - `install_safeops.ps1`

### Purpose
Automated installation of SafeOps v2.0 kernel driver and userspace service with comprehensive error handling, logging, and verification.

### Usage

#### Basic Installation
```powershell
# Run as Administrator
.\install_safeops.ps1
```

#### With Specific Paths
```powershell
.\install_safeops.ps1 -DriverPath "C:\path\to\SafeOps.sys" -ServicePath "C:\path\to\SafeOpsService.exe"
```

#### Debug Mode
```powershell
.\install_safeops.ps1 -EnableDebugMode
```

#### Unattended Installation
```powershell
.\install_safeops.ps1 -Unattended
```

#### Skip Post-Installation Verification
```powershell
.\install_safeops.ps1 -SkipVerification
```

### Features

#### 1. Pre-Installation Checks
- Administrator privilege verification
- Windows version compatibility check (Windows 10/11, Server 2019/2022)
- Test signing mode validation
- Build artifact verification
- Existing installation detection

#### 2. Test Signing Configuration
- Automatic detection of test signing status
- One-click test signing enablement via `bcdedit`
- System restart management
- Automatic re-entry after restart

#### 3. Directory Setup
Creates installation structure:
```
C:\Program Files\SafeOps\              # Application directory
├── SafeOps.sys                        # Kernel driver
├── SafeOpsService.exe                 # Userspace service
└── [Other binaries]

%APPDATA%\SafeOps\                     # Configuration
├── defaults/
├── ids_ips/
├── network/
├── firewall/
└── safeops.conf

%ProgramData%\SafeOps\Logs\            # Logging
└── [log files]
```

#### 4. Kernel Driver Installation
- Binary copy to installation directory
- Service creation (type: Kernel)
- Service startup management
- Error handling and recovery

#### 5. Userspace Service Installation
- Executable copy to installation directory
- Service registration with Windows
- Startup type configuration (Automatic)
- Dependency management (Tcpip, WinSock2)
- Recovery options setup (auto-restart on failure)

#### 6. Configuration Setup
- Default configuration file generation
- Configuration directory structure creation
- Permission management
- Template configuration with logging and performance settings

#### 7. Post-Installation Verification
- Service status checks
- Installation file verification
- Event Viewer error detection
- Health assessment

#### 8. Helper Script Generation
- Automatic creation of `uninstall_safeops.ps1`
- Automatic creation of `verify_installation.ps1`

### Installation Flow

```
┌─────────────────────────────────────────┐
│    Pre-Installation Checks              │
│  ├─ Admin privileges                    │
│  ├─ OS version                          │
│  ├─ Test signing                        │
│  ├─ Build artifacts                     │
│  └─ Existing installation               │
└──────────────┬──────────────────────────┘
               │
┌──────────────▼──────────────────────────┐
│    Directory Setup                      │
│  ├─ Create install directory            │
│  ├─ Create config directory             │
│  └─ Create log directory                │
└──────────────┬──────────────────────────┘
               │
┌──────────────▼──────────────────────────┐
│    Kernel Driver Installation           │
│  ├─ Copy SafeOps.sys                    │
│  ├─ Create driver service               │
│  └─ Start driver                        │
└──────────────┬──────────────────────────┘
               │
┌──────────────▼──────────────────────────┐
│    Userspace Service Installation       │
│  ├─ Copy SafeOpsService.exe             │
│  ├─ Register service                    │
│  ├─ Configure recovery                  │
│  └─ Start service                       │
└──────────────┬──────────────────────────┘
               │
┌──────────────▼──────────────────────────┐
│    Configuration Setup                  │
│  ├─ Create config directories           │
│  ├─ Generate config file                │
│  └─ Set permissions                     │
└──────────────┬──────────────────────────┘
               │
┌──────────────▼──────────────────────────┐
│    Verification                         │
│  ├─ Check driver status                 │
│  ├─ Check service status                │
│  ├─ Verify files                        │
│  └─ Check Event Viewer                  │
└──────────────┬──────────────────────────┘
               │
┌──────────────▼──────────────────────────┐
│    Summary & Helper Scripts             │
│  └─ Create uninstall/verify scripts     │
└─────────────────────────────────────────┘
```

### Logging

All installation activity is logged to:
```
%TEMP%\safeops_install_YYYYMMDD_HHMMSS.log
```

Log entries include:
- Timestamp
- Log level (INFO, WARNING, ERROR, SUCCESS, DEBUG)
- Detailed messages
- Stack traces for errors

### Configuration Files

#### Default Configuration (`safeops.conf`)
```ini
[Service]
Name=SafeOpsService
Version=2.0.0
Description=Enterprise Network Security Gateway

[Driver]
Name=SafeOps.sys
Version=2.0.0

[Logging]
LogLevel=INFO
LogPath=%ProgramData%\SafeOps\Logs
MaxLogSize=104857600
LogRotation=true

[Performance]
PacketBufferSize=1048576
RingBufferSize=2097152
MaxConnections=10000

[Network]
EnableIPv4=true
EnableIPv6=true
EnablePacketCapture=true

[Security]
EnableSignatureVerification=true
RequireKernelMode=true
```

### Error Handling

The script provides comprehensive error handling:
- Try-catch blocks for all critical operations
- Detailed error messages with remediation suggestions
- Automatic cleanup on failure
- Service state recovery
- Registry rollback capabilities

### Parameters

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| SkipVerification | Switch | False | Skip post-install verification |
| Unattended | Switch | False | Non-interactive mode |
| DriverPath | String | Auto-detect | Path to SafeOps.sys |
| ServicePath | String | Auto-detect | Path to SafeOpsService.exe |
| LogPath | String | Auto-generate | Custom log file path |
| EnableDebugMode | Switch | False | Verbose debug output |

---

## Uninstallation Script - `uninstall_safeops.ps1`

### Purpose
Safe removal of SafeOps with flexible configuration and log preservation.

### Usage

#### Basic Uninstallation
```powershell
# Run as Administrator
.\uninstall_safeops.ps1
```

#### Remove Everything Including Configuration
```powershell
.\uninstall_safeops.ps1 -RemoveConfig -RemoveLogs
```

#### Unattended Removal
```powershell
.\uninstall_safeops.ps1 -Unattended
```

### Features

#### 1. Pre-Uninstallation Checks
- Administrator privilege verification
- Installation detection
- User confirmation (interactive mode)

#### 2. Service Management
- Graceful service shutdown
- Driver service stop
- Service registry removal
- Error handling for stuck services

#### 3. File Removal
- Installation directory cleanup
- Configuration preservation (by default)
- Log preservation (by default)
- Orphaned file detection

#### 4. Configuration Options
- **Default behavior:** Preserves configuration and logs
- **-RemoveConfig:** Also removes configuration directory
- **-RemoveLogs:** Also removes log files
- **-Unattended:** Skips confirmation prompts

#### 5. Registry Cleanup
- Service registry key verification
- Orphaned registry detection
- Automatic cleanup via service removal

#### 6. Firewall Rules Cleanup
- SafeOps firewall rule detection
- Automatic rule removal
- Graceful error handling

#### 7. Event Log Handling
- Event log entry preservation
- Archive support
- Safe cleanup procedures

### Uninstallation Flow

```
┌──────────────────────────────────────────┐
│    Pre-Uninstallation Checks             │
│  ├─ Admin privileges                     │
│  ├─ Installation detection               │
│  └─ User confirmation                    │
└────────────────┬─────────────────────────┘
                 │
┌────────────────▼─────────────────────────┐
│    Stop Services                         │
│  ├─ Stop userspace service               │
│  └─ Stop kernel driver                   │
└────────────────┬─────────────────────────┘
                 │
┌────────────────▼─────────────────────────┐
│    Remove Services                       │
│  ├─ Remove from registry                 │
│  └─ Clean up service entries             │
└────────────────┬─────────────────────────┘
                 │
┌────────────────▼─────────────────────────┐
│    File Removal                          │
│  ├─ Remove installation directory        │
│  ├─ Preserve config (optional)           │
│  └─ Preserve logs (optional)             │
└────────────────┬─────────────────────────┘
                 │
┌────────────────▼─────────────────────────┐
│    Cleanup Operations                    │
│  ├─ Registry cleanup                     │
│  ├─ Firewall rules                       │
│  └─ Event log entries                    │
└────────────────┬─────────────────────────┘
                 │
┌────────────────▼─────────────────────────┐
│    Summary & Log                         │
│  └─ Generate uninstall report            │
└──────────────────────────────────────────┘
```

### Logging

Uninstallation activity is logged to:
```
%TEMP%\safeops_uninstall_YYYYMMDD_HHMMSS.log
```

### Parameters

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| RemoveConfig | Switch | False | Remove configuration directory |
| RemoveLogs | Switch | False | Remove log files |
| Unattended | Switch | False | Non-interactive mode |

---

## Verification Script - `verify_installation.ps1`

### Purpose
Comprehensive health check and diagnostics for SafeOps installation.

### Usage

#### Basic Verification
```powershell
.\verify_installation.ps1
```

#### Verbose Output
```powershell
.\verify_installation.ps1 -Verbose
```

#### Full Report with Details
```powershell
.\verify_installation.ps1 -FullReport -Verbose
```

### Features

#### 1. System Information
- Hostname and user details
- OS version and architecture
- PowerShell version
- Build information
- Test signing status

#### 2. Service Status
- Userspace service (SafeOpsService) status
- Kernel driver (SafeOps) status
- Startup type verification
- Display names and descriptions
- Service dependencies

#### 3. Installation Files
- Installation directory existence
- Kernel driver file verification
  - File location
  - File size
  - Last modified time
- Userspace service executable verification
  - File location
  - File size
  - Last modified time

#### 4. Configuration Verification
- Configuration directory existence
- Configuration file presence
- Subdirectory enumeration
  - defaults/
  - ids_ips/
  - network/
  - firewall/

#### 5. Logging Status
- Log directory existence
- Log file enumeration
- Log file sizes
- Recent activity tracking

#### 6. Event Viewer Analysis
- SafeOps event count
- Recent event display (last 5)
- Error event detection
- Warning categorization
- Event timestamp tracking

#### 7. Network Configuration
- Active network adapter detection
- Adapter count and details
- Interface descriptions
- DNS resolution testing

#### 8. Registry Check
- Service registry entries
- Driver registry entries
- Key existence verification

#### 9. Comprehensive Reporting
- Pass/Fail/Warning summary
- Success rate calculation
- Detailed check listing
- Health status assessment

### Verification Report

#### Health Status Levels

- **HEALTHY** - All critical components functional
- **DEGRADED** - Some components may not be working
- **UNHEALTHY** - Multiple critical failures

#### Report Sections

```
System Information
├─ Hostname, User
├─ OS Version
├─ Architecture
├─ PowerShell Version
└─ Test Signing Status

Service Status
├─ Userspace Service
│  ├─ Running/Stopped
│  ├─ Startup Type
│  └─ Dependencies
└─ Kernel Driver
   ├─ Running/Stopped
   ├─ Startup Type
   └─ Display Name

Installation Files
├─ Installation Directory
├─ Kernel Driver File
│  ├─ Exists/Missing
│  ├─ Size
│  └─ Modified Date
└─ Service Executable
   ├─ Exists/Missing
   ├─ Size
   └─ Modified Date

Configuration
├─ Config Directory
├─ Config File
└─ Subdirectories

Logging
├─ Log Directory
└─ Log Files

Event Viewer
├─ Recent Events
├─ Error Count
└─ Warnings

Network
├─ Active Adapters
└─ DNS Resolution

Registry
├─ Service Entry
└─ Driver Entry

SUMMARY
├─ Passed Checks
├─ Failed Checks
├─ Warnings
└─ Success Rate
```

### Exit Codes

| Code | Meaning |
|------|---------|
| 0 | All checks passed (HEALTHY) |
| 1 | Some checks failed (DEGRADED/UNHEALTHY) |

### Parameters

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| Verbose | Switch | False | Show detailed messages |
| FullReport | Switch | False | Display complete check results |

---

## Implementation Details

### Service Configuration

#### Kernel Driver Service
```
Service Name: SafeOps
Type: Kernel (Windows Driver)
Startup: Demand
Binary Path: C:\Program Files\SafeOps\SafeOps.sys
```

#### Userspace Service
```
Service Name: SafeOpsService
Display Name: SafeOps Network Security Service
Description: SafeOps v2.0 - Enterprise Network Security Gateway
Startup: Automatic
Binary Path: C:\Program Files\SafeOps\SafeOpsService.exe
Dependencies: Tcpip, WinSock2
Recovery: Restart service on failure (5 second intervals)
```

### Directory Structure Created

```
C:\Program Files\SafeOps\
├── SafeOps.sys                 # Kernel driver
└── SafeOpsService.exe          # Userspace service

%APPDATA%\SafeOps\
├── safeops.conf                # Main configuration
├── defaults/                   # Default configurations
├── ids_ips/                    # IDS/IPS rules
├── network/                    # Network policies
└── firewall/                   # Firewall rules

%ProgramData%\SafeOps\
└── Logs/                       # Application logs
    └── *.log                   # Log files
```

### Registry Entries

Services created in:
- `HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\SafeOps`
- `HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\SafeOpsService`

---

## Troubleshooting

### Common Issues

#### "Administrator privileges required"
**Solution:** Right-click PowerShell → "Run as Administrator"

#### "Test signing is NOT enabled"
**Solution:** Script will prompt to enable. System restart required.

#### "Kernel Driver not found"
**Solution:** Verify build artifacts exist at specified paths
```powershell
Test-Path "C:\path\to\build\driver\release\x64\SafeOps.sys"
```

#### "Service failed to start"
**Troubleshooting:**
1. Check Event Viewer for detailed error
2. Verify driver is properly signed
3. Run `verify_installation.ps1` for diagnostics

#### "Configuration not found"
**Solution:** Script creates default configuration automatically

#### "Permission denied on log directory"
**Solution:** Check %ProgramData%\SafeOps\Logs permissions

### Debug Mode

Enable debug output for troubleshooting:
```powershell
.\install_safeops.ps1 -EnableDebugMode
```

### Log Analysis

Review installation logs:
```powershell
Get-Content $env:TEMP\safeops_install_*.log | Select-String ERROR
```

---

## Security Considerations

### Administrator Privileges
All scripts require administrator privileges:
- Kernel driver installation requires kernel-mode access
- Service registration requires registry modifications
- System configuration requires elevated permissions

### Test Signing
Development installations use test signing mode:
- Enabled via `bcdedit /set testsigning on`
- Required for unsigned drivers
- Production should use proper code signing

### Configuration Security
- Configuration files stored in user AppData
- Logs stored in protected ProgramData
- Service runs with appropriate privileges

### Verification Security
- Signature verification checks
- File integrity validation
- Registry consistency checks

---

## Best Practices

### Installation
1. Always run as Administrator
2. Review configuration before deployment
3. Enable debug mode for troubleshooting
4. Save installation logs
5. Test on isolated system first

### Maintenance
1. Monitor logs regularly
2. Run verification script periodically
3. Keep backup of configuration
4. Document customizations

### Uninstallation
1. Preserve configuration for rollback
2. Archive logs before removal
3. Verify service stopped before removal
4. Restart system after uninstall

### Updating
1. Verify current installation
2. Back up configuration
3. Uninstall current version
4. Restart system
5. Install new version

---

## Technical Specifications

### Requirements
- **OS:** Windows 10 Pro/Enterprise, Windows 11, Windows Server 2019/2022
- **Privileges:** Administrator
- **Architecture:** x64 (ARM64 supported with manual configuration)
- **Framework:** PowerShell 5.0+
- **Dependencies:** Windows Driver Kit (WDK) for build only

### Performance Impact
- Driver: ~1-2% CPU in idle state
- Service: ~5-10 MB RAM at rest
- Logging: Configurable, default ~100 MB/month

### Build Artifacts

**Expected File Paths:**
```
build/driver/release/x64/SafeOps.sys
build/userspace_service/release/SafeOpsService.exe
```

These paths can be customized via script parameters.

---

## Appendices

### A. Full Parameter Reference

#### install_safeops.ps1
```powershell
# Example: Custom paths and debug mode
.\install_safeops.ps1 `
    -DriverPath "D:\Builds\SafeOps.sys" `
    -ServicePath "D:\Builds\SafeOpsService.exe" `
    -EnableDebugMode `
    -Unattended
```

#### uninstall_safeops.ps1
```powershell
# Example: Complete removal including configuration
.\uninstall_safeops.ps1 -RemoveConfig -RemoveLogs -Unattended
```

#### verify_installation.ps1
```powershell
# Example: Detailed verification report
.\verify_installation.ps1 -Verbose -FullReport
```

### B. Log File Analysis

Find error entries:
```powershell
Get-Content $env:TEMP\safeops_install_*.log | Select-String "\[ERROR\]"
```

Get recent entries:
```powershell
Get-Content $env:TEMP\safeops_install_*.log | Select-Object -Last 50
```

### C. Service Management Commands

Check service status:
```powershell
Get-Service SafeOpsService, SafeOps
```

Restart service:
```powershell
Restart-Service SafeOpsService
```

View service logs:
```powershell
Get-EventLog System -Source SafeOps | Select-Object -Last 10
```

### D. Event Viewer Locations

- **Application Events:** Event Viewer → Windows Logs → Application
- **System Events:** Event Viewer → Windows Logs → System (Source: SafeOps)
- **Filter:** Source contains "SafeOps"

---

## Version History

| Version | Date | Changes |
|---------|------|---------|
| 1.0 | 2025-12-25 | Initial release |

---

## Support & Documentation

For additional help:
1. Check logs in `%TEMP%\safeops_*.log`
2. Review Event Viewer for system messages
3. Run verification script for diagnostics
4. Consult BUILD_GUIDE.md for compilation
5. Review DOCUMENTATION_INDEX.md for technical details

---

**End of Document**
