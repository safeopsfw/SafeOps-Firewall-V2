# Windows Service Installation - Future Implementation

> **Status**: Planned for future implementation  
> **Priority**: Medium  
> **Last Updated**: 2026-01-23

## Overview

This document outlines how to install SafeOps Firewall Engine and SafeOps Launcher as Windows Services that start automatically at boot time.

## Current State

Currently, the SafeOps executables run as foreground processes:
- `SafeOps-Launcher.exe` - Starts all SafeOps services
- `firewall-engine.exe` - Firewall Engine V4 with WFP dual-engine support

## Goal

Install these as Windows Services so they:
1. Start automatically when Windows boots (before user login)
2. Run in the background without a console window
3. Restart automatically on failure
4. Respect Windows service lifecycle (stop/start/pause)

## Implementation Approaches

### Option 1: Native Windows Service with `golang.org/x/sys/windows/svc`

```go
import (
    "golang.org/x/sys/windows/svc"
    "golang.org/x/sys/windows/svc/mgr"
)

// Service struct implementing svc.Handler
type SafeOpsService struct {
    // ... service state
}

func (s *SafeOpsService) Execute(args []string, r <-chan svc.ChangeRequest, changes chan<- svc.Status) (bool, uint32) {
    // Report service startup
    changes <- svc.Status{State: svc.StartPending}
    
    // Initialize and start services
    // ... 
    
    changes <- svc.Status{State: svc.Running, Accepts: svc.AcceptStop | svc.AcceptShutdown}
    
    // Handle service control requests
    for c := range r {
        switch c.Cmd {
        case svc.Stop, svc.Shutdown:
            changes <- svc.Status{State: svc.StopPending}
            // Graceful shutdown
            return false, 0
        }
    }
    return false, 0
}
```

### Option 2: NSSM (Non-Sucking Service Manager)

A simpler approach using NSSM:
```powershell
# Install as service
nssm install SafeOpsLauncher "D:\SafeOpsFV2\bin\SafeOps-Launcher.exe"
nssm set SafeOpsLauncher Description "SafeOps Firewall & Security Services"
nssm set SafeOpsLauncher Start SERVICE_AUTO_START
nssm set SafeOpsLauncher AppPriority ABOVE_NORMAL_PRIORITY_CLASS

# For firewall (if running standalone)
nssm install SafeOpsFirewall "D:\SafeOpsFV2\bin\firewall-engine\firewall-engine.exe"
nssm set SafeOpsFirewall Start SERVICE_AUTO_START
nssm set SafeOpsFirewall DependOnService SafeOpsEngine
```

### Option 3: sc.exe with wrapper

```cmd
sc create SafeOpsLauncher binPath= "D:\SafeOpsFV2\bin\SafeOps-Launcher.exe" start= auto
sc description SafeOpsLauncher "SafeOps Firewall and Security Services"
sc failure SafeOpsLauncher reset= 86400 actions= restart/60000/restart/60000/restart/60000
```

> ⚠️ This requires the exe to be built as a proper Windows service handler.

## Recommended Approach

**Use Option 1 (Native Go Windows Service)** for production because:
- No external dependencies (like NSSM)
- Full control over service lifecycle
- Proper integration with Windows Event Log
- Can implement health checks and recovery

## Service Dependencies

```
SafeOpsLauncher
├── DependsOn: Base Filtering Engine (BFE) - for WFP
├── DependsOn: TCP/IP (Tcpip) - for network
└── Starts:
    ├── SafeOps Engine
    ├── Firewall Engine V4 (with WFP)
    ├── Network Logger
    ├── DHCP Monitor
    └── (other services)
```

## WFP Boot-Time Protection

The WFP persistent filters are *already* boot-time active:
- `FWPM_FILTER_FLAG_PERSISTENT` filters survive reboots
- They activate when BFE service starts (very early in boot)
- Critical rules are protected even before our service starts

## Installation Script (Future)

```powershell
# install-service.ps1
param(
    [switch]$Install,
    [switch]$Uninstall
)

$ServiceName = "SafeOpsLauncher"
$ServicePath = "$PSScriptRoot\bin\SafeOps-Launcher.exe"

if ($Install) {
    # Check admin rights
    if (-not ([Security.Principal.WindowsPrincipal]::new([Security.Principal.WindowsIdentity]::GetCurrent())).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        throw "Administrator rights required"
    }
    
    # Register service
    & $ServicePath -install
    
    # Set to auto-start
    Set-Service -Name $ServiceName -StartupType Automatic
    
    # Start service
    Start-Service -Name $ServiceName
}

if ($Uninstall) {
    Stop-Service -Name $ServiceName -Force
    & $ServicePath -uninstall
}
```

## Files to Modify for Implementation

1. **`src/launcher/main.go`** - Add service mode detection and handler
2. **`src/firewall_engine/cmd/main.go`** - Add service mode (optional, if standalone)
3. **Create `src/launcher/service_windows.go`** - Windows-specific service code
4. **Create `scripts/install-service.ps1`** - Installation script

## References

- [Go Windows Service Package](https://pkg.go.dev/golang.org/x/sys/windows/svc)
- [NSSM Documentation](https://nssm.cc/usage)
- [Windows Service Best Practices](https://docs.microsoft.com/en-us/windows/win32/services/services)

---

**Next Step**: When ready to implement, create a task to add Windows Service support following Option 1.
