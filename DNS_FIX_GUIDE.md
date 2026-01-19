# SafeOps DNS Configuration Fix

## Problem Summary
The SafeOps Engine was losing internet connectivity because the Go proxy couldn't resolve DNS queries. The proxy was using the system's default DNS resolver instead of the local dnsproxy running on port 15353.

## Root Cause
1. **dnsproxy** runs on `127.0.0.1:15353` ✅
2. **WinpkFilter** redirects DNS packets to dnsproxy ✅
3. **BUT**: Go's `net.Dial()` bypasses packet-level redirection and uses the system DNS resolver directly ❌

## Permanent Solution (3-Part Fix)

### 1. **Custom DNS Resolver in Go Proxy**
- Modified `internal/proxy/proxy.go` to use a custom DNS dialer
- All DNS queries from the proxy now go directly to `127.0.0.1:15353`
- Location: `src/safeops-engine/internal/proxy/proxy.go:31-67`

### 2. **Multi-NIC DNS Auto-Configuration**
- New module: `internal/sysconfig/dns_windows.go`
- Automatically configures DNS for **all physical network interfaces** (Wi-Fi, Ethernet, etc.)
- Sets DNS to `127.0.0.1` on startup
- Restores original DNS settings on shutdown
- Skips virtual adapters (VMware, Hyper-V, etc.)

### 3. **Windows Service Auto-Start**
- Service installer: `scripts/install_safeops_service.ps1`
- Complete setup script: `scripts/setup_safeops.ps1`
- Starts automatically on boot (delayed start)
- Runs with administrator privileges

## Installation

### Quick Setup (Recommended)
```powershell
# Run as Administrator
cd D:\SafeOpsFV2
.\scripts\setup_safeops.ps1
```

This will:
1. Build the SafeOps Engine
2. Verify dependencies (dnsproxy, WinpkFilter)
3. Test run for 10 seconds
4. Install as Windows service
5. Configure to auto-start on boot

### Manual Installation

#### Step 1: Build the Engine
```powershell
cd D:\SafeOpsFV2\src\safeops-engine
go build -o safeops-engine.exe ./cmd
```

#### Step 2: Install as Service
```powershell
# Run as Administrator
cd D:\SafeOpsFV2
.\scripts\install_safeops_service.ps1
```

#### Step 3: Start the Service
```powershell
Start-Service SafeOpsEngine
```

## How It Works Now

### Startup Sequence:
1. **Service starts** (on boot or manually)
2. **dnsproxy spawns** on `127.0.0.1:15353`
3. **DNS configurator** detects all physical NICs (Wi-Fi, Ethernet, etc.)
4. **System DNS configured** to `127.0.0.1` on each NIC
5. **Go proxy starts** with custom DNS resolver pointing to `127.0.0.1:15353`
6. **WinpkFilter activates** tunnel mode on all adapters
7. **Ready**: All DNS queries → dnsproxy → upstream DNS (Google/Cloudflare)

### Shutdown Sequence:
1. **Service stops** (shutdown or manually)
2. **DNS restored** to original settings (or DHCP) on all NICs
3. **System proxy disabled**
4. **Clean exit**

## Verification

### Check Service Status
```powershell
Get-Service SafeOpsEngine
```

### Check DNS Configuration
```powershell
# Check all interfaces
netsh interface ipv4 show dnsservers

# Should show 127.0.0.1 for all physical adapters
```

### Check Logs
```powershell
# Main engine log
Get-Content D:\SafeOpsFV2\data\logs\engine.log -Tail 50

# Service logs (if using NSSM)
Get-Content D:\SafeOpsFV2\data\logs\service_stdout.log -Tail 50
```

### Test DNS Resolution
```powershell
# Test if dnsproxy is responding
nslookup google.com 127.0.0.1

# Should return IP addresses
```

### Test Internet Connectivity
```powershell
# Start the service
Start-Service SafeOpsEngine

# Wait 5 seconds
Start-Sleep -Seconds 5

# Test connectivity
Test-NetConnection google.com -Port 443

# Should succeed
```

## Troubleshooting

### Problem: Service won't start
**Solution:**
1. Check if WinpkFilter driver is installed: `sc.exe query ndisapi`
2. Check if dnsproxy.exe exists: `Test-Path D:\SafeOpsFV2\bin\dnsproxy\windows-amd64\dnsproxy.exe`
3. Check logs: `D:\SafeOpsFV2\data\logs\engine.log`

### Problem: No internet after starting
**Solution:**
1. Check DNS configuration: `netsh interface ipv4 show dnsservers`
2. Check if dnsproxy is running: `netstat -ano | findstr 15353`
3. Test DNS: `nslookup google.com 127.0.0.1`
4. Check proxy settings: `netsh winhttp show proxy`

### Problem: DNS not configured on all NICs
**Solution:**
1. Stop service: `Stop-Service SafeOpsEngine`
2. Manually reset DNS to DHCP: `netsh interface ipv4 set dnsservers "Wi-Fi" dhcp`
3. Start service again: `Start-Service SafeOpsEngine`
4. Check logs for DNS configuration messages

### Problem: Service installed but won't auto-start on boot
**Solution:**
```powershell
# Check service startup type
Get-Service SafeOpsEngine | Select-Object Name, StartType, Status

# Should be "Automatic"
# If not, fix it:
Set-Service SafeOpsEngine -StartupType Automatic
```

## Uninstallation

### Remove Service
```powershell
# Run as Administrator
.\scripts\install_safeops_service.ps1 -Uninstall
```

### Manual DNS Reset (if needed)
```powershell
# Reset all interfaces to DHCP
$interfaces = netsh interface show interface | Select-String "Connected" | ForEach-Object { ($_ -split '\s+')[-1] }
foreach ($iface in $interfaces) {
    netsh interface ipv4 set dnsservers $iface dhcp
}
```

### Disable System Proxy
```powershell
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings" /v ProxyEnable /t REG_DWORD /d 0 /f
```

## Service Management

### Start/Stop/Restart
```powershell
Start-Service SafeOpsEngine
Stop-Service SafeOpsEngine
Restart-Service SafeOpsEngine
```

### Check Status
```powershell
Get-Service SafeOpsEngine
```

### View Service Details
```powershell
Get-Service SafeOpsEngine | Format-List *
```

## Architecture Overview

```
┌─────────────────────────────────────────────────────────────┐
│                     Windows System                          │
│                                                             │
│  ┌──────────┐  ┌──────────┐  ┌──────────┐                │
│  │   Wi-Fi  │  │ Ethernet │  │ Ethernet2│ ... (All NICs) │
│  │DNS:127.0.0.1│DNS:127.0.0.1│DNS:127.0.0.1               │
│  └─────┬────┘  └─────┬────┘  └─────┬────┘                │
│        │             │              │                      │
│        └─────────────┼──────────────┘                      │
│                      │                                     │
│                      ▼                                     │
│            ┌──────────────────┐                            │
│            │   dnsproxy       │                            │
│            │ 127.0.0.1:15353  │                            │
│            └────────┬─────────┘                            │
│                     │                                      │
│                     ▼                                      │
│            ┌──────────────────┐                            │
│            │ Upstream DNS     │                            │
│            │ (Google/Cloudflare)                           │
│            └──────────────────┘                            │
│                                                             │
│  ┌──────────────────────────────────────────────────────┐  │
│  │              Go Inline Proxy                         │  │
│  │            127.0.0.1:8080                            │  │
│  │  ┌────────────────────────────────────────────────┐  │  │
│  │  │ Custom DNS Resolver → 127.0.0.1:15353          │  │  │
│  │  └────────────────────────────────────────────────┘  │  │
│  │                                                      │  │
│  │  • HTTP/HTTPS pass-through                          │  │
│  │  • Domain logging                                   │  │
│  │  • No MITM (no certs needed)                        │  │
│  └──────────────────────────────────────────────────────┘  │
│                                                             │
│  ┌──────────────────────────────────────────────────────┐  │
│  │            WinpkFilter Driver                        │  │
│  │  • Packet-level inspection                          │  │
│  │  • DNS redirection (fallback)                       │  │
│  │  • Multi-NIC support                                │  │
│  └──────────────────────────────────────────────────────┘  │
└─────────────────────────────────────────────────────────────┘
```

## Key Files Modified/Created

### New Files:
- `src/safeops-engine/internal/sysconfig/dns_windows.go` - Multi-NIC DNS configurator
- `scripts/install_safeops_service.ps1` - Service installer
- `scripts/setup_safeops.ps1` - Complete setup automation
- `DNS_FIX_GUIDE.md` - This guide

### Modified Files:
- `src/safeops-engine/internal/proxy/proxy.go` - Added custom DNS resolver
- `src/safeops-engine/cmd/main.go` - Added DNS configuration on startup

## Benefits

1. **Auto-start on boot** - No manual intervention needed
2. **Multi-NIC support** - Works with Wi-Fi, Ethernet, multiple adapters
3. **Clean shutdown** - Restores DNS settings properly
4. **No manual DNS config** - Fully automated
5. **Production-ready** - Runs as a Windows service with proper logging
6. **Hotplug support** - Ready for new adapters (future enhancement)

## Future Enhancements

1. **Interface monitoring** - Detect and configure new NICs automatically (VPN, hotplug)
2. **NSSM integration** - Better service management with log rotation
3. **GUI dashboard** - Service status monitoring
4. **Auto-update** - Service restart on binary updates
