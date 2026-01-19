# NDISAPI Files - What's Used and How to Get Them

## Files Currently in Use

### ✅ 1. **Kernel Driver (REQUIRED)**
```
File: C:\Windows\System32\drivers\ndisrd.sys
Version: 3.6.2.1
Status: Running as Windows service
Purpose: NDIS filter driver for packet interception
```

**How to verify:**
```powershell
sc query ndisrd
dir C:\Windows\System32\drivers\ndisrd.sys
```

**How to get:**
1. Download installer from: https://github.com/wiresock/ndisapi/releases
2. Choose: `Windows.Packet.Filter.3.6.2.1.x64.msi` (for 64-bit Windows)
3. Run installer (requires Administrator)
4. Driver will be installed to `C:\Windows\System32\drivers\`

---

### ✅ 2. **Go Package (REQUIRED)**
```
Package: github.com/wiresock/ndisapi-go v1.0.1
Location: Auto-downloaded by Go modules
Purpose: Pure Go wrapper for NDISAPI syscalls
```

**How to get:**
```powershell
# Automatically downloaded when you run:
go mod tidy

# Or explicitly:
go get github.com/wiresock/ndisapi-go@v1.0.1
```

**Where it's stored:**
```
%GOPATH%\pkg\mod\github.com\wiresock\ndisapi-go@v1.0.1\
```

---

## Files NOT Used (Deleted)

### ❌ 1. **ndisapi.dll**
```
Previous Location: D:\SafeOpsFV2\bin\ndisapi.dll
Status: DELETED (not needed)
Reason: Go package uses direct syscalls, doesn't need DLL
```

### ❌ 2. **ndisapi-3.6.2 folder**
```
Previous Location: D:\SafeOpsFV2\bin\ndisapi-3.6.2\
Status: DELETED (not needed)
Reason: Source code not needed for Go implementation
```

---

## Architecture

```
SafeOps Engine (Go)
        ↓
github.com/wiresock/ndisapi-go (Go package)
        ↓
Windows Syscalls (DeviceIoControl)
        ↓
ndisrd.sys (Kernel Driver)
        ↓
Network Stack
```

**Key Point:** The Go package talks directly to the kernel driver via Windows syscalls. No DLL needed!

---

## How SafeOps Engine Uses NDISAPI

### Import Statement:
```go
import "github.com/wiresock/ndisapi-go"
```

### Main API Calls:
```go
// 1. Open driver connection
api, err := ndisapi.NewNdisApi()

// 2. Get network adapters
adapterList, err := api.GetTcpipBoundAdaptersInfo()

// 3. Set tunnel mode
mode := ndisapi.AdapterMode{
    AdapterHandle: adapter.Handle,
    Flags: ndisapi.MSTCP_FLAG_SENT_TUNNEL | ndisapi.MSTCP_FLAG_RECV_TUNNEL,
}
api.SetAdapterMode(&mode)

// 4. Set packet event
api.SetPacketEvent(adapter.Handle, event)

// 5. Read packets
api.ReadPacket(request)

// 6. Forward packets
api.SendPacketToAdapter(request)  // Outbound
api.SendPacketToMstcp(request)    // Inbound

// 7. Close driver
api.Close()
```

---

## Installation Guide

### First Time Setup:

1. **Install WinpkFilter Driver:**
   ```powershell
   # Download from GitHub releases
   Invoke-WebRequest -Uri "https://github.com/wiresock/ndisapi/releases/download/v3.6.2/Windows.Packet.Filter.3.6.2.1.x64.msi" -OutFile "WinpkFilter.msi"
   
   # Run installer (requires Admin)
   Start-Process msiexec.exe -ArgumentList "/i WinpkFilter.msi /quiet" -Wait -Verb RunAs
   
   # Verify installation
   sc query ndisrd
   ```

2. **Install Go Dependencies:**
   ```powershell
   cd D:\SafeOpsFV2\src\safeops-engine
   go mod tidy
   ```

3. **Build SafeOps Engine:**
   ```powershell
   go build -o D:\SafeOpsFV2\bin\safeops-engine.exe cmd/main.go
   ```

4. **Run (requires Admin):**
   ```powershell
   Start-Process -FilePath "D:\SafeOpsFV2\bin\safeops-engine.exe" -WorkingDirectory "D:\SafeOpsFV2\src\safeops-engine" -Verb RunAs
   ```

---

## Troubleshooting

### Issue: "Failed to open NDISAPI driver"

**Check if driver is running:**
```powershell
sc query ndisrd
```

**Expected output:**
```
SERVICE_NAME: ndisrd
TYPE               : 1  KERNEL_DRIVER
STATE              : 4  RUNNING
```

**If not running:**
```powershell
sc start ndisrd
```

---

### Issue: "Cannot find package github.com/wiresock/ndisapi-go"

**Solution:**
```powershell
cd D:\SafeOpsFV2\src\safeops-engine
go mod tidy
go get github.com/wiresock/ndisapi-go@v1.0.1
```

---

### Issue: Internet stops working after running engine

**Solution:**
```powershell
# Stop the engine (Ctrl+C)
# Or restart the driver
sc stop ndisrd
sc start ndisrd
```

---

## Summary

**What you need:**
1. ✅ `ndisrd.sys` - Kernel driver (install via MSI)
2. ✅ `github.com/wiresock/ndisapi-go` - Go package (auto-download)

**What you DON'T need:**
1. ❌ `ndisapi.dll` - Not used by Go
2. ❌ `ndisapi.lib` - Not used by Go
3. ❌ Source code - Not needed for runtime

**Total size:** ~70KB driver + ~200KB Go package = Minimal footprint!
