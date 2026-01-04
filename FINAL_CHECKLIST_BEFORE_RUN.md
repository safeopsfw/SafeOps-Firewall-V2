# ✅ Final Checklist Before Running

**Status:** Ready to run! Just verify these items first.

---

## 🔍 Pre-Flight Verification

### 1. Binaries Exist ✅
```powershell
# Check all binaries are built
ls D:\SafeOpsFV2\src\nic_management\target\release\packet_engine.exe
ls D:\SafeOpsFV2\src\tls_proxy\tls_proxy.exe
ls D:\SafeOpsFV2\src\dhcp_monitor\dhcp_monitor.exe

# Expected output: All 3 files exist with recent dates (2026-01-04)
```

**Status:**
- ✅ packet_engine.exe (1.6 MB, Jan 4 10:21) - **LATEST with comprehensive monitoring**
- ✅ tls_proxy.exe (18 MB, Jan 4 09:55)
- ✅ dhcp_monitor.exe (18 MB, Jan 4 09:55)

---

### 2. PostgreSQL Running ✅
```powershell
# Check PostgreSQL is running
Get-Service | findstr postgres

# OR
psql -U postgres -d safeops_dhcp -c "SELECT 1;"
```

**Expected:** Service running, able to connect to database

---

### 3. Database Migration Applied
```powershell
# Check if ca_cert_installed column exists
psql -U postgres -d safeops_dhcp -c "\d devices"

# Should see:
# ca_cert_installed       | boolean
# ca_cert_installed_at    | timestamp with time zone
```

**If not applied:**
```powershell
psql -U postgres -d safeops_dhcp
\i D:\SafeOpsFV2\src\dhcp_monitor\migrations\003_add_ca_cert_tracking.sql
```

---

### 4. Ports Available
```powershell
# Check if ports are free
netstat -ano | findstr "50051 50052 50055 8444"

# Expected: No output (all ports free)
```

**If ports in use:**
```powershell
# Kill processes on those ports
# Find PID from netstat, then:
taskkill /PID <PID> /F
```

---

### 5. Administrator Privileges
```powershell
# Check if running as admin
[Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent() | Select-Object -ExpandProperty IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)

# Expected: True
```

**If False:**
- Close PowerShell
- Right-click PowerShell → "Run as Administrator"
- Try again

---

## 🚀 How to Run

### Option 1: Quick Start (HTTP Only - Recommended First Test)
```powershell
cd D:\SafeOpsFV2
.\start-phase-3AB.ps1
```

**This starts:**
1. DHCP Monitor (port 50055)
2. TLS Proxy (ports 50051, 50052) - MITM **DISABLED**
3. Packet Engine (comprehensive monitoring)

**Expected behavior:**
- 3 PowerShell windows open
- No errors in logs
- Network speed: 450+ Mbps
- Packet capture logs show HTTP/HTTPS/SSH/etc.

---

### Option 2: Full MITM (After Testing Option 1)
```powershell
cd D:\SafeOpsFV2
.\start-phase-3AB.ps1 -EnableMITM
```

**This adds:**
- TLS Proxy with MITM **ENABLED**
- Certificate generation for HTTPS domains
- SNI extraction and logging

**Expected behavior:**
- Same as Option 1
- TLS Proxy logs show "MITM mode: ENABLED"
- Certificate generation for visited HTTPS domains

---

## 📊 What to Monitor

### Terminal 1: DHCP Monitor
```
[DHCP_MONITOR] Starting on port 50055
[DHCP_MONITOR] Database connection established
[DHCP_MONITOR] gRPC server listening on :50055
```

✅ **Success:** No errors, port 50055 listening

---

### Terminal 2: TLS Proxy
```
[TLS_PROXY] Starting packet processing service on :50051
[TLS_PROXY] Starting DNS decision service on :50052
[TLS_PROXY] DHCP Monitor connected at localhost:50055
[TLS_PROXY] MITM mode: DISABLED (or ENABLED)
[TLS_PROXY] Certificate cache: Enabled (max 1000 domains, TTL 24h)
```

✅ **Success:** Both services running, DHCP Monitor connected

---

### Terminal 3: Packet Engine
```
[packet_engine] Starting NIC Management Packet Engine (Rust) with WinDivert...
[packet_engine] 🚀 MULTI-THREADED MODE: 2 worker threads
[packet_engine] Configuration loaded. TLS Proxy: http://localhost:50051
[packet_engine] WinDivert handle opened successfully
[packet_engine] Packet capture started. Press Ctrl+C to stop.
```

✅ **Success:** WinDivert initialized, no errors

**As you browse:**
```
[packet_engine] Captured packet: dst=142.250.65.46:443 (HTTPS to Google)
[packet_engine] Captured packet: dst=203.0.113.50:22 (SSH)
[packet_engine] Total packets: 147 | To TLS: 23
```

---

## 🧪 Test Plan

### Test 1: Services Start (2 minutes)
1. Run `.\start-phase-3AB.ps1`
2. Wait for all 3 windows to open
3. Check each window for errors
4. Verify no crashes

✅ **Pass if:** All services running, no errors

---

### Test 2: Network Speed (1 minute)
1. Open browser
2. Visit https://fast.com
3. Wait for speed test to complete

✅ **Pass if:** Speed > 400 Mbps (>80% of normal)
🚨 **Fail if:** Speed < 100 Mbps (stop immediately!)

---

### Test 3: HTTP Capture (2 minutes)
1. Visit http://neverssl.com
2. Check Packet Engine logs for "dst=X.X.X.X:80"
3. Should see HTTP packet captured

✅ **Pass if:** HTTP packets logged

---

### Test 4: HTTPS SNI Extraction (3 minutes)
1. Visit https://www.google.com
2. Check TLS Proxy logs for "TLS ClientHello for domain: www.google.com"
3. Should see SNI extraction

✅ **Pass if:** Domain name extracted from HTTPS traffic

---

### Test 5: SSH Metadata Logging (2 minutes)
1. SSH to any server: `ssh user@server.com`
2. Check Packet Engine logs for "dst=X.X.X.X:22"
3. Should see SSH packet logged (metadata only)

✅ **Pass if:** SSH connection logged without decryption

---

### Test 6: Memory Stability (10 minutes)
1. Open 10 browser tabs
2. Browse normally (YouTube, social media, etc.)
3. Monitor memory in separate PowerShell:

```powershell
while ($true) {
    $proc = Get-Process packet_engine -ErrorAction SilentlyContinue
    if ($proc) {
        $memMB = [math]::Round($proc.WorkingSet64 / 1MB, 2)
        Write-Host "Memory: $memMB MB" -ForegroundColor Cyan
    }
    Start-Sleep -Seconds 10
}
```

✅ **Pass if:** Memory stays under 20MB, doesn't continuously grow
🚨 **Fail if:** Memory > 50MB or continuously growing

---

### Test 7: CA Certificate Download (5 minutes)
1. Navigate to https://captive.safeops.local:8444/welcome
2. Click "Download CA Certificate"
3. Check DHCP Monitor logs for "MarkCACertInstalled"
4. Verify database:

```powershell
psql -U postgres -d safeops_dhcp -c "SELECT current_ip, ca_cert_installed FROM devices WHERE ca_cert_installed = true;"
```

✅ **Pass if:** Database shows `ca_cert_installed = t`

---

## 🛑 Emergency Stop

**If network freezes or system becomes sluggish:**

1. Press **Ctrl+C** in Packet Engine window (Terminal 3)
2. If that doesn't work: **Ctrl+Alt+Del** → Task Manager
3. Find "packet_engine.exe" → End Task
4. Check network speed returns to normal

**After stopping:**
```powershell
# Verify network is back to normal
# Visit: https://fast.com
# Expected: 500+ Mbps
```

---

## ⚠️ Known Issues & Workarounds

### Issue 1: "WinDivert64.sys not found"
**Solution:** You're not running as Administrator
```powershell
# Close PowerShell
# Right-click PowerShell → "Run as Administrator"
# Try again
```

---

### Issue 2: "Port already in use"
**Solution:** Kill existing process
```powershell
netstat -ano | findstr "50051"
# Note the PID (last column)
taskkill /PID <PID> /F
```

---

### Issue 3: "DHCP Monitor connection failed"
**Solution:** Start services in correct order
1. Stop all services (Ctrl+C)
2. Start DHCP Monitor first (wait 5 seconds)
3. Start TLS Proxy (wait 5 seconds)
4. Start Packet Engine

---

### Issue 4: Network speed very slow
**Possible causes:**
1. Old binary (with `"ip"` filter) - Rebuild packet_engine
2. Too many packets captured - Check filter in logs
3. Memory leak - Check memory usage

**Solution:**
```powershell
# Stop packet engine
# Rebuild with latest code
cd D:\SafeOpsFV2\src\nic_management
cargo build --release

# Verify filter
cat internal\bin\packet_engine.rs | Select-String -Pattern "let filter"
# Should show: tcp.DstPort == 80 or tcp.DstPort == 443 or tcp.DstPort == 22...
```

---

## 📈 Success Criteria

After 10 minutes of heavy browsing:

✅ **All of these must be true:**
- [ ] Network speed > 400 Mbps
- [ ] Memory < 20 MB (stable, not growing)
- [ ] CPU usage < 50% (one core)
- [ ] System responsive (can open Task Manager)
- [ ] Packet Engine logs show captured traffic
- [ ] TLS Proxy logs show SNI extraction
- [ ] No errors or crashes
- [ ] No network freeze

**If ALL checkboxes pass:** 🎉 **Phase 3A+3B+3C is working!**

---

## 🎯 What You'll See

### Successful Run Example:

**Terminal 1 (DHCP Monitor):**
```
[DHCP_MONITOR] Starting on port 50055
[DHCP_MONITOR] Database connection established
[GRPC_SERVER] GetDeviceByIP: ip=192.168.1.100 device=abc-123 trust=UNTRUSTED ca_cert=false
```

**Terminal 2 (TLS Proxy):**
```
[TLS_PROXY] MITM mode: DISABLED
[MITM] TLS ClientHello for domain: www.google.com
[MITM] Device 192.168.1.100 CA cert installed: false
[MITM] Action: FORWARD (CA cert not installed)
[Cert Cache] Certificate generated for www.google.com
```

**Terminal 3 (Packet Engine):**
```
[packet_engine] WinDivert handle opened successfully
[packet_engine] Captured packet: dst=142.250.65.46:443 (Google)
[packet_engine] Captured packet: dst=203.0.113.50:22 (SSH)
[packet_engine] Total packets: 347 | To TLS: 47
```

---

## ✅ You're Ready!

**Everything is in place:**
- ✅ Binaries built (latest with comprehensive monitoring)
- ✅ Startup script fixed (uses Rust packet_engine)
- ✅ Network freeze bug fixed (restrictive filter)
- ✅ CA certificate tracking implemented
- ✅ Comprehensive protocol monitoring (9 protocols)
- ✅ Documentation complete

**Just run:**
```powershell
cd D:\SafeOpsFV2
.\start-phase-3AB.ps1
```

**And monitor your network speed at:** https://fast.com

🚀 **Good luck!**
