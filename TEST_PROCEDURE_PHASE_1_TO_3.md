# 🧪 SafeOps Phase 1-3 Complete Test Procedure

**Purpose:** Step-by-step verification of all components from Phase 1 to Phase 3B
**Last Updated:** 2026-01-04
**Status:** Ready for Testing

---

## ⚠️ PRE-FLIGHT CHECKLIST

Before starting, verify these requirements:

### 1. Database Migration
```powershell
# Connect to PostgreSQL
psql -U postgres -d safeops_dhcp

# Apply migration
\i D:\SafeOpsFV2\src\dhcp_monitor\migrations\003_add_ca_cert_tracking.sql

# Verify columns exist
\d devices

# You should see:
# ca_cert_installed       | boolean
# ca_cert_installed_at    | timestamp with time zone
```

### 2. Port Availability Check
```powershell
# Check if ports are free
netstat -ano | findstr "50051 50052 50055 8444"

# If any port is in use, kill the process:
# taskkill /PID <PID> /F
```

### 3. Admin Privileges
```powershell
# CRITICAL: Run PowerShell as Administrator
# Right-click PowerShell → "Run as Administrator"
# WinDivert requires admin rights
```

### 4. Binary Verification
```powershell
# Verify binaries exist with recent build dates
ls D:\SafeOpsFV2\src\nic_management\target\release\packet_engine.exe
ls D:\SafeOpsFV2\src\tls_proxy\tls_proxy.exe
ls D:\SafeOpsFV2\src\dhcp_monitor\dhcp_monitor.exe

# All should exist and be dated 2026-01-04
```

---

## 📊 PHASE 1: DHCP Monitor Service

### Step 1.1: Start PostgreSQL Database
```powershell
# If PostgreSQL service is not running:
net start postgresql-x64-14

# Verify connection:
psql -U postgres -d safeops_dhcp -c "SELECT COUNT(*) FROM devices;"
```

**Expected Output:**
```
 count
-------
   X
(1 row)
```

### Step 1.2: Start DHCP Monitor
```powershell
cd D:\SafeOpsFV2\src\dhcp_monitor
.\dhcp_monitor.exe
```

**Expected Logs:**
```
[DHCP_MONITOR] Starting on port 50055
[DHCP_MONITOR] Database connection established
[DHCP_MONITOR] gRPC server listening on :50055
```

**✅ SUCCESS CRITERIA:**
- No errors in startup logs
- Port 50055 listening
- Database queries succeed

### Step 1.3: Verify DHCP Monitor Health
```powershell
# Open NEW PowerShell window (keep DHCP Monitor running)
# Test gRPC health endpoint (if you have grpcurl):
grpcurl -plaintext localhost:50055 dhcp_monitor.DHCPMonitor/HealthCheck

# OR check via database:
psql -U postgres -d safeops_dhcp -c "SELECT device_id, current_ip, trust_status, ca_cert_installed FROM devices LIMIT 5;"
```

**Expected Output:**
```
 device_id | current_ip  | trust_status | ca_cert_installed
-----------+-------------+--------------+-------------------
 <uuid>    | 192.168.x.x | UNTRUSTED    | f
```

**✅ PHASE 1 COMPLETE** if:
- ✅ DHCP Monitor running without errors
- ✅ Port 50055 listening
- ✅ Database accessible
- ✅ ca_cert_installed column exists

---

## 🔐 PHASE 2: TLS Proxy Service

### Step 2.1: Start TLS Proxy (Phase 3A Mode - No MITM)
```powershell
# Open NEW PowerShell window
cd D:\SafeOpsFV2\src\tls_proxy

# Start WITHOUT MITM first (safer testing)
.\tls_proxy.exe
```

**Expected Logs:**
```
[TLS_PROXY] Starting packet processing service on :50051
[TLS_PROXY] Starting DNS decision service on :50052
[TLS_PROXY] DHCP Monitor connected at localhost:50055
[TLS_PROXY] MITM mode: DISABLED
[TLS_PROXY] Policy mode: ALLOW_ONCE
[TLS_PROXY] Certificate cache: Enabled (max 1000 domains, TTL 24h)
```

**✅ SUCCESS CRITERIA:**
- No connection errors to DHCP Monitor
- Ports 50051 and 50052 listening
- MITM mode shows as DISABLED

### Step 2.2: Verify TLS Proxy Services
```powershell
# Check ports are listening
netstat -ano | findstr "50051 50052"

# Should show:
# TCP  0.0.0.0:50051  LISTENING
# TCP  0.0.0.0:50052  LISTENING
```

**✅ PHASE 2 COMPLETE** if:
- ✅ TLS Proxy running without errors
- ✅ Ports 50051 and 50052 listening
- ✅ DHCP Monitor connection successful
- ✅ MITM mode DISABLED (for now)

---

## 📡 PHASE 3A: HTTP Packet Capture & Captive Portal

### Step 3A.1: Start Packet Engine
```powershell
# Open NEW PowerShell window AS ADMINISTRATOR
cd D:\SafeOpsFV2\src\nic_management\target\release

# CRITICAL: Must run as admin for WinDivert
.\packet_engine.exe
```

**Expected Logs:**
```
[Packet Engine] Starting...
[Packet Engine] WinDivert initialized
[Packet Engine] Filter: outbound and tcp
[Packet Engine] gRPC client connected to localhost:50051
[Packet Engine] Workers started: 2 threads
[Packet Engine] Queue size: 1000 packets (max 1.5MB)
[Packet Engine] Packet buffer: 48KB
```

**✅ SUCCESS CRITERIA:**
- No "WinDivert not found" errors
- No "gRPC connection failed" errors
- Worker threads started
- Memory allocation shown as 48KB (not 4MB!)

### Step 3A.2: Monitor Memory Usage (Critical Test)
```powershell
# Open NEW PowerShell window
# Run memory monitor script
while ($true) {
    $proc = Get-Process packet_engine -ErrorAction SilentlyContinue
    if ($proc) {
        $memMB = [math]::Round($proc.WorkingSet64 / 1MB, 2)
        $cpu = $proc.CPU
        $timestamp = Get-Date -Format 'HH:mm:ss'
        Write-Host "[$timestamp] Memory: $memMB MB | CPU: $cpu sec" -ForegroundColor Cyan

        # RED FLAG: Memory growing continuously
        if ($memMB -gt 50) {
            Write-Host "⚠️  WARNING: Memory > 50MB! Stop immediately!" -ForegroundColor Red
        }
    }
    Start-Sleep -Seconds 5
}
```

**Expected Values:**
- Initial memory: 2-5MB
- After 5 minutes: 5-10MB
- **MUST NOT continuously grow**

**🚨 RED FLAGS:**
- Memory > 50MB
- Memory growing continuously (>1MB per minute)
- CPU usage 100%

**If red flags appear:** Press Ctrl+C in packet_engine window immediately!

### Step 3A.3: Generate Test Traffic (Light Test)
```powershell
# From your main PC (connected to SafeOps network)
# Open browser and visit HTTP sites (not HTTPS yet)

# Test sites:
# http://neverssl.com
# http://example.com
```

**Expected Packet Engine Logs:**
```
[Packet Engine] Captured packet: src=192.168.x.x:xxxxx dst=93.184.216.34:80 proto=TCP
[Packet Engine] HTTP packet detected (port 80)
[Packet Engine] Sending to TLS Proxy...
[Packet Engine] Total packets: 15 | To TLS: 3
```

**Expected TLS Proxy Logs:**
```
[MITM Processor] Packet: src=192.168.x.x:xxxxx dst=93.184.216.34:80 proto=TCP
[MITM] Device 192.168.x.x trust: UNTRUSTED, CA cert installed: false
[MITM] ALLOW_ONCE: First visit → Redirect to captive portal
```

**✅ SUCCESS CRITERIA:**
- Packet Engine captures HTTP traffic
- Packets sent to TLS Proxy (port 50051)
- TLS Proxy queries DHCP Monitor for device trust
- Device shows as UNTRUSTED with ca_cert_installed=false

### Step 3A.4: Test Captive Portal Redirect
```powershell
# Browser should redirect to:
# https://captive.safeops.local:8444/welcome

# If not automatic, manually navigate to HTTP site again
```

**Expected Behavior:**
- Browser redirected to captive portal
- Portal shows welcome page
- Device MAC/IP displayed

**Expected DHCP Monitor Logs:**
```
[GRPC_SERVER] GetDeviceByIP: ip=192.168.x.x device=<uuid> trust=UNTRUSTED ca_cert=false
```

**✅ PHASE 3A COMPLETE** if:
- ✅ Packet Engine captures HTTP traffic
- ✅ Memory stays under 10MB after 5 minutes
- ✅ No continuous memory growth
- ✅ TLS Proxy receives packets on port 50051
- ✅ DHCP Monitor queries succeed
- ✅ Captive portal redirect works
- ✅ portal_shown tracked in database

**Wait 5 minutes and monitor memory before proceeding to Phase 3B!**

---

## 🔓 PHASE 3B: HTTPS MITM Inspection

### Step 3B.1: Stop TLS Proxy and Restart with MITM Enabled
```powershell
# In TLS Proxy window, press Ctrl+C

# Restart with MITM flag
cd D:\SafeOpsFV2\src\tls_proxy
.\tls_proxy.exe -enable-mitm
```

**Expected Logs:**
```
[TLS_PROXY] Starting packet processing service on :50051
[TLS_PROXY] MITM mode: ENABLED ⚠️
[TLS_PROXY] Certificate cache initialized
[TLS_PROXY] Traffic inspector: Enabled (log first 1KB)
```

**✅ SUCCESS CRITERIA:**
- MITM mode shows as ENABLED
- Certificate cache initialized

### Step 3B.2: Generate HTTPS Traffic (WITHOUT CA Cert)
```powershell
# From browser, visit HTTPS sites:
# https://www.google.com
# https://www.youtube.com
```

**Expected TLS Proxy Logs:**
```
[MITM] TLS ClientHello for domain: www.google.com
[MITM] Device 192.168.x.x trust: UNTRUSTED, CA cert installed: false
[MITM] ⚠️  Device 192.168.x.x has NOT installed CA cert - forwarding without MITM
[MITM] Action: FORWARD (CA cert not installed)
```

**Expected Packet Engine Logs:**
```
[Packet Engine] Captured packet: dst=142.250.x.x:443 proto=TCP
[Packet Engine] HTTPS packet (port 443)
[Packet Engine] Sending to TLS Proxy...
```

**✅ SUCCESS CRITERIA:**
- TLS ClientHello detected
- SNI extracted (domain name shown)
- MITM NOT performed (CA cert not installed)
- Traffic forwarded without inspection

### Step 3B.3: Download CA Certificate
```powershell
# In browser, navigate to captive portal:
# https://captive.safeops.local:8444/welcome

# Click "Download CA Certificate" button
# Save safeops-root-ca.crt to Downloads folder
```

**Expected Captive Portal Logs:**
```
[Handlers] CA certificate download requested from 192.168.x.x
[Handlers] ✅ Marked CA cert installed for 192.168.x.x
```

**Expected DHCP Monitor Logs:**
```
[GRPC_SERVER] MarkCACertInstalled: ip=192.168.x.x
[GRPC_SERVER] ✅ MarkCACertInstalled: device=<uuid> IP=192.168.x.x MAC=xx:xx:xx:xx:xx:xx ca_cert=true
```

**Verify in Database:**
```powershell
psql -U postgres -d safeops_dhcp -c "SELECT current_ip, ca_cert_installed, ca_cert_installed_at FROM devices WHERE current_ip = '192.168.x.x';"

# Expected output:
#  current_ip  | ca_cert_installed |     ca_cert_installed_at
# -------------+-------------------+-------------------------------
#  192.168.x.x | t                 | 2026-01-04 10:30:15.123456+00
```

**✅ SUCCESS CRITERIA:**
- CA cert file downloaded successfully
- Captive portal marks ca_cert_installed=true
- DHCP Monitor database updated
- Timestamp recorded in ca_cert_installed_at

### Step 3B.4: Install CA Certificate in Browser
```powershell
# Windows: Double-click safeops-root-ca.crt
# 1. Click "Install Certificate"
# 2. Select "Current User"
# 3. Select "Place all certificates in the following store"
# 4. Click "Browse" → Select "Trusted Root Certification Authorities"
# 5. Click "Next" → "Finish"
# 6. Accept security warning

# Verify installation:
# certmgr.msc → Trusted Root Certification Authorities → Certificates
# Look for "SafeOps Network" certificate
```

**✅ SUCCESS CRITERIA:**
- Certificate installed in Windows certificate store
- Listed under Trusted Root Certification Authorities

### Step 3B.5: Test HTTPS MITM Inspection (WITH CA Cert)
```powershell
# Close and reopen browser (to load new cert trust)
# Visit HTTPS sites again:
# https://www.google.com
# https://www.youtube.com
# https://www.github.com
```

**Expected TLS Proxy Logs:**
```
[MITM] TLS ClientHello for domain: www.google.com
[MITM] Device 192.168.x.x trust: UNTRUSTED, CA cert installed: true
[MITM] ✓ MITM inspection enabled for www.google.com (trusted device)
[MITM] Certificate ready for www.google.com - would establish dual TLS
[Cert Cache] Cache HIT for www.google.com
[MITM] Action: FORWARD (MITM ready for www.google.com)
```

**Expected Certificate Cache Logs:**
```
[Cert Cache] Generating certificate for www.google.com
[Cert Cache] ECDSA P-256 key generated
[Cert Cache] Certificate signed (self-signed, 24h TTL)
[Cert Cache] Cached certificate for www.google.com
[Cert Cache] Cache size: 1/1000
```

**Browser Behavior:**
- HTTPS sites load normally
- No certificate warnings (CA cert trusted)
- Lock icon shows "Secure"
- Certificate issuer: "SafeOps Network" (if you inspect cert details)

**✅ SUCCESS CRITERIA:**
- TLS ClientHello detected for each HTTPS request
- SNI extraction works (domain names shown)
- Device check shows ca_cert_installed=true
- MITM inspection enabled message appears
- Certificates generated and cached
- Cache hit rate increases on revisits
- Browser trusts certificates (no warnings)

### Step 3B.6: Test Certificate Caching
```powershell
# Visit www.google.com multiple times
# Refresh page 5 times
```

**Expected Logs:**
```
# First request:
[Cert Cache] Generating certificate for www.google.com
[Cert Cache] Cached certificate for www.google.com

# Subsequent requests:
[Cert Cache] Cache HIT for www.google.com
[Cert Cache] Cache HIT for www.google.com
[Cert Cache] Cache HIT for www.google.com
```

**✅ SUCCESS CRITERIA:**
- First request generates certificate
- Subsequent requests hit cache
- No redundant certificate generation

### Step 3B.7: High Traffic Test (Memory/Performance)
```powershell
# Open 10 browser tabs simultaneously
# Visit different HTTPS sites in each:
# - www.google.com
# - www.youtube.com
# - www.github.com
# - www.stackoverflow.com
# - www.reddit.com
# - www.twitter.com
# - www.facebook.com
# - www.amazon.com
# - www.netflix.com
# - www.wikipedia.org

# Play YouTube videos
# Scroll through social media feeds
# Perform searches
```

**Monitor Memory in Real-Time:**
```powershell
# Memory monitor window should show:
[10:35:15] Memory: 8.45 MB | CPU: 12.34 sec
[10:35:20] Memory: 9.12 MB | CPU: 13.56 sec
[10:35:25] Memory: 8.98 MB | CPU: 14.23 sec
[10:35:30] Memory: 9.34 MB | CPU: 15.67 sec
```

**✅ SUCCESS CRITERIA:**
- Memory stays under 20MB
- Memory fluctuates but does NOT continuously grow
- CPU usage reasonable (<50% of one core)
- System remains responsive
- Can open Task Manager
- Packet Engine logs show increasing packet count
- TLS Proxy logs show MITM inspection for all domains
- No errors or crashes

**🚨 CRITICAL TEST:**
- Run heavy traffic for **10 minutes minimum**
- If memory exceeds 50MB, stop immediately
- If system becomes unresponsive, stop immediately

### Step 3B.8: Mobile Device Test
```powershell
# Connect mobile device to SafeOps network
# Should get DHCP lease
```

**Expected DHCP Monitor Logs:**
```
[DHCP_MONITOR] New device detected: IP=192.168.x.y MAC=aa:bb:cc:dd:ee:ff
[DHCP_MONITOR] Device type: Phone, Vendor: Apple/Samsung
[DHCP_MONITOR] Trust status: UNTRUSTED, CA cert: false
```

**Test CA Cert Download on Mobile:**
```
1. Open browser on mobile device
2. Visit http://neverssl.com (should redirect to captive portal)
3. Download CA certificate from portal
4. Install CA cert on mobile device:
   - iOS: Settings → Profile Downloaded → Install
   - Android: Settings → Security → Install from storage
5. Visit HTTPS sites and verify MITM inspection logs
```

**Expected After CA Cert Install:**
```
[DHCP_MONITOR] MarkCACertInstalled: device=<uuid> IP=192.168.x.y
[MITM] Device 192.168.x.y trust: UNTRUSTED, CA cert installed: true
[MITM] ✓ MITM inspection enabled for mobile.twitter.com
```

**✅ SUCCESS CRITERIA:**
- Mobile device detected by DHCP Monitor
- Captive portal redirect works
- CA cert download works on mobile
- After install, MITM inspection works
- Database updated with ca_cert_installed=true

---

## 📊 FINAL VERIFICATION

### System Health Check
```powershell
# Run this after 10+ minutes of heavy traffic:

# 1. Memory check
Get-Process packet_engine | Select-Object Name, @{Name="Memory(MB)";Expression={[math]::Round($_.WorkingSet64/1MB,2)}}, CPU

# Expected:
# Name          Memory(MB) CPU
# ----          ---------- ---
# packet_engine 8.45       45.67

# 2. Port check
netstat -ano | findstr "50051 50052 50055 8444"

# Expected: All 4 ports listening

# 3. Database check
psql -U postgres -d safeops_dhcp -c "SELECT COUNT(*) as total, COUNT(*) FILTER (WHERE ca_cert_installed = true) as with_cert FROM devices;"

# Expected:
#  total | with_cert
# -------+-----------
#   X    |    Y
```

### Success Criteria Summary

**✅ PHASE 1-3 COMPLETE** if ALL of these are true:

**Phase 1: DHCP Monitor**
- ✅ Service running on port 50055
- ✅ Database connection healthy
- ✅ ca_cert_installed column exists

**Phase 2: TLS Proxy**
- ✅ Packet Processing Service on port 50051
- ✅ DNS Decision Service on port 50052
- ✅ DHCP Monitor connection working

**Phase 3A: HTTP Interception**
- ✅ Packet Engine captures HTTP traffic
- ✅ WinDivert working (no driver errors)
- ✅ Captive portal redirect works
- ✅ Memory stays under 10MB

**Phase 3B: HTTPS MITM**
- ✅ SNI extraction from TLS ClientHello
- ✅ CA cert download tracked in database
- ✅ MITM only performed if ca_cert_installed=true
- ✅ Certificate generation works (ECDSA P-256)
- ✅ Certificate caching works (hit rate increases)
- ✅ Browser trusts certificates (no warnings)
- ✅ Mobile device CA cert download works

**Memory/Performance:**
- ✅ Packet Engine memory <20MB after 10 minutes
- ✅ No continuous memory growth
- ✅ CPU usage <50% (one core)
- ✅ System remains responsive
- ✅ No freeze or hang

---

## 🚨 TROUBLESHOOTING

### Issue: "WinDivert64.sys not found"
**Solution:**
```powershell
# 1. Verify you're running as Administrator
# 2. Check Cargo.toml has vendored feature:
cat D:\SafeOpsFV2\src\nic_management\Cargo.toml | findstr vendored

# Should show:
# windivert = { version = "0.6", features = ["vendored"] }
```

### Issue: "gRPC connection failed"
**Solution:**
```powershell
# 1. Verify services started in correct order:
#    DHCP Monitor FIRST, then TLS Proxy, then Packet Engine
# 2. Check ports are listening:
netstat -ano | findstr "50051 50055"

# 3. Restart services in order
```

### Issue: Memory continuously growing
**Solution:**
```powershell
# 1. Stop packet_engine immediately (Ctrl+C)
# 2. Verify packet_engine.rs has fixes:
cat D:\SafeOpsFV2\src\nic_management\internal\bin\packet_engine.rs | findstr "BATCH_SIZE\|MAX_PACKET_SIZE"

# Should show:
# const MAX_PACKET_SIZE: usize = 1500;
# const BATCH_SIZE: usize = 32;

# 3. Rebuild if necessary:
cd D:\SafeOpsFV2\src\nic_management
cargo build --release
```

### Issue: System freeze (100% CPU, can't open Task Manager)
**Solution:**
```powershell
# EMERGENCY STOP:
# 1. Press Ctrl+Alt+Del
# 2. Select "Task Manager" (may take 30+ seconds)
# 3. Find "packet_engine.exe"
# 4. Click "End Task"

# After stopping, verify error handling sleep:
cat D:\SafeOpsFV2\src\nic_management\internal\bin\packet_engine.rs | Select-String -Pattern "sleep.*10" -Context 2

# Should show:
# std::thread::sleep(Duration::from_millis(10));
```

### Issue: CA cert not marked in database
**Solution:**
```powershell
# 1. Check captive portal logs for MarkCACertInstalled call
# 2. Verify DHCP Monitor received request:
#    Check DHCP Monitor logs for "MarkCACertInstalled"
# 3. Manually verify database:
psql -U postgres -d safeops_dhcp -c "SELECT current_ip, ca_cert_installed FROM devices WHERE current_ip = 'X.X.X.X';"

# 4. If false, manually update for testing:
psql -U postgres -d safeops_dhcp -c "UPDATE devices SET ca_cert_installed = true WHERE current_ip = 'X.X.X.X';"
```

### Issue: MITM not working even with CA cert installed
**Solution:**
```powershell
# 1. Verify TLS Proxy started with -enable-mitm flag
# 2. Check TLS Proxy logs show "MITM mode: ENABLED"
# 3. Verify device has ca_cert_installed=true in database
# 4. Check browser has CA cert in Trusted Root CAs
# 5. Restart browser after installing cert
```

---

## 📁 LOG COLLECTION (For Debugging)

If anything fails, collect these logs:

```powershell
# Create debug info bundle
$timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
$debugDir = "D:\SafeOpsFV2\debug_logs_$timestamp"
mkdir $debugDir

# Memory snapshot
Get-Process packet_engine | Format-List * > "$debugDir\memory_snapshot.txt"

# Database state
psql -U postgres -d safeops_dhcp -c "SELECT * FROM devices;" > "$debugDir\devices_snapshot.txt"

# Port status
netstat -ano > "$debugDir\netstat.txt"

# Event Viewer errors
Get-EventLog -LogName System -Newest 50 -EntryType Error > "$debugDir\event_log_errors.txt"

Write-Host "Debug info saved to: $debugDir" -ForegroundColor Green
```

---

## ✅ COMPLETION CHECKLIST

Mark each item as you complete testing:

**Pre-Flight:**
- [ ] Database migration applied (ca_cert_installed columns exist)
- [ ] All ports free (50051, 50052, 50055, 8444)
- [ ] Running PowerShell as Administrator
- [ ] All binaries built (packet_engine, tls_proxy, dhcp_monitor)

**Phase 1:**
- [ ] DHCP Monitor started successfully
- [ ] Port 50055 listening
- [ ] Database connection healthy
- [ ] Health check passes

**Phase 2:**
- [ ] TLS Proxy started successfully
- [ ] Ports 50051 and 50052 listening
- [ ] DHCP Monitor connection works
- [ ] MITM mode configurable

**Phase 3A:**
- [ ] Packet Engine started successfully
- [ ] WinDivert initialized (no errors)
- [ ] HTTP traffic captured
- [ ] Packets sent to TLS Proxy (port 50051)
- [ ] Captive portal redirect works
- [ ] Memory under 10MB after 5 minutes

**Phase 3B:**
- [ ] TLS Proxy restarted with MITM enabled
- [ ] TLS ClientHello detected
- [ ] SNI extraction works (domain names shown)
- [ ] CA cert download works
- [ ] Database updated (ca_cert_installed=true)
- [ ] CA cert installed in browser
- [ ] MITM inspection works
- [ ] Certificates generated (ECDSA P-256)
- [ ] Certificate caching works
- [ ] Browser trusts certificates (no warnings)
- [ ] Heavy traffic test passes (10+ minutes)
- [ ] Memory under 20MB
- [ ] No system freeze
- [ ] Mobile device test passes

**Final Verification:**
- [ ] All services running
- [ ] All ports listening
- [ ] Memory stable
- [ ] CPU usage normal
- [ ] System responsive
- [ ] Database shows devices with CA certs

---

## 🎯 EXPECTED FINAL STATE

After completing all tests, your system should be in this state:

**Services Running:**
1. PostgreSQL database
2. DHCP Monitor (port 50055)
3. TLS Proxy (ports 50051, 50052) with MITM enabled
4. Packet Engine (capturing traffic)

**Database State:**
- Multiple devices in `devices` table
- Some devices with `ca_cert_installed = true`
- Timestamps in `ca_cert_installed_at`

**Memory Usage:**
- Packet Engine: 5-15MB (stable, not growing)
- TLS Proxy: 15-25MB
- DHCP Monitor: 10-20MB

**Traffic Flow:**
1. Device makes HTTPS request
2. Packet Engine captures TLS packet
3. Sent to TLS Proxy (port 50051)
4. TLS Proxy extracts SNI (domain name)
5. TLS Proxy queries DHCP Monitor (device trust + CA cert status)
6. If ca_cert_installed=true → MITM inspection enabled
7. Certificate generated/cached for domain
8. Traffic inspected and forwarded

**Logs Show:**
- SNI extraction working
- CA cert checks working
- MITM decisions correct
- Certificate caching working
- No memory leaks
- No CPU spikes
- No errors

---

## 🚀 YOU'RE DONE!

If all checkboxes are marked, **Phase 1-3 is fully operational!**

**Next Steps:**
- Phase 4: Actual dual TLS connection establishment (currently just forwarding)
- Phase 4: Real-time traffic inspection and filtering
- Phase 4: Integration with DNS server for domain blocking

**Current Status:** Phase 3B complete - MITM infrastructure ready, certificate generation working, trust-based decisions working.

---

**Good luck with testing! 🎉**
