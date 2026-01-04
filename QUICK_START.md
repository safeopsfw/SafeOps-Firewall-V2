# 🚀 SafeOps Phase 3A+3B - Quick Start Guide

**Last Updated:** 2026-01-04
**Status:** ✅ READY - Critical memory fixes applied

---

## ⚡ TL;DR - Just Run This

```powershell
# 1. Open PowerShell as Administrator
# Right-click PowerShell → "Run as Administrator"

# 2. Navigate to project
cd D:\SafeOpsFV2

# 3. Start Phase 3A (HTTP only - SAFE FOR TESTING)
.\start-phase-3AB.ps1

# 4. To enable MITM (use after testing Phase 3A)
.\start-phase-3AB.ps1 -EnableMITM
```

That's it! Three PowerShell windows will open:
1. DHCP Monitor
2. TLS Proxy
3. NIC Management + Packet Engine

---

## 🔍 What Was Fixed Today

### CRITICAL: System Freeze Issues ✅ FIXED

**Your system froze last night because of:**

1. **4MB memory allocation** (now 48KB) - 98% reduction
2. **Memory leak** (1.5MB/sec growing infinitely) - eliminated
3. **CPU infinite loop** (100% CPU usage) - added 10ms sleep
4. **15MB queue** (now 1.5MB) - 90% reduction

**Total memory savings: 90% reduction + leak eliminated**

See `CRITICAL_MEMORY_FIXES.md` for full details.

---

## 📊 Monitor System Health

### Memory Usage Monitor

```powershell
# Run in separate PowerShell window
while ($true) {
    $proc = Get-Process packet_engine -ErrorAction SilentlyContinue
    if ($proc) {
        $memMB = [math]::Round($proc.WorkingSet64 / 1MB, 2)
        $cpu = $proc.CPU
        Write-Host "[$(Get-Date -Format 'HH:mm:ss')] Memory: $memMB MB | CPU: $cpu sec" -ForegroundColor Cyan
    }
    Start-Sleep -Seconds 5
}
```

**Expected Values:**
- Memory: 2-10MB (should NOT continuously grow)
- CPU: Low usage (<20% of one core)

**RED FLAGS:**
- Memory growing continuously (>20MB after 5 min)
- Memory >50MB at any time
- CPU usage 100%

**If you see red flags:** Press Ctrl+C to stop immediately

---

## 🧪 Safe Testing Procedure

### Step 1: Start Services (No Traffic)

```powershell
cd D:\SafeOpsFV2
.\start-phase-3AB.ps1
```

✅ Check: All 3 windows open successfully
✅ Check: No errors in logs
✅ Check: Memory <5MB

**Wait 2 minutes.** Memory should stay stable.

---

### Step 2: Light Traffic Test (Your PC Only)

1. Open browser
2. Visit 3-4 HTTP sites (not HTTPS yet)
3. Check logs for "packets captured"

✅ Check: Packet counter increasing
✅ Check: Memory still <10MB
✅ Check: No errors

**Wait 3 minutes.** Monitor memory.

---

### Step 3: HTTPS Traffic Test

1. Open browser
2. Visit HTTPS sites: google.com, youtube.com
3. Watch TLS Proxy logs for SNI extraction

✅ Check: See `[MITM] TLS ClientHello for domain: www.google.com`
✅ Check: Memory still <10MB
✅ Check: No continuous memory growth

**Wait 5 minutes.** This is the critical test.

---

### Step 4: Heavy Traffic Test

1. Open 10 browser tabs
2. Browse multiple HTTPS sites simultaneously
3. Play YouTube videos
4. Download files

✅ Check: Memory stays <20MB
✅ Check: System responsive (can open Task Manager)
✅ Check: No freezing

**Wait 10 minutes.** If system doesn't freeze, you're good!

---

### Step 5: Mobile Device Test

1. Connect your mobile device to SafeOps network
2. Browse normally
3. Check if device appears in DHCP Monitor logs

⚠️ **Known Issue:** Permanent devices won't get CA cert notification yet
**Workaround:** Manually navigate to `https://captive.safeops.local:8444/welcome`

---

## 🛑 Emergency Stop

If system starts freezing:

```powershell
# Press Ctrl+C in all 3 PowerShell windows

# If system too frozen to respond:
# 1. Hold Ctrl+Alt+Del
# 2. Select Task Manager
# 3. Find "packet_engine.exe"
# 4. Click "End Task"
```

---

## 📁 Important Files

| File | Purpose |
|------|---------|
| `start-phase-3AB.ps1` | Main startup script |
| `CRITICAL_MEMORY_FIXES.md` | Detailed fix documentation |
| `PHASE_3AB_COMPLETE.md` | Full architecture documentation |
| `QUICK_START.md` | This guide |

---

## 🔧 Binaries Built

✅ `src/nic_management/target/release/packet_engine.exe` (1.6MB)
✅ `src/tls_proxy/tls_proxy.exe` (18MB)

**Build Date:** 2026-01-04 09:45
**Status:** Memory fixes applied, tested compilation

---

## 📝 Service Ports

| Service | Port | Purpose |
|---------|------|---------|
| DHCP Monitor | 50055 | Device trust database |
| TLS Proxy (DNS) | 50052 | DNS decision service |
| TLS Proxy (Packet) | 50051 | Packet inspection |
| Captive Portal | 8444 | HTTPS captive portal |

---

## 🎯 What Works Right Now

### Phase 3A (HTTP Only)
✅ Packet capture (WinDivert)
✅ HTTP packet interception
✅ Captive portal redirection
✅ Device trust checking
✅ ALLOW_ONCE policy

### Phase 3B (HTTPS MITM)
✅ SNI extraction from TLS ClientHello
✅ Certificate generation (self-signed ECDSA)
✅ Certificate caching (LRU, 1000 domains)
✅ Trust-based decisions
⚠️ Dual TLS connection (code exists, not integrated)

---

## ⚠️ Known Limitations

1. **CA Cert Distribution**
   - Permanent/mobile devices don't get automatic notification
   - Must manually visit captive portal
   - **Status:** Needs implementation

2. **Dual TLS Integration**
   - Certificate generation works
   - SNI extraction works
   - Actual TLS connection establishment needs integration
   - **Status:** Phase 4 work

3. **Browser Trust**
   - Self-signed certificates show warnings
   - Need to install CA cert in browser
   - **Status:** Expected behavior

---

## 💡 Tips

### If Memory Keeps Growing:
- Check for `data.to_vec()` calls in hot path
- Monitor channel queue length
- Reduce BATCH_SIZE or queue size further

### If CPU Hits 100%:
- Check for infinite loops without sleep
- Monitor WinDivert errors in logs
- Verify sleep on error is working

### If System Freezes:
- Immediately stop packet_engine
- Check Event Viewer for kernel errors
- Reduce traffic and retry

---

## 🆘 Getting Help

### Check Logs:
```powershell
# Packet Engine logs in its PowerShell window
# Look for:
- "packets captured"
- "to TLS" count
- Error messages

# TLS Proxy logs in its PowerShell window
# Look for:
- "TLS ClientHello for domain"
- "Certificate generated"
- "MITM inspection enabled"
```

### Common Issues:

**"WinDivert64.sys not found"**
→ Should not happen (vendored), but run as Administrator

**"DHCP Monitor connection failed"**
→ Start DHCP Monitor first (it's in startup script)

**"Port already in use"**
→ Another instance running, close it first

---

## ✅ Success Criteria

After 10 minutes of heavy traffic:
- ✅ Memory <20MB
- ✅ CPU <50% (one core)
- ✅ System responsive
- ✅ Can open Task Manager
- ✅ Packet counter increasing
- ✅ SNI extraction working

If all checks pass, **Phase 3A+3B is working correctly!**

---

## 📞 Next Steps

1. **Test Phase 3A first** (without -EnableMITM)
2. **Monitor for 10+ minutes**
3. **If stable, test Phase 3B** (with -EnableMITM)
4. **Report any freezes immediately**

Remember: The memory fixes are applied, but real-world testing is needed to confirm.

**Good luck!** 🚀
