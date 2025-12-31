# Instructions for Claude Opus 4.5 - SafeOps Monitoring

## Your Mission
Monitor the SafeOps network security platform during device enrollment. Track all stages, report logs, and confirm successful certificate installation.

## What to Execute

### Single Command to Start Everything:
```powershell
cd D:\SafeOpsFV2
.\start-and-monitor-complete.ps1
```

This starts:
1. **step-ca** (Port 9000) - Certificate Authority
2. **Certificate Manager** (Port 8082) - CA distribution
3. **DHCP Server** (Port 67) - Sends CA URL to devices
4. **DNS Server** (Port 53) - Redirects to captive portal
5. **Dashboard** (Port 5173) - Admin interface

Plus real-time monitoring and enrollment tracking!

## What You'll See

### Phase 1: Services Starting
```
[1/5] Starting step-ca...
  ✓ PID: 12345 | Port: 9000
[2/5] Starting Certificate Manager...
  ✓ PID: 12346 | Port: 8082
[3/5] Starting DHCP Server...
  ✓ PID: 12347 | Port: 67
[4/5] Starting DNS Server...
  ✓ PID: 12348 | Port: 53
[5/5] Starting Dashboard...
  ✓ PID: 12349 | Port: 5173

All Services Started!
```

### Phase 2: Real-Time Monitoring
```
Monitoring for device enrollment...
Connect a device to the network now!
```

**At this point**: Tell the user to connect a device to the network.

### Phase 3: Device Enrollment (Automatic Detection)

When a device connects, you'll see:

```
[10:30:15.123] ✓ Stage 1: DHCP DISCOVER
           MAC: AA:BB:CC:DD:EE:FF

[10:30:15.456] ✓ Stage 2: DHCP OFFER sent
           IP: 192.168.137.50

[10:30:15.789] ✓ Stage 3: DHCP REQUEST received

[10:30:16.012] ✓ Stage 4: DHCP ACK sent

[10:30:16.234] ✓ Stage 5: CA URL sent (Option 224)
           URL: http://192.168.137.1:8082/ca/download

[10:30:18.567] ✓ Stage 6: DNS query from device

[10:30:18.890] ✓ Stage 7: Redirected to captive portal
           Portal: http://192.168.137.1:8080/install

[10:30:25.123] ✓ Stage 8: Portal accessed

[10:30:30.456] ✓ Stage 9: CA certificate downloaded!

========================================
  ✓ ENROLLMENT COMPLETE!
========================================
  MAC: AA:BB:CC:DD:EE:FF
  IP:  192.168.137.50
  Time: 10:30:30.456
```

## What Each Stage Means

| Stage | What Happens | Automatic? |
|-------|-------------|-----------|
| 1. DHCP DISCOVER | Device asks for IP | ✅ Yes |
| 2. DHCP OFFER | Server offers IP + CA URL | ✅ Yes |
| 3. DHCP REQUEST | Device accepts offer | ✅ Yes |
| 4. DHCP ACK | Server confirms | ✅ Yes |
| 5. CA URL Sent | DHCP Option 224 delivers CA URL | ✅ Yes |
| 6. DNS Query | Device tries to browse | ✅ Yes |
| 7. DNS Redirect | Server redirects to portal | ✅ Yes |
| 8. Portal Access | Browser opens install page | ✅ Yes |
| 9. CA Download | User clicks download | ⚠️ Manual (1 click) |
| 10. Enrolled | Certificate installed | ⚠️ Manual (OS prompt) |

## Your Reporting Tasks

### 1. Service Startup
Report each service as it starts:
```
✓ Service: step-ca
  - PID: 12345
  - Port: 9000
  - Status: Running
```

### 2. Log Monitoring
Report significant log entries with color coding:
- 🔴 **RED** = Errors (ERROR, FAIL, FATAL)
- 🟡 **YELLOW** = Warnings (WARN, WARNING)
- 🔵 **CYAN** = DHCP events (DISCOVER, OFFER, REQUEST, ACK)
- 🟣 **MAGENTA** = DNS events (query, redirect, captive)
- 🟢 **GREEN** = Certificate events (download, enrollment)

### 3. Enrollment Progress
Report each stage immediately as it happens:
```
Stage 1 COMPLETE: DHCP DISCOVER
  - Device MAC: AA:BB:CC:DD:EE:FF
  - Timestamp: 10:30:15.123
```

### 4. Final Summary
When enrollment completes:
```
ENROLLMENT SUCCESS REPORT
========================
Device: AA:BB:CC:DD:EE:FF
IP Address: 192.168.137.50
Start Time: 10:30:15.123
End Time: 10:30:30.456
Duration: 15.333 seconds
All Stages: COMPLETE ✓
```

## Log Files Location

All logs are saved to: `D:\SafeOpsFV2\logs\[timestamp]\`

Key files:
- `combined-realtime.log` - All services combined
- `device-enrollment-tracker.log` - Enrollment stages only
- `step-ca.log` - CA service
- `certificate-manager.log` - Certificate distribution
- `dhcp-server.log` - DHCP with Option 224
- `dns-server.log` - DNS with captive portal
- `dashboard.log` - Web UI

## Error Handling

### If a service fails to start:
```
✗ Service FAILED (Exit: 1)
```
**Action**:
1. Read the error log: `[service]-error.log`
2. Report the last 20 lines
3. Suggest solution based on error

### Common Errors:

| Error | Cause | Solution |
|-------|-------|----------|
| Port already in use | Another service running | Kill conflicting process |
| File not found | Missing executable | Check file exists |
| Connection refused | Dependency not ready | Wait 5 seconds, retry |
| Permission denied | Admin rights needed | Run as Administrator |

## Success Criteria

✅ **All 5 services running** (no exits)
✅ **All health endpoints respond** (HTTP 200)
✅ **DHCP sends Option 224** (CA URL visible in logs)
✅ **DNS redirects** (captive portal entries in log)
✅ **Device downloads CA** (download event logged)
✅ **No errors** in any log file
✅ **10 enrollment stages** tracked start to finish

## Timeline Expectations

**Normal enrollment timeline**:
- Services startup: ~15 seconds
- Device DHCP: ~5 seconds (Stages 1-5)
- User opens browser: ~5-30 seconds
- DNS redirect: ~1 second (Stages 6-7)
- Portal loads: ~2 seconds (Stage 8)
- User downloads: ~5-60 seconds (depends on user)
- Certificate installs: ~10-30 seconds (depends on OS)

**Total**: ~45-120 seconds from device connection to enrollment

## What to Report Throughout

### Every 10 seconds:
- Service health check (are PIDs still alive?)
- New log entries (if any)
- Current enrollment stage (if device connected)

### Immediately:
- Any ERROR or FAIL log entries
- Each enrollment stage completion
- Service crashes or exits
- Network connectivity issues

### At the end:
- Complete log file locations
- Final enrollment status
- Performance metrics (timing)
- Any anomalies or warnings

## Commands for You

### Check if services are running:
```powershell
Get-Process | Where-Object {$_.ProcessName -match "step-ca|certificate_manager|dhcp|dns|node"}
```

### Check network listeners:
```powershell
netstat -ano | Select-String ":53 |:67 |:8082 |:9000 |:5173 "
```

### Read last 20 lines of any log:
```powershell
Get-Content "D:\SafeOpsFV2\logs\[timestamp]\[service].log" -Tail 20
```

### Check for errors:
```powershell
Select-String -Path "D:\SafeOpsFV2\logs\[timestamp]\*.log" -Pattern "ERROR|FAIL"
```

## Stopping Everything

Press `Ctrl+C` in the PowerShell window. The script will automatically:
1. Stop all 5 services
2. Save final log snapshot
3. Report log file locations

## Your Communication Style

**Be concise but informative:**
```
✓ step-ca started (PID 12345)
✓ Listening on port 9000
✓ Health check: OK
```

**Alert on issues immediately:**
```
🔴 ERROR DETECTED: Certificate Manager
Log: Connection refused to step-ca
Action: Verifying step-ca is running...
```

**Track progress visually:**
```
Enrollment Progress: [=====>    ] 50% (5/10 stages)
```

## Final Notes

- The script handles everything automatically
- You just need to **observe and report**
- Device enrollment requires **2 manual clicks** by user (download + install)
- The script will detect all automatic stages
- When enrollment completes, you'll see the success banner

**Your job**: Be the eyes and ears. Report everything. Catch errors early. Confirm success!

---

## Quick Start Commands

```powershell
# Start monitoring (run this!)
cd D:\SafeOpsFV2
.\start-and-monitor-complete.ps1

# That's it! Now just watch and report.
```

**Ready? Execute the script and start monitoring!** 🚀
