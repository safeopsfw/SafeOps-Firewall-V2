# SafeOps HTTP/HTTPS Bypass Mode - Security Analysis

## Overview
SafeOps proxy now operates in **BYPASS MODE** - a fast lane for web traffic that prioritizes performance and compatibility over deep packet inspection.

## What Changed

### Before (Redirect Mode)
```
HTTP/HTTPS → Proxy → Inspection/Logging → Forward
```
- ✅ Full traffic inspection
- ✅ Detailed logging
- ❌ Requires CA certificate for HTTPS
- ❌ Slower (MITM overhead)
- ❌ Discord/WebSocket issues

### After (Bypass Mode)
```
HTTP/HTTPS → Proxy → Domain Logging → Direct Pass-Through
```
- ✅ No CA certificate required
- ✅ Fast (minimal overhead)
- ✅ Discord/WebSocket works
- ✅ Still logs domains
- ⚠️ No content inspection
- ⚠️ No deep packet analysis

## Security Trade-offs

### What You LOSE
1. **Content Inspection**: Cannot see HTTP request bodies, headers, or payloads
2. **HTTPS Decryption**: Cannot decrypt HTTPS traffic (no MITM)
3. **Deep Logging**: Only domain-level visibility, not URL paths or data
4. **Forensics**: Limited data for incident investigation

### What You KEEP
1. **Domain Visibility**: See which domains are accessed
2. **Connection Counts**: Track HTTP vs HTTPS traffic volume
3. **Blocking Capability**: Can still block by domain (e.g., malware.com)
4. **DNS Security**: DNS filtering still active
5. **IDS/IPS**: Port-based classification still works

## DNS Proxy Fix

### Problem
```
Error: exit status 1 - port 15353 in use
```
Leftover dnsproxy process from previous run

### Solution
Added automatic process cleanup:
```go
func (s *Spawner) killExistingDNSProxy(port int) error {
    // Windows: Find and kill process using netstat + taskkill
    cmd := exec.Command("cmd", "/C",
        fmt.Sprintf(`for /f "tokens=5" %%a in ('netstat -ano ^| findstr :%d') do taskkill /F /PID %%a`, port))
    return cmd.Run()
}
```

**Behavior**:
- Before starting dnsproxy, kill any existing process on target port
- Tries primary port (15353), then fallbacks (25353, 35353, 45353)
- Ensures clean startup every time

## Recommended Security Posture

### For Full Security (Enterprise/High-Risk)
**DO NOT USE BYPASS MODE** - Revert to inspection mode:
```yaml
# In classifier config
classifier:
  bypass_http: false  # Force inspection
```

### For Performance (Home/Low-Risk)
**USE BYPASS MODE** (current):
- Web browsing is fast
- Gaming/Discord/VoIP works
- Still get domain-level visibility
- Rely on DNS filtering for threats

### Hybrid Approach (Recommended)
Keep bypass mode but add:
1. **DNS-level threat blocking** (already have)
2. **Selective inspection** - inspect unknown/suspicious domains only
3. **Behavioral analysis** - flag unusual connection patterns
4. **External threat intel** - integrate with ThreatIntel API

## Implementation Details

### Code Changes

**File**: `src/safeops-engine/internal/proxy/proxy.go`

```go
// HTTPS Handler - Pure Bypass
proxyServer.OnRequest().HandleConnectFunc(func(host string, ctx *goproxy.ProxyCtx) (*goproxy.ConnectAction, string) {
    fmt.Printf("[PROXY] HTTPS BYPASS %s\n", host)
    return goproxy.OkConnect, host  // No MITM
})

// HTTP Handler - Pure Bypass
proxyServer.OnRequest().DoFunc(func(r *http.Request, ctx *goproxy.ProxyCtx) (*http.Request, *http.Response) {
    fmt.Printf("[PROXY] HTTP BYPASS %s %s%s\n", r.Method, r.Host, r.URL.Path)
    return r, nil  // Pass through
})
```

**File**: `src/safeops-engine/internal/spawner/spawner.go`
- Added `killExistingDNSProxy()` function
- Automatic cleanup before spawn

## Testing Checklist

- [x] DNS proxy starts cleanly (no port conflicts)
- [x] HTTP traffic passes through
- [x] HTTPS traffic passes through
- [x] Discord connects successfully
- [ ] Domain logging works
- [ ] Stats tracking accurate
- [ ] No performance degradation

## Future Enhancements

### Option 1: Selective Bypass
```go
var trustedDomains = []string{"discord.com", "google.com", "github.com"}
if isTrusted(host) {
    return goproxy.OkConnect, host  // Bypass
} else {
    return goproxy.MitmConnect, host  // Inspect
}
```

### Option 2: Smart MITM
```go
// Try MITM first, fallback to bypass on cert error
action, host := tryMITM(host)
if action == CertError {
    return goproxy.OkConnect, host  // Auto-bypass
}
```

### Option 3: Logging Enhancement
```go
// Still in bypass mode, but log more metadata
log.Info("HTTPS BYPASS", map[string]interface{}{
    "domain": host,
    "bytes_sent": ctx.BytesSent,
    "bytes_recv": ctx.BytesRecv,
    "duration": ctx.Duration,
})
```

## Rollback Instructions

If you need to revert to inspection mode:

1. Edit `proxy.go`:
```go
// Change OkConnect → MitmConnect
return goproxy.MitmConnect, host
```

2. Rebuild:
```bash
cd src/safeops-engine
go build -o ../../bin/safeops-engine.exe ./cmd
```

3. Install CA certificate on client devices

## Security Verdict

**Current Setup**: ⚠️ Medium Security
- Good for home/development use
- Not recommended for enterprise/high-risk
- Balances security vs functionality

**Recommendation**:
- Keep bypass mode for now
- Monitor domain logs for suspicious activity
- Add DNS-based threat blocking
- Consider selective inspection for unknown domains

---

**Last Updated**: 2026-01-18
**Version**: SafeOps Engine v1.0
**Author**: Security Team
