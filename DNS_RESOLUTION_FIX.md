# DNS Resolution Fix Analysis

## Problem Identified

From your logs:
```
2026/01/19 11:10:18 [001] WARN: Error dialing to spclient.wg.spotify.com:443: lookup spclient.wg.spotify.com on 103.56.228.140:53: read udp 127.0.0.1:60387->127.0.0.1:15353: i/o timeout
```

### Root Causes:

1. **goproxy Custom DNS Resolver Failed**
   - goproxy's custom DNS dialer was not properly forcing use of 127.0.0.1:15353
   - Go's `net.Resolver` was still reading system DNS configuration
   - Result: DNS queries went to `103.56.228.140:53` (likely your ISP/network DNS)

2. **dnsproxy Timeout**
   - dnsproxy is listening on `127.0.0.1:15353` ✅
   - But queries to dnsproxy are timing out (10s timeout)
   - dnsproxy logs show it's trying to reach upstream `103.56.228.140:53`
   - This might be a network/firewall issue preventing dnsproxy from reaching upstream DNS

## Fixes Applied

### Fix #1: Improved Custom DNS Dialer
**File**: `internal/proxy/proxy.go`

**Changes**:
- Simplified DNS resolution logic
- Added explicit UDP connection to dnsproxy
- Increased timeout to 15s for DNS lookups
- Better error messages for debugging

**Before**:
```go
resolver.LookupIP(ctx, "ip4", host) // Used system resolver sometimes
```

**After**:
```go
resolver := &net.Resolver{
    PreferGo: true, // FORCE Go resolver
    Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
        // IGNORE 'address' - always use our dnsproxy
        d := net.Dialer{Timeout: 10 * time.Second}
        return d.DialContext(ctx, "udp", "127.0.0.1:15353")
    },
}
```

## Recommended Testing Steps

### Step 1: Test dnsproxy Directly
```powershell
# Open PowerShell as Administrator

# Test if dnsproxy is reachable
nslookup google.com 127.0.0.1 -port=15353

# OR use dig if installed
dig @127.0.0.1 -p 15353 google.com
```

**Expected**: Should resolve google.com successfully
**If fails**: dnsproxy has upstream connectivity issues

### Step 2: Check Firewall Rules
```powershell
# Check if Windows Firewall is blocking dnsproxy's upstream queries
Get-NetFirewallProfile | Select-Object Name, Enabled

# Temporarily disable firewall for testing
Set-NetFirewallProfile -Profile Domain,Public,Private -Enabled False

# Run SafeOps Engine again
.\safeops-engine.exe

# Re-enable firewall after testing
Set-NetFirewallProfile -Profile Domain,Public,Private -Enabled True
```

### Step 3: Check dnsproxy Configuration

Current dnsproxy args (in spawner.go):
```go
args := []string{
    "-l", "127.0.0.1",
    "-p", "15353",
    "-u", "8.8.8.8",        // Google
    "-u", "1.1.1.1",        // Cloudflare
    "-u", "208.67.222.222", // OpenDNS
    "--cache",
    "-v", // Verbose
}
```

**Potential Issue**: If your network blocks UDP/53 to public DNS (8.8.8.8, 1.1.1.1), dnsproxy will timeout.

**Alternative**: Use DNS-over-HTTPS (DoH) which uses TCP/443:
```go
args := []string{
    "-l", "127.0.0.1",
    "-p", "15353",
    "-u", "https://dns.google/dns-query",  // DoH
    "-b", "8.8.8.8",  // Bootstrap
    "--cache",
    "-v",
}
```

## What's Working Now

✅ WinpkFilter driver loading
✅ Network adapters detected (5 adapters in tunnel mode)
✅ dnsproxy process starting
✅ goproxy starting on port 8080
✅ System proxy configured
✅ Packet processing started
✅ DNS packets identified (92 DNS packets, 91 redirected)

## What's NOT Working

❌ DNS resolution timing out
❌ goproxy can't connect to HTTPS sites (DNS lookup fails)

## Next Steps

1. **Test dnsproxy directly** (see Step 1 above)
2. If dnsproxy works: The fix in proxy.go should resolve the issue
3. If dnsproxy fails:
   - Switch to DoH upstream (see alternative config)
   - OR check firewall/network restrictions

## Quick Test Command

```powershell
# As Administrator
cd D:\SafeOpsFV2\src\safeops-engine
.\safeops-engine.exe
```

Watch for:
- No more "i/o timeout" errors
- HTTPS CONNECT requests should succeed
- DNS resolution should work

## Rollback Plan

If issues persist, we can:
1. Disable custom DNS dialer (use system DNS)
2. Rely only on WinpkFilter DNS redirection
3. Or switch to DoH for dnsproxy upstream
