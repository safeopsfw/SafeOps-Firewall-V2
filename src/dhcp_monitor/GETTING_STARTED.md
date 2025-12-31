# Getting Started with DHCP Monitor

## 🎯 Quick Start

This guide will help you set up the DHCP Monitor service to automatically distribute Step-CA certificates to devices connecting to your network via Windows DHCP.

---

## ✅ Prerequisites

### 1. **Windows DHCP Server**
- Installed and running
- At least one scope configured

**Check DHCP Server:**
```powershell
Get-Service DHCPServer
Get-DhcpServerv4Scope
```

### 2. **Step-CA Installed**
- Step-CA running on port 9000
- Root certificate available at: `D:/SafeOpsFV2/certs/step-ca/ca/certs/root_ca.crt`

**Verify Step-CA:**
```bash
step-ca --version
ls D:/SafeOpsFV2/certs/step-ca/ca/certs/root_ca.crt
```

### 3. **Go 1.23 or later**
```bash
go version
```

### 4. **Administrator Privileges**
- Required for DNS server (port 53)
- Required for configuring Windows DHCP

---

## 🚀 Installation Steps

### Step 1: Configure Settings

Edit `config/config.yaml`:

```yaml
stepca:
  root_cert_path: "D:/SafeOpsFV2/certs/step-ca/ca/certs/root_ca.crt"

portal:
  ip: "auto"  # Will auto-detect your IP

dns:
  enabled: true
  upstream: "8.8.8.8"  # Your preferred DNS
```

### Step 2: Install Dependencies

```bash
cd D:\SafeOpsFV2\src\dhcp_monitor
go mod download
```

### Step 3: Configure Windows DHCP

**Option A: Automatic (Recommended)**

Run as Administrator:
```powershell
.\configure_windows_dhcp.ps1
```

This will configure all DHCP scopes to:
- Set DNS server to your machine's IP
- Set gateway to your machine's IP

**Option B: Manual**

```powershell
# Get your IP
$myIP = (Get-NetIPAddress -AddressFamily IPv4 | Where-Object { $_.InterfaceAlias -notlike "*Loopback*" })[0].IPAddress

# Get scope ID
$scopeId = (Get-DhcpServerv4Scope)[0].ScopeId

# Configure DHCP options
Set-DhcpServerv4OptionValue -ScopeId $scopeId -OptionId 6 -Value $myIP  # DNS
Set-DhcpServerv4OptionValue -ScopeId $scopeId -OptionId 3 -Value $myIP  # Gateway
```

### Step 4: Configure Firewall

Run as Administrator:
```powershell
# Allow DNS (port 53)
New-NetFirewallRule -DisplayName "DHCP Monitor - DNS" -Direction Inbound -Protocol UDP -LocalPort 53 -Action Allow

# Allow HTTP (port 80)
New-NetFirewallRule -DisplayName "DHCP Monitor - HTTP" -Direction Inbound -Protocol TCP -LocalPort 80 -Action Allow

# Optional: Allow HTTPS (port 443)
New-NetFirewallRule -DisplayName "DHCP Monitor - HTTPS" -Direction Inbound -Protocol TCP -LocalPort 443 -Action Allow
```

### Step 5: Build the Service

```bash
cd D:\SafeOpsFV2\src\dhcp_monitor
go build -o dhcp_monitor.exe cmd/main.go
```

### Step 6: Run the Service

**As Administrator:**
```bash
.\dhcp_monitor.exe
```

You should see:
```
[INFO] Starting DHCP Monitor v1.0.0
[INFO] Configuration loaded successfully
[INFO] Initializing device tracking database...
[INFO] Connecting to Windows DHCP Server...
[INFO] Starting DHCP poller (interval: 30s)...
[INFO] Starting DNS hijacking server on port 53...
[INFO] Starting captive portal on port 80...
[INFO] DHCP Monitor started successfully

============================================================
  DHCP Monitor v1.0.0 - Running
============================================================
  Portal IP:       192.168.1.100
  HTTP Portal:     http://192.168.1.100:80
  DNS Server:      192.168.1.100:53
  Database:        ./devices.db
  Step-CA Root:    D:/SafeOpsFV2/certs/step-ca/ca/certs/root_ca.crt
============================================================
  Total Devices:   0
  Enrolled:        0
  Unenrolled:      0
============================================================
```

---

## 📱 Testing the Complete Flow

### Test with a Mobile Device

1. **Connect device to network** (WiFi/Ethernet on same network as your machine)

2. **Device gets IP from Windows DHCP**
   - Windows DHCP assigns IP
   - Sets DNS to your machine (192.168.1.100)
   - Sets gateway to your machine

3. **DHCP Monitor detects device**
   ```
   [INFO] New device detected: IP=192.168.100.50, MAC=AA:BB:CC:DD:EE:FF, Hostname=iPhone
   ```

4. **Device tries to access internet**
   - DNS query goes to your DNS server (port 53)
   - DNS hijacking returns portal IP for all queries
   - OS detects captive portal

5. **Captive portal notification appears**
   - iOS: "Sign in to Wi-Fi" notification
   - Android: "Sign in to network" notification
   - Windows: Browser opens automatically

6. **User sees portal page**
   - OS is auto-detected
   - Shows device-specific installation instructions
   - Provides download button

7. **User downloads and installs certificate**
   - iOS: Downloads `.mobileconfig` profile
   - Android/Windows/macOS: Downloads `.crt` file
   - User follows installation steps

8. **Portal detects installation**
   - Portal polls every 5 seconds
   - Verifies certificate via TLS handshake (if HTTPS enabled)
   - Shows success message

9. **Internet access granted**
   ```
   [INFO] Device 192.168.100.50 successfully enrolled (certificate installed)
   ```
   - DNS hijacking stops for this device
   - All DNS queries forwarded to real DNS (8.8.8.8)
   - Device has full internet access

---

## 🔍 Monitoring and Debugging

### View Devices

Check the SQLite database:
```bash
sqlite3 devices.db "SELECT ip, mac, hostname, has_certificate FROM devices;"
```

### View Logs

Service logs go to stdout. To capture:
```bash
.\dhcp_monitor.exe > dhcp_monitor.log 2>&1
```

### Check DNS Hijacking

From an unenrolled device:
```bash
nslookup google.com
# Should return your portal IP (192.168.1.100)
```

From an enrolled device:
```bash
nslookup google.com
# Should return real Google IP
```

### Check DHCP Configuration

```powershell
Get-DhcpServerv4OptionValue -ScopeId <scope_id>
```

Should show:
- Option 3 (Router): Your IP
- Option 6 (DNS Servers): Your IP

---

## 🛠️ Troubleshooting

### "Failed to bind to port 53"
- **Cause**: Another DNS server is running (like Windows DNS Server)
- **Solution**:
  ```powershell
  Stop-Service DNS  # If Windows DNS Server is running
  ```
  Or change DNS port in `config.yaml`

### "Failed to connect to Windows DHCP"
- **Cause**: DHCP Server not running or PowerShell DHCP module not available
- **Solution**:
  ```powershell
  Start-Service DHCPServer
  Import-Module DhcpServer
  ```

### "Captive portal doesn't appear"
- **Cause**: DNS hijacking not working
- **Check**:
  1. Is DNS server running? (netstat -an | findstr :53)
  2. Did DHCP assign correct DNS? (ipconfig /all on device)
  3. Is firewall blocking port 53?

### "Certificate verification fails"
- **Cause**: Step-CA root certificate not found or invalid
- **Solution**:
  ```bash
  ls D:/SafeOpsFV2/certs/step-ca/ca/certs/root_ca.crt
  # Verify file exists and is readable
  ```

### Devices stuck on "Checking for certificate..."
- **Cause**: Portal can't verify certificate (HTTPS not enabled)
- **Solution**: Certificate verification works better with HTTPS enabled
- **Workaround**: Manual verification or rely on DNS forwarding test

---

## 🔧 Advanced Configuration

### Enable HTTPS for Portal

1. Generate portal certificate from Step-CA:
```bash
step ca certificate portal.local portal.crt portal.key
```

2. Update config.yaml:
```yaml
portal:
  https_enabled: true
  cert_path: "portal.crt"
  key_path: "portal.key"
```

3. Restart service

### Change Poll Interval

In `config.yaml`:
```yaml
windows_dhcp:
  poll_interval: "10s"  # Check every 10 seconds (default: 30s)
```

### Use Different Upstream DNS

In `config.yaml`:
```yaml
dns:
  upstream: "1.1.1.1"  # Cloudflare DNS
  # Or: "9.9.9.9"  # Quad9
```

---

## 📊 Service Architecture

```
┌─────────────────────────────────────────────────────────┐
│              Your Windows Machine                        │
│                                                          │
│  ┌───────────────┐  ┌────────────┐  ┌──────────────┐  │
│  │ DHCP Monitor  │  │  Windows   │  │   Step-CA    │  │
│  │               │  │   DHCP     │  │  Port 9000   │  │
│  │ • DNS :53     │  │            │  │              │  │
│  │ • HTTP :80    │  │            │  │              │  │
│  │ • Poll :30s   │  │            │  │              │  │
│  └───────┬───────┘  └─────┬──────┘  └──────────────┘  │
│          │                 │                            │
│          └─────────────────┴────────────────────────────│
│                             ↓                            │
│                   ┌─────────────────┐                   │
│                   │  Device DB      │                   │
│                   │  (SQLite)       │                   │
│                   └─────────────────┘                   │
└─────────────────────────────────────────────────────────┘
                          ↕
            ┌──────────────────────────┐
            │   Connected Devices      │
            │   (Phone/Laptop/Tablet)  │
            └──────────────────────────┘
```

---

## 🎉 Success!

Once running, any device that connects to your network will:
1. Get an IP from Windows DHCP
2. Be detected by DHCP Monitor
3. Have DNS hijacked to captive portal
4. See installation instructions
5. Install Step-CA root certificate
6. Get verified and granted internet access

**All automatically, with zero interference to Windows DHCP!** 🚀
