# SafeOps Network Security Platform

**Enterprise-Grade Network Security & Certificate Management System**

---

## 🎯 What is SafeOps?

SafeOps is a comprehensive network security platform that provides:
- **Certificate Management** (powered by step-ca)
- **DHCP Server** with automatic CA distribution
- **DNS Server** with captive portal redirection
- **Device Enrollment** via captive portal
- **Real-time Monitoring Dashboard**

### Current Status: Phase 3 Complete ✅

✅ **Working Now:**
- NIC Management
- DHCP Server (IP assignment + CA URL distribution)
- DNS Server (resolution + captive portal redirect)
- Certificate Manager (with step-ca backend)
- Captive Portal (forced CA installation)
- Dashboard (real-time monitoring)

❌ **Not Yet Built:**
- TLS/SSL Proxy (critical for SSL interception)
- Firewall Engine
- IDS/IPS
- Network Logger

---

## 📚 Documentation

### Getting Started
| Document | Purpose |
|----------|---------|
| **[ARCHITECTURE_DECISIONS.md](ARCHITECTURE_DECISIONS.md)** | **START HERE** - Why step-ca? What's working? Technical decisions |
| **[README_STEP_CA.md](README_STEP_CA.md)** | Complete step-ca integration guide |
| **[QUICK_START_STEP_CA.md](QUICK_START_STEP_CA.md)** | Quick start in 3 commands |
| **[QUICK_REFERENCE.md](QUICK_REFERENCE.md)** | Quick command reference |

### Detailed Documentation
| Document | Purpose |
|----------|---------|
| [STEP_CA_INTEGRATION_COMPLETE.md](STEP_CA_INTEGRATION_COMPLETE.md) | Detailed step-ca integration documentation |

---

## 🚀 Quick Start

### Start All Services

**Option 1: Master Startup Script (Recommended)**
```powershell
# Run as Administrator
D:\SafeOpsFV2\start-safeops-with-stepca.ps1
```

**Option 2: Manual Startup**
```powershell
# Terminal 1: step-ca
D:\SafeOpsFV2\certs\step-ca\start-safeops-ca.ps1

# Terminal 2: Certificate Manager
cd D:\SafeOpsFV2\src\certificate_manager
.\start_certificate_manager.ps1

# Terminal 3: DHCP Server (as Admin)
cd D:\SafeOpsFV2\src\dhcp_server
.\start_dhcp.bat

# Terminal 4: DNS Server (as Admin)
cd D:\SafeOpsFV2\src\dns_server
.\start_dns.bat

# Terminal 5: Dashboard
cd D:\SafeOpsFV2\src\ui\dev
npm run dev
```

### Verify Services

```powershell
# Check step-ca
curl -k https://192.168.137.1:9000/health

# Check Dashboard
Start-Process "http://localhost:5173"
```

---

## 🏗️ Architecture

### Current Implementation

```
Device Connects
    ↓
DHCP Server (assigns IP + CA URL)
    ↓
DNS Server (checks CA installed? → redirects if not)
    ↓
Captive Portal (forces CA installation)
    ↓
User Installs CA (10-30 seconds)
    ↓
Internet Access Granted ✅
    ↓
SSL Interception (NOT YET BUILT ❌)
```

### Services

| Service | Port | Status | Purpose |
|---------|------|--------|---------|
| **step-ca** | 9000 | ✅ Working | Certificate Authority backend |
| **Certificate Manager** | 8082 | ✅ Working | CA distribution |
| **DHCP Server** | 67 | ✅ Working | IP assignment |
| **DNS Server** | 53 | ✅ Working | DNS resolution + redirect |
| **Captive Portal** | 8080 | ✅ Working | Force CA installation |
| **Dashboard** | 5173 | ✅ Working | Monitoring UI |
| **TLS Proxy** | 443 | ❌ Not Built | SSL interception |

---

## 🔐 Certificate Management (step-ca)

### Why step-ca?

We chose step-ca over custom implementation because:
- ✅ **3x faster** certificate signing (<50ms vs ~150ms)
- ✅ **Security audited** by professionals
- ✅ **Battle-tested** (used by thousands of companies)
- ✅ **ACME/SCEP/OCSP** built-in
- ✅ **100% FREE** (Apache 2.0 license)
- ✅ **Unlimited devices**
- ✅ **Community maintained**

See: [ARCHITECTURE_DECISIONS.md](ARCHITECTURE_DECISIONS.md) for full comparison.

### SafeOps CA Details

```
Organization: SafeOps Network
Root CA: SafeOps Root CA (10 years validity)
Intermediate CA: SafeOps Intermediate CA (5 years)
Key Size: RSA 4096-bit
Algorithm: SHA256-RSA
Location: D:\SafeOpsFV2\certs\safeops-root-ca.crt
```

### step-ca Endpoints

```
API Server: https://192.168.137.1:9000
ACME Endpoint: https://192.168.137.1:9000/acme/safeops-acme/directory
Health Check: https://192.168.137.1:9000/health
Root CA: https://192.168.137.1:9000/root
```

---

## 📊 What's Working

### ✅ Complete Features

**Network Foundation**
- NIC Management (interface control)
- DHCP Server (IP assignment, CA URL distribution)
- DNS Server (resolution, captive portal redirect, enrollment checking)

**Certificate Infrastructure**
- step-ca Certificate Authority (fast, secure, free)
- Certificate Manager (CA distribution, device tracking)
- Captive Portal (forced installation, OS detection)

**Monitoring**
- Real-time Dashboard (service status, device tracking)
- Device enrollment tracking
- Service health monitoring

### ❌ Missing Components

**Critical (Needed for SSL Interception)**
- TLS/SSL Proxy - **HIGHEST PRIORITY**

**Important (Security Features)**
- Firewall Engine
- IDS/IPS (Intrusion Detection/Prevention)
- Network Logger
- Threat Intelligence

---

## 🎓 How Device Enrollment Works

1. **Device connects** to network
2. **DHCP assigns** IP + DNS + Gateway + CA URL (automatic)
3. **User opens browser** → any website
4. **DNS intercepts** → checks if CA installed
5. **If NO CA**: Redirects to captive portal (automatic)
6. **Captive portal opens** → "Install SafeOps CA" (automatic)
7. **User clicks download** → Gets certificate (1 click)
8. **User installs** → 10-30 seconds (manual - OS security)
9. **DNS detects install** → via TLS handshake (automatic)
10. **Internet granted** → Device can browse (automatic)

**Only step 8 requires manual user action** (cannot be automated - OS security restriction)

---

## 📁 Project Structure

```
D:\SafeOpsFV2\
├── certs/
│   ├── safeops-root-ca.crt          # Root CA for distribution
│   └── step-ca/                     # step-ca installation
│       ├── step-ca.exe              # CA server binary
│       ├── ca/                      # CA data
│       └── start-safeops-ca.ps1     # Startup script
│
├── config/
│   ├── safeops.toml                 # Main configuration
│   └── step-ca-integration.toml     # step-ca integration config
│
├── src/
│   ├── certificate_manager/         # ✅ CA distribution service
│   ├── dhcp_server/                 # ✅ DHCP with CA URL
│   ├── dns_server/                  # ✅ DNS + captive redirect
│   ├── nic_management/              # ✅ Network interface control
│   ├── ui/dev/                      # ✅ Dashboard
│   ├── tls_proxy/                   # ❌ NOT BUILT (empty)
│   ├── firewall_engine/             # ❌ NOT BUILT (empty)
│   └── ids_ips/                     # ❌ NOT BUILT (empty)
│
├── start-safeops-with-stepca.ps1    # Master startup script
│
└── Documentation/
    ├── README.md                    # This file
    ├── ARCHITECTURE_DECISIONS.md    # Technical decisions & status
    ├── README_STEP_CA.md            # step-ca guide
    └── QUICK_START_STEP_CA.md       # Quick start
```

---

## 🔧 Configuration

### Main Config: `config/safeops.toml`

```toml
[network]
server_ip = "192.168.137.1"
managed_subnet = "192.168.137.0/24"

[dhcp]
pool_start = "192.168.137.100"
pool_end = "192.168.137.200"
dns_server = "192.168.137.1"
gateway = "192.168.137.1"

[dns]
upstream_servers = ["8.8.8.8:53", "1.1.1.1:53"]
authoritative_zones = ["safeops.local"]

[certificate_manager]
ca_cert_path = "D:/SafeOpsFV2/certs/safeops-root-ca.crt"
```

### step-ca Config: `certs/step-ca/ca/config/ca.json`

```json
{
  "address": "192.168.137.1:9000",
  "dnsNames": ["safeops.local", "192.168.137.1"],
  "authority": {
    "provisioners": [{
      "type": "ACME",
      "name": "safeops-acme"
    }]
  }
}
```

---

## 📊 Service Limits & Performance

### Device Capacity

| Devices | step-ca Performance | Your Hardware Requirement |
|---------|---------------------|---------------------------|
| 1-50 | Instant (<20ms) | Any modern PC |
| 50-100 | Very fast (<30ms) | Normal PC (4GB+ RAM) |
| 100-500 | Fast (<50ms) | Good server (8GB+ RAM) |
| 500-1000 | Good (<100ms) | Enterprise server (16GB+ RAM) |
| 1000+ | Enterprise | Dedicated server (32GB+ RAM) |

**step-ca itself: UNLIMITED** (no license restrictions)

### Current Bottlenecks

- **DHCP Pool**: 100 IPs (192.168.137.100-200) - easily expandable
- **Hardware**: Depends on your PC specs
- **step-ca**: No limits

---

## 💰 Cost

| Component | License | Cost |
|-----------|---------|------|
| **step-ca** | Apache 2.0 | ✅ FREE |
| **SafeOps Code** | Your Code | ✅ FREE |
| **Device Limits** | None | ✅ Unlimited |
| **Certificate Signing** | Unlimited | ✅ FREE |
| **Support** | Community | ✅ FREE |

**Total Cost: $0 forever**

---

## 🛣️ Roadmap

### Phase 1: Network Foundation ✅ COMPLETE
- [x] NIC Management
- [x] DHCP Server
- [x] DNS Server
- [x] Basic configuration

### Phase 2: Certificate Infrastructure ✅ COMPLETE
- [x] step-ca installation & configuration
- [x] SafeOps CA creation
- [x] Certificate Manager
- [x] Captive Portal
- [x] CA distribution

### Phase 3: Monitoring ✅ COMPLETE
- [x] Real-time Dashboard
- [x] Device tracking
- [x] Service monitoring

### Phase 4: SSL Interception ❌ NEXT PRIORITY
- [ ] TLS/SSL Proxy implementation
- [ ] Certificate request to step-ca
- [ ] HTTPS decryption
- [ ] Traffic logging

### Phase 5: Security Features ❌ FUTURE
- [ ] Firewall Engine
- [ ] IDS/IPS
- [ ] Threat Intelligence
- [ ] Network Logger

---

## 🧪 Testing

### Test step-ca
```powershell
curl -k https://192.168.137.1:9000/health
# Expected: {"status":"ok"}
```

### Test Complete Flow
1. Connect a device to your network
2. Device gets IP from DHCP (automatic)
3. Open browser → google.com
4. Redirected to captive portal (automatic)
5. Download SafeOps CA certificate
6. Install certificate (10-30 seconds)
7. Internet access granted!

See: [QUICK_START_STEP_CA.md](QUICK_START_STEP_CA.md) for detailed testing guide.

---

## 📞 Troubleshooting

### Services Won't Start?

**Check if running as Administrator:**
```powershell
# Right-click PowerShell → Run as Administrator
```

**Check ports:**
```powershell
netstat -ano | findstr ":9000 :67 :53 :8082"
```

### Can't Access step-ca?

**Allow through firewall:**
```powershell
netsh advfirewall firewall add rule name="SafeOps CA" dir=in action=allow protocol=TCP localport=9000
```

### Dashboard Not Loading?

**Check Node.js:**
```powershell
cd D:\SafeOpsFV2\src\ui\dev
npm install
npm run dev
```

---

## 📖 Additional Resources

### Official Documentation
- **step-ca**: https://smallstep.com/docs/step-ca
- **ACME Protocol**: https://smallstep.com/docs/tutorials/acme-protocol-acme-clients

### SafeOps Documentation
- **Architecture Decisions**: [ARCHITECTURE_DECISIONS.md](ARCHITECTURE_DECISIONS.md)
- **step-ca Integration**: [README_STEP_CA.md](README_STEP_CA.md)
- **Quick Start**: [QUICK_START_STEP_CA.md](QUICK_START_STEP_CA.md)

---

## 🤝 Contributing

This is a personal project. The codebase structure:
- **Go**: DHCP, DNS, Certificate Manager, Orchestrator
- **JavaScript/React**: Dashboard UI
- **Configuration**: TOML files

---

## 📄 License

- **SafeOps Code**: Your proprietary code
- **step-ca**: Apache 2.0 (100% FREE)

---

## ✅ Summary

**What You Have:**
- ✅ Complete device enrollment system
- ✅ Enterprise-grade CA (step-ca)
- ✅ Automated CA distribution
- ✅ Real-time monitoring
- ✅ 100% FREE, unlimited devices
- ✅ Full SafeOps branding

**What You Need Next:**
- ❌ TLS/SSL Proxy (for HTTPS interception)
- ❌ Firewall Engine
- ❌ IDS/IPS

**To Get Started:**
```powershell
# Start everything
D:\SafeOpsFV2\start-safeops-with-stepca.ps1

# Open dashboard
Start-Process "http://localhost:5173"
```

---

**SafeOps Network Security Platform**
*Powered by step-ca Certificate Authority*
