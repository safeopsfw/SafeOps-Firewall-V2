# SafeOps FV2 - Quick Reference Guide

**Last Updated:** 2026-01-21
**Version:** 2.0.0

## 🚀 Quick Start

### Start All Services
```cmd
cd D:\SafeOpsFV2
.\bin\SafeOps-Launcher.exe
```

### Stop All Services
Press **Ctrl+C** in the launcher window

### Access Web Interface
Open browser to: **http://localhost:3003**

---

## 📦 Component Quick Reference

| Component | Executable | Port(s) | Purpose |
|-----------|-----------|---------|---------|
| **SafeOps Launcher** | `bin/SafeOps-Launcher.exe` | - | Orchestrates all services |
| **NIC Management** | `bin/nic_management/nic_management.exe` | 8081, 50054 | Network interfaces, Multi-WAN, NAT |
| **DHCP Monitor** | `bin/dhcp_monitor/dhcp_monitor.exe` | 50055 | Device detection & tracking |
| **Threat Intel** | `bin/threat_intel/threat_intel.exe` | 8080 | IP/Domain reputation |
| **Network Logger** | `bin/network_logger/network_logger.exe` | 50052, 9092 | Packet capture & logging |
| **SafeOps Engine** | `bin/safeops-engine/safeops-engine.exe` | 9002, 50053 | Firewall & DDoS protection |
| **DNS Proxy** | `bin/dnsproxy/windows-amd64/dnsproxy.exe` | 15353 | DNS filtering & caching |
| **Captive Portal** | `bin/captive_portal/captive_portal.exe` | 8082 | Device authentication |
| **Step-CA** | `bin/step-ca/bin/step-ca.exe` | 9000 | Certificate Authority |
| **PostgreSQL** | External | 5432 | Database |
| **Elasticsearch** | External | 9200 | SIEM indexing |
| **Kibana** | External | 5601 | SIEM visualization |

---

## 🔌 Port Reference

### REST APIs
- **8080** - Threat Intelligence API
- **8081** - NIC Management API
- **8082** - Captive Portal
- **9002** - SafeOps Engine API

### gRPC Services
- **50052** - Network Logger
- **50053** - Firewall Engine
- **50054** - NIC Management
- **50055** - DHCP Monitor

### Metrics (Prometheus)
- **9092** - Network Logger metrics
- **9093** - Firewall Engine metrics
- **9095** - DHCP Monitor metrics
- **9154** - NIC Management metrics

### Other Services
- **5432** - PostgreSQL
- **3003** - Frontend UI
- **9000** - Step-CA (PKI)
- **9200** - Elasticsearch
- **5601** - Kibana
- **15353** - DNS Proxy
- **67** - DHCP Server (UDP)

---

## 📂 Important Locations

### Executables
```
D:\SafeOpsFV2\bin\
```

### Source Code
```
D:\SafeOpsFV2\src\
```

### Configuration
```
D:\SafeOpsFV2\config\
├── defaults\application_settings.toml
├── defaults\home_network.toml
└── templates\firewall.toml
```

### Logs
```
D:\SafeOpsFV2\logs\
├── network_packets_master.jsonl  # Network traffic
├── firewall.log                  # Firewall events
├── ids.log                       # IDS/IPS alerts
├── devices.jsonl                 # Connected devices
└── engine.log                    # SafeOps Engine
```

### Documentation
```
D:\SafeOpsFV2\docs\
├── README.md                     # Master documentation
├── PROJECT-STATS.md              # Project statistics
├── QUICK-REFERENCE.md            # This file
└── components\                   # Component docs
```

---

## 🔍 Common Commands

### Check Running Services
```powershell
Get-Process | Where-Object {$_.ProcessName -like "*safeops*" -or $_.ProcessName -like "*dhcp*" -or $_.ProcessName -like "*threat*"}
```

### View Network Activity
```cmd
tail -f D:\SafeOpsFV2\logs\network_packets_master.jsonl
```

### View Firewall Logs
```cmd
tail -f D:\SafeOpsFV2\logs\firewall.log
```

### Update Threat Intelligence
```cmd
cd D:\SafeOpsFV2\bin\threat_intel
.\threat_intel.exe
```

### Start SIEM Stack
```cmd
cd D:\SafeOps-SIEM-Integration\scripts
.\start-all.bat
```

### Stop SIEM Stack
```cmd
cd D:\SafeOps-SIEM-Integration\scripts
.\stop-all.bat
```

---

## 🗄️ Database Quick Reference

### Connect to PostgreSQL
```cmd
psql -U postgres -h localhost -d safeops
```

### Key Databases
- **safeops** - Main database
- **threat_intel_db** - Threat intelligence
- **nic_management** - Network management
- **dhcp_monitor** - Device tracking

### Key Tables
```sql
-- View connected devices
SELECT * FROM devices ORDER BY last_seen DESC;

-- View threat intelligence IPs
SELECT * FROM ip_blacklist LIMIT 10;

-- View firewall rules
SELECT * FROM firewall_rules WHERE enabled = true;

-- View DHCP leases
SELECT * FROM dhcp_leases WHERE lease_state = 'ACTIVE';
```

---

## 🌐 Web Interfaces

| Service | URL | Credentials |
|---------|-----|-------------|
| Frontend UI | http://localhost:3003 | None (dev) |
| Kibana (SIEM) | http://localhost:5601 | None (dev) |
| Elasticsearch | http://localhost:9200 | None (dev) |
| NIC Management API | http://localhost:8081/api/nics | None |
| Threat Intel API | http://localhost:8080/v1/stats | None |

---

## ⚙️ Configuration Quick Edits

### Firewall Rules
Edit: `D:\SafeOpsFV2\config\templates\firewall.toml`

### Network Settings
Edit: `D:\SafeOpsFV2\config\defaults\application_settings.toml`

### DNS Proxy
Edit: `D:\SafeOpsFV2\src\safeops-engine\configs\dnsproxy.yaml`

### Threat Feed Sources
Edit: `D:\SafeOpsFV2\src\threat_intel\config\sources.yaml`

---

## 🐛 Troubleshooting

### Service Won't Start
```powershell
# Check if port is in use
netstat -ano | findstr "PORT_NUMBER"

# Kill process on port
taskkill /PID <PID> /F
```

### Database Connection Failed
```cmd
# Check PostgreSQL status
pg_ctl status -D "C:/Program Files/PostgreSQL/16/data"

# Start PostgreSQL
pg_ctl start -D "C:/Program Files/PostgreSQL/16/data"
```

### High CPU Usage
1. Check Network Logger buffer size
2. Reduce threat feed update frequency
3. Limit packet capture interfaces
4. Check for runaway processes

### Logs Not Appearing
1. Verify component is running
2. Check log directory permissions
3. Verify log path in config
4. Check disk space

---

## 📊 Component Statistics

### Network Logger
- **Capture Rate:** 50K-150K packets/second
- **Log Rotation:** 5-minute rolling window
- **Memory:** <500 MB

### Threat Intelligence
- **Malicious IPs:** 34,000+
- **Malicious Domains:** 1.1M+
- **VPN/Tor/Proxy IPs:** 1,300+
- **File Hashes:** 10,000+
- **GeoIP Records:** 1.1M+

### Firewall Engine
- **Packet Rate:** ~6,500 pps
- **Max Connections:** 1M+
- **State Table:** 1M buckets

### DHCP Monitor
- **Detection Speed:** 15-35ms
- **Cache TTL:** 10 seconds

---

## 🔐 Security Defaults

### Firewall
- **Inbound Policy:** DENY (secure default)
- **Outbound Policy:** ALLOW
- **Forward Policy:** DENY

### Device Trust
- **New Devices:** UNTRUSTED
- **Captive Portal:** Required for trust
- **Blocked Devices:** DROP all traffic

### SIEM
- **Authentication:** None (local dev only)
- **⚠️ Enable for production:** Yes

### APIs
- **Default Binding:** localhost only
- **⚠️ Production:** Enable TLS

---

## 🚨 Emergency Procedures

### Stop All Network Filtering
```powershell
# Stop SafeOps Engine
Get-Process -Name "safeops-engine" | Stop-Process -Force

# Stop DNS Proxy
Get-Process -Name "dnsproxy" | Stop-Process -Force

# Stop Network Logger
Get-Process -Name "network_logger" | Stop-Process -Force
```

### Reset Firewall to Default
```cmd
# Backup current rules
copy D:\SafeOpsFV2\config\firewall.toml D:\SafeOpsFV2\config\firewall.toml.bak

# Restore template
copy D:\SafeOpsFV2\config\templates\firewall.toml D:\SafeOpsFV2\config\firewall.toml

# Restart engine
```

### Clear All Logs
```powershell
# Stop services first!
Remove-Item D:\SafeOpsFV2\logs\*.* -Force

# Restart services
```

---

## 📚 Documentation Links

- **Master README:** `docs/README.md`
- **Project Statistics:** `docs/PROJECT-STATS.md`
- **Component Docs:** `docs/components/`
- **SIEM Setup:** `docs/components/01-SIEM.md`

---

## 📞 Quick Reference Card

**Start Everything:** `.\bin\SafeOps-Launcher.exe`
**Web UI:** http://localhost:3003
**SIEM Dashboard:** http://localhost:5601
**Logs:** `D:\SafeOpsFV2\logs\`
**Config:** `D:\SafeOpsFV2\config\`
**Stop:** Ctrl+C in launcher window

---

**For detailed documentation, see:** `D:\SafeOpsFV2\docs\README.md`
