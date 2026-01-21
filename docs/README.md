# SafeOps FV2 - Complete Component Documentation

> 📚 **Complete Documentation Available!** All 10 components have detailed documentation covering file locations, functionality, ports, APIs, dependencies, configuration, and troubleshooting.

## Table of Contents

- [Quick Start](#quick-start)
- [📚 Complete Component Documentation](#-complete-component-documentation) ← **DETAILED DOCS FOR ALL COMPONENTS**
- [Port Reference](#port-reference)
- [Data Flow](#data-flow)
- [System Requirements](#system-requirements)
- [Configuration Files](#configuration-files)
- [Logs and Data](#logs-and-data)
- [Common Tasks](#common-tasks)
- [Troubleshooting](#troubleshooting)
- [Security Considerations](#security-considerations)
- [Development](#development)
- [Version Information](#version-information)

## Project Overview

SafeOps FV2 is a comprehensive network security platform featuring firewall, threat intelligence, network monitoring, and security services with **11 major components** and **35+ supporting modules**.

## Component Architecture

```
SafeOps-Launcher.exe (Orchestrator)
├── PostgreSQL Database (Port 5432)
├── NIC Management API (Port 8081)
├── DHCP Server (Port 67)
├── DHCP Monitor (Port 50055)
├── Threat Intelligence API (Port 8080)
├── Network Logger (Port 50052)
├── SafeOps Engine (Port 9002)
├── DNS Proxy (Port 15353)
├── Captive Portal (Port 8082)
├── Step-CA PKI (Port 9000)
└── Frontend UI (Port 3003)
```

## Quick Start

### 1. Start All Services
```cmd
cd D:\SafeOpsFV2
.\bin\SafeOps-Launcher.exe
```

### 2. Access Web UI
Open browser to: http://localhost:3003

### 3. Stop All Services
Press **Ctrl+C** in the launcher window

## 📚 Complete Component Documentation

**All components have detailed documentation!** Each document includes:
- ✅ File locations (source code, binaries, configs)
- ✅ Complete functionality description
- ✅ Default ports and network settings
- ✅ API endpoints and gRPC services
- ✅ Dependencies and integration points
- ✅ Configuration examples
- ✅ Database schemas
- ✅ Troubleshooting guides

### Core Components (Click for Detailed Docs)

#### 1. **[SafeOps Launcher](components/00-SafeOps-Launcher.md)** 🚀
   - **What it does:** Unified service orchestrator that starts/stops all SafeOps components
   - **Executable:** `bin/SafeOps-Launcher.exe`
   - **Manages:** PostgreSQL, NIC Management, DHCP, Threat Intel, Frontend UI
   - **[📖 View Full Documentation →](components/00-SafeOps-Launcher.md)**

#### 2. **[NIC Management API](components/02-NIC-Management.md)** 🌐
   - **What it does:** Multi-WAN load balancing, NAT translation, packet forwarding
   - **Executable:** `bin/nic_management/nic_management.exe`
   - **Ports:** 8081 (REST API), 50054 (gRPC), 9154 (metrics)
   - **Performance:** 1M+ concurrent NAT mappings, zero-copy packet processing
   - **[📖 View Full Documentation →](components/02-NIC-Management.md)**

#### 3. **[DHCP Monitor](components/03-DHCP-Monitor.md)** 📱
   - **What it does:** Real-time device detection (15-35ms), trust management
   - **Executable:** `bin/dhcp_monitor/dhcp_monitor.exe`
   - **Port:** 50055 (gRPC)
   - **Database:** PostgreSQL (devices, dhcp_leases, ip_history)
   - **[📖 View Full Documentation →](components/03-DHCP-Monitor.md)**

#### 4. **[Threat Intelligence](components/04-Threat-Intelligence.md)** 🛡️
   - **What it does:** Aggregates 100+ threat feeds, IP/Domain/Hash reputation
   - **Executables:** `threat_intel.exe` (pipeline), `threat_intel_api.exe` (API)
   - **Port:** 8080 (REST API)
   - **Database:** 34K+ IPs, 1.1M+ domains, 10K+ hashes, 1.1M+ GeoIP records
   - **[📖 View Full Documentation →](components/04-Threat-Intelligence.md)** ⏳ *In Progress*

#### 5. **[Network Logger](components/05-Network-Logger.md)** 📊
   - **What it does:** Packet capture (50K-150K pps), protocol parsing, flow tracking
   - **Executable:** `bin/network_logger/network_logger.exe`
   - **Ports:** 50052 (gRPC), 9092 (metrics)
   - **Protocols:** DNS, HTTP, TLS, TCP, UDP, ICMP
   - **[📖 View Full Documentation →](components/05-Network-Logger.md)** ⏳ *In Progress*

#### 6. **[SafeOps Engine](components/06-SafeOps-Engine.md)** 🔥
   - **What it does:** Stateful firewall, DDoS protection, packet filtering
   - **Executable:** `bin/safeops-engine/safeops-engine.exe`
   - **Ports:** 9002 (API), 50053 (gRPC)
   - **Performance:** 6,500 pps, 1M+ connection tracking, zone-based filtering
   - **[📖 View Full Documentation →](components/06-SafeOps-Engine.md)** ⏳ *In Progress*

#### 7. **[DNS Proxy](components/07-DNS-Proxy.md)** 🔍
   - **What it does:** DNS filtering, caching (10K entries), DNS-over-HTTPS
   - **Executable:** `bin/dnsproxy/windows-amd64/dnsproxy.exe`
   - **Port:** 15353
   - **Upstream:** Google DoH, Cloudflare DoH
   - **[📖 View Full Documentation →](components/07-DNS-Proxy.md)** ⏳ *In Progress*

#### 8. **[Captive Portal](components/08-Captive-Portal.md)** 🔐
   - **What it does:** Device authentication, CA certificate installation
   - **Executable:** `bin/captive_portal/captive_portal.exe`
   - **Port:** 8082 (HTTPS)
   - **Features:** Auto-verify, OS detection, trust management
   - **[📖 View Full Documentation →](components/08-Captive-Portal.md)**

#### 9. **[Step-CA (PKI)](components/09-Step-CA.md)** 🔑
   - **What it does:** Certificate Authority, TLS cert management, ACME protocol
   - **Executable:** `bin/step-ca/bin/step-ca.exe`
   - **Port:** 9000 (HTTPS)
   - **Features:** Root/Intermediate CA, automated certificate issuance
   - **[📖 View Full Documentation →](components/09-Step-CA.md)**

#### 10. **[SIEM (ELK Stack)](components/01-SIEM.md)** 📈
    - **What it does:** Security monitoring, log aggregation, visualization
    - **Services:** Elasticsearch (9200), Kibana (5601), Logstash (5000)
    - **Installation:** PowerShell script, ~1.1 GB download
    - **[📖 View Full Documentation →](components/01-SIEM.md)**

---

### 📂 Additional Documentation

- **[PROJECT-STATS.md](PROJECT-STATS.md)** - Complete project statistics and metrics
- **[QUICK-REFERENCE.md](QUICK-REFERENCE.md)** - One-page quick reference guide
- **[Architecture Diagram](safeops_architecture%20(3).md)** - System architecture overview
- **[CA Certificate Guide](safeops_ca_certificate.md)** - Certificate management details

## Port Reference

| Component | Port(s) | Protocol | Purpose |
|-----------|---------|----------|---------|
| PostgreSQL | 5432 | TCP | Database |
| NIC Management | 8081, 50054 | HTTP, gRPC | Network management |
| DHCP Server | 67 | UDP | DHCP services |
| DHCP Monitor | 50055 | gRPC | Device tracking |
| Threat Intel API | 8080 | HTTP | Threat feeds |
| Network Logger | 50052, 9092 | gRPC, HTTP | Packet logging |
| SafeOps Engine | 9002, 50053 | HTTP, gRPC | Firewall |
| DNS Proxy | 15353 | UDP | DNS filtering |
| Captive Portal | 8082 | HTTP | Device auth |
| Step-CA | 9000 | HTTPS | PKI/Certificates |
| Frontend UI | 3003 | HTTP | Web interface |
| Elasticsearch | 9200 | HTTP | Search/indexing |
| Kibana | 5601 | HTTP | Visualization |
| Logstash | 5000 | TCP | Log ingestion |

## Data Flow

```
Network Traffic
    ↓
SafeOps Engine (Firewall)
    ↓
    ├→ DNS Proxy (DNS filtering)
    ├→ Threat Intel (IP/Domain reputation)
    ├→ Network Logger (Packet logging)
    └→ DHCP Monitor (Device tracking)
    ↓
Allowed/Blocked Decision
    ↓
    ├→ Network Logger (Logging)
    └→ SIEM (Elasticsearch) (Analysis)
```

## System Requirements

### Minimum Requirements
- **OS:** Windows 10/11 (64-bit)
- **RAM:** 8 GB
- **Disk:** 20 GB free space
- **CPU:** 4 cores

### Recommended Requirements
- **OS:** Windows 11 (64-bit)
- **RAM:** 16 GB
- **Disk:** 50 GB SSD
- **CPU:** 8 cores
- **Network:** Gigabit Ethernet

### Software Dependencies
- PostgreSQL 12+
- Go 1.24.0+
- Node.js 18+
- Python 3.9+ (for SIEM setup)
- Npcap driver (for packet capture)

## Configuration Files

### Main Configuration
```
D:\SafeOpsFV2\config\
├── defaults\
│   ├── application_settings.toml    # Global settings
│   ├── home_network.toml            # Home deployment
│   └── enterprise.toml              # Enterprise deployment
└── templates\
    ├── firewall.toml                # Firewall rules
    ├── firewall_engine.toml         # Engine config
    ├── nic_management.yaml          # NIC settings
    ├── wifi_ap.toml                 # WiFi AP config
    └── ... (other component configs)
```

### Component Configs
Each component has its own config file in `bin/{component}/config/`

## Logs and Data

### Log Locations
```
D:\SafeOpsFV2\logs\
├── network_packets_master.jsonl     # Network traffic
├── firewall.log                     # Firewall events
├── ids.log                          # IDS/IPS alerts
├── devices.jsonl                    # Connected devices
├── sslkeys.log                      # TLS keys
└── engine.log                       # SafeOps Engine logs
```

### Data Storage
- **PostgreSQL:** All component databases
- **Elasticsearch:** Log indexing and search
- **File System:** Raw packet captures, threat feeds

## Common Tasks

### View Network Activity
```cmd
# Real-time packet logging
tail -f D:\SafeOpsFV2\logs\network_packets_master.jsonl
```

### Check Service Status
```powershell
# Check if services are running
Get-Process | Where-Object {$_.ProcessName -like "*safeops*"}
```

### Update Threat Intelligence
```cmd
cd D:\SafeOpsFV2\bin\threat_intel
.\threat_intel.exe
```

### View Firewall Logs
```cmd
tail -f D:\SafeOpsFV2\logs\firewall.log
```

### Access SIEM Dashboard
Open browser to: http://localhost:5601 (Kibana)

## Troubleshooting

### Service Won't Start
1. Check if port is already in use
2. Verify dependencies are installed
3. Check logs in `D:\SafeOpsFV2\logs\`
4. Ensure admin privileges for services requiring them

### Network Not Filtering
1. Verify SafeOps Engine is running
2. Check firewall rules in `config/firewall.toml`
3. Verify Npcap driver is installed
4. Check DNS Proxy is running

### Database Connection Errors
1. Verify PostgreSQL is running
2. Check connection settings in config files
3. Verify database exists
4. Check credentials

### High CPU/Memory Usage
1. Check Network Logger buffer sizes
2. Reduce threat feed update frequency
3. Limit packet capture to specific interfaces
4. Adjust worker thread counts

## Security Considerations

### Default Settings
- Firewall: **DENY** inbound by default
- Devices: **UNTRUSTED** by default
- SIEM: **No authentication** (local dev only)
- APIs: **Localhost only** by default

### Production Checklist
- [ ] Enable TLS for all services
- [ ] Set strong database passwords
- [ ] Configure firewall rules for production
- [ ] Enable SIEM authentication
- [ ] Restrict API access
- [ ] Enable audit logging
- [ ] Configure backup procedures

## Development

### Building from Source
```cmd
# Build all components
cd D:\SafeOpsFV2
go work sync
make build

# Build specific component
cd src\{component}
go build -o ..\..\bin\{component}\{component}.exe
```

### Running Tests
```cmd
# Run all tests
go test ./...

# Run specific component tests
cd src\{component}
go test -v
```

## Support and Documentation

- **Project Root:** `D:\SafeOpsFV2`
- **Documentation:** `D:\SafeOpsFV2\docs\`
- **Component Docs:** `D:\SafeOpsFV2\docs\components\`
- **Source Code:** `D:\SafeOpsFV2\src\`
- **Binaries:** `D:\SafeOpsFV2\bin\`

## Version Information

- **SafeOps Version:** 2.0.0
- **Go Version:** 1.24.0
- **PostgreSQL:** 16.x
- **Elasticsearch:** 8.11.3
- **Node.js:** 18.x

---

**Last Updated:** 2026-01-21
**Status:** Active Development
**Platform:** Windows 10/11 (64-bit)
