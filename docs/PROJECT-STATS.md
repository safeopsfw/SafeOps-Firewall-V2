# SafeOps FV2 - Project Statistics & Component Overview

Generated: 2026-01-21

## Executive Summary

SafeOps FV2 is a comprehensive network security platform with **11 major components** and **35+ supporting modules**.

## Component Inventory

### 1. SafeOps Launcher
- **Executable:** `bin/SafeOps-Launcher.exe`
- **Language:** Go 1.24.0
- **Purpose:** Unified service orchestrator
- **Manages:** 5 services (PostgreSQL, NIC Management, DHCP, Threat Intel, Frontend)
- **Documentation:** `docs/components/00-SafeOps-Launcher.md`

### 2. NIC Management API
- **Executable:** `bin/nic_management/nic_management.exe`
- **Language:** Hybrid Go + Rust
- **Purpose:** Network interface management, Multi-WAN load balancing, NAT
- **Ports:** 8081 (HTTP), 50054 (gRPC), 9154 (metrics)
- **Dependencies:** 70+ Rust crates
- **Max Connections:** 1,000,000 NAT mappings
- **Documentation:** Agent analysis available

### 3. DHCP Monitor
- **Executable:** `bin/dhcp_monitor/dhcp_monitor.exe`
- **Language:** Go 1.24.0
- **Purpose:** Real-time device detection and tracking
- **Port:** 50055 (gRPC)
- **Detection Speed:** 15-35ms
- **Database:** PostgreSQL (3 tables: devices, dhcp_leases, ip_history)
- **Documentation:** Agent analysis available

### 4. Threat Intelligence
- **Executables:**
  - `bin/threat_intel/threat_intel.exe` (pipeline)
  - `bin/threat_intel/threat_intel_api.exe` (API server)
- **Language:** Go
- **Purpose:** Threat feed aggregation and IP/Domain reputation
- **Port:** 8080 (REST API), 5050 (legacy)
- **Threat Feeds:** 100+ sources
- **Database Records:**
  - 34,000+ malicious IPs
  - 1.1M+ malicious domains
  - 1,300+ VPN/Tor/Proxy IPs
  - 10,000+ file hashes
  - 1.1M+ GeoIP records
- **Documentation:** Agent analysis available

### 5. Network Logger
- **Executable:** `bin/network_logger/network_logger.exe`
- **Language:** Go 1.21+
- **Purpose:** Packet capture, protocol parsing, flow tracking
- **Ports:** 50052 (gRPC), 9092 (metrics)
- **Capture Rate:** 50,000-150,000 packets/second
- **Log File:** `logs/network_packets_master.jsonl` (5-minute rolling window)
- **Protocols:** DNS, HTTP, TLS, TCP, UDP, ICMP
- **Documentation:** Agent analysis available

### 6. SafeOps Engine (Firewall)
- **Executable:** `bin/safeops-engine/safeops-engine.exe`
- **Language:** Go + Rust
- **Purpose:** Stateful firewall, DDoS protection, packet filtering
- **Ports:** 9002 (API), 50053 (gRPC)
- **Packet Rate:** ~6,500 packets/sec
- **State Table:** 1,048,576 buckets
- **Features:** NAT, Zone-based filtering, DDoS protection
- **Documentation:** Agent analysis available

### 7. DNS Proxy
- **Executable:** `bin/dnsproxy/windows-amd64/dnsproxy.exe`
- **Language:** Go (external binary)
- **Purpose:** DNS filtering, caching, DoH support
- **Port:** 15353 (overridden from 5353)
- **Cache:** 10,000 entries (5min-1hour TTL)
- **Upstream:** Google DoH, Cloudflare DoH
- **Documentation:** Agent analysis available

### 8. Captive Portal
- **Executable:** `bin/captive_portal/captive_portal.exe`
- **Language:** Go
- **Purpose:** User authentication, device onboarding
- **Port:** 8082
- **Features:** CA cert installation, trust management
- **Documentation:** Pending

### 9. Step-CA (PKI)
- **Executables:**
  - `bin/step-ca/bin/step-ca.exe` (CA server)
  - `bin/step-ca/bin/step.exe` (CLI tool)
- **Language:** Go
- **Purpose:** Certificate Authority, TLS cert management
- **Port:** 9000
- **Scripts:** 6 PowerShell management scripts
- **Documentation:** Pending

### 10. SIEM (ELK Stack)
- **Components:**
  - Elasticsearch 8.11.3 (port 9200)
  - Kibana 8.11.3 (port 5601)
  - Logstash 8.11.3 (port 5000)
- **Installation:** PowerShell script (`bin/siem/Install-SIEM.ps1`)
- **Size:** ~1.1 GB download
- **Purpose:** Security monitoring, log aggregation, visualization
- **Documentation:** `docs/components/01-SIEM.md`

### 11. Frontend UI
- **Location:** `src/ui/dev`
- **Language:** React + Node.js
- **Port:** 3003
- **Purpose:** Web-based management interface
- **Documentation:** Inline

## Port Allocation Summary

| Port | Component | Protocol | Purpose |
|------|-----------|----------|---------|
| 67 | DHCP Server | UDP | DHCP services |
| 3003 | Frontend UI | HTTP | Web interface |
| 5000 | Logstash | TCP | Log ingestion |
| 5353 | DNS Proxy (config) | UDP | DNS |
| 5432 | PostgreSQL | TCP | Database |
| 5601 | Kibana | HTTP | SIEM visualization |
| 8080 | Threat Intel | HTTP | REST API |
| 8081 | NIC Management | HTTP | REST API |
| 8082 | Captive Portal | HTTP | Auth portal |
| 9000 | Step-CA | HTTPS | PKI/Certificates |
| 9002 | SafeOps Engine | HTTP | Firewall API |
| 9092 | Network Logger | HTTP | Prometheus metrics |
| 9093 | Firewall Engine | HTTP | Prometheus metrics |
| 9095 | DHCP Monitor | HTTP | Prometheus metrics |
| 9154 | NIC Management | HTTP | Prometheus metrics |
| 9200 | Elasticsearch | HTTP | Search/indexing |
| 15353 | DNS Proxy (engine) | UDP | DNS filtering |
| 50052 | Network Logger | gRPC | Packet logging |
| 50053 | Firewall Engine | gRPC | Firewall control |
| 50054 | NIC Management | gRPC | Network control |
| 50055 | DHCP Monitor | gRPC | Device tracking |

## File Statistics

### Binaries
```
bin/
├── SafeOps-Launcher.exe          # Size: Unknown
├── captive_portal/
│   └── captive_portal.exe
├── dhcp_monitor/
│   └── dhcp_monitor.exe
├── dnsproxy/windows-amd64/
│   └── dnsproxy.exe               # 56 KB
├── network_logger/
│   └── network_logger.exe         # 11.6 MB
├── nic_management/
│   └── nic_management.exe
├── safeops-engine/
│   └── safeops-engine.exe         # 3.7 MB
├── siem/                          # 6 batch/PowerShell scripts
├── step-ca/bin/
│   ├── step-ca.exe
│   └── step.exe
└── threat_intel/
    ├── threat_intel.exe
    └── threat_intel_api.exe

Total Executables: 13
```

### Source Code
```
src/
├── captive_portal/               # Go
├── dhcp_monitor/                 # Go
├── dhcp_server/                  # Go
├── network_logger/               # Go
├── nic_management/               # Go + Rust (hybrid)
├── safeops_launcher/             # Go
├── safeops-engine/               # Go
├── SIEM/                         # PowerShell + scripts
├── threat_intel/                 # Go
├── ui/dev/                       # React + Node.js
└── shared/rust/                  # Shared Rust libraries

Total Components: 11 major + supporting modules
```

### Configuration Files
```
config/
├── defaults/
│   ├── application_settings.toml    # 100+ settings
│   ├── home_network.toml
│   └── enterprise.toml
└── templates/
    ├── firewall.toml                # 620+ lines, 50+ rules
    ├── firewall_engine.toml         # 400+ lines
    ├── nic_management.yaml
    ├── wifi_ap.toml
    └── ... (more component configs)

Total Config Files: 20+
```

### Documentation
```
docs/
├── README.md                        # Master index
├── PROJECT-STATS.md                 # This file
├── components/
│   ├── 00-SafeOps-Launcher.md
│   └── 01-SIEM.md
├── DEVICE_ENROLLMENT_FLOW.md
├── LOG_FORWARDER_DESIGN.md
├── safeops_architecture (3).md      # 76 KB
├── safeops_ca_certificate.md        # 42 KB
└── SafeOps v2.0 - Architecture.pdf  # 204 KB

Total Docs: 10+ files
```

### Logs
```
logs/
├── network_packets_master.jsonl     # ~132 MB (57,532 packets)
├── firewall.log                     # ~19.5 MB
├── ids.log                          # ~294 KB
├── devices.jsonl
├── sslkeys.log
├── unknown_ips.csv                  # 45 KB
└── engine.log

Total Log Size: ~150+ MB
```

### Database
```
PostgreSQL Schemas:
├── firewall_engine                  # 4 tables
├── dhcp_monitor                     # 3 tables
├── nic_management                   # 10+ tables
├── threat_intel_db                  # 5 tables
└── ... (more component databases)

Total Tables: 30+
```

## Technology Stack

### Languages
- **Go:** 8 components (Launcher, NIC Management, DHCP Monitor, DHCP Server, Network Logger, SafeOps Engine, Threat Intel, Captive Portal, Step-CA)
- **Rust:** 1 component + shared libraries (NIC Management hybrid, Firewall Engine)
- **JavaScript/React:** Frontend UI
- **Python:** SIEM setup scripts
- **PowerShell:** Windows automation scripts

### Frameworks & Libraries
- **gRPC:** Inter-component communication
- **PostgreSQL:** Data persistence
- **Elasticsearch:** Log indexing
- **Npcap:** Packet capture
- **WinpkFilter:** Windows packet filtering
- **React:** Frontend framework
- **Express:** Backend API server

### External Dependencies
- **Threat Feeds:** 100+ sources (IP blacklists, domain lists, hashes, GeoIP)
- **DNS Upstreams:** Google DoH, Cloudflare DoH
- **Certificate Authority:** Step-CA
- **SIEM Stack:** Elasticsearch, Kibana, Logstash

## Performance Metrics

### Network Logger
- **Capture Rate:** 50,000-150,000 packets/second
- **Memory:** <500 MB for 1M packets
- **Latency:** <1ms per packet
- **Log Rotation:** 5-minute rolling window

### SafeOps Engine
- **Packet Rate:** ~6,500 packets/second
- **Latency:** <10 microseconds
- **State Table:** 1,048,576 buckets
- **Max Connections:** 1,000,000+

### NIC Management
- **NAT Mappings:** 1,000,000 concurrent
- **Worker Threads:** 8 (multi-queue)
- **Batch Size:** 64 packets
- **Zero-Copy:** Enabled

### DHCP Monitor
- **Detection Speed:** 15-35ms
- **Max Devices:** Unlimited (PostgreSQL backed)
- **Cache TTL:** 10 seconds

### Threat Intelligence
- **Database Size:**
  - 34K IPs
  - 1.1M domains
  - 10K hashes
  - 1.1M GeoIP records
- **Update Frequency:** 5 minutes - 24 hours (per feed)

## Integration Points

### Service Dependencies
```
SafeOps Engine → Network Logger (packet logging)
SafeOps Engine → Threat Intel (IP/domain reputation)
SafeOps Engine → DHCP Monitor (device info)
SafeOps Engine → DNS Proxy (DNS filtering)
NIC Management → Firewall Engine (interface events)
Network Logger → SIEM (log forwarding)
All Services → PostgreSQL (data storage)
```

### gRPC Services
- Network Logger: 50052
- Firewall Engine: 50053
- NIC Management: 50054
- DHCP Monitor: 50055

### REST APIs
- NIC Management: 8081
- Threat Intel: 8080
- Captive Portal: 8082
- SafeOps Engine: 9002

## Security Features

### Firewall
- Stateful packet inspection
- Zone-based filtering
- NAT/DNAT
- DDoS protection
- Connection tracking

### Device Management
- Real-time device detection
- Trust status (UNTRUSTED/TRUSTED/BLOCKED)
- Captive portal authentication
- CA certificate installation

### Threat Intelligence
- IP reputation scoring
- Domain blocking
- VPN/Tor/Proxy detection
- GeoIP lookups
- File hash checking

### Network Security
- TLS inspection (Step-CA)
- DNS filtering
- Packet logging
- Flow analysis

## Deployment Modes

### Home Network
- Simplified configuration
- Consumer-grade features
- Optional WiFi AP

### Small Business
- Enhanced security
- Multi-WAN support
- VLAN support

### Enterprise
- 802.1X authentication
- Advanced zone management
- RADIUS integration
- Compliance logging

## System Requirements

### Minimum
- Windows 10/11 (64-bit)
- 8 GB RAM
- 20 GB disk
- 4 CPU cores

### Recommended
- Windows 11 (64-bit)
- 16 GB RAM
- 50 GB SSD
- 8 CPU cores
- Gigabit Ethernet

## Next Steps

### Documentation Completion
- [ ] Create individual component docs (02-09)
- [ ] Add troubleshooting guides
- [ ] Create deployment guides
- [ ] Add API reference docs

### Feature Development
- [ ] Complete captive portal integration
- [ ] Finish Step-CA integration
- [ ] Add WiFi AP support
- [ ] Complete SIEM dashboards

### Testing & Validation
- [ ] Performance benchmarks
- [ ] Load testing
- [ ] Security audits
- [ ] Integration testing

---

**Project Status:** Active Development
**Version:** 2.0.0
**Last Updated:** 2026-01-21
**Platform:** Windows 10/11 (64-bit)
