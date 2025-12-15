# SafeOps v2.0 Configuration Directory

> **Configuration Version:** 2.0.0  
> **Last Updated:** December 13, 2024  
> **Total Files:** 35+ configuration files  
> **Total Lines:** ~15,000+ lines of configuration and documentation

This directory contains all configuration files, templates, schemas, network topology, and documentation for SafeOps v2.0 Network Security Gateway.

---

## Quick Overview

```
config/
├── templates/           # 20 service configuration templates (TOML/YAML)
├── defaults/            # 5 deployment profiles
├── examples/            # 7 example configurations
├── schemas/             # 6 JSON/YAML validation schemas
├── ids_ips/             # 2 IDS/IPS specific configurations
├── network_topology.yaml
├── config_validator.ps1
├── HOW_TO_MANAGE_NETWORK.md
└── README.md (this file)
```

---

## 📁 Service Templates (`templates/`)

### Core Configuration Files

| File | Service | gRPC Port | Purpose |
|------|---------|-----------|---------|
| `safeops.toml` | Main Config | N/A | Master system configuration |
| `kernel_driver.toml` | Kernel Driver | N/A | WFP/NDIS packet capture, ring buffer |
| `network_logger.toml` | Network Logger | 50051 | Ring buffer reader, PostgreSQL bulk inserts |
| `firewall.toml` | Firewall Rules | N/A | Rule definitions and policies |
| `firewall_engine.toml` | Firewall Engine | 50052 | Rule engine, NAT, connection tracking |
| `tls_proxy.toml` | TLS Proxy | 50053 | TLS interception, dynamic certs |
| `ids_ips.toml` | IDS/IPS Engine | 50054 | Signature/anomaly detection |
| `ids_ips.yaml` | IDS/IPS Rules | N/A | Suricata rule configurations |
| `threat_intel.toml` | Threat Intel | 50055 | Feed aggregation, reputation scoring |
| `dns_server.toml` | DNS Server | 50056 | Forwarding, caching, filtering, DNSSEC |
| `dns_dhcp_combined.toml` | DNS+DHCP | N/A | Integrated DNS/DHCP configuration |
| `dhcp_server.toml` | DHCP Server | 50057 | Dual pools, static reservations |
| `wifi_ap.toml` | WiFi AP | 50058 | WiFi 6, WPA3, client isolation |
| `vpn_server.toml` | VPN Server | N/A | WireGuard/OpenVPN/IPsec |
| `certificate_manager.toml` | Cert Manager | 50059 | Root CA, dynamic certs, CRL/OCSP |
| `backup_restore.toml` | Backup & Restore | 50060 | GFS retention, VSS, multi-tier storage |
| `update_manager.toml` | Update Manager | 50061 | Multi-channel updates, delta updates |
| `orchestrator.toml` | Orchestrator | 50062 | Master coordinator, service management |
| `web_ui.toml` | Web UI | 50063 | RBAC, real-time dashboard, MFA |
| `logging.toml` | Logging | N/A | Centralized logging configuration |

---

## 📋 Default Profiles (`defaults/`)

| File | Profile | Use Case | Key Features |
|------|---------|----------|--------------|
| `application_settings.toml` | **Default** | Standard deployment | Main default values |
| `home_network.toml` | Home | 1-10 devices | IDS only, DNS ad-blocking |
| `small_business.toml` | Business | 10-50 devices | VLANs, IPS, TLS inspection |
| `enterprise.toml` | Enterprise | 100+ devices | HA, compliance, SIEM |
| `monitoring_only.toml` | Monitoring | Any size | Passive detection only |

---

## 🎯 Example Configurations (`examples/`)

| File | Purpose |
|------|---------|
| `home_network.toml` | Complete home network setup |
| `small_business.toml` | Small business with VLANs and IPS |
| `enterprise.toml` | Enterprise with compliance and SIEM |
| `custom_firewall_rules.yaml` | Firewall rule examples |
| `threat_feed_sources.yaml` | Threat feed configurations |
| `network_interfaces.yaml` | Interface configurations |
| `user_policies.yaml` | User access policies |

---

## 📐 Validation Schemas (`schemas/`)

| File | Purpose |
|------|---------|
| `config_schema.json` | JSON Schema for main config validation |
| `firewall_rules_schema.json` | Firewall rules validation |
| `ids_ips_rules_schema.json` | IDS/IPS rules validation |
| `ids_ips_suricata.rules` | Native Suricata format rules |
| `suricata_rules_format.md` | Suricata syntax documentation |
| `validation_rules.md` | Human-readable validation rules |

---

## 🔍 IDS/IPS Configuration (`ids_ips/`)

| File | Purpose |
|------|---------|
| `suricata_vars.yaml` | Auto-generated Suricata variables |
| `rule_categories.toml` | Rule categories (malware, exploits, etc.) |

---

## Service Dependency Graph

```
orchestrator.toml (Master Coordinator - Port 50062)
    │
    ├── kernel_driver.toml (Start Order: 1, Critical)
    │       └── WFP/NDIS driver, ring buffer
    │
    ├── network_logger.toml (Start Order: 2, Critical)
    │       └── Depends on: kernel_driver
    │
    ├── firewall_engine.toml (Start Order: 3, Critical)
    │       └── Depends on: kernel_driver, network_logger
    │
    ├── certificate_manager.toml (Start Order: 4)
    │       └── No dependencies (needed by TLS proxy)
    │
    ├── threat_intel.toml (Start Order: 5)
    │       └── No dependencies (needed by IDS/IPS, DNS)
    │
    ├── tls_proxy.toml (Start Order: 5)
    │       └── Depends on: kernel_driver, network_logger, certificate_manager
    │
    ├── ids_ips.toml (Start Order: 6, Critical)
    │       └── Depends on: kernel_driver, network_logger, threat_intel
    │
    ├── dns_server.toml (Start Order: 7, Critical)
    │       └── Depends on: threat_intel
    │
    ├── dhcp_server.toml (Start Order: 8)
    │       └── Depends on: dns_server
    │
    ├── wifi_ap.toml (Start Order: 9)
    │       └── Depends on: dhcp_server, dns_server
    │
    ├── backup_restore.toml (Start Order: 10)
    │       └── Low priority
    │
    ├── update_manager.toml (Start Order: 10)
    │       └── Low priority
    │
    └── web_ui.toml (Start Order: 11, Last)
            └── Depends on: firewall_engine, network_logger
```

---

## gRPC Port Assignments

| Port | Service | Description |
|------|---------|-------------|
| 50051 | network_logger | Packet logging and queries |
| 50052 | firewall_engine | Rule management and stats |
| 50053 | tls_proxy | Certificate management |
| 50054 | ids_ips | Alert management |
| 50055 | threat_intel | Reputation lookups |
| 50056 | dns_server | DNS queries and config |
| 50057 | dhcp_server | Lease management |
| 50058 | wifi_ap | AP control |
| 50059 | certificate_manager | PKI operations |
| 50060 | backup_restore | Backup scheduling |
| 50061 | update_manager | Update control |
| 50062 | orchestrator | Service management |
| 50063 | web_ui | UI backend |

---

## Getting Started

### Quick Start (Windows)

```powershell
# 1. Copy main config
Copy-Item "config\templates\safeops.toml" "C:\ProgramData\SafeOps\config\safeops.toml"

# 2. Copy service templates
Copy-Item "config\templates\*.toml" "C:\ProgramData\SafeOps\config\"

# 3. Edit network settings
notepad "C:\ProgramData\SafeOps\config\safeops.toml"

# 4. Validate configuration
.\config\config_validator.ps1

# 5. Start services
safeops.exe start
```

### Environment Variables

Set sensitive values via environment variables:

```powershell
$env:POSTGRES_PASSWORD = "your_db_password"
$env:REDIS_PASSWORD = "your_redis_password"
$env:WIFI_PASSWORD = "your_wifi_password"
$env:WEB_UI_TLS_CERT = "C:\Program Files\SafeOps\certs\web.crt"
$env:WEB_UI_TLS_KEY = "C:\Program Files\SafeOps\certs\web.key"
```

---

## Directory Paths (Windows)

| Path | Purpose |
|------|---------|
| `C:\Program Files\SafeOps\` | Application binaries |
| `C:\Program Files\SafeOps\bin\` | Service executables |
| `C:\Program Files\SafeOps\certs\` | Certificates and keys |
| `C:\Program Files\SafeOps\rules\` | IDS/IPS rules |
| `C:\ProgramData\SafeOps\` | Runtime data |
| `C:\ProgramData\SafeOps\config\` | Active configuration |
| `C:\ProgramData\SafeOps\logs\` | Log files |
| `C:\SafeOps_Backups\` | Backup storage |

---

## Configuration Hierarchy

```
1. Default values (built into SafeOps binaries)
2. defaults/application_settings.toml (base profile)
3. templates/*.toml (service-specific settings)
4. Environment variables (SAFEOPS_*)
5. Command-line arguments
```

Later sources override earlier ones.

---

## Version History

### v2.0.0 (December 13, 2024)

**Complete configuration suite for SafeOps v2.0**

#### Templates Created (20 files)
- ✅ `safeops.toml` - Main system configuration
- ✅ `kernel_driver.toml` - Windows kernel driver
- ✅ `network_logger.toml` - Packet capture
- ✅ `firewall.toml` + `firewall_engine.toml` - Firewall
- ✅ `tls_proxy.toml` - TLS interception
- ✅ `ids_ips.toml` + `ids_ips.yaml` - IDS/IPS
- ✅ `threat_intel.toml` - Threat intelligence
- ✅ `dns_server.toml` + `dns_dhcp_combined.toml` - DNS
- ✅ `dhcp_server.toml` - DHCP
- ✅ `wifi_ap.toml` - WiFi AP
- ✅ `vpn_server.toml` - VPN
- ✅ `certificate_manager.toml` - PKI
- ✅ `backup_restore.toml` - Backup
- ✅ `update_manager.toml` - Updates
- ✅ `orchestrator.toml` - Orchestrator
- ✅ `web_ui.toml` - Web UI
- ✅ `logging.toml` - Logging

#### Default Profiles (5 files)
- ✅ `application_settings.toml`, `home_network.toml`, `small_business.toml`, `enterprise.toml`, `monitoring_only.toml`

#### Example Configurations (7 files)
- ✅ Updated with Windows paths and v2.0 structure

---

## License

SafeOps is licensed under [Apache 2.0](../LICENSE).

---

*Configuration Version 2.0.0 - Last Updated December 13, 2024*
