
<div align="center">

# 🛡️ SafeOps Firewall V2
### Next-Generation Network Security Platform

![Version](https://img.shields.io/badge/Version-2.0.0-blue?style=for-the-badge&logo=semver)
![Status](https://img.shields.io/badge/Status-Active-success?style=for-the-badge)
![License](https://img.shields.io/badge/License-Proprietary-red?style=for-the-badge)
![Platform](https://img.shields.io/badge/Platform-Windows-0078D6?style=for-the-badge&logo=windows)

![Go](https://img.shields.io/badge/Go-1.21-00ADD8?style=for-the-badge&logo=go)
![React](https://img.shields.io/badge/React-19.2-61DAFB?style=for-the-badge&logo=react)
![PostgreSQL](https://img.shields.io/badge/PostgreSQL-16-336791?style=for-the-badge&logo=postgresql)
![Rust](https://img.shields.io/badge/Rust-1.75-000000?style=for-the-badge&logo=rust)

<br/>

**Complete network visibility, threat intelligence, and access control in a single unified platform.**

[Quick Start](#-quick-start) • [Architecture](#-architecture) • [Features](#-key-features) • [Documentation](#-documentation)

</div>

---

## 📖 Overview

**SafeOps Firewall V2** is an enterprise-grade security solution designed for comprehensive network monitoring and protection. Unlike traditional firewalls, SafeOps integrates Layer 2-7 packet inspection, real-time threat intelligence, a built-in Certificate Authority, and a captive portal into a cohesive system managed by a modern React dashboard.

> **Key Capabilities**: Unified Packet Capture • Device Trust Management • Threat Feed Aggregation • Zero-Trust Access Control • Real-Time SIEM

---

## 🏗️ Architecture

SafeOps operates a microservices architecture orchestrated by a unified launcher.

```mermaid
graph TD
    %% Clients
    User([Admin User]) -->|HTTP :3001| UI[UI Dashboard]
    Guest([Guest Device]) -->|HTTP :8090| CP[Captive Portal]

    %% Frontend & Orchestration
    UI -->|REST/SSE :8081| NIC[NIC Management]
    UI -->|gRPC :50055| DHCP[DHCP Monitor]
    UI -->|HTTPS :9000| CA[Step-CA]
    UI -->|REST :5050| TI_API[Threat Intel API]

    %% Core Services
    subgraph Core Security Services
        NIC -->|Manage| Engine[SafeOps Engine]
        Engine -->|Packets| Logger[Network Logger]
        CP -->|Verify| DHCP
    end

    %% Data & Intelligence
    subgraph Data & Storage
        Logger -->|JSONL| SIEM[SIEM / ELK Stack]
        TI_API -->|Query| DB[(PostgreSQL)]
        TI_Pipe[Threat Pipeline] -->|Feed Updates| DB
    end

    %% Styles
    classDef service fill:#f9f,stroke:#333,stroke-width:2px;
    classDef db fill:#ff9,stroke:#333,stroke-width:2px;
    class UI,NIC,DHCP,CA,TI_API,Engine,Logger,CP service;
    class DB,SIEM db;
```

---

## 🚀 Quick Start

### Prerequisites
- **OS**: Windows 10/11 (64-bit) (Run as Administrator)
- **Database**: PostgreSQL Service running on port `5432`
- **Dependencies**: Npcap driver installed

### One-Click Launch
The unified launcher handles all service dependencies and startup sequences.

```powershell
# 1. Open PowerShell as Administrator
# 2. Navigate to project root
cd D:\SafeOpsFV2

# 3. Start the platform
.\SafeOps-Launcher.exe
```

> **What happens next?**
> - All 7 backend services start in the background.
> - The UI Dashboard automatically opens at `http://localhost:3001`.
> - A console window displays real-time health status.
> - **To Stop**: Simply press `Enter` or `Ctrl+C` in the launcher window for a graceful shutdown.

---

## ✨ Key Features

| Domain | Feature Set |
| :--- | :--- |
| **🛡️ Network Security** | • **Layer 7 Inspection**: Deep packet analysis for HTTP, DNS, and TLS.<br>• **IDS/IPS**: Real-time intrusion detection and prevention.<br>• **GeoIP Blocking**: Location-based traffic filtering. |
| **🔒 Access Control** | • **Captive Portal**: Guest authentication and device enrollment.<br>• **Step-CA**: Internal PKI for secure mTLS and certificate management.<br>• **DHCP Monitoring**: Real-time tracking of new devices on the network. |
| **🧠 Threat Intelligence** | • **Feed Aggregation**: Integrates 30+ sources (Feodo, URLhaus, Tor Exit Nodes).<br>• **Real-time Lookup**: Instant IP/Domain reputation checks.<br>• **Pattern Matching**: Heuristic analysis for unknown threats. |
| **📊 Visibility & Ops** | • **SIEM Integration**: Full logging to ELK Stack (Elasticsearch, Kibana).<br>• **NIC Management**: Multi-WAN load balancing and failover.<br>• **Live Dashboard**: React-based visual topology and traffic charts. |

---

## 🔧 Services & Configuration

All services run from the `bin/` directory and share a common configuration structure.

### Service Port Map

| Service Name | Port | Protocol | Description | Configuration File |
| :--- | :--- | :--- | :--- | :--- |
| **UI Dashboard** | `3001` | HTTP | Frontend Management Console | `src/ui/dev/vite.config.js` |
| **Threat Intel API** | `5050` | HTTP | REST API for Threat Data | `bin/threat_intel/config.yaml` |
| **NIC Management** | `8081` | REST/SSE | Interface & Traffic Control | `bin/nic_management/config.yaml` |
| **DHCP Monitor** | `50055` | gRPC | Device Discovery | `bin/dhcp_monitor/config.yaml` |
| **Step-CA** | `9000` | HTTPS | Certificate Authority | `bin/step-ca/config/ca.json` |
| **Captive Portal** | `8090` | HTTP | Guest Access Portal | `bin/captive_portal/config.yaml` |
| **SafeOps Engine** | N/A | RAW | Packet Inspection Kernel | `bin/safeops-engine/config.yaml` |

### Database Schema (PostgreSQL)

The system relies on two primary databases: `safeops` and `threat_intel_db`.

- **`threat_intel_db`**:
    - `ip_blacklist`: Known malicious IPs (34k+ records)
    - `domains`: Malicious domain names (1.1M+ records)
    - `ip_geolocation`: IP-to-Country mapping (1.1M+ records)
- **`safeops`**:
    - `devices`: Inventory of known MAC addresses and trust levels.
    - `audit_logs`: System-wide operator actions.

---

## 📂 Project Structure

```text
SafeOpsFV2/
├── SafeOps-Launcher.exe       # 🏁 Main Entry Point
├── bin/                       # 📦 Compiled Binaries
│   ├── captive_portal/        # Guest portal assets & config
│   ├── dhcp_monitor/          # DHCP logic
│   ├── network_logger/        # Traffic logs (JSONL output)
│   ├── nic_management/        # Rust-based high-perf networking
│   ├── safeops-engine/        # WinpkFilter engine
│   ├── step-ca/               # PKI infrastructure
│   └── threat_intel/          # Feed pipeline & API
├── src/                       # 🧑‍💻 Source Code
│   ├── ui/dev/                # React 19 Frontend
│   ├── launcher/              # Go Launcher Source
│   └── ... (Service Sources)
├── data/                      # 💾 Runtime Data
└── logs/                      # 📝 Application Logs
```

---

## 📚 Documentation

Detailed technical documentation is available for each subsystem:

- **[NIC Management Deep Dive](file:///D:/plan/NIC_MANAGEMENT_DEEP_DIVE.md)** - Load balancing, failover, and interface control.
- **[Captive Portal Architecture](file:///D:/plan/CAPTIVE_PORTAL_DEEP_DIVE.md)** - Guest flows and certificate distribution.
- **[Threat Intelligence System](file:///D:/plan/THREAT_INTEL_DEEP_DIVE.md)** - Feed sources, parsing, and database design.
- **[Network Logger Internals](file:///D:/plan/NETWORK_LOGGER_DEEP_DIVE.md)** - Packet pipelines and log rotation strategies.
- **[SIEM / ELK Setup](file:///D:/plan/SIEM_DEEP_DIVE.md)** - Log ingestion and dashboarding with Elastic Stack.
- **[UI Dashboard Guide](file:///D:/plan/UI_DASHBOARD_DEEP_DIVE.md)** - React components and visual topology.

---

## 🛠️ Development

### Building from Source

To rebuild the Unified Launcher or any service:

```powershell
# Build Launcher
cd src/launcher
go build -o ../../SafeOps-Launcher.exe

# Build UI
cd src/ui/dev
npm install
npm run build
```

### Adding Threat Feeds

Edit `bin/threat_intel/config/sources.yaml`:

```yaml
sources:
  - name: "My Custom Feed"
    url: "https://example.com/feed.csv"
    format: "csv" # or "json", "txt"
    interval: "24h"
```

Then run the updater:
```powershell
.\bin\threat_intel\threat_intel.exe -fetch -process
```

---

## 📄 License

**Proprietary & Confidential**  
Copyright (c) 2026 SafeOps Project. All Rights Reserved.  
Unauthorized copying or distribution of this software is strictly prohibited.

---
<div align="center">

**SafeOps Engineering Team** • Built with ❤️ for Secure Networks

</div>
