
<div align="center">

# SafeOps Firewall V2
### Next-Generation Network Security Platform

![Version](https://img.shields.io/badge/Version-1.0.0-blue?style=for-the-badge&logo=semver)
![Status](https://img.shields.io/badge/Status-Active-success?style=for-the-badge)
![License](https://img.shields.io/badge/License-Proprietary-red?style=for-the-badge)
![Platform](https://img.shields.io/badge/Platform-Windows-0078D6?style=for-the-badge&logo=windows)

![Go](https://img.shields.io/badge/Go-1.25-00ADD8?style=for-the-badge&logo=go)
![React](https://img.shields.io/badge/React-19.2-61DAFB?style=for-the-badge&logo=react)
![PostgreSQL](https://img.shields.io/badge/PostgreSQL-16-336791?style=for-the-badge&logo=postgresql)

<br/>

**Complete network visibility, threat intelligence, and access control in a single unified platform.**

[Download](#download) | [Features](#key-features) | [Architecture](#architecture) | [Quick Start](#quick-start) | [Authors](#authors)

</div>

---

## Download

> **[Download SafeOps-Complete-Setup.exe (v1.0.0)](https://github.com/safeopsfw/SafeOps-Firewall-V2/releases/latest)**
>
> One installer. Downloads all dependencies. Sets up everything. Auto-launches on login.

### What the installer does
1. Downloads & installs PostgreSQL 16, Node.js 20, WinPkFilter, Elasticsearch 8.11, Kibana 8.11
2. Creates databases and applies all schemas
3. Installs all SafeOps binaries, engines, and services
4. Creates desktop shortcut, start menu entry, and auto-launch scheduled task
5. SafeOps runs in the system tray — always watching your network

**Requirements:** Windows 10/11 64-bit, Administrator, Internet connection (~2GB downloads), ~4GB disk space

---

## Key Features

| Domain | Feature Set |
| :--- | :--- |
| **Network Security** | Layer 7 deep packet inspection (HTTP, DNS, TLS/SNI) - IDS/IPS with real-time detection - GeoIP/ASN-based traffic filtering - DDoS, brute force, and port scan detection |
| **Access Control** | Captive Portal for guest authentication - Step-CA internal PKI (mTLS, certificates) - DHCP monitoring for device discovery |
| **Threat Intelligence** | 100+ threat feed aggregation (Feodo, URLhaus, Tor exits, etc.) - Real-time IP/Domain reputation checks - Automatic domain blocking after repeated malicious visits |
| **Firewall Engine** | 8-stage detection pipeline - Custom rule engine (TOML-based) - Rate limiting, IP/domain blocklists - SOC verdict logging (JSONL) with gzip rotation |
| **Visibility & Ops** | SIEM integration (ELK Stack) - React dashboard with 11 firewall tabs - NIC management with multi-WAN support - System tray with background operation |

---

## Architecture

SafeOps runs as a set of coordinated services managed by a desktop launcher with system tray support.

```
SafeOps.exe (Desktop Launcher)
    |
    |-- safeops-engine      NDIS packet capture via WinPkFilter (gRPC :50051, HTTP :50052)
    |-- firewall-engine     Decision engine with 8-stage pipeline (REST :8443, gRPC :50054)
    |-- Web UI              React dashboard (:3001) + Node.js backend (:5050)
    |-- nic-management      Multi-WAN & NAT management (:8081)
    |-- dhcp-monitor        Device discovery via ARP/DHCP (gRPC :50055)
    |-- captive-portal      Guest authentication portal (:8090)
    |-- step-ca             Internal Certificate Authority (HTTPS :9000)
    |-- network-logger      Packet capture to JSONL logs
    |-- siem-forwarder      Log forwarding to Elasticsearch
    |-- threat-intel        Feed fetcher & processor (:5050)
```

### Detection Pipeline (Firewall Engine)

Packets flow through these stages in order:
1. **Security Monitoring** — DDoS, rate limit, brute force, port scan (always runs)
2. **Whitelist Check** — Trusted IPs bypass remaining checks
3. **Manual IP Blocklist** — Admin-configured blocked IPs
4. **GeoIP Check** — Country and ASN filtering
5. **Threat Intel IP** — Known malicious IP lookup
6. **Domain Filter** — Config list, categories, threat intel, auto-block tracking
7. **Custom Rules** — User-defined rules from `rules.toml`
8. **Packet Inspector** — Stateful protocol analysis

---

## Quick Start

### Option 1: Use the Installer (Recommended)
Download `SafeOps-Complete-Setup.exe` from [Releases](https://github.com/safeopsfw/SafeOps-Firewall-V2/releases/latest), run as Administrator, and follow the wizard. Everything is handled automatically.

### Option 2: Run from Source
```powershell
# Prerequisites: Go 1.25+, Node.js 20+, PostgreSQL 16, WinPkFilter driver

# Build desktop launcher
cd safeops-app
wails build

# Or run directly
cd bin
.\SafeOps.exe
```

### Service Port Map

| Service | Port | Protocol | Description |
| :--- | :--- | :--- | :--- |
| UI Dashboard | `3001` | HTTP | React management console |
| Backend API | `5050` | HTTP | Node.js REST API |
| SafeOps Engine | `50051` | gRPC | Packet metadata stream |
| SafeOps Engine | `50052` | HTTP | Control API (domain sync) |
| Firewall Engine | `8443` | HTTPS | REST API |
| Firewall Engine | `50054` | gRPC | Management interface |
| NIC Management | `8081` | REST/SSE | Interface control |
| DHCP Monitor | `50055` | gRPC | Device discovery |
| Step-CA | `9000` | HTTPS | Certificate Authority |
| Captive Portal | `8090` | HTTP | Guest portal |

---

## System Requirements

| Resource | Minimum |
|----------|---------|
| **OS** | Windows 10/11 (64-bit) |
| **CPU** | 4 cores (2.4 GHz+) |
| **RAM** | 4 GB |
| **Disk** | 4 GB free space |
| **Network** | WinPkFilter driver |
| **Privileges** | Administrator |

---

## Authors

- **Arjun Mishra**
- **Hari Krishan**
- **Raghav SOM**

## License

**Proprietary & Confidential**
Copyright (c) 2026 SafeOps Project. All Rights Reserved.
Unauthorized copying or distribution of this software is strictly prohibited.

---
<div align="center">

**Made by Arjun Mishra, Hari Krishan & Raghav SOM** | Built for Secure Networks

</div>
