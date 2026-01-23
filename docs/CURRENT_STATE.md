# SafeOps Firewall V2 - Current State Documentation

**Date:** 2026-01-23
**Branch:** main

This document provides a comprehensive snapshot of the current state of the SafeOps Firewall V2 codebase. It details existing components, their implementation status, and the directory structure.

---

## 📂 Repository Structure

The project is organized into modular services located in `src/`.

| Directory | Component | Language | Status | Description |
| :--- | :--- | :--- | :--- | :--- |
| `src/safeops-engine` | **SafeOps Engine** | Go | ✅ Core | Kernel-level packet interception (NDIS), gRPC server, metadata extraction. |
| `src/firewall_engine` | **Firewall Engine** | Go | 🔄 Active | Main decision engine. Phase 1 (gRPC integration) complete. Phase 2 (Rules) in progress. |
| `src/nic_management` | **NIC Management** | Rust/Go | ✅ Stable | Network Interface Card management, failover, and metrics. |
| `src/dhcp_monitor` | **DHCP Monitor** | Go | ✅ Stable | Monitors DHCP traffic to detect and track devices on the network. |
| `src/network_logger` | **Network Logger** | Go | ✅ Stable | logs network traffic to JSONL files for SIEM ingestion. |
| `src/threat_intel` | **Threat Intelligence** | Go | ✅ Stable | Fetches and aggregates threat feeds (IP/Domain blocklists). |
| `src/captive_portal` | **Captive Portal** | Go | ✅ Stable | Web portal for guest authentication and device enrollment. |
| `src/step-ca` | **Step CA** | Go | ✅ Stable | Integration with Smallstep CA for PKI and certificate management. |
| `src/launcher` | **Launcher** | Go | ✅ Stable | Unified process orchestrator to start/stop all services. |
| `src/ui` | **Web UI** | React | ⚠️ Legacy | Previous React-based dashboard (ToBeReplaced by Native UI). |
| `src/SIEM` | **SIEM** | ELK | ✅ Config | Elastic Stack configuration for log analysis. |

---

## 🧩 Component Details

### 1. SafeOps Engine (`src/safeops-engine`)
**Role:** The "kernel" of the system. Interfaces with the Windows NDIS driver (WinpkFilter) to intercept packets.
- **Features Implemented:**
    - Packet interception and injection.
    - 5-tuple metadata extraction.
    - gRPC server for streaming packet data to other components.
    - Basic verdict enforcement (Block IP/Port).
- **Key Files:** `cmd/main.go`, `internal/driver/`, `pkg/grpc/`.

### 2. Firewall Engine (`src/firewall_engine`)
**Role:** The "brain" that makes allow/deny decisions.
- **Current Status:**
    - **gRPC Integration:** Connects to SafeOps Engine to receive packet stream.
    - **Internal Structure:** Extensive package structure created (`rules`, `enforcement`, `inspector`, `wfp`), but many are skeletons waiting for logic implementation.
    - **No Active Rules:** currently acts as a pass-through or basic logger during development.
- **Key Files:** `internal/integration/safeops_grpc_client.go`, `internal/inspector/`.

### 3. NIC Management (`src/nic_management`)
**Role:** Manages physical and virtual network adapters.
- **Features Implemented:**
    - Network adapter discovery and configuration.
    - Multi-WAN failover logic.
    - Real-time traffic metrics (bytes in/out).
    - Hybrid Rust/Go implementation for performance.
- **Key Files:** `src/main.rs` (Rust core), `api/` (Go wrappers).

### 4. DHCP Monitor (`src/dhcp_monitor`)
**Role:** Passive network scanner.
- **Features Implemented:**
    - Listens for DHCP Discover/Request packets.
    - Maintains a database of active devices (MAC, IP, Hostname).
    - Detects new/rogue devices.

### 5. Network Logger (`src/network_logger`)
**Role:** Traffic recorder.
- **Features Implemented:**
    - Consumes packet metadata stream.
    - Writes structured logs (JSONL) to disk.
    - Handles log rotation.

### 6. Threat Intelligence (`src/threat_intel`)
**Role:** External data aggregator.
- **Features Implemented:**
    - Fetches blocklists from configurable sources (URLHaus, Tor nodes, etc.).
    - Parses CSV/JSON feeds.
    - Exports consolidated blocklists for the Firewall Engine.

---

## 🛠️ Build & Runtime

- **Launcher:** The `SafeOps-Launcher.exe` (built from `src/launcher`) is the entry point. It reads a master config and spawns all enabled child services.
- **Database:** PostgreSQL is used for persistent storage (Device inventory, Threat DB).
- **Communication:** Services communicate via gRPC (high perf) and HTTP REST (management).

## ⚠️ Notes for Future Development

- **UI Transition:** The existing `src/ui` (React) is deprecated in favor of a future Native Windows UI.
- **Firewall Logic:** The `firewall_engine` is the primary active development area. It needs the "logging" and "rule engine" logic filled in.
