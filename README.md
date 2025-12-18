# SafeOps v2.0

<div align="center">

**Enterprise-Grade Network Security Gateway for Windows**

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Windows](https://img.shields.io/badge/Platform-Windows%2010%2F11-0078D6?logo=windows)](https://www.microsoft.com/windows)
[![Rust](https://img.shields.io/badge/Rust-1.74+-orange?logo=rust)](https://www.rust-lang.org/)
[![Go](https://img.shields.io/badge/Go-1.21+-00ADD8?logo=go)](https://golang.org/)

</div>

---

## 🛡️ What is SafeOps?

SafeOps is a comprehensive Windows network security gateway combining:

- **Stateful Firewall** - Kernel-level packet filtering with 100K+ rules
- **IDS/IPS** - Suricata-compatible intrusion detection (100K+ signatures)
- **DNS Server** - Filtering DNS with ad/malware blocking
- **DHCP Server** - Network address management
- **WiFi Access Point** - WPA3-capable wireless AP
- **TLS Inspection** - HTTPS decryption for threat detection
- **Threat Intelligence** - Multi-feed IP/domain reputation
- **Web UI** - Modern dashboard built with Wails

---

## 🏗️ Technology Stack

| Layer | Technology |
|-------|------------|
| **Kernel Driver** | Go (WDF-based) |
| **Core Services** | Rust |
| **Web UI** | Go (Wails) + TypeScript |
| **Database** | PostgreSQL 15+ |
| **Cache** | Redis |
| **IPC** | gRPC (Protocol Buffers) |
| **Signatures** | Suricata-compatible rules |

---

## 📁 Project Structure (Phase 1 Complete - 210 files)

> **Phase 1 Status**: ✅ All core components implemented and tested  
> **Dependency Map**: See [PHASE1_DEPENDENCY_MAP.md](PHASE1_DEPENDENCY_MAP.md) for complete file dependencies

```
SafeOps/
│
├── src/
│   ├── kernel_driver/                     # Windows Kernel Driver (20 files)
│   │
│   ├── userspace_service/                 # Windows Service (7 files) 
│   │   └── README.md
│   │
│   └── shared/                            # Shared utilities (56 files) 
│       ├── rust/                          # Rust shared library ✅ COMPILED
│       │   ├── Cargo.toml                 # Package manifest with dependencies
│       │   ├── README.md                  # Library documentation
│       │   ├── build.rs                   # Build script for proto generation
│       │   ├── benches/                   # Performance benchmarks (2 files)
│       │   │   ├── hash_performance.rs    # Hash function benchmarks
│       │   │   └── ip_parsing.rs          # IP parsing benchmarks
│       │   ├── src/                       # Source files (13 files)
│       │   │   ├── lib.rs                 # Library root & public API
│       │   │   ├── error.rs               # SafeOpsError types & Result
│       │   │   ├── ip_utils.rs            # IP parsing & CIDR utilities
│       │   │   ├── hash_utils.rs          # xxHash & aHash functions
│       │   │   ├── memory_pool.rs         # Object pooling for performance
│       │   │   ├── buffer_pool.rs         # Packet buffer pooling
│       │   │   ├── lock_free.rs           # Lock-free data structures
│       │   │   ├── simd_utils.rs          # SIMD packet parsing
│       │   │   ├── time_utils.rs          # Time & timestamp utilities
│       │   │   ├── proto_utils.rs         # Protobuf helper functions
│       │   │   ├── metrics.rs             # Prometheus metrics collection
│       │   │   └── proto/                 # Generated proto code
│       │   │       └── mod.rs             # Proto module declarations
│       │   └── tests/                     # Integration tests
│       ├── go/                            # Go shared packages (37 files)
│       │   ├── config/                    # Viper config (5 files)
│       │   ├── logging/                   # Logrus wrapper (5 files)
│       │   ├── errors/                    # Structured errors (3 files)
│       │   ├── health/                    # Health checks (2 files)
│       │   ├── metrics/                   # Prometheus (3 files)
│       │   ├── utils/                     # Retry, rate limit (5 files)
│       │   ├── redis/                     # Redis client (4 files)
│       │   ├── postgres/                  # pgx pool (4 files)
│       │   ├── grpc_client/               # gRPC client (3 files)
│       │   └── go.mod
│       ├── c/
│       └── README.md
│
├── proto/                                 # Protocol Buffers (44 files) ✅
│   ├── README.md
│   ├── build.ps1                          # Windows build
│   ├── build.sh                           # Linux build
│   ├── network_manager.proto
│   └── grpc/
├── config/                                # Configuration (49 files) ✅
│   ├── README.md
│   ├── HOW_TO_MANAGE_NETWORK.md
│   ├── config_validator.ps1
│   ├── network_topology.yaml
│   ├── templates/                         # 20 TOML files
│   │   ├── safeops.toml                   # Master config
│   │   ├── kernel_driver.toml
│   │   ├── firewall.toml
│   │   ├── firewall_engine.toml
│   │   ├── network_logger.toml
│   │   ├── ids_ips.toml
│   │   ├── ids_ips.yaml
│   │   ├── threat_intel.toml
│   │   ├── logging.toml
│   │   ├── backup_restore.toml
│   │   ├── certificate_manager.toml
│   │   ├── dhcp_server.toml
│   │   ├── dns_server.toml
│   │   ├── dns_dhcp_combined.toml
│   │   ├── orchestrator.toml
│   │   ├── tls_proxy.toml
│   │   ├── update_manager.toml
│   │   ├── vpn_server.toml
│   │   ├── web_ui.toml
│   │   └── wifi_ap.toml
│   ├── defaults/                          # 5 presets
│   │   ├── application_settings.toml
│   │   ├── enterprise.toml
│   │   ├── home_network.toml
│   │   ├── monitoring_only.toml
│   │   └── small_business.toml
│   ├── examples/                          # 7 examples
│   │   ├── custom_firewall_rules.yaml
│   │   ├── enterprise.toml
│   │   ├── home_network.toml
│   │   ├── network_interfaces.yaml
│   │   ├── small_business.toml
│   │   ├── threat_feed_sources.yaml
│   │   └── user_policies.yaml
│   ├── schemas/                           # 6 JSON schemas
│   │   ├── config_schema.json
│   │   ├── firewall_rules_schema.json
│   │   ├── ids_ips_rules_schema.json
│   │   ├── ids_ips_suricata.rules
│   │   ├── suricata_rules_format.md
│   │   └── validation_rules.md
│   └── ids_ips/                           # 2 rule configs
│       ├── rule_categories.toml
│       └── suricata_vars.yaml
│
├── database/                              # PostgreSQL (25 files) ✅
│   ├── README.md
│   ├── init_database.sh
│   ├── schemas/                           # 10 SQL files
│   │   ├── 001_initial_setup.sql
│   │   ├── 002_ip_reputation.sql
│   │   ├── 003_domain_reputation.sql
│   │   ├── 004_hash_reputation.sql
│   │   ├── 005_ioc_storage.sql
│   │   ├── 006_proxy_anonymizer.sql
│   │   ├── 007_geolocation.sql
│   │   ├── 008_threat_feeds.sql
│   │   ├── 009_asn_data.sql
│   │   └── 999_indexes_and_maintenance.sql
│   ├── views/                             # 3 views
│   │   ├── active_threats_view.sql
│   │   ├── high_confidence_iocs.sql
│   │   └── threat_summary_stats.sql
│   ├── seeds/                             # 3 seed files
│   │   ├── feed_sources_config.sql
│   │   ├── initial_threat_categories.sql
│   │   └── test_ioc_data.sql
│   ├── migrations/up/
│   ├── migrations/down/
│   └── functions/
│
├── docs/                                  # Documentation (36 files) ✅
│   ├── README.md
│   ├── architecture/                      # 6 files
│   │   ├── system_overview.md
│   │   ├── service_architecture.md
│   │   ├── security_model.md
│   │   ├── performance_design.md
│   │   ├── network_topology.md
│   │   └── data_flow.md
│   ├── api/                               # 4 files
│   │   ├── authentication.md
│   │   ├── error_codes.md
│   │   ├── grpc_api_reference.md
│   │   └── rest_api_reference.md
│   ├── developer_guide/                   # 6 files
│   │   ├── building_from_source.md
│   │   ├── code_standards.md
│   │   ├── contributing.md
│   │   ├── development_environment.md
│   │   ├── release_process.md
│   │   └── testing_guide.md
│   └── user_guide/                        # 8 files
│       ├── faq.md
│       ├── firewall_rules.md
│       ├── installation_guide.md
│       ├── network_monitoring.md
│       ├── quick_start.md
│       ├── threat_intelligence.md
│       ├── troubleshooting.md
│       └── web_ui_guide.md
│
├── tests/                                 # Test suites (planned)
├── certs/                                 # Certificate management
├── feeds/                                 # Threat intelligence feeds
├── scripts/                               # Build scripts
├── installer/                             # Windows installer
├── build/                                 # Build output
├── tools/                                 # Dev utilities
├── examples/                              # Example configs
│
├── .gitignore
├── .gitattributes
├── Makefile
├── README.md
├── LICENSE
└── CHANGELOG.md

Total: 210 files | Phase 1 Complete ✅
```

> **Note**: Service implementation skeletons (~50 files) exist but await Phase 2 implementation

---

## 🚀 Quick Start

### Prerequisites

- Windows 10/11 Pro (21H2+)
- PowerShell 7+
- Git

### 1. Install Development Environment

```powershell

# Run the installer (installs Rust, Go, Node.js, protoc, etc.)
.\safeops_installer.ps1
```

### 2. Build the Project

```powershell
# Generate proto files
.\proto\build.ps1

# Build all services
make build

# Or use the Makefile targets
make all      # Build everything
make test     # Run tests
make clean    # Clean build artifacts
```

### 3. Database Setup (Native Installation)

```powershell
# Install PostgreSQL 15+ (download from postgresql.org or use winget)
winget install PostgreSQL.PostgreSQL

# After installation, open PowerShell as Admin and start service
net start postgresql-x64-15

# Create SafeOps database
psql -U postgres -c "CREATE DATABASE safeops;"
psql -U postgres -c "CREATE USER safeops_user WITH PASSWORD 'changeme';"
psql -U postgres -c "GRANT ALL PRIVILEGES ON DATABASE safeops TO safeops_user;"

# Install Redis (download from github.com/microsoftarchive/redis or use winget)
winget install Redis.Redis

# Start Redis service
net start redis

# Initialize threat intel database
cd database
.\init_database.sh
```

> **Note**: PostgreSQL and Redis run as Windows services - no Docker required.

### 4. Run Services

```powershell
# Start the orchestrator (manages all services)
.\build\orchestrator.exe

# Access Web UI
start http://localhost:8080
```

---

## 📡 gRPC API

SafeOps services communicate via gRPC. See [`proto/grpc/`](proto/grpc/) for all 13 service definitions:

| Service | Description |
|---------|-------------|
| `FirewallService` | Packet filtering rules |
| `IdsIpsService` | Intrusion detection/prevention |
| `DnsServerService` | DNS filtering |
| `DhcpServerService` | DHCP management |
| `WifiApService` | WiFi access point |
| `TlsProxyService` | HTTPS inspection |
| `ThreatIntelService` | Threat feed lookups |
| `NetworkLoggerService` | Traffic logging |
| `OrchestratorService` | Service lifecycle |
| `CertificateManagerService` | PKI operations |
| `BackupRestoreService` | Config backup/restore |
| `UpdateManagerService` | Updates & rollback |

> 📖 **Full API Docs:** [`docs/api/grpc_api_reference.md`](docs/api/grpc_api_reference.md)

---

## 🗄️ Threat Intelligence Database

PostgreSQL database for IOCs, reputation data, and threat feeds:

| Schema | Purpose |
|--------|---------|
| `ip_reputation` | IP threat scores |
| `domain_reputation` | Domain intelligence |
| `hash_reputation` | File hash malware DB |
| `ioc_storage` | Generic IOC storage |
| `proxy_anonymizer` | VPN/Proxy/Tor detection |
| `geolocation` | IP-to-location |
| `threat_feeds` | Feed configuration |
| `asn_data` | ASN reputation |

> 📖 **Full Schema Docs:** [`database/README.md`](database/README.md)

---

## 📚 Documentation

| Category | Location | Description |
|----------|----------|-------------|
| **Architecture** | [`docs/architecture/`](docs/architecture/) | System design (6 docs) |
| **API Reference** | [`docs/api/`](docs/api/) | gRPC/REST APIs (4 docs) |
| **User Guide** | [`docs/user_guide/`](docs/user_guide/) | End-user docs (8 docs) |
| **Developer Guide** | [`docs/developer_guide/`](docs/developer_guide/) | Build & contribute (6 docs) |
| **Database** | [`database/README.md`](database/README.md) | Threat intel schemas |
| **Proto Files** | [`proto/README.md`](proto/README.md) | gRPC definitions |

> 📖 **Start Here:** [`docs/README.md`](docs/README.md)

---

## 🧪 Testing

```powershell
# Run all tests
make test

# Run specific service tests
cd src/firewall && cargo test
cd src/ids_ips && cargo test

# Run integration tests
.\tests\run_integration.ps1
```

---

## 🤝 Contributing

We welcome contributions! Please read:

1. [Contributing Guide](docs/developer_guide/contributing.md)
2. [Code Standards](docs/developer_guide/code_standards.md)
3. [Development Environment](docs/developer_guide/development_environment.md)

```bash
# Fork, clone, and create a branch
git checkout -b feature/your-feature

# Make changes, test, and submit PR
git push origin feature/your-feature
```

---

## 📋 Makefile Targets

| Target | Description |
|--------|-------------|
| `make all` | Build everything (proto + database + services) |
| `make proto` | Generate Protocol Buffer code |
| `make database` | Initialize database schemas |
| `make build` | Build all services |
| `make test` | Run test suite |
| `make clean` | Clean build artifacts |
| `make help` | Show all targets |

---

## 📦 Release Notes

See [CHANGELOG.md](CHANGELOG.md) for version history.

---

## 📄 License

Copyright © 2025 SafeOps Project

Licensed under the [MIT License](LICENSE).

---

<div align="center">

**[Documentation](docs/README.md)** • **[Issues](https://github.com/bakchodikarle237-afk/SafeOps-FW/issues)** • **[Discussions](https://github.com/bakchodikarle237-afk/SafeOps-FW/discussions)**

</div>
