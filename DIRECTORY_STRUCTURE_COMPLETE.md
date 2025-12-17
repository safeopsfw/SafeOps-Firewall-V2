# SafeOps v2.0 - Complete Directory Structure

> **Complete file and folder structure for the SafeOps Firewall project**
>
> Generated: 2025-12-17 | Total Files: 800+

---

## 📂 Root Directory

```
SafeOpsFV2/
├── DATA_STRUCTURES.md                      # Complete data structure reference
├── DIRECTORY_STRUCTURE.md                  # This file
├── README.md                               # Project overview
├── README_DATASTRUCTURES.md                # Data structure index
├── LICENSE                                 # MIT License
├── Makefile                                # Build automation
├── .gitignore                              # Git ignore rules
├── .gitattributes                          # Git attributes
├── safeops_installer.ps1                   # Development environment installer
├── git_interactive.ps1                     # Git workflow helper
├── rebuild_structure.ps1                   # Project structure regeneration
└── setup_github.ps1                        # GitHub repository setup
```

---

## 📁 Complete Directory Tree

### `.agent/` - Workflow Automation
```
.agent/
└── workflows/
    └── safeops-project-context.md          # Project context workflow
```

### `build/` - Build Outputs
```
build/
├── bin/                                    # Compiled binaries
├── lib/                                    # Compiled libraries
├── installer/                              # Built installers
└── proto/                                  # Generated protocol buffer code
    ├── go/                                 # Go generated code (28 files)
    │   ├── backup_restore.pb.go
    │   ├── certificate_manager.pb.go
    │   ├── common.pb.go
    │   ├── dhcp_server.pb.go
    │   ├── dns_server.pb.go
    │   ├── firewall.pb.go
    │   ├── ids_ips.pb.go
    │   ├── network_logger.pb.go
    │   ├── network_manager.pb.go
    │   ├── orchestrator.pb.go
    │   ├── threat_intel.pb.go
    │   ├── tls_proxy.pb.go
    │   ├── update_manager.pb.go
    │   ├── wifi_ap.pb.go
    │   └── *_grpc.pb.go (gRPC implementations)
    └── rust/                               # Rust generated code
        └── build.rs.template
```

### `certs/` - Certificate Management
```
certs/
├── ca/                                     # Certificate Authority files
└── distribution/                           # Distributed certificates
```

### `config/` - Configuration Files (44 files)
```
config/
├── README.md                               # Configuration guide
├── README_STRUCTURES.md                    # Configuration data structures
├── config_validator.ps1                    # Validation script
├── HOW_TO_MANAGE_NETWORK.md               # Network management guide
├── network_topology.yaml                   # Network topology definition
│
├── defaults/                               # Preset configurations (5 files)
│   ├── application_settings.toml
│   ├── enterprise.toml
│   ├── home_network.toml
│   ├── monitoring_only.toml
│   └── small_business.toml
│
├── examples/                               # Example configurations (7 files)
│   ├── custom_firewall_rules.yaml
│   ├── enterprise.toml
│   ├── home_network.toml
│   ├── network_interfaces.yaml
│   ├── small_business.toml
│   ├── threat_feed_sources.yaml
│   └── user_policies.yaml
│
├── ids_ips/                                # IDS/IPS specific (2 files)
│   ├── rule_categories.toml
│   └── suricata_vars.yaml
│
├── schemas/                                # Validation schemas (6 files)
│   ├── config_schema.json
│   ├── firewall_rules_schema.json
│   ├── ids_ips_rules_schema.json
│   ├── ids_ips_suricata.rules
│   ├── suricata_rules_format.md
│   └── validation_rules.md
│
└── templates/                              # Service templates (20 files)
    ├── safeops.toml                        # Master configuration
    ├── kernel_driver.toml
    ├── firewall.toml
    ├── firewall_engine.toml
    ├── threat_intel.toml
    ├── ids_ips.toml
    ├── ids_ips.yaml
    ├── dns_server.toml
    ├── dhcp_server.toml
    ├── dns_dhcp_combined.toml
    ├── tls_proxy.toml
    ├── wifi_ap.toml
    ├── vpn_server.toml
    ├── certificate_manager.toml
    ├── backup_restore.toml
    ├── update_manager.toml
    ├── orchestrator.toml
    ├── network_logger.toml
    ├── logging.toml
    └── web_ui.toml
```

### `database/` - Database Schema & Scripts (19 files)
```
database/
├── README.md                               # Quick start guide
├── DATA_DICTIONARY.md                      # Complete schema reference
├── init_database.ps1                       # Windows initialization script
├── init_database.sh                        # Linux initialization script
│
├── schemas/                                # SQL schema files (10 files)
│   ├── 001_initial_setup.sql              # Database setup, extensions
│   ├── 002_ip_reputation.sql              # IP reputation tables
│   ├── 003_domain_reputation.sql          # Domain reputation tables
│   ├── 004_hash_reputation.sql            # File hash reputation
│   ├── 005_ioc_storage.sql                # IOC indicators
│   ├── 006_proxy_anonymizer.sql           # Proxy/VPN detection
│   ├── 007_geolocation.sql                # IP geolocation data
│   ├── 008_threat_feeds.sql               # Threat feed management
│   ├── 009_asn_data.sql                   # ASN reputation data
│   └── 999_indexes_and_maintenance.sql    # Indexes, maintenance functions
│
├── views/                                  # Database views (3 files)
│   ├── active_threats_view.sql
│   ├── high_confidence_iocs.sql
│   └── threat_summary_stats.sql
│
├── seeds/                                  # Seed data (3 files)
│   ├── feed_sources_config.sql            # 18 threat feed sources
│   ├── initial_threat_categories.sql      # 37 threat categories
│   └── test_ioc_data.sql                  # Sample test data
│
├── functions/                              # PostgreSQL functions
└── migrations/                             # Database migrations
    ├── up/                                 # Forward migrations
    └── down/                               # Rollback migrations
```

### `docs/` - Documentation
```
docs/
├── architecture/                           # Architecture documentation
├── api/                                    # API documentation
├── developer_guide/                        # Developer documentation
├── user_guide/                             # User documentation
├── proto/                                  # Protocol buffer documentation
│   └── network_manager_SPEC.md
├── config/                                 # Configuration documentation
├── database/                               # Database documentation
├── services/                               # Service documentation
├── integration/                            # Integration documentation
└── shared/                                 # Shared libraries documentation
    ├── go/
    │   ├── config/
    │   ├── errors/
    │   ├── grpc_client/
    │   ├── health/
    │   ├── logging/
    │   ├── metrics/
    │   ├── postgres/
    │   ├── redis/
    │   └── utils/
    └── rust/
```

### `examples/` - Example Code
```
examples/
└── configurations/                         # Configuration examples
```

### `feeds/` - Threat Feed Storage (Runtime)
```
feeds/
└── sources/                                # Downloaded threat feeds
```

### `installer/` - Installation Packages
```
installer/
├── windows/                                # Windows MSI installer (WiX)
├── packages/                               # Bundled dependencies
│   ├── postgresql/                         # PostgreSQL installer
│   ├── redis/                              # Redis installer
│   └── vcredist/                           # Visual C++ redistributables
└── assets/                                 # Installer assets
    ├── icons/
    └── images/
```

### `logs/` - Runtime Logs
```
logs/
└── .gitkeep                                # Keep directory in git
```

### `proto/` - Protocol Buffer Definitions (17 files)
```
proto/
├── README.md                               # Proto documentation
├── README_STRUCTURES.md                    # Proto data structures
├── build.ps1                               # Windows build script
├── build.sh                                # Linux build script
│
└── grpc/                                   # gRPC service definitions (14 files)
    ├── common.proto                        # Common types
    ├── firewall.proto                      # Firewall service
    ├── threat_intel.proto                  # Threat intelligence service
    ├── ids_ips.proto                       # IDS/IPS service
    ├── dns_server.proto                    # DNS service
    ├── dhcp_server.proto                   # DHCP service
    ├── tls_proxy.proto                     # TLS proxy service
    ├── wifi_ap.proto                       # WiFi AP service
    ├── network_logger.proto                # Network logger service
    ├── network_manager.proto               # Network manager service
    ├── orchestrator.proto                  # Orchestrator service
    ├── certificate_manager.proto           # Certificate manager service
    ├── backup_restore.proto                # Backup/restore service
    └── update_manager.proto                # Update manager service
```

### `scripts/` - Utility Scripts
```
scripts/
├── build/                                  # Build automation scripts
├── install/                                # Installation scripts
├── setup/                                  # Setup scripts
├── testing/                                # Test automation
├── maintenance/                            # Maintenance scripts
└── hyperv/                                 # Hyper-V VM automation (3 files)
    ├── Create-SafeOpsTestVM.ps1           # VM creation
    ├── Configure-VMForDriverDev.ps1       # VM configuration
    └── Test-SafeOpsInVM.ps1               # Automated testing in VM
```

### `src/` - Source Code (700+ files)
```
src/
├── README.md                               # Source code overview
│
├── kernel_driver/                          # Windows WFP/NDIS kernel driver (20 files)
│   ├── README.md                           # Kernel driver documentation
│   ├── DEPENDENCIES.md                     # Kernel dependencies
│   ├── driver.c                            # Main driver entry point
│   ├── driver.h
│   ├── driver_part2.c
│   ├── filter_engine.c                     # WFP filter engine
│   ├── filter_engine.h
│   ├── packet_capture.c                    # Packet capture
│   ├── packet_capture.h
│   ├── nic_management.c                    # NIC management
│   ├── nic_management.h
│   ├── shared_memory.c                     # Ring buffer
│   ├── shared_memory.h
│   ├── ioctl_handler.c                     # IOCTL communication
│   ├── ioctl_handler.h
│   ├── performance.c                       # Performance optimization
│   ├── performance.h
│   ├── safeops.inf                         # Driver installation manifest
│   ├── safeops.rc                          # Resource file
│   └── makefile                            # Build configuration
│
├── userspace_service/                      # Windows service (7 files)
│   ├── README.md
│   ├── service_main.c                      # Service entry point (320 lines)
│   ├── userspace_service.h                 # Shared definitions
│   ├── ioctl_client.c                      # Driver communication (961 lines)
│   ├── ring_reader.c                       # Ring buffer reader (250 lines)
│   ├── log_writer.c                        # JSON log writer (100 lines)
│   └── rotation_manager.c                  # 5-min log rotation (747 lines)
│
├── shared/                                 # Shared libraries (61 files)
│   ├── README.md                           # Shared libraries overview
│   │
│   ├── c/                                  # C header files (5 files)
│   │   ├── README.md
│   │   ├── ring_buffer.h                   # Ring buffer structures
│   │   ├── packet_structs.h                # Packet data structures
│   │   ├── ioctl_codes.h                   # IOCTL command codes
│   │   └── shared_constants.h              # Shared constants
│   │
│   ├── go/                                 # Go shared library (37 files)
│   │   ├── README.md
│   │   ├── go.mod                          # Go module definition
│   │   ├── go.sum                          # Go dependency checksums
│   │   │
│   │   ├── config/                         # Configuration management (5 files)
│   │   │   ├── config.go                   # Viper-based config loader
│   │   │   ├── config_test.go
│   │   │   ├── env.go                      # Environment variables
│   │   │   ├── validator.go                # Config validation
│   │   │   └── watcher.go                  # Hot-reload watcher
│   │   │
│   │   ├── logging/                        # Logging framework (5 files)
│   │   │   ├── logger.go                   # Logrus wrapper
│   │   │   ├── logger_test.go
│   │   │   ├── levels.go
│   │   │   ├── formatters.go               # JSON/text formatters
│   │   │   └── rotation.go                 # Log rotation
│   │   │
│   │   ├── errors/                         # Error handling (3 files)
│   │   │   ├── errors.go                   # Custom error types
│   │   │   ├── codes.go                    # Error codes
│   │   │   └── wrapping.go                 # Error wrapping
│   │   │
│   │   ├── health/                         # Health checks (2 files)
│   │   │   ├── health.go
│   │   │   └── checks.go
│   │   │
│   │   ├── metrics/                        # Prometheus metrics (3 files)
│   │   │   ├── metrics.go
│   │   │   ├── registry.go
│   │   │   └── http_handler.go
│   │   │
│   │   ├── utils/                          # Utilities (5 files)
│   │   │   ├── retry.go                    # Retry with backoff
│   │   │   ├── rate_limit.go               # Rate limiting
│   │   │   ├── bytes.go
│   │   │   ├── strings.go
│   │   │   └── validation.go
│   │   │
│   │   ├── redis/                          # Redis client (4 files)
│   │   │   ├── redis.go                    # Connection manager
│   │   │   ├── pubsub.go                   # Pub/sub implementation
│   │   │   ├── lua_scripts.go              # Lua script execution
│   │   │   └── pipeline.go                 # Pipeline operations
│   │   │
│   │   ├── postgres/                       # PostgreSQL client (4 files)
│   │   │   ├── postgres.go                 # pgx connection pool
│   │   │   ├── transactions.go             # Transaction management
│   │   │   ├── bulk_insert.go              # Bulk insert optimization
│   │   │   └── migrations.go               # Migration runner
│   │   │
│   │   └── grpc_client/                    # gRPC client utilities (7 files)
│   │       ├── client.go                   # gRPC client wrapper
│   │       ├── interceptors.go             # Client interceptors
│   │       ├── retry.go                    # Retry logic
│   │       ├── circuit_breaker.go          # Circuit breaker pattern
│   │       ├── load_balancer.go            # Load balancing
│   │       ├── retry_budget.go             # Retry budget tracking
│   │       └── service_discovery.go        # Service discovery
│   │
│   └── rust/                               # Rust shared library (12 files)
│       ├── README.md
│       ├── Cargo.toml                      # Rust dependencies
│       ├── build.rs                        # Build script
│       │
│       ├── src/                            # Rust source (10 files)
│       │   ├── lib.rs                      # Library root
│       │   ├── error.rs                    # Error types
│       │   ├── ip_utils.rs                 # IP parsing, CIDR utilities
│       │   ├── hash_utils.rs               # xxHash, aHash implementations
│       │       ├── memory_pool.rs              # Object pooling
│       │   ├── lock_free.rs                # Lock-free queue
│       │   ├── simd_utils.rs               # SIMD packet parsing
│       │   ├── time_utils.rs               # Timestamp utilities
│       │   ├── proto_utils.rs              # Protobuf helpers
│       │   ├── buffer_pool.rs              # Buffer pooling
│       │   └── metrics.rs                  # Prometheus metrics
│       │
│       ├── benches/                        # Benchmarks
│       └── tests/                          # Tests
│
├── firewall_engine/                        # Firewall engine (Rust) [Phase 2]
│   ├── README.md
│   ├── src/
│   │   ├── rules/                          # Rule engine
│   │   ├── connection/                     # Connection tracking
│   │   ├── nat/                            # NAT implementation
│   │   ├── ddos/                           # DDoS protection
│   │   ├── matcher/                        # Packet matching
│   │   └── api/                            # gRPC API
│   ├── config/
│   ├── benches/
│   └── tests/
│
├── threat_intel/                           # Threat intelligence (Rust) [Phase 2]
│   ├── README.md
│   ├── src/
│   │   ├── feeds/                          # Feed ingestion
│   │   ├── reputation/                     # Reputation engine
│   │   ├── storage/                        # Storage layer
│   │   ├── utils/                          # Utilities
│   │   └── api/                            # gRPC API
│   ├── config/
│   ├── feeds/
│   └── tests/
│
├── ids_ips/                                # IDS/IPS (Go) [Phase 2]
│   ├── README.md
│   ├── cmd/
│   ├── internal/
│   │   ├── signatures/                     # Signature matching
│   │   ├── anomaly/                        # Anomaly detection
│   │   ├── protocol/                       # Protocol analysis
│   │   ├── alerts/                         # Alert management
│   │   └── blocking/                       # Blocking actions
│   ├── pkg/
│   └── tests/
│
├── dns_server/                             # DNS server (Go) [Phase 2]
│   ├── README.md
│   ├── cmd/
│   ├── internal/
│   │   ├── resolver/                       # DNS resolution
│   │   ├── filtering/                      # Domain filtering
│   │   └── cache/                          # DNS caching
│   ├── pkg/
│   └── tests/
│
├── dhcp_server/                            # DHCP server (Go) [Phase 2]
│   ├── README.md
│   ├── cmd/
│   ├── internal/
│   │   ├── leases/                         # Lease management
│   │   ├── pool/                           # IP pool management
│   │   └── server/                         # DHCP server
│   ├── pkg/
│   └── tests/
│
├── tls_proxy/                              # TLS proxy (Go) [Phase 2]
│   ├── README.md
│   ├── cmd/
│   ├── internal/
│   │   ├── proxy/                          # Proxy implementation
│   │   ├── certificate/                    # Certificate handling
│   │   ├── sni/                            # SNI inspection
│   │   └── cache/                          # Certificate cache
│   ├── pkg/
│   └── tests/
│
├── wifi_ap/                                # WiFi AP (Go) [Phase 2]
│   ├── README.md
│   ├── cmd/
│   ├── internal/
│   │   ├── hostapd/                        # hostapd integration
│   │   ├── clients/                        # Client management
│   │   └── portal/                         # Captive portal
│   ├── pkg/
│   └── tests/
│
├── orchestrator/                           # Orchestrator (Go) [Phase 2]
│   ├── README.md
│   ├── cmd/
│   ├── internal/
│   │   ├── lifecycle/                      # Service lifecycle
│   │   ├── health/                         # Health checking
│   │   ├── metrics/                        # Metrics aggregation
│   │   └── gateway/                        # API gateway
│   ├── pkg/
│   └── tests/
│
├── certificate_manager/                    # Certificate manager (Go) [Phase 2]
│   ├── README.md
│   ├── cmd/
│   ├── internal/
│   │   ├── ca/                             # Certificate Authority
│   │   ├── generation/                     # Certificate generation
│   │   └── distribution/                   # Certificate distribution
│   ├── pkg/
│   └── tests/
│
├── backup_restore/                         # Backup/restore (Go) [Phase 2]
│   ├── README.md
│   ├── cmd/
│   ├── internal/
│   │   ├── backup/                         # Backup logic
│   │   ├── restore/                        # Restore logic
│   │   └── scheduler/                      # Backup scheduling
│   ├── pkg/
│   └── tests/
│
├── update_manager/                         # Update manager (Go) [Phase 2]
│   ├── README.md
│   ├── cmd/
│   ├── internal/
│   │   ├── checker/                        # Update checking
│   │   ├── downloader/                     # Update download
│   │   └── installer/                      # Update installation
│   ├── pkg/
│   └── tests/
│
└── ui/                                     # Web UI (Wails) [Phase 3]
    ├── desktop/                            # Desktop app
    │   ├── frontend/                       # React/Vue frontend
    │   └── backend/                        # Go backend
    └── frontend/                           # Web frontend
        ├── src/
        │   ├── components/
        │   ├── pages/
        │   ├── hooks/
        │   ├── services/
        │   ├── styles/
        │   └── utils/
        ├── public/
        ├── config/
        └── tests/
```

### `tests/` - Testing
```
tests/
├── integration/                            # Integration tests
├── unit/                                   # Unit tests
├── performance/                            # Performance benchmarks
├── security/                               # Security tests
└── e2e/                                    # End-to-end tests
```

### `tools/` - Development Tools
```
tools/
├── proto_validator/                        # Proto validation
└── config_generator/                       # Config generation
```

---

## 📊 File Statistics

### By Category

| Category | File Count | Description |
|----------|------------|-------------|
| **Configuration** | 44 | TOML/YAML configuration files |
| **Database** | 19 | SQL schemas, views, seeds |
| **Protocol Buffers** | 17 | gRPC service definitions |
| **Generated Code** | 30 | Auto-generated from .proto files |
| **Kernel Driver** | 20 | C kernel mode driver |
| **Userspace Service** | 7 | C Windows service |
| **Shared Libraries** | 61 | Rust (12), Go (37), C (5) |
| **Documentation** | 20+ | Markdown documentation |
| **Scripts** | 15 | PowerShell/Bash automation |
| **Services (Planned)** | 600+ | Go/Rust microservices |
| **Total Project** | **800+** | All files |

### By Language

| Language | Files | Lines of Code (Approx) |
|----------|-------|------------------------|
| **C** | 30 | 15,000+ |
| **Rust** | 50 | 8,000+ |
| **Go** | 200+ | 25,000+ |
| **SQL** | 19 | 12,000+ |
| **Protocol Buffers** | 14 | 2,000+ |
| **TOML/YAML** | 50 | 3,000+ |
| **Markdown** | 30+ | - |
| **PowerShell** | 10 | 5,000+ |

---

## 🏗️ Build Phases

### ✅ Phase 1: Foundation (COMPLETE)
- Protocol Buffers (17 files)
- Configuration (44 files)
- Database Schemas (19 files)
- Kernel Driver (20 files)
- Userspace Service (7 files)
- Shared Libraries (61 files)

**Status:** 210+ files implemented

### 🔄 Phase 2: Core Services (IN PROGRESS)
- Firewall Engine (Rust)
- Threat Intelligence (Rust)
- IDS/IPS (Go)
- DNS Server (Go)
- DHCP Server (Go)
- TLS Proxy (Go)
- WiFi AP (Go)
- Orchestrator (Go)
- Certificate Manager (Go)
- Backup/Restore (Go)
- Update Manager (Go)

**Status:** Service skeletons exist, implementation pending

### ⏳ Phase 3: UI & Distribution (PLANNED)
- Web UI (Wails - Go + TypeScript)
- Windows Installer (WiX)
- Integration Tests

**Status:** Not started

---

## 📝 Notes

- **DELETE_ME_WHEN_ADDING_FILES.txt**: Placeholder files to preserve empty directories in Git
- **.gitkeep**: Alternative placeholder for empty directories
- **Total Files**: 800+ files across all directories
- **Languages**: C, Rust, Go, SQL, TOML, YAML, Protocol Buffers
- **Documentation**: 50,000+ words across all README files

---

## 🔗 Quick Links

- [Data Structures Reference](./DATA_STRUCTURES.md)
- [Database Schema](./database/DATA_DICTIONARY.md)
- [Kernel Driver](./src/kernel_driver/README.md)
- [Configuration Guide](./config/README.md)
- [Protocol Buffers](./proto/README_STRUCTURES.md)

---

**Generated:** 2025-12-17  
**Version:** 2.0.0  
**License:** MIT
