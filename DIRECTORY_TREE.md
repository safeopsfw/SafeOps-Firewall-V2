# SafeOps v2.0 - Directory Structure

```
SafeOpsFV2/
├── .agent/                          # Agent workflows
│   └── workflows/
├── .claude/                         # Claude configuration
├── .vscode/                         # VS Code settings
├── certs/                           # Certificate storage
│   ├── ca/                          # Certificate Authority
│   └── distribution/                # Distributed certs
├── config/                          # Global configuration
│   ├── defaults/                    # Default configs
│   ├── examples/                    # Example configs
│   ├── ids_ips/                     # IDS/IPS rules
│   ├── schemas/                     # Config schemas
│   └── templates/                   # Config templates
├── docs/                            # Documentation
│   ├── api/                         # API documentation
│   ├── architecture/                # Architecture docs
│   ├── config/                      # Config documentation
│   ├── developer_guide/             # Developer guides
│   ├── integration/                 # Integration guides
│   ├── proto/                       # Protobuf docs
│   ├── services/                    # Service docs
│   ├── shared/                      # Shared library docs
│   │   ├── go/                      # Go libraries
│   │   └── rust/                    # Rust libraries
│   └── user_guide/                  # User guides
├── examples/                        # Example files
│   └── configurations/              # Example configs
├── feeds/                           # Threat intel feeds
│   └── sources/                     # Feed sources
├── installer/                       # Windows installer
│   ├── assets/                      # Installer assets
│   │   ├── icons/
│   │   └── images/
│   ├── packages/                    # Bundled packages
│   │   ├── postgresql/
│   │   ├── redis/
│   │   └── vcredist/
│   └── windows/                     # Windows installer scripts
├── logs/                            # Application logs
├── proto/                           # Protocol Buffers
│   └── grpc/                        # gRPC definitions
├── sandbox/                         # Development sandbox
├── scripts/                         # Utility scripts
│   ├── hyperv/                      # Hyper-V scripts
│   ├── install/                     # Installation scripts
│   ├── maintenance/                 # Maintenance scripts
│   ├── setup/                       # Setup scripts
│   └── testing/                     # Testing scripts
├── src/                             # Source code
│   ├── backup_restore/              # Backup & Restore service
│   │   ├── cmd/
│   │   ├── config/
│   │   ├── internal/
│   │   │   ├── backup/
│   │   │   ├── restore/
│   │   │   └── scheduler/
│   │   ├── pkg/
│   │   └── tests/
│   ├── certificate_manager/         # Certificate Manager
│   │   ├── cmd/
│   │   ├── config/
│   │   ├── internal/
│   │   │   ├── ca/
│   │   │   ├── distribution/
│   │   │   └── generation/
│   │   ├── pkg/
│   │   └── tests/
│   ├── dhcp_server/                 # DHCP Server
│   │   ├── cmd/
│   │   ├── config/
│   │   ├── internal/
│   │   │   ├── leases/
│   │   │   ├── pool/
│   │   │   └── server/
│   │   ├── pkg/
│   │   └── tests/
│   ├── dns_server/                  # DNS Server
│   │   ├── cmd/
│   │   ├── config/
│   │   ├── internal/
│   │   │   ├── cache/
│   │   │   ├── filtering/
│   │   │   └── resolver/
│   │   ├── pkg/
│   │   └── tests/
│   ├── firewall_engine/             # Firewall Engine (Rust)
│   │   ├── benches/
│   │   ├── config/
│   │   ├── src/
│   │   │   ├── api/
│   │   │   ├── connection/
│   │   │   ├── ddos/
│   │   │   ├── matcher/
│   │   │   ├── nat/
│   │   │   └── rules/
│   │   └── tests/
│   ├── ids_ips/                     # IDS/IPS System
│   │   ├── cmd/
│   │   ├── config/
│   │   ├── internal/
│   │   │   ├── alerts/
│   │   │   ├── anomaly/
│   │   │   ├── blocking/
│   │   │   ├── protocol/
│   │   │   └── signatures/
│   │   ├── pkg/
│   │   └── tests/
│   ├── kernel_driver/               # Windows Kernel Driver (C)
│   │   ├── driver.c
│   │   ├── driver.h
│   │   ├── filter_engine.c/h
│   │   ├── ioctl_handler.c/h
│   │   ├── nic_management.c/h
│   │   ├── packet_capture.c/h
│   │   ├── performance.c/h
│   │   ├── shared_memory.c/h
│   │   └── statistics.c/h
│   ├── orchestrator/                # Service Orchestrator
│   │   ├── cmd/
│   │   ├── config/
│   │   ├── internal/
│   │   │   ├── gateway/
│   │   │   ├── health/
│   │   │   ├── lifecycle/
│   │   │   └── metrics/
│   │   ├── pkg/
│   │   └── tests/
│   ├── shared/                      # Shared Libraries
│   │   ├── c/                       # C headers
│   │   │   ├── error_codes.h
│   │   │   ├── ioctl_codes.h
│   │   │   ├── packet_structs.h
│   │   │   ├── ring_buffer.h
│   │   │   └── shared_constants.h
│   │   ├── go/                      # Go shared packages
│   │   │   ├── config/
│   │   │   ├── errors/
│   │   │   ├── grpc_client/
│   │   │   ├── health/
│   │   │   ├── logging/
│   │   │   ├── metrics/
│   │   │   ├── postgres/
│   │   │   ├── redis/
│   │   │   └── utils/
│   │   └── rust/                    # Rust shared crates
│   │       └── src/proto/
│   ├── threat_intel/                # Threat Intelligence ⭐
│   │   ├── cmd/
│   │   │   ├── api/                 # REST API server
│   │   │   ├── fetcher/             # Feed fetcher
│   │   │   ├── parser_test/
│   │   │   ├── pipeline/            # Full pipeline
│   │   │   ├── processor/           # Data processor
│   │   │   ├── server/
│   │   │   ├── storage_test/
│   │   │   └── verify/
│   │   ├── config/
│   │   ├── models/
│   │   ├── src/
│   │   │   ├── api/
│   │   │   ├── fetcher/
│   │   │   ├── parser/
│   │   │   ├── processor/
│   │   │   ├── storage/
│   │   │   └── worker/
│   │   └── utils/
│   ├── tls_proxy/                   # TLS Interception Proxy
│   │   ├── cmd/
│   │   ├── config/
│   │   ├── internal/
│   │   │   ├── cache/
│   │   │   ├── certificate/
│   │   │   ├── proxy/
│   │   │   └── sni/
│   │   ├── pkg/
│   │   └── tests/
│   ├── ui/                          # User Interfaces ⭐
│   │   ├── dev/                     # Developer Dashboard
│   │   │   ├── public/
│   │   │   ├── server/              # Node.js API server
│   │   │   │   └── server.js        # Express.js backend
│   │   │   └── src/
│   │   │       ├── assets/
│   │   │       ├── components/
│   │   │       ├── context/
│   │   │       ├── hooks/
│   │   │       ├── pages/
│   │   │       └── services/
│   │   └── user/                    # User Dashboard
│   │       └── src/
│   ├── update_manager/              # Update Manager
│   │   ├── cmd/
│   │   ├── config/
│   │   ├── internal/
│   │   │   ├── checker/
│   │   │   ├── downloader/
│   │   │   └── installer/
│   │   ├── pkg/
│   │   └── tests/
│   ├── userspace_service/           # Userspace Service (C)
│   │   ├── build/                   # Build output
│   │   │   └── SafeOpsService.exe   # Compiled service
│   │   ├── ioctl_client.c
│   │   ├── log_writer.c/h
│   │   ├── ring_reader.c/h
│   │   ├── rotation_manager.c/h
│   │   ├── service_main.c/h
│   │   └── userspace_service.h
│   └── wifi_ap/                     # WiFi Access Point
│       ├── cmd/
│       ├── config/
│       ├── internal/
│       │   ├── clients/
│       │   ├── hostapd/
│       │   └── portal/
│       ├── pkg/
│       └── tests/
├── tests/                           # Test suites
│   ├── e2e/                         # End-to-end tests
│   ├── integration/                 # Integration tests
│   ├── performance/                 # Performance tests
│   └── unit/                        # Unit tests
└── tools/                           # Development tools
    └── dev-utils/
```

## Key Components

| Component         | Language | Purpose                                  |
| ----------------- | -------- | ---------------------------------------- |
| kernel_driver     | C        | Windows NDIS driver for packet capture   |
| userspace_service | C        | Windows service for driver communication |
| firewall_engine   | Rust     | High-performance packet filtering        |
| threat_intel      | Go       | Threat intelligence pipeline             |
| ids_ips           | Go       | Intrusion detection/prevention           |
| dns_server        | Go       | DNS filtering and caching                |
| tls_proxy         | Go       | TLS/SSL interception                     |
| ui/dev            | React    | Developer management console             |
| ui/user           | React    | End-user security dashboard              |

## Running Services

```bash
# Dev UI (port 3001)
cd src/ui/dev && npm run dev

# Node.js API Server (port 8080)
cd src/ui/dev && npm run server

# Threat Intel Go API (port 8080)
cd src/threat_intel/cmd/api && go run main.go

# Run threat intel pipeline
cd src/threat_intel && go run ./cmd/pipeline
```
