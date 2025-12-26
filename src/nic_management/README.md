# NIC Management Service

Network Interface Card (NIC) Management Service for SafeOps Firewall V2.

## Directory Structure

```
src/nic_management/
├── cmd/
│   ├── main.go                          # Service entry point (Go)
│   ├── installer.go                     # Windows service installer
│   └── uninstaller.go                   # Service uninstaller
│
├── config/
│   └── config.go                        # Configuration loader (Go)
│
├── internal/
│   ├── discovery/
│   │   ├── enumerator.go                # NIC enumeration engine (Go)
│   │   ├── classifier.go                # WAN/LAN classification logic (Go)
│   │   ├── monitor.go                   # Interface state monitoring (Go)
│   │   ├── physical_detector.go         # Physical vs virtual NIC detection (Go)
│   │   └── capabilities.go              # NIC capability detection - speed, duplex (Go)
│   │
│   ├── router/
│   │   ├── packet_capture.rs            # Multi-queue packet capture (Rust)
│   │   ├── routing_engine.rs            # Core routing decision logic (Rust)
│   │   ├── forwarding_engine.rs         # High-speed packet forwarding (Rust)
│   │   ├── connection_tracker.go        # Connection state tracking (Go)
│   │   └── packet_queue.rs              # Multi-queue packet buffer management (Rust)
│   │
│   ├── nat/
│   │   ├── translator.rs                # NAT/NAPT translation engine (Rust)
│   │   ├── port_allocator.go            # Dynamic port allocation pool (Go)
│   │   ├── mapping_table.go             # NAT mapping table - LAN IP:Port to WAN IP:Port (Go)
│   │   ├── session_tracker.go           # Session lifecycle management (Go)
│   │   └── cleanup.go                   # Expired connection cleanup (Go)
│   │
│   ├── loadbalancer/
│   │   ├── wan_selector.go              # WAN selection logic - round-robin, weighted, least-conn (Go)
│   │   ├── health_checker.go            # WAN link health monitoring (Go)
│   │   ├── traffic_distributor.go       # Traffic distribution engine (Go)
│   │   ├── session_affinity.go          # Session persistence - same WAN for same flow (Go)
│   │   └── metrics_collector.go         # Per-WAN performance metrics (Go)
│   │
│   ├── failover/
│   │   ├── wan_monitor.go               # Continuous WAN availability monitoring (Go)
│   │   ├── failover_handler.go          # Automatic failover logic (Go)
│   │   ├── recovery_manager.go          # WAN recovery detection & switchback (Go)
│   │   └── state_machine.go             # Failover state machine (Go)
│   │
│   ├── configuration/
│   │   ├── interface_config.go          # IP address assignment & management (Go)
│   │   ├── dhcp_integration.go          # DHCP client/server integration (Go)
│   │   ├── gateway_manager.go           # Gateway configuration (Go)
│   │   ├── dns_manager.go               # DNS settings management (Go)
│   │   └── mtu_manager.go               # MTU/speed control (Go)
│   │
│   ├── performance/
│   │   ├── statistics.go                # Per-interface statistics collector (Go)
│   │   ├── throughput.go                # Throughput calculation engine (Go)
│   │   ├── packet_rate.go               # Packet rate tracking (Go)
│   │   ├── error_counter.go             # Error/drop counter (Go)
│   │   └── metrics_aggregator.go        # Real-time metrics aggregation (Go)
│   │
│   ├── integration/
│   │   ├── firewall_hooks.go            # Firewall engine integration points (Go)
│   │   ├── ids_hooks.go                 # IDS/IPS inspection hooks (Go)
│   │   ├── logger_hooks.go              # Network logger integration (Go)
│   │   ├── qos_hooks.go                 # QoS priority hooks (Go)
│   │   └── event_publisher.go           # Event bus publisher (Go)
│   │
│   ├── driver/
│   │   ├── winpcap_wrapper.go           # WinPcap/Npcap wrapper (Go + CGO)
│   │   ├── ndis_interface.go            # NDIS driver interface - Windows (Go)
│   │   ├── iphlpapi_wrapper.go          # Windows IP Helper API wrapper (Go)
│   │   ├── wmi_queries.go               # WMI queries for NIC info (Go)
│   │   └── raw_socket_linux.rs          # Linux raw socket handling (Rust)
│   │
│   ├── grpc/
│   │   ├── server.go                    # gRPC service implementation (Go)
│   │   ├── handlers.go                  # RPC method handlers (Go)
│   │   └── stream_handlers.go           # Streaming statistics handlers (Go)
│   │
│   └── rust_bridge/
│       ├── lib.rs                       # Rust library entry point
│       ├── ffi.rs                       # FFI bindings for Go interop
│       └── packet_processor.rs          # Main packet processing pipeline (Rust)
│
├── pkg/
│   ├── client/
│   │   └── client.go                    # Client library for other services (Go)
│   │
│   └── types/
│       ├── types.go                     # Core types & structs (Go)
│       ├── nic_types.go                 # NIC-specific types (Go)
│       ├── routing_types.go             # Routing data structures (Go)
│       └── nat_types.go                 # NAT data structures (Go)
│
├── tests/
│   ├── integration_test.go              # Integration tests (Go)
│   ├── unit_test.go                     # Unit tests (Go)
│   ├── performance_test.go              # Performance benchmarks (Go)
│   └── rust_tests.rs                    # Rust unit tests
│
├── Cargo.toml                           # Rust dependencies
├── go.mod                               # Go dependencies
├── go.sum
└── README.md                            # Service documentation

config/templates/
└── nic_management.yaml                  # Configuration file

database/schemas/
└── 020_nic_management.sql               # Database schema for connection tracking, NAT mappings

proto/grpc/
└── nic_management.proto                 # gRPC service definition

web/data/
└── nic_management.json                  # Web UI data file for NIC management

scripts/nic_management/
├── install_service.ps1                  # Windows service installer
├── uninstall_service.ps1                # Service uninstaller
├── install_linux.sh                     # Linux installation script
└── test_routing.sh                      # Routing testing script
```
