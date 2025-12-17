# SafeOps v2.0 - Complete Dependency Map

> **File-by-file dependency analysis for all implemented components**
>
> Generated: 2025-12-17 | Files Analyzed: 150+ | Phase 1 Complete

---

## 📋 Build Order (Bottom-to-Top)

This document shows dependencies from foundational files (bottom) up to dependent files (top).
**Rule:** Build files at each level only after all files at lower levels are built.

---

## 🔢 Level 0: No Dependencies (Pure Definitions)

These files have no project-internal dependencies.

### Protocol Buffers - Base Types
```
proto/grpc/common.proto
  └── Dependencies: NONE
  └── Contains: Timestamp, Empty, Status, Metadata types
  └── Required By: ALL other .proto files (13 services)
```

### C Shared Headers - Base Types
```
src/shared/c/shared_constants.h
  └── Dependencies: <stdint.h>
  └── Contains: MAX_*, MIN_*, TIMEOUT_* constants
  └── Required By: packet_structs.h, ring_buffer.h, ioctl_codes.h

src/shared/c/packet_structs.h
  └── Dependencies: <stdint.h>, <winsock2.h> (Windows), <arpa/inet.h> (Linux)
  └── Contains: TCP_HEADER, UDP_HEADER, IPV4_HEADER, PACKET_INFO
  └── Required By: ring_buffer.h, kernel_driver/*

src/shared/c/ring_buffer.h
  └── Dependencies: <stdint.h>, <intrin.h> (Windows), <stdatomic.h> (Linux)
  └── Contains: RING_BUFFER_HEADER, SafeOpsRingBuffer
  └── Required By: shared_memory.h, ring_reader.c

src/shared/c/ioctl_codes.h
  └── Dependencies: <windows.h>
  └── Contains: IOCTL_SAFEOPS_* command codes
  └── Required By: ioctl_handler.h, ioctl_client.c
```

### Database - Initial Setup (Must Run First)
```
database/schemas/001_initial_setup.sql
  └── Dependencies: PostgreSQL 16+
  └── Creates:
      - Extensions: pgcrypto, uuid-ossp, citext, pg_trgm, btree_gist
      - Tables: threat_categories, threat_feeds, ioc_indicators
      - Tables: ioc_campaigns, ioc_campaign_members, ioc_relationships
      - Functions: set_updated_at(), calculate_confidence_score()
  └── Required By: ALL other schema files (002-009, views, seeds)
```

---

## 🔢 Level 1: Foundation Dependencies

### Protocol Buffers - Services
All depend on `common.proto`:

```
proto/grpc/firewall.proto         → Depends: common.proto
proto/grpc/threat_intel.proto     → Depends: common.proto
proto/grpc/network_manager.proto  → Depends: common.proto
proto/grpc/network_logger.proto   → Depends: common.proto
proto/grpc/ids_ips.proto          → Depends: common.proto
proto/grpc/dns_server.proto       → Depends: common.proto
proto/grpc/dhcp_server.proto      → Depends: common.proto
proto/grpc/tls_proxy.proto        → Depends: common.proto
proto/grpc/wifi_ap.proto          → Depends: common.proto
proto/grpc/orchestrator.proto     → Depends: common.proto
proto/grpc/certificate_manager.proto → Depends: common.proto
proto/grpc/backup_restore.proto   → Depends: common.proto
proto/grpc/update_manager.proto   → Depends: common.proto
```

### Kernel Driver - Core Headers
```
src/kernel_driver/driver.h
  └── Dependencies:
      - Windows WDK: <ntddk.h>, <wdf.h>
      - WFP: <fwpsk.h>, <fwpmk.h>
      - NDIS: <ndis.h>
      - System: <ntstrsafe.h>
  └── Contains: SAFEOPS_DEVICE_EXTENSION, callback declarations
  └── Required By: driver.c, ioctl_handler.h, shared_memory.h

src/kernel_driver/filter_engine.h
  └── Dependencies: <ntddk.h>, <fwpsk.h>, <fwpmk.h>, <netiodef.h>
  └── Contains: FilterEngine*, WfpCallout* functions
  └── Required By: filter_engine.c, driver.c

src/kernel_driver/packet_capture.h
  └── Dependencies: <ntddk.h>, <ndis.h>, <netiodef.h>, <in6addr.h>, <ip2string.h>
  └── Contains: CAPTURED_PACKET, PacketCapture* functions
  └── Required By: packet_capture.c, driver.c

src/kernel_driver/nic_management.h
  └── Dependencies: <ntddk.h>, <ndis.h>
  └── Contains: NIC_INFO, NicMgmt* functions
  └── Required By: nic_management.c, driver.c

src/kernel_driver/performance.h
  └── Dependencies: <ntddk.h>, <ndis.h>
  └── Contains: PERFORMANCE_COUNTERS, Perf* functions
  └── Required By: performance.c, driver.c
```

### Go Shared - Error Handling (Foundation)
```
src/shared/go/errors/codes.go
  └── Dependencies: Go stdlib only
  └── Contains: Error codes (ErrCodeInternal, ErrCodeNotFound, etc.)
  └── Required By: errors.go, wrapping.go

src/shared/go/errors/errors.go
  └── Dependencies: "fmt", "errors"
  └── Contains: SafeOpsError struct, New(), Wrap(), Is()
  └── Required By: ALL Go shared packages

src/shared/go/errors/wrapping.go
  └── Dependencies: "fmt", "errors"
  └── Contains: WithStack(), WithContext(), Cause()
  └── Required By: All Go error handling
```

### Rust Shared - Error Handling (Foundation)
```
src/shared/rust/src/error.rs
  └── Dependencies: thiserror, anyhow
  └── Contains: SafeOpsError enum, Result type alias
  └── Required By: ALL other Rust modules
```

### Database - Core Reputation Tables
```
database/schemas/002_ip_reputation.sql
  └── Dependencies: 001_initial_setup.sql (threat_categories, threat_feeds)
  └── Creates:
      - Tables: ip_reputation, ip_reputation_sources, ip_reputation_history
      - Tables: ip_whitelist, ip_blacklist, ip_reputation_scores
      - Indexes: 15+ optimized indexes
      - Triggers: score update triggers
  └── Required By: Views, threat_intel service, firewall_engine

database/schemas/003_domain_reputation.sql
  └── Dependencies: 001_initial_setup.sql (threat_categories, threat_feeds)
  └── Creates:
      - Tables: domain_reputation, domain_reputation_sources, domain_reputation_history
      - Tables: domain_whitelist, domain_blacklist, domain_dns_records
      - Indexes: Trigram index for fuzzy search
  └── Required By: Views, dns_server, threat_intel

database/schemas/004_hash_reputation.sql
  └── Dependencies: 001_initial_setup.sql (threat_categories, threat_feeds)
  └── Creates:
      - Tables: hash_reputation, hash_reputation_sources, hash_reputation_history
      - Tables: malware_families, hash_analysis_results, hash_relationships
  └── Required By: Views, threat_intel

database/schemas/005_ioc_storage.sql
  └── Dependencies: 001_initial_setup.sql (ioc_indicators, threat_feeds, threat_categories)
  └── Creates:
      - Tables: ioc_sightings, ioc_campaign_members, ioc_relationships
      - Partitions: By IOC type
      - Functions: IOC expiration, sighting tracking
  └── Required By: Views, ids_ips
```

---

## 🔢 Level 2: Secondary Dependencies

### Kernel Driver - Implementation Files
```
src/kernel_driver/driver.c
  └── Dependencies:
      - driver.h
      - <ntstrsafe.h>, <wdmsec.h>
  └── Contains: DriverEntry(), DriverUnload(), device callbacks
  └── Required By: safeops.sys (driver binary)

src/kernel_driver/driver_part2.c
  └── Dependencies: driver.h
  └── Contains: Additional driver functions (split for compilation)
  └── Required By: safeops.sys

src/kernel_driver/filter_engine.c
  └── Dependencies: filter_engine.h
  └── Contains: WFP callout implementations, classify functions
  └── Required By: safeops.sys

src/kernel_driver/packet_capture.c
  └── Dependencies: packet_capture.h
  └── Contains: Packet parsing, capture logic
  └── Required By: safeops.sys

src/kernel_driver/nic_management.c
  └── Dependencies: nic_management.h
  └── Contains: NIC enumeration, RSS, offload configuration
  └── Required By: safeops.sys

src/kernel_driver/performance.c
  └── Dependencies: performance.h
  └── Contains: DMA init, RSS config, performance tuning
  └── Required By: safeops.sys

src/kernel_driver/ioctl_handler.h
  └── Dependencies: driver.h
  └── Contains: IOCTL codes, command structures
  └── Required By: ioctl_handler.c

src/kernel_driver/ioctl_handler.c
  └── Dependencies: ioctl_handler.h
  └── Contains: IOCTL dispatch, command processing
  └── Required By: safeops.sys

src/kernel_driver/shared_memory.h
  └── Dependencies: driver.h
  └── Contains: Ring buffer section, shared memory functions
  └── Required By: shared_memory.c

src/kernel_driver/shared_memory.c
  └── Dependencies: shared_memory.h
  └── Contains: Ring buffer creation, kernel→userspace communication
  └── Required By: safeops.sys
```

### Go Shared - Core Utilities
```
src/shared/go/config/config.go
  └── Dependencies:
      - External: github.com/spf13/viper, gopkg.in/yaml.v3
      - Internal: errors package
  └── Contains: Config struct, Load(), Get(), Watch()
  └── Required By: ALL Go services

src/shared/go/config/env.go
  └── Dependencies: "os", "strconv"
  └── Contains: GetEnv(), GetEnvWithDefault()
  └── Required By: config.go

src/shared/go/config/validator.go
  └── Dependencies: "reflect", "regexp"
  └── Contains: Validate(), ValidateRequired()
  └── Required By: config.go

src/shared/go/config/watcher.go
  └── Dependencies: github.com/fsnotify/fsnotify
  └── Contains: Watch(), OnConfigChange()
  └── Required By: Hot-reload functionality

src/shared/go/logging/logger.go
  └── Dependencies:
      - External: github.com/sirupsen/logrus
      - Internal: errors package
  └── Contains: Logger struct, Info/Debug/Error/Warn methods
  └── Required By: ALL Go services

src/shared/go/logging/levels.go
  └── Dependencies: logrus
  └── Contains: Level type, ParseLevel()
  └── Required By: logger.go

src/shared/go/logging/formatters.go
  └── Dependencies: logrus, "encoding/json", "time"
  └── Contains: JSONFormatter, TextFormatter
  └── Required By: logger.go

src/shared/go/logging/rotation.go
  └── Dependencies: "os", "path/filepath", "io"
  └── Contains: RotatingWriter, file rotation logic
  └── Required By: logger.go
```

### Rust Shared - Core Utilities
```
src/shared/rust/src/ip_utils.rs
  └── Dependencies: ipnet, cidr-utils
  └── Contains: IP parsing, CIDR matching, network checks
  └── Required By: threat_intel, firewall_engine

src/shared/rust/src/hash_utils.rs
  └── Dependencies: ahash, xxhash-rust
  └── Contains: fast_hash(), xxh3_hash(), ahash()
  └── Required By: firewall_engine, ids_ips

src/shared/rust/src/time_utils.rs
  └── Dependencies: chrono
  └── Contains: now_utc(), format_timestamp(), duration_*
  └── Required By: ALL Rust services

src/shared/rust/src/lock_free.rs
  └── Dependencies: crossbeam, parking_lot
  └── Contains: LockFreeQueue, AtomicCounter
  └── Required By: High-performance services

src/shared/rust/src/memory_pool.rs
  └── Dependencies: parking_lot
  └── Contains: ObjectPool, PooledObject
  └── Required By: Performance-critical paths

src/shared/rust/src/buffer_pool.rs
  └── Dependencies: None (std only)
  └── Contains: BufferPool, reusable byte buffers
  └── Required By: Packet processing

src/shared/rust/src/simd_utils.rs
  └── Dependencies: packed_simd_2
  └── Contains: SIMD-accelerated byte searches
  └── Required By: Deep packet inspection

src/shared/rust/src/proto_utils.rs
  └── Dependencies: prost
  └── Contains: Protobuf helpers, encoding utilities
  └── Required By: gRPC services

src/shared/rust/src/metrics.rs
  └── Dependencies: prometheus
  └── Contains: Histogram, Counter, Gauge wrappers
  └── Required By: ALL Rust services
```

### Database - Additional Tables
```
database/schemas/006_proxy_anonymizer.sql
  └── Dependencies: 001_initial_setup.sql
  └── Creates:
      - Tables: proxy_services, vpn_providers, tor_exit_nodes
      - Tables: datacenter_ips, hosting_providers
      - Detection functions
  └── Required By: threat_intel, firewall_engine

database/schemas/007_geolocation.sql
  └── Dependencies: 001_initial_setup.sql
  └── Creates:
      - Tables: ip_geolocation, country_info, city_info
      - Tables: threat_zones, geofence_rules
      - Partitions: By continent
  └── Required By: threat_intel, dashboard

database/schemas/008_threat_feeds.sql
  └── Dependencies: 001_initial_setup.sql (threat_feeds table)
  └── Creates:
      - Tables: feed_credentials, feed_schedules, feed_health
      - Tables: feed_update_history, feed_statistics
      - Encrypted credential storage
  └── Required By: threat_intel feed ingestion

database/schemas/009_asn_data.sql
  └── Dependencies: 001_initial_setup.sql
  └── Creates:
      - Tables: asn_data, asn_prefixes, asn_peers
      - Tables: asn_reputation, asn_abuse_contacts
      - BGP routing data
  └── Required By: threat_intel, network analysis
```

---

## 🔢 Level 3: Service Dependencies

### Go Shared - Client Libraries
```
src/shared/go/postgres/postgres.go
  └── Dependencies:
      - External: github.com/jackc/pgx/v5
      - Internal: config, logging, errors
  └── Contains: DB struct, Connect(), Query(), Exec()
  └── Required By: ALL database-connected services

src/shared/go/postgres/transactions.go
  └── Dependencies: pgx, postgres.go
  └── Contains: Tx struct, Begin(), Commit(), Rollback()
  └── Required By: Multi-statement operations

src/shared/go/postgres/bulk_insert.go
  └── Dependencies: pgx, postgres.go
  └── Contains: BulkInsert(), CopyFrom()
  └── Required By: Feed ingestion, batch processing

src/shared/go/postgres/migrations.go
  └── Dependencies: pgx, postgres.go, "path/filepath"
  └── Contains: RunMigrations(), MigrationStatus()
  └── Required By: Database setup

src/shared/go/redis/redis.go
  └── Dependencies:
      - External: github.com/go-redis/redis/v8
      - Internal: config, logging, errors
  └── Contains: Client struct, Get(), Set(), Del()
  └── Required By: Caching services

src/shared/go/redis/pubsub.go
  └── Dependencies: redis/v8, redis.go
  └── Contains: Subscribe(), Publish(), channels
  └── Required By: Event-driven services

src/shared/go/redis/pipeline.go
  └── Dependencies: redis/v8, redis.go
  └── Contains: Pipeline(), batch operations
  └── Required By: Bulk cache operations

src/shared/go/redis/lua_scripts.go
  └── Dependencies: redis/v8, redis.go
  └── Contains: Eval(), atomic Lua scripts
  └── Required By: Rate limiting, counters

src/shared/go/grpc_client/client.go
  └── Dependencies:
      - External: google.golang.org/grpc
      - Internal: config, logging, errors
  └── Contains: GRPCClient struct, Dial(), Close()
  └── Required By: ALL service-to-service communication

src/shared/go/grpc_client/interceptors.go
  └── Dependencies: grpc, logging, metrics
  └── Contains: UnaryInterceptor, StreamInterceptor
  └── Required By: client.go

src/shared/go/grpc_client/retry.go
  └── Dependencies: grpc, time, context
  └── Contains: RetryUnary(), exponential backoff
  └── Required By: client.go

src/shared/go/grpc_client/circuit_breaker.go
  └── Dependencies: "sync", "time"
  └── Contains: CircuitBreaker, Open/Close/HalfOpen states
  └── Required By: client.go

src/shared/go/grpc_client/load_balancer.go
  └── Dependencies: grpc/balancer
  └── Contains: RoundRobin, WeightedRoundRobin
  └── Required By: client.go

src/shared/go/grpc_client/retry_budget.go
  └── Dependencies: "sync/atomic", "time"
  └── Contains: RetryBudget, token bucket
  └── Required By: retry.go

src/shared/go/grpc_client/service_discovery.go
  └── Dependencies: grpc/resolver
  └── Contains: Resolver, ServiceRegistry
  └── Required By: client.go

src/shared/go/health/health.go
  └── Dependencies: logging, errors, "sync"
  └── Contains: HealthChecker, Check(), Status
  └── Required By: ALL services

src/shared/go/health/checks.go
  └── Dependencies: health.go, postgres, redis
  └── Contains: CheckPostgres(), CheckRedis(), CheckGRPC()
  └── Required By: health.go

src/shared/go/metrics/metrics.go
  └── Dependencies:
      - External: github.com/prometheus/client_golang
  └── Contains: Counter, Histogram, Gauge wrappers
  └── Required By: ALL services

src/shared/go/metrics/registry.go
  └── Dependencies: prometheus
  └── Contains: Registry, registration functions
  └── Required By: metrics.go

src/shared/go/metrics/http_handler.go
  └── Dependencies: prometheus, "net/http"
  └── Contains: MetricsHandler, /metrics endpoint
  └── Required By: Services with HTTP server

src/shared/go/utils/retry.go
  └── Dependencies: "time", "context"
  └── Contains: Retry(), WithBackoff(), MaxRetries
  └── Required By: Resilient operations

src/shared/go/utils/rate_limit.go
  └── Dependencies: "sync", "time"
  └── Contains: RateLimiter, TokenBucket, Allow()
  └── Required By: API rate limiting

src/shared/go/utils/bytes.go
  └── Dependencies: "encoding/binary"
  └── Contains: byte utilities, endianness
  └── Required By: Protocol handling

src/shared/go/utils/strings.go
  └── Dependencies: "strings", "unicode"
  └── Contains: string utilities
  └── Required By: Input validation

src/shared/go/utils/validation.go
  └── Dependencies: "regexp", "net"
  └── Contains: ValidateIP(), ValidateDomain(), ValidatePort()
  └── Required By: Input validation
```

### Userspace Service Files
```
src/userspace_service/userspace_service.h
  └── Dependencies: <windows.h>, <stdio.h>, <stdlib.h>, <string.h>, <time.h>
  └── Contains: Common definitions, types
  └── Required By: ALL userspace_service/*.c files

src/userspace_service/ioctl_client.c
  └── Dependencies: <windows.h>, <winioctl.h>, ioctl_codes.h
  └── Contains: Driver communication, DeviceIoControl wrapper
  └── Required By: service_main.c

src/userspace_service/ring_reader.c
  └── Dependencies: <windows.h>, <intrin.h>, ring_buffer.h, packet_structs.h
  └── Contains: Ring buffer consumer, lock-free reads
  └── Required By: service_main.c

src/userspace_service/log_writer.c
  └── Dependencies: <windows.h>, <time.h>, packet_structs.h
  └── Contains: JSON log formatting, file writing
  └── Required By: service_main.c

src/userspace_service/rotation_manager.c
  └── Dependencies: <windows.h>, <time.h>
  └── Contains: 5-minute log rotation, compression
  └── Required By: service_main.c

src/userspace_service/service_main.c
  └── Dependencies:
      - Windows: <windows.h>, <tchar.h>, <strsafe.h>, <psapi.h>
      - Internal: userspace_service.h, ring_reader.h, log_writer.h
      - Internal: rotation_manager.h, ioctl_client.h
  └── Contains: ServiceMain(), main(), service control handler
  └── Required By: userspace_service.exe (final binary)
```

### Database - Indexes and Views
```
database/schemas/999_indexes_and_maintenance.sql
  └── Dependencies: ALL schema files (001-009)
  └── Creates:
      - Composite indexes for common queries
      - Partial indexes for active records
      - Materialized view refresh functions
      - Maintenance procedures
      - pg_cron scheduled jobs
  └── Required By: Production performance

database/views/active_threats_view.sql
  └── Dependencies: ip_reputation, domain_reputation, hash_reputation, ioc_indicators
  └── Creates: active_threats_view (materialized)
  └── Used By: Dashboard, alerting

database/views/high_confidence_iocs.sql
  └── Dependencies: ioc_indicators, ip_reputation, domain_reputation, hash_reputation
  └── Creates: high_confidence_iocs (materialized)
  └── Used By: Automated blocking

database/views/threat_summary_stats.sql
  └── Dependencies: ALL reputation tables
  └── Creates: threat_summary_stats (materialized)
  └── Used By: Reporting, dashboards
```

### Database - Seed Data
```
database/seeds/initial_threat_categories.sql
  └── Dependencies: 001_initial_setup.sql (threat_categories table)
  └── Inserts: 37 threat categories
  └── Required By: ALL reputation tables (foreign key)

database/seeds/feed_sources_config.sql
  └── Dependencies: 001_initial_setup.sql (threat_feeds table)
  └── Inserts: 18 threat feed configurations
  └── Required By: Threat feed ingestion

database/seeds/test_ioc_data.sql
  └── Dependencies: ALL schemas + initial_threat_categories + feed_sources_config
  └── Inserts: Sample IOC data for testing
  └── Optional: Skip in production (-SkipTestData)
```

---

## 🔢 Level 4: Driver & Service Binary

### Kernel Driver Binary
```
src/kernel_driver/safeops.sys
  └── Dependencies:
      - driver.c
      - driver_part2.c
      - filter_engine.c
      - packet_capture.c
      - nic_management.c
      - performance.c
      - ioctl_handler.c
      - shared_memory.c
  └── Linker Dependencies:
      - ntoskrnl.lib
      - fwpkclnt.lib
      - ndis.lib
      - wdf01000.lib
  └── Build Tool: WDK nmake/msbuild

src/kernel_driver/safeops.inf
  └── Dependencies: safeops.sys
  └── Contains: Driver installation manifest
  └── Required By: Windows driver installation
```

### Userspace Service Binary
```
src/userspace_service/userspace_service.exe
  └── Dependencies:
      - service_main.c
      - ioctl_client.c
      - ring_reader.c
      - log_writer.c
      - rotation_manager.c
  └── Linker Dependencies:
      - kernel32.lib
      - advapi32.lib
      - psapi.lib
  └── Build Tool: cl.exe (MSVC)
```

---

## 📊 Dependency Statistics

### File Counts by Component

| Component | Files | Lines (est.) | External Deps |
|-----------|-------|--------------|---------------|
| Kernel Driver | 15 | 8,000+ | WDK (5 libs) |
| Userspace Service | 7 | 3,000+ | Win32 (3 libs) |
| Shared C Headers | 4 | 500+ | None |
| Shared Go | 37 | 6,000+ | 7 packages |
| Shared Rust | 10 | 2,000+ | 11 crates |
| Proto Definitions | 14 | 1,500+ | google.protobuf |
| Database Schemas | 10 | 8,000+ | PostgreSQL 16+ |
| Database Views | 3 | 500+ | Schema tables |
| Database Seeds | 3 | 300+ | Schema tables |
| **Total** | **103** | **30,000+** | - |

### External Dependencies

#### Go (go.mod)
```
github.com/go-redis/redis/v8    # Redis client
github.com/jackc/pgx/v5         # PostgreSQL driver
github.com/prometheus/client_golang  # Metrics
github.com/sirupsen/logrus      # Logging
github.com/spf13/viper          # Configuration
google.golang.org/grpc          # gRPC framework
gopkg.in/yaml.v3                # YAML parsing
```

#### Rust (Cargo.toml)
```
ipnet = "2.9"                   # IP/CIDR handling
cidr-utils = "0.6"              # CIDR utilities
ahash = "0.8"                   # Fast hashing
xxhash-rust = "0.8"             # xxHash
packed_simd_2 = "0.3"           # SIMD
crossbeam = "0.8"               # Lock-free data structures
parking_lot = "0.12"            # Fast mutex
prost = "0.12"                  # Protobuf
chrono = "0.4"                  # DateTime
thiserror = "1.0"               # Error derive
prometheus = "0.13"             # Metrics
```

#### Windows (WDK)
```
ntoskrnl.lib                    # Kernel functions
fwpkclnt.lib                    # WFP callouts
ndis.lib                        # NDIS functions
wdf01000.lib                    # WDF framework
wdmsec.lib                      # WDM security
```

---

## 🔧 Build Order Commands

### 1. Proto Generation (Level 0)
```powershell
cd proto
.\build.ps1
# Generates: build/proto/go/*.pb.go, build/proto/rust/*.rs
```

### 2. Database Setup (Level 0-3)
```powershell
cd database
.\init_database.ps1 -DatabaseName safeops_threat_intel
# Runs: 001-009 schemas → views → seeds
```

### 3. Shared Libraries (Level 1-2)
```powershell
# Rust
cd src/shared/rust
cargo build --release

# Go (verify dependencies)
cd src/shared/go
go mod tidy
go build ./...
```

### 4. Kernel Driver (Level 0-4)
```powershell
cd src/kernel_driver
nmake
# Produces: safeops.sys, safeops.inf
```

### 5. Userspace Service (Level 3)
```powershell
cd src/userspace_service
cl /Fe:userspace_service.exe *.c kernel32.lib advapi32.lib psapi.lib
```

---

## ✅ Verification Checklist

- [ ] All Level 0 files exist (proto/common.proto, shared/c/*.h, schemas/001)
- [ ] All Level 1 dependencies resolve (headers include correctly)
- [ ] All Level 2 implementations compile
- [ ] All Level 3 services link correctly
- [ ] Database migrations run in order
- [ ] Proto generation succeeds
- [ ] Final binaries build

---

**Generated:** 2025-12-17  
**Files Analyzed:** 103 source files  
**Phase:** 1 (Foundation Complete)  
**Next Phase:** Service implementations (firewall_engine, threat_intel, etc.)
