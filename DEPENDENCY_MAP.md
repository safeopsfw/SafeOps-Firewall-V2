# SafeOps v2.0 - Complete File Interconnection Map

> **File-by-file dependency analysis: What uses what, compiled vs raw**
>
> Generated: 2025-12-17 | Phase 1 Complete | Ready for Phase 2

---

## 📊 Current Progress Visualization

```
SafeOps File Completion Status (Phase 1)
=========================================

FOUNDATION LAYER (100% Complete)
├── Proto Definitions     ████████████████████ 14/14 files
├── C Headers            ████████████████████  4/4  files
├── Database Schemas     ████████████████████ 16/16 files
├── Kernel Driver        ████████████████████ 15/15 files
├── Userspace Service    ████████████████████  7/7  files
└── Shared Libraries     ████████████████████ 61/61 files
    ├── Go (37 files)    ████████████████████ 100%
    ├── Rust (12 files)  ████████████████████ 100%
    └── C (4 files)      ████████████████████ 100%

SERVICE LAYER (0% - Phase 2)
├── Firewall Engine      ░░░░░░░░░░░░░░░░░░░░  0/~20 files
├── Threat Intel         ░░░░░░░░░░░░░░░░░░░░  0/~25 files
├── IDS/IPS              ░░░░░░░░░░░░░░░░░░░░  0/~30 files
├── DNS Server           ░░░░░░░░░░░░░░░░░░░░  0/~15 files
├── DHCP Server          ░░░░░░░░░░░░░░░░░░░░  0/~15 files
└── Other Services       ░░░░░░░░░░░░░░░░░░░░  0/~100 files

UI LAYER (0% - Phase 3)
└── Web UI               ░░░░░░░░░░░░░░░░░░░░  0/~50 files

TOTAL: ~117 files implemented / ~400 planned
```

---

## 🔄 File Usage Type Reference

| Usage Type | Symbol | Meaning |
|------------|--------|---------|
| **RAW** | 📄 | Source code imported/included directly |
| **COMPILED** | ⚙️ | Compiled library (.lib, .a, .so) linked |
| **GENERATED** | 🔧 | Auto-generated from source (proto→code) |
| **RUNTIME** | 🔌 | Used at runtime via IPC/API/database |

---

## 📁 FILE-BY-FILE INTERCONNECTION

### src/shared/c/ (C Headers - Always RAW)

```
┌─────────────────────────────────────────────────────────────────────────┐
│ shared_constants.h                                                       │
│ Usage: 📄 RAW (header-only, #include)                                    │
│ Size: ~150 lines                                                         │
├─────────────────────────────────────────────────────────────────────────┤
│ USED BY (Current):                                                       │
│   📄 → packet_structs.h          (includes for constants)               │
│   📄 → ring_buffer.h             (includes for buffer sizes)            │
│   📄 → kernel_driver/*.c         (throughinclude chain)                │
│   📄 → userspace_service/*.c     (through include chain)                │
├─────────────────────────────────────────────────────────────────────────┤
│ WILL BE USED BY (Future Phase 2):                                        │
│   📄 → firewall_engine (Rust FFI binding)                               │
│   📄 → threat_intel (Rust FFI binding)                                  │
└─────────────────────────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────────────────────────┐
│ packet_structs.h                                                         │
│ Usage: 📄 RAW (header-only, #include)                                    │
│ Size: ~280 lines                                                         │
├─────────────────────────────────────────────────────────────────────────┤
│ USED BY (Current):                                                       │
│   📄 → ring_buffer.h             (PACKET_INFO struct)                   │
│   📄 → kernel_driver/packet_capture.h                                   │
│   📄 → kernel_driver/filter_engine.h                                    │
│   📄 → userspace_service/ring_reader.c                                  │
│   📄 → userspace_service/log_writer.c                                   │
├─────────────────────────────────────────────────────────────────────────┤
│ WILL BE USED BY (Future):                                                │
│   📄 → firewall_engine/src/driver_interface (Rust FFI)                  │
│   📄 → ids_ips (Go CGO for packet parsing)                              │
└─────────────────────────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────────────────────────┐
│ ring_buffer.h                                                            │
│ Usage: 📄 RAW (header-only, #include)                                    │
│ Size: ~200 lines                                                         │
├─────────────────────────────────────────────────────────────────────────┤
│ USED BY (Current):                                                       │
│   📄 → kernel_driver/shared_memory.c  (ring buffer creation)            │
│   📄 → userspace_service/ring_reader.c (ring buffer reading)            │
├─────────────────────────────────────────────────────────────────────────┤
│ WILL BE USED BY (Future):                                                │
│   📄 → firewall_engine (if direct kernel communication)                 │
└─────────────────────────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────────────────────────┐
│ ioctl_codes.h                                                            │
│ Usage: 📄 RAW (header-only, #include)                                    │
│ Size: ~120 lines                                                         │
├─────────────────────────────────────────────────────────────────────────┤
│ USED BY (Current):                                                       │
│   📄 → kernel_driver/ioctl_handler.c  (IOCTL dispatch)                  │
│   📄 → userspace_service/ioctl_client.c (DeviceIoControl calls)         │
├─────────────────────────────────────────────────────────────────────────┤
│ WILL BE USED BY (Future):                                                │
│   📄 → firewall_engine (kernel communication)                           │
│   📄 → orchestrator (driver health checks)                              │
└─────────────────────────────────────────────────────────────────────────┘
```

---

### src/shared/go/ (Go Packages - COMPILED into services)

```
┌─────────────────────────────────────────────────────────────────────────┐
│ PACKAGE: errors/                                                         │
│ Usage: ⚙️ COMPILED (Go import, compiled into binary)                    │
│ Files: codes.go, errors.go, wrapping.go                                  │
│ Import: github.com/safeops/shared/errors                                 │
├─────────────────────────────────────────────────────────────────────────┤
│ USED BY (Current):                                                       │
│   ⚙️ → shared/go/config/*        (error wrapping)                       │
│   ⚙️ → shared/go/logging/*       (error logging)                        │
│   ⚙️ → shared/go/postgres/*      (DB errors)                            │
│   ⚙️ → shared/go/redis/*         (cache errors)                         │
│   ⚙️ → shared/go/grpc_client/*   (RPC errors)                           │
│   ⚙️ → shared/go/health/*        (health check errors)                  │
├─────────────────────────────────────────────────────────────────────────┤
│ WILL BE USED BY (ALL Phase 2 Go services):                               │
│   ⚙️ → ids_ips/                  (compiled into binary)                 │
│   ⚙️ → dns_server/               (compiled into binary)                 │
│   ⚙️ → dhcp_server/              (compiled into binary)                 │
│   ⚙️ → tls_proxy/                (compiled into binary)                 │
│   ⚙️ → wifi_ap/                  (compiled into binary)                 │
│   ⚙️ → orchestrator/             (compiled into binary)                 │
│   ⚙️ → certificate_manager/      (compiled into binary)                 │
│   ⚙️ → backup_restore/           (compiled into binary)                 │
│   ⚙️ → update_manager/           (compiled into binary)                 │
└─────────────────────────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────────────────────────┐
│ PACKAGE: config/                                                         │
│ Usage: ⚙️ COMPILED (Go import)                                          │
│ Files: config.go, env.go, validator.go, watcher.go, config_test.go      │
│ Import: github.com/safeops/shared/config                                 │
│ External Deps: github.com/spf13/viper, gopkg.in/yaml.v3                  │
├─────────────────────────────────────────────────────────────────────────┤
│ USED BY (Current - internal dependencies):                               │
│   ⚙️ → shared/go/logging/logger.go   (config-based log levels)         │
│   ⚙️ → shared/go/postgres/postgres.go (DB config)                       │
│   ⚙️ → shared/go/redis/redis.go      (cache config)                     │
│   ⚙️ → shared/go/grpc_client/client.go (gRPC config)                    │
├─────────────────────────────────────────────────────────────────────────┤
│ WILL BE USED BY (ALL Phase 2 services):                                  │
│   ⚙️ → Every Go service (compiled in, reads config/*.toml)             │
└─────────────────────────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────────────────────────┐
│ PACKAGE: logging/                                                        │
│ Usage: ⚙️ COMPILED (Go import)                                          │
│ Files: logger.go, levels.go, formatters.go, rotation.go, logger_test.go │
│ Import: github.com/safeops/shared/logging                                │
│ External Deps: github.com/sirupsen/logrus                                │
├─────────────────────────────────────────────────────────────────────────┤
│ USED BY (Current):                                                       │
│   ⚙️ → shared/go/postgres/*      (query logging)                        │
│   ⚙️ → shared/go/redis/*         (operation logging)                    │
│   ⚙️ → shared/go/grpc_client/*   (request logging)                      │
│   ⚙️ → shared/go/health/*        (health check logging)                 │
├─────────────────────────────────────────────────────────────────────────┤
│ WILL BE USED BY (ALL Phase 2 services):                                  │
│   ⚙️ → Every Go service (compiled in)                                   │
└─────────────────────────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────────────────────────┐
│ PACKAGE: postgres/                                                       │
│ Usage: ⚙️ COMPILED (Go import)                                          │
│ Files: postgres.go, transactions.go, bulk_insert.go, migrations.go      │
│ Import: github.com/safeops/shared/postgres                               │
│ External Deps: github.com/jackc/pgx/v5                                   │
├─────────────────────────────────────────────────────────────────────────┤
│ USED BY (Current):                                                       │
│   ⚙️ → shared/go/health/checks.go    (DB health check)                  │
├─────────────────────────────────────────────────────────────────────────┤
│ WILL BE USED BY (Database-connected services):                           │
│   ⚙️ → threat_intel/             (reputation queries)                   │
│   ⚙️ → ids_ips/                  (alert storage)                        │
│   ⚙️ → dns_server/               (domain filtering)                     │
│   ⚙️ → backup_restore/           (backup operations)                    │
│   ⚙️ → certificate_manager/      (cert storage)                         │
│   ⚙️ → dhcp_server/              (lease storage)                        │
└─────────────────────────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────────────────────────┐
│ PACKAGE: redis/                                                          │
│ Usage: ⚙️ COMPILED (Go import)                                          │
│ Files: redis.go, pubsub.go, pipeline.go, lua_scripts.go                  │
│ Import: github.com/safeops/shared/redis                                  │
│ External Deps: github.com/go-redis/redis/v8                              │
├─────────────────────────────────────────────────────────────────────────┤
│ USED BY (Current):                                                       │
│   ⚙️ → shared/go/health/checks.go    (Redis health check)               │
├─────────────────────────────────────────────────────────────────────────┤
│ WILL BE USED BY (Cache-enabled services):                                │
│   ⚙️ → threat_intel/             (reputation cache)                     │
│   ⚙️ → dns_server/               (DNS cache)                            │
│   ⚙️ → firewall_engine/          (rule cache via Rust FFI)              │
│   ⚙️ → orchestrator/             (service state)                        │
└─────────────────────────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────────────────────────┐
│ PACKAGE: grpc_client/                                                    │
│ Usage: ⚙️ COMPILED (Go import)                                          │
│ Files: client.go, interceptors.go, retry.go, circuit_breaker.go         │
│        load_balancer.go, retry_budget.go, service_discovery.go          │
│ Import: github.com/safeops/shared/grpc_client                            │
│ External Deps: google.golang.org/grpc                                    │
├─────────────────────────────────────────────────────────────────────────┤
│ WILL BE USED BY (ALL inter-service communication):                       │
│   ⚙️ → orchestrator/             (calls all services)                   │
│   ⚙️ → ids_ips/                  (calls threat_intel, firewall)         │
│   ⚙️ → dns_server/               (calls threat_intel)                   │
│   ⚙️ → tls_proxy/                (calls certificate_manager)            │
│   ⚙️ → update_manager/           (calls orchestrator)                   │
│   ⚙️ → ui/backend/               (calls all services)                   │
└─────────────────────────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────────────────────────┐
│ PACKAGE: metrics/                                                        │
│ Usage: ⚙️ COMPILED (Go import)                                          │
│ Files: metrics.go, registry.go, http_handler.go                          │
│ Import: github.com/safeops/shared/metrics                                │
│ External Deps: github.com/prometheus/client_golang                       │
├─────────────────────────────────────────────────────────────────────────┤
│ WILL BE USED BY (ALL services with /metrics endpoint):                   │
│   ⚙️ → ALL Go services (compiled in, exposes :9090/metrics)            │
└─────────────────────────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────────────────────────┐
│ PACKAGE: health/                                                         │
│ Usage: ⚙️ COMPILED (Go import)                                          │
│ Files: health.go, checks.go                                              │
│ Import: github.com/safeops/shared/health                                 │
├─────────────────────────────────────────────────────────────────────────┤
│ WILL BE USED BY (ALL services):                                          │
│   ⚙️ → ALL Go services (health check endpoints)                         │
│   ⚙️ → orchestrator/ (calls health checks on all services)              │
└─────────────────────────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────────────────────────┐
│ PACKAGE: utils/                                                          │
│ Usage: ⚙️ COMPILED (Go import)                                          │
│ Files: retry.go, rate_limit.go, bytes.go, strings.go, validation.go     │
│ Import: github.com/safeops/shared/utils                                  │
├─────────────────────────────────────────────────────────────────────────┤
│ WILL BE USED BY:                                                         │
│   ⚙️ → ALL Go services (utility functions)                              │
└─────────────────────────────────────────────────────────────────────────┘
```

---

### src/shared/rust/ (Rust Crate - COMPILED as library)

```
┌─────────────────────────────────────────────────────────────────────────┐
│ CRATE: safeops_shared                                                    │
│ Usage: ⚙️ COMPILED (Cargo dependency, static library)                   │
│ Output: libsafeops_shared.rlib OR safeops_shared.dll (cdylib)           │
│ Cargo.toml declares: crate-type = ["lib", "cdylib"]                      │
├─────────────────────────────────────────────────────────────────────────┤
│ Files and Their Individual Usage:                                        │
├─────────────────────────────────────────────────────────────────────────┤
│                                                                          │
│ src/lib.rs                                                               │
│   → Module root, re-exports all other modules                            │
│   → Usage: 📄 RAW (Rust mod declarations)                               │
│                                                                          │
│ src/error.rs                                                             │
│   → Contains: SafeOpsError enum, Result<T> alias                         │
│   → Usage: ⚙️ COMPILED into all Rust services                           │
│   → Used by: ALL other modules in this crate                             │
│   → Will be used by: firewall_engine, threat_intel                       │
│                                                                          │
│ src/ip_utils.rs                                                          │
│   → Contains: parse_ip(), is_private(), cidr_contains()                  │
│   → Usage: ⚙️ COMPILED                                                  │
│   → Used by: (internal validation)                                       │
│   → Will be used by: firewall_engine (rule matching)                     │
│   →                   threat_intel (IP reputation)                       │
│   →                   dns_server (via FFI if needed)                     │
│                                                                          │
│ src/hash_utils.rs                                                        │
│   → Contains: fast_hash(), xxh3(), ahash_map()                           │
│   → Usage: ⚙️ COMPILED                                                  │
│   → Will be used by: firewall_engine (fast rule lookup)                  │
│   →                   ids_ips (signature matching)                       │
│                                                                          │
│ src/memory_pool.rs                                                       │
│   → Contains: ObjectPool<T>, PooledObject<T>                             │
│   → Usage: ⚙️ COMPILED                                                  │
│   → Will be used by: firewall_engine (packet buffer reuse)               │
│   →                   threat_intel (connection pooling)                  │
│                                                                          │
│ src/lock_free.rs                                                         │
│   → Contains: LockFreeQueue, AtomicCounter                               │
│   → Usage: ⚙️ COMPILED                                                  │
│   → Will be used by: firewall_engine (high-perf packet processing)       │
│                                                                          │
│ src/simd_utils.rs                                                        │
│   → Contains: SIMD byte search, memcmp acceleration                      │
│   → Usage: ⚙️ COMPILED                                                  │
│   → Will be used by: ids_ips (deep packet inspection)                    │
│                                                                          │
│ src/time_utils.rs                                                        │
│   → Contains: now_utc(), format_timestamp()                              │
│   → Usage: ⚙️ COMPILED                                                  │
│   → Will be used by: ALL Rust services                                   │
│                                                                          │
│ src/proto_utils.rs                                                       │
│   → Contains: Protobuf encode/decode helpers                             │
│   → Usage: ⚙️ COMPILED                                                  │
│   → Will be used by: ALL Rust gRPC services                              │
│                                                                          │
│ src/buffer_pool.rs                                                       │
│   → Contains: BufferPool, reusable Vec<u8>                               │
│   → Usage: ⚙️ COMPILED                                                  │
│   → Will be used by: firewall_engine, threat_intel                       │
│                                                                          │
│ src/metrics.rs                                                           │
│   → Contains: Prometheus metric wrappers                                 │
│   → Usage: ⚙️ COMPILED                                                  │
│   → Will be used by: ALL Rust services                                   │
└─────────────────────────────────────────────────────────────────────────┘
```

---

### proto/grpc/ (Protocol Buffers - GENERATED)

```
┌─────────────────────────────────────────────────────────────────────────┐
│ Proto Files → Generated Code Flow                                       │
├─────────────────────────────────────────────────────────────────────────┤
│                                                                          │
│ common.proto                                                             │
│   → Usage: 🔧 GENERATED (protoc generates code)                         │
│   → Generates: build/proto/go/common.pb.go                              │
│   →            build/proto/rust/common.rs (planned)                     │
│   → Used by: ALL other .proto files (import "common.proto")            │
│   → Runtime: Types compiled into service binaries                       │
│                                                                          │
│ firewall.proto                                                           │
│   → Generates: firewall.pb.go, firewall_grpc.pb.go                      │
│   → Used by: firewall_engine (server), orchestrator (client)            │
│   →          ui/backend (client)                                        │
│                                                                          │
│ threat_intel.proto                                                       │
│   → Generates: threat_intel.pb.go, threat_intel_grpc.pb.go              │
│   → Used by: threat_intel (server), ids_ips (client)                    │
│   →          dns_server (client), firewall_engine (client)              │
│                                                                          │
│ network_manager.proto                                                    │
│   → Generates: network_manager.pb.go, network_manager_grpc.pb.go        │
│   → Used by: kernel_driver interface, orchestrator                      │
│                                                                          │
│ [Similar pattern for all 14 proto files...]                              │
│                                                                          │
├─────────────────────────────────────────────────────────────────────────┤
│ Build Command: proto/build.ps1                                           │
│ Output Location: build/proto/go/, build/proto/rust/                      │
│ Runtime Usage: ⚙️ COMPILED into each service binary                    │
└─────────────────────────────────────────────────────────────────────────┘
```

---

### src/kernel_driver/ (Kernel Code - COMPILED to .sys)

```
┌─────────────────────────────────────────────────────────────────────────┐
│ Kernel Driver Files → Single Binary Output                              │
├─────────────────────────────────────────────────────────────────────────┤
│                                                                          │
│ driver.h                          │ Usage: 📄 RAW (#include)            │
│   ↓ included by                                                          │
│ driver.c                          │ Usage: ⚙️ COMPILED → safeops.obj   │
│ driver_part2.c                    │ Usage: ⚙️ COMPILED → safeops2.obj  │
│ ioctl_handler.h + .c              │ Usage: ⚙️ COMPILED → ioctl.obj     │
│ shared_memory.h + .c              │ Usage: ⚙️ COMPILED → shmem.obj     │
│ filter_engine.h + .c              │ Usage: ⚙️ COMPILED → filter.obj    │
│ packet_capture.h + .c             │ Usage: ⚙️ COMPILED → capture.obj   │
│ nic_management.h + .c             │ Usage: ⚙️ COMPILED → nic.obj       │
│ performance.h + .c                │ Usage: ⚙️ COMPILED → perf.obj      │
│   ↓ linked together                                                      │
│ safeops.sys                       │ Final kernel driver binary           │
│ safeops.inf                       │ Installation manifest                │
│                                                                          │
├─────────────────────────────────────────────────────────────────────────┤
│ RUNTIME CONNECTION TO OTHER COMPONENTS:                                  │
│                                                                          │
│ safeops.sys ←──🔌 RUNTIME (IOCTL)──→ userspace_service.exe              │
│             ←──🔌 RUNTIME (shared memory)──→ ring_reader.c               │
│                                                                          │
│ Future connections:                                                      │
│ safeops.sys ←──🔌 RUNTIME──→ firewall_engine (via userspace bridge)     │
└─────────────────────────────────────────────────────────────────────────┘
```

---

### src/userspace_service/ (User Service - COMPILED to .exe)

```
┌─────────────────────────────────────────────────────────────────────────┐
│ Userspace Service Files → Single Binary Output                          │
├─────────────────────────────────────────────────────────────────────────┤
│                                                                          │
│ userspace_service.h               │ Usage: 📄 RAW (#include)            │
│   ↓ included by all                                                      │
│ service_main.c                    │ Usage: ⚙️ COMPILED → main.obj      │
│   ├── includes ring_reader.h                                             │
│   ├── includes log_writer.h                                              │
│   ├── includes rotation_manager.h                                        │
│   └── includes ioctl_client.h                                            │
│                                                                          │
│ ioctl_client.c                    │ Usage: ⚙️ COMPILED → ioctl.obj     │
│ ring_reader.c                     │ Usage: ⚙️ COMPILED → ring.obj      │
│ log_writer.c                      │ Usage: ⚙️ COMPILED → log.obj       │
│ rotation_manager.c                │ Usage: ⚙️ COMPILED → rotate.obj    │
│   ↓ linked together                                                      │
│ userspace_service.exe             │ Final Windows service binary         │
│                                                                          │
├─────────────────────────────────────────────────────────────────────────┤
│ RUNTIME CONNECTIONS:                                                     │
│                                                                          │
│ userspace_service.exe                                                    │
│   ←──🔌 RUNTIME──→ safeops.sys (IOCTL + shared memory)                  │
│   ←──🔌 RUNTIME──→ logs/*.json (file output)                            │
│                                                                          │
│ Future:                                                                  │
│   ←──🔌 RUNTIME──→ orchestrator (gRPC health check)                     │
│   ←──🔌 RUNTIME──→ network_logger (log forwarding)                      │
└─────────────────────────────────────────────────────────────────────────┘
```

---

### database/ (SQL - RUNTIME database connection)

```
┌─────────────────────────────────────────────────────────────────────────┐
│ Database Files → PostgreSQL Runtime                                     │
├─────────────────────────────────────────────────────────────────────────┤
│                                                                          │
│ ALL .sql files are 📄 RAW SQL scripts executed by psql                  │
│ They CREATE tables/indexes that services connect to at 🔌 RUNTIME       │
│                                                                          │
│ Execution Order (init_database.ps1):                                     │
│   001_initial_setup.sql     → Creates: threat_categories, threat_feeds  │
│   002_ip_reputation.sql     → Creates: ip_reputation, ip_*_history      │
│   003_domain_reputation.sql → Creates: domain_reputation, domain_*      │
│   004_hash_reputation.sql   → Creates: hash_reputation, malware_*       │
│   005_ioc_storage.sql       → Creates: ioc_indicators, ioc_*            │
│   006_proxy_anonymizer.sql  → Creates: proxy_*, vpn_*, tor_*            │
│   007_geolocation.sql       → Creates: ip_geolocation, country_*        │
│   008_threat_feeds.sql      → Creates: feed_*, update_history           │
│   009_asn_data.sql          → Creates: asn_data, asn_*                  │
│   999_indexes_*.sql         → Creates: performance indexes              │
│                                                                          │
│ views/*.sql                 → Creates: materialized views               │
│ seeds/*.sql                 → Inserts: initial data                     │
│                                                                          │
├─────────────────────────────────────────────────────────────────────────┤
│ RUNTIME CONNECTIONS FROM SERVICES:                                       │
│                                                                          │
│ PostgreSQL Database ←──🔌 RUNTIME (pgx)──→ threat_intel service         │
│                    ←──🔌 RUNTIME (pgx)──→ ids_ips service               │
│                    ←──🔌 RUNTIME (pgx)──→ dns_server service            │
│                    ←──🔌 RUNTIME (pgx)──→ backup_restore service        │
│                    ←──🔌 RUNTIME (pgx)──→ certificate_manager           │
└─────────────────────────────────────────────────────────────────────────┘
```

---

## 🏗️ Future Service File Dependencies

### Phase 2 Service → Shared Library Usage

```
┌────────────────────────────────────────────────────────────────────────────┐
│ SERVICE              │ SHARED GO        │ SHARED RUST    │ RUNTIME DB     │
├──────────────────────┼──────────────────┼────────────────┼────────────────┤
│ firewall_engine      │ (none - Rust)    │ ALL modules    │ Redis          │
│ threat_intel         │ (none - Rust)    │ ALL modules    │ PostgreSQL     │
│ ids_ips              │ ALL packages     │ via FFI        │ PostgreSQL     │
│ dns_server           │ ALL packages     │ (none)         │ PostgreSQL     │
│ dhcp_server          │ ALL packages     │ (none)         │ PostgreSQL     │
│ tls_proxy            │ ALL packages     │ (none)         │ (none)         │
│ wifi_ap              │ ALL packages     │ (none)         │ (none)         │
│ orchestrator         │ ALL packages     │ (none)         │ Redis          │
│ certificate_manager  │ ALL packages     │ (none)         │ PostgreSQL     │
│ backup_restore       │ ALL packages     │ (none)         │ PostgreSQL     │
│ update_manager       │ ALL packages     │ (none)         │ (none)         │
│ ui/backend           │ ALL packages     │ (none)         │ (none)         │
└────────────────────────────────────────────────────────────────────────────┘

Legend:
  ALL packages = errors, config, logging, postgres, redis, grpc_client, 
                 health, metrics, utils (compiled into service binary)
  ALL modules  = error, ip_utils, hash_utils, memory_pool, lock_free,
                 time_utils, proto_utils, metrics (compiled into binary)
  via FFI      = Rust library called from Go using cgo
```

---

## 📋 Quick Reference: Compiled vs Raw

| Code Type | Usage | Example |
|-----------|-------|---------|
| **.h files** | 📄 RAW always | `#include "packet_structs.h"` |
| **.c files** | ⚙️ COMPILED to .obj → linked | `driver.c` → `safeops.sys` |
| **.go files** | ⚙️ COMPILED into service binary | `config.go` → `ids_ips.exe` |
| **.rs files** | ⚙️ COMPILED into .rlib/.dll | `ip_utils.rs` → `libsafeops_shared.rlib` |
| **.proto files** | 🔧 GENERATED → .pb.go/.rs | `firewall.proto` → `firewall.pb.go` |
| **.sql files** | 📄 RAW executed by psql | Creates tables at install time |
| **Database connection** | 🔌 RUNTIME via pgx/redis | Service queries DB at runtime |
| **gRPC calls** | 🔌 RUNTIME via HTTP/2 | Service-to-service calls |
| **IOCTL calls** | 🔌 RUNTIME via DeviceIoControl | Userspace → kernel communication |

---

**Generated:** 2025-12-17  
**Phase:** 1 Complete (117 files) | Phase 2 Ready (shared libraries)
