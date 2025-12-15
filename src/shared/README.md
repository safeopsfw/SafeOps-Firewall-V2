# SafeOps Shared Libraries

This directory contains shared utilities used across all SafeOps components, organized by language.

## Directory Structure

```
src/shared/
├── rust/           # Rust shared library
├── go/             # Go shared packages
└── c/              # C shared headers
```

## Rust Shared Library (`rust/`)

High-performance utilities for the Rust components:

| Module | Description |
|--------|-------------|
| `ip_utils` | IP parsing, CIDR matching, prefix tree lookup |
| `hash_utils` | xxHash3, aHash, consistent hashing |
| `memory_pool` | Thread-safe object pooling |
| `lock_free` | Lock-free queues, MPSC, ring buffers |
| `simd_utils` | Fast packet parsing, checksums |
| `time_utils` | Timestamps, stopwatch, rate limiting |
| `proto_utils` | Protobuf encode/decode helpers |
| `buffer_pool` | Buffer pooling, zero-copy views |
| `metrics` | Counter, Gauge, Histogram, Prometheus |
| `error` | Structured error types |

```bash
cd src/shared/rust
cargo build
cargo test
```

## Go Shared Packages (`go/`)

Common utilities for Go services:

| Package | Description |
|---------|-------------|
| `config` | Viper-based configuration with hot-reload |
| `logging` | Structured logging with logrus |
| `errors` | Structured errors with codes |
| `health` | Health check framework |
| `metrics` | Prometheus metrics wrappers |
| `utils` | Retry, rate limiting, validation |
| `redis` | Redis client with pub/sub |
| `postgres` | PostgreSQL pool, transactions, migrations |
| `grpc_client` | gRPC client with interceptors |

```bash
cd src/shared/go
go build ./...
go test ./...
```

## C Shared Headers (`c/`)

Shared structures for kernel-userspace communication:

| Header | Description |
|--------|-------------|
| `ring_buffer.h` | Ring buffer structures |
| `packet_structs.h` | Network packet structures |
| `ioctl_codes.h` | IOCTL command definitions |
| `shared_constants.h` | Common constants |

## Usage

### Rust
```rust
use safeops_shared::{ip_utils, hash_utils, metrics};
```

### Go
```go
import (
    "github.com/safeops/shared/config"
    "github.com/safeops/shared/logging"
)
```

### C
```c
#include "shared/ring_buffer.h"
#include "shared/packet_structs.h"
```
