# SafeOps Protocol Buffers Documentation

## Overview

### What are Protocol Buffers?

Protocol Buffers (protobuf) is Google's language-neutral, platform-neutral, extensible mechanism for serializing structured data. Think of it as a more efficient, type-safe alternative to XML or JSON for defining data structures and service APIs.

### Why SafeOps Uses Protocol Buffers

SafeOps leverages Protocol Buffers for several critical advantages:

- **Language-Agnostic Service Definitions**: Define once, use in Go, Rust, Python, and more
- **Strong Typing & Schema Validation**: Compile-time type checking prevents runtime errors
- **Efficient Binary Serialization**: 3-10x smaller than JSON, faster parsing
- **Backward & Forward Compatibility**: Evolve APIs without breaking existing clients
- **Automatic Code Generation**: Generate idiomatic code for Go and Rust automatically
- **Native gRPC Support**: First-class support for high-performance RPC communication
- **Clear Service Contracts**: Self-documenting API definitions

### Role in SafeOps Architecture

Protocol Buffers serve as the foundation of SafeOps' microservices architecture:

- **Inter-Service Communication**: All services communicate via gRPC using these proto definitions
- **Type-Safe Contracts**: Compile-time guarantees that services speak the same language
- **API Definitions**: Single source of truth for all service interfaces
- **Data Consistency**: Ensures consistent data structures across all components

---

## Directory Structure

```
proto/
├── README.md                    # This file
├── build.sh                     # Linux/Mac build script
├── build.ps1                    # Windows PowerShell build script
├── gen/                         # Generated code output (gitignored)
│   ├── go/                      # Go generated code
│   └── rust/                    # Rust generated code
└── grpc/                        # Protocol Buffer definitions
    ├── common.proto             # Shared types and utilities
    ├── network_logger.proto     # Network traffic capture
    ├── firewall.proto           # Firewall engine
    ├── threat_intel.proto       # Threat intelligence
    ├── orchestrator.proto       # Service orchestration
    ├── dns_server.proto         # DNS query logging
    ├── dhcp_server.proto        # DHCP lease management
    ├── wifi_ap.proto            # WiFi access point
    ├── tls_proxy.proto          # TLS interception
    ├── ids_ips.proto            # IDS/IPS alerts
    ├── certificate_manager.proto # Certificate lifecycle
    ├── backup_restore.proto     # Backup/restore operations
    └── update_manager.proto     # Software updates
```

### Proto File Descriptions

| File | Purpose |
|------|---------|
| **common.proto** | Shared message types, enums, and utility messages used across all services (timestamps, IPs, pagination, health checks) |
| **network_logger.proto** | Network traffic logging, deep packet inspection, and query API |
| **firewall.proto** | Firewall rules, policies, connection tracking, and NAT management |
| **threat_intel.proto** | Threat intelligence feed management, reputation scoring, and IP/domain checking |
| **orchestrator.proto** | Service lifecycle management, monitoring, and inter-service coordination |
| **dns_server.proto** | DNS query logging, blacklist/whitelist management, and cache operations |
| **dhcp_server.proto** | DHCP lease management, reservation handling, and pool statistics |
| **wifi_ap.proto** | WiFi access point management, client control, and bandwidth limiting |
| **tls_proxy.proto** | TLS/SSL interception, certificate management, and domain rules |
| **ids_ips.proto** | Intrusion detection/prevention alerts, signature management, and IP blocking |
| **certificate_manager.proto** | Root CA management, certificate generation, and lifecycle operations |
| **backup_restore.proto** | Configuration backup, restoration, and scheduled backup management |
| **update_manager.proto** | Software update management, version control, and rollback operations |

---

## Prerequisites

### Protocol Buffers Compiler (protoc)

**Version Required:** 3.20.0 or later (recommended: 3.21.0+)

**Installation:**

- **Windows:**
  ```powershell
  # Using Chocolatey
  choco install protoc
  
  # Or download from GitHub releases
  # https://github.com/protocolbuffers/protobuf/releases
  ```

- **macOS:**
  ```bash
  brew install protobuf
  ```

- **Ubuntu/Debian:**
  ```bash
  sudo apt-get update
  sudo apt-get install protobuf-compiler
  ```

- **Arch Linux:**
  ```bash
  sudo pacman -S protobuf
  ```

**Verification:**
```bash
protoc --version
# Should output: libprotoc 3.21.0 (or newer)
```

### Go Plugins

Required for Go code generation:

**protoc-gen-go** (Protocol Buffers messages):
```bash
go install google.golang.org/protobuf/cmd/protoc-gen-go@latest
```

**protoc-gen-go-grpc** (gRPC services):
```bash
go install google.golang.org/grpc/cmd/protoc-gen-go-grpc@latest
```

**Verification:**
```bash
which protoc-gen-go
which protoc-gen-go-grpc
# Both should be in $GOPATH/bin or $HOME/go/bin
```

**Important:** Ensure `$GOPATH/bin` (or `$HOME/go/bin`) is in your `PATH`:
```bash
# Add to ~/.bashrc or ~/.zshrc
export PATH="$PATH:$(go env GOPATH)/bin"
```

### Rust Plugin (Optional)

Required for Rust code generation:

**protoc-gen-rust**:
```bash
cargo install protobuf-codegen
```

**Verification:**
```bash
which protoc-gen-rust
```

**Note:** Rust generation is optional. Go is the primary development language for SafeOps services.

---

## Building Generated Code

### Quick Start

**Linux/Mac:**
```bash
cd proto
chmod +x build.sh
./build.sh
```

**Windows:**
```powershell
cd proto
.\build.ps1
```

### Build Script Options

Both `build.sh` and `build.ps1` support the following options:

| Option | Description |
|--------|-------------|
| `--clean` / `-Clean` | Remove previously generated code before building |
| `--go-only` / `-GoOnly` | Generate only Go code (skip Rust) |
| `--rust-only` / `-RustOnly` | Generate only Rust code (skip Go) |
| `--help` / `-Help` | Display help message and usage examples |

**Examples:**

```bash
# Clean build (removes gen/ directory first)
./build.sh --clean

# Generate only Go code
./build.sh --go-only

# Generate only Rust code
./build.sh --rust-only

# Windows PowerShell equivalent
.\build.ps1 -Clean
.\build.ps1 -GoOnly
```

### Output Locations

Generated code is placed in the `gen/` directory:

- **Go:** `proto/gen/go/`
  - Contains `.pb.go` (message types) and `_grpc.pb.go` (service interfaces)
  
- **Rust:** `proto/gen/rust/`
  - Contains `.rs` files with message and service definitions
  - Includes auto-generated `mod.rs` for module declarations

### Generated Files

For each `.proto` file, the following code is generated:

**Go Output:**
- `<name>.pb.go` - Message type definitions
- `<name>_grpc.pb.go` - gRPC service client and server interfaces

**Rust Output:**
- `<name>.rs` - Combined message types and service definitions

**Example:**
```
network_logger.proto
  → network_logger.pb.go         (Go messages)
  → network_logger_grpc.pb.go    (Go gRPC)
  → network_logger.rs            (Rust)
```

---

## Protocol Buffer Best Practices

### Naming Conventions

**File Names:**
- Use `snake_case.proto` (e.g., `network_logger.proto`)
- Names should be descriptive of the service/domain

**Message Types:**
- Use `PascalCase` (e.g., `FirewallRule`, `PacketMetadata`)
- Should be nouns describing the data structure

**Service Names:**
- Use `PascalCase` ending in `Service` (e.g., `FirewallService`, `NetworkLoggerService`)

**Field Names:**
- Use `snake_case` (e.g., `packet_id`, `source_ip`, `created_at`)
- Should be descriptive and unambiguous

**Enum Types:**
- Enum names: `PascalCase` (e.g., `AlertSeverity`, `UpdateStatus`)
- Enum values: `SCREAMING_SNAKE_CASE` (e.g., `ALERT_SEVERITY_CRITICAL`, `UPDATE_STATUS_INSTALLED`)
- Always include `UNSPECIFIED = 0` as the default value

### Field Numbering

- **Never reuse field numbers** - This breaks backward compatibility
- **Reserve deprecated numbers:**
  ```protobuf
  message Example {
    reserved 2, 15, 9 to 11;
    reserved "old_field_name";
  }
  ```
- **Use ranges for organization:**
  - 1-15: Most frequently used fields (1-byte encoding)
  - 16-2047: Less frequently used fields (2-byte encoding)
  - 19000-19999: Reserved for internal use
  - 50000+: Extension fields

### Versioning and Compatibility

**Adding Fields:**
- ✅ Safe: New `optional` or `repeated` fields
- ✅ Safe: New enum values
- ⚠️ Document: Impact on existing code

**Modifying Fields:**
- ❌ Never: Change field number
- ❌ Never: Change field type (except compatible scalar upgrades)
- ❌ Never: Change field name in incompatible way
- ✅ Safe: Add `[deprecated = true]` option

**Deleting Fields:**
- Don't delete - mark as `reserved` instead:
  ```protobuf
  message Example {
    reserved 5, 8;
    reserved "old_field";
  }
  ```

### Documentation

- Use `//` comments for field and message documentation
- Document units, constraints, and expected values:
  ```protobuf
  message Example {
    // Unique packet identifier in format: pkt_<timestamp>_<uuid>
    string packet_id = 1;
    
    // Packet size in bytes (max: 65535)
    int32 packet_size = 2;
    
    // Connection timestamp in Unix milliseconds (UTC)
    int64 timestamp = 3;
  }
  ```

### Common Patterns

**Pagination:**
```protobuf
message ListRequest {
  int32 page_size = 1;    // Max: 1000
  string page_token = 2;   // Empty for first page
}

message ListResponse {
  repeated Item items = 1;
  string next_page_token = 2;
  int64 total_count = 3;
}
```

**Timestamps:**
```protobuf
import "google/protobuf/timestamp.proto";

message Event {
  google.protobuf.Timestamp created_at = 1;  // Preferred
  // Avoid: int64 created_at = 1;  // Unix timestamp
}
```

**Status Responses:**
```protobuf
message StatusResponse {
  StatusCode status = 1;
  string message = 2;
  string error = 3;       // Optional error details
}
```

---

##  Troubleshooting

### Common Issues

**1. `protoc: command not found`**
- Install Protocol Buffers compiler (see Prerequisites section)
- Verify with: `protoc --version`

**2. `protoc-gen-go: program not found`**
- Install Go plugins: `go install google.golang.org/protobuf/cmd/protoc-gen-go@latest`
- Add `$GOPATH/bin` to PATH
- Verify with: `which protoc-gen-go`

**3. `Import "grpc/common.proto" was not found`**
- Ensure you're running build script from `proto/` directory
- Check that `grpc/common.proto` exists
- Verify `--proto_path` is set correctly

**4. Generated files not found**
- Check `gen/go/` or `gen/rust/` directories
- Run build script with `--clean` to rebuild
- Look for error messages during build

**5. Version compatibility errors**
- Ensure protoc version is 3.20.0+
- Update Go plugins to latest versions
- Clear generated code and rebuild

### Getting Help

- **Protocol Buffers Documentation**: https://protobuf.dev/
- **gRPC Documentation**: https://grpc.io/docs/
- **Go protobuf Guide**: https://protobuf.dev/getting-started/gotutorial/
- **SafeOps Issues**: https://github.com/your-org/SafeOps/issues

---

## Development Workflow

### 1. Modify Proto Definitions

Edit `.proto` files in the `grpc/` directory:
```bash
vim grpc/firewall.proto
```

### 2. Regenerate Code

Run the build script:
```bash
./build.sh --clean
```

### 3. Update Service Implementations

Update Go/Rust code to use new proto definitions:
```bash
cd ../services/firewall
go mod tidy
go build
```

### 4. Test Changes

Run integration tests to verify compatibility:
```bash
cd ../tests
go test ./...
```

### 5. Commit Changes

Commit both `.proto` files and generated code:
```bash
git add proto/grpc/*.proto
git add proto/gen/
git commit -m "feat: update firewall proto with new fields"
```

---

## Version History

- **v0.2.0** (2025-01-12) - Complete gRPC proto definitions for all 13 services
- **v0.1.0** (2024-12-xx) - Initial proto structure and common types

---

## License

Copyright © 2024 SafeOps Project. All rights reserved.

This documentation and the associated proto definitions are proprietary and confidential.
