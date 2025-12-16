# SafeOps Protocol Buffers Documentation

## Introduction

### What Are Protocol Buffers?

Protocol Buffers (protobuf) is Google's language-neutral, platform-neutral, extensible mechanism for serializing structured data. Think of it as a more efficient, type-safe alternative to XML or JSON for defining data structures and service APIs.

**Key Benefits:**
- **Strong Typing**: Compile-time type checking prevents runtime errors
- **Efficient Serialization**: 3-10x smaller than JSON, faster parsing
- **Backward & Forward Compatibility**: Evolve APIs without breaking existing clients
- **Multi-Language Support**: Generate code for Go, Rust, Python, C++, Java, and more
- **Native gRPC Support**: First-class integration with high-performance RPC framework
- **Self-Documenting**: Service contracts are clear and explicit

### Why SafeOps Uses Protocol Buffers

SafeOps leverages Protocol Buffers as the foundation of its microservices architecture:

- **Inter-Service Communication**: All services communicate via gRPC using these proto definitions
- **Type-Safe Contracts**: Compile-time guarantees that services speak the same language
- **API Definitions**: Single source of truth for all service interfaces
- **Data Consistency**: Ensures consistent data structures across all components
- **Version Control**: API contracts are versioned alongside code

### Directory Purpose

This `proto/` directory serves as:
- **Central Location** for all gRPC service contracts
- **Source of Truth** for inter-service communication protocols
- **Shared Definitions** ensuring client-server compatibility
- **Version-Controlled** API contracts tracked in Git

---

## Directory Structure

```
proto/
├── README.md                      # This comprehensive documentation
├── build.ps1                      # Windows PowerShell build script
├── build.sh                       # Linux/Unix bash build script
└── grpc/                          # Protocol Buffer definitions
    ├── common.proto               # Shared types, enums, and utilities
    ├── orchestrator.proto         # Service lifecycle and coordination
    ├── firewall.proto             # Packet filtering and NAT
    ├── threat_intel.proto         # Threat intelligence feeds
    ├── ids_ips.proto              # Intrusion detection/prevention
    ├── network_logger.proto       # Centralized network logging
    ├── dns_server.proto           # DNS resolution with filtering
    ├── dhcp_server.proto          # IP address management
    ├── tls_proxy.proto            # SSL/TLS termination and inspection
    ├── wifi_ap.proto              # Wireless network management
    ├── backup_restore.proto       # System backup and disaster recovery
    ├── certificate_manager.proto  # Certificate lifecycle management
    ├── update_manager.proto       # System updates and patching
    └── network_manager.proto      # Network configuration and topology
```

### Proto File Descriptions

| File | Purpose | RPC Methods |
|------|---------|-------------|
| **common.proto** | Shared message types, enums, and utility messages used across all services (timestamps, IPs, pagination, health checks) | N/A (shared types only) |
| **orchestrator.proto** | Service lifecycle management, health monitoring, metrics collection, and inter-service coordination | 8 methods |
| **firewall.proto** | Firewall rules, policies, connection tracking, NAT management, and DDoS protection | 16 methods |
| **threat_intel.proto** | Threat intelligence feed management, reputation scoring, IP/domain lookups, and IOC tracking | 15 methods |
| **ids_ips.proto** | Intrusion detection/prevention alerts, signature management, IP blocking, and attack mitigation | 17 methods |
| **network_logger.proto** | High-throughput network event logging, querying, streaming, and log retention management | 18 methods |
| **dns_server.proto** | DNS resolution, caching, threat-integrated filtering, DNSSEC validation, and custom rules | 23 methods |
| **dhcp_server.proto** | IP address assignment, lease tracking, static reservations, and Dynamic DNS integration | 24 methods |
| **tls_proxy.proto** | SSL/TLS termination, SNI routing, certificate management, and traffic inspection | 25 methods |
| **wifi_ap.proto** | WiFi access point management, SSID control, client management, and guest network configuration | 27 methods |
| **backup_restore.proto** | Configuration backup, scheduled backups, restoration, retention policies, and storage management | 18 methods |
| **certificate_manager.proto** | Certificate generation, ACME integration, CA operations, validation, and expiration tracking | 18 methods |
| **update_manager.proto** | Software update management, version control, rollback, scheduling, and health monitoring | 14 methods (11 unary + 3 streaming) |
| **network_manager.proto** | Network interface configuration, routing, VLANs, bridges, topology discovery, and monitoring | 23 methods (20 unary + 3 streaming) |

**Total:** 14 proto files defining **250+ RPC methods** across the SafeOps platform.

### Generated Code Location

After running the build scripts, generated code is placed in:

```
build/proto/
├── go/                            # Go generated code
│   ├── common/                    # common.proto → common.pb.go
│   ├── orchestrator/              # orchestrator.proto → orchestrator.pb.go + orchestrator_grpc.pb.go
│   ├── firewall/                  # firewall.proto → firewall.pb.go + firewall_grpc.pb.go
│   ├── threat_intel/              # And so on for all services...
│   ├── ids_ips/
│   ├── network_logger/
│   ├── dns_server/
│   ├── dhcp_server/
│   ├── tls_proxy/
│   ├── wifi_ap/
│   ├── backup_restore/
│   ├── certificate_manager/
│   ├── update_manager/
│   └── network_manager/
└── rust/                          # Rust build template
    └── build.rs.template          # Template for Rust services using tonic-build
```

**Per Service Output:**
- `<service>.pb.go` - Protocol buffer message type definitions
- `<service>_grpc.pb.go` - gRPC service client and server interfaces

---

## Build Instructions

### Prerequisites

#### 1. Protocol Buffer Compiler (protoc)

**Required Version:** 3.19.0 or later (recommended: 3.21.0+)

**Installation:**

**Windows:**
```powershell
# Using Chocolatey
choco install protoc

# Or download from GitHub releases
# https://github.com/protocolbuffers/protobuf/releases
```

**macOS:**
```bash
brew install protobuf
```

**Ubuntu/Debian:**
```bash
sudo apt-get update
sudo apt-get install protobuf-compiler
```

**Arch Linux:**
```bash
sudo pacman -S protobuf
```

**Verification:**
```bash
protoc --version
# Should output: libprotoc 3.21.0 (or newer)
```

#### 2. Go Protocol Buffer Plugins

Required for Go code generation:

**protoc-gen-go** (Protocol Buffer messages):
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

#### 3. Go Toolchain

**Required Version:** Go 1.19 or later (recommended: 1.21+)

**Verification:**
```bash
go version
# Should output: go version go1.21+ ...
```

### Building Generated Code

#### Linux/macOS Build

```bash
# From proto directory
cd proto
chmod +x build.sh
./build.sh

# With options
./build.sh --clean            # Remove existing generated code first
./build.sh --verbose          # Show detailed compilation output
./build.sh --check            # Syntax validation only (no code generation)
./build.sh --parallel         # Enable parallel compilation (requires GNU parallel)

# From project root using Makefile
make proto                    # Runs proto build script
```

#### Windows Build

```powershell
# From proto directory
cd proto
.\build.ps1

# With options
.\build.ps1 -Clean            # Remove existing generated code first
.\build.ps1 -VerboseOutput    # Show detailed compilation output
.\build.ps1 -CheckOnly        # Syntax validation only (no code generation)

# From project root using Makefile (if using make on Windows)
make proto-windows            # Runs Windows proto build script
```

### Verifying Build Success

After running the build script, verify:

1. **Check Generated Files:**
   ```bash
   ls -la build/proto/go/
   # Should see directories for all 14 services
   ```

2. **Update Go Dependencies:**
   ```bash
   cd ..  # Return to project root
   go mod tidy
   ```

3. **Verify Compilation:**
   ```bash
   go build ./...
   # Should complete without errors
   ```

4. **Run Tests:**
   ```bash
   go test ./...
   ```

---

## Proto File Guidelines

### Writing New Proto Files

**Basic Structure:**
```protobuf
syntax = "proto3";

package safeops.service_name;

import "common.proto";

option go_package = "safeops/build/proto/go/service_name";

// Service definition
service ServiceNameService {
  rpc MethodName(MethodNameRequest) returns (MethodNameResponse);
}

// Request and response messages
message MethodNameRequest {
  string field_name = 1;
}

message MethodNameResponse {
  common.Status status = 1;
  string result = 2;
}
```

**Naming Conventions:**
- **File Names:** Use `snake_case.proto` (e.g., `network_logger.proto`)
- **Package Names:** Use `safeops.service_name` pattern
- **Service Names:** Use `PascalCase` ending in `Service` (e.g., `FirewallService`)
- **Message Types:** Use `PascalCase` (e.g., `FirewallRule`, `PacketMetadata`)
- **Field Names:** Use `snake_case` (e.g., `packet_id`, `source_ip`, `created_at`)
- **Enum Types:** `PascalCase` for name, `SCREAMING_SNAKE_CASE` for values
- **RPC Methods:** Use `PascalCase` verbs (e.g., `CreateRule`, `ListConnections`, `GetStatus`)

**Required Elements:**
- `syntax = "proto3";` declaration
- Package name following `safeops.<service>` pattern
- `import "common.proto";` for shared types
- `option go_package` for Go module path
- Both request and response messages for each RPC
- Comprehensive field documentation comments

### Message Design Principles

**Keep Messages Focused:**
```protobuf
// ✅ Good: Single-purpose message
message CreateFirewallRuleRequest {
  string rule_name = 1;
  string source_ip = 2;
  string dest_ip = 3;
  string action = 4;
}

// ❌ Bad: Kitchen sink message
message FirewallRequest {
  string action_type = 1;  // create, update, delete, list...
  string rule_name = 2;
  // ... dozens of optional fields ...
}
```

**Use Nested Messages for Complex Structures:**
```protobuf
message FirewallRule {
  string id = 1;
  string name = 2;
  MatchConditions match = 3;  // Nested message
  RuleAction action = 4;        // Nested message
}

message MatchConditions {
  string source_ip = 1;
  string dest_ip = 2;
  repeated uint32 ports = 3;
}
```

**Define Enums for Fixed Value Sets:**
```protobuf
enum Protocol {
  PROTOCOL_UNKNOWN = 0;  // Always include UNKNOWN = 0
  PROTOCOL_TCP = 1;
  PROTOCOL_UDP = 2;
  PROTOCOL_ICMP = 3;
}
```

**Use Appropriate Field Types:**
```protobuf
// ✅ Good: Structured types
message Connection {
  common.IPAddress source_ip = 1;
  common.Timestamp created_at = 2;
  uint32 port = 3;
}

// ❌ Bad: String abuse
message Connection {
  string source_ip = 1;      // Use IPAddress type
  string created_at = 2;     // Use Timestamp type
  string port = 3;           // Use uint32
}
```

### Service Design Principles

**One Service Per Proto File:**
```protobuf
// ✅ Good: Matches component architecture
service FirewallService {
  rpc CreateRule(CreateRuleRequest) returns (RuleResponse);
  rpc DeleteRule(DeleteRuleRequest) returns (RuleResponse);
  // ... other firewall methods
}

// ❌ Bad: Multiple unrelated services
service MixedService {
  rpc CreateFirewallRule(...) returns (...);
  rpc QueryDNS(...) returns (...);
  rpc AssignIPAddress(...) returns (...);
}
```

**Group Related RPCs:**
```protobuf
service NetworkLoggerService {
  // Logging Methods
  rpc LogConnection(LogConnectionRequest) returns (LogResponse);
  rpc BulkLogEvents(stream LogEventRequest) returns (BulkLogResponse);
  
  // Query Methods
  rpc QueryLogs(QueryRequest) returns (QueryResponse);
  rpc SearchLogs(SearchRequest) returns (SearchResponse);
  
  // Statistics Methods
  rpc GetStats(GetStatsRequest) returns (StatsResponse);
  rpc GetStorageUtilization(GetStorageRequest) returns (StorageResponse);
}
```

**Use Streaming for Appropriate Cases:**
```protobuf
service NetworkLoggerService {
  // Server streaming: Long-running queries
  rpc StreamLogs(StreamRequest) returns (stream LogEvent);
  
  // Client streaming: Bulk uploads
  rpc BulkLogEvents(stream LogEventRequest) returns (BulkLogResponse);
  
  // Bidirectional streaming: Real-time monitoring
  rpc MonitorTraffic(stream MonitorRequest) returns (stream TrafficEvent);
}
```

---

## Common Proto Patterns

### Standard Request/Response Pattern

```protobuf
// Standard RPC pattern
service ExampleService {
  rpc CreateResource(CreateResourceRequest) returns (CreateResourceResponse);
}

message CreateResourceRequest {
  string name = 1;              // Required parameters
  string description = 2;
  bool enabled = 3;
}

message CreateResourceResponse {
  string resource_id = 1;       // Created resource ID
  common.Status status = 2;     // Operation status
  string message = 3;           // Human-readable message
}
```

### Pagination Pattern

```protobuf
message ListResourcesRequest {
  uint32 page_size = 1;         // Max items per page (default: 50, max: 1000)
  string page_token = 2;        // Empty for first page
}

message ListResourcesResponse {
  repeated Resource resources = 1;
  string next_page_token = 2;   // Empty if no more pages
  uint32 total_count = 3;       // Total items across all pages
}
```

### Filtering Pattern

```protobuf
message ListFirewallRulesRequest {
  string name_filter = 1;       // Filter by name (supports wildcards)
  RuleAction action_filter = 2; // Filter by action
  bool enabled_only = 3;        // Only enabled rules
  common.Pagination pagination = 4;
}
```

### Streaming Patterns

**Server Streaming (Log Tailing):**
```protobuf
service NetworkLoggerService {
  rpc TailLogs(TailLogsRequest) returns (stream LogEvent);
}

message TailLogsRequest {
  string query = 1;
  common.Timestamp since = 2;
}
```

**Client Streaming (Bulk Upload):**
```protobuf
service NetworkLoggerService {
  rpc BulkLogEvents(stream LogEventRequest) returns (BulkLogResponse);
}
```

**Bidirectional Streaming (Real-Time Monitoring):**
```protobuf
service NetworkManagerService {
  rpc MonitorInterfaces(stream MonitorRequest) returns (stream InterfaceEvent);
}
```

### Error Handling Pattern

```protobuf
message OperationResponse {
  common.Status status = 1;     // SUCCESS, FAILURE, etc.
  string message = 2;           // Human-readable message
  ErrorInfo error = 3;          // Detailed error if status != SUCCESS
}

message ErrorInfo {
  string error_code = 1;        // Machine-readable error code
  string error_message = 2;     // Detailed error description
  repeated string details = 3;  // Additional context
}
```

---

## Integration with Go Code

### Importing Generated Code

```go
import (
    // Import generated proto packages
    common "safeops/build/proto/go/common"
    firewall "safeops/build/proto/go/firewall"
    orchestrator "safeops/build/proto/go/orchestrator"
    
    // Import gRPC dependencies
    "google.golang.org/grpc"
    "google.golang.org/grpc/credentials/insecure"
)
```

### Implementing a Service

```go
package main

import (
    "context"
    pb "safeops/build/proto/go/firewall"
)

// FirewallServer implements the generated FirewallServiceServer interface
type FirewallServer struct {
    pb.UnimplementedFirewallServiceServer  // Embed for forward compatibility
}

// CreateRule implements the CreateRule RPC method
func (s *FirewallServer) CreateRule(
    ctx context.Context,
    req *pb.CreateRuleRequest,
) (*pb.RuleResponse, error) {
    // Implementation logic here
    return &pb.RuleResponse{
        RuleId: "rule-12345",
        Status: &pb.Status{
            Code: pb.StatusCode_SUCCESS,
            Message: "Rule created successfully",
        },
    }, nil
}

func main() {
    lis, _ := net.Listen("tcp", ":50051")
    grpcServer := grpc.NewServer()
    
    // Register the service
    pb.RegisterFirewallServiceServer(grpcServer, &FirewallServer{})
    
    grpcServer.Serve(lis)
}
```

### Creating a Client

```go
package main

import (
    "context"
    "log"
    
    pb "safeops/build/proto/go/firewall"
    "google.golang.org/grpc"
    "google.golang.org/grpc/credentials/insecure"
)

func main() {
    // Connect to the gRPC server
    conn, err := grpc.Dial("localhost:50051", 
        grpc.WithTransportCredentials(insecure.NewCredentials()))
    if err != nil {
        log.Fatalf("Failed to connect: %v", err)
    }
    defer conn.Close()
    
    // Create client stub
    client := pb.NewFirewallServiceClient(conn)
    
    // Call RPC method
    resp, err := client.CreateRule(context.Background(), &pb.CreateRuleRequest{
        RuleName: "allow-http",
        SourceIp: "0.0.0.0/0",
        DestPort: 80,
        Action: "ALLOW",
    })
    
    if err != nil {
        log.Fatalf("CreateRule failed: %v", err)
    }
    
    log.Printf("Rule created: %s", resp.RuleId)
}
```

### Handling Streaming Responses

```go
// Server streaming example
stream, err := client.StreamLogs(ctx, &pb.StreamLogsRequest{
    Query: "severity:high",
})
if err != nil {
    log.Fatalf("StreamLogs failed: %v", err)
}

for {
    event, err := stream.Recv()
    if err == io.EOF {
        break  // Stream ended
    }
    if err != nil {
        log.Fatalf("Stream error: %v", err)
    }
    
    // Process event
    log.Printf("Log event: %+v", event)
}
```

---

## Dependency Map

### Proto Import Dependencies

```
common.proto (foundation - no dependencies)
  ↑
  ├── orchestrator.proto
  ├── firewall.proto
  ├── threat_intel.proto
  ├── ids_ips.proto
  ├── network_logger.proto
  ├── dns_server.proto
  ├── dhcp_server.proto
  ├── tls_proxy.proto
  ├── wifi_ap.proto
  ├── backup_restore.proto
  ├── certificate_manager.proto
  ├── update_manager.proto
  └── network_manager.proto
```

**All service protos import `common.proto` for shared types.**

### Component to Proto Mapping

| Go Service | Proto File | Package Import |
|-----------|------------|----------------|
| `cmd/orchestrator/main.go` | `orchestrator.proto` | `safeops/build/proto/go/orchestrator` |
| `cmd/firewall_engine/main.go` | `firewall.proto` | `safeops/build/proto/go/firewall` |
| `cmd/threat_intel/main.go` | `threat_intel.proto` | `safeops/build/proto/go/threat_intel` |
| `cmd/ids_ips/main.go` | `ids_ips.proto` | `safeops/build/proto/go/ids_ips` |
| `cmd/network_logger/main.go` | `network_logger.proto` | `safeops/build/proto/go/network_logger` |
| `cmd/dns_server/main.go` | `dns_server.proto` | `safeops/build/proto/go/dns_server` |
| `cmd/dhcp_server/main.go` | `dhcp_server.proto` | `safeops/build/proto/go/dhcp_server` |
| `cmd/tls_proxy/main.go` | `tls_proxy.proto` | `safeops/build/proto/go/tls_proxy` |
| `cmd/wifi_ap/main.go` | `wifi_ap.proto` | `safeops/build/proto/go/wifi_ap` |
| `cmd/backup_restore/main.go` | `backup_restore.proto` | `safeops/build/proto/go/backup_restore` |
| `cmd/certificate_manager/main.go` | `certificate_manager.proto` | `safeops/build/proto/go/certificate_manager` |
| `cmd/update_manager/main.go` | `update_manager.proto` | `safeops/build/proto/go/update_manager` |
| `cmd/network_manager/main.go` | `network_manager.proto` | `safeops/build/proto/go/network_manager` |

---

## Versioning and Compatibility

### Backward Compatibility Rules

**Golden Rules:**
1. **NEVER remove or renumber existing fields**
2. **NEVER change field types** (except compatible scalar upgrades)
3. **ALWAYS add new fields with new numbers**
4. **ALWAYS use `reserved` for deprecated fields**

**Safe Changes:**
```protobuf
// ✅ Adding new optional fields
message FirewallRule {
  string id = 1;
  string name = 2;
  string action = 3;
  string description = 4;  // NEW: Safe to add
}

// ✅ Adding new enum values
enum Protocol {
  PROTOCOL_UNKNOWN = 0;
  PROTOCOL_TCP = 1;
  PROTOCOL_UDP = 2;
  PROTOCOL_SCTP = 3;  // NEW: Safe to add
}

// ✅ Adding new RPC methods
service FirewallService {
  rpc CreateRule(...) returns (...);
  rpc DeleteRule(...) returns (...);
  rpc GetRuleMetrics(...) returns (...);  // NEW: Safe to add
}
```

**Unsafe Changes:**
```protobuf
// ❌ NEVER: Changing field numbers
message FirewallRule {
  string id = 1;
  string name = 3;     // Changed from 2 - BREAKS COMPATIBILITY!
}

// ❌ NEVER: Changing field types
message FirewallRule {
  string id = 1;
  int32 name = 2;      // Changed from string - BREAKS COMPATIBILITY!
}

// ❌ NEVER: Removing fields without reserving
message FirewallRule {
  string id = 1;
  // name field removed - BREAKS COMPATIBILITY!
}
```

### Deprecation Process

**Step 1: Mark as Deprecated**
```protobuf
message FirewallRule {
  string id = 1;
  string name = 2 [deprecated = true];  // Mark deprecated
  string display_name = 3;              // New replacement field
}
```

**Step 2: Document Migration**
```protobuf
message FirewallRule {
  string id = 1;
  // Deprecated: Use display_name instead. This field will be removed in v3.0.
  string name = 2 [deprecated = true];
  // Preferred field for rule name display
  string display_name = 3;
}
```

**Step 3: Reserve After Removal (Future Version)**
```protobuf
message FirewallRule {
  reserved 2;
  reserved "name";
  
  string id = 1;
  string display_name = 3;
}
```

---

## Troubleshooting

### Common Build Errors

**Error: `protoc: command not found`**
```
Solution: Install Protocol Buffer compiler
- Windows: choco install protoc
- macOS: brew install protobuf
- Ubuntu: sudo apt-get install protobuf-compiler

Verify: protoc --version
```

**Error: `protoc-gen-go: program not found or is not executable`**
```
Solution: Install Go protoc plugins and add to PATH
1. go install google.golang.org/protobuf/cmd/protoc-gen-go@latest
2. go install google.golang.org/grpc/cmd/protoc-gen-go-grpc@latest
3. export PATH="$PATH:$(go env GOPATH)/bin"

Verify: which protoc-gen-go
        which protoc-gen-go-grpc
```

**Error: `Import "common.proto" was not found`**
```
Solution: Check proto file location and build command
1. Ensure common.proto exists in proto/grpc/
2. Run build script from proto/ directory
3. Verify --proto_path flag includes grpc/ directory

Check: ls proto/grpc/common.proto
```

**Error: `Circular dependency between proto files`**
```
Solution: Refactor proto imports
1. Identify circular import chain
2. Extract shared types to common.proto
3. Remove cross-service imports
4. Use string references instead of message references

Bad: serviceA.proto imports serviceB.proto which imports serviceA.proto
Good: Both import common.proto for shared types
```

### Generated Code Issues

**Issue: Missing methods in generated code**
```
Solution:
1. Check proto syntax - ensure all RPC methods defined
2. Run build script with --clean flag
3. Verify protoc and plugin versions
4. Check for compilation errors in build output

Debug: ./build.sh --clean --verbose
```

**Issue: Import path errors in Go**
```
Solution:
1. Check go_package option in proto file
2. Verify module path in go.mod matches proto package
3. Run go mod tidy after regenerating
4. Check import statements in Go code

Example go_package: option go_package = "safeops/build/proto/go/firewall";
```

**Issue: Type mismatches**
```
Solution:
1. Ensure proto field types match Go usage
2. Use appropriate wrapper types (common.IPAddress, common.Timestamp)
3. Check for uint32 vs int32 mismatches
4. Verify enum usage matches proto definition

Common: Use uint32 for ports, not string
        Use common.Timestamp, not int64
```

---

## Contributing

### Adding a New Service

**Step-by-Step Guide:**

1. **Create Proto File**
   ```bash
   cd proto/grpc
   touch new_service.proto
   ```

2. **Define Service Structure**
   ```protobuf
   syntax = "proto3";
   
   package safeops.new_service;
   
   import "common.proto";
   
   option go_package = "safeops/build/proto/go/new_service";
   
   service NewServiceService {
     rpc CreateResource(CreateResourceRequest) returns (ResourceResponse);
     rpc GetResource(GetResourceRequest) returns (ResourceResponse);
   }
   
   message CreateResourceRequest {
     string name = 1;
   }
   
   message ResourceResponse {
     string id = 1;
     common.Status status = 2;
   }
   ```

3. **Generate Code**
   ```bash
   cd ..
   ./build.sh --clean
   ```

4. **Implement Service**
   ```bash
   mkdir -p cmd/new_service
   # Create main.go implementing NewServiceServiceServer
   ```

5. **Update Documentation**
   - Add service to this README in "Proto File Descriptions" table
   - Document RPC methods and use cases
   - Add to dependency map

6. **Add Tests**
   ```bash
   mkdir -p cmd/new_service/tests
   # Create integration tests
   ```

### Modifying Existing Services

**Step-by-Step Guide:**

1. **Review Compatibility Rules**
   - Check "Versioning and Compatibility" section
   - Ensure changes are backward compatible

2. **Update Proto File**
   ```protobuf
   // Add new field with new number
   message ExistingMessage {
     string id = 1;
     string name = 2;
     string new_field = 3;  // Add with highest number + 1
   }
   ```

3. **Document Changes**
   ```protobuf
   // Add comments explaining new fields
   message ExistingMessage {
     string id = 1;
     string name = 2;
     // Added in v1.2: Description of the new field's purpose
     string new_field = 3;
   }
   ```

4. **Regenerate Code**
   ```bash
   ./build.sh --clean
   ```

5. **Update Service Implementation**
   ```go
   // Update server implementation to handle new fields
   func (s *Server) Method(ctx context.Context, req *pb.Request) (*pb.Response, error) {
       // Handle new field if present
       if req.NewField != "" {
           // Process new field
       }
       // ... rest of implementation
   }
   ```

6. **Test Backward Compatibility**
   - Test with old clients (without new fields)
   - Test with new clients (with new fields)
   - Verify old clients don't break

7. **Update API Documentation**
   - Document new fields in API docs
   - Update usage examples

---

## Reference Links

### Official Documentation

- **Protocol Buffers**: https://protobuf.dev/
- **Proto3 Language Guide**: https://protobuf.dev/programming-guides/proto3/
- **gRPC Official Site**: https://grpc.io/
- **gRPC Go Quick Start**: https://grpc.io/docs/languages/go/quickstart/
- **Go Generated Code Guide**: https://protobuf.dev/reference/go/go-generated/
- **gRPC-Go Documentation**: https://pkg.go.dev/google.golang.org/grpc

### Internal Documentation

- [DIRECTORY_STRUCTURE.md](../DIRECTORY_STRUCTURE.md) - Full project layout and organization
- [DEPENDENCY_MAP.md](../DEPENDENCY_MAP.md) - Service dependencies and relationships
- [ARCHITECTURE.md](../ARCHITECTURE.md) - System design and architecture overview
- [CONTRIBUTING.md](../CONTRIBUTING.md) - Development guidelines and workflows

### Tutorials and Guides

- **Protocol Buffers Tutorial**: https://protobuf.dev/getting-started/
- **gRPC Basics Tutorial**: https://grpc.io/docs/languages/go/basics/
- **Best Practices**: https://protobuf.dev/programming-guides/dos-donts/
- **Style Guide**: https://protobuf.dev/programming-guides/style/

---

## Version History

- **v2.0.0** (2025-12-16) - Complete gRPC proto definitions for all 14 services with 250+ RPC methods
- **v1.0.0** (2024-12-01) - Initial proto structure with common types and basic services

---

## License

Copyright © 2024-2025 SafeOps Project. All rights reserved.

This documentation and the associated proto definitions are part of the SafeOps platform and are proprietary and confidential.

---

## Summary

**Proto Files:** 14/14 complete ✅  
**Build Scripts:** 2/2 complete ✅  
**RPC Methods:** 250+ defined ✅  
**Documentation:** Complete ✅

All protocol buffer definitions are ready for code generation and service implementation!
