# Protocol Buffers - Data Structures

> **gRPC service definitions and message structures**

---

## 📡 Service Definitions

### Firewall Service

```protobuf
// proto/firewall_service.proto

syntax = "proto3";
package safeops.firewall.v1;

import "google/protobuf/timestamp.proto";

service FirewallService {
  rpc AddRule(AddRuleRequest) returns (AddRuleResponse);
  rpc DeleteRule(DeleteRuleRequest) returns (DeleteRuleResponse);
  rpc UpdateRule(UpdateRuleRequest) returns (UpdateRuleResponse);
  rpc ListRules(ListRulesRequest) returns (ListRulesResponse);
  rpc GetStats(GetStatsRequest) returns (GetStatsResponse);
  rpc StreamEvents(StreamEventsRequest) returns (stream FirewallEvent);
}

message FirewallRule {
  uint32 id = 1;
  string name = 2;
  string description = 3;
  bool enabled = 4;
  uint32 priority = 5;
  
  enum Action {
    BLOCK = 0;
    ALLOW = 1;
    INSPECT = 2;
  }
  Action action = 6;
  
  enum Direction {
    ANY = 0;
    INBOUND = 1;
    OUTBOUND = 2;
  }
  Direction direction = 7;
  
  AddressMatch source = 8;
  AddressMatch destination = 9;
  Protocol protocol = 10;
  
  bool log_matches = 11;
  uint64 hit_count = 12;
  
  google.protobuf.Timestamp created_at = 13;
  google.protobuf.Timestamp updated_at = 14;
}

message AddressMatch {
  repeated string ip_ranges = 1;  // CIDR notation
  repeated uint32 ports = 2;
  repeated PortRange port_ranges = 3;
}

message PortRange {
  uint32 start = 1;
  uint32 end = 2;
}

enum Protocol {
  ANY = 0;
  TCP = 6;
  UDP = 17;
  ICMP = 1;
}
```

### Threat Intelligence Service

```protobuf
// proto/threat_intel_service.proto

syntax = "proto3";
package safeops.threat.v1;

service ThreatIntelService {
  rpc CheckIP(CheckIPRequest) returns (CheckIPResponse);
  rpc CheckDomain(CheckDomainRequest) returns (CheckDomainResponse);
  rpc CheckHash(CheckHashRequest) returns (CheckHashResponse);
  rpc GetIOCs(GetIOCsRequest) returns (GetIOCsResponse);
  rpc ReportSighting(ReportSightingRequest) returns (ReportSightingResponse);
}

message IPReputation {
  string ip_address = 1;
  int32 reputation_score = 2;  // -100 to +100
  float confidence = 3;         // 0.0 to 1.0
  
  enum Severity {
    INFO = 0;
    LOW = 1;
    MEDIUM = 2;
    HIGH = 3;
    CRITICAL = 4;
  }
  Severity severity = 4;
  
  string category = 5;
  repeated string tags = 6;
  
  GeoLocation geo = 7;
  ASNInfo asn = 8;
  
  bool is_proxy = 9;
  bool is_vpn = 10;
  bool is_tor = 11;
  
  google.protobuf.Timestamp first_seen = 12;
  google.protobuf.Timestamp last_seen = 13;
}

message GeoLocation {
  string country_code = 1;
  string country_name = 2;
  string city = 3;
  double latitude = 4;
  double longitude = 5;
}

message ASNInfo {
  uint32 asn_number = 1;
  string asn_name = 2;
  string organization = 3;
}
```

### Network Manager Service

```protobuf
// proto/network_manager.proto

syntax = "proto3";
package safeops.network.v1;

service NetworkManager {
  rpc GetConnections(GetConnectionsRequest) returns (GetConnectionsResponse);
  rpc GetInterfaces(GetInterfacesRequest) returns (GetInterfacesResponse);
  rpc GetStats(GetStatsRequest) returns (GetStatsResponse);
  rpc StreamPackets(StreamPacketsRequest) returns (stream PacketEvent);
}

message Connection {
  uint64 flow_id = 1;
  string local_ip = 2;
  uint32 local_port = 3;
  string remote_ip = 4;
  uint32 remote_port = 5;
  Protocol protocol = 6;
  
  enum State {
    NEW = 0;
    ESTABLISHED = 1;
    CLOSING = 2;
    CLOSED = 3;
  }
  State state = 7;
  
  uint32 process_id = 8;
  string process_name = 9;
  
  uint64 bytes_sent = 10;
  uint64 bytes_received = 11;
  uint32 packets_sent = 12;
  uint32 packets_received = 13;
  
  google.protobuf.Timestamp start_time = 14;
  google.protobuf.Timestamp last_seen = 15;
}

message PacketEvent {
  uint64 packet_id = 1;
  uint64 timestamp_ns = 2;
  
  string src_ip = 3;
  uint32 src_port = 4;
  string dst_ip = 5;
  uint32 dst_port = 6;
  Protocol protocol = 7;
  
  enum Direction {
    INBOUND = 0;
    OUTBOUND = 1;
  }
  Direction direction = 8;
  
  uint32 packet_size = 9;
  
  enum Action {
    PERMIT = 0;
    BLOCK = 1;
  }
  Action action = 10;
  
  uint32 rule_id = 11;
  int32 threat_level = 12;
}
```

---

## 🔄 Message Flow

```
Client Application
       │
       ▼
┌─────────────────┐
│  gRPC Client    │
│  (Generated)    │
└─────────────────┘
       │
       │ HTTP/2 + TLS
       ▼
┌─────────────────┐
│  gRPC Server    │
│  (Go/Rust)      │
└─────────────────┘
       │
       ▼
┌─────────────────┐
│ Business Logic  │
└─────────────────┘
```

---

## 📦 Generated Code

After running `proto/build.ps1`:

```
build/proto/
├── go/
│   ├── firewall/v1/
│   │   ├── firewall.pb.go
│   │   └── firewall_grpc.pb.go
│   └── threat/v1/
│       ├── threat.pb.go
│       └── threat_grpc.pb.go
└── rust/
    ├── firewall.rs
    └── threat.rs
```

---

## 🔧 Build Command

```powershell
# Windows
.\proto\build.ps1

# Generates code for:
# - Go (protoc-gen-go, protoc-gen-go-grpc)
# - Rust (prost, tonic)
```

---

**Version:** 2.0.0  
**Last Updated:** 2025-12-17
