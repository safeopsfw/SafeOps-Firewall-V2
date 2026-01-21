# Firewall Engine Implementation Plan
**SafeOps V2 - Advanced Firewall Integration**

## Executive Summary

The Firewall Engine will enhance Windows Firewall by integrating with SafeOps Engine for real-time packet drop/redirect decisions and Network Logger for forensic analysis. It will translate high-level firewall rules (TOML config) into Windows Filtering Platform (WFP) filters and provide stateful inspection with connection tracking.

---

## 1. Architecture Overview

```
┌─────────────────────────────────────────────────────────────────┐
│                     USER INTERFACE LAYER                         │
├─────────────────────────────────────────────────────────────────┤
│  • Web UI (React)                                                │
│  • REST API (Express.js)                                         │
│  • CLI Management Tool                                           │
└─────────────────────────────────────────────────────────────────┘
                              ↓
┌─────────────────────────────────────────────────────────────────┐
│                     FIREWALL ENGINE (Go)                         │
├─────────────────────────────────────────────────────────────────┤
│  Components:                                                     │
│  ┌──────────────────┐  ┌──────────────────┐                    │
│  │  Rule Manager    │  │  WFP Integration │                    │
│  │  • TOML Parser   │  │  • Filter CRUD   │                    │
│  │  • Validation    │  │  • Kernel Driver │                    │
│  │  • Priority Sort │  │  • IOCTL Calls   │                    │
│  └──────────────────┘  └──────────────────┘                    │
│  ┌──────────────────┐  ┌──────────────────┐                    │
│  │ Packet Inspector │  │ Verdict Engine   │                    │
│  │  • 5-tuple Match │  │  • Allow/Drop    │                    │
│  │  • State Track   │  │  • TCP RST       │                    │
│  │  • Cache         │  │  • DNS Redirect  │                    │
│  └──────────────────┘  └──────────────────┘                    │
│  ┌──────────────────┐  ┌──────────────────┐                    │
│  │  gRPC Services   │  │  Database Layer  │                    │
│  │  • InspectPacket │  │  • Rule Storage  │                    │
│  │  • UpdateRule    │  │  • Statistics    │                    │
│  │  • GetStats      │  │  • Packet Logs   │                    │
│  └──────────────────┘  └──────────────────┘                    │
└─────────────────────────────────────────────────────────────────┘
                              ↓
┌─────────────────────────────────────────────────────────────────┐
│                   INTEGRATION LAYER                              │
├─────────────────────────────────────────────────────────────────┤
│  ┌──────────────────────────────────────────────────────────┐  │
│  │  SafeOps Engine Integration                              │  │
│  │  • Subscribe to metadata stream                          │  │
│  │  • Receive parsed packet metadata (5-tuple, domain)      │  │
│  │  • Apply firewall rules                                  │  │
│  │  • Return verdict: ALLOW/BLOCK/DROP                      │  │
│  │  • Update verdict engine for drop/redirect               │  │
│  └──────────────────────────────────────────────────────────┘  │
│  ┌──────────────────────────────────────────────────────────┐  │
│  │  Network Logger Integration                              │  │
│  │  • Send firewall decisions to FirewallCollector          │  │
│  │  • Log: action, reason, 5-tuple, TCP flags, geo         │  │
│  │  • Connection deduplication (30-second window)           │  │
│  │  • Always log TCP control packets (SYN/FIN/RST)          │  │
│  └──────────────────────────────────────────────────────────┘  │
│  ┌──────────────────────────────────────────────────────────┐  │
│  │  NIC Management Integration                              │  │
│  │  • Query active interfaces via REST API                  │  │
│  │  • Get interface stats (WAN/LAN/WIFI)                    │  │
│  │  • Subscribe to interface up/down events                 │  │
│  │  • Adjust firewall rules on interface changes            │  │
│  └──────────────────────────────────────────────────────────┘  │
└─────────────────────────────────────────────────────────────────┘
                              ↓
┌─────────────────────────────────────────────────────────────────┐
│                 WINDOWS KERNEL LAYER                             │
├─────────────────────────────────────────────────────────────────┤
│  • Windows Filtering Platform (WFP)                             │
│  • SafeOpsDriver (custom kernel driver)                         │
│  • NDISAPI for packet injection (TCP RST, DNS spoofing)         │
└─────────────────────────────────────────────────────────────────┘
```

---

## 2. Component Breakdown

### 2.1 Rule Manager

**Responsibilities:**
- Parse `firewall.toml` configuration
- Validate rule syntax and object references
- Sort rules by priority (group priority → rule priority)
- Translate high-level rules to internal structures
- Support dynamic rule updates (hot-reload)

**Key Structures:**
```go
type FirewallRule struct {
    RuleID          uuid.UUID
    Name            string
    Description     string
    Action          ActionType        // ALLOW, DENY, DROP, REJECT
    Direction       DirectionType     // INBOUND, OUTBOUND, ANY
    Protocol        ProtocolType      // TCP, UDP, ICMP, ANY
    SrcAddress      AddressMatcher    // IP, CIDR, range, object ref
    DstAddress      AddressMatcher
    SrcPort         PortMatcher       // Single, list, range
    DstPort         PortMatcher
    Interface       string            // WAN, LAN, WIFI, or adapter name
    State           []ConnState       // NEW, ESTABLISHED, RELATED, INVALID
    Priority        int               // 1-1000
    Enabled         bool
    LogEnabled      bool
    GroupName       string
    CreatedAt       time.Time
    UpdatedAt       time.Time
}

type AddressMatcher struct {
    Type          string    // "SINGLE", "CIDR", "RANGE", "OBJECT_REF", "ANY"
    Value         string    // "192.168.1.100", "10.0.0.0/8", "LAN_NETWORK"
    Negation      bool      // Support for !RFC1918_PRIVATE
    ResolvedIPs   []net.IP  // Expanded from object references
}

type RuleGroup struct {
    GroupName   string
    Enabled     bool
    Priority    int         // 100, 200, 300, etc.
    Description string
}
```

**Rule Evaluation Order:**
1. Rules sorted by `group.priority` (ascending)
2. Within group, sorted by `rule.priority` (ascending)
3. First matching rule wins
4. If no match, apply default policy

---

### 2.2 WFP Integration Layer

**Responsibilities:**
- Translate FirewallRule → WFP Filter
- Manage WFP filter lifecycle (add/remove/modify)
- Communicate with kernel driver via IOCTL
- Batch filter operations (up to 100 per IOCTL)
- Handle driver health checks and restarts

**Windows API Integration:**
```c
// wfp_api.c - Windows Filtering Platform C bindings

#include <windows.h>
#include <fwpmu.h>
#include <fwpmtypes.h>

// Initialize WFP session
DWORD WfpInit(HANDLE* engineHandle, HANDLE* sessionHandle);

// Create WFP filter from rule
DWORD WfpCreateFilter(
    HANDLE sessionHandle,
    const FirewallRuleC* rule,
    GUID* filterGuid
);

// Delete WFP filter
DWORD WfpDeleteFilter(HANDLE sessionHandle, const GUID* filterGuid);

// Batch filter operations (add/remove up to 100)
DWORD WfpBatchOperation(
    HANDLE sessionHandle,
    const FilterOperation* operations,
    DWORD operationCount
);

// Query WFP statistics
DWORD WfpGetFilterStats(
    HANDLE sessionHandle,
    const GUID* filterGuid,
    FilterStats* stats
);
```

**Kernel Driver Communication:**
```go
// Driver IOCTL interface
const (
    IOCTL_SAFEOPS_ADD_FILTER    = 0x222004
    IOCTL_SAFEOPS_REMOVE_FILTER = 0x222008
    IOCTL_SAFEOPS_GET_STATS     = 0x22200C
)

type SafeOpsDriverClient struct {
    deviceHandle syscall.Handle
    timeout      time.Duration
}

func (c *SafeOpsDriverClient) AddFilter(filter *KernelFilter) error
func (c *SafeOpsDriverClient) RemoveFilter(filterID uint64) error
func (c *SafeOpsDriverClient) GetStats() (*DriverStats, error)
func (c *SafeOpsDriverClient) HealthCheck() error
```

**WFP Layer Selection:**
- **FWPM_LAYER_INBOUND_IPPACKET_V4**: Inbound IPv4 packets (earliest interception)
- **FWPM_LAYER_OUTBOUND_IPPACKET_V4**: Outbound IPv4 packets
- **FWPM_LAYER_ALE_AUTH_CONNECT_V4**: Connection authorization (stateful)
- **FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V4**: Inbound connection authorization

---

### 2.3 Packet Inspector

**Responsibilities:**
- Receive packet metadata from SafeOps Engine
- Match packets against firewall rules (5-tuple + state)
- Maintain verdict cache (LRU, 60-second TTL)
- Track connection states (NEW, ESTABLISHED, CLOSING, CLOSED)
- Send verdicts back to SafeOps Engine

**Integration with SafeOps Engine:**
```go
// Subscribe to SafeOps Engine metadata stream
func (fw *FirewallEngine) SubscribeToSafeOpsEngine() {
    driver := safeops.GetEnhancedDriver()
    metadataStream := driver.GetMetadataStream()

    for metadata := range metadataStream.Receive() {
        verdict, reason := fw.InspectPacket(metadata)

        if verdict == VerdictDrop || verdict == VerdictBlock {
            // Update SafeOps verdict engine
            verdictEngine := driver.GetVerdictEngine()

            if verdict == VerdictBlock {
                // Send TCP RST (active rejection)
                verdictEngine.BlockIP(metadata.DstIP, verdict.VerdictBlock)
            } else {
                // Silent drop
                verdictEngine.BlockIP(metadata.DstIP, verdict.VerdictDrop)
            }

            // Log to Network Logger
            fw.LogBlockedPacket(metadata, reason)
        }
    }
}

// Packet inspection with rule matching
func (fw *FirewallEngine) InspectPacket(meta *PacketMetadata) (Verdict, string) {
    // 1. Check verdict cache
    cacheKey := fmt.Sprintf("%s:%d-%s:%d-%d",
        meta.SrcIP, meta.SrcPort, meta.DstIP, meta.DstPort, meta.Protocol)

    if cachedVerdict, found := fw.verdictCache.Get(cacheKey); found {
        return cachedVerdict.Verdict, cachedVerdict.Reason
    }

    // 2. Match against rules (sorted by priority)
    for _, rule := range fw.sortedRules {
        if fw.matchRule(rule, meta) {
            verdict := fw.actionToVerdict(rule.Action)
            reason := fmt.Sprintf("Matched rule: %s", rule.Name)

            // Cache verdict
            fw.verdictCache.Set(cacheKey, verdict, reason, 60*time.Second)

            // Update rule hit count
            fw.updateRuleHitCount(rule.RuleID)

            return verdict, reason
        }
    }

    // 3. Apply default policy
    verdict := fw.getDefaultPolicy(meta.Direction)
    reason := "Default policy"

    fw.verdictCache.Set(cacheKey, verdict, reason, 60*time.Second)
    return verdict, reason
}

// Rule matching logic
func (fw *FirewallEngine) matchRule(rule *FirewallRule, meta *PacketMetadata) bool {
    // Direction check
    if !fw.matchDirection(rule.Direction, meta.Direction) {
        return false
    }

    // Protocol check
    if !fw.matchProtocol(rule.Protocol, meta.Protocol) {
        return false
    }

    // Source IP check
    if !fw.matchAddress(rule.SrcAddress, net.ParseIP(meta.SrcIP)) {
        return false
    }

    // Destination IP check
    if !fw.matchAddress(rule.DstAddress, net.ParseIP(meta.DstIP)) {
        return false
    }

    // Port checks
    if !fw.matchPort(rule.SrcPort, meta.SrcPort) {
        return false
    }

    if !fw.matchPort(rule.DstPort, meta.DstPort) {
        return false
    }

    // Connection state check
    if len(rule.State) > 0 {
        connState := fw.getConnectionState(meta)
        if !fw.matchState(rule.State, connState) {
            return false
        }
    }

    // Interface check
    if rule.Interface != "" && rule.Interface != "ANY" {
        if !fw.matchInterface(rule.Interface, meta.AdapterName) {
            return false
        }
    }

    return true
}
```

**Connection State Tracking:**
```go
type ConnectionTracker struct {
    connections sync.Map  // string(5-tuple) → *ConnectionInfo
    timeout     time.Duration
}

type ConnectionInfo struct {
    FiveTuple    FiveTuple
    State        ConnState      // NEW, ESTABLISHED, CLOSING, CLOSED
    FirstSeen    time.Time
    LastSeen     time.Time
    PacketCount  uint64
    ByteCount    uint64
    TCPFlags     uint8          // Seen TCP flags
}

func (ct *ConnectionTracker) UpdateState(meta *PacketMetadata) ConnState {
    key := meta.FiveTupleKey()

    connInfo, exists := ct.connections.Load(key)
    if !exists {
        // New connection
        newConn := &ConnectionInfo{
            FiveTuple:   meta.To5Tuple(),
            State:       ConnStateNew,
            FirstSeen:   time.Now(),
            LastSeen:    time.Now(),
            PacketCount: 1,
            TCPFlags:    meta.TCPFlags,
        }
        ct.connections.Store(key, newConn)
        return ConnStateNew
    }

    conn := connInfo.(*ConnectionInfo)
    conn.LastSeen = time.Now()
    conn.PacketCount++
    conn.TCPFlags |= meta.TCPFlags

    // Update state based on TCP flags
    if meta.Protocol == 6 {  // TCP
        if meta.IsSYN && !meta.IsACK {
            conn.State = ConnStateNew
        } else if meta.IsSYN && meta.IsACK {
            conn.State = ConnStateEstablished
        } else if meta.IsFIN || meta.IsRST {
            conn.State = ConnStateClosing
        }
    } else {
        // UDP/ICMP: pseudo-stateful
        if conn.PacketCount > 1 {
            conn.State = ConnStateEstablished
        }
    }

    return conn.State
}
```

---

### 2.4 Verdict Engine Integration

**SafeOps Engine Verdict Update:**
```go
// Update SafeOps verdict engine in real-time
func (fw *FirewallEngine) ApplyBlockVerdict(ip net.IP, verdict Verdict) error {
    driver := safeops.GetEnhancedDriver()
    verdictEngine := driver.GetVerdictEngine()

    switch verdict {
    case VerdictBlock:
        // Block with TCP RST injection
        verdictEngine.BlockIP(ip, verdict.VerdictBlock)

    case VerdictDrop:
        // Silent drop (no RST)
        verdictEngine.BlockIP(ip, verdict.VerdictDrop)

    case VerdictRedirect:
        // DNS redirect (if domain-based)
        if domain != "" {
            redirectIP := net.ParseIP("192.168.1.1")  // Captive portal
            verdictEngine.AddDNSRedirect(domain, redirectIP)
        }
    }

    return nil
}

// TCP RST injection for active blocking
func (fw *FirewallEngine) SendTCPReset(conn *ConnectionInfo) error {
    driver := safeops.GetEnhancedDriver()
    verdictEngine := driver.GetVerdictEngine()

    // Get adapter handle and MAC addresses from NIC Management
    adapter := fw.getAdapterByName(conn.AdapterName)

    return verdictEngine.SendTCPReset(
        adapter.Handle,
        conn.FiveTuple.SrcIP,
        conn.FiveTuple.DstIP,
        conn.FiveTuple.SrcPort,
        conn.FiveTuple.DstPort,
        adapter.SrcMAC,
        adapter.DstMAC,
    )
}
```

---

### 2.5 Network Logger Integration

**Firewall Log Format:**
```go
type FirewallLogEntry struct {
    Action        string              `json:"action"`          // "allow", "drop", "reject"
    Reason        string              `json:"reason"`          // Rule name or "default policy"
    TimestampIST  string              `json:"timestamp_ist"`
    EventID       string              `json:"event_id"`
    SrcIP         string              `json:"src_ip"`
    DstIP         string              `json:"dst_ip"`
    SrcPort       uint16              `json:"src_port"`
    DstPort       uint16              `json:"dst_port"`
    Protocol      string              `json:"protocol"`        // "TCP", "UDP", "ICMP"
    Direction     string              `json:"direction"`       // "inbound", "outbound"
    TCPFlags      string              `json:"tcp_flags,omitempty"`
    TotalBytes    uint64              `json:"total_bytes"`
    TLSSNI        string              `json:"tls_sni,omitempty"`
    SrcGeo        *GeoInfo            `json:"src_geo,omitempty"`
    DstGeo        *GeoInfo            `json:"dst_geo,omitempty"`
    RuleName      string              `json:"rule_name,omitempty"`
    RuleID        string              `json:"rule_id,omitempty"`
}

// Send logs to Network Logger's FirewallCollector
func (fw *FirewallEngine) LogFirewallDecision(meta *PacketMetadata, verdict Verdict, reason string) {
    logEntry := &FirewallLogEntry{
        Action:       verdict.String(),
        Reason:       reason,
        TimestampIST: time.Now().Format(time.RFC3339),
        EventID:      fmt.Sprintf("pkt_%s", uuid.New().String()[:8]),
        SrcIP:        meta.SrcIP,
        DstIP:        meta.DstIP,
        SrcPort:      meta.SrcPort,
        DstPort:      meta.DstPort,
        Protocol:     meta.ProtocolString(),
        Direction:    fw.classifyDirection(meta),
        TCPFlags:     meta.TCPFlagsString(),
        TotalBytes:   uint64(meta.PacketSize),
        TLSSNI:       meta.Domain,
    }

    // Check deduplication (30-second window)
    connKey := fmt.Sprintf("%s:%d-%s:%d-%s",
        meta.SrcIP, meta.SrcPort, meta.DstIP, meta.DstPort, meta.ProtocolString())

    if fw.shouldLogConnection(connKey, meta) {
        fw.writeLog(logEntry)
    }
}

// Connection deduplication logic
func (fw *FirewallEngine) shouldLogConnection(connKey string, meta *PacketMetadata) bool {
    // Always log TCP control packets
    if meta.IsSYN || meta.IsFIN || meta.IsRST {
        return true
    }

    // Check dedup window (30 seconds)
    lastLogged, exists := fw.loggedConnections.Load(connKey)
    if exists {
        if time.Since(lastLogged.(time.Time)) < 30*time.Second {
            return false  // Suppress duplicate
        }
    }

    // Log and update timestamp
    fw.loggedConnections.Store(connKey, time.Now())
    return true
}
```

**Log File Management:**
```go
// Firewall logs written to: logs/firewall.log
// Format: JSONL (one JSON object per line)
// Rotation: 5-minute cycle (matches Network Logger)
// Max size: 10 MB per file

type FirewallLogWriter struct {
    file          *os.File
    batch         []*FirewallLogEntry
    batchSize     int           // 75 packets per write
    flushInterval time.Duration // 500ms
    rotateSize    int64         // 10 MB
    rotateCycle   time.Duration // 5 minutes
}
```

---

### 2.6 NIC Management Integration

**Interface Discovery:**
```go
// Query active network interfaces via REST API
func (fw *FirewallEngine) SyncNetworkInterfaces() error {
    resp, err := http.Get("http://localhost:8080/api/nics")
    if err != nil {
        return err
    }
    defer resp.Body.Close()

    var interfaces []NICInfo
    json.NewDecoder(resp.Body).Decode(&interfaces)

    // Update firewall interface mappings
    for _, nic := range interfaces {
        fw.interfaceMap[nic.Name] = &InterfaceInfo{
            Name:      nic.Name,
            Type:      nic.Type,        // WAN, LAN, WIFI
            Status:    nic.Status,      // UP, DOWN
            IPv4:      nic.IPv4,
            MAC:       nic.MAC,
            AdapterHandle: nic.Handle,  // For packet injection
        }
    }

    return nil
}

// Subscribe to interface events via SSE
func (fw *FirewallEngine) SubscribeToInterfaceEvents() {
    resp, err := http.Get("http://localhost:8080/api/nics/events")
    if err != nil {
        log.Error("Failed to subscribe to NIC events:", err)
        return
    }
    defer resp.Body.Close()

    reader := bufio.NewReader(resp.Body)
    for {
        line, err := reader.ReadString('\n')
        if err != nil {
            break
        }

        if strings.HasPrefix(line, "data: ") {
            eventData := strings.TrimPrefix(line, "data: ")
            var event NICEvent
            json.Unmarshal([]byte(eventData), &event)

            fw.handleInterfaceEvent(&event)
        }
    }
}

// Handle interface state changes
func (fw *FirewallEngine) handleInterfaceEvent(event *NICEvent) {
    switch event.Type {
    case "interface_down":
        // Interface went down, block traffic on this interface
        fw.blockInterface(event.InterfaceName)

    case "interface_up":
        // Interface came up, re-enable rules
        fw.enableInterface(event.InterfaceName)

    case "interface_added":
        // New interface detected, apply default rules
        fw.applyDefaultRules(event.InterfaceName)
    }
}
```

---

## 3. gRPC Service Definitions

**Firewall Engine gRPC API:**
```protobuf
// proto/firewall_engine.proto

syntax = "proto3";
package safeops.firewall;

import "google/protobuf/timestamp.proto";

service FirewallEngine {
    // Packet inspection (called by NIC Management)
    rpc InspectPacket(InspectPacketRequest) returns (InspectPacketResponse);

    // Rule management
    rpc AddRule(AddRuleRequest) returns (AddRuleResponse);
    rpc UpdateRule(UpdateRuleRequest) returns (UpdateRuleResponse);
    rpc DeleteRule(DeleteRuleRequest) returns (DeleteRuleResponse);
    rpc ListRules(ListRulesRequest) returns (ListRulesResponse);
    rpc ReloadRules(ReloadRulesRequest) returns (ReloadRulesResponse);

    // Statistics
    rpc GetFirewallStats(GetStatsRequest) returns (FirewallStatsResponse);
    rpc GetRuleStats(GetRuleStatsRequest) returns (RuleStatsResponse);

    // Connection tracking
    rpc ListConnections(ListConnectionsRequest) returns (ListConnectionsResponse);
    rpc TerminateConnection(TerminateConnectionRequest) returns (TerminateConnectionResponse);

    // Cache management
    rpc InvalidateCache(InvalidateCacheRequest) returns (InvalidateCacheResponse);
}

message InspectPacketRequest {
    bytes packet = 1;
    string src_ip = 2;
    string dst_ip = 3;
    uint32 src_port = 4;
    uint32 dst_port = 5;
    uint32 protocol = 6;
    string direction = 7;        // "INBOUND", "OUTBOUND"
    string wan_interface = 8;
    uint32 tcp_flags = 9;
    string domain = 10;          // From SNI, HTTP Host, DNS
}

message InspectPacketResponse {
    string verdict = 1;          // "ALLOW", "DENY", "DROP"
    string reason = 2;           // Rule name or policy
    string rule_id = 3;
    bool from_cache = 4;
}

message AddRuleRequest {
    string name = 1;
    string description = 2;
    string action = 3;           // "ALLOW", "BLOCK", "DROP", "REJECT"
    string protocol = 4;
    string src_address = 5;
    string dst_address = 6;
    string src_port = 7;
    string dst_port = 8;
    string direction = 9;
    string interface = 10;
    repeated string state = 11;
    int32 priority = 12;
    bool enabled = 13;
    bool log_enabled = 14;
    string group_name = 15;
}

message FirewallStatsResponse {
    uint64 total_packets = 1;
    uint64 allowed_packets = 2;
    uint64 blocked_packets = 3;
    uint64 dropped_packets = 4;
    uint64 cache_hit_rate = 5;
    uint64 active_connections = 6;
    double avg_latency_ms = 7;
}
```

---

## 4. Database Schema

**Already Implemented** (see `database/schemas/016_firewall_engine.sql`):

- `firewall_rules`: Rule definitions with hit counts
- `firewall_stats`: Daily aggregated statistics
- `packet_logs`: Real-time packet activity (last 1000/day)
- `device_policies`: Per-device overrides (bandwidth limits, time restrictions)

**Additional Indexes for Performance:**
```sql
-- Optimize rule lookups by priority
CREATE INDEX idx_firewall_rules_priority_enabled
ON firewall_rules(priority ASC, enabled) WHERE enabled = true;

-- Optimize packet log queries
CREATE INDEX idx_packet_logs_srcip_dstip
ON packet_logs(src_ip, dst_ip, timestamp DESC);

-- Optimize device policy lookups
CREATE INDEX idx_device_policies_mac_active
ON device_policies(device_mac) WHERE default_action = 'ALLOW';
```

---

## 5. Configuration Management

**firewall.toml → In-Memory Rules:**
```go
type ConfigLoader struct {
    configPath      string
    reloadInterval  time.Duration
    lastModified    time.Time
    rules           []*FirewallRule
    addressObjects  map[string]*AddressObject
    portObjects     map[string]*PortObject
}

func (cl *ConfigLoader) LoadConfig() error {
    // 1. Parse TOML
    var config FirewallConfig
    if err := toml.DecodeFile(cl.configPath, &config); err != nil {
        return err
    }

    // 2. Build object lookup tables
    cl.addressObjects = make(map[string]*AddressObject)
    for _, obj := range config.AddressObjects {
        cl.addressObjects[obj.ObjectName] = &obj
    }

    // 3. Expand object references in rules
    for _, rule := range config.Rules {
        // Resolve source address
        if strings.HasPrefix(rule.SourceAddress, "!") {
            // Negation
            rule.SrcAddress.Negation = true
            rule.SourceAddress = strings.TrimPrefix(rule.SourceAddress, "!")
        }

        if obj, exists := cl.addressObjects[rule.SourceAddress]; exists {
            // Expand object to IP list
            rule.SrcAddress.ResolvedIPs = cl.expandAddressObject(obj)
        }

        // Similar for destination, ports, etc.
    }

    // 4. Sort rules by priority
    cl.sortRules()

    // 5. Validate rules
    return cl.validateRules()
}

// Hot-reload on file change
func (cl *ConfigLoader) WatchConfig() {
    watcher, _ := fsnotify.NewWatcher()
    watcher.Add(cl.configPath)

    for {
        select {
        case event := <-watcher.Events:
            if event.Op&fsnotify.Write == fsnotify.Write {
                log.Info("Config file changed, reloading...")
                if err := cl.LoadConfig(); err != nil {
                    log.Error("Failed to reload config:", err)
                } else {
                    // Push updated rules to WFP
                    cl.applyRulesToWFP()
                }
            }
        }
    }
}
```

---

## 6. Performance Optimizations

### 6.1 Verdict Cache
- **LRU cache**: 100,000 entries
- **TTL**: 60 seconds
- **Key**: `{srcIP}:{srcPort}-{dstIP}:{dstPort}-{protocol}`
- **Hit rate target**: >80%

### 6.2 Rule Matching Optimization
```go
// Fast-path checks (before full rule evaluation)
func (fw *FirewallEngine) fastPathCheck(meta *PacketMetadata) (Verdict, bool) {
    // 1. Check if destination port is in common allow list
    if fw.isCommonAllowPort(meta.DstPort) {
        return VerdictAllow, true
    }

    // 2. Check if source IP is in blocklist
    if fw.isBlockedIP(meta.SrcIP) {
        return VerdictDrop, true
    }

    // 3. Check if protocol is allowed by default policy
    if meta.Direction == DirectionOutbound && fw.defaultOutboundPolicy == "ALLOW" {
        return VerdictAllow, true
    }

    return VerdictAllow, false  // Continue to full rule evaluation
}

// Common allow ports (DNS, HTTP, HTTPS, NTP)
var commonAllowPorts = map[uint16]bool{
    53:  true,  // DNS
    80:  true,  // HTTP
    443: true,  // HTTPS
    123: true,  // NTP
}
```

### 6.3 Batch Processing
- **WFP filter operations**: Batch up to 100 filters per IOCTL
- **Database writes**: Batch rule updates (10 rules/transaction)
- **Log writes**: Batch 75 log entries per write (500ms flush)

### 6.4 Parallel Processing
```go
// Inspect packets in parallel workers
func (fw *FirewallEngine) StartInspectionWorkers(numWorkers int) {
    for i := 0; i < numWorkers; i++ {
        go func(workerID int) {
            for meta := range fw.packetQueue {
                verdict, reason := fw.InspectPacket(meta)
                fw.applyVerdict(meta, verdict, reason)
            }
        }(i)
    }
}
```

---

## 7. Implementation Phases

### Phase 1: Core Infrastructure (Week 1-2)
- [ ] Set up Go project structure
- [ ] Implement Rule Manager (TOML parser, validation)
- [ ] Create database models and migrations
- [ ] Build in-memory rule cache
- [ ] Implement configuration hot-reload

### Phase 2: WFP Integration (Week 3-4)
- [ ] Develop C bindings for WFP API (`wfp_api.c`)
- [ ] Create Go-C bridge via CGo
- [ ] Implement IOCTL communication with SafeOpsDriver
- [ ] Build WFP filter CRUD operations
- [ ] Add filter batch processing

### Phase 3: Packet Inspection (Week 5-6)
- [ ] Implement 5-tuple rule matching
- [ ] Build connection state tracker
- [ ] Create verdict cache (LRU)
- [ ] Integrate with SafeOps Engine metadata stream
- [ ] Add fast-path optimizations

### Phase 4: Verdict Enforcement (Week 7-8)
- [ ] Integrate with SafeOps verdict engine
- [ ] Implement TCP RST injection
- [ ] Add DNS redirect support
- [ ] Build fail-safe mechanisms (fail-open/fail-closed)
- [ ] Add health checks and metrics

### Phase 5: Logging Integration (Week 9-10)
- [ ] Integrate with Network Logger FirewallCollector
- [ ] Implement connection deduplication
- [ ] Build log batching and rotation
- [ ] Add geolocation enrichment
- [ ] Create log analytics queries

### Phase 6: gRPC Services (Week 11-12)
- [ ] Define proto files
- [ ] Implement gRPC server
- [ ] Add authentication and authorization
- [ ] Build client libraries (Go, JS)
- [ ] Add rate limiting and quotas

### Phase 7: UI Integration (Week 13-14)
- [ ] Update React UI for rule management
- [ ] Build real-time firewall dashboard
- [ ] Add rule creation wizard
- [ ] Implement statistics visualization
- [ ] Create connection monitor

### Phase 8: Testing & Optimization (Week 15-16)
- [ ] Unit tests (rule matching, state tracking)
- [ ] Integration tests (SafeOps Engine, Network Logger)
- [ ] Performance benchmarks (throughput, latency)
- [ ] Load testing (10k+ rules, 100k+ pps)
- [ ] Security audit and hardening

---

## 8. Testing Strategy

### 8.1 Unit Tests
```go
// Test rule matching
func TestRuleMatching(t *testing.T) {
    rule := &FirewallRule{
        Action:     ActionBlock,
        Protocol:   ProtocolTCP,
        DstPort:    PortMatcher{Ports: []uint16{445}},
    }

    meta := &PacketMetadata{
        Protocol: 6,
        DstPort:  445,
    }

    assert.True(t, matchRule(rule, meta))
}

// Test connection state tracking
func TestConnectionStateTracking(t *testing.T) {
    tracker := NewConnectionTracker()

    // SYN packet
    synMeta := &PacketMetadata{TCPFlags: 0x02}
    state := tracker.UpdateState(synMeta)
    assert.Equal(t, ConnStateNew, state)

    // SYN-ACK packet
    synAckMeta := &PacketMetadata{TCPFlags: 0x12}
    state = tracker.UpdateState(synAckMeta)
    assert.Equal(t, ConnStateEstablished, state)
}
```

### 8.2 Integration Tests
```go
// Test SafeOps Engine integration
func TestSafeOpsEngineIntegration(t *testing.T) {
    fw := NewFirewallEngine()
    driver := safeops.GetEnhancedDriver()

    // Block IP via firewall
    fw.BlockIP(net.ParseIP("1.2.3.4"), VerdictDrop)

    // Verify verdict engine updated
    verdict := driver.GetVerdictEngine().CheckIP(net.ParseIP("1.2.3.4"))
    assert.Equal(t, verdict.VerdictDrop, verdict)
}

// Test Network Logger integration
func TestNetworkLoggerIntegration(t *testing.T) {
    fw := NewFirewallEngine()

    meta := &PacketMetadata{
        SrcIP: "192.168.1.100",
        DstIP: "8.8.8.8",
    }

    fw.LogFirewallDecision(meta, VerdictBlock, "Rule: Block_Google_DNS")

    // Verify log written to firewall.log
    logEntry := readLastLogEntry("logs/firewall.log")
    assert.Equal(t, "drop", logEntry.Action)
}
```

### 8.3 Performance Tests
```bash
# Packet throughput test
go test -bench=BenchmarkPacketInspection -benchtime=10s
# Target: >100,000 packets/second

# Rule matching latency test
go test -bench=BenchmarkRuleMatching -benchtime=10s
# Target: <50 microseconds per packet

# Cache hit rate test
go test -run=TestCacheHitRate
# Target: >80% hit rate
```

---

## 9. Monitoring & Metrics

### 9.1 Prometheus Metrics
```go
var (
    packetsInspected = promauto.NewCounter(prometheus.CounterOpts{
        Name: "firewall_packets_inspected_total",
    })

    packetsBlocked = promauto.NewCounterVec(prometheus.CounterOpts{
        Name: "firewall_packets_blocked_total",
    }, []string{"reason", "rule_name"})

    inspectionLatency = promauto.NewHistogram(prometheus.HistogramOpts{
        Name:    "firewall_inspection_latency_microseconds",
        Buckets: prometheus.ExponentialBuckets(10, 2, 10),
    })

    cacheHitRate = promauto.NewGauge(prometheus.GaugeOpts{
        Name: "firewall_cache_hit_rate_percent",
    })

    activeConnections = promauto.NewGauge(prometheus.GaugeOpts{
        Name: "firewall_active_connections",
    })
)
```

### 9.2 Health Endpoints
```go
// HTTP health check
func (fw *FirewallEngine) HealthCheck() gin.HandlerFunc {
    return func(c *gin.Context) {
        health := map[string]interface{}{
            "status":              "UP",
            "wfp_session":         fw.wfpSession.IsHealthy(),
            "driver_connection":   fw.driverClient.IsHealthy(),
            "cache_size":          fw.verdictCache.Len(),
            "active_connections":  fw.connectionTracker.Count(),
            "rules_loaded":        len(fw.sortedRules),
        }

        c.JSON(200, health)
    }
}
```

---

## 10. Security Considerations

### 10.1 Rule Validation
- **Syntax validation**: Ensure CIDR, port ranges are valid
- **Circular reference detection**: Prevent object reference loops
- **Priority conflicts**: Warn if conflicting rules at same priority
- **Resource limits**: Max 10,000 rules, max 1M connections

### 10.2 API Security
- **Authentication**: JWT tokens for gRPC and REST API
- **Authorization**: Role-based access (admin, operator, viewer)
- **Rate limiting**: 100 requests/minute per client
- **Input sanitization**: Validate all user inputs

### 10.3 Fail-Safe Mechanisms
```go
// Fail mode: "open" (allow on error) or "closed" (deny on error)
func (fw *FirewallEngine) applyFailMode(err error) Verdict {
    if fw.config.FailMode == "closed" {
        log.Error("Inspection error, DENYING packet (fail-closed):", err)
        return VerdictDrop
    }

    log.Warn("Inspection error, ALLOWING packet (fail-open):", err)
    return VerdictAllow
}

// Automatic rule rollback on error
func (fw *FirewallEngine) RollbackRules() error {
    if err := fw.LoadConfig(fw.lastGoodConfigPath); err != nil {
        return err
    }

    return fw.applyRulesToWFP()
}
```

---

## 11. Success Metrics

### 11.1 Performance Targets
- **Packet inspection throughput**: >100,000 pps
- **Rule matching latency**: <50 μs per packet
- **Cache hit rate**: >80%
- **WFP filter operations**: <10ms per batch
- **Database writes**: <5ms per transaction

### 11.2 Reliability Targets
- **Uptime**: 99.9% (8.76 hours downtime/year)
- **Config reload**: <1 second
- **Failover time**: <100ms (fail-open mode)
- **Memory usage**: <500 MB for 10k rules
- **CPU usage**: <20% at 50k pps

### 11.3 Functional Targets
- **Rule capacity**: 10,000+ rules
- **Connection tracking**: 1,000,000 concurrent connections
- **Log throughput**: 10,000 entries/second
- **Hot-reload**: Zero packet loss during reload

---

## 12. Risks & Mitigations

| Risk | Impact | Mitigation |
|------|--------|------------|
| **WFP API failure** | High | Implement fallback to SafeOps verdict engine only |
| **Driver crash** | High | Auto-restart driver, fail-open mode |
| **Rule conflict** | Medium | Validation, priority warnings, UI alerts |
| **Cache poisoning** | Medium | TTL expiration, size limits, LRU eviction |
| **Memory exhaustion** | Medium | Connection limits, cache size caps, leak detection |
| **Config corruption** | Low | Backup last good config, rollback on error |
| **Database failure** | Low | In-memory cache continues, retry writes |

---

## 13. Future Enhancements

### 13.1 Advanced Features
- **Application-aware filtering**: Block by process name/executable
- **Geofencing**: Block traffic from specific countries
- **Time-based rules**: Enable/disable rules by schedule
- **Bandwidth shaping**: Per-rule rate limiting
- **IPS integration**: Inline IPS with signature matching

### 13.2 ML-Based Features
- **Anomaly detection**: Machine learning for behavior-based blocking
- **Threat intelligence feeds**: Auto-update blocklists from TI feeds
- **Smart caching**: Predict cache entries based on traffic patterns

### 13.3 Enterprise Features
- **Multi-tenancy**: Separate firewall policies per tenant
- **Policy templates**: Pre-built rule sets (gaming, office, server)
- **Compliance reports**: PCI-DSS, HIPAA compliance checks
- **Audit logging**: Immutable audit trail for all changes

---

## 14. Documentation Requirements

- [ ] User Guide: Firewall rule syntax and examples
- [ ] API Reference: gRPC and REST API documentation
- [ ] Architecture Diagrams: Component interactions
- [ ] Performance Tuning Guide: Optimization tips
- [ ] Troubleshooting Guide: Common issues and solutions
- [ ] Security Best Practices: Hardening recommendations

---

## Conclusion

This plan provides a comprehensive roadmap for implementing the Firewall Engine with deep integration into SafeOps Engine and Network Logger. The phased approach ensures incremental delivery with testable milestones.

**Estimated Timeline**: 16 weeks (4 months)
**Team Size**: 2-3 developers
**Dependencies**: SafeOps Engine, Network Logger, NIC Management, Windows WFP API
