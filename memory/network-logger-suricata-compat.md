# Network Logger - Suricata Compatibility & E-W / N-S Traffic Classification

## Overview

Transform the network logger output to be directly compatible with Suricata IDS/IPS detection engine while adding traffic direction classification (East-West internal + North-South perimeter).

---

## Current Network Logger Output

**Format**: `network_packets_master.jsonl` - Generic packet capture format

**Limitation**: Raw packet data only, no threat detection context

---

## Target: Suricata EVE JSON Format

Suricata uses unified EVE JSON format with these key features:

```json
{
  "timestamp": "2026-02-15T12:34:56.789123Z",
  "flow_id": 1234567890,
  "in_iface": "eth0",
  "event_type": "alert|flow|http|dns|tls|stats",

  // ALERT events
  "alert": {
    "action": "allowed",
    "gid": 1,
    "signature_id": 2027880,
    "rev": 1,
    "signature": "Malware.C2.DOMAIN",
    "category": "Trojan Traffic",
    "severity": 3
  },

  // FLOW context
  "flow": {
    "pkts_toserver": 15,
    "pkts_toclient": 8,
    "bytes_toserver": 2048,
    "bytes_toclient": 512,
    "start": "2026-02-15T12:34:50Z",
    "end": "2026-02-15T12:34:56Z",
    "age": 6,
    "state": "closed"
  },

  // Protocol-specific
  "http": {...},
  "dns": {...},
  "tls": {...},

  // Traffic classification
  "traffic_type": "east_west|north_south|internal|external",
  "direction": "client2server|server2client"
}
```

---

## East-West vs North-South Traffic Classification

### Definition

**North-South (Perimeter Traffic)**
- Source: External IP ↔ Destination: Internal IP
- **Ingress**: Internet → Corporate network (inbound threats)
- **Egress**: Corporate network → Internet (data exfiltration, C2 beacons)
- **Risk**: High (Internet-facing risks)

**East-West (Internal Traffic)**
- Source: Internal IP ↔ Destination: Internal IP (both on LAN)
- **Lateral Movement**: Attacker pivoting within network
- **Inter-server Communication**: Database, file shares, APIs
- **Risk**: Medium (insider threat, compromised host spreading)

### Examples

| Traffic | Type | Risk |
|---------|------|------|
| 192.168.1.100 → 8.8.8.8:443 | North-South (Egress) | 🔴 High |
| 8.8.8.8 → 192.168.1.100:80 | North-South (Ingress) | 🔴 High |
| 192.168.1.100 → 192.168.1.200:445 (SMB) | East-West | 🟠 Medium |
| 192.168.1.100 → 192.168.1.1:53 (DNS) | East-West | 🟡 Low |
| 192.168.1.100 → 10.0.0.100 (VPN) | North-South | 🔴 High |

---

## Implementation: Enhanced Master Log Format

### Step 1: Update Packet Model with Classification

**File**: `src/network_logger/pkg/models/packet.go`

Add fields to `PacketLog`:

```go
// TrafficClass categorizes the traffic
type TrafficClass struct {
    Type        string `json:"type"`        // "north_south", "east_west"
    Direction   string `json:"direction"`   // "ingress", "egress", "internal"
    Source      string `json:"source"`      // "external", "internal"
    Destination string `json:"destination"` // "external", "internal"
}

// Add to PacketLog struct
type PacketLog struct {
    // ... existing fields ...

    // NEW: Traffic classification
    TrafficClass  *TrafficClass `json:"traffic_class,omitempty"`

    // NEW: Suricata-compatible fields
    SuricataEvent *SuricataEvent `json:"suricata_event,omitempty"`
}

// SuricataEvent provides Suricata EVE JSON compatibility
type SuricataEvent struct {
    EventType   string                 `json:"event_type"` // "alert", "flow", "http", "dns", "tls"
    Severity    int                    `json:"severity,omitempty"`    // 1-3
    Action      string                 `json:"action,omitempty"`      // "allow", "drop", "reject"
    FlowID      int64                  `json:"flow_id,omitempty"`
    Alert       *SuricataAlert         `json:"alert,omitempty"`
    Flow        *SuricataFlow          `json:"flow,omitempty"`
}

type SuricataAlert struct {
    Action       string   `json:"action"`
    Signature    string   `json:"signature"`
    SignatureID  int      `json:"signature_id"`
    SignatureRev int      `json:"rev"`
    Category     string   `json:"category"`
    Severity     int      `json:"severity"`
}

type SuricataFlow struct {
    PktsToServer   int64  `json:"pkts_toserver"`
    PktsToclient   int64  `json:"pkts_toclient"`
    BytesToServer  int64  `json:"bytes_toserver"`
    BytesToClient  int64  `json:"bytes_toclient"`
    State          string `json:"state"`
}
```

### Step 2: Create Traffic Classifier

**File**: `src/network_logger/internal/classifier/traffic_classifier.go` (NEW)

```go
package classifier

import (
    "net"
    "github.com/safeops/network_logger/pkg/models"
)

// TrafficClassifier determines traffic type and direction
type TrafficClassifier struct {
    internalNetworks []*net.IPNet
    hotspotSubnet    *net.IPNet
}

// NewTrafficClassifier initializes the classifier
func NewTrafficClassifier() *TrafficClassifier {
    tc := &TrafficClassifier{
        internalNetworks: make([]*net.IPNet, 0),
    }

    // Define internal networks (RFC1918)
    tc.addNetwork("10.0.0.0/8")
    tc.addNetwork("172.16.0.0/12")
    tc.addNetwork("192.168.0.0/16")
    tc.addNetwork("127.0.0.0/8")        // Loopback
    tc.addNetwork("169.254.0.0/16")     // Link-local

    // Windows hotspot subnet
    tc.addNetwork("192.168.137.0/24")

    return tc
}

func (tc *TrafficClassifier) addNetwork(cidr string) {
    _, net, _ := net.ParseCIDR(cidr)
    if net != nil {
        tc.internalNetworks = append(tc.internalNetworks, net)
    }
}

// ClassifyPacket determines traffic type
func (tc *TrafficClassifier) ClassifyPacket(pkt *models.PacketLog) *models.TrafficClass {
    if pkt.Layers.Network == nil {
        return nil
    }

    srcIP := net.ParseIP(pkt.Layers.Network.SrcIP)
    dstIP := net.ParseIP(pkt.Layers.Network.DstIP)

    srcInternal := tc.isInternal(srcIP)
    dstInternal := tc.isInternal(dstIP)

    traffic := &models.TrafficClass{
        Source:      "external",
        Destination: "external",
    }

    // Determine source/dest classification
    if srcInternal {
        traffic.Source = "internal"
    }
    if dstInternal {
        traffic.Destination = "internal"
    }

    // Determine traffic type
    if srcInternal && dstInternal {
        // Internal ↔ Internal = East-West
        traffic.Type = "east_west"
        traffic.Direction = "internal"
    } else if srcInternal && !dstInternal {
        // Internal → External = North-South Egress
        traffic.Type = "north_south"
        traffic.Direction = "egress"
    } else if !srcInternal && dstInternal {
        // External → Internal = North-South Ingress
        traffic.Type = "north_south"
        traffic.Direction = "ingress"
    } else {
        // External ↔ External (unlikely in local capture)
        traffic.Type = "external"
        traffic.Direction = "external"
    }

    return traffic
}

func (tc *TrafficClassifier) isInternal(ip net.IP) bool {
    if ip == nil {
        return false
    }

    for _, network := range tc.internalNetworks {
        if network.Contains(ip) {
            return true
        }
    }
    return false
}

// GetRiskLevel returns risk score based on traffic type
func (tc *TrafficClassifier) GetRiskLevel(traffic *models.TrafficClass) int {
    if traffic == nil {
        return 1
    }

    // North-South = High Risk
    if traffic.Type == "north_south" {
        return 3
    }

    // East-West = Medium Risk
    if traffic.Type == "east_west" {
        return 2
    }

    // Internal = Low Risk
    return 1
}
```

### Step 3: Integrate Classification into Packet Processor

**File**: `src/network_logger/internal/capture/packet_processor.go`

Add classifier:

```go
import (
    "github.com/safeops/network_logger/internal/classifier"
)

type PacketProcessor struct {
    // ... existing fields ...
    trafficClassifier *classifier.TrafficClassifier  // NEW
}

func NewPacketProcessor() *PacketProcessor {
    return &PacketProcessor{
        // ... existing init ...
        trafficClassifier: classifier.NewTrafficClassifier(),
    }
}

func (pp *PacketProcessor) ProcessPacket(rawPkt *models.RawPacket) *models.PacketLog {
    // ... existing processing ...

    // NEW: Classify traffic
    packetLog.TrafficClass = pp.trafficClassifier.ClassifyPacket(packetLog)

    // ... rest of processing ...
    return packetLog
}
```

---

## Step 4: Create Suricata EVE JSON Collector

**File**: `src/network_logger/internal/collectors/suricata_log_collector.go` (NEW)

```go
package collectors

import (
    "bufio"
    "context"
    "encoding/json"
    "fmt"
    "log"
    "os"
    "sync"
    "time"

    "github.com/safeops/network_logger/pkg/models"
)

// SuricataCollector generates Suricata-compatible EVE JSON logs
type SuricataCollector struct {
    logPath       string
    batchQueue    chan map[string]interface{}
    mu            sync.Mutex
    file          *os.File
    writer        *bufio.Writer
    batchSize     int
    logsWritten   int64
    cycleInterval time.Duration
    flowID        int64
}

// NewSuricataCollector creates a new Suricata collector
func NewSuricataCollector(logPath string, cycleInterval time.Duration) *SuricataCollector {
    return &SuricataCollector{
        logPath:       logPath,
        batchQueue:    make(chan map[string]interface{}, 5000),
        batchSize:     50,
        cycleInterval: cycleInterval,
        flowID:        1000000,
    }
}

// Start begins the Suricata collector
func (c *SuricataCollector) Start(ctx context.Context) {
    c.openFile()
    go c.batchWriter(ctx)
    go c.cycleLoop(ctx)
}

// Process converts packet to Suricata event
func (c *SuricataCollector) Process(pkt *models.PacketLog) {
    // Convert to Suricata EVE JSON format
    event := c.toSuricataEvent(pkt)
    if event == nil {
        return
    }

    select {
    case c.batchQueue <- event:
    default:
        // Queue full, drop
    }
}

// toSuricataEvent converts PacketLog to Suricata EVE format
func (c *SuricataCollector) toSuricataEvent(pkt *models.PacketLog) map[string]interface{} {
    event := map[string]interface{}{
        "timestamp": pkt.Timestamp.ISO8601,
        "event_type": c.determineEventType(pkt),
        "flow_id": c.flowID,
    }

    c.flowID++

    // Network info
    if pkt.Layers.Network != nil {
        event["src_ip"] = pkt.Layers.Network.SrcIP
        event["dest_ip"] = pkt.Layers.Network.DstIP
    }

    // Transport info
    if pkt.Layers.Transport != nil {
        event["src_port"] = pkt.Layers.Transport.SrcPort
        event["dest_port"] = pkt.Layers.Transport.DstPort
        event["proto"] = c.protoName(pkt.Layers.Network.Protocol)
    }

    // Traffic classification
    if pkt.TrafficClass != nil {
        event["traffic_type"] = pkt.TrafficClass.Type
        event["direction"] = pkt.TrafficClass.Direction
    }

    // HTTP data
    if pkt.ParsedApplication.HTTP != nil {
        httpData := map[string]interface{}{
            "hostname": pkt.ParsedApplication.HTTP.Host,
            "url": pkt.ParsedApplication.HTTP.URI,
            "http_user_agent": pkt.ParsedApplication.HTTP.UserAgent,
            "http_method": pkt.ParsedApplication.HTTP.Method,
            "status": pkt.ParsedApplication.HTTP.StatusCode,
        }
        event["http"] = httpData
    }

    // DNS data
    if pkt.ParsedApplication.DNS != nil {
        dnsData := map[string]interface{}{
            "queries": pkt.ParsedApplication.DNS.Queries,
            "answers": pkt.ParsedApplication.DNS.Answers,
        }
        event["dns"] = dnsData
    }

    // TLS data
    if pkt.ParsedApplication.TLS != nil && pkt.ParsedApplication.TLS.ClientHello != nil {
        tlsData := map[string]interface{}{
            "sni": pkt.ParsedApplication.TLS.ClientHello.SNI,
            "version": pkt.ParsedApplication.TLS.ClientHello.Version,
        }
        event["tls"] = tlsData
    }

    // Flow stats
    if pkt.FlowContext != nil {
        flowData := map[string]interface{}{
            "pkts_toserver": pkt.FlowContext.PacketsForward,
            "pkts_toclient": pkt.FlowContext.PacketsBackward,
            "bytes_toserver": pkt.FlowContext.BytesForward,
            "bytes_toclient": pkt.FlowContext.BytesBackward,
            "state": pkt.FlowContext.FlowState,
        }
        event["flow"] = flowData
    }

    return event
}

func (c *SuricataCollector) determineEventType(pkt *models.PacketLog) string {
    app := pkt.ParsedApplication.DetectedProtocol

    switch app {
    case "http":
        return "http"
    case "dns":
        return "dns"
    case "tls":
        return "tls"
    default:
        return "flow"
    }
}

func (c *SuricataCollector) protoName(proto uint8) string {
    names := map[uint8]string{
        1: "ICMP",
        6: "TCP",
        17: "UDP",
    }
    if name, ok := names[proto]; ok {
        return name
    }
    return "OTHER"
}

func (c *SuricataCollector) openFile() error {
    c.mu.Lock()
    defer c.mu.Unlock()

    if c.file != nil {
        if c.writer != nil {
            c.writer.Flush()
        }
        c.file.Close()
    }

    file, err := os.OpenFile(c.logPath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0644)
    if err != nil {
        return err
    }

    c.file = file
    c.writer = bufio.NewWriter(file)
    c.logsWritten = 0
    return nil
}

func (c *SuricataCollector) batchWriter(ctx context.Context) {
    batch := make([]map[string]interface{}, 0, c.batchSize)
    ticker := time.NewTicker(500 * time.Millisecond)
    defer ticker.Stop()

    for {
        select {
        case <-ctx.Done():
            if len(batch) > 0 {
                c.writeBatch(batch)
            }
            c.closeFile()
            return
        case event := <-c.batchQueue:
            batch = append(batch, event)
            if len(batch) >= c.batchSize {
                c.writeBatch(batch)
                batch = make([]map[string]interface{}, 0, c.batchSize)
            }
        case <-ticker.C:
            if len(batch) > 0 {
                c.writeBatch(batch)
                batch = make([]map[string]interface{}, 0, c.batchSize)
            }
        }
    }
}

func (c *SuricataCollector) writeBatch(batch []map[string]interface{}) {
    c.mu.Lock()
    defer c.mu.Unlock()

    if c.writer == nil {
        return
    }

    for _, event := range batch {
        data, err := json.Marshal(event)
        if err != nil {
            continue
        }
        c.writer.Write(data)
        c.writer.WriteByte('\n')
        c.logsWritten++
    }
    c.writer.Flush()
}

func (c *SuricataCollector) cycleLoop(ctx context.Context) {
    ticker := time.NewTicker(c.cycleInterval)
    defer ticker.Stop()

    for {
        select {
        case <-ctx.Done():
            return
        case <-ticker.C:
            log.Printf("🔄 Suricata EVE log cycled")
            c.openFile()
        }
    }
}

func (c *SuricataCollector) closeFile() {
    c.mu.Lock()
    defer c.mu.Unlock()

    if c.writer != nil {
        c.writer.Flush()
        c.writer = nil
    }
    if c.file != nil {
        c.file.Close()
        c.file = nil
    }
}

// GetStats returns collector statistics
func (c *SuricataCollector) GetStats() map[string]interface{} {
    c.mu.Lock()
    defer c.mu.Unlock()

    return map[string]interface{}{
        "logs_written": c.logsWritten,
        "queue_size": len(c.batchQueue),
    }
}
```

---

## Step 5: Update Main to Enable Suricata Collector

**File**: `src/network_logger/cmd/logger/main.go`

```go
// In main():

// Create Suricata EVE JSON collector
suricataCollector := collectors.NewSuricataCollector(
    filepath.Join(logDir, "suricata_eve.jsonl"),
    5*time.Minute,
)
suricataCollector.Start(ctx)

// Process packets through both collectors
processor.OnPacket(func(pkt *models.PacketLog) {
    idsCollector.Process(pkt)
    suricataCollector.Process(pkt)        // NEW
})
```

---

## Configuration

### Update config.yaml

```yaml
collectors:
  ids_log:
    enabled: true
    path: "../../logs/network_packets_ids.jsonl"
    cycle_minutes: 5
    batch_size: 50

  suricata_eve:
    enabled: true
    path: "../../logs/suricata_eve.jsonl"
    cycle_minutes: 5
    batch_size: 50

traffic_classification:
  internal_networks:
    - "10.0.0.0/8"
    - "172.16.0.0/12"
    - "192.168.0.0/16"
    - "192.168.137.0/24"  # Windows hotspot

  risk_levels:
    north_south: 3  # High risk
    east_west: 2    # Medium risk
    internal: 1     # Low risk
```

---

## Sample Output: North-South (Egress)

```json
{
  "timestamp": "2026-02-15T12:34:56.123456Z",
  "event_type": "tls",
  "flow_id": 1000001,
  "src_ip": "192.168.1.100",
  "dest_ip": "8.8.8.8",
  "src_port": 54321,
  "dest_port": 443,
  "proto": "TCP",
  "traffic_type": "north_south",
  "direction": "egress",
  "tls": {
    "sni": "evil-c2.com",
    "version": "TLS1.2"
  },
  "flow": {
    "pkts_toserver": 15,
    "pkts_toclient": 8,
    "bytes_toserver": 2048,
    "bytes_toclient": 512,
    "state": "closed"
  }
}
```

---

## Sample Output: East-West (Lateral Movement)

```json
{
  "timestamp": "2026-02-15T12:35:10.234567Z",
  "event_type": "flow",
  "flow_id": 1000002,
  "src_ip": "192.168.1.100",
  "dest_ip": "192.168.1.200",
  "src_port": 12345,
  "dest_port": 445,
  "proto": "TCP",
  "traffic_type": "east_west",
  "direction": "internal",
  "flow": {
    "pkts_toserver": 50,
    "pkts_toclient": 45,
    "bytes_toserver": 8192,
    "bytes_toclient": 4096,
    "state": "closed"
  }
}
```

---

## Integration with Firewall Engine

Connect Suricata EVE logs to the SafeOps firewall engine:

**Location**: `src/firewall_engine/internal/api/server.go`

```go
// Add endpoint to query threat classification
router.GET("/api/traffic-classification/:flow_id", func(c *gin.Context) {
    flowID := c.Param("flow_id")

    // Read from suricata_eve.jsonl
    classification := lookupFlowTrafficType(flowID)

    c.JSON(200, map[string]interface{}{
        "flow_id": flowID,
        "type": classification.Type,        // "north_south", "east_west"
        "direction": classification.Direction, // "ingress", "egress", "internal"
        "risk_level": getRiskLevel(classification),
    })
})
```

---

## Logging Locations

After implementation:

```
logs/
├── network_packets_master.jsonl     # Generic packet capture (existing)
├── network_packets_ids.jsonl        # IDS-optimized format (enhanced)
├── suricata_eve.jsonl               # Suricata EVE JSON (NEW)
└── traffic_classification.log       # Classification stats (NEW)
```

---

## Real-Time Analysis Dashboard

Example queries using the new logs:

**Find all North-South Egress traffic:**
```bash
cat logs/suricata_eve.jsonl | jq 'select(.direction == "egress")'
```

**Find all East-West suspicious:**
```bash
cat logs/suricata_eve.jsonl | jq 'select(.traffic_type == "east_west" and .dest_port == 445)'
```

**High-risk IDS alerts:**
```bash
cat logs/network_packets_ids.jsonl | jq 'select(.anomalies.risk_score > 70)'
```

---

## Summary

| Feature | Before | After |
|---------|--------|-------|
| **Packet Capture** | ✅ All packets | ✅ All packets |
| **Traffic Classification** | ❌ No | ✅ North-South / East-West |
| **Suricata Compatible** | ❌ No | ✅ EVE JSON format |
| **IDS Detection Ready** | ⚠️ Partial | ✅ Full |
| **Risk Scoring** | ❌ No | ✅ By traffic type |
| **Threat Intelligence Integration** | ❌ No | ✅ Via EVE format |

This makes SafeOps network logger a **professional-grade threat detection system** ready for enterprise IDS/IPS deployment.

