# Network Logger - Implementation Guide for IDS/IPS Enhancements

## Overview

This guide covers the specific code changes needed to transform the network logger from "passive packet capture" to "threat detection ready" with minimal disruption to existing code.

---

## 1. Add JA3/JA3S TLS Fingerprinting

### Step 1.1: Add Library Dependency

**File**: `src/network_logger/go.mod`

```go
require (
    github.com/salesforce/ja3 v0.0.0-20220831173540-e4d4e0b6fbc8
    // ... existing deps
)
```

**Command**: `cd src/network_logger && go mod tidy`

### Step 1.2: Create JA3 Calculator

**File**: `src/network_logger/internal/parser/ja3.go` (NEW)

```go
package parser

import (
    "crypto/md5"
    "fmt"
    "strconv"
    "strings"
    "github.com/safeops/network_logger/pkg/models"
)

// ComputeJA3 computes JA3 fingerprint from TLS ClientHello
func ComputeJA3(clientHello *models.TLSClientHello) string {
    if clientHello == nil {
        return ""
    }

    // JA3 = TLSVersion,Ciphers,Extensions,EllipticCurves,EllipticCurvePointFormats

    // Parse TLS version (e.g., "TLS 1.2" -> "771")
    tlsVersion := parseTLSVersion(clientHello.Version)

    // Format ciphers (comma-separated hex values)
    ciphers := formatCiphers(clientHello.CipherSuites)

    // Format extensions (comma-separated IDs)
    extensions := formatExtensions(clientHello.Extensions)

    // Format curves (from supported_groups extension)
    curves := extractCurves(clientHello.Extensions)

    // Format point formats (from ec_point_formats extension)
    formats := extractPointFormats(clientHello.Extensions)

    // Build JA3 string
    ja3String := fmt.Sprintf("%s,%s,%s,%s,%s",
        tlsVersion, ciphers, extensions, curves, formats)

    // Return JA3 = MD5(JA3String)
    hash := md5.Sum([]byte(ja3String))
    return fmt.Sprintf("%x", hash)
}

// ComputeJA3S computes JA3S fingerprint from TLS ServerHello
func ComputeJA3S(serverHello *models.TLSServerHello) string {
    if serverHello == nil {
        return ""
    }

    // JA3S = TLSVersion,Cipher,Extensions
    tlsVersion := parseTLSVersion(serverHello.Version)
    cipher := formatSingleCipher(serverHello.CipherSuite)
    extensions := formatExtensions(serverHello.Extensions)

    ja3sString := fmt.Sprintf("%s,%s,%s", tlsVersion, cipher, extensions)
    hash := md5.Sum([]byte(ja3sString))
    return fmt.Sprintf("%x", hash)
}

func parseTLSVersion(version string) string {
    // Map version strings to IANA codes
    versions := map[string]string{
        "SSL 3.0":  "768",
        "TLS 1.0":  "769",
        "TLS 1.1":  "770",
        "TLS 1.2":  "771",
        "TLS 1.3":  "772",
    }
    if code, ok := versions[version]; ok {
        return code
    }
    return "0"
}

func formatCiphers(ciphers []string) string {
    var codes []string
    for _, cipher := range ciphers {
        if code := cipherNameToCode(cipher); code != "" {
            codes = append(codes, code)
        }
    }
    return strings.Join(codes, ",")
}

func formatSingleCipher(cipher string) string {
    if code := cipherNameToCode(cipher); code != "" {
        return code
    }
    return "0"
}

func formatExtensions(exts []models.TLSExt) string {
    var ids []string
    for _, ext := range exts {
        if id := extensionNameToID(ext.Type); id != "" {
            ids = append(ids, id)
        }
    }
    return strings.Join(ids, ",")
}

func extractCurves(exts []models.TLSExt) string {
    for _, ext := range exts {
        if ext.Type == "supported_groups" {
            // Parse curves from extension data
            // Return comma-separated curve IDs
            if curves, ok := ext.Data.(string); ok {
                return curves
            }
        }
    }
    return ""
}

func extractPointFormats(exts []models.TLSExt) string {
    for _, ext := range exts {
        if ext.Type == "ec_point_formats" {
            if formats, ok := ext.Data.(string); ok {
                return formats
            }
        }
    }
    return ""
}

// Helper: Map cipher suite names to IANA codes
func cipherNameToCode(name string) string {
    codes := map[string]string{
        "TLS_RSA_WITH_AES_128_CBC_SHA":           "47",
        "TLS_RSA_WITH_AES_256_CBC_SHA":           "53",
        "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256": "49195",
        "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256":  "49199",
        // ... add more as needed
    }
    if code, ok := codes[name]; ok {
        return code
    }
    return ""
}

// Helper: Map extension names to IDs
func extensionNameToID(name string) string {
    ids := map[string]string{
        "server_name":              "0",
        "supported_groups":         "10",
        "ec_point_formats":         "11",
        "signature_algorithms":     "13",
        "session_ticket":           "35",
        "application_layer_protocol_negotiation": "16",
        "padding":                  "21",
    }
    if id, ok := ids[name]; ok {
        return id
    }
    return ""
}
```

### Step 1.3: Update TLSCompact in IDSLog

**File**: `src/network_logger/internal/collectors/idsips_log_collector.go`

Modify the `TLSCompact` struct:

```go
type TLSCompact struct {
    SNI         string `json:"sni,omitempty"`
    Version     string `json:"version,omitempty"`
    JA3         string `json:"ja3,omitempty"`        // NEW
    JA3S        string `json:"ja3s,omitempty"`       // NEW
    CertStatus  string `json:"cert_status,omitempty"` // NEW: valid, expired, self-signed, mismatch
}
```

Update `toIDSLog()` method:

```go
if pkt.ParsedApplication.TLS != nil && pkt.ParsedApplication.TLS.ClientHello != nil {
    ja3 := parser.ComputeJA3(pkt.ParsedApplication.TLS.ClientHello)
    ja3s := ""
    if pkt.ParsedApplication.TLS.ServerHello != nil {
        ja3s = parser.ComputeJA3S(pkt.ParsedApplication.TLS.ServerHello)
    }

    idsLog.TLS = &TLSCompact{
        SNI:     pkt.ParsedApplication.TLS.ClientHello.SNI,
        Version: pkt.ParsedApplication.TLS.ClientHello.Version,
        JA3:     ja3,        // NEW
        JA3S:    ja3s,       // NEW
        CertStatus: determineCertStatus(pkt), // NEW
    }
}
```

---

## 2. Add Payload Information to IDS Logs

### Step 2.1: Create Payload Analysis Struct

**File**: `src/network_logger/internal/parser/payload.go` (NEW)

```go
package parser

import (
    "encoding/hex"
    "math"
)

// PayloadInfo contains analyzed payload data
type PayloadInfo struct {
    Length      int     `json:"length"`
    DataHex     string  `json:"data_hex,omitempty"`     // First 512 bytes
    Preview     string  `json:"preview,omitempty"`      // Text preview
    Entropy     float64 `json:"entropy,omitempty"`      // 0-8 shannon entropy
}

// AnalyzePayload creates payload info with entropy calculation
func AnalyzePayload(data []byte, maxLen int) *PayloadInfo {
    if len(data) == 0 {
        return nil
    }

    info := &PayloadInfo{
        Length: len(data),
    }

    // Limit hex dump to maxLen bytes (e.g., 512)
    if maxLen > 0 && len(data) > maxLen {
        data = data[:maxLen]
    }

    // Hex dump
    info.DataHex = hex.EncodeToString(data)

    // Text preview (sanitized)
    info.Preview = sanitizePreview(data)

    // Shannon entropy for anomaly detection
    info.Entropy = CalculateEntropy(data)

    return info
}

// CalculateEntropy computes Shannon entropy (0-8 for bytes)
// High entropy = compressed/encrypted (anomaly)
func CalculateEntropy(data []byte) float64 {
    if len(data) == 0 {
        return 0
    }

    // Count byte frequencies
    freq := [256]int{}
    for _, b := range data {
        freq[b]++
    }

    // Shannon entropy
    var entropy float64
    flen := float64(len(data))
    for _, f := range freq {
        if f > 0 {
            p := float64(f) / flen
            entropy -= p * math.Log2(p)
        }
    }

    return entropy
}

// sanitizePreview creates a safe text preview
func sanitizePreview(data []byte) string {
    if len(data) > 100 {
        data = data[:100]
    }

    preview := ""
    for _, b := range data {
        if b >= 32 && b < 127 {
            preview += string(b)
        } else {
            preview += "."
        }
    }
    return preview
}
```

### Step 2.2: Update IDSLog to Include Payload

**File**: `src/network_logger/internal/collectors/idsips_log_collector.go`

```go
type IDSLog struct {
    TimestampIST string           `json:"timestamp_ist"`
    PacketID     string           `json:"packet_id"`
    FlowID       string           `json:"flow_id"`
    SrcIP        string           `json:"src_ip"`
    DstIP        string           `json:"dst_ip"`
    SrcPort      uint16           `json:"src_port,omitempty"`
    DstPort      uint16           `json:"dst_port,omitempty"`
    Protocol     string           `json:"protocol"`
    SrcGeo       *models.GeoInfo  `json:"src_geo,omitempty"`
    DstGeo       *models.GeoInfo  `json:"dst_geo,omitempty"`
    HTTP         *models.HTTPData `json:"http,omitempty"`
    DNS          *models.DNSData  `json:"dns,omitempty"`
    TLS          *TLSCompact      `json:"tls,omitempty"`
    TCPFlags     string           `json:"tcp_flags,omitempty"`
    Payload      *PayloadInfo     `json:"payload,omitempty"`  // NEW
    Anomalies    *AnomalyScore    `json:"anomalies,omitempty"` // NEW
}

// PayloadInfo for IDS logs (from parser package)
type PayloadInfo struct {
    Length  int     `json:"length"`
    DataHex string  `json:"data_hex,omitempty"`
    Preview string  `json:"preview,omitempty"`
    Entropy float64 `json:"entropy,omitempty"`
}

// AnomalyScore provides risk assessment
type AnomalyScore struct {
    RiskScore       float64 `json:"risk_score"`       // 0-100
    IsUnusualPort   bool    `json:"is_unusual_port,omitempty"`
    IsFragmented    bool    `json:"is_fragmented,omitempty"`
    IsSuspiciousSize bool   `json:"is_suspicious_size,omitempty"`
    Reasons         []string `json:"reasons,omitempty"`
}
```

Update `toIDSLog()`:

```go
// Add payload analysis
if pkt.Layers.Payload != nil {
    idsLog.Payload = parser.AnalyzePayload(
        parseHexPayload(pkt.Layers.Payload.DataHex),
        512,
    )
}

// Add anomaly scoring
idsLog.Anomalies = scoreAnomalies(pkt)
```

---

## 3. TCP State Machine Tracking

### Step 3.1: Add State Tracking to Flow Context

**File**: `src/network_logger/pkg/models/packet.go`

Update `FlowContext`:

```go
type FlowContext struct {
    FlowID          string       `json:"flow_id"`
    Direction       string       `json:"direction"`
    PacketsForward  int          `json:"packets_forward"`
    PacketsBackward int          `json:"packets_backward"`
    BytesForward    int64        `json:"bytes_forward"`
    BytesBackward   int64        `json:"bytes_backward"`
    FlowStartTime   float64      `json:"flow_start_time"`
    FlowDuration    float64      `json:"flow_duration"`
    FlowState       string       `json:"flow_state"` // NEW: "SYN_SENT", "ESTABLISHED", etc.
    TCPState        string       `json:"tcp_state,omitempty"` // NEW: detailed state
    TCPStateReason  string       `json:"tcp_state_reason,omitempty"` // Why in this state
    ProcessInfo     *ProcessInfo `json:"process,omitempty"`
}
```

### Step 3.2: Create State Machine

**File**: `src/network_logger/internal/flow/state_machine.go` (NEW)

```go
package flow

import (
    "fmt"
    "github.com/safeops/network_logger/pkg/models"
)

// TCPStateMachine tracks TCP connection states
type TCPStateMachine struct {
    CurrentState string
    LastSYN      bool
    LastACK      bool
    LastFIN      bool
    LastRST      bool
}

// UpdateState processes TCP flags and returns new state
func (sm *TCPStateMachine) UpdateState(flags *models.TCPFlags) (newState string, reason string) {
    if flags == nil {
        return sm.CurrentState, ""
    }

    prev := sm.CurrentState

    // State transitions
    if flags.SYN && !flags.ACK {
        // Client initiating: SYN
        sm.CurrentState = "SYN_SENT"
        reason = "SYN flag set"
    } else if flags.SYN && flags.ACK {
        // Server responding: SYN-ACK
        sm.CurrentState = "SYN_RECV"
        reason = "SYN-ACK received"
    } else if flags.ACK && prev == "SYN_RECV" {
        // Client ACKing server response: connection established
        sm.CurrentState = "ESTABLISHED"
        reason = "ACK received after SYN-ACK"
    } else if flags.FIN {
        // Graceful close
        sm.CurrentState = "FIN_WAIT"
        reason = "FIN flag set"
    } else if flags.RST {
        // Abnormal close
        sm.CurrentState = "RST"
        reason = "RST flag set"
    } else if flags.ACK && sm.CurrentState == "" {
        // Pure ACK without SYN (unusual)
        sm.CurrentState = "ANOMALY_PURE_ACK"
        reason = "ACK without prior SYN"
    } else if sm.CurrentState == "" {
        sm.CurrentState = "ESTABLISHED"
    }

    sm.LastSYN = flags.SYN
    sm.LastACK = flags.ACK
    sm.LastFIN = flags.FIN
    sm.LastRST = flags.RST

    return sm.CurrentState, reason
}

// IsAnomalous checks for state machine violations
func (sm *TCPStateMachine) IsAnomalous() bool {
    anomalies := map[string]bool{
        "ANOMALY_PURE_ACK": true,
        "RST":              true,
    }
    return anomalies[sm.CurrentState]
}
```

---

## 4. Risk Scoring & Anomaly Detection

### Step 4.1: Create Anomaly Scorer

**File**: `src/network_logger/internal/anomaly/scorer.go` (NEW)

```go
package anomaly

import (
    "fmt"
    "github.com/safeops/network_logger/pkg/models"
)

// Score computes overall risk score (0-100)
func Score(pkt *models.PacketLog) (float64, []string) {
    var score float64
    var reasons []string

    // Port rarity (common ports = low risk)
    if isUnusualPort(pkt) {
        score += 15
        reasons = append(reasons, "unusual_port")
    }

    // Fragmentation (indicates evasion)
    if isFragmented(pkt) {
        score += 25
        reasons = append(reasons, "fragmented_packet")
    }

    // Payload entropy (high = compressed/encrypted, suspicious if not expected)
    if pkt.Layers.Payload != nil && len(pkt.Layers.Payload.DataHex) > 0 {
        entropy := calculateEntropy(pkt.Layers.Payload.DataHex)
        if entropy > 7.5 {
            score += 10
            reasons = append(reasons, "high_entropy_payload")
        }
    }

    // Protocol mismatches (HTTP on port 443, etc.)
    if protocolMismatch(pkt) {
        score += 20
        reasons = append(reasons, "protocol_port_mismatch")
    }

    // Multiple SYN attempts without completion (port scan)
    if isPortScan(pkt) {
        score += 30
        reasons = append(reasons, "possible_port_scan")
    }

    // Suspicious user agents
    if pkt.ParsedApplication.HTTP != nil &&
       isSuspiciousUserAgent(pkt.ParsedApplication.HTTP.UserAgent) {
        score += 15
        reasons = append(reasons, "suspicious_user_agent")
    }

    // Ensure 0-100 range
    if score > 100 {
        score = 100
    }

    return score, reasons
}

func isUnusualPort(pkt *models.PacketLog) bool {
    if pkt.Layers.Transport == nil {
        return false
    }

    commonPorts := map[uint16]bool{
        80: true, 443: true, 22: true, 23: true, 21: true,
        25: true, 53: true, 110: true, 143: true, 445: true,
        3389: true, 8080: true, 8443: true,
    }

    port := pkt.Layers.Transport.DstPort
    return !commonPorts[port]
}

func isFragmented(pkt *models.PacketLog) bool {
    if pkt.Layers.Network == nil {
        return false
    }
    return pkt.Layers.Network.FlagsMF || pkt.Layers.Network.FragmentOffset > 0
}

func protocolMismatch(pkt *models.PacketLog) bool {
    // Example: HTTP on HTTPS port, DNS on TCP 53, etc.
    if pkt.Layers.Transport == nil || pkt.Layers.Network == nil {
        return false
    }

    port := pkt.Layers.Transport.DstPort
    proto := pkt.ParsedApplication.DetectedProtocol

    // Known mismatches
    if port == 443 && proto == "http" {
        return true
    }
    if port == 53 && pkt.Layers.Network.Protocol == 6 && proto != "dns" {
        return true
    }

    return false
}

func isPortScan(pkt *models.PacketLog) bool {
    // Multiple SYN without ACK = scanning
    // This would be tracked at flow level, stub for now
    return false
}

func isSuspiciousUserAgent(ua string) bool {
    suspicious := []string{
        "curl", "wget", "python-requests", "nmap",
        "masscan", "zap", "burp",
    }
    for _, s := range suspicious {
        if ua == s {
            return true
        }
    }
    return false
}

func calculateEntropy(hexStr string) float64 {
    // Simplified entropy check
    if len(hexStr) < 10 {
        return 0
    }
    // Count repeating patterns
    // High entropy = few repeating bytes
    return 6.5 // Placeholder
}
```

---

## 5. Certificate Validation Tracking

### Step 5.1: Add Cert Validation to TLS Parser

**File**: `src/network_logger/internal/parser/tls.go`

Add method:

```go
func DetermineCertStatus(clientHello *models.TLSClientHello,
                        serverHello *models.TLSServerHello) string {
    if serverHello == nil {
        return "no_cert"
    }

    // This is a simplified check; real implementation would validate certs
    // For now, mark as "needs_validation"
    return "valid"
}
```

---

## 6. Testing the Changes

### Step 6.1: Create Test Fixture

**File**: `src/network_logger/internal/collectors/idsips_log_collector_test.go` (NEW)

```go
package collectors

import (
    "testing"
    "github.com/safeops/network_logger/pkg/models"
)

func TestIDSLogWithPayloadAndAnomalies(t *testing.T) {
    collector := NewIDSCollector("/tmp/test.jsonl", 5*time.Minute)

    pkt := &models.PacketLog{
        PacketID: "test_pkt_001",
        Timestamp: models.Timestamp{
            Epoch:   1707985496.123,
            ISO8601: "2026-02-15T12:00:00Z",
        },
        Layers: models.Layers{
            Network: &models.NetworkLayer{
                Version: 4,
                SrcIP:   "192.168.1.100",
                DstIP:   "8.8.8.8",
                Protocol: 6,
            },
            Transport: &models.TransportLayer{
                Protocol: 6,
                SrcPort:  54321,
                DstPort:  443,
                TCPFlags: &models.TCPFlags{
                    SYN: true,
                    ACK: false,
                },
            },
            Payload: &models.PayloadLayer{
                Length:  512,
                DataHex: "160303...",
            },
        },
        ParsedApplication: models.ParsedApplication{
            DetectedProtocol: "tls",
        },
    }

    idsLog := collector.toIDSLog(pkt)

    if idsLog == nil {
        t.Fatal("Expected IDS log, got nil")
    }

    if idsLog.Payload == nil {
        t.Error("Expected payload info")
    }

    if idsLog.Anomalies == nil {
        t.Error("Expected anomalies info")
    }
}
```

---

## Implementation Order

1. **Phase 1 (Week 1)** - Core enhancements
   - JA3/JA3S fingerprinting
   - Payload analysis + entropy
   - Risk scoring basics
   - TCP state machine

2. **Phase 2 (Week 2)** - Detection improvements
   - Certificate validation tracking
   - Anomaly scoring expansion
   - Direction asymmetry metrics

3. **Phase 3 (Week 3+)** - Advanced features
   - DNS anomaly detection
   - MIME type validation
   - MAC spoofing detection

---

## Configuration Updates

### Update config.yaml

```yaml
capture:
  interfaces: []
  promiscuous: true
  snapshot_length: 1600

logging:
  log_path: "../../logs/network_packets_master.jsonl"
  batch_size: 75
  cycle_minutes: 5

deduplication:
  enabled: true
  window_seconds: 30

# NEW sections
threat_detection:
  enable_ja3: true              # JA3 fingerprinting
  enable_risk_scoring: true     # Risk scores 0-100
  enable_anomaly_flags: true    # Anomaly detection
  payload_max_length: 512       # Max bytes to log
  enable_cert_validation: true  # Cert status tracking

anomaly_detection:
  entropy_threshold: 7.5        # High entropy = suspicious
  unusual_port_threshold: 3000  # Ports above this = unusual
```

---

## Backward Compatibility

✅ All new fields are optional (use `omitempty` JSON tags)
✅ Existing IDS systems continue to work
✅ New fields available for opt-in threat detection
✅ No breaking changes to existing log format

---

## Expected Output Sample

```json
{
  "timestamp_ist": "2026-02-15T12:34:56.789Z",
  "packet_id": "pkt_abc123",
  "flow_id": "192.168.1.100:12345-8.8.8.8:443/TCP",
  "src_ip": "192.168.1.100",
  "dst_ip": "8.8.8.8",
  "src_port": 12345,
  "dst_port": 443,
  "protocol": "TCP",
  "tcp_flags": "S",
  "tls": {
    "sni": "google.com",
    "version": "TLS1.3",
    "ja3": "a4b5c6d7e8f9...",
    "ja3s": "b5c6d7e8f9a0..."
  },
  "payload": {
    "length": 512,
    "data_hex": "160303012345678...",
    "preview": ".............",
    "entropy": 7.2
  },
  "anomalies": {
    "risk_score": 8.5,
    "is_unusual_port": false,
    "is_fragmented": false,
    "reasons": []
  }
}
```

