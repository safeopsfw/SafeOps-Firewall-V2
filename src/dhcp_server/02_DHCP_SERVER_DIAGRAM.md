# DHCP Server Component - Architecture Diagram

**File:** 02_DHCP_SERVER_DIAGRAM.md
**Component:** DHCP Server
**Purpose:** Automatic IP allocation, lease management, dynamic DNS updates, CA certificate distribution

---

## 🎯 DHCP Server Architecture

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                            DHCP SERVER SERVICE                               │
│                            Port: 67 (UDP)                                    │
│                            gRPC: 50054                                       │
│                            Metrics: 9154 (Prometheus)                        │
└─────────────────────────────────────────────────────────────────────────────┘
                                    │
                ┌───────────────────┼───────────────────┐
                │                   │                   │
                ▼                   ▼                   ▼
    ┌───────────────────┐  ┌───────────────────┐  ┌───────────────────┐
    │ DHCP PROTOCOL     │  │ LEASE MANAGEMENT  │  │ CA INTEGRATION    │
    │ (RFC 2131)        │  │ (PostgreSQL)      │  │ (gRPC)            │
    ├───────────────────┤  ├───────────────────┤  ├───────────────────┤
    │ • DISCOVER        │  │ • IP Allocation   │  │ • GetCertInfo()   │
    │ • OFFER           │  │ • Renewal (T1/T2) │  │ • Option 224/225  │
    │ • REQUEST         │  │ • Conflict Check  │  │ • Option 252      │
    │ • ACK (+ CA URLs) │  │ • Expiry Cleanup  │  │ • URL Caching     │
    └───────────────────┘  └───────────────────┘  └───────────────────┘
```

---

## 📊 DHCP Protocol Flow (with CA Certificate Distribution)

```
┌─────────────────────────────────────────────────────────────────────────────┐
│ STEP 1: Device connects to network                                          │
│ MAC: AA:BB:CC:DD:EE:FF                                                      │
│ Hostname: "johns-laptop"                                                     │
└────────────────────┬────────────────────────────────────────────────────────┘
                     │
                     │ Broadcasts: DHCP DISCOVER
                     │ Src: 0.0.0.0:68
                     │ Dst: 255.255.255.255:67
                     │
                     ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│ STEP 2: DHCP Server receives DISCOVER                                       │
│ Location: internal/server/listener.go                                       │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                              │
│  UDP Listener (0.0.0.0:67)                                                  │
│  ┌────────────────────────────────────────┐                                 │
│  │ Receives broadcast packet:             │                                 │
│  │ • Parse DHCP packet                    │                                 │
│  │ • Extract MAC: AA:BB:CC:DD:EE:FF       │                                 │
│  │ • Extract Hostname: "johns-laptop"     │                                 │
│  │ • Message Type: DISCOVER               │                                 │
│  └────────────────────────────────────────┘                                 │
│          │                                                                   │
│          ▼                                                                   │
│  packet_handler.go                                                           │
│  ┌────────────────────────────────────────┐                                 │
│  │ Route to discovery/discovery.go        │                                 │
│  └────────────────────────────────────────┘                                 │
└────────────────────┬────────────────────────────────────────────────────────┘
                     │
                     ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│ STEP 3: Lease Allocation                                                    │
│ Location: internal/discovery/discovery.go                                   │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                              │
│  allocator.go                                                                │
│  ┌────────────────────────────────────────┐                                 │
│  │ 1. Check for existing lease:           │                                 │
│  │    SELECT * FROM dhcp_leases           │                                 │
│  │    WHERE mac_address = 'AA:BB:CC:DD:EE:FF'                              │
│  │    Result: None                        │                                 │
│  │                                         │                                 │
│  │ 2. Check for static reservation:       │                                 │
│  │    SELECT * FROM dhcp_reservations     │                                 │
│  │    WHERE mac_address = 'AA:BB:CC:DD:EE:FF'                              │
│  │    Result: None                        │                                 │
│  │                                         │                                 │
│  │ 3. Find next available IP:             │                                 │
│  │    Pool: office-network (192.168.1.0/24)│                                │
│  │    Range: 192.168.1.100-192.168.1.200  │                                 │
│  │    Next available: 192.168.1.100       │                                 │
│  └────────────────────────────────────────┘                                 │
│          │                                                                   │
│          ▼                                                                   │
│  conflict.go (ICMP ping test)                                                │
│  ┌────────────────────────────────────────┐                                 │
│  │ Ping 192.168.1.100 (timeout: 500ms)   │                                 │
│  │ Result: No response ✅                 │                                 │
│  │ IP is available                        │                                 │
│  └────────────────────────────────────────┘                                 │
└────────────────────┬────────────────────────────────────────────────────────┘
                     │
                     ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│ STEP 4: DHCP OFFER                                                           │
│ Location: internal/discovery/offer.go                                       │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                              │
│  Build OFFER message:                                                        │
│  ┌────────────────────────────────────────┐                                 │
│  │ Message Type: DHCP OFFER               │                                 │
│  │ Your IP: 192.168.1.100                 │                                 │
│  │ Server IP: 192.168.1.1                 │                                 │
│  │                                         │                                 │
│  │ Standard DHCP Options:                 │                                 │
│  │ • Option 1: Subnet Mask = 255.255.255.0│                                 │
│  │ • Option 3: Router = 192.168.1.1       │                                 │
│  │ • Option 6: DNS = 192.168.1.1          │                                 │
│  │ • Option 15: Domain = local.network    │                                 │
│  │ • Option 51: Lease Time = 86400 (24h)  │                                 │
│  └────────────────────────────────────────┘                                 │
│          │                                                                   │
│          ▼                                                                   │
│  sender.go                                                                   │
│  ┌────────────────────────────────────────┐                                 │
│  │ Send OFFER to 192.168.1.100:68         │                                 │
│  │ (broadcast if client IP is 0.0.0.0)    │                                 │
│  └────────────────────────────────────────┘                                 │
└─────────────────────────────────────────────────────────────────────────────┘
                     │
                     │ Device receives OFFER
                     │ Device sends: DHCP REQUEST
                     │
                     ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│ STEP 5: DHCP REQUEST Handler                                                │
│ Location: internal/discovery/request.go                                     │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                              │
│  Validate REQUEST:                                                           │
│  ┌────────────────────────────────────────┐                                 │
│  │ Requested IP: 192.168.1.100            │                                 │
│  │ MAC: AA:BB:CC:DD:EE:FF                 │                                 │
│  │                                         │                                 │
│  │ ✅ IP still available                  │                                 │
│  │ ✅ No conflicts                        │                                 │
│  │ ✅ Can create lease                    │                                 │
│  └────────────────────────────────────────┘                                 │
│          │                                                                   │
│          ▼                                                                   │
│  Create Lease:                                                               │
│  ┌────────────────────────────────────────┐                                 │
│  │ INSERT INTO dhcp_leases                │                                 │
│  │ VALUES (                               │                                 │
│  │   'AA:BB:CC:DD:EE:FF',                 │                                 │
│  │   '192.168.1.100',                     │                                 │
│  │   'johns-laptop',                      │                                 │
│  │   NOW(),                               │                                 │
│  │   NOW() + INTERVAL '24 hours',         │                                 │
│  │   'ACTIVE'                             │                                 │
│  │ )                                       │                                 │
│  └────────────────────────────────────────┘                                 │
└────────────────────┬────────────────────────────────────────────────────────┘
                     │
                     ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│ ⭐ STEP 6: DHCP ACK with CA Certificate URLs (CRITICAL)                     │
│ Location: internal/discovery/ack.go                                         │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                              │
│  Phase 1: Build Standard DHCP ACK                                           │
│  ┌────────────────────────────────────────┐                                 │
│  │ Message Type: DHCP ACK                 │                                 │
│  │ Your IP: 192.168.1.100                 │                                 │
│  │ Server IP: 192.168.1.1                 │                                 │
│  │                                         │                                 │
│  │ Standard Options:                      │                                 │
│  │ • Option 1: Subnet Mask = 255.255.255.0│                                 │
│  │ • Option 3: Router = 192.168.1.1       │                                 │
│  │ • Option 6: DNS = 192.168.1.1          │                                 │
│  │ • Option 15: Domain = local.network    │                                 │
│  │ • Option 51: Lease Time = 86400        │                                 │
│  └────────────────────────────────────────┘                                 │
│          │                                                                   │
│          ▼                                                                   │
│  Phase 2: ⭐ Call Certificate Manager (gRPC)                                │
│  ┌────────────────────────────────────────┐                                 │
│  │ Function: cert_integration/ca_provider.go                               │
│  │ gRPC Call: GetCertificateInfo()        │                                 │
│  │ Target: localhost:50060                │                                 │
│  └────────────────────────────────────────┘                                 │
│          │                                                                   │
│          │ gRPC request                                                      │
│          ▼                                                                   │
│  ┌────────────────────────────────────────┐                                 │
│  │ Certificate Manager Response:          │                                 │
│  │                                         │                                 │
│  │ CertificateInfo {                      │                                 │
│  │   ca_url: "http://192.168.1.1/ca.crt"  │                                 │
│  │   install_script_urls: [               │                                 │
│  │     "http://192.168.1.1/install-ca.sh" │                                 │
│  │     "http://192.168.1.1/install-ca.ps1"│                                 │
│  │   ]                                     │                                 │
│  │   wpad_url: "http://192.168.1.1/wpad.dat"                               │
│  │   crl_url: "http://192.168.1.1/crl.pem"│                                 │
│  │   ocsp_url: "http://192.168.1.1:8888"  │                                 │
│  │ }                                       │                                 │
│  └────────────────────────────────────────┘                                 │
│          │                                                                   │
│          │ Cached for 1 hour (cache.go)                                     │
│          ▼                                                                   │
│  Phase 3: ⭐ Build Custom DHCP Options                                      │
│  ┌────────────────────────────────────────┐                                 │
│  │ Function: cert_integration/option_builder.go                            │
│  │                                         │                                 │
│  │ Custom CA Options:                     │                                 │
│  │ • Option 224: "http://192.168.1.1/ca.crt"                               │
│  │ • Option 225: "http://192.168.1.1/install-ca.sh"                        │
│  │ • Option 252: "http://192.168.1.1/wpad.dat"                             │
│  └────────────────────────────────────────┘                                 │
│          │                                                                   │
│          ▼                                                                   │
│  Phase 4: Send DHCP ACK with ALL Options                                    │
│  ┌────────────────────────────────────────┐                                 │
│  │ Complete DHCP ACK Packet:              │                                 │
│  │                                         │                                 │
│  │ Standard Options: 1, 3, 6, 15, 51      │                                 │
│  │ ⭐ CA Options: 224, 225, 252           │                                 │
│  │                                         │                                 │
│  │ Sent to: 192.168.1.100:68              │                                 │
│  └────────────────────────────────────────┘                                 │
│          │                                                                   │
│          ▼                                                                   │
│  Phase 5: Trigger DNS Update (gRPC)                                         │
│  ┌────────────────────────────────────────┐                                 │
│  │ Function: dns_integration/dynamic_dns.go                                │
│  │ gRPC Call: DynamicUpdate()             │                                 │
│  │ Target: localhost:50053 (DNS server)   │                                 │
│  │                                         │                                 │
│  │ Create DNS records:                    │                                 │
│  │ • A: johns-laptop.local.network → 192.168.1.100                         │
│  │ • PTR: 100.1.168.192.in-addr.arpa → johns-laptop.local.network         │
│  └────────────────────────────────────────┘                                 │
└─────────────────────────────────────────────────────────────────────────────┘
                     │
                     │ DHCP ACK delivered
                     ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│ STEP 7: Device Configuration                                                │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                              │
│  Device applies configuration:                                              │
│  ┌────────────────────────────────────────┐                                 │
│  │ Standard Network Config:               │                                 │
│  │ • IP: 192.168.1.100 ✅                 │                                 │
│  │ • Subnet: 255.255.255.0 ✅             │                                 │
│  │ • Gateway: 192.168.1.1 ✅              │                                 │
│  │ • DNS: 192.168.1.1 ✅                  │                                 │
│  │ • Domain: local.network ✅             │                                 │
│  │                                         │                                 │
│  │ ⭐ CA Certificate Info:                │                                 │
│  │ • Option 224 → http://192.168.1.1/ca.crt                                │
│  │ • Option 225 → http://192.168.1.1/install-ca.sh                         │
│  │ • Option 252 → http://192.168.1.1/wpad.dat                              │
│  │                                         │                                 │
│  │ Network Status:                        │                                 │
│  │ ✅ IP assigned                         │                                 │
│  │ ✅ Gateway reachable                   │                                 │
│  │ ✅ DNS functional                      │                                 │
│  │ ✅ CA URLs available                   │                                 │
│  └────────────────────────────────────────┘                                 │
└─────────────────────────────────────────────────────────────────────────────┘
```

---

## 🗄️ Database Schema (PostgreSQL)

```sql
-- DHCP address pools
CREATE TABLE dhcp_pools (
  id SERIAL PRIMARY KEY,
  name VARCHAR(100),              -- "office-network"
  subnet CIDR,                    -- 192.168.1.0/24
  range_start INET,               -- 192.168.1.100
  range_end INET,                 -- 192.168.1.200
  lease_time INTEGER,             -- 86400 (24 hours)
  gateway INET,                   -- 192.168.1.1
  dns_servers INET[],             -- {192.168.1.1, 8.8.8.8}
  domain_name VARCHAR(255),       -- "local.network"
  created_at TIMESTAMP DEFAULT NOW()
);

-- Active DHCP leases
CREATE TABLE dhcp_leases (
  id SERIAL PRIMARY KEY,
  mac_address VARCHAR(17) UNIQUE, -- AA:BB:CC:DD:EE:FF
  ip_address INET,                -- 192.168.1.100
  hostname VARCHAR(255),          -- "johns-laptop"
  lease_start TIMESTAMP,          -- 2025-12-27 10:30:00
  lease_end TIMESTAMP,            -- 2025-12-28 10:30:00
  state VARCHAR(20),              -- "ACTIVE", "EXPIRED"
  pool_id INTEGER REFERENCES dhcp_pools(id),
  INDEX idx_mac (mac_address),
  INDEX idx_ip (ip_address),
  INDEX idx_expiry (lease_end)
);

-- Static MAC → IP reservations
CREATE TABLE dhcp_reservations (
  id SERIAL PRIMARY KEY,
  mac_address VARCHAR(17) UNIQUE, -- AA:BB:CC:DD:EE:FF
  ip_address INET,                -- 192.168.1.50 (reserved)
  hostname VARCHAR(255),          -- "printer-office"
  pool_id INTEGER REFERENCES dhcp_pools(id),
  created_at TIMESTAMP DEFAULT NOW()
);

-- DHCP option overrides (per-pool)
CREATE TABLE dhcp_options (
  id SERIAL PRIMARY KEY,
  pool_id INTEGER REFERENCES dhcp_pools(id),
  option_code INTEGER,            -- 224 (CA URL), 225 (Install Scripts)
  option_value TEXT,
  created_at TIMESTAMP DEFAULT NOW()
);
```

---

## 🔄 Lease Renewal Process (T1/T2 Timers)

```
┌─────────────────────────────────────────────────────────────────────────────┐
│ LEASE RENEWAL (Automatic - No User Intervention)                            │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                              │
│  Timeline:                                                                   │
│  ─────────────────────────────────────────────────────────────────────────  │
│                                                                              │
│  T=0h  ┌──────────────────────────────────────────────────────────┐        │
│        │ Lease Created:                                            │        │
│        │ • IP: 192.168.1.100                                       │        │
│        │ • Lease Duration: 24 hours                                │        │
│        │ • T1 (50%): 12 hours → Renewal time                       │        │
│        │ • T2 (87.5%): 21 hours → Rebind time                      │        │
│        └──────────────────────────────────────────────────────────┘        │
│                                                                              │
│  T=12h (T1 timer expires)                                                    │
│        ┌──────────────────────────────────────────────────────────┐        │
│        │ Device sends DHCP REQUEST (renewal)                      │        │
│        │ Destination: 192.168.1.1:67 (unicast to DHCP server)    │        │
│        │                                                           │        │
│        │ DHCP Server Response:                                    │        │
│        │ • Extend lease for another 24 hours                      │        │
│        │ • Send DHCP ACK with same configuration                  │        │
│        │ • Include CA URLs again (Options 224, 225, 252)          │        │
│        │ • Update lease_end in database                           │        │
│        └──────────────────────────────────────────────────────────┘        │
│                                                                              │
│  If T1 renewal fails → Wait for T2                                          │
│                                                                              │
│  T=21h (T2 timer expires)                                                    │
│        ┌──────────────────────────────────────────────────────────┐        │
│        │ Device sends DHCP REQUEST (rebind)                       │        │
│        │ Destination: 255.255.255.255:67 (broadcast)              │        │
│        │ Accepts response from any DHCP server                    │        │
│        └──────────────────────────────────────────────────────────┘        │
│                                                                              │
│  T=24h (Lease expires)                                                       │
│        ┌──────────────────────────────────────────────────────────┐        │
│        │ If no renewal/rebind:                                    │        │
│        │ • Device stops using IP                                  │        │
│        │ • DHCP server marks lease as EXPIRED                     │        │
│        │ • IP returns to pool                                     │        │
│        │ • DNS records removed                                    │        │
│        └──────────────────────────────────────────────────────────┘        │
└─────────────────────────────────────────────────────────────────────────────┘
```

**Key Files:**
- `internal/lease_manager/renewal.go` - T1/T2 timer handling
- `internal/lease_manager/expiry.go` - Expired lease cleanup (runs every 5 minutes)

---

## 📡 gRPC API (Port 50054)

```protobuf
service DHCPServer {
  // Lease management
  rpc GetLeases() returns (LeaseList);
  rpc GetLease(LeaseRequest) returns (Lease);
  rpc ReleaseLease(ReleaseRequest) returns (ReleaseResponse);

  // Pool management
  rpc ListPools() returns (PoolList);
  rpc GetPoolInfo(PoolRequest) returns (PoolInfo);
  rpc GetPoolStats(PoolRequest) returns (PoolStats);

  // Statistics
  rpc GetStats() returns (DHCPStats);
}

message LeaseRequest {
  string mac_address = 1; // "AA:BB:CC:DD:EE:FF"
}

message Lease {
  string mac_address = 1;
  string ip_address = 2;
  string hostname = 3;
  int64 lease_start = 4;  // Unix timestamp
  int64 lease_end = 5;    // Unix timestamp
  string state = 6;       // "ACTIVE", "EXPIRED"
}

message PoolStats {
  string pool_name = 1;
  int32 total_ips = 2;
  int32 allocated_ips = 3;
  int32 available_ips = 4;
  float utilization_percent = 5;
}
```

---

## 📊 Prometheus Metrics (Port 9154)

```
# DHCP request counters
dhcp_requests_total{type="DISCOVER"} 145
dhcp_requests_total{type="REQUEST"} 143
dhcp_requests_total{type="RELEASE"} 2

# Active leases
dhcp_leases_active 143

# Pool utilization (percentage)
dhcp_pool_utilization{pool="office-network"} 0.71  # 71%

# DNS update counters
dhcp_dns_updates_total 143
dhcp_dns_update_failures_total 0

# CA distribution counter
dhcp_ca_distribution_total 143  # Option 224 sent

# Response time histogram
dhcp_response_time_seconds{quantile="0.5"} 0.012   # 12ms median
dhcp_response_time_seconds{quantile="0.95"} 0.045  # 45ms p95
```

---

## 🔗 Integration with Other Services

### ➡️ Certificate Manager (gRPC - Port 50060)

```
Location: internal/cert_integration/ca_provider.go

gRPC Call: GetCertificateInfo()
Target: localhost:50060

Response:
{
  "ca_url": "http://192.168.1.1/ca.crt",
  "install_script_urls": [
    "http://192.168.1.1/install-ca.sh",
    "http://192.168.1.1/install-ca.ps1"
  ],
  "wpad_url": "http://192.168.1.1/wpad.dat",
  "crl_url": "http://192.168.1.1/crl.pem",
  "ocsp_url": "http://192.168.1.1:8888"
}

Usage:
- Called on every DHCP ACK
- Results cached for 1 hour (cert_integration/cache.go)
- Embedded in DHCP Options 224, 225, 252
```

### ➡️ DNS Server (gRPC - Port 50053)

```
Location: internal/dns_integration/dynamic_dns.go

gRPC Call: DynamicUpdate()
Target: localhost:50053

Request:
{
  "hostname": "johns-laptop",
  "ip": "192.168.1.100",
  "mac": "AA:BB:CC:DD:EE:FF",
  "lease_expiry": 1735293000  // Unix timestamp
}

Actions:
- Creates A record: johns-laptop.local.network → 192.168.1.100
- Creates PTR record: 100.1.168.192.in-addr.arpa → johns-laptop
- Sets TTL to lease duration (24 hours)

Triggers:
- On lease creation (DHCP ACK)
- On lease renewal
- On lease release (removes records)
```

---

## 📂 File Structure

```
src/dhcp_server/
├── internal/
│   ├── server/             # UDP listener, packet handling
│   ├── lease_manager/      # IP allocation, renewal, expiry
│   ├── pool/               # Pool management, subnet calculations
│   ├── options/            # DHCP options handling
│   ├── cert_integration/   # ⭐ CA certificate integration (gRPC)
│   ├── dns_integration/    # Dynamic DNS updates (gRPC)
│   ├── discovery/          # DISCOVER, OFFER, REQUEST, ACK, NAK
│   ├── storage/            # PostgreSQL connection, repositories
│   ├── monitoring/         # Prometheus metrics, pool alerts
│   └── api/                # gRPC service
├── pkg/
│   ├── models/             # Lease, Pool, Packet structures
│   ├── protocol/           # DHCP constants, message types
│   └── client/             # gRPC client library
├── cmd/
│   └── main.go             # Service entry point
└── tests/
    ├── server_test.go
    ├── lease_test.go
    ├── options_test.go
    ├── ca_integration_test.go  # ⭐ Test CA options
    └── integration_test.go
```

---

## 🎯 Performance Characteristics

```
Lease Allocation Rate:     1000+ leases/sec
Response Time:             <50ms (DISCOVER → OFFER)
DNS Update Reliability:    100% (with retry)
CA Certificate Dist:       Zero-touch (automatic)
Pool Utilization Alert:    >80% (configurable)
Database Query Time:       <5ms (indexed lookups)
```

---

**End of DHCP Server Diagram**
