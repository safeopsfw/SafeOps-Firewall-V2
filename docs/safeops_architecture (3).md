# SafeOps v2.0 - System Architecture & Flow Diagrams

**Document Type:** Architecture & Flow Visualization  
**Operating System:** Windows 11 Professional/Enterprise (64-bit)  
**Network Configuration:** 3 NICs (1 Onboard RJ45 + 1 USB-C RJ45 + 1 WiFi)  
**No Code - Diagrams Only**

---

## 1. Physical Network Topology - 3 NIC Configuration

```
                                    INTERNET
                                       |
                                       | (ISP Connection)
                                       |
                    ┌──────────────────┴──────────────────┐
                    │  WAN Interface (NIC 1)              │
                    │  Type: Onboard RJ45 (Built-in)      │
                    │  External IP: Public/Dynamic         │
                    │  Speed: 1-10 Gbps (Gigabit/10G)     │
                    │  Purpose: Internet Gateway           │
                    └──────────────────┬──────────────────┘
                                       |
                    ═══════════════════════════════════════
                    ║                                     ║
                    ║   SAFEOPS SECURITY GATEWAY         ║
                    ║   (Windows 11 Pro/Enterprise)      ║
                    ║                                     ║
                    ║   Hardware: Desktop/Workstation    ║
                    ║   CPU: 8+ cores @ 3.0+ GHz         ║
                    ║   RAM: 16+ GB                      ║
                    ║   Storage: 100+ GB SSD             ║
                    ║                                     ║
                    ║   ┌─────────────────────────┐      ║
                    ║   │   Kernel Space (Ring 0) │      ║
                    ║   │                         │      ║
                    ║   │  [Kernel Driver Layer]  │      ║
                    ║   │   - NDIS 6.x Filter     │      ║
                    ║   │   - WFP Callouts        │      ║
                    ║   │   - Shared Memory (2GB) │      ║
                    ║   │   - NIC Binding (3 NICs)│      ║
                    ║   └──────────┬──────────────┘      ║
                    ║              |                      ║
                    ║   ┌──────────┴──────────────┐      ║
                    ║   │   User Space (Ring 3)   │      ║
                    ║   │                         │      ║
                    ║   │  [Service Layer]        │      ║
                    ║   │   - Network Logger      │      ║
                    ║   │   - Firewall Engine     │      ║
                    ║   │   - IDS/IPS Engine      │      ║
                    ║   │   - TLS Proxy           │      ║
                    ║   │   - Threat Intel        │      ║
                    ║   │   - WiFi AP Service     │      ║
                    ║   │   - NAT/Routing Engine  │      ║
                    ║   │   - Orchestrator        │      ║
                    ║   └─────────────────────────┘      ║
                    ║                                     ║
                    ═══════════════════════════════════════
                             |                    |
                             |                    |
        ┌────────────────────┴─────┐    ┌────────┴──────────────────┐
        │                          │    │                           │
        │  LAN Interface (NIC 2)   │    │  WiFi AP (NIC 3)         │
        │  Type: USB-C to RJ45     │    │  Type: Built-in WiFi     │
        │  Internal IP: 192.168.1.1│    │  SSID: SafeOps-Secure    │
        │  Speed: 1-2.5 Gbps       │    │  IP Range: 192.168.2.x   │
        │  Purpose: Wired LAN      │    │  Speed: WiFi 6 (ax)      │
        │  DHCP: 192.168.1.10-200  │    │  DHCP: 192.168.2.10-200  │
        └────────────┬─────────────┘    └──────────┬───────────────┘
                     |                             |
                     |                             |
        ┌────────────┴─────────────┐    ┌─────────┴──────────────────┐
        │                          │    │                            │
        │   WIRED LAN DEVICES      │    │   WIRELESS DEVICES         │
        │   - Desktop PCs          │    │   - Laptops                │
        │   - Workstations         │    │   - Smartphones            │
        │   - Servers              │    │   - Tablets                │
        │   - Network Printers     │    │   - IoT Devices            │
        │   - NAS Storage          │    │   - Smart TVs              │
        │                          │    │   - Guest Devices          │
        └──────────────────────────┘    └────────────────────────────┘
```

 Complete Traffic Flow Diagram (All 3 NICs)

```
═══════════════════════════════════════════════════════════════
                    3-NIC TRAFFIC FLOW MATRIX
═══════════════════════════════════════════════════════════════

SCENARIO 1: Internet → Wired LAN
┌────────┐      ┌────────┐      ┌────────┐      ┌────────┐
│Internet├─────►│ NIC 1  ├─────►│ SafeOps├─────►│ NIC 2  ├────►LAN Client
│        │  ▲   │  WAN   │  ▲   │ Engine │  ▲   │  LAN   │  ▲  192.168.1.x
└────────┘  │   └────────┘  │   └────────┘  │   └────────┘  │
           1ms             50µs            500µs            50µs
        (ISP Latency)  (Capture)     (Processing)      (Forward)

SCENARIO 2: Wired LAN → Internet
┌────────┐      ┌────────┐      ┌────────┐      ┌────────┐
│LAN     ├─────►│ NIC 2  ├─────►│ SafeOps├─────►│ NIC 1  ├────►Internet
│Client  │  ▲   │  LAN   │  ▲   │ + NAT  │  ▲   │  WAN   │  ▲
└────────┘  │   └────────┘  │   └────────┘  │   └────────┘  │
           50µs             50µs            600µs            50µs
        (LAN Switch)    (Capture)    (FW+NAT+TLS)       (Forward)

SCENARIO 3: WiFi → Internet
┌────────┐      ┌────────┐      ┌────────┐      ┌────────┐
│WiFi    ├─────►│ NIC 3  ├─────►│ SafeOps├─────►│ NIC 1  ├────►Internet
│Client  │  ▲   │  WiFi  │  ▲   │ + NAT  │  ▲   │  WAN   │  ▲
└────────┘  │   └────────┘  │   └────────┘  │   └────────┘  │
         2-5ms            100µs            700µs            50µs
     (WiFi Latency)    (Capture)  (FW+NAT+Isolation)   (Forward)

SCENARIO 4: WiFi → Wired LAN (BLOCKED by default)
┌────────┐      ┌────────┐      ┌────────┐
│WiFi    ├─────►│ NIC 3  ├─────►│ SafeOps├────X (Firewall blocks)
│Client  │      │  WiFi  │      │ Engine │
└────────┘      └────────┘      └────────┘
                                Rule: WiFi cannot access LAN network

SCENARIO 5: Wired LAN → WiFi (Configurable)
┌────────┐      ┌────────┐      ┌────────┐      ┌────────┐
│LAN     ├─────►│ NIC 2  ├─────►│ SafeOps├─────►│ NIC 3  ├────►WiFi Client
│Client  │      │  LAN   │      │ Engine │      │  WiFi  │     192.168.2.x
└────────┘      └────────┘      └────────┘      └────────┘
                                Rule: Allow if enabled in firewall

SCENARIO 6: WiFi Client A → WiFi Client B (BLOCKED)
┌────────┐      ┌────────┐      ┌────────┐
│WiFi    ├─────►│ NIC 3  ├─────►│ SafeOps├────X (Client isolation)
│Client A│      │  WiFi  │      │ Engine │
└────────┘      └────────┘      └────────┘
                                Rule: WiFi client isolation enabled
```

---

## 10. CPU Core Affinity & Thread Distribution

```
┌───────────────────────────────────────────────────────────────┐
│               CPU CORE ASSIGNMENT (8-Core System)             │
└───────────────────────────────────────────────────────────────┘

CORE 0: SYSTEM & ORCHESTRATOR
┌──────────────────────────────────────────────────────────────┐
│ - Windows OS threads                                         │
│ - Orchestrator main thread                                   │
│ - gRPC API gateway                                           │
│ - Light load (~20% utilization)                              │
└──────────────────────────────────────────────────────────────┘

CORE 1: NETWORK LOGGER (Ring Buffer Reader)
┌──────────────────────────────────────────────────────────────┐
│ - Read from kernel shared memory                             │
│ - High priority thread (real-time priority)                  │
│ - Lock-free consumer loop                                    │
│ - Heavy load (~80% utilization)                              │
└──────────────────────────────────────────────────────────────┘

CORE 2-3: FIREWALL ENGINE (Packet Processing)
┌──────────────────────────────────────────────────────────────┐
│ CORE 2:                                                      │
│ - Firewall rule evaluation (WAN packets)                     │
│ - Connection tracking                                        │
│ - NAT translation                                            │
│                                                              │
│ CORE 3:                                                      │
│ - Firewall rule evaluation (LAN/WiFi packets)                │
│ - DDoS mitigation                                            │
│ - Rate limiting                                              │
│ Heavy load (~90% utilization each)                           │
└──────────────────────────────────────────────────────────────┘

CORE 4-5: IDS/IPS ENGINE
┌──────────────────────────────────────────────────────────────┐
│ CORE 4:                                                      │
│ - Signature matching (Snort rules)                           │
│ - Pattern matching (Aho-Corasick)                            │
│                                                              │
│ CORE 5:                                                      │
│ - Anomaly detection                                          │
│ - Behavior analysis                                          │
│ - Protocol analysis                                          │
│ Medium load (~60% utilization each)                          │
└──────────────────────────────────────────────────────────────┘

CORE 6: TLS PROXY & THREAT INTEL
┌──────────────────────────────────────────────────────────────┐
│ - TLS interception (MITM)                                    │
│ - Certificate generation/caching                             │
│ - Threat intelligence lookups                                │
│ - Redis cache queries                                        │
│ Medium load (~50% utilization)                               │
└──────────────────────────────────────────────────────────────┘

CORE 7: DATABASE & WIFI AP
┌──────────────────────────────────────────────────────────────┐
│ - PostgreSQL write threads                                   │
│ - Redis operations                                           │
│ - WiFi AP service (hostapd)                                  │
│ - DHCP server (2 instances: LAN + WiFi)                      │
│ Light load (~30% utilization)                                │
└──────────────────────────────────────────────────────────────┘

INTERRUPT HANDLING:
┌──────────────────────────────────────────────────────────────┐
│ NIC 1 (WAN) interrupts   → Core 1 (RSS Queue 0)              │
│ NIC 2 (LAN) interrupts   → Core 2 (RSS Queue 1)              │
│ NIC 3 (WiFi) interrupts  → Core 3 (RSS Queue 2)              │
│                                                              │
│ RSS (Receive Side Scaling) distributes packet processing     │
│ across multiple CPU cores for maximum throughput             │
└──────────────────────────────────────────────────────────────┘
```

---

## 11. Boot Sequence & Service Startup Order

```
┌───────────────────────────────────────────────────────────────┐
│                      SAFEOPS BOOT SEQUENCE                    │
└───────────────────────────────────────────────────────────────┘

PHASE 1: WINDOWS BOOT (0-30 seconds)
├─ Windows 11 kernel loads
├─ Device drivers initialize
├─ Network adapters detected (3 NICs)
└─ SafeOps service registry read

PHASE 2: DATABASE INITIALIZATION (30-35 seconds)
├─ PostgreSQL 16 starts (embedded)
│  ├─ Load configuration──────────────┐    ║
║  │  NIC 1: WAN (Internet Facing)                               │    ║
║  ├─────────────────────────────────────────────────────────────┤    ║
║  │  Type: Onboard RJ45 (Built-in Ethernet)                     │    ║
║  │  Chipset: Intel I225-V / Realtek RTL8125                    │    ║
║  │  Speed: 1 Gbps / 2.5 Gbps / 10 Gbps                         │    ║
║  │  IP Assignment: DHCP from ISP / Static Public IP            │    ║
║  │  Purpose: Internet Gateway (Untrusted)                      │    ║
║  │  Security Zone: EXTERNAL                                    │    ║
║  │  Traffic Direction: INGRESS (Inbound from Internet)         │    ║
║  └─────────────────────────────────────────────────────────────┘    ║
║                                                                       ║
║  ┌─────────────────────────────────────────────────────────────┐    ║
║  │  NIC 2: LAN (Wired Internal Network)                        │    ║
║  ├─────────────────────────────────────────────────────────────┤    ║
║  │  Type: USB 3.0/3.1 Type-C to RJ45 Adapter                   │    ║
║  │  Chipset: Realtek RTL8153 / ASIX AX88179                    │    ║
║  │  Speed: 1 Gbps / 2.5 Gbps                                   │    ║
║  │  IP Assignment: Static 192.168.1.1/24                       │    ║
║  │  Purpose: Wired LAN Gateway (Trusted)                       │    ║
║  │  Security Zone: INTERNAL_WIRED                              │    ║
║  │  Traffic Direction: EGRESS (Outbound to Wired Devices)      │    ║
║  │  Services: DHCP Server, DNS Forwarder                       │    ║
║  └─────────────────────────────────────────────────────────────┘    ║
║                                                                       ║
║  ┌─────────────────────────────────────────────────────────────┐    ║
║  │  NIC 3: WiFi AP (Wireless Access Point)                     │    ║
║  ├─────────────────────────────────────────────────────────────┤    ║
║  │  Type: Built-in WiFi Adapter (Intel AX200/AX210)            │    ║
║  │  Standard: WiFi 6 (802.11ax) / WiFi 6E                      │    ║
║  │  Speed: Up to 2.4 Gbps (theoretical)                        │    ║
║  │  IP Assignment: Static 192.168.2.1/24                       │    ║
║  │  Purpose: Wireless LAN Gateway (Semi-trusted)               │    ║
║  │  Security Zone: INTERNAL_WIRELESS                           │    ║
║  │  Traffic Direction: EGRESS (Outbound to WiFi Devices)       │    ║
║  │  Services: Hostapd (AP Mode), DHCP Server, DNS Forwarder    │    ║
║  │  Security: WPA3-Personal / WPA2-Personal                    │    ║
║  │  SSID: SafeOps-Secure                                       │    ║
║  │  Encryption: AES-256                                        │    ║
║  └─────────────────────────────────────────────────────────────┘    ║
║                                                                       ║
╚═══════════════════════════════════════════════════════════════════════╝
```

---

## 3. Complete System Architecture - Layer by Layer

```
┌───────────────────────────────────────────────────────────────────────┐
│                         LAYER 1: HARDWARE LAYER                       │
├───────────────────────────────────────────────────────────────────────┤
│                                                                       │
│  ┌──────────┐  ┌──────────┐  ┌──────────┐  ┌──────────┐            │
│  │  NIC 1   │  │  NIC 2   │  │  NIC 3   │  │   CPU    │            │
│  │  WAN     │  │  LAN     │  │  WiFi    │  │  8-Core  │            │
│  │  RJ45    │  │  USB-C   │  │  802.11ax│  │  @ 3GHz  │            │
│  └────┬─────┘  └────┬─────┘  └────┬─────┘  └────┬─────┘            │
│       │             │             │             │                    │
│       └─────────────┴─────────────┴─────────────┘                    │
│                     │                                                │
│              ┌──────┴──────┐                                         │
│              │   PCIe Bus  │                                         │
│              └──────┬──────┘                                         │
│                     │                                                │
│  ┌──────────────────┴──────────────────┐  ┌──────────────────┐     │
│  │         RAM (16+ GB)                │  │  SSD (100+ GB)   │     │
│  │  - Kernel Buffers (2 GB)            │  │  - OS & Apps     │     │
│  │  - Service Memory (8 GB)            │  │  - Database      │     │
│  │  - Connection Tables (4 GB)         │  │  - Logs          │     │
│  │  - Packet Buffers (2 GB)            │  │  - Config Files  │     │
│  └─────────────────────────────────────┘  └──────────────────┘     │
│                                                                       │
└───────────────────────────────────────────────────────────────────────┘

┌───────────────────────────────────────────────────────────────────────┐
│                  LAYER 2: WINDOWS 11 KERNEL LAYER                     │
├───────────────────────────────────────────────────────────────────────┤
│                                                                       │
│  ┌─────────────────────────────────────────────────────────────┐    │
│  │             Windows 11 Kernel (ntoskrnl.exe)                │    │
│  │                     Ring 0 (Kernel Mode)                     │    │
│  └──────────────────────────┬──────────────────────────────────┘    │
│                             │                                        │
│  ┌──────────────────────────┴──────────────────────────────────┐    │
│  │                  NDIS 6.x Stack                              │    │
│  │  ┌────────────┐  ┌────────────┐  ┌────────────┐            │    │
│  │  │ NIC 1 Drv  │  │ NIC 2 Drv  │  │ NIC 3 Drv  │            │    │
│  │  │ (Intel)    │  │ (Realtek)  │  │ (Intel)    │            │    │
│  │  └─────┬──────┘  └─────┬──────┘  └─────┬──────┘            │    │
│  │        │               │               │                    │    │
│  │  ┌─────┴───────────────┴───────────────┴──────┐            │    │
│  │  │       NDIS Filter Manager                  │            │    │
│  │  └──────────────────┬─────────────────────────┘            │    │
│  │                     │                                       │    │
│  │  ┌──────────────────┴─────────────────────────┐            │    │
│  │  │      SafeOps NDIS Filter Driver            │            │    │
│  │  │  - Packet Capture (All 3 NICs)             │            │    │
│  │  │  - DMA to Ring Buffer (Zero-Copy)          │            │    │
│  │  │  - Hardware RSS Support                    │            │    │
│  │  │  - Checksum Offload                        │            │    │
│  │  └──────────────────┬─────────────────────────┘            │    │
│  └─────────────────────┼────────────────────────────────────  │    │
│                        │                                       │    │
│  ┌─────────────────────┴─────────────────────────────────┐    │    │
│  │         Windows Filtering Platform (WFP)              │    │    │
│  │  ┌──────────────────────────────────────────────┐     │    │    │
│  │  │     SafeOps WFP Callout Driver               │     │    │    │
│  │  │  - Layer 2/3/4 Filtering                     │     │    │    │
│  │  │  - Connection Tracking                       │     │    │    │
│  │  │  - NAT Support (3 NICs)                      │     │    │    │
│  │  │  - Policy Enforcement                        │     │    │    │
│  │  └──────────────────┬───────────────────────────┘     │    │    │
│  └─────────────────────┼───────────────────────────────── │    │    │
│                        │                                  │    │    │
│  ┌─────────────────────┴─────────────────────────────────┴─┐  │    │
│  │         Shared Memory Ring Buffer (2 GB)                │  │    │
│  │  - Lock-free Producer (Kernel)                          │  │    │
│  │  - Lock-free Consumer (Userspace)                       │  │    │
│  │  - 16 Million Packet Capacity                           │  │    │
│  │  - Per-NIC Queues (3 queues)                            │  │    │
│  └─────────────────────────────────────────────────────────┘  │    │
│                                                                │    │
└────────────────────────────────────────────────────────────────┘    │

┌───────────────────────────────────────────────────────────────────────┐
│                 LAYER 3: USER MODE SERVICE LAYER                      │
│                         Ring 3 (User Mode)                            │
├───────────────────────────────────────────────────────────────────────┤
│                                                                       │
│  ┌─────────────────────────────────────────────────────────────┐    │
│  │                    ORCHESTRATOR SERVICE                      │    │
│  │  (Go - Process ID: 1000)                                     │    │
│  │  - Service Lifecycle Management                              │    │
│  │  - Health Monitoring                                         │    │
│  │  - Config Distribution                                       │    │
│  │  - gRPC API Gateway (Port: 50051)                            │    │
│  │  - Metrics Aggregation                                       │    │
│  └──────┬──────────────────────────────────────────────────────┘    │
│         │                                                            │
│         │ (Spawns and Manages All Services)                         │
│         │                                                            │
│  ┌──────┴──────────────────────────────────────────────────────┐    │
│  │                                                              │    │
│  │  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐      │    │
│  │  │   Network    │  │   Firewall   │  │     TLS      │      │    │
│  │  │   Logger     │  │    Engine    │  │    Proxy     │      │    │
│  │  │   (Go)       │  │   (Rust)     │  │    (Go)      │      │    │
│  │  │   PID: 1001  │  │   PID: 1002  │  │   PID: 1003  │      │    │
│  │  └──────┬───────┘  └──────┬───────┘  └──────┬───────┘      │    │
│  │         │                 │                 │               │    │
│  │  ┌──────┴───────┐  ┌──────┴───────┐  ┌──────┴───────┐      │    │
│  │  │   IDS/IPS    │  │    Threat    │  │     WiFi     │      │    │
│  │  │   Engine     │  │    Intel     │  │  AP Service  │      │    │
│  │  │   (Go)       │  │   (Rust)     │  │    (Go)      │      │    │
│  │  │   PID: 1004  │  │   PID: 1005  │  │   PID: 1006  │      │    │
│  │  └──────┬───────┘  └──────┬───────┘  └──────┬───────┘      │    │
│  │         │                 │                 │               │    │
│  └─────────┴─────────────────┴─────────────────┴───────────────┘    │
│                              │                                       │
│  ┌───────────────────────────┴─────────────────────────────────┐    │
│  │                  Inter-Process Communication                 │    │
│  │  - gRPC (TCP: localhost:50051-50060)                         │    │
│  │  - Shared Memory (Fast Path)                                 │    │
│  │  - Named Pipes (Control Channel)                             │    │
│  │  - Redis Pub/Sub (Event Broadcasting)                        │    │
│  └───────────────────────────────────────────────────────────── │    │
│                                                                       │
└───────────────────────────────────────────────────────────────────────┘

┌───────────────────────────────────────────────────────────────────────┐
│                     LAYER 4: DATA STORAGE LAYER                       │
├───────────────────────────────────────────────────────────────────────┤
│                                                                       │
│  ┌──────────────────────────────────────────────────────────────┐   │
│  │              PostgreSQL 16 (Embedded)                        │   │
│  │  Port: 5432 (localhost only)                                 │   │
│  │  ┌────────────────────────────────────────────────────────┐  │   │
│  │  │  Tables:                                               │  │   │
│  │  │  - network_traffic (partitioned by date)              │  │   │
│  │  │  - firewall_rules (indexed)                           │  │   │
│  │  │  - threat_indicators (hash indexed)                   │  │   │
│  │  │  - ids_alerts (partitioned)                           │  │   │
│  │  │  - wifi_clients (connection tracking)                 │  │   │
│  │  │  - nat_sessions (3 NIC routing)                       │  │   │
│  │  │  - dhcp_leases (LAN + WiFi)                           │  │   │
│  │  └────────────────────────────────────────────────────────┘  │   │
│  └──────────────────────────────────────────────────────────────┘   │
│                                                                       │
│  ┌──────────────────────────────────────────────────────────────┐   │
│  │              Redis 7 (Embedded)                              │   │
│  │  Port: 6379 (localhost only)                                 │   │
│  │  ┌────────────────────────────────────────────────────────┐  │   │
│  │  │  Caches:                                               │  │   │
│  │  │  - Session cache (5-min packet buffer)                │  │   │
│  │  │  - Connection tracking (fast lookup)                  │  │   │
│  │  │  - Threat intel cache (IP reputation)                 │  │   │
│  │  │  - DNS cache (resolver)                               │  │   │
│  │  │  - WiFi client cache                                  │  │   │
│  │  │  - NAT translation table                              │  │   │
│  │  │  - DHCP lease cache                                   │  │   │
│  │  └────────────────────────────────────────────────────────┘  │   │
│  └──────────────────────────────────────────────────────────────┘   │
│                                                                       │
└───────────────────────────────────────────────────────────────────────┘

┌───────────────────────────────────────────────────────────────────────┐
│                   LAYER 5: USER INTERFACE LAYER                       │
├───────────────────────────────────────────────────────────────────────┤
│                                                                       │
│  ┌──────────────────────────────────────────────────────────────┐   │
│  │           Desktop Application (Wails + React)                │   │
│  │  ┌────────────────────────────────────────────────────────┐  │   │
│  │  │  Frontend (React + TypeScript)                         │  │   │
│  │  │  - Real-time Dashboard                                 │  │   │
│  │  │  - 3-NIC Traffic Monitor                               │  │   │
│  │  │  - Firewall Rule Manager                               │  │   │
│  │  │  - WiFi AP Configuration                               │  │   │
│  │  │  - IDS/IPS Alert Viewer                                │  │   │
│  │  │  - NAT/Routing Configuration                           │  │   │
│  │  └────────────────────────────────────────────────────────┘  │   │
│  │  ┌────────────────────────────────────────────────────────┐  │   │
│  │  │  Backend (Go)                                          │  │   │
│  │  │  - WebView2 (Edge Chromium)                           │  │   │
│  │  │  - gRPC Client to Orchestrator                        │  │   │
│  │  │  - WebSocket for Real-time Updates                    │  │   │
│  │  │  - System Tray Integration                            │  │   │
│  │  └────────────────────────────────────────────────────────┘  │   │
│  └──────────────────────────────────────────────────────────────┘   │
│                                                                       │
│  ┌──────────────────────────────────────────────────────────────┐   │
│  │           Web Interface (Optional Remote Access)             │   │
│  │  HTTPS Port: 8443                                            │   │
│  │  - Same features as desktop app                              │   │
│  │  - Access from any device on LAN/WiFi                        │   │
│  └──────────────────────────────────────────────────────────────┘   │
│                                                                       │
└───────────────────────────────────────────────────────────────────────┘
```

---

## 4. Packet Flow - Internet to LAN (Inbound Traffic)

```
STEP 1: PACKET ARRIVAL AT NIC 1 (WAN)
┌───────────────────────────────────────────────────────────────┐
│  INTERNET → ISP Router → NIC 1 (WAN Interface)                │
│  Packet: [IP: 8.8.8.8:443 → Public_IP:12345]                  │
│  Protocol: TCP SYN                                            │
└────────────────────────┬──────────────────────────────────────┘
                         │
                         ▼
STEP 2: HARDWARE PROCESSING
┌───────────────────────────────────────────────────────────────┐
│  NIC 1 Hardware (Intel I225-V)                                │
│  - RSS (Receive Side Scaling) → Queue Assignment             │
│  - Hardware Checksum Validation                              │
│  - DMA Transfer to RAM                                        │
│  Time: <10 microseconds                                       │
└────────────────────────┬──────────────────────────────────────┘
                         │
                         ▼
STEP 3: KERNEL DRIVER PROCESSING
┌───────────────────────────────────────────────────────────────┐
│  SafeOps NDIS Filter Driver (Kernel Mode)                     │
│  ┌─────────────────────────────────────────────────────────┐  │
│  │  1. Packet Capture                                      │  │
│  │     - Extract: Source IP, Dest IP, Ports, Protocol     │  │
│  │     - Timestamp: High-resolution clock                  │  │
│  │     - NIC Tag: "WAN" (NIC 1)                            │  │
│  │                                                         │  │
│  │  2. Write to Ring Buffer (Zero-Copy)                   │  │
│  │     - Producer writes packet metadata                   │  │
│  │     - No memcpy (pointer reference)                     │  │
│  │     - Atomic increment ring buffer index                │  │
│  │                                                         │  │
│  │  3. WFP Callout Hook                                    │  │
│  │     - FWPM_LAYER_INBOUND_IPPACKET_V4                    │  │
│  │     - Pass packet to userspace for decision             │  │
│  └─────────────────────────────────────────────────────────┘  │
│  Time: <50 microseconds                                       │
└────────────────────────┬──────────────────────────────────────┘
                         │
                         ▼
STEP 4: PARALLEL USERSPACE PROCESSING (Multi-threaded)
┌───────────────────────────────────────────────────────────────┐
│  Thread 1: Network Logger (Go - Core 1)                       │
│  ┌─────────────────────────────────────────────────────────┐  │
│  │  - Read from ring buffer (lock-free)                    │  │
│  │  - Parse packet headers                                 │  │
│  │  - Store in 5-minute circular buffer                    │  │
│  │  - Batch to PostgreSQL (every 1 second)                 │  │
│  │  - Update Redis session cache                           │  │
│  └─────────────────────────────────────────────────────────┘  │
│                                                               │
│  Thread 2: Firewall Engine (Rust - Core 2-3)                 │
│  ┌─────────────────────────────────────────────────────────┐  │
│  │  1. Connection Tracking                                 │  │
│  │     - Lookup in connection table (hash table)           │  │
│  │     - Check TCP state machine                           │  │
│  │     - NAT session lookup (3 NIC routing)                │  │
│  │                                                         │  │
│  │  2. Rule Evaluation                                     │  │
│  │     - Match against 100K firewall rules                 │  │
│  │     - Patricia Trie for IP matching                     │  │
│  │     - Port range checking                               │  │
│  │     - Protocol filtering                                │  │
│  │                                                         │  │
│  │  3. Decision: ALLOW / DENY / RATE_LIMIT                 │  │
│  │     - If ALLOW → Forward to NAT engine                  │  │
│  │     - If DENY → Send RST, log event                     │  │
│  │     - If RATE_LIMIT → Queue packet                      │  │
│  └─────────────────────────────────────────────────────────┘  │
│                                                               │
│  Thread 3: IDS/IPS Engine (Go - Core 4-5)                    │
│  ┌─────────────────────────────────────────────────────────┐  │
│  │  1. Signature Matching                                  │  │
│  │     - Aho-Corasick multi-pattern search                 │  │
│  │     - Check against 50K Snort rules                     │  │
│  │     - Payload inspection (deep packet)                  │  │
│  │                                                         │  │
│  │  2. Anomaly Detection                                   │  │
│  │     - Compare against traffic baseline                  │  │
│  │     - Detect port scans, brute force                    │  │
│  │     - Entropy analysis                                  │  │
│  │                                                         │  │
│  │  3. Threat Response                                     │  │
│  │     - If threat detected → Auto-block via firewall      │  │
│  │     - Generate alert (severity scoring)                 │  │
│  │     - Log to PostgreSQL                                 │  │
│  └─────────────────────────────────────────────────────────┘  │
│                                                               │
│  Thread 4: Threat Intel Lookup (Rust - Core 6)               │
│  ┌─────────────────────────────────────────────────────────┐  │
│  │  - Check source IP reputation                           │  │
│  │  - Bloom filter → Redis cache → PostgreSQL              │  │
│  │  - Lookup time: <10 microseconds (cache hit)            │  │
│  │  - If blacklisted → Notify firewall to block            │  │
│  └─────────────────────────────────────────────────────────┘  │
│                                                               │
│  Time: <500 microseconds total (parallel processing)         │
└────────────────────────┬──────────────────────────────────────┘
                         │
                         ▼
STEP 5: NAT & ROUTING (3-NIC Translation)
┌───────────────────────────────────────────────────────────────┐
│  NAT Engine (Firewall Service)                                │
│  ┌─────────────────────────────────────────────────────────┐  │
│  │  1. NAT Session Creation                                │  │
│  │     Original: [8.8.8.8:443 → Public_IP:12345]           │  │
│  │     Translated: [8.8.8.8:443 → 192.168.1.50:12345]      │  │
│  │     (LAN Client IP)                                     │  │
│  │                                                         │  │
│  │  2. NAT Table Update                                    │  │
│  │     - Store in Redis (fast lookup)                      │  │
│  │     - Session timeout: 300 seconds                      │  │
│  │     - Bidirectional mapping                             │  │
│  │                                                         │  │
│  │  3. Route Decision                                      │  │
│  │     - Destination: 192.168.1.50 (Wired LAN)             │  │
│  │     - Exit Interface: NIC 2 (USB-C RJ45)                │  │
│  └─────────────────────────────────────────────────────────┘  │
│  Time: <100 microseconds                                      │
└────────────────────────┬──────────────────────────────────────┘
                         │
                         ▼
STEP 6: PACKET FORWARDING TO LAN
┌───────────────────────────────────────────────────────────────┐
│  WFP Callout (Kernel Driver)                                  │
│  - FWPM_LAYER_OUTBOUND_IPPACKET_V4                            │
│  - Rewrite destination MAC address                            │
│  - Forward to NIC 2 (LAN Interface)                           │
│  - Hardware checksum offload                                  │
│  Time: <50 microseconds                                       │
└────────────────────────┬──────────────────────────────────────┘
                         │
                         ▼
STEP 7: TRANSMISSION TO LAN CLIENT
┌───────────────────────────────────────────────────────────────┐
│  NIC 2 (USB-C RJ45) → LAN Switch → Client Device              │
│  Packet: [8.8.8.8:443 → 192.168.1.50:12345]                   │
│  Total Latency: <1 millisecond (WAN to LAN)                   │
└───────────────────────────────────────────────────────────────┘

═══════════════════════════════════════════════════════════════
                    PERFORMANCE SUMMARY
───────────────────────────────────────────────────────────────
  Hardware Processing:      <10 µs
  Kernel Driver:            <50 µs
  Firewall Decision:        <500 µs
  NAT Translation:          <100 µs
  Packet Forwarding:        <50 µs
  ───────────────────────────────────
  TOTAL END-TO-END:         <1 ms (1000 µs)
═══════════════════════════════════════════════════════════════
```

---

## 5. Packet Flow - LAN to Internet (Outbound Traffic)

```
STEP 1: CLIENT REQUEST FROM WIRED LAN
┌───────────────────────────────────────────────────────────────┐
│  LAN Client (192.168.1.50) → NIC 2 (USB-C RJ45)               │
│  Request: [192.168.1.50:55123 → 1.1.1.1:443] (HTTPS)          │
│  Destination: Cloudflare DNS                                  │
└────────────────────────┬──────────────────────────────────────┘
                         │
                         ▼
STEP 2: KERNEL CAPTURE (NIC 2)
┌───────────────────────────────────────────────────────────────┐
│  SafeOps NDIS Filter Driver                                   │
│  - Capture from NIC 2 (LAN Interface)                         │
│  - Tag: "LAN_WIRED"                                           │
│  - Write to ring buffer                                       │
│  - Pass to WFP layer                                          │
└────────────────────────┬──────────────────────────────────────┘
                         │
                         ▼
STEP 3: FIREWALL OUTBOUND RULES
┌───────────────────────────────────────────────────────────────┐
│  Firewall Engine (Rust)                                       │
│  ┌─────────────────────────────────────────────────────────┐  │
│  │  1. User/Application Filtering                          │  │
│  │     - Check if 192.168.1.50 has internet access         │  │
│  │     - Check destination IP/Port rules                   │  │
│  │     - Protocol validation (HTTPS allowed)               │  │
│  │                                                         │  │
│  │  2. Threat Intelligence Check                           │  │
│  │     - Is 1.1.1.1 in blacklist? (No - Safe)              │  │
│  │     - Domain reputation check                           │  │
│  │     - Category filtering (allowed categories)           │  │
│  │                                                         │  │
│  │  3. Decision: ALLOW                                     │  │
│  └─────────────────────────────────────────────────────────┘  │
└────────────────────────┬──────────────────────────────────────┘
                         │
                         ▼
STEP 4: TLS INTERCEPTION (Optional - if enabled)
┌───────────────────────────────────────────────────────────────┐
│  TLS Proxy Service (Go)                                       │
│  ┌─────────────────────────────────────────────────────────┐  │
│  │  1. TLS Handshake Interception                          │  │
│  │     - Client → Proxy: TLS ClientHello                   │  │
│  │     - Proxy extracts SNI: "one.one.one.one"             │  │
│  │                                                         │  │
│  │  2. Certificate Generation                              │  │
│  │     - Check certificate cache (Redis)                   │  │
│  │     - If not cached: Generate cert for domain           │  │
│  │     - Sign with SafeOps Root CA                         │  │
│  │     - Cache for 24 hours                                │  │
│  │                                                         │  │
│  │  3. MITM Connection                                     │  │
│  │     Client ←→ Proxy ←→ Real Server                      │  │
│  │     - Inspect HTTP/2 frames                             │  │
│  │     - Log domains, URLs, headers                        │  │
│  │     - DLP (Data Loss Prevention) scanning               │  │
│  │     - Forward to real server                            │  │
│  └─────────────────────────────────────────────────────────┘  │
│  Latency Impact: +3-5 milliseconds                            │
└────────────────────────┬──────────────────────────────────────┘
                         │
                         ▼
STEP 5: SOURCE NAT (SNAT)
┌───────────────────────────────────────────────────────────────┐
│  NAT Engine (3-NIC Translation)                               │
│  ┌─────────────────────────────────────────────────────────┐  │
│  │  Original Packet:                                       │  │
│  │    [192.168.1.50:55123 → 1.1.1.1:443]                   │  │
│  │                                                         │  │
│  │  After SNAT:                                            │  │
│  │    [Public_IP:32768 → 1.1.1.1:443]                      │  │
│  │                                                         │  │
│  │  NAT Session:                                           │  │
│  │    Internal: 192.168.1.50:55123                         │  │
│  │    External: Public_IP:32768                            │  │
│  │    Destination: 1.1.1.1:443                             │  │
│  │    Timeout: 300 seconds                                 │  │
│  │    Store in Redis for fast return path                  │  │
│  └─────────────────────────────────────────────────────────┘  │
└────────────────────────┬──────────────────────────────────────┘
                         │
                         ▼
STEP 6: ROUTE TO WAN INTERFACE
┌───────────────────────────────────────────────────────────────┐
│  Routing Decision                                             │
│  - Destination: 1.1.1.1 (Internet)                            │
│  - Exit Interface: NIC 1 (WAN - Onboard RJ45)                 │
│  - Next Hop: ISP Gateway                                      │
└────────────────────────┬──────────────────────────────────────┘
                         │
                         ▼
STEP 7: TRANSMISSION TO INTERNET
┌───────────────────────────────────────────────────────────────┐
│  NIC 1 (WAN) → ISP Router → Internet → 1.1.1.1                │
│  Packet: [Public_IP:32768 → 1.1.1.1:443]                      │
│  Total Latency: <5 milliseconds (LAN to WAN)                  │
└───────────────────────────────────────────────────────────────┘

STEP 8: RETURN PATH (Response from Internet)
┌───────────────────────────────────────────────────────────────┐
│  Internet → NIC 1 → NAT Lookup → Translate Back → NIC 2       │
│  Response: [1.1.1.1:443 → Public_IP:32768]                    │
│  After NAT: [1.1.1.1:443 → 192.168.1.50:55123]                │
│  Forward to LAN client via NIC 2                              │
└───────────────────────────────────────────────────────────────┘
```

---

## 6. WiFi Access Point Flow (NIC 3)

```
STEP 1: WIFI CLIENT ASSOCIATION
┌───────────────────────────────────────────────────────────────┐
│  Smartphone → WiFi (NIC 3 - Intel AX200)                      │
│  ┌─────────────────────────────────────────────────────────┐  │
│  │  1. WiFi Association Request                            │  │
│  │     SSID: "SafeOps-Secure"                              │  │
│  │     Security: WPA3-Personal                             │  │
│  │     Password: [User configured]                         │  │
│  │                                                         │  │
│  │  2. WPA3 4-Way Handshake                                │  │
│  │     - SAE (Simultaneous Authentication of Equals)       │  │
│  │     - PMK derivation                                    │  │
│  │     - Key installation                                  │  │
│  │                                                         │  │
│  │  3. Association Complete                                │  │
│  │     - Client MAC: AA:BB:CC:DD:EE:FF                     │  │
│  │     - Status: Authenticated + Associated                │  │
│  └─────────────────────────────────────────────────────────┘  │
└────────────────────────┬──────────────────────────────────────┘
                         │
                         ▼
STEP 2: DHCP IP ASSIGNMENT
┌───────────────────────────────────────────────────────────────┐
│  DHCP Server (WiFi AP Service)                                │
│  ┌─────────────────────────────────────────────────────────┐  │
│  │  DHCP Discover (Client → Broadcast)                     │  │
│  │  DHCP Offer (Server → Client)                           │  │
│  │    IP: 192.168.2.100                                    │  │
│  │    Subnet: 255.255.255.0                                │  │
│  │    Gateway: 192.168.2.1 (NIC 3 IP)                      │  │
│  │    DNS: 192.168.2.1 (SafeOps DNS Forwarder)             │  │
│  │    Lease: 86400 seconds (24 hours)                      │  │
│  │                                                         │  │
│  │  DHCP Request (Client → Server)                         │  │
│  │  DHCP Ack (Server → Client)                             │  │
│  │                                                         │  │
│  │  Store lease in PostgreSQL + Redis cache                │  │
│  └─────────────────────────────────────────────────────────┘  │
└────────────────────────┬──────────────────────────────────────┘
                         │
                         ▼
STEP 3: CLIENT INTERNET REQUEST
┌───────────────────────────────────────────────────────────────┐
│  WiFi Client (192.168.2.100) → NIC 3                          │
│  Request: [192.168.2.100:49876 → 8.8.8.8:53] (DNS Query)      │
│  ┌─────────────────────────────────────────────────────────┐  │
│  │  1. Packet Capture (Kernel Driver)                      │  │
│  │     - Tag: "WIFI_AP" (NIC 3)                            │  │
│  │     - Ring buffer write                                 │  │
│  │                                                         │  │
│  │  2. Firewall Processing                                 │  │
│  │     - WiFi zone rules (separate from LAN)               │  │
│  │     - Check client permissions                          │  │
│  │     - Apply rate limiting (per-client)                  │  │
│  │     - Decision: ALLOW                                   │  │
│  │                                                         │  │
│  │  3. DNS Inspection (if DNS query)                       │  │
│  │     - Check against DNS blacklist                       │  │
│  │     - Log domain requests                               │  │
│  │     - Forward to upstream DNS                           │  │
│  │                                                         │  │
│  │  4. Source NAT                                          │  │
│  │     Original: [192.168.2.100:49876 → 8.8.8.8:53]        │  │
│  │     After NAT: [Public_IP:40000 → 8.8.8.8:53]           │  │
│  │                                                         │  │
│  │  5. Route to WAN (NIC 1)                                │  │
│  │     - Exit via WAN interface                            │  │
│  │     - Transmit to Internet                              │  │
│  └─────────────────────────────────────────────────────────┘  │
└───────────────────────────────────────────────────────────────┘

STEP 4: WIFI-SPECIFIC SECURITY FEATURES
┌───────────────────────────────────────────────────────────────┐
│  WiFi Security Layer                                          │
│  ┌─────────────────────────────────────────────────────────┐  │
│  │  1. Client Isolation                                    │  │
│  │     - WiFi clients cannot see each other                │  │
│  │     - No direct WiFi-to-WiFi communication              │  │
│  │     - Only WiFi-to-Internet traffic allowed             │  │
│  │                                                         │  │
│  │  2. Guest Network Features                              │  │
│  │     - Separate VLAN: 192.168.2.0/24                     │  │
│  │     - No access to LAN (192.168.1.0/24)                 │  │
│  │     - Bandwidth throttling (optional)                   │  │
│  │     - Time-based access restrictions                    │  │
│  │                                                         │  │
│  │  3. Captive Portal (Optional)                           │  │
│  │     - Splash page for guest authentication              │  │
│  │     - Terms of service acceptance                       │  │
│  │     - Social login (Facebook/Google)                    │  │
│  │                                                         │  │
│  │  4. Per-Client Monitoring                               │  │
│  │     - Bandwidth usage tracking                          │  │
│  │     - Connection duration                               │  │
│  │     - Device fingerprinting                             │  │
│  │     - Threat detection (per WiFi client)                │  │
│  └─────────────────────────────────────────────────────────┘  │
└───────────────────────────────────────────────────────────────┘
```
