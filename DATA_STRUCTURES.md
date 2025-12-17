# SafeOps v2.0 - Complete Data Structures Reference

> **Comprehensive data structure documentation for all SafeOps components**
> 
> Last Updated: 2025-12-17  
> Version: 2.0.0

---

## 📚 Table of Contents

- [Database Structures](#database-structures)
- [Kernel Driver Structures](#kernel-driver-structures)
- [Network Protocol Structures](#network-protocol-structures)
- [Configuration Structures](#configuration-structures)
- [gRPC Message Structures](#grpc-message-structures)
- [Shared Memory Structures](#shared-memory-structures)
- [Performance Structures](#performance-structures)

---

## 🗄️ Database Structures

### Core Tables Overview

| Table Name | Primary Key | Partitioned | Row Estimate | Purpose |
|------------|-------------|-------------|--------------|---------|
| `ip_reputation` | ip_id | Yes (by continent) | 100M+ | IP threat scoring |
| `domain_reputation` | domain_id | No | 50M+ | Domain filtering |
| `hash_reputation` | hash_id | No | 10M+ | File malware detection |
| `ioc_indicators` | ioc_id | Yes (by type) | 25M+ | Indicators of Compromise |
| `threat_feeds` | feed_id | No | ~100 | Feed source configuration |
| `geolocation_data` | ip_start | Yes (by continent) | 5M+ | IP geolocation |
| `asn_data` | asn_number | No | 100K | ASN ownership |

---

### IP Reputation Structure

```sql
CREATE TABLE ip_reputation (
    -- Primary Key
    ip_id                 BIGSERIAL PRIMARY KEY,
    ip_address            INET NOT NULL UNIQUE,
    
    -- Classification
    reputation_score      INTEGER CHECK (reputation_score BETWEEN -100 AND 100),
    confidence_level      NUMERIC(3,2) CHECK (confidence_level BETWEEN 0 AND 1),
    threat_category_id    INTEGER REFERENCES threat_categories(category_id),
    
    -- Geographic Context
    country_code          CHAR(2),
    city                  VARCHAR(100),
    continent_code        VARCHAR(2),
    latitude              NUMERIC(9,6),
    longitude             NUMERIC(9,6),
    
    -- Network Context
    asn_number            BIGINT,
    hosting_provider      VARCHAR(200),
    is_proxy              BOOLEAN DEFAULT FALSE,
    is_vpn                BOOLEAN DEFAULT FALSE,
    is_tor                BOOLEAN DEFAULT FALSE,
    is_datacenter         BOOLEAN DEFAULT FALSE,
    
    -- Source Attribution
    source_feeds          INTEGER[] DEFAULT '{}',
    first_seen            TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    last_seen             TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    last_updated          TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    
    -- Metadata
    tags                  TEXT[] DEFAULT '{}',
    notes                 TEXT,
    false_positive_flag   BOOLEAN DEFAULT FALSE
    
) PARTITION BY LIST (continent_code);

-- Reputation Score Scale:
--   -100 to -76: Critical threat (auto-block)
--    -75 to -51: High threat (block recommended)
--    -50 to -26: Medium threat (alert)
--    -25 to   0: Low threat (monitor)
--      1 to  25: Neutral/Unknown
--     26 to  50: Trusted
--     51 to  75: Highly trusted
--     76 to 100: Whitelisted
```

**Indexes:**
- `idx_ip_reputation_score` - B-tree on (reputation_score, last_seen)
- `idx_ip_reputation_country` - B-tree on (country_code)
- `idx_ip_reputation_asn` - B-tree on (asn_number)
- `idx_ip_reputation_threat_cat` - B-tree on (threat_category_id)
- `idx_ip_reputation_updated` - BRIN on (last_updated)
- `idx_ip_reputation_tags` - GIN on (tags)

---

### Domain Reputation Structure

```sql
CREATE TABLE domain_reputation (
    -- Primary Key
    domain_id             BIGSERIAL PRIMARY KEY,
    domain_name           CITEXT NOT NULL UNIQUE,  -- Case-insensitive
    
    -- Parent Domain Context
    parent_domain         CITEXT,
    tld                   VARCHAR(50),
    is_subdomain          BOOLEAN DEFAULT FALSE,
    
    -- Classification
    reputation_score      INTEGER CHECK (reputation_score BETWEEN -100 AND 100),
    confidence_level      NUMERIC(3,2) CHECK (confidence_level BETWEEN 0 AND 1),
    threat_category_id    INTEGER REFERENCES threat_categories(category_id),
    
    -- Domain Properties
    domain_age_days       INTEGER,
    registrar             VARCHAR(200),
    registration_date     DATE,
    expiration_date       DATE,
    
    -- DNS Properties
    has_mx_records        BOOLEAN,
    has_spf_record        BOOLEAN,
    has_dmarc_record      BOOLEAN,
    nameservers           TEXT[],
    
    -- Content Analysis
    content_category      VARCHAR(100),
    has_ssl               BOOLEAN DEFAULT FALSE,
    ssl_issuer            VARCHAR(200),
    ssl_valid_until       TIMESTAMP WITH TIME ZONE,
    
    -- Behavioral Indicators
    dga_score             NUMERIC(3,2) CHECK (dga_score BETWEEN 0 AND 1),  -- Domain Generation Algorithm
    typosquatting_target  VARCHAR(255),
    homograph_attack      BOOLEAN DEFAULT FALSE,
    
    -- Source Attribution
    source_feeds          INTEGER[] DEFAULT '{}',
    blocked_by_feeds      INTEGER[] DEFAULT '{}',
    first_seen            TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    last_seen             TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    last_updated          TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    
    -- DNS Query Analytics
    query_count_24h       BIGINT DEFAULT 0,
    query_count_7d        BIGINT DEFAULT 0,
    query_count_30d       BIGINT DEFAULT 0,
    unique_clients_24h    INTEGER DEFAULT 0,
    
    -- Metadata
    tags                  TEXT[] DEFAULT '{}',
    notes                 TEXT,
    false_positive_flag   BOOLEAN DEFAULT FALSE,
    whitelisted           BOOLEAN DEFAULT FALSE
);

-- Fuzzy Matching Support
CREATE INDEX idx_domain_trigram ON domain_reputation 
    USING GIN (domain_name gin_trgm_ops);
```

**Key Features:**
- **CITEXT**: Case-insensitive domain matching
- **Trigram Indexing**: Fast fuzzy search for typosquatting detection
- **DNS Analytics**: Built-in query counters for trend analysis
- **DGA Detection**: Algorithm-generated domain scoring

---

### Hash Reputation Structure

```sql
CREATE TABLE hash_reputation (
    -- Primary Key
    hash_id               BIGSERIAL PRIMARY KEY,
    
    -- Multi-Hash Support
    md5_hash              CHAR(32) UNIQUE,
    sha1_hash             CHAR(40) UNIQUE,
    sha256_hash           CHAR(64) UNIQUE,
    sha512_hash           CHAR(128) UNIQUE,
    ssdeep_hash           VARCHAR(255),  -- Fuzzy hashing
    
    -- File Properties
    file_size             BIGINT,
    file_type             VARCHAR(100),
    file_extension        VARCHAR(50),
    mime_type             VARCHAR(200),
    
    -- Classification
    reputation_score      INTEGER CHECK (reputation_score BETWEEN -100 AND 100),
    confidence_level      NUMERIC(3,2) CHECK (confidence_level BETWEEN 0 AND 1),
    threat_category_id    INTEGER REFERENCES threat_categories(category_id),
    
    -- Malware Analysis
    malware_family        VARCHAR(200),
    malware_variant       VARCHAR(200),
    is_packed             BOOLEAN DEFAULT FALSE,
    packer_type           VARCHAR(100),
    
    -- Detection Coverage
    av_detections         INTEGER DEFAULT 0,
    av_total_engines      INTEGER DEFAULT 0,
    sandbox_score         INTEGER CHECK (sandbox_score BETWEEN 0 AND 100),
    
    -- Behavioral Indicators
    creates_process       BOOLEAN,
    modifies_registry     BOOLEAN,
    network_activity      BOOLEAN,
    file_operations       BOOLEAN,
    
    -- PE Header Info (Windows executables)
    pe_imphash            CHAR(32),
    pe_compile_time       TIMESTAMP,
    pe_signature_valid    BOOLEAN,
    pe_signer             VARCHAR(255),
    
    -- Source Attribution
    source_feeds          INTEGER[] DEFAULT '{}',
    first_seen            TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    last_seen             TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    last_updated          TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    
    -- Distribution
    seen_count            BIGINT DEFAULT 1,
    unique_sources        INTEGER DEFAULT 1,
    
    -- Metadata
    tags                  TEXT[] DEFAULT '{}',
    notes                 TEXT,
    false_positive_flag   BOOLEAN DEFAULT FALSE
);

-- Ensure at least one hash is provided
ALTER TABLE hash_reputation ADD CONSTRAINT at_least_one_hash
    CHECK (md5_hash IS NOT NULL OR sha1_hash IS NOT NULL OR 
           sha256_hash IS NOT NULL OR sha512_hash IS NOT NULL);
```

**Multi-Hash Strategy:**
- Query ANY hash type for instant lookup
- Correlate files across different hash algorithms
- SSDeep for fuzzy/similar file detection

---

### IOC Indicators Structure

```sql
CREATE TABLE ioc_indicators (
    -- Primary Key
    ioc_id                BIGSERIAL PRIMARY KEY,
    
    -- IOC Type Classification
    ioc_type              VARCHAR(50) NOT NULL 
        CHECK (ioc_type IN (
            'IP', 'DOMAIN', 'URL', 'EMAIL', 'HASH_MD5', 'HASH_SHA1', 
            'HASH_SHA256', 'HASH_SHA512', 'MUTEX', 'REGISTRY_KEY', 
            'FILE_PATH', 'USER_AGENT', 'ASN', 'CIDR', 'CVE'
        )),
    ioc_value             TEXT NOT NULL,
    
    -- Classification
    severity              VARCHAR(20) CHECK (severity IN ('CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO')),
    confidence_level      NUMERIC(3,2) CHECK (confidence_level BETWEEN 0 AND 1),
    threat_category_id    INTEGER REFERENCES threat_categories(category_id),
    
    -- Campaign Attribution
    campaign_id           BIGINT REFERENCES threat_campaigns(campaign_id),
    threat_actor          VARCHAR(200),
    attack_technique      VARCHAR(200),  -- MITRE ATT&CK ID
    
    -- STIX/TAXII Support
    stix_id               VARCHAR(255),
    stix_version          VARCHAR(10),
    taxii_collection      VARCHAR(200),
    
    -- Context
    description           TEXT,
    context               JSONB,  -- Flexible metadata
    
    -- Status
    is_active             BOOLEAN DEFAULT TRUE,
    is_validated          BOOLEAN DEFAULT FALSE,
    requires_investigation BOOLEAN DEFAULT FALSE,
    
    -- Source Attribution
    source_feed_id        INTEGER REFERENCES threat_feeds(feed_id),
    first_seen            TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    last_seen             TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    expires_at            TIMESTAMP WITH TIME ZONE,
    
    -- Sighting Tracking
    sighting_count        BIGINT DEFAULT 0,
    last_sighting         TIMESTAMP WITH TIME ZONE,
    
    -- Relationships
    related_iocs          BIGINT[] DEFAULT '{}',
    
    -- Metadata
    tags                  TEXT[] DEFAULT '{}',
    notes                 TEXT,
    false_positive_flag   BOOLEAN DEFAULT FALSE,
    
    UNIQUE (ioc_type, ioc_value)
    
) PARTITION BY LIST (ioc_type);

-- Create partitions for each IOC type
CREATE TABLE ioc_indicators_ip PARTITION OF ioc_indicators 
    FOR VALUES IN ('IP', 'CIDR');
CREATE TABLE ioc_indicators_domain PARTITION OF ioc_indicators 
    FOR VALUES IN ('DOMAIN', 'URL', 'EMAIL');
CREATE TABLE ioc_indicators_hash PARTITION OF ioc_indicators 
    FOR VALUES IN ('HASH_MD5', 'HASH_SHA1', 'HASH_SHA256', 'HASH_SHA512');
```

**IOC Type Coverage:**
- **Network**: IP, Domain, URL, Email, CIDR, ASN
- **File**: MD5, SHA1, SHA256, SHA512, File paths
- **System**: Registry keys, Mutexes, User agents
- **Vulnerabilities**: CVE identifiers

---

### Threat Categories Reference

```sql
CREATE TABLE threat_categories (
    category_id           SERIAL PRIMARY KEY,
    category_name         VARCHAR(100) NOT NULL UNIQUE,
    category_code         VARCHAR(50) NOT NULL UNIQUE,
    parent_category_id    INTEGER REFERENCES threat_categories(category_id),
    severity_default      VARCHAR(20) CHECK (severity_default IN ('CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO')),
    description           TEXT,
    mitigation_advice     TEXT,
    is_active             BOOLEAN DEFAULT TRUE,
    display_order         INTEGER DEFAULT 0
);

-- 37 Pre-defined Categories:
-- MALWARE: Ransomware, Trojan, Worm, RAT, Cryptominer, etc.
-- PHISHING: Credential harvesting, Business Email Compromise
-- BOTNET: C2 servers, Bot infrastructure
-- EXPLOIT: Exploit kits, 0-day servers
-- SPAM: Spam sources, Email threats
-- PROXY: VPN, TOR, Anonymous proxies
-- SCANNER: Port scanners, Vulnerability scanners
-- BRUTE_FORCE: SSH/RDP/FTP brute force
-- DDoS: Amplification sources, Attack infrastructure
```

---

### Threat Feeds Configuration

```sql
CREATE TABLE threat_feeds (
    -- Primary Key
    feed_id               SERIAL PRIMARY KEY,
    
    -- Feed Identity
    feed_name             VARCHAR(100) NOT NULL UNIQUE,
    feed_provider         VARCHAR(200) NOT NULL,
    feed_url              TEXT NOT NULL,
    feed_type             VARCHAR(50) CHECK (feed_type IN ('CSV', 'JSON', 'XML', 'TAXII', 'STIX', 'API')),
    
    -- Access Configuration
    requires_auth         BOOLEAN DEFAULT FALSE,
    auth_type             VARCHAR(50) CHECK (auth_type IN ('NONE', 'API_KEY', 'BASIC', 'BEARER', 'OAUTH2')),
    credential_vault_id   UUID,  -- Encrypted storage reference
    
    -- Update Schedule
    update_frequency_hours INTEGER DEFAULT 24,
    last_update           TIMESTAMP WITH TIME ZONE,
    next_scheduled_update TIMESTAMP WITH TIME ZONE,
    
    -- Quality Metrics
    reliability_score     INTEGER CHECK (reliability_score BETWEEN 0 AND 100),
    false_positive_rate   NUMERIC(5,4),
    data_freshness_hours INTERVAL,
    
    -- Health Monitoring
    is_active             BOOLEAN DEFAULT TRUE,
    consecutive_failures  INTEGER DEFAULT 0,
    last_error            TEXT,
    last_success          TIMESTAMP WITH TIME ZONE,
    
    -- Data Processing
    parser_config         JSONB,  -- Custom parsing rules
    priority              INTEGER DEFAULT 50,
    auto_validate         BOOLEAN DEFAULT FALSE,
    retention_days        INTEGER DEFAULT 90,
    
    -- Statistics
    total_records_added   BIGINT DEFAULT 0,
    total_records_updated BIGINT DEFAULT 0,
    avg_processing_time_ms INTEGER,
    
    -- Metadata
    description           TEXT,
    documentation_url     TEXT,
    tags                  TEXT[] DEFAULT '{}',
    created_at            TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at            TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- 18 Pre-configured Feeds:
-- - AbuseIPDB, Blocklist.de, Spamhaus, EmergingThreats
-- - AlienVault OTX, VirusTotal, URLhaus, PhishTank
-- - Talos Intelligence, Proofpoint, MalwareBazaar, etc.
```

---

### Geolocation Data Structure

```sql
CREATE TABLE geolocation_data (
    -- IP Range (Primary Key)
    ip_start              INET NOT NULL,
    ip_end                INET NOT NULL,
    
    -- Geographic Location
    country_code          CHAR(2) NOT NULL,
    country_name          VARCHAR(100),
    region                VARCHAR(100),
    city                  VARCHAR(100),
    postal_code           VARCHAR(20),
    continent_code        VARCHAR(2) NOT NULL,
    
    -- Coordinates
    latitude              NUMERIC(9,6),
    longitude             NUMERIC(9,6),
    accuracy_radius_km    INTEGER,
    
    -- Network Information
    asn_number            BIGINT,
    asn_name              VARCHAR(255),
    isp                   VARCHAR(255),
    organization          VARCHAR(255),
    
    -- Threat Intelligence
    is_anonymous_proxy    BOOLEAN DEFAULT FALSE,
    is_satellite_provider BOOLEAN DEFAULT FALSE,
    is_hosting_provider   BOOLEAN DEFAULT FALSE,
    
    -- Metadata
    last_updated          TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    
    PRIMARY KEY (ip_start, ip_end)
    
) PARTITION BY LIST (continent_code);

-- Partitions: AF, AS, EU, NA, SA, OC, AN

-- IP Range Query Index (for BETWEEN operations)
CREATE INDEX idx_geolocation_ip_range ON geolocation_data 
    USING GIST (inet_range(ip_start, ip_end));
```

---

### ASN Data Structure

```sql
CREATE TABLE asn_data (
    -- Primary Key
    asn_number            BIGINT PRIMARY KEY,
    
    -- Organization
    asn_name              VARCHAR(255) NOT NULL,
    organization          VARCHAR(255),
    country_code          CHAR(2),
    
    -- Network Ranges
    ipv4_prefixes         CIDR[] DEFAULT '{}',
    ipv6_prefixes         CIDR[] DEFAULT '{}',
    total_ips             BIGINT,
    
    -- Classification
    asn_type              VARCHAR(50) CHECK (asn_type IN ('ISP', 'HOSTING', 'ENTERPRISE', 'GOVERNMENT', 'EDUCATION', 'RESEARCH')),
    reputation_score      INTEGER CHECK (reputation_score BETWEEN -100 AND 100),
    
    -- Traffic Characteristics
    is_transit_provider   BOOLEAN DEFAULT FALSE,
    peer_asns             BIGINT[] DEFAULT '{}',
    upstream_asns         BIGINT[] DEFAULT '{}',
    
    -- Security Metrics
    abuse_score           INTEGER CHECK (abuse_score BETWEEN 0 AND 100),
    spam_score            INTEGER CHECK (spam_score BETWEEN 0 AND 100),
    malware_score         INTEGER CHECK (malware_score BETWEEN 0 AND 100),
    
    -- Abuse Contact
    abuse_email           VARCHAR(255),
    abuse_phone           VARCHAR(50),
    abuse_url             TEXT,
    
    -- WHOIS Data
    whois_data            JSONB,
    registration_date     DATE,
    last_updated          TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    
    -- Statistics
    threat_count_30d      INTEGER DEFAULT 0,
    clean_count_30d       INTEGER DEFAULT 0
);
```

---

## 🔧 Kernel Driver Structures

### Packet Metadata Structure

```c
// File: src/shared/c/packet_structs.h

#define MAX_PAYLOAD_SNAPSHOT 128
#define MAX_PACKET_METADATA_SIZE 512

typedef struct _PACKET_METADATA {
    // Packet Identifiers
    UINT64         PacketId;           // Unique packet ID
    UINT64         Timestamp;          // High-resolution timestamp (100ns units)
    UINT32         ProcessId;          // Owning process ID
    UINT32         ThreadId;           // Thread ID that initiated connection
    
    // Network Layer (L3)
    UINT8          IpVersion;          // 4 or 6
    UINT32         SourceIp;           // IPv4 source (network byte order)
    UINT32         DestIp;             // IPv4 destination
    UINT8          SourceIpv6[16];     // IPv6 source
    UINT8          DestIpv6[16];       // IPv6 destination
    UINT8          Protocol;           // TCP=6, UDP=17, ICMP=1
    UINT8          Ttl;                // Time to live
    UINT16         IpHeaderLength;     // IP header length
    UINT16         TotalLength;        // Total packet length
    
    // Transport Layer (L4)
    UINT16         SourcePort;         // Source port
    UINT16         DestPort;           // Destination port
    UINT32         TcpSeqNumber;       // TCP sequence number
    UINT32         TcpAckNumber;       // TCP acknowledgment number
    UINT8          TcpFlags;           // SYN, ACK, FIN, RST, etc.
    UINT16         TcpWindowSize;      // TCP window
    UINT16         UdpLength;          // UDP packet length
    
    // Direction & Interface
    UINT8          Direction;          // 0=Inbound, 1=Outbound
    UINT32         InterfaceIndex;     // Network interface LUID
    UINT32         SubInterfaceIndex;  // Sub-interface index
    
    // Classification Results
    UINT32         FilterId;           // Matching WFP filter ID
    UINT16         LayerId;            // WFP layer ID
    UINT64         ClassifyHandle;     // WFP classify handle
    
    // Decision Results
    UINT8          Action;             // 0=PERMIT, 1=BLOCK, 2=PENDING
    UINT8          Reason;             // Why was decision made
    UINT8          RulePriority;       // Priority of matching rule
    UINT32         RuleId;             // ID of matching firewall rule
    
    // Deep Packet Inspection
    UINT16         PayloadLength;      // Actual payload size
    UINT16         PayloadSnapshotLength; // Bytes captured
    UINT8          PayloadSnapshot[MAX_PAYLOAD_SNAPSHOT]; // Payload data
    
    // Connection Tracking
    UINT64         FlowId;             // Connection flow ID
    UINT32         PacketNumber;       // Packet # in flow
    UINT64         FlowByteCount;      // Total bytes in flow
    UINT64         FlowPacketCount;    // Total packets in flow
    
    // Performance Metrics
    UINT32         ProcessingTimeMicroseconds; // Time spent processing
    UINT8          CpuId;              // Which CPU processed this
    
    // Flags
    UINT32         Flags;              // Various boolean flags
    
} PACKET_METADATA, *PPACKET_METADATA;

// Flag definitions
#define PKT_FLAG_FRAGMENTED       0x00000001
#define PKT_FLAG_REASSEMBLED      0x00000002
#define PKT_FLAG_ENCRYPTED        0x00000004
#define PKT_FLAG_SUSPICIOUS       0x00000008
#define PKT_FLAG_MATCHED_RULE     0x00000010
#define PKT_FLAG_THREAT_DETECTED  0x00000020
#define PKT_FLAG_CONNECTION_START 0x00000040
#define PKT_FLAG_CONNECTION_END   0x00000080
```

---

### Ring Buffer Structure

```c
// Lock-free ring buffer for kernel-userspace communication

#define RING_BUFFER_SIZE (16 * 1024 * 1024)  // 16 MB
#define RING_BUFFER_ENTRIES (RING_BUFFER_SIZE / sizeof(PACKET_METADATA))

typedef struct _RING_BUFFER_HEADER {
    UINT32   Magic;                // 0x53414645 ('SAFE')
    UINT32   Version;              // Buffer version
    UINT64   TotalEntries;         // Total slots in buffer
    
    // Lock-free indices (aligned to cache line)
    alignas(64) volatile UINT64 WriteIndex;  // Next write position
    alignas(64) volatile UINT64 ReadIndex;   // Next read position
    
    // Statistics (aligned to cache line)
    alignas(64) volatile UINT64 PacketsWritten;  // Total packets written
    alignas(64) volatile UINT64 PacketsRead;     // Total packets read
    alignas(64) volatile UINT64 Drops;           // Packets dropped (full buffer)
    alignas(64) volatile UINT64 Wraps;           // Buffer wrap-around count
    
} RING_BUFFER_HEADER, *PRING_BUFFER_HEADER;

typedef struct _RING_BUFFER {
    RING_BUFFER_HEADER Header;
    PACKET_METADATA    Entries[RING_BUFFER_ENTRIES];
    
} RING_BUFFER, *PRING_BUFFER;

// Shared memory section name
#define RING_BUFFER_SECTION_NAME L"\\BaseNamedObjects\\SafeOpsRingBuffer"
```

**Key Features:**
- **Lock-free design**: Uses atomic operations for concurrent access
- **Cache-line alignment**: Prevents false sharing between kernel/user
- **Producer-consumer pattern**: Kernel writes, userspace reads
- **Overwrite policy**: Drops old packets when buffer full

---

### Connection Tracking Structure

```c
typedef struct _CONNECTION_ENTRY {
    // 5-tuple identifier
    UINT32         LocalIp;
    UINT32         RemoteIp;
    UINT16         LocalPort;
    UINT16         RemotePort;
    UINT8          Protocol;
    
    // Connection State
    UINT8          State;              // TCP states, UDP=ACTIVE
    UINT64         FlowId;             // Unique flow identifier
    
    // Timestamps
    UINT64         CreationTime;       // When connection started
    UINT64         LastSeenTime;       // Last packet timestamp
    UINT64         ExpirationTime;     // When to remove if idle
    
    // Traffic Counters
    UINT64         BytesSent;          // Outbound bytes
    UINT64         BytesReceived;      // Inbound bytes
    UINT32         PacketsSent;        // Outbound packets
    UINT32         PacketsReceived;    // Inbound packets
    
    // Process Information
    UINT32         ProcessId;
    WCHAR          ProcessPath[260];   // Full executable path
    
    // Security Classification
    UINT8          ThreatLevel;        // 0=Clean, 100=Critical
    UINT16         RuleId;             // Applied firewall rule
    UINT32         Flags;              // Connection flags
    
    // Hash table linkage
    struct _CONNECTION_ENTRY* Next;    // Collision chain
    
} CONNECTION_ENTRY, *PCONNECTION_ENTRY;

#define CONN_STATE_TCP_SYN_SENT       1
#define CONN_STATE_TCP_SYN_RECV       2
#define CONN_STATE_TCP_ESTABLISHED    3
#define CONN_STATE_TCP_FIN_WAIT       4
#define CONN_STATE_TCP_CLOSE_WAIT     5
#define CONN_STATE_TCP_CLOSED         6
#define CONN_STATE_UDP_ACTIVE         10
#define CONN_STATE_ICMP_ACTIVE        11
```

---

### Firewall Rule Structure

```c
#define MAX_RULE_NAME_LEN 128
#define MAX_RULE_DESC_LEN 256

typedef struct _FIREWALL_RULE {
    // Rule Identity
    UINT32         RuleId;
    WCHAR          RuleName[MAX_RULE_NAME_LEN];
    WCHAR          Description[MAX_RULE_DESC_LEN];
    
    // Rule Status
    BOOLEAN        Enabled;
    UINT8          Priority;           // 0=Highest, 255=Lowest
    UINT32         HitCount;           // Times rule matched
    BOOLEAN        LogMatches;         // Log when matched
    
    // Match Criteria - Source
    UINT32         SourceIp;           // 0.0.0.0 = Any
    UINT32         SourceMask;         // Subnet mask
    UINT16         SourcePortStart;    // 0 = Any
    UINT16         SourcePortEnd;
    
    // Match Criteria - Destination
    UINT32         DestIp;
    UINT32         DestMask;
    UINT16         DestPortStart;
    UINT16         DestPortEnd;
    
    // Protocol & Direction
    UINT8          Protocol;           // 0=Any, 6=TCP, 17=UDP
    UINT8          Direction;          // 0=Any, 1=Inbound, 2=Outbound
    
    // Process Filtering
    UINT32         ProcessId;          // 0 = Any process
    WCHAR          ProcessPath[260];   // Empty = Any
    
    // Action
    UINT8          Action;             // 0=BLOCK, 1=ALLOW, 2=INSPECT
    
    // Time-based Rules
    UINT64         ValidFrom;          // UTC timestamp (0 = always)
    UINT64         ValidUntil;         // 0 = never expires
    
    // Advanced Options
    UINT32         RateLimitPPS;       // Packets per second (0 = unlimited)
    UINT32         RateLimitBPS;       // Bytes per second
    BOOLEAN        RequireEstablished; // Only allow established connections
    BOOLEAN        RequireEncryption;  // Require TLS/SSL
    
    // Threat Intelligence Integration
    BOOLEAN        CheckThreatIntel;   // Query threat database
    UINT8          MinThreatScore;     // Block if score >= this
    
    // List linkage
    struct _FIREWALL_RULE* Next;
    
} FIREWALL_RULE, *PFIREWALL_RULE;

// Action codes
#define RULE_ACTION_BLOCK   0
#define RULE_ACTION_ALLOW   1
#define RULE_ACTION_INSPECT 2
#define RULE_ACTION_LOG     3
```

---

## 🌐 Network Protocol Structures

### TCP Header (Windows Native)

```c
typedef struct _TCP_HEADER {
    UINT16  SourcePort;
    UINT16  DestPort;
    UINT32  SequenceNumber;
    UINT32  AckNumber;
    UINT8   DataOffset;      // Upper 4 bits = header length in 32-bit words
    UINT8   Flags;           // URG, ACK, PSH, RST, SYN, FIN
    UINT16  WindowSize;
    UINT16  Checksum;
    UINT16  UrgentPointer;
    // Options and data follow...
} TCP_HEADER, *PTCP_HEADER;

// TCP Flags
#define TCP_FLAG_FIN  0x01
#define TCP_FLAG_SYN  0x02
#define TCP_FLAG_RST  0x04
#define TCP_FLAG_PSH  0x08
#define TCP_FLAG_ACK  0x10
#define TCP_FLAG_URG  0x20
```

### UDP Header

```c
typedef struct _UDP_HEADER {
    UINT16  SourcePort;
    UINT16  DestPort;
    UINT16  Length;
    UINT16  Checksum;
    // Data follows...
} UDP_HEADER, *PUDP_HEADER;
```

### IPv4 Header

```c
typedef struct _IPV4_HEADER {
    UINT8   VersionAndHeaderLength;  // Version (4 bits) + IHL (4 bits)
    UINT8   TypeOfService;
    UINT16  TotalLength;
    UINT16  Identification;
    UINT16  FlagsAndFragmentOffset;
    UINT8   TimeToLive;
    UINT8   Protocol;
    UINT16  HeaderChecksum;
    UINT32  SourceAddress;
    UINT32  DestAddress;
    // Options and data follow...
} IPV4_HEADER, *PIPV4_HEADER;

#define IPV4_PROTOCOL_ICMP   1
#define IPV4_PROTOCOL_TCP    6
#define IPV4_PROTOCOL_UDP    17
#define IPV4_PROTOCOL_ICMPV6 58
```

---

## ⚙️ Configuration Structures

### Master Configuration (safeops.toml)

```toml
[system]
version = "2.0.0"
node_id = "safeops-node-01"
environment = "production"  # production, staging, development
log_level = "info"          # trace, debug, info, warn, error
config_validation = true

[kernel_driver]
enabled = true
driver_path = "C:\\Windows\\System32\\drivers\\safeops.sys"
ring_buffer_size_mb = 16
max_packet_rate = 1000000  # packets/sec
enable_deep_inspection = true

[firewall]
default_policy = "BLOCK"   # BLOCK, ALLOW
enable_stateful_tracking = true
connection_timeout_seconds = 3600
max_connections = 1000000
enable_nat = true
enable_ddos_protection = true

[threat_intelligence]
enabled = true
database_host = "localhost"
database_port = 5432
database_name = "safeops_threat_intel"
cache_enabled = true
cache_ttl_seconds = 300
update_interval_minutes = 60

[ids_ips]
enabled = true
detection_mode = "inline"  # inline, passive
signature_updates = true
anomaly_detection = true
alert_threshold = "medium"  # low, medium, high, critical

[logging]
output_directory = "C:\\ProgramData\\SafeOps\\logs"
rotation_interval = "5min"
max_file_size_mb = 100
retention_days = 30
compression = true
format = "json"

[metrics]
enabled = true
prometheus_port = 9090
update_interval_seconds = 10
```

---

### Firewall Rule Configuration

```yaml
# config/examples/custom_firewall_rules.yaml

rules:
  - id: 1001
    name: "Block Known C2 Servers"
    enabled: true
    priority: 10
    action: BLOCK
    direction: OUTBOUND
    source:
      any: true
    destination:
      threat_intel: true
      min_threat_score: 75
    log: true
    
  - id: 1002
    name: "Allow HTTPS Outbound"
    enabled: true
    priority: 100
    action: ALLOW
    direction: OUTBOUND
    protocol: TCP
    destination:
      ports: [443]
    rate_limit:
      connections_per_minute: 1000
    
  - id: 1003
    name: "Block SSH Brute Force"
    enabled: true
    priority: 20
    action: BLOCK
    direction: INBOUND
    protocol: TCP
    destination:
      ports: [22]
    rate_limit:
      connections_per_minute: 5
      block_duration_minutes: 60
```

---

## 📡 gRPC Message Structures

### Network Manager Service

```protobuf
// proto/network_manager.proto

message FirewallRule {
    uint32 rule_id = 1;
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
    
    message AddressMatch {
        string ip = 1;
        uint32 prefix_length = 2;
        uint32 port_start = 3;
        uint32 port_end = 4;
    }
    AddressMatch source = 8;
    AddressMatch destination = 9;
    
    enum Protocol {
        PROTOCOL_ANY = 0;
        PROTOCOL_TCP = 6;
        PROTOCOL_UDP = 17;
        PROTOCOL_ICMP = 1;
    }
    Protocol protocol = 10;
    
    bool log_matches = 11;
    uint64 hit_count = 12;
    
    google.protobuf.Timestamp created_at = 13;
    google.protobuf.Timestamp updated_at = 14;
}

message ConnectionInfo {
    uint64 flow_id = 1;
    string local_ip = 2;
    uint32 local_port = 3;
    string remote_ip = 4;
    uint32 remote_port = 5;
    
    enum Protocol {
        TCP = 0;
        UDP = 1;
        ICMP = 2;
    }
    Protocol protocol = 6;
    
    enum State {
        SYN_SENT = 0;
        ESTABLISHED = 1;
        FIN_WAIT = 2;
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

message ThreatIndicator {
    enum IndicatorType {
        IP_ADDRESS = 0;
        DOMAIN = 1;
        URL = 2;
        HASH = 3;
        EMAIL = 4;
    }
    IndicatorType type = 1;
    string value = 2;
    
    enum Severity {
        INFO = 0;
        LOW = 1;
        MEDIUM = 2;
        HIGH = 3;
        CRITICAL = 4;
    }
    Severity severity = 3;
    
    int32 reputation_score = 4;  // -100 to 100
    float confidence = 5;         // 0.0 to 1.0
    
    repeated string tags = 6;
    string description = 7;
    
    google.protobuf.Timestamp first_seen = 8;
    google.protobuf.Timestamp last_seen = 9;
}
```

---

## 🚀 Performance Structures

### Performance Metrics

```c
typedef struct _PERFORMANCE_STATS {
    // Packet Processing
    alignas(64) UINT64 TotalPacketsProcessed;
    alignas(64) UINT64 PacketsAllowed;
    alignas(64) UINT64 PacketsBlocked;
    alignas(64) UINT64 PacketsInspected;
    
    // Throughput (updated every second)
    alignas(64) UINT32 CurrentPacketsPerSecond;
    alignas(64) UINT64 CurrentBytesPerSecond;
    alignas(64) UINT32 PeakPacketsPerSecond;
    alignas(64) UINT64 PeakBytesPerSecond;
    
    // Latency (microseconds)
    UINT32 AvgProcessingLatency;
    UINT32 MinProcessingLatency;
    UINT32 MaxProcessingLatency;
    UINT32 P50ProcessingLatency;  // Median
    UINT32 P95ProcessingLatency;
    UINT32 P99ProcessingLatency;
    
    // Connection Tracking
    UINT32 ActiveConnections;
    UINT32 PeakConnections;
    UINT64 TotalConnectionsCreated;
    UINT64 TotalConnectionsClosed;
    
    // Resource Usage
    UINT32 CpuUsagePercent;
    UINT64 MemoryUsageBytes;
    UINT32 RingBufferUsagePercent;
    UINT64 RingBufferDrops;
    
    // Error Counters
    UINT64 AllocationFailures;
    UINT64 LockContentions;
    UINT64 BufferOverruns;
    
} PERFORMANCE_STATS, *PPERFORMANCE_STATS;
```

---

## 📊 Quick Reference Tables

### Data Type Sizes

| Type | Size | Range |
|------|------|-------|
| UINT8 | 1 byte | 0 to 255 |
| UINT16 | 2 bytes | 0 to 65,535 |
| UINT32 | 4 bytes | 0 to 4,294,967,295 |
| UINT64 | 8 bytes | 0 to 18,446,744,073,709,551,615 |
| INET (PostgreSQL) | 7-19 bytes | IPv4/IPv6 addresses |
| CIDR (PostgreSQL) | 7-19 bytes | Network prefixes |

### Port Number Ranges

| Range | Purpose |
|-------|---------|
| 0-1023 | Well-known ports (HTTP:80, HTTPS:443, SSH:22) |
| 1024-49151 | Registered ports (application services) |
| 49152-65535 | Dynamic/ephemeral ports |

---

## 📝 Notes

- All timestamps use UTC timezone
- Network byte order (big-endian) for IP/port fields in wire protocols
- Database uses host byte order (little-endian on x86)
- All strings are UTF-8 unless specified as WCHAR (UTF-16)
- Atomic operations required for lock-free structures
- Cache-line alignment (64 bytes) prevents false sharing

---

**Document Version:** 2.0.0  
**Last Updated:** 2025-12-17  
**Maintainer:** SafeOps Development Team
