# DNS Proxy - Component Documentation

## Overview
The DNS Proxy is a high-performance DNS forwarding and filtering service built on AdGuard's dnsproxy. It provides DNS caching, upstream forwarding (DNS-over-HTTPS, DNS-over-TLS), domain filtering, local DNS server functionality, and integration with threat intelligence feeds for malicious domain blocking.

## Component Information

**Component Type:** DNS Resolver & Filter
**Language:** Go (AdGuard dnsproxy)
**Architecture:** Multi-protocol DNS proxy with caching and filtering
**Platform:** Cross-platform (Windows, Linux, macOS)

## Files and Locations

### Binary/Executable
```
D:\SafeOpsFV2\bin\dnsproxy\windows-amd64\
├── dnsproxy.exe                    # AdGuard DNS proxy binary
├── LICENSE                         # MIT License
└── README.md                       # AdGuard documentation
```

### Configuration Files
```
D:\SafeOpsFV2\src\safeops-engine\configs\
└── dnsproxy.yaml                   # DNS proxy configuration
```

### Source Repository
- **Upstream:** https://github.com/AdguardTeam/dnsproxy
- **License:** MIT License
- **Version:** Latest stable (pre-compiled)

## Functionality

### Core Functions

#### 1. DNS Resolution
- **Local DNS Server** - Listens on configurable port (15353 default)
- **Upstream Forwarding** - Forwards queries to upstream resolvers
- **Protocol Support** - DNS (UDP/TCP), DNS-over-HTTPS (DoH), DNS-over-TLS (DoT), DNSCrypt
- **Parallel Queries** - Sends to multiple upstreams simultaneously
- **Fastest Response** - Returns first successful response
- **Fallback Upstreams** - Tries alternate resolvers on failure

#### 2. DNS Caching
- **Response Caching** - Caches DNS responses for TTL duration
- **Cache Size** - Configurable memory cache
- **TTL Respect** - Honors DNS TTL from authoritative servers
- **Negative Caching** - Caches NXDOMAIN responses
- **Cache Eviction** - LRU eviction when cache full

#### 3. Domain Filtering
- **Blocklist Support** - AdGuard filter syntax (hosts, domains, wildcards)
- **Whitelist Support** - Exception rules for blocked domains
- **Regex Support** - Regular expression patterns
- **Response Rewrite** - NXDOMAIN or custom IP response for blocked domains
- **Threat Intel Integration** - Blocks domains from threat feeds
- **Custom Rules** - User-defined block/allow lists

#### 4. Upstream Resolver Support
**DNS (UDP/TCP):**
- Standard DNS queries to public resolvers
- Examples: 8.8.8.8, 1.1.1.1, 208.67.222.222

**DNS-over-HTTPS (DoH):**
- Encrypted DNS over HTTPS protocol
- Examples: https://dns.google/dns-query, https://cloudflare-dns.com/dns-query

**DNS-over-TLS (DoT):**
- Encrypted DNS over TLS protocol
- Examples: tls://1.1.1.1, tls://dns.google

**DNSCrypt:**
- DNSCrypt v2 protocol support
- Examples: sdns://AQcAAAAAAAAADjIwOC42Ny4yMjAuMjIw

#### 5. Local DNS Records
- **Custom A/AAAA Records** - Override DNS responses
- **CNAME Records** - Domain aliases
- **PTR Records** - Reverse DNS lookups
- **Local Zone** - Serve local domain (e.g., safeops.local)

#### 6. DNS Analytics
- **Query Logging** - Logs all DNS queries (optional)
- **Query Statistics** - Total queries, cache hits, blocked queries
- **Top Domains** - Most frequently queried domains
- **Client Statistics** - Queries per client IP
- **Response Times** - Upstream resolver performance

#### 7. Security Features
- **DNSSEC Validation** - Validates DNSSEC signatures
- **Anti-CNAME Rebinding** - Prevents DNS rebinding attacks
- **Rate Limiting** - Prevents DNS amplification attacks
- **Bogus NXDomain** - Filters ISP DNS hijacking
- **Private Reverse DNS** - Blocks queries for private IPs

#### 8. Performance Optimization
- **Connection Reuse** - HTTP/2 for DoH upstreams
- **Prefetching** - Proactive cache refresh before TTL expiry
- **Parallel Upstream** - Queries multiple upstreams simultaneously
- **Edns-client-subnet** - Sends client subnet for geolocation
- **Compression** - DNS compression for smaller packets

## Default Ports

| Port | Service | Purpose | Mode |
|------|---------|---------|------|
| **15353** | DNS Server | DNS query listener (UDP/TCP) | Server |
| 25353 | Fallback | Alternate port if 15353 busy | Server |
| 35353 | Fallback | Alternate port if 25353 busy | Server |
| 45353 | Fallback | Alternate port if 35353 busy | Server |
| 53 | Standard DNS | Standard DNS port (optional) | Server |
| 443 | DoH | DNS-over-HTTPS client | Client |
| 853 | DoT | DNS-over-TLS client | Client |

### Port Configuration Notes
- **Default Port:** 15353 (changed from 5353 to avoid mDNS/Steam conflicts)
- **Fallback Ports:** Automatically tries 25353, 35353, 45353 if 15353 is in use
- **System DNS:** Can bind to port 53 with admin privileges (not recommended)

## API Endpoints

**No REST API** - DNS Proxy is a standard DNS server. Clients query using DNS protocol (UDP/TCP).

**DNS Query Format:**
- Protocol: DNS (RFC 1035)
- Query: Standard DNS query packet
- Response: Standard DNS response packet

**Example Query (dig):**
```bash
dig @127.0.0.1 -p 15353 google.com
```

**Example Query (nslookup):**
```
nslookup google.com 127.0.0.1:15353
```

## Dependencies

### Go Dependencies (dnsproxy)

**DNS Libraries:**
- github.com/miekg/dns - DNS protocol implementation
- github.com/AdguardTeam/golibs/log - Logging

**Network:**
- github.com/AdguardTeam/dnsproxy/proxy - Core proxy logic
- github.com/AdguardTeam/dnsproxy/upstream - Upstream resolver support

**Cryptography (for DoH/DoT):**
- crypto/tls - TLS support
- golang.org/x/net/http2 - HTTP/2 for DoH

**Configuration:**
- gopkg.in/yaml.v3 - YAML config parsing

### External Dependencies
- **None** - dnsproxy.exe is a standalone binary with no external dependencies

### Optional Integration
- Threat Intelligence Service (50058) - Domain reputation lookups
- PostgreSQL (5432) - Domain blacklist storage

## Component Interconnections

### Architecture
```
┌─────────────────────────────────────────────────┐
│         DNS Proxy (15353)                       │
│   (Query, Cache, Filter, Forward)               │
└─────────────────────────────────────────────────┘
    ↓           ↓          ↓          ↓
[Clients]   [Upstream]  [Threat     [Cache]
(Apps)      (DoH/DoT)   Intel]      (Memory)
    ↓           ↓          ↓
[SafeOps    [Google     [Block
Engine]      DNS]       List]
             [Cloudflare]
```

### Integration Points

**From Clients:**
1. **SafeOps Engine** - Routes DNS queries (port 53 → 15353)
2. **System Apps** - Browsers, email, games
3. **Network Devices** - IoT, phones, tablets

**To Upstream Resolvers:**
- Google DNS (8.8.8.8, https://dns.google/dns-query)
- Cloudflare DNS (1.1.1.1, https://cloudflare-dns.com/dns-query)
- Quad9 DNS (9.9.9.9, https://dns.quad9.net/dns-query)
- OpenDNS (208.67.222.222)

**To Other Components:**
- Threat Intelligence (50058) - Domain reputation checks
- SafeOps Engine (9002) - Domain filtering decisions
- SIEM - DNS query logs (optional)

### Query Flow
```
Application → System DNS → SafeOps Engine → DNS Proxy (15353)
                                              ↓
                                         [Check Cache]
                                              ↓
                                         [Check Blocklist]
                                              ↓
                                         [Forward to Upstream]
                                              ↓
                                         [Return Response]
                                              ↓
                                         [Update Cache]
                                              ↓
                               Application ← SafeOps Engine
```

## Database Schema

**No database** - DNS Proxy is a stateless service. Blocklists are loaded from files. Optionally integrates with Threat Intel database for domain reputation.

## Configuration

### Example Configuration (dnsproxy.yaml)

```yaml
# Listen Configuration
listen:
  - 127.0.0.1:15353        # Local DNS server
  - 0.0.0.0:15353          # All interfaces

# Upstream Resolvers
upstream:
  # DNS-over-HTTPS (encrypted)
  - https://dns.google/dns-query
  - https://cloudflare-dns.com/dns-query

  # Standard DNS (fallback)
  - 8.8.8.8
  - 1.1.1.1

# Bootstrap DNS (for DoH hostname resolution)
bootstrap:
  - 8.8.8.8
  - 1.1.1.1

# Fallback DNS (if all upstreams fail)
fallback:
  - 208.67.222.222         # OpenDNS

# Caching
cache:
  enabled: true
  size: 4096               # Cache size (number of entries)
  min-ttl: 60              # Minimum TTL (seconds)
  max-ttl: 3600            # Maximum TTL (seconds)

# Filtering
filtering:
  enabled: true
  blocklist-file: "D:/SafeOpsFV2/config/blocklist.txt"
  whitelist-file: "D:/SafeOpsFV2/config/whitelist.txt"

# Security
security:
  dnssec: true             # Enable DNSSEC validation
  refuse-any: true         # Block ANY queries (anti-amplification)
  edns-client-subnet: false  # Disable ECS for privacy

# Logging
logging:
  enabled: false           # Disable query logging by default
  file: "D:/SafeOpsFV2/data/logs/dnsproxy.log"

# Performance
performance:
  fastest-addr: true       # Return fastest upstream response
  parallel-queries: true   # Query all upstreams in parallel
  max-goroutines: 300      # Max concurrent goroutines
```

### Blocklist File Format

**Hosts Format:**
```
# Comment
0.0.0.0 ads.example.com
0.0.0.0 tracker.example.com
```

**Domain Format:**
```
ads.example.com
tracker.example.com
```

**AdGuard Syntax:**
```
||ads.example.com^
||tracker.example.com^
@@||whitelist.example.com^  # Whitelist exception
```

**Regex Syntax:**
```
/.*-ads\..*/
/^ad[0-9]+\./
```

### Whitelist File Format
```
# Whitelisted domains (exceptions to blocklist)
google.com
youtube.com
@@||cdn.example.com^
```

## Important Notes

### Performance
- 1000+ queries/second per core
- <1ms cache lookup time
- <50ms upstream query time (DoH/DoT)
- HTTP/2 connection reuse for DoH
- Parallel upstream queries for speed

### Reliability
- Automatic fallback to alternate upstreams
- Graceful degradation if upstream fails
- Persistent cache across restarts (optional)
- Health checks for upstream resolvers

### Security
- **DNSSEC Validation** - Ensures DNS integrity
- **DoH/DoT Encryption** - Prevents ISP snooping
- **Anti-Rebinding** - Prevents DNS rebinding attacks
- **Rate Limiting** - Prevents amplification attacks
- **Bogus NXDomain** - Filters ISP hijacking

### Privacy
- **No Logging** - Query logging disabled by default
- **No ECS** - Edns-client-subnet disabled for privacy
- **Encrypted DNS** - DoH/DoT hides queries from ISP
- **No 3rd-party** - Self-hosted resolver

### Capacity
- Unlimited query rate (CPU bound)
- 4096 cache entries (configurable)
- 100+ MB/s throughput
- <10 MB memory footprint

### Limitations
- **Not a DNS Server** - Cannot host authoritative zones (use dnsmasq/BIND)
- **No Dynamic DNS** - Cannot update DNS records dynamically
- **No DHCP** - DNS only, no DHCP server
- **No DNS Firewall** - Use threat intel integration for blocking

## Connection to Other Components

| Component | Connection Type | Purpose |
|-----------|----------------|---------|
| SafeOps Engine | DNS Client | Routes DNS queries (port 53 → 15353) |
| System Apps | DNS Client | Direct DNS queries from applications |
| Threat Intelligence | gRPC Client | Domain reputation lookups |
| Google DNS | DNS Client | Upstream DNS resolution |
| Cloudflare DNS | DoH Client | Encrypted DNS resolution |
| SIEM | Log Consumer | DNS query analytics (optional) |

---

**Status:** Production Ready
**Auto-Start:** Via SafeOps Launcher (optional)
**Dependencies:** None (standalone binary)
**Managed By:** SafeOps Engine (process spawn)
**Version:** Latest (AdGuard dnsproxy)
**License:** MIT License
**Upstream Repository:** https://github.com/AdguardTeam/dnsproxy
**Privileges Required:** Administrator (for port 53 binding)
