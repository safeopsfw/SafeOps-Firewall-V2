# Suricata IDS/IPS Rule Format Schema

## Overview
Suricata (and Snort) use a text-based rule format, not JSON. This document describes the schema and format for creating IDS/IPS rules.

## File Format
- **Extension**: `.rules`
- **Encoding**: UTF-8
- **Line Format**: One rule per line
- **Comments**: Lines starting with `#`

## Rule Structure

### Basic Syntax
```
action protocol src_ip src_port direction dst_ip dst_port (options)
```

### Example
```
alert tcp any any -> 192.168.1.0/24 80 (msg:"Test Rule"; sid:1000001; rev:1;)
```

## Components

### 1. Action
The action determines what happens when a rule matches.

| Action | Description | Use Case |
|--------|-------------|----------|
| `alert` | Generate alert, log packet | IDS mode - detect only |
| `drop` | Drop packet, generate alert | IPS mode - block threat |
| `reject` | Send RST/ICMP unreachable, drop | Active rejection |
| `pass` | Ignore packet, no alert | Whitelist traffic |

### 2. Protocol
Supported protocols:

| Protocol | Description |
|----------|-------------|
| `tcp` | TCP traffic |
| `udp` | UDP traffic |
| `icmp` | ICMP traffic |
| `ip` | IP traffic (any protocol) |
| `http` | HTTP traffic (requires http parser) |
| `dns` | DNS traffic |
| `tls` | TLS/SSL traffic |
| `ssh` | SSH traffic |
| `smb` | SMB/CIFS traffic |
| `ftp` | FTP traffic |

### 3. Source/Destination
```
IP_ADDRESS PORT
```

**IP Address Formats**:
- `any` - Any IP address
- `192.168.1.1` - Single IP
- `192.168.1.0/24` - CIDR notation
- `[192.168.1.1,192.168.1.2]` - List
- `!192.168.1.0/24` - Negation (NOT)
- `$HOME_NET` - Variable reference

**Port Formats**:
- `any` - Any port
- `80` - Single port
- `80:443` - Port range
- `[80,443,8080]` - Port list
- `!22` - Negation
- `$HTTP_PORTS` - Variable reference

### 4. Direction
- `->` - From source to destination
- `<>` - Bidirectional (both directions)

## Rule Options

### Required Options

#### msg (Message)
Alert description shown in logs.
```
msg:"ET WEB SQL Injection Attempt";
```

#### sid (Signature ID)
Unique identifier for the rule.
- **Range**: 1000000-99999999 (custom rules)
- **Format**: Integer
```
sid:1000001;
```

#### rev (Revision)
Version number of the rule.
```
rev:1;
```

### Content Matching

#### content
Match exact bytes in payload.
```
content:"GET";
content:"|0d 0a|";  # Hex notation
content:!"admin";    # Negated match
```

**Modifiers**:
- `nocase` - Case-insensitive matching
- `offset:N` - Start matching at byte N
- `depth:N` - Match within first N bytes
- `distance:N` - Distance from previous match
- `within:N` - Within N bytes of previous match
- `startswith` - Content must be at start
- `endswith` - Content must be at end

Example:
```
content:"UNION"; nocase; content:"SELECT"; distance:0; within:20;
```

#### pcre (Regex)
Perl-compatible regular expression.
```
pcre:"/^User-Agent:.*(bot|crawler)/i";
```

Modifiers: `/i` (case insensitive), `/s` (dot matches newline)

### HTTP Keywords

When using `protocol: http`:

```
http_method;           # Match in HTTP method (GET, POST, etc.)
http_uri;              # Match in URI
http_user_agent;       # Match in User-Agent header
http_host;             # Match in Host header
http_header;           # Match in any header
http_cookie;           # Match in Cookie header
http_request_body;     # Match in POST data
http_response_body;    # Match in response body
http_stat_code;        # Match HTTP status code
```

Example:
```
alert http any any -> any any (msg:"SQL Injection in URI"; 
  content:"UNION"; nocase; http_uri; 
  content:"SELECT"; nocase; http_uri; 
  sid:1000001;)
```

### DNS Keywords

```
dns_query;        # Match DNS query name
dns.answer;       # Match DNS answer
```

Example:
```
alert dns any any -> any 53 (msg:"Malicious Domain Query"; 
  dns_query; content:"evil.com"; nocase; 
  sid:1000002;)
```

### TLS/SSL Keywords

```
tls.sni;           # Server Name Indication
tls.cert_subject;  # Certificate subject
tls.cert_issuer;   # Certificate issuer
tls.version;       # TLS version (1.0, 1.1, 1.2, 1.3)
```

Example:
```
alert tls any any -> any 443 (msg:"Old TLS Version"; 
  tls.version:1.0; 
  sid:1000003;)
```

### Flow Keywords

```
flow:established;            # Established connection
flow:to_server;              # Traffic to server
flow:to_client;              # Traffic to client
flow:stateless;              # No state tracking
flow:only_stream;            # Only reassembled stream
```

Example:
```
alert tcp any any -> any any (msg:"Test"; 
  flow:established,to_server; 
  sid:1000004;)
```

### Threshold/Rate Limiting

```
threshold:type threshold, track by_src, count 5, seconds 60;
```

**Types**:
- `threshold` - Alert once after N matches
- `limit` - Alert every N matches
- `both` - Combination

**Track by**:
- `by_src` - Track by source IP
- `by_dst` - Track by destination IP
- `by_both` - Track by both
- `by_rule` - Track globally for rule

Example:
```
alert tcp any any -> any 22 (msg:"SSH Brute Force"; 
  threshold:type threshold, track by_src, count 5, seconds 60; 
  sid:1000005;)
```

### TCP Flags

```
flags:S;      # SYN flag
flags:SA;     # SYN+ACK flags
flags:!A;     # NOT ACK flag
```

Common flags: `S` (SYN), `A` (ACK), `F` (FIN), `R` (RST), `P` (PSH), `U` (URG)

### File Keywords

```
fileext;              # File extension
filemagic;            # File magic (MIME type)
filename;             # Filename
filestore;            # Store matched file
```

Example:
```
alert http any any -> any any (msg:"Malicious File Download"; 
  fileext:"exe"; 
  filemagic:"PE32 executable"; 
  filestore; 
  sid:1000006;)
```

### Classification

```
classtype:<type>;
```

Common types:
- `web-application-attack`
- `trojan-activity`
- `attempted-admin`
- `attempted-recon`
- `policy-violation`
- `bad-unknown`

### References

```
reference:url,example.com;
reference:cve,2021-12345;
reference:bugtraq,12345;
```

### Metadata

MITRE ATT&CK tags:
```
metadata:mitre_tactic_id TA0001, mitre_technique_id T1190;
```

Custom tags:
```
metadata:attack_target Server, tag SQLi, signature_severity Major;
```

## Complete Example

```suricata
alert http $EXTERNAL_NET any -> $HOME_NET any (
  msg:"ET WEB SQL Injection UNION SELECT"; 
  flow:established,to_server; 
  content:"UNION"; nocase; http_uri;
  content:"SELECT"; nocase; distance:0; within:20; http_uri;
  classtype:web-application-attack; 
  sid:1000001; 
  rev:1; 
  reference:url,owasp.org/sql-injection;
  metadata:attack_target Server, 
           signature_severity Major, 
           tag SQLi, 
           mitre_tactic_id TA0001, 
           mitre_technique_id T1190;
)
```

## Variable Definitions

Define in `suricata.yaml` or separate `vars.yaml`:

```yaml
vars:
  address-groups:
    HOME_NET: "[192.168.0.0/16]"
    EXTERNAL_NET: "!$HOME_NET"
    HTTP_SERVERS: "$HOME_NET"
    SMTP_SERVERS: "$HOME_NET"
    DNS_SERVERS: "$HOME_NET"
  
  port-groups:
    HTTP_PORTS: "80,443,8080"
    SHELLCODE_PORTS: "!80"
```

## Best Practices

### 1. SID Numbering
- 1-999,999: Reserved
- 1,000,000-1,999,999: Local custom rules
- 2,000,000+: Community rules

### 2. Performance
- Use `fast_pattern` for most specific content
- Limit expensive operations (pcre, deep inspection)
- Use flow direction when possible
- Order content matches from most to least specific

Example:
```
content:"specific_string"; fast_pattern;
content:"less_specific";
```

### 3. Tuning
- Use thresholds to prevent alert floods
- Test rules in `alert` mode before `drop`
- Use metadata for rule management
- Include references for context

### 4. Maintenance
- Increment `rev` when modifying rules
- Document changes in comments
- Group related rules together
- Use consistent naming conventions

## File Organization

```
/etc/suricata/rules/
├── local.rules              # Custom local rules
├── emerging-threats.rules   # ET ruleset
├── malware.rules           # Malware detection
├── web-attacks.rules       # Web application attacks
├── policy.rules            # Policy violations
└── disabled.rules          # Disabled rules
```

## Integration with SafeOps

Rules will be loaded from:
```
config/ids_ips/rules/
├── custom/
│   ├── web-attacks.rules
│   ├── malware.rules
│   └── policy.rules
├── community/
│   └── emerging-threats.rules
└── disabled/
    └── old-rules.rules
```

## Validation

Use Suricata's test mode:
```bash
suricata -T -c /etc/suricata/suricata.yaml
```

## References

- **Suricata Documentation**: https://suricata.readthedocs.io/en/latest/rules/
- **Emerging Threats**: https://rules.emergingthreats.net/
- **MITRE ATT&CK**: https://attack.mitre.org/
