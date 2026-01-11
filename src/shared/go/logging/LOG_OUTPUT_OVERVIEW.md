# SafeOps Logging Package - Output Overview

## 📊 Log Output Examples

### 1. JSON Format (Production - Machine Readable)

**Use Case:** Production deployments, log aggregation (ELK, Splunk, Datadog)

**Basic Log:**
```json
{"timestamp":"2025-12-19T16:18:03.123456789+05:30","level":"info","message":"Service started successfully"}
```

**With Fields:**
```json
{"timestamp":"2025-12-19T16:18:03.234567890+05:30","level":"info","message":"User login successful","ip_address":"192.168.1.100","request_id":"req-abc-456","user_id":"user123"}
```

**With Error:**
```json
{"timestamp":"2025-12-19T16:18:03.345678901+05:30","level":"error","message":"Database operation failed","error":"database connection timeout"}
```

**With Context (Request Tracing):**
```json
{"timestamp":"2025-12-19T16:18:03.456789012+05:30","level":"info","message":"Admin action performed","request_id":"req-xyz-789","user_id":"admin"}
```

**Complex Service Log:**
```json
{"timestamp":"2025-12-19T16:18:03.567890123+05:30","level":"info","message":"DNS query processed","cache_hit":true,"query":"example.com","response_time_ms":45,"service":"dns-server"}
```

---

### 2. Text Format (Development - Human Readable)

**Use Case:** Local development, console debugging, grep-friendly logs

**Different Log Levels (with colors in terminal):**
```
[2025-12-19 16:18:03] [DEBUG] Debugging information
[2025-12-19 16:18:03] [INFO] Service started successfully
[2025-12-19 16:18:03] [WARN] This is a warning
[2025-12-19 16:18:03] [ERROR] An error occurred
```

**With Fields:**
```
[2025-12-19 16:18:03] [INFO] User login successful ip_address=192.168.1.100 request_id=req-abc-456 user_id=user123
```

**With Error:**
```
[2025-12-19 16:18:03] [ERROR] Database operation failed error="database connection timeout"
```

**With Context:**
```
[2025-12-19 16:18:03] [INFO] Admin action performed request_id=req-xyz-789 user_id=admin
```

**Service Log:**
```
[2025-12-19 16:18:03] [INFO] DNS query processed cache_hit=true query=example.com response_time_ms=45 service=dns-server
```

---

### 3. Color Coding (Terminal Output)

**Colors automatically applied when output is a terminal:**

- 🔵 **DEBUG** - Cyan
- 🟢 **INFO** - Green  
- 🟡 **WARN** - Yellow
- 🔴 **ERROR** - Red
- 🔴 **FATAL/PANIC** - Red Bold

**Disabled automatically when:**
- Output is redirected to file
- `NO_COLOR` environment variable set
- Not a TTY (pipe, log file)

---

### 4. Service Logs with Permanent Fields

**Every log includes service context:**
```json
{"timestamp":"2025-12-19T16:18:03.678901234+05:30","level":"info","message":"Service initialized","environment":"production","host":"safeops-01","service":"dns-server","version":"2.0.0"}
```

```json
{"timestamp":"2025-12-19T16:18:03.789012345+05:30","level":"info","message":"Health check","environment":"production","host":"safeops-01","service":"dns-server","uptime_seconds":3600,"version":"2.0.0"}
```

---

### 5. Real-World Service Examples

#### DNS Server Logs

**JSON:**
```json
{"timestamp":"2025-12-19T16:18:03.890123456+05:30","level":"info","message":"DNS query received","cache_hit":false,"client_ip":"192.168.1.50","query_type":"A","query":"example.com","service":"dns-server"}
{"timestamp":"2025-12-19T16:18:03.901234567+05:30","level":"debug","message":"Cache lookup","cache_key":"A:example.com","found":false}
{"timestamp":"2025-12-19T16:18:03.912345678+05:30","level":"info","message":"Upstream query","resolver":"8.8.8.8","timeout_ms":5000}
{"timestamp":"2025-12-19T16:18:04.023456789+05:30","level":"info","message":"DNS response sent","response_code":"NOERROR","response_time_ms":131,"ttl":300}
```

**Text:**
```
[2025-12-19 16:18:03] [INFO] DNS query received cache_hit=false client_ip=192.168.1.50 query=example.com query_type=A service=dns-server
[2025-12-19 16:18:03] [DEBUG] Cache lookup cache_key=A:example.com found=false
[2025-12-19 16:18:03] [INFO] Upstream query resolver=8.8.8.8 timeout_ms=5000
[2025-12-19 16:18:04] [INFO] DNS response sent response_code=NOERROR response_time_ms=131 ttl=300
```

#### DHCP Server Logs

**JSON:**
```json
{"timestamp":"2025-12-19T16:18:05.123456789+05:30","level":"info","message":"DHCP DISCOVER received","client_mac":"AA:BB:CC:DD:EE:FF","service":"dhcp-server"}
{"timestamp":"2025-12-19T16:18:05.234567890+05:30","level":"info","message":"IP address assigned","assigned_ip":"192.168.1.150","client_mac":"AA:BB:CC:DD:EE:FF","lease_time_seconds":86400}
{"timestamp":"2025-12-19T16:18:05.345678901+05:30","level":"info","message":"DHCP OFFER sent","offered_ip":"192.168.1.150","transaction_id":"0x12345678"}
```

#### IDS/IPS Logs

**JSON:**
```json
{"timestamp":"2025-12-19T16:18:06.456789012+05:30","level":"warn","message":"Suspicious traffic detected","destination":"10.0.0.100:22","pattern":"ssh-brute-force","service":"ids-ips","severity":"medium","source":"203.0.113.50"}
{"timestamp":"2025-12-19T16:18:06.567890123+05:30","level":"error","message":"Threat blocked","action":"DROP","pattern":"sql-injection","rule_id":"IDS-1024","source":"203.0.113.75"}
```

**Text:**
```
[2025-12-19 16:18:06] [WARN] Suspicious traffic detected destination=10.0.0.100:22 pattern=ssh-brute-force service=ids-ips severity=medium source=203.0.113.50
[2025-12-19 16:18:06] [ERROR] Threat blocked action=DROP pattern=sql-injection rule_id=IDS-1024 source=203.0.113.75
```

---

### 6. Log Rotation - File Organization

**During normal operation:**
```
/var/log/safeops/
├── dns-server.log                          (current, 80 MB)
├── dhcp-server.log                         (current, 45 MB)
├── ids-ips.log                             (current, 120 MB)
├── orchestrator.log                        (current, 30 MB)
```

**After rotation (reaching 100 MB threshold):**
```
/var/log/safeops/
├── dns-server.log                          (new, 15 MB)
├── dns-server-2025-12-19T10-30-45.log.gz  (compressed, 12 MB - was 100 MB)
├── dns-server-2025-12-18T14-20-30.log.gz  (compressed, 14 MB)
├── dns-server-2025-12-17T09-15-20.log.gz  (compressed, 13 MB)
├── dns-server-2025-12-16T11-45-10.log.gz  (compressed, 15 MB)
├── dns-server-2025-12-15T08-30-00.log.gz  (compressed, 14 MB)
└── (older files deleted, only 5 backups kept)
```

---

## 📈 Key Features Summary

✅ **Two Output Formats:**
- JSON for machines (ELK, Splunk, Datadog)
- Text for humans (console, grep, less)

✅ **Consistent Timestamps:**
- JSON: RFC3339Nano (`2025-12-19T16:18:03.123456789+05:30`)
- Text: Human-readable (`2025-12-19 16:18:03`)

✅ **Field Ordering:**
- JSON: timestamp → level → message → alphabetically sorted fields
- Text: timestamp → level → message → field=value pairs

✅ **Context Tracing:**
- request_id, user_id, trace_id automatically extracted
- Enables distributed tracing across services

✅ **Automatic Rotation:**
- Size-based (100 MB default)
- Age-based cleanup (30 days default)
- Compression (70-90% space savings)
- Max backups limit (5 default)

✅ **Colors:**
- Auto-detected for terminals
- Disabled for files/pipes
- Respects NO_COLOR environment variable

✅ **Performance:**
- Thread-safe concurrent logging
- Atomic log rotation (no data loss)
- Minimal allocations (sync.Pool internally)

---

## 🔍 Typical Production Use

**Scenario:** DNS query with full context

```json
{
  "timestamp": "2025-12-19T16:18:03.123456789+05:30",
  "level": "info",
  "message": "DNS query processed successfully",
  "service": "dns-server",
  "version": "2.0.0",
  "environment": "production",
  "host": "safeops-node-01",
  "request_id": "req-abc-123",
  "client_ip": "192.168.1.100",
  "query": "example.com",
  "query_type": "A",
  "response_code": "NOERROR",
  "response_time_ms": 45,
  "cache_hit": true,
  "ttl": 300,
  "upstream_resolver": "8.8.8.8"
}
```

**This single log entry enables:**
- Performance monitoring (response_time_ms)
- Error tracking (response_code)
- Cache effectiveness (cache_hit)
- Request tracing (request_id)
- Client analysis (client_ip)
- Service identification (service, host, version)
- Environment tracking (environment)
