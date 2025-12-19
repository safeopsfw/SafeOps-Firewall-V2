# SafeOps - Master JSON Log Examples

## 🌐 Network Packet Log (Complete Example)

### Full Packet Inspection Log
```json
{
  "timestamp": "2025-12-19T16:22:30.123456789+05:30",
  "level": "info",
  "message": "Packet processed",
  
  "service": "firewall",
  "version": "2.0.0",
  "environment": "production",
  "host": "safeops-fw-01",
  "request_id": "pkt-7f3e9a2b-4c1d-8e5f-a6b7-c8d9e0f1a2b3",
  
  "packet": {
    "direction": "inbound",
    "interface": "eth0",
    "size_bytes": 1500,
    "truncated": false,
    
    "ethernet": {
      "src_mac": "00:11:22:33:44:55",
      "dst_mac": "AA:BB:CC:DD:EE:FF",
      "ethertype": "0x0800"
    },
    
    "ip": {
      "version": 4,
      "header_length": 20,
      "tos": 0,
      "total_length": 1480,
      "id": 54321,
      "flags": "DF",
      "fragment_offset": 0,
      "ttl": 64,
      "protocol": "TCP",
      "checksum": "0x1a2b",
      "src_ip": "203.0.113.50",
      "dst_ip": "192.168.1.100",
      "src_country": "US",
      "dst_country": "IN",
      "src_asn": 15169,
      "src_org": "Google LLC"
    },
    
    "tcp": {
      "src_port": 443,
      "dst_port": 52341,
      "seq": 1234567890,
      "ack": 987654321,
      "data_offset": 5,
      "flags": {
        "syn": false,
        "ack": true,
        "fin": false,
        "rst": false,
        "psh": true,
        "urg": false
      },
      "window_size": 65535,
      "checksum": "0x3c4d",
      "urgent_pointer": 0
    },
    
    "payload": {
      "length": 1420,
      "encrypted": true,
      "protocol": "TLS",
      "tls_version": "1.3",
      "cipher_suite": "TLS_AES_256_GCM_SHA384",
      "sni": "api.example.com"
    }
  },
  
  "firewall": {
    "action": "ACCEPT",
    "rule_id": "FW-2048",
    "rule_name": "allow-https-outbound",
    "chain": "FORWARD",
    "connection_state": "ESTABLISHED",
    "nat_applied": false
  },
  
  "ids_ips": {
    "scanned": true,
    "threats_detected": 0,
    "rules_matched": [],
    "signature_version": "2025.12.19.001",
    "scan_time_us": 234
  },
  
  "session": {
    "session_id": "sess-a1b2c3d4e5f6",
    "established_at": "2025-12-19T16:20:15.000000000+05:30",
    "duration_seconds": 135,
    "packets_sent": 42,
    "packets_received": 38,
    "bytes_sent": 28416,
    "bytes_received": 52340
  },
  
  "geolocation": {
    "src_latitude": 37.4219999,
    "src_longitude": -122.0840575,
    "src_city": "Mountain View",
    "src_region": "California",
    "dst_latitude": 19.0759837,
    "dst_longitude": 72.8776559,
    "dst_city": "Mumbai",
    "dst_region": "Maharashtra"
  },
  
  "performance": {
    "processing_time_us": 456,
    "queue_wait_time_us": 23,
    "kernel_to_userspace_us": 12,
    "total_latency_us": 491
  },
  
  "metadata": {
    "captured_at_monotonic_ns": 123456789012345,
    "cpu_core": 3,
    "worker_thread_id": 7
  }
}
```

---

## 🔒 IDS/IPS Threat Detection Log

### Malicious Packet Blocked
```json
{
  "timestamp": "2025-12-19T16:22:31.234567890+05:30",
  "level": "error",
  "message": "SQL injection attack blocked",
  
  "service": "ids-ips",
  "version": "2.0.0",
  "environment": "production",
  "host": "safeops-ids-01",
  "request_id": "threat-9f8e7d6c-5b4a-3210-fedc-ba9876543210",
  
  "threat": {
    "type": "sql-injection",
    "severity": "critical",
    "confidence": 0.98,
    "cve_id": "CVE-2024-12345",
    "mitre_attack_id": "T1190",
    "signature_id": "IDS-3072",
    "signature_name": "SQL Injection - UNION SELECT",
    "payload_hash": "sha256:a1b2c3d4e5f6...",
    "malicious_pattern": "' UNION SELECT * FROM users--"
  },
  
  "packet": {
    "src_ip": "203.0.113.25",
    "dst_ip": "192.168.1.50",
    "src_port": 54321,
    "dst_port": 80,
    "protocol": "TCP",
    "size_bytes": 842,
    "direction": "inbound"
  },
  
  "http": {
    "method": "GET",
    "uri": "/admin/users.php?id=1'+UNION+SELECT+*+FROM+users--",
    "host": "internal.example.com",
    "user_agent": "sqlmap/1.7.2",
    "referer": null,
    "headers": {
      "X-Forwarded-For": "10.0.0.5, 203.0.113.25",
      "Accept": "*/*"
    }
  },
  
  "action": {
    "taken": "DROP",
    "blocked": true,
    "alert_sent": true,
    "quarantine": true,
    "blacklist_added": true,
    "blacklist_duration_seconds": 3600
  },
  
  "attacker": {
    "ip": "203.0.113.25",
    "country": "CN",
    "city": "Shanghai",
    "asn": 4134,
    "org": "Chinanet",
    "reputation_score": 12,
    "known_bad_actor": true,
    "previous_attacks": 47,
    "first_seen": "2025-12-15T08:30:00+05:30",
    "last_seen": "2025-12-19T16:22:31+05:30"
  },
  
  "response": {
    "http_status": 403,
    "response_sent": "Access Forbidden",
    "connection_closed": true
  }
}
```

---

## 📡 DNS Query Log (Complete)

```json
{
  "timestamp": "2025-12-19T16:22:32.345678901+05:30",
  "level": "info",
  "message": "DNS query resolved",
  
  "service": "dns-server",
  "version": "2.0.0",
  "environment": "production",
  "host": "safeops-dns-01",
  "request_id": "dns-a1b2c3d4-e5f6-7890-abcd-ef1234567890",
  
  "query": {
    "domain": "api.example.com",
    "type": "A",
    "class": "IN",
    "recursion_desired": true,
    "dnssec_ok": true,
    "transaction_id": "0x1a2b"
  },
  
  "client": {
    "ip": "192.168.1.100",
    "port": 53241,
    "mac": "AA:BB:CC:DD:EE:FF",
    "hostname": "laptop-01",
    "user": "john.doe",
    "protocol": "UDP"
  },
  
  "resolution": {
    "cache_hit": false,
    "cache_key": "A:api.example.com",
    "upstream_resolver": "8.8.8.8",
    "upstream_port": 53,
    "recursive": true,
    "query_count": 1
  },
  
  "response": {
    "code": "NOERROR",
    "authoritative": false,
    "truncated": false,
    "recursion_available": true,
    "answers": [
      {
        "name": "api.example.com",
        "type": "A",
        "class": "IN",
        "ttl": 300,
        "data": "93.184.216.34"
      }
    ],
    "answer_count": 1,
    "authority_count": 0,
    "additional_count": 0
  },
  
  "filter": {
    "blacklist_checked": true,
    "blacklisted": false,
    "category": "business",
    "safe_search_enforced": false,
    "parental_control_applied": false
  },
  
  "performance": {
    "cache_lookup_us": 12,
    "upstream_query_ms": 23,
    "total_time_ms": 24,
    "response_size_bytes": 64
  },
  
  "dnssec": {
    "validated": true,
    "signature_valid": true,
    "chain_of_trust": "secure"
  }
}
```

---

## 🌐 DHCP Lease Assignment Log

```json
{
  "timestamp": "2025-12-19T16:22:33.456789012+05:30",
  "level": "info",
  "message": "DHCP lease assigned",
  
  "service": "dhcp-server",
  "version": "2.0.0",
  "environment": "production",
  "host": "safeops-dhcp-01",
  "request_id": "dhcp-1234abcd-5678-ef90-1234-567890abcdef",
  
  "client": {
    "mac": "00:11:22:33:44:55",
    "hostname": "iphone-123",
    "vendor": "Apple, Inc.",
    "device_type": "mobile",
    "fingerprint": "1,3,6,15,119,252"
  },
  
  "transaction": {
    "type": "DHCPACK",
    "xid": "0x12345678",
    "broadcast": false,
    "relay_agent": null
  },
  
  "lease": {
    "ip": "192.168.1.150",
    "subnet": "192.168.1.0/24",
    "lease_time_seconds": 86400,
    "renewal_time_seconds": 43200,
    "rebinding_time_seconds": 75600,
    "expires_at": "2025-12-20T16:22:33+05:30"
  },
  
  "network_config": {
    "subnet_mask": "255.255.255.0",
    "gateway": "192.168.1.1",
    "dns_servers": ["192.168.1.2", "192.168.1.3"],
    "ntp_servers": ["192.168.1.4"],
    "domain_name": "internal.safeops.local",
    "mtu": 1500
  },
  
  "pool": {
    "name": "default-pool",
    "range_start": "192.168.1.100",
    "range_end": "192.168.1.200",
    "available_ips": 47,
    "total_ips": 101,
    "utilization_percent": 53.5
  },
  
  "history": {
    "previous_ip": "192.168.1.145",
    "lease_count": 5,
    "first_seen": "2025-12-15T10:30:00+05:30",
    "last_seen": "2025-12-19T16:22:33+05:30"
  }
}
```

---

## 🔐 WiFi AP Authentication Log

```json
{
  "timestamp": "2025-12-19T16:22:34.567890123+05:30",
  "level": "info",
  "message": "Client authenticated successfully",
  
  "service": "wifi-ap",
  "version": "2.0.0",
  "environment": "production",
  "host": "safeops-ap-01",
  "request_id": "wifi-auth-abcd1234-5678-90ef-abcd-1234567890ab",
  
  "client": {
    "mac": "AA:BB:CC:DD:EE:FF",
    "ip": "192.168.2.50",
    "hostname": "android-phone",
    "device_type": "smartphone",
    "manufacturer": "Samsung",
    "os": "Android 14"
  },
  
  "wireless": {
    "ssid": "SafeOps-Corporate",
    "bssid": "00:11:22:33:44:55",
    "channel": 36,
    "frequency_mhz": 5180,
    "band": "5GHz",
    "mode": "802.11ac",
    "encryption": "WPA3-Enterprise"
  },
  
  "authentication": {
    "method": "802.1X",
    "eap_type": "EAP-TLS",
    "username": "john.doe@safeops.local",
    "radius_server": "192.168.1.10",
    "success": true,
    "auth_time_ms": 234
  },
  
  "signal": {
    "rssi_dbm": -45,
    "noise_dbm": -95,
    "snr_db": 50,
    "quality_percent": 95,
    "tx_rate_mbps": 867,
    "rx_rate_mbps": 867
  },
  
  "session": {
    "session_id": "wifi-sess-12345",
    "connected_at": "2025-12-19T16:22:34+05:30",
    "roamed_from": "safeops-ap-02",
    "roam_time_ms": 50,
    "handoff_count": 2
  },
  
  "security": {
    "vlan_id": 100,
    "firewall_profile": "corporate-users",
    "qos_profile": "high-priority",
    "bandwidth_limit_mbps": 50,
    "isolation_enabled": false
  }
}
```

---

## 📊 All Fields Master Reference

### Common Fields (All Logs)
- `timestamp` - ISO 8601 with nanosecond precision
- `level` - Log severity (trace, debug, info, warn, error, fatal, panic)
- `message` - Human-readable description
- `service` - Service name (dns-server, firewall, ids-ips, etc.)
- `version` - Service version (SemVer)
- `environment` - Deployment environment (production, staging, development)
- `host` - Server hostname/identifier
- `request_id` - Unique request/transaction ID (UUID v4)

### Network Packet Fields
- Ethernet: src_mac, dst_mac, ethertype
- IP: version, src_ip, dst_ip, protocol, ttl, flags, etc.
- TCP: src_port, dst_port, flags (SYN, ACK, FIN, etc.), seq, ack
- UDP: src_port, dst_port, length, checksum
- Payload: length, encrypted, protocol, application data

### Security Fields
- Threat type, severity, confidence, CVE ID
- MITRE ATT&CK technique ID
- IDS/IPS signature ID and name
- Action taken (ACCEPT, DROP, REJECT)
- Blacklist/whitelist status

### Performance Metrics
- Processing time (microseconds/milliseconds)
- Queue wait time
- Latency measurements
- Resource usage (CPU core, memory)

### Geolocation
- Country, city, region
- Latitude, longitude
- ASN (Autonomous System Number)
- ISP/Organization

This comprehensive logging structure enables:
✅ **Full packet reconstruction**
✅ **Threat correlation**
✅ **Performance analysis**
✅ **Compliance auditing**
✅ **Incident response**
