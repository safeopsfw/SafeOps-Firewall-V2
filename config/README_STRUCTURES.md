# Configuration - Data Structures

> **Configuration schema and data structure reference**

---

## 📋 Configuration Files

### Master Configuration

```toml
# config/templates/safeops.toml

[system]
version = "2.0.0"
node_id = "safeops-node-01"
environment = "production"
log_level = "info"

[kernel_driver]
enabled = true
driver_path = "C:\\Windows\\System32\\drivers\\safeops.sys"
ring_buffer_size_mb = 16
max_packet_rate = 1000000

[firewall]
default_policy = "BLOCK"
enable_stateful_tracking = true
connection_timeout_seconds = 3600
max_connections = 1000000

[threat_intelligence]
enabled = true
database_host = "localhost"
database_port = 5432
update_interval_minutes = 60

[logging]
output_directory = "C:\\ProgramData\\SafeOps\\logs"
rotation_interval = "5min"
format = "json"
```

### Firewall Rules

```yaml
# config/examples/custom_firewall_rules.yaml

rules:
  - id: 1001
    name: "Block Known C2 Servers"
    enabled: true
    priority: 10
    action: BLOCK
    direction: OUTBOUND
    destination:
      threat_intel: true
      min_threat_score: 75
```

### Network Topology

```yaml
# config/network_topology.yaml

interfaces:
  - name: "WAN"
    device: "Ethernet0"
    ipv4: "192.168.1.1/24"
    gateway: "192.168.1.254"
    
  - name: "LAN"
    device: "Ethernet1"
    ipv4: "10.0.0.1/24"
    dhcp_server: true
```

---

## 📊 JSON Schema

All configuration files are validated against JSON schemas:

```json
{
  "$schema": "http://json-schema.org/draft-07/schema#",
  "type": "object",
  "properties": {
    "system": {
      "type": "object",
      "properties": {
        "version": { "type": "string", "pattern": "^\\d+\\.\\d+\\.\\d+$" },
        "node_id": { "type": "string" },
        "environment": { "enum": ["production", "staging", "development"] }
      },
      "required": ["version", "node_id"]
    }
  }
}
```

---

**Version:** 2.0.0  
**Last Updated:** 2025-12-17
