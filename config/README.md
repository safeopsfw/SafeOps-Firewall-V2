# SafeOps v2.0 Configuration Guide

## 📋 Overview

This directory contains all configuration files for SafeOps v2.0. This guide covers file organization, customization workflows, validation procedures, and troubleshooting.

---

## 📁 Configuration Hierarchy

```
config/
├── safeops.toml              # Master configuration (entry point)
├── presets/                  # Pre-configured environments
│   ├── home_user.toml        # Home/personal use
│   ├── small_business.toml   # Small office (10-50 users)
│   └── enterprise.toml       # Large organizations
├── templates/                # Service-specific configurations
│   ├── firewall_engine.toml  # Firewall rules engine
│   ├── threat_intel.toml     # Threat intelligence feeds
│   ├── dns_server.toml       # DNS/DHCP services
│   └── ...                   # Other service configs
├── examples/                 # Reference configurations
├── ids_ips/                  # IDS/IPS specific configs
├── security/                 # Certificates and secrets
└── config_validator.ps1      # Validation script
```

### Configuration Loading Order

1. **Master Config** (`safeops.toml`) - Loaded first
2. **Preset** - Based on `preset =` value in master config
3. **Service Configs** - Individual service templates
4. **Overrides** - Custom overrides from `overrides/` directory

> [!NOTE]
> Later configurations override earlier ones. Service-specific settings take precedence over preset defaults.

### Hot-Reload Capabilities

| Config Type | Hot Reload | Restart Required |
|-------------|------------|------------------|
| Firewall rules | ✅ Yes | No |
| DNS records | ✅ Yes | No |
| Threat feeds | ✅ Yes | No |
| Network topology | ❌ No | Yes |
| Kernel driver | ❌ No | Yes (reboot) |

---

## 🚀 Quick Start

### Step 1: Choose a Preset

```toml
# In safeops.toml, set your environment type:
preset = "small_business"  # Options: home_user, small_business, enterprise
```

| Preset | Use Case | Default Security Level |
|--------|----------|----------------------|
| `home_user` | Personal use, 1-5 devices | Medium |
| `small_business` | Small office, 10-50 users | High |
| `enterprise` | Large org, 100+ users | Maximum |

### Step 2: Customize Network Settings

Edit `config/network_topology.yaml`:

```yaml
networks:
  - name: "Office LAN"
    network: "192.168.1.0/24"
    gateway: "192.168.1.1"
    vlan_id: 10
```

### Step 3: Validate Configuration

```powershell
# Run the configuration validator
.\config_validator.ps1 -Full

# Validate specific file
.\config_validator.ps1 -ConfigFile "templates\firewall_engine.toml"
```

### Step 4: Apply Configuration

```powershell
# Apply with backup
safeops-cli config apply --backup

# Test mode (validates without applying)
safeops-cli config apply --dry-run
```

> [!IMPORTANT]
> Always backup before making changes:
> ```powershell
> safeops-cli config backup --output "backup_$(Get-Date -Format 'yyyyMMdd').zip"
> ```

---

## 📚 Configuration Files Reference

### Master Configuration: `safeops.toml`

The entry point for all SafeOps configuration.

```toml
[general]
preset = "small_business"
log_level = "INFO"
data_directory = "C:\\SafeOps\\data"

[services]
firewall_engine = { enabled = true, config = "templates/firewall_engine.toml" }
threat_intel = { enabled = true, config = "templates/threat_intel.toml" }
dns_server = { enabled = true, config = "templates/dns_server.toml" }
ids_ips = { enabled = true, config = "templates/ids_ips.toml" }

[performance]
max_threads = 8
memory_limit = "4GB"
```

### Service Configurations

| File | Purpose | Key Settings |
|------|---------|--------------|
| `firewall_engine.toml` | Packet filtering engine | Default action, rule sets, logging |
| `threat_intel.toml` | Threat intelligence | Feed sources, update intervals |
| `dns_server.toml` | DNS resolution | Upstream servers, caching, blocking |
| `dhcp_server.toml` | IP assignment | Pools, reservations, lease times |
| `ids_ips.toml` | Intrusion detection | Rule categories, actions |
| `tls_proxy.toml` | TLS inspection | Certificate paths, bypass lists |
| `vpn_gateway.toml` | VPN services | WireGuard/OpenVPN settings |

---

## ✅ Best Practices

### Security Hardening Checklist

- [ ] Change default admin password
- [ ] Enable TLS for all management interfaces
- [ ] Restrict management access to specific IPs
- [ ] Enable comprehensive logging
- [ ] Configure log rotation and retention
- [ ] Set up automated backups
- [ ] Enable threat intelligence feeds
- [ ] Review firewall rules quarterly

### Performance Tuning

```toml
# For high-traffic networks (>1 Gbps)
[performance]
max_threads = 16
packet_buffer_size = "256MB"
connection_table_size = 1000000

# Enable hardware offloading if available
[hardware]
rx_checksum_offload = true
tx_checksum_offload = true
segmentation_offload = true
```

### Version Control

Store configurations in Git for change tracking:

```bash
cd C:\SafeOps\config
git init
git add .
git commit -m "Initial configuration"
```

---

## 🔧 Common Tasks

### Adding Firewall Rules

**Via Configuration File:**
```yaml
# In config/examples/custom_firewall_rules.yaml
- rule_name: "Allow HTTPS"
  action: ALLOW
  protocol: TCP
  destination_port: 443
  source: internal
```

**Via CLI:**
```powershell
safeops-cli firewall add-rule --name "Allow HTTPS" --action ALLOW --port 443
```

### Configuring DHCP Pools

```toml
# In templates/dhcp_server.toml
[[dhcp.pools]]
pool_name = "Office Network"
network = "192.168.10.0/24"
range_start = "192.168.10.100"
range_end = "192.168.10.200"
gateway = "192.168.10.1"
dns_servers = ["192.168.10.1", "8.8.8.8"]
lease_time = 86400
```

### Setting Up VPN Access

```toml
# In templates/vpn_gateway.toml
[wireguard]
enabled = true
listen_port = 51820
interface = "wg0"
address = "10.0.0.1/24"

[[wireguard.peers]]
name = "remote-user"
public_key = "PUBLIC_KEY_HERE"
allowed_ips = ["10.0.0.2/32"]
```

### Integrating Threat Feeds

```toml
# In templates/threat_intel.toml
[[feeds]]
name = "Emerging Threats"
url = "https://rules.emergingthreats.net/open/suricata/emerging.rules.tar.gz"
update_interval = 3600
enabled = true
```

---

## 🔍 Variable Substitution

Use environment variables in configuration files:

```toml
# Reference environment variables with ${VAR_NAME}
data_directory = "${SAFEOPS_DATA_DIR}"
admin_email = "${ADMIN_EMAIL}"
api_key = "${THREAT_INTEL_API_KEY}"
```

Set environment variables:
```powershell
$env:SAFEOPS_DATA_DIR = "D:\SafeOps\data"
$env:ADMIN_EMAIL = "admin@company.com"
```

---

## ✔️ Schema Validation

### Using the Validator

```powershell
# Full validation with dependency checks
.\config_validator.ps1 -Full

# Export validation report
.\config_validator.ps1 -Full -ExportReport -ReportPath "report.json"

# Quiet mode (errors only)
.\config_validator.ps1 -Quiet
```

### Validation Checks Performed

| Check | Description |
|-------|-------------|
| Syntax | TOML/YAML syntax errors |
| Required Fields | All mandatory fields present |
| Value Ranges | Values within acceptable limits |
| File References | Referenced files exist |
| Network Config | Valid IPs, no overlaps |
| Dependencies | Service dependencies met |

---

## 🛠️ Troubleshooting

### Configuration Validation Errors

**Error: "Missing required field"**
```
Solution: Add the missing field to the configuration file
Example: Add 'enabled = true' to the [service] section
```

**Error: "Invalid CIDR format"**
```
Solution: Use correct CIDR notation (e.g., 192.168.1.0/24)
Check: Network address matches the subnet mask
```

### Service Startup Failures

```powershell
# Check service status
safeops-cli service status --all

# View detailed logs
Get-Content "C:\SafeOps\logs\safeops.log" -Tail 100

# Validate configuration before restart
.\config_validator.ps1 -Full
safeops-cli service restart firewall_engine
```

### Common Issues

| Issue | Cause | Solution |
|-------|-------|----------|
| Service won't start | Config syntax error | Run validator, check logs |
| Rules not applying | Hot-reload disabled | Restart service |
| High memory usage | Buffer too large | Reduce `packet_buffer_size` |
| Slow DNS | Upstream timeout | Check upstream DNS servers |

---

## 📦 Migration Guide

### Upgrading from v1.x to v2.0

1. **Backup existing configuration**
   ```powershell
   safeops-cli config backup --output "v1_backup.zip"
   ```

2. **Run migration tool**
   ```powershell
   safeops-cli migrate --from-version 1.x --config-path "C:\SafeOps\config"
   ```

3. **Validate migrated configuration**
   ```powershell
   .\config_validator.ps1 -Full
   ```

4. **Review and apply**
   ```powershell
   safeops-cli config apply --dry-run
   safeops-cli config apply
   ```

### Breaking Changes in v2.0

| v1.x Setting | v2.0 Equivalent |
|--------------|-----------------|
| `firewall.rules_file` | `firewall_engine.rules_path` |
| `dns.upstream` | `dns_server.forwarders` |
| `logging.file` | `logging.outputs.file.path` |

---

## 📞 Getting Help

- **Documentation:** `docs/` directory
- **CLI Help:** `safeops-cli --help`
- **Validate Configs:** `.\config_validator.ps1 -Full`
- **Support:** See `SUPPORT.md` in root directory

---

*Last Updated: December 2025 | SafeOps v2.0*
