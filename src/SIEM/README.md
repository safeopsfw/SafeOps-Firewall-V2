# SafeOps SIEM - ELK Stack Integration

A Python-based installer for setting up Elasticsearch, Logstash, and Kibana (ELK Stack) integrated with SafeOps Network Security Platform.

## Quick Start

```powershell
# Run as Administrator
cd D:\SafeOpsFV2\src\SIEM
python setup_elk.py
```

## Default Credentials

| Setting | Value |
|---------|-------|
| **Username** | `safeops_admin` |
| **Password** | `SafeOps@SIEM2026!` |

## Port Configuration

| Service | Port | Status |
|---------|------|--------|
| Elasticsearch | 9200 | Default |
| Kibana | 5601 | Default |
| Logstash (Beats) | 5044 | Default |

> **Note:** These ports are chosen to avoid conflicts with SafeOps services (8080, 9000, 9002).

---

## Changing Credentials

### Method 1: Before Installation

Edit `setup_elk.py` and modify the `CONFIG` dictionary at the top:

```python
CONFIG = {
    "username": "your_username",      # Change this
    "password": "YourNewPassword!",   # Change this
    # ... rest of config
}
```

Then run the installer:
```powershell
python setup_elk.py
```

### Method 2: After Installation

1. Stop all services:
   ```powershell
   D:\SafeOpsFV2\bin\elk\stop-siem.bat
   ```

2. Change Elasticsearch password:
   ```powershell
   cd D:\SafeOpsFV2\bin\elk\elasticsearch-8.17.0\bin
   elasticsearch-reset-password -u safeops_admin -i
   ```

3. Update Kibana config (`D:\SafeOpsFV2\bin\elk\kibana-8.17.0\config\kibana.yml`):
   ```yaml
   elasticsearch.password: "YourNewPassword"
   ```

4. Update Logstash config (`D:\SafeOpsFV2\bin\elk\logstash-8.17.0\config\conf.d\safeops.conf`):
   ```ruby
   output {
       elasticsearch {
           password => "YourNewPassword"
       }
   }
   ```

5. Restart services:
   ```powershell
   D:\SafeOpsFV2\bin\elk\start-siem.bat
   ```

---

## Installation Directory Structure

```
D:\SafeOpsFV2\bin\elk\
├── elasticsearch-8.17.0\     # Elasticsearch installation
├── kibana-8.17.0\            # Kibana installation
├── logstash-8.17.0\          # Logstash installation
├── data\                     # Data storage
│   ├── elasticsearch\
│   └── logstash\
├── logs\                     # Log files
│   ├── elasticsearch\
│   ├── kibana\
│   └── logstash\
├── start-siem.bat            # Start all services
├── stop-siem.bat             # Stop all services
└── setup-security.bat        # First-time security setup
```

---

## Usage

### Starting SIEM

```powershell
D:\SafeOpsFV2\bin\elk\start-siem.bat
```

### Stopping SIEM

```powershell
D:\SafeOpsFV2\bin\elk\stop-siem.bat
```

### Accessing Kibana

Open browser to: **http://localhost:5601**

Login with:
- Username: `safeops_admin`
- Password: `SafeOps@SIEM2026!`

---

## SafeOps Log Ingestion

Logstash is pre-configured to ingest these SafeOps logs:

| Log File | Index Pattern | Description |
|----------|--------------|-------------|
| `network_packets_master.jsonl` | `safeops-network_packets-*` | All network traffic |
| `ids.log` | `safeops-ids_alerts-*` | IDS alerts |
| `firewall.log` | `safeops-firewall-*` | Firewall events |
| `devices.jsonl` | `safeops-devices-*` | Device inventory |

---

## Rebuilding / Reinstalling

To completely reinstall:

```powershell
# Uninstall existing
python setup_elk.py --uninstall

# Reinstall
python setup_elk.py
```

---

## Troubleshooting

### Elasticsearch won't start
- Check if port 9200 is in use: `netstat -an | findstr 9200`
- Check logs: `D:\SafeOpsFV2\bin\elk\logs\elasticsearch\`
- Increase heap size in config if out of memory

### Kibana can't connect to Elasticsearch
- Ensure Elasticsearch is running first
- Check credentials match in `kibana.yml`
- Wait 30-60 seconds after starting Elasticsearch

### Logstash not ingesting logs
- Verify log files exist at specified paths
- Check Logstash logs for parsing errors
- Ensure SafeOps Logger is running and generating logs

---

## System Requirements

- **OS:** Windows 10/11 or Windows Server 2019+
- **RAM:** Minimum 8GB (16GB recommended)
- **Disk:** 20GB+ free space
- **Java:** Not required (bundled with ELK)
- **Python:** 3.8+

---

## Security Notes

> ⚠️ **Important:** Change the default password in production!

The default configuration is for **local development only**:
- HTTPS is disabled
- Basic authentication is enabled
- Services bind to localhost only

For production, enable:
- TLS/HTTPS encryption
- Strong passwords
- Network firewall rules
- Role-based access control (RBAC)
