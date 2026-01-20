# SafeOps SIEM Integration

Complete SIEM (Security Information and Event Management) installer for SafeOps Firewall V2 using the ELK Stack.

## Overview

This installer automates the complete setup of Elasticsearch, Logstash, and Kibana (ELK Stack) on your D: drive, with automatic integration into SafeOps logging infrastructure.

**What gets installed:**
- **Elasticsearch 8.11.3** - Search and analytics engine (Port 9200)
- **Kibana 8.11.3** - Visualization dashboard (Port 5601)
- **Logstash 8.11.3** - Log processing pipeline (Port 5044)

**Installation location:** `D:\SafeOps-SIEM-Integration\` (uses 1TB D: drive)

## Why ELK Stack?

- ✓ Free and open-source
- ✓ Industry standard for log management
- ✓ Powerful search with Kibana Query Language (KQL)
- ✓ Excellent visualization capabilities
- ✓ Large community and extensive documentation

**Alternatives mentioned:** Wazuh (security-focused), Graylog (simpler), Security Onion (Linux-only)

## Quick Start

### Build the Installer

```bash
cd D:\SafeOpsFV2\src\SIEM
go run build.go
```

This creates:
- `D:\SafeOpsFV2\bin\siem\safeops-siem-setup.exe`
- `D:\SafeOpsFV2\bin\siem\config.yaml`

### Run the Installer

```bash
# Open Command Prompt as Administrator
cd D:\SafeOpsFV2\bin\siem
safeops-siem-setup.exe
```

### Installation Flow

1. **Shows banner** with ELK Stack information
2. **Displays configuration** with all settings
3. **Interactive modification** - Change any setting:
   - Installation directory (default: D:\SafeOps-SIEM-Integration)
   - Elasticsearch password (default: SafeOps2026!)
   - Ports (ES: 9200, Kibana: 5601, Logstash: 5044)
   - Memory allocation (default: 2g heap)
   - Windows service settings
4. **Confirms installation**
5. **Downloads ELK Stack** (~2-3 GB, 5-10 minutes)
6. **Extracts and configures** all components
7. **Creates startup scripts** and services
8. **Integrates with SafeOps logs** automatically

### Start the SIEM

```bash
cd D:\SafeOps-SIEM-Integration\scripts
start-all.bat
```

Or start individually:
```bash
install-elasticsearch-service.bat  # Install ES as Windows service
start-kibana.bat                   # Start Kibana
start-logstash.bat                 # Start Logstash
```

### Access Kibana

1. Wait 30-60 seconds for services to start
2. Open browser: http://localhost:5601
3. Login with credentials set during installation (default: elastic / SafeOps2026!)

## Configuration

### config.yaml

All installation settings are in `config.yaml`. Key sections:

```yaml
installation:
  install_dir: "D:\\SafeOps-SIEM-Integration"
  data_dir: "D:\\SafeOps-SIEM-Integration\\data"
  logs_dir: "D:\\SafeOps-SIEM-Integration\\logs"

elk_stack:
  elasticsearch:
    version: "8.11.3"
    port: 9200
    heap_size: "2g"  # Adjust: 1g (low RAM) or 4g (high performance)

  kibana:
    version: "8.11.3"
    port: 5601

  logstash:
    version: "8.11.3"
    port: 5044

credentials:
  elasticsearch_username: "elastic"
  elasticsearch_password: "SafeOps2026!"  # CHANGE THIS!
  kibana_encryption_key: "SafeOpsKibana2026SecretKey123456"

safeops_integration:
  log_sources:
    - "D:\\SafeOpsFV2\\bin\\logs\\netflow"    # Network traffic
    - "D:\\SafeOpsFV2\\bin\\logs\\engine.log" # Engine logs
    - "D:\\SafeOpsFV2\\bin\\logs\\ids.log"    # IDS events

windows_service:
  create_services: true   # Install as Windows service
  auto_start: true        # Start on Windows boot
```

### Interactive Configuration

During installation, you can modify any setting:

```
╔═══════════════════════════════════════════════════════════════╗
║                 Current Configuration                         ║
╚═══════════════════════════════════════════════════════════════╝

Installation Settings:
  [1] Installation Directory: D:\SafeOps-SIEM-Integration
  [2] Data Directory:         D:\SafeOps-SIEM-Integration\data
  [3] Logs Directory:         D:\SafeOps-SIEM-Integration\logs

ELK Stack Components:
  [4] Elasticsearch Version: 8.11.3 (Port: 9200)
  [5] Elasticsearch Heap:    2g
  [6] Kibana Version:        8.11.3 (Port: 5601)
  [7] Logstash Version:      8.11.3 (Port: 5044)

Security Credentials:
  [8] Elasticsearch Username: elastic
  [9] Elasticsearch Password: Sa******6!

Windows Service:
  [10] Create Windows Services: true
  [11] Auto-start on Boot:     true

Do you want to modify any settings? (yes/no):
```

## SafeOps Integration

The installer automatically configures Logstash to read SafeOps logs:

**Log Sources:**
- `D:\SafeOpsFV2\bin\logs\netflow\*.log` → Index: `safeops-network-*`
- `D:\SafeOpsFV2\bin\logs\ids.log` → Index: `safeops-ids-*`
- `D:\SafeOpsFV2\bin\logs\engine.log` → Index: `safeops-engine-*`

**In Kibana, create index patterns:**
1. Go to Stack Management → Index Patterns
2. Create: `safeops-network-*` for network traffic
3. Create: `safeops-ids-*` for intrusion detection
4. Create: `safeops-engine-*` for engine logs

## Requirements

### System Requirements
- **OS:** Windows 10/11 (64-bit)
- **Privileges:** Administrator rights required
- **Disk:** 5+ GB free on D: drive (2 GB download, 3 GB installed, plus data growth)
- **RAM:** 4+ GB (2 GB for Elasticsearch, 1 GB for Kibana, 1 GB for Logstash)
- **CPU:** 4+ cores recommended
- **Network:** Internet connection for downloading ELK components

### Resource Usage
- **Idle:** 5-10% CPU, 3-4 GB RAM
- **Active:** 20-45% CPU, 4-6 GB RAM
- **Disk growth:** 100 MB - 5 GB per day (depends on log volume)

## Post-Installation

### First Time Setup

1. **Change default password** (IMPORTANT!)
   - Login to Kibana
   - Go to Stack Management → Security → Users
   - Select `elastic` user and change password

2. **Create dashboards**
   - Go to Dashboard → Create new dashboard
   - Add visualizations for network traffic, IDS alerts, etc.

3. **Set up alerts**
   - Go to Stack Management → Rules and Connectors
   - Create alerts for suspicious activity

### Verify Installation

```bash
# Check Elasticsearch
curl http://localhost:9200

# Check Kibana
curl http://localhost:5601/api/status
```

Should see JSON responses indicating services are running.

## Windows Startup

### Automatic Startup
If enabled during installation, SIEM starts automatically on system boot.

### Manual Startup Configuration
Add to Windows startup:
1. Press `Win + R`, type `shell:startup`
2. Create shortcut to: `D:\SafeOps-SIEM-Integration\scripts\start-all.bat`

## Troubleshooting

### Build Issues

**Error:** `go: command not found`
**Fix:** Install Go from https://go.dev/dl/

**Error:** `cannot find package`
**Fix:** Run `go mod download` manually

### Installation Issues

**Error:** Download fails
**Fix:** Check internet connection and firewall settings

**Error:** Insufficient disk space
**Fix:** Free up space on D: drive (need 5+ GB)

**Error:** Port already in use
**Fix:** During configuration, change the conflicting port

### Runtime Issues

**Error:** Elasticsearch won't start
**Fix:** Check logs at `D:\SafeOps-SIEM-Integration\logs\elasticsearch\`

**Error:** Kibana shows "Unable to connect to Elasticsearch"
**Fix:** Verify Elasticsearch is running: `curl http://localhost:9200`

**Error:** No logs appearing in Kibana
**Fix:**
1. Check SafeOps is generating logs at `D:\SafeOpsFV2\bin\logs\`
2. Verify Logstash pipeline config
3. Restart Logstash

**Error:** High CPU/memory usage
**Fix:** Reduce Elasticsearch heap size in `config.yaml` to "1g"

## Maintenance

### Checking Service Status
```bash
curl http://localhost:9200/_cluster/health  # Elasticsearch
curl http://localhost:5601/api/status       # Kibana
```

### Restarting Services
```bash
net stop SafeOps-Elasticsearch
cd D:\SafeOps-SIEM-Integration\scripts
start-all.bat
```

### Backup
```bash
xcopy /E /I /H /Y D:\SafeOps-SIEM-Integration\data D:\Backups\SIEM\data
```

### Log Rotation
Configure Index Lifecycle Management (ILM) in Kibana:
- Stack Management → Index Lifecycle Policies
- Set retention: Hot (7 days) → Delete (30 days)

## Security

**Critical security steps:**
1. ✓ Change default password immediately
2. ✓ Use strong passwords (12+ characters)
3. ✓ Services bind to 127.0.0.1 (localhost only)
4. ✓ Block external access to ports 9200, 5601, 5044
5. ✓ Enable SSL/TLS for production use
6. ✓ Regular backups of data directory

## Uninstallation

```bash
# Stop services
net stop SafeOps-Elasticsearch

# Remove services
sc delete SafeOps-Elasticsearch
sc delete SafeOps-Kibana
sc delete SafeOps-Logstash

# Delete files
rmdir /s /q D:\SafeOps-SIEM-Integration

# Remove startup shortcut
del "%APPDATA%\Microsoft\Windows\Start Menu\Programs\Startup\SafeOps-SIEM.lnk"
```

## Project Structure

```
src/SIEM/
├── main.go          # Main installer application
├── build.go         # Build tool
├── config.yaml      # Default configuration
├── go.mod           # Go dependencies
└── README.md        # This file

bin/siem/            # Output directory (created after build)
├── safeops-siem-setup.exe
└── config.yaml
```

## Advanced Usage

### Custom Logstash Pipelines
Add custom pipelines in:
`D:\SafeOps-SIEM-Integration\logstash\logstash-*\config\pipeline\`

### Multi-Node Cluster
For high availability, install on multiple machines and configure cluster discovery in Elasticsearch config.

### SSL/TLS Setup
Generate certificates using SafeOps Step-CA and update Elasticsearch configuration.

## Support

**Resources:**
- Elasticsearch docs: https://www.elastic.co/guide/
- Kibana docs: https://www.elastic.co/guide/en/kibana/
- SafeOps main README: `D:\SafeOpsFV2\README.md`

**For issues:**
1. Check logs first
2. Review troubleshooting section
3. Search Elastic community forums
4. Contact SafeOps support

## License

Part of SafeOps Firewall V2
Copyright (c) 2026 SafeOps Project. All Rights Reserved.

---

**Quick Reference:**

```bash
# Build
cd D:\SafeOpsFV2\src\SIEM
go run build.go

# Install
cd D:\SafeOpsFV2\bin\siem
safeops-siem-setup.exe

# Start
cd D:\SafeOps-SIEM-Integration\scripts
start-all.bat

# Access
http://localhost:5601
```

**Default Credentials:** elastic / SafeOps2026! (CHANGE IMMEDIATELY!)
