# SafeOps SIEM Component Documentation

## Overview
The SIEM (Security Information and Event Management) component integrates the ELK Stack (Elasticsearch, Kibana, Logstash) into SafeOps for centralized log collection, analysis, and visualization.

## Component Information

**Component Type:** External Integration (ELK Stack)
**Language:** Java (Elasticsearch, Logstash), JavaScript (Kibana)
**Installation Type:** Standalone Windows Services
**Version:** 8.11.3

## Files and Locations

### Source Files
```
D:\SafeOpsFV2\src\SIEM\
├── README.md                          # Quick start guide
└── Install-SIEM.ps1 → (moved to bin)  # Installer script
```

### Binary/Executable Files
```
D:\SafeOpsFV2\bin\siem\
├── Install-SIEM.ps1                   # Main installer script
├── 1-start-elasticsearch.bat          # Start Elasticsearch
├── 2-start-kibana.bat                 # Start Kibana
├── 3-start-logstash.bat               # Start Logstash
├── start-all.bat                      # Start all components
└── stop-all.bat                       # Stop all components
```

### Installation Directory
```
D:\SafeOps-SIEM-Integration\
├── elasticsearch\
│   └── elasticsearch-8.11.3\          # Elasticsearch installation
├── kibana\
│   └── kibana-8.11.3\                 # Kibana installation
├── logstash\
│   └── logstash-8.11.3\               # Logstash installation
├── scripts\                           # Generated startup scripts
│   ├── 1-start-elasticsearch.bat
│   ├── 2-start-kibana.bat
│   ├── 3-start-logstash.bat
│   ├── start-all.bat
│   └── stop-all.bat
├── data\                              # Persistent data
│   └── elasticsearch\                 # Indexed data
├── logs\                              # Component logs
│   ├── elasticsearch\
│   ├── kibana\
│   └── logstash\
└── temp\                              # Temporary files
```

## Default Configuration

### Elasticsearch
```yaml
cluster.name: safeops-siem
node.name: safeops-node-1
path.data: D:/SafeOps-SIEM-Integration/data/elasticsearch
path.logs: D:/SafeOps-SIEM-Integration/logs/elasticsearch
network.host: 127.0.0.1
http.port: 9200
xpack.security.enabled: false           # ⚠️ Disabled for local dev
xpack.security.enrollment.enabled: false
xpack.security.http.ssl.enabled: false
xpack.security.transport.ssl.enabled: false
discovery.type: single-node
```

**Access URL:** http://localhost:9200

### Kibana
```yaml
server.port: 5601
server.host: "127.0.0.1"
server.name: "safeops-kibana"
elasticsearch.hosts: ["http://127.0.0.1:9200"]
logging.root.level: info
path.data: D:/SafeOps-SIEM-Integration/data/kibana
```

**Access URL:** http://localhost:5601

### Logstash
```yaml
path.data: D:/SafeOps-SIEM-Integration/data/logstash
path.logs: D:/SafeOps-SIEM-Integration/logs/logstash
pipeline.workers: 2
pipeline.batch.size: 125
config.reload.automatic: true
```

**Ports Used:**
- **9200** - Elasticsearch HTTP API
- **5601** - Kibana Web Interface
- **9300** - Elasticsearch Transport (internal)

## Installation Requirements

### System Requirements
- **OS:** Windows 10/11 or Windows Server 2016+
- **RAM:** 4 GB minimum, 8 GB recommended
- **Disk Space:** 2 GB for installation, 10+ GB for data
- **Java:** JDK 11+ (bundled with ELK components)
- **PowerShell:** Version 5.1+ (Administrator privileges required)

### Network Requirements
- Internet connection for initial download (~1.1 GB total)
- Ports 9200, 5601 available on localhost

### Download Sizes
- **Elasticsearch:** ~350 MB
- **Kibana:** ~350 MB
- **Logstash:** ~250 MB
- **Total:** ~1.1 GB

## Installation Steps

### First-Time Installation

1. **Open PowerShell as Administrator**
   ```
   Right-click PowerShell → "Run as Administrator"
   ```

2. **Navigate to SIEM directory**
   ```powershell
   cd D:\SafeOpsFV2\bin\siem
   ```

3. **Run the installer**
   ```powershell
   .\Install-SIEM.ps1
   ```

4. **Wait for installation** (5-15 minutes depending on internet speed)
   - Downloads ELK Stack components
   - Extracts to D:\SafeOps-SIEM-Integration
   - Configures all components
   - Creates Windows services (Elasticsearch)
   - Generates startup scripts

### Installation Options

**Force Reinstall:**
```powershell
.\Install-SIEM.ps1 -Force
```
Redownloads and reinstalls everything, even if already present.

**Skip Download:**
```powershell
.\Install-SIEM.ps1 -SkipDownload
```
Uses previously downloaded files (useful for reconfiguration).

## Starting the SIEM Stack

### Manual Sequential Startup (Recommended)

Start components in order with 30-second delays:

```batch
# Step 1: Start Elasticsearch (wait ~30 seconds for startup)
D:\SafeOps-SIEM-Integration\scripts\1-start-elasticsearch.bat

# Step 2: Start Kibana (wait ~30 seconds for startup)
D:\SafeOps-SIEM-Integration\scripts\2-start-kibana.bat

# Step 3: Start Logstash
D:\SafeOps-SIEM-Integration\scripts\3-start-logstash.bat
```

### Quick Startup (All at Once)

```batch
D:\SafeOps-SIEM-Integration\scripts\start-all.bat
```

⚠️ **Note:** Components may take 1-2 minutes to fully initialize.

### Stopping All Components

```batch
D:\SafeOps-SIEM-Integration\scripts\stop-all.bat
```

## Verifying Installation

### 1. Check Elasticsearch
Open browser to: http://localhost:9200

Expected response:
```json
{
  "name" : "safeops-node-1",
  "cluster_name" : "safeops-siem",
  "version" : {
    "number" : "8.11.3"
  }
}
```

### 2. Check Kibana
Open browser to: http://localhost:5601

Should see Kibana dashboard (no login required).

### 3. Check Logstash
Look for console output showing:
```
[INFO] Successfully started Logstash API endpoint
```

## Integration with SafeOps

### Log Forwarding

SafeOps components forward logs to Logstash for processing:

**Source:** SafeOps components (Firewall, IDS, DHCP Monitor, etc.)
**Destination:** Logstash input pipeline
**Format:** JSON-structured logs
**Transport:** Syslog (UDP/TCP) or Direct HTTP

### Data Flow
```
SafeOps Components → Logstash (Parse/Filter) → Elasticsearch (Index) → Kibana (Visualize)
```

### Example: Firewall Logs
1. Firewall Engine blocks connection
2. Logs event to `D:\SafeOpsFV2\data\logs\firewall.log`
3. Logstash tails log file or receives syslog
4. Logstash parses and enriches log data
5. Sends to Elasticsearch for indexing
6. Visible in Kibana dashboards

## Important Notes

### Security Warnings

⚠️ **SECURITY DISABLED:** This installation disables all security features for local development:
- No authentication required
- No SSL/TLS encryption
- Accessible only on localhost (127.0.0.1)

**For Production Use:**
- Enable X-Pack security
- Configure SSL/TLS certificates
- Set strong passwords
- Restrict network access with firewall rules

### Performance Considerations

- **First Startup:** Takes 1-2 minutes for all components to initialize
- **Memory Usage:** Elasticsearch uses ~1-2 GB RAM by default
- **Disk I/O:** Heavy indexing can impact system performance
- **Adjust JVM Heap:** Edit `jvm.options` in each component's config directory

### Troubleshooting

**Elasticsearch won't start:**
- Check if port 9200 is already in use: `netstat -ano | findstr 9200`
- Check logs: `D:\SafeOps-SIEM-Integration\logs\elasticsearch\`
- Verify JVM heap settings in `config\jvm.options`

**Kibana shows "Unable to connect to Elasticsearch":**
- Ensure Elasticsearch started successfully first
- Wait 30 seconds after Elasticsearch startup
- Verify Elasticsearch at http://localhost:9200

**Logstash errors:**
- Check pipeline configuration in `config\pipelines.yml`
- Verify log file paths exist
- Check logs: `D:\SafeOps-SIEM-Integration\logs\logstash\`

## Configuration Files Reference

### Elasticsearch
- **Main Config:** `elasticsearch-8.11.3\config\elasticsearch.yml`
- **JVM Options:** `elasticsearch-8.11.3\config\jvm.options`
- **Log4j Config:** `elasticsearch-8.11.3\config\log4j2.properties`

### Kibana
- **Main Config:** `kibana-8.11.3\config\kibana.yml`
- **Node Options:** `kibana-8.11.3\config\node.options`

### Logstash
- **Main Config:** `logstash-8.11.3\config\logstash.yml`
- **Pipelines:** `logstash-8.11.3\config\pipelines.yml`
- **JVM Options:** `logstash-8.11.3\config\jvm.options`

## Maintenance

### Clearing Old Data
```powershell
# Stop all components first
D:\SafeOps-SIEM-Integration\scripts\stop-all.bat

# Delete indexed data
Remove-Item -Recurse D:\SafeOps-SIEM-Integration\data\elasticsearch\*

# Restart
D:\SafeOps-SIEM-Integration\scripts\start-all.bat
```

### Uninstalling
```powershell
# Stop all services
D:\SafeOps-SIEM-Integration\scripts\stop-all.bat

# Remove installation directory
Remove-Item -Recurse -Force D:\SafeOps-SIEM-Integration
```

## Connection to Other Components

| Component | Connection Type | Purpose |
|-----------|----------------|---------|
| Firewall Engine | Log forwarding | Security event analysis |
| IDS/IPS | Alert forwarding | Intrusion detection alerts |
| DHCP Monitor | Event logging | Network device tracking |
| Threat Intelligence | Data enrichment | IP/domain reputation |
| Network Manager | Metrics collection | Network performance data |
| Orchestrator | Service health | Component monitoring |

## Default Credentials

**None Required** - Security is disabled for local development.

For production, default Elasticsearch user is `elastic` with auto-generated password during setup.

## Next Steps

1. Configure SafeOps components to forward logs to Logstash
2. Create Kibana dashboards for security monitoring
3. Set up index lifecycle management for data retention
4. Configure alerts and watchers for security events

---

**Status:** Installed via PowerShell script
**Auto-Start:** Manual (run startup scripts)
**Dependencies:** None (self-contained)
**Managed By:** Manual or Windows Task Scheduler
