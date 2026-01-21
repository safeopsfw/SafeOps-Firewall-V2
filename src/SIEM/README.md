# SafeOps SIEM Integration

Complete ELK Stack (Elasticsearch, Kibana, Logstash) integration for SafeOps.

## Quick Start

### First Time Installation

1. Open PowerShell **as Administrator**
2. Run:
```powershell
cd D:\SafeOpsFV2\bin\siem
.\Install-SIEM.ps1
```

This will:
- Download ELK Stack (~1.1 GB)
- Extract to `D:\SafeOps-SIEM-Integration`
- Configure all components
- Install Elasticsearch as Windows service
- Create numbered start scripts

### Starting the Stack

After installation, run scripts in order:

```
D:\SafeOps-SIEM-Integration\scripts\1-start-elasticsearch.bat
D:\SafeOps-SIEM-Integration\scripts\2-start-kibana.bat
D:\SafeOps-SIEM-Integration\scripts\3-start-logstash.bat
```

Or use `start-all.bat` to launch all at once.

### Access URLs

- **Elasticsearch**: http://localhost:9200
- **Kibana**: http://localhost:5601

No login required (security disabled for local development).

## Files

| File | Purpose |
|------|---------|
| `Install-SIEM.ps1` | Master installer script |
| `config.yaml` | Configuration reference |

## Installed Location

`D:\SafeOps-SIEM-Integration\`

```
├── elasticsearch\
├── kibana\
├── logstash\
├── scripts\
│   ├── 1-start-elasticsearch.bat
│   ├── 2-start-kibana.bat
│   ├── 3-start-logstash.bat
│   ├── start-all.bat
│   └── stop-all.bat
├── data\
├── logs\
└── temp\
```

## Reinstall / Force Update

```powershell
.\Install-SIEM.ps1 -Force
```

## Skip Download (if already downloaded)

```powershell
.\Install-SIEM.ps1 -SkipDownload
```
