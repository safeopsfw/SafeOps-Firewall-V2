---
description: Start the SafeOps development server (backend + frontend + all services)
---

# Run Dev Server Workflow

Starts all SafeOps services for development.

## Quick Start

// turbo
1. **Launch all services**
   ```powershell
   .\start_dev_server.ps1
   ```

## What Gets Started

| Service | Port | Description |
|---------|------|-------------|
| Frontend UI | 3001 | Vite React dev server |
| Backend API | 5050 | Node.js Express API |
| Threat Intel | 8080 | Go threat intelligence API |
| NIC Management | 8081 | Go network interface service |
| DHCP Monitor | 53, 80, 8068 | DNS hijack, Portal, Health |

## Options

```powershell
.\start_dev_server.ps1               # All services
.\start_dev_server.ps1 -Minimal      # Backend + Frontend only
.\start_dev_server.ps1 -BackendOnly  # Backend only
.\start_dev_server.ps1 -FrontendOnly # Frontend only
.\start_dev_server.ps1 -ServicesOnly # Go services only
```

## Health Checks

- Backend: http://localhost:5050/health
- Threat Intel: http://localhost:8080/api/health
- DHCP Monitor: http://localhost:8068/health

## DHCP Monitor Notes

The DHCP Monitor requires **Administrator privileges** for DNS port 53.
- Captive Portal: http://localhost:80
- DNS Hijack: localhost:53

## Database

- PostgreSQL on localhost:5432
- Database: `threat_intel_db`
- User: `safeops` / Password: `safeops123`
