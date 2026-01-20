# SafeOps Requirements Setup Installer

Automated installer for all SafeOps dependencies.

## What It Installs

1. **PostgreSQL 16.1**
   - Creates 3 databases: `threat_intel_db`, `safeops_network`, `safeops`
   - Creates 4 users: `safeops`, `threat_intel_app`, `dhcp_server`, `dns_server`
   - Applies all SQL schemas and migrations

2. **Node.js 20.11.0 LTS**
   - Required for UI Frontend (Vite dev server)
   - Required for Backend API (Express server)

3. **WinPkFilter 3.4.8**
   - Packet capture driver for SafeOps Engine

## Building the Installer

```bash
cd src/requirements_setup
go run build.go
```

This creates:
- `bin/requirements_setup/safeops-requirements-setup.exe`
- `bin/requirements_setup/config.yaml`

## Running the Installer

```bash
cd bin/requirements_setup
safeops-requirements-setup.exe
```

**IMPORTANT: Run as Administrator!**

## Configuration

Edit `config.yaml` before running to customize:
- Installation directories
- PostgreSQL passwords
- Port numbers
- Component versions

## Default Passwords

⚠️ **CHANGE THESE AFTER INSTALLATION!**

- PostgreSQL superuser: `postgres`
- SafeOps users: `admin`

## Requirements

- Windows 10/11
- Administrator privileges
- ~500 MB disk space
- Internet connection (for downloads)

## What Gets Installed Where

```
C:\Program Files\PostgreSQL\16\        # PostgreSQL installation
C:\Program Files\nodejs\               # Node.js installation
C:\Program Files\SafeOps\WinPkFilter\  # WinPkFilter driver
```

## Database Details

### threat_intel_db
- 11 schemas for threat intelligence and IOCs
- Used by Threat Intel service and Network Logger

### safeops_network
- 7 schemas for network operations
- Used by DHCP Monitor, NIC Management, Captive Portal

### safeops
- General application data
- Used by Captive Portal (fallback)

## Troubleshooting

### PostgreSQL won't start
```bash
net start postgresql-x64-16
```

### Check PostgreSQL service
```bash
sc query postgresql-x64-16
```

### Test database connection
```bash
psql -U postgres -h localhost -p 5432 -d threat_intel_db
```

### Check Node.js installation
```bash
node --version
npm --version
```

## Next Steps

After installation:

1. Change default passwords
2. Run SafeOps launcher: `bin\launcher.exe`
3. (Optional) Install SIEM: `bin\siem\safeops-siem-setup.exe`
