# SafeOps Pre-Installation Requirements

This document outlines the software and system requirements that must be installed before running the SafeOps Launcher.

---

## ⚙️ System Requirements

| Requirement | Minimum | Recommended |
|-------------|---------|-------------|
| **Operating System** | Windows 10 (64-bit) | Windows 11 (64-bit) |
| **RAM** | 4 GB | 8 GB+ |
| **Storage** | 2 GB free space | 5 GB+ |
| **CPU** | Dual-core | Quad-core+ |
| **Network** | Ethernet/WiFi adapter | Multiple NICs for hotspot |

---

## 📦 Required Software

### 1. PostgreSQL Database (Required)
The threat intelligence and device databases require PostgreSQL.

**Download:** https://www.postgresql.org/download/windows/

**Installation:**
1. Download PostgreSQL 15 or later
2. Run installer with default settings
3. Set password for `postgres` user (remember this!)
4. Default port: `5432`

**Required Databases:**
- `threat_intel_db` - Threat intelligence data
- `safeops` - Device management data

> After installation, create databases using pgAdmin or psql:
> ```sql
> CREATE DATABASE threat_intel_db;
> CREATE DATABASE safeops;
> ```

---

### 2. Node.js (Required)
Required for the backend API server and UI development server.

**Download:** https://nodejs.org/

**Version:** Node.js 18.x LTS or later

**Verify Installation:**
```powershell
node --version    # Should show v18.x.x or higher
npm --version     # Should show 9.x.x or higher
```

---

### 3. WinpkFilter Driver (Required for Packet Capture)
Required for SafeOps Engine packet capture functionality.

**Download:** https://www.ntkernel.com/windows-packet-filter/

**Installation:**
1. Download WinpkFilter SDK
2. Run installer as Administrator
3. Reboot system after installation

> ⚠️ The SafeOps Engine will not capture packets without this driver installed.

---

### 4. Visual C++ Redistributable (Required)
Required for running compiled Go and C++ executables.

**Download:** https://aka.ms/vs/17/release/vc_redist.x64.exe

---

## 🔧 Optional Software

### Git (Optional)
For cloning and updating the SafeOps repository.

**Download:** https://git-scm.com/download/win

---

### Go (Development Only)
Only required if building from source.

**Download:** https://go.dev/dl/

**Version:** Go 1.21 or later

---

## 📁 First-Time Setup

After installing all prerequisites:

### 1. Install Node Dependencies

```powershell
# Backend
cd D:\SafeOpsFV2\backend
npm install

# UI Dev
cd D:\SafeOpsFV2\src\ui\dev
npm install
```

### 2. Configure Database Credentials

Create `.env` file in `backend/` folder:
```env
DB_HOST=localhost
DB_PORT=5432
DB_USER=postgres
DB_PASSWORD=your_password_here
DB_NAME=threat_intel_db
```

### 3. Run the Launcher

```powershell
# Run as Administrator (required for packet capture)
D:\SafeOpsFV2\bin\safeops_launcher.exe
```

---

## 🌐 Ports Used

| Service | Port | Protocol |
|---------|------|----------|
| PostgreSQL | 5432 | TCP |
| Backend API | 5050 | HTTP |
| UI Frontend | 3001 | HTTP |
| Step-CA | 9000 | HTTPS |
| NIC Management | 8081 | HTTP |
| DHCP Monitor | 50055 | gRPC |
| Captive Portal | 8090/8445 | HTTP/HTTPS |

> Ensure these ports are not blocked by Windows Firewall.

---

## ✅ Pre-Flight Checklist

Before running SafeOps Launcher, verify:

- [ ] PostgreSQL installed and running
- [ ] Node.js 18+ installed
- [ ] WinpkFilter driver installed (reboot completed)
- [ ] Visual C++ Redistributable installed
- [ ] `npm install` completed in `backend/` and `src/ui/dev/`
- [ ] Databases `threat_intel_db` and `safeops` created
- [ ] `.env` file configured with database credentials
- [ ] Running as Administrator

---

## 🆘 Troubleshooting

### "Database connection failed"
- Ensure PostgreSQL service is running
- Check database credentials in `.env`
- Verify databases exist

### "Step-CA failed to start"
- This is auto-fixed by the launcher (clears corrupted DB)
- If persistent, manually delete `bin/step-ca/db/` folder

### "Packet capture not working"
- Ensure WinpkFilter driver is installed
- Must run launcher as Administrator
- Reboot after driver installation

### "npm: command not found"
- Node.js not installed or not in PATH
- Restart terminal after installing Node.js
