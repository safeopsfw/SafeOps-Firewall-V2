# SafeOps Service Startup Reference
# Run each service in a SEPARATE Admin PowerShell/CMD window
# Updated: 2026-01-05

## Prerequisites
- PostgreSQL running with `safeops` database and user configured
- Admin privileges for Packet Engine

---

## Startup Order (CRITICAL - follow this exact order!)

### 1. NIC Management (port 8081) - Core Interface Control
```powershell
cd D:\SafeOpsFV2\bin
.\nic_management.exe
```
*Initializes network interfaces and firewall rules.*

---

### 2. DHCP Monitor (port 50055) - Device Database
```powershell
cd D:\SafeOpsFV2\bin
.\dhcp_monitor.exe
```
*Maintains device inventory and trust status.*
*Requires: PostgreSQL with `safeops` database*

---

### 3. Step-CA (port 9000) - PKI/Certificate Authority
```powershell
cd D:\SafeOpsFV2\src\step-ca
.\bin\step-ca.exe .\config\ca.json --password-file .\secrets\password.txt
```
*Provides certificate issuance and root CA trust.*
*Password: SafeOpsCA2026!*

---

### 4. TLS Proxy (ports 50051/50052) - Inspection & Routing
```powershell
cd D:\SafeOpsFV2\bin
.\tls_proxy.exe
```
*Handles DNS decisions and HTTP packet interception.*

---

### 5. DNS Server (internal port 5354) - Name Resolution
```powershell
cd D:\SafeOpsFV2\bin
.\dns_server.exe
```
*Listens on internal port 5354.*
*Packet Engine intercepts port 53 and redirects here.*
*Resolves local domains and blocks ads/malware.*

---

### 6. Captive Portal (port 8444) - User Onboarding
```powershell
cd D:\SafeOpsFV2\bin
.\captive_portal.exe
```
*Serves CA certificate download page for untrusted devices.*

---

### 7. Packet Engine (LAST - Intercepts Traffic)
**⚠️ MUST BE RUN AS ADMINISTRATOR**
```powershell
cd D:\SafeOpsFV2\bin
.\packet_engine.exe
```
*Intercepts DNS (port 53 → 5354), redirects HTTP/HTTPS to TLS Proxy.*
*This activates the entire network inspection system.*

---

## Stop All Services
```powershell
Get-Process -Name "nic_management","dhcp_monitor","step-ca","tls_proxy","dns_server","captive_portal","packet_engine" -ErrorAction SilentlyContinue | Stop-Process -Force
```

---

## Service Ports Summary

| Service | Port | Protocol |
|---------|------|----------|
| NIC Management | 8081 | HTTP API |
| DHCP Monitor | 50055 | gRPC |
| Step-CA | 9000 | HTTPS |
| TLS Proxy | 50051, 50052 | gRPC |
| DNS Server | 5354 (internal) | UDP |
| Captive Portal | 8444 (HTTPS), 8080 (HTTP redirect) | HTTPS |
| Packet Engine | N/A (WinDivert) | Kernel |

---

## DNS Architecture

```
Device → DNS query to port 53
       ↓
Packet Engine (WinDivert) intercepts
       ↓ (rewrites 53 → 5354)
SafeOps DNS Server (0.0.0.0:5354)
       ↓
Response
       ↓ (rewrites 5354 → 53)
Device receives DNS response (appears from port 53)
```

*This avoids conflict with Windows DNS Client on port 53.*
