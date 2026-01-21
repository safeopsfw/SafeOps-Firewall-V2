# Step-CA (PKI) - Component Documentation

## Overview
Step-CA is an open-source Certificate Authority that provides TLS certificate management, ACME protocol support, and automated certificate issuance for the SafeOps security platform.

## Component Information

**Component Type:** Certificate Authority (PKI)
**Software:** Smallstep Step-CA
**Language:** Go
**Version:** Latest stable
**Platform:** Windows/Linux

## Files and Locations

### Binary/Executable Files
```
D:\SafeOpsFV2\bin\step-ca\bin\
├── step-ca.exe                      # CA server executable
└── step.exe                         # CLI management tool
```

### Configuration Files
```
D:\SafeOpsFV2\src\step-ca\
├── config\
│   └── ca.json                      # Main CA configuration
├── certs\
│   ├── root_ca.crt                  # Root CA certificate
│   └── intermediate_ca.crt          # Intermediate CA certificate
├── secrets\
│   └── intermediate_ca_key          # Encrypted intermediate key
└── db\                              # BadgerDB database directory
```

### Management Scripts
```
D:\SafeOpsFV2\bin\step-ca\scripts\
├── start-stepca.ps1                 # Start CA with password from DB
├── stop-stepca.ps1                  # Stop CA gracefully
├── restart-stepca.ps1               # Restart CA
├── get-password.ps1                 # Retrieve CA password from PostgreSQL
├── health-check.ps1                 # Check CA health status
├── backup-stepca.ps1                # Backup CA data
└── reinit-stepca.ps1                # Reinitialize CA (destructive)
```

## Functionality

### Core Functions

#### 1. Certificate Authority Services
- **Root CA:** Issues and manages root certificate (self-signed)
- **Intermediate CA:** Issues end-entity certificates
- **Certificate Issuance:** Automated certificate generation
- **Certificate Revocation:** CRL and OCSP support
- **Certificate Renewal:** Automatic renewal before expiry

#### 2. ACME Protocol Support
- **Automated Certificate Management:** ACME v2 protocol
- **Challenge Types:**
  - HTTP-01 (web server validation)
  - DNS-01 (DNS record validation)
  - TLS-ALPN-01 (TLS validation)
- **Wildcard Certificates:** Via DNS-01 challenge
- **Let's Encrypt Compatible:** Standard ACME implementation

#### 3. Provisioners
**JWK Provisioner (Default):**
- Name: `safeops-admin`
- Type: JSON Web Key (JWK)
- Algorithm: ES256 (ECDSA P-256)
- Encrypted with password

**Supported Provisioner Types:**
- JWK (JSON Web Key)
- OIDC (OpenID Connect)
- ACME (Automated)
- SSHPOP (SSH Proof of Possession)
- X5C (X.509 Certificate)

#### 4. Database Storage
- **Type:** BadgerDB v2 (embedded key-value store)
- **Location:** `D:\SafeOpsFV2\src\step-ca\db`
- **Stores:**
  - Issued certificates
  - Revocation lists
  - ACME challenges
  - Provisioner state

#### 5. Password Management
- **Storage:** PostgreSQL database (encrypted)
- **Retrieval:** PowerShell script (`get-password.ps1`)
- **Security:** Password file is temporary (deleted after use)
- **Environment Variable:** `STEP_CA_PASSWORD` (fallback)

## Default Ports

| Port | Protocol | Purpose |
|------|----------|---------|
| **9000** | HTTPS | CA server (certificate issuance, ACME) |

### DNS Names
The CA responds to requests on:
- `localhost`
- `safeops-ca.local`
- `192.168.137.1` (Windows Mobile Hotspot)
- `127.0.0.1`

## API Endpoints

### Certificate Authority Endpoints
```
GET  /root_ca.crt                    # Download root CA certificate
GET  /health                         # Health check endpoint
GET  /version                        # CA version information
```

### ACME Protocol Endpoints
```
GET  /acme/directory                 # ACME directory (metadata)
POST /acme/new-account               # Create ACME account
POST /acme/new-order                 # Request new certificate
POST /acme/authz/{id}                # Authorization challenge
POST /acme/challenge/{id}            # Complete challenge
POST /acme/finalize/{id}             # Finalize certificate order
POST /acme/certificate/{id}          # Download issued certificate
POST /acme/revoke-cert               # Revoke certificate
```

### Certificate Issuance (Manual)
```
POST /sign                           # Sign certificate request (CSR)
POST /renew                          # Renew existing certificate
POST /revoke                         # Revoke certificate
POST /rekey                          # Rekey certificate with new key
```

### SSH Certificate Endpoints
```
POST /ssh/sign                       # Sign SSH certificate
POST /ssh/renew                      # Renew SSH certificate
POST /ssh/revoke                     # Revoke SSH certificate
POST /ssh/config                     # Get SSH config templates
```

## Configuration

### CA Configuration (ca.json)
```json
{
  "root": "D:\\SafeOpsFV2\\src\\step-ca\\certs\\root_ca.crt",
  "crt": "D:\\SafeOpsFV2\\src\\step-ca\\certs\\intermediate_ca.crt",
  "key": "D:\\SafeOpsFV2\\src\\step-ca\\secrets\\intermediate_ca_key",
  "address": ":9000",
  "dnsNames": [
    "localhost",
    "safeops-ca.local",
    "192.168.137.1",
    "127.0.0.1"
  ],
  "logger": {
    "format": "text"
  },
  "db": {
    "type": "badgerv2",
    "dataSource": "D:\\SafeOpsFV2\\src\\step-ca\\db"
  },
  "authority": {
    "provisioners": [
      {
        "type": "JWK",
        "name": "safeops-admin",
        "key": { ... },
        "encryptedKey": "..."
      }
    ]
  },
  "tls": {
    "cipherSuites": [
      "TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256",
      "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256"
    ],
    "minVersion": 1.2,
    "maxVersion": 1.3,
    "renegotiation": false
  }
}
```

### Certificate Defaults
```json
{
  "duration": "24h",              # Default certificate validity
  "backdate": "1m",               # Backdate to account for clock skew
  "disableRenewal": false,        # Allow renewal
  "renewPeriod": "16h",           # Renew when <16h remaining
  "maxDuration": "8760h"          # 1 year max validity
}
```

## Management Scripts

### Start Step-CA
```powershell
# Start CA with password from PostgreSQL
.\bin\step-ca\scripts\start-stepca.ps1

# Start CA with manual password entry
$env:STEP_CA_PASSWORD="your-password"
.\bin\step-ca\bin\step-ca.exe config\ca.json
```

### Stop Step-CA
```powershell
# Graceful shutdown
.\bin\step-ca\scripts\stop-stepca.ps1

# Force kill
Get-Process -Name "step-ca" | Stop-Process -Force
```

### Restart Step-CA
```powershell
# Restart CA
.\bin\step-ca\scripts\restart-stepca.ps1
```

### Health Check
```powershell
# Check if CA is running and healthy
.\bin\step-ca\scripts\health-check.ps1

# Manual health check
curl https://localhost:9000/health -k
```

### Backup CA Data
```powershell
# Backup certificates and database
.\bin\step-ca\scripts\backup-stepca.ps1

# Creates timestamped backup in backup_YYYYMMDD_HHMMSS/
```

### Reinitialize CA (⚠️ Destructive)
```powershell
# Delete and recreate CA (loses all certificates!)
.\bin\step-ca\scripts\reinit-stepca.ps1
```

## CLI Tool Usage (step.exe)

### Certificate Management
```powershell
# Download root CA certificate
.\bin\step-ca\bin\step.exe ca root root_ca.crt --ca-url https://localhost:9000

# Request new certificate
.\bin\step-ca\bin\step.exe ca certificate example.com example.crt example.key

# Renew certificate
.\bin\step-ca\bin\step.exe ca renew example.crt example.key

# Revoke certificate
.\bin\step-ca\bin\step.exe ca revoke --cert example.crt
```

### Certificate Inspection
```powershell
# Inspect certificate
.\bin\step-ca\bin\step.exe certificate inspect example.crt

# Verify certificate chain
.\bin\step-ca\bin\step.exe certificate verify example.crt --roots root_ca.crt
```

### ACME Client
```powershell
# Request certificate via ACME
.\bin\step-ca\bin\step.exe ca certificate --acme example.com example.crt example.key
```

## Dependencies

### External Dependencies
- **PostgreSQL:** Password storage (retrieval via PowerShell)
- **PowerShell 5.1+:** Management scripts
- **Windows or Linux OS:** Platform support

### Internal Dependencies
- **Captive Portal:** Downloads root CA certificate from `/root_ca.crt`
- **TLS Proxy:** May use CA for certificate verification (future)

## Component Interconnections

### Architecture
```
┌─────────────────────────────────────────────────┐
│         Step-CA Certificate Authority           │
│              (HTTPS:9000)                       │
└─────────────────────────────────────────────────┘
    ↓                     ↓                   ↓
[Captive Portal]   [PostgreSQL]      [TLS Proxy]
(Download CA)      (Password)        (Future)
```

### Integration Points

**With Captive Portal:**
```
Captive Portal → GET https://localhost:9000/root_ca.crt
              ↓
       Serve CA Certificate to Device
              ↓
       Device Installs in Trust Store
```

**With PostgreSQL:**
```
get-password.ps1 → PostgreSQL Query
                 ↓
              Retrieve Encrypted Password
                 ↓
              Decrypt and Write to Temp File
                 ↓
              Step-CA Reads Password
                 ↓
              Start CA Server
```

**With TLS Proxy (Phase 3B):**
```
TLS Proxy → Request Certificate via ACME
          ↓
    Step-CA Issues Certificate
          ↓
    TLS Proxy Uses for HTTPS Interception
```

## Database Schema

### PostgreSQL Table
```sql
CREATE TABLE step_ca_config (
    id SERIAL PRIMARY KEY,
    config_key VARCHAR(255) UNIQUE NOT NULL,
    config_value TEXT NOT NULL,
    encrypted BOOLEAN DEFAULT FALSE,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Example: Password storage
INSERT INTO step_ca_config (config_key, config_value, encrypted)
VALUES ('ca_password', 'encrypted_password_here', TRUE);
```

### BadgerDB (Embedded)
- Key-value store for CA state
- No SQL schema (NoSQL)
- Stores certificates, revocation lists, ACME state

## Important Notes

### Security Considerations
- **Password Protection:** Intermediate CA key is encrypted
- **TLS Only:** CA only serves HTTPS (port 9000)
- **Strong Ciphers:** Uses ChaCha20-Poly1305 and AES-128-GCM
- **TLS 1.2/1.3:** No support for older protocols
- **No Renegotiation:** Prevents downgrade attacks

### Certificate Validity
- **Default Duration:** 24 hours
- **Max Duration:** 1 year (8760 hours)
- **Renew Period:** 16 hours before expiry
- **Backdate:** 1 minute (clock skew tolerance)

### Backup Recommendations
- **Frequency:** Daily backups via `backup-stepca.ps1`
- **Critical Data:**
  - Root CA certificate (`root_ca.crt`)
  - Intermediate CA certificate (`intermediate_ca.crt`)
  - Intermediate CA key (`intermediate_ca_key`)
  - CA password (PostgreSQL)
  - BadgerDB database directory
- **Backup Location:** `backup_YYYYMMDD_HHMMSS/`

### Disaster Recovery
```powershell
# Restore from backup
Stop-Process -Name "step-ca" -Force -ErrorAction SilentlyContinue
Remove-Item -Recurse -Force D:\SafeOpsFV2\src\step-ca\certs
Remove-Item -Recurse -Force D:\SafeOpsFV2\src\step-ca\secrets
Remove-Item -Recurse -Force D:\SafeOpsFV2\src\step-ca\db

Copy-Item -Recurse backup_20260104_212900\* D:\SafeOpsFV2\src\step-ca\

.\bin\step-ca\scripts\start-stepca.ps1
```

## Connection to Other Components

| Component | Connection Type | Purpose |
|-----------|----------------|---------|
| Captive Portal | HTTP Client | Download root CA certificate |
| PostgreSQL | Database | CA password storage and retrieval |
| TLS Proxy | ACME Client | Certificate issuance (future) |
| Web Browsers | HTTPS | Manual certificate downloads |

## Troubleshooting

### CA Won't Start
```powershell
# Check if already running
Get-Process -Name "step-ca"

# Check password retrieval
.\bin\step-ca\scripts\get-password.ps1

# Check configuration syntax
.\bin\step-ca\bin\step-ca.exe validate config\ca.json

# Check logs (console output)
```

### Cannot Download CA Certificate
```powershell
# Verify CA is running
.\bin\step-ca\scripts\health-check.ps1

# Test endpoint manually
curl https://localhost:9000/health -k
curl https://localhost:9000/root_ca.crt -k -o test_ca.crt

# Check firewall allows port 9000
```

### Certificate Validation Fails
```powershell
# Verify certificate chain
.\bin\step-ca\bin\step.exe certificate verify cert.crt --roots root_ca.crt

# Check certificate expiry
.\bin\step-ca\bin\step.exe certificate inspect cert.crt

# Check clock synchronization (NTP)
```

---

**Status:** Production Ready (Phase 3A)
**Auto-Start:** Manual or via orchestrator
**Dependencies:** PostgreSQL (password storage)
**Managed By:** PowerShell scripts
