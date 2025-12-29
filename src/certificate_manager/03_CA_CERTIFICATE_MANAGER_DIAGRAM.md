# CA Certificate Manager Component - Architecture Diagram

**File:** 03_CA_CERTIFICATE_MANAGER_DIAGRAM.md
**Component:** Certificate Manager
**Purpose:** Root CA generation, HTTP distribution, device tracking, TLS certificate signing, revocation (CRL/OCSP)

---

## 🎯 Certificate Manager Architecture

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                     CERTIFICATE MANAGER SERVICE                              │
│                     gRPC: 50060                                              │
│                     HTTP: 80 (CA distribution)                               │
│                     OCSP: 8888 (revocation)                                  │
│                     Metrics: 9160 (Prometheus)                               │
└─────────────────────────────────────────────────────────────────────────────┘
                                    │
                ┌───────────────────┼───────────────────┐
                │                   │                   │
                ▼                   ▼                   ▼
    ┌───────────────────┐  ┌───────────────────┐  ┌───────────────────┐
    │ CA GENERATION     │  │ HTTP DISTRIBUTION │  │ TLS INTEGRATION   │
    │ (Crypto)          │  │ (Port 80)         │  │ (gRPC)            │
    ├───────────────────┤  ├───────────────────┤  ├───────────────────┤
    │ • RSA 4096 Root CA│  │ • /ca.crt (PEM)   │  │ • Sign Certs      │
    │ • AES-256 Encrypt │  │ • /ca.der (DER)   │  │ • Certificate     │
    │ • 10-year validity│  │ • Install Scripts │  │   Templates       │
    │ • Auto-generated  │  │ • QR Codes        │  │ • Cache (24h)     │
    └───────────────────┘  └───────────────────┘  └───────────────────┘
                │                   │                   │
                └───────────────────┼───────────────────┘
                                    │
                                    ▼
                    ┌───────────────────────────────┐
                    │ CERTIFICATE REVOCATION        │
                    │ (CRL + OCSP)                  │
                    ├───────────────────────────────┤
                    │ • CRL Generation (24h)        │
                    │ • OCSP Responder (Port 8888)  │
                    │ • Revocation Database         │
                    │ • gRPC Revoke API             │
                    └───────────────────────────────┘
```

---

## 📊 CA Certificate Lifecycle

```
┌─────────────────────────────────────────────────────────────────────────────┐
│ PHASE 1: CA Generation (First Run)                                          │
│ Location: internal/ca/generator.go                                          │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                              │
│  Step 1: Generate RSA 4096 Key Pair                                         │
│  ┌────────────────────────────────────────┐                                 │
│  │ crypto/rsa.GenerateKey(4096)           │                                 │
│  │                                         │                                 │
│  │ Private Key: 4096-bit RSA              │                                 │
│  │ Public Key: Extracted from private     │                                 │
│  │                                         │                                 │
│  │ Security: Cryptographically random     │                                 │
│  └────────────────────────────────────────┘                                 │
│          │                                                                   │
│          ▼                                                                   │
│  Step 2: Create Self-Signed Root CA                                         │
│  ┌────────────────────────────────────────┐                                 │
│  │ X.509 Certificate:                     │                                 │
│  │                                         │                                 │
│  │ Subject:                               │                                 │
│  │   CN = SafeOps Root CA                 │                                 │
│  │   O = SafeOps Network                  │                                 │
│  │   C = US                                │                                 │
│  │                                         │                                 │
│  │ Issuer: (same as Subject - self-signed)│                                 │
│  │                                         │                                 │
│  │ Validity:                              │                                 │
│  │   Not Before: 2025-12-27 00:00:00     │                                 │
│  │   Not After:  2035-12-27 00:00:00     │                                 │
│  │   (10 years)                           │                                 │
│  │                                         │                                 │
│  │ Public Key: RSA 4096                   │                                 │
│  │ Signature Algorithm: SHA256-RSA        │                                 │
│  │ Serial Number: Random 128-bit hex      │                                 │
│  │                                         │                                 │
│  │ Extensions:                            │                                 │
│  │   BasicConstraints: CA:TRUE            │                                 │
│  │   KeyUsage: Certificate Sign, CRL Sign │                                 │
│  └────────────────────────────────────────┘                                 │
│          │                                                                   │
│          ▼                                                                   │
│  Step 3: ⭐ Encrypt Private Key (AES-256-GCM)                               │
│  ┌────────────────────────────────────────┐                                 │
│  │ Function: internal/ca/key_encryption.go│                                 │
│  │                                         │                                 │
│  │ 1. Generate passphrase (32 bytes random)│                                │
│  │ 2. Derive encryption key (PBKDF2):     │                                 │
│  │    • 100,000 iterations                │                                 │
│  │    • SHA-256 hash                      │                                 │
│  │    • Random salt (16 bytes)            │                                 │
│  │                                         │                                 │
│  │ 3. Encrypt private key (AES-256-GCM):  │                                 │
│  │    • Algorithm: AES-256 in GCM mode    │                                 │
│  │    • Authenticated encryption          │                                 │
│  │    • Nonce: Random 12 bytes            │                                 │
│  └────────────────────────────────────────┘                                 │
│          │                                                                   │
│          ▼                                                                   │
│  Step 4: Store CA Files                                                     │
│  ┌────────────────────────────────────────┐                                 │
│  │ /etc/safeops/ca/root-cert.pem          │                                 │
│  │ ├─ Public certificate (PEM)            │                                 │
│  │ ├─ Permissions: 0644 (world-readable)  │                                 │
│  │                                         │                                 │
│  │ /etc/safeops/ca/root-key.pem.enc       │                                 │
│  │ ├─ ⭐ Encrypted private key            │                                 │
│  │ ├─ Permissions: 0600 (owner-only)      │                                 │
│  │                                         │                                 │
│  │ /etc/safeops/secrets/ca_passphrase     │                                 │
│  │ ├─ ⭐ Encryption passphrase            │                                 │
│  │ ├─ Permissions: 0400 (owner read-only) │                                 │
│  │                                         │                                 │
│  │ /var/safeops/ca/crl.pem                │                                 │
│  │ ├─ ⭐ Certificate Revocation List      │                                 │
│  │ ├─ Initially empty, updated daily      │                                 │
│  └────────────────────────────────────────┘                                 │
└─────────────────────────────────────────────────────────────────────────────┘
```

---

## 🌐 HTTP Distribution Server (Port 80)

```
┌─────────────────────────────────────────────────────────────────────────────┐
│ HTTP SERVER (internal/distribution/http_server.go)                          │
│ Bind: 192.168.1.1:80                                                        │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                              │
│  User browses: http://192.168.1.1/ca.crt                                    │
│  ──────────────────────────────────────────────────────────────────────────  │
│                                                                              │
│  HTTP GET /ca.crt                                                            │
│  ┌────────────────────────────────────────┐                                 │
│  │ Handler: handlers.go                   │                                 │
│  │                                         │                                 │
│  │ 1. Read CA certificate:                │                                 │
│  │    /etc/safeops/ca/root-cert.pem       │                                 │
│  │                                         │                                 │
│  │ 2. Track download:                     │                                 │
│  │    INSERT INTO certificate_downloads   │                                 │
│  │    VALUES ('192.168.1.100', 'PEM', NOW())                               │
│  │                                         │                                 │
│  │ 3. Return HTTP response:               │                                 │
│  │    HTTP/1.1 200 OK                     │                                 │
│  │    Content-Type: application/x-x509-ca-cert                             │
│  │    Content-Disposition: attachment; filename="safeops-ca.crt"           │
│  │    Content-Length: 1456                │                                 │
│  │                                         │                                 │
│  │    -----BEGIN CERTIFICATE-----         │                                 │
│  │    MIIFazCCA1OgAwIBAgIUQk5...         │                                 │
│  │    -----END CERTIFICATE-----           │                                 │
│  └────────────────────────────────────────┘                                 │
│                                                                              │
│  Available Endpoints:                                                        │
│  ──────────────────────────────────────────────────────────────────────────  │
│                                                                              │
│  /ca.crt                   → PEM format (most common)                       │
│  /ca.der                   → DER format (Windows binary)                    │
│  /install-ca.sh            → Linux bash script                              │
│  /install-ca.ps1           → Windows PowerShell script                      │
│  /install-ca.pkg           → macOS package installer                        │
│  /install-ca.mobileconfig  → iOS/iPadOS configuration profile              │
│  /crl.pem                  → ⭐ Certificate Revocation List                 │
│  /trust-guide.html         → ⭐ Platform-specific trust instructions        │
│  /ca-qr-code.png           → ⭐ QR code for mobile device installation      │
│  /wpad.dat                 → Web Proxy Auto-Discovery configuration         │
│                                                                              │
└─────────────────────────────────────────────────────────────────────────────┘
```

**Key Files:**
- `internal/distribution/http_server.go` - HTTP server
- `internal/distribution/handlers.go` - Endpoint handlers
- `internal/distribution/format_converter.go` - PEM ↔ DER conversion
- `internal/distribution/script_generator.go` - Generate install scripts
- `internal/distribution/qr_code_generator.go` - QR code generation
- `internal/distribution/trust_instructions.go` - Platform-specific guides

---

## 🔐 Certificate Signing for TLS Proxy

```
┌─────────────────────────────────────────────────────────────────────────────┐
│ TLS Proxy calls Certificate Manager (gRPC)                                  │
└────────────────────┬────────────────────────────────────────────────────────┘
                     │
                     │ gRPC: SignCertificate("example.com")
                     │ Target: localhost:50060
                     │
                     ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│ CERTIFICATE SIGNING SERVICE                                                  │
│ Location: internal/tls_integration/signing_service.go                       │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                              │
│  Step 1: Check Cache                                                        │
│  ┌────────────────────────────────────────┐                                 │
│  │ Function: cache.go                     │                                 │
│  │ Look for: example.com                  │                                 │
│  │ TTL: 24 hours                          │                                 │
│  │                                         │                                 │
│  │ If found and valid → Return cached     │                                 │
│  │ If not found → Proceed to signing      │                                 │
│  └────────────────────────────────────────┘                                 │
│          │                                                                   │
│          ▼                                                                   │
│  Step 2: ⭐ Check Revocation Status                                         │
│  ┌────────────────────────────────────────┐                                 │
│  │ Function: revocation/revocation_checker.go                              │
│  │                                         │                                 │
│  │ Check if domain is revoked:            │                                 │
│  │ • Query revoked_certificates table     │                                 │
│  │ • Check CRL                            │                                 │
│  │                                         │                                 │
│  │ If revoked → Reject signing request    │                                 │
│  │ If not revoked → Proceed               │                                 │
│  └────────────────────────────────────────┘                                 │
│          │                                                                   │
│          ▼                                                                   │
│  Step 3: Generate Certificate                                               │
│  ┌────────────────────────────────────────┐                                 │
│  │ X.509 Certificate:                     │                                 │
│  │                                         │                                 │
│  │ Subject: CN = example.com              │                                 │
│  │ Issuer: CN = SafeOps Root CA           │                                 │
│  │                                         │                                 │
│  │ Subject Alternative Names (SAN):       │                                 │
│  │   • DNS: example.com                   │                                 │
│  │   • DNS: *.example.com (wildcard)      │                                 │
│  │                                         │                                 │
│  │ Validity: 90 days                      │                                 │
│  │ Key Usage: Digital Signature, Key Encipherment                          │
│  │ Extended Key Usage: TLS Web Server Authentication                       │
│  └────────────────────────────────────────┘                                 │
│          │                                                                   │
│          ▼                                                                   │
│  Step 4: Sign with CA Private Key                                           │
│  ┌────────────────────────────────────────┐                                 │
│  │ 1. Load encrypted CA key:              │                                 │
│  │    /etc/safeops/ca/root-key.pem.enc    │                                 │
│  │                                         │                                 │
│  │ 2. Decrypt with passphrase:            │                                 │
│  │    • Read: /etc/safeops/secrets/ca_passphrase                           │
│  │    • Decrypt: AES-256-GCM              │                                 │
│  │    • Load private key to memory        │                                 │
│  │                                         │                                 │
│  │ 3. Sign certificate:                   │                                 │
│  │    • Algorithm: SHA256-RSA             │                                 │
│  │    • Sign cert with CA private key     │                                 │
│  │                                         │                                 │
│  │ 4. Clear private key from memory       │                                 │
│  │    (security best practice)            │                                 │
│  └────────────────────────────────────────┘                                 │
│          │                                                                   │
│          ▼                                                                   │
│  Step 5: Store & Cache                                                      │
│  ┌────────────────────────────────────────┐                                 │
│  │ 1. Store in cache (24h TTL)            │                                 │
│  │                                         │                                 │
│  │ 2. Store in database:                  │                                 │
│  │    INSERT INTO issued_certificates     │                                 │
│  │    VALUES (                            │                                 │
│  │      serial_number,                    │                                 │
│  │      'example.com',                    │                                 │
│  │      '{example.com, *.example.com}',   │                                 │
│  │      NOW(),                            │                                 │
│  │      NOW() + INTERVAL '90 days',       │                                 │
│  │      'server'                          │                                 │
│  │    )                                    │                                 │
│  │                                         │                                 │
│  │ 3. ⭐ Audit log:                       │                                 │
│  │    INSERT INTO ca_audit_log            │                                 │
│  │    VALUES (NOW(), 'sign', 'example.com', serial, 'tls_proxy', TRUE)    │
│  └────────────────────────────────────────┘                                 │
│          │                                                                   │
│          ▼                                                                   │
│  Return signed certificate to TLS Proxy                                     │
└─────────────────────────────────────────────────────────────────────────────┘
```

**Key Files:**
- `internal/tls_integration/signing_service.go` - Certificate signing
- `internal/tls_integration/cache.go` - Certificate cache (24h TTL)
- `internal/tls_integration/template_manager.go` - Certificate templates
- `internal/ca/storage.go` - Load/decrypt CA private key

---

## 🚫 Certificate Revocation (CRL + OCSP)

```
┌─────────────────────────────────────────────────────────────────────────────┐
│ ⭐ CERTIFICATE REVOCATION SYSTEM                                            │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                              │
│  CRL (Certificate Revocation List) - Updated Every 24 Hours                 │
│  ──────────────────────────────────────────────────────────────────────────  │
│                                                                              │
│  Location: internal/revocation/crl_generator.go                             │
│  ┌────────────────────────────────────────┐                                 │
│  │ 1. Query revoked certificates:         │                                 │
│  │    SELECT * FROM revoked_certificates  │                                 │
│  │                                         │                                 │
│  │ 2. Generate X.509 CRL:                 │                                 │
│  │    Issuer: SafeOps Root CA             │                                 │
│  │    This Update: 2025-12-27 00:00:00   │                                 │
│  │    Next Update: 2025-12-28 00:00:00   │                                 │
│  │    Revoked Certificates:               │                                 │
│  │      • Serial: 3A:F2:E8:D1:9C:4B...    │                                 │
│  │        Revocation Date: 2025-12-26     │                                 │
│  │        Reason: compromised             │                                 │
│  │                                         │                                 │
│  │ 3. Sign CRL with CA private key        │                                 │
│  │                                         │                                 │
│  │ 4. Write to: /var/safeops/ca/crl.pem   │                                 │
│  │                                         │                                 │
│  │ 5. Serve via HTTP:                     │                                 │
│  │    http://192.168.1.1/crl.pem          │                                 │
│  └────────────────────────────────────────┘                                 │
│                                                                              │
│  OCSP (Online Certificate Status Protocol) - Real-time                      │
│  ──────────────────────────────────────────────────────────────────────────  │
│                                                                              │
│  Location: internal/revocation/ocsp_responder.go                            │
│  Port: 192.168.1.1:8888                                                     │
│  ┌────────────────────────────────────────┐                                 │
│  │ OCSP Request:                          │                                 │
│  │   POST http://192.168.1.1:8888         │                                 │
│  │   Body: DER-encoded OCSP request       │                                 │
│  │   Serial Number: 3A:F2:E8:D1:9C:4B...  │                                 │
│  │                                         │                                 │
│  │ OCSP Responder Actions:                │                                 │
│  │ 1. Parse OCSP request                  │                                 │
│  │ 2. Extract serial number               │                                 │
│  │ 3. Check revocation status:            │                                 │
│  │    SELECT * FROM revoked_certificates  │                                 │
│  │    WHERE serial_number = '...'         │                                 │
│  │                                         │                                 │
│  │ 4. Generate OCSP response:             │                                 │
│  │    • Status: good | revoked | unknown  │                                 │
│  │    • This Update: NOW()                │                                 │
│  │    • Next Update: NOW() + 1 hour       │                                 │
│  │                                         │                                 │
│  │ 5. Sign response with CA key           │                                 │
│  │                                         │                                 │
│  │ 6. Return DER-encoded response         │                                 │
│  └────────────────────────────────────────┘                                 │
│                                                                              │
│  Revocation API (gRPC)                                                       │
│  ──────────────────────────────────────────────────────────────────────────  │
│                                                                              │
│  Location: internal/grpc/revocation_rpc.go                                  │
│  ┌────────────────────────────────────────┐                                 │
│  │ RPC: RevokeCertificate()               │                                 │
│  │                                         │                                 │
│  │ Request:                               │                                 │
│  │   serial_number: "3A:F2:E8:D1:9C:4B..."│                                 │
│  │   reason: "compromised"                │                                 │
│  │   revoked_by: "admin"                  │                                 │
│  │                                         │                                 │
│  │ Actions:                               │                                 │
│  │ 1. Insert into revoked_certificates    │                                 │
│  │ 2. Update CRL immediately              │                                 │
│  │ 3. Audit log revocation                │                                 │
│  │                                         │                                 │
│  │ Response:                              │                                 │
│  │   success: true                        │                                 │
│  │   crl_updated_at: 1735293000           │                                 │
│  └────────────────────────────────────────┘                                 │
└─────────────────────────────────────────────────────────────────────────────┘
```

**Key Files:**
- `internal/revocation/crl_generator.go` - CRL generation
- `internal/revocation/crl_server.go` - Serve CRL via HTTP
- `internal/revocation/ocsp_responder.go` - OCSP implementation (RFC 6960)
- `internal/revocation/revocation_storage.go` - Revocation database
- `internal/grpc/revocation_rpc.go` - Revoke certificate RPC

---

## 🗄️ Database Schema (PostgreSQL)

```sql
-- Device CA installation status
CREATE TABLE device_ca_status (
  id SERIAL PRIMARY KEY,
  device_ip INET,                  -- 192.168.1.100
  mac_address VARCHAR(17),         -- AA:BB:CC:DD:EE:FF
  ca_installed BOOLEAN DEFAULT FALSE,
  detected_at TIMESTAMP,
  created_at TIMESTAMP DEFAULT NOW(),
  INDEX idx_device_ip (device_ip),
  INDEX idx_mac (mac_address)
);

-- Certificate download history
CREATE TABLE certificate_downloads (
  id SERIAL PRIMARY KEY,
  device_ip INET,                  -- 192.168.1.100
  format VARCHAR(10),              -- "PEM", "DER"
  timestamp TIMESTAMP DEFAULT NOW()
);

-- ⭐ Revoked certificates (CRL/OCSP)
CREATE TABLE revoked_certificates (
  id SERIAL PRIMARY KEY,
  serial_number VARCHAR(128) UNIQUE NOT NULL,
  revoked_at TIMESTAMP DEFAULT NOW(),
  revocation_reason VARCHAR(50),   -- "compromised", "superseded", "cessation_of_operation"
  certificate_common_name VARCHAR(255),
  revoked_by VARCHAR(100),         -- Admin username
  INDEX idx_serial (serial_number),
  INDEX idx_revoked_at (revoked_at)
);

-- ⭐ Issued certificates metadata
CREATE TABLE issued_certificates (
  id SERIAL PRIMARY KEY,
  serial_number VARCHAR(128) UNIQUE NOT NULL,
  common_name VARCHAR(255) NOT NULL,
  subject_alt_names TEXT[],        -- {example.com, *.example.com}
  not_before TIMESTAMP NOT NULL,
  not_after TIMESTAMP NOT NULL,
  issued_at TIMESTAMP DEFAULT NOW(),
  certificate_type VARCHAR(50),    -- "server", "client", "code_signing"
  certificate_pem TEXT,
  INDEX idx_common_name (common_name),
  INDEX idx_not_after (not_after)
);

-- ⭐ CA audit log (tamper-proof)
CREATE TABLE ca_audit_log (
  id SERIAL PRIMARY KEY,
  timestamp TIMESTAMP DEFAULT NOW(),
  operation VARCHAR(100) NOT NULL, -- "issue", "revoke", "renew", "sign"
  subject VARCHAR(255),
  serial_number VARCHAR(128),
  performed_by VARCHAR(100),
  ip_address INET,
  success BOOLEAN,
  error_message TEXT,
  prev_entry_hash VARCHAR(64),     -- ⭐ Hash chain for tamper detection
  INDEX idx_timestamp (timestamp),
  INDEX idx_operation (operation)
);

-- ⭐ CA backups
CREATE TABLE ca_backups (
  id SERIAL PRIMARY KEY,
  backup_timestamp TIMESTAMP DEFAULT NOW(),
  backup_location VARCHAR(500),
  encryption_key_fingerprint VARCHAR(64),
  backup_size_bytes BIGINT,
  backup_checksum VARCHAR(128),    -- SHA-256 checksum
  restored BOOLEAN DEFAULT FALSE
);
```

---

## 📡 gRPC API (Port 50060)

```protobuf
service CertificateManager {
  // ⭐ CA distribution (called by DHCP)
  rpc GetCertificateInfo() returns (CertificateInfo);

  // Device tracking
  rpc GetDeviceStatus(DeviceRequest) returns (DeviceStatus);

  // Certificate signing (called by TLS proxy)
  rpc SignCertificate(SignRequest) returns (Certificate);

  // ⭐ Certificate revocation
  rpc RevokeCertificate(RevokeRequest) returns (RevokeResponse);
  rpc CheckRevocationStatus(RevocationCheckRequest) returns (RevocationStatus);

  // Certificate lifecycle
  rpc ListIssuedCertificates(ListRequest) returns (CertificateList);
  rpc GetCertificateDetails(CertificateRequest) returns (CertificateDetails);
}

message CertificateInfo {
  string ca_url = 1;                    // "http://192.168.1.1/ca.crt"
  repeated string install_script_urls = 2;
  string wpad_url = 3;
  string crl_url = 4;                   // ⭐ "http://192.168.1.1/crl.pem"
  string ocsp_url = 5;                  // ⭐ "http://192.168.1.1:8888"
}
```

---

## 📊 Prometheus Metrics (Port 9160)

```
# Issued certificates
certificate_manager_certificates_issued_total 547

# Revoked certificates
certificate_manager_certificates_revoked_total 3

# CA downloads
certificate_manager_ca_downloads_total 143

# Devices with CA installed
certificate_manager_devices_with_ca_installed 138  # 96.5%

# CRL update duration
certificate_manager_crl_update_duration_seconds 0.234

# OCSP requests
certificate_manager_ocsp_requests_total 1245
certificate_manager_ocsp_good_responses_total 1242
certificate_manager_ocsp_revoked_responses_total 3

# Certificate expiry monitoring
certificate_manager_certificates_expiring_soon{days="30"} 5
certificate_manager_certificates_expiring_soon{days="7"} 1
```

---

## 📂 File Structure

```
src/certificate_manager/
├── internal/
│   ├── ca/                 # CA generation, encryption, storage
│   ├── distribution/       # HTTP server, scripts, QR codes
│   ├── device_tracking/    # TLS handshake detection
│   ├── tls_integration/    # Certificate signing for TLS proxy
│   ├── revocation/         # ⭐ CRL generation, OCSP responder
│   ├── security/           # ⭐ Key protection, audit logging, backups
│   ├── validation/         # ⭐ Chain validation, expiry monitoring
│   ├── grpc/               # gRPC service
│   ├── storage/            # PostgreSQL repositories
│   └── monitoring/         # Prometheus metrics
├── pkg/
│   ├── types/              # Core types, certificate structures
│   └── client/             # gRPC client library
├── cmd/
│   └── main.go             # Service entry point
└── tests/
    ├── ca_generation_test.go
    ├── http_server_test.go
    ├── grpc_test.go
    ├── revocation_test.go  # ⭐ CRL/OCSP tests
    ├── security_test.go    # ⭐ Encryption tests
    └── integration_test.go
```

---

**End of CA Certificate Manager Diagram**
