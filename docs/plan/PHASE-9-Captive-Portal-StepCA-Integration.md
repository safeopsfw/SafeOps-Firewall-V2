# PHASE 9: CAPTIVE PORTAL & STEP CA INTEGRATION

**Status:** 🔜 Future Phase (After Phase 8 Complete)
**Duration:** 3 weeks
**Goal:** Device authentication and certificate management via captive portal and Step CA PKI
**Deliverable:** Devices must install CA cert and authenticate before accessing network

---

## 📋 Phase Overview

**What Changes in Phase 9:**
- **Phase 8 Reality:** Domain blocking works (DNS/TLS/HTTP), but basic captive portal only shows block page
- **Phase 9 Goal:** Full device authentication workflow - untrusted devices redirected to portal, install CA cert, authenticate, become trusted
- **Integration Point:** Firewall ↔ Captive Portal ↔ Step CA ↔ Database (trust status sync)

**Existing Components (Already Built):**
- ✅ Step CA server running (port 9000) - issues certificates
- ✅ Basic captive portal (port 8082) - serves root CA download page
- ❌ No firewall integration yet (portal standalone, firewall doesn't check trust status)
- ❌ No authentication workflow (no login, no device trust management)
- ❌ No TLS interception (HTTPS traffic still encrypted, can't inspect)

**Dependencies:**
- ✅ Phase 1-7: Core firewall functionality complete
- ✅ Phase 8: Domain-based filtering active (DNS redirect capability needed)
- ✅ External: Step CA server deployed (port 9000)
- ✅ External: PostgreSQL database (store device trust status)
- ✅ External: Captive portal web server (port 8082)

---

## 🎯 Phase 9 Outcomes (What You Should See)

### After Compilation & Execution:

**Initial Startup:**
```
[INFO] Firewall Engine v9.0.0 Starting...
[INFO] Connected to SafeOps Engine (127.0.0.1:50053)
[INFO] Loaded 150 firewall rules from firewall.toml
[INFO] Domain Filtering: ENABLED
[INFO] Captive Portal Integration: ENABLED
[INFO] ├─ Portal URL: http://192.168.1.1:8082
[INFO] ├─ Step CA URL: https://ca.internal.com:9000
[INFO] ├─ Database: PostgreSQL (127.0.0.1:5432/safeops)
[INFO] ├─ Device Trust: ENABLED (query DB for trust status)
[INFO] └─ DNS Redirect: ENABLED (untrusted → portal)
[INFO] Step CA Client: INITIALIZED
[INFO] ├─ Root CA: CN=SafeOps Root CA
[INFO] ├─ Intermediate CA: CN=SafeOps Intermediate CA
[INFO] ├─ Root Fingerprint: SHA256:a1b2c3d4...
[INFO] └─ Cert Renewal: ENABLED (auto-renew 7 days before expiry)
[INFO] Firewall ready - captive portal active
```

---

### **Device Authentication Workflow (New User)**

#### Step 1: Untrusted Device Attempts Internet Access

```
# New device (192.168.1.100) tries to access google.com
# Device MAC: 00:11:22:33:44:55
# Device has no CA certificate installed

[DEBUG] DNS: Query received
[DEBUG] ├─ Domain: google.com
[DEBUG] ├─ Client: 192.168.1.100:54321
[DEBUG] └─ Client MAC: 00:11:22:33:44:55

[INFO] Device Trust Check: Querying database
[INFO] ├─ Client IP: 192.168.1.100
[INFO] ├─ Client MAC: 00:11:22:33:44:55
[INFO] ├─ Query: SELECT trusted FROM devices WHERE mac = '00:11:22:33:44:55'
[INFO] └─ Result: NOT FOUND (device unknown)

[WARN] Device Trust: UNTRUSTED (device not registered)
[INFO] ├─ Device: 192.168.1.100 (MAC: 00:11:22:33:44:55)
[INFO] ├─ Action: REDIRECT to captive portal
[INFO] └─ Original request: google.com (will be blocked)

[INFO] DNS: Injecting fake response (captive portal redirect)
[INFO] ├─ Query: google.com → ?
[INFO] ├─ Response: google.com → 192.168.1.1 (captive portal IP)
[INFO] └─ DNS response injected

[INFO] [REDIRECT] DNS 192.168.1.100:54321 -> 8.8.8.8:53 [Query: google.com] [Redirect: 192.168.1.1] [Reason: UNTRUSTED_DEVICE]

# User's browser receives: google.com = 192.168.1.1
# Browser navigates to: http://192.168.1.1:8082
# Result: Captive portal page shown
```

---

#### Step 2: Captive Portal Landing Page

**User sees in browser:**
```
URL: http://google.com (redirected to 192.168.1.1:8082)

╔════════════════════════════════════════════════════════════╗
║                     🔐 SafeOps Network                    ║
║                  Device Authentication Required            ║
╚════════════════════════════════════════════════════════════╝

Welcome to the SafeOps Network!

Your device is not yet trusted. To access the internet, you must:
1. Install the SafeOps Root CA certificate
2. Authenticate with your credentials
3. Wait for administrator approval (if required)

┌────────────────────────────────────────────────────────────┐
│ Device Information                                         │
├────────────────────────────────────────────────────────────┤
│ IP Address:     192.168.1.100                              │
│ MAC Address:    00:11:22:33:44:55                          │
│ Hostname:       JOHNS-LAPTOP                               │
│ User Agent:     Chrome/120.0 (Windows 10)                  │
│ Status:         🔴 UNTRUSTED                               │
└────────────────────────────────────────────────────────────┘

[📥 Step 1: Download CA Certificate]  [🔑 Step 2: Login / Register]
```

**Firewall logs during portal access:**
```
[INFO] Captive Portal: Access detected
[INFO] ├─ Client: 192.168.1.100 (MAC: 00:11:22:33:44:55)
[INFO] ├─ URL: http://192.168.1.1:8082/
[INFO] ├─ User-Agent: Chrome/120.0 (Windows 10)
[INFO] └─ Action: ALLOW (portal traffic always allowed)

[INFO] Firewall Rule: Captive Portal Bypass
[INFO] ├─ Rule: Allow_Captive_Portal_Traffic
[INFO] ├─ Source: 192.168.1.100
[INFO] ├─ Destination: 192.168.1.1:8082 (captive portal)
[INFO] └─ Verdict: ALLOW (portal must be accessible to untrusted devices)

[INFO] Firewall Rule: Step CA Access
[INFO] ├─ Rule: Allow_StepCA_Traffic
[INFO] ├─ Source: 192.168.1.100
[INFO] ├─ Destination: ca.internal.com:9000 (Step CA)
[INFO] └─ Verdict: ALLOW (CA cert download must work for untrusted devices)
```

---

#### Step 3: User Downloads CA Certificate

**User clicks "Download CA Certificate"**

```
[INFO] Captive Portal: CA cert download requested
[INFO] ├─ Client: 192.168.1.100
[INFO] ├─ Request: GET /download-ca-cert
[INFO] └─ Action: Fetch from Step CA

[INFO] Step CA Client: Fetching root CA certificate
[INFO] ├─ URL: https://ca.internal.com:9000/roots.pem
[INFO] ├─ Method: GET
[INFO] └─ TLS: Skip verify (bootstrapping trust)

[DEBUG] Step CA: HTTP Request
[DEBUG] GET /roots.pem HTTP/1.1
[DEBUG] Host: ca.internal.com:9000
[DEBUG] User-Agent: SafeOps-Firewall/9.0.0

[DEBUG] Step CA: HTTP Response
[DEBUG] HTTP/1.1 200 OK
[DEBUG] Content-Type: application/x-pem-file
[DEBUG] Content-Length: 1456
[DEBUG]
[DEBUG] -----BEGIN CERTIFICATE-----
[DEBUG] MIIDXTCCAkWgAwIBAgIQX2VjVB... (truncated)
[DEBUG] -----END CERTIFICATE-----

[INFO] Step CA: Root CA certificate retrieved
[INFO] ├─ Subject: CN=SafeOps Root CA, O=SafeOps, C=US
[INFO] ├─ Issuer: CN=SafeOps Root CA (self-signed)
[INFO] ├─ Valid From: 2025-01-01 00:00:00
[INFO] ├─ Valid Until: 2035-01-01 00:00:00 (10 years)
[INFO] ├─ Serial: X2VjVB...
[INFO] ├─ Fingerprint: SHA256:a1b2c3d4e5f6...
[INFO] └─ Key: RSA 4096-bit

[INFO] Captive Portal: Serving CA certificate to client
[INFO] ├─ Client: 192.168.1.100
[INFO] ├─ Filename: safeops-root-ca.crt
[INFO] ├─ Content-Type: application/x-x509-ca-cert
[INFO] └─ Content-Disposition: attachment; filename="safeops-root-ca.crt"

[INFO] Captive Portal: CA cert download complete
[INFO] └─ Client: 192.168.1.100

# User's browser downloads: safeops-root-ca.crt (saved to Downloads folder)
```

**Portal shows installation instructions:**
```
╔════════════════════════════════════════════════════════════╗
║            ✅ Certificate Downloaded Successfully          ║
╚════════════════════════════════════════════════════════════╝

File saved: safeops-root-ca.crt

Now install the certificate on your device:

┌────────────────────────────────────────────────────────────┐
│ 🪟 Windows Installation                                    │
├────────────────────────────────────────────────────────────┤
│ 1. Open the downloaded file: safeops-root-ca.crt          │
│ 2. Click "Install Certificate"                            │
│ 3. Select "Local Machine" (requires admin) or "Current User"│
│ 4. Choose "Place all certificates in the following store" │
│ 5. Browse → Select "Trusted Root Certification Authorities"│
│ 6. Click "Next" → "Finish"                                │
│ 7. Accept security warning: "Yes"                         │
│ 8. You should see: "The import was successful"            │
└────────────────────────────────────────────────────────────┘

┌────────────────────────────────────────────────────────────┐
│ 🍎 macOS Installation                                      │
├────────────────────────────────────────────────────────────┤
│ 1. Open the downloaded file: safeops-root-ca.crt          │
│ 2. Keychain Access opens automatically                    │
│ 3. Enter your password to add to System keychain          │
│ 4. Find "SafeOps Root CA" in Keychain Access              │
│ 5. Double-click → Expand "Trust" section                  │
│ 6. Set "When using this certificate" to "Always Trust"    │
│ 7. Close window → Enter password to save changes          │
└────────────────────────────────────────────────────────────┘

┌────────────────────────────────────────────────────────────┐
│ 🐧 Linux Installation (Ubuntu/Debian)                     │
├────────────────────────────────────────────────────────────┤
│ Run these commands in terminal:                           │
│                                                            │
│ sudo cp safeops-root-ca.crt /usr/local/share/ca-certificates/
│ sudo update-ca-certificates                               │
│                                                            │
│ You should see: "1 added, 0 removed"                      │
└────────────────────────────────────────────────────────────┘

After installation, click [✓ I've Installed the Certificate]
```

---

#### Step 4: User Installs Certificate (OS-Specific)

**Windows Certificate Installation:**
```
# User double-clicks safeops-root-ca.crt
# Windows Certificate Import Wizard opens

Certificate Information
  Issued to: SafeOps Root CA
  Issued by: SafeOps Root CA
  Valid from: 01/01/2025 to 01/01/2035

[Install Certificate]

Certificate Import Wizard
  Store Location:
    ○ Current User
    ● Local Machine (requires administrator privileges)

  [Next]

Certificate Store:
  ● Place all certificates in the following store:
    Certificate store: Trusted Root Certification Authorities

  [Browse...] [Next]

Completing the Certificate Import Wizard
  You are about to import the following certificate:
    SafeOps Root CA
    Thumbprint (sha1): a1 b2 c3 d4 e5...

  [Finish]

Security Warning
  You are about to install a certificate from a certification authority
  (CA) claiming to represent:
    SafeOps Root CA

  Do you want to install this certificate?

  [Yes] [No]

# User clicks [Yes]

The import was successful.
[OK]

# Certificate now installed in Windows Trust Store
```

---

#### Step 5: Portal Verifies Certificate Installation

**User clicks "I've Installed the Certificate"**

```
[INFO] Captive Portal: Cert verification requested
[INFO] ├─ Client: 192.168.1.100
[INFO] ├─ Request: POST /verify-cert-installation
[INFO] └─ Action: Test TLS connection with client

[INFO] Certificate Verification: Testing TLS handshake
[INFO] ├─ Client: 192.168.1.100
[INFO] ├─ Method: Redirect to HTTPS test URL
[INFO] └─ Test URL: https://verify.safeops.internal:8443/test

[DEBUG] DNS: Injecting response for verify.safeops.internal
[DEBUG] ├─ Domain: verify.safeops.internal
[DEBUG] ├─ Response IP: 192.168.1.1 (captive portal)
[DEBUG] └─ Purpose: Test HTTPS connection to verify cert trust

# User's browser redirected to: https://verify.safeops.internal:8443/test
# Browser attempts HTTPS connection to 192.168.1.1:8443

[INFO] TLS Server: Client connection received
[INFO] ├─ Client: 192.168.1.100:54400
[INFO] ├─ SNI: verify.safeops.internal
[INFO] └─ Action: Present certificate signed by SafeOps Root CA

[DEBUG] TLS: Presenting server certificate
[DEBUG] ├─ Subject: CN=verify.safeops.internal
[DEBUG] ├─ Issuer: CN=SafeOps Intermediate CA
[DEBUG] ├─ Chain: verify.safeops.internal → Intermediate CA → Root CA
[DEBUG] └─ Signature: RSA-SHA256

[INFO] TLS Handshake: SUCCESS
[INFO] ├─ Client: 192.168.1.100
[INFO] ├─ Protocol: TLS 1.3
[INFO] ├─ Cipher: TLS_AES_128_GCM_SHA256
[INFO] └─ Result: Client trusts certificate (no browser warning)

[INFO] Certificate Verification: PASSED
[INFO] ├─ Client: 192.168.1.100
[INFO] ├─ Root CA: TRUSTED (client accepted cert)
[INFO] ├─ Timestamp: 2026-01-22 10:35:20
[INFO] └─ Next Step: User authentication

[INFO] Database: Updating device trust status
[INFO] ├─ MAC: 00:11:22:33:44:55
[INFO] ├─ IP: 192.168.1.100
[INFO] ├─ Field: cert_installed = TRUE
[INFO] ├─ Field: cert_install_time = 2026-01-22 10:35:20
[INFO] └─ Query: UPDATE devices SET cert_installed = TRUE, cert_install_time = NOW() WHERE mac = '00:11:22:33:44:55'
```

**If certificate NOT installed (browser shows warning):**
```
[WARN] TLS Handshake: FAILED
[WARN] ├─ Client: 192.168.1.100
[WARN] ├─ Error: Client rejected certificate (untrusted root CA)
[WARN] └─ Result: Certificate NOT installed or not trusted

[INFO] Certificate Verification: FAILED
[INFO] ├─ Client: 192.168.1.100
[INFO] ├─ Root CA: NOT TRUSTED
[INFO] └─ Action: Show error message to user

# Portal shows:
❌ Certificate Not Detected

The SafeOps Root CA certificate is not yet trusted by your browser.
Please ensure you:
1. Installed the certificate in the correct store (Trusted Root CAs)
2. Restarted your browser after installation
3. Followed the OS-specific instructions above

[Try Again] [View Installation Guide]
```

---

**⚠️ IMPORTANT NOTE: Certificate Installation is OPTIONAL for Basic Internet Access**

```
User Journey Options:

Option A: Install Certificate (Recommended)
├─ 1. Download CA cert
├─ 2. Install cert in OS trust store
├─ 3. Verify installation (HTTPS test)
├─ 4. Login/Register
├─ 5. Device trusted → Full internet access
└─ Benefit: HTTPS traffic can be inspected (TLS interception works)

Option B: Skip Certificate (Basic Access)
├─ 1. Skip certificate download
├─ 2. Login/Register directly
├─ 3. Device trusted → Full internet access
└─ Limitation: HTTPS traffic encrypted (TLS interception fails)

Key Point:
- Certificate installation enables TLS interception (HTTPS inspection)
- WITHOUT certificate: User still gets internet, but firewall cannot inspect HTTPS
- WITH certificate: User gets internet + firewall can decrypt/inspect HTTPS traffic
```

**Portal Flow (with skip option):**
```
┌──────────────────────────────────────────────────────┐
│  Step 1: Download CA Certificate (OPTIONAL)         │
├──────────────────────────────────────────────────────┤
│  [📥 Download Certificate]  [⏭️ Skip (Not Recommended)]│
└──────────────────────────────────────────────────────┘
         │                              │
         ↓ (install cert)               ↓ (skip)
┌────────────────────┐          ┌─────────────────────┐
│ Step 2: Verify     │          │  Warning:           │
│ Installation       │          │  Without cert,      │
│ (HTTPS test)       │          │  HTTPS inspection   │
└─────────┬──────────┘          │  disabled           │
          │                     └──────────┬──────────┘
          │                                │
          └────────────┬───────────────────┘
                       ↓
              ┌────────────────────┐
              │ Step 3: Login      │
              └─────────┬──────────┘
                        ↓
              ┌────────────────────┐
              │ Device Trusted     │
              │ Internet Access: ✅│
              │ HTTPS Inspection:  │
              │  - With cert: ✅   │
              │  - Without cert: ❌│
              └────────────────────┘
```

---

#### Step 6: User Authentication

**After certificate verification, portal shows login page:**
```
╔════════════════════════════════════════════════════════════╗
║               ✅ Certificate Verified                      ║
║                  Now Authenticate                          ║
╚════════════════════════════════════════════════════════════╝

Your device trusts the SafeOps Root CA.
Now log in to complete device registration.

┌────────────────────────────────────────────────────────────┐
│ 🔑 Login / Register                                        │
├────────────────────────────────────────────────────────────┤
│                                                            │
│  Username:  [________________]                             │
│  Password:  [________________]                             │
│                                                            │
│  [🔐 Login]  [📝 Create Account]                          │
│                                                            │
│  Forgot password? | Need help?                            │
└────────────────────────────────────────────────────────────┘

🔐 Security Notice:
This login will register your device (MAC: 00:11:22:33:44:55) and
associate it with your user account. Future connections from this
device will be automatically trusted.
```

**User enters credentials and clicks Login:**
```
[INFO] Captive Portal: Authentication request
[INFO] ├─ Client: 192.168.1.100
[INFO] ├─ MAC: 00:11:22:33:44:55
[INFO] ├─ Username: john.doe
[INFO] └─ Request: POST /auth/login

[DEBUG] Authentication: Validating credentials
[DEBUG] ├─ Username: john.doe
[DEBUG] ├─ Password: ******** (hashed: bcrypt)
[DEBUG] └─ Query: SELECT id, password_hash, role FROM users WHERE username = 'john.doe'

[INFO] Database: User found
[INFO] ├─ User ID: 1234
[INFO] ├─ Username: john.doe
[INFO] ├─ Role: employee
[INFO] └─ Password hash: $2a$10$N9qo8...

[DEBUG] Password verification: bcrypt.CompareHashAndPassword()
[DEBUG] ├─ Input: ******** → hash: $2a$10$...
[DEBUG] ├─ Stored hash: $2a$10$N9qo8...
[DEBUG] └─ Result: MATCH

[INFO] Authentication: SUCCESS
[INFO] ├─ User: john.doe (ID: 1234)
[INFO] ├─ Role: employee
[INFO] └─ Timestamp: 2026-01-22 10:36:00

[INFO] Device Registration: Linking device to user
[INFO] ├─ MAC: 00:11:22:33:44:55
[INFO] ├─ IP: 192.168.1.100
[INFO] ├─ User ID: 1234 (john.doe)
[INFO] ├─ Hostname: JOHNS-LAPTOP
[INFO] ├─ OS: Windows 10
[INFO] └─ Browser: Chrome/120.0

[INFO] Database: Inserting/updating device record
[INFO] Query:
INSERT INTO devices (mac, ip, user_id, hostname, os, browser, cert_installed, trusted, first_seen, last_seen)
VALUES ('00:11:22:33:44:55', '192.168.1.100', 1234, 'JOHNS-LAPTOP', 'Windows 10', 'Chrome/120.0', TRUE, TRUE, NOW(), NOW())
ON CONFLICT (mac) DO UPDATE
SET ip = EXCLUDED.ip, user_id = EXCLUDED.user_id, trusted = TRUE, last_seen = NOW()

[INFO] Device Trust: GRANTED
[INFO] ├─ MAC: 00:11:22:33:44:55
[INFO] ├─ User: john.doe
[INFO] ├─ Status: TRUSTED (full network access)
[INFO] └─ Timestamp: 2026-01-22 10:36:01

[INFO] Session: Creating authentication token
[INFO] ├─ User: john.doe
[INFO] ├─ Device MAC: 00:11:22:33:44:55
[INFO] ├─ Token: JWT (expires in 30 days)
[INFO] ├─ Claims: {user_id: 1234, mac: "00:11:22:33:44:55", role: "employee"}
[INFO] └─ Signed with: HS256 (secret key)

[INFO] Captive Portal: Redirecting to success page
[INFO] └─ URL: /auth/success
```

---

#### Step 7: Device Now Trusted (Success Page)

**Portal shows success page:**
```
╔════════════════════════════════════════════════════════════╗
║               ✅ Device Authenticated Successfully         ║
╚════════════════════════════════════════════════════════════╝

Welcome, john.doe!

Your device is now trusted and has full network access.

┌────────────────────────────────────────────────────────────┐
│ Device Status                                              │
├────────────────────────────────────────────────────────────┤
│ Status:          ✅ TRUSTED                                │
│ User:            john.doe                                  │
│ Device:          JOHNS-LAPTOP                              │
│ MAC Address:     00:11:22:33:44:55                         │
│ IP Address:      192.168.1.100                             │
│ Certificate:     ✅ Installed & Verified                   │
│ Authenticated:   2026-01-22 10:36:01                       │
│ Session Expires: 2026-02-21 10:36:01 (30 days)            │
└────────────────────────────────────────────────────────────┘

You can now close this window and browse normally.

[🌐 Start Browsing] [📊 View My Devices] [⚙️ Settings] [🚪 Logout]
```

---

#### Step 8: Trusted Device Accesses Internet

**User tries to access google.com again (now trusted):**
```
[DEBUG] DNS: Query received
[DEBUG] ├─ Domain: google.com
[DEBUG] ├─ Client: 192.168.1.100:54500
[DEBUG] └─ Client MAC: 00:11:22:33:44:55

[INFO] Device Trust Check: Querying database
[INFO] ├─ Client IP: 192.168.1.100
[INFO] ├─ Client MAC: 00:11:22:33:44:55
[INFO] ├─ Query: SELECT trusted, user_id FROM devices WHERE mac = '00:11:22:33:44:55'
[INFO] └─ Result: FOUND

[INFO] Device Trust: TRUSTED
[INFO] ├─ Device: 192.168.1.100 (MAC: 00:11:22:33:44:55)
[INFO] ├─ User: john.doe (ID: 1234)
[INFO] ├─ Status: TRUSTED (cert_installed=TRUE, authenticated=TRUE)
[INFO] ├─ Action: ALLOW (forward DNS query to real DNS server)
[INFO] └─ No captive portal redirect needed

[INFO] [ALLOW] DNS 192.168.1.100:54500 -> 8.8.8.8:53 [Query: google.com] [User: john.doe] [Action: FORWARD]

[DEBUG] DNS: Query forwarded to upstream DNS
[DEBUG] ├─ Upstream: 8.8.8.8:53
[DEBUG] ├─ Query: google.com (A record)
[DEBUG] └─ Response: google.com = 142.250.185.46

[INFO] DNS: Response forwarded to client
[INFO] ├─ Client: 192.168.1.100
[INFO] └─ Answer: google.com = 142.250.185.46

# User's browser receives real DNS response
# Browser connects to 142.250.185.46 (Google)
# Result: Google.com loads successfully! 🎉
```

---

### **TLS Interception (HTTPS Inspection)**

#### When Trusted Device Accesses HTTPS Site:

```
# User (trusted) accesses: https://example.com
# Firewall performs TLS interception (decrypt-inspect-re-encrypt)

[DEBUG] TCP: Connection established
[DEBUG] ├─ Client: 192.168.1.100:54600
[DEBUG] ├─ Server: 93.184.216.34:443 (example.com)
[DEBUG] └─ Protocol: TCP

[DEBUG] TLS: ClientHello received (from client)
[DEBUG] ├─ SNI: example.com
[DEBUG] ├─ TLS Version: 1.3
[DEBUG] └─ Cipher Suites: [TLS_AES_128_GCM_SHA256, ...]

[INFO] Device Trust Check: Client is TRUSTED
[INFO] ├─ Client: 192.168.1.100 (john.doe)
[INFO] ├─ Action: TLS INTERCEPTION (decrypt and inspect)
[INFO] └─ Reason: Trusted devices subject to content inspection

[INFO] TLS Interception: Generating MITM certificate
[INFO] ├─ Original server: example.com
[INFO] ├─ Original cert: CN=example.com, O=Internet Corporation for Assigned Names and Numbers
[INFO] ├─ Action: Generate fake cert matching original
[INFO] └─ Fake cert will be signed by SafeOps Intermediate CA

[DEBUG] Step CA: Requesting certificate for example.com
[DEBUG] ├─ URL: https://ca.internal.com:9000/sign
[DEBUG] ├─ CSR: Generated on-the-fly (RSA 2048-bit)
[DEBUG] ├─ Subject: CN=example.com
[DEBUG] └─ SANs: example.com, www.example.com

POST /sign HTTP/1.1
Host: ca.internal.com:9000
Content-Type: application/json
Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...

{
  "csr": "-----BEGIN CERTIFICATE REQUEST-----\nMIIC...",
  "ott": "one-time-token-for-auth"
}

[DEBUG] Step CA: Response
HTTP/1.1 201 Created
Content-Type: application/json

{
  "crt": "-----BEGIN CERTIFICATE-----\nMIID...",
  "ca": "-----BEGIN CERTIFICATE-----\nMIID...",
  "certChain": ["-----BEGIN CERTIFICATE-----\n..."]
}

[INFO] Step CA: Certificate issued
[INFO] ├─ Subject: CN=example.com
[INFO] ├─ Issuer: CN=SafeOps Intermediate CA
[INFO] ├─ Serial: 0x1a2b3c4d5e6f
[INFO] ├─ Valid: 2026-01-22 10:40:00 to 2026-02-21 10:40:00 (30 days)
[INFO] └─ Fingerprint: SHA256:f1e2d3c4...

[INFO] TLS Interception: Certificate ready
[INFO] ├─ Certificate: CN=example.com (signed by SafeOps)
[INFO] ├─ Chain: example.com → Intermediate CA → Root CA
[INFO] └─ Client will trust (Root CA installed earlier)

[INFO] TLS: Establishing two connections
[INFO] ├─ Client ↔ Firewall: TLS 1.3 (fake cert for example.com)
[INFO] └─ Firewall ↔ Server: TLS 1.3 (real cert from example.com)

[DEBUG] TLS: Client-side handshake (Firewall ← Client)
[DEBUG] ├─ ServerHello: TLS 1.3, TLS_AES_128_GCM_SHA256
[DEBUG] ├─ Certificate: CN=example.com (FAKE, signed by SafeOps)
[DEBUG] ├─ CertificateVerify: Signature with fake private key
[DEBUG] └─ Finished

[INFO] TLS: Client-side connection established
[INFO] ├─ Client: 192.168.1.100
[INFO] ├─ Firewall: Acts as example.com (MITM)
[INFO] └─ Client trusts certificate (Root CA installed)

[DEBUG] TLS: Server-side handshake (Firewall → Server)
[DEBUG] ├─ ClientHello: TLS 1.3 (firewall acts as client)
[DEBUG] ├─ SNI: example.com
[DEBUG] └─ Connecting to: 93.184.216.34:443

[DEBUG] TLS: Server-side response
[DEBUG] ├─ ServerHello: TLS 1.3
[DEBUG] ├─ Certificate: CN=example.com (REAL cert from server)
[DEBUG] ├─ Verify: Check against OS trust store → TRUSTED
[DEBUG] └─ Finished

[INFO] TLS: Server-side connection established
[INFO] ├─ Firewall: Acts as client to example.com
[INFO] ├─ Server: 93.184.216.34:443 (example.com)
[INFO] └─ Certificate verified: example.com (legitimate)

[INFO] TLS Interception: ACTIVE
[INFO] ├─ Client → Firewall: ENCRYPTED (client thinks it's talking to example.com)
[INFO] ├─ Firewall: DECRYPTS traffic (plaintext visible)
[INFO] ├─ Firewall: INSPECTS content (DPI, malware scan, policy check)
[INFO] ├─ Firewall: RE-ENCRYPTS traffic
[INFO] └─ Firewall → Server: ENCRYPTED (server sees legitimate client)

# Now firewall can inspect HTTPS traffic!

[DEBUG] HTTP: Decrypted request (Client → Firewall → Server)
GET / HTTP/1.1
Host: example.com
User-Agent: Chrome/120.0
Accept: text/html,...

[INFO] Content Inspection: Analyzing HTTP request
[INFO] ├─ Method: GET
[INFO] ├─ Path: /
[INFO] ├─ Host: example.com
[INFO] ├─ User: john.doe (192.168.1.100)
[INFO] └─ Policy Check: ALLOW (no violations)

[DEBUG] HTTP: Decrypted response (Server → Firewall → Client)
HTTP/1.1 200 OK
Content-Type: text/html
Content-Length: 1256

<!DOCTYPE html>
<html>
<head><title>Example Domain</title></head>
<body><h1>Example Domain</h1>...</body>
</html>

[INFO] Content Inspection: Analyzing HTTP response
[INFO] ├─ Status: 200 OK
[INFO] ├─ Content-Type: text/html
[INFO] ├─ Size: 1256 bytes
[INFO] ├─ Malware Scan: CLEAN (no threats detected)
[INFO] ├─ DLP Check: PASS (no sensitive data leaked)
[INFO] └─ Policy Check: ALLOW

[INFO] [ALLOW] HTTPS 192.168.1.100:54600 -> 93.184.216.34:443 [SNI: example.com] [User: john.doe] [Inspected: YES] [Verdict: CLEAN]

# Traffic forwarded to client
# User sees: https://example.com loads normally (no indication of interception)
```

---

### **Certificate Pinning Detection**

**If app uses certificate pinning (blocks MITM):**
```
# User opens mobile app that pins certificate (e.g., banking app)
# App expects exact certificate from bank.com server

[DEBUG] TLS: ClientHello received (from mobile app)
[DEBUG] ├─ Client: 192.168.1.100:54700
[DEBUG] ├─ SNI: api.bank.com
[DEBUG] └─ App: Banking App v2.5.0

[INFO] TLS Interception: Generating MITM certificate
[INFO] ├─ Domain: api.bank.com
[INFO] └─ Certificate: CN=api.bank.com (signed by SafeOps)

[DEBUG] TLS: Presenting fake certificate to client
[DEBUG] ├─ Certificate: CN=api.bank.com (SafeOps-signed)
[DEBUG] └─ Expected by app: CN=api.bank.com (DigiCert-signed)

[WARN] TLS: Client rejected certificate
[WARN] ├─ Reason: Certificate pinning violation
[WARN] ├─ App expected fingerprint: SHA256:a1b2c3d4... (DigiCert)
[WARN] ├─ Firewall presented fingerprint: SHA256:f1e2d3c4... (SafeOps)
[WARN] └─ App closes connection (TLS error)

[INFO] Certificate Pinning: DETECTED
[INFO] ├─ App: Banking App v2.5.0
[INFO] ├─ Domain: api.bank.com
[INFO] ├─ Action: BYPASS interception (allow direct connection)
[INFO] └─ Reason: Pinning prevents MITM (user experience > inspection)

[INFO] TLS: Switching to passthrough mode
[INFO] ├─ Client ↔ Server: Direct connection (no interception)
[INFO] ├─ Traffic: ENCRYPTED (firewall cannot inspect)
[INFO] └─ Reason: Avoid breaking legitimate app

[INFO] [ALLOW] HTTPS 192.168.1.100:54700 -> api.bank.com:443 [SNI: api.bank.com] [Inspected: NO] [Reason: CERT_PINNING] [Verdict: PASSTHROUGH]

# App connects directly to bank server (no interception)
# App works normally (no certificate error)
```

**Firewall maintains pinning whitelist:**
```
Certificate Pinning Whitelist:
├─ api.bank.com (Banking App)
├─ graph.facebook.com (Facebook App)
├─ android.googleapis.com (Google Play Services)
├─ api.twitter.com (Twitter App)
└─ *.apple.com (Apple services)

Action for pinned domains:
├─ Bypass TLS interception (passthrough)
├─ Log connection (visibility)
└─ No content inspection (encrypted)

Trade-off:
├─ User experience: Apps work without errors
├─ Security: Cannot inspect pinned traffic (blind spot)
└─ Balance: Most web traffic inspected, critical apps work
```

---

### **Certificate Renewal (Automated)**

**7 days before MITM certificate expiry:**
```
[INFO] Certificate Monitor: Scanning certificates
[INFO] ├─ Total certificates: 1,245 (cached MITM certs)
[INFO] ├─ Expiring soon (<7 days): 15
[INFO] └─ Expired: 3 (will be removed from cache)

[INFO] Certificate Renewal: Starting renewal process
[INFO] ├─ Certificates to renew: 15
[INFO] └─ Method: Request new certs from Step CA

[DEBUG] Certificate Renewal: example.com
[DEBUG] ├─ Current cert expires: 2026-01-29 10:40:00
[DEBUG] ├─ Days remaining: 6
[DEBUG] └─ Action: Request renewal from Step CA

[DEBUG] Step CA: Certificate renewal request
POST /renew HTTP/1.1
Host: ca.internal.com:9000
Content-Type: application/json
Authorization: Bearer eyJ...

{
  "csr": "-----BEGIN CERTIFICATE REQUEST-----\n...",
  "ott": "renewal-token"
}

[INFO] Step CA: Certificate renewed
[INFO] ├─ Domain: example.com
[INFO] ├─ New cert expires: 2026-02-28 10:40:00 (30 days)
[INFO] ├─ Serial: 0x2b3c4d5e6f7a
[INFO] └─ Action: Update cache

[INFO] Certificate Cache: Updated
[INFO] ├─ Domain: example.com
[INFO] ├─ Old cert removed (expired)
[INFO] ├─ New cert added
[INFO] └─ Cache size: 1,243 certificates (2 removed, 15 renewed)

[INFO] Certificate Renewal: Complete
[INFO] ├─ Renewed: 15
[INFO] ├─ Failed: 0
[INFO] └─ Duration: 1.2 seconds
```

---

## 🏗️ Phase 9 Architecture

### **Overall System Architecture:**

```
┌─────────────────────────────────────────────────────────────┐
│                      Internet                                │
└────────────────────────────┬────────────────────────────────┘
                             │
                             │ (All traffic flows through firewall)
                             ↓
              ┌──────────────────────────────┐
              │   Firewall Engine (Go)       │
              │                              │
              │  ┌────────────────────────┐  │
              │  │ Device Trust Checker   │  │
              │  │ Query: Is MAC trusted? │  │
              │  └───────────┬────────────┘  │
              │              │                │
              │              ↓                │
              │    ┌─────────────────────┐   │
              │    │  PostgreSQL DB      │   │
              │    │  devices table:     │   │
              │    │  - mac (PK)         │   │
              │    │  - trusted (bool)   │   │
              │    │  - user_id          │   │
              │    │  - cert_installed   │   │
              │    └─────────────────────┘   │
              │              │                │
              │              ↓                │
              │    If trusted: ALLOW         │
              │    If untrusted: REDIRECT    │
              │              │                │
              └──────────────┼────────────────┘
                             │
           ┌─────────────────┼─────────────────┐
           │                 │                 │
     (Trusted)          (Untrusted)            │
           │                 │                 │
           │                 ↓                 │
           │    ┌─────────────────────────┐   │
           │    │  DNS Redirect           │   │
           │    │  domain → 192.168.1.1   │   │
           │    └────────────┬────────────┘   │
           │                 │                 │
           │                 ↓                 │
           │    ┌─────────────────────────────┐
           │    │  Captive Portal (Go/React)  │
           │    │  Port: 8082                 │
           │    │                             │
           │    │  1. Show landing page       │
           │    │  2. Download CA cert        │
           │    │  3. Verify installation     │
           │    │  4. User authentication     │
           │    │  5. Device registration     │
           │    └────────────┬────────────────┘
           │                 │                 │
           │                 │ (Get CA cert)   │
           │                 ↓                 │
           │    ┌─────────────────────────────┐
           │    │  Step CA (PKI Server)       │
           │    │  Port: 9000                 │
           │    │                             │
           │    │  - Issue root CA cert       │
           │    │  - Issue MITM certs         │
           │    │  - Certificate renewal      │
           │    │  - Revocation checking      │
           │    └─────────────────────────────┘
           │                                    │
           ↓                                    │
    ┌──────────────────────────────────────────┘
    │  TLS Interception Pipeline
    │  (Decrypt-Inspect-Re-encrypt)
    │
    │  Client ←(TLS)→ Firewall ←(TLS)→ Server
    │         (fake cert)      (real cert)
    │
    │  Content Inspection:
    │  - HTTP request/response
    │  - Malware scanning
    │  - DLP (Data Loss Prevention)
    │  - Policy enforcement
    └─────────────────────────────────────────┘
```

---

### **Device Trust State Machine:**

```
                         START
                           ↓
                    [Unknown Device]
                           ↓
                  DNS query intercepted
                           ↓
                  Query DB: trusted?
                           ↓
                    ┌──────┴──────┐
                    │             │
                  NO              YES
                    │             │
                    ↓             ↓
          [UNTRUSTED]      [TRUSTED]
                    │             │
        Redirect to portal    Allow traffic
                    │             │
                    ↓             ↓
        ┌──────────────┐    Normal routing
        │ Portal Flow  │         │
        └──────┬───────┘         │
               │                 │
               ↓                 │
    1. Download CA cert          │
               ↓                 │
    2. Install cert (user action)│
               ↓                 │
    3. Verify installation       │
       (HTTPS test)              │
               ↓                 │
    4. User login/register       │
       (credentials)             │
               ↓                 │
    5. Update DB: trusted=TRUE   │
               ↓                 │
        [Device TRUSTED]         │
               │                 │
               └─────────────────┘
                       │
                       ↓
               All future traffic:
               - DB query: trusted=YES
               - Action: ALLOW
               - TLS interception: YES
                       │
                       ↓
                  [ACTIVE]
                       │
               (Session expires or
                cert revoked or
                user logout)
                       │
                       ↓
                [UNTRUSTED]
                (repeat flow)
```

---

## 📦 Phase 9 Components (5 Sub-Tasks)

### Sub-Task 9.1: Captive Portal Integration (`internal/integration/captive_portal.go`)

**Purpose:** Integrate firewall with captive portal - redirect untrusted devices, sync trust status

**Core Concept:**
Firewall queries database for device trust status on every connection. Untrusted devices → DNS redirect to portal. Trusted devices → allow traffic + TLS interception.

---

#### What to Create:

**1. Device Trust Checker**

**Database Schema:**
```sql
CREATE TABLE devices (
  id SERIAL PRIMARY KEY,
  mac VARCHAR(17) UNIQUE NOT NULL,  -- MAC address: 00:11:22:33:44:55
  ip INET,                          -- Last seen IP: 192.168.1.100
  user_id INTEGER REFERENCES users(id), -- Linked user (NULL if not authenticated)
  hostname VARCHAR(255),            -- Device hostname: JOHNS-LAPTOP
  os VARCHAR(100),                  -- Operating system: Windows 10
  browser VARCHAR(100),             -- Browser: Chrome/120.0
  cert_installed BOOLEAN DEFAULT FALSE,  -- CA certificate installed?
  cert_install_time TIMESTAMP,     -- When cert was installed
  trusted BOOLEAN DEFAULT FALSE,   -- Is device trusted?
  first_seen TIMESTAMP DEFAULT NOW(),
  last_seen TIMESTAMP DEFAULT NOW(),
  created_at TIMESTAMP DEFAULT NOW(),
  updated_at TIMESTAMP DEFAULT NOW()
);

CREATE INDEX idx_devices_mac ON devices(mac);
CREATE INDEX idx_devices_ip ON devices(ip);
CREATE INDEX idx_devices_trusted ON devices(trusted);
CREATE INDEX idx_devices_user_id ON devices(user_id);

CREATE TABLE users (
  id SERIAL PRIMARY KEY,
  username VARCHAR(255) UNIQUE NOT NULL,
  email VARCHAR(255) UNIQUE NOT NULL,
  password_hash VARCHAR(255) NOT NULL,  -- bcrypt hash
  role VARCHAR(50) DEFAULT 'user',      -- user, admin, etc.
  active BOOLEAN DEFAULT TRUE,
  created_at TIMESTAMP DEFAULT NOW(),
  updated_at TIMESTAMP DEFAULT NOW()
);

CREATE INDEX idx_users_username ON users(username);
CREATE INDEX idx_users_email ON users(email);
```

**Trust Checker Implementation:**
```go
type DeviceTrustChecker struct {
  db     *sql.DB
  cache  *cache.Cache  // In-memory cache (5 min TTL)
  logger *logging.Logger
}

type DeviceTrustStatus struct {
  MAC            string
  IP             string
  Trusted        bool
  CertInstalled  bool
  UserID         *int     // NULL if not authenticated
  Username       string   // "" if not authenticated
  Hostname       string
  LastSeen       time.Time
}

func (dtc *DeviceTrustChecker) IsTrusted(mac string, ip string) (bool, error) {
  // 1. Check cache first (avoid DB query on every packet)
  cacheKey := fmt.Sprintf("trust:%s", mac)
  if cached, found := dtc.cache.Get(cacheKey); found {
    dtc.logger.Debug().
      Str("mac", mac).
      Bool("trusted", cached.(bool)).
      Msg("Device trust status (cached)")
    return cached.(bool), nil
  }

  // 2. Query database
  var status DeviceTrustStatus
  query := `
    SELECT
      d.mac, d.ip, d.trusted, d.cert_installed,
      d.user_id, u.username, d.hostname, d.last_seen
    FROM devices d
    LEFT JOIN users u ON d.user_id = u.id
    WHERE d.mac = $1
  `

  err := dtc.db.QueryRow(query, mac).Scan(
    &status.MAC,
    &status.IP,
    &status.Trusted,
    &status.CertInstalled,
    &status.UserID,
    &status.Username,
    &status.Hostname,
    &status.LastSeen,
  )

  if err == sql.ErrNoRows {
    // Device not found in database (first time seen)
    dtc.logger.Warn().
      Str("mac", mac).
      Str("ip", ip).
      Msg("Device not found in database (unknown device)")

    // Insert new device record (untrusted by default)
    dtc.insertNewDevice(mac, ip)

    // Cache result
    dtc.cache.Set(cacheKey, false, 5*time.Minute)

    return false, nil  // Untrusted
  } else if err != nil {
    return false, fmt.Errorf("database query failed: %w", err)
  }

  // 3. Update last_seen timestamp and IP (if changed)
  dtc.updateLastSeen(mac, ip)

  // 4. Cache result (5 min TTL)
  dtc.cache.Set(cacheKey, status.Trusted, 5*time.Minute)

  dtc.logger.Info().
    Str("mac", mac).
    Str("ip", ip).
    Bool("trusted", status.Trusted).
    Bool("cert_installed", status.CertInstalled).
    Str("user", status.Username).
    Msg("Device trust status (database)")

  return status.Trusted, nil
}

func (dtc *DeviceTrustChecker) insertNewDevice(mac string, ip string) error {
  query := `
    INSERT INTO devices (mac, ip, trusted, cert_installed, first_seen, last_seen)
    VALUES ($1, $2, FALSE, FALSE, NOW(), NOW())
    ON CONFLICT (mac) DO NOTHING
  `
  _, err := dtc.db.Exec(query, mac, ip)
  if err != nil {
    return fmt.Errorf("failed to insert device: %w", err)
  }

  dtc.logger.Info().
    Str("mac", mac).
    Str("ip", ip).
    Msg("New device registered (untrusted)")

  return nil
}

func (dtc *DeviceTrustChecker) updateLastSeen(mac string, ip string) error {
  query := `
    UPDATE devices
    SET last_seen = NOW(), ip = $2
    WHERE mac = $1
  `
  _, err := dtc.db.Exec(query, mac, ip)
  return err
}
```

---

**2. DNS Redirect Logic**

**Integration with DNS Parser:**
```go
func (fw *Firewall) processDNSQuery(packet *Packet) (Verdict, error) {
  // Parse DNS query
  query, err := fw.dnsParser.Parse(packet.Payload)
  if err != nil {
    // Not a valid DNS query, skip
    return ALLOW, nil
  }

  // Extract client MAC address (from packet metadata)
  clientMAC := packet.SrcMAC  // e.g., "00:11:22:33:44:55"
  clientIP := packet.SrcIP    // e.g., "192.168.1.100"

  // Check if client is trusted
  trusted, err := fw.deviceTrustChecker.IsTrusted(clientMAC, clientIP)
  if err != nil {
    fw.logger.Error().Err(err).Msg("Failed to check device trust")
    // On error, assume untrusted (fail closed)
    trusted = false
  }

  if !trusted {
    // Device untrusted → redirect to captive portal
    fw.logger.Warn().
      Str("mac", clientMAC).
      Str("ip", clientIP).
      Str("query", query.Domain).
      Msg("Untrusted device detected - redirecting to captive portal")

    // Inject fake DNS response (domain → captive portal IP)
    captivePortalIP := "192.168.1.1"
    err := fw.dnsRedirector.InjectFakeResponse(query, packet, captivePortalIP)
    if err != nil {
      fw.logger.Error().Err(err).Msg("Failed to inject DNS response")
      return DROP, nil  // Fallback: drop query
    }

    // Metrics
    fw.metrics.IncrementCounter("firewall_captive_portal_redirects_total", map[string]string{
      "mac": clientMAC,
    })

    return DROP, nil  // Drop original query (fake response injected)
  }

  // Device trusted → continue with normal DNS filtering
  // Check domain against blocklist
  match, rule := fw.domainMatcher.Match(query.Domain)
  if match {
    // Domain blocked
    fw.logger.Info().
      Str("domain", query.Domain).
      Str("rule", rule.Name).
      Str("user", fw.getUsernameByMAC(clientMAC)).
      Msg("Domain blocked")

    return DROP, nil
  }

  // Allow DNS query (forward to upstream DNS)
  return ALLOW, nil
}
```

---

**3. Captive Portal Traffic Whitelist**

**Problem:**
```
Untrusted device needs to access captive portal (192.168.1.1:8082) and Step CA (port 9000).
But firewall blocks all traffic from untrusted devices!
How can untrusted device reach portal?

Solution: Whitelist captive portal and Step CA traffic
```

**Whitelist Rules:**
```go
func (fw *Firewall) isPortalTraffic(packet *Packet) bool {
  // Allow traffic to captive portal
  if packet.DstIP == "192.168.1.1" && packet.DstPort == 8082 {
    return true  // Captive portal HTTP
  }
  if packet.DstIP == "192.168.1.1" && packet.DstPort == 8443 {
    return true  // Captive portal HTTPS (cert verification)
  }

  // Allow traffic to Step CA
  if packet.DstIP == "ca.internal.com" && packet.DstPort == 9000 {
    return true  // Step CA API
  }

  return false
}

func (fw *Firewall) processPacket(packet *Packet) (Verdict, error) {
  // Special case: Allow captive portal traffic (even for untrusted devices)
  if fw.isPortalTraffic(packet) {
    fw.logger.Debug().
      Str("src", packet.SrcIP).
      Str("dst", packet.DstIP).
      Int("port", packet.DstPort).
      Msg("Captive portal traffic - allowing")
    return ALLOW, nil
  }

  // Check device trust
  trusted, err := fw.deviceTrustChecker.IsTrusted(packet.SrcMAC, packet.SrcIP)
  if err != nil {
    return DROP, err
  }

  if !trusted {
    // Untrusted device trying to access non-portal destination
    fw.logger.Warn().
      Str("mac", packet.SrcMAC).
      Str("ip", packet.SrcIP).
      Str("dst", packet.DstIP).
      Int("port", packet.DstPort).
      Msg("Untrusted device blocked (non-portal traffic)")

    return DROP, nil  // Block all non-portal traffic
  }

  // Device trusted → continue with normal firewall rules
  return fw.applyFirewallRules(packet)
}
```

---

**4. Trust Status Synchronization**

**Portal Updates Database → Firewall Sees Changes:**
```
Timeline:
1. User logs in on portal (192.168.1.1:8082)
2. Portal updates DB: UPDATE devices SET trusted = TRUE WHERE mac = '...'
3. Firewall cache still has old value: trusted = FALSE (5 min TTL)
4. User tries to access internet → still redirected to portal (cache stale!)
5. Problem: User authenticated but firewall doesn't know yet

Solutions:

Option 1: Cache Invalidation (Push)
├─ Portal publishes event: "Device MAC:XX trusted"
├─ Firewall subscribes to events (Redis Pub/Sub or gRPC stream)
├─ Firewall invalidates cache entry immediately
└─ Pros: Instant, Cons: Requires event bus

Option 2: Short Cache TTL
├─ Reduce cache TTL from 5 min to 30 seconds
├─ Firewall queries DB every 30s for untrusted devices
├─ Pros: Simple, Cons: More DB load

Option 3: Portal API Call
├─ Portal calls firewall API: POST /api/device/trust/invalidate
├─ Firewall invalidates cache entry
├─ Pros: Direct, Cons: Requires firewall HTTP API

Recommended: Option 1 (Redis Pub/Sub for production, Option 2 for Phase 9)
```

**Redis Pub/Sub Implementation:**
```go
type DeviceTrustSync struct {
  redisClient *redis.Client
  cache       *cache.Cache
  logger      *logging.Logger
}

func (dts *DeviceTrustSync) Start() {
  // Subscribe to device trust events
  pubsub := dts.redisClient.Subscribe(context.Background(), "device:trust")
  defer pubsub.Close()

  dts.logger.Info().Msg("Listening for device trust events...")

  for {
    msg, err := pubsub.ReceiveMessage(context.Background())
    if err != nil {
      dts.logger.Error().Err(err).Msg("Failed to receive message")
      continue
    }

    // Parse event: "MAC:00:11:22:33:44:55:TRUSTED" or "MAC:...:UNTRUSTED"
    parts := strings.Split(msg.Payload, ":")
    if len(parts) != 3 {
      dts.logger.Warn().Str("payload", msg.Payload).Msg("Invalid event format")
      continue
    }

    mac := parts[1]
    trustStatus := parts[2] == "TRUSTED"

    dts.logger.Info().
      Str("mac", mac).
      Bool("trusted", trustStatus).
      Msg("Device trust status changed - invalidating cache")

    // Invalidate cache entry
    cacheKey := fmt.Sprintf("trust:%s", mac)
    dts.cache.Delete(cacheKey)
  }
}

// Portal publishes event after authentication:
func (portal *CaptivePortal) markDeviceTrusted(mac string) error {
  // Update database
  _, err := portal.db.Exec(
    "UPDATE devices SET trusted = TRUE, updated_at = NOW() WHERE mac = $1",
    mac,
  )
  if err != nil {
    return err
  }

  // Publish event (firewall will invalidate cache)
  portal.redisClient.Publish(
    context.Background(),
    "device:trust",
    fmt.Sprintf("MAC:%s:TRUSTED", mac),
  )

  portal.logger.Info().Str("mac", mac).Msg("Device marked as trusted")

  return nil
}
```

---

#### Files to Create:
```
internal/integration/
├── captive_portal.go          # Captive portal integration
├── device_trust_checker.go    # Device trust status checker
├── trust_sync.go              # Redis Pub/Sub trust sync
└── dns_redirect.go            # DNS redirect logic (from Phase 8)

Database migrations:
migrations/
├── 001_create_users_table.sql
└── 002_create_devices_table.sql
```

---

### Sub-Task 9.2: Certificate Installation Workflow (`internal/integration/cert_installer.go`)

**Purpose:** Guide users through CA certificate installation and verify installation

**Core Concept:**
Captive portal serves root CA certificate from Step CA. User downloads and installs. Portal verifies installation by testing HTTPS connection with SafeOps-signed certificate.

---

#### What to Create:

**1. CA Certificate Download Handler**

**Portal Endpoint:**
```go
func (portal *CaptivePortal) handleDownloadCACert(w http.ResponseWriter, r *http.Request) {
  clientIP := getClientIP(r)
  clientMAC := portal.getClientMAC(clientIP)

  portal.logger.Info().
    Str("client", clientIP).
    Str("mac", clientMAC).
    Msg("CA certificate download requested")

  // Fetch root CA certificate from Step CA
  cert, err := portal.stepCAClient.GetRootCACertificate()
  if err != nil {
    portal.logger.Error().Err(err).Msg("Failed to fetch root CA cert")
    http.Error(w, "Failed to retrieve certificate", 500)
    return
  }

  // Serve certificate as downloadable file
  w.Header().Set("Content-Type", "application/x-x509-ca-cert")
  w.Header().Set("Content-Disposition", "attachment; filename=\"safeops-root-ca.crt\"")
  w.Header().Set("Content-Length", strconv.Itoa(len(cert)))

  _, err = w.Write(cert)
  if err != nil {
    portal.logger.Error().Err(err).Msg("Failed to write certificate")
    return
  }

  portal.logger.Info().
    Str("client", clientIP).
    Int("size", len(cert)).
    Msg("CA certificate served to client")

  // Metrics
  portal.metrics.IncrementCounter("captive_portal_ca_downloads_total")
}
```

**Step CA Client:**
```go
type StepCAClient struct {
  baseURL    string  // https://ca.internal.com:9000
  httpClient *http.Client
  logger     *logging.Logger

  // Cached root CA cert (avoid fetching on every request)
  cachedRootCA  []byte
  cacheExpiry   time.Time
}

func (sc *StepCAClient) GetRootCACertificate() ([]byte, error) {
  // Check cache first (24 hour TTL)
  if sc.cachedRootCA != nil && time.Now().Before(sc.cacheExpiry) {
    sc.logger.Debug().Msg("Returning cached root CA certificate")
    return sc.cachedRootCA, nil
  }

  // Fetch from Step CA
  url := fmt.Sprintf("%s/roots.pem", sc.baseURL)
  sc.logger.Debug().Str("url", url).Msg("Fetching root CA certificate")

  resp, err := sc.httpClient.Get(url)
  if err != nil {
    return nil, fmt.Errorf("HTTP request failed: %w", err)
  }
  defer resp.Body.Close()

  if resp.StatusCode != 200 {
    return nil, fmt.Errorf("unexpected status code: %d", resp.StatusCode)
  }

  cert, err := io.ReadAll(resp.Body)
  if err != nil {
    return nil, fmt.Errorf("failed to read response body: %w", err)
  }

  // Parse and validate certificate (sanity check)
  block, _ := pem.Decode(cert)
  if block == nil || block.Type != "CERTIFICATE" {
    return nil, fmt.Errorf("invalid PEM certificate")
  }

  x509Cert, err := x509.ParseCertificate(block.Bytes)
  if err != nil {
    return nil, fmt.Errorf("failed to parse X.509 certificate: %w", err)
  }

  // Log certificate details
  sc.logger.Info().
    Str("subject", x509Cert.Subject.String()).
    Str("issuer", x509Cert.Issuer.String()).
    Time("not_before", x509Cert.NotBefore).
    Time("not_after", x509Cert.NotAfter).
    Str("serial", x509Cert.SerialNumber.String()).
    Msg("Root CA certificate retrieved")

  // Cache certificate (24 hour TTL)
  sc.cachedRootCA = cert
  sc.cacheExpiry = time.Now().Add(24 * time.Hour)

  return cert, nil
}
```

---

**2. Installation Instructions (OS-Specific)**

**Portal shows dynamic instructions based on User-Agent:**
```go
func (portal *CaptivePortal) detectOS(userAgent string) string {
  ua := strings.ToLower(userAgent)

  if strings.Contains(ua, "windows") {
    return "windows"
  } else if strings.Contains(ua, "macintosh") || strings.Contains(ua, "mac os") {
    return "macos"
  } else if strings.Contains(ua, "linux") {
    return "linux"
  } else if strings.Contains(ua, "android") {
    return "android"
  } else if strings.Contains(ua, "iphone") || strings.Contains(ua, "ipad") {
    return "ios"
  }

  return "unknown"
}

func (portal *CaptivePortal) handleInstallInstructions(w http.ResponseWriter, r *http.Request) {
  os := portal.detectOS(r.UserAgent())

  tmpl, err := template.ParseFiles("templates/install_instructions.html")
  if err != nil {
    http.Error(w, "Template error", 500)
    return
  }

  data := struct {
    OS              string
    DownloadURL     string
    CertificateName string
  }{
    OS:              os,
    DownloadURL:     "/download-ca-cert",
    CertificateName: "safeops-root-ca.crt",
  }

  err = tmpl.Execute(w, data)
  if err != nil {
    portal.logger.Error().Err(err).Msg("Failed to render template")
  }
}
```

**Template Example (Simplified):**
```html
{{if eq .OS "windows"}}
<h2>🪟 Windows Installation</h2>
<ol>
  <li><a href="{{.DownloadURL}}">Download certificate</a></li>
  <li>Open the downloaded file: {{.CertificateName}}</li>
  <li>Click "Install Certificate"</li>
  <li>Select "Local Machine" or "Current User"</li>
  <li>Choose "Trusted Root Certification Authorities"</li>
  <li>Click "Next" → "Finish" → Accept warning</li>
</ol>
{{else if eq .OS "macos"}}
<h2>🍎 macOS Installation</h2>
<ol>
  <li><a href="{{.DownloadURL}}">Download certificate</a></li>
  <li>Double-click certificate file</li>
  <li>Enter password to add to Keychain</li>
  <li>Open Keychain Access → Find "SafeOps Root CA"</li>
  <li>Double-click → Expand "Trust"</li>
  <li>Set to "Always Trust" → Save</li>
</ol>
{{else if eq .OS "linux"}}
<h2>🐧 Linux Installation</h2>
<pre>
sudo cp {{.CertificateName}} /usr/local/share/ca-certificates/
sudo update-ca-certificates
</pre>
{{else}}
<h2>Installation Instructions</h2>
<p>Please refer to your operating system documentation for installing root CA certificates.</p>
{{end}}
```

---

**3. Certificate Installation Verification**

**Test HTTPS Connection with SafeOps-Signed Certificate:**
```go
func (portal *CaptivePortal) handleVerifyCertInstallation(w http.ResponseWriter, r *http.Request) {
  clientIP := getClientIP(r)
  clientMAC := portal.getClientMAC(clientIP)

  portal.logger.Info().
    Str("client", clientIP).
    Str("mac", clientMAC).
    Msg("Certificate installation verification requested")

  // Method: Redirect user to HTTPS test URL
  // If browser accepts certificate → cert installed
  // If browser shows warning → cert NOT installed

  // Test URL: https://verify.safeops.internal:8443/test
  // This URL is served by captive portal with SafeOps-signed cert

  testURL := "https://verify.safeops.internal:8443/test?mac=" + clientMAC

  w.Header().Set("Content-Type", "application/json")
  json.NewEncoder(w).Encode(map[string]string{
    "redirect_url": testURL,
    "method":       "https_test",
  })
}
```

**HTTPS Test Endpoint (on captive portal HTTPS server):**
```go
func (portal *CaptivePortal) startHTTPSServer() {
  // Load certificate (signed by SafeOps Root CA)
  cert, err := tls.LoadX509KeyPair(
    "certs/verify.safeops.internal.crt",
    "certs/verify.safeops.internal.key",
  )
  if err != nil {
    portal.logger.Fatal().Err(err).Msg("Failed to load TLS certificate")
  }

  tlsConfig := &tls.Config{
    Certificates: []tls.Certificate{cert},
    MinVersion:   tls.VersionTLS12,
  }

  mux := http.NewServeMux()
  mux.HandleFunc("/test", portal.handleHTTPSTest)

  server := &http.Server{
    Addr:      ":8443",
    Handler:   mux,
    TLSConfig: tlsConfig,
  }

  portal.logger.Info().Msg("HTTPS verification server started on :8443")

  err = server.ListenAndServeTLS("", "")  // Certs already in TLSConfig
  if err != nil {
    portal.logger.Fatal().Err(err).Msg("HTTPS server failed")
  }
}

func (portal *CaptivePortal) handleHTTPSTest(w http.ResponseWriter, r *http.Request) {
  mac := r.URL.Query().Get("mac")

  portal.logger.Info().
    Str("mac", mac).
    Msg("HTTPS test successful - certificate trusted by client")

  // Update database: cert_installed = TRUE
  _, err := portal.db.Exec(
    `UPDATE devices SET cert_installed = TRUE, cert_install_time = NOW()
     WHERE mac = $1`,
    mac,
  )
  if err != nil {
    portal.logger.Error().Err(err).Msg("Failed to update database")
  }

  // Return success message
  w.Header().Set("Content-Type", "application/json")
  json.NewEncoder(w).Encode(map[string]interface{}{
    "success": true,
    "message": "Certificate verified successfully",
    "mac":     mac,
  })
}
```

**Client-Side JavaScript (handles redirect):**
```javascript
// User clicks "I've Installed the Certificate"
async function verifyCertInstallation() {
  // Request test URL from portal
  const resp = await fetch('/verify-cert-installation');
  const data = await resp.json();

  const testURL = data.redirect_url;

  // Try to fetch HTTPS test URL
  try {
    const testResp = await fetch(testURL);
    const testData = await testResp.json();

    if (testData.success) {
      // Certificate verified!
      showSuccess("Certificate verified successfully!");
      // Proceed to authentication step
      window.location.href = "/auth/login";
    } else {
      showError("Verification failed. Please try again.");
    }
  } catch (err) {
    // Fetch failed → certificate not trusted (browser blocked request)
    showError("Certificate not detected. Please ensure you installed it correctly.");
    console.error("HTTPS test failed:", err);
  }
}
```

---

**4. Certificate Fingerprint Display**

**Show certificate fingerprint to users (for manual verification):**
```go
func (sc *StepCAClient) GetRootCAFingerprint() (string, error) {
  cert, err := sc.GetRootCACertificate()
  if err != nil {
    return "", err
  }

  // Parse certificate
  block, _ := pem.Decode(cert)
  x509Cert, err := x509.ParseCertificate(block.Bytes)
  if err != nil {
    return "", err
  }

  // Calculate SHA256 fingerprint
  hash := sha256.Sum256(x509Cert.Raw)
  fingerprint := fmt.Sprintf("SHA256:%X", hash)

  // Format: SHA256:A1:B2:C3:D4:... (colon-separated)
  formatted := ""
  for i, b := range hash {
    if i > 0 {
      formatted += ":"
    }
    formatted += fmt.Sprintf("%02X", b)
  }

  return formatted, nil
}
```

**Display on portal:**
```html
<div class="certificate-info">
  <h3>Certificate Details</h3>
  <p><strong>Subject:</strong> CN=SafeOps Root CA, O=SafeOps, C=US</p>
  <p><strong>Issuer:</strong> CN=SafeOps Root CA (self-signed)</p>
  <p><strong>Valid Until:</strong> 2035-01-01</p>
  <p><strong>Fingerprint:</strong></p>
  <code class="fingerprint">SHA256:A1:B2:C3:D4:E5:F6:...</code>
  <p class="help-text">
    After installation, verify this fingerprint matches the installed certificate.
  </p>
</div>
```

---

#### Files to Create:
```
internal/integration/
├── cert_installer.go         # Certificate installation workflow
├── cert_verifier.go          # HTTPS test endpoint
└── stepca_client.go          # Step CA API client (fetch certs)

Captive Portal:
captive-portal/
├── handlers/
│   ├── download_ca_cert.go   # CA cert download handler
│   ├── verify_cert.go        # Cert verification handler
│   └── https_test.go         # HTTPS test endpoint
├── templates/
│   └── install_instructions.html  # OS-specific instructions
└── static/
    └── js/cert_installer.js  # Client-side verification logic

Certificates (generated by Step CA):
certs/
├── verify.safeops.internal.crt  # Test domain cert (signed by SafeOps)
└── verify.safeops.internal.key  # Private key
```

---

### Sub-Task 9.3: Device Trust Management (`internal/device/trust_manager.go`)

**Purpose:** Manage device lifecycle - query trust status, allow trusted, block untrusted, auto-verify

**Core Concept:**
Devices have states: UNKNOWN → UNTRUSTED → CERT_INSTALLED → AUTHENTICATED → TRUSTED. Firewall enforces policy based on trust state.

---

#### What to Create:

**1. Device Trust State Machine**

**Trust States:**
```
Device Trust States:

1. UNKNOWN
   ├─ Device never seen before
   ├─ No database record exists
   ├─ Action: INSERT into DB (transition to UNTRUSTED)
   └─ Internet Access: ❌ BLOCKED (redirect to portal)

2. UNTRUSTED
   ├─ Device known but not authenticated
   ├─ Database: trusted = FALSE, cert_installed = FALSE
   ├─ Action: Redirect to captive portal
   └─ Internet Access: ❌ BLOCKED (only portal + Step CA allowed)

3. CERT_INSTALLED (Optional State)
   ├─ Device installed CA certificate
   ├─ Database: trusted = FALSE, cert_installed = TRUE
   ├─ Action: Still need authentication (user login)
   └─ Internet Access: ❌ BLOCKED (redirect to login page)

4. AUTHENTICATED
   ├─ User logged in successfully
   ├─ Database: trusted = TRUE, cert_installed = TRUE/FALSE
   ├─ Device linked to user account
   └─ Internet Access: ✅ ALLOWED

5. TRUSTED
   ├─ Same as AUTHENTICATED (alias)
   ├─ Database: trusted = TRUE
   ├─ Full network access
   └─ TLS Interception: Depends on cert_installed flag
      ├─ cert_installed = TRUE → TLS interception ENABLED
      └─ cert_installed = FALSE → TLS interception DISABLED (passthrough)

6. SUSPENDED
   ├─ Admin manually suspended device
   ├─ Database: trusted = FALSE, suspended = TRUE
   ├─ Reason: Policy violation, security incident, etc.
   └─ Internet Access: ❌ BLOCKED (show suspension notice)

7. EXPIRED
   ├─ Device authentication expired (e.g., 90 days)
   ├─ Database: trusted = FALSE, session_expired = TRUE
   ├─ Action: Require re-authentication
   └─ Internet Access: ❌ BLOCKED (redirect to re-auth page)
```

**State Transitions:**
```
UNKNOWN → UNTRUSTED (automatic on first packet)
  ├─ Trigger: First packet from new MAC address
  └─ Action: INSERT device record

UNTRUSTED → CERT_INSTALLED (optional, user installs cert)
  ├─ Trigger: HTTPS test succeeds (cert verification)
  └─ Action: UPDATE devices SET cert_installed = TRUE

UNTRUSTED → AUTHENTICATED (if user skips cert)
  ├─ Trigger: User logs in without installing cert
  └─ Action: UPDATE devices SET trusted = TRUE, cert_installed = FALSE

CERT_INSTALLED → AUTHENTICATED (if user installed cert)
  ├─ Trigger: User logs in after cert installation
  └─ Action: UPDATE devices SET trusted = TRUE

AUTHENTICATED → SUSPENDED (admin action)
  ├─ Trigger: Admin clicks "Suspend Device"
  └─ Action: UPDATE devices SET trusted = FALSE, suspended = TRUE

AUTHENTICATED → EXPIRED (time-based)
  ├─ Trigger: Cron job checks last_seen > 90 days
  └─ Action: UPDATE devices SET trusted = FALSE, session_expired = TRUE

SUSPENDED → AUTHENTICATED (admin re-enables)
  ├─ Trigger: Admin clicks "Unsuspend Device"
  └─ Action: UPDATE devices SET trusted = TRUE, suspended = FALSE

EXPIRED → AUTHENTICATED (user re-authenticates)
  ├─ Trigger: User logs in again
  └─ Action: UPDATE devices SET trusted = TRUE, session_expired = FALSE
```

---

**2. Trust Manager Implementation**

```go
type TrustManager struct {
  db     *sql.DB
  cache  *cache.Cache
  logger *logging.Logger
}

type DeviceState int

const (
  StateUnknown DeviceState = iota
  StateUntrusted
  StateCertInstalled
  StateAuthenticated
  StateTrusted  // Alias for Authenticated
  StateSuspended
  StateExpired
)

type Device struct {
  ID               int
  MAC              string
  IP               string
  Hostname         string
  OS               string
  Browser          string
  UserID           *int
  Username         string
  CertInstalled    bool
  Trusted          bool
  Suspended        bool
  SessionExpired   bool
  FirstSeen        time.Time
  LastSeen         time.Time
  AuthenticatedAt  *time.Time
  SuspendedAt      *time.Time
  SuspensionReason string
}

func (tm *TrustManager) GetDeviceState(mac string) (DeviceState, *Device, error) {
  // Query database
  query := `
    SELECT id, mac, ip, hostname, os, browser, user_id,
           cert_installed, trusted, suspended, session_expired,
           first_seen, last_seen
    FROM devices
    WHERE mac = $1
  `

  var device Device
  err := tm.db.QueryRow(query, mac).Scan(
    &device.ID, &device.MAC, &device.IP,
    &device.Hostname, &device.OS, &device.Browser,
    &device.UserID, &device.CertInstalled,
    &device.Trusted, &device.Suspended, &device.SessionExpired,
    &device.FirstSeen, &device.LastSeen,
  )

  if err == sql.ErrNoRows {
    return StateUnknown, nil, nil
  } else if err != nil {
    return StateUnknown, nil, err
  }

  // Determine state based on flags
  if device.Suspended {
    return StateSuspended, &device, nil
  }

  if device.SessionExpired {
    return StateExpired, &device, nil
  }

  if device.Trusted {
    return StateTrusted, &device, nil
  }

  if device.CertInstalled {
    return StateCertInstalled, &device, nil
  }

  return StateUntrusted, &device, nil
}

func (tm *TrustManager) ShouldAllowInternet(mac string, ip string) (bool, string) {
  state, device, err := tm.GetDeviceState(mac)
  if err != nil {
    tm.logger.Error().Err(err).Msg("Failed to get device state")
    return false, "database_error"  // Fail closed
  }

  switch state {
  case StateUnknown:
    // New device - register and block
    tm.registerNewDevice(mac, ip)
    return false, "device_unknown"

  case StateUntrusted, StateCertInstalled:
    // Not authenticated yet - block
    return false, "device_untrusted"

  case StateTrusted:
    // Authenticated - allow
    return true, "device_trusted"

  case StateSuspended:
    // Admin suspended - block
    return false, "device_suspended"

  case StateExpired:
    // Session expired - block
    return false, "session_expired"

  default:
    return false, "unknown_state"
  }
}

func (tm *TrustManager) MarkTrusted(mac string, userID int) error {
  query := `
    UPDATE devices
    SET trusted = TRUE,
        user_id = $2,
        authenticated_at = NOW(),
        updated_at = NOW()
    WHERE mac = $1
  `

  _, err := tm.db.Exec(query, mac, userID)
  if err != nil {
    return fmt.Errorf("failed to update device: %w", err)
  }

  // Invalidate cache
  cacheKey := fmt.Sprintf("trust:%s", mac)
  tm.cache.Delete(cacheKey)

  tm.logger.Info().
    Str("mac", mac).
    Int("user_id", userID).
    Msg("Device marked as trusted")

  return nil
}
```

---

**3. Auto-Verification After Certificate Installation**

**Concept:**
```
Flow without auto-verification (manual):
1. User installs cert
2. User clicks "Verify Installation" button
3. Portal tests HTTPS connection
4. Portal marks cert_installed = TRUE
5. User proceeds to login

Flow with auto-verification (automatic):
1. User installs cert
2. Browser automatically makes HTTPS requests
3. Portal detects successful HTTPS connection
4. Portal auto-marks cert_installed = TRUE (no button click needed)
5. Portal redirects to login page automatically
```

**Implementation:**
```go
// Embed hidden iframe in portal page
// Iframe tries to load HTTPS test URL
// If successful → cert installed

func (portal *CaptivePortal) handleInstallInstructions(w http.ResponseWriter, r *http.Request) {
  clientMAC := portal.getClientMAC(getClientIP(r))

  data := struct {
    MAC            string
    AutoVerifyURL  string
  }{
    MAC:           clientMAC,
    AutoVerifyURL: fmt.Sprintf("https://verify.safeops.internal:8443/auto-verify?mac=%s", clientMAC),
  }

  tmpl.Execute(w, data)
}
```

**HTML Template (with auto-verification):**
```html
<div id="install-instructions">
  <h2>Installing Certificate...</h2>
  <p>Follow the instructions above to install the certificate.</p>

  <!-- Hidden iframe for auto-verification -->
  <iframe
    id="auto-verify-frame"
    src="{{.AutoVerifyURL}}"
    style="display:none;"
    onload="handleAutoVerify()">
  </iframe>

  <div id="status">
    <p>⏳ Waiting for certificate installation...</p>
  </div>
</div>

<script>
let verificationAttempts = 0;
const maxAttempts = 30;  // Try for 30 seconds

function handleAutoVerify() {
  // Iframe loaded successfully → certificate trusted!
  document.getElementById('status').innerHTML = `
    <p>✅ Certificate detected and verified!</p>
    <p>Redirecting to login...</p>
  `;

  // Redirect to login after 2 seconds
  setTimeout(() => {
    window.location.href = '/auth/login';
  }, 2000);
}

// Fallback: Retry iframe loading every 1 second (in case cert installed later)
function retryAutoVerify() {
  verificationAttempts++;

  if (verificationAttempts > maxAttempts) {
    // Give up after 30 seconds
    document.getElementById('status').innerHTML = `
      <p>❌ Certificate not detected after 30 seconds.</p>
      <p><button onclick="location.reload()">Retry</button> or <a href="/auth/login">Skip (Not Recommended)</a></p>
    `;
    return;
  }

  // Reload iframe (retry HTTPS connection)
  const iframe = document.getElementById('auto-verify-frame');
  iframe.src = iframe.src + '&retry=' + verificationAttempts;

  setTimeout(retryAutoVerify, 1000);  // Retry in 1 second
}

// Start auto-verification attempts
setTimeout(retryAutoVerify, 1000);
</script>
```

---

**4. Device Trust Metrics & Dashboard**

**Prometheus Metrics:**
```go
// Device trust metrics
firewall_devices_total{state="unknown"} gauge
firewall_devices_total{state="untrusted"} gauge
firewall_devices_total{state="cert_installed"} gauge
firewall_devices_total{state="trusted"} gauge
firewall_devices_total{state="suspended"} gauge
firewall_devices_total{state="expired"} gauge

// Trust checks
firewall_device_trust_checks_total counter
firewall_device_trust_check_duration_seconds histogram

// Authentication
firewall_device_authentications_total{result="success|failure"} counter
firewall_device_cert_installations_total counter
```

**Database Query for Metrics:**
```go
func (tm *TrustManager) GetDeviceStatistics() (map[string]int, error) {
  query := `
    SELECT
      COUNT(CASE WHEN NOT trusted AND NOT cert_installed THEN 1 END) AS untrusted,
      COUNT(CASE WHEN NOT trusted AND cert_installed THEN 1 END) AS cert_installed,
      COUNT(CASE WHEN trusted AND NOT suspended THEN 1 END) AS trusted,
      COUNT(CASE WHEN suspended THEN 1 END) AS suspended,
      COUNT(CASE WHEN session_expired THEN 1 END) AS expired
    FROM devices
  `

  var stats struct {
    Untrusted      int
    CertInstalled  int
    Trusted        int
    Suspended      int
    Expired        int
  }

  err := tm.db.QueryRow(query).Scan(
    &stats.Untrusted,
    &stats.CertInstalled,
    &stats.Trusted,
    &stats.Suspended,
    &stats.Expired,
  )

  if err != nil {
    return nil, err
  }

  return map[string]int{
    "untrusted":      stats.Untrusted,
    "cert_installed": stats.CertInstalled,
    "trusted":        stats.Trusted,
    "suspended":      stats.Suspended,
    "expired":        stats.Expired,
  }, nil
}
```

---

#### Files to Create:
```
internal/device/
├── trust_manager.go          # Device trust state management
├── trust_checker.go          # Fast trust checking (cached)
├── device_lifecycle.go       # State transitions
└── auto_verify.go            # Automatic cert verification

Database migrations:
migrations/
└── 003_add_device_trust_fields.sql
    ALTER TABLE devices ADD COLUMN suspended BOOLEAN DEFAULT FALSE;
    ALTER TABLE devices ADD COLUMN session_expired BOOLEAN DEFAULT FALSE;
    ALTER TABLE devices ADD COLUMN suspended_at TIMESTAMP;
    ALTER TABLE devices ADD COLUMN suspension_reason TEXT;
```

---

### Sub-Task 9.4: Step CA PKI Integration (`internal/integration/stepca_client.go`)

**Purpose:** Full Step CA integration - fetch root CA, verify device certs, auto-renewal, revocation

**Core Concept:**
Step CA is the PKI backend. Firewall acts as client to fetch certs for TLS interception and verify device certificates.

---

#### What to Create:

**1. Step CA API Client (Comprehensive)**

```go
type StepCAClient struct {
  baseURL      string  // https://ca.internal.com:9000
  provisioner  string  // Provisioner name (e.g., "firewall-provisioner")
  provisionerPassword string  // Provisioner password
  httpClient   *http.Client
  certCache    *CertificateCache
  logger       *logging.Logger
}

type CertificateCache struct {
  mu    sync.RWMutex
  certs map[string]*CachedCert  // domain → cached cert
}

type CachedCert struct {
  Certificate []byte
  PrivateKey  []byte
  Expiry      time.Time
}

func NewStepCAClient(baseURL, provisioner, password string) *StepCAClient {
  // Skip TLS verification for Step CA (bootstrapping trust)
  tlsConfig := &tls.Config{
    InsecureSkipVerify: true,
  }

  httpClient := &http.Client{
    Transport: &http.Transport{
      TLSClientConfig: tlsConfig,
    },
    Timeout: 10 * time.Second,
  }

  return &StepCAClient{
    baseURL:             baseURL,
    provisioner:         provisioner,
    provisionerPassword: password,
    httpClient:          httpClient,
    certCache:           &CertificateCache{certs: make(map[string]*CachedCert)},
  }
}
```

---

**2. Get Root CA Certificate**

```go
func (sc *StepCAClient) GetRootCACertificate() ([]byte, error) {
  url := fmt.Sprintf("%s/roots.pem", sc.baseURL)

  resp, err := sc.httpClient.Get(url)
  if err != nil {
    return nil, fmt.Errorf("failed to fetch root CA: %w", err)
  }
  defer resp.Body.Close()

  if resp.StatusCode != 200 {
    return nil, fmt.Errorf("unexpected status code: %d", resp.StatusCode)
  }

  cert, err := io.ReadAll(resp.Body)
  if err != nil {
    return nil, fmt.Errorf("failed to read response: %w", err)
  }

  sc.logger.Info().
    Str("url", url).
    Int("size", len(cert)).
    Msg("Root CA certificate fetched")

  return cert, nil
}
```

---

**3. Request Certificate for TLS Interception (MITM)**

```go
func (sc *StepCAClient) RequestCertificate(domain string) (*CachedCert, error) {
  // Check cache first
  if cached := sc.certCache.Get(domain); cached != nil {
    if time.Now().Before(cached.Expiry.Add(-7 * 24 * time.Hour)) {
      // Certificate valid for at least 7 more days
      sc.logger.Debug().Str("domain", domain).Msg("Using cached certificate")
      return cached, nil
    }
    // Certificate expiring soon, request new one
    sc.logger.Info().Str("domain", domain).Msg("Certificate expiring soon, requesting renewal")
  }

  sc.logger.Info().Str("domain", domain).Msg("Requesting new certificate from Step CA")

  // Generate CSR (Certificate Signing Request)
  privateKey, csr, err := sc.generateCSR(domain)
  if err != nil {
    return nil, fmt.Errorf("failed to generate CSR: %w", err)
  }

  // Get one-time token (OTT) for authentication
  ott, err := sc.getOneTimeToken()
  if err != nil {
    return nil, fmt.Errorf("failed to get OTT: %w", err)
  }

  // Request certificate from Step CA
  reqBody := map[string]interface{}{
    "csr": string(csr),
    "ott": ott,
  }

  jsonBody, _ := json.Marshal(reqBody)
  url := fmt.Sprintf("%s/sign", sc.baseURL)

  resp, err := sc.httpClient.Post(url, "application/json", bytes.NewReader(jsonBody))
  if err != nil {
    return nil, fmt.Errorf("failed to sign certificate: %w", err)
  }
  defer resp.Body.Close()

  if resp.StatusCode != 201 {
    body, _ := io.ReadAll(resp.Body)
    return nil, fmt.Errorf("certificate signing failed: %d %s", resp.StatusCode, string(body))
  }

  var signResp struct {
    Crt       string `json:"crt"`
    CA        string `json:"ca"`
    CertChain []string `json:"certChain"`
  }

  err = json.NewDecoder(resp.Body).Decode(&signResp)
  if err != nil {
    return nil, fmt.Errorf("failed to decode response: %w", err)
  }

  // Parse certificate to get expiry
  block, _ := pem.Decode([]byte(signResp.Crt))
  x509Cert, _ := x509.ParseCertificate(block.Bytes)

  // Cache certificate
  cached := &CachedCert{
    Certificate: []byte(signResp.Crt),
    PrivateKey:  privateKey,
    Expiry:      x509Cert.NotAfter,
  }

  sc.certCache.Set(domain, cached)

  sc.logger.Info().
    Str("domain", domain).
    Time("expiry", x509Cert.NotAfter).
    Msg("Certificate issued and cached")

  return cached, nil
}

func (sc *StepCAClient) generateCSR(domain string) ([]byte, []byte, error) {
  // Generate RSA private key
  privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
  if err != nil {
    return nil, nil, err
  }

  // Serialize private key to PEM
  privateKeyPEM := pem.EncodeToMemory(&pem.Block{
    Type:  "RSA PRIVATE KEY",
    Bytes: x509.MarshalPKCS1PrivateKey(privateKey),
  })

  // Create CSR template
  template := x509.CertificateRequest{
    Subject: pkix.Name{
      CommonName: domain,
    },
    DNSNames: []string{domain},
  }

  // Create CSR
  csrDER, err := x509.CreateCertificateRequest(rand.Reader, &template, privateKey)
  if err != nil {
    return nil, nil, err
  }

  // Serialize CSR to PEM
  csrPEM := pem.EncodeToMemory(&pem.Block{
    Type:  "CERTIFICATE REQUEST",
    Bytes: csrDER,
  })

  return privateKeyPEM, csrPEM, nil
}

func (sc *StepCAClient) getOneTimeToken() (string, error) {
  // Request OTT from Step CA using provisioner credentials
  url := fmt.Sprintf("%s/provisioners/%s/token", sc.baseURL, sc.provisioner)

  reqBody := map[string]string{
    "password": sc.provisionerPassword,
  }

  jsonBody, _ := json.Marshal(reqBody)

  resp, err := sc.httpClient.Post(url, "application/json", bytes.NewReader(jsonBody))
  if err != nil {
    return "", err
  }
  defer resp.Body.Close()

  var tokenResp struct {
    Token string `json:"token"`
  }

  err = json.NewDecoder(resp.Body).Decode(&tokenResp)
  if err != nil {
    return "", err
  }

  return tokenResp.Token, nil
}
```

---

**4. Certificate Renewal (Automated Background Task)**

```go
func (sc *StepCAClient) StartCertificateRenewal() {
  ticker := time.NewTicker(1 * time.Hour)
  defer ticker.Stop()

  sc.logger.Info().Msg("Certificate renewal background task started")

  for range ticker.C {
    sc.renewExpiringSertificates()
  }
}

func (sc *StepCAClient) renewExpiringCertificates() {
  sc.certCache.mu.RLock()
  domains := make([]string, 0, len(sc.certCache.certs))
  for domain, cert := range sc.certCache.certs {
    // Renew if expiring in less than 7 days
    if time.Until(cert.Expiry) < 7*24*time.Hour {
      domains = append(domains, domain)
    }
  }
  sc.certCache.mu.RUnlock()

  if len(domains) == 0 {
    sc.logger.Debug().Msg("No certificates need renewal")
    return
  }

  sc.logger.Info().Int("count", len(domains)).Msg("Renewing certificates")

  for _, domain := range domains {
    _, err := sc.RequestCertificate(domain)  // Will fetch new cert
    if err != nil {
      sc.logger.Error().Err(err).Str("domain", domain).Msg("Failed to renew certificate")
    } else {
      sc.logger.Info().Str("domain", domain).Msg("Certificate renewed")
    }
  }
}
```

---

**5. Certificate Revocation Checking**

```go
func (sc *StepCAClient) IsCertificateRevoked(serialNumber string) (bool, error) {
  // Query Step CA revocation list
  url := fmt.Sprintf("%s/revoke/%s", sc.baseURL, serialNumber)

  resp, err := sc.httpClient.Get(url)
  if err != nil {
    return false, fmt.Errorf("failed to check revocation: %w", err)
  }
  defer resp.Body.Close()

  if resp.StatusCode == 200 {
    // Certificate revoked
    return true, nil
  } else if resp.StatusCode == 404 {
    // Certificate not revoked
    return false, nil
  }

  return false, fmt.Errorf("unexpected status code: %d", resp.StatusCode)
}
```

---

#### Files to Create:
```
internal/integration/
├── stepca_client.go           # Step CA API client
├── stepca_certs.go            # Certificate request/renewal
├── stepca_revocation.go       # Revocation checking
└── cert_cache.go              # Certificate cache

Config file (firewall.toml):
[stepca]
base_url = "https://ca.internal.com:9000"
provisioner = "firewall-provisioner"
provisioner_password_file = "/etc/safeops/stepca-password.txt"
cert_cache_size = 1000
cert_renewal_days = 7
```

---

### Sub-Task 9.5: TLS Interception Preparation (`internal/tls/interceptor.go`)

**Purpose:** Implement TLS interception pipeline - decrypt, inspect, re-encrypt HTTPS traffic

**Core Concept:**
Trusted devices with CA cert installed → HTTPS traffic intercepted. Firewall acts as MITM (man-in-the-middle) with user consent (cert installation = consent).

---

#### What to Create:

**1. TLS Interception Pipeline Architecture**

```
Normal HTTPS (No Interception):
Client ────(TLS)────> Server
       (encrypted)

TLS Interception (MITM):
Client ───(TLS A)───> Firewall ───(TLS B)───> Server
      (fake cert)                (real cert)

Details:
- TLS A: Client ↔ Firewall
  ├─ Certificate: Fake cert for example.com (signed by SafeOps Root CA)
  ├─ Client trusts it (SafeOps Root CA installed)
  └─ Firewall decrypts client traffic (sees plaintext HTTP)

- TLS B: Firewall ↔ Server
  ├─ Certificate: Real cert from example.com server
  ├─ Firewall validates it (acts as normal client)
  └─ Firewall encrypts traffic before sending to server

- Firewall sees:
  ├─ Plaintext HTTP request from client
  ├─ Plaintext HTTP response from server
  ├─ Can inspect, log, block, modify content
  └─ User unaware (transparent MITM)
```

---

**2. TLS Interceptor Implementation**

```go
type TLSInterceptor struct {
  stepCAClient  *StepCAClient
  certCache     *CertificateCache
  pinnedDomains map[string]bool  // Domains that pin certificates (bypass)
  logger        *logging.Logger
}

func (ti *TLSInterceptor) ShouldIntercept(domain string, clientMAC string) bool {
  // Check if domain uses certificate pinning (bypass interception)
  if ti.pinnedDomains[domain] {
    ti.logger.Debug().Str("domain", domain).Msg("Certificate pinning detected - bypass")
    return false
  }

  // Check if client has CA certificate installed
  device, err := ti.getDeviceInfo(clientMAC)
  if err != nil || !device.CertInstalled {
    // Client doesn't have cert installed → cannot intercept (TLS error)
    ti.logger.Debug().Str("mac", clientMAC).Msg("Client cert not installed - bypass")
    return false
  }

  // Intercept!
  return true
}

func (ti *TLSInterceptor) InterceptConnection(clientConn net.Conn, serverAddr string, sni string) error {
  ti.logger.Info().
    Str("client", clientConn.RemoteAddr().String()).
    Str("server", serverAddr).
    Str("sni", sni).
    Msg("Intercepting TLS connection")

  // 1. Get/generate MITM certificate for SNI
  cert, err := ti.stepCAClient.RequestCertificate(sni)
  if err != nil {
    return fmt.Errorf("failed to get certificate: %w", err)
  }

  // 2. Load certificate and private key
  tlsCert, err := tls.X509KeyPair(cert.Certificate, cert.PrivateKey)
  if err != nil {
    return fmt.Errorf("failed to load key pair: %w", err)
  }

  // 3. Start TLS server for client (Firewall acts as server)
  tlsConfig := &tls.Config{
    Certificates: []tls.Certificate{tlsCert},
    MinVersion:   tls.VersionTLS12,
  }

  clientTLSConn := tls.Server(clientConn, tlsConfig)

  // 4. TLS handshake with client
  err = clientTLSConn.Handshake()
  if err != nil {
    return fmt.Errorf("client handshake failed: %w", err)
  }

  ti.logger.Debug().Msg("Client-side TLS handshake complete")

  // 5. Connect to real server (Firewall acts as client)
  serverConn, err := net.Dial("tcp", serverAddr)
  if err != nil {
    return fmt.Errorf("failed to connect to server: %w", err)
  }
  defer serverConn.Close()

  // 6. Start TLS client for server
  serverTLSConn := tls.Client(serverConn, &tls.Config{
    ServerName: sni,
    MinVersion: tls.VersionTLS12,
  })

  // 7. TLS handshake with server
  err = serverTLSConn.Handshake()
  if err != nil {
    return fmt.Errorf("server handshake failed: %w", err)
  }

  ti.logger.Debug().Msg("Server-side TLS handshake complete")

  // 8. Proxy decrypted traffic (with inspection)
  go ti.proxyWithInspection(clientTLSConn, serverTLSConn, "client→server")
  go ti.proxyWithInspection(serverTLSConn, clientTLSConn, "server→client")

  return nil
}

func (ti *TLSInterceptor) proxyWithInspection(src, dst net.Conn, direction string) {
  buf := make([]byte, 32*1024)  // 32KB buffer

  for {
    n, err := src.Read(buf)
    if err != nil {
      break
    }

    // INSPECT DECRYPTED TRAFFIC HERE
    data := buf[:n]
    ti.inspectHTTP(data, direction)

    // Forward to destination
    _, err = dst.Write(data)
    if err != nil {
      break
    }
  }
}

func (ti *TLSInterceptor) inspectHTTP(data []byte, direction string) {
  // Parse HTTP request/response
  if direction == "client→server" {
    // Parse HTTP request
    if bytes.HasPrefix(data, []byte("GET ")) || bytes.HasPrefix(data, []byte("POST ")) {
      ti.logger.Debug().
        Str("direction", direction).
        Int("size", len(data)).
        Str("preview", string(data[:min(100, len(data))])).
        Msg("HTTP request intercepted")

      // TODO: DPI, malware scan, policy check, DLP
    }
  } else {
    // Parse HTTP response
    if bytes.HasPrefix(data, []byte("HTTP/")) {
      ti.logger.Debug().
        Str("direction", direction).
        Int("size", len(data)).
        Msg("HTTP response intercepted")

      // TODO: Content filtering, malware scan
    }
  }
}
```

---

**3. Certificate Pinning Detection & Bypass**

```go
type PinningDetector struct {
  pinnedDomains map[string]bool
  logger        *logging.Logger
}

func (pd *PinningDetector) LoadPinnedDomains() {
  // Hardcoded list of known pinned domains
  pd.pinnedDomains = map[string]bool{
    "api.bank.com":              true,
    "graph.facebook.com":        true,
    "android.googleapis.com":    true,
    "api.twitter.com":           true,
    "apple.com":                 true,
  }

  // TODO: Load from config file or database
}

func (pd *PinningDetector) IsPinned(domain string) bool {
  return pd.pinnedDomains[domain]
}
```

---

**4. Performance Optimization**

```
TLS interception is CPU-intensive:
- RSA/ECDSA signatures
- AES-GCM encryption/decryption
- Certificate validation

Optimizations:

1. Certificate caching (already implemented)
   ├─ Avoid requesting new cert for every connection
   └─ Reuse cert for same domain (30-day TTL)

2. TLS session resumption
   ├─ Cache TLS session tickets
   └─ Resume session without full handshake (10× faster)

3. Hardware acceleration
   ├─ Use AES-NI (CPU instructions for AES)
   ├─ Intel QuickAssist (dedicated crypto hardware)
   └─ Can handle 10Gbps encrypted traffic

4. Connection pooling
   ├─ Reuse server connections (HTTP keep-alive)
   └─ Reduce handshake overhead

5. Selective interception
   ├─ Don't intercept everything (e.g., video streams)
   ├─ Whitelist bandwidth-heavy domains (youtube.com, netflix.com)
   └─ Focus on high-risk traffic (downloads, form submissions)
```

---

#### Files to Create:
```
internal/tls/
├── interceptor.go              # Main TLS interception logic
├── mitm_proxy.go               # MITM proxy (decrypt-inspect-re-encrypt)
├── pinning_detector.go         # Certificate pinning detection
├── inspection.go               # HTTP content inspection
└── performance.go              # Performance optimizations

Config file:
[tls_interception]
enabled = true
cert_pinning_bypass = true
pinned_domains_file = "/etc/safeops/pinned-domains.txt"
session_cache_size = 10000
inspection_depth = "full"  # "full" or "metadata-only"
```

---

## 📊 Phase 9 Success Criteria

**By end of Phase 9, the system must demonstrate:**

1. ✅ **Captive Portal Integration:**
   - Untrusted devices redirected to portal (DNS injection working)
   - Portal accessible (even for untrusted devices)
   - Step CA accessible (for cert download)
   - Trust status synchronized (database ↔ firewall)

2. ✅ **Certificate Installation Workflow:**
   - Root CA cert downloadable from portal
   - OS-specific installation instructions shown
   - Certificate installation verified (HTTPS test)
   - Auto-verification working (iframe-based detection)

3. ✅ **Device Trust Management:**
   - Device states tracked (UNKNOWN → UNTRUSTED → TRUSTED)
   - Database queries efficient (cached, <1ms lookup)
   - Trust status changes reflected immediately (Redis Pub/Sub)
   - Metrics and dashboard functional

4. ✅ **Step CA PKI Integration:**
   - Root CA cert fetched from Step CA
   - MITM certs requested on-demand
   - Certificate caching working (30-day TTL)
   - Automated cert renewal (7 days before expiry)
   - Revocation checking functional

5. ✅ **TLS Interception:**
   - HTTPS traffic intercepted for trusted devices (with cert)
   - HTTPS traffic passed through for devices without cert
   - Certificate pinning detected and bypassed
   - HTTP content inspection working (see plaintext)
   - Performance acceptable (<10ms overhead per connection)

---

## 📈 Phase 9 Metrics

**Prometheus Metrics:**
```
# Captive portal
firewall_captive_portal_redirects_total counter
firewall_captive_portal_access_total counter
firewall_ca_cert_downloads_total counter
firewall_cert_verifications_total{result="success|failure"} counter

# Device trust
firewall_devices_total{state="untrusted|trusted|suspended"} gauge
firewall_device_authentications_total counter
firewall_trust_checks_per_second gauge

# Step CA
firewall_stepca_cert_requests_total counter
firewall_stepca_cert_cache_hits_total counter
firewall_stepca_cert_renewals_total counter

# TLS interception
firewall_tls_interceptions_total counter
firewall_tls_bypassed_total{reason="no_cert|pinning|error"} counter
firewall_tls_inspection_duration_seconds histogram
```

---

## 🚀 Next Steps After Phase 9

After Phase 9 completion, proceed to:
- **Phase 10:** Production Hardening (High availability, load balancing, disaster recovery)
- **Phase 11:** Advanced Content Inspection (DLP, malware scanning, threat intelligence)
- **Phase 12:** Enterprise Features (SAML/LDAP auth, reporting, compliance)

**Estimated Total Time for Phase 9:** 3 weeks

---

**END OF PHASE 9 DOCUMENTATION**