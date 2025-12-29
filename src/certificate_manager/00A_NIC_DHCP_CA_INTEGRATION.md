# ENHANCED: NIC + DHCP + CA CERTIFICATE AUTO-PROVISIONING
## Automated CA Certificate Distribution During Network Connection

```
════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════
                    COMPLETE FLOW: USER CONNECTS → AUTO-PROVISIONED WITH CA CERTIFICATE
════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════

    👤 NEW USER DEVICE
    │  (Fresh laptop, no CA certificate installed)
    │  MAC: AA:BB:CC:DD:EE:FF
    │  OS: Windows 10 / macOS / Linux
    │
    │  Plugs in Ethernet cable / Connects to WiFi
    ▼


════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════
                            PHASE 1: PHYSICAL CONNECTION (NIC MANAGEMENT)
════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════

┌─────────────────────────────────────────────────────────────────────────────────────────────────────────────────────┐
│  COMPONENT 01: NIC MANAGEMENT                                                                                       │
│  ┌────────────────────────────────────────────────────────────────────────────────────────────────────────────┐   │
│  │  STEP 1: Physical Link Detection                                                                            │   │
│  │  ────────────────────────────────────────────────────────────────────────                                   │   │
│  │  ⚡ Port eth0 - Link State Changed: DOWN → UP                                                                │   │
│  │  📡 MAC Address Learned: AA:BB:CC:DD:EE:FF                                                                   │   │
│  │                                                                                                              │   │
│  │  STEP 2: Device Identification & Security Check                                                             │   │
│  │  ────────────────────────────────────────────────────────────────────────                                   │   │
│  │  🔍 Check MAC against database:                                                                              │   │
│  │     ┌──────────────────────────────────────────────────────────┐                                           │   │
│  │     │  MAC Database Lookup: AA:BB:CC:DD:EE:FF                   │                                           │   │
│  │     │                                                            │                                           │   │
│  │     │  Status: NEW DEVICE (Not in database)                     │                                           │   │
│  │     │  Action: Check if MAC is blacklisted                      │                                           │   │
│  │     │  Result: ✓ Not blacklisted                                │                                           │   │
│  │     │                                                            │                                           │   │
│  │     │  Decision: ALLOW with auto-provisioning                   │                                           │   │
│  │     └──────────────────────────────────────────────────────────┘                                           │   │
│  │                                                                                                              │   │
│  │  STEP 3: Network Assignment                                                                                 │   │
│  │  ────────────────────────────────────────────────────────────────────────                                   │   │
│  │  🏷️  VLAN Assignment: VLAN 100 (Corporate Network)                                                          │   │
│  │  🔓 Port Security: Enabled                                                                                   │   │
│  │  ✅ Port State: ENABLED                                                                                      │   │
│  │                                                                                                              │   │
│  │  STEP 4: Notify DHCP Server About New Device                                                                │   │
│  │  ────────────────────────────────────────────────────────────────────────                                   │   │
│  │  📤 Send notification to DHCP:                                                                               │   │
│  │     "New device on port eth0"                                                                                │   │
│  │     "MAC: AA:BB:CC:DD:EE:FF"                                                                                 │   │
│  │     "VLAN: 100"                                                                                              │   │
│  │     "Device Type: Unknown (pending DHCP fingerprinting)"                                                     │   │
│  │     "Auto-Provision Flag: TRUE (needs CA certificate)"      ─────────────────┐                              │   │
│  │                                                                               │                              │   │
│  └───────────────────────────────────────────────────────────────────────────────┼──────────────────────────────┘   │
└───────────────────────────────────────────────────────────────────────────────────┼──────────────────────────────────┘
                                                                                    │
                                                                                    │
════════════════════════════════════════════════════════════════════════════════════▼══════════════════════════════════
                            PHASE 2: DHCP WITH ENHANCED OPTIONS (CA CERTIFICATE DELIVERY)
════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════

┌─────────────────────────────────────────────────────────────────────────────────────────────────────────────────────┐
│  COMPONENT 02: DHCP SERVER (Enhanced with Auto-Provisioning)                                                       │
│  ┌────────────────────────────────────────────────────────────────────────────────────────────────────────────┐   │
│  │                                                                                                              │   │
│  │  ⚡ Receives notification from NIC: "New device, needs auto-provisioning"                                    │   │
│  │                                                                                                              │   │
│  │  ┌──────────────────────────────────────────────────────────────────────────────────────────────┐          │   │
│  │  │  DHCP DISCOVER (Broadcast from User Device)                                                  │          │   │
│  │  │  ────────────────────────────────────────────────────────────────────────────────────────    │          │   │
│  │  │  Source MAC: AA:BB:CC:DD:EE:FF                                                                │          │   │
│  │  │  Message: "I need an IP address and network configuration!"                                  │          │   │
│  │  │                                                                                               │          │   │
│  │  │  DHCP Option 55 (Parameter Request List):                                                    │          │   │
│  │  │   - Option 1: Subnet Mask                                                                    │          │   │
│  │  │   - Option 3: Default Gateway                                                                │          │   │
│  │  │   - Option 6: DNS Servers                                                                    │          │   │
│  │  │   - Option 15: Domain Name                                                                   │          │   │
│  │  │   - Option 42: NTP Servers                                                                   │          │   │
│  │  │   - Option 121: Classless Static Routes                                                      │          │   │
│  │  │   - Option 252: WPAD (Web Proxy Auto-Discovery)                                              │          │   │
│  │  └──────────────────────────────────────────────────────────────────────────────────────────────┘          │   │
│  │                                                                                                              │   │
│  │  🔧 DHCP SERVER PROCESSING:                                                                                  │   │
│  │  ────────────────────────────────────────────────────────────────────────────                               │   │
│  │                                                                                                              │   │
│  │  1️⃣  Check IP Pool Availability: 10.0.1.0/24                                                                │   │
│  │      Available IP: 10.0.1.50 ✓                                                                              │   │
│  │                                                                                                              │   │
│  │  2️⃣  MAC Validation: AA:BB:CC:DD:EE:FF                                                                      │   │
│  │      ✓ Not blacklisted                                                                                      │   │
│  │      ✓ Not in reservation conflicts                                                                         │   │
│  │                                                                                                              │   │
│  │  3️⃣  Device Fingerprinting (from DHCP Discover options):                                                   │   │
│  │      ┌──────────────────────────────────────────────────────────┐                                          │   │
│  │      │  DHCP Fingerprint Analysis:                              │                                          │   │
│  │      │  - Vendor Class ID: "MSFT 5.0"                           │                                          │   │
│  │      │  - Hostname: "LAPTOP-USER"                               │                                          │   │
│  │      │  - OS Detection: Windows 10 Enterprise                   │                                          │   │
│  │      │  - Device Type: Corporate Laptop                         │                                          │   │
│  │      └──────────────────────────────────────────────────────────┘                                          │   │
│  │                                                                                                              │   │
│  │  4️⃣  Check Auto-Provisioning Requirements:                                                                 │   │
│  │      ┌──────────────────────────────────────────────────────────┐                                          │   │
│  │      │  Query CA Manager API ────────────────────────┐          │                                          │   │
│  │      │  "Does device AA:BB:CC:DD:EE:FF have our      │          │                                          │   │
│  │      │   Root CA certificate installed?"             │          │                                          │   │
│  │      │                                                │          │                                          │   │
│  │      │  CA Manager Response:                         │          │                                          │   │
│  │      │  ❌ NO - Device does not have CA cert         │          │                                          │   │
│  │      │  ✅ ACTION REQUIRED: Auto-provision CA cert   │          │                                          │   │
│  │      └────────────────────────────────────────────────┼──────────┘                                          │   │
│  │                                                       │                                                     │   │
│  │  5️⃣  Prepare Enhanced DHCP OFFER                     │                                                     │   │
│  │      ───────────────────────────────────────────      │                                                     │   │
│  │                                                       │                                                     │   │
│  │  ┌────────────────────────────────────────────────────▼─────────────────────────────────────────────┐     │   │
│  │  │  📨 DHCP OFFER (Enhanced with Custom Options)                                                     │     │   │
│  │  │  ══════════════════════════════════════════════════════════════════════════════════════════       │     │   │
│  │  │                                                                                                    │     │   │
│  │  │  ┌─ STANDARD DHCP OPTIONS ─────────────────────────────────────────────────────────────┐         │     │   │
│  │  │  │                                                                                       │         │     │   │
│  │  │  │  Option 1  - Subnet Mask:       255.255.255.0                                        │         │     │   │
│  │  │  │  Option 3  - Default Gateway:   10.0.1.1 (Firewall)                                 │         │     │   │
│  │  │  │  Option 6  - DNS Servers:       10.0.0.53 (Internal DNS)                            │         │     │   │
│  │  │  │  Option 15 - Domain Name:       corp.internal                                        │         │     │   │
│  │  │  │  Option 42 - NTP Server:        10.0.0.123                                           │         │     │   │
│  │  │  │  Option 51 - Lease Time:        86400 seconds (24 hours)                            │         │     │   │
│  │  │  │  Option 54 - DHCP Server ID:    10.0.0.105                                           │         │     │   │
│  │  │  │                                                                                       │         │     │   │
│  │  │  └───────────────────────────────────────────────────────────────────────────────────────┘         │     │   │
│  │  │                                                                                                    │     │   │
│  │  │  ┌─ ENHANCED OPTIONS FOR AUTO-PROVISIONING ────────────────────────────────────────────┐         │     │   │
│  │  │  │                                                                                       │         │     │   │
│  │  │  │  🆕 Option 224 (Custom) - CA Certificate URL:                                        │         │     │   │
│  │  │  │      http://10.0.0.105:8080/ca/root-ca.crt                                          │         │     │   │
│  │  │  │                                                                                       │         │     │   │
│  │  │  │  🆕 Option 225 (Custom) - CA Certificate Chain URL:                                  │         │     │   │
│  │  │  │      http://10.0.0.105:8080/ca/certificate-chain.pem                                │         │     │   │
│  │  │  │                                                                                       │         │     │   │
│  │  │  │  🆕 Option 226 (Custom) - Auto-Provisioning Script URL:                              │         │     │   │
│  │  │  │      Windows:  http://10.0.0.105:8080/scripts/install-ca-windows.ps1               │         │     │   │
│  │  │  │      macOS:    http://10.0.0.105:8080/scripts/install-ca-macos.sh                  │         │     │   │
│  │  │  │      Linux:    http://10.0.0.105:8080/scripts/install-ca-linux.sh                  │         │     │   │
│  │  │  │                                                                                       │         │     │   │
│  │  │  │  🆕 Option 227 (Custom) - Certificate Fingerprint (SHA-256):                         │         │     │   │
│  │  │  │      AB:CD:EF:12:34:56:78:90:AB:CD:EF:12:34:56:78:90:AB:CD:EF:12                   │         │     │   │
│  │  │  │      (For validation before installation)                                            │         │     │   │
│  │  │  │                                                                                       │         │     │   │
│  │  │  │  🆕 Option 228 (Custom) - Captive Portal URL (if user action needed):                │         │     │   │
│  │  │  │      https://portal.corp.internal/setup                                              │         │     │   │
│  │  │  │      (Redirects browser for manual download if auto-install fails)                   │         │     │   │
│  │  │  │                                                                                       │         │     │   │
│  │  │  │  🆕 Option 229 (Custom) - GPO/MDM Configuration URL:                                 │         │     │   │
│  │  │  │      http://10.0.0.105:8080/config/enterprise-settings.xml                          │         │     │   │
│  │  │  │      (For domain-joined devices - automatic Group Policy)                            │         │     │   │
│  │  │  │                                                                                       │         │     │   │
│  │  │  │  🆕 Option 230 (Custom) - Certificate Installation Instructions:                     │         │     │   │
│  │  │  │      "This network requires Root CA certificate installation.                        │         │     │   │
│  │  │  │       Your device will auto-install it. If manual install needed,                    │         │     │   │
│  │  │  │       visit: https://portal.corp.internal/setup"                                     │         │     │   │
│  │  │  │                                                                                       │         │     │   │
│  │  │  └───────────────────────────────────────────────────────────────────────────────────────┘         │     │   │
│  │  │                                                                                                    │     │   │
│  │  │  Offered IP Address: 10.0.1.50                                                                    │     │   │
│  │  │                                                                                                    │     │   │
│  │  └────────────────────────────────────────────────────────────────────────────────────────────────────┘     │   │
│  │                                                                                                              │   │
│  │  📤 DHCP OFFER sent to AA:BB:CC:DD:EE:FF                                                                     │   │
│  │                                                                                                              │   │
│  └──────────────────────────────────────────────────────────────────────────────────────────────────────────────┘   │
└─────────────────────────────────────────────────────────────────────────────────────────────────────────────────────┘

    │
    │ User device receives DHCP OFFER with CA certificate info
    ▼

┌─────────────────────────────────────────────────────────────────────────────────────────────────────────────────────┐
│  USER DEVICE (Client-Side Processing)                                                                              │
│  ┌────────────────────────────────────────────────────────────────────────────────────────────────────────────┐   │
│  │                                                                                                              │   │
│  │  📥 DHCP OFFER received and parsed                                                                           │   │
│  │                                                                                                              │   │
│  │  ✅ Standard options processed:                                                                              │   │
│  │     - IP: 10.0.1.50                                                                                          │   │
│  │     - Gateway: 10.0.1.1                                                                                      │   │
│  │     - DNS: 10.0.0.53                                                                                         │   │
│  │                                                                                                              │   │
│  │  🔍 Enhanced options detected:                                                                               │   │
│  │     - Option 224: CA Certificate URL found                                                                   │   │
│  │     - Option 226: Auto-provisioning script URL found                                                         │   │
│  │                                                                                                              │   │
│  │  📨 Send DHCP REQUEST                                                                                        │   │
│  │     "I accept IP 10.0.1.50 and all offered options"                                                          │   │
│  │                                                                                                              │   │
│  └──────────────────────────────────────────────────────────────────────────────────────────────────────────────┘   │
└─────────────────────────────────────────────────────────────────────────────────────────────────────────────────────┘

    │
    ▼

┌─────────────────────────────────────────────────────────────────────────────────────────────────────────────────────┐
│  COMPONENT 02: DHCP SERVER (Finalizing Lease)                                                                      │
│  ┌────────────────────────────────────────────────────────────────────────────────────────────────────────────┐   │
│  │                                                                                                              │   │
│  │  📥 DHCP REQUEST received from AA:BB:CC:DD:EE:FF                                                             │   │
│  │                                                                                                              │   │
│  │  ✅ Commit IP lease to database                                                                              │   │
│  │  ✅ Register hostname in DNS (via Dynamic DNS)                                                               │   │
│  │                                                                                                              │   │
│  │  📨 Send DHCP ACK                                                                                            │   │
│  │     ┌──────────────────────────────────────────────────────────┐                                           │   │
│  │     │  ✓ Lease confirmed: 10.0.1.50                             │                                           │   │
│  │     │  ✓ Lease time: 24 hours                                   │                                           │   │
│  │     │  ✓ All options confirmed (including CA cert URLs)         │                                           │   │
│  │     └──────────────────────────────────────────────────────────┘                                           │   │
│  │                                                                                                              │   │
│  │  📝 Log Event:                                                                                               │   │
│  │     "Lease 10.0.1.50 assigned to AA:BB:CC:DD:EE:FF"                                                          │   │
│  │     "Auto-provisioning enabled: CA certificate"                                                              │   │
│  │     "Device type: Windows 10 Corporate Laptop"                                                               │   │
│  │                                                                                                              │   │
│  │  🔔 Notify CA Manager: "Device 10.0.1.50 ready for certificate installation"  ──────────────┐              │   │
│  │                                                                                               │              │   │
│  └───────────────────────────────────────────────────────────────────────────────────────────────┼──────────────┘   │
└───────────────────────────────────────────────────────────────────────────────────────────────────┼──────────────────┘
                                                                                                    │
                                                                                                    │
════════════════════════════════════════════════════════════════════════════════════════════════════▼══════════════════
                            PHASE 3: AUTOMATIC CA CERTIFICATE INSTALLATION
════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════

┌─────────────────────────────────────────────────────────────────────────────────────────────────────────────────────┐
│  USER DEVICE - Auto-Provisioning Client (Built into OS or Custom Agent)                                            │
│  ┌────────────────────────────────────────────────────────────────────────────────────────────────────────────┐   │
│  │                                                                                                              │   │
│  │  🎯 OPTION A: OPERATING SYSTEM NATIVE INTEGRATION                                                            │   │
│  │  ══════════════════════════════════════════════════════════════════════════════════════                     │   │
│  │                                                                                                              │   │
│  │  📱 Windows 10/11 (Via DHCP Client Service):                                                                 │   │
│  │  ┌────────────────────────────────────────────────────────────────────────────────────────┐                │   │
│  │  │  1. DHCP Client service detects Option 226 (script URL)                                │                │   │
│  │  │  2. Automatically downloads:                                                            │                │   │
│  │  │     http://10.0.0.105:8080/scripts/install-ca-windows.ps1                              │                │   │
│  │  │                                                                                         │                │   │
│  │  │  3. PowerShell script executes with SYSTEM privileges:                                 │                │   │
│  │  │     ┌─────────────────────────────────────────────────────────────────┐               │                │   │
│  │  │     │  # Download Root CA Certificate                                  │               │                │   │
│  │  │     │  Invoke-WebRequest -Uri "http://10.0.0.105:8080/ca/root-ca.crt" │               │                │   │
│  │  │     │                     -OutFile "$env:TEMP\root-ca.crt"             │               │                │   │
│  │  │     │                                                                   │               │                │   │
│  │  │     │  # Verify certificate fingerprint (Option 227)                   │               │                │   │
│  │  │     │  $cert = New-Object System.Security.Cryptography.X509...         │               │                │   │
│  │  │     │  $fingerprint = $cert.Thumbprint                                 │               │                │   │
│  │  │     │  if ($fingerprint -ne "ABCDEF123456...") { Exit 1 }              │               │                │   │
│  │  │     │                                                                   │               │                │   │
│  │  │     │  # Install to Trusted Root Certification Authorities             │               │                │   │
│  │  │     │  Import-Certificate -FilePath "$env:TEMP\root-ca.crt"            │               │                │   │
│  │  │     │                     -CertStoreLocation "Cert:\LocalMachine\Root" │               │                │   │
│  │  │     │                                                                   │               │                │   │
│  │  │     │  # Verify installation                                           │               │                │   │
│  │  │     │  Get-ChildItem "Cert:\LocalMachine\Root" | Where Subject -like...│               │                │   │
│  │  │     │                                                                   │               │                │   │
│  │  │     │  # Report back to CA Manager                                     │               │                │   │
│  │  │     │  Invoke-RestMethod -Uri "http://10.0.0.105:8080/api/report"     │               │                │   │
│  │  │     │                    -Method POST                                  │               │                │   │
│  │  │     │                    -Body @{mac="AA:BB:CC:DD:EE:FF";              │               │                │   │
│  │  │     │                             status="installed";                   │               │                │   │
│  │  │     │                             cert_thumbprint="..."}                │               │                │   │
│  │  │     └─────────────────────────────────────────────────────────────────┘               │                │   │
│  │  │                                                                                         │                │   │
│  │  │  4. ✅ Certificate installed successfully!                                             │                │   │
│  │  │  5. 🔔 Windows notification: "Corporate network certificate installed"                │                │   │
│  │  └────────────────────────────────────────────────────────────────────────────────────────┘                │   │
│  │                                                                                                              │   │
│  │  🍎 macOS (Via System Configuration Profile):                                                               │   │
│  │  ┌────────────────────────────────────────────────────────────────────────────────────────┐                │   │
│  │  │  1. DHCP client detects Option 229 (MDM configuration URL)                             │                │   │
│  │  │  2. Downloads configuration profile from:                                              │                │   │
│  │  │     http://10.0.0.105:8080/config/enterprise-settings.mobileconfig                     │                │   │
│  │  │                                                                                         │                │   │
│  │  │  3. Profile includes:                                                                   │                │   │
│  │  │     - Root CA certificate (embedded in profile)                                        │                │   │
│  │  │     - WiFi settings                                                                    │                │   │
│  │  │     - VPN configuration                                                                │                │   │
│  │  │     - Proxy settings                                                                   │                │   │
│  │  │                                                                                         │                │   │
│  │  │  4. System prompts user:                                                               │                │   │
│  │  │     "Install configuration profile from corp.internal?"                                │                │   │
│  │  │     [Cancel] [Install]                                                                 │                │   │
│  │  │                                                                                         │                │   │
│  │  │  5. User clicks [Install] → Certificate auto-installed to System Keychain             │                │   │
│  │  └────────────────────────────────────────────────────────────────────────────────────────┘                │   │
│  │                                                                                                              │   │
│  │  🐧 Linux (Via Network Manager Hook):                                                                       │   │
│  │  ┌────────────────────────────────────────────────────────────────────────────────────────┐                │   │
│  │  │  1. NetworkManager detects DHCP options                                                 │                │   │
│  │  │  2. Executes dispatcher script: /etc/NetworkManager/dispatcher.d/99-install-ca         │                │   │
│  │  │                                                                                         │                │   │
│  │  │  3. Bash script:                                                                        │                │   │
│  │  │     ┌─────────────────────────────────────────────────────────────────┐               │                │   │
│  │  │     │  #!/bin/bash                                                     │               │                │   │
│  │  │     │  # Download CA cert                                              │               │                │   │
│  │  │     │  wget http://10.0.0.105:8080/ca/root-ca.crt -O /tmp/root-ca.crt │               │                │   │
│  │  │     │                                                                   │               │                │   │
│  │  │     │  # Install to system trust store                                 │               │                │   │
│  │  │     │  cp /tmp/root-ca.crt /usr/local/share/ca-certificates/           │               │                │   │
│  │  │     │  update-ca-certificates                                          │               │                │   │
│  │  │     │                                                                   │               │                │   │
│  │  │     │  # For Firefox (separate cert store)                             │               │                │   │
│  │  │     │  certutil -A -n "Corp Root CA" -t "C,," -d ~/.mozilla/firefox... │               │                │   │
│  │  │     └─────────────────────────────────────────────────────────────────┘               │                │   │
│  │  │                                                                                         │                │   │
│  │  │  4. ✅ Certificate installed system-wide                                               │                │   │
│  │  └────────────────────────────────────────────────────────────────────────────────────────┘                │   │
│  │                                                                                                              │   │
│  │  ═══════════════════════════════════════════════════════════════════════════════════════════════════       │   │
│  │                                                                                                              │   │
│  │  🎯 OPTION B: CAPTIVE PORTAL (If auto-install fails or user interaction required)                           │   │
│  │  ══════════════════════════════════════════════════════════════════════════════════════                     │   │
│  │                                                                                                              │   │
│  │  ┌────────────────────────────────────────────────────────────────────────────────────────┐                │   │
│  │  │  1. User opens web browser                                                              │                │   │
│  │  │  2. First HTTP request intercepted → Redirect to:                                      │                │   │
│  │  │     https://portal.corp.internal/setup (Option 228)                                     │                │   │
│  │  │                                                                                         │                │   │
│  │  │  3. Captive portal page displays:                                                       │                │   │
│  │  │     ┌───────────────────────────────────────────────────────────────┐                 │                │   │
│  │  │     │  🏢 Welcome to Corporate Network                               │                 │                │   │
│  │  │     │                                                                 │                 │                │   │
│  │  │     │  To access network resources, please install the               │                 │                │   │
│  │  │     │  Root CA Certificate:                                          │                 │                │   │
│  │  │     │                                                                 │                 │                │   │
│  │  │     │  [Download Certificate for Windows]                            │                 │                │   │
│  │  │     │  [Download Certificate for macOS]                              │                 │                │   │
│  │  │     │  [Download Certificate for Linux]                              │                 │                │   │
│  │  │     │                                                                 │                 │                │   │
│  │  │     │  Or scan QR code with mobile device:                           │                 │                │   │
│  │  │     │  [QR Code]                                                     │                 │                │   │
│  │  │     │                                                                 │                 │                │   │
│  │  │     │  Installation instructions: [View Guide]                       │                 │                │   │
│  │  │     └───────────────────────────────────────────────────────────────┘                 │                │   │
│  │  │                                                                                         │                │   │
│  │  │  4. User downloads certificate and follows OS-specific instructions                    │                │   │
│  │  └────────────────────────────────────────────────────────────────────────────────────────┘                │   │
│  │                                                                                                              │   │
│  │  ═══════════════════════════════════════════════════════════════════════════════════════════════════       │   │
│  │                                                                                                              │   │
│  │  🎯 OPTION C: ENTERPRISE MANAGEMENT (For domain-joined devices)                                             │   │
│  │  ══════════════════════════════════════════════════════════════════════════════════════                     │   │
│  │                                                                                                              │   │
│  │  ┌────────────────────────────────────────────────────────────────────────────────────────┐                │   │
│  │  │  📋 Windows Group Policy (GPO):                                                         │                │   │
│  │  │     - DHCP Option 229 points to GPO settings                                            │                │   │
│  │  │     - Certificate deployed via: Computer Configuration → Windows Settings →            │                │   │
│  │  │       Security Settings → Public Key Policies → Trusted Root CAs                       │                │   │
│  │  │     - Auto-applied on next Group Policy refresh (every 90 minutes)                     │                │   │
│  │  │                                                                                         │                │   │
│  │  │  📋 MDM (Mobile Device Management) for BYOD:                                            │                │   │
│  │  │     - Intune / JAMF / Workspace ONE                                                     │                │   │
│  │  │     - Certificate pushed via configuration profile                                     │                │   │
│  │  │     - Enforced enrollment before network access                                        │                │   │
│  │  └────────────────────────────────────────────────────────────────────────────────────────┘                │   │
│  │                                                                                                              │   │
│  └──────────────────────────────────────────────────────────────────────────────────────────────────────────────┘   │
└─────────────────────────────────────────────────────────────────────────────────────────────────────────────────────┘

    │
    │ Certificate installation in progress...
    ▼


════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════
                            PHASE 4: CA CERTIFICATE MANAGER VERIFICATION
════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════

┌─────────────────────────────────────────────────────────────────────────────────────────────────────────────────────┐
│  COMPONENT 03: CA CERTIFICATE MANAGER                                                                               │
│  ┌────────────────────────────────────────────────────────────────────────────────────────────────────────────┐   │
│  │                                                                                                              │   │
│  │  📥 Receives installation report from device 10.0.1.50:                                                      │   │
│  │     ┌──────────────────────────────────────────────────────────┐                                           │   │
│  │     │  POST /api/report                                         │                                           │   │
│  │     │  {                                                         │                                           │   │
│  │     │    "mac_address": "AA:BB:CC:DD:EE:FF",                    │                                           │   │
│  │     │    "ip_address": "10.0.1.50",                             │                                           │   │
│  │     │    "hostname": "LAPTOP-USER",                             │                                           │   │
│  │     │    "os": "Windows 10 Enterprise",                         │                                           │   │
│  │     │    "certificate_thumbprint": "AB:CD:EF:12:34:56...",      │                                           │   │
│  │     │    "installation_status": "success",                      │                                           │   │
│  │     │    "installation_method": "auto-powershell",              │                                           │   │
│  │     │    "timestamp": "2025-12-28T09:15:45Z"                    │                                           │   │
│  │     │  }                                                         │                                           │   │
│  │     └──────────────────────────────────────────────────────────┘                                           │   │
│  │                                                                                                              │   │
│  │  🔍 Verification Steps:                                                                                      │   │
│  │  ┌────────────────────────────────────────────────────────────────────────────────────────┐                │   │
│  │  │  1. Validate certificate thumbprint matches our Root CA                                │                │   │
│  │  │     ✓ Thumbprint verified                                                               │                │   │
│  │  │                                                                                         │                │   │
│  │  │  2. Update device database:                                                             │                │   │
│  │  │     ┌─────────────────────────────────────────────────────────────┐                   │                │   │
│  │  │     │  Device Record:                                              │                   │                │   │
│  │  │     │  - MAC: AA:BB:CC:DD:EE:FF                                    │                   │                │   │
│  │  │     │  - IP: 10.0.1.50                                             │                   │                │   │
│  │  │     │  - Hostname: LAPTOP-USER                                     │                   │                │   │
│  │  │     │  - CA Cert Installed: ✅ YES                                 │                   │                │   │
│  │  │     │  - Installation Date: 2025-12-28 09:15:45                   │                   │                │   │
│  │  │     │  - Certificate Expiry: 2045-12-28 (20 years)                │                   │                │   │
│  │  │     │  - Compliance Status: ✅ COMPLIANT                           │                   │                │   │
│  │  │     └─────────────────────────────────────────────────────────────┘                   │                │   │
│  │  │                                                                                         │                │   │
│  │  │  3. Notify other components:                                                            │                │   │
│  │  │     ────────► TLS Inspection: "Device 10.0.1.50 can now be inspected"                  │                │   │
│  │  │     ────────► Firewall: "Device 10.0.1.50 compliant, allow full access"                │                │   │
│  │  │     ────────► SIEM: "Device provisioning complete"                                     │                │   │
│  │  │                                                                                         │                │   │
│  │  │  4. ✅ Device fully provisioned and compliant!                                          │                │   │
│  │  └────────────────────────────────────────────────────────────────────────────────────────┘                │   │
│  │                                                                                                              │   │
│  │  📊 Update Statistics Dashboard:                                                                             │   │
│  │     - Total devices provisioned today: 47                                                                    │   │
│  │     - Auto-provisioning success rate: 94%                                                                    │   │
│  │     - Manual intervention required: 6%                                                                       │   │
│  │                                                                                                              │   │
│  └──────────────────────────────────────────────────────────────────────────────────────────────────────────────┘   │
└─────────────────────────────────────────────────────────────────────────────────────────────────────────────────────┘


════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════
                            PHASE 5: NETWORK ACCESS WITH TLS INSPECTION ENABLED
════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════

    👤 USER (10.0.1.50)
    │  Now has:
    │  ✅ IP Address: 10.0.1.50
    │  ✅ Network connectivity
    │  ✅ Root CA certificate installed
    │  ✅ Trusted corp.internal SSL certificates
    │
    │  Opens browser and types: https://www.google.com
    ▼

┌─────────────────────────────────────────────────────────────────────────────────────────────────────────────────────┐
│  COMPONENT 11: TLS INSPECTION PROXY                                                                                 │
│  ┌────────────────────────────────────────────────────────────────────────────────────────────────────────────┐   │
│  │                                                                                                              │   │
│  │  🔐 TLS Interception (Now Possible!)                                                                         │   │
│  │                                                                                                              │   │
│  │  Before CA cert installation:                                                                                │   │
│  │     ❌ Browser shows: "Your connection is not private"                                                       │   │
│  │     ❌ Certificate error: "Issued by unknown authority"                                                      │   │
│  │     ❌ User must manually bypass warning (security risk!)                                                    │   │
│  │                                                                                                              │   │
│  │  After CA cert installation:                                                                                 │   │
│  │     ✅ Browser trusts proxy certificate (issued by corp.internal CA)                                         │   │
│  │     ✅ NO security warnings                                                                                  │   │
│  │     ✅ Seamless TLS inspection                                                                               │   │
│  │     ✅ User has no idea traffic is being inspected (transparent!)                                            │   │
│  │                                                                                                              │   │
│  │  TLS Session Established:                                                                                    │   │
│  │  ┌────────────────────────────────────────────────────────────────────────────────────────┐                │   │
│  │  │  User ◄──── TLS 1.3 (Trusted) ────► Proxy ◄──── TLS 1.3 ────► Google                  │                │   │
│  │  │             Certificate:                         Certificate:                           │                │   │
│  │  │             CN=*.google.com                      CN=*.google.com                        │                │   │
│  │  │             Issued by: Corp CA ✅                Issued by: Google CA ✅                │                │   │
│  │  └────────────────────────────────────────────────────────────────────────────────────────┘                │   │
│  │                                                                                                              │   │
│  │  ✅ Traffic decrypted → Inspected → Re-encrypted                                                            │   │
│  │  ✅ Malware scanning enabled                                                                                 │   │
│  │  ✅ DLP (Data Loss Prevention) enabled                                                                       │   │
│  │  ✅ Full visibility into HTTPS traffic                                                                       │   │
│  │                                                                                                              │   │
│  └──────────────────────────────────────────────────────────────────────────────────────────────────────────────┘   │
└─────────────────────────────────────────────────────────────────────────────────────────────────────────────────────┘

    │
    │ User browses internet seamlessly with full security inspection
    │ ✅ No certificate warnings
    │ ✅ All HTTPS traffic inspected
    │ ✅ Complete security posture
    ▼

    👤 USER: "Wow, everything just works!"


════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════
                                    COMPLETE INTEGRATION SUMMARY
════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════

┌────────────────────────────────────────────────────────────────────────────────────────────────────────────────────┐
│  COMPONENT INTERACTION FLOW                                                                                        │
│                                                                                                                     │
│  ┌─────────────────────┐                                                                                          │
│  │  01: NIC MANAGEMENT │                                                                                          │
│  │  - Detects device   │                                                                                          │
│  │  - Enables port     │                                                                                          │
│  │  - Assigns VLAN     │                                                                                          │
│  └─────────┬───────────┘                                                                                          │
│            │ Notifies "New device, needs provisioning"                                                            │
│            ▼                                                                                                       │
│  ┌─────────────────────┐          Queries          ┌──────────────────────┐                                      │
│  │  02: DHCP SERVER    │◄───────────────────────────│ 03: CA MANAGER       │                                      │
│  │  - Assigns IP       │  "Does device have CA?"    │ - Provides CA cert   │                                      │
│  │  - Provides DNS     │                            │ - Tracks installation│                                      │
│  │  - Sends CA cert    │──────────────────────────► │ - Verifies compliance│                                      │
│  │    URLs in DHCP     │  CA cert download URLs     │                      │                                      │
│  │    options          │                            │                      │                                      │
│  └─────────┬───────────┘                            └──────────────────────┘                                      │
│            │ Device gets IP + CA cert instructions                                                                │
│            ▼                                                                                                       │
│  ┌─────────────────────┐                                                                                          │
│  │  USER DEVICE        │                                                                                          │
│  │  - Gets 10.0.1.50   │                                                                                          │
│  │  - Auto-downloads   │──────────────────────────► Downloads from:                                               │
│  │    and installs CA  │                            http://10.0.0.105:8080/ca/root-ca.crt                         │
│  │    certificate      │                                                                                          │
│  └─────────┬───────────┘                                                                                          │
│            │ Reports "Installation successful"                                                                    │
│            ▼                                                                                                       │
│  ┌─────────────────────┐                            ┌──────────────────────┐                                      │
│  │  03: CA MANAGER     │───────────────────────────►│ 11: TLS INSPECTION   │                                      │
│  │  - Verifies install │  "Device compliant,        │ - Now can inspect    │                                      │
│  │  - Updates database │   enable inspection"       │   HTTPS traffic      │                                      │
│  └─────────────────────┘                            │ - No cert warnings   │                                      │
│                                                      └──────────────────────┘                                      │
│                                                                                                                     │
│  BENEFITS OF INTEGRATION:                                                                                          │
│  ══════════════════════════════════════════════════════════════════════════════════════════                       │
│  ✅ Zero-touch provisioning - User does nothing!                                                                   │
│  ✅ No manual certificate installation required                                                                    │
│  ✅ No browser security warnings                                                                                   │
│  ✅ Transparent TLS inspection enabled immediately                                                                 │
│  ✅ Full security visibility from first connection                                                                 │
│  ✅ Compliance enforced automatically                                                                              │
│  ✅ Scalable - works for 1 device or 10,000 devices                                                                │
│  ✅ Cross-platform - Windows, macOS, Linux, mobile                                                                 │
│                                                                                                                     │
└────────────────────────────────────────────────────────────────────────────────────────────────────────────────────┘


════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════
                                    TROUBLESHOOTING & FALLBACK
════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════

SCENARIO 1: Auto-Installation Fails
────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
Problem: PowerShell execution policy blocks script, or user doesn't have admin rights

Solution:
  1. Device gets limited network access (Internet only, no internal resources)
  2. User opens browser → Redirected to captive portal (Option 228)
  3. Portal shows installation instructions + download link
  4. User manually installs certificate
  5. Portal verifies installation → Grants full network access

SCENARIO 2: BYOD (Bring Your Own Device) - Non-Domain Joined
────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
Problem: Personal device not managed by IT

Solution:
  1. DHCP provides guest VLAN assignment
  2. Limited network access (Internet + captive portal only)
  3. User enrolls device via captive portal
  4. MDM profile installed (if allowed by policy)
  5. CA certificate included in MDM profile
  6. Device granted appropriate access level (guest/contractor/employee)

SCENARIO 3: Mobile Devices (iOS/Android)
────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
Problem: Cannot run scripts on mobile devices

Solution:
  1. DHCP Option 228 → Captive portal URL
  2. User opens browser → Portal detected
  3. Portal provides configuration profile download (iOS) or APK (Android)
  4. User taps "Install Profile" → CA cert auto-installed
  5. Full network access granted

SCENARIO 4: Certificate Expiry & Renewal
────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
Root CA expiring in 20 years:

  1. CA Manager tracks expiry dates
  2. 1 year before expiry: Generate new Root CA
  3. DHCP options updated with new CA cert URL
  4. Devices automatically download and install new cert alongside old one
  5. After grace period (6 months): Old cert can be removed
  6. Zero downtime, seamless transition!

════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════
                                    END OF INTEGRATION DIAGRAM
════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════
```
