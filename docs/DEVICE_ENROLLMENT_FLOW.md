# SafeOps Device Enrollment Flow

## Complete Flow Diagram

```
┌─────────────────────────────────────────────────────────────────────────────────┐
│                    NEW DEVICE CONNECTS TO NETWORK                                │
└─────────────────────────────────────────────────────────────────────────────────┘
                                      │
                                      ▼
┌─────────────────────────────────────────────────────────────────────────────────┐
│  STEP 1: PHYSICAL CONNECTION                                                     │
│  ─────────────────────────────                                                   │
│  Device connects via:                                                            │
│    • WiFi (connects to SafeOps AP)                                               │
│    • Ethernet (plugs into managed switch)                                        │
│    • Hotspot (connects to SafeOps hotspot)                                       │
└─────────────────────────────────────────────────────────────────────────────────┘
                                      │
                                      ▼
┌─────────────────────────────────────────────────────────────────────────────────┐
│  STEP 2: DHCP REQUEST                                                            │
│  ─────────────────────                                                           │
│  Device: "I need an IP address!"                                                 │
│                                                                                  │
│  ┌──────────────────┐         DHCP Discover          ┌──────────────────────┐   │
│  │   New Device     │ ──────────────────────────────▶│  SafeOps DHCP Server │   │
│  │   (No IP yet)    │                                │     (Port 67)        │   │
│  └──────────────────┘                                └──────────────────────┘   │
└─────────────────────────────────────────────────────────────────────────────────┘
                                      │
                                      ▼
┌─────────────────────────────────────────────────────────────────────────────────┐
│  STEP 3: DHCP RESPONSE                                                           │
│  ──────────────────────                                                          │
│  DHCP Server assigns:                                                            │
│    ✓ IP Address:    192.168.1.105                                                │
│    ✓ Subnet Mask:   255.255.255.0                                                │
│    ✓ Gateway:       192.168.1.1                                                  │
│    ✓ DNS Server:    192.168.1.1  ← KEY! Points to SafeOps DNS                   │
│                                                                                  │
│  ┌──────────────────┐         DHCP Offer/Ack         ┌──────────────────────┐   │
│  │   New Device     │ ◀──────────────────────────────│  SafeOps DHCP Server │   │
│  │  IP: 192.168.1.105│                               │                      │   │
│  └──────────────────┘                                └──────────────────────┘   │
│                                                                                  │
│  ┌─────── LINUX MANAGED DEVICES ───────┐                                         │
│  │ DHCP Hook runs → Cert auto-installed │  ← ZERO-CLICK PATH!                    │
│  │ Device marked enrolled → DONE! ✅    │                                         │
│  └──────────────────────────────────────┘                                         │
└─────────────────────────────────────────────────────────────────────────────────┘
                                      │
                                      ▼
┌─────────────────────────────────────────────────────────────────────────────────┐
│  STEP 4: DEVICE MAKES FIRST DNS QUERY                                            │
│  ─────────────────────────────────────────                                       │
│  Browser/App tries to access internet:                                           │
│                                                                                  │
│  ┌──────────────────┐    "What IP is google.com?"    ┌──────────────────────┐   │
│  │   New Device     │ ──────────────────────────────▶│  SafeOps DNS Server  │   │
│  │                  │                                │     (Port 53)        │   │
│  └──────────────────┘                                └──────────────────────┘   │
└─────────────────────────────────────────────────────────────────────────────────┘
                                      │
                                      ▼
┌─────────────────────────────────────────────────────────────────────────────────┐
│  STEP 5: DNS SERVER CHECKS ENROLLMENT                                            │
│  ─────────────────────────────────────────                                       │
│                                                                                  │
│  DNS Server checks:                                                              │
│    ┌────────────────────────────────────────────────────────────────────┐       │
│    │  IsDeviceEnrolled(192.168.1.105)?                                  │       │
│    │                                                                    │       │
│    │  1. Check in-memory cache                                          │       │
│    │  2. Check database (device_enrollment table)                       │       │
│    │  3. Query Certificate Manager                                      │       │
│    │                                                                    │       │
│    │  Result: NOT ENROLLED (new device)                                 │       │
│    └────────────────────────────────────────────────────────────────────┘       │
└─────────────────────────────────────────────────────────────────────────────────┘
                                      │
                         ┌────────────┴────────────┐
                         │                         │
                    ENROLLED?                 NOT ENROLLED
                         │                         │
                         ▼                         ▼
┌──────────────────────────────┐    ┌──────────────────────────────────────────────┐
│  NORMAL RESOLUTION           │    │  STEP 6: DNS HIJACKS RESPONSE                │
│  ─────────────────────       │    │  ─────────────────────────────               │
│                              │    │                                              │
│  DNS returns real IP:        │    │  Instead of real google.com IP,              │
│  google.com → 172.217.x.x    │    │  DNS returns PORTAL IP:                      │
│                              │    │                                              │
│  ┌────────────────────────┐  │    │  google.com → 192.168.1.1 (Portal)           │
│  │ Device browses normally│  │    │                                              │
│  │ All traffic is secure  │  │    │  ┌─────────────────────────────────────────┐ │
│  │ (CA cert validates TLS)│  │    │  │ ANY domain → Portal IP                  │ │
│  └────────────────────────┘  │    │  │ (Until device is enrolled)              │ │
│                              │    │  └─────────────────────────────────────────┘ │
│  ✅ DONE!                    │    │                                              │
└──────────────────────────────┘    └──────────────────────────────────────────────┘
                                                       │
                                                       ▼
┌─────────────────────────────────────────────────────────────────────────────────┐
│  STEP 7: BROWSER LOADS CAPTIVE PORTAL                                            │
│  ─────────────────────────────────────                                           │
│                                                                                  │
│  User's browser tries to load google.com                                         │
│  But actually connects to 192.168.1.1 (Portal)                                   │
│                                                                                  │
│  ┌─────────────────────────────────────────────────────────────────────────┐    │
│  │                                                                         │    │
│  │   ┌─────────────────────────────────────────────────────────────────┐   │    │
│  │   │                    🔐 SafeOps Network                           │   │    │
│  │   │                                                                 │   │    │
│  │   │   To access the network securely, please install                │   │    │
│  │   │   the SafeOps security certificate.                             │   │    │
│  │   │                                                                 │   │    │
│  │   │   Detected: Windows                                             │   │    │
│  │   │                                                                 │   │    │
│  │   │              [ Download Certificate ]  ← USER CLICKS            │   │    │
│  │   │                                                                 │   │    │
│  │   │   Installation Steps:                                           │   │    │
│  │   │   1. Click Download                                             │   │    │
│  │   │   2. Open the file                                              │   │    │
│  │   │   3. Install to Trusted Root                                    │   │    │
│  │   └─────────────────────────────────────────────────────────────────┘   │    │
│  │                                                                         │    │
│  └─────────────────────────────────────────────────────────────────────────┘    │
│                                                                                  │
│  ┌─────── WINDOWS DOMAIN DEVICES ───────┐                                         │
│  │ GPO already pushed cert at login     │  ← ZERO-CLICK PATH!                    │
│  │ Device was already enrolled → SKIP   │                                         │
│  └──────────────────────────────────────┘                                         │
└─────────────────────────────────────────────────────────────────────────────────┘
                                      │
                                      ▼
┌─────────────────────────────────────────────────────────────────────────────────┐
│  STEP 8: USER DOWNLOADS & INSTALLS CERTIFICATE                                   │
│  ───────────────────────────────────────────────                                 │
│                                                                                  │
│  ┌──────────────────┐    GET /download?os=Windows    ┌──────────────────────┐   │
│  │   User's Browser │ ──────────────────────────────▶│  Captive Portal      │   │
│  │                  │                                │     (Port 80)        │   │
│  │                  │ ◀──────────────────────────────│                      │   │
│  │                  │    SafeOps-CA.crt              │                      │   │
│  └──────────────────┘                                └──────────────────────┘   │
│                                                                                  │
│  User installs certificate:                                                      │
│    Windows: Double-click → Install Certificate → Trusted Root                   │
│    macOS:   Double-click → Add to Keychain → Trust                              │
│    Linux:   Copy to /usr/local/share/ca-certificates → update-ca-certificates  │
│    Android: Settings → Security → Install certificate                           │
│    iOS:     Settings → Profile → Install → Trust                                │
└─────────────────────────────────────────────────────────────────────────────────┘
                                      │
                                      ▼
┌─────────────────────────────────────────────────────────────────────────────────┐
│  STEP 9: PORTAL MARKS DEVICE AS ENROLLED                                         │
│  ─────────────────────────────────────────                                       │
│                                                                                  │
│  After download, browser redirects to /success                                   │
│                                                                                  │
│  ┌──────────────────┐      POST /api/enroll          ┌──────────────────────┐   │
│  │  Captive Portal  │ ──────────────────────────────▶│  DNS Server API      │   │
│  │                  │    {ip: "192.168.1.105",       │                      │   │
│  │                  │     os: "Windows",             │                      │   │
│  │                  │     method: "portal"}          │                      │   │
│  └──────────────────┘                                └──────────────────────┘   │
│                                                                                  │
│  DNS Server:                                                                     │
│    1. Updates in-memory cache: 192.168.1.105 = ENROLLED                         │
│    2. Saves to database: device_enrollment table                                │
│    3. Logs: "Device enrolled: 192.168.1.105"                                    │
└─────────────────────────────────────────────────────────────────────────────────┘
                                      │
                                      ▼
┌─────────────────────────────────────────────────────────────────────────────────┐
│  STEP 10: DEVICE BROWSES NORMALLY                                                │
│  ──────────────────────────────────                                              │
│                                                                                  │
│  Now when device makes DNS queries:                                              │
│                                                                                  │
│  ┌──────────────────┐    "What IP is google.com?"    ┌──────────────────────┐   │
│  │   Device         │ ──────────────────────────────▶│  SafeOps DNS Server  │   │
│  │  (ENROLLED)      │                                │                      │   │
│  │                  │ ◀──────────────────────────────│  IsEnrolled? YES ✓   │   │
│  │                  │    google.com → 172.217.x.x    │  Return REAL IP      │   │
│  └──────────────────┘         (Real IP)              └──────────────────────┘   │
│                                                                                  │
│  ┌──────────────────────────────────────────────────────────────────────────┐   │
│  │                                                                          │   │
│  │   Device can now:                                                        │   │
│  │   ✅ Browse internet normally                                            │   │
│  │   ✅ Access HTTPS sites (CA validates certificates)                      │   │
│  │   ✅ TLS Proxy can inspect traffic (if configured)                       │   │
│  │   ✅ Threat Intelligence can block malicious domains                     │   │
│  │                                                                          │   │
│  └──────────────────────────────────────────────────────────────────────────┘   │
└─────────────────────────────────────────────────────────────────────────────────┘
                                      │
                                      ▼
                             ╔═══════════════════╗
                             ║   ✅ COMPLETE!    ║
                             ║   Device Secured  ║
                             ╚═══════════════════╝


┌─────────────────────────────────────────────────────────────────────────────────┐
│                           ZERO-CLICK PATHS SUMMARY                               │
├─────────────────────────────────────────────────────────────────────────────────┤
│                                                                                  │
│  WINDOWS DOMAIN:                                                                 │
│  ───────────────                                                                 │
│  Device joins domain → GPO applies → Cert installed → Already enrolled!         │
│  Flow: Step 1 → 2 → 3 → 4 → 5 → ENROLLED → Normal browsing                      │
│                                                                                  │
│  LINUX WITH DHCP HOOK:                                                           │
│  ─────────────────────                                                           │
│  Device gets DHCP → Hook script runs → Cert installed → Auto-enrolled!          │
│  Flow: Step 1 → 2 → 3 (hook runs) → 4 → 5 → ENROLLED → Normal browsing          │
│                                                                                  │
│  ANDROID WITH HEADWIND MDM:                                                      │
│  ──────────────────────────                                                      │
│  Device enrolled in MDM → Cert pushed → Already enrolled!                        │
│  Flow: Step 1 → 2 → 3 → 4 → 5 → ENROLLED → Normal browsing                      │
│                                                                                  │
│  macOS/iOS WITH MDM:                                                             │
│  ───────────────────                                                             │
│  Device enrolled in MDM → Profile pushed → Already enrolled!                     │
│  Flow: Step 1 → 2 → 3 → 4 → 5 → ENROLLED → Normal browsing                      │
│                                                                                  │
└─────────────────────────────────────────────────────────────────────────────────┘
```

## Component Interaction Diagram

```
┌─────────────────────────────────────────────────────────────────────────────────┐
│                         SAFEOPS COMPONENT ARCHITECTURE                           │
└─────────────────────────────────────────────────────────────────────────────────┘

                           ┌───────────────────────────────┐
                           │         NEW DEVICE            │
                           │    (Phone/Laptop/IoT)         │
                           └───────────────┬───────────────┘
                                           │
                    ┌──────────────────────┼──────────────────────┐
                    │                      │                      │
                    ▼                      ▼                      ▼
         ┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐
         │   NIC Manager   │    │   DHCP Server   │    │   DNS Server    │
         │   (Port 50051)  │    │   (Port 67)     │    │   (Port 53)     │
         │                 │    │                 │    │                 │
         │  • Interface    │    │  • IP Pool      │    │  • Caching      │
         │    Management   │    │  • Lease Mgmt   │    │  • Filtering    │
         │  • WiFi/Hotspot │    │  • DNS Config   │    │  • Captive      │
         │  • VLAN         │    │                 │    │    Portal       │
         └────────┬────────┘    └────────┬────────┘    └────────┬────────┘
                  │                      │                      │
                  │                      │                      │
                  └──────────────────────┴──────────────────────┘
                                         │
                                         ▼
                              ┌─────────────────────┐
                              │ Captive Portal HTTP │
                              │     (Port 80)       │
                              │                     │
                              │  • Install Page     │
                              │  • Cert Download    │
                              │  • OS Detection     │
                              │  • Enrollment API   │
                              └──────────┬──────────┘
                                         │
                                         ▼
                              ┌─────────────────────┐
                              │ Certificate Manager │
                              │    (Port 50055)     │
                              │                     │
                              │  • CA Generation    │
                              │  • Cert Signing     │
                              │  • Device Tracking  │
                              └──────────┬──────────┘
                                         │
                                         ▼
                              ┌─────────────────────┐
                              │     PostgreSQL      │
                              │    (Port 5432)      │
                              │                     │
                              │  • device_enrollment│
                              │  • dns_zones        │
                              │  • dhcp_leases      │
                              └─────────────────────┘
```
