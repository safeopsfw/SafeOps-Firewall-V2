# Complete Integrated System - NIC + DHCP + CA Working Together

**File:** 04_COMPLETE_INTEGRATED_SYSTEM_DIAGRAM.md
**Purpose:** Complete end-to-end flow showing NIC Management, DHCP Server, and Certificate Manager working together
**Scenario:** User connects device → Gets IP → Receives CA URLs → Browses HTTPS → Zero warnings

---

## 🎯 Complete System Architecture

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                         SAFEOPS NETWORK GATEWAY                              │
│                         (Multi-WAN Router + Firewall)                        │
└─────────────────────────────────────────────────────────────────────────────┘
                                    │
                ┌───────────────────┼───────────────────┐
                │                   │                   │
                ▼                   ▼                   ▼
    ┌───────────────────┐  ┌───────────────────┐  ┌───────────────────┐
    │ NIC MANAGEMENT    │  │ DHCP SERVER       │  │ CERTIFICATE MGR   │
    │ Port: 50054       │  │ Port: 67 (UDP)    │  │ Port: 50060       │
    │ Metrics: 9154     │  │ gRPC: 50054       │  │ HTTP: 80          │
    │                   │  │ Metrics: 9154     │  │ OCSP: 8888        │
    │ • Multi-WAN       │  │                   │  │ Metrics: 9160     │
    │ • NAT/NAPT        │  │ • IP Allocation   │  │                   │
    │ • Load Balancing  │  │ • Lease Mgmt      │  │ • Root CA Gen     │
    │ • Failover        │  │ • DNS Integration │  │ • HTTP Distrib    │
    │ • Packet Routing  │  │ • CA Integration  │  │ • TLS Signing     │
    │                   │  │                   │  │ • CRL/OCSP        │
    └───────────────────┘  └───────────────────┘  └───────────────────┘
            │                       │                       │
            │                       │                       │
            └───────────────────────┼───────────────────────┘
                                    │
                                    ▼
                        ┌───────────────────────┐
                        │ PostgreSQL Database   │
                        │ Port: 5432            │
                        ├───────────────────────┤
                        │ • network_interfaces  │
                        │ • connection_tracking │
                        │ • nat_mappings        │
                        │ • dhcp_leases         │
                        │ • dhcp_pools          │
                        │ • device_ca_status    │
                        │ • issued_certificates │
                        │ • revoked_certificates│
                        └───────────────────────┘
```

---

## 📊 Complete Network Flow: Device Connection to HTTPS Browsing

```
┌─────────────────────────────────────────────────────────────────────────────┐
│ STEP 1: User connects device to network                                     │
│ Device: Laptop (johns-laptop)                                               │
│ MAC: AA:BB:CC:DD:EE:FF                                                      │
│ Physical Connection: Ethernet cable plugged into LAN port                   │
└────────────────────┬────────────────────────────────────────────────────────┘
                     │
                     ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│ NIC MANAGEMENT: Detects cable insertion (hotplug)                           │
│ Location: internal/discovery/monitor.go                                     │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                              │
│  Event: Cable inserted on Ethernet 3                                        │
│  ┌────────────────────────────────────────┐                                 │
│  │ Interface: Ethernet 3                  │                                 │
│  │ Type: LAN                              │                                 │
│  │ IP: 192.168.1.1 (gateway)              │                                 │
│  │ Status: LINK UP                        │                                 │
│  │ Speed: 1000 Mbps (Gigabit)             │                                 │
│  │                                         │                                 │
│  │ Action: Ready to receive DHCP requests │                                 │
│  └────────────────────────────────────────┘                                 │
└────────────────────┬────────────────────────────────────────────────────────┘
                     │
                     │ Device broadcasts: DHCP DISCOVER
                     │ Src: 0.0.0.0:68
                     │ Dst: 255.255.255.255:67
                     │
                     ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│ DHCP SERVER: Receives DISCOVER, allocates IP                                │
│ Location: internal/server/listener.go → discovery/discovery.go              │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                              │
│  1. Parse DHCP DISCOVER                                                     │
│  ┌────────────────────────────────────────┐                                 │
│  │ MAC: AA:BB:CC:DD:EE:FF                 │                                 │
│  │ Hostname: johns-laptop                 │                                 │
│  │ Requested IP: None                     │                                 │
│  └────────────────────────────────────────┘                                 │
│          │                                                                   │
│          ▼                                                                   │
│  2. Allocate IP from pool                                                   │
│  ┌────────────────────────────────────────┐                                 │
│  │ Pool: office-network (192.168.1.0/24)  │                                 │
│  │ Range: 192.168.1.100-192.168.1.200     │                                 │
│  │ Next available: 192.168.1.100          │                                 │
│  │ ICMP conflict check: No response ✅    │                                 │
│  └────────────────────────────────────────┘                                 │
│          │                                                                   │
│          ▼                                                                   │
│  3. Send DHCP OFFER                                                         │
│  ┌────────────────────────────────────────┐                                 │
│  │ Offered IP: 192.168.1.100              │                                 │
│  │ Subnet: 255.255.255.0                  │                                 │
│  │ Gateway: 192.168.1.1                   │                                 │
│  │ DNS: 192.168.1.1                       │                                 │
│  │ Lease: 24 hours                        │                                 │
│  └────────────────────────────────────────┘                                 │
└────────────────────┬────────────────────────────────────────────────────────┘
                     │
                     │ Device accepts OFFER
                     │ Device sends: DHCP REQUEST
                     │
                     ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│ DHCP SERVER: Processes REQUEST, calls Certificate Manager                   │
│ Location: internal/discovery/ack.go                                         │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                              │
│  Phase 1: Create lease                                                      │
│  ┌────────────────────────────────────────┐                                 │
│  │ INSERT INTO dhcp_leases                │                                 │
│  │ VALUES (                               │                                 │
│  │   'AA:BB:CC:DD:EE:FF',                 │                                 │
│  │   '192.168.1.100',                     │                                 │
│  │   'johns-laptop',                      │                                 │
│  │   NOW(),                               │                                 │
│  │   NOW() + INTERVAL '24 hours',         │                                 │
│  │   'ACTIVE'                             │                                 │
│  │ )                                       │                                 │
│  └────────────────────────────────────────┘                                 │
│          │                                                                   │
│          ▼                                                                   │
│  Phase 2: ⭐ gRPC call to Certificate Manager                               │
│  ┌────────────────────────────────────────┐                                 │
│  │ Function: cert_integration/ca_provider.go                               │
│  │ gRPC Call: GetCertificateInfo()        │                                 │
│  │ Target: localhost:50060                │                                 │
│  └────────────────────────────────────────┘                                 │
└────────────────────┬────────────────────────────────────────────────────────┘
                     │
                     │ gRPC request
                     ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│ CERTIFICATE MANAGER: Returns CA URLs                                        │
│ Location: internal/grpc/certificate_info.go                                 │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                              │
│  gRPC Method: GetCertificateInfo()                                          │
│  ┌────────────────────────────────────────┐                                 │
│  │ Returns:                               │                                 │
│  │                                         │                                 │
│  │ CertificateInfo {                      │                                 │
│  │   ca_url: "http://192.168.1.1/ca.crt"  │                                 │
│  │   install_script_urls: [               │                                 │
│  │     "http://192.168.1.1/install-ca.sh" │                                 │
│  │     "http://192.168.1.1/install-ca.ps1"│                                 │
│  │   ]                                     │                                 │
│  │   wpad_url: "http://192.168.1.1/wpad.dat"                               │
│  │   crl_url: "http://192.168.1.1/crl.pem"│                                 │
│  │   ocsp_url: "http://192.168.1.1:8888"  │                                 │
│  │ }                                       │                                 │
│  │                                         │                                 │
│  │ Note: Base URL = gateway IP (192.168.1.1)                               │
│  │ Cached for 1 hour                      │                                 │
│  └────────────────────────────────────────┘                                 │
└────────────────────┬────────────────────────────────────────────────────────┘
                     │
                     │ Returns to DHCP Server
                     ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│ DHCP SERVER: Builds DHCP ACK with CA options                                │
│ Location: internal/cert_integration/option_builder.go                       │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                              │
│  Build DHCP ACK packet:                                                     │
│  ┌────────────────────────────────────────┐                                 │
│  │ Message Type: DHCP ACK                 │                                 │
│  │ Your IP: 192.168.1.100                 │                                 │
│  │ Server IP: 192.168.1.1                 │                                 │
│  │                                         │                                 │
│  │ Standard DHCP Options:                 │                                 │
│  │ • Option 1: Subnet Mask = 255.255.255.0│                                 │
│  │ • Option 3: Router = 192.168.1.1       │                                 │
│  │ • Option 6: DNS = 192.168.1.1          │                                 │
│  │ • Option 15: Domain = local.network    │                                 │
│  │ • Option 51: Lease Time = 86400        │                                 │
│  │                                         │                                 │
│  │ ⭐ Custom CA Options:                  │                                 │
│  │ • Option 224: "http://192.168.1.1/ca.crt"                               │
│  │ • Option 225: "http://192.168.1.1/install-ca.sh"                        │
│  │ • Option 252: "http://192.168.1.1/wpad.dat"                             │
│  │                                         │                                 │
│  │ Sent to: 192.168.1.100:68              │                                 │
│  └────────────────────────────────────────┘                                 │
│          │                                                                   │
│          ▼                                                                   │
│  Simultaneously: Update DNS                                                 │
│  ┌────────────────────────────────────────┐                                 │
│  │ gRPC Call: DynamicUpdate()             │                                 │
│  │ Target: localhost:50053 (DNS Server)   │                                 │
│  │                                         │                                 │
│  │ Create DNS records:                    │                                 │
│  │ • A: johns-laptop.local.network → 192.168.1.100                         │
│  │ • PTR: 100.1.168.192.in-addr.arpa → johns-laptop                        │
│  └────────────────────────────────────────┘                                 │
└────────────────────┬────────────────────────────────────────────────────────┘
                     │
                     │ DHCP ACK delivered
                     ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│ DEVICE: Applies network configuration                                       │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                              │
│  Network Configuration Applied:                                             │
│  ┌────────────────────────────────────────┐                                 │
│  │ IP Address: 192.168.1.100 ✅           │                                 │
│  │ Subnet Mask: 255.255.255.0 ✅          │                                 │
│  │ Default Gateway: 192.168.1.1 ✅        │                                 │
│  │ DNS Server: 192.168.1.1 ✅             │                                 │
│  │ Domain Name: local.network ✅          │                                 │
│  │                                         │                                 │
│  │ ⭐ CA Certificate URLs stored:         │                                 │
│  │ • Option 224 → http://192.168.1.1/ca.crt                                │
│  │ • Option 225 → http://192.168.1.1/install-ca.sh                         │
│  │ • Option 252 → http://192.168.1.1/wpad.dat                              │
│  └────────────────────────────────────────┘                                 │
│                                                                              │
│  Network Status:                                                            │
│  ✅ IP assigned and configured                                              │
│  ✅ Gateway reachable (ping 192.168.1.1)                                    │
│  ✅ DNS functional (can resolve domains)                                    │
│  ✅ Internet access available (via NAT)                                     │
│  ✅ CA URLs available in DHCP lease info                                    │
└────────────────────┬────────────────────────────────────────────────────────┘
                     │
                     │ User opens browser
                     │ Navigates to: http://192.168.1.1/ca.crt
                     │
                     ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│ CERTIFICATE MANAGER: Serves CA certificate via HTTP                         │
│ Location: internal/distribution/http_server.go (Port 80)                    │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                              │
│  HTTP GET /ca.crt                                                            │
│  ┌────────────────────────────────────────┐                                 │
│  │ 1. Read CA certificate:                │                                 │
│  │    /etc/safeops/ca/root-cert.pem       │                                 │
│  │                                         │                                 │
│  │ 2. Track download:                     │                                 │
│  │    INSERT INTO certificate_downloads   │                                 │
│  │    VALUES ('192.168.1.100', 'PEM', NOW())                               │
│  │                                         │                                 │
│  │ 3. Return HTTP 200 OK                  │                                 │
│  │    Content-Type: application/x-x509-ca-cert                             │
│  │    Content-Disposition: attachment; filename="safeops-ca.crt"           │
│  │                                         │                                 │
│  │    -----BEGIN CERTIFICATE-----         │                                 │
│  │    MIIFazCCA1OgAwIBAgIUQk5...         │                                 │
│  │    -----END CERTIFICATE-----           │                                 │
│  └────────────────────────────────────────┘                                 │
└────────────────────┬────────────────────────────────────────────────────────┘
                     │
                     │ CA certificate downloaded
                     │ User installs certificate (manual or script)
                     │
                     ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│ USER: Installs CA certificate (Manual)                                      │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                              │
│  Windows:                                                                   │
│  1. Double-click safeops-ca.crt                                             │
│  2. Click "Install Certificate..."                                          │
│  3. Select "Trusted Root Certification Authorities"                         │
│  4. Click "Yes" on security warning                                         │
│  ✅ CA installed to Windows trust store                                     │
│                                                                              │
│  macOS:                                                                     │
│  1. Double-click safeops-ca.crt                                             │
│  2. Keychain Access opens                                                   │
│  3. Double-click cert → Trust → "Always Trust"                              │
│  ✅ CA installed to macOS Keychain                                          │
│                                                                              │
│  Linux:                                                                     │
│  $ sudo cp safeops-ca.crt /usr/local/share/ca-certificates/                │
│  $ sudo update-ca-certificates                                              │
│  ✅ CA installed to Linux trust store                                       │
└────────────────────┬────────────────────────────────────────────────────────┘
                     │
                     │ User browses to: https://example.com
                     │
                     ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│ NIC MANAGEMENT: Routes HTTPS traffic through gateway                        │
│ Location: internal/router/routing_engine.rs (Rust)                          │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                              │
│  Outbound Packet:                                                           │
│  ┌────────────────────────────────────────┐                                 │
│  │ Source: 192.168.1.100:54321 (LAN)      │                                 │
│  │ Dest: 93.184.216.34:443 (example.com)  │                                 │
│  │ Protocol: TCP                          │                                 │
│  └────────────────────────────────────────┘                                 │
│          │                                                                   │
│          ▼                                                                   │
│  NAT Translation (translator.rs - Rust):                                    │
│  ┌────────────────────────────────────────┐                                 │
│  │ Before NAT:                            │                                 │
│  │   Src: 192.168.1.100:54321             │                                 │
│  │                                         │                                 │
│  │ After NAT (via WAN 1):                 │                                 │
│  │   Src: 203.0.113.5:10001               │                                 │
│  │                                         │                                 │
│  │ NAT Mapping Stored:                    │                                 │
│  │   192.168.1.100:54321 → 203.0.113.5:10001                               │
│  └────────────────────────────────────────┘                                 │
│          │                                                                   │
│          ▼                                                                   │
│  Forward to WAN 1 → Internet                                                │
│                                                                              │
│  BUT FIRST: TLS Proxy Intercepts!                                           │
│  ┌────────────────────────────────────────┐                                 │
│  │ TLS Proxy needs to decrypt HTTPS       │                                 │
│  │ • Intercept TCP connection to :443     │                                 │
│  │ • Establish TLS with real example.com  │                                 │
│  │ • Present certificate to client        │                                 │
│  │                                         │                                 │
│  │ → Needs signed certificate for example.com                              │
│  └────────────────────────────────────────┘                                 │
└────────────────────┬────────────────────────────────────────────────────────┘
                     │
                     │ TLS Proxy calls Certificate Manager
                     │ gRPC: SignCertificate("example.com")
                     │
                     ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│ CERTIFICATE MANAGER: Signs on-the-fly certificate                           │
│ Location: internal/tls_integration/signing_service.go                       │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                              │
│  1. Check cache (24h TTL)                                                   │
│  ┌────────────────────────────────────────┐                                 │
│  │ Look for: example.com                  │                                 │
│  │ Cache miss → Proceed to signing        │                                 │
│  └────────────────────────────────────────┘                                 │
│          │                                                                   │
│          ▼                                                                   │
│  2. ⭐ Check revocation status                                              │
│  ┌────────────────────────────────────────┐                                 │
│  │ Query: revoked_certificates            │                                 │
│  │ Result: example.com NOT revoked ✅     │                                 │
│  └────────────────────────────────────────┘                                 │
│          │                                                                   │
│          ▼                                                                   │
│  3. Generate & sign certificate                                             │
│  ┌────────────────────────────────────────┐                                 │
│  │ Subject: CN=example.com                │                                 │
│  │ Issuer: CN=SafeOps Root CA             │                                 │
│  │ SAN: example.com, *.example.com        │                                 │
│  │ Validity: 90 days                      │                                 │
│  │                                         │                                 │
│  │ Sign with CA private key:              │                                 │
│  │ • Load encrypted key                   │                                 │
│  │ • Decrypt with passphrase              │                                 │
│  │ • Sign certificate (SHA256-RSA)        │                                 │
│  │ • Clear key from memory                │                                 │
│  └────────────────────────────────────────┘                                 │
│          │                                                                   │
│          ▼                                                                   │
│  4. Store & cache                                                           │
│  ┌────────────────────────────────────────┐                                 │
│  │ • Cache for 24h                        │                                 │
│  │ • Store in issued_certificates table   │                                 │
│  │ • Audit log: sign operation            │                                 │
│  └────────────────────────────────────────┘                                 │
│          │                                                                   │
│          ▼                                                                   │
│  Return signed certificate to TLS Proxy                                     │
└────────────────────┬────────────────────────────────────────────────────────┘
                     │
                     │ TLS Proxy presents certificate to client
                     ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│ TLS PROXY: Presents certificate to client browser                           │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                              │
│  TLS Handshake:                                                             │
│  ┌────────────────────────────────────────┐                                 │
│  │ Server Hello:                          │                                 │
│  │ • Cipher Suite: TLS_ECDHE_RSA_...      │                                 │
│  │ • TLS Version: 1.3                     │                                 │
│  │                                         │                                 │
│  │ Certificate:                           │                                 │
│  │ • Subject: CN=example.com              │                                 │
│  │ • Issuer: CN=SafeOps Root CA ⭐        │                                 │
│  │ • Validity: 90 days                    │                                 │
│  │ • SAN: example.com, *.example.com      │                                 │
│  └────────────────────────────────────────┘                                 │
│          │                                                                   │
│          ▼                                                                   │
│  Client (Browser) Verification:                                             │
│  ┌────────────────────────────────────────┐                                 │
│  │ 1. Check certificate chain:            │                                 │
│  │    Issuer: SafeOps Root CA             │                                 │
│  │                                         │                                 │
│  │ 2. Lookup in trust store:              │                                 │
│  │    Found: SafeOps Root CA ✅           │                                 │
│  │                                         │                                 │
│  │ 3. Verify signature:                   │                                 │
│  │    Valid signature ✅                  │                                 │
│  │                                         │                                 │
│  │ 4. Check validity period:              │                                 │
│  │    Within range ✅                     │                                 │
│  │                                         │                                 │
│  │ 5. Verify hostname:                    │                                 │
│  │    example.com matches SAN ✅          │                                 │
│  │                                         │                                 │
│  │ 6. ⭐ Check revocation (Optional):     │                                 │
│  │    OCSP check to 192.168.1.1:8888      │                                 │
│  │    Status: GOOD ✅                     │                                 │
│  └────────────────────────────────────────┘                                 │
│          │                                                                   │
│          ▼                                                                   │
│  Result: Certificate TRUSTED ✅                                             │
│  ┌────────────────────────────────────────┐                                 │
│  │ ✅ TLS handshake successful            │                                 │
│  │ ✅ No certificate warnings             │                                 │
│  │ ✅ Browser shows padlock (secure)      │                                 │
│  │ ✅ User unaware of interception        │                                 │
│  └────────────────────────────────────────┘                                 │
└────────────────────┬────────────────────────────────────────────────────────┘
                     │
                     ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│ CERTIFICATE MANAGER: Detects CA installation                                │
│ Location: internal/device_tracking/detector.go                              │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                              │
│  Background Service (runs every 5 minutes):                                 │
│  ┌────────────────────────────────────────┐                                 │
│  │ For device: 192.168.1.100              │                                 │
│  │                                         │                                 │
│  │ 1. Create test certificate:            │                                 │
│  │    • CN=test.local                     │                                 │
│  │    • Signed by SafeOps Root CA         │                                 │
│  │                                         │                                 │
│  │ 2. Attempt TLS handshake:              │                                 │
│  │    • Connect to device (or proxy)      │                                 │
│  │    • Present test certificate          │                                 │
│  │                                         │                                 │
│  │ 3. Observe result:                     │                                 │
│  │    ✅ Handshake succeeded              │                                 │
│  │    → Device trusts SafeOps CA!         │                                 │
│  │                                         │                                 │
│  │ 4. Update database:                    │                                 │
│  │    UPDATE device_ca_status             │                                 │
│  │    SET ca_installed = TRUE,            │                                 │
│  │        detected_at = NOW()             │                                 │
│  │    WHERE device_ip = '192.168.1.100'   │                                 │
│  └────────────────────────────────────────┘                                 │
└─────────────────────────────────────────────────────────────────────────────┘
```

---

## 🔄 Component Interaction Summary

### 1. NIC Management ↔ DHCP Server

```
Coordination:
• NIC Management detects LAN interfaces (192.168.1.1)
• Reports gateway IP to DHCP Server
• DHCP uses gateway IP for Option 3 (Router)
```

### 2. DHCP Server ↔ Certificate Manager

```
Integration Point: internal/cert_integration/ca_provider.go

Flow:
1. DHCP Server → gRPC GetCertificateInfo()
2. Certificate Manager → Returns CA URLs
3. DHCP Server → Embeds in DHCP Options 224, 225, 252
4. Device → Receives CA URLs automatically

Caching:
• CA URLs cached for 1 hour
• Reduces gRPC calls (performance optimization)
```

### 3. NIC Management ↔ TLS Proxy ↔ Certificate Manager

```
Integration Point: internal/tls_integration/signing_service.go

Flow:
1. NIC Management routes HTTPS traffic through gateway
2. TLS Proxy intercepts connection
3. TLS Proxy → gRPC SignCertificate("example.com")
4. Certificate Manager → Signs certificate, returns
5. TLS Proxy → Presents certificate to client
6. Client → Trusts certificate (SafeOps CA installed)
7. Connection established with zero warnings
```

### 4. Certificate Manager: Revocation Integration

```
CRL (Certificate Revocation List):
• Generated every 24 hours
• Served via HTTP: http://192.168.1.1/crl.pem
• Browsers/apps check CRL periodically

OCSP (Online Certificate Status Protocol):
• Real-time revocation status
• Port: 192.168.1.1:8888
• Responds to status queries
```

---

## 📊 Database Integration

```
┌─────────────────────────────────────────────────────────────────────────────┐
│ PostgreSQL Database (Shared Across Services)                                │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                              │
│ NIC Management Tables:                                                      │
│ • network_interfaces → WAN/LAN inventory                                    │
│ • connection_tracking → Active sessions                                     │
│ • nat_mappings → LAN IP:Port → WAN IP:Port                                  │
│ • wan_health_history → WAN uptime tracking                                  │
│                                                                              │
│ DHCP Server Tables:                                                         │
│ • dhcp_pools → IP address pools                                             │
│ • dhcp_leases → Active leases (MAC → IP mapping)                            │
│ • dhcp_reservations → Static MAC → IP bindings                              │
│                                                                              │
│ Certificate Manager Tables:                                                 │
│ • device_ca_status → Which devices have CA installed                        │
│ • certificate_downloads → Download tracking                                 │
│ • issued_certificates → All signed certificates                             │
│ • revoked_certificates → Revoked certificate serial numbers                 │
│ • ca_audit_log → Tamper-proof audit trail                                   │
│                                                                              │
│ Cross-Service Queries:                                                      │
│ • DHCP leases → Device CA status (track coverage)                           │
│ • NAT mappings → Certificate downloads (forensics)                          │
│ • Connection tracking → Issued certificates (TLS inspection audit)          │
└─────────────────────────────────────────────────────────────────────────────┘
```

---

## 📡 gRPC Service Communication Map

```
┌─────────────────────────────────────────────────────────────────────────────┐
│ gRPC Communication Between Services                                         │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                              │
│ DHCP Server → Certificate Manager (Port 50060)                              │
│ ┌──────────────────────────────────────────────────────────────────────┐   │
│ │ RPC: GetCertificateInfo()                                            │   │
│ │ Frequency: On every DHCP ACK (cached for 1h)                         │   │
│ │ Purpose: Get CA URLs for DHCP Options 224, 225, 252                  │   │
│ │ Returns: ca_url, install_script_urls, wpad_url, crl_url, ocsp_url   │   │
│ └──────────────────────────────────────────────────────────────────────┘   │
│                                                                              │
│ DHCP Server → DNS Server (Port 50053)                                       │
│ ┌──────────────────────────────────────────────────────────────────────┐   │
│ │ RPC: DynamicUpdate()                                                 │   │
│ │ Frequency: On lease create/renew/release                             │   │
│ │ Purpose: Create/update/delete DNS records (A + PTR)                  │   │
│ │ Data: hostname, IP, MAC, lease_expiry                                │   │
│ └──────────────────────────────────────────────────────────────────────┘   │
│                                                                              │
│ TLS Proxy → Certificate Manager (Port 50060)                                │
│ ┌──────────────────────────────────────────────────────────────────────┐   │
│ │ RPC: SignCertificate()                                               │   │
│ │ Frequency: On every new HTTPS domain (cached for 24h)                │   │
│ │ Purpose: Get signed certificate for TLS interception                 │   │
│ │ Input: domain name (e.g., "example.com")                             │   │
│ │ Returns: Signed X.509 certificate (PEM format)                       │   │
│ └──────────────────────────────────────────────────────────────────────┘   │
│                                                                              │
│ Admin Tool → Certificate Manager (Port 50060)                               │
│ ┌──────────────────────────────────────────────────────────────────────┐   │
│ │ RPC: RevokeCertificate()                                             │   │
│ │ Frequency: Manual admin action                                       │   │
│ │ Purpose: Revoke compromised certificates                             │   │
│ │ Input: serial_number, reason, revoked_by                             │   │
│ │ Result: Certificate added to CRL, OCSP updated                       │   │
│ └──────────────────────────────────────────────────────────────────────┘   │
└─────────────────────────────────────────────────────────────────────────────┘
```

---

## 📈 Performance & Monitoring

```
┌─────────────────────────────────────────────────────────────────────────────┐
│ Prometheus Metrics (Aggregated)                                             │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                              │
│ NIC Management (Port 9154):                                                 │
│ • nic_wan_status{interface="Ethernet 1"} 1                                  │
│ • nic_wan_latency_ms{interface="Ethernet 1"} 12                             │
│ • nic_nat_sessions_total 1523                                               │
│ • nic_interface_rx_bytes_per_sec{interface="Ethernet 1"} 987654321          │
│                                                                              │
│ DHCP Server (Port 9154):                                                    │
│ • dhcp_leases_active 143                                                    │
│ • dhcp_pool_utilization{pool="office-network"} 0.71                         │
│ • dhcp_ca_distribution_total 143                                            │
│ • dhcp_dns_updates_total 143                                                │
│                                                                              │
│ Certificate Manager (Port 9160):                                            │
│ • certificate_manager_certificates_issued_total 547                         │
│ • certificate_manager_certificates_revoked_total 3                          │
│ • certificate_manager_devices_with_ca_installed 138                         │
│ • certificate_manager_ocsp_requests_total 1245                              │
│                                                                              │
│ Combined Health Dashboard:                                                  │
│ • WAN1 Status: HEALTHY (12ms latency)                                       │
│ • WAN2 Status: HEALTHY (18ms latency)                                       │
│ • DHCP Leases: 143 active (71% pool utilization)                            │
│ • CA Installation Rate: 96.5% (138/143 devices)                             │
│ • NAT Sessions: 1,523 active                                                │
│ • TLS Inspection: Operational (zero cert warnings)                          │
└─────────────────────────────────────────────────────────────────────────────┘
```

---

## ✅ End Result: Zero-Touch HTTPS Inspection

```
┌─────────────────────────────────────────────────────────────────────────────┐
│ USER EXPERIENCE SUMMARY                                                      │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                              │
│ Step 1: User plugs Ethernet cable                                           │
│         ✅ Device gets IP automatically (DHCP)                              │
│                                                                              │
│ Step 2: Device receives CA URLs in DHCP (Options 224, 225, 252)             │
│         ✅ Zero manual configuration                                        │
│                                                                              │
│ Step 3: User clicks link or gateway redirects to http://192.168.1.1/ca.crt  │
│         ✅ One-click CA certificate download                                │
│                                                                              │
│ Step 4: User installs CA certificate (double-click on Windows/Mac)          │
│         ✅ Simple installation wizard                                       │
│                                                                              │
│ Step 5: User browses to https://example.com                                 │
│         ✅ TLS Proxy intercepts connection                                  │
│         ✅ Certificate Manager signs on-the-fly cert                        │
│         ✅ Browser trusts certificate (SafeOps CA installed)                │
│         ✅ No certificate warnings                                          │
│         ✅ Green padlock shown (secure connection)                          │
│                                                                              │
│ Result: Transparent HTTPS inspection with zero user friction                │
│                                                                              │
│ Security Benefits:                                                           │
│ • ✅ HTTPS traffic visible to firewall                                      │
│ • ✅ Malware detection in encrypted traffic                                 │
│ • ✅ Data Loss Prevention (DLP) works on HTTPS                              │
│ • ✅ Content filtering operational                                          │
│ • ✅ Compliance requirements met                                            │
│ • ✅ Certificate revocation supported (CRL + OCSP)                          │
│ • ✅ Full audit trail (tamper-proof logging)                                │
└─────────────────────────────────────────────────────────────────────────────┘
```

---

**End of Complete Integrated System Diagram**
