# Integration Examples
## How to Integrate Certificate Manager with Other SafeOps Services

---

## 📡 gRPC Proto Definitions

First, ensure you have the proto definitions. The Certificate Manager exposes these gRPC services:

```protobuf
// File: proto/certificate_manager.proto

syntax = "proto3";

package certificate_manager;

option go_package = "certificate_manager/pkg/grpc";

// ============================================================================
// Service Definition
// ============================================================================

service CertificateManager {
    // Sign a certificate for SSL interception
    rpc SignCertificate(SignCertificateRequest) returns (SignCertificateResponse);

    // Get CA certificate info for DHCP distribution
    rpc GetCertificateInfo(GetCertificateInfoRequest) returns (GetCertificateInfoResponse);

    // Check device CA installation status
    rpc GetDeviceStatus(GetDeviceStatusRequest) returns (GetDeviceStatusResponse);

    // Revoke a certificate
    rpc RevokeCertificate(RevokeCertificateRequest) returns (RevokeCertificateResponse);

    // Get service health status
    rpc GetHealth(HealthRequest) returns (HealthResponse);
}

// ============================================================================
// Sign Certificate (for TLS Proxy)
// ============================================================================

message SignCertificateRequest {
    string domain = 1;                 // Primary domain (e.g., "example.com")
    repeated string sans = 2;          // Subject Alternative Names
    int32 validity_days = 3;           // Certificate validity in days
    bool enable_wildcard = 4;          // Generate wildcard cert (*.example.com)
    string request_id = 5;             // Optional request tracking ID
}

message SignCertificateResponse {
    bytes certificate_pem = 1;         // Signed certificate in PEM format
    bytes private_key_pem = 2;         // Private key in PEM format
    string serial_number = 3;          // Certificate serial number
    bool from_cache = 4;               // Whether served from cache
    int64 signing_time_ms = 5;         // Time taken to sign (milliseconds)
    string cache_key = 6;              // Cache key for this certificate
}

// ============================================================================
// Get Certificate Info (for DHCP)
// ============================================================================

message GetCertificateInfoRequest {
    string device_mac = 1;             // Device MAC address
    string device_ip = 2;              // Device IP address
    string device_hostname = 3;        // Device hostname (optional)
    string device_type = 4;            // Device type/OS (optional)
}

message GetCertificateInfoResponse {
    string ca_url = 1;                            // CA certificate download URL
    repeated string install_script_urls = 2;      // Auto-install script URLs
    string wpad_url = 3;                          // WPAD URL for proxy config
    string crl_url = 4;                           // CRL download URL
    string ocsp_url = 5;                          // OCSP responder URL
    string trust_guide_url = 6;                   // Installation guide URL
    string qr_code_url = 7;                       // QR code URL for mobile
    map<string, string> platform_specific_urls = 8; // Platform-specific URLs
}

// ============================================================================
// Get Device Status (for DNS/Firewall)
// ============================================================================

message GetDeviceStatusRequest {
    string device_mac = 1;             // Device MAC address
    string device_ip = 2;              // Device IP address
}

message GetDeviceStatusResponse {
    bool ca_installed = 1;             // Whether CA is installed on device
    string installation_timestamp = 2;  // When CA was installed (RFC3339)
    string detection_method = 3;        // How it was detected (e.g., "tls_handshake")
    string last_verified = 4;           // Last verification timestamp
    int32 successful_handshakes = 5;    // Number of successful TLS handshakes
}

// ============================================================================
// Revoke Certificate
// ============================================================================

message RevokeCertificateRequest {
    string serial_number = 1;          // Certificate serial to revoke
    string reason = 2;                 // Revocation reason
}

message RevokeCertificateResponse {
    bool success = 1;
    string message = 2;
}

// ============================================================================
// Health Check
// ============================================================================

message HealthRequest {}

message HealthResponse {
    bool healthy = 1;
    string status = 2;
    bool ca_loaded = 3;
    int64 cache_size = 4;
    int64 uptime_seconds = 5;
    string version = 6;
}
```

---

## 🔐 Integration 1: TLS Proxy

### Go Implementation

```go
// File: src/tls_proxy/internal/mitm/certificate_client.go

package mitm

import (
    "context"
    "crypto/tls"
    "crypto/x509"
    "encoding/pem"
    "fmt"
    "log"
    "sync"
    "time"

    "google.golang.org/grpc"
    "google.golang.org/grpc/credentials/insecure"
    pb "certificate_manager/pkg/grpc"
)

// ============================================================================
// Certificate Client for TLS Proxy
// ============================================================================

// CertificateClient handles communication with Certificate Manager
type CertificateClient struct {
    conn   *grpc.ClientConn
    client pb.CertificateManagerClient

    // Local cache (additional layer on top of server-side cache)
    cache      map[string]*tls.Certificate
    cacheMu    sync.RWMutex
    cacheExpiry time.Duration

    // Statistics
    totalRequests    int64
    cacheHits        int64
    cacheMisses      int64
    signingErrors    int64
}

// NewCertificateClient creates a new certificate client
func NewCertificateClient(certManagerAddr string) (*CertificateClient, error) {
    // Connect to Certificate Manager gRPC server
    conn, err := grpc.Dial(
        certManagerAddr,
        grpc.WithTransportCredentials(insecure.NewCredentials()),
        grpc.WithDefaultCallOptions(
            grpc.MaxCallRecvMsgSize(10 * 1024 * 1024), // 10 MB
        ),
    )
    if err != nil {
        return nil, fmt.Errorf("failed to connect to certificate manager: %w", err)
    }

    client := pb.NewCertificateManagerClient(conn)

    cc := &CertificateClient{
        conn:        conn,
        client:      client,
        cache:       make(map[string]*tls.Certificate),
        cacheExpiry: 1 * time.Hour, // Local cache for 1 hour
    }

    // Verify connection
    if err := cc.checkHealth(); err != nil {
        conn.Close()
        return nil, fmt.Errorf("certificate manager health check failed: %w", err)
    }

    log.Printf("[tls-proxy] Connected to Certificate Manager at %s", certManagerAddr)
    return cc, nil
}

// checkHealth verifies Certificate Manager is healthy
func (cc *CertificateClient) checkHealth() error {
    ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
    defer cancel()

    resp, err := cc.client.GetHealth(ctx, &pb.HealthRequest{})
    if err != nil {
        return err
    }

    if !resp.Healthy || !resp.CaLoaded {
        return fmt.Errorf("certificate manager not ready (healthy=%v, ca_loaded=%v)",
            resp.Healthy, resp.CaLoaded)
    }

    log.Printf("[tls-proxy] Certificate Manager: %s (v%s, cache_size=%d)",
        resp.Status, resp.Version, resp.CacheSize)
    return nil
}

// ============================================================================
// Main Function: Get Certificate for Domain
// ============================================================================

// GetCertificateForDomain gets or generates a certificate for the given domain
func (cc *CertificateClient) GetCertificateForDomain(ctx context.Context, domain string) (*tls.Certificate, error) {
    // Check local cache first
    cc.cacheMu.RLock()
    if cert, ok := cc.cache[domain]; ok {
        cc.cacheMu.RUnlock()
        cc.cacheHits++
        log.Printf("[tls-proxy] Certificate for %s served from local cache", domain)
        return cert, nil
    }
    cc.cacheMu.RUnlock()

    cc.cacheMisses++
    cc.totalRequests++

    // Call Certificate Manager to sign certificate
    req := &pb.SignCertificateRequest{
        Domain:       domain,
        Sans:         []string{domain, "www." + domain},
        ValidityDays: 90,
        EnableWildcard: false,
    }

    reqCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
    defer cancel()

    resp, err := cc.client.SignCertificate(reqCtx, req)
    if err != nil {
        cc.signingErrors++
        return nil, fmt.Errorf("failed to sign certificate for %s: %w", domain, err)
    }

    // Parse certificate and private key
    cert, err := cc.parseCertificateResponse(resp)
    if err != nil {
        return nil, fmt.Errorf("failed to parse certificate response: %w", err)
    }

    // Cache locally
    cc.cacheMu.Lock()
    cc.cache[domain] = cert
    cc.cacheMu.Unlock()

    if resp.FromCache {
        log.Printf("[tls-proxy] Certificate for %s served from server cache (signing_time=%dms)",
            domain, resp.SigningTimeMs)
    } else {
        log.Printf("[tls-proxy] Certificate for %s generated (signing_time=%dms)",
            domain, resp.SigningTimeMs)
    }

    return cert, nil
}

// parseCertificateResponse converts gRPC response to tls.Certificate
func (cc *CertificateClient) parseCertificateResponse(resp *pb.SignCertificateResponse) (*tls.Certificate, error) {
    // Parse certificate PEM
    certBlock, _ := pem.Decode(resp.CertificatePem)
    if certBlock == nil {
        return nil, fmt.Errorf("failed to decode certificate PEM")
    }

    _, err := x509.ParseCertificate(certBlock.Bytes)
    if err != nil {
        return nil, fmt.Errorf("failed to parse certificate: %w", err)
    }

    // Parse private key PEM
    keyBlock, _ := pem.Decode(resp.PrivateKeyPem)
    if keyBlock == nil {
        return nil, fmt.Errorf("failed to decode private key PEM")
    }

    // Create tls.Certificate
    cert, err := tls.X509KeyPair(resp.CertificatePem, resp.PrivateKeyPem)
    if err != nil {
        return nil, fmt.Errorf("failed to create X509 key pair: %w", err)
    }

    return &cert, nil
}

// ============================================================================
// Usage in TLS Handshake
// ============================================================================

// GetConfigForClient returns TLS config for the given ClientHello
// This is called by the TLS library during each handshake
func (cc *CertificateClient) GetConfigForClient(hello *tls.ClientHelloInfo) (*tls.Config, error) {
    // Extract domain from SNI (Server Name Indication)
    domain := hello.ServerName
    if domain == "" {
        return nil, fmt.Errorf("no SNI provided in ClientHello")
    }

    log.Printf("[tls-proxy] Intercepting connection to %s", domain)

    // Get certificate for this domain
    cert, err := cc.GetCertificateForDomain(context.Background(), domain)
    if err != nil {
        return nil, fmt.Errorf("failed to get certificate for %s: %w", domain, err)
    }

    // Return TLS config with our certificate
    return &tls.Config{
        Certificates: []tls.Certificate{*cert},
        MinVersion:   tls.VersionTLS12,
        MaxVersion:   tls.VersionTLS13,
    }, nil
}

// ============================================================================
// Statistics
// ============================================================================

// GetStats returns client statistics
func (cc *CertificateClient) GetStats() map[string]int64 {
    cc.cacheMu.RLock()
    defer cc.cacheMu.RUnlock()

    return map[string]int64{
        "total_requests":    cc.totalRequests,
        "cache_hits":        cc.cacheHits,
        "cache_misses":      cc.cacheMisses,
        "signing_errors":    cc.signingErrors,
        "local_cache_size":  int64(len(cc.cache)),
    }
}

// Close closes the connection to Certificate Manager
func (cc *CertificateClient) Close() error {
    if cc.conn != nil {
        return cc.conn.Close()
    }
    return nil
}
```

### Integration in TLS Proxy Main

```go
// File: src/tls_proxy/cmd/main.go

package main

import (
    "crypto/tls"
    "log"
    "net"

    "tls_proxy/internal/mitm"
)

func main() {
    // Initialize Certificate Client
    certClient, err := mitm.NewCertificateClient("localhost:50060")
    if err != nil {
        log.Fatalf("Failed to initialize certificate client: %v", err)
    }
    defer certClient.Close()

    // Create TLS listener with dynamic certificate generation
    tlsConfig := &tls.Config{
        GetConfigForClient: certClient.GetConfigForClient,
        MinVersion:         tls.VersionTLS12,
    }

    listener, err := tls.Listen("tcp", ":443", tlsConfig)
    if err != nil {
        log.Fatalf("Failed to start TLS listener: %v", err)
    }

    log.Printf("TLS Proxy listening on :443")

    for {
        conn, err := listener.Accept()
        if err != nil {
            log.Printf("Accept error: %v", err)
            continue
        }

        go handleConnection(conn, certClient)
    }
}

func handleConnection(clientConn net.Conn, certClient *mitm.CertificateClient) {
    defer clientConn.Close()

    tlsConn, ok := clientConn.(*tls.Conn)
    if !ok {
        log.Printf("Connection is not TLS")
        return
    }

    // Complete TLS handshake
    if err := tlsConn.Handshake(); err != nil {
        log.Printf("TLS handshake error: %v", err)
        return
    }

    // Get target domain
    domain := tlsConn.ConnectionState().ServerName
    log.Printf("Connected to client, target domain: %s", domain)

    // Now connect to real server and proxy traffic
    // ... (rest of proxy logic)
}
```

---

## 📡 Integration 2: DHCP Server

### Go Implementation

```go
// File: src/dhcp_server/internal/certificate/client.go

package certificate

import (
    "context"
    "fmt"
    "log"
    "time"

    "google.golang.org/grpc"
    "google.golang.org/grpc/credentials/insecure"
    pb "certificate_manager/pkg/grpc"
)

// ============================================================================
// Certificate Info Client for DHCP
// ============================================================================

// InfoClient retrieves CA certificate URLs for DHCP distribution
type InfoClient struct {
    conn   *grpc.ClientConn
    client pb.CertificateManagerClient
}

// NewInfoClient creates a new certificate info client
func NewInfoClient(certManagerAddr string) (*InfoClient, error) {
    conn, err := grpc.Dial(
        certManagerAddr,
        grpc.WithTransportCredentials(insecure.NewCredentials()),
    )
    if err != nil {
        return nil, fmt.Errorf("failed to connect: %w", err)
    }

    return &InfoClient{
        conn:   conn,
        client: pb.NewCertificateManagerClient(conn),
    }, nil
}

// GetCertificateURLs gets CA certificate URLs for a device
func (ic *InfoClient) GetCertificateURLs(ctx context.Context, mac, ip, hostname, deviceType string) (*CertificateInfo, error) {
    req := &pb.GetCertificateInfoRequest{
        DeviceMac:      mac,
        DeviceIp:       ip,
        DeviceHostname: hostname,
        DeviceType:     deviceType,
    }

    ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
    defer cancel()

    resp, err := ic.client.GetCertificateInfo(ctx, req)
    if err != nil {
        return nil, fmt.Errorf("failed to get certificate info: %w", err)
    }

    return &CertificateInfo{
        CAURL:              resp.CaUrl,
        InstallScriptURLs:  resp.InstallScriptUrls,
        WPADURL:           resp.WpadUrl,
        CRLURL:            resp.CrlUrl,
        OCSPURL:           resp.OcspUrl,
        TrustGuideURL:     resp.TrustGuideUrl,
        QRCodeURL:         resp.QrCodeUrl,
        PlatformURLs:      resp.PlatformSpecificUrls,
    }, nil
}

// CertificateInfo holds CA certificate information
type CertificateInfo struct {
    CAURL             string
    InstallScriptURLs []string
    WPADURL           string
    CRLURL            string
    OCSPURL           string
    TrustGuideURL     string
    QRCodeURL         string
    PlatformURLs      map[string]string
}

func (ic *InfoClient) Close() error {
    if ic.conn != nil {
        return ic.conn.Close()
    }
    return nil
}
```

### Integration in DHCP ACK Response

```go
// File: src/dhcp_server/internal/server/dhcp_handler.go

package server

import (
    "context"
    "log"
    "net"

    "github.com/insomniacslk/dhcp/dhcpv4"
    "dhcp_server/internal/certificate"
)

type DHCPHandler struct {
    certClient *certificate.InfoClient
    // ... other fields
}

func (h *DHCPHandler) HandleDHCPRequest(req *dhcpv4.DHCPv4) (*dhcpv4.DHCPv4, error) {
    // Extract device info
    mac := req.ClientHWAddr.String()
    hostname := req.HostName()

    // Determine device type from DHCP fingerprint
    deviceType := h.identifyDeviceType(req)

    // Get certificate URLs from Certificate Manager
    certInfo, err := h.certClient.GetCertificateURLs(
        context.Background(),
        mac,
        "",  // IP assigned later
        hostname,
        deviceType,
    )
    if err != nil {
        log.Printf("[dhcp] Failed to get certificate info: %v", err)
        // Continue without CA distribution
    }

    // Build DHCP ACK response
    resp := &dhcpv4.DHCPv4{
        OpCode:        dhcpv4.OpcodeBootReply,
        HWType:        req.HWType,
        ClientHWAddr:  req.ClientHWAddr,
        YourIPAddr:    net.ParseIP("10.0.0.50"), // Assigned IP
        ServerIPAddr:  net.ParseIP("10.0.0.1"),  // DHCP server IP
        // ... other fields
    }

    // Add standard DHCP options
    resp.Options.Update(dhcpv4.OptSubnetMask(net.IPv4Mask(255, 255, 255, 0)))
    resp.Options.Update(dhcpv4.OptRouter(net.ParseIP("10.0.0.1")))
    resp.Options.Update(dhcpv4.OptDNS(net.ParseIP("10.0.0.1")))
    resp.Options.Update(dhcpv4.OptIPAddressLeaseTime(24 * 3600)) // 24 hours

    // Add CA certificate distribution options (if available)
    if certInfo != nil {
        // Option 224: CA Certificate URL (custom)
        resp.Options.Update(dhcpv4.OptGeneric(
            dhcpv4.OptionCode(224),
            []byte(certInfo.CAURL),
        ))

        // Option 225: Install Script URLs (custom)
        if len(certInfo.InstallScriptURLs) > 0 {
            resp.Options.Update(dhcpv4.OptGeneric(
                dhcpv4.OptionCode(225),
                []byte(certInfo.InstallScriptURLs[0]),
            ))
        }

        // Option 252: WPAD (standard)
        if certInfo.WPADURL != "" {
            resp.Options.Update(dhcpv4.OptGeneric(
                dhcpv4.OptionCode(252),
                []byte(certInfo.WPADURL),
            ))
        }

        log.Printf("[dhcp] Provided CA URL to %s (%s): %s",
            mac, deviceType, certInfo.CAURL)
    }

    return resp, nil
}

func (h *DHCPHandler) identifyDeviceType(req *dhcpv4.DHCPv4) string {
    // Identify device type from DHCP fingerprint
    // This is a simplified example

    vendorClass := req.Options.Get(dhcpv4.OptionVendorClassIdentifier)
    if vendorClass != nil {
        vc := string(vendorClass)
        switch {
        case contains(vc, "iPhone"):
            return "iOS"
        case contains(vc, "android"):
            return "Android"
        case contains(vc, "MSFT"):
            return "Windows"
        case contains(vc, "Apple"):
            return "macOS"
        }
    }

    return "Unknown"
}

func contains(s, substr string) bool {
    return len(s) >= len(substr) && s[:len(substr)] == substr
}
```

---

## 🌐 Integration 3: DNS Server

### Go Implementation

```go
// File: src/dns_server/internal/certificate/status_checker.go

package certificate

import (
    "context"
    "fmt"
    "log"
    "sync"
    "time"

    "google.golang.org/grpc"
    "google.golang.org/grpc/credentials/insecure"
    pb "certificate_manager/pkg/grpc"
)

// ============================================================================
// Device Status Checker for DNS
// ============================================================================

// StatusChecker checks if devices have CA installed
type StatusChecker struct {
    conn   *grpc.ClientConn
    client pb.CertificateManagerClient

    // Cache device status to avoid repeated gRPC calls
    cache   map[string]*DeviceStatus
    cacheMu sync.RWMutex
    cacheTTL time.Duration
}

// DeviceStatus represents CA installation status
type DeviceStatus struct {
    MAC              string
    IP               string
    CAInstalled      bool
    LastVerified     time.Time
    CachedAt         time.Time
}

// NewStatusChecker creates a new status checker
func NewStatusChecker(certManagerAddr string) (*StatusChecker, error) {
    conn, err := grpc.Dial(
        certManagerAddr,
        grpc.WithTransportCredentials(insecure.NewCredentials()),
    )
    if err != nil {
        return nil, fmt.Errorf("failed to connect: %w", err)
    }

    return &StatusChecker{
        conn:     conn,
        client:   pb.NewCertificateManagerClient(conn),
        cache:    make(map[string]*DeviceStatus),
        cacheTTL: 5 * time.Minute,
    }, nil
}

// IsCAInstalled checks if device has CA certificate installed
func (sc *StatusChecker) IsCAInstalled(ctx context.Context, mac, ip string) (bool, error) {
    // Check cache first
    cacheKey := mac
    if cacheKey == "" {
        cacheKey = ip
    }

    sc.cacheMu.RLock()
    if status, ok := sc.cache[cacheKey]; ok {
        if time.Since(status.CachedAt) < sc.cacheTTL {
            sc.cacheMu.RUnlock()
            log.Printf("[dns] Device %s CA status from cache: %v", cacheKey, status.CAInstalled)
            return status.CAInstalled, nil
        }
    }
    sc.cacheMu.RUnlock()

    // Query Certificate Manager
    req := &pb.GetDeviceStatusRequest{
        DeviceMac: mac,
        DeviceIp:  ip,
    }

    ctx, cancel := context.WithTimeout(ctx, 2*time.Second)
    defer cancel()

    resp, err := sc.client.GetDeviceStatus(ctx, req)
    if err != nil {
        return false, fmt.Errorf("failed to get device status: %w", err)
    }

    // Update cache
    status := &DeviceStatus{
        MAC:          mac,
        IP:           ip,
        CAInstalled:  resp.CaInstalled,
        LastVerified: time.Now(),
        CachedAt:     time.Now(),
    }

    sc.cacheMu.Lock()
    sc.cache[cacheKey] = status
    sc.cacheMu.Unlock()

    log.Printf("[dns] Device %s CA installed: %v (method: %s, successful_handshakes: %d)",
        cacheKey, resp.CaInstalled, resp.DetectionMethod, resp.SuccessfulHandshakes)

    return resp.CaInstalled, nil
}

func (sc *StatusChecker) Close() error {
    if sc.conn != nil {
        return sc.conn.Close()
    }
    return nil
}
```

### Integration in DNS Query Handler

```go
// File: src/dns_server/internal/server/dns_handler.go

package server

import (
    "context"
    "log"
    "net"

    "github.com/miekg/dns"
    "dns_server/internal/certificate"
)

type DNSHandler struct {
    certStatusChecker *certificate.StatusChecker
    captivePortalIP   net.IP
    // ... other fields
}

func (h *DNSHandler) ServeDNS(w dns.ResponseWriter, req *dns.Msg) {
    resp := new(dns.Msg)
    resp.SetReply(req)
    resp.Authoritative = true

    // Get client info
    clientAddr, _ := w.RemoteAddr().(*net.UDPAddr)
    clientIP := clientAddr.IP.String()

    // Look up client MAC from ARP cache (implementation specific)
    clientMAC := h.lookupMAC(clientIP)

    // Get query domain
    if len(req.Question) == 0 {
        w.WriteMsg(resp)
        return
    }
    question := req.Question[0]
    domain := question.Name

    log.Printf("[dns] Query from %s (%s) for %s", clientIP, clientMAC, domain)

    // Check if device has CA installed
    caInstalled, err := h.certStatusChecker.IsCAInstalled(
        context.Background(),
        clientMAC,
        clientIP,
    )
    if err != nil {
        log.Printf("[dns] Failed to check CA status: %v", err)
        // On error, assume not installed and redirect to captive portal
        caInstalled = false
    }

    if !caInstalled {
        // Device doesn't have CA - redirect to captive portal
        log.Printf("[dns] Device %s doesn't have CA, redirecting to captive portal", clientMAC)

        // Return captive portal IP for all domains
        // Exception: Allow connectivity check domains
        if !h.isConnectivityCheckDomain(domain) {
            rr := &dns.A{
                Hdr: dns.RR_Header{
                    Name:   question.Name,
                    Rrtype: dns.TypeA,
                    Class:  dns.ClassINET,
                    Ttl:    0, // No caching
                },
                A: h.captivePortalIP,
            }
            resp.Answer = append(resp.Answer, rr)
            w.WriteMsg(resp)
            return
        }
    }

    // Device has CA installed or connectivity check domain
    // Forward to upstream DNS and return real IP
    realIP, err := h.resolveUpstream(domain)
    if err != nil {
        resp.Rcode = dns.RcodeServerFailure
        w.WriteMsg(resp)
        return
    }

    rr := &dns.A{
        Hdr: dns.RR_Header{
            Name:   question.Name,
            Rrtype: dns.TypeA,
            Class:  dns.ClassINET,
            Ttl:    300,
        },
        A: realIP,
    }
    resp.Answer = append(resp.Answer, rr)

    log.Printf("[dns] Resolved %s to %s for %s", domain, realIP, clientMAC)
    w.WriteMsg(resp)
}

func (h *DNSHandler) isConnectivityCheckDomain(domain string) bool {
    // Allow these domains to always resolve to real IPs
    // so devices can detect captive portal properly
    connectivityDomains := []string{
        "captive.apple.com.",
        "connectivitycheck.gstatic.com.",
        "msftconnecttest.com.",
        "clients3.google.com.",
    }

    for _, cd := range connectivityDomains {
        if domain == cd {
            return true
        }
    }
    return false
}

func (h *DNSHandler) resolveUpstream(domain string) (net.IP, error) {
    // Query upstream DNS server (e.g., 8.8.8.8)
    // Implementation omitted for brevity
    return net.ParseIP("93.184.216.34"), nil
}

func (h *DNSHandler) lookupMAC(ip string) string {
    // Look up MAC address from ARP cache or device database
    // Implementation specific to your system
    return "AA:BB:CC:DD:EE:FF"
}
```

---

## 🧪 Testing the Integrations

### Test TLS Proxy Integration

```bash
# Terminal 1: Start Certificate Manager
cd src/certificate_manager
./certificate_manager.exe

# Terminal 2: Test certificate signing via gRPC
grpcurl -plaintext \
  -d '{"domain":"example.com","sans":["example.com","www.example.com"],"validity_days":90}' \
  localhost:50060 \
  certificate_manager.CertificateManager/SignCertificate

# Expected output: Certificate and private key in PEM format
```

### Test DHCP Integration

```bash
# Test getting certificate info
grpcurl -plaintext \
  -d '{"device_mac":"AA:BB:CC:DD:EE:FF","device_ip":"10.0.0.50","device_type":"Windows"}' \
  localhost:50060 \
  certificate_manager.CertificateManager/GetCertificateInfo

# Expected output:
{
  "caUrl": "http://192.168.1.1/ca.crt",
  "installScriptUrls": ["http://192.168.1.1/install-ca.ps1"],
  "wpadUrl": "http://192.168.1.1/wpad.dat",
  "crlUrl": "http://192.168.1.1/crl.pem",
  "ocspUrl": "http://192.168.1.1:8888"
}
```

### Test DNS Integration

```bash
# Test device status check
grpcurl -plaintext \
  -d '{"device_mac":"AA:BB:CC:DD:EE:FF","device_ip":"10.0.0.50"}' \
  localhost:50060 \
  certificate_manager.CertificateManager/GetDeviceStatus

# Expected output:
{
  "caInstalled": false,
  "installationTimestamp": "",
  "detectionMethod": "",
  "lastVerified": "",
  "successfulHandshakes": 0
}
```

---

## 📊 Complete Integration Flow

```
1. Device Connects
        ↓
2. DHCP assigns IP + calls GetCertificateInfo()
        ↓
3. DHCP includes CA URL in options
        ↓
4. Device makes DNS query
        ↓
5. DNS calls GetDeviceStatus() → CA not installed
        ↓
6. DNS returns captive portal IP
        ↓
7. Device redirected to captive portal
        ↓
8. User downloads and installs CA
        ↓
9. Device makes HTTPS request
        ↓
10. TLS Proxy intercepts, calls SignCertificate()
         ↓
11. Certificate Manager signs cert for domain
         ↓
12. TLS Proxy presents cert to device
         ↓
13. Device validates cert (signed by installed CA) → SUCCESS
         ↓
14. Certificate Manager detects successful handshake
         ↓
15. Updates device status: CA installed = TRUE
         ↓
16. Future DNS queries return real IPs
         ↓
17. Full SSL interception enabled!
```

---

That's the complete integration! All services work together seamlessly through the Certificate Manager's gRPC API.
