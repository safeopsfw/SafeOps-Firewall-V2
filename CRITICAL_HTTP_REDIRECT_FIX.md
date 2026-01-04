# 🚨 CRITICAL: HTTP Redirect Fix

## Problem: HTTP Redirect to Captive Portal Doesn't Work

**You're RIGHT** - we need to BLOCK and wait for TLS Proxy response!

**Current flow (BROKEN):**
```
Packet Engine → Forward packet IMMEDIATELY
             → Send copy to TLS Proxy (response ignored!)
```

**Required flow (CORRECT):**
```
Packet Engine → Send to TLS Proxy → WAIT for response
             → If INJECT: Send 302 redirect
             → If FORWARD: Send original packet
```

---

## Solution: Use Go NIC Management (10 minutes)

The **Rust packet_engine.exe** we just built has the memory fixes but **doesn't wait for TLS Proxy response**.

The **Go version** (`cmd/main.go`) **DOES** wait properly!

### Quick Fix:

Edit `start-phase-3AB.ps1` line 77-79:

**CHANGE FROM:**
```powershell
Write-Host "[3/3] Starting Packet Engine (Rust)..." -ForegroundColor Green
$packetEnginePath = "D:\SafeOpsFV2\src\nic_management\target\release"
Start-Process powershell -ArgumentList "-NoExit", "-Command", "cd '$packetEnginePath'; .\packet_engine.exe"
```

**CHANGE TO:**
```powershell
Write-Host "[3/3] Starting NIC Management (Go with gRPC blocking)..." -ForegroundColor Green
$nicManagementPath = "D:\SafeOpsFV2\src\nic_management"
Start-Process powershell -ArgumentList "-NoExit", "-Command", "cd '$nicManagementPath'; go run cmd/main.go"
```

### Why This Works:

The Go version has proper gRPC integration that **blocks** waiting for TLS Proxy response:

```go
// cmd/main.go (Go version)
func processPacket(packet *Packet) {
    // Send to TLS Proxy and WAIT for response
    response, err := tlsProxyClient.ProcessPacket(ctx, packet)

    switch response.Action {
    case INJECT:
        // Send modified packet (302 redirect)
        windivert.Send(response.ModifiedPacket)
    case FORWARD:
        // Send original packet
        windivert.Send(packet.RawData)
    case DROP:
        // Don't send anything
    }
}
```

---

## CA Certificate Fix (Critical!)

### Problem: We're Serving the WRONG Certificate!

**What users need:**
- **Root CA certificate** (one cert that signs all domains)
- Format: Self-signed with `CA:TRUE`
- Filename: `safeops-root-ca.crt`

**What we're giving:**
- Per-domain certificate for `captive.safeops.local`
- Format: Leaf cert with `CA:FALSE`
- **Doesn't work as root CA!**

### Files to Fix:

**1. Generate Root CA (Once at Startup)**

File: `src/tls_proxy/internal/integration/step_ca_client.go`

Add this method:

```go
func (c *StepCAClient) GenerateRootCA() error {
    log.Println("[Step-CA Client] Generating SafeOps Root CA...")

    // Generate CA private key
    caPriv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
    if err != nil {
        return fmt.Errorf("failed to generate CA key: %w", err)
    }

    // Create root CA certificate template
    serialNumber, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))

    caTemplate := x509.Certificate{
        SerialNumber: serialNumber,
        Subject: pkix.Name{
            Organization: []string{"SafeOps Network"},
            CommonName:   "SafeOps Root CA",
        },
        NotBefore:             time.Now(),
        NotAfter:              time.Now().Add(10 * 365 * 24 * time.Hour), // 10 years
        KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
        BasicConstraintsValid: true,
        IsCA:                  true,  // ← CRITICAL!
        MaxPathLen:            2,
    }

    // Self-sign CA certificate
    caCertDER, err := x509.CreateCertificate(rand.Reader, &caTemplate, &caTemplate, &caPriv.PublicKey, caPriv)
    if err != nil {
        return fmt.Errorf("failed to create CA cert: %w", err)
    }

    // Encode to PEM
    c.rootCACert = pem.EncodeToMemory(&pem.Block{
        Type:  "CERTIFICATE",
        Bytes: caCertDER,
    })

    caPrivBytes, err := x509.MarshalECPrivateKey(caPriv)
    if err != nil {
        return fmt.Errorf("failed to marshal CA key: %w", err)
    }

    c.rootCAKey = pem.EncodeToMemory(&pem.Block{
        Type:  "EC PRIVATE KEY",
        Bytes: caPrivBytes,
    })

    // Parse for signing domain certs
    c.rootCACertParsed, err = x509.ParseCertificate(caCertDER)
    if err != nil {
        return fmt.Errorf("failed to parse CA cert: %w", err)
    }

    c.rootCAKeyParsed, err = x509.ParseECPrivateKey(caPrivBytes)
    if err != nil {
        return fmt.Errorf("failed to parse CA key: %w", err)
    }

    // Save to disk for user download
    err = os.WriteFile("certs/safeops-root-ca.crt", c.rootCACert, 0644)
    if err != nil {
        return fmt.Errorf("failed to save CA cert: %w", err)
    }

    log.Printf("[Step-CA Client] ✅ Root CA generated and saved to certs/safeops-root-ca.crt")
    return nil
}
```

**2. Add Root CA Fields to StepCAClient struct:**

```go
type StepCAClient struct {
    address            string
    insecureSkipVerify bool

    // Root CA certificate and key (generated once)
    rootCACert       []byte
    rootCAKey        []byte
    rootCACertParsed *x509.Certificate
    rootCAKeyParsed  *ecdsa.PrivateKey
}
```

**3. Call GenerateRootCA at Startup:**

File: `src/tls_proxy/cmd/tls_proxy/main.go`

```go
// After creating Step-CA client
stepCA := integration.NewStepCAClient(stepCAURL, true)

// Generate root CA (once)
err := stepCA.GenerateRootCA()
if err != nil {
    log.Fatalf("Failed to generate root CA: %v", err)
}
```

**4. Update Captive Portal to Serve Root CA:**

File: `src/captive_portal/internal/server/handlers.go`

```go
func (h *Handlers) HandleDownloadCA(w http.ResponseWriter, r *http.Request) {
    log.Printf("[Handlers] CA certificate download requested from %s", getClientIP(r))

    // Read root CA cert from disk
    caCert, err := os.ReadFile("D:/SafeOpsFV2/src/tls_proxy/certs/safeops-root-ca.crt")
    if err != nil {
        log.Printf("[Handlers] Failed to read root CA: %v", err)
        http.Error(w, "CA certificate not available", http.StatusInternalServerError)
        return
    }

    // Set headers for download
    w.Header().Set("Content-Type", "application/x-x509-ca-cert")
    w.Header().Set("Content-Disposition", "attachment; filename=safeops-root-ca.crt")
    w.Header().Set("Content-Length", fmt.Sprintf("%d", len(caCert)))

    // Send root CA certificate
    w.Write(caCert)

    // Mark CA cert as installed (async)
    go func() {
        bgCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
        defer cancel()

        clientIP := getClientIP(r)
        if err := h.dhcpClient.MarkCACertInstalled(bgCtx, clientIP); err != nil {
            log.Printf("[Handlers] Failed to mark CA cert installed for %s: %v", clientIP, err)
        } else {
            log.Printf("[Handlers] ✅ Marked CA cert installed for %s", clientIP)
        }
    }()
}
```

---

## Testing After Fixes:

### Test 1: HTTP Redirect Works
```powershell
# 1. Update start-phase-3AB.ps1 to use Go version
# 2. Start all services
.\start-phase-3AB.ps1

# 3. Open browser, visit: http://neverssl.com
```

✅ **Expected:** Browser redirects to `https://captive.safeops.local:8444/welcome`

### Test 2: CA Certificate is Correct
```powershell
# 1. Download CA cert from portal
# 2. Double-click safeops-root-ca.crt
# 3. Check certificate details
```

✅ **Expected:**
```
Subject: CN=SafeOps Root CA, O=SafeOps Network
Issuer: CN=SafeOps Root CA, O=SafeOps Network (self-signed)
Basic Constraints: Subject Type=CA, Path Length=2
Valid: 10 years
```

### Test 3: Install and Trust CA
```powershell
# 1. Install cert in Windows
#    - Double-click → Install Certificate
#    - Store: Trusted Root Certification Authorities
# 2. Browse to HTTPS site
# 3. Check certificate chain
```

✅ **Expected:** All HTTPS sites show "Trusted" (signed by SafeOps Root CA)

---

## Summary:

**Two critical fixes needed:**

1. **HTTP Redirect:** Use Go NIC Management (has blocking gRPC)
2. **CA Certificate:** Generate proper root CA (not per-domain cert)

**Time:** 1-2 hours total

**Result:**
- ✅ HTTP redirect to captive portal works
- ✅ CA certificate properly signs all domains
- ✅ Users can install ONE cert for all HTTPS MITM
