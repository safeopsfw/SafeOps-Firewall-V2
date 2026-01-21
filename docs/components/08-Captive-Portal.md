# Captive Portal - Component Documentation

## Overview
The Captive Portal is a user-facing authentication and onboarding system that manages device trust and CA certificate installation for new devices connecting to the SafeOps network.

## Component Information

**Component Type:** Web-based Device Authentication
**Language:** Go 1.24.0
**Version:** 1.0.0 (Phase 3A)
**Build Date:** 2026-01-03
**Platform:** Windows/Linux

## Files and Locations

### Source Files
```
D:\SafeOpsFV2\src\captive_portal\
├── cmd\captive_portal\main.go          # Application entry point
├── internal\
│   ├── config\
│   │   ├── config.go                   # Configuration loader
│   │   └── types.go                    # Config data structures
│   ├── server\
│   │   ├── http_server.go              # HTTPS/HTTP server
│   │   ├── handlers.go                 # HTTP request handlers
│   │   └── os_detector.go              # Device OS detection
│   ├── stepca\
│   │   └── client.go                   # Step-CA integration client
│   └── database\
│       └── dhcp_client.go              # DHCP Monitor gRPC client
├── proto\gen\
│   ├── dhcp_monitor.pb.go              # DHCP Monitor protobuf
│   └── dhcp_monitor_grpc.pb.go         # DHCP Monitor gRPC stubs
└── go.mod                              # Go module dependencies
```

### Binary/Executable
```
D:\SafeOpsFV2\bin\captive_portal\
└── captive_portal.exe                  # Windows executable
```

### Configuration Files
```
D:\SafeOpsFV2\src\captive_portal\config\
└── captive_portal.yaml                 # Default configuration
```

### Static Assets
```
D:\SafeOpsFV2\src\captive_portal\
├── static\
│   ├── css\                            # Stylesheets
│   └── js\                             # JavaScript files
└── templates\                          # HTML templates
```

## Functionality

### Core Functions

#### 1. Device Onboarding Flow
1. **Redirect Detection:**
   - New untrusted device attempts internet access
   - TLS Proxy detects untrusted device
   - Redirects all HTTP/HTTPS traffic to captive portal

2. **Portal Presentation:**
   - Serves captive portal page over HTTPS
   - Displays welcome message and instructions
   - Shows device information (MAC, IP, hostname)
   - Presents CA certificate download button

3. **CA Certificate Installation:**
   - Provides downloadable CA certificate
   - OS-specific instructions (Windows, macOS, Linux, iOS, Android)
   - Auto-detection of device operating system
   - User installs certificate to trust store

4. **Verification:**
   - Auto-verify certificate installation (polling)
   - Manual verify button for user-triggered check
   - Checks certificate trust status via Step-CA API
   - Updates device trust status in DHCP Monitor

5. **Trust Grant:**
   - Marks device as TRUSTED in database
   - Updates `portal_shown` flag
   - Updates `ca_cert_installed` flag
   - Redirects user to internet (success page)

#### 2. Device OS Detection
- User-Agent parsing
- Automatic platform detection:
  - Windows (Vista/7/8/10/11)
  - macOS
  - Linux
  - iOS (iPhone/iPad)
  - Android
- OS-specific installation instructions

#### 3. Integration with DHCP Monitor
- gRPC client connection to DHCP Monitor (port 50055)
- API calls:
  - `GetDeviceByIP()` - Retrieve device information
  - `MarkPortalShown()` - Track portal display
  - `MarkCACertInstalled()` - Track certificate installation
  - `UpdateTrustStatus()` - Grant TRUSTED status

#### 4. Integration with Step-CA
- HTTP client to Step-CA (port 9000)
- Endpoints:
  - `/root_ca.crt` - Download root CA certificate
  - `/health` - Health check
  - Certificate verification API

#### 5. Session Management
- Session timeout tracking
- Session secret for CSRF protection
- Rate limiting per IP
- CORS support (optional)

#### 6. Automatic Verification
- Background polling (configurable interval)
- Checks certificate installation status
- Auto-updates trust status when detected
- Timeout after configurable duration

## Default Ports

| Port | Protocol | Purpose |
|------|----------|---------|
| **8082** | HTTPS | Captive portal web server (primary) |
| **8083** | HTTP | CA certificate download (optional) |
| 50055 | gRPC | DHCP Monitor integration |
| 9000 | HTTPS | Step-CA API integration |

### Server Configuration
- **HTTPS Port:** 8082 (default)
- **HTTP Port:** 8083 (disabled by default)
- **HTTP Redirect:** Optional redirect to HTTPS
- **Read Timeout:** 30 seconds
- **Write Timeout:** 30 seconds
- **Idle Timeout:** 60 seconds

## Configuration

### Portal Settings
```yaml
portal:
  title: "SafeOps Network Access"
  welcome_message: "Welcome to SafeOps Network"
  ca_cert_name: "SafeOps Root CA"
  ca_cert_description: "Install this certificate to access the internet"
  auto_verify_enabled: true
  verify_interval_seconds: 5
  verify_timeout_seconds: 300
```

### Server Settings
```yaml
server:
  https_port: 8082
  https_enabled: true
  cert_file: "D:/SafeOpsFV2/config/certs/portal.crt"
  key_file: "D:/SafeOpsFV2/config/certs/portal.key"
  http_port: 8083
  http_enabled: false                 # Disabled by default
  http_redirect_to_https: true
  read_timeout: 30s
  write_timeout: 30s
  idle_timeout: 60s
```

### Integrations
```yaml
integrations:
  dhcp_monitor:
    grpc_address: "127.0.0.1:50055"
    timeout: 5s
    retry_attempts: 3
    retry_delay: 1s

  step_ca:
    api_url: "https://127.0.0.1:9000"
    verify_ssl: false                  # Dev mode
    root_ca_endpoint: "/root_ca.crt"
    timeout: 10s

  database:
    enabled: false                     # Fallback only
    host: "localhost"
    port: 5432
    database: "safeops"
    user: "captive_portal"
    password: "${DB_PASSWORD}"
    sslmode: "disable"
```

### Static Assets
```yaml
static:
  css_path: "D:/SafeOpsFV2/src/captive_portal/static/css"
  js_path: "D:/SafeOpsFV2/src/captive_portal/static/js"
```

### Templates
```yaml
templates:
  path: "D:/SafeOpsFV2/src/captive_portal/templates"
  reload_on_change: true               # Dev mode
```

### Security
```yaml
security:
  cors_enabled: false
  cors_origins: ["*"]
  rate_limit_enabled: true
  rate_limit_requests: 100             # Per window
  rate_limit_window: "1m"
  session_timeout: "30m"
  session_secret: "${SESSION_SECRET}"  # From environment
```

### Logging
```yaml
logging:
  level: "info"                        # debug/info/warn/error
  format: "json"                       # json/text
  output: "stdout"                     # stdout/file
  max_size: 100                        # MB
  max_backups: 3
  max_age: 28                          # Days
  compress: true
```

## Dependencies

### Go Module Dependencies
```
google.golang.org/grpc         # gRPC client for DHCP Monitor
google.golang.org/protobuf     # Protocol Buffers
github.com/gorilla/mux         # HTTP routing
github.com/gorilla/sessions    # Session management
gopkg.in/yaml.v3               # YAML configuration
```

### External Service Dependencies
- **DHCP Monitor (gRPC:50055):** Device tracking and trust management
- **Step-CA (HTTPS:9000):** CA certificate download and verification
- **PostgreSQL (5432):** Fallback database (optional)

## Component Interconnections

### Architecture
```
┌─────────────────────────────────────────────────┐
│      Captive Portal (HTTPS:8082)                │
│  (Device Authentication & CA Cert Install)      │
└─────────────────────────────────────────────────┘
    ↓                   ↓                   ↓
[TLS Proxy]      [DHCP Monitor]       [Step-CA]
(Redirect)       (gRPC:50055)         (HTTPS:9000)
                 Trust Management      CA Certificates
```

### Integration Flow

**Phase 1: Redirect**
```
New Device → TLS Proxy → Check Trust Status → UNTRUSTED
                        ↓
                  Redirect to Captive Portal (8082)
```

**Phase 2: Portal Display**
```
Captive Portal → DHCP Monitor.GetDeviceByIP(ip)
              ↓
         Display Portal Page
              ↓
         DHCP Monitor.MarkPortalShown(device_id)
```

**Phase 3: Certificate Download**
```
User Clicks Download → Step-CA.GetRootCA()
                     ↓
              Download CA Certificate File
                     ↓
              User Installs in OS Trust Store
```

**Phase 4: Verification**
```
Auto-Verify Polling (every 5s) → Step-CA Certificate Check
                                ↓
                           Certificate Trusted?
                                ↓
                    DHCP Monitor.MarkCACertInstalled(device_id)
                                ↓
                    DHCP Monitor.UpdateTrustStatus(device_id, TRUSTED)
                                ↓
                         Redirect to Internet
```

### gRPC API Calls (DHCP Monitor)
- `GetDeviceByIP(IPRequest) → Device` - Retrieve device info by IP
- `MarkPortalShown(MarkPortalShownRequest) → Device` - Track portal display
- `MarkCACertInstalled(MarkCACertInstalledRequest) → Device` - Track cert install
- `UpdateTrustStatus(TrustUpdateRequest) → Device` - Grant TRUSTED status

## HTTP Routes

| Route | Method | Purpose |
|-------|--------|---------|
| `/` | GET | Main portal landing page |
| `/download-ca` | GET | Download CA certificate |
| `/verify` | POST | Manual certificate verification |
| `/status` | GET | Auto-verify status endpoint (AJAX) |
| `/success` | GET | Success page after trust granted |
| `/static/css/{file}` | GET | CSS stylesheets |
| `/static/js/{file}` | GET | JavaScript files |
| `/health` | GET | Health check endpoint |

## Important Notes

### Security Considerations
- **HTTPS Required:** Portal MUST use HTTPS with valid certificate
- **Session Secret:** Use strong random session secret (environment variable)
- **Rate Limiting:** Prevents brute force and DoS attacks
- **CORS:** Disabled by default for security
- **Certificate Verification:** Uses Step-CA API for validation

### User Experience
- **Auto-Verify:** Polls every 5 seconds for certificate installation
- **Timeout:** Stops polling after 5 minutes (300 seconds)
- **Manual Verify:** User can click "Verify" button anytime
- **OS Detection:** Automatic platform-specific instructions
- **Responsive Design:** Works on all devices (desktop, mobile, tablet)

### Database Fallback
- PostgreSQL connection is **optional**
- Primary data source is DHCP Monitor gRPC
- Database used only if gRPC fails (fallback)

### Phase 3A Limitations
- No user accounts/passwords (certificate-based only)
- No multi-step authentication
- No custom branding beyond config
- No detailed logging/analytics (Phase 3B)

## Connection to Other Components

| Component | Connection Type | Purpose |
|-----------|----------------|---------|
| DHCP Monitor | gRPC Client | Device tracking and trust management |
| Step-CA | HTTP Client | CA certificate download and verification |
| TLS Proxy | Redirected Traffic | Receives redirected untrusted devices |
| PostgreSQL | Database | Fallback device lookup (optional) |

## Troubleshooting

### Portal Not Loading
1. Verify captive_portal.exe is running
2. Check HTTPS certificate is valid
3. Verify port 8082 is not blocked
4. Check firewall allows inbound 8082

### Certificate Download Fails
1. Verify Step-CA is running (port 9000)
2. Check Step-CA `/root_ca.crt` endpoint accessible
3. Verify SSL verification settings in config

### Device Not Getting Trusted
1. Check DHCP Monitor is running (port 50055)
2. Verify gRPC connection to DHCP Monitor
3. Check device exists in DHCP Monitor database
4. Verify certificate is actually installed in OS trust store

### Auto-Verify Not Working
1. Check `auto_verify_enabled: true` in config
2. Verify `verify_interval_seconds` is reasonable (5-10s)
3. Check browser console for AJAX errors
4. Verify Step-CA certificate verification API working

---

**Status:** Phase 3A Complete
**Auto-Start:** Via SafeOps Launcher
**Dependencies:** DHCP Monitor (gRPC), Step-CA (HTTPS)
**Managed By:** Orchestrator
