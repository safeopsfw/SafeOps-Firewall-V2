# DHCP Monitor & Captive Portal

**Windows DHCP Integration with Step-CA Certificate Distribution**

## Architecture

This service monitors Windows DHCP Server (non-invasively) and provides automatic CA certificate distribution to connecting devices via a captive portal.

## Flow

```
1. Device connects to network
   ↓
2. Windows DHCP assigns IP (we watch this happen)
   ↓
3. Our Go app detects the new lease (via WMI/PowerShell)
   ↓
4. Our DNS server hijacks requests → redirects to captive portal
   ↓
5. User installs Step-CA root certificate
   ↓
6. Our app verifies installation
   ↓
7. DNS hijacking stops → device gets internet
```

## Components

### 1. Windows DHCP Monitor
- Monitors Windows DHCP Server via WMI/PowerShell
- Detects new device connections
- Tracks lease assignments
- **Does NOT interfere with Windows DHCP**

### 2. DNS Hijacking Server
- Runs on port 53
- Intercepts DNS queries from unenrolled devices
- Returns portal IP for all queries (triggers captive portal detection)
- Forwards real DNS queries for enrolled devices

### 3. Captive Portal
- HTTP/HTTPS server on port 80/443
- Detects device OS (iOS, Android, Windows, macOS)
- Serves device-specific certificate installation instructions
- Provides Step-CA root certificate download
- Tracks installation status

### 4. Step-CA Integration
- Reads Step-CA root certificate
- Verifies device certificates
- Marks devices as enrolled when cert is installed

### 5. Device Tracking Database
- SQLite database
- Tracks: IP, MAC, hostname, enrollment status
- Records first seen, last seen timestamps

## Configuration

See `config/config.yaml` for configuration options.

## Running

### Prerequisites
1. Windows DHCP Server must be running
2. Step-CA must be installed and running
3. Run as Administrator (required for DNS port 53)

### Start Service
```bash
cd src/dhcp_monitor
go run cmd/main.go
```

### Production Build
```bash
go build -o dhcp_monitor.exe cmd/main.go
.\dhcp_monitor.exe
```

## Windows DHCP Configuration

The service automatically configures Windows DHCP to:
- Set DNS server to this machine's IP
- Set gateway to this machine's IP

Or configure manually:
```powershell
Set-DhcpServerv4OptionValue -ScopeId 192.168.100.0 -DnsServer <YOUR_IP>
Set-DhcpServerv4OptionValue -ScopeId 192.168.100.0 -Router <YOUR_IP>
```

## Security Notes

- Root CA certificate is served over HTTP (safe, it's public)
- Portal can optionally use HTTPS (requires portal certificate from Step-CA)
- All device tracking is local (SQLite database)
- No personal data is collected

## Ports Used

- **53** - DNS hijacking server
- **80** - HTTP captive portal
- **443** - HTTPS captive portal (optional)
- **9155** - Prometheus metrics
- **8068** - Health check endpoint

## Integration with Existing Services

- **DNS Server (port 53)** - Integrates with SafeOps DNS server
- **Step-CA (port 9000)** - Reads root certificate from Step-CA
- **NIC Management** - Can query NIC status for device identification
