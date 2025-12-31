# ============================================================================
# SafeOps Certificate Manager - Startup Script (PowerShell)
# SSL Interception Support
# ============================================================================

param(
    [switch]$NoBuild,
    [switch]$NoFirewall,
    [string]$Config = "config/templates/ssl_interception.toml"
)

# Check if running as administrator
$isAdmin = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)

if (-not $isAdmin) {
    Write-Host ""
    Write-Host "[WARN] Not running as Administrator" -ForegroundColor Yellow
    Write-Host "       Some features may not work properly" -ForegroundColor Yellow
    Write-Host "       Please run: powershell -ExecutionPolicy Bypass -File start_certificate_manager.ps1" -ForegroundColor Yellow
    Write-Host ""
}

Write-Host ""
Write-Host "========================================================================" -ForegroundColor Cyan
Write-Host "  SafeOps Certificate Manager - SSL Interception" -ForegroundColor Cyan
Write-Host "========================================================================" -ForegroundColor Cyan
Write-Host ""

# Set working directory
Set-Location $PSScriptRoot
Write-Host "[INFO] Working directory: $(Get-Location)" -ForegroundColor Gray
Write-Host ""

# Create required directories
Write-Host "[INFO] Creating directories..." -ForegroundColor Gray
$directories = @("certs", "keys", "logs", "backups", "config")
foreach ($dir in $directories) {
    if (-not (Test-Path $dir)) {
        New-Item -ItemType Directory -Path $dir -Force | Out-Null
    }
}
Write-Host "[OK] Directories created" -ForegroundColor Green
Write-Host ""

# Build if needed
if (-not $NoBuild) {
    if (-not (Test-Path "certificate_manager.exe")) {
        Write-Host "[INFO] Binary not found, building..." -ForegroundColor Yellow
        go build -o certificate_manager.exe cmd/main.go
        if ($LASTEXITCODE -ne 0) {
            Write-Host "[ERROR] Build failed!" -ForegroundColor Red
            exit 1
        }
        Write-Host "[OK] Build successful" -ForegroundColor Green
        Write-Host ""
    }
}

# Check configuration
if (-not (Test-Path $Config)) {
    $Config = "config/templates/certificate_manager.toml"
    if (-not (Test-Path $Config)) {
        Write-Host "[ERROR] Configuration file not found!" -ForegroundColor Red
        Write-Host "       Expected: config/templates/ssl_interception.toml" -ForegroundColor Red
        Write-Host "       Or: config/templates/certificate_manager.toml" -ForegroundColor Red
        exit 1
    }
}

Write-Host "[INFO] Using configuration: $Config" -ForegroundColor Gray
Write-Host ""

# Check for existing CA
if (Test-Path "certs/ca.crt") {
    Write-Host "[INFO] Found existing CA certificate: certs/ca.crt" -ForegroundColor Gray
    Write-Host ""

    # Try to display CA info
    if (Get-Command openssl -ErrorAction SilentlyContinue) {
        Write-Host "CA Certificate Details:" -ForegroundColor Cyan
        openssl x509 -in certs/ca.crt -noout -subject -issuer -dates
        Write-Host ""
    } else {
        Write-Host "[WARN] OpenSSL not installed, cannot display CA details" -ForegroundColor Yellow
        Write-Host ""
    }
} else {
    Write-Host "[INFO] No existing CA found" -ForegroundColor Yellow
    Write-Host "[INFO] CA will be auto-generated on first run" -ForegroundColor Yellow
    Write-Host ""
}

# Network configuration check
Write-Host "[INFO] Network Configuration Check" -ForegroundColor Gray
Write-Host "----------------------------------------" -ForegroundColor Gray
Write-Host ""

$adapters = Get-NetIPAddress -AddressFamily IPv4 | Where-Object { $_.IPAddress -notlike "127.*" }
foreach ($adapter in $adapters) {
    Write-Host "Interface: $($adapter.InterfaceAlias)" -ForegroundColor Cyan
    Write-Host "  IP Address: $($adapter.IPAddress)" -ForegroundColor Gray
    Write-Host "  Prefix Length: $($adapter.PrefixLength)" -ForegroundColor Gray
    Write-Host ""
}

Write-Host "[INFO] Make sure your firewall IP is correctly set in the config file" -ForegroundColor Yellow
Write-Host "[INFO] Current config: $Config" -ForegroundColor Yellow
Write-Host ""

# Firewall rules
if (-not $NoFirewall -and $isAdmin) {
    Write-Host "[INFO] Checking firewall rules..." -ForegroundColor Gray

    $firewallRules = @(
        @{Name="Certificate Manager HTTP"; Port=80},
        @{Name="Certificate Manager gRPC"; Port=50060},
        @{Name="Certificate Manager OCSP"; Port=8888},
        @{Name="Certificate Manager Metrics"; Port=9093}
    )

    foreach ($rule in $firewallRules) {
        $existing = Get-NetFirewallRule -DisplayName $rule.Name -ErrorAction SilentlyContinue
        if (-not $existing) {
            Write-Host "[INFO] Adding firewall rule: $($rule.Name) (Port $($rule.Port))" -ForegroundColor Yellow
            New-NetFirewallRule -DisplayName $rule.Name -Direction Inbound -Action Allow -Protocol TCP -LocalPort $rule.Port | Out-Null
        }
    }

    Write-Host "[OK] Firewall rules configured" -ForegroundColor Green
    Write-Host ""
}

# Service information
Write-Host "========================================================================" -ForegroundColor Cyan
Write-Host "  Service Endpoints" -ForegroundColor Cyan
Write-Host "========================================================================" -ForegroundColor Cyan
Write-Host ""
Write-Host "HTTP Distribution: http://localhost:80" -ForegroundColor Gray
Write-Host "  - CA Certificate: http://localhost:80/ca.crt" -ForegroundColor Gray
Write-Host "  - Trust Guide: http://localhost:80/trust-guide.html" -ForegroundColor Gray
Write-Host "  - QR Code: http://localhost:80/ca-qr-code.png" -ForegroundColor Gray
Write-Host ""
Write-Host "gRPC API: localhost:50060" -ForegroundColor Gray
Write-Host "OCSP Responder: http://localhost:8888" -ForegroundColor Gray
Write-Host "Metrics: http://localhost:9093/metrics" -ForegroundColor Gray
Write-Host "Health: http://localhost:8093/health" -ForegroundColor Gray
Write-Host ""

# Start Certificate Manager
Write-Host "========================================================================" -ForegroundColor Cyan
Write-Host "  Starting Certificate Manager..." -ForegroundColor Cyan
Write-Host "========================================================================" -ForegroundColor Cyan
Write-Host ""
Write-Host "[INFO] Press Ctrl+C to stop the service" -ForegroundColor Yellow
Write-Host ""

# Run the service
try {
    & ./certificate_manager.exe
} catch {
    Write-Host ""
    Write-Host "[ERROR] Service error: $_" -ForegroundColor Red
    exit 1
}

# If service exits
Write-Host ""
Write-Host "========================================================================" -ForegroundColor Cyan
Write-Host "  Certificate Manager stopped" -ForegroundColor Cyan
Write-Host "========================================================================" -ForegroundColor Cyan
Write-Host ""
