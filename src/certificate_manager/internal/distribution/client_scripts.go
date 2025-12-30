// Package distribution provides client-side auto-installation scripts.
// These scripts are served via HTTP and executed by devices to auto-install CA certificates.
package distribution

// ============================================================================
// Windows PowerShell Auto-Install Script
// ============================================================================

// WindowsAutoInstallScript is the PowerShell script for automatic CA installation.
const WindowsAutoInstallScript = `#Requires -RunAsAdministrator
# SafeOps Root CA Auto-Installation Script for Windows
# This script is automatically downloaded and executed via DHCP Option 226

# Configuration
$CA_URL = "{{.CAURL}}"
$CA_FINGERPRINT = "{{.CAFingerprint}}"
$REPORT_URL = "{{.ReportURL}}"
$TEMP_CERT = "$env:TEMP\safeops-root-ca.crt"

# Functions
function Write-Log {
    param([string]$Message, [string]$Level = "INFO")
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    Write-Host "[$timestamp] [$Level] $Message"
}

function Get-MACAddress {
    $mac = (Get-NetAdapter | Where-Object {$_.Status -eq "Up"} | Select-Object -First 1).MacAddress
    return $mac -replace '-', ':'
}

function Report-Installation {
    param([string]$Status, [string]$Message)

    $mac = Get-MACAddress
    $hostname = $env:COMPUTERNAME
    $ip = (Get-NetIPAddress -AddressFamily IPv4 | Where-Object {$_.IPAddress -notlike "127.*"} | Select-Object -First 1).IPAddress

    $body = @{
        mac_address = $mac
        ip_address = $ip
        hostname = $hostname
        os = "Windows $([System.Environment]::OSVersion.Version.Major).$([System.Environment]::OSVersion.Version.Minor)"
        certificate_thumbprint = $CA_FINGERPRINT
        installation_status = $Status
        installation_method = "auto-powershell"
        timestamp = (Get-Date).ToUniversalTime().ToString("o")
        message = $Message
    } | ConvertTo-Json

    try {
        Invoke-RestMethod -Uri $REPORT_URL -Method POST -Body $body -ContentType "application/json" -ErrorAction SilentlyContinue
    } catch {
        Write-Log "Failed to report installation status: $_" "WARN"
    }
}

# Main installation logic
try {
    Write-Log "Starting SafeOps Root CA auto-installation"

    # Check if already installed
    $existingCert = Get-ChildItem -Path Cert:\LocalMachine\Root | Where-Object {
        $_.Thumbprint -eq $CA_FINGERPRINT
    }

    if ($existingCert) {
        Write-Log "Certificate already installed (Thumbprint: $CA_FINGERPRINT)" "INFO"
        Report-Installation -Status "already_installed" -Message "Certificate already present in Trusted Root store"
        exit 0
    }

    Write-Log "Downloading certificate from $CA_URL"

    # Download certificate
    try {
        Invoke-WebRequest -Uri $CA_URL -OutFile $TEMP_CERT -UseBasicParsing
        Write-Log "Certificate downloaded successfully"
    } catch {
        Write-Log "Failed to download certificate: $_" "ERROR"
        Report-Installation -Status "failed" -Message "Download failed: $_"
        exit 1
    }

    # Load and verify certificate
    try {
        $cert = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2($TEMP_CERT)
        $actualThumbprint = $cert.Thumbprint

        Write-Log "Certificate Subject: $($cert.Subject)"
        Write-Log "Certificate Thumbprint: $actualThumbprint"
        Write-Log "Certificate Valid From: $($cert.NotBefore)"
        Write-Log "Certificate Valid Until: $($cert.NotAfter)"

        # Verify fingerprint
        if ($actualThumbprint -ne $CA_FINGERPRINT) {
            Write-Log "Certificate thumbprint mismatch! Expected: $CA_FINGERPRINT, Got: $actualThumbprint" "ERROR"
            Report-Installation -Status "failed" -Message "Fingerprint verification failed"
            Remove-Item $TEMP_CERT -Force
            exit 1
        }

        Write-Log "Certificate fingerprint verified successfully"

    } catch {
        Write-Log "Failed to verify certificate: $_" "ERROR"
        Report-Installation -Status "failed" -Message "Verification failed: $_"
        exit 1
    }

    # Install certificate to Trusted Root Certification Authorities
    try {
        Write-Log "Installing certificate to Trusted Root CA store"

        Import-Certificate -FilePath $TEMP_CERT -CertStoreLocation "Cert:\LocalMachine\Root" -ErrorAction Stop | Out-Null

        Write-Log "Certificate installed successfully!" "SUCCESS"

        # Verify installation
        $installedCert = Get-ChildItem -Path Cert:\LocalMachine\Root | Where-Object {
            $_.Thumbprint -eq $CA_FINGERPRINT
        }

        if ($installedCert) {
            Write-Log "Installation verified - Certificate is now trusted" "SUCCESS"
            Report-Installation -Status "success" -Message "Certificate installed and verified"

            # Show notification
            Add-Type -AssemblyName System.Windows.Forms
            $notification = New-Object System.Windows.Forms.NotifyIcon
            $notification.Icon = [System.Drawing.SystemIcons]::Information
            $notification.BalloonTipTitle = "SafeOps Network"
            $notification.BalloonTipText = "Security certificate installed successfully"
            $notification.Visible = $true
            $notification.ShowBalloonTip(5000)
            Start-Sleep -Seconds 2
            $notification.Dispose()
        } else {
            throw "Certificate not found after installation"
        }

    } catch {
        Write-Log "Failed to install certificate: $_" "ERROR"
        Report-Installation -Status "failed" -Message "Installation failed: $_"
        exit 1
    } finally {
        # Cleanup
        if (Test-Path $TEMP_CERT) {
            Remove-Item $TEMP_CERT -Force
        }
    }

    Write-Log "Auto-installation completed successfully" "SUCCESS"
    exit 0

} catch {
    Write-Log "Unexpected error: $_" "ERROR"
    Report-Installation -Status "failed" -Message "Unexpected error: $_"
    exit 1
}
`

// ============================================================================
// Linux Bash Auto-Install Script
// ============================================================================

// LinuxAutoInstallScript is the bash script for automatic CA installation.
const LinuxAutoInstallScript = `#!/bin/bash
# SafeOps Root CA Auto-Installation Script for Linux
# This script is automatically downloaded and executed via DHCP Option 226

set -e

# Configuration
CA_URL="{{.CAURL}}"
CA_FINGERPRINT="{{.CAFingerprint}}"
REPORT_URL="{{.ReportURL}}"
TEMP_CERT="/tmp/safeops-root-ca.crt"
CERT_NAME="safeops-root-ca"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Functions
log_info() {
    echo -e "${GREEN}[INFO]${NC} $1"
}

log_warn() {
    echo -e "${YELLOW}[WARN]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

get_mac_address() {
    ip link show | grep -oP '(?<=link/ether )[0-9a-f:]+' | head -1
}

get_ip_address() {
    ip -4 addr show | grep -oP '(?<=inet\s)\d+(\.\d+){3}' | grep -v '127.0.0.1' | head -1
}

report_installation() {
    local status="$1"
    local message="$2"

    local mac=$(get_mac_address)
    local ip=$(get_ip_address)
    local hostname=$(hostname)
    local os=$(cat /etc/os-release | grep PRETTY_NAME | cut -d'"' -f2)

    local json_data=$(cat <<EOF
{
    "mac_address": "$mac",
    "ip_address": "$ip",
    "hostname": "$hostname",
    "os": "$os",
    "certificate_thumbprint": "$CA_FINGERPRINT",
    "installation_status": "$status",
    "installation_method": "auto-bash",
    "timestamp": "$(date -u +%Y-%m-%dT%H:%M:%SZ)",
    "message": "$message"
}
EOF
)

    curl -s -X POST -H "Content-Type: application/json" -d "$json_data" "$REPORT_URL" >/dev/null 2>&1 || true
}

# Check if running as root
if [ "$EUID" -ne 0 ]; then
    log_error "This script must be run as root"
    report_installation "failed" "Not run as root"
    exit 1
fi

log_info "Starting SafeOps Root CA auto-installation"

# Detect Linux distribution
if [ -f /etc/debian_version ]; then
    DISTRO="debian"
    CA_DIR="/usr/local/share/ca-certificates"
    UPDATE_CMD="update-ca-certificates"
elif [ -f /etc/redhat-release ]; then
    DISTRO="redhat"
    CA_DIR="/etc/pki/ca-trust/source/anchors"
    UPDATE_CMD="update-ca-trust"
else
    log_warn "Unknown distribution, attempting Debian-style installation"
    DISTRO="debian"
    CA_DIR="/usr/local/share/ca-certificates"
    UPDATE_CMD="update-ca-certificates"
fi

log_info "Detected distribution: $DISTRO"

# Check if already installed
if [ -f "$CA_DIR/$CERT_NAME.crt" ]; then
    log_info "Certificate already installed at $CA_DIR/$CERT_NAME.crt"

    # Verify fingerprint
    INSTALLED_FP=$(openssl x509 -in "$CA_DIR/$CERT_NAME.crt" -noout -fingerprint -sha256 | cut -d'=' -f2 | tr -d ':')
    EXPECTED_FP=$(echo "$CA_FINGERPRINT" | tr -d ':')

    if [ "$INSTALLED_FP" = "$EXPECTED_FP" ]; then
        log_info "Certificate fingerprint verified"
        report_installation "already_installed" "Certificate already present and verified"
        exit 0
    else
        log_warn "Installed certificate fingerprint does not match, re-installing"
    fi
fi

# Download certificate
log_info "Downloading certificate from $CA_URL"
if ! wget -q -O "$TEMP_CERT" "$CA_URL"; then
    log_error "Failed to download certificate"
    report_installation "failed" "Download failed"
    exit 1
fi

log_info "Certificate downloaded successfully"

# Verify certificate
log_info "Verifying certificate..."
CERT_SUBJECT=$(openssl x509 -in "$TEMP_CERT" -noout -subject | cut -d'=' -f2-)
CERT_ISSUER=$(openssl x509 -in "$TEMP_CERT" -noout -issuer | cut -d'=' -f2-)
CERT_FP=$(openssl x509 -in "$TEMP_CERT" -noout -fingerprint -sha256 | cut -d'=' -f2 | tr -d ':')
CERT_NOTBEFORE=$(openssl x509 -in "$TEMP_CERT" -noout -startdate | cut -d'=' -f2)
CERT_NOTAFTER=$(openssl x509 -in "$TEMP_CERT" -noout -enddate | cut -d'=' -f2)

log_info "Certificate Subject: $CERT_SUBJECT"
log_info "Certificate Issuer: $CERT_ISSUER"
log_info "Certificate Fingerprint: $CERT_FP"
log_info "Valid From: $CERT_NOTBEFORE"
log_info "Valid Until: $CERT_NOTAFTER"

# Verify fingerprint
EXPECTED_FP=$(echo "$CA_FINGERPRINT" | tr -d ':')
if [ "$CERT_FP" != "$EXPECTED_FP" ]; then
    log_error "Certificate fingerprint mismatch!"
    log_error "Expected: $EXPECTED_FP"
    log_error "Got: $CERT_FP"
    rm -f "$TEMP_CERT"
    report_installation "failed" "Fingerprint verification failed"
    exit 1
fi

log_info "Certificate fingerprint verified successfully"

# Install certificate
log_info "Installing certificate to $CA_DIR"
cp "$TEMP_CERT" "$CA_DIR/$CERT_NAME.crt"
chmod 644 "$CA_DIR/$CERT_NAME.crt"

# Update CA trust store
log_info "Updating CA trust store..."
if $UPDATE_CMD; then
    log_info "CA trust store updated successfully"
else
    log_error "Failed to update CA trust store"
    report_installation "failed" "Trust store update failed"
    exit 1
fi

# Verify installation
if [ -f /etc/ssl/certs/$CERT_NAME.pem ] || [ -f /etc/pki/tls/certs/$CERT_NAME.pem ]; then
    log_info "Installation verified - Certificate is now trusted system-wide"
    report_installation "success" "Certificate installed and verified"
else
    log_warn "Could not verify installation in standard location, but installation may have succeeded"
    report_installation "success" "Certificate installed"
fi

# Install for Firefox (if installed)
if command -v firefox >/dev/null 2>&1; then
    log_info "Firefox detected, installing certificate for Firefox..."

    for PROFILE_DIR in $HOME/.mozilla/firefox/*.default*; do
        if [ -d "$PROFILE_DIR" ]; then
            log_info "Installing to Firefox profile: $PROFILE_DIR"
            certutil -A -n "$CERT_NAME" -t "C,," -i "$CA_DIR/$CERT_NAME.crt" -d sql:"$PROFILE_DIR" 2>/dev/null || true
        fi
    done
fi

# Cleanup
rm -f "$TEMP_CERT"

log_info "Auto-installation completed successfully!"
exit 0
`

// ============================================================================
// macOS Bash Auto-Install Script
// ============================================================================

// MacOSAutoInstallScript is the bash script for automatic CA installation on macOS.
const MacOSAutoInstallScript = `#!/bin/bash
# SafeOps Root CA Auto-Installation Script for macOS
# This script is automatically downloaded and executed via DHCP Option 226

set -e

# Configuration
CA_URL="{{.CAURL}}"
CA_FINGERPRINT="{{.CAFingerprint}}"
REPORT_URL="{{.ReportURL}}"
TEMP_CERT="/tmp/safeops-root-ca.crt"

# Functions
log_info() {
    echo "[INFO] $1"
}

log_error() {
    echo "[ERROR] $1" >&2
}

get_mac_address() {
    ifconfig en0 | grep ether | awk '{print $2}'
}

get_ip_address() {
    ipconfig getifaddr en0 || ipconfig getifaddr en1 || echo "unknown"
}

report_installation() {
    local status="$1"
    local message="$2"

    local mac=$(get_mac_address)
    local ip=$(get_ip_address)
    local hostname=$(hostname)
    local os="macOS $(sw_vers -productVersion)"

    local json_data=$(cat <<EOF
{
    "mac_address": "$mac",
    "ip_address": "$ip",
    "hostname": "$hostname",
    "os": "$os",
    "certificate_thumbprint": "$CA_FINGERPRINT",
    "installation_status": "$status",
    "installation_method": "auto-bash-macos",
    "timestamp": "$(date -u +%Y-%m-%dT%H:%M:%SZ)",
    "message": "$message"
}
EOF
)

    curl -s -X POST -H "Content-Type: application/json" -d "$json_data" "$REPORT_URL" >/dev/null 2>&1 || true
}

# Check if running as root
if [ "$EUID" -ne 0 ]; then
    log_error "This script must be run with sudo"
    report_installation "failed" "Not run as root"
    exit 1
fi

log_info "Starting SafeOps Root CA auto-installation for macOS"

# Download certificate
log_info "Downloading certificate from $CA_URL"
if ! curl -s -o "$TEMP_CERT" "$CA_URL"; then
    log_error "Failed to download certificate"
    report_installation "failed" "Download failed"
    exit 1
fi

log_info "Certificate downloaded successfully"

# Verify certificate
log_info "Verifying certificate..."
CERT_FP=$(openssl x509 -in "$TEMP_CERT" -noout -fingerprint -sha256 | cut -d'=' -f2 | tr -d ':')
EXPECTED_FP=$(echo "$CA_FINGERPRINT" | tr -d ':')

if [ "$CERT_FP" != "$EXPECTED_FP" ]; then
    log_error "Certificate fingerprint mismatch!"
    rm -f "$TEMP_CERT"
    report_installation "failed" "Fingerprint verification failed"
    exit 1
fi

log_info "Certificate fingerprint verified"

# Install to System keychain
log_info "Installing certificate to System Keychain..."
if security add-trusted-cert -d -r trustRoot -k /Library/Keychains/System.keychain "$TEMP_CERT"; then
    log_info "Certificate installed successfully to System Keychain"
    report_installation "success" "Certificate installed and trusted"

    # Show notification
    osascript -e 'display notification "Security certificate installed successfully" with title "SafeOps Network"'
else
    log_error "Failed to install certificate"
    report_installation "failed" "Keychain installation failed"
    rm -f "$TEMP_CERT"
    exit 1
fi

# Cleanup
rm -f "$TEMP_CERT"

log_info "Auto-installation completed successfully!"
exit 0
`
