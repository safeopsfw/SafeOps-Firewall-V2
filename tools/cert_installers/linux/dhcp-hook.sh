#!/bin/bash
# SafeOps CA Certificate - DHCP Client Hook Script
# =================================================
# This script automatically installs the CA certificate when DHCP assigns an IP
#
# Installation:
#   Debian/Ubuntu: sudo cp dhcp-hook.sh /etc/dhcp/dhclient-exit-hooks.d/safeops-cert
#   RHEL/CentOS:   sudo cp dhcp-hook.sh /etc/dhcp/dhclient.d/safeops-cert.sh
#   Fedora:        sudo cp dhcp-hook.sh /etc/NetworkManager/dispatcher.d/99-safeops-cert
#
# Make executable: sudo chmod +x <path>

CERT_URL="http://192.168.1.1/download?os=Linux"
CERT_NAME="SafeOps-CA.crt"
LOG_FILE="/var/log/safeops-cert.log"

log() {
    echo "$(date '+%Y-%m-%d %H:%M:%S') $1" >> "$LOG_FILE"
}

install_cert() {
    log "DHCP event triggered, checking certificate..."
    
    # Check if already installed
    if [ -f "/usr/local/share/ca-certificates/$CERT_NAME" ]; then
        log "Certificate already installed, skipping"
        return 0
    fi
    
    # Download certificate
    log "Downloading certificate from $CERT_URL"
    if ! curl -fsSL "$CERT_URL" -o "/tmp/$CERT_NAME" 2>/dev/null; then
        log "Failed to download certificate (portal may not be reachable)"
        return 1
    fi
    
    # Verify it's a valid certificate
    if ! openssl x509 -in "/tmp/$CERT_NAME" -noout 2>/dev/null; then
        log "Downloaded file is not a valid certificate"
        rm -f "/tmp/$CERT_NAME"
        return 1
    fi
    
    # Install based on distro
    if [ -d /usr/local/share/ca-certificates ]; then
        # Debian/Ubuntu
        cp "/tmp/$CERT_NAME" /usr/local/share/ca-certificates/
        update-ca-certificates 2>/dev/null
        log "Certificate installed (Debian/Ubuntu)"
    elif [ -d /etc/pki/ca-trust/source/anchors ]; then
        # RHEL/CentOS/Fedora
        cp "/tmp/$CERT_NAME" /etc/pki/ca-trust/source/anchors/
        update-ca-trust extract 2>/dev/null
        log "Certificate installed (RHEL/CentOS)"
    elif [ -d /etc/ca-certificates/trust-source/anchors ]; then
        # Arch Linux
        cp "/tmp/$CERT_NAME" /etc/ca-certificates/trust-source/anchors/
        trust extract-compat 2>/dev/null
        log "Certificate installed (Arch)"
    else
        log "Unknown distribution, attempting generic install"
        mkdir -p /usr/local/share/ca-certificates
        cp "/tmp/$CERT_NAME" /usr/local/share/ca-certificates/
    fi
    
    rm -f "/tmp/$CERT_NAME"
    
    # Notify portal
    curl -s -X POST "http://192.168.1.1/api/enroll" \
        -d "ip=$(hostname -I | awk '{print $1}')" \
        -d "os=Linux" \
        -d "method=dhcp-hook" \
        2>/dev/null || true
    
    log "Certificate installation complete"
    return 0
}

# For dhclient-exit-hooks (Debian/Ubuntu)
case "$reason" in
    BOUND|RENEW|REBIND|REBOOT)
        install_cert
        ;;
esac

# For NetworkManager dispatcher (Fedora/modern distros)
if [ "$2" = "up" ] || [ "$2" = "dhcp4-change" ]; then
    install_cert
fi
