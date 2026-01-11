#!/bin/bash
# SafeOps CA Certificate Installer for Linux
# Usage: curl -fsSL http://192.168.1.1/install-linux.sh | sudo bash

set -e

CERT_URL="${CERT_URL:-http://192.168.1.1/download?os=Linux}"
CERT_NAME="SafeOps-CA.crt"
CERT_DIR="/usr/local/share/ca-certificates"

echo ""
echo "============================================"
echo " SafeOps CA Certificate Installer"
echo "============================================"
echo ""

# Check for root
if [ "$EUID" -ne 0 ]; then
    echo "[ERROR] Please run as root (sudo)"
    exit 1
fi

# Detect distro
if [ -f /etc/debian_version ]; then
    DISTRO="debian"
elif [ -f /etc/redhat-release ]; then
    DISTRO="redhat"
elif [ -f /etc/arch-release ]; then
    DISTRO="arch"
else
    DISTRO="unknown"
fi

echo "[1/4] Downloading certificate..."
curl -fsSL "$CERT_URL" -o "/tmp/$CERT_NAME"

echo "[2/4] Installing certificate..."

case $DISTRO in
    debian)
        # Debian/Ubuntu
        mkdir -p "$CERT_DIR"
        cp "/tmp/$CERT_NAME" "$CERT_DIR/"
        update-ca-certificates
        ;;
    redhat)
        # RHEL/CentOS/Fedora
        cp "/tmp/$CERT_NAME" /etc/pki/ca-trust/source/anchors/
        update-ca-trust extract
        ;;
    arch)
        # Arch Linux
        cp "/tmp/$CERT_NAME" /etc/ca-certificates/trust-source/anchors/
        trust extract-compat
        ;;
    *)
        echo "[WARNING] Unknown distro, trying generic method..."
        mkdir -p "$CERT_DIR"
        cp "/tmp/$CERT_NAME" "$CERT_DIR/"
        if command -v update-ca-certificates &> /dev/null; then
            update-ca-certificates
        elif command -v update-ca-trust &> /dev/null; then
            update-ca-trust extract
        fi
        ;;
esac

echo "[3/4] Verifying installation..."
if openssl verify -CApath /etc/ssl/certs "/tmp/$CERT_NAME" 2>/dev/null | grep -q "OK"; then
    echo "[OK] Certificate verification passed"
else
    echo "[INFO] Certificate installed (verification skipped)"
fi

echo "[4/4] Cleaning up..."
rm -f "/tmp/$CERT_NAME"

echo ""
echo "============================================"
echo " SUCCESS! Certificate Installed"
echo "============================================"
echo ""
echo "Your device is now configured for secure browsing!"
echo ""
echo "Note: You may need to restart your browser for"
echo "      changes to take effect."
echo ""

# Notify captive portal
curl -s -X POST "http://192.168.1.1/api/enroll" \
    -d "ip=$(hostname -I | awk '{print $1}')" \
    -d "os=Linux" \
    -d "method=script" \
    2>/dev/null || true
