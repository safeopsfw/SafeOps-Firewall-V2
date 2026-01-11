#!/bin/bash
# SafeOps CA Certificate Installer for macOS
# Usage: curl -fsSL http://192.168.1.1/install-macos.sh | bash

set -e

CERT_URL="${CERT_URL:-http://192.168.1.1/download?os=macOS}"
CERT_NAME="SafeOps-CA.crt"

echo ""
echo "============================================"
echo " SafeOps CA Certificate Installer"
echo "============================================"
echo ""

echo "[1/3] Downloading certificate..."
curl -fsSL "$CERT_URL" -o "/tmp/$CERT_NAME"

echo "[2/3] Installing certificate to System Keychain..."
echo ""
echo "You will be prompted for your password."
echo ""

# Add to System Keychain and trust
sudo security add-trusted-cert -d -r trustRoot -k /Library/Keychains/System.keychain "/tmp/$CERT_NAME"

echo "[3/3] Verifying installation..."

# Verify
if security find-certificate -a -c "SafeOps" /Library/Keychains/System.keychain 2>/dev/null | grep -q "SafeOps"; then
    echo ""
    echo "============================================"
    echo " SUCCESS! Certificate Installed"
    echo "============================================"
    echo ""
    echo "Your Mac is now configured for secure browsing!"
    echo ""
    
    # Cleanup
    rm -f "/tmp/$CERT_NAME"
    
    # Notify captive portal
    curl -s -X POST "http://192.168.1.1/api/enroll" \
        -d "ip=$(ipconfig getifaddr en0 2>/dev/null || ipconfig getifaddr en1 2>/dev/null)" \
        -d "os=macOS" \
        -d "method=script" \
        2>/dev/null || true
else
    echo "[WARNING] Could not verify installation."
    echo "          The certificate may still be installed correctly."
    echo "          Check Keychain Access to confirm."
fi
