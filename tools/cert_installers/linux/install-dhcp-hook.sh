#!/bin/bash
# SafeOps Linux DHCP Hook Installer
# ==================================
# This script installs the DHCP hook for automatic certificate installation
# Run as root: sudo ./install-dhcp-hook.sh

set -e

HOOK_SCRIPT="dhcp-hook.sh"
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"

echo ""
echo "============================================"
echo " SafeOps DHCP Hook Installer"
echo "============================================"
echo ""

# Check for root
if [ "$EUID" -ne 0 ]; then
    echo "[ERROR] Please run as root (sudo)"
    exit 1
fi

# Detect distro and install location
if [ -f /etc/debian_version ]; then
    # Debian/Ubuntu
    HOOK_DIR="/etc/dhcp/dhclient-exit-hooks.d"
    HOOK_NAME="safeops-cert"
    echo "[INFO] Detected: Debian/Ubuntu"
elif [ -f /etc/redhat-release ]; then
    # RHEL/CentOS
    HOOK_DIR="/etc/dhcp/dhclient.d"
    HOOK_NAME="safeops-cert.sh"
    echo "[INFO] Detected: RHEL/CentOS"
elif [ -d /etc/NetworkManager/dispatcher.d ]; then
    # Fedora/Modern with NetworkManager
    HOOK_DIR="/etc/NetworkManager/dispatcher.d"
    HOOK_NAME="99-safeops-cert"
    echo "[INFO] Detected: NetworkManager (Fedora/modern)"
else
    echo "[ERROR] Unsupported distribution"
    exit 1
fi

# Create hook directory if needed
mkdir -p "$HOOK_DIR"

# Copy hook script
echo "[1/3] Installing DHCP hook..."
cp "$SCRIPT_DIR/$HOOK_SCRIPT" "$HOOK_DIR/$HOOK_NAME"
chmod +x "$HOOK_DIR/$HOOK_NAME"

# Create log file
echo "[2/3] Setting up logging..."
touch /var/log/safeops-cert.log
chmod 644 /var/log/safeops-cert.log

# Test hook
echo "[3/3] Testing hook script..."
if bash -n "$HOOK_DIR/$HOOK_NAME" 2>/dev/null; then
    echo "[OK] Hook script syntax valid"
else
    echo "[WARNING] Hook script may have issues"
fi

echo ""
echo "============================================"
echo " SUCCESS! DHCP Hook Installed"
echo "============================================"
echo ""
echo "Location: $HOOK_DIR/$HOOK_NAME"
echo "Log file: /var/log/safeops-cert.log"
echo ""
echo "The certificate will be automatically installed"
echo "when this machine receives a DHCP lease from SafeOps."
echo ""
