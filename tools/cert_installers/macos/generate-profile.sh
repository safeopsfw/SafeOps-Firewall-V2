#!/bin/bash
# SafeOps Configuration Profile Generator for macOS/iOS
# ======================================================
# This script creates a .mobileconfig file from your CA certificate
# Usage: ./generate-profile.sh /path/to/ca.crt

set -e

if [ -z "$1" ]; then
    echo "Usage: $0 <path-to-ca.crt>"
    exit 1
fi

CERT_FILE="$1"
OUTPUT_FILE="SafeOps-Network.mobileconfig"

if [ ! -f "$CERT_FILE" ]; then
    echo "[ERROR] Certificate file not found: $CERT_FILE"
    exit 1
fi

# Generate UUIDs
CERT_UUID=$(uuidgen 2>/dev/null || cat /proc/sys/kernel/random/uuid)
PROFILE_UUID=$(uuidgen 2>/dev/null || cat /proc/sys/kernel/random/uuid)

# Base64 encode certificate
CERT_DATA=$(base64 < "$CERT_FILE" | tr -d '\n')

echo "Generating configuration profile..."

cat > "$OUTPUT_FILE" << EOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>PayloadContent</key>
    <array>
        <dict>
            <key>PayloadCertificateFileName</key>
            <string>SafeOps-CA.crt</string>
            <key>PayloadContent</key>
            <data>$CERT_DATA</data>
            <key>PayloadDescription</key>
            <string>Adds the SafeOps Root CA certificate</string>
            <key>PayloadDisplayName</key>
            <string>SafeOps Root CA</string>
            <key>PayloadIdentifier</key>
            <string>com.safeops.certificate.rootca</string>
            <key>PayloadType</key>
            <string>com.apple.security.root</string>
            <key>PayloadUUID</key>
            <string>$CERT_UUID</string>
            <key>PayloadVersion</key>
            <integer>1</integer>
        </dict>
    </array>
    <key>PayloadDescription</key>
    <string>Installs the SafeOps security certificate for network access</string>
    <key>PayloadDisplayName</key>
    <string>SafeOps Network Security</string>
    <key>PayloadIdentifier</key>
    <string>com.safeops.profile.network</string>
    <key>PayloadOrganization</key>
    <string>SafeOps Security</string>
    <key>PayloadRemovalDisallowed</key>
    <false/>
    <key>PayloadType</key>
    <string>Configuration</string>
    <key>PayloadUUID</key>
    <string>$PROFILE_UUID</string>
    <key>PayloadVersion</key>
    <integer>1</integer>
</dict>
</plist>
EOF

echo ""
echo "============================================"
echo " Profile Generated: $OUTPUT_FILE"
echo "============================================"
echo ""
echo "Deploy via:"
echo "  - MDM (Jamf, Mosyle, Kandji)"
echo "  - Apple Business Manager"
echo "  - Email to users (they double-click)"
echo "  - Host on captive portal for download"
echo ""
