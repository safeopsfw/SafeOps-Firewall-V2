#!/bin/bash
# DNS Testing Script

echo "Testing DNS Server..."

# Test recursive resolution
echo "Testing recursive resolution (google.com)..."
nslookup google.com 127.0.0.1

# Test local resolution (if zone configured)
echo "Testing local resolution (safeops.local)..."
nslookup ns1.safeops.local 127.0.0.1

echo "DNS tests complete"
