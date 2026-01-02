#!/bin/bash
# DNS Server Installation Script

echo "Installing DNS Server..."

# Build the DNS server
cd src/dns_server
go mod tidy
go build -o ../../bin/dns_server.exe ./cmd/dns_server

echo "DNS Server installed to bin/dns_server.exe"
