# DNS Server

SafeOps DNS Server providing authoritative DNS for safeops.local and recursive forwarding.

## Features

- Authoritative DNS for internal zones (safeops.local)
- Recursive DNS forwarding to 8.8.8.8, 1.1.1.1
- Dynamic DNS updates from DHCP Monitor via gRPC
- In-memory query cache (50,000 entries)
- PostgreSQL-backed zone and record storage

## Ports

- **UDP/TCP 53**: DNS queries
- **gRPC 50053**: Internal API for DynamicUpdate()
- **HTTP 9153**: Prometheus metrics

## Quick Start

```bash
# Build
go build -o dns_server.exe ./cmd/dns_server

# Run
./dns_server.exe
```

## Configuration

See `config/templates/dns_server.toml` for configuration options.
