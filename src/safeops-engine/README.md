# SafeOps Engine v3.0.0

**High-Performance Network Packet Pipeline for Windows**

## Overview

SafeOps Engine is a pure passthrough network packet capture engine built on WinpkFilter (NDISAPI). It captures all network traffic and forwards it immediately without modification.

```
Network Traffic → SafeOps Engine → Forward Immediately
                        ↓
                  (logs to file)
```

## Quick Facts

- **Platform:** Windows 10/11 (64-bit)
- **Performance:** ~6,500 packets/sec, <10μs latency
- **Memory:** 8-16 MB
- **Binary Size:** 3.5 MB
- **Packet Loss:** 0%

## What It Does

1. Captures all network packets (IPv4 + IPv6)
2. Forwards them immediately (zero delay)
3. Logs statistics to file

## What It Provides

**Reusable Internal Modules:**
- `internal/driver` - Packet capture/forward
- `internal/verdict` - IP blocking, TCP RST, DNS redirect
- `internal/parser` - Domain extraction (DNS, SNI, HTTP, DHCP)
- `internal/metadata` - Packet metadata structures
- `internal/config` - Configuration structures

**Other programs** (firewalls, IDS, loggers) can import these modules to build on top of SafeOps.

## Quick Start

```powershell
# Run as Administrator
cd D:\SafeOpsFV2\src\safeops-engine
.\safeops-engine.exe
```

## Requirements

- Windows 10/11 (64-bit)
- WinpkFilter driver (ndisrd.sys)
- Administrator privileges

## Complete Documentation

For complete technical documentation, integration examples, and API reference, see:

**[COMPLETE_DOCUMENTATION.md](COMPLETE_DOCUMENTATION.md)**

This includes:
- Architecture and packet flow
- File structure and internal modules
- Verdict engine usage (IP blocking, TCP RST, DNS redirect)
- Integration guide with code examples
- Configuration and performance tuning
- Troubleshooting

## Version

**v3.0.0** - Pure passthrough mode with reusable internal modules

## License

See project root for license information.
