# SafeOps Shared C Headers

Shared header files for kernel driver and userspace communication.

## Headers

| File | Purpose |
|------|---------|
| `ring_buffer.h` | Ring buffer structures for zero-copy packet transfer |
| `packet_structs.h` | Ethernet/IP/TCP/UDP packet headers |
| `ioctl_codes.h` | IOCTL command codes for driver control |
| `shared_constants.h` | Common constants (log levels, protocols, actions) |

## Usage

```c
// In kernel driver
#include "../../shared/c/ring_buffer.h"
#include "../../shared/c/ioctl_codes.h"

// In userspace service
#include "../shared/c/ioctl_codes.h"
#include "../shared/c/packet_structs.h"
```

## Key Structures

- **ring_buffer_header_t**: Ring buffer metadata (head, tail, size)
- **ring_buffer_entry_t**: Individual packet entry (timestamp, length, data)
- **eth/ipv4/tcp/udp_header_t**: Protocol headers for parsing
