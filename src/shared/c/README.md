# SafeOps C Shared Header Library

## Introduction and Overview

### What is the C Shared Header Library?

The SafeOps C shared header library is a collection of 4 C header files defining the complete ABI (Application Binary Interface) contract between the Windows kernel driver and userspace service. Unlike traditional shared libraries that provide compiled code, these headers establish data structure layouts, constant values, and command codes that must remain synchronized between kernel-mode and user-mode components for correct operation.

**Purpose:** Enable zero-copy, high-performance communication between:
- **Kernel Driver** (`safeops.sys`) - Packet capture, filtering, ring buffer producer
- **Userspace Service** (`userspace_service.exe`) - Ring buffer consumer, log writer, driver control

**Key Characteristics:**
- Header-only library (no .lib or .dll compilation)
- Both components include identical headers at compile-time
- Structures define binary memory layouts (not just type definitions)
- Changes to headers require recompiling both kernel and userspace
- Single source of truth for cross-boundary communication

---

## Library Contents

### Header Files (4 total)

1. **[shared_constants.h](shared_constants.h)** (Foundational Constants)
   - System-wide constants and limits
   - Version numbers and ABI compatibility markers
   - Ring buffer dimensions (2GB size, 16KB entries)
   - Protocol identifiers (EtherTypes, IP protocols)
   - NIC classification tags (WAN/LAN/WiFi)
   - IOCTL command ranges and categories
   - Resource limits (max rules, connections, buffers)
   - **No dependencies on other SafeOps headers**

2. **[ring_buffer.h](ring_buffer.h)** (Ring Buffer Structures)
   - Lock-free ring buffer header (metadata)
   - Ring buffer entry structure (packet container)
   - Memory mapping structures for userspace
   - Statistics structures for monitoring
   - Helper macros for index calculations
   - **Depends on:** `shared_constants.h`

3. **[packet_structs.h](packet_structs.h)** (Network Packet Structures)
   - Layer 2: Ethernet, VLAN headers
   - Layer 3: IPv4, IPv6 headers
   - Layer 4: TCP, UDP, ICMP, ICMPv6 headers
   - Unified SAFEOPS_PACKET structure with metadata
   - Protocol-specific unions for fast access
   - **Depends on:** `shared_constants.h`

4. **[ioctl_codes.h](ioctl_codes.h)** (IOCTL Command Definitions)
   - 20+ IOCTL commands for driver control
   - Organized into categories (stats, filters, capture, NIC, ring buffer)
   - Uses Windows CTL_CODE macro
   - Transfer methods (buffered, direct)
   - Access rights (read, write)
   - **Depends on:** `shared_constants.h`

### Documentation (1 file)

5. **README.md** (This File)
   - Overview of library purpose and structure
   - Usage patterns and best practices
   - Binary compatibility guidelines
   - Build integration instructions
   - Troubleshooting and common issues

---

## Architecture Overview

### Communication Model

```
┌─────────────────────────────────────────────────────────────────┐
│                    Windows Kernel Mode                           │
│                                                                   │
│  ┌───────────────────────────────────────────────────────────┐  │
│  │  Kernel Driver (safeops.sys)                              │  │
│  │                                                             │  │
│  │  • Includes all 4 C headers at compile-time               │  │
│  │  • Captures packets from NDIS filter                      │  │
│  │  • Parses using packet_structs.h definitions              │  │
│  │  • Writes to ring buffer (ring_buffer.h structures)       │  │
│  │  • Processes IOCTL commands (ioctl_codes.h)               │  │
│  └───────────────────────────────────────────────────────────┘  │
│                            │                                      │
│                            │ Ring Buffer (2GB Shared Memory)      │
│                            │ IOCTL Commands (DeviceIoControl)     │
└────────────────────────────┼──────────────────────────────────────┘
                             │
                             ▼
┌─────────────────────────────────────────────────────────────────┐
│                    Windows User Mode                             │
│                                                                   │
│  ┌───────────────────────────────────────────────────────────┐  │
│  │  Userspace Service (userspace_service.exe)               │  │
│  │                                                             │  │
│  │  • Includes all 4 C headers at compile-time               │  │
│  │  • Maps ring buffer into process memory                   │  │
│  │  • Reads packets using ring_buffer.h structures           │  │
│  │  • Parses using packet_structs.h definitions              │  │
│  │  • Sends IOCTL commands using ioctl_codes.h               │  │
│  │  • Converts to JSON logs and proto messages               │  │
│  └───────────────────────────────────────────────────────────┘  │
│                            │                                      │
└────────────────────────────┼──────────────────────────────────────┘
                             │
                             ▼
                    Higher-Level Services
                    (Firewall, IDS, DNS, etc.)
                    via gRPC/Proto messages
```

### Data Flow

#### 1. Packet Capture Flow

```
Network Adapter → NDIS Filter → Kernel Driver
                                      ↓
                                 Parse packet using packet_structs.h
                                      ↓
                                 Write to ring buffer using ring_buffer.h
                                      ↓
                                 2GB Shared Memory
                                      ↓
Userspace Service reads from ring buffer
                                      ↓
                                 Parse using packet_structs.h
                                      ↓
                                 Convert to JSON logs
                                      ↓
                                 Convert to proto.Packet messages
                                      ↓
                                 Send to services via gRPC
```

#### 2. Control Flow (IOCTL)

```
Higher-Level Service → gRPC call → Userspace Service
                                        ↓
                                   Construct IOCTL using ioctl_codes.h
                                        ↓
                                   DeviceIoControl() Win32 API
                                        ↓
                                   Windows I/O Manager
                                        ↓
                                   Kernel Driver IRP handler
                                        ↓
                                   Process command (add rule, get stats, etc.)
                                        ↓
                                   Return result
                                        ↓
                                   Userspace receives response
                                        ↓
                                   gRPC response to service
```

---

## Header Dependencies

### Dependency Graph

```
shared_constants.h (Level 0 - No dependencies)
        │
        ├─────────────┬─────────────┬─────────────┐
        ▼             ▼             ▼             ▼
  ring_buffer.h  packet_structs.h  ioctl_codes.h  README.md
   (Level 1)        (Level 1)       (Level 1)     (Level 1)
```

### Include Order

```c
// In kernel driver or userspace service:
#include <windows.h>           // Windows SDK (always first)
#include <winsock2.h>          // Network types
#include <winioctl.h>          // IOCTL macros

#include "shared_constants.h"  // Must be first SafeOps header
#include "ring_buffer.h"       // Depends on shared_constants.h
#include "packet_structs.h"    // Depends on shared_constants.h
#include "ioctl_codes.h"       // Depends on shared_constants.h
```

**Why This Order Matters:**
- Windows headers must come before SafeOps headers (provide base types)
- `shared_constants.h` must come before other SafeOps headers (provides constants they need)
- Order of `ring_buffer.h`, `packet_structs.h`, `ioctl_codes.h` doesn't matter (no interdependencies)

---

## Usage Patterns

### Pattern 1: Kernel Driver - Packet Capture

```c
// In kernel driver packet_capture.c:
#include "packet_structs.h"

NTSTATUS CapturePacket(PNET_BUFFER netBuffer, ULONG interfaceIndex) {
    // Allocate packet buffer
    UCHAR packetData[MAX_PACKET_SIZE];
    ULONG packetLength = CopyNetBufferToArray(netBuffer, packetData, MAX_PACKET_SIZE);
    
    // Parse Ethernet header
    ETHERNET_HEADER* eth = (ETHERNET_HEADER*)packetData;
    USHORT etherType = ntohs(eth->etherType);
    
    // Parse IP header based on EtherType
    if (etherType == ETHERTYPE_IPV4) {
        IPV4_HEADER* ip = (IPV4_HEADER*)(packetData + sizeof(ETHERNET_HEADER));
        
        // Parse transport layer based on protocol
        if (ip->protocol == IPPROTO_TCP) {
            ULONG ipHeaderLen = (ip->versionAndHeaderLength & 0x0F) * 4;
            TCP_HEADER* tcp = (TCP_HEADER*)((UCHAR*)ip + ipHeaderLen);
            
            // Populate SAFEOPS_PACKET with parsed data
            SAFEOPS_PACKET packet = {0};
            packet.signature = PACKET_ENTRY_SIGNATURE;
            packet.version = STRUCT_VERSION_V1;
            packet.timestamp = KeQuerySystemTime();
            packet.interfaceIndex = interfaceIndex;
            packet.etherType = etherType;
            packet.ipVersion = 4;
            packet.protocol = IPPROTO_TCP;
            packet.sourcePort = ntohs(tcp->sourcePort);
            packet.destinationPort = ntohs(tcp->destinationPort);
            packet.capturedLength = packetLength;
            RtlCopyMemory(packet.data, packetData, packetLength);
            
            // Write to ring buffer
            return WritePacketToRingBuffer(&packet);
        }
    }
    
    return STATUS_SUCCESS;
}
```

### Pattern 2: Userspace Service - Ring Buffer Consumer

```c
// In userspace service ring_reader.c:
#include "ring_buffer.h"
#include "packet_structs.h"

BOOL ReadPacketsFromRingBuffer(void) {
    // Get ring buffer header
    RING_BUFFER_HEADER* header = (RING_BUFFER_HEADER*)g_ringBufferBase;
    
    // Check if packets available
    while (!RING_BUFFER_IS_EMPTY(header)) {
        // Get current read index
        ULONG64 readIndex = header->readIndex;
        
        // Get entry at read index
        RING_BUFFER_ENTRY* entry = RING_BUFFER_GET_ENTRY(header, readIndex);
        
        // Validate entry signature
        if (entry->signature != PACKET_ENTRY_SIGNATURE) {
            LogError("Invalid packet signature at index %llu", readIndex);
            return FALSE;
        }
        
        // Cast entry data to SAFEOPS_PACKET
        SAFEOPS_PACKET* packet = (SAFEOPS_PACKET*)entry->data;
        
        // Validate packet signature
        if (packet->signature != PACKET_ENTRY_SIGNATURE) {
            LogError("Invalid SAFEOPS_PACKET signature");
            return FALSE;
        }
        
        // Process packet (convert to JSON, proto, etc.)
        ProcessPacket(packet);
        
        // Increment read index (atomic operation)
        InterlockedIncrement64(&header->readIndex);
    }
    
    return TRUE;
}
```

### Pattern 3: Userspace Service - IOCTL Commands

```c
// In userspace service ioctl_client.c:
#include "ioctl_codes.h"

NTSTATUS GetDriverVersion(SAFEOPS_VERSION_INFO* versionInfo) {
    DWORD bytesReturned;
    
    // Send IOCTL_SAFEOPS_GET_VERSION to driver
    BOOL success = DeviceIoControl(
        g_driverHandle,                    // Driver device handle
        IOCTL_SAFEOPS_GET_VERSION,        // IOCTL code from ioctl_codes.h
        NULL,                              // No input buffer
        0,                                 // No input
        versionInfo,                       // Output buffer
        sizeof(SAFEOPS_VERSION_INFO),     // Output size
        &bytesReturned,                    // Bytes returned
        NULL                               // Not overlapped
    );
    
    if (!success) {
        DWORD error = GetLastError();
        LogError("IOCTL_SAFEOPS_GET_VERSION failed: %u", error);
        return STATUS_UNSUCCESSFUL;
    }
    
    // Validate returned data
    if (bytesReturned != sizeof(SAFEOPS_VERSION_INFO)) {
        LogError("Unexpected return size: %u", bytesReturned);
        return STATUS_INVALID_BUFFER_SIZE;
    }
    
    return STATUS_SUCCESS;
}

NTSTATUS AddFirewallRule(FILTER_RULE* rule, ULONG* ruleId) {
    DWORD bytesReturned;
    
    // Send IOCTL_SAFEOPS_ADD_FILTER_RULE to driver
    BOOL success = DeviceIoControl(
        g_driverHandle,
        IOCTL_SAFEOPS_ADD_FILTER_RULE,   // IOCTL code
        rule,                              // Input: rule structure
        sizeof(FILTER_RULE),
        ruleId,                            // Output: assigned rule ID
        sizeof(ULONG),
        &bytesReturned,
        NULL
    );
    
    if (!success) {
        return STATUS_UNSUCCESSFUL;
    }
    
    LogInfo("Added firewall rule, ID: %u", *ruleId);
    return STATUS_SUCCESS;
}
```

---

## Binary Compatibility Requirements

### Critical Rules for Maintaining ABI Compatibility

#### Rule 1: Structure Size Immutability

- Once a structure is defined and deployed, its size **CANNOT** change
- Adding fields requires creating new versioned structures (e.g., `SAFEOPS_PACKET_V2`)
- Both kernel and userspace must use same structure version
- Use compile-time assertions to verify sizes:

```c
C_ASSERT(sizeof(RING_BUFFER_HEADER) == 192);
C_ASSERT(sizeof(SAFEOPS_PACKET) <= MAX_PACKET_SIZE);
```

#### Rule 2: Field Offset Stability

- Field offsets (byte positions within structure) must **never** change
- Reordering fields breaks compatibility even if size remains same
- Adding fields: append to end (before any padding)
- Use compile-time assertions to verify offsets:

```c
C_ASSERT(FIELD_OFFSET(RING_BUFFER_HEADER, writeIndex) == 32);
C_ASSERT(FIELD_OFFSET(SAFEOPS_PACKET, signature) == 0);
```

#### Rule 3: Packing Directive Consistency

- Both kernel and userspace must use identical `#pragma pack()` settings
- Recommended: `#pragma pack(push, name, 1)` for all shared structures
- Never remove or change packing directives
- Compiler may insert padding differently without explicit packing

#### Rule 4: IOCTL Code Immutability

- Once an IOCTL code is defined, its value **CANNOT** change
- IOCTL codes are part of the driver's public API
- Old userspace must work with new driver (forward compatibility)
- Adding new IOCTLs: use next available function code in category range

#### Rule 5: Byte Order Consistency

- Network structures store values in network byte order (big-endian)
- Always use `ntohs()`, `ntohl()` when reading multi-byte network fields
- Never store host byte order values in shared structures
- Both sides must apply same byte order conversions

#### Rule 6: Version Negotiation

- Every major structure includes version field
- Userspace checks driver version at initialization
- Incompatible versions prevent service startup
- Version checking prevents silent data corruption

**Example Version Check:**

```c
// Userspace initialization:
SAFEOPS_VERSION_INFO driverVersion;
GetDriverVersion(&driverVersion);

if (driverVersion.abiVersion != SAFEOPS_ABI_VERSION) {
    LogError("ABI version mismatch: driver=%u, service=%u",
             driverVersion.abiVersion, SAFEOPS_ABI_VERSION);
    return ERROR_VERSION_MISMATCH;
}

LogInfo("Driver ABI version compatible: %u", driverVersion.abiVersion);
```

---

## Build Integration

### Kernel Driver Build (Visual Studio + WDK)

**Project Structure:**
```
src/kernel_driver/
  ├── driver.c
  ├── packet_capture.c
  ├── filter_engine.c
  ├── shared_memory.c
  ├── ioctl_handler.c
  └── driver.h  (includes all shared headers)
```

**Include Paths (Project Settings):**
```
- $(ProjectDir)\..\shared\c\      # SafeOps shared headers
- $(WDKDIR)\Include\              # WDK headers
- $(SDKDIR)\Include\              # Windows SDK headers
```

**Build Steps:**
1. Preprocessor includes `shared_constants.h`, `ring_buffer.h`, etc.
2. Compiler validates structure sizes with `C_ASSERT()`
3. Linker produces `safeops.sys` with embedded structure definitions
4. Driver installs into `C:\Windows\System32\drivers\`

### Userspace Service Build (Visual Studio or gcc)

**Project Structure:**
```
src/userspace_service/
  ├── service_main.c
  ├── ioctl_client.c
  ├── ring_reader.c
  ├── log_writer.c
  └── userspace_service.h  (includes all shared headers)
```

**Include Paths (Project Settings):**
```
- $(ProjectDir)\..\shared\c\      # SafeOps shared headers (SAME PATH as kernel)
- $(SDKDIR)\Include\              # Windows SDK headers
```

**Build Steps:**
1. Preprocessor includes `shared_constants.h`, `ring_buffer.h`, etc.
2. Compiler validates structure sizes with `static_assert()`
3. Linker produces `userspace_service.exe` with embedded structure definitions
4. Service installs as Windows service

> **Critical:** Both projects must reference SAME physical location for shared headers
> - Use relative paths or symbolic links
> - Never copy headers into project directories
> - Single source of truth prevents version drift

### Verification Script (PowerShell)

```powershell
# Verify both projects use same header files
$kernelHeaders = Get-Item "src\kernel_driver\..\shared\c\*.h" -Resolve
$userspaceHeaders = Get-Item "src\userspace_service\..\shared\c\*.h" -Resolve

if ($kernelHeaders -ne $userspaceHeaders) {
    Write-Error "Header file paths differ between kernel and userspace!"
    exit 1
}

Write-Host "✓ Both projects reference same shared headers"
```

---

## Testing and Validation

### Build-Time Validation

```c
// In both kernel driver and userspace service:

// Verify structure sizes
C_ASSERT(sizeof(ETHERNET_HEADER) == 14);
C_ASSERT(sizeof(IPV4_HEADER) == 20);
C_ASSERT(sizeof(TCP_HEADER) == 20);
C_ASSERT(sizeof(RING_BUFFER_HEADER) % 64 == 0);  // Cache-line aligned
C_ASSERT(sizeof(SAFEOPS_PACKET) <= MAX_PACKET_SIZE);

// Verify field offsets
C_ASSERT(FIELD_OFFSET(RING_BUFFER_HEADER, writeIndex) == 32);
C_ASSERT(FIELD_OFFSET(RING_BUFFER_HEADER, readIndex) == 40);
C_ASSERT(FIELD_OFFSET(SAFEOPS_PACKET, signature) == 0);

// Verify IOCTL code uniqueness
C_ASSERT(IOCTL_SAFEOPS_GET_VERSION != IOCTL_SAFEOPS_GET_CAPABILITIES);
C_ASSERT(IOCTL_SAFEOPS_ADD_FILTER_RULE != IOCTL_SAFEOPS_REMOVE_FILTER_RULE);

// Verify constants match
C_ASSERT(RING_BUFFER_SIZE == 2147483648ULL);  // 2GB
C_ASSERT(RING_BUFFER_ENTRY_SIZE == 16384);    // 16KB
C_ASSERT(MAX_PACKET_SIZE == 16384);
```

### Runtime Validation

```c
// Userspace service initialization checks:
BOOL ValidateDriverCompatibility(void) {
    // Check driver version
    SAFEOPS_VERSION_INFO version;
    if (GetDriverVersion(&version) != STATUS_SUCCESS) {
        LogError("Failed to query driver version");
        return FALSE;
    }
    
    // Verify ABI compatibility
    if (version.abiVersion != SAFEOPS_ABI_VERSION) {
        LogError("ABI version mismatch: driver=%u, service=%u",
                 version.abiVersion, SAFEOPS_ABI_VERSION);
        return FALSE;
    }
    
    // Verify ring buffer size
    RING_BUFFER_HEADER* header = MapRingBuffer();
    if (header->totalSize != RING_BUFFER_SIZE) {
        LogError("Ring buffer size mismatch: driver=%llu, service=%llu",
                 header->totalSize, RING_BUFFER_SIZE);
        return FALSE;
    }
    
    // Verify ring buffer signature
    if (header->signature != RING_BUFFER_SIGNATURE) {
        LogError("Invalid ring buffer signature: 0x%08X", header->signature);
        return FALSE;
    }
    
    LogInfo("Driver compatibility validated successfully");
    return TRUE;
}
```

---

## Common Issues and Troubleshooting

### Issue 1: Structure Size Mismatch

**Symptoms:**
- Userspace reads garbage data from ring buffer
- Packet parsing returns nonsensical values
- System may crash when accessing structures

**Cause:**
- Kernel and userspace compiled with different header versions
- Compiler settings differ (packing, alignment)
- One side modified structure without recompiling other side

**Solution:**

```c
// Add compile-time size checks in both projects:
C_ASSERT(sizeof(SAFEOPS_PACKET) == EXPECTED_SIZE);

// Add runtime size validation:
if (header->entrySize != RING_BUFFER_ENTRY_SIZE) {
    LogError("Entry size mismatch: expected %u, got %u",
             RING_BUFFER_ENTRY_SIZE, header->entrySize);
    return ERROR;
}
```

### Issue 2: IOCTL Command Not Recognized

**Symptoms:**
- `DeviceIoControl()` returns FALSE
- `GetLastError()` returns `ERROR_INVALID_FUNCTION`
- Driver logs "Unknown IOCTL code"

**Cause:**
- IOCTL code mismatch between userspace and kernel
- Driver doesn't implement requested IOCTL
- IOCTL code calculated incorrectly

**Solution:**

```c
// Verify IOCTL code value matches:
LogInfo("Sending IOCTL: 0x%08X", IOCTL_SAFEOPS_GET_VERSION);

// In kernel driver, log received IOCTL:
ULONG ioControlCode = IoGetCurrentIrpStackLocation(Irp)->Parameters.DeviceIoControl.IoControlCode;
LogInfo("Received IOCTL: 0x%08X", ioControlCode);

// Compare values - should match exactly
```

### Issue 3: Ring Buffer Corruption

**Symptoms:**
- Invalid packet signatures
- Read index exceeds write index
- Dropped packet counter increases rapidly
- Userspace crashes when reading packets

**Cause:**
- Concurrent access without proper atomics
- Buffer overflow (write index wraps incorrectly)
- Memory corruption from other components

**Solution:**

```c
// Always use atomic operations for indices:
InterlockedIncrement64(&header->writeIndex);  // Kernel
InterlockedIncrement64(&header->readIndex);   // Userspace

// Validate indices before access:
if (header->readIndex > header->writeIndex) {
    LogError("Read index (%llu) > write index (%llu) - corruption detected",
             header->readIndex, header->writeIndex);
    return ERROR;
}

// Validate packet signatures:
if (packet->signature != PACKET_ENTRY_SIGNATURE) {
    LogError("Invalid packet signature: 0x%08X", packet->signature);
    // Skip this packet, don't crash
    return ERROR;
}
```

### Issue 4: Network Byte Order Confusion

**Symptoms:**
- Port numbers appear as large values (e.g., 20480 instead of 80)
- IP addresses display incorrectly
- Protocol identification fails

**Cause:**
- Forgetting to call `ntohs()`/`ntohl()` on network fields
- Converting values twice (double conversion)
- Storing host byte order in structures

**Solution:**

```c
// Always convert when reading from network structures:
USHORT port = ntohs(tcpHeader->sourcePort);  // CORRECT
// NOT: USHORT port = tcpHeader->sourcePort;  // WRONG

// Never convert when writing to network structures:
ethHeader->etherType = htons(0x0800);        // CORRECT
// NOT: ethHeader->etherType = 0x0800;        // WRONG (on little-endian systems)

// Convert only once:
ULONG ip = ntohl(ipHeader->sourceAddress);   // CORRECT
// NOT: ULONG ip = ntohl(htonl(ipHeader->sourceAddress));  // WRONG (double conversion)
```

---

## Best Practices

### 1. Single Source of Truth

- Maintain one copy of shared headers in `src/shared/c/`
- Both kernel and userspace reference this location
- Never duplicate or copy headers into project directories
- Use version control to track header changes

### 2. Compile-Time Validation

- Add `C_ASSERT()` for structure sizes in both projects
- Add `FIELD_OFFSET()` checks for critical fields
- Fail compilation if sizes/offsets don't match expectations
- Better to catch at compile-time than runtime

### 3. Version Everything

- Include version field in every major structure
- Check versions at runtime before processing data
- Increment ABI version on any breaking change
- Document version changes in changelog

### 4. Document Breaking Changes

- Any structure modification is potentially breaking
- Document what changed and why
- Provide migration guide for updating both components
- Test thoroughly after any header changes

### 5. Atomic Operations for Shared Data

- Use `InterlockedIncrement64()` for ring buffer indices
- Use `MemoryBarrier()` before/after signature writes
- Never use regular assignments on volatile shared fields
- Follow acquire/release memory ordering semantics

### 6. Defensive Validation

- Validate signatures before accessing structures
- Bounds-check all indices and sizes
- Handle version mismatches gracefully
- Log errors with enough detail for debugging

---

## Further Reading

### Internal Documentation

- [shared_constants.h](shared_constants.h) - Detailed documentation of all constants
- [ring_buffer.h](ring_buffer.h) - Ring buffer structure specifications
- [packet_structs.h](packet_structs.h) - Network protocol structure definitions
- [ioctl_codes.h](ioctl_codes.h) - IOCTL command reference

### External Resources

- **Windows Driver Kit (WDK) Documentation** - Kernel development fundamentals
- **Windows SDK Documentation** - Win32 API reference for `DeviceIoControl()`
- **RFC 791 (IPv4)**, **RFC 8200 (IPv6)**, **RFC 793 (TCP)**, **RFC 768 (UDP)** - Protocol specifications
- **IEEE 802.3 (Ethernet)**, **IEEE 802.1Q (VLAN)** - Data link layer standards

### SafeOps Project Documentation

- `docs/kernel_driver/` - Kernel driver architecture and implementation
- `docs/userspace_service/` - Userspace service architecture
- `docs/proto/` - Protocol buffer message definitions (data plane)
- `docs/integration/` - Service integration patterns

---

**Last Updated:** 2025-12-20  
**Version:** 2.0.0  
**ABI Version:** 0x00020000
