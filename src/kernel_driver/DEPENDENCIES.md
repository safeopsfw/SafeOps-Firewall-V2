# SafeOps Kernel Driver - Module Dependency Map

**Version:** 2.0.0  
**Last Updated:** 2024-12-13

---

## Overview

This document defines the complete dependency relationships between all kernel driver modules. Understanding these dependencies is critical for:
- **Build order** - Modules must compile in dependency order
- **Architecture** - Maintaining clean separation of concerns
- **Maintenance** - Avoiding circular dependencies and tight coupling
- **Testing** - Understanding which modules can be unit tested independently

---

## Visual Dependency Graph

```
                    ┌─────────────────┐
                    │   driver.c      │ (Entry Point - Level 7)
                    │  DriverEntry()  │
                    └────────┬────────┘
                             │
                ┌────────────┼────────────┐
                │            │            │
                ▼            ▼            ▼
         ┌──────────┐  ┌──────────┐  ┌──────────┐
         │ ioctl_   │  │ filter_  │  │ packet_  │ (Level 6, 5, 4)
         │handler.c │  │ engine.c │  │ capture.c│
         └────┬─────┘  └────┬─────┘  └────┬─────┘
              │             │             │
              └─────────────┼─────────────┘
                            │
                ┌───────────┼──────────┐
                │           │          │
                ▼           ▼          ▼
         ┌──────────┐  ┌──────────┐  ┌──────────┐
         │   nic_   │  │ shared_  │  │performance│ (Level 3, 2, 1)
         │management│  │ memory.c │  │    .c    │
         └────┬─────┘  └────┬─────┘  └────┬─────┘
              │             │             │
              └─────────────┴─────────────┘
                            │
                            ▼
                    ┌──────────────┐
                    │  driver.h    │ (Level 0 - Foundation)
                    └──────────────┘
```

---

## Dependency Hierarchy (Bottom-Up)

### **Level 0: Foundation (No Dependencies)**

#### driver.h
- **Type**: Header file
- **Depends on**: Nothing (foundation)
- **Provides**: 
  - Global type definitions
  - Common macros and constants
  - Shared structures (DRIVER_CONTEXT, DEVICE_EXTENSION)
  - Function prototypes
- **Included by**: All other modules

---

### **Level 1: Performance Utilities**

#### performance.c / performance.h
- **Depends on**: `driver.h`
- **Provides**:
  - DMA buffer management
  - RSS (Receive Side Scaling) configuration
  - NUMA-aware memory allocation
  - Hardware offload management
  - Interrupt coalescing
  - CPU affinity control
  - Performance statistics collection
- **Called by**: 
  - `packet_capture.c` - Get RSS queue info, DMA buffers
  - `ioctl_handler.c` - Query performance statistics
- **Depends on modules**: None (standalone utility)

---

### **Level 2: Core Storage**

#### shared_memory.c / shared_memory.h
- **Depends on**: `driver.h`
- **Provides**:
  - Lock-free ring buffer (2 GB)
  - Producer/consumer synchronization
  - Memory mapping to userspace
  - Atomic write operations
  - Overflow handling
- **Called by**:
  - `packet_capture.c` - Write packet metadata
  - `ioctl_handler.c` - Map buffer to userspace
  - Userspace (Network Logger) - Read packet metadata
- **Depends on modules**: None (pure storage layer)

---

### **Level 3: NIC Management**

#### nic_management.c / nic_management.h
- **Depends on**: `driver.h` ✅ **ONLY**
- **Provides**:
  - NIC detection and enumeration
  - NIC tagging (WAN=1, LAN=2, WiFi=3)
  - NIC GUID to Tag mapping
  - NIC information queries
  - Automatic NIC binding
- **Called by**:
  - `packet_capture.c` - Get NIC tags for packets
  - `ioctl_handler.c` - Query NIC information
- **Depends on modules**: None (standalone detection)
- **Important**: Does **NOT** depend on `packet_capture.h` to avoid circular dependency ⚠️

---

### **Level 4: Packet Processing**

#### packet_capture.c / packet_capture.h
- **Depends on**:
  - `driver.h` - Global definitions
  - `shared_memory.h` - Write packet metadata
  - `nic_management.h` - Get NIC tags
  - `performance.h` - RSS and DMA utilities
- **Provides**:
  - NDIS lightweight filter registration
  - Packet interception (send/receive paths)
  - Metadata extraction (IPs, ports, protocol)
  - Flow direction detection (North-South vs East-West)
  - Packet tagging with NIC ID
  - Zero-copy packet handling
- **Called by**:
  - NDIS subsystem - Filter callbacks
  - `driver.c` - Initialize/shutdown
  - `ioctl_handler.c` - Start/stop capture
- **Depends on modules**: `shared_memory.c`, `nic_management.c`, `performance.c`

---

### **Level 5: Filtering**

#### filter_engine.c / filter_engine.h
- **Depends on**:
  - `driver.h` - Global definitions
  - `packet_capture.h` - Packet metadata structures (struct definitions only)
  - `ioctl_handler.h` - Filter rule structures (struct definitions only)
- **Provides**:
  - WFP callout registration (8 layers)
  - Packet filtering decisions
  - NAT (Network Address Translation)
  - Connection tracking (1M+ concurrent connections)
  - DDoS protection
  - Rule hash table lookup
- **Called by**:
  - WFP subsystem - Callout functions
  - `driver.c` - Initialize/shutdown
  - `ioctl_handler.c` - Apply firewall rules
- **Depends on modules**: None directly (only includes headers for struct definitions)
- **Note**: Header-only dependencies are acceptable (no circular call chains)

---

### **Level 6: Control Interface**

#### ioctl_handler.c / ioctl_handler.h
- **Depends on**: **ALL other modules**
  - `driver.h` - Global definitions
  - `packet_capture.h` - Start/stop capture
  - `filter_engine.h` - Apply filter rules
  - `shared_memory.h` - Map memory to userspace
  - `nic_management.h` - Query NIC info
  - `performance.h` - Get performance stats
- **Provides**:
  - Device object creation (`\Device\SafeOps`)
  - Symbolic link creation (`\??\SafeOps`)
  - IOCTL command dispatch (20+ commands)
  - Userspace communication interface
  - Configuration management
- **Called by**:
  - Userspace applications - Send IOCTL commands via DeviceIoControl()
  - `driver.c` - Initialize/shutdown
- **Depends on modules**: ALL (orchestrates all functionality)

**IOCTL Commands Provided:**
- `IOCTL_SAFEOPS_START_CAPTURE` (0x800)
- `IOCTL_SAFEOPS_STOP_CAPTURE` (0x801)
- `IOCTL_SAFEOPS_GET_STATS` (0x802)
- `IOCTL_SAFEOPS_ADD_RULE` (0x803)
- `IOCTL_SAFEOPS_DELETE_RULE` (0x804)
- `IOCTL_SAFEOPS_MAP_SHARED_MEMORY` (0x806)
- ... (see ioctl_handler.h for complete list)

---

### **Level 7: Entry Point**

#### driver.c / driver.h
- **Depends on**: **ALL module headers**
  - `driver.h` - Own header
  - `packet_capture.h`
  - `filter_engine.h`
  - `shared_memory.h`
  - `ioctl_handler.h`
  - `nic_management.h`
  - `performance.h`
- **Provides**:
  - `DriverEntry()` - Entry point called by Windows Kernel
  - `DriverUnload()` - Cleanup on driver unload
  - Global driver context
  - Module initialization orchestration
  - Error handling and rollback
- **Called by**: Windows Kernel
- **Depends on modules**: ALL

**Initialization Order in DriverEntry():**
```c
1. PerformanceInitialize()      // DMA, RSS setup
2. SharedMemoryInitialize()     // Create 2GB ring buffer
3. NicManagementInitialize()    // Detect NICs, assign tags
4. PacketCaptureInitialize()    // Register NDIS filter
5. FilterEngineInitialize()     // Register WFP callouts
6. IoctlHandlerInitialize()     // Create device object
```

**Shutdown Order in DriverUnload():**
```c
1. IoctlHandlerShutdown()       // Close device object
2. FilterEngineShutdown()       // Unregister WFP callouts
3. PacketCaptureShutdown()      // Unregister NDIS filter
4. NicManagementShutdown()      // Clean up NIC list
5. SharedMemoryShutdown()       // Destroy ring buffer
6. PerformanceShutdown()        // Release DMA buffers
```

---

## Build Order (Makefile)

**Correct compilation order to respect dependencies:**

```makefile
# Object files in dependency order
OBJS = \
    $(OBJ_DIR)\performance.obj      \  # Level 1
    $(OBJ_DIR)\shared_memory.obj    \  # Level 2
    $(OBJ_DIR)\nic_management.obj   \  # Level 3 (NO packet_capture dependency)
    $(OBJ_DIR)\packet_capture.obj   \  # Level 4 (uses nic_management)
    $(OBJ_DIR)\filter_engine.obj    \  # Level 5
    $(OBJ_DIR)\ioctl_handler.obj    \  # Level 6
    $(OBJ_DIR)\driver.obj              # Level 7 (entry point)

# Link order (same as compilation order)
$(DRIVER_BINARY): $(OBJS)
    link.exe /DRIVER /OUT:$@ $(OBJS) $(LIBS)
```

---

## Module Interaction Matrix

| Module | performance.c | shared_memory.c | nic_management.c | packet_capture.c | filter_engine.c | ioctl_handler.c | driver.c |
|--------|--------------|----------------|-----------------|-----------------|----------------|----------------|----------|
| **performance.c** | - | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ |
| **shared_memory.c** | ❌ | - | ❌ | ❌ | ❌ | ❌ | ❌ |
| **nic_management.c** | ❌ | ❌ | - | ❌ | ❌ | ❌ | ❌ |
| **packet_capture.c** | ✅ | ✅ | ✅ | - | ❌ | ❌ | ❌ |
| **filter_engine.c** | ❌ | ❌ | ❌ | 📋* | - | 📋* | ❌ |
| **ioctl_handler.c** | ✅ | ✅ | ✅ | ✅ | ✅ | - | ❌ |
| **driver.c** | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | - |

**Legend:**
- ✅ = Direct dependency (includes header and calls functions)
- ❌ = No dependency
- 📋* = Header-only dependency (struct definitions only, no function calls)

---

## Call Flow (Runtime)

### **Driver Load Sequence**
```
1. Windows Kernel → driver.c::DriverEntry()
         ↓
2. driver.c → PerformanceInitialize()
         ↓
3. driver.c → SharedMemoryInitialize()
         ↓
4. driver.c → NicManagementInitialize()
         ↓  (Detects NICs, assigns WAN=1, LAN=2, WiFi=3)
         ↓
5. driver.c → PacketCaptureInitialize()
         ↓  (Registers NDIS filter on all NICs)
         ↓
6. driver.c → FilterEngineInitialize()
         ↓  (Registers 8 WFP callouts)
         ↓
7. driver.c → IoctlHandlerInitialize()
         ↓  (Creates \Device\SafeOps)
         ↓
8. Driver ready, waiting for events
```

### **Packet Capture Flow**
```
1. Packet arrives at NIC hardware
         ↓
2. NDIS.sys → packet_capture.c::FilterSendNetBufferLists()
         ↓
3. packet_capture.c → NicGetTagByGuid() (nic_management.c)
         ↓  Returns: 1 (WAN), 2 (LAN), or 3 (WiFi)
         ↓
4. packet_capture.c extracts metadata (100 bytes)
         ↓
5. packet_capture.c → SharedMemoryWrite() (shared_memory.c)
         ↓  Writes to ring buffer (lock-free)
         ↓
6. packet_capture.c returns packet to NDIS
         ↓
7. Network Logger (userspace) reads from ring buffer
```

### **IOCTL Command Flow**
```
1. Userspace → DeviceIoControl(\\.SafeOps, IOCTL_SAFEOPS_START_CAPTURE, ...)
         ↓
2. Windows I/O Manager → ioctl_handler.c::IoctlDispatch()
         ↓
3. ioctl_handler.c → PacketCaptureStart() (packet_capture.c)
         ↓
4. packet_capture.c starts capturing packets
         ↓
5. ioctl_handler.c returns STATUS_SUCCESS to userspace
```

---

## Dependency Rules and Best Practices

### ✅ **DO:**
1. **Follow the hierarchy** - Lower levels never depend on higher levels
2. **Minimize dependencies** - Each module should depend on as few others as possible
3. **Use clean interfaces** - Expose minimal public API in headers
4. **Document dependencies** - Update this file when adding new dependencies
5. **Test independently** - Lower-level modules should be unit-testable in isolation

### ❌ **DON'T:**
1. **Create circular dependencies** - Never have A→B and B→A
2. **Include unnecessary headers** - Only include what you actually use
3. **Expose internals** - Keep module-private functions static
4. **Skip initialization order** - Always follow the documented init sequence
5. **Mix levels** - Don't have a Level 2 module directly call Level 5

---

## Circular Dependency Detection

**Known Resolved Issues:**
- ❌ **WRONG**: `nic_management.c` depends on `packet_capture.h` (would create cycle)
- ✅ **CORRECT**: `nic_management.c` depends only on `driver.h`

**Current Status:** ✅ **No circular dependencies** - All dependencies form a clean DAG (Directed Acyclic Graph)

**Validation Command:**
```bash
# Check for circular includes (run in src/kernel_driver/)
python scripts/check_circular_deps.py *.c *.h
```

---

## Testing Strategy by Level

### **Level 1-3: Unit Testing (Standalone)**
- `performance.c` - Mock driver.h, test DMA/RSS functions
- `shared_memory.c` - Test ring buffer operations in isolation
- `nic_management.c` - Mock NDIS APIs, test NIC detection

### **Level 4-5: Integration Testing**
- `packet_capture.c` - Requires real NDIS stack or mock
- `filter_engine.c` - Requires real WFP or mock

### **Level 6-7: System Testing**
- `ioctl_handler.c` - Requires driver loaded, test from userspace
- `driver.c` - Full driver load/unload tests

---

## Maintenance Checklist

When adding a new module or modifying dependencies:

- [ ] Update this dependency map document
- [ ] Update Makefile build order if needed
- [ ] Update driver.c initialization order
- [ ] Verify no circular dependencies introduced
- [ ] Update module interaction matrix
- [ ] Update call flow diagrams
- [ ] Add unit tests for new module
- [ ] Document dependencies in module header file

---

## Userspace Service Dependencies

The userspace service (`src/userspace_service/`) communicates with the kernel driver and manages packet logging. Here is the dependency map:

### Visual Dependency Graph (Userspace)

```
                    ┌─────────────────┐
                    │ service_main.c  │ (Entry Point)
                    │  WinMain()      │
                    └────────┬────────┘
                             │
            ┌────────────────┼────────────────┐
            │                │                │
            ▼                ▼                ▼
     ┌──────────┐    ┌──────────────┐   ┌──────────────┐
     │ ioctl_   │    │  ring_       │   │ rotation_    │
     │client.c  │    │  reader.c    │   │ manager.c    │
     └────┬─────┘    └──────┬───────┘   └──────┬───────┘
          │                 │                   │
          │                 └───────────────────┘
          │                          │
          ▼                          ▼
    ┌──────────┐             ┌──────────────┐
    │  Kernel  │             │ log_writer.c │
    │  Driver  │             └──────────────┘
    └──────────┘
```

### Userspace Module Hierarchy

#### **Level 0: Shared Header**
- `userspace_service.h` - Shared structures and constants

#### **Level 1: Foundation Modules**
- `log_writer.c` - Writes JSON logs to disk (no internal dependencies)
- `ioctl_client.c` - Communicates with kernel driver (no internal dependencies)

#### **Level 2: Data Processing**
- `ring_reader.c` - Reads from shared memory ring buffer
  - **Depends on**: `ioctl_client.c` (for shared memory mapping)

#### **Level 3: Management**
- `rotation_manager.c` - 5-minute log rotation
  - **Depends on**: `log_writer.c` (coordinates file operations)

#### **Level 4: Orchestrator**
- `service_main.c` - Windows Service entry point
  - **Depends on**: ALL modules (initializes and coordinates)

### Userspace Files Summary

| File | Lines | Dependencies | Purpose |
|------|-------|--------------|---------|
| `service_main.c` | 320 | ALL | Windows Service entry, orchestration |
| `ioctl_client.c` | 961 | Kernel driver | DeviceIoControl communication |
| `ring_reader.c` | 250 | ioctl_client | Lock-free ring buffer reading |
| `log_writer.c` | 100 | File I/O | JSON log writing to disk |
| `rotation_manager.c` | 747 | log_writer | 5-min rotation, IDS archiving |
| `userspace_service.h` | 50 | None | Shared definitions |
| **TOTAL** | **2,428** | | |

### Kernel ↔ Userspace Communication

```
┌─────────────────────────────────────────────────────────────────┐
│                        KERNEL MODE                               │
│  ┌──────────────┐    ┌─────────────────┐    ┌───────────────┐  │
│  │packet_capture│───▶│ shared_memory   │    │ ioctl_handler │  │
│  │ (writes)     │    │ (2GB ring buf)  │    │ (commands)    │  │
│  └──────────────┘    └────────┬────────┘    └───────┬───────┘  │
│                               │                      │          │
└───────────────────────────────┼──────────────────────┼──────────┘
                                │                      │
          ═══════════════════════════════════════════════════════
                          SHARED MEMORY           DeviceIoControl
          ═══════════════════════════════════════════════════════
                                │                      │
┌───────────────────────────────┼──────────────────────┼──────────┐
│                               ▼                      ▼          │
│  ┌──────────────┐    ┌─────────────────┐    ┌───────────────┐  │
│  │ ring_reader  │◀───│ mapped memory   │    │ ioctl_client  │  │
│  │ (reads)      │    │ (user view)     │    │ (sends cmds)  │  │
│  └──────┬───────┘    └─────────────────┘    └───────────────┘  │
│         │                                                       │
│         ▼                                                       │
│  ┌──────────────┐    ┌─────────────────┐                       │
│  │  log_writer  │◀───│rotation_manager │                       │
│  │ (JSON logs)  │    │ (5-min cycle)   │                       │
│  └──────────────┘    └─────────────────┘                       │
│                        USERSPACE MODE                           │
└─────────────────────────────────────────────────────────────────┘
```

### Userspace Initialization Order

```c
// In service_main.c::ServiceMain()
1. InitializeLogging()           // Setup logging
2. IoctlClientInitialize()       // Open driver handle
3. IoctlStartCapture()           // Start packet capture
4. MapSharedMemory()             // Map ring buffer
5. RingReaderInitialize()        // Setup reader
6. LogWriterInitialize()         // Open log file
7. RotationManagerInitialize()   // Start 5-min timer
8. StartProcessingLoop()         // Main loop
```

### Userspace Shutdown Order

```c
// In service_main.c::ServiceStop()
1. StopProcessingLoop()          // Stop main loop
2. RotationManagerShutdown()     // Stop timer, final rotation
3. LogWriterShutdown()           // Flush and close log
4. RingReaderShutdown()          // Cleanup reader
5. IoctlStopCapture()            // Stop capture
6. IoctlClientShutdown()         // Close driver handle
```

---

## References

- **Makefile**: `src/kernel_driver/Makefile` - Build order implementation
- **Driver Entry**: `src/kernel_driver/driver.c` - Initialization sequence
- **Module Headers**: `src/kernel_driver/*.h` - Public APIs and dependencies
- **Userspace Service**: `src/userspace_service/` - Service implementation

---

**Last Verified:** 2024-12-13  
**Verified By:** Architecture Review  
**Status:** ✅ All dependencies validated, no circular dependencies
