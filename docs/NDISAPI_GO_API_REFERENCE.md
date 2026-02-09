# NDISAPI-GO v1.0.1 - Complete API Reference

**Module:** `github.com/wiresock/ndisapi-go v1.0.1`  
**Module Location:** `/c/Users/02arj/go/pkg/mod/github.com/wiresock/ndisapi-go@v1.0.1`  
**Windows Only:** `//go:build windows`

---

## CRITICAL FINDING: FlushAdapterPacketQueue EXISTS

The library DOES have a `FlushAdapterPacketQueue` method for flushing packet queues.

---

## NdisApi Type Overview

### Constructor
```go
func NewNdisApi() (*NdisApi, error)
```

Creates and initializes a new NdisApi instance to interact with NDISRD driver.

### Main Resource Cleanup
```go
func (a *NdisApi) Close()
```

Closes and releases NDISRD driver resources.

### Status Check
```go
func (a *NdisApi) IsDriverLoaded() bool
```

Checks if the NDISRD driver is currently loaded and operational.

---

## CRITICAL METHOD: FlushAdapterPacketQueue

```go
func (a *NdisApi) FlushAdapterPacketQueue(adapter Handle) error
```

**Purpose:** Clears pending packets from an adapter's queue

**File:** `ndisapi_adapter.go` (line 92)

**Parameters:**
- `adapter` (Handle): The network adapter handle to flush

**Returns:**
- `error`: nil on success, error object if operation fails

**Internal IOCTL:** `IOCTL_NDISRD_FLUSH_ADAPTER_QUEUE`

**Implementation:**
```go
return a.DeviceIoControl(
    IOCTL_NDISRD_FLUSH_ADAPTER_QUEUE,
    unsafe.Pointer(&adapter),
    uint32(len(adapter)),
    nil,
    0,
    &a.bytesReturned,
    nil,
)
```

---

## Adapter Management Interface (NdisApiAdapter)

### SetAdapterMode
```go
func (a *NdisApi) SetAdapterMode(currentMode *AdapterMode) error
```

**Purpose:** Set the operational/filter mode of an adapter

**File:** `ndisapi_adapter.go` (line 66)

**Parameters:**
- `currentMode` (*AdapterMode): Mode configuration to apply

**Returns:**
- `error`: nil on success

**Usage in SafeOps:**
```go
mode := ndisapi.AdapterMode{
    AdapterHandle: adapter.Handle,
    Flags: ndisapi.MSTCP_FLAG_SENT_TUNNEL | ndisapi.MSTCP_FLAG_RECV_TUNNEL,
}
d.api.SetAdapterMode(&mode)
```

### GetAdapterMode
```go
func (a *NdisApi) GetAdapterMode(currentMode *AdapterMode) error
```

**Purpose:** Retrieve current operational mode of an adapter

**File:** `ndisapi_adapter.go` (line 79)

**Returns:**
- `error`: nil on success

### GetAdapterPacketQueueSize
```go
func (a *NdisApi) GetAdapterPacketQueueSize(adapter Handle, size *uint32) error
```

**Purpose:** Query the current size of a packet queue

**File:** `ndisapi_adapter.go` (line 105)

### GetTcpipBoundAdaptersInfo
```go
func (a *NdisApi) GetTcpipBoundAdaptersInfo() (*TcpAdapterList, error)
```

**Purpose:** Enumerate all TCP/IP bound network adapters

### SetPacketEvent
```go
func (a *NdisApi) SetPacketEvent(adapter Handle, win32Event windows.Handle) error
```

**Purpose:** Register a Windows event to signal when packets are available

**File:** `ndisapi_adapter.go` (line 118)

### SetAdapterListChangeEvent
```go
func (a *NdisApi) SetAdapterListChangeEvent(win32Event windows.Handle) error
```

**Purpose:** Register event to signal when adapter list changes

**File:** `ndisapi_adapter.go` (line 149)

### ConvertWindows2000AdapterName
```go
func (a *NdisApi) ConvertWindows2000AdapterName(adapterName string) string
```

**Purpose:** Convert legacy Windows 2000 adapter name format

**File:** `ndisapi_adapter.go` (line 162)

---

## Packet I/O Interface (NdisApiIO)

### Send Methods
```go
func (a *NdisApi) SendPacketToMstcp(packet *EtherRequest) error
func (a *NdisApi) SendPacketToAdapter(packet *EtherRequest) error
func (a *NdisApi) SendPacketsToMstcp(packet *EtherMultiRequest) error
func (a *NdisApi) SendPacketsToAdapter(packet *EtherMultiRequest) error
```

**Purpose:** Send packets back to network stack or adapter

**File:** `ndisapi_io.go`

### Read Methods
```go
func (a *NdisApi) ReadPacket(packet *EtherRequest) bool
func (a *NdisApi) ReadPackets(packet *EtherMultiRequest) bool
```

**Purpose:** Read intercepted packets from queue

**File:** `ndisapi_io.go`

**Returns:**
- `bool`: true if packet(s) available, false otherwise

---

## Fast I/O Interface (NdisApiFastIO)

```go
func (a *NdisApi) InitializeFastIo(pFastIo *InitializeFastIOSection, dwSize uint32) bool
func (a *NdisApi) AddSecondaryFastIo(fastIo *InitializeFastIOSection, size uint32) bool
func (a *NdisApi) ReadPacketsUnsorted(packets []*IntermediateBuffer, ...) bool
func (a *NdisApi) SendPacketsToAdaptersUnsorted(packets []*IntermediateBuffer, ...) bool
func (a *NdisApi) SendPacketsToMstcpUnsorted(packets []*IntermediateBuffer, ...) bool
```

**Purpose:** Optimized fast-path packet processing in kernel mode

**File:** `ndisapi_fastio.go`

---

## Static Filters Interface (NdisApiStaticFilters)

```go
func (a *NdisApi) SetPacketFilterTable(packet *StaticFilterTable) error
func (a *NdisApi) GetPacketFilterTableSize() (uint32, error)
func (a *NdisApi) GetPacketFilterTable(uint32) (*StaticFilterTable, error)
func (a *NdisApi) GetPacketFilterTableResetStats() (*StaticFilterTable, error)
func (a *NdisApi) ResetPacketFilterTable() error
func (a *NdisApi) AddStaticFilterFront(filter *StaticFilter) error
func (a *NdisApi) AddStaticFilterBack(filter *StaticFilter) error
func (a *NdisApi) InsertStaticFilter(filter *StaticFilter, position uint32) error
func (a *NdisApi) RemoveStaticFilter(filterID uint32) error
func (a *NdisApi) SetPacketFilterCacheState(state bool) error
func (a *NdisApi) SetPacketFragmentCacheState(state bool) error
func (a *NdisApi) EnablePacketFilterCache() error
func (a *NdisApi) DisablePacketFilterCache() error
func (a *NdisApi) EnablePacketFragmentCache() error
func (a *NdisApi) DisablePacketFragmentCache() error
```

**Purpose:** Configure static kernel-level packet filtering rules

**File:** `ndisapi_static.go`

---

## Cleanup Strategy

### Proper Cleanup Sequence
```go
// 1. Disable all adapters
for _, adapter := range adapters {
    mode := ndisapi.AdapterMode{
        AdapterHandle: adapter.Handle,
        Flags: 0,
    }
    api.SetAdapterMode(&mode)
}

// 2. Flush queues
for _, adapter := range adapters {
    api.FlushAdapterPacketQueue(adapter.Handle)
}

// 3. Close API handle
api.Close()
```

---

## Utility Methods

```go
func (a *NdisApi) GetVersion() (uint32, error)
func (a *NdisApi) GetIntermediateBufferPoolSize(size uint32) error
func (a *NdisApi) GetBytesReturned() uint32
func (a *NdisApi) IsWindows10OrGreater() bool
func (a *NdisApi) IsNdiswanInterfaces(adapterName, ndiswanName string) bool
func (a *NdisApi) IsNdiswanIP(adapterName string) bool
func (a *NdisApi) IsNdiswanIPv6(adapterName string) bool
func (a *NdisApi) IsNdiswanBh(adapterName string) bool
```

---

## Summary

✓ FlushAdapterPacketQueue method EXISTS and is fully functional
✓ SetAdapterMode/GetAdapterMode for state control
✓ SetPacketEvent for async signaling
✓ ResetPacketFilterTable for filter cleanup
✓ Full adapter enumeration and management support

The ndisapi-go library provides complete adapter queue management capabilities.
