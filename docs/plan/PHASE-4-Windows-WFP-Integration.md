# PHASE 4: WINDOWS WFP INTEGRATION (DUAL ENGINE)

**Status:** 🔜 Future Phase (After Phase 3 Complete)
**Duration:** 3 weeks
**Goal:** Add Windows Filtering Platform for persistent, application-aware filtering
**Deliverable:** Dual-engine firewall (SafeOps + WFP) with defense-in-depth protection

---

## 📋 Phase Overview

**What Changes in Phase 4:**
- **Phase 3 Reality:** Firewall uses SafeOps kernel driver for enforcement (fast, domain-aware)
- **Phase 4 Goal:** Add Windows WFP as second enforcement engine (persistent, application-aware)
- **Integration Point:** Both engines run simultaneously, providing redundant protection

**Dependencies:**
- ✅ Phase 1: gRPC metadata stream working
- ✅ Phase 2: Rule matching engine functional
- ✅ Phase 3: SafeOps verdict enforcement working

---

## 🎯 Phase 4 Outcomes (What You Should See)

### After Compilation & Execution:

**Console Output Example:**
```
[INFO] Firewall Engine v4.0.0 Starting...
[INFO] Connected to SafeOps Engine (127.0.0.1:50053)
[INFO] Loaded 150 firewall rules from firewall.toml
[INFO] Dual Engine Mode: ENABLED
[INFO] ├─ SafeOps Engine: ACTIVE (kernel-level packet filtering)
[INFO] └─ Windows WFP Engine: ACTIVE (persistent OS-level filtering)

[INFO] Translating 150 firewall rules to WFP filters...
[INFO] WFP Filter Session created: {12345678-1234-5678-90AB-CDEF01234567}
[INFO] Installing WFP filters...
[INFO] ├─ Installed 150 WFP filters to FWPM_LAYER_OUTBOUND_IPPACKET_V4
[INFO] ├─ Installed 150 WFP filters to FWPM_LAYER_INBOUND_IPPACKET_V4
[INFO] └─ Installed 75 WFP filters to FWPM_LAYER_ALE_AUTH_CONNECT_V4 (application-aware)
[INFO] WFP filters installed successfully (375 total filters)

[INFO] Dual enforcement active:
[INFO] Packet: 192.168.1.100:54321 -> 157.240.0.35:443 TCP [DENY] Rule: Block_Facebook
[INFO] ├─ SafeOps: TCP RST injected
[INFO] └─ WFP: Filter applied (FWP_ACTION_BLOCK)

[INFO] Application-aware rule triggered:
[INFO] Process: chrome.exe (PID: 12345) -> facebook.com:443 [DENY] Rule: Block_Chrome_Facebook
[INFO] ├─ SafeOps: Domain matched (*.facebook.com)
[INFO] └─ WFP: Application filter applied (chrome.exe blocked)

[INFO] Statistics:
[INFO] ├─ Total Packets: 150,000
[INFO] ├─ SafeOps Blocks: 30,000 (kernel-level)
[INFO] ├─ WFP Blocks: 30,000 (OS-level)
[INFO] ├─ Dual Enforcement: 100% (both engines agree)
[INFO] └─ Performance: 100K pps throughput maintained
```

**Real-World Network Behavior:**
1. **SafeOps + WFP (Both Active):** Maximum security - packets blocked at kernel AND OS level
2. **SafeOps Fails, WFP Active:** Firewall continues working (persistent protection)
3. **WFP Bypassed, SafeOps Active:** Kernel driver still protects (defense-in-depth)
4. **Application-Aware Filtering:** Block chrome.exe from Facebook, but allow firefox.exe

**Performance Metrics Achieved:**
- Throughput: 100,000 packets/sec sustained (no degradation from dual engines)
- WFP filter installation: <2 seconds for 1000 rules
- Application-aware latency: <50μs additional overhead
- Memory usage: <100MB additional for WFP subsystem
- Boot-time protection: WFP filters active before user login

---

## 🏗️ Dual Engine Architecture

### Why Two Engines?

**Defense-in-Depth Security:**
```
┌─────────────────────────────────────────────────────────┐
│                    Network Packet                        │
└─────────────────────┬───────────────────────────────────┘
                      ↓
         ┌────────────────────────────┐
         │  SafeOps NDIS Driver       │  ← Kernel bypass (fast)
         │  (WinpkFilter)             │
         └────────────┬───────────────┘
                      ↓ (If bypassed somehow)
         ┌────────────────────────────┐
         │  Windows TCP/IP Stack      │
         └────────────┬───────────────┘
                      ↓
         ┌────────────────────────────┐
         │  Windows WFP               │  ← OS firewall (persistent)
         │  (fwpuclnt.dll)            │
         └────────────┬───────────────┘
                      ↓
         ┌────────────────────────────┐
         │  Application Layer         │
         │  (chrome.exe, etc.)        │
         └────────────────────────────┘
```

**Redundancy Benefits:**
1. **If SafeOps driver crashes:** WFP continues blocking
2. **If WFP is disabled:** SafeOps kernel driver continues blocking
3. **If attacker bypasses one engine:** Other engine still protects
4. **Boot-time protection:** WFP active before SafeOps loads

**Complementary Strengths:**

```
Feature                  | SafeOps Engine        | Windows WFP
-------------------------+-----------------------+------------------------
Speed                    | Wire-speed (kernel)   | Fast (OS-level)
Domain Awareness         | ✅ Yes (DNS/SNI/HTTP) | ❌ No (IP-only)
Application Awareness    | ❌ No (packet-level)  | ✅ Yes (per-process)
Persistent (Boot-time)   | ❌ No (service start) | ✅ Yes (kernel filters)
Deep Packet Inspection   | ✅ Yes (metadata)     | ❌ No (header-only)
DNS Redirection          | ✅ Yes (injection)    | ❌ No
TCP RST Injection        | ✅ Yes (active)       | ❌ No (passive block)
Bypass Resistance        | Medium (driver-level) | High (OS-integrated)
```

**Coverage Analysis:**
- **SafeOps alone:** Covers 95% of attacks (fast, domain-aware)
- **WFP alone:** Covers 80% of attacks (persistent, app-aware)
- **Both together:** Covers 99.9% of attacks (overlapping + unique strengths)

---

## 📦 Phase 4 Components (5 Sub-Tasks)

### Sub-Task 4.1: WFP C API Bindings (`internal/wfp/bindings/`)

**Purpose:** Create Go bindings to Windows WFP native C APIs

**Core Concept:**
Windows Filtering Platform is a native Windows C API (`fwpuclnt.dll`). Go cannot directly call C APIs. We need CGo (Go-to-C bridge) to create bindings. This is the most complex part of Phase 4 due to language interoperability.

---

#### What to Create:

**1. CGo Header Files**

**Purpose:** Define C function signatures that Go can call

**What is CGo:**
CGo is Go's foreign function interface (FFI) - it allows Go code to call C libraries. CGo works by:
1. Go code writes special comments with C code: `// #include <windows.h>`
2. Go compiler generates C wrapper functions
3. At runtime, Go calls C wrappers, which call actual Windows DLLs

**WFP DLL Dependencies:**
```
Windows System DLLs (must be present on system):
├─ fwpuclnt.dll     # Firewall Platform User-mode Client Library
├─ rpcrt4.dll       # RPC Runtime (for GUID handling)
├─ advapi32.dll     # Advanced Windows API (for security)
└─ kernel32.dll     # Windows Kernel API (for handles)
```

**Key WFP Functions to Bind:**
```
1. Session Management:
   ├─ FwpmEngineOpen0()           # Open connection to WFP engine
   ├─ FwpmEngineClose0()          # Close connection
   └─ FwpmTransactionBegin0()     # Start atomic transaction (batch filters)

2. Filter Management:
   ├─ FwpmFilterAdd0()            # Add single filter
   ├─ FwpmFilterDeleteById0()     # Delete filter by GUID
   ├─ FwpmFilterDeleteByKey0()    # Delete filter by key
   └─ FwpmFilterEnum0()           # Enumerate all filters

3. Layer Management:
   ├─ FwpmLayerGetByKey0()        # Get layer info (inbound, outbound, etc.)
   └─ FwpmLayerEnum0()            # List all available layers

4. Callout Management (Advanced):
   ├─ FwpmCalloutAdd0()           # Register custom callout (for DPI)
   └─ FwpmCalloutDeleteById0()    # Remove callout

5. Provider Management:
   ├─ FwpmProviderAdd0()          # Register firewall provider (SafeOps)
   └─ FwpmProviderDeleteByKey0()  # Unregister provider
```

**CGo Data Type Mapping:**
```
Windows C Type          | Go Type               | Notes
------------------------+-----------------------+----------------------------------
HANDLE                  | syscall.Handle        | Windows handle (pointer)
DWORD                   | uint32                | 32-bit unsigned integer
UINT64                  | uint64                | 64-bit unsigned integer
GUID                    | [16]byte              | 128-bit unique identifier
LPWSTR (wchar_t*)       | *uint16               | Wide-character string (UTF-16)
SOCKADDR                | [128]byte             # IP address structure
FWP_BYTE_BLOB           | []byte                | Binary data blob
FWP_ACTION_TYPE (enum)  | uint32                | Action: BLOCK, PERMIT, CALLOUT
```

**Example CGo Binding (Conceptual Structure):**
```
File: internal/wfp/bindings/fwpm.go

Package structure:
├─ Import "C" (CGo magic import)
├─ C header includes (windows.h, fwpmu.h)
├─ Go struct definitions (mirroring C structs)
├─ Go wrapper functions (calling C functions)
└─ Helper functions (GUID conversion, string conversion)

Key challenges:
1. GUID handling: Windows uses 128-bit GUIDs, Go has no native GUID type
2. Unicode strings: Windows uses UTF-16 (wchar_t*), Go uses UTF-8
3. Struct alignment: C struct padding must match Windows ABI
4. Error handling: Windows returns HRESULT codes, must convert to Go errors
5. Memory management: C allocates memory, Go must free it (or leak)
```

**GUID Handling (Critical):**
Every WFP object (filter, layer, provider) has a unique GUID identifier:
- Filters: `{12345678-1234-5678-90AB-CDEF01234567}`
- Layers: `FWPM_LAYER_OUTBOUND_IPPACKET_V4` = `{1E5C9FAE-8A84-4135-A331-950B54229EC1}`

Go must:
1. Generate GUIDs for new filters (use Windows `CoCreateGuid()`)
2. Convert Go `[16]byte` ↔ Windows `GUID` struct
3. Store GUIDs for later deletion (rule hot-reload)

---

**2. WFP Data Structures**

**Purpose:** Define Go structs that match Windows WFP C structs

**Critical Structs to Define:**

**A. FWPM_SESSION0 (WFP Session)**
```
Represents connection to Windows Firewall engine

Fields:
├─ sessionKey (GUID):         Unique session identifier
├─ displayData (name, desc):  Human-readable session info
├─ flags:                     Session options (dynamic, read-only)
├─ txnWaitTimeoutInMSec:      Transaction timeout (5000ms default)
└─ processId:                 Owning process ID (firewall_engine.exe)

Usage:
- One session per firewall engine process
- All filters belong to this session
- When process exits: Windows auto-deletes all filters (cleanup)
- Exception: Persistent filters survive reboot (special flag)
```

**B. FWPM_FILTER0 (Firewall Filter)**
```
Represents single firewall rule in WFP

Fields:
├─ filterKey (GUID):          Unique filter ID (for deletion)
├─ displayData (name, desc):  Rule name/description
├─ layerKey (GUID):           Which layer (INBOUND/OUTBOUND/ALE)
├─ action:                    FWP_ACTION_BLOCK (deny) or FWP_ACTION_PERMIT (allow)
├─ weight:                    Filter priority (0-15, higher = evaluated first)
├─ numFilterConditions:       Number of match conditions (1-20)
├─ filterCondition[]:         Array of match conditions (IP, port, protocol, app)
├─ providerKey (GUID):        Provider ID (SafeOps firewall)
└─ flags:                     Filter options (persistent, boottime, etc.)

Example filter:
{
  filterKey: {12345678-1234-5678-90AB-CDEF01234567}
  displayData: "Block Facebook (SafeOps)"
  layerKey: FWPM_LAYER_OUTBOUND_IPPACKET_V4
  action: FWP_ACTION_BLOCK
  weight: 10
  conditions: [
    {IP_REMOTE_ADDRESS = 157.240.0.35/32},
    {IP_PROTOCOL = TCP},
    {IP_REMOTE_PORT = 443}
  ]
}
```

**C. FWPM_FILTER_CONDITION0 (Match Condition)**
```
Represents single match criterion (IP, port, protocol, app)

Fields:
├─ fieldKey (GUID):           Condition type (IP_REMOTE_ADDRESS, IP_PROTOCOL, etc.)
├─ matchType:                 How to match (EQUAL, GREATER, LESS, RANGE, PREFIX)
└─ conditionValue:            Value to match (IP, port, protocol number, app path)

Common field types:
1. FWPM_CONDITION_IP_REMOTE_ADDRESS:
   ├─ matchType: FWP_MATCH_EQUAL or FWP_MATCH_PREFIX (CIDR)
   └─ value: FWP_V4_ADDR_AND_MASK {157.240.0.35, 255.255.255.255}

2. FWPM_CONDITION_IP_REMOTE_PORT:
   ├─ matchType: FWP_MATCH_EQUAL or FWP_MATCH_RANGE
   └─ value: FWP_UINT16 {443}

3. FWPM_CONDITION_IP_PROTOCOL:
   ├─ matchType: FWP_MATCH_EQUAL
   └─ value: FWP_UINT8 {6 for TCP, 17 for UDP}

4. FWPM_CONDITION_ALE_APP_ID (Application):
   ├─ matchType: FWP_MATCH_EQUAL
   └─ value: FWP_BYTE_BLOB {C:\Program Files\Google\Chrome\Application\chrome.exe}
```

**D. FWP_VALUE0 (Condition Value Union)**
```
Union type - can hold different data types

Variants:
├─ type = FWP_UINT8:          uint8 (protocol number)
├─ type = FWP_UINT16:         uint16 (port number)
├─ type = FWP_UINT32:         uint32 (flags)
├─ type = FWP_UINT64:         uint64 (large numbers)
├─ type = FWP_BYTE_ARRAY16:   [16]byte (IPv6 address)
├─ type = FWP_BYTE_BLOB:      []byte (app path, binary data)
└─ type = FWP_V4_ADDR_MASK:   {IP, Netmask} (IPv4 CIDR)

CGo challenge: C unions don't exist in Go
Solution: Use unsafe.Pointer + type casting
```

**Struct Alignment Challenge:**
Windows expects specific byte alignment (padding between fields). Go must match exactly:
- Windows x64 ABI: 8-byte alignment for pointers
- Struct padding: Compiler inserts padding bytes for alignment
- CGo pragma: `//go:cgo_ldflag "-Wl,--enable-stdcall-fixup"`

---

**3. Error Handling**

**Purpose:** Convert Windows HRESULT error codes to Go errors

**Windows Error Codes (HRESULT):**
```
0x00000000 (S_OK):                     Success
0x80070005 (E_ACCESSDENIED):           Access denied (need admin rights)
0x80320001 (FWP_E_ALREADY_EXISTS):     Filter already exists
0x80320002 (FWP_E_IN_USE):             Filter in use, can't delete
0x80320003 (FWP_E_DYNAMIC_SESSION_IN_PROGRESS): Session active
0x80320004 (FWP_E_WRONG_SESSION):      Invalid session handle
0x80320009 (FWP_E_NOT_FOUND):          Filter not found
0x8032000A (FWP_E_FILTER_NOT_FOUND):   Specific filter not found
```

**Error Handling Flow:**
```
1. Call Windows API via CGo:
   result := C.FwpmFilterAdd0(session, filter, nil, nil)

2. Check HRESULT:
   if result != 0 {
       // Error occurred
   }

3. Convert HRESULT to Go error:
   func hresultToError(hr uint32) error {
       switch hr {
       case 0x80070005:
           return errors.New("access denied - run as administrator")
       case 0x80320001:
           return errors.New("filter already exists")
       case 0x80320009:
           return errors.New("filter not found")
       default:
           return fmt.Errorf("WFP error: 0x%08X", hr)
       }
   }

4. Return to caller:
   return fmt.Errorf("failed to add WFP filter: %w", err)
```

**Admin Privilege Check:**
WFP requires administrator privileges. Must check before calling:
```
Check process token:
1. Call Windows API: OpenProcessToken()
2. Call Windows API: GetTokenInformation(TokenElevation)
3. If not elevated:
   - Log error: "WFP requires administrator privileges"
   - Disable WFP engine
   - Fall back to SafeOps-only mode
   - Return error to user
```

---

**4. Memory Management**

**Purpose:** Prevent memory leaks when crossing Go-C boundary

**Memory Ownership Rules:**
```
1. Go allocates, Go frees:
   ├─ Go creates filter struct
   ├─ Go passes to C via CGo
   └─ Go frees after C returns (automatic)

2. C allocates, Go must free:
   ├─ Windows allocates GUID via CoCreateGuid()
   ├─ Go receives pointer
   ├─ Go MUST call C.CoTaskMemFree() when done
   └─ Failure = memory leak (process grows indefinitely)

3. Shared allocation:
   ├─ Go allocates, C holds reference
   ├─ Go must keep alive until C done
   └─ Use runtime.KeepAlive() to prevent GC
```

**String Conversion (UTF-8 ↔ UTF-16):**
```
Windows uses UTF-16 (wchar_t*), Go uses UTF-8 (string)

Go to Windows:
1. Go string: "Block Facebook"
2. Convert to UTF-16: []uint16{0x0042, 0x006C, ...}
3. Pass pointer to Windows: (*uint16)(unsafe.Pointer(&wstr[0]))
4. Windows reads UTF-16 string
5. Go frees []uint16 after call returns

Windows to Go:
1. Windows returns UTF-16 string: *uint16
2. Calculate length: count until null terminator (0x0000)
3. Convert to Go string: syscall.UTF16ToString()
4. Go now owns string (garbage collected)
```

**GUID Allocation:**
```
Generate new GUID for filter:
1. Allocate GUID: var guid C.GUID
2. Call Windows: C.CoCreateGuid(&guid)
3. Convert to Go [16]byte: copy(goGuid[:], C.GoBytes(unsafe.Pointer(&guid), 16))
4. Store in database for later deletion
5. No explicit free needed (stack allocation)
```

---

**5. Testing Strategy**

**Purpose:** Verify CGo bindings work correctly on Windows

**Unit Tests:**
```
Test 1: Open/Close WFP Session
├─ Call FwpmEngineOpen0()
├─ Verify session handle != nil
├─ Call FwpmEngineClose0()
└─ Verify no memory leaks

Test 2: Add/Delete Filter
├─ Create test filter (allow 8.8.8.8:53)
├─ Call FwpmFilterAdd0()
├─ Verify filter exists (enumerate filters)
├─ Call FwpmFilterDeleteByKey0()
└─ Verify filter removed

Test 3: GUID Conversion
├─ Generate Windows GUID
├─ Convert to Go [16]byte
├─ Convert back to Windows GUID
└─ Verify round-trip equality

Test 4: String Conversion
├─ Convert Go string to UTF-16
├─ Pass to Windows
├─ Read back from Windows
└─ Verify string matches original

Test 5: Error Handling
├─ Call API without admin rights
├─ Verify E_ACCESSDENIED returned
├─ Verify error message correct
└─ Verify no crash
```

**Integration Tests:**
```
Test 1: Dual Engine Blocking
├─ Add SafeOps rule: Block 1.1.1.1
├─ Add WFP filter: Block 1.1.1.1
├─ Send packet to 1.1.1.1
├─ Verify SafeOps blocks
├─ Verify WFP blocks
└─ Verify both log the block

Test 2: Application-Aware Filtering
├─ Add WFP filter: Block chrome.exe -> facebook.com
├─ Launch chrome.exe
├─ Navigate to facebook.com
├─ Verify WFP blocks (app match)
├─ Launch firefox.exe
├─ Navigate to facebook.com
└─ Verify WFP allows (different app)

Test 3: Persistent Filters
├─ Add WFP filter with PERSISTENT flag
├─ Stop firewall service
├─ Verify filter still exists (enumerate)
├─ Reboot system
├─ Verify filter still exists
└─ Delete filter
```

---

#### Files to Create:
```
internal/wfp/bindings/
├── fwpm.go              # Core WFP API bindings (session, filter management)
├── fwpm_types.go        # WFP data structures (FWPM_FILTER0, FWPM_SESSION0)
├── fwp_types.go         # FWP value types (FWP_VALUE0, FWP_CONDITION_VALUE0)
├── guid.go              # GUID generation and conversion utilities
├── errors.go            # HRESULT to Go error conversion
├── strings.go           # UTF-8 ↔ UTF-16 string conversion
├── memory.go            # Memory management helpers (alloc/free)
└── constants.go         # WFP constants (layer GUIDs, action types)
```

---

### Sub-Task 4.2: Go-C Bridge Wrapper (`internal/wfp/`)

**Purpose:** Create high-level Go API that hides CGo complexity

**Core Concept:**
CGo bindings are low-level and unsafe (raw pointers, manual memory management). Create a safe, idiomatic Go wrapper that developers can use without touching CGo or C code.

---

#### What to Create:

**1. WFP Engine Manager**

**Purpose:** Manage WFP session lifecycle (open, close, health check)

**Session Lifecycle:**
```
Firewall Startup:
1. Check admin privileges (WFP requires elevation)
2. Open WFP session: FwpmEngineOpen0()
3. Receive session handle (used for all operations)
4. Register SafeOps as WFP provider (branding)
5. Store session handle in manager struct

Firewall Running:
1. Manager holds session handle
2. All filter operations use this session
3. Health check every 30s: verify session still valid
4. If session lost: reconnect automatically

Firewall Shutdown:
1. Delete all filters (cleanup)
2. Unregister provider
3. Close session: FwpmEngineClose0()
4. Session handle invalidated
```

**Session Options:**
```
Session Flags:
├─ FWPM_SESSION_FLAG_DYNAMIC:
│  └─ All filters auto-deleted when session closes (default)
│
├─ FWPM_SESSION_FLAG_RESERVED:
│  └─ Persistent filters survive reboot (boot-time protection)
│
└─ Transaction timeout: 5000ms (batch operations)
```

**Admin Privilege Handling:**
```
If NOT running as admin:
├─ Log warning: "WFP requires administrator privileges"
├─ Disable WFP engine (WFP = nil)
├─ Continue with SafeOps-only mode
└─ Return error (non-fatal)

If running as admin:
├─ Open WFP session successfully
├─ Enable dual-engine mode
└─ Log: "WFP engine active"
```

**Health Monitoring:**
```
Every 30 seconds:
1. Test session validity:
   ├─ Call FwpmFilterEnum0(session, ...)
   └─ If error: Session invalid

2. If session lost:
   ├─ Log error: "WFP session lost, reconnecting..."
   ├─ Close old session
   ├─ Open new session
   ├─ Reinstall all filters
   └─ Log: "WFP session restored"

3. If reconnect fails 3x:
   ├─ Log error: "WFP unavailable, switching to SafeOps-only"
   ├─ Disable WFP engine
   └─ Continue with SafeOps (graceful degradation)
```

---

**2. Filter Manager**

**Purpose:** Add, update, delete WFP filters

**Filter CRUD Operations:**

**A. Add Filter:**
```
Input: FirewallRule (from Phase 2 rule engine)
Process:
1. Generate unique GUID for filter
2. Translate rule to WFP filter:
   ├─ Rule action → WFP action (ALLOW/DENY → PERMIT/BLOCK)
   ├─ Rule priority → WFP weight (1-15)
   ├─ Rule conditions → WFP filter conditions
   └─ Add metadata (rule name, description)

3. Select WFP layer:
   ├─ If direction = OUTBOUND → FWPM_LAYER_OUTBOUND_IPPACKET_V4
   ├─ If direction = INBOUND → FWPM_LAYER_INBOUND_IPPACKET_V4
   └─ If app-aware → FWPM_LAYER_ALE_AUTH_CONNECT_V4

4. Build WFP filter struct:
   ├─ filterKey = generated GUID
   ├─ layerKey = selected layer GUID
   ├─ action = BLOCK or PERMIT
   ├─ weight = rule priority
   ├─ conditions = array of match conditions
   └─ providerKey = SafeOps provider GUID

5. Call Windows API:
   ├─ FwpmFilterAdd0(session, &filter, nil, &filterId)
   └─ If error: Return error to caller

6. Store filter mapping:
   ├─ ruleID → filterGUID (for deletion during hot-reload)
   └─ Store in memory map: map[uuid.UUID]GUID
```

**B. Delete Filter:**
```
Input: Rule UUID (from hot-reload)
Process:
1. Lookup filter GUID by rule UUID:
   ├─ filterGUID = filterMap[ruleUUID]
   └─ If not found: Return error (filter never added)

2. Call Windows API:
   ├─ FwpmFilterDeleteByKey0(session, &filterGUID)
   └─ If error: Log warning (filter may already be deleted)

3. Remove from mapping:
   ├─ delete(filterMap, ruleUUID)
   └─ Free memory
```

**C. Update Filter (Hot-Reload):**
```
Input: Updated FirewallRule
Process:
1. Delete old filter (if exists)
2. Add new filter
3. Update mapping

Note: WFP doesn't support in-place updates, must delete+add
```

**D. Enumerate Filters:**
```
Purpose: List all active WFP filters (debugging)
Process:
1. Create filter enumeration template:
   ├─ providerKey = SafeOps GUID (only list our filters)
   └─ layerKey = all layers

2. Call Windows API:
   ├─ FwpmFilterCreateEnumHandle0(session, template, &enumHandle)
   ├─ FwpmFilterEnum0(enumHandle, maxEntries, &filters, &numReturned)
   └─ FwpmFilterDestroyEnumHandle0(enumHandle)

3. Parse results:
   ├─ For each filter: Print {GUID, name, action, layer, conditions}
   └─ Return array of filter summaries
```

---

**3. Rule-to-Filter Translator**

**Purpose:** Convert firewall rules (Phase 2) to WFP filters

**Translation Logic:**

**A. Action Translation:**
```
Firewall Rule Action  | WFP Action              | Notes
----------------------+-------------------------+---------------------------
ALLOW                 | FWP_ACTION_PERMIT       | Allow packet through
DENY                  | FWP_ACTION_BLOCK        | Block packet (silent)
DROP                  | FWP_ACTION_BLOCK        | Same as DENY in WFP
REDIRECT              | FWP_ACTION_PERMIT       | WFP can't redirect DNS (SafeOps handles)
REJECT                | FWP_ACTION_BLOCK        | WFP can't send ICMP (just blocks)
```

**WFP Limitations:**
- No TCP RST injection (WFP passively blocks)
- No DNS redirection (WFP doesn't see DNS payload)
- No ICMP unreachable (WFP doesn't craft packets)

**Result:** SafeOps handles active enforcement, WFP provides passive blocking

**B. Condition Translation:**

**Source IP:**
```
Firewall Rule:
├─ src_address = "192.168.1.100"

WFP Filter Condition:
├─ fieldKey = FWPM_CONDITION_IP_LOCAL_ADDRESS
├─ matchType = FWP_MATCH_EQUAL
└─ value = {type: FWP_UINT32, uint32: 0xC0A80164} // 192.168.1.100 in hex
```

**Source IP (CIDR):**
```
Firewall Rule:
├─ src_address = "192.168.0.0/16"

WFP Filter Condition:
├─ fieldKey = FWPM_CONDITION_IP_LOCAL_ADDRESS
├─ matchType = FWP_MATCH_PREFIX
└─ value = {type: FWP_V4_ADDR_MASK, addr: 0xC0A80000, mask: 0xFFFF0000}
```

**Destination IP:**
```
Firewall Rule:
├─ dst_address = "8.8.8.8"

WFP Filter Condition:
├─ fieldKey = FWPM_CONDITION_IP_REMOTE_ADDRESS
├─ matchType = FWP_MATCH_EQUAL
└─ value = {type: FWP_UINT32, uint32: 0x08080808}
```

**Destination Port:**
```
Firewall Rule:
├─ dst_port = 443

WFP Filter Condition:
├─ fieldKey = FWPM_CONDITION_IP_REMOTE_PORT
├─ matchType = FWP_MATCH_EQUAL
└─ value = {type: FWP_UINT16, uint16: 443}
```

**Port Range:**
```
Firewall Rule:
├─ dst_port = "1000-2000"

WFP Filter Condition:
├─ fieldKey = FWPM_CONDITION_IP_REMOTE_PORT
├─ matchType = FWP_MATCH_RANGE
└─ value = {type: FWP_RANGE, valueLow: 1000, valueHigh: 2000}
```

**Protocol:**
```
Firewall Rule:
├─ protocol = TCP

WFP Filter Condition:
├─ fieldKey = FWPM_CONDITION_IP_PROTOCOL
├─ matchType = FWP_MATCH_EQUAL
└─ value = {type: FWP_UINT8, uint8: 6} // TCP = 6, UDP = 17, ICMP = 1
```

**Application (Process):**
```
Firewall Rule:
├─ application = "chrome.exe"

WFP Filter Condition:
├─ fieldKey = FWPM_CONDITION_ALE_APP_ID
├─ matchType = FWP_MATCH_EQUAL
└─ value = {type: FWP_BYTE_BLOB, data: "C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe"}

Note: Must use full path (resolve from process name)
```

**Direction:**
```
Firewall Rule:
├─ direction = OUTBOUND

WFP Layer Selection:
├─ Use FWPM_LAYER_OUTBOUND_IPPACKET_V4 (not a condition, selects layer)

Firewall Rule:
├─ direction = INBOUND

WFP Layer Selection:
├─ Use FWPM_LAYER_INBOUND_IPPACKET_V4
```

**Domain Matching (Limitation):**
```
Firewall Rule:
├─ dst_domain = "*.facebook.com"

WFP Cannot Match:
├─ WFP operates at IP layer (no domain awareness)
├─ Solution: SafeOps handles domain matching
├─ SafeOps resolves domain → IP
├─ Create WFP filter for resolved IPs (dynamic)

Workflow:
1. SafeOps sees DNS query for facebook.com → 157.240.0.35
2. SafeOps notifies firewall: "facebook.com = 157.240.0.35"
3. Firewall adds temporary WFP filter: Block 157.240.0.35
4. TTL = DNS TTL (300s typical)
5. After TTL: Remove temporary filter
```

**C. Priority Translation:**
```
Firewall Rule Priority  | WFP Weight   | Notes
------------------------+--------------+--------------------------------
1-10 (highest priority) | 15 (max)     | Critical system rules
11-100                  | 10           | High priority rules
101-1000                | 5            | Normal priority rules
1001+ (low priority)    | 1            | Default/catch-all rules

WFP evaluates filters by weight (highest first)
If multiple filters match, highest weight wins
```

---

**4. Batch Operations**

**Purpose:** Add/delete multiple filters efficiently

**Why Batch:**
Adding filters one-by-one is slow:
- 1000 rules × 5ms per filter = 5 seconds total

Batching groups operations:
- 1000 rules in 10 batches of 100 = 500ms total (10x faster)

**WFP Transaction API:**
```
Start transaction:
1. FwpmTransactionBegin0(session)
2. Add 100 filters in memory (no commit yet)
3. FwpmTransactionCommit0(session)
4. All 100 filters committed atomically
5. If error: FwpmTransactionAbort0() (rollback all)

Benefits:
├─ Atomic: All filters added or none
├─ Fast: Reduces API call overhead
└─ Consistent: No partial state visible
```

**Batch Size Tuning:**
```
Batch Size | Time to add 1000 filters | Memory Usage | Error Granularity
-----------+--------------------------+--------------+------------------
1          | 5000ms (1 per call)      | Low (1 filter) | High (know exact failure)
10         | 1000ms                   | Low          | Medium
100        | 500ms ✓ OPTIMAL          | Medium       | Low (100 filters fail together)
1000       | 400ms                    | High (1000)  | Very Low (all or nothing)
```

**Recommendation:** Batch size = 100 filters (balance speed vs granularity)

**Error Handling:**
```
If transaction fails:
1. FwpmTransactionAbort0() (undo all changes in batch)
2. Retry each filter individually (find which one failed)
3. Log failed filter for debugging
4. Continue with next batch
```

---

**5. Provider Registration**

**Purpose:** Register SafeOps as official WFP provider (branding/identification)

**What is a Provider:**
WFP allows third-party firewalls to register as providers:
- Provider name: "SafeOps Firewall Engine"
- Provider GUID: `{SAFEOPS-1234-5678-90AB-CDEF01234567}` (fixed, not random)
- Provider description: "Enterprise Network Security Platform"

**Why Register:**
1. **Identification:** Windows knows filters belong to SafeOps (not another firewall)
2. **Management:** Group all SafeOps filters together (easy enumeration)
3. **Cleanup:** If SafeOps crashes, Windows can identify orphaned filters
4. **UI Integration:** Windows Firewall UI shows "SafeOps" as provider

**Registration Process:**
```
On firewall startup:
1. Create provider struct:
   ├─ providerKey = SafeOps GUID (hardcoded)
   ├─ displayData = "SafeOps Firewall Engine"
   ├─ serviceName = "firewall_engine.exe"
   └─ flags = 0 (default)

2. Call Windows API:
   ├─ FwpmProviderAdd0(session, &provider, nil)
   └─ If already exists (E_ALREADY_EXISTS): OK, ignore error

3. All future filters reference this provider GUID

On firewall shutdown:
1. Delete all filters first (cleanup)
2. Unregister provider:
   ├─ FwpmProviderDeleteByKey0(session, &providerGUID)
   └─ Windows removes provider from registry
```

---

#### Files to Create:
```
internal/wfp/
├── engine.go            # WFP engine manager (session lifecycle)
├── filter.go            # Filter CRUD operations (add, delete, enumerate)
├── translator.go        # Rule-to-filter translation logic
├── batch.go             # Batch operations (transactions)
├── provider.go          # Provider registration/unregistration
├── layers.go            # WFP layer management (inbound, outbound, ALE)
└── app_resolver.go      # Resolve process name → full path (chrome.exe → C:\...\chrome.exe)
```

---

### Sub-Task 4.3: Application-Aware Filtering (`internal/wfp/application/`)

**Purpose:** Block specific applications from accessing network (per-process rules)

**Core Concept:**
WFP's killer feature: filter by application (process name). Example:
- Block chrome.exe from accessing facebook.com
- Allow firefox.exe to access facebook.com
- Block steam.exe from updating during work hours

---

#### What to Create:

**1. Process Path Resolver**

**Purpose:** Convert process name (chrome.exe) to full path (C:\Program Files\...\chrome.exe)

**Why Full Path Required:**
WFP's `ALE_APP_ID` condition requires full executable path:
- ❌ Wrong: "chrome.exe"
- ✅ Correct: "C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe"

**Resolution Strategy:**

**A. Running Process Lookup:**
```
1. Enumerate all running processes (Windows API: CreateToolhelp32Snapshot)
2. For each process:
   ├─ Get process name (chrome.exe)
   ├─ Get full path (QueryFullProcessImageName)
   └─ Store in map: {"chrome.exe" → "C:\\...\\chrome.exe"}

3. When rule references "chrome.exe":
   ├─ Lookup in map
   └─ Return full path

Limitation: Only finds running processes
```

**B. Registry Lookup:**
```
Common Windows registry paths for installed applications:
├─ HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\App Paths
├─ HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\App Paths
└─ HKEY_CLASSES_ROOT\Applications

Example:
HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\App Paths\chrome.exe
├─ (Default) = "C:\Program Files\Google\Chrome\Application\chrome.exe"
└─ Path = "C:\Program Files\Google\Chrome\Application"
```

**C. Environment Path Search:**
```
Search %PATH% environment variable:
1. Get PATH: "C:\Windows;C:\Windows\System32;C:\Program Files\..."
2. Split by ';' separator
3. For each directory:
   ├─ Check if "chrome.exe" exists
   └─ Return full path if found

Example:
├─ Search C:\Windows → not found
├─ Search C:\Windows\System32 → not found
├─ Search C:\Program Files\Google\Chrome\Application → found!
└─ Return "C:\Program Files\Google\Chrome\Application\chrome.exe"
```

**D. Fallback Strategy:**
```
If all lookups fail:
1. Log warning: "Could not resolve full path for chrome.exe"
2. Use partial match (risky):
   ├─ WFP condition: Match any path ending with "chrome.exe"
   ├─ Risk: Matches malware disguised as chrome.exe in other directories
3. Or skip application-aware filter:
   ├─ Fall back to IP-based filtering only
   └─ Log: "Application-aware filtering disabled for chrome.exe"
```

---

**2. ALE Layer Integration**

**Purpose:** Use WFP's Application Layer Enforcement (ALE) for app-aware filtering

**What is ALE:**
```
WFP has multiple layers (where filters are applied):
├─ IP Packet Layer (FWPM_LAYER_IPPACKET_V4):
│  ├─ Sees raw packets (IP header only)
│  ├─ No application info (can't tell which process sent packet)
│  └─ Used for IP/port filtering

└─ ALE Layer (FWPM_LAYER_ALE_AUTH_CONNECT_V4):
   ├─ Sees connection attempts (socket level)
   ├─ HAS application info (process ID, executable path)
   └─ Used for application-aware filtering

Key difference:
- IP layer: Packet arrives → filter checks IP/port → allow/block
- ALE layer: App calls connect() → filter checks app path → allow/block
```

**ALE Layers:**
```
1. FWPM_LAYER_ALE_AUTH_CONNECT_V4 (Outbound Connections):
   ├─ Triggered: Application calls connect() (TCP) or sendto() (UDP)
   ├─ Available data: Process ID, app path, local IP/port, remote IP/port
   └─ Use case: Block chrome.exe from connecting to facebook.com

2. FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V4 (Inbound Connections):
   ├─ Triggered: Application calls accept() (server socket)
   ├─ Available data: Process ID, app path, local IP/port, remote IP/port
   └─ Use case: Allow nginx.exe to accept connections on port 80

3. FWPM_LAYER_ALE_AUTH_LISTEN_V4 (Listen):
   ├─ Triggered: Application calls listen() (bind to port)
   ├─ Available data: Process ID, app path, local port
   └─ Use case: Prevent malware from opening backdoor on port 4444
```

**When to Use ALE:**
```
Rule has "application" field → Use ALE layer
Rule has no "application" field → Use IP packet layer
```

---

**3. Application Filter Builder**

**Purpose:** Create WFP filters for application-aware rules

**Example Rule:**
```
[[rule]]
name = "Block_Chrome_Facebook"
action = "DENY"
protocol = "TCP"
application = "chrome.exe"
dst_domain = "*.facebook.com"
dst_port = 443
priority = 100
```

**Translation to WFP Filter:**
```
1. Resolve application path:
   chrome.exe → C:\Program Files\Google\Chrome\Application\chrome.exe

2. Resolve domain to IPs (SafeOps handles):
   *.facebook.com → [157.240.0.35, 157.240.0.36, ...]

3. Create WFP filter:
   {
     filterKey: {GUID}
     layerKey: FWPM_LAYER_ALE_AUTH_CONNECT_V4 ← ALE layer (app-aware)
     action: FWP_ACTION_BLOCK
     weight: 10
     conditions: [
       {
         field: FWPM_CONDITION_ALE_APP_ID
         matchType: FWP_MATCH_EQUAL
         value: "C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe"
       },
       {
         field: FWPM_CONDITION_IP_REMOTE_ADDRESS
         matchType: FWP_MATCH_EQUAL
         value: 157.240.0.35
       },
       {
         field: FWPM_CONDITION_IP_REMOTE_PORT
         matchType: FWP_MATCH_EQUAL
         value: 443
       },
       {
         field: FWPM_CONDITION_IP_PROTOCOL
         matchType: FWP_MATCH_EQUAL
         value: 6 (TCP)
       }
     ]
   }

4. Install filter to WFP

Result:
- chrome.exe → facebook.com:443: BLOCKED
- firefox.exe → facebook.com:443: ALLOWED (different app)
- chrome.exe → google.com:443: ALLOWED (different destination)
```

---

**4. Process Monitoring (Real-Time)**

**Purpose:** Detect new processes starting and update WFP filters

**Why Monitor:**
- User installs new application (discord.exe)
- Firewall rule: "Block discord.exe from internet"
- Problem: Full path unknown until discord.exe runs first time
- Solution: Monitor process starts, resolve path, update WFP filter

**Implementation:**

**A. ETW (Event Tracing for Windows):**
```
Subscribe to Windows process events:
1. Register ETW session for process events
2. Windows notifies on:
   ├─ Process start (PID, executable path)
   ├─ Process exit (PID)
   └─ Process rename (rare)

3. On process start:
   ├─ Extract: processName, fullPath
   ├─ Store in cache: {"discord.exe" → "C:\\...\\discord.exe"}
   └─ Check if any firewall rules reference this process

4. If match found:
   ├─ Create WFP filter with resolved path
   ├─ Install filter
   └─ Log: "Application-aware filter added for discord.exe"
```

**B. Polling (Fallback):**
```
If ETW unavailable (older Windows):
1. Every 30 seconds:
   ├─ Enumerate all running processes
   ├─ Compare with previous snapshot
   └─ Detect new processes

2. For each new process:
   ├─ Resolve full path
   ├─ Update cache
   └─ Check firewall rules
```

**Performance:**
- ETW: <1ms latency per event (efficient)
- Polling: 30s delay before detection (acceptable)

---

**5. Application Whitelisting**

**Purpose:** Allow only specific applications to access network (deny all others)

**Use Case:**
Enterprise environment - only allow approved applications:
- ✅ Allow: chrome.exe, firefox.exe, outlook.exe
- ❌ Block: Everything else

**Implementation:**
```
Default Policy: DENY all applications
Whitelist Rules:
1. Allow chrome.exe
2. Allow firefox.exe
3. Allow outlook.exe

WFP Filter Order:
1. Whitelist filters (weight 15, highest):
   ├─ If app = chrome.exe → PERMIT
   ├─ If app = firefox.exe → PERMIT
   └─ If app = outlook.exe → PERMIT

2. Default deny filter (weight 1, lowest):
   └─ If app = * (any) → BLOCK

Result:
- chrome.exe → PERMIT (whitelist match, weight 15)
- malware.exe → BLOCK (default deny, weight 1)
```

**Considerations:**
- Must whitelist system processes (svchost.exe, services.exe) or Windows breaks
- Must whitelist updaters (Windows Update, etc.) or system can't patch
- Requires extensive testing (easy to lock out critical apps)

---

#### Files to Create:
```
internal/wfp/application/
├── resolver.go          # Process name → full path resolution
├── ale.go               # ALE layer filter creation
├── app_filter.go        # Application-aware filter builder
├── process_monitor.go   # Real-time process monitoring (ETW)
└── whitelist.go         # Application whitelist management
```

---

### Sub-Task 4.4: Boot-Time Persistent Filters (`internal/wfp/boottime/`)

**Purpose:** Install WFP filters that survive reboot and protect system before user login

**Core Concept:**
Normal WFP filters are dynamic - deleted when firewall service stops. Persistent filters remain active even after:
- Firewall service crashes
- System reboot
- Windows Safe Mode boot

---

#### What to Create:

**1. Persistent Filter Manager**

**Purpose:** Install filters that survive reboot

**How Persistent Filters Work:**
```
Normal Filter:
├─ Session flag: FWPM_SESSION_FLAG_DYNAMIC
├─ Lifetime: Service running → Service stops → Filter deleted
└─ Use case: Normal operation

Persistent Filter:
├─ Session flag: 0 (no DYNAMIC flag) + PERSISTENT flag on filter
├─ Lifetime: Installed → Survives reboot → Manually deleted
├─ Storage: Windows registry (HKLM\SYSTEM\CurrentControlSet\Services\BFE\Filters)
└─ Use case: Boot-time protection, critical security rules
```

**When Filter Activates:**
```
Boot Timeline:
├─ 0s: BIOS/UEFI
├─ 2s: Windows kernel loads
├─ 5s: WFP subsystem starts ← Persistent filters ACTIVE here
├─ 10s: Network drivers load
├─ 15s: Services start (firewall_engine.exe starts)
├─ 20s: User login
└─ 30s: Desktop loaded

Persistent filter protection: 5s - ∞ (until deleted)
Dynamic filter protection: 15s - service stop
```

**Gap Analysis:**
```
Without persistent filters:
├─ 5s - 15s: Network active, NO firewall protection
├─ Risk: Malware can connect during boot
└─ Attack: Rootkit communicates with C2 before firewall loads

With persistent filters:
├─ 5s - ∞: Firewall protection active
├─ Even if firewall service fails to start: Filters still protect
└─ Defense: Boot-time malware blocked
```

---

**2. Critical Rule Selection**

**Purpose:** Determine which rules should be persistent (can't make ALL rules persistent)

**Why Limit Persistent Filters:**
- Persistent filters stored in registry (limited space)
- Too many persistent filters slow down boot (must parse registry)
- Persistent filters can't be hot-reloaded (must reboot to change)

**Recommendation:** Max 50 persistent filters (critical rules only)

**Critical Rule Criteria:**
```
Rule should be persistent if:
1. Blocks known malware IPs/domains (malware C2 servers)
2. Blocks dangerous ports (RDP 3389 from internet, SMB 445)
3. Blocks untrusted processes (unknown executables)
4. Protects critical system services (DNS, DHCP)
5. Default deny policy (block all except whitelist)

Rule should NOT be persistent if:
1. User-specific (block social media during work hours)
2. Temporary (block during maintenance window)
3. Frequently changed (hot-reload often)
4. Low priority (convenience rules, not security)
```

**Example Persistent Rules:**
```
1. Block_Malware_C2_Servers:
   ├─ Persistent: YES (critical security)
   ├─ Reason: Block malware communication at boot
   └─ Fallback: Even if firewall crashes, malware can't call home

2. Block_RDP_From_Internet:
   ├─ Persistent: YES (critical security)
   ├─ Reason: Prevent brute-force attacks before firewall loads
   └─ Fallback: Even in Safe Mode, RDP blocked

3. Block_Facebook_Work_Hours:
   ├─ Persistent: NO (policy, not security)
   ├─ Reason: Not critical, can wait for firewall service
   └─ Fallback: If firewall not running, allow Facebook (acceptable)
```

**Rule Tagging:**
```
In firewall.toml:
[[rule]]
name = "Block_Malware_C2"
action = "DROP"
dst_address = "185.220.101.50"
priority = 10
persistent = true  ← Mark as persistent

Firewall reads "persistent" flag:
├─ If persistent = true → Install as WFP persistent filter
└─ If persistent = false → Install as WFP dynamic filter
```

---

**3. Registry Storage**

**Purpose:** Store persistent filter metadata in registry for tracking

**Why Registry:**
WFP stores persistent filters in Windows registry automatically. Firewall needs separate storage for:
- Mapping: Rule UUID → WFP filter GUID
- Metadata: Rule name, description, created timestamp
- Cleanup: Track which filters to delete on uninstall

**Registry Structure:**
```
HKEY_LOCAL_MACHINE\SOFTWARE\SafeOps\Firewall\PersistentFilters\
├─ {RULE-UUID-1}:
│  ├─ FilterGUID: {WFP-FILTER-GUID-1}
│  ├─ RuleName: "Block_Malware_C2"
│  ├─ Created: 2026-01-22T10:00:00Z
│  └─ Layer: "OUTBOUND_IPPACKET_V4"
│
├─ {RULE-UUID-2}:
│  ├─ FilterGUID: {WFP-FILTER-GUID-2}
│  ├─ RuleName: "Block_RDP_Internet"
│  ├─ Created: 2026-01-22T10:00:00Z
│  └─ Layer: "INBOUND_IPPACKET_V4"
│
└─ ...
```

**Operations:**
```
Install Persistent Filter:
1. Install WFP filter (Windows stores in BFE registry)
2. Store mapping in SafeOps registry
3. Log: "Persistent filter installed: {GUID}"

Uninstall Persistent Filter:
1. Read SafeOps registry (get filter GUID)
2. Delete WFP filter: FwpmFilterDeleteByKey0()
3. Delete registry entry
4. Log: "Persistent filter removed: {GUID}"

Enumerate Persistent Filters:
1. Read SafeOps registry
2. For each entry: Verify WFP filter still exists
3. If WFP filter missing: Remove registry entry (orphaned)
4. Return list of active persistent filters
```

---

**4. Boot-Time Protection Validation**

**Purpose:** Verify persistent filters are active at boot

**Testing Strategy:**

**Test 1: Reboot Test**
```
1. Install persistent filter: Block 1.1.1.1
2. Reboot system
3. Before firewall service starts:
   ├─ Attempt to ping 1.1.1.1
   └─ Expected: Blocked (WFP filter active)
4. After firewall service starts:
   ├─ Verify filter still exists (enumerate)
   └─ Expected: Filter count unchanged
```

**Test 2: Safe Mode Test**
```
1. Install persistent filter: Block RDP (port 3389)
2. Boot into Safe Mode (firewall service disabled)
3. Attempt RDP connection from remote IP
4. Expected: Connection blocked (WFP active even in Safe Mode)
```

**Test 3: Service Crash Test**
```
1. Install persistent filter: Block malware IP
2. Start firewall service
3. Kill firewall service (simulate crash)
4. Attempt connection to malware IP
5. Expected: Still blocked (persistent filter survives)
```

**Test 4: Orphan Filter Test**
```
1. Install persistent filter
2. Manually delete registry entry (simulate corruption)
3. Reboot system
4. Enumerate WFP filters
5. Expected: Orphan filter detected (WFP filter exists, no registry entry)
6. Cleanup: Delete orphan filter
```

---

**5. Upgrade/Uninstall Cleanup**

**Purpose:** Remove persistent filters when firewall is uninstalled

**Problem:**
Persistent filters survive uninstall - if not explicitly deleted, they remain active forever (zombie filters).

**Cleanup on Uninstall:**
```
Firewall Uninstaller:
1. Stop firewall service
2. Open WFP session
3. Read SafeOps registry (list all persistent filters)
4. For each filter:
   ├─ Delete WFP filter: FwpmFilterDeleteByKey0(filterGUID)
   ├─ Delete registry entry
   └─ Log: "Removed persistent filter: {name}"
5. Unregister WFP provider
6. Delete SafeOps registry key
7. Close WFP session
```

**Upgrade Handling:**
```
Firewall Upgrade (v4.0 → v5.0):
1. Stop old service (v4.0)
2. Persistent filters remain active (protection continues)
3. Install new service (v5.0)
4. New service reads registry (discovers existing persistent filters)
5. Options:
   a. Keep old filters (if compatible)
   b. Delete old filters, install new filters (if format changed)
   c. Merge old + new filters
6. Start new service
```

**Orphan Filter Detection:**
```
On firewall startup:
1. Enumerate all WFP filters (Windows registry)
2. Filter by provider: SafeOps GUID
3. For each WFP filter:
   ├─ Check if exists in SafeOps registry
   └─ If missing: Orphaned filter (WFP exists, SafeOps doesn't know about it)

4. Orphan handling:
   ├─ Option A: Delete orphan (safest, prevents zombie filters)
   ├─ Option B: Import orphan (preserve unknown filters)
   └─ Option C: Log warning and ignore

Recommendation: Delete orphans (clean state)
```

---

#### Files to Create:
```
internal/wfp/boottime/
├── persistent.go        # Persistent filter installation
├── critical.go          # Critical rule selection logic
├── registry.go          # Registry storage for filter metadata
├── validation.go        # Boot-time protection validation tests
└── cleanup.go           # Uninstall cleanup (remove persistent filters)
```

---

### Sub-Task 4.5: Testing & Validation

**Purpose:** Verify WFP integration works correctly

**Core Concept:**
Test dual-engine enforcement, application-aware filtering, and boot-time protection to ensure WFP complements SafeOps without conflicts.

---

#### Test Scenarios:

**1. Dual Engine Enforcement Test**

**Setup:**
```
Create firewall rule:
[[rule]]
name = "Block_Test_IP"
action = "DENY"
dst_address = "1.1.1.1"
priority = 100
```

**Test Execution:**
```
1. Start firewall (both SafeOps + WFP active)
2. Ping 1.1.1.1
3. Verify:
   ├─ SafeOps logs: "DENY 1.1.1.1 (TCP RST sent)"
   ├─ WFP logs: "BLOCK 1.1.1.1 (filter matched)"
   └─ Result: Ping fails (blocked by both engines)

4. Disable SafeOps (simulate driver failure)
5. Ping 1.1.1.1
6. Verify:
   ├─ WFP logs: "BLOCK 1.1.1.1"
   └─ Result: Still blocked (WFP provides fallback)

7. Enable SafeOps, disable WFP
8. Ping 1.1.1.1
9. Verify:
   ├─ SafeOps logs: "DENY 1.1.1.1"
   └─ Result: Still blocked (SafeOps provides fallback)
```

**Success Criteria:**
- ✅ Both engines block when active
- ✅ Either engine blocks when other fails
- ✅ No packet escapes when one engine down

---

**2. Application-Aware Filtering Test**

**Setup:**
```
Create application-aware rule:
[[rule]]
name = "Block_Chrome_Facebook"
action = "DENY"
protocol = "TCP"
application = "chrome.exe"
dst_domain = "*.facebook.com"
dst_port = 443
priority = 100
```

**Test Execution:**
```
1. Start firewall
2. Launch Chrome browser
3. Navigate to facebook.com
4. Verify:
   ├─ WFP logs: "BLOCK chrome.exe → 157.240.0.35:443 (ALE_AUTH_CONNECT)"
   ├─ SafeOps logs: "DENY *.facebook.com (domain matched)"
   └─ Result: Facebook blocked in Chrome

5. Launch Firefox browser
6. Navigate to facebook.com
7. Verify:
   ├─ WFP logs: "PERMIT firefox.exe → 157.240.0.35:443 (no app match)"
   ├─ SafeOps logs: "DENY *.facebook.com" (SafeOps blocks regardless of app)
   └─ Result: Blocked by SafeOps, but WFP would allow (SafeOps stricter)

8. Launch Chrome
9. Navigate to google.com
10. Verify:
    ├─ WFP logs: "PERMIT chrome.exe → 172.217.0.46:443 (different destination)"
    └─ Result: Google allowed in Chrome
```

**Success Criteria:**
- ✅ Chrome blocked from Facebook
- ✅ Firefox allowed to Facebook (WFP perspective, SafeOps may still block)
- ✅ Chrome allowed to other sites
- ✅ Process path resolved correctly

---

**3. Boot-Time Protection Test**

**Setup:**
```
Create persistent rule:
[[rule]]
name = "Block_Malware_IP"
action = "DROP"
dst_address = "185.220.101.50"
persistent = true
priority = 10
```

**Test Execution:**
```
1. Install persistent filter
2. Verify registry entry created:
   HKLM\SOFTWARE\SafeOps\Firewall\PersistentFilters\{RULE-UUID}

3. Reboot system
4. During boot (before firewall service starts):
   ├─ Attempt ping to 185.220.101.50 (from startup script)
   └─ Expected: Blocked (WFP persistent filter active)

5. After firewall service starts:
   ├─ Enumerate WFP filters
   ├─ Verify persistent filter exists
   └─ Check registry entry still present

6. Boot into Safe Mode:
   ├─ Firewall service disabled
   ├─ Attempt ping to 185.220.101.50
   └─ Expected: Still blocked (persistent filter independent of service)
```

**Success Criteria:**
- ✅ Persistent filter active at boot
- ✅ Filter survives reboot
- ✅ Filter active in Safe Mode
- ✅ Registry entry persistent

---

**4. Hot-Reload Test (Dual Engine)**

**Setup:**
```
Initial rules (100 rules loaded)
Both SafeOps and WFP active
```

**Test Execution:**
```
1. Edit firewall.toml: Add new rule "Block_Twitter"
2. Save file (trigger hot-reload)
3. Verify:
   ├─ Firewall logs: "Hot-reload triggered"
   ├─ SafeOps: Loads new rule
   ├─ WFP: Deletes all old filters, installs 101 new filters
   └─ Total time: <2 seconds

4. Test new rule:
   ├─ Navigate to twitter.com
   └─ Expected: Blocked by both engines

5. Verify cache invalidation:
   ├─ Previous verdicts cleared
   └─ New rule applies immediately
```

**Success Criteria:**
- ✅ WFP filters updated without restart
- ✅ New rule enforced immediately
- ✅ No packet loss during reload
- ✅ Both engines synchronized

---

**5. Performance Benchmark (Dual Engine)**

**Setup:**
```
Load 1000 firewall rules
Enable both SafeOps and WFP
Generate 1M test packets
```

**Test Execution:**
```
1. Measure WFP filter installation time:
   ├─ Install 1000 WFP filters
   └─ Expected: <2 seconds (batched transactions)

2. Measure packet throughput:
   ├─ Send 1M packets over 10 seconds (100K pps)
   ├─ Both engines evaluating packets
   └─ Expected: No degradation (still 100K pps)

3. Measure latency (dual engine):
   ├─ SafeOps latency: ~10μs (cache hit)
   ├─ WFP latency: ~5μs (kernel filter)
   ├─ Combined latency: ~15μs (sequential evaluation)
   └─ Expected: <1ms p99

4. Measure memory usage:
   ├─ SafeOps: 300MB (verdict cache, connection table)
   ├─ WFP: 100MB (filter storage)
   ├─ Total: 400MB
   └─ Expected: <500MB

5. Measure CPU usage:
   ├─ 8-core system
   ├─ SafeOps: 30% CPU
   ├─ WFP: 10% CPU (kernel handles most)
   ├─ Total: 40% CPU
   └─ Expected: <50%
```

**Success Criteria:**
- ✅ Filter installation <2s for 1000 rules
- ✅ Throughput ≥100K pps (no degradation)
- ✅ Latency <1ms p99
- ✅ Memory <500MB
- ✅ CPU <50%

---

**6. Failover Test**

**Setup:**
```
Both engines active, processing traffic
```

**Test Execution:**
```
1. Kill SafeOps driver (simulate crash):
   ├─ Stop WinpkFilter service
   └─ SafeOps verdict engine offline

2. Send test packet to blocked IP
3. Verify:
   ├─ WFP still blocks
   ├─ Firewall logs: "SafeOps unavailable, WFP-only mode"
   └─ Result: Traffic still protected

4. Restart SafeOps driver
5. Verify:
   ├─ Firewall logs: "SafeOps reconnected, dual-engine mode restored"
   └─ Both engines active again

6. Disable WFP (simulate OS firewall disabled):
   ├─ Stop BFE (Base Filtering Engine) service
   └─ WFP offline

7. Send test packet
8. Verify:
   ├─ SafeOps still blocks
   ├─ Firewall logs: "WFP unavailable, SafeOps-only mode"
   └─ Result: Traffic still protected

9. Re-enable WFP
10. Verify:
    ├─ Firewall logs: "WFP reconnected, dual-engine mode restored"
    └─ Both engines active
```

**Success Criteria:**
- ✅ Firewall continues working with one engine down
- ✅ Automatic failover (no manual intervention)
- ✅ Automatic recovery when engine comes back
- ✅ Logs clearly indicate current mode

---

#### Performance Benchmarks:

**Target Metrics (Phase 4 Completion):**
```
WFP Filter Installation:
├─ 1000 filters: <2 seconds (batched)
├─ 100 filters: <500ms
└─ 10 filters: <100ms

Dual Engine Throughput:
├─ 100,000 packets/sec sustained (no degradation from Phase 3)
├─ SafeOps + WFP combined: Same performance as SafeOps alone
└─ WFP adds <50μs latency per packet

Application-Aware Latency:
├─ Process path resolution: <10ms (one-time per process)
├─ ALE layer filtering: <50μs per packet
└─ Total overhead: <100μs for app-aware rules

Memory Usage:
├─ WFP subsystem: <100MB (1000 filters)
├─ Total firewall: <500MB (SafeOps 300MB + WFP 100MB + overhead 100MB)
└─ Per-filter overhead: ~100KB

Boot-Time Protection:
├─ WFP filters active: 5 seconds after boot (kernel load)
├─ Firewall service starts: 15 seconds after boot
├─ Protection gap: 0 seconds (persistent filters cover gap)
└─ Persistent filter count: <50 (critical rules only)
```

---

## 📊 Phase 4 Success Criteria

**By end of Phase 4, the firewall must demonstrate:**

1. ✅ **Dual Engine Operation:**
   - SafeOps + WFP both enforcing rules simultaneously
   - Either engine can protect independently if other fails
   - No packet loss during failover (verified with counters)

2. ✅ **Application-Aware Filtering:**
   - Block chrome.exe from facebook.com, allow firefox.exe
   - Process path resolution working (chrome.exe → full path)
   - ALE layer filters installed and functional

3. ✅ **Boot-Time Protection:**
   - Persistent filters active before firewall service starts (verified with boot scripts)
   - Filters survive reboot and Safe Mode boot
   - Registry storage tracking persistent filters

4. ✅ **Performance Targets:**
   - WFP filter installation: <2s for 1000 rules
   - Throughput: 100K pps (no degradation from dual engines)
   - Latency: <1ms p99 (including WFP overhead)
   - Memory: <500MB total (SafeOps + WFP)

5. ✅ **Integration:**
   - Hot-reload updates both SafeOps and WFP filters
   - Statistics track both engine verdicts
   - Logging shows which engine blocked each packet

---

## 📁 File Structure Summary

```
src/firewall_engine/
├── internal/
│   ├── wfp/
│   │   ├── bindings/
│   │   │   ├── fwpm.go              # WFP API bindings
│   │   │   ├── fwpm_types.go        # WFP data structures
│   │   │   ├── fwp_types.go         # FWP value types
│   │   │   ├── guid.go              # GUID utilities
│   │   │   ├── errors.go            # Error conversion
│   │   │   ├── strings.go           # String conversion
│   │   │   ├── memory.go            # Memory management
│   │   │   └── constants.go         # WFP constants
│   │   │
│   │   ├── engine.go                # WFP engine manager
│   │   ├── filter.go                # Filter CRUD
│   │   ├── translator.go            # Rule-to-filter translation
│   │   ├── batch.go                 # Batch operations
│   │   ├── provider.go              # Provider registration
│   │   ├── layers.go                # Layer management
│   │   ├── app_resolver.go          # Process path resolution
│   │   │
│   │   ├── application/
│   │   │   ├── resolver.go          # Application path resolver
│   │   │   ├── ale.go               # ALE layer integration
│   │   │   ├── app_filter.go        # Application filter builder
│   │   │   ├── process_monitor.go   # Real-time process monitoring
│   │   │   └── whitelist.go         # Application whitelist
│   │   │
│   │   └── boottime/
│   │       ├── persistent.go        # Persistent filter management
│   │       ├── critical.go          # Critical rule selection
│   │       ├── registry.go          # Registry storage
│   │       ├── validation.go        # Boot-time validation
│   │       └── cleanup.go           # Uninstall cleanup
│   │
│   ├── enforcement/
│   │   └── dual_engine.go           # (new) Dual-engine coordinator
│   │
│   └── integration/
│       └── wfp_client.go            # (new) WFP client wrapper
│
├── cmd/
│   └── main.go                      # Update: Initialize WFP engine
│
└── go.mod                           # Update: Add WFP dependencies
```

---

## 🚀 Next Steps After Phase 4

After Phase 4 completion, proceed to:
- **Phase 5:** Logging, Statistics & Monitoring (Prometheus metrics, gRPC management API)
- **Phase 6:** Hot-Reload & Configuration Management (zero-downtime rule updates)
- **Phase 7:** Security Features (DDoS protection, rate limiting, GeoIP blocking)

**Estimated Total Time for Phase 4:** 3 weeks

---

**END OF PHASE 4 DOCUMENTATION**
