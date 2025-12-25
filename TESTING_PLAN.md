# SafeOps v2.0 - Testing Plan

Kernel Driver + Userspace Service Verification Strategy

## Overview

| Phase      | Scope                                 | Risk Level          |
| ---------- | ------------------------------------- | ------------------- |
| **Part 1** | IDE/Terminal compilation verification | 🟢 Zero risk        |
| **Part 2** | Full functional testing in VM         | 🟡 Isolated VM only |

### Components Under Test

| Component                                 | Files    | Platform          |
| ----------------------------------------- | -------- | ----------------- |
| Kernel Driver (safeops.sys)               | 20 files | Windows 10/11 x64 |
| Userspace Service (userspace_service.exe) | 7 files  | Windows 10/11 x64 |

---

## Part 1: Host System Testing (Safe Compilation)

### Prerequisites

- Visual Studio 2022
- Windows Driver Kit (WDK) 10.0.22621+
- Windows SDK 10.0.22621+

### Phase 1.1: Kernel Driver Verification

#### Step 1.1.1 - Project Setup

```
File → Open → Project/Solution
Navigate to: src/kernel_driver/kernel_driver.vcxproj
```

**Checklist:**

- [ ] Solution loads without errors
- [ ] All 20 files visible
- [ ] Platform set to x64

#### Step 1.1.2 - Configuration Check

| Setting            | Expected Value    |
| ------------------ | ----------------- |
| Warning Level      | /W4               |
| Runtime Library    | /MTd              |
| Security Check     | /GS               |
| Control Flow Guard | /guard:cf         |
| SubSystem          | /SUBSYSTEM:NATIVE |

#### Step 1.1.3 - Header Compilation

| Header           | Expected          |
| ---------------- | ----------------- |
| driver.h         | ✓ Build succeeded |
| packet_capture.h | ✓ Build succeeded |
| filter_engine.h  | ✓ Build succeeded |
| shared_memory.h  | ✓ Build succeeded |
| ioctl_handler.h  | ✓ Build succeeded |

#### Step 1.1.4 - Source File Compilation

| Source           | Time   | Status |
| ---------------- | ------ | ------ |
| driver.c         | 15-20s | [ ]    |
| packet_capture.c | 20-30s | [ ]    |
| filter_engine.c  | 15-20s | [ ]    |
| shared_memory.c  | 10-15s | [ ]    |
| ioctl_handler.c  | 15-20s | [ ]    |

#### Step 1.1.5 - Static Analysis

```
Analyze → Run Code Analysis → On kernel_driver
```

**Acceptable:** < 20 warnings  
**Critical (must fix):** C6386, C6200, C6385

#### Step 1.1.6 - Full Project Build

```
Build → Build kernel_driver (Ctrl+Shift+B)
```

**Expected:** `Build: 1 succeeded, 0 failed`

---

### Phase 1.2: Userspace Service Verification

#### Step 1.2.1 - Project Setup

```
File → Open → Project
Navigate to: src/userspace_service/userspace_service.vcxproj
```

#### Step 1.2.2 - Configuration Check

| Setting                 | Expected Value            |
| ----------------------- | ------------------------- |
| SubSystem               | /SUBSYSTEM:CONSOLE        |
| Runtime Library         | /MTd                      |
| Additional Dependencies | advapi32.lib kernel32.lib |

#### Step 1.2.3 - File Compilation

| Source             | Time   | Status |
| ------------------ | ------ | ------ |
| service_main.c     | 5-8s   | [ ]    |
| ioctl_client.c     | 10-15s | [ ]    |
| ring_reader.c      | 5-8s   | [ ]    |
| log_writer.c       | 8-12s  | [ ]    |
| rotation_manager.c | 8-12s  | [ ]    |

#### Step 1.2.4 - Full Build

```
Build → Build userspace_service
```

**Expected:** `userspace_service.exe` (100-250 KB)

---

### Part 1 Completion Checklist

**Kernel Driver:**

- [ ] All headers compile independently
- [ ] All source files compile to .obj
- [ ] Static analysis passes (< 20 warnings)
- [ ] Full project builds
- [ ] 9 .obj files present

**Userspace Service:**

- [ ] All source files compile
- [ ] Static analysis passes (< 15 warnings)
- [ ] Executable created (.exe)
- [ ] Dependencies verified

---

## Part 2: VM System Testing

### Prerequisites

| Requirement  | Specification                     |
| ------------ | --------------------------------- |
| OS           | Windows 10 Pro 1809+ / Windows 11 |
| Architecture | 64-bit only                       |
| RAM          | 4GB min, 8GB recommended          |
| Disk Space   | 60GB free                         |
| VM Software  | VMware / Hyper-V / VirtualBox     |

### VM Preparation

- [ ] VM created with specs above
- [ ] Windows fully updated
- [ ] Administrator account configured
- [ ] Network connectivity working
- [ ] **Snapshot created ("Clean Baseline")**
- [ ] Antivirus temporarily disabled

### Files to Transfer

1. `.obj` files from Part 1
2. `safeops.inf`
3. `safeops.rc`
4. `userspace_service.exe`
5. PowerShell test scripts

---

### Phase 2.1: Driver Installation

```powershell
# Install driver
pnputil /add-driver safeops.inf /install

# Verify
sc query SafeOps
```

### Phase 2.2: Service Installation

```cmd
sc create SafeOpsUserspace binPath= "C:\Program Files\SafeOps\userspace_service.exe" start= auto
sc start SafeOpsUserspace
```

### Phase 2.3: Functional Verification

| Test             | Command                           | Expected     |
| ---------------- | --------------------------------- | ------------ |
| Driver loaded    | `sc query SafeOps`                | RUNNING      |
| Service running  | `sc query SafeOpsUserspace`       | RUNNING      |
| Logs created     | `dir C:\ProgramData\SafeOps\logs` | .json files  |
| Packets captured | Check log content                 | JSON packets |

### Phase 2.4: Reboot Persistence

```powershell
Restart-Computer -Force
# After reboot:
sc query SafeOps
sc query SafeOpsUserspace
```

---

## Success Criteria

| Criterion     | Requirement                      |
| ------------- | -------------------------------- |
| Part 1        | Zero critical compilation errors |
| Part 2        | Driver loads, service runs       |
| Functionality | Packets logged to JSON           |
| Stability     | No BSOD, no crashes              |
| Persistence   | Survives reboot                  |

---

**Version:** 2.0.0  
**Date:** 2025-12-24
