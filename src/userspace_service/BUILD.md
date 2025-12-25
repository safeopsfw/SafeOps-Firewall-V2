# SafeOps Userspace Service - Build Guide

**Document Version:** 1.0
**Last Updated:** 2024-12-25
**Component:** Userspace Service
**Status:** Production

---

## Table of Contents

1. [Overview](#overview)
2. [Build Requirements](#build-requirements)
3. [Build Process](#build-process)
4. [Build Configurations](#build-configurations)
5. [Compilation Issues Fixed](#compilation-issues-fixed)
6. [Build Verification](#build-verification)
7. [Troubleshooting](#troubleshooting)

---

## 1. Overview

This document provides comprehensive instructions for building the SafeOps Userspace Service (SafeOpsService.exe) from source code.

### 1.1 Component Description

The userspace service is a Windows Service that:
- Communicates with the kernel driver via IOCTLs
- Reads packets from a 2GB shared memory ring buffer
- Logs packets to disk in JSON format
- Manages log rotation every 5 minutes

### 1.2 Source Files

| File | Lines | Purpose |
|------|-------|---------|
| service_main.c | 909 | Service entry point and orchestration |
| ioctl_client.c | 1,036 | Kernel driver communication |
| ring_reader.c | 265 | Lock-free ring buffer reader |
| log_writer.c | 118 | JSON log writer with buffering |
| rotation_manager.c | 796 | 5-minute log rotation manager |
| userspace_service.h | 289 | Shared structures and definitions |
| service_main.h | 145 | Service main header |
| ring_reader.h | 28 | Ring reader header |
| log_writer.h | 26 | Log writer header |
| packet_metadata.h | 18 | Packet metadata header |
| **Total** | **3,630** | |

---

## 2. Build Requirements

### 2.1 Operating System
- Windows 10 (version 1809 or later) or Windows 11
- Windows Server 2019/2022
- 64-bit (x64) architecture required

### 2.2 Development Tools

**Required:**
- Visual Studio 2019 or 2022
- Desktop development with C++ workload
- Windows SDK 10.0.22621.0 or later

**Recommended:**
- Visual Studio 2022 (latest version)
- C++ build tools
- Windows 11 SDK (10.0.22621.0)

### 2.3 System Requirements
- CPU: Intel/AMD x64, 2+ cores
- RAM: Minimum 4 GB
- Disk: 500 MB free space for build output
- Administrator privileges for installation

### 2.4 Dependencies

**Windows SDK Libraries:**
- advapi32.lib (Service Control Manager)
- kernel32.lib (Windows API)
- user32.lib (User interface)
- ws2_32.lib (Winsock, if needed)

**SafeOps Headers:**
- Located in: `src/shared/c/`
- packet_structs.h
- ring_buffer.h
- shared_constants.h
- ioctl_codes.h
- error_codes.h

---

## 3. Build Process

### 3.1 Method 1: Visual Studio IDE

**Step 1: Open Visual Studio**
1. Launch Visual Studio 2022
2. File → New → Project From Existing Code

**Step 2: Configure Project**
1. Project Type: Visual C++
2. Project Location: `src/userspace_service`
3. Project Name: SafeOpsService
4. Add all .c and .h files

**Step 3: Set Project Properties**

Right-click project → Properties:

**General:**
- Configuration Type: Application (.exe)
- Platform: x64
- Windows SDK Version: 10.0 (latest installed)
- Platform Toolset: v143 (VS 2022) or v142 (VS 2019)

**C/C++ → General:**
- Additional Include Directories:
  - `$(ProjectDir)`
  - `$(ProjectDir)..\shared\c`
  - `$(WindowsSdkDir)Include\$(WindowsSDKVersion)um`
  - `$(WindowsSdkDir)Include\$(WindowsSDKVersion)shared`

**C/C++ → Preprocessor:**
- Preprocessor Definitions:
  - `_WIN32_WINNT=0x0A00` (Windows 10)
  - `UNICODE`
  - `_UNICODE`
  - `WIN32_LEAN_AND_MEAN`
  - `_CRT_SECURE_NO_WARNINGS` (optional, for legacy code)

**C/C++ → Code Generation:**
- Runtime Library: Multi-threaded (/MT) for Release

**Linker → General:**
- SubSystem: Console (for console mode) or Windows (for service only)

**Linker → Input:**
- Additional Dependencies:
  - advapi32.lib
  - kernel32.lib
  - user32.lib

**Step 4: Build**
1. Select Configuration: Release
2. Select Platform: x64
3. Build → Build Solution (Ctrl+Shift+B)
4. Output: `x64\Release\SafeOpsService.exe`

### 3.2 Method 2: Command Line (cl.exe)

**Step 1: Open Developer Command Prompt**
1. Start Menu → Visual Studio 2022
2. Click "x64 Native Tools Command Prompt for VS 2022"

**Step 2: Navigate to Source Directory**
```cmd
cd C:\Users\02arj\.claude-worktrees\SafeOpsFV2\pensive-swanson\src\userspace_service
```

**Step 3: Compile (Debug)**
```cmd
cl.exe /Zi /W4 /D_WIN32_WINNT=0x0A00 /DUNICODE /D_UNICODE ^
    /I. /I..\shared\c ^
    service_main.c ^
    ioctl_client.c ^
    ring_reader.c ^
    log_writer.c ^
    rotation_manager.c ^
    /Fe:SafeOpsService.exe ^
    /link advapi32.lib kernel32.lib user32.lib
```

**Step 4: Compile (Release with Optimizations)**
```cmd
cl.exe /O2 /W4 /D_WIN32_WINNT=0x0A00 /DUNICODE /D_UNICODE ^
    /DWIN32_LEAN_AND_MEAN ^
    /I. /I..\shared\c ^
    service_main.c ^
    ioctl_client.c ^
    ring_reader.c ^
    log_writer.c ^
    rotation_manager.c ^
    /Fe:SafeOpsService.exe ^
    /link advapi32.lib kernel32.lib user32.lib
```

**Compiler Flags Explained:**
- `/O2` - Maximum optimization (speed)
- `/W4` - Warning level 4 (strict warnings)
- `/Zi` - Debug information (only for debug build)
- `/D_WIN32_WINNT=0x0A00` - Target Windows 10+
- `/DUNICODE` - Unicode character set
- `/I` - Include directories
- `/Fe:` - Output executable name
- `/link` - Linker options and libraries

### 3.3 Method 3: MSBuild (Automated)

**Step 1: Create Project File**

Save as `SafeOpsService.vcxproj`:

```xml
<?xml version="1.0" encoding="utf-8"?>
<Project DefaultTargets="Build" xmlns="http://schemas.microsoft.com/developer/msbuild/2003">
  <ItemGroup>
    <ProjectConfiguration Include="Release|x64">
      <Configuration>Release</Configuration>
      <Platform>x64</Platform>
    </ProjectConfiguration>
  </ItemGroup>

  <PropertyGroup>
    <PlatformToolset>v143</PlatformToolset>
    <ConfigurationType>Application</ConfigurationType>
    <CharacterSet>Unicode</CharacterSet>
    <WindowsTargetPlatformVersion>10.0</WindowsTargetPlatformVersion>
  </PropertyGroup>

  <ItemDefinitionGroup>
    <ClCompile>
      <AdditionalIncludeDirectories>.;..\shared\c;%(AdditionalIncludeDirectories)</AdditionalIncludeDirectories>
      <PreprocessorDefinitions>_WIN32_WINNT=0x0A00;UNICODE;_UNICODE;WIN32_LEAN_AND_MEAN;%(PreprocessorDefinitions)</PreprocessorDefinitions>
      <Optimization>MaxSpeed</Optimization>
      <RuntimeLibrary>MultiThreaded</RuntimeLibrary>
      <WarningLevel>Level4</WarningLevel>
    </ClCompile>
    <Link>
      <AdditionalDependencies>advapi32.lib;kernel32.lib;user32.lib;%(AdditionalDependencies)</AdditionalDependencies>
      <SubSystem>Console</SubSystem>
    </Link>
  </ItemDefinitionGroup>

  <ItemGroup>
    <ClCompile Include="service_main.c" />
    <ClCompile Include="ioctl_client.c" />
    <ClCompile Include="ring_reader.c" />
    <ClCompile Include="log_writer.c" />
    <ClCompile Include="rotation_manager.c" />
  </ItemGroup>

  <ItemGroup>
    <ClInclude Include="userspace_service.h" />
    <ClInclude Include="service_main.h" />
    <ClInclude Include="ring_reader.h" />
    <ClInclude Include="log_writer.h" />
    <ClInclude Include="packet_metadata.h" />
  </ItemGroup>

  <Import Project="$(VCTargetsPath)\Microsoft.Cpp.Default.props" />
  <Import Project="$(VCTargetsPath)\Microsoft.Cpp.props" />
  <Import Project="$(VCTargetsPath)\Microsoft.Cpp.targets" />
</Project>
```

**Step 2: Build with MSBuild**
```cmd
msbuild SafeOpsService.vcxproj /p:Configuration=Release /p:Platform=x64
```

---

## 4. Build Configurations

### 4.1 Debug Configuration

**Purpose:** Development, debugging, testing

**Compiler Options:**
- Optimizations: Disabled (/Od)
- Debug Info: Full (/Zi)
- Runtime Checks: Enabled (/RTC1)
- Runtime Library: Multi-threaded Debug DLL (/MDd)

**Linker Options:**
- Generate Debug Info: Yes (/DEBUG)

**Output:**
- Size: ~500 KB (with debug symbols ~2 MB)
- Performance: Slower, suitable for debugging only

### 4.2 Release Configuration

**Purpose:** Production deployment

**Compiler Options:**
- Optimizations: Maximum Speed (/O2)
- Debug Info: None (or PDB only for crash dumps)
- Runtime Checks: Disabled
- Runtime Library: Multi-threaded (/MT) - static linking
- Inline Functions: Any Suitable (/Ob2)
- Whole Program Optimization: Yes (/GL)

**Linker Options:**
- Link Time Code Generation: Yes (/LTCG)
- Optimize References: Yes (/OPT:REF)
- Enable COMDAT Folding: Yes (/OPT:ICF)

**Output:**
- Size: ~200-300 KB (optimized)
- Performance: Maximum, production-ready

### 4.3 Build Targets

**x64 (64-bit):** Primary target
- Required for kernel driver compatibility
- Supports > 4 GB memory
- Modern processor instructions

**ARM64:** Not currently supported

---

## 5. Compilation Issues Fixed

### 5.1 Missing Header Files

**Issue:** Missing custom headers referenced by source files

**Files Created:**
1. `ring_reader.h` - Ring buffer reader interface
2. `log_writer.h` - Log writer interface
3. `packet_metadata.h` - Packet metadata definitions

**Solution:** Created stub headers that reference existing definitions in `userspace_service.h` and `service_main.h`.

### 5.2 Include Path Issues

**Issue:** Could not find shared headers

**Solution:** Added include directory `-I..\shared\c` to access:
- `packet_structs.h`
- `ring_buffer.h`
- `shared_constants.h`

### 5.3 Type Definition Conflicts

**Issue:** Duplicate type definitions between headers

**Solution:** Added include guards to all headers:
```c
#ifndef SAFEOPS_RING_READER_H
#define SAFEOPS_RING_READER_H
// ... content ...
#endif
```

### 5.4 Function Prototype Mismatches

**Issue:** Function signatures between .h and .c files didn't match

**Solution:** Updated function prototypes to match implementation:
- Added `NTSTATUS` return type support
- Fixed parameter types (HANDLE, SIZE_T, UINT64)
- Ensured calling conventions match (WINAPI, etc.)

### 5.5 Windows API Compatibility

**Issue:** Deprecated or incompatible Windows API calls

**Solution:**
- Used `strncpy_s` instead of `strncpy`
- Used `sprintf_s` instead of `sprintf`
- Added `_WIN32_WINNT=0x0A00` to target Windows 10+

### 5.6 Structure Alignment

**Issue:** Structure packing mismatches between kernel and userspace

**Solution:**
- Used `#pragma pack(push, 1)` for shared structures
- Ensured consistent packing across all files
- Added static assertions to verify sizes

### 5.7 Linker Errors

**Issue:** Unresolved external symbols

**Solution:** Added required libraries:
- `advapi32.lib` - Service Control Manager functions
- `kernel32.lib` - Core Windows API
- `user32.lib` - User interface functions

---

## 6. Build Verification

### 6.1 Verify Successful Build

**Check Output File:**
```cmd
dir SafeOpsService.exe
```

Expected output:
```
12/25/2024  10:00 AM           245,760 SafeOpsService.exe
```

**Check File Properties:**
```cmd
SafeOpsService.exe /? (should show help or error message)
```

### 6.2 Dependency Check

**Use Dependency Walker or dumpbin:**
```cmd
dumpbin /dependents SafeOpsService.exe
```

Expected dependencies:
- KERNEL32.dll
- ADVAPI32.dll
- USER32.dll
- MSVCRT.dll (or no C runtime if statically linked)

### 6.3 Digital Signature (Optional)

**For production, sign the executable:**
```cmd
signtool sign /f certificate.pfx /p password SafeOpsService.exe
```

### 6.4 Test Run

**Console Mode:**
```cmd
SafeOpsService.exe -console
```

Expected output:
```
[SafeOps] Running in console mode (debug)
[SafeOps] Initializing components...
[IoctlClient] Initialized successfully
...
```

Press Ctrl+C to stop.

---

## 7. Troubleshooting

### 7.1 Build Errors

#### Error: Cannot open include file

**Symptom:**
```
fatal error C1083: Cannot open include file: 'ring_reader.h': No such file or directory
```

**Solution:**
1. Verify file exists in project directory
2. Check include paths: `/I.` and `/I..\shared\c`
3. Verify file permissions

#### Error: Unresolved external symbol

**Symptom:**
```
error LNK2019: unresolved external symbol _RegisterServiceCtrlHandlerW
```

**Solution:**
- Add `advapi32.lib` to linker input
- Verify library path is correct
- Check function name decoration (Unicode vs ANSI)

#### Error: Incompatible types

**Symptom:**
```
error C2440: '=': cannot convert from 'int' to 'HANDLE'
```

**Solution:**
- Check function return types
- Cast if necessary: `(HANDLE)CreateFile(...)`
- Verify prototype matches implementation

### 7.2 Runtime Errors

#### Service fails to start

**Symptom:** Service starts then immediately stops

**Solution:**
1. Check Event Viewer (Windows Logs → Application)
2. Run in console mode: `SafeOpsService.exe -console`
3. Verify kernel driver is loaded: `sc query SafeOpsDriver`
4. Check log file: `C:\SafeOps\logs\service.log`

#### Access Denied

**Symptom:** Cannot open driver device

**Solution:**
- Run as Administrator
- Verify driver is loaded
- Check driver device name matches: `\\.\\SafeOps`

#### Memory Access Violation

**Symptom:** Crash with access violation (0xC0000005)

**Solution:**
- Check ring buffer mapping succeeded
- Verify pointers are valid before dereferencing
- Use debugger to find exact crash location

### 7.3 Performance Issues

#### High CPU Usage

**Symptom:** Service uses 50%+ CPU

**Solution:**
- Add sleep in ring reader loop (1-10 ms)
- Reduce poll frequency
- Check for busy-wait loops

#### Memory Leak

**Symptom:** Memory usage grows over time

**Solution:**
- Verify `CleanupComponents()` called on shutdown
- Check all allocations have matching frees
- Use memory leak detector (e.g., _CrtSetDbgFlag)

---

## Appendix A: Build Script

**File:** `build.cmd`

```batch
@echo off
REM SafeOps Userspace Service Build Script
REM Requires Visual Studio 2022 Developer Command Prompt

echo ========================================
echo SafeOps Userspace Service Build
echo ========================================
echo.

REM Check if running in Developer Command Prompt
where cl.exe >nul 2>&1
if errorlevel 1 (
    echo ERROR: cl.exe not found
    echo Please run from Visual Studio Developer Command Prompt
    exit /b 1
)

REM Set build configuration
set CONFIG=Release
set PLATFORM=x64

echo Configuration: %CONFIG%
echo Platform: %PLATFORM%
echo.

REM Create output directory
if not exist "build" mkdir build
cd build

REM Compile
echo Compiling...
cl.exe /O2 /W4 /D_WIN32_WINNT=0x0A00 /DUNICODE /D_UNICODE ^
    /DWIN32_LEAN_AND_MEAN ^
    /I.. /I..\..\shared\c ^
    ..\service_main.c ^
    ..\ioctl_client.c ^
    ..\ring_reader.c ^
    ..\log_writer.c ^
    ..\rotation_manager.c ^
    /Fe:SafeOpsService.exe ^
    /link advapi32.lib kernel32.lib user32.lib

if errorlevel 1 (
    echo.
    echo ERROR: Compilation failed
    cd ..
    exit /b 1
)

echo.
echo ========================================
echo Build completed successfully!
echo Output: build\SafeOpsService.exe
echo ========================================
echo.

REM Show file info
dir SafeOpsService.exe

cd ..
exit /b 0
```

---

## Appendix B: Makefile (nmake)

**File:** `Makefile`

```makefile
# SafeOps Userspace Service Makefile
# Usage: nmake [target]

# Compiler and flags
CC = cl.exe
CFLAGS = /O2 /W4 /DUNICODE /D_UNICODE /DWIN32_LEAN_AND_MEAN /D_WIN32_WINNT=0x0A00
INCLUDES = /I. /I..\shared\c
LIBS = advapi32.lib kernel32.lib user32.lib

# Source files
SOURCES = service_main.c ioctl_client.c ring_reader.c log_writer.c rotation_manager.c

# Output
TARGET = SafeOpsService.exe

# Build targets
all: $(TARGET)

$(TARGET): $(SOURCES)
	$(CC) $(CFLAGS) $(INCLUDES) $(SOURCES) /Fe:$(TARGET) /link $(LIBS)

clean:
	del /Q *.obj *.exe *.pdb *.ilk 2>nul

rebuild: clean all

install: $(TARGET)
	copy $(TARGET) C:\SafeOps\bin\
	sc create SafeOpsCapture binPath="C:\SafeOps\bin\$(TARGET)"

uninstall:
	sc stop SafeOpsCapture
	sc delete SafeOpsCapture
	del /Q C:\SafeOps\bin\$(TARGET)

.PHONY: all clean rebuild install uninstall
```

---

**Document End**
