@echo off
REM ============================================================================
REM SafeOps Userspace Service Build Script
REM ============================================================================
REM
REM PURPOSE: Automated build script for SafeOpsService.exe
REM
REM REQUIREMENTS:
REM   - Visual Studio 2019/2022 with C++ workload
REM   - Windows SDK 10.0.22621.0 or later
REM   - Run from "x64 Native Tools Command Prompt for VS"
REM
REM USAGE:
REM   build.cmd [debug|release] [clean]
REM
REM EXAMPLES:
REM   build.cmd              - Build release configuration
REM   build.cmd debug        - Build debug configuration
REM   build.cmd release clean - Clean and build release
REM
REM ============================================================================

setlocal enabledelayedexpansion

REM ============================================================================
REM Configuration
REM ============================================================================

set SCRIPT_DIR=%~dp0
set PROJECT_NAME=SafeOpsService
set OUTPUT_DIR=%SCRIPT_DIR%build

REM Default to Release build
set BUILD_CONFIG=Release
if /I "%1"=="debug" set BUILD_CONFIG=Debug
if /I "%1"=="release" set BUILD_CONFIG=Release

REM Check for clean flag
set CLEAN_BUILD=0
if /I "%1"=="clean" set CLEAN_BUILD=1
if /I "%2"=="clean" set CLEAN_BUILD=1

echo ========================================
echo SafeOps Userspace Service Build
echo ========================================
echo Configuration: %BUILD_CONFIG%
echo Output Directory: %OUTPUT_DIR%
echo.

REM ============================================================================
REM Validate Environment
REM ============================================================================

echo [1/6] Validating build environment...

REM Check if cl.exe is available
where cl.exe >nul 2>&1
if errorlevel 1 (
    echo ERROR: cl.exe not found
    echo.
    echo Please run this script from:
    echo   "x64 Native Tools Command Prompt for VS 2022" or
    echo   "x64 Native Tools Command Prompt for VS 2019"
    echo.
    echo You can find this in Start Menu ^> Visual Studio 2022
    exit /b 1
)

REM Check if link.exe is available
where link.exe >nul 2>&1
if errorlevel 1 (
    echo ERROR: link.exe not found
    exit /b 1
)

echo   Compiler: Found
cl.exe 2>&1 | findstr /C:"Version"
echo   Linker: Found
echo.

REM ============================================================================
REM Verify Source Files
REM ============================================================================

echo [2/6] Verifying source files...

set MISSING_FILES=0

if not exist "%SCRIPT_DIR%service_main.c" (
    echo ERROR: service_main.c not found
    set MISSING_FILES=1
)

if not exist "%SCRIPT_DIR%ioctl_client.c" (
    echo ERROR: ioctl_client.c not found
    set MISSING_FILES=1
)

if not exist "%SCRIPT_DIR%ring_reader.c" (
    echo ERROR: ring_reader.c not found
    set MISSING_FILES=1
)

if not exist "%SCRIPT_DIR%log_writer.c" (
    echo ERROR: log_writer.c not found
    set MISSING_FILES=1
)

if not exist "%SCRIPT_DIR%rotation_manager.c" (
    echo ERROR: rotation_manager.c not found
    set MISSING_FILES=1
)

if %MISSING_FILES%==1 (
    echo.
    echo ERROR: One or more source files are missing
    exit /b 1
)

echo   All source files found
echo.

REM ============================================================================
REM Clean Build (if requested)
REM ============================================================================

if %CLEAN_BUILD%==1 (
    echo [3/6] Cleaning previous build...

    if exist "%OUTPUT_DIR%" (
        rd /S /Q "%OUTPUT_DIR%"
        echo   Cleaned: %OUTPUT_DIR%
    )

    if exist "%SCRIPT_DIR%*.obj" del /Q "%SCRIPT_DIR%*.obj"
    if exist "%SCRIPT_DIR%*.pdb" del /Q "%SCRIPT_DIR%*.pdb"
    if exist "%SCRIPT_DIR%*.ilk" del /Q "%SCRIPT_DIR%*.ilk"
    echo   Cleaned: Intermediate files
    echo.
) else (
    echo [3/6] Skipping clean (use 'clean' flag to clean)
    echo.
)

REM ============================================================================
REM Create Output Directory
REM ============================================================================

echo [4/6] Creating output directory...

if not exist "%OUTPUT_DIR%" (
    mkdir "%OUTPUT_DIR%"
    echo   Created: %OUTPUT_DIR%
) else (
    echo   Exists: %OUTPUT_DIR%
)
echo.

REM ============================================================================
REM Compile
REM ============================================================================

echo [5/6] Compiling %PROJECT_NAME%...
echo.

REM Set compiler flags based on configuration
if /I "%BUILD_CONFIG%"=="Debug" (
    set CFLAGS=/Zi /Od /W4 /RTC1 /MDd
    set LINKFLAGS=/DEBUG
    echo   Debug build: Optimizations disabled, debug info enabled
) else (
    set CFLAGS=/O2 /W4 /MT /GL
    set LINKFLAGS=/LTCG /OPT:REF /OPT:ICF
    echo   Release build: Maximum optimizations, static runtime
)

REM Common flags
set COMMON_FLAGS=/D_WIN32_WINNT=0x0A00 /DUNICODE /D_UNICODE /DWIN32_LEAN_AND_MEAN
set INCLUDE_PATHS=/I"%SCRIPT_DIR%" /I"%SCRIPT_DIR%..\shared\c"
set LIBS=advapi32.lib kernel32.lib user32.lib

REM Full compile command
echo   Invoking compiler...
echo.

cl.exe %CFLAGS% %COMMON_FLAGS% %INCLUDE_PATHS% ^
    "%SCRIPT_DIR%service_main.c" ^
    "%SCRIPT_DIR%ioctl_client.c" ^
    "%SCRIPT_DIR%ring_reader.c" ^
    "%SCRIPT_DIR%log_writer.c" ^
    "%SCRIPT_DIR%rotation_manager.c" ^
    /Fe:"%OUTPUT_DIR%\%PROJECT_NAME%.exe" ^
    /Fo:"%OUTPUT_DIR%\\" ^
    /Fd:"%OUTPUT_DIR%\\" ^
    /link %LINKFLAGS% %LIBS%

if errorlevel 1 (
    echo.
    echo ========================================
    echo BUILD FAILED
    echo ========================================
    echo.
    echo Check the error messages above for details.
    exit /b 1
)

echo.
echo   Compilation successful
echo.

REM ============================================================================
REM Build Verification
REM ============================================================================

echo [6/6] Verifying build output...
echo.

if not exist "%OUTPUT_DIR%\%PROJECT_NAME%.exe" (
    echo ERROR: %PROJECT_NAME%.exe was not created
    exit /b 1
)

REM Show file details
dir "%OUTPUT_DIR%\%PROJECT_NAME%.exe" | findstr /C:"%PROJECT_NAME%.exe"

REM Calculate file size
for %%F in ("%OUTPUT_DIR%\%PROJECT_NAME%.exe") do set FILE_SIZE=%%~zF
set /A FILE_SIZE_KB=%FILE_SIZE% / 1024

echo.
echo   Output: %OUTPUT_DIR%\%PROJECT_NAME%.exe
echo   Size: %FILE_SIZE_KB% KB
echo.

REM ============================================================================
REM Success
REM ============================================================================

echo ========================================
echo BUILD COMPLETED SUCCESSFULLY
echo ========================================
echo.
echo Configuration: %BUILD_CONFIG%
echo Output: %OUTPUT_DIR%\%PROJECT_NAME%.exe
echo.

REM Show next steps
echo Next Steps:
echo   1. Install service: sc create SafeOpsCapture binPath="%OUTPUT_DIR%\%PROJECT_NAME%.exe"
echo   2. Start service: sc start SafeOpsCapture
echo   3. Check status: sc query SafeOpsCapture
echo.
echo For console mode testing:
echo   %OUTPUT_DIR%\%PROJECT_NAME%.exe -console
echo.

exit /b 0
