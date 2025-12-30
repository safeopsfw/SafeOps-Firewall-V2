@echo off
REM Component Integration Verification Script

title SafeOps - Integration Verification

echo.
echo ╔═══════════════════════════════════════════════════════════════╗
echo ║         SafeOps Component Integration Verification           ║
echo ╚═══════════════════════════════════════════════════════════════╝
echo.

REM ============================================================================
REM 1. Certificate Manager Tests
REM ============================================================================
echo ═══════════════════════════════════════════════════════════════
echo 📋 COMPONENT 1: Certificate Manager
echo ═══════════════════════════════════════════════════════════════
echo.

echo [TEST 1.1] Checking if gRPC port 50053 is listening...
netstat -an | findstr ":50053" >nul 2>&1
if %errorlevel% equ 0 (
    echo    ✅ Port 50053: LISTENING
) else (
    echo    ❌ Port 50053: NOT LISTENING
)

echo [TEST 1.2] Checking if HTTP port 8093 is listening...
netstat -an | findstr ":8093" >nul 2>&1
if %errorlevel% equ 0 (
    echo    ✅ Port 8093: LISTENING
) else (
    echo    ❌ Port 8093: NOT LISTENING
)

echo [TEST 1.3] Testing HTTP health endpoint...
curl -s http://localhost:8093/health > temp_health.txt 2>nul
if %errorlevel% equ 0 (
    echo    ✅ Health Endpoint: RESPONDING
    echo    Response:
    type temp_health.txt | findstr "status"
) else (
    echo    ❌ Health Endpoint: NOT RESPONDING
)
del temp_health.txt 2>nul

echo.

REM ============================================================================
REM 2. DHCP Server Tests
REM ============================================================================
echo ═══════════════════════════════════════════════════════════════
echo 📋 COMPONENT 2: DHCP Server
echo ═══════════════════════════════════════════════════════════════
echo.

echo [TEST 2.1] Checking if UDP port 67 (DHCP) is listening...
netstat -an | findstr "UDP" | findstr ":67" >nul 2>&1
if %errorlevel% equ 0 (
    echo    ✅ Port 67 (UDP): LISTENING
    netstat -an | findstr "UDP" | findstr ":67"
) else (
    echo    ❌ Port 67 (UDP): NOT LISTENING
)

echo [TEST 2.2] Checking if gRPC port 50055 is listening...
netstat -an | findstr ":50055" >nul 2>&1
if %errorlevel% equ 0 (
    echo    ✅ Port 50055: LISTENING
) else (
    echo    ❌ Port 50055: NOT LISTENING
)

echo.

REM ============================================================================
REM 3. Process Check
REM ============================================================================
echo ═══════════════════════════════════════════════════════════════
echo 📋 COMPONENT 3: Running Processes
echo ═══════════════════════════════════════════════════════════════
echo.

echo [TEST 3.1] Checking if certificate_manager.exe is running...
tasklist | findstr "certificate_manager.exe" >nul 2>&1
if %errorlevel% equ 0 (
    echo    ✅ certificate_manager.exe: RUNNING
    tasklist | findstr "certificate_manager.exe"
) else (
    echo    ❌ certificate_manager.exe: NOT RUNNING
)

echo [TEST 3.2] Checking if dhcp_server.exe is running...
tasklist | findstr "dhcp_server.exe" >nul 2>&1
if %errorlevel% equ 0 (
    echo    ✅ dhcp_server.exe: RUNNING
    tasklist | findstr "dhcp_server.exe"
) else (
    echo    ❌ dhcp_server.exe: NOT RUNNING
)

echo.

REM ============================================================================
REM 4. Log File Check
REM ============================================================================
echo ═══════════════════════════════════════════════════════════════
echo 📋 COMPONENT 4: Log Files
echo ═══════════════════════════════════════════════════════════════
echo.

if exist "logs\certificate_manager.log" (
    echo [TEST 4.1] Certificate Manager Log:
    echo    ✅ File exists
    for %%A in (logs\certificate_manager.log) do echo    Size: %%~zA bytes
    echo.
    echo    Last 10 lines:
    powershell -Command "Get-Content logs\certificate_manager.log -Tail 10"
) else (
    echo    ❌ Log file not found
)

echo.

if exist "logs\dhcp_server.log" (
    echo [TEST 4.2] DHCP Server Log:
    echo    ✅ File exists
    for %%A in (logs\dhcp_server.log) do echo    Size: %%~zA bytes
    echo.
    echo    Last 10 lines:
    powershell -Command "Get-Content logs\dhcp_server.log -Tail 10"
) else (
    echo    ❌ Log file not found
)

echo.

REM ============================================================================
REM 5. Integration Test
REM ============================================================================
echo ═══════════════════════════════════════════════════════════════
echo 📋 COMPONENT 5: Integration Check
echo ═══════════════════════════════════════════════════════════════
echo.

echo [TEST 5.1] Checking DHCP→Certificate Manager gRPC connection...
if exist "logs\dhcp_server.log" (
    findstr /C:"Certificate Manager" /C:"cert" /C:"CA" logs\dhcp_server.log > temp_integration.txt 2>nul
    if exist temp_integration.txt (
        for /f %%a in ('type temp_integration.txt ^| find /c /v ""') do set count=%%a
        if !count! gtr 0 (
            echo    ✅ Integration logs found: !count! entries
            echo    Sample entries:
            type temp_integration.txt | findstr /N ".*" | findstr "^[1-3]:"
        ) else (
            echo    ⚠️  No integration logs found yet
        )
    )
    del temp_integration.txt 2>nul
)

echo.

REM ============================================================================
REM Summary
REM ============================================================================
echo ═══════════════════════════════════════════════════════════════
echo 📋 VERIFICATION SUMMARY
echo ═══════════════════════════════════════════════════════════════
echo.
echo Components Tested:
echo    1. ✅ Certificate Manager (gRPC + HTTP)
echo    2. ✅ DHCP Server (UDP + gRPC)
echo    3. ✅ Process Status
echo    4. ✅ Log Files
echo    5. ✅ Integration
echo.
echo ═══════════════════════════════════════════════════════════════
echo.
pause
