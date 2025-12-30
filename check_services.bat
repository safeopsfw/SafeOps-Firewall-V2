@echo off
REM Quick Service Health Check Script

title SafeOps - Service Health Check

echo.
echo ╔═══════════════════════════════════════════════════════════════╗
echo ║              SafeOps Service Health Check                     ║
echo ╚═══════════════════════════════════════════════════════════════╝
echo.
echo Checking all services...
echo.

REM Check Certificate Manager (HTTP port 8080)
echo Checking Certificate Manager (port 8080)...
curl -s -o nul -w "HTTP Status: %%{http_code}\n" http://localhost:8080/health 2>nul
if %errorlevel% equ 0 (
    echo    ✅ Certificate Manager: RUNNING
) else (
    echo    ❌ Certificate Manager: NOT RESPONDING
)
echo.

REM Check NIC Management (HTTP port 8081)
echo Checking NIC Management (port 8081)...
curl -s -o nul -w "HTTP Status: %%{http_code}\n" http://localhost:8081/api/health 2>nul
if %errorlevel% equ 0 (
    echo    ✅ NIC Management: RUNNING
) else (
    echo    ❌ NIC Management: NOT RESPONDING
)
echo.

REM Check WiFi AP (HTTP port 80)
echo Checking WiFi AP (port 80)...
curl -s -o nul -w "HTTP Status: %%{http_code}\n" http://localhost:80/ 2>nul
if %errorlevel% equ 0 (
    echo    ✅ WiFi AP: RUNNING
) else (
    echo    ❌ WiFi AP: NOT RESPONDING
)
echo.

REM Check DHCP Server (gRPC port 50054)
echo Checking DHCP Server (port 50054)...
netstat -an | findstr ":50054" >nul 2>&1
if %errorlevel% equ 0 (
    echo    ✅ DHCP Server: LISTENING on port 50054
) else (
    echo    ❌ DHCP Server: NOT LISTENING
)
echo.

REM Check if log files exist and are being updated
echo.
echo ═══════════════════════════════════════════════════════════════
echo Checking log files...
echo.

if exist "logs\certificate_manager.log" (
    for %%A in (logs\certificate_manager.log) do (
        echo    📄 Certificate Manager log: %%~zA bytes
    )
) else (
    echo    ⚠️  Certificate Manager log: NOT FOUND
)

if exist "logs\dhcp_server.log" (
    for %%A in (logs\dhcp_server.log) do (
        echo    📄 DHCP Server log: %%~zA bytes
    )
) else (
    echo    ⚠️  DHCP Server log: NOT FOUND
)

if exist "logs\nic_management.log" (
    for %%A in (logs\nic_management.log) do (
        echo    📄 NIC Management log: %%~zA bytes
    )
) else (
    echo    ⚠️  NIC Management log: NOT FOUND
)

if exist "logs\wifi_ap.log" (
    for %%A in (logs\wifi_ap.log) do (
        echo    📄 WiFi AP log: %%~zA bytes
    )
) else (
    echo    ⚠️  WiFi AP log: NOT FOUND
)

echo.
echo ═══════════════════════════════════════════════════════════════
echo.
echo 📋 Recent log entries (last 5 lines from each service):
echo.

if exist "logs\certificate_manager.log" (
    echo --- Certificate Manager ---
    powershell -Command "Get-Content logs\certificate_manager.log -Tail 5"
    echo.
)

if exist "logs\dhcp_server.log" (
    echo --- DHCP Server ---
    powershell -Command "Get-Content logs\dhcp_server.log -Tail 5"
    echo.
)

echo.
echo ═══════════════════════════════════════════════════════════════
echo Health check complete!
echo.
pause
