@echo off
setlocal EnableDelayedExpansion

echo =============================================
echo     SafeOps Integration Verification
echo =============================================
echo.

:: Check processes
echo === Process Status ===
set found=0
for /f "tokens=*" %%i in ('tasklist /FI "IMAGENAME eq certificate_manager.exe" 2^>nul ^| findstr /I "certificate_manager"') do (
    echo [OK] Certificate Manager: Running
    set /a found+=1
)
for /f "tokens=*" %%i in ('tasklist /FI "IMAGENAME eq dhcp_server.exe" 2^>nul ^| findstr /I "dhcp_server"') do (
    echo [OK] DHCP Server: Running
    set /a found+=1
)
for /f "tokens=*" %%i in ('tasklist /FI "IMAGENAME eq nic_management.exe" 2^>nul ^| findstr /I "nic_management"') do (
    echo [OK] NIC Management: Running
    set /a found+=1
)

if %found% equ 0 (
    echo [!!] No services are running
    echo.
    echo Run start_services.bat first
    pause
    exit /b 1
)

echo.
echo === Port Status ===
echo Checking listening ports...
netstat -an | findstr "LISTENING" | findstr "50054 50055 50060 8082 :67 " 2>nul
if %errorlevel% neq 0 (
    echo [!!] No expected ports found listening
)

echo.
echo === Health Checks ===

:: Check Certificate Manager health endpoint
echo Testing Certificate Manager health (http://localhost:8082/health)...
curl -s http://localhost:8082/health 2>nul
if %errorlevel% equ 0 (
    echo.
    echo [OK] Certificate Manager HTTP responding
) else (
    echo [!!] Certificate Manager HTTP not responding
)

echo.
echo === Recent Log Entries ===
echo.
echo --- Certificate Manager (last 5 lines) ---
for /f "delims=" %%f in ('dir /b /od logs\cert_manager_*.log 2^>nul') do set "latest_cm=%%f"
if defined latest_cm (
    powershell -Command "Get-Content logs\%latest_cm% -Tail 5"
) else (
    echo No logs found
)

echo.
echo --- DHCP Server (last 5 lines) ---
for /f "delims=" %%f in ('dir /b /od logs\dhcp_*.log 2^>nul') do set "latest_dhcp=%%f"
if defined latest_dhcp (
    powershell -Command "Get-Content logs\%latest_dhcp% -Tail 5"
) else (
    echo No logs found
)

echo.
echo --- NIC Management (last 5 lines) ---
for /f "delims=" %%f in ('dir /b /od logs\nic_mgmt_*.log 2^>nul') do set "latest_nic=%%f"
if defined latest_nic (
    powershell -Command "Get-Content logs\%latest_nic% -Tail 5"
) else (
    echo No logs found
)

echo.
echo =============================================
echo     Verification Complete
echo =============================================
pause
