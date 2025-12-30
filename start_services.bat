@echo off
setlocal EnableDelayedExpansion

:: SafeOps Services Launcher
:: Starts Certificate Manager, DHCP Server, and NIC Management

echo =============================================
echo     SafeOps Services Launcher
echo =============================================
echo.

:: Check for admin rights (DHCP needs port 67)
net session >nul 2>&1
if %errorLevel% neq 0 (
    echo [WARNING] Not running as Administrator
    echo [WARNING] DHCP Server requires admin for port 67
    echo.
)

:: Create logs directory if it doesn't exist
if not exist logs mkdir logs

:: Get timestamp for log files
for /f "tokens=2 delims==" %%I in ('wmic os get localdatetime /value') do set datetime=%%I
set logdate=%datetime:~0,8%_%datetime:~8,6%

echo [1/3] Starting Certificate Manager on ports 50060 (gRPC) and 8082 (HTTP)...
start "Certificate Manager" cmd /c "bin\certificate_manager.exe > logs\cert_manager_%logdate%.log 2>&1"
timeout /t 2 /nobreak > nul

echo [2/3] Starting DHCP Server on port 67 (UDP) and 50055 (gRPC)...
start "DHCP Server" cmd /c "bin\dhcp_server.exe > logs\dhcp_%logdate%.log 2>&1"
timeout /t 2 /nobreak > nul

echo [3/3] Starting NIC Management on port 50054 (gRPC)...
start "NIC Management" cmd /c "bin\nic_management.exe > logs\nic_mgmt_%logdate%.log 2>&1"
timeout /t 2 /nobreak > nul

echo.
echo =============================================
echo     All Services Started!
echo =============================================
echo.
echo Service Status:
echo   Certificate Manager: Starting (check logs\cert_manager_%logdate%.log)
echo   DHCP Server: Starting (check logs\dhcp_%logdate%.log)
echo   NIC Management: Starting (check logs\nic_mgmt_%logdate%.log)
echo.
echo Port Summary:
echo   50060 - Certificate Manager gRPC
echo   8082  - Certificate Manager HTTP (health, CA download)
echo   50054 - NIC Management gRPC  
echo   50055 - DHCP Server gRPC
echo   67    - DHCP Server UDP
echo.
echo Commands:
echo   View logs:     type logs\*.log
echo   Stop services: stop_services.bat
echo   Check ports:   netstat -an ^| findstr "50054 50055 50060 8082 67"
echo.
pause
