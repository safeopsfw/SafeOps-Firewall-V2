@echo off
REM Simple launcher - Starts NIC + DHCP + Certificate Manager + Dev UI

net session >nul 2>&1
if %errorlevel% neq 0 (
    powershell -Command "Start-Process '%~f0' -Verb RunAs"
    exit /b
)

title SafeOps - Starting Services

echo Starting Certificate Manager...
cd /d "%~dp0src\certificate_manager"
start "Certificate Manager" cmd /k "go run .\cmd\main.go"
timeout /t 2 /nobreak >nul

echo Starting DHCP Server...
cd /d "%~dp0src\dhcp_server"
start "DHCP Server" cmd /k "go run .\cmd\main.go"
timeout /t 2 /nobreak >nul

echo Starting NIC Management...
cd /d "%~dp0src\nic_management"
start "NIC gRPC" cmd /k "go run .\cmd\."
timeout /t 1 /nobreak >nul

echo Starting NIC API...
cd /d "%~dp0src\nic_management"
start "NIC API" cmd /k "go run .\api\cmd\."
timeout /t 2 /nobreak >nul

echo Starting Dev UI...
cd /d "%~dp0src\ui\dev"
start "Dev UI" cmd /k "npm run dev"
timeout /t 8 /nobreak >nul

start http://localhost:3001/network

echo.
echo All services started!
echo Press any key to stop all services...
pause >nul

taskkill /FI "WindowTitle eq Certificate Manager*" /F >nul 2>&1
taskkill /FI "WindowTitle eq DHCP Server*" /F >nul 2>&1
taskkill /FI "WindowTitle eq NIC gRPC*" /F >nul 2>&1
taskkill /FI "WindowTitle eq NIC API*" /F >nul 2>&1
taskkill /FI "WindowTitle eq Dev UI*" /F >nul 2>&1

echo Services stopped.
timeout /t 2 /nobreak >nul
