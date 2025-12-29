@echo off
REM SafeOps Network Management Suite - Windows Launcher
REM Starts DHCP Server + NIC API + Dev UI + Opens Browser

title SafeOps - Network Management Suite

REM Check for admin privileges and auto-elevate if needed
net session >nul 2>&1
if %errorlevel% neq 0 (
    echo ⚠️  Requesting administrator privileges...
    echo    Hotspot control requires admin rights
    echo.
    powershell -Command "Start-Process '%~f0' -Verb RunAs"
    exit /b
)

echo.
echo ╔═══════════════════════════════════════════════════════╗
echo ║           SafeOps - Network Management Suite         ║
echo ║              Starting All Services...                ║
echo ║            ✅ Running as Administrator                ║
echo ╚═══════════════════════════════════════════════════════╝
echo.

REM Start DHCP Server (optional - continues if fails)
echo 🔧 Starting DHCP Server...
cd /d "%~dp0src\dhcp_server"
start "DHCP Server" cmd /k "go run ./cmd/."
timeout /t 1 /nobreak >nul

REM Start NIC Management gRPC (background)
echo 🔧 Starting NIC Management gRPC...
cd /d "%~dp0src\nic_management"
start "NIC gRPC" cmd /k "go run ./cmd/."
timeout /t 1 /nobreak >nul

REM Start NIC Management REST API
echo 🔧 Starting NIC Management REST API...
cd /d "%~dp0src\nic_management"
start "NIC API" cmd /k "go run ./api/cmd/."
echo    Waiting for NIC API to start...
timeout /t 3 /nobreak >nul

REM Start React Dev UI
echo 🔧 Starting React Dev UI...
cd /d "%~dp0src\ui\dev"
start "Dev UI" cmd /k "npm run dev"

REM Wait for services to start
echo.
echo ⏳ Waiting for services to initialize...
echo    NIC API should be ready in 3 seconds...
echo    Dev UI should be ready in 10 seconds...
timeout /t 10 /nobreak >nul

REM Open browser
echo 🌐 Opening browser...
start http://localhost:3001/network

echo.
echo ✅ All services started!
echo.
echo 📋 Service Status:
echo    • DHCP Server:       http://localhost:50055 (gRPC)
echo    • NIC Management:    http://localhost:8081/api
echo    • Dev UI:            http://localhost:3001
echo.
echo 🌐 Browser opened at: http://localhost:3001/network
echo.
echo Press any key to stop all services and exit...
pause >nul

REM Kill all service windows
echo.
echo 🛑 Stopping all services...
taskkill /FI "WindowTitle eq DHCP Server*" /F >nul 2>&1
taskkill /FI "WindowTitle eq NIC gRPC*" /F >nul 2>&1
taskkill /FI "WindowTitle eq NIC API*" /F >nul 2>&1
taskkill /FI "WindowTitle eq Dev UI*" /F >nul 2>&1

echo ✅ All services stopped. Goodbye!
timeout /t 2 /nobreak >nul
