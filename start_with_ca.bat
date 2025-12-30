@echo off
REM SafeOps Complete Suite - With Certificate Manager
REM Starts Certificate Manager + DHCP Server + NIC API + Dev UI

title SafeOps - Complete Suite with CA

REM Check for admin privileges
net session >nul 2>&1
if %errorlevel% neq 0 (
    echo ⚠️  Requesting administrator privileges...
    echo    DHCP and Hotspot require admin rights
    echo.
    powershell -Command "Start-Process '%~f0' -Verb RunAs"
    exit /b
)

echo.
echo ╔═══════════════════════════════════════════════════════════════╗
echo ║         SafeOps - Complete Network Suite with CA             ║
echo ║           Starting All Services + Certificate Manager         ║
echo ║              ✅ Running as Administrator                       ║
echo ╚═══════════════════════════════════════════════════════════════╝
echo.

REM Start Certificate Manager FIRST (DHCP depends on it)
echo 🔐 Starting Certificate Manager...
cd /d "%~dp0src\certificate_manager"
start "Certificate Manager" cmd /k "go run ./cmd/."
echo    Waiting for Certificate Manager to initialize...
timeout /t 5 /nobreak >nul

REM Start DHCP Server (connects to Certificate Manager)
echo 🔧 Starting DHCP Server...
cd /d "%~dp0src\dhcp_server"
start "DHCP Server" cmd /k "go run ./cmd/."
echo    Waiting for DHCP Server to connect to CA...
timeout /t 3 /nobreak >nul

REM Start NIC Management API
echo 🔧 Starting NIC Management API...
cd /d "%~dp0src\nic_management\api"
start "NIC API" cmd /k "go run cmd/main.go"
echo    Waiting for NIC API to start...
timeout /t 3 /nobreak >nul

REM Start React Dev UI
echo 🌐 Starting React Dev UI...
cd /d "%~dp0src\ui\dev"
start "Dev UI" cmd /k "npm run dev"

REM Wait for all services
echo.
echo ⏳ Waiting for all services to initialize...
timeout /t 10 /nobreak >nul

REM Open browser
echo 🌐 Opening browser...
start http://localhost:3001/network

echo.
echo ✅ All services started!
echo.
echo 📋 Service Status:
echo    • Certificate Manager: http://localhost:8093 (gRPC: 50053)
echo    • DHCP Server:         Port 67 UDP (gRPC: 50054)
echo    • NIC Management:      http://localhost:8081/api
echo    • Dev UI:              http://localhost:3001
echo.
echo 🔐 Certificate Distribution:
echo    • CA Certificate:      http://localhost:8093/ca.crt
echo    • Android Install:     http://localhost:8093/android
echo    • Linux Install:       http://localhost:8093/linux
echo    • Windows Install:     http://localhost:8093/windows
echo.
echo 🌐 Browser opened at: http://localhost:3001/network
echo.
echo 📱 TESTING:
echo    1. Enable hotspot in UI
echo    2. Connect Android/Kali Linux
echo    3. Devices auto-redirected to CA install
echo    4. CA installs automatically
echo.
echo Press any key to stop all services and exit...
pause >nul

REM Kill all service windows
echo.
echo 🛑 Stopping all services...
taskkill /FI "WindowTitle eq Certificate Manager*" /F >nul 2>&1
taskkill /FI "WindowTitle eq DHCP Server*" /F >nul 2>&1
taskkill /FI "WindowTitle eq NIC API*" /F >nul 2>&1
taskkill /FI "WindowTitle eq Dev UI*" /F >nul 2>&1

echo ✅ All services stopped. Goodbye!
timeout /t 2 /nobreak >nul
