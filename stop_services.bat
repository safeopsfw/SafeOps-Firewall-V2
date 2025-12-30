@echo off
echo =============================================
echo     SafeOps Services Stopper
echo =============================================
echo.

echo Stopping Certificate Manager...
taskkill /IM certificate_manager.exe /F 2>nul
if %errorlevel% equ 0 (echo   Stopped) else (echo   Not running)

echo Stopping DHCP Server...
taskkill /IM dhcp_server.exe /F 2>nul
if %errorlevel% equ 0 (echo   Stopped) else (echo   Not running)

echo Stopping NIC Management...
taskkill /IM nic_management.exe /F 2>nul
if %errorlevel% equ 0 (echo   Stopped) else (echo   Not running)

echo.
echo All services stopped.
pause
