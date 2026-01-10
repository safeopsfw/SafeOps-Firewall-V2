@echo off
echo ========================================
echo SafeOps Network Logger - Starter
echo ========================================
echo.
echo [INFO] Starting network packet capture...
echo [INFO] Logs will be saved to: ..\..\logs\
echo [INFO] Press Ctrl+C to stop
echo.
echo ========================================
echo.

REM Check if running as Administrator
net session >nul 2>&1
if %errorLevel% neq 0 (
    echo [ERROR] This program requires Administrator privileges!
    echo.
    echo Right-click this file and select "Run as Administrator"
    echo.
    pause
    exit /b 1
)

REM Ensure bin directory and executable exist
if not exist "bin\safeops-logger.exe" (
    echo [ERROR] Executable not found!
    echo Please run build.bat first to compile the logger.
    echo.
    pause
    exit /b 1
)

REM Start the logger
bin\safeops-logger.exe

pause
