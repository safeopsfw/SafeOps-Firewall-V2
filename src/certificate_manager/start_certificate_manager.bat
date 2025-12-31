@echo off
REM ============================================================================
REM SafeOps Certificate Manager - Startup Script (Windows)
REM SSL Interception Support
REM ============================================================================

setlocal enabledelayedexpansion

echo.
echo ========================================================================
echo   SafeOps Certificate Manager - SSL Interception
echo ========================================================================
echo.

REM Check if running as administrator
net session >nul 2>&1
if %errorLevel% neq 0 (
    echo [WARN] Not running as administrator
    echo        Some features may not work properly
    echo.
)

REM Set working directory
cd /d "%~dp0"
echo [INFO] Working directory: %CD%
echo.

REM Create required directories
echo [INFO] Creating directories...
if not exist "certs" mkdir certs
if not exist "keys" mkdir keys
if not exist "logs" mkdir logs
if not exist "backups" mkdir backups
if not exist "config" mkdir config
echo [OK] Directories created
echo.

REM Check if binary exists
if not exist "certificate_manager.exe" (
    echo [INFO] Binary not found, building...
    go build -o certificate_manager.exe cmd\main.go
    if errorlevel 1 (
        echo [ERROR] Build failed!
        pause
        exit /b 1
    )
    echo [OK] Build successful
    echo.
)

REM Check configuration
set CONFIG_FILE=config\templates\ssl_interception.toml
if not exist "%CONFIG_FILE%" (
    set CONFIG_FILE=config\templates\certificate_manager.toml
)

if not exist "%CONFIG_FILE%" (
    echo [ERROR] Configuration file not found!
    echo        Expected: config\templates\ssl_interception.toml
    echo        Or: config\templates\certificate_manager.toml
    pause
    exit /b 1
)

echo [INFO] Using configuration: %CONFIG_FILE%
echo.

REM Check for existing CA
if exist "certs\ca.crt" (
    echo [INFO] Found existing CA certificate: certs\ca.crt

    REM Display CA info
    openssl x509 -in certs\ca.crt -noout -subject -issuer -dates 2>nul
    if errorlevel 1 (
        echo [WARN] Could not read CA certificate with OpenSSL
        echo        OpenSSL may not be installed
    )
    echo.
) else (
    echo [INFO] No existing CA found
    echo [INFO] CA will be auto-generated on first run
    echo.
)

REM Check network configuration
echo [INFO] Network Configuration Check
echo ----------------------------------------
echo.

REM Get network adapters
ipconfig | findstr /C:"IPv4 Address" /C:"Subnet Mask" /C:"Default Gateway"
echo.

echo [INFO] Make sure your firewall IP is correctly set in the config file
echo [INFO] Current config: %CONFIG_FILE%
echo.

REM Firewall check
echo [INFO] Checking firewall rules...
netsh advfirewall firewall show rule name="Certificate Manager HTTP" >nul 2>&1
if errorlevel 1 (
    echo [WARN] Firewall rule not found
    echo [INFO] Adding firewall rules for HTTP (80), gRPC (50060), OCSP (8888)...

    netsh advfirewall firewall add rule name="Certificate Manager HTTP" dir=in action=allow protocol=TCP localport=80 >nul 2>&1
    netsh advfirewall firewall add rule name="Certificate Manager gRPC" dir=in action=allow protocol=TCP localport=50060 >nul 2>&1
    netsh advfirewall firewall add rule name="Certificate Manager OCSP" dir=in action=allow protocol=TCP localport=8888 >nul 2>&1
    netsh advfirewall firewall add rule name="Certificate Manager Metrics" dir=in action=allow protocol=TCP localport=9093 >nul 2>&1

    echo [OK] Firewall rules added
) else (
    echo [OK] Firewall rules already exist
)
echo.

REM Start Certificate Manager
echo ========================================================================
echo   Starting Certificate Manager...
echo ========================================================================
echo.
echo [INFO] Press Ctrl+C to stop the service
echo.

REM Run the service
certificate_manager.exe

REM If service exits
echo.
echo ========================================================================
echo   Certificate Manager stopped
echo ========================================================================
echo.

pause
