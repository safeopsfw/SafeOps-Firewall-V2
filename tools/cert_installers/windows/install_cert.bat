@echo off
:: SafeOps CA Certificate Installer for Windows
:: This script installs the CA certificate to the Trusted Root store

echo.
echo  ============================================
echo   SafeOps CA Certificate Installer
echo  ============================================
echo.

:: Check for admin rights
net session >nul 2>&1
if %errorLevel% neq 0 (
    echo [ERROR] Administrator privileges required!
    echo         Right-click and "Run as administrator"
    echo.
    pause
    exit /b 1
)

:: Set certificate path
set CERT_FILE=%~dp0SafeOps-CA.crt

:: Check if cert exists
if not exist "%CERT_FILE%" (
    echo [ERROR] Certificate file not found: %CERT_FILE%
    echo         Please ensure SafeOps-CA.crt is in the same folder as this script.
    echo.
    pause
    exit /b 1
)

echo [1/3] Installing certificate to Trusted Root store...

:: Install certificate using certutil
certutil -addstore -f "Root" "%CERT_FILE%"

if %errorLevel% equ 0 (
    echo.
    echo [2/3] Certificate installed successfully!
    echo.
    echo [3/3] Verifying installation...
    certutil -verify "%CERT_FILE%" >nul 2>&1
    echo.
    echo  ============================================
    echo   SUCCESS! SafeOps CA Certificate Installed
    echo  ============================================
    echo.
    echo   Your device is now configured for secure browsing.
    echo   You can close this window.
    echo.
) else (
    echo.
    echo [ERROR] Failed to install certificate!
    echo         Error code: %errorLevel%
    echo.
)

pause
