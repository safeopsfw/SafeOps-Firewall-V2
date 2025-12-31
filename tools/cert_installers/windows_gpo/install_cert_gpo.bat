@echo off
:: SafeOps CA Certificate GPO Startup Script
:: Deploy via: Computer Configuration > Policies > Windows Settings > Scripts > Startup
:: Copy this file and ca.crt to \\domain\NETLOGON\SafeOps\

set CERT_PATH=\\%USERDNSDOMAIN%\NETLOGON\SafeOps\SafeOps-CA.crt
set LOG_PATH=%TEMP%\safeops_cert_install.log

echo [%DATE% %TIME%] SafeOps Certificate Install Starting >> "%LOG_PATH%"

:: Check if already installed
certutil -store Root | findstr /C:"SafeOps" >nul 2>&1
if %errorlevel% equ 0 (
    echo [%DATE% %TIME%] Certificate already installed, skipping >> "%LOG_PATH%"
    exit /b 0
)

:: Check if cert file exists
if not exist "%CERT_PATH%" (
    echo [%DATE% %TIME%] Certificate file not found: %CERT_PATH% >> "%LOG_PATH%"
    exit /b 1
)

:: Install certificate
certutil -addstore -f "Root" "%CERT_PATH%" >> "%LOG_PATH%" 2>&1

if %errorlevel% equ 0 (
    echo [%DATE% %TIME%] Certificate installed successfully >> "%LOG_PATH%"
) else (
    echo [%DATE% %TIME%] Certificate installation failed >> "%LOG_PATH%"
)

exit /b %errorlevel%
