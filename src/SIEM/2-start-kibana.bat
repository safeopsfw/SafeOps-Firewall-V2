@echo off
:: Auto-elevate to admin
>nul 2>&1 "%SYSTEMROOT%\system32\cacls.exe" "%SYSTEMROOT%\system32\config\system"
if '%errorlevel%' NEQ '0' (
    powershell -Command "Start-Process '%~f0' -Verb RunAs"
    exit /b
)

:: Set ELK installation path
set "ELK_HOME=D:\SafeOps-SIEM-Integration"
set "KIBANA_HOME=%ELK_HOME%\kibana\kibana-8.11.3"

title Kibana
echo ============================================
echo   Starting Kibana
echo ============================================
echo.
echo ELK_HOME: %ELK_HOME%
echo.

:: Check if folder exists
if not exist "%KIBANA_HOME%" (
    echo [ERROR] Kibana not found at: %KIBANA_HOME%
    echo Please run Install-SIEM.ps1 first!
    pause
    exit /b 1
)

cd /d "%KIBANA_HOME%\bin"
echo Access: http://localhost:5601
echo.
kibana.bat
