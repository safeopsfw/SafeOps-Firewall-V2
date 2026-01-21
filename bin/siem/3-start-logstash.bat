@echo off
:: Auto-elevate to admin
>nul 2>&1 "%SYSTEMROOT%\system32\cacls.exe" "%SYSTEMROOT%\system32\config\system"
if '%errorlevel%' NEQ '0' (
    powershell -Command "Start-Process '%~f0' -Verb RunAs"
    exit /b
)

:: Set ELK installation path
set "ELK_HOME=D:\SafeOps-SIEM-Integration"
set "LOGSTASH_HOME=%ELK_HOME%\logstash\logstash-8.11.3"

title Logstash
echo ============================================
echo   Starting Logstash
echo ============================================
echo.
echo ELK_HOME: %ELK_HOME%
echo.

:: Check if folder exists
if not exist "%LOGSTASH_HOME%" (
    echo [ERROR] Logstash not found at: %LOGSTASH_HOME%
    echo Please run Install-SIEM.ps1 first!
    pause
    exit /b 1
)

cd /d "%LOGSTASH_HOME%\bin"
logstash.bat -f "%LOGSTASH_HOME%\config\logstash.conf"
