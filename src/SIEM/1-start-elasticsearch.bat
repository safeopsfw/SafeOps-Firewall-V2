@echo off
:: Auto-elevate to admin
>nul 2>&1 "%SYSTEMROOT%\system32\cacls.exe" "%SYSTEMROOT%\system32\config\system"
if '%errorlevel%' NEQ '0' (
    powershell -Command "Start-Process '%~f0' -Verb RunAs"
    exit /b
)

:: Set ELK installation path
set "ELK_HOME=D:\SafeOps-SIEM-Integration"
set "ES_HOME=%ELK_HOME%\elasticsearch\elasticsearch-8.11.3"

title Elasticsearch
echo ============================================
echo   Starting Elasticsearch
echo ============================================
echo.
echo ELK_HOME: %ELK_HOME%
echo.

:: Check if folder exists
if not exist "%ES_HOME%" (
    echo [ERROR] Elasticsearch not found at: %ES_HOME%
    echo Please run Install-SIEM.ps1 first!
    pause
    exit /b 1
)

:: Start service
net start elasticsearch-service-x64
echo.
echo Elasticsearch: http://localhost:9200
pause
