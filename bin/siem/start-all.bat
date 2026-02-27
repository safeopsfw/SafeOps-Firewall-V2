@echo off
:: Auto-elevate to admin
>nul 2>&1 "%SYSTEMROOT%\system32\cacls.exe" "%SYSTEMROOT%\system32\config\system"
if '%errorlevel%' NEQ '0' (
    powershell -Command "Start-Process '%~f0' -Verb RunAs"
    exit /b
)

set "SCRIPT_DIR=%~dp0"

echo ============================================
echo   SafeOps SIEM Stack - Starting All
echo ============================================
echo.

echo [1/3] Starting Elasticsearch service...
net start elasticsearch-service-x64 2>nul
if %errorlevel% equ 0 (echo   Started.) else (echo   Already running.)
echo.

echo [2/3] Starting Kibana...
start "Kibana" cmd /c "cd /d D:\SafeOps-SIEM-Integration\kibana\kibana-8.11.3\bin && kibana.bat"
echo   Launching in new window (takes ~60s to initialize)
echo.

echo [3/3] Starting SIEM Forwarder...
start "SafeOps SIEM Forwarder" cmd /c "cd /d D:\SafeOpsFV2\bin\siem-forwarder && siem-forwarder.exe"
echo   Launching in new window (waits for ES automatically)
echo.

echo ============================================
echo   All components launched!
echo ============================================
echo.
echo   Elasticsearch : http://localhost:9200
echo   Kibana        : http://localhost:5601  (wait ~60s)
echo   SIEM Forwarder: tailing logs to ES
echo.
echo   First time? Run 0-setup-elasticsearch-templates.bat
echo ============================================
pause
