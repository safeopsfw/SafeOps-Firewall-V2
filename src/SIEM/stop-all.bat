@echo off
:: Auto-elevate to admin
>nul 2>&1 "%SYSTEMROOT%\system32\cacls.exe" "%SYSTEMROOT%\system32\config\system"
if '%errorlevel%' NEQ '0' (
    powershell -Command "Start-Process '%~f0' -Verb RunAs"
    exit /b
)

echo ============================================
echo   SafeOps SIEM Stack - Stopping All
echo ============================================
echo.

echo [1/3] Stopping SIEM Forwarder...
taskkill /FI "WINDOWTITLE eq SafeOps SIEM Forwarder*" /F 2>nul
taskkill /IM "siem-forwarder.exe" /F 2>nul
echo   Done.
echo.

echo [2/3] Stopping Kibana...
taskkill /FI "WINDOWTITLE eq Kibana*" /F 2>nul
taskkill /IM "node.exe" /F 2>nul
echo   Done.
echo.

echo [3/3] Stopping Elasticsearch...
net stop elasticsearch-service-x64 2>nul
echo   Done.
echo.

echo ============================================
echo   SIEM Stack stopped.
echo ============================================
pause
