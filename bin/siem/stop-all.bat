@echo off
:: Auto-elevate to admin
>nul 2>&1 "%SYSTEMROOT%\system32\cacls.exe" "%SYSTEMROOT%\system32\config\system"
if '%errorlevel%' NEQ '0' (
    powershell -Command "Start-Process '%~f0' -Verb RunAs"
    exit /b
)

echo ============================================
echo   Stopping SafeOps ELK Stack
echo ============================================
echo.

:: Stop Elasticsearch service
net stop elasticsearch-service-x64 2>nul

:: Kill Kibana and Logstash windows
taskkill /FI "WINDOWTITLE eq Kibana*" /F 2>nul
taskkill /FI "WINDOWTITLE eq Logstash*" /F 2>nul

echo.
echo ELK Stack stopped.
pause
