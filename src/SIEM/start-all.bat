@echo off
:: Auto-elevate to admin
>nul 2>&1 "%SYSTEMROOT%\system32\cacls.exe" "%SYSTEMROOT%\system32\config\system"
if '%errorlevel%' NEQ '0' (
    powershell -Command "Start-Process '%~f0' -Verb RunAs"
    exit /b
)

:: Get script directory
set "SCRIPT_DIR=%~dp0"

echo ============================================
echo   Starting SafeOps ELK Stack
echo ============================================
echo.

:: Launch all 3 in separate windows
start "Elasticsearch" cmd /c "%SCRIPT_DIR%1-start-elasticsearch.bat"
start "Kibana" cmd /c "%SCRIPT_DIR%2-start-kibana.bat"
start "Logstash" cmd /c "%SCRIPT_DIR%3-start-logstash.bat"

echo All components launching in separate windows!
echo.
echo   Elasticsearch: http://localhost:9200
echo   Kibana:        http://localhost:5601
echo.
pause
