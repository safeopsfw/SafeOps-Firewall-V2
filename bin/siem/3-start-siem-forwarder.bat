@echo off
title SafeOps SIEM Forwarder
echo ============================================
echo   Starting SIEM Forwarder
echo ============================================
echo.
echo Tailing SafeOps logs and shipping to Elasticsearch
echo.

set "FORWARDER_HOME=D:\SafeOpsFV2\bin\siem-forwarder"

if not exist "%FORWARDER_HOME%\siem-forwarder.exe" (
    echo [ERROR] SIEM Forwarder not found at: %FORWARDER_HOME%
    echo Please build siem-forwarder.exe first!
    pause
    exit /b 1
)

cd /d "%FORWARDER_HOME%"
siem-forwarder.exe
