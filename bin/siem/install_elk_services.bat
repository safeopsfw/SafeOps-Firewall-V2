@echo off
title SafeOps ELK Stack - Installation
color 0A
echo ╔═══════════════════════════════════════════════════════════════╗
echo ║           SafeOps ELK Stack - Service Installation            ║
echo ╚═══════════════════════════════════════════════════════════════╝
echo.

:: Check for admin
net session >nul 2>&1
if %errorLevel% neq 0 (
    echo [ERROR] Please run this script as Administrator!
    echo Right-click and select "Run as administrator"
    pause
    exit /b 1
)

echo [1/4] Installing Elasticsearch as Windows Service...
cd /d "D:\SafeOps-SIEM-Integration\elasticsearch\elasticsearch-8.11.3\bin"
call elasticsearch-service.bat install
timeout /t 2 /nobreak >nul

echo.
echo [2/4] Configuring Elasticsearch for delayed auto-start...
sc config "elasticsearch-service-x64" start= delayed-auto
timeout /t 1 /nobreak >nul

echo.
echo [3/4] Creating startup shortcut for Kibana and Logstash...
:: Create VBS script to make shortcut
echo Set oWS = WScript.CreateObject("WScript.Shell") > "%TEMP%\CreateShortcut.vbs"
echo sLinkFile = oWS.SpecialFolders("Startup") ^& "\SafeOps-ELK.lnk" >> "%TEMP%\CreateShortcut.vbs"
echo Set oLink = oWS.CreateShortcut(sLinkFile) >> "%TEMP%\CreateShortcut.vbs"
echo oLink.TargetPath = "D:\SafeOps-SIEM-Integration\scripts\start-all.bat" >> "%TEMP%\CreateShortcut.vbs"
echo oLink.WorkingDirectory = "D:\SafeOps-SIEM-Integration\scripts" >> "%TEMP%\CreateShortcut.vbs"
echo oLink.Description = "SafeOps ELK Stack" >> "%TEMP%\CreateShortcut.vbs"
echo oLink.Save >> "%TEMP%\CreateShortcut.vbs"
cscript //nologo "%TEMP%\CreateShortcut.vbs"
del "%TEMP%\CreateShortcut.vbs"

echo.
echo [4/4] Verifying installation...
sc query "elasticsearch-service-x64" | findstr "STATE"

echo.
echo ╔═══════════════════════════════════════════════════════════════╗
echo ║              Installation Complete!                           ║
echo ╚═══════════════════════════════════════════════════════════════╝
echo.
echo Startup Configuration:
echo   - Elasticsearch: Windows Service (Delayed Auto-Start)
echo   - Kibana + Logstash: Startup folder shortcut
echo.
echo To start now, run: D:\SafeOps-SIEM-Integration\scripts\start-all.bat
echo.
pause
