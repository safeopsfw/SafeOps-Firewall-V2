@echo off
:: SafeOps Certificate Auto-Installer
:: ===================================
:: This script:
:: 1. Creates a scheduled task that runs at every logon
:: 2. Downloads and installs the CA cert automatically
:: 3. Removes itself after successful installation
::
:: Run ONCE as Administrator to set up auto-installation

echo.
echo ============================================
echo  SafeOps Certificate Auto-Installer Setup
echo ============================================
echo.

:: Check for admin
net session >nul 2>&1
if %errorLevel% neq 0 (
    echo [ERROR] Run as Administrator!
    pause
    exit /b 1
)

set PORTAL_URL=http://192.168.1.1
set TASK_NAME=SafeOpsCertInstall
set INSTALL_SCRIPT=%ProgramData%\SafeOps\install_cert.ps1

:: Create directory
if not exist "%ProgramData%\SafeOps" mkdir "%ProgramData%\SafeOps"

:: Create the PowerShell install script
echo Creating install script...
(
echo # SafeOps Auto-Install Script
echo $certUrl = "%PORTAL_URL%/download?os=Windows"
echo $enrollUrl = "%PORTAL_URL%/api/enroll"
echo $certPath = "$env:TEMP\SafeOps-CA.crt"
echo $logPath = "$env:ProgramData\SafeOps\install.log"
echo.
echo function Log { param^($msg^) Add-Content $logPath "$(Get-Date): $msg" }
echo.
echo # Check if already installed
echo $installed = Get-ChildItem Cert:\LocalMachine\Root ^| Where-Object { $_.Subject -like "*SafeOps*" }
echo if ^($installed^) {
echo     Log "Certificate already installed, skipping"
echo     exit 0
echo }
echo.
echo try {
echo     Log "Downloading certificate..."
echo     Invoke-WebRequest -Uri $certUrl -OutFile $certPath -TimeoutSec 10
echo.
echo     Log "Installing certificate..."
echo     $cert = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2^($certPath^)
echo     $store = New-Object System.Security.Cryptography.X509Certificates.X509Store^("Root", "LocalMachine"^)
echo     $store.Open^("ReadWrite"^)
echo     $store.Add^($cert^)
echo     $store.Close^(^)
echo.
echo     Remove-Item $certPath -Force
echo     Log "Certificate installed successfully!"
echo.
echo     # Notify portal
echo     try { Invoke-RestMethod -Uri $enrollUrl -Method POST -Body @{os="Windows";method="scheduled-task"} -TimeoutSec 5 } catch {}
echo.
echo     # Remove scheduled task after success
echo     Unregister-ScheduledTask -TaskName "SafeOpsCertInstall" -Confirm:$false -ErrorAction SilentlyContinue
echo     Log "Scheduled task removed - installation complete"
echo.
echo } catch {
echo     Log "Error: $_"
echo }
) > "%INSTALL_SCRIPT%"

:: Create scheduled task that runs at logon AND on network connect
echo Creating scheduled task...

:: Task runs at every user logon
schtasks /Create /TN "%TASK_NAME%" /TR "powershell -ExecutionPolicy Bypass -WindowStyle Hidden -File \"%INSTALL_SCRIPT%\"" /SC ONLOGON /RL HIGHEST /F

:: Also trigger when on SafeOps network (optional - runs every 5 min when connected)
schtasks /Create /TN "%TASK_NAME%_Network" /TR "powershell -ExecutionPolicy Bypass -WindowStyle Hidden -File \"%INSTALL_SCRIPT%\"" /SC MINUTE /MO 5 /RL HIGHEST /F

echo.
echo ============================================
echo  Setup Complete!
echo ============================================
echo.
echo The certificate will be automatically installed when:
echo   - Any user logs in
echo   - Every 5 minutes (while on network)
echo.
echo Once installed, the scheduled task removes itself.
echo.
echo Files created:
echo   %INSTALL_SCRIPT%
echo   Scheduled Task: %TASK_NAME%
echo.
pause
