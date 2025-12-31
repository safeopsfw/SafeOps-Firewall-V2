# View All Logs in Windows Terminal or Separate Windows
# Location: D:\SafeOpsFV2\view_all_logs.ps1

$logPath = "$PSScriptRoot\logs"

Write-Host ""
Write-Host "========================================================================" -ForegroundColor Cyan
Write-Host "  SafeOps Log Viewer" -ForegroundColor Cyan
Write-Host "========================================================================" -ForegroundColor Cyan
Write-Host ""

# Check if logs directory exists
if (-not (Test-Path $logPath)) {
    Write-Host "[ERROR] Logs directory not found: $logPath" -ForegroundColor Red
    Write-Host "Have you started the services yet?" -ForegroundColor Yellow
    Write-Host ""
    pause
    exit 1
}

# Check if Windows Terminal is installed
$wtExists = Get-Command wt -ErrorAction SilentlyContinue

if ($wtExists) {
    Write-Host "Opening logs in Windows Terminal..." -ForegroundColor Green
    Write-Host ""

    # Use Windows Terminal with tabs
    wt `
      new-tab --title "Cert Manager" powershell -NoExit -Command "Write-Host 'Certificate Manager Logs' -ForegroundColor Cyan; Write-Host '========================================' -ForegroundColor Gray; Write-Host ''; Get-Content $logPath\certificate_manager.log -Wait -Tail 100 -ErrorAction SilentlyContinue" `; `
      new-tab --title "DHCP" powershell -NoExit -Command "Write-Host 'DHCP Server Logs' -ForegroundColor Green; Write-Host '========================================' -ForegroundColor Gray; Write-Host ''; Get-Content $logPath\dhcp_server.log -Wait -Tail 100 -ErrorAction SilentlyContinue" `; `
      new-tab --title "DNS" powershell -NoExit -Command "Write-Host 'DNS Server Logs' -ForegroundColor Yellow; Write-Host '========================================' -ForegroundColor Gray; Write-Host ''; Get-Content $logPath\dns_server.log -Wait -Tail 100 -ErrorAction SilentlyContinue" `; `
      new-tab --title "Captive Portal" powershell -NoExit -Command "Write-Host 'Captive Portal Logs' -ForegroundColor Magenta; Write-Host '========================================' -ForegroundColor Gray; Write-Host ''; Get-Content $logPath\captive_portal.log -Wait -Tail 100 -ErrorAction SilentlyContinue" `; `
      new-tab --title "Dashboard" powershell -NoExit -Command "Write-Host 'Dashboard Logs' -ForegroundColor Blue; Write-Host '========================================' -ForegroundColor Gray; Write-Host ''; Get-Content $logPath\dashboard.log -Wait -Tail 100 -ErrorAction SilentlyContinue" `; `
      new-tab --title "All Logs" powershell -NoExit -Command "Write-Host 'All Logs (Combined)' -ForegroundColor White; Write-Host '========================================' -ForegroundColor Gray; Write-Host ''; Get-Content $logPath\*.log -Wait -Tail 50 -ErrorAction SilentlyContinue"

} else {
    Write-Host "Windows Terminal not found. Opening separate PowerShell windows..." -ForegroundColor Yellow
    Write-Host ""

    # Fallback: Open separate PowerShell windows
    Start-Process powershell -ArgumentList "-NoExit", "-Command", "Write-Host 'Certificate Manager Logs' -ForegroundColor Cyan; Write-Host '========================================'; Write-Host ''; Get-Content $logPath\certificate_manager.log -Wait -Tail 100 -ErrorAction SilentlyContinue"

    Start-Process powershell -ArgumentList "-NoExit", "-Command", "Write-Host 'DHCP Server Logs' -ForegroundColor Green; Write-Host '========================================'; Write-Host ''; Get-Content $logPath\dhcp_server.log -Wait -Tail 100 -ErrorAction SilentlyContinue"

    Start-Process powershell -ArgumentList "-NoExit", "-Command", "Write-Host 'DNS Server Logs' -ForegroundColor Yellow; Write-Host '========================================'; Write-Host ''; Get-Content $logPath\dns_server.log -Wait -Tail 100 -ErrorAction SilentlyContinue"

    Start-Process powershell -ArgumentList "-NoExit", "-Command", "Write-Host 'Captive Portal Logs' -ForegroundColor Magenta; Write-Host '========================================'; Write-Host ''; Get-Content $logPath\captive_portal.log -Wait -Tail 100 -ErrorAction SilentlyContinue"

    Start-Process powershell -ArgumentList "-NoExit", "-Command", "Write-Host 'Dashboard Logs' -ForegroundColor Blue; Write-Host '========================================'; Write-Host ''; Get-Content $logPath\dashboard.log -Wait -Tail 100 -ErrorAction SilentlyContinue"

    Write-Host "Opened 5 log windows" -ForegroundColor Green
}

Write-Host ""
