# SafeOps ELK Stack - Setup and Startup Script
# Run this script as Administrator
# This will install Elasticsearch as a service and create startup tasks for Kibana/Logstash

param(
    [switch]$Install,
    [switch]$Start,
    [switch]$Stop
)

$ErrorActionPreference = "Continue"

# Paths
$ELK_ROOT = "D:\SafeOps-SIEM-Integration"
$ES_HOME = "$ELK_ROOT\elasticsearch\elasticsearch-8.11.3"
$KIBANA_HOME = "$ELK_ROOT\kibana\kibana-8.11.3"
$LOGSTASH_HOME = "$ELK_ROOT\logstash\logstash-8.11.3"

Write-Host "╔═══════════════════════════════════════════════════════════════╗" -ForegroundColor Cyan
Write-Host "║           SafeOps ELK Stack - Setup & Startup                 ║" -ForegroundColor Cyan
Write-Host "╚═══════════════════════════════════════════════════════════════╝" -ForegroundColor Cyan
Write-Host ""

# Check if running as admin
$isAdmin = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $isAdmin) {
    Write-Host "[ERROR] This script requires Administrator privileges!" -ForegroundColor Red
    Write-Host "Please right-click and 'Run as Administrator'" -ForegroundColor Yellow
    pause
    exit 1
}

function Install-ElasticsearchService {
    Write-Host "`n[1/3] Installing Elasticsearch as Windows Service..." -ForegroundColor Yellow
    
    $esBat = "$ES_HOME\bin\elasticsearch-service.bat"
    if (Test-Path $esBat) {
        # Install the service
        Push-Location "$ES_HOME\bin"
        & cmd /c "elasticsearch-service.bat install"
        Pop-Location
        
        # Configure for delayed auto-start (low priority at boot)
        Start-Sleep -Seconds 2
        sc.exe config "elasticsearch-service-x64" start= delayed-auto
        
        Write-Host "  [OK] Elasticsearch service installed with delayed auto-start" -ForegroundColor Green
    } else {
        Write-Host "  [ERROR] Elasticsearch not found at: $ES_HOME" -ForegroundColor Red
    }
}

function Install-KibanaStartup {
    Write-Host "`n[2/3] Setting up Kibana startup task..." -ForegroundColor Yellow
    
    $kibanaBat = "$KIBANA_HOME\bin\kibana.bat"
    if (Test-Path $kibanaBat) {
        # Create a scheduled task for Kibana (runs at login with delay)
        $taskName = "SafeOps-Kibana"
        $action = New-ScheduledTaskAction -Execute "cmd.exe" -Argument "/c `"$kibanaBat`"" -WorkingDirectory "$KIBANA_HOME\bin"
        $trigger = New-ScheduledTaskTrigger -AtStartup
        $trigger.Delay = "PT2M"  # 2 minute delay after boot
        $settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -StartWhenAvailable -ExecutionTimeLimit (New-TimeSpan -Hours 0)
        $principal = New-ScheduledTaskPrincipal -UserId "SYSTEM" -LogonType ServiceAccount -RunLevel Highest
        
        # Remove existing task if present
        Unregister-ScheduledTask -TaskName $taskName -Confirm:$false -ErrorAction SilentlyContinue
        
        # Create new task
        Register-ScheduledTask -TaskName $taskName -Action $action -Trigger $trigger -Settings $settings -Principal $principal -Description "SafeOps Kibana Dashboard" | Out-Null
        
        Write-Host "  [OK] Kibana scheduled task created (starts 2 min after boot)" -ForegroundColor Green
    } else {
        Write-Host "  [ERROR] Kibana not found at: $KIBANA_HOME" -ForegroundColor Red
    }
}

function Install-LogstashStartup {
    Write-Host "`n[3/3] Setting up Logstash startup task..." -ForegroundColor Yellow
    
    $logstashBat = "$LOGSTASH_HOME\bin\logstash.bat"
    if (Test-Path $logstashBat) {
        # Create a scheduled task for Logstash (runs at login with delay)
        $taskName = "SafeOps-Logstash"
        $action = New-ScheduledTaskAction -Execute "cmd.exe" -Argument "/c `"$logstashBat`" -f `"$LOGSTASH_HOME\config\pipeline`"" -WorkingDirectory "$LOGSTASH_HOME\bin"
        $trigger = New-ScheduledTaskTrigger -AtStartup
        $trigger.Delay = "PT3M"  # 3 minute delay (after Elasticsearch starts)
        $settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -StartWhenAvailable -ExecutionTimeLimit (New-TimeSpan -Hours 0)
        $principal = New-ScheduledTaskPrincipal -UserId "SYSTEM" -LogonType ServiceAccount -RunLevel Highest
        
        # Remove existing task if present
        Unregister-ScheduledTask -TaskName $taskName -Confirm:$false -ErrorAction SilentlyContinue
        
        # Create new task
        Register-ScheduledTask -TaskName $taskName -Action $action -Trigger $trigger -Settings $settings -Principal $principal -Description "SafeOps Logstash Pipeline" | Out-Null
        
        Write-Host "  [OK] Logstash scheduled task created (starts 3 min after boot)" -ForegroundColor Green
    } else {
        Write-Host "  [ERROR] Logstash not found at: $LOGSTASH_HOME" -ForegroundColor Red
    }
}

function Start-ELKStack {
    Write-Host "`n[Starting ELK Stack...]" -ForegroundColor Cyan
    
    # Start Elasticsearch service
    Write-Host "  Starting Elasticsearch..." -ForegroundColor Yellow
    Start-Service -Name "elasticsearch-service-x64" -ErrorAction SilentlyContinue
    
    Write-Host "  Waiting 30 seconds for Elasticsearch to start..." -ForegroundColor Gray
    Start-Sleep -Seconds 30
    
    # Start Kibana in new window
    Write-Host "  Starting Kibana..." -ForegroundColor Yellow
    Start-Process -FilePath "cmd.exe" -ArgumentList "/k", "title Kibana && cd /d `"$KIBANA_HOME\bin`" && kibana.bat"
    
    Start-Sleep -Seconds 5
    
    # Start Logstash in new window
    Write-Host "  Starting Logstash..." -ForegroundColor Yellow
    Start-Process -FilePath "cmd.exe" -ArgumentList "/k", "title Logstash && cd /d `"$LOGSTASH_HOME\bin`" && logstash.bat -f `"$LOGSTASH_HOME\config\pipeline`""
    
    Write-Host "`n[OK] ELK Stack starting!" -ForegroundColor Green
    Write-Host "  Elasticsearch: http://localhost:9200" -ForegroundColor Cyan
    Write-Host "  Kibana:        http://localhost:5601" -ForegroundColor Cyan
}

function Stop-ELKStack {
    Write-Host "`n[Stopping ELK Stack...]" -ForegroundColor Cyan
    
    # Stop processes
    Stop-Process -Name "java" -Force -ErrorAction SilentlyContinue
    Stop-Process -Name "node" -Force -ErrorAction SilentlyContinue
    Stop-Service -Name "elasticsearch-service-x64" -Force -ErrorAction SilentlyContinue
    
    Write-Host "[OK] ELK Stack stopped" -ForegroundColor Green
}

# Main logic
if ($Install -or (-not $Install -and -not $Start -and -not $Stop)) {
    Write-Host "Installing ELK Stack services and startup tasks..." -ForegroundColor Cyan
    Install-ElasticsearchService
    Install-KibanaStartup
    Install-LogstashStartup
    
    Write-Host "`n╔═══════════════════════════════════════════════════════════════╗" -ForegroundColor Green
    Write-Host "║           Installation Complete!                              ║" -ForegroundColor Green
    Write-Host "╚═══════════════════════════════════════════════════════════════╝" -ForegroundColor Green
    Write-Host ""
    Write-Host "Startup Configuration:" -ForegroundColor Yellow
    Write-Host "  • Elasticsearch: Windows Service (Delayed Auto-Start)" -ForegroundColor White
    Write-Host "  • Kibana: Scheduled Task (2 min delay)" -ForegroundColor White
    Write-Host "  • Logstash: Scheduled Task (3 min delay)" -ForegroundColor White
    Write-Host ""
    Write-Host "To start now, run: .\setup_elk_services.ps1 -Start" -ForegroundColor Cyan
}

if ($Start) {
    Start-ELKStack
}

if ($Stop) {
    Stop-ELKStack
}

Write-Host ""
Write-Host "Press any key to exit..." -ForegroundColor Gray
$null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
