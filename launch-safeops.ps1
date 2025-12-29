# SafeOps Network Management Suite - PowerShell Launcher
# Starts DHCP Server + NIC API + Dev UI + Opens Browser

$host.UI.RawUI.WindowTitle = "SafeOps - Network Management Suite"

Write-Host ""
Write-Host "╔═══════════════════════════════════════════════════════╗" -ForegroundColor Cyan
Write-Host "║           SafeOps - Network Management Suite         ║" -ForegroundColor Cyan
Write-Host "║              Starting All Services...                ║" -ForegroundColor Cyan
Write-Host "╚═══════════════════════════════════════════════════════╝" -ForegroundColor Cyan
Write-Host ""

# Check for admin privileges
$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $isAdmin) {
    Write-Host "⚠️  Warning: Not running as administrator" -ForegroundColor Yellow
    Write-Host "   Some features may require admin privileges" -ForegroundColor Yellow
    Write-Host ""
    Start-Sleep -Seconds 1
}

# Get script directory
$scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path

# Array to track processes
$global:processes = @()

# Function to start a service
function Start-Service {
    param(
        [string]$Name,
        [string]$WorkingDir,
        [string]$Command,
        [string[]]$Arguments
    )

    Write-Host "🔧 Starting $Name..." -ForegroundColor Green

    $psi = New-Object System.Diagnostics.ProcessStartInfo
    $psi.FileName = $Command
    $psi.Arguments = $Arguments -join " "
    $psi.WorkingDirectory = Join-Path $scriptDir $WorkingDir
    $psi.UseShellExecute = $true
    $psi.WindowStyle = "Normal"

    try {
        $process = [System.Diagnostics.Process]::Start($psi)
        $global:processes += $process
        Write-Host "   ✅ $Name started (PID: $($process.Id))" -ForegroundColor Green
        return $true
    }
    catch {
        Write-Host "   ❌ Failed to start $Name : $_" -ForegroundColor Red
        return $false
    }
}

# Cleanup function
function Stop-AllServices {
    Write-Host ""
    Write-Host "🛑 Stopping all services..." -ForegroundColor Yellow

    foreach ($proc in $global:processes) {
        if ($proc -and -not $proc.HasExited) {
            Write-Host "   Stopping PID $($proc.Id)..." -ForegroundColor Yellow
            try {
                $proc.Kill()
                $proc.WaitForExit(5000)
            }
            catch {
                Write-Host "   Warning: Could not stop PID $($proc.Id)" -ForegroundColor Yellow
            }
        }
    }

    Write-Host "✅ All services stopped. Goodbye!" -ForegroundColor Green
}

# Register cleanup on exit
Register-EngineEvent -SourceIdentifier PowerShell.Exiting -Action {
    Stop-AllServices
}

# Start DHCP Server (optional)
$dhcpStarted = Start-Service -Name "DHCP Server" `
    -WorkingDir "src\dhcp_server" `
    -Command "go" `
    -Arguments @("run", "cmd/main.go")

Start-Sleep -Seconds 1

# Start NIC Management API
$nicStarted = Start-Service -Name "NIC Management API" `
    -WorkingDir "src\nic_management\api" `
    -Command "go" `
    -Arguments @("run", "cmd/main.go")

Start-Sleep -Seconds 1

# Start React Dev UI
$uiStarted = Start-Service -Name "React Dev UI" `
    -WorkingDir "src\ui\dev" `
    -Command "npm" `
    -Arguments @("run", "dev")

# Wait for services to initialize
Write-Host ""
Write-Host "⏳ Waiting for services to initialize..." -ForegroundColor Cyan
Start-Sleep -Seconds 4

# Open browser
Write-Host "🌐 Opening browser..." -ForegroundColor Cyan
Start-Process "http://localhost:5173/nic-management"

# Display status
Write-Host ""
Write-Host "✅ All services running!" -ForegroundColor Green
Write-Host ""
Write-Host "📋 Service Status:" -ForegroundColor Cyan
Write-Host "   • DHCP Server:       http://localhost:50054 (gRPC)"
Write-Host "   • NIC Management:    http://localhost:8081/api"
Write-Host "   • Dev UI:            http://localhost:5173"
Write-Host ""
Write-Host "🌐 Browser opened at: http://localhost:5173/nic-management" -ForegroundColor Green
Write-Host ""
Write-Host "Press Ctrl+C to stop all services..." -ForegroundColor Yellow
Write-Host ""

# Wait for Ctrl+C
try {
    while ($true) {
        Start-Sleep -Seconds 1
    }
}
finally {
    Stop-AllServices
}
