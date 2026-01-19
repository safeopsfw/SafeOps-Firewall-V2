# SafeOps Engine - Windows Service Installer
# Requires Administrator privileges

param(
    [switch]$Uninstall
)

$serviceName = "SafeOpsEngine"
$serviceDisplayName = "SafeOps Network Security Engine"
$serviceDescription = "SafeOps network security monitoring and filtering engine with DNS proxy and inline packet inspection"
$exePath = "D:\SafeOpsFV2\src\safeops-engine\safeops-engine.exe"
$workingDir = "D:\SafeOpsFV2"

# Check for admin privileges
if (-NOT ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) {
    Write-Error "This script must be run as Administrator!"
    exit 1
}

if ($Uninstall) {
    Write-Host "Uninstalling SafeOps Engine service..." -ForegroundColor Yellow

    # Stop service if running
    $service = Get-Service -Name $serviceName -ErrorAction SilentlyContinue
    if ($service) {
        if ($service.Status -eq "Running") {
            Write-Host "Stopping service..." -ForegroundColor Yellow
            Stop-Service -Name $serviceName -Force
            Start-Sleep -Seconds 2
        }

        Write-Host "Removing service..." -ForegroundColor Yellow
        sc.exe delete $serviceName

        if ($LASTEXITCODE -eq 0) {
            Write-Host "Service uninstalled successfully!" -ForegroundColor Green
        } else {
            Write-Error "Failed to remove service (exit code: $LASTEXITCODE)"
        }
    } else {
        Write-Host "Service not found, nothing to uninstall." -ForegroundColor Yellow
    }

    exit 0
}

# Install service
Write-Host "Installing SafeOps Engine as Windows Service..." -ForegroundColor Cyan

# Check if executable exists
if (-not (Test-Path $exePath)) {
    Write-Error "Executable not found at: $exePath"
    Write-Host "Please build the engine first: cd src/safeops-engine && go build -o safeops-engine.exe ./cmd" -ForegroundColor Yellow
    exit 1
}

# Check if service already exists
$existingService = Get-Service -Name $serviceName -ErrorAction SilentlyContinue
if ($existingService) {
    Write-Host "Service already exists. Stopping and removing..." -ForegroundColor Yellow

    if ($existingService.Status -eq "Running") {
        Stop-Service -Name $serviceName -Force
        Start-Sleep -Seconds 2
    }

    sc.exe delete $serviceName
    Start-Sleep -Seconds 1
}

# Create service using NSSM (Non-Sucking Service Manager) if available
# Otherwise use sc.exe
$nssmPath = "D:\SafeOpsFV2\bin\nssm\nssm.exe"

if (Test-Path $nssmPath) {
    Write-Host "Installing service with NSSM..." -ForegroundColor Cyan

    & $nssmPath install $serviceName $exePath
    & $nssmPath set $serviceName AppDirectory $workingDir
    & $nssmPath set $serviceName DisplayName $serviceDisplayName
    & $nssmPath set $serviceName Description $serviceDescription
    & $nssmPath set $serviceName Start SERVICE_AUTO_START
    & $nssmPath set $serviceName AppStdout "D:\SafeOpsFV2\data\logs\service_stdout.log"
    & $nssmPath set $serviceName AppStderr "D:\SafeOpsFV2\data\logs\service_stderr.log"
    & $nssmPath set $serviceName AppRotateFiles 1
    & $nssmPath set $serviceName AppRotateBytes 10485760  # 10MB

    Write-Host "Service installed with NSSM successfully!" -ForegroundColor Green
} else {
    Write-Host "NSSM not found, using sc.exe (basic installation)..." -ForegroundColor Yellow

    # Create service with sc.exe
    sc.exe create $serviceName binPath= $exePath start= auto DisplayName= $serviceDisplayName

    if ($LASTEXITCODE -ne 0) {
        Write-Error "Failed to create service (exit code: $LASTEXITCODE)"
        exit 1
    }

    # Set description
    sc.exe description $serviceName $serviceDescription

    Write-Host "Service installed with sc.exe successfully!" -ForegroundColor Green
    Write-Host "Note: For better service management, consider installing NSSM at: $nssmPath" -ForegroundColor Yellow
}

# Set service to delayed auto-start (starts after boot completes)
sc.exe config $serviceName start= delayed-auto

Write-Host ""
Write-Host "Service Configuration:" -ForegroundColor Cyan
Write-Host "  Name: $serviceName" -ForegroundColor White
Write-Host "  Display: $serviceDisplayName" -ForegroundColor White
Write-Host "  Executable: $exePath" -ForegroundColor White
Write-Host "  Startup: Automatic (Delayed)" -ForegroundColor White
Write-Host ""

# Ask if user wants to start the service now
$response = Read-Host "Do you want to start the service now? (Y/N)"
if ($response -eq "Y" -or $response -eq "y") {
    Write-Host "Starting service..." -ForegroundColor Cyan
    Start-Service -Name $serviceName

    Start-Sleep -Seconds 3

    $service = Get-Service -Name $serviceName
    if ($service.Status -eq "Running") {
        Write-Host "Service started successfully!" -ForegroundColor Green
    } else {
        Write-Warning "Service failed to start. Check logs at: D:\SafeOpsFV2\data\logs\"
    }
} else {
    Write-Host "Service installed but not started. Use 'Start-Service $serviceName' to start it." -ForegroundColor Yellow
}

Write-Host ""
Write-Host "Service Management Commands:" -ForegroundColor Cyan
Write-Host "  Start:   Start-Service $serviceName" -ForegroundColor White
Write-Host "  Stop:    Stop-Service $serviceName" -ForegroundColor White
Write-Host "  Restart: Restart-Service $serviceName" -ForegroundColor White
Write-Host "  Status:  Get-Service $serviceName" -ForegroundColor White
Write-Host "  Logs:    D:\SafeOpsFV2\data\logs\engine.log" -ForegroundColor White
Write-Host ""
