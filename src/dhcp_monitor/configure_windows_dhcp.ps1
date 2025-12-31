# Configure Windows DHCP Server for DHCP Monitor
# Run this script as Administrator

Write-Host "==================================" -ForegroundColor Cyan
Write-Host " Windows DHCP Configuration" -ForegroundColor Cyan
Write-Host "==================================" -ForegroundColor Cyan
Write-Host ""

# Check if running as Administrator
$isAdmin = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $isAdmin) {
    Write-Host "ERROR: This script must be run as Administrator!" -ForegroundColor Red
    Write-Host "Right-click PowerShell and select 'Run as Administrator'" -ForegroundColor Yellow
    exit 1
}

# Get local IP address (non-loopback IPv4)
$localIP = (Get-NetIPAddress -AddressFamily IPv4 | Where-Object { $_.InterfaceAlias -notlike "*Loopback*" -and $_.IPAddress -notlike "169.254.*" })[0].IPAddress

if (-not $localIP) {
    Write-Host "ERROR: Could not detect local IP address" -ForegroundColor Red
    exit 1
}

Write-Host "Detected local IP: $localIP" -ForegroundColor Green
Write-Host ""

# Get all DHCP scopes
Write-Host "Getting DHCP scopes..." -ForegroundColor Yellow
try {
    $scopes = Get-DhcpServerv4Scope -ComputerName localhost
    if ($scopes.Count -eq 0) {
        Write-Host "WARNING: No DHCP scopes found. Please create a scope first." -ForegroundColor Yellow
        exit 0
    }

    Write-Host "Found $($scopes.Count) scope(s):" -ForegroundColor Green
    foreach ($scope in $scopes) {
        Write-Host "  - $($scope.ScopeId) ($($scope.Name))" -ForegroundColor Cyan
    }
    Write-Host ""
} catch {
    Write-Host "ERROR: Failed to get DHCP scopes. Is DHCP Server installed?" -ForegroundColor Red
    Write-Host "Error: $_" -ForegroundColor Red
    exit 1
}

# Confirm configuration
Write-Host "This will configure ALL scopes to use this machine as:" -ForegroundColor Yellow
Write-Host "  - DNS Server: $localIP" -ForegroundColor Yellow
Write-Host "  - Gateway:    $localIP" -ForegroundColor Yellow
Write-Host ""
$confirm = Read-Host "Continue? (y/n)"
if ($confirm -ne 'y') {
    Write-Host "Configuration cancelled." -ForegroundColor Yellow
    exit 0
}

# Configure each scope
foreach ($scope in $scopes) {
    Write-Host ""
    Write-Host "Configuring scope $($scope.ScopeId)..." -ForegroundColor Cyan

    try {
        # Set DNS server (Option 6)
        Set-DhcpServerv4OptionValue -ComputerName localhost -ScopeId $scope.ScopeId -OptionId 6 -Value $localIP
        Write-Host "  [OK] DNS Server set to $localIP" -ForegroundColor Green

        # Set Router/Gateway (Option 3)
        Set-DhcpServerv4OptionValue -ComputerName localhost -ScopeId $scope.ScopeId -OptionId 3 -Value $localIP
        Write-Host "  [OK] Gateway set to $localIP" -ForegroundColor Green

    } catch {
        Write-Host "  [ERROR] Failed to configure scope: $_" -ForegroundColor Red
    }
}

Write-Host ""
Write-Host "==================================" -ForegroundColor Cyan
Write-Host " Configuration Complete!" -ForegroundColor Green
Write-Host "==================================" -ForegroundColor Cyan
Write-Host ""
Write-Host "Next steps:" -ForegroundColor Yellow
Write-Host "1. Start the DHCP Monitor service" -ForegroundColor White
Write-Host "2. Connect a device to the network" -ForegroundColor White
Write-Host "3. Device will be redirected to captive portal" -ForegroundColor White
Write-Host ""
Write-Host "To verify configuration:" -ForegroundColor Yellow
Write-Host "  Get-DhcpServerv4OptionValue -ScopeId <scope_id>" -ForegroundColor Cyan
Write-Host ""
