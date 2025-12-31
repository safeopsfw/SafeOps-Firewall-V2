# SafeOps CA Certificate Installer for Windows (PowerShell)
# Run as Administrator: powershell -ExecutionPolicy Bypass -File install_cert.ps1

param(
    [string]$CertPath = "$PSScriptRoot\SafeOps-CA.crt",
    [switch]$Silent
)

# Check for admin privileges
$isAdmin = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)

if (-not $isAdmin) {
    Write-Host "[ERROR] Administrator privileges required!" -ForegroundColor Red
    Write-Host "        Run PowerShell as Administrator and try again." -ForegroundColor Yellow
    if (-not $Silent) { Read-Host "Press Enter to exit" }
    exit 1
}

Write-Host ""
Write-Host "============================================" -ForegroundColor Cyan
Write-Host " SafeOps CA Certificate Installer" -ForegroundColor Cyan
Write-Host "============================================" -ForegroundColor Cyan
Write-Host ""

# Check if certificate exists
if (-not (Test-Path $CertPath)) {
    Write-Host "[ERROR] Certificate not found: $CertPath" -ForegroundColor Red
    if (-not $Silent) { Read-Host "Press Enter to exit" }
    exit 1
}

Write-Host "[1/4] Reading certificate..." -ForegroundColor Yellow
$cert = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2($CertPath)

Write-Host "[2/4] Opening Trusted Root store..." -ForegroundColor Yellow
$store = New-Object System.Security.Cryptography.X509Certificates.X509Store("Root", "LocalMachine")
$store.Open("ReadWrite")

Write-Host "[3/4] Installing certificate..." -ForegroundColor Yellow
$store.Add($cert)
$store.Close()

Write-Host "[4/4] Verifying installation..." -ForegroundColor Yellow

# Verify
$store.Open("ReadOnly")
$installed = $store.Certificates | Where-Object { $_.Thumbprint -eq $cert.Thumbprint }
$store.Close()

if ($installed) {
    Write-Host ""
    Write-Host "============================================" -ForegroundColor Green
    Write-Host " SUCCESS! Certificate Installed" -ForegroundColor Green
    Write-Host "============================================" -ForegroundColor Green
    Write-Host ""
    Write-Host "Certificate Details:" -ForegroundColor Cyan
    Write-Host "  Subject: $($cert.Subject)"
    Write-Host "  Thumbprint: $($cert.Thumbprint)"
    Write-Host "  Valid Until: $($cert.NotAfter)"
    Write-Host ""
    Write-Host "Your device is now configured for secure browsing!" -ForegroundColor Green
    
    # Notify captive portal of enrollment (if running locally)
    try {
        $ip = (Get-NetIPAddress -AddressFamily IPv4 | Where-Object { $_.InterfaceAlias -notmatch "Loopback" } | Select-Object -First 1).IPAddress
        Invoke-RestMethod -Uri "http://192.168.1.1/api/enroll" -Method POST -Body @{ip=$ip; os="Windows"; method="powershell"} -TimeoutSec 5 -ErrorAction SilentlyContinue
    } catch { }
    
    exit 0
} else {
    Write-Host "[ERROR] Certificate verification failed!" -ForegroundColor Red
    exit 1
}

if (-not $Silent) { Read-Host "Press Enter to exit" }
