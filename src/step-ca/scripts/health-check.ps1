# ============================================================================
# Step-CA Health Check
# ============================================================================
# File: D:\SafeOpsFV2\src\step-ca\scripts\health-check.ps1
# ============================================================================

$ErrorActionPreference = 'Continue'
$allPassed = $true

Write-Host "================================================" -ForegroundColor Cyan
Write-Host "Step-CA Health Check" -ForegroundColor Cyan
Write-Host "================================================" -ForegroundColor Cyan
Write-Host ""

# 1. Check if process is running
$process = Get-Process -Name "step-ca" -ErrorAction SilentlyContinue
if ($process) {
    Write-Host "✅ Process: Running (PID: $($process.Id))" -ForegroundColor Green
}
else {
    Write-Host "❌ Process: Not running" -ForegroundColor Red
    $allPassed = $false
}

# 2. Check API health endpoint
try {
    $health = Invoke-RestMethod -Uri "https://localhost:9000/health" -SkipCertificateCheck -TimeoutSec 5
    if ($health.status -eq "ok") {
        Write-Host "✅ API Health: OK" -ForegroundColor Green
    }
    else {
        Write-Host "❌ API Health: $($health.status)" -ForegroundColor Red
        $allPassed = $false
    }
}
catch {
    Write-Host "❌ API Health: Unreachable" -ForegroundColor Red
    $allPassed = $false
}

# 3. Check root CA downloadable
try {
    $rootCa = Invoke-RestMethod -Uri "https://localhost:9000/roots.pem" -SkipCertificateCheck -TimeoutSec 5
    if ($rootCa -match "BEGIN CERTIFICATE") {
        Write-Host "✅ Root CA: Downloadable via API" -ForegroundColor Green
    }
    else {
        Write-Host "❌ Root CA: Invalid response" -ForegroundColor Red
        $allPassed = $false
    }
}
catch {
    Write-Host "⚠️  Root CA: API endpoint check skipped" -ForegroundColor Yellow
}

# 4. Check database password
try {
    $env:PAGER = 'more'
    $passwordCheck = & "C:\Program Files\PostgreSQL\18\bin\psql.exe" -U postgres -d safeops_network -t -A -c "SELECT COUNT(*) FROM secrets WHERE service_name = 'step-ca-master';" 2>$null
    if ($passwordCheck.Trim() -eq "1") {
        Write-Host "✅ Database Password: Stored" -ForegroundColor Green
    }
    else {
        Write-Host "❌ Database Password: Not found" -ForegroundColor Red
        $allPassed = $false
    }
}
catch {
    Write-Host "⚠️  Database Password: Check skipped" -ForegroundColor Yellow
}

# 5. Check certificate files
$certFiles = @(
    @{Path = "D:\SafeOpsFV2\src\step-ca\certs\root_ca.crt"; Name = "Root CA (source)" },
    @{Path = "D:\SafeOpsFV2\src\step-ca\certs\intermediate_ca.crt"; Name = "Intermediate CA" },
    @{Path = "D:\SafeOpsFV2\src\CA Cert\root_ca.crt"; Name = "Root CA (PEM dist)" },
    @{Path = "D:\SafeOpsFV2\src\CA Cert\root_ca.der"; Name = "Root CA (DER dist)" },
    @{Path = "D:\SafeOpsFV2\src\CA Cert\root_ca.p12"; Name = "Root CA (PKCS#12 dist)" }
)

foreach ($cert in $certFiles) {
    if (Test-Path $cert.Path) {
        Write-Host "✅ $($cert.Name)" -ForegroundColor Green
    }
    else {
        Write-Host "❌ $($cert.Name) MISSING" -ForegroundColor Red
        $allPassed = $false
    }
}

# 6. Check scripts exist
$scripts = @("get-password.ps1", "start-stepca.ps1", "stop-stepca.ps1", "restart-stepca.ps1", "backup-stepca.ps1")
$scriptPath = "D:\SafeOpsFV2\src\step-ca\scripts"
$scriptsExist = $true
foreach ($script in $scripts) {
    if (-not (Test-Path (Join-Path $scriptPath $script))) {
        $scriptsExist = $false
    }
}
if ($scriptsExist) {
    Write-Host "✅ Management Scripts: All present" -ForegroundColor Green
}
else {
    Write-Host "⚠️  Management Scripts: Some missing" -ForegroundColor Yellow
}

Write-Host ""
Write-Host "================================================" -ForegroundColor Cyan
if ($allPassed) {
    Write-Host "✅ All critical checks passed - Step-CA is healthy" -ForegroundColor Green
    exit 0
}
else {
    Write-Host "❌ Some checks failed - review above" -ForegroundColor Red
    exit 1
}
