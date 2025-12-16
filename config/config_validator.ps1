# SafeOps Configuration Validator v2.0
# Purpose: Validate configuration files

[CmdletBinding()]
param(
    [string]$ConfigPath = "D:\SafeOpsFV2\config",
    [switch]$Full
)

$ErrorCount = 0
$WarningCount = 0

Write-Host ""
Write-Host "=======================================================" -ForegroundColor Cyan
Write-Host "  SafeOps Configuration Validator v2.0" -ForegroundColor Cyan
Write-Host "=======================================================" -ForegroundColor Cyan
Write-Host ""
Write-Host "[INFO]  Validating: $ConfigPath" -ForegroundColor Cyan
Write-Host ""

$startTime = Get-Date

# Validate Network Topology
$topFile = Join-Path $ConfigPath "network_topology.yaml"
if (Test-Path $topFile) {
    Write-Host "[INFO]  Checking network_topology.yaml..." -ForegroundColor Cyan
    $content = Get-Content $topFile -Raw
    if ($content -match "`t") {
        Write-Host "[ERROR] network_topology.yaml contains tabs" -ForegroundColor Red
        $ErrorCount++
    }
    else {
        Write-Host "[OK]    network_topology.yaml is valid" -ForegroundColor Green
    }
}

# Validate Suricata vars
$suriFile = Join-Path $ConfigPath "ids_ips\suricata_vars.yaml"
if (Test-Path $suriFile) {
    Write-Host "[INFO]  Checking suricata_vars.yaml..." -ForegroundColor Cyan
    $content = Get-Content $suriFile -Raw
    $valid = $true
    foreach ($var in @("HOME_NET", "EXTERNAL_NET", "HTTP_PORTS")) {
        if ($content -notmatch $var) {
            Write-Host "[ERROR] suricata_vars.yaml missing: $var" -ForegroundColor Red
            $ErrorCount++
            $valid = $false
        }
    }
    if ($valid) {
        Write-Host "[OK]    suricata_vars.yaml is valid" -ForegroundColor Green
    }
}

# Validate TOML templates
Write-Host ""
Write-Host "[INFO]  Checking template configurations..." -ForegroundColor Cyan
$templatesPath = Join-Path $ConfigPath "templates"
if (Test-Path $templatesPath) {
    Get-ChildItem -Path $templatesPath -Filter "*.toml" | ForEach-Object {
        $valid = $true
        try {
            $content = Get-Content $_.FullName -Raw -ErrorAction Stop
            Write-Host "[OK]    $($_.Name) is valid" -ForegroundColor Green
        }
        catch {
            Write-Host "[ERROR] $($_.Name) - Cannot read file" -ForegroundColor Red
            $ErrorCount++
        }
    }
}

# Validate default presets
Write-Host ""
Write-Host "[INFO]  Checking default presets..." -ForegroundColor Cyan
$defaultsPath = Join-Path $ConfigPath "defaults"
if (Test-Path $defaultsPath) {
    Get-ChildItem -Path $defaultsPath -Filter "*.toml" | ForEach-Object {
        try {
            $content = Get-Content $_.FullName -Raw -ErrorAction Stop
            Write-Host "[OK]    $($_.Name) is valid" -ForegroundColor Green
        }
        catch {
            Write-Host "[ERROR] $($_.Name) - Cannot read file" -ForegroundColor Red
            $ErrorCount++
        }
    }
}

# Summary
$duration = [math]::Round(((Get-Date) - $startTime).TotalSeconds, 2)

Write-Host ""
Write-Host "=======================================================" -ForegroundColor Cyan
Write-Host "  Validation Summary" -ForegroundColor Cyan
Write-Host "=======================================================" -ForegroundColor Cyan
Write-Host ""

if ($ErrorCount -eq 0) {
    Write-Host "  All validations passed!" -ForegroundColor Green
}
else {
    Write-Host "  Errors:   $ErrorCount" -ForegroundColor Red
    Write-Host "  Warnings: $WarningCount" -ForegroundColor Yellow
}

Write-Host ""
Write-Host "  Duration: $duration seconds" -ForegroundColor Cyan
Write-Host ""
Write-Host "=======================================================" -ForegroundColor Cyan
Write-Host ""

if ($ErrorCount -eq 0) { exit 0 } else { exit 1 }
