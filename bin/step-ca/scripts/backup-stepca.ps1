# ============================================================================
# Backup Step-CA Critical Files
# ============================================================================
# File: D:\SafeOpsFV2\src\step-ca\scripts\backup-stepca.ps1
# ============================================================================

param(
    [Parameter()]
    [string]$BackupPath = "D:\SafeOps_Backups\step-ca"
)

$ErrorActionPreference = 'Stop'

$timestamp = Get-Date -Format "yyyy-MM-dd_HHmmss"
$backupFolder = Join-Path $BackupPath "stepca_backup_$timestamp"

Write-Host "================================================" -ForegroundColor Cyan
Write-Host "Step-CA Backup" -ForegroundColor Cyan
Write-Host "================================================" -ForegroundColor Cyan
Write-Host "Backup location: $backupFolder" -ForegroundColor Yellow

# Create backup directory
New-Item -ItemType Directory -Force -Path $backupFolder | Out-Null

# Files to backup
$backupItems = @(
    @{Source = "D:\SafeOpsFV2\src\step-ca\certs\root_ca.crt"; Dest = "certs\root_ca.crt" },
    @{Source = "D:\SafeOpsFV2\src\step-ca\certs\intermediate_ca.crt"; Dest = "certs\intermediate_ca.crt" },
    @{Source = "D:\SafeOpsFV2\src\step-ca\secrets\root_ca_key"; Dest = "secrets\root_ca_key" },
    @{Source = "D:\SafeOpsFV2\src\step-ca\secrets\intermediate_ca_key"; Dest = "secrets\intermediate_ca_key" },
    @{Source = "D:\SafeOpsFV2\src\step-ca\secrets\db_encryption.key"; Dest = "secrets\db_encryption.key" },
    @{Source = "D:\SafeOpsFV2\src\step-ca\config\ca.json"; Dest = "config\ca.json" },
    @{Source = "D:\SafeOpsFV2\src\step-ca\config\defaults.json"; Dest = "config\defaults.json" }
)

# Copy files
foreach ($item in $backupItems) {
    $destPath = Join-Path $backupFolder $item.Dest
    $destDir = Split-Path $destPath -Parent
    
    if (-not (Test-Path $destDir)) {
        New-Item -ItemType Directory -Force -Path $destDir | Out-Null
    }
    
    if (Test-Path $item.Source) {
        Copy-Item -Path $item.Source -Destination $destPath -Force
        Write-Host "✅ Backed up: $($item.Dest)" -ForegroundColor Green
    }
    else {
        Write-Host "⚠️  Skipped (not found): $($item.Dest)" -ForegroundColor Yellow
    }
}

# Export database secrets
Write-Host "Backing up database secrets..." -ForegroundColor Yellow
$dbBackupDir = Join-Path $backupFolder "database"
New-Item -ItemType Directory -Force -Path $dbBackupDir | Out-Null

try {
    $env:PAGER = 'more'
    & "C:\Program Files\PostgreSQL\18\bin\psql.exe" -U postgres -d safeops_network -t -A -c "SELECT service_name, encryption_method, created_at FROM secrets;" > (Join-Path $dbBackupDir "secrets_metadata.txt")
    Write-Host "✅ Database secrets metadata backed up" -ForegroundColor Green
}
catch {
    Write-Host "⚠️  Database backup skipped: $_" -ForegroundColor Yellow
}

# Create compressed archive
Write-Host "Compressing backup..." -ForegroundColor Yellow
$zipPath = "$backupFolder.zip"
Compress-Archive -Path $backupFolder -DestinationPath $zipPath -Force
Remove-Item $backupFolder -Recurse -Force

$zipSize = [math]::Round((Get-Item $zipPath).Length / 1KB, 2)

Write-Host ""
Write-Host "================================================" -ForegroundColor Green
Write-Host "✅ Backup completed successfully!" -ForegroundColor Green
Write-Host "================================================" -ForegroundColor Green
Write-Host "Backup file: $zipPath" -ForegroundColor Cyan
Write-Host "Size: $zipSize KB" -ForegroundColor Cyan
Write-Host ""
Write-Host "⚠️  CRITICAL: Store this backup in a secure, offline location!" -ForegroundColor Yellow
