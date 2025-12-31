$ErrorActionPreference = "Stop"

$pgPath = "C:\Program Files\PostgreSQL\18"
$dataDir = "$pgPath\data"
$hbaConf = "$dataDir\pg_hba.conf"
$hbaBackup = "$dataDir\pg_hba.conf.bak"
$serviceName = "postgresql-x64-18"

Write-Host "1. Backing up pg_hba.conf..."
Copy-Item -Path $hbaConf -Destination $hbaBackup -Force

Write-Host "2. Modifying pg_hba.conf to trust local connections..."
$content = Get-Content $hbaConf
$newContent = $content -replace "host\s+all\s+all\s+127.0.0.1/32\s+(md5|scram-sha-256)", "host    all             all             127.0.0.1/32            trust"
$newContent = $newContent -replace "host\s+all\s+all\s+::1/128\s+(md5|scram-sha-256)", "host    all             all             ::1/128                 trust"
$newContent | Set-Content $hbaConf

Write-Host "2.5 Stopping any psql processes that might lock the database..."
Stop-Process -Name "psql" -ErrorAction SilentlyContinue

Write-Host "3. Restarting PostgreSQL service..."
Stop-Service -Name $serviceName -Force -ErrorAction SilentlyContinue
$maxRetries = 10
$retryCount = 0
while ((Get-Service -Name $serviceName).Status -eq 'Running' -and $retryCount -lt $maxRetries) {
    Write-Host "  Waiting for service to stop..."
    Start-Sleep -Seconds 2
    $retryCount++
}

if ((Get-Service -Name $serviceName).Status -eq 'Running') {
    Write-Host "Service failed to stop. Attempting taskkill..."
    taskkill /F /FI "SERVICES eq $serviceName"
    Start-Sleep -Seconds 5
}

Start-Service -Name $serviceName
Start-Sleep -Seconds 5

Write-Host "4. Setting new password..."
# Wait a moment for service to be ready
Start-Sleep -Seconds 5
& "$pgPath\bin\psql.exe" -U postgres -h localhost -c "ALTER USER postgres WITH PASSWORD 'safeops123';"

Write-Host "5. Restoring pg_hba.conf..."
Copy-Item -Path $hbaBackup -Destination $hbaConf -Force

Write-Host "6. Restarting PostgreSQL service..."
Restart-Service -Name $serviceName -Force

Write-Host "7. Verifying connection and listing tables..."
Start-Sleep -Seconds 5
$env:PGPASSWORD = "safeops123"
& "$pgPath\bin\psql.exe" -U postgres -h localhost -c "\l"
