# SafeOps SIEM - ELK Setup Script
# Run: powershell -ExecutionPolicy Bypass -File setup_elk.ps1

$ELK = "D:\SafeOpsFV2\bin\elk"
$VER = "8.17.0"

Write-Host "SafeOps SIEM Setup" -ForegroundColor Cyan

# Stop existing
Get-Process -Name "java", "node" -EA SilentlyContinue | Stop-Process -Force
Start-Sleep 3

# Start Elasticsearch
Write-Host "Starting Elasticsearch..." -ForegroundColor Yellow
Start-Process "$ELK\elasticsearch-$VER\bin\elasticsearch.bat" -WindowStyle Minimized
Write-Host "Waiting 60s..." -ForegroundColor Gray
Start-Sleep 60

# Verify ES
try {
    $es = Invoke-RestMethod "http://localhost:9200" -EA Stop
    Write-Host "ES OK: $($es.cluster_name)" -ForegroundColor Green
}
catch { Write-Host "ES still starting..." -ForegroundColor Yellow }

# Start Kibana
Write-Host "Starting Kibana..." -ForegroundColor Yellow
Start-Process "$ELK\kibana-$VER\bin\kibana.bat" -WindowStyle Minimized
Write-Host "Waiting 90s for Kibana..." -ForegroundColor Gray
Start-Sleep 90

# Done
Write-Host "`n========================================" -ForegroundColor Green
Write-Host "  SIEM READY!" -ForegroundColor Green
Write-Host "  Kibana: http://localhost:5601" -ForegroundColor Cyan
Write-Host "  Elasticsearch: http://localhost:9200" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Green
