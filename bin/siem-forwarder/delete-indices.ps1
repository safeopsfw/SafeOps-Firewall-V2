# Delete all SafeOps indices from Elasticsearch
# Run this to start fresh with correct timestamps

$ES_HOST = "http://localhost:9200"

Write-Host "=== SafeOps Index Cleanup ===" -ForegroundColor Cyan
Write-Host ""

# List current safeops indices
Write-Host "Current SafeOps indices:" -ForegroundColor Yellow
try {
    $indices = Invoke-RestMethod -Uri "$ES_HOST/_cat/indices/safeops-*?h=index,docs.count,store.size" -Method GET
    if ($indices) {
        Write-Host $indices
    }
    else {
        Write-Host "No SafeOps indices found."
    }
}
catch {
    Write-Host "Error connecting to Elasticsearch: $_" -ForegroundColor Red
    Write-Host "Make sure Elasticsearch is running on $ES_HOST"
    exit 1
}

Write-Host ""
$confirm = Read-Host "Delete ALL safeops-* indices? (yes/no)"

if ($confirm -eq "yes") {
    Write-Host ""
    Write-Host "Deleting indices..." -ForegroundColor Yellow
    
    # Delete all safeops indices
    try {
        $response = Invoke-RestMethod -Uri "$ES_HOST/safeops-*" -Method DELETE
        Write-Host "Deleted indices successfully!" -ForegroundColor Green
        Write-Host $response
    }
    catch {
        Write-Host "Error deleting indices: $_" -ForegroundColor Red
    }
    
    Write-Host ""
    Write-Host "=== Cleanup Complete ===" -ForegroundColor Cyan
    Write-Host ""
    Write-Host "Next steps:" -ForegroundColor Yellow
    Write-Host "1. Clear position database: Remove 'data/positions.json' to re-read all logs"
    Write-Host "2. Restart the SIEM Forwarder to re-ingest logs with correct timestamps"
    Write-Host "3. Create new Kibana Data Views for the fresh indices"
}
else {
    Write-Host "Aborted." -ForegroundColor Yellow
}
