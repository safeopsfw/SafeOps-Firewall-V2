$Host.UI.RawUI.WindowTitle = "SafeOps Certificate Authority"
Write-Host "========================================" -ForegroundColor Cyan
Write-Host "SafeOps Certificate Authority" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan
Write-Host ""
Write-Host "Starting CA server on https://192.168.137.1:9000" -ForegroundColor Green
Write-Host "ACME endpoint: https://192.168.137.1:9000/acme/safeops-acme/directory" -ForegroundColor Green
Write-Host "Press Ctrl+C to stop" -ForegroundColor Yellow
Write-Host ""

Set-Location "D:\SafeOpsFV2\certs\step-ca"
& .\step-ca.exe "ca\config\ca.json" --password-file "ca\secrets\password.txt"
