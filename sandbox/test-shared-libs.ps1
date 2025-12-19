# SafeOps Shared Libraries - Windows Sandbox Test Script
# This script runs in Windows Sandbox to test all Go shared libraries

Write-Host "=====================================" -ForegroundColor Cyan
Write-Host "SafeOps Shared Libraries Test Suite" -ForegroundColor Cyan
Write-Host "=====================================" -ForegroundColor Cyan
Write-Host ""

# Navigate to project directory
Set-Location "C:\SafeOps\src\shared\go"

Write-Host "[1/6] Checking Go installation..." -ForegroundColor Yellow
$goVersion = go version
if ($LASTEXITCODE -eq 0) {
    Write-Host "✓ Go installed: $goVersion" -ForegroundColor Green
} else {
    Write-Host "✗ Go not found! Installing..." -ForegroundColor Red
    
    # Download and install Go
    $goInstaller = "C:\temp\go-installer.msi"
    Invoke-WebRequest -Uri "https://go.dev/dl/go1.21.5.windows-amd64.msi" -OutFile $goInstaller
    Start-Process msiexec.exe -ArgumentList "/i $goInstaller /quiet /norestart" -Wait
    
    # Add to PATH
    $env:Path += ";C:\Program Files\Go\bin"
    
    Write-Host "✓ Go installed successfully" -ForegroundColor Green
}

Write-Host ""
Write-Host "[2/6] Downloading dependencies..." -ForegroundColor Yellow
go mod download
if ($LASTEXITCODE -eq 0) {
    Write-Host "✓ Dependencies downloaded" -ForegroundColor Green
} else {
    Write-Host "✗ Failed to download dependencies" -ForegroundColor Red
    Read-Host "Press Enter to exit"
    exit 1
}

Write-Host ""
Write-Host "[3/6] Building all packages..." -ForegroundColor Yellow
go build ./...
if ($LASTEXITCODE -eq 0) {
    Write-Host "✓ All packages built successfully" -ForegroundColor Green
} else {
    Write-Host "✗ Build failed" -ForegroundColor Red
    Read-Host "Press Enter to exit"
    exit 1
}

Write-Host ""
Write-Host "[4/6] Running unit tests..." -ForegroundColor Yellow
go test ./... -v -short | Tee-Object -FilePath "C:\SafeOps\sandbox\test-results.txt"
$testExitCode = $LASTEXITCODE

if ($testExitCode -eq 0) {
    Write-Host "✓ All tests passed" -ForegroundColor Green
} else {
    Write-Host "✗ Some tests failed (exit code: $testExitCode)" -ForegroundColor Red
    Write-Host "  Check C:\SafeOps\sandbox\test-results.txt for details" -ForegroundColor Yellow
}

Write-Host ""
Write-Host "[5/6] Running linters..." -ForegroundColor Yellow
go vet ./...
if ($LASTEXITCODE -eq 0) {
    Write-Host "✓ No lint errors" -ForegroundColor Green
} else {
    Write-Host "✗ Lint errors found" -ForegroundColor Red
}

Write-Host ""
Write-Host "[6/6] Coverage analysis..." -ForegroundColor Yellow
go test ./... -cover | Tee-Object -Append -FilePath "C:\SafeOps\sandbox\test-results.txt"

Write-Host ""
Write-Host "=====================================" -ForegroundColor Cyan
Write-Host "Test Summary" -ForegroundColor Cyan
Write-Host "=====================================" -ForegroundColor Cyan

# Count packages
$packageCount = (Get-ChildItem -Directory -Recurse | Where-Object { $_.Name -match "^[a-z_]+$" }).Count
Write-Host "Packages tested: $packageCount" -ForegroundColor White

# Final result
Write-Host ""
if ($testExitCode -eq 0) {
    Write-Host "✓ ALL TESTS PASSED!" -ForegroundColor Green
    Write-Host "  SafeOps shared libraries are production-ready" -ForegroundColor Green
} else {
    Write-Host "✗ TESTS FAILED" -ForegroundColor Red
    Write-Host "  Review test output above for details" -ForegroundColor Yellow
}

Write-Host ""
Write-Host "Results saved to: C:\SafeOps\sandbox\test-results.txt" -ForegroundColor Cyan
Write-Host ""
Write-Host "Press Enter to close sandbox..." -ForegroundColor Yellow
Read-Host
