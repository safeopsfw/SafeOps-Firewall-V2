# ============================================================================
# SafeOps Threat Intelligence - Fetch Utility Builder
# ============================================================================

Write-Host "`n=========================================================="
Write-Host "SafeOps Threat Intelligence - Building Fetch Utility" -ForegroundColor Cyan
Write-Host "==========================================================`n"

# Get script directory and navigate to project root
$scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$projectRoot = Join-Path $scriptDir "..\..\.."
Set-Location $projectRoot

Write-Host "📁 Project root: $(Get-Location)" -ForegroundColor Yellow

# Check if config files exist
$configFile = "config\config.yaml"
$sourcesFile = "config\sources.yaml"

if (-not (Test-Path $configFile)) {
    Write-Host "❌ Missing: $configFile" -ForegroundColor Red
    exit 1
}
if (-not (Test-Path $sourcesFile)) {
    Write-Host "❌ Missing: $sourcesFile" -ForegroundColor Red
    exit 1
}

Write-Host "✅ Configuration files found" -ForegroundColor Green

# Create feeds directory if it doesn't exist
$feedsDir = "feeds"
if (-not (Test-Path $feedsDir)) {
    Write-Host "📂 Creating feeds directory..." -ForegroundColor Yellow
    New-Item -ItemType Directory -Path $feedsDir | Out-Null
}

# Build the executable
Write-Host "`n🔨 Building fetch utility..." -ForegroundColor Yellow
$buildPath = "cmd\fetch"
$outputExe = "fetch.exe"

try {
    Set-Location $buildPath
    go build -o $outputExe main.go
    
    if ($LASTEXITCODE -eq 0) {
        Write-Host "✅ Build successful: $outputExe" -ForegroundColor Green
        
        # Show file info
        $exeInfo = Get-Item $outputExe
        Write-Host "   Size: $([math]::Round($exeInfo.Length / 1MB, 2)) MB" -ForegroundColor Gray
        Write-Host "   Location: $(Resolve-Path $outputExe)" -ForegroundColor Gray
        
        # Ask to run
        Write-Host "`n🚀 Run fetcher now? (Y/N): " -ForegroundColor Cyan -NoNewline
        $response = Read-Host
        
        if ($response -eq 'Y' -or $response -eq 'y') {
            Write-Host "`n⏬ Starting fetch utility...`n" -ForegroundColor Green
            & ".\$outputExe"
        }
        else {
            Write-Host "`n📝 To run manually:" -ForegroundColor Yellow
            Write-Host "   cd $buildPath" -ForegroundColor Gray
            Write-Host "   .\$outputExe" -ForegroundColor Gray
        }
    }
    else {
        Write-Host "❌ Build failed!" -ForegroundColor Red
        exit 1
    }
}
catch {
    Write-Host "❌ Error: $_" -ForegroundColor Red
    exit 1
}

Write-Host "`n==========================================================`n" -ForegroundColor Cyan
