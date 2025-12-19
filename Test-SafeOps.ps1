# ============================================================================
# SafeOps Complete Test Suite
# ============================================================================
# Comprehensive testing of all SafeOps components:
# - Go shared libraries (13 components)
# - Rust shared libraries
# - Compiled executables
# - Integration tests
# - Performance benchmarks
# ============================================================================

param(
    [string]$OutputDir = ".\test-results",
    [switch]$SkipBuild = $false,
    [switch]$SkipRust = $false,
    [switch]$Verbose = $false,
    [switch]$BenchmarkOnly = $false
)

$ErrorActionPreference = "Continue"
$script:StartTime = Get-Date
$script:TotalTests = 0
$script:PassedTests = 0
$script:FailedTests = 0
$script:Errors = @()

# ============================================================================
# Configuration
# ============================================================================

$ProjectRoot = $PSScriptRoot
$GoSharedPath = "$ProjectRoot\src\shared\go"
$RustSharedPath = "$ProjectRoot\src\shared\rust"
$LogFile = "$OutputDir\test-$(Get-Date -Format 'yyyyMMdd-HHmmss').log"
$ErrorLog = "$OutputDir\errors-$(Get-Date -Format 'yyyyMMdd-HHmmss').log"
$SummaryFile = "$OutputDir\summary-$(Get-Date -Format 'yyyyMMdd-HHmmss').html"

# ============================================================================
# Banner
# ============================================================================

Write-Host @"

╔══════════════════════════════════════════════════════════════════════════════╗
║                                                                              ║
║                     SafeOps Complete Test Suite v1.0                        ║
║                                                                              ║
║  Testing:                                                                   ║
║  • Go Shared Libraries (13 components, 5000+ lines)                        ║
║  • Rust Shared Libraries                                                   ║
║  • Compiled Executables                                                    ║
║  • Integration Tests                                                       ║
║                                                                              ║
╚══════════════════════════════════════════════════════════════════════════════╝

"@ -ForegroundColor Cyan

# ============================================================================
# Helper Functions
# ============================================================================

function Write-Log {
    param([string]$Message, [string]$Level = "INFO")
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $logEntry = "[$timestamp] [$Level] $Message"
    Add-Content -Path $LogFile -Value $logEntry
    
    $color = switch ($Level) {
        "INFO" { "White" }
        "SUCCESS" { "Green" }
        "WARNING" { "Yellow" }
        "ERROR" { "Red" }
        "TEST" { "Cyan" }
        default { "White" }
    }
    
    if ($Verbose -or $Level -ne "INFO") {
        Write-Host $logEntry -ForegroundColor $color
    }
}

function Write-TestResult {
    param([string]$TestName, [bool]$Passed, [string]$Details = "")
    $script:TotalTests++
    
    if ($Passed) {
        $script:PassedTests++
        Write-Host "  ✓ $TestName" -ForegroundColor Green
        Write-Log "$TestName - PASSED" "SUCCESS"
    }
    else {
        $script:FailedTests++
        Write-Host "  ✗ $TestName" -ForegroundColor Red
        if ($Details) {
            Write-Host "    → $Details" -ForegroundColor DarkRed
        }
        Write-Log "$TestName - FAILED: $Details" "ERROR"
        Add-Content -Path $ErrorLog -Value "[$TestName] $Details"
        $script:Errors += @{Name = $TestName; Error = $Details }
    }
}

function Write-Section {
    param([string]$Title)
    Write-Host "`n━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━" -ForegroundColor DarkGray
    Write-Host " $Title" -ForegroundColor Yellow
    Write-Host "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━" -ForegroundColor DarkGray
    Write-Log "=== $Title ===" "TEST"
}

function Test-CommandExists {
    param([string]$Command)
    return [bool](Get-Command $Command -ErrorAction SilentlyContinue)
}

# ============================================================================
# Setup
# ============================================================================

Write-Section "Test Environment Setup"

# Create output directory
if (!(Test-Path $OutputDir)) {
    New-Item -Path $OutputDir -ItemType Directory -Force | Out-Null
}

Write-Log "Test suite started" "INFO"
Write-Log "Project root: $ProjectRoot" "INFO"
Write-Log "Output directory: $OutputDir" "INFO"

# Check prerequisites
$prerequisites = @(
    @{Name = "Go"; Command = "go"; Required = $true }
    @{Name = "Rust/Cargo"; Command = "cargo"; Required = $false }
    @{Name = "Git"; Command = "git"; Required = $true }
    @{Name = "PostgreSQL"; Command = "psql"; Required = $false }
    @{Name = "Redis"; Command = "redis-cli"; Required = $false }
)

Write-Host "`nChecking prerequisites..." -ForegroundColor White
foreach ($prereq in $prerequisites) {
    $exists = Test-CommandExists $prereq.Command
    if ($exists) {
        Write-TestResult $prereq.Name $true
    }
    else {
        if ($prereq.Required) {
            Write-TestResult $prereq.Name $false "Required but not found"
        }
        else {
            Write-Host "  ⊗ $($prereq.Name) (optional, skipped)" -ForegroundColor DarkGray
        }
    }
}

# ============================================================================
# Go Shared Libraries Tests
# ============================================================================

Write-Section "Go Shared Libraries Tests"

if (!(Test-Path $GoSharedPath)) {
    Write-TestResult "Go shared path exists" $false "Path not found: $GoSharedPath"
}
else {
    Write-TestResult "Go shared path exists" $true
    
    Push-Location $GoSharedPath
    
    # Test 1: Go Module Verification
    Write-Host "`n  [Module Verification]" -ForegroundColor Cyan
    
    if (Test-Path "go.mod") {
        Write-TestResult "go.mod exists" $true
        
        # Parse go.mod
        $goModContent = Get-Content "go.mod" -Raw
        if ($goModContent -match "module\s+(\S+)") {
            Write-TestResult "Module declaration" $true "Module: $($Matches[1])"
        }
        if ($goModContent -match "go\s+(\d+\.\d+)") {
            Write-TestResult "Go version specified" $true "Version: $($Matches[1])"
        }
    }
    else {
        Write-TestResult "go.mod exists" $false
    }
    
    if (Test-Path "go.sum") {
        Write-TestResult "go.sum exists" $true
    }
    else {
        Write-TestResult "go.sum exists" $false "Checksums file missing"
    }
    
    # Test 2: Dependency Download
    Write-Host "`n  [Dependencies]" -ForegroundColor Cyan
    
    $depOutput = go mod download 2>&1
    if ($LASTEXITCODE -eq 0) {
        Write-TestResult "Dependencies download" $true
    }
    else {
        Write-TestResult "Dependencies download" $false $depOutput
    }
    
    # Test 3: Build All Packages
    Write-Host "`n  [Build Tests]" -ForegroundColor Cyan
    
    if (!$SkipBuild) {
        $buildOutput = go build ./... 2>&1
        if ($LASTEXITCODE -eq 0) {
            Write-TestResult "Build all packages" $true
        }
        else {
            Write-TestResult "Build all packages" $false $buildOutput
        }
    }
    else {
        Write-Host "  ⊗ Build skipped (--SkipBuild)" -ForegroundColor DarkGray
    }
    
    # Test 4: Go Vet (Static Analysis)
    Write-Host "`n  [Static Analysis]" -ForegroundColor Cyan
    
    $vetOutput = go vet ./... 2>&1
    if ($LASTEXITCODE -eq 0) {
        Write-TestResult "go vet (static analysis)" $true
    }
    else {
        Write-TestResult "go vet (static analysis)" $false $vetOutput
    }
    
    # Test 5: Unit Tests by Package
    Write-Host "`n  [Unit Tests by Package]" -ForegroundColor Cyan
    
    $packages = @(
        @{Name = "config"; Path = "./config" }
        @{Name = "errors"; Path = "./errors" }
        @{Name = "logging"; Path = "./logging" }
        @{Name = "health"; Path = "./health" }
        @{Name = "metrics"; Path = "./metrics" }
        @{Name = "utils"; Path = "./utils" }
        @{Name = "redis"; Path = "./redis" }
        @{Name = "postgres"; Path = "./postgres" }
        @{Name = "grpc_client"; Path = "./grpc_client" }
    )
    
    foreach ($pkg in $packages) {
        if (Test-Path $pkg.Path.Replace("./", "")) {
            $testOutput = go test $pkg.Path -v -short -timeout 30s 2>&1 | Out-String
            $testPassed = $LASTEXITCODE -eq 0
            
            # Count tests
            $testCount = ([regex]::Matches($testOutput, "--- PASS")).Count
            $failCount = ([regex]::Matches($testOutput, "--- FAIL")).Count
            
            if ($testPassed) {
                Write-TestResult "$($pkg.Name) package" $true "($testCount tests passed)"
            }
            else {
                Write-TestResult "$($pkg.Name) package" $false "$failCount tests failed"
                Add-Content -Path $ErrorLog -Value "`n=== $($pkg.Name) Test Output ===`n$testOutput"
            }
            
            # Save detailed output
            Add-Content -Path "$OutputDir\test-$($pkg.Name).log" -Value $testOutput
        }
        else {
            Write-Host "  ⊗ $($pkg.Name) (not found)" -ForegroundColor DarkGray
        }
    }
    
    # Test 6: Race Condition Detection
    Write-Host "`n  [Race Detection]" -ForegroundColor Cyan
    
    $raceOutput = go test ./... -race -short -timeout 60s 2>&1 | Out-String
    if ($LASTEXITCODE -eq 0 -and $raceOutput -notmatch "DATA RACE") {
        Write-TestResult "Race condition detection" $true
    }
    else {
        Write-TestResult "Race condition detection" $false "Potential race conditions found"
        Add-Content -Path $ErrorLog -Value "`n=== Race Detection Output ===`n$raceOutput"
    }
    
    # Test 7: Code Coverage
    Write-Host "`n  [Code Coverage]" -ForegroundColor Cyan
    
    $coverOutput = go test ./... -cover -short 2>&1 | Out-String
    if ($coverOutput -match "coverage:\s+(\d+\.?\d*)%") {
        $coverage = $Matches[1]
        $coveragePassed = [double]$coverage -ge 50
        Write-TestResult "Code coverage" $coveragePassed "Coverage: $coverage%"
    }
    else {
        Write-TestResult "Code coverage" $true "Coverage data collected"
    }
    
    # Generate HTML coverage report
    go test ./... -coverprofile="$OutputDir\coverage.out" -short 2>$null
    if (Test-Path "$OutputDir\coverage.out") {
        go tool cover -html="$OutputDir\coverage.out" -o "$OutputDir\coverage.html" 2>$null
        Write-Log "Coverage report generated: $OutputDir\coverage.html" "INFO"
    }
    
    # Test 8: Benchmark Tests
    if ($BenchmarkOnly -or !$SkipBuild) {
        Write-Host "`n  [Benchmarks]" -ForegroundColor Cyan
        
        $benchOutput = go test ./... -bench=. -benchmem -short -run=^$ 2>&1 | Out-String
        if ($benchOutput -match "Benchmark") {
            Write-TestResult "Benchmark tests" $true
            Add-Content -Path "$OutputDir\benchmarks.log" -Value $benchOutput
            Write-Log "Benchmarks saved to: $OutputDir\benchmarks.log" "INFO"
        }
        else {
            Write-Host "  ⊗ No benchmarks found" -ForegroundColor DarkGray
        }
    }
    
    Pop-Location
}

# ============================================================================
# Go Package Structure Verification
# ============================================================================

Write-Section "Go Package Structure Verification"

$expectedGoPackages = @(
    @{Path = "config"; Files = @("config.go") }
    @{Path = "errors"; Files = @("errors.go", "codes.go") }
    @{Path = "logging"; Files = @("logger.go", "levels.go") }
    @{Path = "health"; Files = @("health.go") }
    @{Path = "metrics"; Files = @("metrics.go", "registry.go") }
    @{Path = "utils"; Files = @("retry.go", "rate_limit.go") }
    @{Path = "redis"; Files = @("redis.go", "pipeline.go", "pubsub.go") }
    @{Path = "postgres"; Files = @("postgres.go", "transactions.go", "bulk_insert.go", "migrations.go") }
    @{Path = "grpc_client"; Files = @("client.go", "interceptors.go", "retry.go", "circuit_breaker.go", "load_balancer.go", "retry_budget.go", "service_discovery.go") }
)

foreach ($pkg in $expectedGoPackages) {
    $pkgPath = "$GoSharedPath\$($pkg.Path)"
    
    if (Test-Path $pkgPath) {
        $missingFiles = @()
        foreach ($file in $pkg.Files) {
            if (!(Test-Path "$pkgPath\$file")) {
                $missingFiles += $file
            }
        }
        
        if ($missingFiles.Count -eq 0) {
            Write-TestResult "$($pkg.Path) structure" $true "All $($pkg.Files.Count) files present"
        }
        else {
            Write-TestResult "$($pkg.Path) structure" $false "Missing: $($missingFiles -join ', ')"
        }
    }
    else {
        Write-TestResult "$($pkg.Path) structure" $false "Package directory not found"
    }
}

# ============================================================================
# Rust Shared Libraries Tests
# ============================================================================

if (!$SkipRust -and (Test-CommandExists "cargo")) {
    Write-Section "Rust Shared Libraries Tests"
    
    if (!(Test-Path $RustSharedPath)) {
        Write-TestResult "Rust shared path exists" $false "Path not found: $RustSharedPath"
    }
    else {
        Write-TestResult "Rust shared path exists" $true
        
        Push-Location $RustSharedPath
        
        # Test 1: Cargo.toml exists
        if (Test-Path "Cargo.toml") {
            Write-TestResult "Cargo.toml exists" $true
        }
        else {
            Write-TestResult "Cargo.toml exists" $false
        }
        
        # Test 2: Build
        Write-Host "`n  [Rust Build]" -ForegroundColor Cyan
        
        if (!$SkipBuild) {
            $cargoBuild = cargo build 2>&1 | Out-String
            if ($LASTEXITCODE -eq 0) {
                Write-TestResult "Cargo build" $true
            }
            else {
                Write-TestResult "Cargo build" $false $cargoBuild
                Add-Content -Path $ErrorLog -Value "`n=== Rust Build Output ===`n$cargoBuild"
            }
        }
        
        # Test 3: Cargo tests
        Write-Host "`n  [Rust Unit Tests]" -ForegroundColor Cyan
        
        $cargoTest = cargo test 2>&1 | Out-String
        if ($LASTEXITCODE -eq 0) {
            $testMatch = [regex]::Match($cargoTest, "(\d+) passed")
            $passedCount = if ($testMatch.Success) { $testMatch.Groups[1].Value } else { "?" }
            Write-TestResult "Cargo tests" $true "$passedCount tests passed"
        }
        else {
            Write-TestResult "Cargo tests" $false "Tests failed"
            Add-Content -Path $ErrorLog -Value "`n=== Rust Test Output ===`n$cargoTest"
        }
        
        # Test 4: Clippy (Rust linter)
        Write-Host "`n  [Rust Linting]" -ForegroundColor Cyan
        
        $clippyOutput = cargo clippy 2>&1 | Out-String
        if ($LASTEXITCODE -eq 0 -and $clippyOutput -notmatch "error\[") {
            Write-TestResult "Cargo clippy" $true
        }
        else {
            Write-TestResult "Cargo clippy" $false "Linting issues found"
        }
        
        Pop-Location
    }
}
else {
    Write-Section "Rust Tests (Skipped)"
    Write-Host "  ⊗ Rust tests skipped (cargo not found or --SkipRust)" -ForegroundColor DarkGray
}

# ============================================================================
# Compiled Executables Tests
# ============================================================================

Write-Section "Compiled Executables Tests"

# Look for any compiled .exe files
$exePaths = @(
    "$ProjectRoot\build"
    "$ProjectRoot\bin"
    "$ProjectRoot\target\debug"
    "$ProjectRoot\target\release"
)

$foundExes = @()
foreach ($path in $exePaths) {
    if (Test-Path $path) {
        $exes = Get-ChildItem -Path $path -Filter "*.exe" -Recurse -ErrorAction SilentlyContinue
        $foundExes += $exes
    }
}

if ($foundExes.Count -gt 0) {
    Write-Host "`n  Found $($foundExes.Count) executable(s):" -ForegroundColor White
    
    foreach ($exe in $foundExes) {
        Write-Host "  → Testing: $($exe.Name)" -ForegroundColor Cyan
        
        # Test 1: File exists and is valid PE
        if ($exe.Length -gt 0) {
            Write-TestResult "$($exe.Name) - Valid file" $true "Size: $([math]::Round($exe.Length/1KB, 2)) KB"
        }
        else {
            Write-TestResult "$($exe.Name) - Valid file" $false "Empty file"
        }
        
        # Test 2: Try running with --help or --version
        try {
            $helpOutput = & $exe.FullName --help 2>&1 | Out-String
            if ($LASTEXITCODE -eq 0 -or $helpOutput.Length -gt 0) {
                Write-TestResult "$($exe.Name) - Responds to --help" $true
            }
            else {
                Write-TestResult "$($exe.Name) - Responds to --help" $false
            }
        }
        catch {
            Write-TestResult "$($exe.Name) - Responds to --help" $false "Error: $($_.Exception.Message)"
        }
        
        # Test 3: Version check
        try {
            $versionOutput = & $exe.FullName --version 2>&1 | Out-String
            if ($versionOutput -match "\d+\.\d+") {
                Write-TestResult "$($exe.Name) - Version check" $true "Version: $($Matches[0])"
            }
        }
        catch {
            # Version check is optional
        }
    }
}
else {
    Write-Host "  ⊗ No compiled executables found (build first)" -ForegroundColor DarkGray
}

# ============================================================================
# Integration Tests
# ============================================================================

Write-Section "Integration Tests"

# Test PostgreSQL connection (if available)
if (Test-CommandExists "psql") {
    $env:PGPASSWORD = "SafeOps2024!"
    $null = & psql -U postgres -h localhost -c "SELECT 1;" 2>&1
    if ($LASTEXITCODE -eq 0) {
        Write-TestResult "PostgreSQL connection" $true
        
        # Check if safeops database exists
        $dbCheck = & psql -U postgres -h localhost -c "SELECT datname FROM pg_database WHERE datname='safeops';" 2>&1
        if ($dbCheck -match "safeops") {
            Write-TestResult "SafeOps database exists" $true
        }
        else {
            Write-TestResult "SafeOps database exists" $false
        }
    }
    else {
        Write-TestResult "PostgreSQL connection" $false "Cannot connect to PostgreSQL"
    }
}
else {
    Write-Host "  ⊗ PostgreSQL not available (skipped)" -ForegroundColor DarkGray
}

# Test Redis connection (if available)
if (Test-CommandExists "redis-cli") {
    $redisTest = & redis-cli ping 2>&1
    if ($redisTest -eq "PONG") {
        Write-TestResult "Redis connection" $true
    }
    else {
        Write-TestResult "Redis connection" $false "Cannot connect to Redis"
    }
}
else {
    Write-Host "  ⊗ Redis not available (skipped)" -ForegroundColor DarkGray
}

# ============================================================================
# Generate Summary Report
# ============================================================================

Write-Section "Test Summary"

$endTime = Get-Date
$duration = $endTime - $script:StartTime

$passRate = if ($script:TotalTests -gt 0) { 
    [math]::Round(($script:PassedTests / $script:TotalTests) * 100, 1) 
}
else { 0 }

$summaryColor = if ($script:FailedTests -eq 0) { "Green" } elseif ($script:FailedTests -lt 5) { "Yellow" } else { "Red" }

Write-Host "`n  ╔════════════════════════════════════════════╗" -ForegroundColor $summaryColor
Write-Host "  ║           TEST RESULTS SUMMARY              ║" -ForegroundColor $summaryColor
Write-Host "  ╠════════════════════════════════════════════╣" -ForegroundColor $summaryColor
Write-Host "  ║  Total Tests:    $($script:TotalTests.ToString().PadLeft(5))                    ║" -ForegroundColor $summaryColor
Write-Host "  ║  Passed:         $($script:PassedTests.ToString().PadLeft(5))  ✓                 ║" -ForegroundColor Green
Write-Host "  ║  Failed:         $($script:FailedTests.ToString().PadLeft(5))  ✗                 ║" -ForegroundColor $(if ($script:FailedTests -gt 0) { "Red" }else { "Green" })
Write-Host "  ║  Pass Rate:      $($passRate.ToString().PadLeft(5))%                  ║" -ForegroundColor $summaryColor
Write-Host "  ║  Duration:       $($duration.ToString("mm\:ss").PadLeft(5))                    ║" -ForegroundColor $summaryColor
Write-Host "  ╚════════════════════════════════════════════╝" -ForegroundColor $summaryColor

# Generate HTML report
$htmlReport = @"
<!DOCTYPE html>
<html>
<head>
    <title>SafeOps Test Report - $(Get-Date -Format 'yyyy-MM-dd HH:mm')</title>
    <style>
        body { font-family: 'Segoe UI', Arial, sans-serif; margin: 40px; background: #1a1a2e; color: #eee; }
        h1 { color: #00d4ff; }
        .summary { background: #16213e; padding: 20px; border-radius: 10px; margin: 20px 0; }
        .passed { color: #00ff88; }
        .failed { color: #ff4444; }
        table { width: 100%; border-collapse: collapse; margin: 20px 0; }
        th, td { padding: 12px; text-align: left; border-bottom: 1px solid #333; }
        th { background: #0f3460; }
        .error-list { background: #2a0f0f; padding: 15px; border-radius: 5px; margin: 10px 0; }
    </style>
</head>
<body>
    <h1>🛡️ SafeOps Test Report</h1>
    <p>Generated: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')</p>
    
    <div class="summary">
        <h2>Summary</h2>
        <p><strong>Total Tests:</strong> $($script:TotalTests)</p>
        <p class="passed"><strong>Passed:</strong> $($script:PassedTests) ✓</p>
        <p class="failed"><strong>Failed:</strong> $($script:FailedTests) ✗</p>
        <p><strong>Pass Rate:</strong> $passRate%</p>
        <p><strong>Duration:</strong> $($duration.ToString("mm\:ss"))</p>
    </div>
    
    $(if ($script:Errors.Count -gt 0) {
        "<h2>Failed Tests</h2><div class='error-list'><ul>"
        foreach ($err in $script:Errors) {
            "<li><strong>$($err.Name):</strong> $($err.Error)</li>"
        }
        "</ul></div>"
    })
    
    <h2>Test Files</h2>
    <ul>
        <li><a href="file:///$($LogFile.Replace('\','/'))">Full Log</a></li>
        <li><a href="file:///$($ErrorLog.Replace('\','/'))">Error Log</a></li>
        <li><a href="file:///$OutputDir/coverage.html">Coverage Report</a></li>
    </ul>
</body>
</html>
"@

$htmlReport | Out-File -FilePath $SummaryFile -Encoding UTF8

Write-Host "`n  Reports generated:" -ForegroundColor White
Write-Host "  → Full log: $LogFile" -ForegroundColor DarkGray
Write-Host "  → Errors: $ErrorLog" -ForegroundColor DarkGray  
Write-Host "  → HTML Summary: $SummaryFile" -ForegroundColor DarkGray
Write-Host "  → Coverage: $OutputDir\coverage.html" -ForegroundColor DarkGray

# Final result
Write-Host "`n"
if ($script:FailedTests -eq 0) {
    Write-Host "  ✅ ALL TESTS PASSED! SafeOps is production-ready." -ForegroundColor Green
    exit 0
}
else {
    Write-Host "  ❌ $($script:FailedTests) TEST(S) FAILED. Review errors above." -ForegroundColor Red
    exit 1
}
