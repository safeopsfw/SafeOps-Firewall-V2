<#
.SYNOPSIS
    SafeOps Proto Build Script for Windows

.DESCRIPTION
    PowerShell script to generate Go and Rust code from Protocol Buffers (.proto) files.
    
.PARAMETER Clean
    Remove previously generated code before building

.PARAMETER GoOnly
    Generate only Go code (skip Rust)

.PARAMETER RustOnly
    Generate only Rust code (skip Go)

.PARAMETER Help
    Display help message and exit

.EXAMPLE
    .\build.ps1
    Generate both Go and Rust code

.EXAMPLE
    .\build.ps1 -Clean -GoOnly
    Clean and generate only Go code

.EXAMPLE
    .\build.ps1 -RustOnly
    Generate only Rust code
#>

[CmdletBinding()]
param(
    [switch]$Clean,
    [switch]$GoOnly,
    [switch]$RustOnly,
    [switch]$Help
)

$ErrorActionPreference = "Stop"

################################################################################
# Configuration Variables
################################################################################

$ProtoDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$GrpcDir = Join-Path $ProtoDir "grpc"
$GoOutDir = Join-Path $ProtoDir "gen\go"
$RustOutDir = Join-Path $ProtoDir "gen\rust"

################################################################################
# Helper Functions
################################################################################

function Write-ColorOutput {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Message,
        
        [Parameter(Mandatory = $false)]
        [ValidateSet("Info", "Success", "Warning", "Error")]
        [string]$Type = "Info"
    )
    
    $prefix = ""
    $color = "White"
    
    switch ($Type) {
        "Info" { 
            $prefix = "[i]"
            $color = "Cyan"
        }
        "Success" { 
            $prefix = "[+]"
            $color = "Green"
        }
        "Warning" { 
            $prefix = "[!]"
            $color = "Yellow"
        }
        "Error" { 
            $prefix = "[X]"
            $color = "Red"
        }
    }
    
    Write-Host "$prefix $Message" -ForegroundColor $color
}

function Test-CommandExists {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Command
    )
    
    $oldPreference = $ErrorActionPreference
    $ErrorActionPreference = "SilentlyContinue"
    
    try {
        $null = Get-Command $Command
        return $true
    }
    catch {
        return $false
    }
    finally {
        $ErrorActionPreference = $oldPreference
    }
}

function Show-Help {
    Write-Host ""
    Write-Host "============================================================" -ForegroundColor Cyan
    Write-Host "   SafeOps Proto Build Script for Windows" -ForegroundColor Cyan
    Write-Host "============================================================" -ForegroundColor Cyan
    Write-Host ""
    Write-Host "USAGE:" -ForegroundColor Yellow
    Write-Host "    .\build.ps1 [OPTIONS]"
    Write-Host ""
    Write-Host "OPTIONS:" -ForegroundColor Yellow
    Write-Host "    -Clean      Remove previously generated code before building"
    Write-Host "    -GoOnly     Generate only Go code (skip Rust)"
    Write-Host "    -RustOnly   Generate only Rust code (skip Go)"
    Write-Host "    -Help       Display this help message"
    Write-Host ""
    Write-Host "EXAMPLES:" -ForegroundColor Yellow
    Write-Host "    .\build.ps1                     # Generate both Go and Rust"
    Write-Host "    .\build.ps1 -Clean -GoOnly      # Clean and generate Go only"
    Write-Host "    .\build.ps1 -RustOnly           # Generate Rust only"
    Write-Host ""
    Write-Host "REQUIREMENTS:" -ForegroundColor Yellow
    Write-Host "    - protoc (Protocol Buffers compiler)"
    Write-Host "    - protoc-gen-go (Go plugin)"
    Write-Host "    - protoc-gen-go-grpc (Go gRPC plugin)"
    Write-Host "    - protoc-gen-rust (Rust plugin, optional)"
    Write-Host ""
}

################################################################################
# Help Display
################################################################################

if ($Help) {
    Show-Help
    exit 0
}

################################################################################
# Validate Flags
################################################################################

if ($GoOnly -and $RustOnly) {
    Write-ColorOutput "Cannot use both -GoOnly and -RustOnly flags" -Type Error
    exit 1
}

################################################################################
# Banner
################################################################################

Write-Host ""
Write-Host "============================================================" -ForegroundColor Cyan
Write-Host "   SafeOps Protocol Buffers Code Generation" -ForegroundColor Cyan
Write-Host "============================================================" -ForegroundColor Cyan
Write-Host ""

################################################################################
# Determine What to Generate
################################################################################

$GenerateGo = -not $RustOnly
$GenerateRust = -not $GoOnly

################################################################################
# Dependency Checking
################################################################################

Write-ColorOutput "Checking required dependencies..." -Type Info
Write-Host ""

# Check protoc
if (-not (Test-CommandExists "protoc")) {
    Write-ColorOutput "protoc not found" -Type Error
    Write-Host "Install with:"
    Write-Host "  Chocolatey: choco install protoc"
    Write-Host "  Or download from: https://github.com/protocolbuffers/protobuf/releases"
    exit 1
}
$protocVersion = (protoc --version) -replace "libprotoc ", ""
Write-ColorOutput "protoc found (version $protocVersion)" -Type Success

# Check Go tools
if ($GenerateGo) {
    if (-not (Test-CommandExists "protoc-gen-go")) {
        Write-ColorOutput "protoc-gen-go not found" -Type Error
        Write-Host "Install with: go install google.golang.org/protobuf/cmd/protoc-gen-go@latest"
        exit 1
    }
    Write-ColorOutput "protoc-gen-go found" -Type Success

    if (-not (Test-CommandExists "protoc-gen-go-grpc")) {
        Write-ColorOutput "protoc-gen-go-grpc not found" -Type Error
        Write-Host "Install with: go install google.golang.org/grpc/cmd/protoc-gen-go-grpc@latest"
        exit 1
    }
    Write-ColorOutput "protoc-gen-go-grpc found" -Type Success
}

# Check Rust tools (optional)
if ($GenerateRust) {
    if (-not (Test-CommandExists "protoc-gen-rust")) {
        Write-ColorOutput "protoc-gen-rust not found (skipping Rust generation)" -Type Warning
        Write-Host "Install with: cargo install protobuf-codegen"
        $GenerateRust = $false
    }
    else {
        Write-ColorOutput "protoc-gen-rust found" -Type Success
    }
}

Write-Host ""

################################################################################
# Clean Operation
################################################################################

if ($Clean) {
    Write-ColorOutput "Cleaning previously generated code..." -Type Info
    
    if ($GenerateGo -and (Test-Path $GoOutDir)) {
        Remove-Item -Path $GoOutDir -Recurse -Force
        Write-ColorOutput "Removed Go output directory: $GoOutDir" -Type Success
    }
    
    if ($GenerateRust -and (Test-Path $RustOutDir)) {
        Remove-Item -Path $RustOutDir -Recurse -Force
        Write-ColorOutput "Removed Rust output directory: $RustOutDir" -Type Success
    }
    
    Write-Host ""
}

################################################################################
# Directory Creation
################################################################################

Write-ColorOutput "Creating output directories..." -Type Info

if ($GenerateGo) {
    if (-not (Test-Path $GoOutDir)) {
        New-Item -ItemType Directory -Path $GoOutDir -Force | Out-Null
    }
    Write-ColorOutput "Go output directory: $GoOutDir" -Type Success
}

if ($GenerateRust) {
    if (-not (Test-Path $RustOutDir)) {
        New-Item -ItemType Directory -Path $RustOutDir -Force | Out-Null
    }
    Write-ColorOutput "Rust output directory: $RustOutDir" -Type Success
}

Write-Host ""

################################################################################
# Proto File Discovery
################################################################################

Write-ColorOutput "Discovering .proto files..." -Type Info

if (-not (Test-Path $GrpcDir)) {
    Write-ColorOutput "gRPC directory not found: $GrpcDir" -Type Error
    exit 1
}

$ProtoFiles = Get-ChildItem -Path $GrpcDir -Filter "*.proto" -Recurse | Sort-Object Name
$ProtoCount = $ProtoFiles.Count

if ($ProtoCount -eq 0) {
    Write-ColorOutput "No .proto files found in $GrpcDir" -Type Error
    exit 1
}

Write-ColorOutput "Found $ProtoCount .proto file(s)" -Type Success
Write-Host ""

################################################################################
# Go Code Generation
################################################################################

$GoFileCount = 0

if ($GenerateGo) {
    Write-ColorOutput "Generating Go code..." -Type Info
    Write-Host ""
    
    $GoSuccessCount = 0
    $GoFailCount = 0
    
    foreach ($file in $ProtoFiles) {
        Write-Host "  Processing $($file.Name)... " -NoNewline
        
        try {
            $result = & protoc `
                --proto_path="$GrpcDir" `
                --go_out="$GoOutDir" `
                --go_opt=paths=source_relative `
                --go-grpc_out="$GoOutDir" `
                --go-grpc_opt=paths=source_relative `
                $file.FullName 2>&1
            
            if ($LASTEXITCODE -eq 0) {
                Write-Host "OK" -ForegroundColor Green
                $GoSuccessCount++
            }
            else {
                Write-Host "FAILED" -ForegroundColor Red
                Write-ColorOutput "Error: $result" -Type Error
                $GoFailCount++
            }
        }
        catch {
            Write-Host "FAILED" -ForegroundColor Red
            Write-ColorOutput "Error: $_" -Type Error
            $GoFailCount++
        }
    }
    
    Write-Host ""
    
    if ($GoFailCount -eq 0) {
        $GoFiles = Get-ChildItem -Path $GoOutDir -Filter "*.pb.go" -Recurse -ErrorAction SilentlyContinue
        $GoFileCount = if ($GoFiles) { $GoFiles.Count } else { 0 }
        Write-ColorOutput "Go code generation complete: $GoFileCount file(s) generated" -Type Success
    }
    else {
        Write-ColorOutput "Go code generation completed with $GoFailCount error(s)" -Type Error
        exit 1
    }
    
    Write-Host ""
}

################################################################################
# Rust Code Generation
################################################################################

$RustFileCount = 0

if ($GenerateRust) {
    Write-ColorOutput "Generating Rust code..." -Type Info
    Write-Host ""
    
    $RustSuccessCount = 0
    $RustFailCount = 0
    
    foreach ($file in $ProtoFiles) {
        Write-Host "  Processing $($file.Name)... " -NoNewline
        
        try {
            $result = & protoc `
                --proto_path="$GrpcDir" `
                --rust_out="$RustOutDir" `
                $file.FullName 2>&1
            
            if ($LASTEXITCODE -eq 0) {
                Write-Host "OK" -ForegroundColor Green
                $RustSuccessCount++
            }
            else {
                Write-Host "FAILED" -ForegroundColor Red
                Write-ColorOutput "Error: $result" -Type Error
                $RustFailCount++
            }
        }
        catch {
            Write-Host "FAILED" -ForegroundColor Red
            Write-ColorOutput "Error: $_" -Type Error
            $RustFailCount++
        }
    }
    
    Write-Host ""
    
    if ($RustFailCount -eq 0) {
        $RustFiles = Get-ChildItem -Path $RustOutDir -Filter "*.rs" -Recurse -ErrorAction SilentlyContinue
        $RustFileCount = if ($RustFiles) { $RustFiles.Count } else { 0 }
        Write-ColorOutput "Rust code generation complete: $RustFileCount file(s) generated" -Type Success
        
        # Generate mod.rs
        if ($RustFileCount -gt 0) {
            Write-ColorOutput "Generating mod.rs..." -Type Info
            $ModFile = Join-Path $RustOutDir "mod.rs"
            
            $modContent = @()
            $modContent += "// Auto-generated module file"
            $modContent += "// Generated on: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')"
            $modContent += ""
            
            foreach ($rsFile in $RustFiles) {
                if ($rsFile.Name -ne "mod.rs") {
                    $moduleName = $rsFile.BaseName
                    $modContent += "pub mod $moduleName;"
                }
            }
            
            $modContent | Out-File -FilePath $ModFile -Encoding utf8
            Write-ColorOutput "Generated mod.rs with $RustFileCount module(s)" -Type Success
        }
    }
    else {
        Write-ColorOutput "Rust code generation completed with $RustFailCount error(s)" -Type Error
        exit 1
    }
    
    Write-Host ""
}

################################################################################
# Build Summary
################################################################################

Write-Host ""
Write-Host "============================================================" -ForegroundColor Green
Write-Host "   Build Summary" -ForegroundColor Green
Write-Host "============================================================" -ForegroundColor Green
Write-Host ""
Write-Host "  Proto files processed: $ProtoCount"

if ($GenerateGo) {
    Write-Host "  Go files generated:    $GoFileCount"
    Write-Host "  Go output directory:   $GoOutDir"
}

if ($GenerateRust) {
    Write-Host "  Rust files generated:  $RustFileCount"
    Write-Host "  Rust output directory: $RustOutDir"
}

Write-Host ""
Write-Host "[+] Build completed successfully!" -ForegroundColor Green
Write-Host "    Timestamp: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')"
Write-Host ""

exit 0
