<#
.SYNOPSIS
    SafeOps Protocol Buffers Build Script for Windows

.DESCRIPTION
    PowerShell script to generate Go and Rust code from Protocol Buffers (.proto) files.
    Automates the protocol buffer compilation process with dependency resolution, tool validation,
    and comprehensive error handling for CI/CD integration.
    
.PARAMETER Clean
    Remove previously generated code before building

.PARAMETER VerboseOutput
    Enable detailed output during compilation

.PARAMETER CheckOnly
    Validate proto syntax without generating code

.PARAMETER ProtoPath
    Custom proto source directory (default: proto/grpc/)

.PARAMETER OutputPath
    Custom output directory for generated code (default: build/proto/)

.PARAMETER GoOnly
    Generate only Go code (skip Rust)

.PARAMETER Help
    Display help message and exit

.EXAMPLE
    .\build.ps1
    Generate both Go and Rust code

.EXAMPLE
    .\build.ps1 -Clean -VerboseOutput
    Clean and generate with detailed output

.EXAMPLE
    .\build.ps1 -CheckOnly
    Validate proto files without code generation
#>

[CmdletBinding()]
param(
    [switch]$Clean,
    [switch]$VerboseOutput,
    [switch]$CheckOnly,
    [string]$ProtoPath = "",
    [string]$OutputPath = "",
    [switch]$GoOnly,
    [switch]$Help
)

$ErrorActionPreference = "Stop"
$StartTime = Get-Date

################################################################################
# Configuration Variables
################################################################################

$ProtoDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$ProjectRoot = Split-Path -Parent $ProtoDir
$GrpcDir = if ($ProtoPath) { $ProtoPath } else { Join-Path $ProtoDir "grpc" }
$BuildDir = Join-Path $ProjectRoot "build"
$GoOutDir = if ($OutputPath) { Join-Path $OutputPath "go" } else { Join-Path $BuildDir "proto\go" }
$RustOutDir = if ($OutputPath) { Join-Path $OutputPath "rust" } else { Join-Path $BuildDir "proto\rust" }

# Go module path for generated code
$GoModulePath = "safeops/build/proto/go"

# Minimum version requirements
$MinProtocVersion = "3.19.0"
$MinGoPluginVersion = "1.28.0"

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
            $prefix = "[INFO]"
            $color = "Cyan"
        }
        "Success" { 
            $prefix = "[SUCCESS]"
            $color = "Green"
        }
        "Warning" { 
            $prefix = "[WARNING]"
            $color = "Yellow"
        }
        "Error" { 
            $prefix = "[ERROR]"
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

function Compare-Version {
    param(
        [string]$Version1,
        [string]$Version2
    )
    
    $v1 = [version]($Version1 -replace "[^0-9.]", "")
    $v2 = [version]($Version2 -replace "[^0-9.]", "")
    
    return $v1.CompareTo($v2)
}

function Get-ProtoFiles {
    param(
        [string]$Directory
    )
    
    if (-not (Test-Path $Directory)) {
        Write-ColorOutput "Proto directory not found: $Directory" -Type Error
        exit 1
    }
    
    $protoFiles = Get-ChildItem -Path $Directory -Filter "*.proto" -File | Sort-Object Name
    
    if ($protoFiles.Count -eq 0) {
        Write-ColorOutput "No .proto files found in: $Directory" -Type Warning
    }
    
    return $protoFiles
}

function Show-Help {
    Write-Host ""
    Write-Host "============================================================" -ForegroundColor Cyan
    Write-Host "   SafeOps Protocol Buffers Build Script" -ForegroundColor Cyan
    Write-Host "============================================================" -ForegroundColor Cyan
    Write-Host ""
    Write-Host "USAGE:" -ForegroundColor Yellow
    Write-Host "    .\build.ps1 [OPTIONS]"
    Write-Host ""
    Write-Host "OPTIONS:" -ForegroundColor Yellow
    Write-Host "    -Clean          Remove previously generated code before building"
    Write-Host "    -VerboseOutput  Enable detailed output during compilation"
    Write-Host "    -CheckOnly      Validate proto syntax without generating code"
    Write-Host "    -ProtoPath      Custom proto source directory"
    Write-Host "    -OutputPath     Custom output directory for generated code"
    Write-Host "    -GoOnly         Generate only Go code (skip Rust)"
    Write-Host "    -Help           Display this help message"
    Write-Host ""
    Write-Host "EXAMPLES:" -ForegroundColor Yellow
    Write-Host "    .\build.ps1                          # Full build"
    Write-Host "    .\build.ps1 -Clean -VerboseOutput   # Clean build with details"
    Write-Host "    .\build.ps1 -CheckOnly               # Syntax validation only"
    Write-Host ""
    Write-Host "REQUIREMENTS:" -ForegroundColor Yellow
    Write-Host "    - PowerShell 5.1+ or PowerShell Core 7+"
    Write-Host "    - protoc v$MinProtocVersion+"
    Write-Host "    - protoc-gen-go v$MinGoPluginVersion+"
    Write-Host "    - protoc-gen-go-grpc v1.2.0+"
    Write-Host "    - Go 1.19+ (for Go code generation)"
    Write-Host ""
    Write-Host "OUTPUT STRUCTURE:" -ForegroundColor Yellow
    Write-Host "    build/proto/go/       - Generated Go code"
    Write-Host "    build/proto/rust/     - Generated Rust code"
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
# Banner
################################################################################

Write-Host ""
Write-Host "============================================================" -ForegroundColor Cyan
Write-Host "   SafeOps Protocol Buffers Code Generation" -ForegroundColor Cyan
Write-Host "============================================================" -ForegroundColor Cyan
Write-Host ""

################################################################################
# Environment Validation
################################################################################

Write-ColorOutput "Validating build environment..." -Type Info
Write-Host ""

# Check PowerShell version
$psVersion = $PSVersionTable.PSVersion
if ($psVersion.Major -lt 5 -or ($psVersion.Major -eq 5 -and $psVersion.Minor -lt 1)) {
    Write-ColorOutput "PowerShell 5.1 or higher required (found $psVersion)" -Type Error
    exit 1
}
Write-ColorOutput "PowerShell version: $psVersion" -Type Success

# Check protoc
if (-not (Test-CommandExists "protoc")) {
    Write-ColorOutput "protoc compiler not found in PATH" -Type Error
    Write-Host "Install with:"
    Write-Host "  Chocolatey: choco install protoc"
    Write-Host "  Or download from: https://github.com/protocolbuffers/protobuf/releases"
    exit 1
}
$protocVersionOutput = (protoc --version) -replace "libprotoc ", ""
$protocVersion = $protocVersionOutput.Trim()
if ((Compare-Version $protocVersion $MinProtocVersion) -lt 0) {
    Write-ColorOutput "protoc version $MinProtocVersion+ required (found $protocVersion)" -Type Warning
}
Write-ColorOutput "protoc compiler: v$protocVersion" -Type Success

# Check protoc-gen-go
if (-not (Test-CommandExists "protoc-gen-go")) {
    Write-ColorOutput "protoc-gen-go plugin not found in PATH" -Type Error
    Write-Host "Install with: go install google.golang.org/protobuf/cmd/protoc-gen-go@latest"
    exit 1
}
try {
    $goPluginVersion = (protoc-gen-go --version 2>&1) -replace "protoc-gen-go ", ""
    Write-ColorOutput "protoc-gen-go: v$goPluginVersion" -Type Success
}
catch {
    Write-ColorOutput "protoc-gen-go: installed (version check failed)" -Type Success
}

# Check protoc-gen-go-grpc
if (-not (Test-CommandExists "protoc-gen-go-grpc")) {
    Write-ColorOutput "protoc-gen-go-grpc plugin not found in PATH" -Type Error
    Write-Host "Install with: go install google.golang.org/grpc/cmd/protoc-gen-go-grpc@latest"
    exit 1
}
Write-ColorOutput "protoc-gen-go-grpc: installed" -Type Success

# Check Go installation
if (-not (Test-CommandExists "go")) {
    Write-ColorOutput "Go not found in PATH" -Type Warning
    Write-Host "Go is recommended for module management"
}
else {
    $goVersion = (go version) -replace "go version go", "" -replace " .*", ""
    Write-ColorOutput "Go compiler: v$goVersion" -Type Success
}

Write-Host ""

################################################################################
# Directory Structure Setup
################################################################################

Write-ColorOutput "Setting up directory structure..." -Type Info

# Create build directory if it doesn't exist
if (-not (Test-Path $BuildDir)) {
    New-Item -Path $BuildDir -ItemType Directory -Force | Out-Null
    Write-ColorOutput "Created build directory: $BuildDir" -Type Success
}

# Clean operation
if ($Clean) {
    Write-ColorOutput "Cleaning previously generated code..." -Type Info
    
    if (Test-Path $GoOutDir) {
        Remove-Item -Path $GoOutDir -Recurse -Force
        Write-ColorOutput "Removed: $GoOutDir" -Type Success
    }
    
    if (-not $GoOnly -and (Test-Path $RustOutDir)) {
        Remove-Item -Path $RustOutDir -Recurse -Force
        Write-ColorOutput "Removed: $RustOutDir" -Type Success
    }
}

# Create output directories
if (-not (Test-Path $GoOutDir)) {
    New-Item -Path $GoOutDir -ItemType Directory -Force | Out-Null
    Write-ColorOutput "Created Go output directory: $GoOutDir" -Type Success
}

if (-not $GoOnly -and -not (Test-Path $RustOutDir)) {
    New-Item -Path $RustOutDir -ItemType Directory -Force | Out-Null
    Write-ColorOutput "Created Rust output directory: $RustOutDir" -Type Success
}

Write-Host ""

################################################################################
# Proto File Discovery
################################################################################

Write-ColorOutput "Discovering proto files..." -Type Info

$protoFiles = Get-ProtoFiles -Directory $GrpcDir

if ($protoFiles.Count -eq 0) {
    Write-ColorOutput "No proto files found to compile" -Type Warning
    exit 0
}

Write-ColorOutput "Found $($protoFiles.Count) proto files" -Type Success

if ($Verbose) {
    foreach ($file in $protoFiles) {
        Write-Host "  - $($file.Name)" -ForegroundColor Gray
    }
}

Write-Host ""

################################################################################
# Compilation Loop - Go Code Generation
################################################################################

Write-ColorOutput "Compiling proto files to Go..." -Type Info
Write-Host ""

$successCount = 0
$failCount = 0
$errors = @()

foreach ($protoFile in $protoFiles) {
    $fileName = $protoFile.Name
    $filePath = $protoFile.FullName
    
    # Extract service name for per-service subdirectory
    $serviceName = [System.IO.Path]::GetFileNameWithoutExtension($fileName)
    $serviceOutDir = Join-Path $GoOutDir $serviceName
    
    # Create service-specific output directory
    if (-not (Test-Path $serviceOutDir)) {
        New-Item -Path $serviceOutDir -ItemType Directory -Force | Out-Null
    }
    
    if ($VerboseOutput) {
        Write-ColorOutput "Compiling: $fileName -> $serviceName/" -Type Info
    }
    
    try {
        # Build protoc command for Go (output to service-specific directory)
        $protocArgs = @(
            "--proto_path=$GrpcDir"
            "--go_out=$serviceOutDir"
            "--go_opt=paths=source_relative"
            "--go-grpc_out=$serviceOutDir"
            "--go-grpc_opt=paths=source_relative"
            $filePath
        )
        
        if ($CheckOnly) {
            # Syntax check only
            $protocArgs = @(
                "--proto_path=$GrpcDir"
                "--descriptor_set_out=NUL"
                $filePath
            )
        }
        
        # Execute protoc
        $output = & protoc $protocArgs 2>&1
        
        if ($LASTEXITCODE -ne 0) {
            throw "protoc failed with exit code $LASTEXITCODE`n$output"
        }
        
        $successCount++
        if ($VerboseOutput) {
            Write-ColorOutput "  ✓ $fileName" -Type Success
        }
    }
    catch {
        $failCount++
        $errMsg = "Failed to compile: $fileName`n  Error: $($_.Exception.Message)"
        $errors += $errMsg
        Write-ColorOutput $errMsg -Type Error
    }
}

Write-Host ""

################################################################################
# Rust Code Generation (Template Creation)
################################################################################

if (-not $GoOnly -and -not $CheckOnly) {
    Write-ColorOutput "Setting up Rust proto integration..." -Type Info
    
    $buildRsTemplate = @"
// Rust Proto Build Template for SafeOps
// This file provides guidance for Rust services to use tonic-build for proto compilation.
// 
// USAGE: Copy this to your Rust service's build.rs file and customize as needed.
//
// Example build.rs:
// ```rust
// fn main() -> Result<(), Box<dyn std::error::Error>> {
//     tonic_build::configure()
//         .build_server(true)
//         .build_client(true)
//         .compile(
//             &[
//                 "../../proto/grpc/common.proto",
//                 "../../proto/grpc/firewall.proto",
//                 // Add your proto files here
//             ],
//             &["../../proto/grpc/"],
//         )?;
//     Ok(())
// }
// ```
//
// Add to Cargo.toml:
// [build-dependencies]
// tonic-build = "0.10"
// 
// [dependencies]
// tonic = "0.10"
// prost = "0.12"

"@
    
    $buildRsPath = Join-Path $RustOutDir "build.rs.template"
    $buildRsTemplate | Out-File -FilePath $buildRsPath -Encoding UTF8
    Write-ColorOutput "Created Rust build template: $buildRsPath" -Type Success
    Write-Host ""
}

################################################################################
# Success Reporting
################################################################################

$duration = (Get-Date) - $StartTime

Write-Host ""
Write-Host "============================================================" -ForegroundColor Cyan
Write-Host "   Build Summary" -ForegroundColor Cyan
Write-Host "============================================================" -ForegroundColor Cyan
Write-Host ""

if ($CheckOnly) {
    Write-ColorOutput "Syntax Validation Complete" -Type Success
}
else {
    Write-ColorOutput "Code Generation Complete" -Type Success
}

Write-Host ""
Write-ColorOutput "Proto files processed: $($protoFiles.Count)" -Type Info
Write-ColorOutput "Successfully compiled: $successCount" -Type Success

if ($failCount -gt 0) {
    Write-ColorOutput "Failed to compile: $failCount" -Type Error
    Write-Host ""
    Write-ColorOutput "Errors encountered:" -Type Error
    foreach ($errItem in $errors) {
        Write-Host "  $errItem" -ForegroundColor Red
    }
}

Write-ColorOutput "Build time: $($duration.TotalSeconds.ToString('F2')) seconds" -Type Info

Write-Host ""

# Generated files validation
if (-not $CheckOnly) {
    $goFiles = Get-ChildItem -Path $GoOutDir -Filter "*.pb.go" -Recurse -File
    $grpcFiles = Get-ChildItem -Path $GoOutDir -Filter "*_grpc.pb.go" -Recurse -File
    
    Write-ColorOutput "Generated Go files:" -Type Info
    Write-Host "  - Protocol buffer files: $($goFiles.Count)" -ForegroundColor Gray
    Write-Host "  - gRPC service files: $($grpcFiles.Count)" -ForegroundColor Gray
    
    if ($Verbose) {
        Write-Host ""
        Write-ColorOutput "Output locations:" -Type Info
        Write-Host "  - Go code: $GoOutDir" -ForegroundColor Gray
        if (-not $GoOnly) {
            Write-Host "  - Rust template: $RustOutDir" -ForegroundColor Gray
        }
    }
}

Write-Host ""

# Next steps
if ($failCount -eq 0 -and -not $CheckOnly) {
    Write-ColorOutput "Next steps:" -Type Info
    Write-Host "  1. Run 'go mod tidy' to update Go dependencies" -ForegroundColor Gray
    Write-Host "  2. Import generated packages in your Go services" -ForegroundColor Gray
    Write-Host "  3. For Rust services, use the template in build/proto/rust/" -ForegroundColor Gray
    Write-Host ""
}

# Exit with appropriate code
if ($failCount -gt 0) {
    exit 1
}

exit 0
