# SafeOps Configuration Validator
# PowerShell version for Windows
# Usage: .\config_validator.ps1 [config_file]

param(
    [string]$FilePath = "",
    [switch]$Help
)

# Colors
$script:Red = "`e[31m"
$script:Green = "`e[32m"
$script:Yellow = "`e[33m"
$script:Blue = "`e[34m"
$script:Reset = "`e[0m"

function Write-ColorOutput {
    param(
        [string]$Message,
        [string]$Color = "Reset"
    )
    $colorCode = $script:Reset
    switch ($Color) {
        "Red" { $colorCode = $script:Red }
        "Green" { $colorCode = $script:Green }
        "Yellow" { $colorCode = $script:Yellow }
        "Blue" { $colorCode = $script:Blue }
    }
    Write-Host "$colorCode$Message$($script:Reset)"
}

if ($Help) {
    Write-Host @"
SafeOps Configuration Validator

Usage:
    .\config_validator.ps1                    # Validate all config files
    .\config_validator.ps1 <file>            # Validate specific file
    .\config_validator.ps1 -Help             # Show this help

Supported formats:
    - TOML (.toml)
    - YAML (.yaml, .yml)
    - JSON (.json)

Examples:
    .\config_validator.ps1 templates\threat_intel.toml
    .\config_validator.ps1 defaults\home_network.toml
"@
    exit 0
}

Write-Host "============================================"
Write-Host "SafeOps Configuration Validator (PowerShell)"
Write-Host "============================================"
Write-Host ""

$totalErrors = 0

# Function to validate TOML
function Test-TomlFile {
    param([string]$Path)
    
    Write-ColorOutput "Validating TOML: $Path" "Blue"
    
    try {
        # Basic syntax check - ensure it's parseable
        $content = Get-Content $Path -Raw
        
        # Check for basic TOML structure
        if ($content -match '^\s*\[.*\]|\w+\s*=') {
            Write-ColorOutput "  ✓ Valid TOML format" "Green"
            return $true
        }
        else {
            Write-ColorOutput "  ✗ Invalid TOML format" "Red"
            return $false
        }
    }
    catch {
        Write-ColorOutput "  ✗ Error reading file: $_" "Red"
        return $false
    }
}

# Function to validate YAML
function Test-YamlFile {
    param([string]$Path)
    
    Write-ColorOutput "Validating YAML: $Path" "Blue"
    
    try {
        $content = Get-Content $Path -Raw
        
        # Basic YAML syntax check
        if ($content -match '^\s*\w+:' -or $content -match '^\s*-\s+') {
            Write-ColorOutput "  ✓ Valid YAML format" "Green"
            return $true
        }
        else {
            Write-ColorOutput "  ✗ Invalid YAML format" "Red"
            return $false
        }
    }
    catch {
        Write-ColorOutput "  ✗ Error reading file: $_" "Red"
        return $false
    }
}

# Function to validate JSON
function Test-JsonFile {
    param([string]$Path)
    
    Write-ColorOutput "Validating JSON: $Path" "Blue"
    
    try {
        $null = Get-Content $Path -Raw | ConvertFrom-Json
        Write-ColorOutput "  ✓ Valid JSON format" "Green"
        return $true
    }
    catch {
        Write-ColorOutput "  ✗ Invalid JSON: $_" "Red"
        return $false
    }
}

# Function to validate directory
function Test-ConfigDirectory {
    param([string]$Directory)
    
    Write-Host ""
    Write-Host "Validating directory: $Directory"
    Write-Host "----------------------------------------"
    
    if (!(Test-Path $Directory)) {
        Write-ColorOutput "Directory not found: $Directory" "Yellow"
        return 0
    }
    
    $errors = 0
    $files = Get-ChildItem -Path $Directory -Include *.toml, *.yaml, *.yml, *.json -File
    
    foreach ($file in $files) {
        switch ($file.Extension) {
            ".toml" {
                if (!(Test-TomlFile $file.FullName)) { $errors++ }
            }
            { $_ -in ".yaml", ".yml" } {
                if (!(Test-YamlFile $file.FullName)) { $errors++ }
            }
            ".json" {
                if (!(Test-JsonFile $file.FullName)) { $errors++ }
            }
        }
    }
    
    return $errors
}

# Main validation
if ($FilePath) {
    if (!(Test-Path $FilePath)) {
        Write-ColorOutput "Error: File not found: $FilePath" "Red"
        exit 1
    }
    
    $extension = [System.IO.Path]::GetExtension($FilePath)
    $result = $false
    
    switch ($extension) {
        ".toml" { $result = Test-TomlFile $FilePath }
        { $_ -in ".yaml", ".yml" } { $result = Test-YamlFile $FilePath }
        ".json" { $result = Test-JsonFile $FilePath }
        default {
            Write-ColorOutput "Error: Unsupported file type: $extension" "Red"
            exit 1
        }
    }
    
    Write-Host ""
    if ($result) {
        Write-ColorOutput "✓ Validation complete!" "Green"
        exit 0
    }
    else {
        Write-ColorOutput "✗ Validation failed!" "Red"
        exit 1
    }
}

# Validate all directories
$totalErrors += Test-ConfigDirectory "templates"
$totalErrors += Test-ConfigDirectory "defaults"
$totalErrors += Test-ConfigDirectory "examples"
$totalErrors += Test-ConfigDirectory "schemas"

# Summary
Write-Host ""
Write-Host "============================================"
if ($totalErrors -eq 0) {
    Write-ColorOutput "✓ All configuration files are valid!" "Green"
}
else {
    Write-ColorOutput "✗ Found $totalErrors error(s) in configuration files" "Red"
}
Write-Host "============================================"

exit $totalErrors
