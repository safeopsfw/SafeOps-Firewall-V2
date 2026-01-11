# ============================================================================
# Script: Get Step-CA Password from PostgreSQL
# ============================================================================
# File: D:\SafeOpsFV2\src\step-ca\scripts\get-password.ps1
# Purpose: Retrieve and decrypt Step-CA master password from PostgreSQL
# Usage: Called by start-stepca.ps1 during Step-CA service startup
#
# Output Modes:
#   - Stdout: Write password to console (for piping)
#   - File: Write to temporary file (for --password-file flag)
#   - SecureString: Return as PowerShell SecureString
#
# Security Notes:
#   - Output should never be logged
#   - Temp files must be deleted immediately after use
#   - Encryption key should be in environment variable, not hardcoded
#
# Prerequisites:
#   - PostgreSQL connection configured
#   - Encryption key available (env var or file)
#   - secrets table exists (migration 022 applied)
#   - step-ca-master entry inserted
#
# Author: SafeOps Phase 3A
# Date: 2026-01-03
# ============================================================================

[CmdletBinding()]
param(
    # How to return the password
    [Parameter()]
    [ValidateSet('Stdout', 'File', 'SecureString')]
    [string]$OutputMode = 'File',
    
    # Temporary file path (uses process ID for uniqueness)
    [Parameter()]
    [string]$OutputPath = "$env:TEMP\stepca_password_$PID.tmp",
    
    # PostgreSQL server hostname
    [Parameter()]
    [string]$DatabaseHost = 'localhost',
    
    # PostgreSQL port
    [Parameter()]
    [int]$DatabasePort = 5432,
    
    # Target database
    [Parameter()]
    [string]$DatabaseName = 'safeops_network',
    
    # PostgreSQL username
    [Parameter()]
    [string]$DatabaseUser = 'safeops_admin',
    
    # Where to get encryption key (EnvVar, File)
    [Parameter()]
    [ValidateSet('EnvVar', 'File')]
    [string]$EncryptionKeySource = 'EnvVar',
    
    # Auto-delete temp file when script exits
    [Parameter()]
    [switch]$DeleteOnExit
)

# ============================================================================
# Error Handling Setup
# ============================================================================

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

# ============================================================================
# Main Script Logic
# ============================================================================

try {
    Write-Verbose "Starting Step-CA password retrieval..."
    Write-Verbose "Output Mode: $OutputMode"
    Write-Verbose "Database: $DatabaseHost`:$DatabasePort/$DatabaseName"
    
    # ========================================================================
    # SECTION 1: Get Encryption Key
    # ========================================================================
    
    $encryptionKey = $null
    
    switch ($EncryptionKeySource) {
        'EnvVar' {
            $encryptionKey = $env:SAFEOPS_DB_ENCRYPTION_KEY
            if (-not $encryptionKey) {
                throw "Environment variable SAFEOPS_DB_ENCRYPTION_KEY not set"
            }
            Write-Verbose "Encryption key loaded from environment variable"
        }
        'File' {
            $keyPath = Join-Path $PSScriptRoot "..\secrets\db_encryption.key"
            if (-not (Test-Path $keyPath)) {
                throw "Encryption key file not found: $keyPath"
            }
            $encryptionKey = (Get-Content $keyPath -Raw).Trim()
            Write-Verbose "Encryption key loaded from file: $keyPath"
        }
    }
    
    if ([string]::IsNullOrWhiteSpace($encryptionKey)) {
        throw "Encryption key is empty or null"
    }
    
    # ========================================================================
    # SECTION 2: Build Database Connection
    # ========================================================================
    
    # Check for database password in environment
    $dbPassword = $null
    if ($env:PGPASSWORD) {
        $dbPassword = $env:PGPASSWORD
        Write-Verbose "Using PGPASSWORD environment variable for database auth"
    }
    elseif ($env:SAFEOPS_DB_PASSWORD) {
        $dbPassword = $env:SAFEOPS_DB_PASSWORD
        Write-Verbose "Using SAFEOPS_DB_PASSWORD environment variable for database auth"
    }
    else {
        Write-Verbose "Using .pgpass file or Windows auth for database connection"
    }
    
    # ========================================================================
    # SECTION 3: Build Decryption Query
    # ========================================================================
    
    # Escape single quotes in encryption key for SQL safety
    $escapedKey = $encryptionKey.Replace("'", "''")
    
    $decryptQuery = @"
SELECT pgp_sym_decrypt(
    secret_value_encrypted,
    '$escapedKey'
)::text AS decrypted_password
FROM secrets
WHERE service_name = 'step-ca-master';
"@
    
    # ========================================================================
    # SECTION 4: Execute Database Query
    # ========================================================================
    
    Write-Verbose "Executing decryption query..."
    
    # Find psql executable
    $psqlPath = $null
    $possiblePaths = @(
        "C:\Program Files\PostgreSQL\18\bin\psql.exe",
        "C:\Program Files\PostgreSQL\17\bin\psql.exe",
        "C:\Program Files\PostgreSQL\16\bin\psql.exe",
        "C:\Program Files\PostgreSQL\15\bin\psql.exe",
        "psql.exe"  # Try PATH
    )
    
    foreach ($path in $possiblePaths) {
        if ($path -eq "psql.exe") {
            $found = Get-Command psql.exe -ErrorAction SilentlyContinue
            if ($found) {
                $psqlPath = $found.Source
                break
            }
        }
        elseif (Test-Path $path) {
            $psqlPath = $path
            break
        }
    }
    
    if (-not $psqlPath) {
        throw "psql.exe not found. Install PostgreSQL client tools or add to PATH."
    }
    
    Write-Verbose "Using psql: $psqlPath"
    
    # Set password environment variable temporarily
    $originalPgPassword = $env:PGPASSWORD
    try {
        if ($dbPassword) {
            $env:PGPASSWORD = $dbPassword
        }
        
        # Execute query
        $result = & $psqlPath `
            -h $DatabaseHost `
            -p $DatabasePort `
            -U $DatabaseUser `
            -d $DatabaseName `
            -t -A `
            -c $decryptQuery 2>&1
        
        if ($LASTEXITCODE -ne 0) {
            throw "psql command failed with exit code $LASTEXITCODE`: $result"
        }
        
        $password = $result.Trim()
        
        if ([string]::IsNullOrWhiteSpace($password)) {
            throw "No password retrieved from database. Ensure step-ca-master secret exists."
        }
        
        Write-Verbose "Password retrieved successfully (length: $($password.Length))"
        
    }
    finally {
        # Restore original PGPASSWORD
        if ($originalPgPassword) {
            $env:PGPASSWORD = $originalPgPassword
        }
        else {
            Remove-Item Env:\PGPASSWORD -ErrorAction SilentlyContinue
        }
    }
    
    # ========================================================================
    # SECTION 5: Output Password Based on Mode
    # ========================================================================
    
    switch ($OutputMode) {
        'Stdout' {
            # Output to console (for piping to other commands)
            Write-Output $password
        }
        
        'File' {
            # Write to temporary file
            $password | Out-File -FilePath $OutputPath -Encoding ASCII -NoNewline
            
            # Set restrictive permissions (Owner: Full Control, Others: None)
            try {
                $acl = Get-Acl $OutputPath
                $acl.SetAccessRuleProtection($true, $false)  # Disable inheritance
                
                # Remove all existing rules
                $acl.Access | ForEach-Object { 
                    $acl.RemoveAccessRule($_) | Out-Null 
                }
                
                # Add rule for current user only
                $currentUser = [System.Security.Principal.WindowsIdentity]::GetCurrent().Name
                $rule = New-Object System.Security.AccessControl.FileSystemAccessRule(
                    $currentUser, 
                    'FullControl', 
                    'Allow'
                )
                $acl.AddAccessRule($rule)
                Set-Acl $OutputPath $acl
                
                Write-Verbose "File permissions set to owner-only access"
            }
            catch {
                Write-Warning "Could not set restrictive permissions: $_"
            }
            
            Write-Verbose "Password written to: $OutputPath"
            
            # Register cleanup if requested
            if ($DeleteOnExit) {
                $cleanupPath = $OutputPath
                $null = Register-EngineEvent -SourceIdentifier PowerShell.Exiting -Action {
                    if (Test-Path $cleanupPath) {
                        Remove-Item $cleanupPath -Force -ErrorAction SilentlyContinue
                    }
                }
                Write-Verbose "Registered cleanup action for script exit"
            }
            
            # Return file path for caller
            Write-Output $OutputPath
        }
        
        'SecureString' {
            # Return as PowerShell SecureString
            $securePassword = ConvertTo-SecureString $password -AsPlainText -Force
            Write-Output $securePassword
        }
    }
    
    # Clear password from memory
    $password = $null
    [System.GC]::Collect()
    
    Write-Verbose "Password retrieval completed successfully"
    exit 0
    
}
catch {
    Write-Error "Failed to retrieve Step-CA password: $_"
    Write-Error $_.ScriptStackTrace
    
    # Clean up any temp files created on error
    if ($OutputMode -eq 'File' -and (Test-Path $OutputPath -ErrorAction SilentlyContinue)) {
        Remove-Item $OutputPath -Force -ErrorAction SilentlyContinue
        Write-Verbose "Cleaned up temporary file after error"
    }
    
    exit 1
}

# ============================================================================
# Usage Examples
# ============================================================================
<#
.SYNOPSIS
    Retrieves the Step-CA master password from PostgreSQL secrets table.

.DESCRIPTION
    This script connects to the safeops_network database, decrypts the
    step-ca-master password using pgcrypto, and outputs it in the 
    specified format for Step-CA startup.

.EXAMPLE
    # Write to temp file (default) - returns file path
    $passwordFile = .\get-password.ps1
    .\bin\step-ca.exe config\ca.json --password-file $passwordFile

.EXAMPLE
    # Output to stdout for piping
    $password = .\get-password.ps1 -OutputMode Stdout

.EXAMPLE
    # Write to file with auto-cleanup on exit
    $passwordFile = .\get-password.ps1 -OutputMode File -DeleteOnExit
    .\bin\step-ca.exe config\ca.json --password-file $passwordFile

.EXAMPLE
    # Using custom database connection
    .\get-password.ps1 -DatabaseHost "db.safeops.local" -DatabaseUser "stepca_reader"

.EXAMPLE
    # Get as SecureString for PowerShell automation
    $securePass = .\get-password.ps1 -OutputMode SecureString

.NOTES
    Requires:
    - PostgreSQL client tools (psql.exe)
    - SAFEOPS_DB_ENCRYPTION_KEY environment variable
    - Network access to PostgreSQL server
    - secrets table with step-ca-master entry
#>
