# SafeOps v2.0 - Development Environment Installer for Windows
# Installs all required components for SafeOps development
# No database setup, no indexes - just basic installation and configuration

param(
    [switch]$SkipChecks,
    [switch]$Unattended
)

$ErrorActionPreference = "Stop"
$ProgressPreference = "SilentlyContinue"

# ---------- Configuration ----------
$LogFile = Join-Path $env:TEMP "safeops_installer_$(Get-Date -Format 'yyyyMMdd_HHmmss').log"
$ConfigDir = Join-Path $env:APPDATA "SafeOps\Setup"

# Create config directory
if (-not (Test-Path $ConfigDir)) {
    New-Item -ItemType Directory -Path $ConfigDir -Force | Out-Null
}

# ---------- Helper Functions ----------
function Write-Log {
    param(
        [string]$Message,
        [string]$Level = "INFO"
    )
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $logMessage = "[$timestamp] [$Level] $Message"
    Add-Content -Path $LogFile -Value $logMessage
    
    switch ($Level) {
        "ERROR" { Write-Host $Message -ForegroundColor Red }
        "WARNING" { Write-Host $Message -ForegroundColor Yellow }
        "SUCCESS" { Write-Host $Message -ForegroundColor Green }
        "INFO" { Write-Host $Message -ForegroundColor Cyan }
        default { Write-Host $Message }
    }
}

function Write-Section {
    param([string]$Title)
    Write-Host ""
    Write-Host "===========================================" -ForegroundColor Magenta
    Write-Host " $Title" -ForegroundColor Magenta
    Write-Host "===========================================" -ForegroundColor Magenta
    Write-Log "Starting: $Title"
}

function Test-Administrator {
    $currentUser = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($currentUser)
    return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Test-InternetConnection {
    try {
        $null = Test-Connection -ComputerName "8.8.8.8" -Count 1 -Quiet
        return $true
    }
    catch {
        return $false
    }
}

function Test-CommandExists {
    param([string]$Command)
    try {
        $null = Get-Command $Command -ErrorAction Stop
        return $true
    }
    catch {
        return $false
    }
}

function Confirm-Continue {
    param([string]$Message = "Do you want to continue?")
    if ($Unattended) { return $true }
    $response = Read-Host "$Message (Y/n)"
    return ($response -eq "" -or $response -eq "Y" -or $response -eq "y")
}

# ---------- Installation Functions ----------

function Install-Winget {
    Write-Section "Installing winget (Windows Package Manager)"
    
    if (Test-CommandExists "winget") {
        Write-Log "winget is already installed" "SUCCESS"
        return $true
    }
    
    Write-Log "winget not found. Installing..." "WARNING"
    
    try {
        # Download and install App Installer (includes winget)
        $appInstallerUrl = "https://aka.ms/getwinget"
        Write-Log "Opening Microsoft Store to install winget..."
        Start-Process $appInstallerUrl
        
        Write-Host ""
        Write-Host "Please install 'App Installer' from the Microsoft Store that just opened." -ForegroundColor Yellow
        Write-Host "After installation, close the Store and press Enter to continue..." -ForegroundColor Yellow
        if (-not $Unattended) { Read-Host }
        
        # Verify installation
        if (Test-CommandExists "winget") {
            Write-Log "winget installed successfully" "SUCCESS"
            return $true
        }
        else {
            Write-Log "winget installation could not be verified. Please restart PowerShell." "WARNING"
            return $false
        }
    }
    catch {
        Write-Log "Failed to install winget: $_" "ERROR"
        return $false
    }
}

function Install-Git {
    Write-Section "Installing Git"
    
    if (Test-CommandExists "git") {
        $version = git --version
        Write-Log "Git is already installed: $version" "SUCCESS"
        return $true
    }
    
    Write-Log "Installing Git via winget..."
    try {
        winget install --id Git.Git -e --source winget --silent --accept-package-agreements --accept-source-agreements
        
        # Refresh PATH
        $env:Path = [System.Environment]::GetEnvironmentVariable("Path", "Machine") + ";" + [System.Environment]::GetEnvironmentVariable("Path", "User")
        
        if (Test-CommandExists "git") {
            Write-Log "Git installed successfully" "SUCCESS"
            return $true
        }
        else {
            Write-Log "Git installation completed but command not found. Restart PowerShell." "WARNING"
            return $false
        }
    }
    catch {
        Write-Log "Failed to install Git: $_" "ERROR"
        return $false
    }
}

function Install-GitHubCLI {
    Write-Section "Installing GitHub CLI"
    
    if (Test-CommandExists "gh") {
        $version = gh --version
        Write-Log "GitHub CLI is already installed: $version" "SUCCESS"
        return $true
    }
    
    Write-Log "Installing GitHub CLI via winget..."
    try {
        winget install --id GitHub.cli -e --source winget --silent --accept-package-agreements --accept-source-agreements
        
        # Refresh PATH
        $env:Path = [System.Environment]::GetEnvironmentVariable("Path", "Machine") + ";" + [System.Environment]::GetEnvironmentVariable("Path", "User")
        
        if (Test-CommandExists "gh") {
            Write-Log "GitHub CLI installed successfully" "SUCCESS"
            return $true
        }
        else {
            Write-Log "GitHub CLI installation completed but command not found. Restart PowerShell." "WARNING"
            return $false
        }
    }
    catch {
        Write-Log "Failed to install GitHub CLI: $_" "ERROR"
        return $false
    }
}

function Install-VisualStudioBuildTools {
    Write-Section "Installing Visual Studio 2022 Build Tools"
    
    # Check if already installed
    $vsPath = "C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools"
    if (Test-Path $vsPath) {
        Write-Log "Visual Studio Build Tools already installed at $vsPath" "SUCCESS"
        return $true
    }
    
    Write-Log "Installing Visual Studio Build Tools (this will take 10-20 minutes)..."
    Write-Host "Required components:" -ForegroundColor Yellow
    Write-Host "  - Desktop development with C++" -ForegroundColor Yellow
    Write-Host "  - Windows 11 SDK" -ForegroundColor Yellow
    Write-Host "  - MSVC compiler" -ForegroundColor Yellow
    Write-Host ""
    
    if (-not (Confirm-Continue "This will download ~4 GB. Continue?")) {
        Write-Log "Installation skipped by user" "WARNING"
        return $false
    }
    
    try {
        winget install --id Microsoft.VisualStudio.2022.BuildTools -e --source winget --silent --accept-package-agreements --accept-source-agreements
        Write-Log "Visual Studio Build Tools installed successfully" "SUCCESS"
        Write-Log "Note: You may need to manually add C++ workload via Visual Studio Installer" "WARNING"
        return $true
    }
    catch {
        Write-Log "Failed to install Visual Studio Build Tools: $_" "ERROR"
        Write-Log "Please install manually from: https://visualstudio.microsoft.com/downloads/" "INFO"
        return $false
    }
}

function Install-WindowsSDK {
    Write-Section "Installing Windows SDK"
    
    $sdkPath = "C:\Program Files (x86)\Windows Kits\10"
    if (Test-Path $sdkPath) {
        Write-Log "Windows SDK already installed at $sdkPath" "SUCCESS"
        return $true
    }
    
    Write-Log "Installing Windows 11 SDK..."
    try {
        winget install --id Microsoft.WindowsSDK.10 -e --source winget --silent --accept-package-agreements --accept-source-agreements
        Write-Log "Windows SDK installed successfully" "SUCCESS"
        return $true
    }
    catch {
        Write-Log "Failed to install Windows SDK: $_" "ERROR"
        return $false
    }
}

function Install-Rust {
    Write-Section "Installing Rust"
    
    if (Test-CommandExists "rustc") {
        $version = rustc --version
        Write-Log "Rust is already installed: $version" "SUCCESS"
        return $true
    }
    
    Write-Log "Installing Rust via rustup..."
    try {
        # Download rustup-init
        $rustupUrl = "https://win.rustup.rs/x86_64"
        $rustupPath = Join-Path $env:TEMP "rustup-init.exe"
        
        Write-Log "Downloading rustup installer..."
        Invoke-WebRequest -Uri $rustupUrl -OutFile $rustupPath -UseBasicParsing
        
        Write-Log "Running rustup installer (this may take 5-10 minutes)..."
        Start-Process -FilePath $rustupPath -ArgumentList "-y" -Wait -NoNewWindow
        
        # Refresh PATH
        $env:Path = [System.Environment]::GetEnvironmentVariable("Path", "Machine") + ";" + [System.Environment]::GetEnvironmentVariable("Path", "User")
        
        # Add Cargo to current session
        $env:Path += ";$env:USERPROFILE\.cargo\bin"
        
        if (Test-CommandExists "rustc") {
            Write-Log "Rust installed successfully" "SUCCESS"
            
            # Install additional components
            Write-Log "Installing Rust components..."
            rustup component add clippy rustfmt
            rustup target add x86_64-pc-windows-msvc
            
            Write-Log "Rust components installed" "SUCCESS"
            return $true
        }
        else {
            Write-Log "Rust installation completed but command not found. Restart PowerShell." "WARNING"
            return $false
        }
    }
    catch {
        Write-Log "Failed to install Rust: $_" "ERROR"
        return $false
    }
}

function Install-Go {
    Write-Section "Installing Go"
    
    if (Test-CommandExists "go") {
        $version = go version
        Write-Log "Go is already installed: $version" "SUCCESS"
        return $true
    }
    
    Write-Log "Installing Go via winget..."
    try {
        winget install --id GoLang.Go -e --source winget --silent --accept-package-agreements --accept-source-agreements
        
        # Refresh PATH
        $env:Path = [System.Environment]::GetEnvironmentVariable("Path", "Machine") + ";" + [System.Environment]::GetEnvironmentVariable("Path", "User")
        
        if (Test-CommandExists "go") {
            Write-Log "Go installed successfully" "SUCCESS"
            return $true
        }
        else {
            Write-Log "Go installation completed but command not found. Restart PowerShell." "WARNING"
            return $false
        }
    }
    catch {
        Write-Log "Failed to install Go: $_" "ERROR"
        return $false
    }
}

function Install-NodeJS {
    Write-Section "Installing Node.js"
    
    if (Test-CommandExists "node") {
        $version = node --version
        Write-Log "Node.js is already installed: $version" "SUCCESS"
        return $true
    }
    
    Write-Log "Installing Node.js LTS via winget..."
    try {
        winget install --id OpenJS.NodeJS.LTS -e --source winget --silent --accept-package-agreements --accept-source-agreements
        
        # Refresh PATH
        $env:Path = [System.Environment]::GetEnvironmentVariable("Path", "Machine") + ";" + [System.Environment]::GetEnvironmentVariable("Path", "User")
        
        if (Test-CommandExists "node") {
            Write-Log "Node.js installed successfully" "SUCCESS"
            return $true
        }
        else {
            Write-Log "Node.js installation completed but command not found. Restart PowerShell." "WARNING"
            return $false
        }
    }
    catch {
        Write-Log "Failed to install Node.js: $_" "ERROR"
        return $false
    }
}

function Install-PowerShell7 {
    Write-Section "Installing PowerShell 7"
    
    if (Test-Path "C:\Program Files\PowerShell\7\pwsh.exe") {
        Write-Log "PowerShell 7 is already installed" "SUCCESS"
        return $true
    }
    
    Write-Log "Installing PowerShell 7 via winget..."
    try {
        winget install --id Microsoft.PowerShell -e --source winget --silent --accept-package-agreements --accept-source-agreements
        Write-Log "PowerShell 7 installed successfully" "SUCCESS"
        return $true
    }
    catch {
        Write-Log "Failed to install PowerShell 7: $_" "ERROR"
        return $false
    }
}

function Install-OpenSSL {
    Write-Section "Installing OpenSSL"
    
    if (Test-CommandExists "openssl") {
        $version = openssl version
        Write-Log "OpenSSL is already installed: $version" "SUCCESS"
        return $true
    }
    
    Write-Log "Installing OpenSSL..."
    try {
        # Download OpenSSL installer
        $opensslUrl = "https://slproweb.com/download/Win64OpenSSL_Light-3_2_0.exe"
        $opensslPath = Join-Path $env:TEMP "openssl_installer.exe"
        
        Write-Log "Downloading OpenSSL installer..."
        Invoke-WebRequest -Uri $opensslUrl -OutFile $opensslPath -UseBasicParsing
        
        Write-Log "Running OpenSSL installer..."
        Start-Process -FilePath $opensslPath -ArgumentList "/VERYSILENT /SUPPRESSMSGBOXES /NORESTART /SP-" -Wait
        
        # Add to PATH
        $opensslBinPath = "C:\Program Files\OpenSSL-Win64\bin"
        if (Test-Path $opensslBinPath) {
            $currentPath = [Environment]::GetEnvironmentVariable("Path", "Machine")
            if ($currentPath -notlike "*$opensslBinPath*") {
                [Environment]::SetEnvironmentVariable("Path", "$currentPath;$opensslBinPath", "Machine")
                $env:Path += ";$opensslBinPath"
            }
            Write-Log "OpenSSL installed successfully" "SUCCESS"
            return $true
        }
        else {
            Write-Log "OpenSSL installation completed but binary not found" "WARNING"
            return $false
        }
    }
    catch {
        Write-Log "Failed to install OpenSSL: $_" "ERROR"
        return $false
    }
}

function Install-ProtocolBuffers {
    Write-Section "Installing Protocol Buffers Compiler"
    
    $protocPath = "C:\Tools\protoc"
    $protocBin = Join-Path $protocPath "bin\protoc.exe"
    
    if (Test-Path $protocBin) {
        Write-Log "Protocol Buffers compiler already installed at $protocPath" "SUCCESS"
        return $true
    }
    
    Write-Log "Installing Protocol Buffers compiler..."
    try {
        # Create directory
        if (-not (Test-Path $protocPath)) {
            New-Item -ItemType Directory -Path $protocPath -Force | Out-Null
        }
        
        # Download latest protoc
        $protocUrl = "https://github.com/protocolbuffers/protobuf/releases/download/v25.1/protoc-25.1-win64.zip"
        $protocZip = Join-Path $env:TEMP "protoc.zip"
        
        Write-Log "Downloading protoc..."
        Invoke-WebRequest -Uri $protocUrl -OutFile $protocZip -UseBasicParsing
        
        Write-Log "Extracting protoc..."
        Expand-Archive -Path $protocZip -DestinationPath $protocPath -Force
        
        # Add to PATH
        $protocBinPath = Join-Path $protocPath "bin"
        $currentPath = [Environment]::GetEnvironmentVariable("Path", "Machine")
        if ($currentPath -notlike "*$protocBinPath*") {
            [Environment]::SetEnvironmentVariable("Path", "$currentPath;$protocBinPath", "Machine")
            $env:Path += ";$protocBinPath"
        }
        
        Write-Log "Protocol Buffers compiler installed successfully" "SUCCESS"
        return $true
    }
    catch {
        Write-Log "Failed to install Protocol Buffers: $_" "ERROR"
        return $false
    }
}

function Install-SQLServerLocalDB {
    Write-Section "Installing SQL Server Express LocalDB"
    
    # Check if LocalDB is already installed
    if (Test-CommandExists "sqllocaldb") {
        try {
            $instances = sqllocaldb info 2>$null
            Write-Log "SQL Server LocalDB is already installed" "SUCCESS"
            if ($instances) {
                Write-Log "Available instances: $($instances -join ', ')" "INFO"
            }
            return $true
        }
        catch {
            Write-Log "sqllocaldb command found but not responding properly" "WARNING"
        }
    }
    
    Write-Log "Installing SQL Server Express LocalDB..."
    Write-Host "This will be used for bundling in the installer (not for development)." -ForegroundColor Yellow
    Write-Host "LocalDB is a lightweight, on-demand database engine (~50 MB)." -ForegroundColor Yellow
    
    if (-not (Confirm-Continue "Install SQL Server Express LocalDB (~50 MB)?")) {
        Write-Log "SQL Server LocalDB installation skipped" "WARNING"
        return $false
    }
    
    try {
        # Install SQL Server Express LocalDB via winget
        winget install --id Microsoft.SQLServer.2022.LocalDB -e --source winget --silent --accept-package-agreements --accept-source-agreements
        
        # Refresh PATH
        $env:Path = [System.Environment]::GetEnvironmentVariable("Path", "Machine") + ";" + [System.Environment]::GetEnvironmentVariable("Path", "User")
        
        # Verify installation
        if (Test-CommandExists "sqllocaldb") {
            Write-Log "SQL Server LocalDB installed successfully" "SUCCESS"
            
            # Create a default instance for SafeOps
            try {
                Write-Log "Creating SafeOps LocalDB instance..."
                sqllocaldb create "SafeOps" -s 2>$null
                Write-Log "SafeOps instance created and started" "SUCCESS"
            }
            catch {
                Write-Log "Could not create SafeOps instance, using default MSSQLLocalDB" "WARNING"
            }
            
            return $true
        }
        else {
            Write-Log "SQL Server LocalDB installation completed but command not found. Restart PowerShell." "WARNING"
            return $false
        }
    }
    catch {
        Write-Log "Failed to install SQL Server LocalDB: $_" "ERROR"
        Write-Log "You can install manually from: https://aka.ms/ssmsfullsetup" "INFO"
        return $false
    }
}

function Install-Redis {
    Write-Section "Installing Redis (Windows Port)"
    
    $redisPath = "C:\Tools\Redis"
    
    if (Test-Path $redisPath) {
        Write-Log "Redis already downloaded at $redisPath" "SUCCESS"
        return $true
    }
    
    Write-Log "Downloading Redis for Windows..."
    Write-Host "This will be used for bundling in the installer (not for development)." -ForegroundColor Yellow
    
    if (-not (Confirm-Continue "Download Redis (~15 MB)?")) {
        Write-Log "Redis download skipped" "WARNING"
        return $false
    }
    
    try {
        # Create directory
        New-Item -ItemType Directory -Path $redisPath -Force | Out-Null
        
        # Download Redis
        $redisUrl = "https://github.com/tporadowski/redis/releases/download/v5.0.14.1/Redis-x64-5.0.14.1.zip"
        $redisZip = Join-Path $env:TEMP "redis.zip"
        
        Write-Log "Downloading Redis..."
        Invoke-WebRequest -Uri $redisUrl -OutFile $redisZip -UseBasicParsing
        
        Write-Log "Extracting Redis..."
        Expand-Archive -Path $redisZip -DestinationPath $redisPath -Force
        
        Write-Log "Redis downloaded successfully to $redisPath" "SUCCESS"
        return $true
    }
    catch {
        Write-Log "Failed to download Redis: $_" "ERROR"
        return $false
    }
}

function Install-VSCode {
    Write-Section "Installing Visual Studio Code (Optional)"
    
    if (Test-CommandExists "code") {
        Write-Log "VS Code is already installed" "SUCCESS"
        return $true
    }
    
    if (-not (Confirm-Continue "Install Visual Studio Code?")) {
        Write-Log "VS Code installation skipped" "WARNING"
        return $false
    }
    
    Write-Log "Installing VS Code via winget..."
    try {
        winget install --id Microsoft.VisualStudioCode -e --source winget --silent --accept-package-agreements --accept-source-agreements
        Write-Log "VS Code installed successfully" "SUCCESS"
        return $true
    }
    catch {
        Write-Log "Failed to install VS Code: $_" "ERROR"
        return $false
    }
}

function Install-WindowsTerminal {
    Write-Section "Installing Windows Terminal (Optional)"
    
    $terminalPath = "C:\Program Files\WindowsApps\Microsoft.WindowsTerminal*"
    if (Test-Path $terminalPath) {
        Write-Log "Windows Terminal is already installed" "SUCCESS"
        return $true
    }
    
    if (-not (Confirm-Continue "Install Windows Terminal?")) {
        Write-Log "Windows Terminal installation skipped" "WARNING"
        return $false
    }
    
    Write-Log "Installing Windows Terminal via winget..."
    try {
        winget install --id Microsoft.WindowsTerminal -e --source winget --silent --accept-package-agreements --accept-source-agreements
        Write-Log "Windows Terminal installed successfully" "SUCCESS"
        return $true
    }
    catch {
        Write-Log "Failed to install Windows Terminal: $_" "ERROR"
        return $false
    }
}

function Install-Wails {
    Write-Section "Installing Wails CLI"
    
    if (Test-CommandExists "wails") {
        Write-Log "Wails is already installed" "SUCCESS"
        return $true
    }
    
    if (-not (Test-CommandExists "go")) {
        Write-Log "Go is required for Wails. Skipping..." "WARNING"
        return $false
    }
    
    Write-Log "Installing Wails via go install..."
    try {
        go install github.com/wailsapp/wails/v2/cmd/wails@latest
        
        # Add GOPATH\bin to PATH if not already there
        $goPath = go env GOPATH
        $goBin = Join-Path $goPath "bin"
        $env:Path += ";$goBin"
        
        Write-Log "Wails installed successfully" "SUCCESS"
        Write-Log "Run 'wails doctor' to check Wails dependencies" "INFO"
        return $true
    }
    catch {
        Write-Log "Failed to install Wails: $_" "ERROR"
        return $false
    }
}

function Set-EnvironmentVariables {
    Write-Section "Setting Environment Variables"
    
    try {
        # Rust
        if (-not [Environment]::GetEnvironmentVariable("RUSTUP_HOME", "User")) {
            [Environment]::SetEnvironmentVariable("RUSTUP_HOME", "$env:USERPROFILE\.rustup", "User")
            Write-Log "Set RUSTUP_HOME" "SUCCESS"
        }
        
        if (-not [Environment]::GetEnvironmentVariable("CARGO_HOME", "User")) {
            [Environment]::SetEnvironmentVariable("CARGO_HOME", "$env:USERPROFILE\.cargo", "User")
            Write-Log "Set CARGO_HOME" "SUCCESS"
        }
        
        # Go
        if (-not [Environment]::GetEnvironmentVariable("GOPATH", "User")) {
            [Environment]::SetEnvironmentVariable("GOPATH", "$env:USERPROFILE\go", "User")
            Write-Log "Set GOPATH" "SUCCESS"
        }
        
        if (-not [Environment]::GetEnvironmentVariable("GOBIN", "User")) {
            [Environment]::SetEnvironmentVariable("GOBIN", "$env:USERPROFILE\go\bin", "User")
            Write-Log "Set GOBIN" "SUCCESS"
        }
        
        Write-Log "Environment variables configured" "SUCCESS"
        return $true
    }
    catch {
        Write-Log "Failed to set environment variables: $_" "ERROR"
        return $false
    }
}

function Show-Summary {
    Write-Section "Installation Summary"
    
    Write-Host ""
    Write-Host "Installation Log: $LogFile" -ForegroundColor Cyan
    Write-Host ""
    Write-Host "Installed Components:" -ForegroundColor Green
    Write-Host "=====================" -ForegroundColor Green
    
    $components = @(
        @{ Name = "winget"; Command = "winget" }
        @{ Name = "Git"; Command = "git" }
        @{ Name = "GitHub CLI"; Command = "gh" }
        @{ Name = "Rust"; Command = "rustc" }
        @{ Name = "Go"; Command = "go" }
        @{ Name = "Node.js"; Command = "node" }
        @{ Name = "PowerShell 7"; Command = "pwsh" }
        @{ Name = "OpenSSL"; Command = "openssl" }
        @{ Name = "Protocol Buffers"; Command = "protoc" }
        @{ Name = "VS Code"; Command = "code" }
        @{ Name = "Wails"; Command = "wails" }
    )
    
    foreach ($comp in $components) {
        if (Test-CommandExists $comp.Command) {
            Write-Host "  [OK] $($comp.Name)" -ForegroundColor Green
        }
        else {
            Write-Host "  [X] $($comp.Name) (not installed or not in PATH)" -ForegroundColor Yellow
        }
    }
    
    Write-Host ""
    Write-Host "Database & Tools Locations:" -ForegroundColor Yellow
    Write-Host "==========================" -ForegroundColor Yellow
    Write-Host "  SQL Server LocalDB: Installed via winget" -ForegroundColor Cyan
    Write-Host "  Redis: C:\Tools\Redis" -ForegroundColor Cyan
    Write-Host "  Protocol Buffers: C:\Tools\protoc" -ForegroundColor Cyan
    
    Write-Host ""
    Write-Host "Next Steps:" -ForegroundColor Green
    Write-Host "===========" -ForegroundColor Green
    Write-Host "  1. Restart your terminal/PowerShell to load new PATH variables"
    Write-Host "  2. Run 'wails doctor' to verify Wails setup"
    Write-Host "  3. Run 'gh auth login' to authenticate GitHub CLI"
    Write-Host "  4. Clone the SafeOps repository and start development"
    Write-Host ""
    Write-Host "Documentation:" -ForegroundColor Cyan
    Write-Host "  - See SafeOps Setup and Directory Structure.md for project structure"
    Write-Host "  - See safeops-simple-roadmap.md for build order"
    Write-Host ""
}

# ---------- Main Installation Flow ----------

Write-Host ""
Write-Host "===================================================" -ForegroundColor Cyan
Write-Host "|                                                 |" -ForegroundColor Cyan
Write-Host "|     SafeOps v2.0 Development Environment        |" -ForegroundColor Cyan
Write-Host "|              Installer for Windows              |" -ForegroundColor Cyan
Write-Host "|                                                 |" -ForegroundColor Cyan
Write-Host "===================================================" -ForegroundColor Cyan
Write-Host ""

Write-Log "Installation started" "INFO"
Write-Log "Log file: $LogFile" "INFO"

# Pre-flight checks
Write-Section "Pre-flight Checks"

if (-not (Test-Administrator)) {
    Write-Log "WARNING: Not running as Administrator" "WARNING"
    Write-Log "Some installations may fail without admin rights" "WARNING"
    if (-not (Confirm-Continue "Continue anyway?")) {
        exit 1
    }
}

if (-not (Test-InternetConnection)) {
    Write-Log "ERROR: No internet connection detected" "ERROR"
    Write-Log "Internet connection is required for installation" "ERROR"
    exit 1
}

Write-Log "Pre-flight checks passed" "SUCCESS"

# Install components
Write-Host ""
Write-Host "This installer will install the following components:" -ForegroundColor Yellow
Write-Host "  - winget (Windows Package Manager)"
Write-Host "  - Git"
Write-Host "  - GitHub CLI"
Write-Host "  - Visual Studio 2022 Build Tools"
Write-Host "  - Windows SDK"
Write-Host "  - Rust (via rustup)"
Write-Host "  - Go"
Write-Host "  - Node.js LTS"
Write-Host "  - PowerShell 7"
Write-Host "  - OpenSSL"
Write-Host "  - Protocol Buffers Compiler"
Write-Host "  - SQL Server Express LocalDB (for bundling)"
Write-Host "  - Redis (portable, for bundling)"
Write-Host "  - Wails CLI"
Write-Host "  - VS Code (optional)"
Write-Host "  - Windows Terminal (optional)"
Write-Host ""
Write-Host "Estimated total download: ~5.5-7.5 GB" -ForegroundColor Yellow
Write-Host "Estimated installation time: 30-60 minutes" -ForegroundColor Yellow
Write-Host ""

if (-not (Confirm-Continue "Start installation?")) {
    Write-Log "Installation cancelled by user" "WARNING"
    exit 0
}

# Core installations (required)
$success = $true
$success = (Install-Winget) -and $success
$success = (Install-Git) -and $success
$success = (Install-GitHubCLI) -and $success
$success = (Install-VisualStudioBuildTools) -and $success
$success = (Install-WindowsSDK) -and $success
$success = (Install-Rust) -and $success
$success = (Install-Go) -and $success
$success = (Install-NodeJS) -and $success
$success = (Install-PowerShell7) -and $success
$success = (Install-OpenSSL) -and $success
$success = (Install-ProtocolBuffers) -and $success

# Database and cache components (for installer bundling)
Install-SQLServerLocalDB | Out-Null
Install-Redis | Out-Null

# Go-based tools
Install-Wails | Out-Null

# Optional tools
Install-VSCode | Out-Null
Install-WindowsTerminal | Out-Null

# Environment variables
Set-EnvironmentVariables | Out-Null

# Summary
Show-Summary

Write-Log "Installation completed" "SUCCESS"

Write-Host ""
Write-Host "â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•" -ForegroundColor Green
Write-Host " Installation Complete!" -ForegroundColor Green
Write-Host "â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•" -ForegroundColor Green
Write-Host ""
Write-Host "IMPORTANT: Restart your terminal/PowerShell now!" -ForegroundColor Yellow
Write-Host ""
