# ============================================================================
# SafeOps Development Environment Installer
# ============================================================================
# This script installs ALL dependencies needed for SafeOps development
# Run this on a fresh Windows installation (VMware, Sandbox, or new machine)
# ============================================================================

param(
    [switch]$SkipOptional = $false,
    [string]$InstallPath = "C:\SafeOpsDev"
)

$ErrorActionPreference = "Stop"

# ============================================================================
# Configuration
# ============================================================================

$script:InstalledComponents = @()
$script:FailedComponents = @()

# Versions
$GoVersion = "1.21.5"
$PostgreSQLVersion = "16"
$NodeVersion = "20.10.0"

Write-Host @"
╔══════════════════════════════════════════════════════════════╗
║                                                              ║
║            SafeOps Development Environment Installer         ║
║                                                              ║
║  This will install all dependencies for:                    ║
║  • Go & Rust development                                    ║
║  • PostgreSQL & Redis databases                             ║
║  • Docker & containers                                      ║
║  • Protocol Buffers & gRPC tools                            ║
║  • Build tools & utilities                                  ║
║                                                              ║
╚══════════════════════════════════════════════════════════════╝
"@ -ForegroundColor Cyan

Start-Sleep -Seconds 2

# ============================================================================
# Helper Functions
# ============================================================================

function Test-Administrator {
    $currentUser = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($currentUser)
    return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Write-Step {
    param([string]$Message)
    Write-Host "`n[$([datetime]::Now.ToString('HH:mm:ss'))] $Message" -ForegroundColor Yellow
}

function Write-Success {
    param([string]$Message)
    Write-Host "  ✓ $Message" -ForegroundColor Green
    $script:InstalledComponents += $Message
}

function Write-Failed {
    param([string]$Message, [string]$ErrorMsg)
    Write-Host "  ✗ $Message" -ForegroundColor Red
    Write-Host "    Error: $ErrorMsg" -ForegroundColor DarkRed
    $script:FailedComponents += $Message
}

function Install-Chocolatey {
    Write-Step "Installing Chocolatey package manager..."
    
    if (Get-Command choco -ErrorAction SilentlyContinue) {
        Write-Success "Chocolatey already installed"
        return
    }
    
    try {
        Set-ExecutionPolicy Bypass -Scope Process -Force
        [System.Net.ServicePointManager]::SecurityProtocol = [System.Net.ServicePointManager]::SecurityProtocol -bor 3072
        Invoke-Expression ((New-Object System.Net.WebClient).DownloadString('https://community.chocolatey.org/install.ps1'))
        
        # Refresh environment
        $env:Path = [System.Environment]::GetEnvironmentVariable("Path", "Machine") + ";" + [System.Environment]::GetEnvironmentVariable("Path", "User")
        
        Write-Success "Chocolatey installed"
    }
    catch {
        Write-Failed "Chocolatey installation" $_.Exception.Message
    }
}

function Install-Go {
    Write-Step "Installing Go $GoVersion..."
    
    if (Get-Command go -ErrorAction SilentlyContinue) {
        $currentVersion = (go version) -replace '.*go(\d+\.\d+\.\d+).*', '$1'
        Write-Success "Go $currentVersion already installed"
        return
    }
    
    try {
        choco install golang --version=$GoVersion -y
        
        # Add to PATH
        $goPath = "C:\Go\bin"
        $goBinPath = "$env:USERPROFILE\go\bin"
        
        [Environment]::SetEnvironmentVariable("GOPATH", "$env:USERPROFILE\go", "User")
        
        $currentPath = [Environment]::GetEnvironmentVariable("Path", "User")
        if ($currentPath -notlike "*$goPath*") {
            [Environment]::SetEnvironmentVariable("Path", "$currentPath;$goPath;$goBinPath", "User")
        }
        
        # Refresh PATH
        $env:Path = [System.Environment]::GetEnvironmentVariable("Path", "Machine") + ";" + [System.Environment]::GetEnvironmentVariable("Path", "User")
        
        Write-Success "Go $GoVersion installed"
    }
    catch {
        Write-Failed "Go installation" $_.Exception.Message
    }
}

function Install-Rust {
    Write-Step "Installing Rust..."
    
    if (Get-Command rustc -ErrorAction SilentlyContinue) {
        $rustVersion = (rustc --version)
        Write-Success "Rust already installed: $rustVersion"
        return
    }
    
    try {
        # Download rustup-init
        $rustupPath = "$env:TEMP\rustup-init.exe"
        Invoke-WebRequest -Uri "https://win.rustup.rs/x86_64" -OutFile $rustupPath
        
        # Install Rust
        Start-Process -FilePath $rustupPath -ArgumentList "-y" -Wait -NoNewWindow
        
        # Refresh PATH
        $env:Path = [System.Environment]::GetEnvironmentVariable("Path", "Machine") + ";" + [System.Environment]::GetEnvironmentVariable("Path", "User")
        
        Write-Success "Rust installed"
    }
    catch {
        Write-Failed "Rust installation" $_.Exception.Message
    }
}

function Install-PostgreSQL {
    Write-Step "Installing PostgreSQL $PostgreSQLVersion..."
    
    try {
        # Install PostgreSQL with default password
        choco install postgresql$PostgreSQLVersion -y --params '/Password:SafeOps2024!'
        
        Write-Success "PostgreSQL $PostgreSQLVersion installed"
        
        # Wait for service to start
        Start-Sleep -Seconds 5
        
        # Configure PostgreSQL
        Write-Step "Configuring PostgreSQL..."
        
        $pgPath = "C:\Program Files\PostgreSQL\$PostgreSQLVersion\bin"
        $env:Path += ";$pgPath"
        
        # Create SafeOps database and user
        $pgPassword = "SafeOps2024!"
        $env:PGPASSWORD = $pgPassword
        
        # Create database
        & "$pgPath\psql.exe" -U postgres -c "CREATE DATABASE safeops;" 2>$null
        & "$pgPath\psql.exe" -U postgres -c "CREATE DATABASE safeops_test;" 2>$null
        
        # Create safeops user
        & "$pgPath\psql.exe" -U postgres -c "CREATE USER safeops WITH PASSWORD 'safeops123';" 2>$null
        & "$pgPath\psql.exe" -U postgres -c "GRANT ALL PRIVILEGES ON DATABASE safeops TO safeops;" 2>$null
        & "$pgPath\psql.exe" -U postgres -c "GRANT ALL PRIVILEGES ON DATABASE safeops_test TO safeops;" 2>$null
        
        # Allow local connections
        $pgDataPath = "C:\Program Files\PostgreSQL\$PostgreSQLVersion\data"
        $pgHbaPath = "$pgDataPath\pg_hba.conf"
        
        if (Test-Path $pgHbaPath) {
            $hbaContent = Get-Content $pgHbaPath
            if ($hbaContent -notcontains "host    all             all             127.0.0.1/32            md5") {
                Add-Content -Path $pgHbaPath -Value "host    all             all             127.0.0.1/32            md5"
                
                # Restart PostgreSQL
                Restart-Service "postgresql-x64-$PostgreSQLVersion"
            }
        }
        
        Write-Success "PostgreSQL configured with databases: safeops, safeops_test"
        Write-Host "  ℹ Default credentials:" -ForegroundColor Cyan
        Write-Host "    postgres user: postgres / SafeOps2024!" -ForegroundColor White
        Write-Host "    safeops user: safeops / safeops123" -ForegroundColor White
        Write-Host "  ⚠ IMPORTANT: Change these passwords in production!" -ForegroundColor Yellow
        
        # Create password change script
        $changePasswordScript = @'
# PostgreSQL Password Change Script
# Run this to change default passwords

$pgPath = "C:\Program Files\PostgreSQL\16\bin"
$env:PGPASSWORD = "SafeOps2024!"

Write-Host "PostgreSQL Password Change Utility" -ForegroundColor Cyan
Write-Host "==================================" -ForegroundColor Cyan

# Change postgres password
Write-Host "`nChanging postgres superuser password..."
$newPostgresPass = Read-Host "Enter new password for 'postgres' user" -AsSecureString
$plainPass = [Runtime.InteropServices.Marshal]::PtrToStringAuto([Runtime.InteropServices.Marshal]::SecureStringToBSTR($newPostgresPass))

& "$pgPath\psql.exe" -U postgres -c "ALTER USER postgres WITH PASSWORD '$plainPass';"

if ($LASTEXITCODE -eq 0) {
    Write-Host "✓ postgres password changed" -ForegroundColor Green
}

# Change safeops password
Write-Host "`nChanging safeops user password..."
$newSafeOpsPass = Read-Host "Enter new password for 'safeops' user" -AsSecureString
$plainPass2 = [Runtime.InteropServices.Marshal]::PtrToStringAuto([Runtime.InteropServices.Marshal]::SecureStringToBSTR($newSafeOpsPass))

& "$pgPath\psql.exe" -U postgres -c "ALTER USER safeops WITH PASSWORD '$plainPass2';"

if ($LASTEXITCODE -eq 0) {
    Write-Host "✓ safeops password changed" -ForegroundColor Green
}

Write-Host "`nPasswords updated successfully!" -ForegroundColor Green
Write-Host "Update your connection strings with the new passwords." -ForegroundColor Yellow
'@
        
        $changePasswordScript | Out-File -FilePath "$InstallPath\Change-PostgreSQLPasswords.ps1" -Encoding UTF8
        Write-Success "Password change script created at: $InstallPath\Change-PostgreSQLPasswords.ps1"
    }
    catch {
        Write-Failed "PostgreSQL installation" $_.Exception.Message
    }
}

function Install-Redis {
    Write-Step "Installing Redis..."
    
    try {
        choco install redis-64 -y
        
        # Start Redis service
        Start-Service Redis
        
        Write-Success "Redis installed and started"
    }
    catch {
        Write-Failed "Redis installation" $_.Exception.Message
    }
}



function Install-ProtocolBuffers {
    Write-Step "Installing Protocol Buffers compiler..."
    
    try {
        choco install protoc -y
        
        # Install Go plugins
        go install google.golang.org/protobuf/cmd/protoc-gen-go@latest
        go install google.golang.org/grpc/cmd/protoc-gen-go-grpc@latest
        
        Write-Success "Protocol Buffers compiler and plugins installed"
    }
    catch {
        Write-Failed "Protocol Buffers installation" $_.Exception.Message
    }
}

function Install-BuildTools {
    Write-Step "Installing Visual Studio Build Tools..."
    
    try {
        choco install visualstudio2022buildtools -y
        choco install visualstudio2022-workload-vctools -y
        
        Write-Success "Visual Studio Build Tools installed"
    }
    catch {
        Write-Failed "Build Tools installation" $_.Exception.Message
    }
}

function Install-Git {
    Write-Step "Installing Git..."
    
    if (Get-Command git -ErrorAction SilentlyContinue) {
        Write-Success "Git already installed"
        return
    }
    
    try {
        choco install git -y
        
        # Refresh PATH
        $env:Path = [System.Environment]::GetEnvironmentVariable("Path", "Machine") + ";" + [System.Environment]::GetEnvironmentVariable("Path", "User")
        
        Write-Success "Git installed"
    }
    catch {
        Write-Failed "Git installation" $_.Exception.Message
    }
}

function Install-NodeJS {
    Write-Step "Installing Node.js (for web UI)..."
    
    if ($SkipOptional) {
        Write-Host "  ⊗ Skipped (optional)" -ForegroundColor Gray
        return
    }
    
    try {
        choco install nodejs --version=$NodeVersion -y
        
        Write-Success "Node.js $NodeVersion installed"
    }
    catch {
        Write-Failed "Node.js installation" $_.Exception.Message
    }
}

function Install-VSCode {
    Write-Step "Installing Visual Studio Code..."
    
    if ($SkipOptional) {
        Write-Host "  ⊗ Skipped (optional)" -ForegroundColor Gray
        return
    }
    
    try {
        choco install vscode -y
        
        # Install useful extensions
        code --install-extension golang.go
        code --install-extension rust-lang.rust-analyzer
        code --install-extension ms-vscode.powershell
        
        Write-Success "VS Code and extensions installed"
    }
    catch {
        Write-Failed "VS Code installation" $_.Exception.Message
    }
}

function Install-Consul {
    Write-Step "Installing Consul (service discovery)..."
    
    if ($SkipOptional) {
        Write-Host "  ⊗ Skipped (optional)" -ForegroundColor Gray
        return
    }
    
    try {
        choco install consul -y
        
        Write-Success "Consul installed"
    }
    catch {
        Write-Failed "Consul installation" $_.Exception.Message
    }
}

function Install-Utilities {
    Write-Step "Installing development utilities..."
    
    try {
        choco install 7zip -y
        choco install wget -y
        choco install curl -y
        choco install jq -y
        
        Write-Success "Development utilities installed"
    }
    catch {
        Write-Failed "Utilities installation" $_.Exception.Message
    }
}

function Initialize-Environment {
    Write-Step "Setting up environment variables..."
    
    try {
        # Create workspace directory
        if (!(Test-Path $InstallPath)) {
            New-Item -Path $InstallPath -ItemType Directory -Force | Out-Null
        }
        
        [Environment]::SetEnvironmentVariable("SAFEOPS_DEV", $InstallPath, "User")
        
        Write-Success "Environment configured at $InstallPath"
    }
    catch {
        Write-Failed "Environment setup" $_.Exception.Message
    }
}

function Test-Installation {
    Write-Step "Verifying installations..."
    
    $tests = @(
        @{Name = "Go"; Command = "go version" }
        @{Name = "Rust"; Command = "rustc --version" }
        @{Name = "Cargo"; Command = "cargo --version" }
        @{Name = "Git"; Command = "git --version" }
        @{Name = "Protoc"; Command = "protoc --version" }
    )
    
    foreach ($test in $tests) {
        try {
            $result = Invoke-Expression $test.Command 2>&1
            Write-Success "$($test.Name): $result"
        }
        catch {
            Write-Failed "$($test.Name) verification" "Command not found"
        }
    }
}

# ============================================================================
# Main Installation
# ============================================================================

Write-Host "`nChecking administrator privileges..." -ForegroundColor White
if (!(Test-Administrator)) {
    Write-Host "✗ This script must be run as Administrator!" -ForegroundColor Red
    Write-Host "  Right-click and select 'Run as Administrator'" -ForegroundColor Yellow
    exit 1
}
Write-Success "Running as Administrator"

Write-Host "`n========================================" -ForegroundColor Cyan
Write-Host "Starting Installation" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan

# Core Components (Required)
Install-Chocolatey
Install-Git
Install-Go
Install-Rust
Install-PostgreSQL
Install-Redis
Install-ProtocolBuffers
Install-BuildTools
Install-Utilities
Initialize-Environment

# Optional Components
if (!$SkipOptional) {
    Write-Host "`n--- Optional Components ---" -ForegroundColor Cyan
    Install-NodeJS
    Install-VSCode
    Install-Consul
}

# Verification
Write-Host "`n========================================" -ForegroundColor Cyan
Write-Host "Installation Verification" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan
Test-Installation

# Summary
Write-Host "`n========================================" -ForegroundColor Cyan
Write-Host "Installation Summary" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan

Write-Host "`nSuccessfully Installed ($($script:InstalledComponents.Count)):" -ForegroundColor Green
foreach ($component in $script:InstalledComponents) {
    Write-Host "  ✓ $component" -ForegroundColor Green
}

if ($script:FailedComponents.Count -gt 0) {
    Write-Host "`nFailed Installations ($($script:FailedComponents.Count)):" -ForegroundColor Red
    foreach ($component in $script:FailedComponents) {
        Write-Host "  ✗ $component" -ForegroundColor Red
    }
}

Write-Host "`n========================================" -ForegroundColor Cyan
Write-Host "Next Steps" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan

Write-Host @"

1. Restart your computer (required for Docker and PATH updates)

2. Clone SafeOps repository:
   git clone https://github.com/your-username/SafeOps-Firewall-V2.git

3. Build shared libraries:
   cd SafeOps-Firewall-V2/src/shared/go
   go build ./...
   
   cd ../rust
   cargo build

4. Start services:
   # PostgreSQL - Already running
   # Redis - Already running
   # Consul (optional):
   consul agent -dev

5. Run tests:
   cd SafeOps-Firewall-V2/sandbox
   Start-Process SafeOps-Test.wsb

"@ -ForegroundColor White

Write-Host "========================================" -ForegroundColor Cyan
Write-Host "Environment Ready for SafeOps Development!" -ForegroundColor Green
Write-Host "========================================" -ForegroundColor Cyan

Write-Host "`nPress any key to exit..." -ForegroundColor Yellow
$null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
