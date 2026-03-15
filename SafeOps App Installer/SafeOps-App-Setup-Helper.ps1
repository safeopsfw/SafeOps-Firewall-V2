# SafeOps App Installer - PowerShell Helper
# Handles post-install tasks for the SafeOps application installer
# Run as Administrator. Called by Inno Setup during installation.

param(
    [string]$InstallDir = "C:\Program Files\SafeOps",
    [string]$BinDir = "C:\Program Files\SafeOps\bin",
    [string]$DataDir = "$env:ProgramData\SafeOps"
)

$ErrorActionPreference = "Continue"
$logFile = "$env:USERPROFILE\Desktop\SafeOps-App.log"
$installLog = "$env:USERPROFILE\Desktop\SafeOps-Install-$(Get-Date -f 'yyyy-MM-dd').log"

function Log($msg) {
    $ts = Get-Date -f "HH:mm:ss"
    $line = "[$ts] $msg"
    Write-Host $line
    Add-Content -Path $logFile -Value $line -ErrorAction SilentlyContinue
    Add-Content -Path $installLog -Value $line -ErrorAction SilentlyContinue
}

New-Item -ItemType Directory -Force -Path $DataDir | Out-Null

Log "=== SafeOps App Installer - Post-Install Setup ==="
Log "InstallDir : $InstallDir"
Log "BinDir     : $BinDir"

# ─── 1. Set SAFEOPS_HOME environment variable ───────────────────────────────
Log "[1] Setting SAFEOPS_HOME system environment variable..."
[System.Environment]::SetEnvironmentVariable("SAFEOPS_HOME", $InstallDir, "Machine")
$env:SAFEOPS_HOME = $InstallDir
Log "    SAFEOPS_HOME = $InstallDir"

# ─── 2. Read or create install-paths.json ────────────────────────────────────
Log "[2] Writing install-paths.json..."
$existingPaths = $null
$pathsFile = "$DataDir\install-paths.json"

if (Test-Path $pathsFile) {
    try {
        $existingPaths = Get-Content $pathsFile | ConvertFrom-Json
        Log "    Found existing install-paths.json"
    } catch {}
}

# Build paths object, merging with any existing dep installer paths
$paths = @{
    install_dir  = $InstallDir
    bin_dir      = $BinDir
    data_dir     = $DataDir
    ui_dir       = "$InstallDir\src\ui\dev"
    backend_dir  = "$InstallDir\backend"
    siem_dir     = "$BinDir\siem"
    es_dir       = if ($existingPaths?.es_dir) { $existingPaths.es_dir } else { "$BinDir\siem\elasticsearch" }
    kibana_dir   = if ($existingPaths?.kibana_dir) { $existingPaths.kibana_dir } else { "$BinDir\siem\kibana" }
    schemas_dir  = "$InstallDir\database\schemas"
    version      = "1.0.0"
    installed_at = (Get-Date -f "yyyy-MM-dd HH:mm:ss")
    app_installed = $true
}

$json = $paths | ConvertTo-Json -Depth 3
$json | Set-Content $pathsFile -Encoding UTF8
$json | Set-Content "$InstallDir\install-paths.json" -Encoding UTF8
Log "    Written: $pathsFile"

# ─── 3. Install npm dependencies (if Node available) ─────────────────────────
Log "[3] Installing npm dependencies..."
$nodePath = "$env:ProgramFiles\nodejs"
$env:PATH = "$nodePath;$env:PATH"

$uiDir = "$InstallDir\src\ui\dev"
$backendDir = "$InstallDir\backend"

if (Test-Path "$uiDir\package.json") {
    Log "    Installing UI dependencies..."
    Push-Location $uiDir
    & npm install --silent --prefer-offline 2>&1 | ForEach-Object { Log "    npm: $_" }
    Pop-Location
}

if (Test-Path "$backendDir\package.json") {
    Log "    Installing backend dependencies..."
    Push-Location $backendDir
    & npm install --silent --prefer-offline 2>&1 | ForEach-Object { Log "    npm: $_" }
    Pop-Location
}

# ─── 4. Add bin/ to system PATH ──────────────────────────────────────────────
Log "[4] Adding SafeOps bin to system PATH..."
$currentPath = [System.Environment]::GetEnvironmentVariable("PATH", "Machine")
if ($currentPath -notlike "*$BinDir*") {
    [System.Environment]::SetEnvironmentVariable("PATH", "$currentPath;$BinDir", "Machine")
    Log "    Added: $BinDir"
} else {
    Log "    Already in PATH."
}

# ─── 5. Verify key executables ───────────────────────────────────────────────
Log "[5] Verifying installed executables..."
$exes = @(
    @{ Name = "SafeOps Launcher";    Path = "$BinDir\SafeOps.exe" },
    @{ Name = "SafeOps Engine";      Path = "$BinDir\safeops-engine\safeops-engine.exe" },
    @{ Name = "Firewall Engine";     Path = "$BinDir\firewall-engine\firewall-engine.exe" },
    @{ Name = "NIC Management";      Path = "$BinDir\nic_management\nic_management.exe" },
    @{ Name = "DHCP Monitor";        Path = "$BinDir\dhcp_monitor\dhcp_monitor.exe" },
    @{ Name = "Step CA";             Path = "$BinDir\step-ca\bin\step-ca.exe" },
    @{ Name = "SIEM Forwarder";      Path = "$BinDir\siem-forwarder\siem-forwarder.exe" },
    @{ Name = "Threat Intel";        Path = "$BinDir\threat_intel\threat_intel.exe" }
)
foreach ($e in $exes) {
    if (Test-Path $e.Path) {
        Log "    [OK] $($e.Name)"
    } else {
        Log "    [WARN] Missing: $($e.Name) at $($e.Path)"
    }
}

# ─── 6. Register scheduled task (run as admin at every login) ─────────────────
Log "[6] Registering SafeOps as elevated startup task..."
try {
    $exe = "$BinDir\SafeOps.exe"
    $action    = New-ScheduledTaskAction -Execute $exe -WorkingDirectory $BinDir
    $trigger   = New-ScheduledTaskTrigger -AtLogon
    $principal = New-ScheduledTaskPrincipal -UserId "BUILTIN\Administrators" -RunLevel Highest -LogonType Group
    $settings  = New-ScheduledTaskSettingsSet `
                    -ExecutionTimeLimit ([TimeSpan]::Zero) `
                    -MultipleInstances IgnoreNew `
                    -StartWhenAvailable
    $null = Register-ScheduledTask `
        -TaskName "SafeOps Launcher" `
        -TaskPath "\SafeOps\" `
        -Action $action `
        -Trigger $trigger `
        -Principal $principal `
        -Settings $settings `
        -Description "SafeOps Network Security Platform - auto-start with admin rights" `
        -Force
    Log "    [OK] Scheduled task registered: \SafeOps\SafeOps Launcher"
    Log "         Triggers: at every user logon"
    Log "         Privilege: Highest (Administrator)"
} catch {
    Log "    [WARN] Could not register startup task: $_"
    Log "           You can add it manually in Task Scheduler."
}

Log ""
Log "=== SafeOps App Installation Complete ==="
Log "  Launch: $BinDir\SafeOps.exe (runs as Administrator)"
Log "  Web Console: http://localhost:3001 (after launching)"
Log "  Startup: SafeOps auto-starts at every login (Task Scheduler \SafeOps\)"
Log "  Log: $logFile"
