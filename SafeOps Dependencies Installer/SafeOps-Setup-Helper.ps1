# SafeOps Dependencies Installer - PowerShell Helper
# Run as Administrator. Called by Inno Setup during installation.
# Usage: SafeOps-Setup-Helper.ps1 -Step <1-8> -InstallDir <path> -BinDir <path>

param(
    [int]$Step = 0,
    [string]$InstallDir = "C:\Program Files\SafeOps",
    [string]$BinDir = "C:\Program Files\SafeOps\bin",
    [string]$DataDir = "$env:ProgramData\SafeOps"
)

$ErrorActionPreference = "Continue"
$logFile = "$env:USERPROFILE\Desktop\SafeOps-Install-$(Get-Date -f 'yyyy-MM-dd').log"

function Log($msg) {
    $ts = Get-Date -f "HH:mm:ss"
    $line = "[$ts] $msg"
    Write-Host $line
    Add-Content -Path $logFile -Value $line -ErrorAction SilentlyContinue
}

function DownloadFile($url, $dest) {
    Log "Downloading: $url"
    try {
        $wc = New-Object System.Net.WebClient
        $wc.DownloadFile($url, $dest)
        Log "  Downloaded to: $dest"
        return $true
    } catch {
        Log "  WARN: Download failed: $_"
        return $false
    }
}

function IsInstalled($name) {
    $reg = @(
        "HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*",
        "HKLM:\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*"
    )
    foreach ($path in $reg) {
        $found = Get-ItemProperty $path -ErrorAction SilentlyContinue |
            Where-Object { $_.DisplayName -like "*$name*" }
        if ($found) { return $true }
    }
    return $false
}

function RunPsql($sql, $db = "postgres") {
    $psql = "C:\Program Files\PostgreSQL\16\bin\psql.exe"
    if (-not (Test-Path $psql)) {
        $psql = (Get-Command psql -ErrorAction SilentlyContinue)?.Source
    }
    if (-not $psql) { Log "  ERROR: psql not found!"; return }
    $env:PGPASSWORD = "admin"
    & $psql -U postgres -d $db -c $sql 2>&1 | ForEach-Object { Log "  PG: $_" }
}

function RunSqlFile($file, $db = "postgres") {
    $psql = "C:\Program Files\PostgreSQL\16\bin\psql.exe"
    if (-not (Test-Path $psql)) {
        $psql = (Get-Command psql -ErrorAction SilentlyContinue)?.Source
    }
    if (-not $psql) { Log "  ERROR: psql not found!"; return }
    $env:PGPASSWORD = "admin"
    Log "  Running: $(Split-Path $file -Leaf) on $db"
    & $psql -U postgres -d $db -f $file 2>&1 | ForEach-Object { Log "    $_" }
}

New-Item -ItemType Directory -Force -Path $DataDir | Out-Null
Log "=== SafeOps Dependencies Installer - Step $Step ==="
Log "InstallDir : $InstallDir"
Log "BinDir     : $BinDir"

switch ($Step) {

    1 {
        # Install PostgreSQL 16
        Log "[Step 1] Installing PostgreSQL 16..."
        $pgExe = "C:\Program Files\PostgreSQL\16\bin\psql.exe"
        if (Test-Path $pgExe) {
            Log "  PostgreSQL already installed, skipping."
        } else {
            $tmpDir = "$env:TEMP\SafeOps-Setup"
            New-Item -ItemType Directory -Force -Path $tmpDir | Out-Null
            $pgInstaller = "$tmpDir\postgresql-16-installer.exe"
            $downloaded = DownloadFile `
                "https://get.enterprisedb.com/postgresql/postgresql-16.2-1-windows-x64.exe" `
                $pgInstaller
            if ($downloaded -and (Test-Path $pgInstaller)) {
                Log "  Running PostgreSQL installer (silent)..."
                $args = "--mode unattended --superpassword admin --servicename postgresql-16 " +
                        "--serviceaccount postgres --serverport 5432"
                Start-Process -FilePath $pgInstaller -ArgumentList $args -Wait -NoNewWindow
                Log "  PostgreSQL install complete."
            } else {
                Log "  ERROR: Could not download PostgreSQL installer."
                Log "  Please install PostgreSQL 16 manually from https://www.postgresql.org/download/windows/"
                Log "  Set superuser password to: admin"
            }
        }

        # Install Node.js 20 LTS
        Log "[Step 1b] Installing Node.js 20 LTS..."
        $nodePath = "$env:ProgramFiles\nodejs\node.exe"
        if (Test-Path $nodePath) {
            Log "  Node.js already installed."
        } else {
            $tmpDir = "$env:TEMP\SafeOps-Setup"
            New-Item -ItemType Directory -Force -Path $tmpDir | Out-Null
            $nodeInstaller = "$tmpDir\node-installer.msi"
            $downloaded = DownloadFile `
                "https://nodejs.org/dist/v20.11.0/node-v20.11.0-x64.msi" `
                $nodeInstaller
            if ($downloaded -and (Test-Path $nodeInstaller)) {
                Log "  Running Node.js installer (silent)..."
                Start-Process msiexec -ArgumentList "/i `"$nodeInstaller`" /quiet /norestart" -Wait -NoNewWindow
                Log "  Node.js install complete."
            } else {
                Log "  ERROR: Could not download Node.js installer."
                Log "  Please install Node.js 20 LTS manually from https://nodejs.org/"
            }
        }
    }

    2 {
        # Wait for PostgreSQL to start, then create databases/users
        Log "[Step 2] Configuring PostgreSQL databases and users..."
        Start-Sleep -Seconds 5

        $maxRetry = 10
        for ($i = 0; $i -lt $maxRetry; $i++) {
            $env:PGPASSWORD = "admin"
            $test = & "C:\Program Files\PostgreSQL\16\bin\psql.exe" -U postgres -c "SELECT 1" 2>&1
            if ($LASTEXITCODE -eq 0) { Log "  PostgreSQL is ready."; break }
            Log "  Waiting for PostgreSQL... ($i/$maxRetry)"
            Start-Sleep -Seconds 3
        }

        # Create databases
        $databases = @("threat_intel_db", "safeops_network", "safeops")
        foreach ($db in $databases) {
            Log "  Creating database: $db"
            RunPsql "CREATE DATABASE $db;" "postgres"
        }

        # Create users
        $users = @{
            "safeops"          = "safeops_pass"
            "threat_intel_app" = "threat_pass"
            "dhcp_server"      = "dhcp_pass"
            "dns_server"       = "dns_pass"
        }
        foreach ($u in $users.Keys) {
            RunPsql "CREATE USER $u WITH PASSWORD '$($users[$u])';" "postgres"
        }

        # Grant privileges
        RunPsql "GRANT ALL PRIVILEGES ON DATABASE safeops TO safeops;" "postgres"
        RunPsql "GRANT ALL PRIVILEGES ON DATABASE safeops_network TO safeops;" "postgres"
        RunPsql "GRANT ALL PRIVILEGES ON DATABASE threat_intel_db TO threat_intel_app;" "postgres"
        RunPsql "GRANT ALL PRIVILEGES ON DATABASE safeops_network TO dhcp_server;" "postgres"
        RunPsql "GRANT ALL PRIVILEGES ON DATABASE safeops_network TO dns_server;" "postgres"
        Log "  Database setup complete."
    }

    3 {
        # Run all SQL schema files
        Log "[Step 3] Running database schema files..."
        $schemaDir = "$InstallDir\database\schemas"
        if (-not (Test-Path $schemaDir)) {
            Log "  ERROR: Schema directory not found: $schemaDir"
            exit 1
        }

        # Map schema files to their target database
        $dbMap = @{
            "001_initial_setup.sql"    = "safeops"
            "002_ip_reputation.sql"    = "safeops"
            "003_domain_reputation.sql"= "safeops"
            "004_hash_reputation.sql"  = "safeops"
            "007_geolocation.sql"      = "safeops"
            "008_threat_feeds.sql"     = "safeops"
            "010_whitelist_filters.sql"= "safeops"
            "013_dhcp_server.sql"      = "safeops_network"
            "016_firewall_engine.sql"  = "safeops"
            "017_ids_ips.sql"          = "safeops"
            "020_nic_management.sql"   = "safeops_network"
            "021_threat_intel.sql"     = "threat_intel_db"
            "022_step_ca.sql"          = "safeops_network"
            "023_ssl_certificates.sql" = "safeops"
            "users.sql"                = "safeops"
        }

        Get-ChildItem "$schemaDir\*.sql" | Sort-Object Name | ForEach-Object {
            $fileName = $_.Name
            $targetDb = if ($dbMap.ContainsKey($fileName)) { $dbMap[$fileName] } else { "safeops" }
            RunSqlFile $_.FullName $targetDb
        }
        Log "  All schema files executed."
    }

    4 {
        # Install Elasticsearch
        Log "[Step 4] Installing Elasticsearch 8.11..."
        $esDir = "$BinDir\siem\elasticsearch"
        if (Test-Path "$esDir\bin\elasticsearch.bat") {
            Log "  Elasticsearch already present, skipping."
        } else {
            $tmpDir = "$env:TEMP\SafeOps-Setup"
            New-Item -ItemType Directory -Force -Path $tmpDir | Out-Null
            $esZip = "$tmpDir\elasticsearch.zip"
            $downloaded = DownloadFile `
                "https://artifacts.elastic.co/downloads/elasticsearch/elasticsearch-8.11.3-windows-x86_64.zip" `
                $esZip
            if ($downloaded -and (Test-Path $esZip)) {
                Log "  Extracting Elasticsearch..."
                New-Item -ItemType Directory -Force -Path "$BinDir\siem" | Out-Null
                Expand-Archive -Path $esZip -DestinationPath "$BinDir\siem" -Force
                Rename-Item "$BinDir\siem\elasticsearch-8.11.3" "elasticsearch" -ErrorAction SilentlyContinue
                Log "  Elasticsearch extracted."
            } else {
                Log "  WARN: Could not download Elasticsearch."
            }
        }
    }

    5 {
        # Install Kibana
        Log "[Step 5] Installing Kibana 8.11..."
        $kibanaDir = "$BinDir\siem\kibana"
        if (Test-Path "$kibanaDir\bin\kibana.bat") {
            Log "  Kibana already present, skipping."
        } else {
            $tmpDir = "$env:TEMP\SafeOps-Setup"
            New-Item -ItemType Directory -Force -Path $tmpDir | Out-Null
            $kibanaZip = "$tmpDir\kibana.zip"
            $downloaded = DownloadFile `
                "https://artifacts.elastic.co/downloads/kibana/kibana-8.11.3-windows-x86_64.zip" `
                $kibanaZip
            if ($downloaded -and (Test-Path $kibanaZip)) {
                Log "  Extracting Kibana..."
                New-Item -ItemType Directory -Force -Path "$BinDir\siem" | Out-Null
                Expand-Archive -Path $kibanaZip -DestinationPath "$BinDir\siem" -Force
                Rename-Item "$BinDir\siem\kibana-8.11.3" "kibana" -ErrorAction SilentlyContinue
                Log "  Kibana extracted."
            } else {
                Log "  WARN: Could not download Kibana."
            }
        }
    }

    6 {
        # Install npm dependencies for UI and backend
        Log "[Step 6] Installing npm dependencies..."
        $uiDir = "$InstallDir\src\ui\dev"
        $backendDir = "$InstallDir\backend"
        $nodePath = "$env:ProgramFiles\nodejs"

        $env:PATH = "$nodePath;$env:PATH"

        if (Test-Path "$uiDir\package.json") {
            Log "  Installing UI dependencies..."
            Set-Location $uiDir
            & npm install --silent 2>&1 | ForEach-Object { Log "  npm: $_" }
        }
        if (Test-Path "$backendDir\package.json") {
            Log "  Installing backend dependencies..."
            Set-Location $backendDir
            & npm install --silent 2>&1 | ForEach-Object { Log "  npm: $_" }
        }
        Log "  npm dependencies installed."
    }

    7 {
        # Write install-paths.json
        Log "[Step 7] Writing install-paths.json..."
        New-Item -ItemType Directory -Force -Path $DataDir | Out-Null

        # Detect SIEM dirs
        $esDir = "$BinDir\siem\elasticsearch"
        $kibanaDir = "$BinDir\siem\kibana"

        $pathsJson = @{
            install_dir  = $InstallDir
            bin_dir      = $BinDir
            data_dir     = $DataDir
            es_dir       = $esDir
            kibana_dir   = $kibanaDir
            siem_dir     = "$BinDir\siem"
            schemas_dir  = "$InstallDir\database\schemas"
            ui_dir       = "$InstallDir\src\ui\dev"
            backend_dir  = "$InstallDir\backend"
            version      = "1.0.0"
            installed_at = (Get-Date -f "yyyy-MM-dd HH:mm:ss")
        } | ConvertTo-Json -Depth 3

        $pathsJson | Set-Content "$DataDir\install-paths.json" -Encoding UTF8
        $pathsJson | Set-Content "$InstallDir\install-paths.json" -Encoding UTF8
        Log "  Written: $DataDir\install-paths.json"
        Log "  Written: $InstallDir\install-paths.json"
    }

    8 {
        # Final verification
        Log "[Step 8] Verifying installation..."
        $checks = @(
            @{ Name = "PostgreSQL binary"; Path = "C:\Program Files\PostgreSQL\16\bin\psql.exe" },
            @{ Name = "Node.js binary";    Path = "$env:ProgramFiles\nodejs\node.exe" },
            @{ Name = "install-paths.json"; Path = "$DataDir\install-paths.json" }
        )
        $allOk = $true
        foreach ($c in $checks) {
            if (Test-Path $c.Path) {
                Log "  [OK] $($c.Name)"
            } else {
                Log "  [WARN] Missing: $($c.Name) at $($c.Path)"
                $allOk = $false
            }
        }
        if ($allOk) {
            Log "  All checks passed! SafeOps dependencies are installed."
        } else {
            Log "  Some checks failed. See log for details."
        }

        # Show summary
        Log ""
        Log "=== INSTALLATION SUMMARY ==="
        Log "  PostgreSQL password: admin"
        Log "  Databases: safeops, safeops_network, threat_intel_db"
        Log "  Users: safeops / threat_intel_app / dhcp_server / dns_server"
        Log "  install-paths.json: $DataDir\install-paths.json"
        Log "  Log file: $logFile"
    }

    default {
        Log "Unknown step: $Step"
        exit 1
    }
}

Log "[Step $Step] DONE."
