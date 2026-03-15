# SafeOps Complete Installer - PowerShell Helper
# Handles ALL installation steps: deps, DB, schemas, SIEM, app, paths
# Must be run as Administrator (Inno Setup does this automatically)
#
# Usage: SafeOps-Install-Helper.ps1 -Step <1-10> -InstallDir <path> -BinDir <path>

param(
    [int]$Step = 0,
    [string]$InstallDir = "C:\Program Files\SafeOps",
    [string]$BinDir = "C:\Program Files\SafeOps\bin",
    [string]$DataDir = "$env:ProgramData\SafeOps",
    [string]$Username = "admin",
    [string]$Password = "safeops123"
)

$ErrorActionPreference = "Continue"
$logDate = Get-Date -f 'yyyyMMdd-HHmmss'
New-Item -ItemType Directory -Force -Path $DataDir | Out-Null

# Log to both %ProgramData%\SafeOps\ AND Desktop (for easy sharing from VMs)
$logFile       = "$DataDir\install-$logDate.log"
$desktopLog    = "$env:PUBLIC\Desktop\SafeOps-Install-$logDate.log"
# Also a fixed-name log that gets overwritten each run (easy to find)
$desktopLatest = "$env:PUBLIC\Desktop\SafeOps-Install-Latest.log"

function Log($msg) {
    $ts = Get-Date -f "HH:mm:ss"
    $line = "[$ts] $msg"
    Write-Host $line
    Add-Content -Path $logFile       -Value $line -ErrorAction SilentlyContinue
    Add-Content -Path $desktopLog    -Value $line -ErrorAction SilentlyContinue
    Add-Content -Path $desktopLatest -Value $line -ErrorAction SilentlyContinue
}

function DownloadFile($url, $dest) {
    Log "  Downloading: $([System.IO.Path]::GetFileName($dest))..."
    try {
        $wc = New-Object System.Net.WebClient
        $wc.DownloadFile($url, $dest)
        Log "  OK: $dest"
        return $true
    } catch {
        Log "  WARN: Download failed — $_"
        return $false
    }
}

function WaitForPostgres($maxRetries = 20) {
    $psql = Find-Psql
    if (-not $psql) { return $false }
    for ($i = 0; $i -lt $maxRetries; $i++) {
        $env:PGPASSWORD = "admin"
        $out = & $psql -U postgres -c "SELECT 1" 2>&1
        if ($LASTEXITCODE -eq 0) { Log "  PostgreSQL is ready."; return $true }
        Log "  Waiting for PostgreSQL... ($($i+1)/$maxRetries)"
        Start-Sleep -Seconds 3
    }
    return $false
}

function Find-Psql {
    $paths = @(
        "C:\Program Files\PostgreSQL\16\bin\psql.exe",
        "C:\Program Files\PostgreSQL\15\bin\psql.exe",
        "C:\Program Files\PostgreSQL\17\bin\psql.exe"
    )
    foreach ($p in $paths) { if (Test-Path $p) { return $p } }
    $cmd = Get-Command psql -ErrorAction SilentlyContinue
    if ($cmd) { return $cmd.Source }
    return $null
}

function RunPsql($sql, $db = "postgres") {
    $psql = Find-Psql
    if (-not $psql) { Log "  ERROR: psql not found"; return }
    $env:PGPASSWORD = "admin"
    & $psql -U postgres -d $db -c $sql 2>&1 | ForEach-Object { Log "    PG: $_" }
}

function RunSqlFile($file, $db) {
    $psql = Find-Psql
    if (-not $psql) { Log "  ERROR: psql not found"; return }
    $env:PGPASSWORD = "admin"
    Log "  Schema: $(Split-Path $file -Leaf) → $db"
    & $psql -U postgres -d $db -f $file 2>&1 | ForEach-Object { Log "    $_" }
}

$tmp = "$env:TEMP\SafeOps-Install"
New-Item -ItemType Directory -Force -Path $tmp | Out-Null

Log "═══════════════════════════════════════════════════════"
Log " SafeOps Complete Installer — Step $Step"
Log "═══════════════════════════════════════════════════════"
Log " InstallDir  : $InstallDir"
Log " BinDir      : $BinDir"
Log " DataDir     : $DataDir"
Log " Machine     : $env:COMPUTERNAME"
Log " User        : $env:USERNAME"
Log " Date        : $(Get-Date -f 'yyyy-MM-dd HH:mm:ss')"
Log " LogFile     : $logFile"
Log " Desktop log : $desktopLog"
Log "═══════════════════════════════════════════════════════"

switch ($Step) {

    # ─────────────────────────────────────────────────────
    1 {
        Log "[STEP 1] Installing PostgreSQL 16..."
        $pgExe = "C:\Program Files\PostgreSQL\16\bin\psql.exe"
        if (Test-Path $pgExe) {
            Log "  PostgreSQL 16 already installed — skipping."
        } else {
            $installer = "$tmp\pg16-installer.exe"
            $ok = DownloadFile `
                "https://get.enterprisedb.com/postgresql/postgresql-16.2-1-windows-x64.exe" `
                $installer
            if ($ok) {
                Log "  Running PostgreSQL installer (silent)..."
                $args = "--mode unattended --superpassword admin " +
                        "--servicename postgresql-16 --serviceaccount postgres " +
                        "--serverport 5432 --install_runtimes 0"
                Start-Process -FilePath $installer -ArgumentList $args -Wait -NoNewWindow
                Log "  PostgreSQL 16 installed."
            } else {
                Log "  WARN: Could not download PostgreSQL. Install manually:"
                Log "        https://www.postgresql.org/download/windows/"
                Log "        (Set superuser password to: admin)"
            }
        }
    }

    # ─────────────────────────────────────────────────────
    2 {
        Log "[STEP 2] Installing Node.js 20 LTS..."
        $nodeExe = "$env:ProgramFiles\nodejs\node.exe"
        if (Test-Path $nodeExe) {
            Log "  Node.js already installed — skipping."
        } else {
            $installer = "$tmp\nodejs-installer.msi"
            $ok = DownloadFile `
                "https://nodejs.org/dist/v20.11.0/node-v20.11.0-x64.msi" `
                $installer
            if ($ok) {
                Log "  Running Node.js installer (silent)..."
                Start-Process msiexec -ArgumentList "/i `"$installer`" /quiet /norestart ADDLOCAL=ALL" -Wait -NoNewWindow
                Log "  Node.js 20 installed."
            } else {
                Log "  WARN: Could not download Node.js. Install manually: https://nodejs.org/"
            }
        }
    }

    # ─────────────────────────────────────────────────────
    3 {
        Log "[STEP 3] Installing WinPkFilter driver (NDIS packet capture)..."
        $driverPath = "$BinDir\safeops-engine"
        # Check if already installed by looking for the DLL used by safeops-engine
        $dllCheck = @(
            "C:\Windows\System32\drivers\ndisrd.sys",
            "$env:SystemRoot\System32\drivers\ndisrd.sys"
        )
        $alreadyInstalled = $dllCheck | Where-Object { Test-Path $_ }
        if ($alreadyInstalled) {
            Log "  WinPkFilter driver already present — skipping."
        } else {
            $installer = "$tmp\WinPktFilter_Setup.exe"
            $ok = DownloadFile `
                "https://www.ntkernel.com/downloads/WinPktFilter_Setup.exe" `
                $installer
            if ($ok) {
                Log "  Installing WinPkFilter driver (silent)..."
                Start-Process -FilePath $installer -ArgumentList "/VERYSILENT /NORESTART" -Wait -NoNewWindow
                Log "  WinPkFilter driver installed."
            } else {
                Log "  WARN: Could not download WinPkFilter."
                Log "        SafeOps Engine requires this driver for packet capture."
                Log "        Manual install: https://www.ntkernel.com/windows-packet-filter/"
            }
        }
    }

    # ─────────────────────────────────────────────────────
    4 {
        Log "[STEP 4] Configuring PostgreSQL databases and users..."
        if (-not (WaitForPostgres)) {
            Log "  ERROR: PostgreSQL not reachable. Ensure PostgreSQL service is running."
            exit 1
        }

        # Create databases
        foreach ($db in @("safeops", "safeops_network", "threat_intel_db")) {
            Log "  Creating database: $db"
            RunPsql "CREATE DATABASE $db;" "postgres"
        }

        # Create app users
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
        Log "  Database users and permissions configured."
    }

    # ─────────────────────────────────────────────────────
    5 {
        Log "[STEP 5] Running database schema files..."
        $schemaDir = "$InstallDir\database\schemas"
        if (-not (Test-Path $schemaDir)) {
            Log "  ERROR: Schema dir not found: $schemaDir"
            exit 1
        }

        # Schema → database mapping
        $dbMap = @{
            "001_initial_setup.sql"     = "safeops"
            "002_ip_reputation.sql"     = "safeops"
            "003_domain_reputation.sql" = "safeops"
            "004_hash_reputation.sql"   = "safeops"
            "007_geolocation.sql"       = "safeops"
            "008_threat_feeds.sql"      = "safeops"
            "010_whitelist_filters.sql" = "safeops"
            "013_dhcp_server.sql"       = "safeops_network"
            "016_firewall_engine.sql"   = "safeops"
            "017_ids_ips.sql"           = "safeops"
            "020_nic_management.sql"    = "safeops_network"
            "021_threat_intel.sql"      = "threat_intel_db"
            "022_step_ca.sql"           = "safeops_network"
            "023_ssl_certificates.sql"  = "safeops"
            "users.sql"                 = "safeops"
        }

        Get-ChildItem "$schemaDir\*.sql" | Sort-Object Name | ForEach-Object {
            $targetDb = if ($dbMap.ContainsKey($_.Name)) { $dbMap[$_.Name] } else { "safeops" }
            RunSqlFile $_.FullName $targetDb
        }

        # Run patches if any
        $patchDir = "$InstallDir\database\patches"
        if (Test-Path $patchDir) {
            Get-ChildItem "$patchDir\*.sql" | Sort-Object Name | ForEach-Object {
                RunSqlFile $_.FullName "safeops"
            }
        }

        Log "  All schema files executed."
    }

    # ─────────────────────────────────────────────────────
    6 {
        Log "[STEP 6] Creating default admin user in database..."
        if (-not (WaitForPostgres 5)) {
            Log "  WARN: PostgreSQL not reachable, skipping user creation."
        } else {
            $env:PGPASSWORD = "admin"
            $psql = Find-Psql
            $sql = "INSERT INTO users (username, password_hash, role, created_at, is_active) " +
                   "VALUES ('$Username', '$Password', 'superadmin', NOW(), true) " +
                   "ON CONFLICT (username) DO UPDATE SET password_hash = '$Password', role = 'superadmin', is_active = true;"
            & $psql -U postgres -d safeops -c $sql 2>&1 | ForEach-Object { Log "  $_" }
            Log "  Default admin user created: $Username / $Password"
        }
    }

    # ─────────────────────────────────────────────────────
    7 {
        Log "[STEP 7] Setting up Elasticsearch 8.11..."
        $esTarget = "$BinDir\siem\elasticsearch"
        if (Test-Path "$esTarget\bin\elasticsearch.bat") {
            Log "  Elasticsearch already present — skipping."
        } else {
            New-Item -ItemType Directory -Force -Path "$BinDir\siem" | Out-Null
            $esZip = "$tmp\elasticsearch.zip"
            $ok = DownloadFile `
                "https://artifacts.elastic.co/downloads/elasticsearch/elasticsearch-8.11.3-windows-x86_64.zip" `
                $esZip
            if ($ok) {
                Log "  Extracting Elasticsearch (~700MB, please wait)..."
                Expand-Archive -Path $esZip -DestinationPath "$BinDir\siem" -Force
                $extracted = Get-ChildItem "$BinDir\siem" -Filter "elasticsearch-*" -Directory | Select-Object -First 1
                if ($extracted) { Rename-Item $extracted.FullName "elasticsearch" -ErrorAction SilentlyContinue }
                Log "  Elasticsearch extracted."

                # Disable security for local development
                $configFile = "$esTarget\config\elasticsearch.yml"
                if (Test-Path $configFile) {
                    Add-Content -Path $configFile -Value "`nxpack.security.enabled: false"
                    Add-Content -Path $configFile -Value "xpack.security.http.ssl.enabled: false"
                    Log "  Elasticsearch security disabled (local dev mode)."
                }
            } else {
                Log "  WARN: Could not download Elasticsearch. Run SIEM scripts manually later."
            }
        }
    }

    # ─────────────────────────────────────────────────────
    8 {
        Log "[STEP 8] Setting up Kibana 8.11..."
        $kibanaTarget = "$BinDir\siem\kibana"
        if (Test-Path "$kibanaTarget\bin\kibana.bat") {
            Log "  Kibana already present — skipping."
        } else {
            New-Item -ItemType Directory -Force -Path "$BinDir\siem" | Out-Null
            $kibanaZip = "$tmp\kibana.zip"
            $ok = DownloadFile `
                "https://artifacts.elastic.co/downloads/kibana/kibana-8.11.3-windows-x86_64.zip" `
                $kibanaZip
            if ($ok) {
                Log "  Extracting Kibana (~700MB, please wait)..."
                Expand-Archive -Path $kibanaZip -DestinationPath "$BinDir\siem" -Force
                $extracted = Get-ChildItem "$BinDir\siem" -Filter "kibana-*" -Directory | Select-Object -First 1
                if ($extracted) { Rename-Item $extracted.FullName "kibana" -ErrorAction SilentlyContinue }
                Log "  Kibana extracted."
            } else {
                Log "  WARN: Could not download Kibana. Run SIEM scripts manually later."
            }
        }
    }

    # ─────────────────────────────────────────────────────
    9 {
        Log "[STEP 9] Installing Node.js dependencies (UI + backend)..."
        $nodePath = "$env:ProgramFiles\nodejs"
        $env:PATH = "$nodePath;$env:PATH"

        $uiDir     = "$InstallDir\src\ui\dev"
        $backendDir = "$InstallDir\backend"

        foreach ($dir in @($uiDir, $backendDir)) {
            if (Test-Path "$dir\package.json") {
                Log "  npm install in: $dir"
                Push-Location $dir
                & npm install --silent --prefer-offline 2>&1 | ForEach-Object { Log "    $_" }
                Pop-Location
            }
        }
        Log "  npm dependencies installed."
    }

    # ─────────────────────────────────────────────────────
    10 {
        Log "[STEP 10] Finalizing installation..."

        # Set SAFEOPS_HOME env var (system-wide)
        [System.Environment]::SetEnvironmentVariable("SAFEOPS_HOME", $InstallDir, "Machine")
        $env:SAFEOPS_HOME = $InstallDir
        Log "  SAFEOPS_HOME = $InstallDir"

        # Add bin to PATH
        $currentPath = [System.Environment]::GetEnvironmentVariable("PATH", "Machine")
        if ($currentPath -notlike "*$BinDir*") {
            [System.Environment]::SetEnvironmentVariable("PATH", "$currentPath;$BinDir", "Machine")
            Log "  Added $BinDir to system PATH."
        }

        # Write install-paths.json
        $esDir     = "$BinDir\siem\elasticsearch"
        $kibanaDir = "$BinDir\siem\kibana"

        $paths = @{
            install_dir  = $InstallDir
            bin_dir      = $BinDir
            data_dir     = $DataDir
            ui_dir       = "$InstallDir\src\ui\dev"
            backend_dir  = "$InstallDir\backend"
            siem_dir     = "$BinDir\siem"
            es_dir       = $esDir
            kibana_dir   = $kibanaDir
            schemas_dir  = "$InstallDir\database\schemas"
            version      = "1.0.0"
            installed_at = (Get-Date -f "yyyy-MM-dd HH:mm:ss")
        } | ConvertTo-Json -Depth 3

        New-Item -ItemType Directory -Force -Path $DataDir | Out-Null
        $paths | Set-Content "$DataDir\install-paths.json" -Encoding UTF8
        $paths | Set-Content "$InstallDir\install-paths.json" -Encoding UTF8
        Log "  install-paths.json written."

        # Write getting-started README
        $siemDir = "$BinDir\siem"
        $readme = @"
═══════════════════════════════════════════════════════════════════
   SAFEOPS - GETTING STARTED GUIDE
   Generated: $(Get-Date -f "yyyy-MM-dd HH:mm")
═══════════════════════════════════════════════════════════════════

IMPORTANT: Follow this order for first launch!

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
STEP 1 — SIEM Setup (do this FIRST, takes 5-15 minutes)
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

  1a. Start Elasticsearch:
      $siemDir\1-start-elasticsearch.bat
      → Wait until you see "started" in the output (~2-3 min)

  1b. Set up ES index templates:
      $siemDir\0-setup-elasticsearch-templates.bat
      → Wait until "Templates created" message

  1c. Start Kibana:
      $siemDir\2-start-kibana.bat
      ⚠ KIBANA IS SLOW — takes 3-5 minutes to start
      → Then open: http://localhost:5601

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
STEP 2 — Start SafeOps Services (from the Launcher)
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

  Open SafeOps Launcher from your Desktop or Start Menu.
  It auto-starts: Firewall Engine + Web UI

  Then start manually as needed:
    • SafeOps Engine      (NDIS packet capture — needs driver)
    • SIEM Forwarder      (ships logs → Elasticsearch)
    • NIC Management      (network interface control)
    • DHCP Monitor        (lease tracking)
    • Captive Portal      (CA cert delivery)
    • Threat Intel        (feed updates)

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
STEP 3 — Open Web Dashboard
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

  Click "Open Web Console" in the Launcher, or visit:
  → http://localhost:3001

  Login: $Username / $Password

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
PORTS REFERENCE
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

  Web Dashboard   → http://localhost:3001
  Kibana (SIEM)   → http://localhost:5601
  Elasticsearch   → http://localhost:9200
  Firewall API    → http://localhost:50052
  Step-CA         → https://localhost:9000
  NIC Management  → http://localhost:8081
  Captive Portal  → http://localhost:8090
  PostgreSQL      → localhost:5432  (password: admin)

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
NOTES
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

  • All services run as Administrator
  • No CMD windows appear when launched from SafeOps Launcher
  • WinPkFilter driver required for SafeOps Engine (packet capture)
  • Install log : $logFile
  • Desktop log : $desktopLog  ← share this when reporting issues
  • Runtime log : See SafeOps-Startup-<date>.log on Desktop after first launch

═══════════════════════════════════════════════════════════════════
"@
        $readmePath = "$InstallDir\IMPORTANT-README.txt"
        $readme | Set-Content $readmePath -Encoding UTF8
        # Also put on desktop for visibility
        $desktopReadme = "$env:PUBLIC\Desktop\SafeOps-README.txt"
        $readme | Set-Content $desktopReadme -Encoding UTF8 -ErrorAction SilentlyContinue
        Log "  README written to: $readmePath"
        Log "  README also on Desktop: $desktopReadme"

        # Final verification
        Log ""
        Log "  Verifying installed components..."
        $checks = @(
            @{ Name = "SafeOps Launcher";    Path = "$BinDir\SafeOps.exe" },
            @{ Name = "Firewall Engine";     Path = "$BinDir\firewall-engine\firewall-engine.exe" },
            @{ Name = "SafeOps Engine";      Path = "$BinDir\safeops-engine\safeops-engine.exe" },
            @{ Name = "NIC Management";      Path = "$BinDir\nic_management\nic_management.exe" },
            @{ Name = "DHCP Monitor";        Path = "$BinDir\dhcp_monitor\dhcp_monitor.exe" },
            @{ Name = "Step-CA";             Path = "$BinDir\step-ca\bin\step-ca.exe" },
            @{ Name = "SIEM Forwarder";      Path = "$BinDir\siem-forwarder\siem-forwarder.exe" },
            @{ Name = "Captive Portal";      Path = "$BinDir\captive_portal\captive_portal.exe" },
            @{ Name = "Network Logger";      Path = "$BinDir\network-logger\network-logger.exe" },
            @{ Name = "Threat Intel";        Path = "$BinDir\threat_intel\threat_intel.exe" },
            @{ Name = "PostgreSQL";          Path = "C:\Program Files\PostgreSQL\16\bin\psql.exe" },
            @{ Name = "Node.js";             Path = "$env:ProgramFiles\nodejs\node.exe" },
            @{ Name = "install-paths.json";  Path = "$DataDir\install-paths.json" }
        )
        foreach ($c in $checks) {
            $status = if (Test-Path $c.Path) { "[OK]   " } else { "[WARN] " }
            Log "  $status $($c.Name)"
        }

        # Register elevated startup scheduled task
        Log ""
        Log "  Registering SafeOps as elevated startup task..."
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
            Log "  [OK]   Startup task: \SafeOps\SafeOps Launcher (runs elevated at every login)"
        } catch {
            Log "  [WARN] Startup task failed: $_ (add manually in Task Scheduler)"
        }

        Log ""
        Log "═══════════════════════════════════════════════════════"
        Log " SafeOps installation complete!"
        Log " Launch   : $BinDir\SafeOps.exe"
        Log " Startup  : Auto-starts at login (Task Scheduler \SafeOps\)"
        Log " Read     : $readmePath"
        Log " Log file : $desktopLog"
        Log "═══════════════════════════════════════════════════════"
        Log " ← SafeOps-Install-Latest.log on Desktop for easy sharing"
        Log "═══════════════════════════════════════════════════════"
    }

    default {
        Log "Unknown step: $Step"
        exit 1
    }
}

Log "[Step $Step] DONE."
