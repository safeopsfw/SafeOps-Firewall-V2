# SafeOps SIEM - Elasticsearch + Kibana Installer
# Downloads, Extracts, and Configures ES + Kibana
# SIEM Forwarder (Go binary) replaces Logstash — no Logstash needed
# Run as Administrator

#Requires -RunAsAdministrator

param(
    [switch]$SkipDownload,
    [switch]$Force
)

# ============== CONFIGURATION ==============
$ELK_VERSION = "8.11.3"
$INSTALL_DIR = "D:\SafeOps-SIEM-Integration"
$SAFEOPS_ROOT = "D:\SafeOpsFV2"

$ES_URL = "https://artifacts.elastic.co/downloads/elasticsearch/elasticsearch-$ELK_VERSION-windows-x86_64.zip"
$KIBANA_URL = "https://artifacts.elastic.co/downloads/kibana/kibana-$ELK_VERSION-windows-x86_64.zip"

# ============== FUNCTIONS ==============

function Write-Step {
    param([string]$Message)
    Write-Host "`n[$((Get-Date).ToString('HH:mm:ss'))] $Message" -ForegroundColor Cyan
}

function Write-OK {
    param([string]$Message)
    Write-Host "  [OK] $Message" -ForegroundColor Green
}

function Write-Skip {
    param([string]$Message)
    Write-Host "  [SKIP] $Message" -ForegroundColor Yellow
}

function Get-Component {
    param([string]$Name, [string]$Url, [string]$OutFile)

    if ((Test-Path $OutFile) -and -not $Force) {
        Write-Skip "$Name already downloaded"
        return
    }

    Write-Host "  Downloading $Name (~300-400 MB)..." -ForegroundColor White
    $ProgressPreference = 'SilentlyContinue'
    Invoke-WebRequest -Uri $Url -OutFile $OutFile -UseBasicParsing
    $ProgressPreference = 'Continue'
    Write-OK "$Name downloaded"
}

function Expand-Component {
    param([string]$Name, [string]$ZipFile, [string]$DestDir)

    $existing = Get-ChildItem -Path $DestDir -Directory -ErrorAction SilentlyContinue |
    Where-Object { $_.Name -like "$Name-*" }

    if ($existing -and -not $Force) {
        Write-Skip "$Name already extracted"
        return
    }

    Write-Host "  Extracting $Name..." -ForegroundColor White
    Expand-Archive -Path $ZipFile -DestinationPath $DestDir -Force
    Write-OK "$Name extracted"
}

function Set-ElasticsearchConfig {
    $esDir = Get-ChildItem "$INSTALL_DIR\elasticsearch" -Directory |
    Where-Object { $_.Name -like "elasticsearch-*" } | Select-Object -First 1

    $config = @"
# SafeOps Elasticsearch Configuration
cluster.name: safeops-siem
node.name: safeops-node-1
path.data: $INSTALL_DIR/data/elasticsearch
path.logs: $INSTALL_DIR/logs/elasticsearch
network.host: 127.0.0.1
http.port: 9200
xpack.security.enabled: false
xpack.security.enrollment.enabled: false
xpack.security.http.ssl.enabled: false
xpack.security.transport.ssl.enabled: false
xpack.ml.enabled: false
xpack.watcher.enabled: false
xpack.monitoring.collection.enabled: false
discovery.type: single-node
"@

    $config | Out-File "$($esDir.FullName)\config\elasticsearch.yml" -Encoding UTF8 -Force

    # Set ES heap to 512MB (sufficient for local dev)
    $jvmDir = "$($esDir.FullName)\config\jvm.options.d"
    New-Item -Path $jvmDir -ItemType Directory -Force | Out-Null
    $jvmOptions = @"
-Xms512m
-Xmx512m
"@
    $jvmOptions | Out-File "$jvmDir\safeops.options" -Encoding UTF8 -Force

    Write-OK "Elasticsearch configured (512MB heap, security disabled)"
}

function Set-KibanaConfig {
    $kibanaDir = Get-ChildItem "$INSTALL_DIR\kibana" -Directory |
    Where-Object { $_.Name -like "kibana-*" } | Select-Object -First 1

    $config = @"
# SafeOps Kibana Configuration
server.port: 5601
server.host: "127.0.0.1"
server.name: "safeops-kibana"
elasticsearch.hosts: ["http://127.0.0.1:9200"]
logging:
  appenders:
    console:
      type: console
      layout:
        type: pattern
  root:
    appenders: [console]
    level: info
xpack.encryptedSavedObjects.encryptionKey: "safeops2026encryptionkey123456789"
xpack.reporting.encryptionKey: "safeops2026reportingkey1234567890"
xpack.security.encryptionKey: "safeops2026securitykey12345678901"
"@

    $config | Out-File "$($kibanaDir.FullName)\config\kibana.yml" -Encoding UTF8 -Force
    Write-OK "Kibana configured"
}

function Install-ElasticsearchService {
    $esDir = Get-ChildItem "$INSTALL_DIR\elasticsearch" -Directory |
    Where-Object { $_.Name -like "elasticsearch-*" } | Select-Object -First 1

    $service = Get-Service -Name "elasticsearch-service-x64" -ErrorAction SilentlyContinue
    if (-not $service) {
        Push-Location "$($esDir.FullName)\bin"
        & cmd /c "elasticsearch-service.bat install" 2>&1 | Out-Null
        Pop-Location
        Write-OK "Elasticsearch Windows service installed"
    }
    else {
        Write-Skip "Elasticsearch service already installed"
    }

    # Set to delayed auto-start
    & sc.exe config "elasticsearch-service-x64" start= delayed-auto 2>&1 | Out-Null
}

function New-StartScripts {
    $scriptsDir = "$INSTALL_DIR\scripts"
    New-Item -Path $scriptsDir -ItemType Directory -Force | Out-Null

    $kibanaDir = (Get-ChildItem "$INSTALL_DIR\kibana" -Directory | Where-Object { $_.Name -like "kibana-*" } | Select-Object -First 1).FullName

    # 0 - First-time setup: ES templates + Kibana data views
    @"
@echo off
>nul 2>&1 "%SYSTEMROOT%\system32\cacls.exe" "%SYSTEMROOT%\system32\config\system"
if '%errorlevel%' NEQ '0' (powershell -Command "Start-Process '%~f0' -Verb RunAs" & exit /b)
title SafeOps ES Setup
echo ============================================
echo   SafeOps Elasticsearch Index Templates
echo ============================================
echo.
echo Checking Elasticsearch at http://127.0.0.1:9200 ...

REM Wait for ES
:wait_es
curl -s -o nul -w "%%%%{http_code}" http://127.0.0.1:9200 > %TEMP%\es_status.txt 2>nul
set /p ES_STATUS=<%TEMP%\es_status.txt
if "%ES_STATUS%" NEQ "200" (
    echo   ES not ready, retrying in 5s...
    timeout /t 5 /nobreak >nul
    goto wait_es
)
echo   Elasticsearch is UP.
echo.

echo Creating index template: firewall ...
curl -s -X PUT "http://127.0.0.1:9200/_index_template/firewall" -H "Content-Type: application/json" -d "{\"index_patterns\":[\"firewall-*\"],\"priority\":100,\"template\":{\"settings\":{\"number_of_shards\":1,\"number_of_replicas\":0},\"mappings\":{\"dynamic\":true,\"properties\":{\"ts\":{\"type\":\"date\"},\"@timestamp\":{\"type\":\"date\"},\"forwarded_at\":{\"type\":\"date\"},\"src\":{\"type\":\"ip\"},\"dst\":{\"type\":\"ip\"},\"sp\":{\"type\":\"integer\"},\"dp\":{\"type\":\"integer\"},\"proto\":{\"type\":\"keyword\"},\"action\":{\"type\":\"keyword\"},\"detector\":{\"type\":\"keyword\"},\"domain\":{\"type\":\"keyword\"},\"severity\":{\"type\":\"keyword\"},\"dir\":{\"type\":\"keyword\"},\"ttype\":{\"type\":\"keyword\"},\"cid\":{\"type\":\"keyword\"},\"event_type\":{\"type\":\"keyword\"},\"flags\":{\"type\":\"keyword\"},\"flow_id\":{\"type\":\"long\"},\"size\":{\"type\":\"integer\"},\"ttl\":{\"type\":\"integer\"},\"src_geo\":{\"type\":\"keyword\"},\"dst_geo\":{\"type\":\"keyword\"},\"src_asn\":{\"type\":\"keyword\"},\"dst_asn\":{\"type\":\"keyword\"},\"reason\":{\"type\":\"text\",\"fields\":{\"keyword\":{\"type\":\"keyword\"}}},\"log_type\":{\"type\":\"keyword\"},\"source_file\":{\"type\":\"keyword\"}}}}}" >nul 2>&1
echo   Done.

echo Creating index template: ids ...
curl -s -X PUT "http://127.0.0.1:9200/_index_template/ids" -H "Content-Type: application/json" -d "{\"index_patterns\":[\"ids-*\"],\"priority\":100,\"template\":{\"settings\":{\"number_of_shards\":1,\"number_of_replicas\":0},\"mappings\":{\"dynamic\":true,\"properties\":{\"timestamp\":{\"type\":\"date\"},\"@timestamp\":{\"type\":\"date\"},\"forwarded_at\":{\"type\":\"date\"},\"src_ip\":{\"type\":\"ip\"},\"dst_ip\":{\"type\":\"ip\"},\"src_port\":{\"type\":\"integer\"},\"dst_port\":{\"type\":\"integer\"},\"proto\":{\"type\":\"keyword\"},\"event_type\":{\"type\":\"keyword\"},\"flow_id\":{\"type\":\"keyword\"},\"community_id\":{\"type\":\"keyword\"},\"direction\":{\"type\":\"keyword\"},\"app_proto\":{\"type\":\"keyword\"},\"dns\":{\"type\":\"object\"},\"http\":{\"type\":\"object\"},\"tls\":{\"type\":\"object\"},\"src_geo\":{\"type\":\"object\",\"properties\":{\"country\":{\"type\":\"keyword\"},\"country_name\":{\"type\":\"keyword\"},\"lat\":{\"type\":\"float\"},\"lon\":{\"type\":\"float\"},\"asn\":{\"type\":\"long\"},\"asn_org\":{\"type\":\"keyword\"}}},\"dst_geo\":{\"type\":\"object\",\"properties\":{\"country\":{\"type\":\"keyword\"},\"country_name\":{\"type\":\"keyword\"},\"lat\":{\"type\":\"float\"},\"lon\":{\"type\":\"float\"},\"asn\":{\"type\":\"long\"},\"asn_org\":{\"type\":\"keyword\"}}},\"log_type\":{\"type\":\"keyword\"},\"source_file\":{\"type\":\"keyword\"}}}}}" >nul 2>&1
echo   Done.

echo Creating index template: east-west ...
curl -s -X PUT "http://127.0.0.1:9200/_index_template/east-west" -H "Content-Type: application/json" -d "{\"index_patterns\":[\"east-west-*\"],\"priority\":100,\"template\":{\"settings\":{\"number_of_shards\":1,\"number_of_replicas\":0},\"mappings\":{\"dynamic\":true,\"properties\":{\"timestamp\":{\"type\":\"date\"},\"@timestamp\":{\"type\":\"date\"},\"forwarded_at\":{\"type\":\"date\"},\"flow_start\":{\"type\":\"date\"},\"flow_end\":{\"type\":\"date\"},\"src_ip\":{\"type\":\"ip\"},\"dst_ip\":{\"type\":\"ip\"},\"src_port\":{\"type\":\"integer\"},\"dst_port\":{\"type\":\"integer\"},\"proto\":{\"type\":\"integer\"},\"protocol\":{\"type\":\"keyword\"},\"app_proto\":{\"type\":\"keyword\"},\"direction\":{\"type\":\"keyword\"},\"flow_id\":{\"type\":\"keyword\"},\"community_id\":{\"type\":\"keyword\"},\"initiator\":{\"type\":\"keyword\"},\"flow_end_reason\":{\"type\":\"keyword\"},\"tcp_state\":{\"type\":\"keyword\"},\"tcp_flags_ts\":{\"type\":\"keyword\"},\"tcp_flags_tc\":{\"type\":\"keyword\"},\"pkts_toserver\":{\"type\":\"long\"},\"pkts_toclient\":{\"type\":\"long\"},\"bytes_toserver\":{\"type\":\"long\"},\"bytes_toclient\":{\"type\":\"long\"},\"flow_duration_sec\":{\"type\":\"float\"},\"tos\":{\"type\":\"integer\"},\"dscp\":{\"type\":\"integer\"},\"src_geo\":{\"type\":\"object\",\"properties\":{\"country\":{\"type\":\"keyword\"},\"country_name\":{\"type\":\"keyword\"},\"lat\":{\"type\":\"float\"},\"lon\":{\"type\":\"float\"},\"asn\":{\"type\":\"long\"},\"asn_org\":{\"type\":\"keyword\"}}},\"dst_geo\":{\"type\":\"object\",\"properties\":{\"country\":{\"type\":\"keyword\"},\"country_name\":{\"type\":\"keyword\"},\"lat\":{\"type\":\"float\"},\"lon\":{\"type\":\"float\"},\"asn\":{\"type\":\"long\"},\"asn_org\":{\"type\":\"keyword\"}}},\"log_type\":{\"type\":\"keyword\"},\"source_file\":{\"type\":\"keyword\"}}}}}" >nul 2>&1
echo   Done.

echo Creating index template: north-south ...
curl -s -X PUT "http://127.0.0.1:9200/_index_template/north-south" -H "Content-Type: application/json" -d "{\"index_patterns\":[\"north-south-*\"],\"priority\":100,\"template\":{\"settings\":{\"number_of_shards\":1,\"number_of_replicas\":0},\"mappings\":{\"dynamic\":true,\"properties\":{\"timestamp\":{\"type\":\"date\"},\"@timestamp\":{\"type\":\"date\"},\"forwarded_at\":{\"type\":\"date\"},\"flow_start\":{\"type\":\"date\"},\"flow_end\":{\"type\":\"date\"},\"src_ip\":{\"type\":\"ip\"},\"dst_ip\":{\"type\":\"ip\"},\"src_port\":{\"type\":\"integer\"},\"dst_port\":{\"type\":\"integer\"},\"proto\":{\"type\":\"integer\"},\"protocol\":{\"type\":\"keyword\"},\"app_proto\":{\"type\":\"keyword\"},\"direction\":{\"type\":\"keyword\"},\"flow_id\":{\"type\":\"keyword\"},\"community_id\":{\"type\":\"keyword\"},\"initiator\":{\"type\":\"keyword\"},\"flow_end_reason\":{\"type\":\"keyword\"},\"tcp_state\":{\"type\":\"keyword\"},\"tcp_flags_ts\":{\"type\":\"keyword\"},\"tcp_flags_tc\":{\"type\":\"keyword\"},\"pkts_toserver\":{\"type\":\"long\"},\"pkts_toclient\":{\"type\":\"long\"},\"bytes_toserver\":{\"type\":\"long\"},\"bytes_toclient\":{\"type\":\"long\"},\"flow_duration_sec\":{\"type\":\"float\"},\"tos\":{\"type\":\"integer\"},\"dscp\":{\"type\":\"integer\"},\"src_geo\":{\"type\":\"object\",\"properties\":{\"country\":{\"type\":\"keyword\"},\"country_name\":{\"type\":\"keyword\"},\"lat\":{\"type\":\"float\"},\"lon\":{\"type\":\"float\"},\"asn\":{\"type\":\"long\"},\"asn_org\":{\"type\":\"keyword\"}}},\"dst_geo\":{\"type\":\"object\",\"properties\":{\"country\":{\"type\":\"keyword\"},\"country_name\":{\"type\":\"keyword\"},\"lat\":{\"type\":\"float\"},\"lon\":{\"type\":\"float\"},\"asn\":{\"type\":\"long\"},\"asn_org\":{\"type\":\"keyword\"}}},\"log_type\":{\"type\":\"keyword\"},\"source_file\":{\"type\":\"keyword\"}}}}}" >nul 2>&1
echo   Done.

echo.
echo Creating Kibana data views...

REM Wait for Kibana
:wait_kibana
curl -s -o nul -w "%%%%{http_code}" http://127.0.0.1:5601/api/status > %TEMP%\kb_status.txt 2>nul
set /p KB_STATUS=<%TEMP%\kb_status.txt
if "%KB_STATUS%" NEQ "200" (
    echo   Kibana not ready, retrying in 10s...
    timeout /t 10 /nobreak >nul
    goto wait_kibana
)
echo   Kibana is UP.

curl -s -X POST "http://127.0.0.1:5601/api/data_views/data_view" -H "kbn-xsrf: true" -H "Content-Type: application/json" -d "{\"data_view\":{\"title\":\"firewall-*\",\"name\":\"Firewall\",\"timeFieldName\":\"ts\"}}" >nul 2>&1
echo   Created: Firewall
curl -s -X POST "http://127.0.0.1:5601/api/data_views/data_view" -H "kbn-xsrf: true" -H "Content-Type: application/json" -d "{\"data_view\":{\"title\":\"ids-*\",\"name\":\"IDS/IPS\",\"timeFieldName\":\"timestamp\"}}" >nul 2>&1
echo   Created: IDS/IPS
curl -s -X POST "http://127.0.0.1:5601/api/data_views/data_view" -H "kbn-xsrf: true" -H "Content-Type: application/json" -d "{\"data_view\":{\"title\":\"east-west-*\",\"name\":\"East-West\",\"timeFieldName\":\"timestamp\"}}" >nul 2>&1
echo   Created: East-West
curl -s -X POST "http://127.0.0.1:5601/api/data_views/data_view" -H "kbn-xsrf: true" -H "Content-Type: application/json" -d "{\"data_view\":{\"title\":\"north-south-*\",\"name\":\"North-South\",\"timeFieldName\":\"timestamp\"}}" >nul 2>&1
echo   Created: North-South

echo.
echo ============================================
echo   Setup Complete!
echo ============================================
echo.
echo   4 index templates created in Elasticsearch
echo   4 data views created in Kibana
echo.
echo   You only need to run this ONCE.
echo   After this, just use start-all.bat
echo ============================================
pause
"@ | Out-File "$scriptsDir\0-setup-elasticsearch-templates.bat" -Encoding ASCII

    # 1 - Start Elasticsearch
    @"
@echo off
>nul 2>&1 "%SYSTEMROOT%\system32\cacls.exe" "%SYSTEMROOT%\system32\config\system"
if '%errorlevel%' NEQ '0' (powershell -Command "Start-Process '%~f0' -Verb RunAs" & exit /b)
title Elasticsearch
echo Starting Elasticsearch service...
net start elasticsearch-service-x64
echo Elasticsearch: http://localhost:9200
pause
"@ | Out-File "$scriptsDir\1-start-elasticsearch.bat" -Encoding ASCII

    # 2 - Start Kibana
    @"
@echo off
>nul 2>&1 "%SYSTEMROOT%\system32\cacls.exe" "%SYSTEMROOT%\system32\config\system"
if '%errorlevel%' NEQ '0' (powershell -Command "Start-Process '%~f0' -Verb RunAs" & exit /b)
title Kibana
cd /d "$kibanaDir\bin"
echo Starting Kibana... Access: http://localhost:5601
echo (First start takes ~5 minutes for initialization)
kibana.bat
"@ | Out-File "$scriptsDir\2-start-kibana.bat" -Encoding ASCII

    # 3 - Start SIEM Forwarder
    @"
@echo off
title SafeOps SIEM Forwarder
echo Starting SIEM Forwarder...
echo Tailing SafeOps logs and shipping to Elasticsearch
echo.
cd /d "$SAFEOPS_ROOT\bin\siem-forwarder"
siem-forwarder.exe
"@ | Out-File "$scriptsDir\3-start-siem-forwarder.bat" -Encoding ASCII

    # Start All
    @"
@echo off
>nul 2>&1 "%SYSTEMROOT%\system32\cacls.exe" "%SYSTEMROOT%\system32\config\system"
if '%errorlevel%' NEQ '0' (powershell -Command "Start-Process '%~f0' -Verb RunAs" & exit /b)
echo ============================================
echo   SafeOps SIEM Stack - Starting All
echo ============================================
echo.
echo [1/3] Starting Elasticsearch service...
net start elasticsearch-service-x64 2>nul
if %errorlevel% equ 0 (echo   Started.) else (echo   Already running.)
echo.
echo [2/3] Starting Kibana...
start "Kibana" cmd /c "cd /d $kibanaDir\bin && kibana.bat"
echo   Launching in new window (takes ~60s to initialize)
echo.
echo [3/3] Starting SIEM Forwarder...
start "SafeOps SIEM Forwarder" cmd /c "cd /d $SAFEOPS_ROOT\bin\siem-forwarder && siem-forwarder.exe"
echo   Launching in new window (waits for ES automatically)
echo.
echo ============================================
echo   All components launched!
echo ============================================
echo.
echo   Elasticsearch : http://localhost:9200
echo   Kibana        : http://localhost:5601  (wait ~60s)
echo   SIEM Forwarder: tailing logs to ES
echo.
echo   First time? Run 0-setup-elasticsearch-templates.bat
echo ============================================
pause
"@ | Out-File "$scriptsDir\start-all.bat" -Encoding ASCII

    # Stop All
    @"
@echo off
>nul 2>&1 "%SYSTEMROOT%\system32\cacls.exe" "%SYSTEMROOT%\system32\config\system"
if '%errorlevel%' NEQ '0' (powershell -Command "Start-Process '%~f0' -Verb RunAs" & exit /b)
echo ============================================
echo   SafeOps SIEM Stack - Stopping All
echo ============================================
echo.
echo [1/3] Stopping SIEM Forwarder...
taskkill /FI "WINDOWTITLE eq SafeOps SIEM Forwarder*" /F 2>nul
taskkill /IM "siem-forwarder.exe" /F 2>nul
echo   Done.
echo.
echo [2/3] Stopping Kibana...
taskkill /FI "WINDOWTITLE eq Kibana*" /F 2>nul
taskkill /IM "node.exe" /F 2>nul
echo   Done.
echo.
echo [3/3] Stopping Elasticsearch...
net stop elasticsearch-service-x64 2>nul
echo   Done.
echo.
echo ============================================
echo   SIEM Stack stopped.
echo ============================================
pause
"@ | Out-File "$scriptsDir\stop-all.bat" -Encoding ASCII

    Write-OK "Start scripts created (0-setup, 1-es, 2-kibana, 3-forwarder, start-all, stop-all)"
}

# ============== MAIN ==============

Write-Host ""
Write-Host "============================================" -ForegroundColor Cyan
Write-Host "  SafeOps SIEM - ES + Kibana Installer" -ForegroundColor Cyan
Write-Host "  Version: $ELK_VERSION" -ForegroundColor Cyan
Write-Host "  (Logstash replaced by SIEM Forwarder)" -ForegroundColor Cyan
Write-Host "============================================" -ForegroundColor Cyan

# Create directories
Write-Step "Creating directories..."
$dirs = @(
    $INSTALL_DIR, "$INSTALL_DIR\temp", "$INSTALL_DIR\data",
    "$INSTALL_DIR\data\elasticsearch", "$INSTALL_DIR\logs",
    "$INSTALL_DIR\logs\elasticsearch", "$INSTALL_DIR\elasticsearch",
    "$INSTALL_DIR\kibana", "$INSTALL_DIR\scripts"
)
foreach ($dir in $dirs) { New-Item -Path $dir -ItemType Directory -Force | Out-Null }
Write-OK "Directories created"

# Download (no Logstash)
if (-not $SkipDownload) {
    Write-Step "Downloading ES + Kibana (~700 MB total)..."
    Get-Component "Elasticsearch" $ES_URL "$INSTALL_DIR\temp\elasticsearch.zip"
    Get-Component "Kibana" $KIBANA_URL "$INSTALL_DIR\temp\kibana.zip"
}

# Extract
Write-Step "Extracting components..."
Expand-Component "elasticsearch" "$INSTALL_DIR\temp\elasticsearch.zip" "$INSTALL_DIR\elasticsearch"
Expand-Component "kibana" "$INSTALL_DIR\temp\kibana.zip" "$INSTALL_DIR\kibana"

# Configure
Write-Step "Configuring components..."
Set-ElasticsearchConfig
Set-KibanaConfig

# Install Elasticsearch service
Write-Step "Installing Elasticsearch Windows service..."
Install-ElasticsearchService

# Create start scripts
Write-Step "Creating start scripts..."
New-StartScripts

# Summary
Write-Host ""
Write-Host "============================================" -ForegroundColor Green
Write-Host "  Installation Complete!" -ForegroundColor Green
Write-Host "============================================" -ForegroundColor Green
Write-Host ""
Write-Host "  First-time setup:" -ForegroundColor White
Write-Host "    1. Run start-all.bat (starts ES + Kibana + Forwarder)" -ForegroundColor Cyan
Write-Host "    2. Run 0-setup-elasticsearch-templates.bat" -ForegroundColor Cyan
Write-Host "       (creates index templates and Kibana data views)" -ForegroundColor Cyan
Write-Host ""
Write-Host "  Daily use:" -ForegroundColor White
Write-Host "    start-all.bat   - Start everything" -ForegroundColor Cyan
Write-Host "    stop-all.bat    - Stop everything" -ForegroundColor Cyan
Write-Host ""
Write-Host "  Access URLs:" -ForegroundColor White
Write-Host "    Elasticsearch: http://localhost:9200" -ForegroundColor Cyan
Write-Host "    Kibana:        http://localhost:5601" -ForegroundColor Cyan
Write-Host ""
Write-Host "  Index names in Kibana:" -ForegroundColor White
Write-Host "    firewall-*     - Firewall verdicts" -ForegroundColor Cyan
Write-Host "    ids-*          - IDS/IPS events (DNS, HTTP, TLS)" -ForegroundColor Cyan
Write-Host "    east-west-*    - Internal LAN flow logs" -ForegroundColor Cyan
Write-Host "    north-south-*  - External WAN flow logs" -ForegroundColor Cyan
Write-Host ""
Write-Host "  No login required (security disabled for local dev)" -ForegroundColor Yellow
Write-Host ""

Read-Host "Press Enter to exit"
