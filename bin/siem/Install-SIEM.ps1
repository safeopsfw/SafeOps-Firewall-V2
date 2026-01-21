# SafeOps SIEM - ELK Stack Installer
# Downloads, Extracts, and Configures Elasticsearch, Kibana, Logstash
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
$LOGSTASH_URL = "https://artifacts.elastic.co/downloads/logstash/logstash-$ELK_VERSION-windows-x86_64.zip"

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
discovery.type: single-node
"@
    
    $config | Out-File "$($esDir.FullName)\config\elasticsearch.yml" -Encoding UTF8 -Force
    Write-OK "Elasticsearch configured (security disabled for local dev)"
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
logging.dest: stdout
xpack.encryptedSavedObjects.encryptionKey: "safeops2026encryptionkey123456789"
xpack.reporting.encryptionKey: "safeops2026reportingkey1234567890"
xpack.security.encryptionKey: "safeops2026securitykey12345678901"
"@
    
    $config | Out-File "$($kibanaDir.FullName)\config\kibana.yml" -Encoding UTF8 -Force
    Write-OK "Kibana configured"
}

function Set-LogstashConfig {
    $logstashDir = Get-ChildItem "$INSTALL_DIR\logstash" -Directory | 
    Where-Object { $_.Name -like "logstash-*" } | Select-Object -First 1
    
    $config = @"
input {
  file {
    path => "$SAFEOPS_ROOT/bin/logs/netflow/*.log"
    start_position => "beginning"
    codec => "json"
    tags => ["safeops", "netflow"]
  }
  file {
    path => "$SAFEOPS_ROOT/bin/logs/engine.log"
    start_position => "beginning"
    codec => "json"
    tags => ["safeops", "engine"]
  }
}

filter {
  if "safeops" in [tags] {
    mutate { add_field => { "[@metadata][index]" => "safeops-logs" } }
  }
}

output {
  elasticsearch {
    hosts => ["http://127.0.0.1:9200"]
    index => "safeops-logs-%{+YYYY.MM.dd}"
  }
}
"@
    
    $config | Out-File "$($logstashDir.FullName)\config\logstash.conf" -Encoding UTF8 -Force
    Write-OK "Logstash configured"
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
    
    $null = (Get-ChildItem "$INSTALL_DIR\elasticsearch" -Directory | Where-Object { $_.Name -like "elasticsearch-*" } | Select-Object -First 1).FullName
    $kibanaDir = (Get-ChildItem "$INSTALL_DIR\kibana" -Directory | Where-Object { $_.Name -like "kibana-*" } | Select-Object -First 1).FullName
    $logstashDir = (Get-ChildItem "$INSTALL_DIR\logstash" -Directory | Where-Object { $_.Name -like "logstash-*" } | Select-Object -First 1).FullName

    # Elasticsearch script
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

    # Kibana script
    @"
@echo off
>nul 2>&1 "%SYSTEMROOT%\system32\cacls.exe" "%SYSTEMROOT%\system32\config\system"
if '%errorlevel%' NEQ '0' (powershell -Command "Start-Process '%~f0' -Verb RunAs" & exit /b)
title Kibana
cd /d "$kibanaDir\bin"
echo Starting Kibana... Access: http://localhost:5601
kibana.bat
"@ | Out-File "$scriptsDir\2-start-kibana.bat" -Encoding ASCII

    # Logstash script
    @"
@echo off
>nul 2>&1 "%SYSTEMROOT%\system32\cacls.exe" "%SYSTEMROOT%\system32\config\system"
if '%errorlevel%' NEQ '0' (powershell -Command "Start-Process '%~f0' -Verb RunAs" & exit /b)
title Logstash
cd /d "$logstashDir\bin"
echo Starting Logstash...
logstash.bat -f "$logstashDir\config\logstash.conf"
"@ | Out-File "$scriptsDir\3-start-logstash.bat" -Encoding ASCII

    # Start All script
    @"
@echo off
>nul 2>&1 "%SYSTEMROOT%\system32\cacls.exe" "%SYSTEMROOT%\system32\config\system"
if '%errorlevel%' NEQ '0' (powershell -Command "Start-Process '%~f0' -Verb RunAs" & exit /b)
echo Starting SafeOps ELK Stack...
start "" "$scriptsDir\1-start-elasticsearch.bat"
start "" "$scriptsDir\2-start-kibana.bat"
start "" "$scriptsDir\3-start-logstash.bat"
echo All components launching!
echo   Elasticsearch: http://localhost:9200
echo   Kibana: http://localhost:5601
"@ | Out-File "$scriptsDir\start-all.bat" -Encoding ASCII

    # Stop All script
    @"
@echo off
>nul 2>&1 "%SYSTEMROOT%\system32\cacls.exe" "%SYSTEMROOT%\system32\config\system"
if '%errorlevel%' NEQ '0' (powershell -Command "Start-Process '%~f0' -Verb RunAs" & exit /b)
echo Stopping SafeOps ELK Stack...
net stop elasticsearch-service-x64 2>nul
taskkill /FI "WINDOWTITLE eq Kibana*" /F 2>nul
taskkill /FI "WINDOWTITLE eq Logstash*" /F 2>nul
echo ELK Stack stopped.
pause
"@ | Out-File "$scriptsDir\stop-all.bat" -Encoding ASCII

    Write-OK "Start scripts created (numbered for run order)"
}

# ============== MAIN ==============

Write-Host ""
Write-Host "============================================" -ForegroundColor Cyan
Write-Host "  SafeOps SIEM - ELK Stack Installer" -ForegroundColor Cyan
Write-Host "  Version: $ELK_VERSION" -ForegroundColor Cyan
Write-Host "============================================" -ForegroundColor Cyan

# Create directories
Write-Step "Creating directories..."
$dirs = @(
    $INSTALL_DIR, "$INSTALL_DIR\temp", "$INSTALL_DIR\data", 
    "$INSTALL_DIR\data\elasticsearch", "$INSTALL_DIR\logs",
    "$INSTALL_DIR\logs\elasticsearch", "$INSTALL_DIR\elasticsearch",
    "$INSTALL_DIR\kibana", "$INSTALL_DIR\logstash", "$INSTALL_DIR\scripts"
)
foreach ($dir in $dirs) { New-Item -Path $dir -ItemType Directory -Force | Out-Null }
Write-OK "Directories created"

# Download
if (-not $SkipDownload) {
    Write-Step "Downloading ELK Stack (~1.1 GB total)..."
    Get-Component "Elasticsearch" $ES_URL "$INSTALL_DIR\temp\elasticsearch.zip"
    Get-Component "Kibana" $KIBANA_URL "$INSTALL_DIR\temp\kibana.zip"
    Get-Component "Logstash" $LOGSTASH_URL "$INSTALL_DIR\temp\logstash.zip"
}

# Extract
Write-Step "Extracting components..."
Expand-Component "elasticsearch" "$INSTALL_DIR\temp\elasticsearch.zip" "$INSTALL_DIR\elasticsearch"
Expand-Component "kibana" "$INSTALL_DIR\temp\kibana.zip" "$INSTALL_DIR\kibana"
Expand-Component "logstash" "$INSTALL_DIR\temp\logstash.zip" "$INSTALL_DIR\logstash"

# Configure
Write-Step "Configuring components..."
Set-ElasticsearchConfig
Set-KibanaConfig
Set-LogstashConfig

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
Write-Host "  Scripts (run in order):" -ForegroundColor White
Write-Host "    1-start-elasticsearch.bat" -ForegroundColor Cyan
Write-Host "    2-start-kibana.bat" -ForegroundColor Cyan
Write-Host "    3-start-logstash.bat" -ForegroundColor Cyan
Write-Host ""
Write-Host "  Or run: start-all.bat" -ForegroundColor White
Write-Host ""
Write-Host "  Access URLs:" -ForegroundColor White
Write-Host "    Elasticsearch: http://localhost:9200" -ForegroundColor Cyan
Write-Host "    Kibana: http://localhost:5601" -ForegroundColor Cyan
Write-Host ""
Write-Host "  No login required (security disabled for local dev)" -ForegroundColor Yellow
Write-Host ""

Read-Host "Press Enter to exit"
