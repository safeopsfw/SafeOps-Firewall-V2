#!/usr/bin/env python3
"""
SafeOps SIEM - ELK Stack Installer
===================================
This script downloads, installs, and configures the ELK stack (Elasticsearch, Logstash, Kibana)
for use with SafeOps Network Security Platform.

Default Credentials:
    Username: safeops_admin
    Password: SafeOps@SIEM2026!

Port Configuration (non-conflicting with SafeOps):
    Elasticsearch: 9200 (default)
    Kibana: 5601 (default)
    Logstash: 5044 (Beats input)
    
Run as Administrator!
"""

import os
import sys
import subprocess
import urllib.request
import zipfile
import shutil
import json
import time
import socket
from pathlib import Path

# ============================================================================
# CONFIGURATION - MODIFY THESE AS NEEDED
# ============================================================================

CONFIG = {
    # Default credentials
    "username": "safeops_admin",
    "password": "SafeOps@SIEM2026!",
    
    # ELK Version
    "elk_version": "8.17.0",
    
    # Installation directory
    "install_dir": "D:/SafeOpsFV2/bin/elk",
    
    # Port configuration (avoiding SafeOps conflicts: 8080, 9000, 9002)
    "elasticsearch_port": 9200,
    "kibana_port": 5601,
    "logstash_beats_port": 5044,
    
    # Memory settings (adjust based on system RAM)
    "elasticsearch_heap": "1g",  # Elasticsearch JVM heap
    
    # SafeOps log paths to ingest
    "safeops_logs": [
        "D:/SafeOpsFV2/logs/network_packets_master.jsonl",
        "D:/SafeOpsFV2/logs/ids.log",
        "D:/SafeOpsFV2/logs/firewall.log",
        "D:/SafeOpsFV2/logs/devices.jsonl",
    ],
}

# Download URLs
DOWNLOAD_URLS = {
    "elasticsearch": f"https://artifacts.elastic.co/downloads/elasticsearch/elasticsearch-{CONFIG['elk_version']}-windows-x86_64.zip",
    "kibana": f"https://artifacts.elastic.co/downloads/kibana/kibana-{CONFIG['elk_version']}-windows-x86_64.zip",
    "logstash": f"https://artifacts.elastic.co/downloads/logstash/logstash-{CONFIG['elk_version']}-windows-x86_64.zip",
}


def print_banner():
    """Print SafeOps SIEM banner."""
    banner = """
╔══════════════════════════════════════════════════════════════════╗
║                 SafeOps SIEM - ELK Stack Installer               ║
║                                                                  ║
║  Elasticsearch + Logstash + Kibana                               ║
║  Integrated with SafeOps Network Security Platform               ║
╚══════════════════════════════════════════════════════════════════╝
    """
    print(banner)
    print(f"  ELK Version: {CONFIG['elk_version']}")
    print(f"  Install Dir: {CONFIG['install_dir']}")
    print(f"  Default User: {CONFIG['username']}")
    print(f"  Default Pass: {CONFIG['password']}")
    print()


def check_admin():
    """Check if running as administrator."""
    try:
        import ctypes
        return ctypes.windll.shell32.IsUserAnAdmin()
    except:
        return False


def check_port_available(port):
    """Check if a port is available."""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        try:
            s.bind(("127.0.0.1", port))
            return True
        except OSError:
            return False


def download_file(url, dest_path, desc=""):
    """Download a file with progress indicator."""
    print(f"📥 Downloading {desc}...")
    print(f"   URL: {url}")
    
    try:
        # Get file size
        with urllib.request.urlopen(url) as response:
            total_size = int(response.headers.get('Content-Length', 0))
            
            # Download with progress
            block_size = 1024 * 1024  # 1MB blocks
            downloaded = 0
            
            with open(dest_path, 'wb') as f:
                while True:
                    buffer = response.read(block_size)
                    if not buffer:
                        break
                    f.write(buffer)
                    downloaded += len(buffer)
                    
                    if total_size > 0:
                        percent = (downloaded / total_size) * 100
                        mb_downloaded = downloaded / (1024 * 1024)
                        mb_total = total_size / (1024 * 1024)
                        print(f"\r   Progress: {percent:.1f}% ({mb_downloaded:.1f}/{mb_total:.1f} MB)", end="", flush=True)
            
            print()  # New line after progress
        
        print(f"   ✅ Downloaded: {dest_path}")
        return True
        
    except Exception as e:
        print(f"   ❌ Download failed: {e}")
        return False


def extract_zip(zip_path, extract_to, desc=""):
    """Extract a zip file."""
    print(f"📦 Extracting {desc}...")
    try:
        with zipfile.ZipFile(zip_path, 'r') as zip_ref:
            zip_ref.extractall(extract_to)
        print(f"   ✅ Extracted to: {extract_to}")
        return True
    except Exception as e:
        print(f"   ❌ Extraction failed: {e}")
        return False


def configure_elasticsearch():
    """Configure Elasticsearch."""
    print("\n🔧 Configuring Elasticsearch...")
    
    es_dir = Path(CONFIG['install_dir']) / f"elasticsearch-{CONFIG['elk_version']}"
    config_file = es_dir / "config" / "elasticsearch.yml"
    
    config_content = f"""# SafeOps SIEM - Elasticsearch Configuration
# Generated by SafeOps ELK Installer

cluster.name: safeops-siem
node.name: safeops-node-1

# Network
network.host: 127.0.0.1
http.port: {CONFIG['elasticsearch_port']}

# Security (using basic auth)
xpack.security.enabled: true
xpack.security.enrollment.enabled: true

# Disable HTTPS for local development (enable in production)
xpack.security.http.ssl.enabled: false
xpack.security.transport.ssl.enabled: false

# Memory
indices.memory.index_buffer_size: 20%

# Paths
path.data: {CONFIG['install_dir']}/data/elasticsearch
path.logs: {CONFIG['install_dir']}/logs/elasticsearch

# Disable machine learning (saves memory)
xpack.ml.enabled: false
"""
    
    # Create directories
    (Path(CONFIG['install_dir']) / "data" / "elasticsearch").mkdir(parents=True, exist_ok=True)
    (Path(CONFIG['install_dir']) / "logs" / "elasticsearch").mkdir(parents=True, exist_ok=True)
    
    with open(config_file, 'w') as f:
        f.write(config_content)
    
    # Configure JVM heap
    jvm_options = es_dir / "config" / "jvm.options.d" / "safeops.options"
    jvm_options.parent.mkdir(parents=True, exist_ok=True)
    
    with open(jvm_options, 'w') as f:
        f.write(f"-Xms{CONFIG['elasticsearch_heap']}\n")
        f.write(f"-Xmx{CONFIG['elasticsearch_heap']}\n")
    
    print(f"   ✅ Elasticsearch configured (port {CONFIG['elasticsearch_port']})")


def configure_kibana():
    """Configure Kibana."""
    print("\n🔧 Configuring Kibana...")
    
    kibana_dir = Path(CONFIG['install_dir']) / f"kibana-{CONFIG['elk_version']}"
    config_file = kibana_dir / "config" / "kibana.yml"
    
    config_content = f"""# SafeOps SIEM - Kibana Configuration
# Generated by SafeOps ELK Installer

server.port: {CONFIG['kibana_port']}
server.host: "127.0.0.1"
server.name: "SafeOps SIEM"

# Elasticsearch connection
elasticsearch.hosts: ["http://127.0.0.1:{CONFIG['elasticsearch_port']}"]
elasticsearch.username: "{CONFIG['username']}"
elasticsearch.password: "{CONFIG['password']}"

# Paths
logging.dest: {CONFIG['install_dir']}/logs/kibana/kibana.log
pid.file: {CONFIG['install_dir']}/logs/kibana/kibana.pid

# UI Settings
server.publicBaseUrl: "http://localhost:{CONFIG['kibana_port']}"
"""
    
    # Create directories
    (Path(CONFIG['install_dir']) / "logs" / "kibana").mkdir(parents=True, exist_ok=True)
    
    with open(config_file, 'w') as f:
        f.write(config_content)
    
    print(f"   ✅ Kibana configured (port {CONFIG['kibana_port']})")


def configure_logstash():
    """Configure Logstash for SafeOps logs."""
    print("\n🔧 Configuring Logstash...")
    
    logstash_dir = Path(CONFIG['install_dir']) / f"logstash-{CONFIG['elk_version']}"
    config_dir = logstash_dir / "config" / "conf.d"
    config_dir.mkdir(parents=True, exist_ok=True)
    
    # Create directories
    (Path(CONFIG['install_dir']) / "logs" / "logstash").mkdir(parents=True, exist_ok=True)
    
    # SafeOps log pipeline
    safeops_pipeline = f"""# SafeOps Network Logs Pipeline
# Ingests logs from SafeOps Network Logger

input {{
    # Network packets master log (JSONL)
    file {{
        path => "D:/SafeOpsFV2/logs/network_packets_master.jsonl"
        start_position => "beginning"
        sincedb_path => "{CONFIG['install_dir']}/data/logstash/sincedb_master"
        codec => json
        type => "network_packets"
    }}
    
    # IDS log
    file {{
        path => "D:/SafeOpsFV2/logs/ids.log"
        start_position => "beginning"
        sincedb_path => "{CONFIG['install_dir']}/data/logstash/sincedb_ids"
        codec => json
        type => "ids_alerts"
    }}
    
    # Firewall log
    file {{
        path => "D:/SafeOpsFV2/logs/firewall.log"
        start_position => "beginning"
        sincedb_path => "{CONFIG['install_dir']}/data/logstash/sincedb_firewall"
        codec => json
        type => "firewall"
    }}
    
    # Device inventory
    file {{
        path => "D:/SafeOpsFV2/logs/devices.jsonl"
        start_position => "beginning"
        sincedb_path => "{CONFIG['install_dir']}/data/logstash/sincedb_devices"
        codec => json
        type => "devices"
    }}
}}

filter {{
    # Add common fields
    mutate {{
        add_field => {{ "[@metadata][index_prefix]" => "safeops" }}
    }}
    
    # Parse timestamps if present
    if [timestamp] {{
        date {{
            match => [ "timestamp", "ISO8601" ]
            target => "@timestamp"
        }}
    }}
    
    # Enrich with SafeOps metadata
    mutate {{
        add_field => {{ 
            "[safeops][platform]" => "SafeOps FV2"
            "[safeops][version]" => "2.0.0"
        }}
    }}
}}

output {{
    elasticsearch {{
        hosts => ["http://127.0.0.1:{CONFIG['elasticsearch_port']}"]
        user => "{CONFIG['username']}"
        password => "{CONFIG['password']}"
        index => "safeops-%{{type}}-%{{+YYYY.MM.dd}}"
    }}
    
    # Debug output (comment out in production)
    # stdout {{ codec => rubydebug }}
}}
"""
    
    with open(config_dir / "safeops.conf", 'w') as f:
        f.write(safeops_pipeline)
    
    # Create sincedb directory
    (Path(CONFIG['install_dir']) / "data" / "logstash").mkdir(parents=True, exist_ok=True)
    
    print(f"   ✅ Logstash configured (Beats port {CONFIG['logstash_beats_port']})")


def create_startup_scripts():
    """Create startup and stop scripts."""
    print("\n📝 Creating startup scripts...")
    
    scripts_dir = Path(CONFIG['install_dir'])
    
    # Start all script
    start_all = f"""@echo off
echo Starting SafeOps SIEM (ELK Stack)...
echo =====================================

echo Starting Elasticsearch...
start "Elasticsearch" /D "{CONFIG['install_dir']}\\elasticsearch-{CONFIG['elk_version']}\\bin" elasticsearch.bat

echo Waiting for Elasticsearch to start (30 seconds)...
timeout /t 30 /nobreak

echo Starting Kibana...
start "Kibana" /D "{CONFIG['install_dir']}\\kibana-{CONFIG['elk_version']}\\bin" kibana.bat

echo Waiting for Kibana to start (15 seconds)...
timeout /t 15 /nobreak

echo Starting Logstash...
start "Logstash" /D "{CONFIG['install_dir']}\\logstash-{CONFIG['elk_version']}\\bin" logstash.bat -f "{CONFIG['install_dir']}\\logstash-{CONFIG['elk_version']}\\config\\conf.d\\safeops.conf"

echo.
echo =====================================
echo SafeOps SIEM Started!
echo.
echo   Elasticsearch: http://localhost:{CONFIG['elasticsearch_port']}
echo   Kibana:        http://localhost:{CONFIG['kibana_port']}
echo.
echo   Username: {CONFIG['username']}
echo   Password: {CONFIG['password']}
echo =====================================
"""
    
    with open(scripts_dir / "start-siem.bat", 'w') as f:
        f.write(start_all)
    
    # Stop all script
    stop_all = """@echo off
echo Stopping SafeOps SIEM (ELK Stack)...

taskkill /FI "WINDOWTITLE eq Elasticsearch*" /F 2>nul
taskkill /FI "WINDOWTITLE eq Kibana*" /F 2>nul
taskkill /FI "WINDOWTITLE eq Logstash*" /F 2>nul

echo SafeOps SIEM stopped.
"""
    
    with open(scripts_dir / "stop-siem.bat", 'w') as f:
        f.write(stop_all)
    
    print(f"   ✅ Created: start-siem.bat")
    print(f"   ✅ Created: stop-siem.bat")


def setup_elasticsearch_user():
    """Set up Elasticsearch user with password."""
    print("\n🔐 Setting up Elasticsearch security...")
    
    es_dir = Path(CONFIG['install_dir']) / f"elasticsearch-{CONFIG['elk_version']}"
    
    # Create a setup script for first-time initialization
    setup_script = f"""@echo off
echo Setting up Elasticsearch security...
echo.
echo This will:
echo   1. Start Elasticsearch
echo   2. Set the password for elastic user
echo   3. Create safeops_admin user
echo.
echo Please wait...

cd /d "{es_dir}\\bin"

echo Starting Elasticsearch for initial setup...
start /B elasticsearch.bat
timeout /t 60 /nobreak

echo Setting elastic user password...
elasticsearch-reset-password -u elastic -i -b

echo Creating safeops_admin user...
elasticsearch-users useradd {CONFIG['username']} -p {CONFIG['password']} -r superuser

echo.
echo ===================================
echo Security setup complete!
echo.
echo   Username: {CONFIG['username']}
echo   Password: {CONFIG['password']}
echo ===================================
echo.
echo You can now close this window and run start-siem.bat
pause
"""
    
    with open(Path(CONFIG['install_dir']) / "setup-security.bat", 'w') as f:
        f.write(setup_script)
    
    print(f"   ✅ Created: setup-security.bat")
    print(f"   ⚠️  Run setup-security.bat after installation to configure authentication")


def install_elk():
    """Main installation function."""
    print_banner()
    
    # Check admin
    if not check_admin():
        print("⚠️  Warning: Not running as administrator. Some features may not work.")
        print("   Consider running this script as Administrator.")
        print()
    
    # Check ports
    print("🔍 Checking port availability...")
    ports = [
        (CONFIG['elasticsearch_port'], "Elasticsearch"),
        (CONFIG['kibana_port'], "Kibana"),
    ]
    
    for port, name in ports:
        if check_port_available(port):
            print(f"   ✅ Port {port} ({name}) is available")
        else:
            print(f"   ⚠️  Port {port} ({name}) is in use - may conflict!")
    
    # Create install directory
    install_path = Path(CONFIG['install_dir'])
    install_path.mkdir(parents=True, exist_ok=True)
    print(f"\n📁 Install directory: {install_path}")
    
    # Download and extract each component
    temp_dir = install_path / "temp"
    temp_dir.mkdir(exist_ok=True)
    
    for component, url in DOWNLOAD_URLS.items():
        zip_name = f"{component}-{CONFIG['elk_version']}.zip"
        zip_path = temp_dir / zip_name
        
        # Check if already downloaded
        component_dir = install_path / f"{component}-{CONFIG['elk_version']}"
        if component_dir.exists():
            print(f"\n✅ {component.title()} already installed, skipping download...")
            continue
        
        # Download
        if not zip_path.exists():
            if not download_file(url, zip_path, component.title()):
                print(f"❌ Failed to download {component}. Aborting.")
                return False
        
        # Extract
        if not extract_zip(zip_path, install_path, component.title()):
            print(f"❌ Failed to extract {component}. Aborting.")
            return False
    
    # Configure components
    configure_elasticsearch()
    configure_kibana()
    configure_logstash()
    
    # Create scripts
    create_startup_scripts()
    setup_elasticsearch_user()
    
    # Cleanup temp
    print("\n🧹 Cleaning up temporary files...")
    shutil.rmtree(temp_dir, ignore_errors=True)
    
    # Print completion message
    print("\n" + "=" * 60)
    print("✅ SafeOps SIEM (ELK Stack) Installation Complete!")
    print("=" * 60)
    print(f"""
Next Steps:
-----------
1. Run 'setup-security.bat' to configure authentication
2. Run 'start-siem.bat' to start all services
3. Access Kibana at: http://localhost:{CONFIG['kibana_port']}

Credentials:
   Username: {CONFIG['username']}
   Password: {CONFIG['password']}

Port Summary:
   Elasticsearch: {CONFIG['elasticsearch_port']}
   Kibana:        {CONFIG['kibana_port']}
   Logstash:      {CONFIG['logstash_beats_port']}

Log paths being monitored:
""")
    for log in CONFIG['safeops_logs']:
        print(f"   - {log}")
    
    print("\n" + "=" * 60)
    return True


def uninstall_elk():
    """Uninstall ELK stack."""
    print("🗑️  Uninstalling SafeOps SIEM...")
    
    install_path = Path(CONFIG['install_dir'])
    
    if not install_path.exists():
        print("   Nothing to uninstall.")
        return
    
    # Stop services first
    print("   Stopping services...")
    os.system("taskkill /FI \"WINDOWTITLE eq Elasticsearch*\" /F 2>nul")
    os.system("taskkill /FI \"WINDOWTITLE eq Kibana*\" /F 2>nul")
    os.system("taskkill /FI \"WINDOWTITLE eq Logstash*\" /F 2>nul")
    time.sleep(2)
    
    # Remove installation
    print(f"   Removing {install_path}...")
    shutil.rmtree(install_path, ignore_errors=True)
    
    print("   ✅ Uninstallation complete.")


if __name__ == "__main__":
    if len(sys.argv) > 1 and sys.argv[1] == "--uninstall":
        uninstall_elk()
    else:
        install_elk()
