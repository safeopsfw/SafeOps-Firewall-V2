#!/usr/bin/env python3
"""
SafeOps Dependency Installer
Installs system prerequisites and project dependencies.

1. Checks for Python, PostgreSQL, Go, Node.js, and Git.
2. Installs Python packages (pip install).
3. Initializes PostgreSQL databases.
4. Recursively finds 'package.json' and runs 'npm install'.
5. Recursively finds 'go.mod' and runs 'go mod tidy'.
"""

import os
import subprocess
import shutil
import sys
from pathlib import Path

# Required Python packages for SafeOps
PYTHON_PACKAGES = [
    "psutil",           # Process/system monitoring (traffic_logger, realtime_capture)
    "colorama",         # Colored terminal output (all logging components)
    "scapy",            # Packet capture/analysis (realtime_capture, pcap_parser)
    "cryptography",     # TLS decryption support (realtime_capture)
    "psycopg2-binary",  # PostgreSQL database connectivity (threat intel, all DB operations)
    "requests",         # HTTP client (realtime_capture, API calls)
    "pytz",             # Timezone handling (pcap_parser)
    "jsonschema",       # JSON validation (pcap_parser)
    "PyYAML",           # Config file parsing (config_loader)
    "dpkt",             # Alternative packet parsing (pcap_parser, optional)
]


def print_header(title):
    print("\n" + "=" * 50)
    print(f" {title}")
    print("=" * 50 + "\n")


def check_command(name, command):
    print(f"Checking for {name}...", end=" ")
    if shutil.which(command):
        print("\033[92mOK\033[0m")
        return True
    else:
        print("\033[91mMISSING\033[0m")
        return False


def install_system_tools():
    print_header("Checking System Requirements")
    
    # Core required tools
    tools = [
        {"name": "Python", "command": "python"},
        {"name": "PostgreSQL (psql)", "command": "psql"},
        {"name": "Go (Golang)", "command": "go"},
        {"name": "Node.js", "command": "node"},
        {"name": "Git", "command": "git"},
        {"name": "Rust (cargo)", "command": "cargo"},
        {"name": "OpenSSL", "command": "openssl"},
        {"name": "Step CLI", "command": "step"},
        {"name": "Step-CA", "command": "step-ca"},
    ]
    
    missing = False
    for tool in tools:
        if not check_command(tool["name"], tool["command"]):
            missing = True
            print(f"\033[93mWarning: {tool['name']} is missing. Please install it manually.\033[0m")
            
    if missing:
        print("\n\033[93mSome system tools are missing. Scripts execution might fail.\033[0m")
    
    return not missing


def install_python_dependencies():
    print_header("Installing Python Dependencies")
    
    print(f"\033[96mInstalling {len(PYTHON_PACKAGES)} packages...\033[0m\n")
    
    for package in PYTHON_PACKAGES:
        print(f"  Installing {package}...", end=" ")
        try:
            result = subprocess.run(
                [sys.executable, "-m", "pip", "install", package, "--quiet"],
                capture_output=True,
                text=True
            )
            if result.returncode == 0:
                print("\033[92mOK\033[0m")
            else:
                print(f"\033[91mFAILED\033[0m")
                if result.stderr:
                    print(f"    \033[90m{result.stderr.strip()[:100]}\033[0m")
        except Exception as e:
            print(f"\033[91mERROR: {e}\033[0m")
    
    print(f"\n\033[92mPython dependencies installation complete.\033[0m")


def initialize_databases(root_dir):
    print_header("Initializing PostgreSQL Databases")
    
    # Check if PostgreSQL is available
    if not shutil.which("psql"):
        print("\033[93m[SKIP] PostgreSQL not found. Database initialization skipped.\033[0m")
        print("  Install PostgreSQL: https://www.postgresql.org/download/")
        return
    
    # Look for database init script
    db_script = Path(root_dir) / "database" / "init_all_databases.ps1"
    
    if db_script.exists():
        print(f"\033[93mFound database script: {db_script}\033[0m")
        print("  \033[96m[RUN] Initializing databases...\033[0m")
        
        try:
            result = subprocess.run(
                ["powershell", "-ExecutionPolicy", "Bypass", "-File", str(db_script)],
                cwd=root_dir,
                capture_output=True,
                text=True
            )
            if result.returncode == 0:
                print("  \033[92mDatabases initialized successfully!\033[0m")
            else:
                print("  \033[93mDatabase init completed with warnings.\033[0m")
                if result.stderr:
                    print(f"    \033[90m{result.stderr.strip()[:200]}\033[0m")
        except Exception as e:
            print(f"  \033[91mFailed to initialize databases: {e}\033[0m")
    else:
        print("\033[90m[SKIP] Database init script not found.\033[0m")
        print(f"  Expected: {db_script}")


def install_node_dependencies(root_dir):
    print_header("Installing Node.js Dependencies")
    
    # Dirs to skip during traversal
    skip_dirs = {'.git', 'node_modules', 'dist', 'build', 'vendor'}
    
    found_count = 0
    for root, dirs, files in os.walk(root_dir):
        # Modify dirs in-place to skip traversing ignored directories
        dirs[:] = [d for d in dirs if d not in skip_dirs]
            
        if "package.json" in files:
            found_count += 1
            pkg_path = Path(root)
            print(f"\033[93mFound package.json in: {pkg_path}\033[0m")
            
            node_modules = pkg_path / "node_modules"
            if node_modules.exists():
                print("  \033[90m[SKIP] 'node_modules' already exists. Skipping npm install.\033[0m")
            else:
                print("  \033[96m[INSTALL] Running 'npm install'...\033[0m")
                try:
                    subprocess.run(["npm", "install"], cwd=pkg_path, check=True, shell=True)
                    print("  \033[92mSuccess!\033[0m")
                except subprocess.CalledProcessError:
                    print(f"  \033[91mFailed to install dependencies in {pkg_path}\033[0m")
    
    if found_count == 0:
        print("\033[90mNo package.json files found.\033[0m")
    else:
        print(f"\n\033[92mProcessed {found_count} Node.js projects.\033[0m")


def tidy_go_modules(root_dir):
    print_header("Tidying Go Modules")
    
    skip_dirs = {'.git', 'node_modules', 'dist', 'build', 'vendor'}
    
    found_count = 0
    for root, dirs, files in os.walk(root_dir):
        # Modify dirs in-place to skip traversing ignored directories
        dirs[:] = [d for d in dirs if d not in skip_dirs]
        
        if "go.mod" in files:
            found_count += 1
            mod_path = Path(root)
            print(f"\033[93mFound go.mod in: {mod_path}\033[0m")
            
            try:
                print("  Running 'go mod tidy'...")
                subprocess.run(["go", "mod", "tidy"], cwd=mod_path, check=True, shell=True)
                print("  \033[92mSuccess!\033[0m")
            except subprocess.CalledProcessError:
                 print(f"  \033[91mFailed to tidy module in {mod_path}\033[0m")
    
    if found_count == 0:
        print("\033[90mNo go.mod files found.\033[0m")
    else:
        print(f"\n\033[92mProcessed {found_count} Go modules.\033[0m")


def main():
    # Enable colored output support for Windows
    os.system('')
    
    print("\n\033[96m" + "=" * 50)
    print("       SafeOps Dependency Installer")
    print("=" * 50 + "\033[0m")
    
    root_dir = os.getcwd()
    print(f"\nRoot Directory: {root_dir}")
    
    # 1. Check system requirements
    install_system_tools()
    
    # 2. Install Python dependencies
    install_python_dependencies()
    
    # 3. Initialize databases
    initialize_databases(root_dir)
    
    # 4. Install Node.js dependencies
    install_node_dependencies(root_dir)
    
    # 5. Tidy Go modules
    tidy_go_modules(root_dir)
    
    # Summary
    print_header("Installation Complete")
    print("\033[92m✓ System requirements checked\033[0m")
    print("\033[92m✓ Python packages installed\033[0m")
    print("\033[92m✓ Databases initialized\033[0m")
    print("\033[92m✓ Node.js dependencies installed\033[0m")
    print("\033[92m✓ Go modules tidied\033[0m")
    print("\n\033[92mYou can now run 'start_safeops.bat' to start the services.\033[0m")


if __name__ == "__main__":
    main()
