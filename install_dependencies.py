#!/usr/bin/env python3
"""
SafeOps Dependency Installer
Installs system prerequisites and project dependencies (Node.js & Go).

1. Checks for Go, Node.js, and Git.
2. Recursively finds 'package.json' and runs 'npm install'.
3. Recursively finds 'go.mod' and runs 'go mod tidy'.
"""

import os
import subprocess
import shutil
import sys
from pathlib import Path

def print_header(title):
    print("\n" + "=" * 40)
    print(f" {title}")
    print("=" * 40 + "\n")

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
    tools = [
        {"name": "Go (Golang)", "command": "go"},
        {"name": "Node.js", "command": "node"},
        {"name": "Git", "command": "git"}
    ]
    
    missing = False
    for tool in tools:
        if not check_command(tool["name"], tool["command"]):
            missing = True
            print(f"\033[93mWarning: {tool['name']} is missing. Please install it manually.\033[0m")
            
    if missing:
        print("\n\033[93mSome system tools are missing. Scripts execution might fail.\033[0m")

def install_node_dependencies(root_dir):
    print_header("Installing Node.js Dependencies")
    
    # Dirs to skip during traversal
    skip_dirs = {'.git', 'node_modules', 'dist', 'build', 'vendor'}
    
    for root, dirs, files in os.walk(root_dir):
        # Modify dirs in-place to skip traversing ignored directories
        dirs[:] = [d for d in dirs if d not in skip_dirs]
            
        if "package.json" in files:
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

def tidy_go_modules(root_dir):
    print_header("Tidying Go Modules")
    
    skip_dirs = {'.git', 'node_modules', 'dist', 'build', 'vendor'}
    
    for root, dirs, files in os.walk(root_dir):
        # Modify dirs in-place to skip traversing ignored directories
        dirs[:] = [d for d in dirs if d not in skip_dirs]
        
        if "go.mod" in files:
            mod_path = Path(root)
            print(f"\033[93mFound go.mod in: {mod_path}\033[0m")
            
            try:
                print("  Running 'go mod tidy'...")
                subprocess.run(["go", "mod", "tidy"], cwd=mod_path, check=True, shell=True)
                print("  \033[92mSuccess!\033[0m")
            except subprocess.CalledProcessError:
                 print(f"  \033[91mFailed to tidy module in {mod_path}\033[0m")

def main():
    # Enable colored output support for Windows
    os.system('')
    
    root_dir = os.getcwd()
    print(f"Root Directory: {root_dir}")
    
    install_system_tools()
    install_node_dependencies(root_dir)
    tidy_go_modules(root_dir)
    
    print_header("Installation Complete")
    print("\033[92mYou can now run 'start_safeops.bat' to start the services.\033[0m")

if __name__ == "__main__":
    main()
