# SafeOps Development Environment Installer - README

## 🚀 Quick Start

### Install Everything (Recommended)
```powershell
# Run as Administrator
.\Install-SafeOpsDev.ps1
```

### Install Without Optional Components
```powershell
# Skips Docker, Node.js, VS Code, Consul
.\Install-SafeOpsDev.ps1 -SkipOptional
```

### Custom Install Path
```powershell
.\Install-SafeOpsDev.ps1 -InstallPath "D:\MyDev"
```

---

## 📦 What Gets Installed

### Core Components (Required)
- ✅ **Chocolatey** - Package manager
- ✅ **Git** - Version control
- ✅ **Go 1.21.5** - Go language
- ✅ **Rust** - Rust language + Cargo
- ✅ **PostgreSQL 16** - Database
- ✅ **Redis** - Cache/message broker
- ✅ **Protocol Buffers** - gRPC compiler + plugins
- ✅ **Visual Studio Build Tools** - C/C++ compiler
- ✅ **Utilities** - 7zip, wget, curl, jq

### Optional Components
- 🔹 **Docker Desktop** - Containerization
- 🔹 **Node.js 20** - UI development
- 🔹 **Visual Studio Code** - IDE + extensions
- 🔹 **Consul** - Service discovery

---

## ⚙️ System Requirements

### Minimum
- **OS**: Windows 10 Pro/Enterprise or Windows 11
- **RAM**: 8GB (16GB recommended)
- **Disk**: 20GB free space
- **Internet**: Required for downloads

### Administrator Access
**MUST run as Administrator!**

Right-click PowerShell → "Run as Administrator"

---

## 📋 Installation Process

The installer will:

1. ✅ Check administrator privileges
2. ✅ Install Chocolatey package manager
3. ✅ Install all core components
4. ✅ Configure environment variables
5. ✅ Set up Go, Rust toolchains
6. ✅ Start PostgreSQL and Redis services
7. ✅ Install optional components (if not skipped)
8. ✅ Verify all installations
9. ✅ Display summary and next steps

**Estimated Time**: 15-30 minutes (depending on internet speed)

---

## 🔍 Post-Installation Verification

### Check Versions
```powershell
go version        # Go 1.21.5
rustc --version   # Rust stable
git --version     # Git
protoc --version  # Protocol Buffers
psql --version    # PostgreSQL 16
redis-cli ping    # PONG (if Redis is running)
```

### Test Services
```powershell
# PostgreSQL
psql -U postgres -c "SELECT version();"

# Redis
redis-cli ping

# Docker (after restart)
docker --version
docker run hello-world
```

---

## 🛠️ Default Credentials

### PostgreSQL
- **Username**: `postgres`
- **Password**: `postgres`
- **Port**: `5432`
- **Host**: `localhost`

### Redis
- **Port**: `6379`
- **Host**: `localhost`
- **Password**: None (dev mode)

---

## 📁 Directory Structure

```
C:\SafeOpsDev\              # Default install path
├── workspace\              # Your projects go here
└── logs\                   # Installation logs

%USERPROFILE%\go\           # Go workspace
├── bin\                    # Go binaries
├── pkg\                    # Go packages
└── src\                    # Go source

%USERPROFILE%\.cargo\       # Rust installation
```

---

## 🐛 Troubleshooting

### "This script must be run as Administrator"
- Right-click PowerShell
- Select "Run as Administrator"
- Run the script again

### Chocolatey installation fails
```powershell
# Manual install
Set-ExecutionPolicy Bypass -Scope Process -Force
[System.Net.ServicePointManager]::SecurityProtocol = 3072
iex ((New-Object System.Net.WebClient).DownloadString('https://community.chocolatey.org/install.ps1'))
```

### Component installation fails
```powershell
# Try manual install
choco install <component-name> -y

# Examples:
choco install golang -y
choco install rust -y
choco install postgresql16 -y
```

### PATH not updated
```powershell
# Restart PowerShell or run:
$env:Path = [System.Environment]::GetEnvironmentVariable("Path","Machine") + ";" + [System.Environment]::GetEnvironmentVariable("Path","User")
```

### PostgreSQL won't start
```powershell
# Check service
Get-Service postgresql*

# Start manually
Start-Service postgresql-x64-16
```

### Redis connection refused
```powershell
# Start Redis service
Start-Service Redis

# Test connection
redis-cli ping
```

---

## 🔄 Uninstallation

### Remove All Components
```powershell
# Uninstall via Chocolatey
choco uninstall golang rust postgresql16 redis-64 protoc docker-desktop -y

# Remove Chocolatey
Remove-Item -Path C:\ProgramData\chocolatey -Recurse -Force
```

### Clean Environment Variables
```powershell
# Remove GOPATH
[Environment]::SetEnvironmentVariable("GOPATH", $null, "User")

# Remove from PATH (manual)
# System Properties → Environment Variables → Edit Path
```

---

## 📝 For VMware Setup

### Recommended VM Configuration
- **RAM**: 8GB minimum (16GB for Docker)
- **CPU**: 4 cores
- **Disk**: 60GB (thin provisioned)
- **Network**: NAT or Bridged

### After VM Creation
1. Install Windows (10/11)
2. Enable virtualization (for Docker)
3. Install VMware Tools
4. Copy SafeOps project to VM
5. Run this installer
6. Restart VM
7. Start development!

---

## 🎯 Next Steps After Installation

1. **Restart Computer** (required for Docker & PATH)

2. **Clone SafeOps**:
   ```powershell
   cd C:\SafeOpsDev\workspace
   git clone https://github.com/your-username/SafeOps-Firewall-V2.git
   cd SafeOps-Firewall-V2
   ```

3. **Build Shared Libraries**:
   ```powershell
   # Go libraries
   cd src/shared/go
   go mod download
   go build ./...
   go test ./...
   
   # Rust libraries
   cd ../rust
   cargo build
   cargo test
   ```

4. **Run Sandbox Tests**:
   ```powershell
   cd ../../sandbox
   .\SafeOps-Test.wsb
   ```

5. **Start Development**! 🎉

---

## 📧 Support

If installation fails:
1. Check logs in PowerShell output
2. Try manual installation of failed component
3. Verify internet connection
4. Ensure administrator privileges
5. Check system requirements

**Your development environment will be ready in ~20 minutes!** ⚡
