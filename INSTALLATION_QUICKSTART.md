# SafeOps v2.0 Installation - Quick Start Guide

## Installation in 5 Minutes

### Prerequisites
- Windows 10/11 Pro/Enterprise or Windows Server 2019/2022
- Administrator privileges
- Build artifacts ready (SafeOps.sys and SafeOpsService.exe)

### Step 1: Prepare
```powershell
# Open PowerShell as Administrator
# Navigate to SafeOps project root
cd C:\path\to\SafeOps
```

### Step 2: Run Installation
```powershell
.\install_safeops.ps1
```

The script will:
- Check your system
- Enable test signing if needed (may restart)
- Install kernel driver
- Install and start service
- Create configuration
- Generate helper scripts

### Step 3: Verify Installation
```powershell
.\verify_installation.ps1
```

Expected output:
```
Status: HEALTHY
SafeOps appears to be properly installed and configured.
```

---

## Common Commands

### Check Status
```powershell
# Detailed verification
.\verify_installation.ps1 -Verbose -FullReport

# Quick service status
Get-Service SafeOpsService, SafeOps

# View recent events
Get-EventLog System -Source SafeOps -Newest 10
```

### Restart Service
```powershell
Restart-Service SafeOpsService
```

### View Logs
```powershell
# Installation logs
Get-Content $env:TEMP\safeops_install_*.log | Select-Object -Last 50

# Application logs
Get-ChildItem "C:\ProgramData\SafeOps\Logs" -Filter *.log
```

### Uninstall
```powershell
# Remove SafeOps (keeps configuration)
.\uninstall_safeops.ps1

# Remove everything including configuration
.\uninstall_safeops.ps1 -RemoveConfig -RemoveLogs
```

---

## Installation Locations

| Component | Location |
|-----------|----------|
| Driver | `C:\Program Files\SafeOps\SafeOps.sys` |
| Service | `C:\Program Files\SafeOps\SafeOpsService.exe` |
| Configuration | `%APPDATA%\SafeOps\` |
| Logs | `%ProgramData%\SafeOps\Logs\` |
| Installation Log | `%TEMP%\safeops_install_*.log` |

---

## Troubleshooting

### "Must run as Administrator"
```powershell
# Right-click PowerShell and select "Run as Administrator"
```

### "Test signing not enabled"
```powershell
# Script will prompt. Press Y to enable and restart
```

### Service won't start
```powershell
# Check Event Viewer for errors
Get-EventLog System -Source SafeOps -EntryType Error

# Or run detailed verification
.\verify_installation.ps1 -Verbose -FullReport
```

### "Driver not found"
```powershell
# Verify build artifacts exist
Test-Path "build\driver\release\x64\SafeOps.sys"
Test-Path "build\userspace_service\release\SafeOpsService.exe"

# Or specify paths explicitly
.\install_safeops.ps1 -DriverPath "C:\path\to\SafeOps.sys" -ServicePath "C:\path\to\SafeOpsService.exe"
```

---

## Next Steps

1. **Configure SafeOps**
   - Edit `%APPDATA%\SafeOps\safeops.conf`
   - Configure network rules in `%APPDATA%\SafeOps\network\`
   - Set IDS/IPS rules in `%APPDATA%\SafeOps\ids_ips\`

2. **Monitor Service**
   ```powershell
   # Start service auto-restart
   Get-Service SafeOpsService | Set-Service -StartupType Automatic
   ```

3. **Enable Logging**
   ```powershell
   # Configure log level in safeops.conf
   LogLevel=DEBUG
   ```

4. **Test Connectivity**
   - Monitor Event Viewer for SafeOps events
   - Check `%ProgramData%\SafeOps\Logs\` for application logs

---

## Important Notes

- **Test Signing:** Required for development installations. Production requires proper code signing.
- **Configuration:** Default configuration is created automatically but should be customized for your environment.
- **Logs:** Installation logs are saved to %TEMP% and can be reviewed for troubleshooting.
- **Backup:** Keep backup of configuration files before major changes.
- **Restart:** System restart recommended after installation completion.

---

## Complete Feature List

### Installation Script Features
- Administrator privilege verification
- Test signing mode configuration
- Kernel driver installation
- Userspace service installation
- Automatic configuration creation
- Service dependency management
- Recovery policy setup
- Post-installation verification
- Helper script generation
- Comprehensive logging

### Uninstallation Script Features
- Safe service shutdown
- Registry cleanup
- Firewall rule removal
- Configuration preservation options
- Log preservation options
- Unattended mode
- Comprehensive logging

### Verification Script Features
- System health checks
- Service status verification
- File integrity checks
- Configuration validation
- Event log analysis
- Network diagnostics
- Registry verification
- Detailed health reporting
- Exit code based results

---

## Performance Tips

- Monitor service memory: ~5-10 MB at idle
- Check log sizes periodically (configure rotation)
- Use debug mode only during troubleshooting
- Review configuration for unnecessary features

---

## Security Reminders

1. **Always Run as Administrator** - Required for kernel-mode operations
2. **Test Signing** - Development only. Use proper signing for production
3. **Configuration** - Store sensitive data securely
4. **Logs** - May contain sensitive network information
5. **Access Control** - Restrict service installation to trusted users

---

## Support Resources

- **Installation Guide:** `INSTALLATION_SCRIPTS_GUIDE.md`
- **Build Guide:** `BUILD_GUIDE.md`
- **Documentation Index:** `DOCUMENTATION_INDEX.md`
- **Event Viewer:** View SafeOps events under System logs
- **Logs:** `%ProgramData%\SafeOps\Logs\` for application logs

---

## Quick Reference

```powershell
# Install
.\install_safeops.ps1

# Verify
.\verify_installation.ps1

# Uninstall
.\uninstall_safeops.ps1

# Check service
Get-Service SafeOpsService

# View logs
Get-EventLog System -Source SafeOps

# Restart
Restart-Service SafeOpsService

# Stop
Stop-Service SafeOpsService

# Enable autostart
Set-Service SafeOpsService -StartupType Automatic
```

---

**Last Updated:** 2025-12-25
**Version:** 1.0
