# Install Npcap for Packet Capture

## Steps to Install Npcap

1. **Download Npcap:**
   - Go to: https://npcap.com/#download
   - Download the latest Npcap installer (e.g., npcap-1.79.exe)

2. **Run Installer as Administrator:**
   - Right-click the downloaded .exe file
   - Select "Run as administrator"

3. **Installation Options (IMPORTANT):**
   - ✅ Check "Install Npcap in WinPcap API-compatible mode"
   - ✅ Check "Support loopback traffic"
   - Click "I Agree" and "Install"

4. **Verify Installation:**
   - Open Command Prompt
   - Run: `sc query npcap`
   - Should show: STATE = RUNNING

5. **After Installation:**
   - Restart your terminal/PowerShell
   - The Packet.lib file will be available at:
     - `C:\Windows\System32\Npcap\` (64-bit)
     - `C:\Windows\SysWOW64\Npcap\` (32-bit compat)

## Then Build Packet Engine

After Npcap is installed, run:

```bash
cd D:\SafeOpsFV2\src\nic_management
cargo build --release --bin packet_engine
```

The binary will be at: `target/release/packet_engine.exe`
