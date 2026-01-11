# Install Npcap SDK for Development

You have Npcap installed (runtime), but you need the **Npcap SDK** to build packet_engine.

## Download and Install Npcap SDK

1. **Download Npcap SDK:**
   - Go to: https://npcap.com/#download
   - Scroll down to "Npcap SDK"
   - Download: `npcap-sdk-1.13.zip` (or latest version)

2. **Extract SDK:**
   - Extract the ZIP file to: `C:\npcap-sdk\`
   - Or any location you prefer

3. **Set Environment Variable:**
   Open PowerShell as Administrator and run:
   ```powershell
   [System.Environment]::SetEnvironmentVariable("LIB", "$env:LIB;C:\npcap-sdk\Lib\x64", "User")
   ```

   Or manually:
   - Right-click "This PC" → Properties → Advanced System Settings
   - Environment Variables → User Variables
   - Find or create "LIB" variable
   - Add: `;C:\npcap-sdk\Lib\x64` to the value

4. **Restart Terminal:**
   Close and reopen your terminal/PowerShell for changes to take effect

5. **Build packet_engine:**
   ```bash
   cd D:\SafeOpsFV2\src\nic_management
   cargo build --release --bin packet_engine
   ```

## Alternative: Copy Library Files

If you don't want to set environment variables, copy the lib files:

```powershell
# From SDK Lib\x64 folder, copy to:
Copy-Item "C:\npcap-sdk\Lib\x64\Packet.lib" "C:\Users\02arj\.cargo\registry\src\index.crates.io-*\pnet-0.34.0\lib\x64\"
Copy-Item "C:\npcap-sdk\Lib\x64\wpcap.lib" "C:\Users\02arj\.cargo\registry\src\index.crates.io-*\pnet-0.34.0\lib\x64\"
```

Then rebuild.
