# macOS Installation Instructions

## SafeOps Root CA Certificate

### Installation Steps:

1. **Double-click** `root_ca.crt`

2. **Keychain Access** app will open

3. Select "**System**" keychain

4. Click "**Add**"

5. Find "**SafeOps Root CA**" in the list

6. **Double-click** the certificate

7. Expand "**Trust**" section

8. Set "**When using this certificate**" to "**Always Trust**"

9. **Close** window (enter password when prompted)

10. **Restart** Safari/Chrome

### Command Line Alternative:

```bash
sudo security add-trusted-cert -d -r trustRoot -k /Library/Keychains/System.keychain root_ca.crt
```

### Verification:
Visit `https://captive.safeops.local:8444` - should show valid certificate (no warnings)
