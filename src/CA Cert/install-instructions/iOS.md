# iOS Installation Instructions

## SafeOps Root CA Certificate

### Installation Steps:

1. **Transfer** `root_ca.p12` to your iPhone:
   - Via AirDrop
   - Email attachment
   - Download from captive portal

2. **Tap** the file to install

3. Go to **Settings > General > VPN & Device Management**

4. Tap "**SafeOps Root CA**" and click "**Install**"

5. Enter your device **passcode**

6. Go to **Settings > General > About > Certificate Trust Settings**

7. **Enable** "SafeOps Root CA" under "Enable Full Trust for Root Certificates"

8. **Restart** Safari/Chrome

### Verification:
Visit `https://captive.safeops.local:8444` - should show valid certificate (no warnings)
