# Android Installation Instructions

## SafeOps Root CA Certificate

### Installation Steps:

1. **Transfer** `root_ca.crt` to your Android device

2. Go to **Settings > Security > Encryption & credentials**

3. Tap "**Install a certificate**" > "**CA certificate**"

4. If prompted, tap "**Install anyway**"

5. Navigate to Downloads and select `root_ca.crt`

6. Name it "**SafeOps Root CA**"

7. Tap "**OK**"

8. **Restart** Chrome

### Verification:
Visit `https://captive.safeops.local:8444` - should show valid certificate (no warnings)

### Note:
- On Android 11+, user-installed CAs may only work in certain apps
- For system-wide trust, device may need to be rooted
