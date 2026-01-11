# Headwind MDM + SafeOps Integration Guide

## Zero-Touch Android CA Certificate Deployment

> **Headwind MDM** is a free, open-source Mobile Device Management solution that supports Android Enterprise and can automatically deploy CA certificates to managed devices.

---

## Architecture

```
┌──────────────────────────────────────────────────────────────────┐
│                    Zero-Touch Flow                                │
└──────────────────────────────────────────────────────────────────┘

  1. Admin sets up Headwind MDM (one-time)
  2. Admin uploads SafeOps CA cert to Headwind
  3. Admin creates enrollment QR code

  Then for EACH new device:

  User scans QR → Device auto-enrolls → Cert auto-installed → Done!

  Total user interaction: ONE QR scan! 📱
```

---

## Step 1: Install Headwind MDM Server

### Option A: Quick Install (Ubuntu/Debian)

```bash
# Download and run installer
wget https://h-mdm.com/files/hmdm-install.sh
sudo bash hmdm-install.sh
```

### Option B: Manual Install

```bash
# Install dependencies
sudo apt update
sudo apt install -y openjdk-11-jdk tomcat9 postgresql postgresql-contrib

# Download Headwind MDM
wget https://h-mdm.com/files/hmdm-5.xx-os.war -O /var/lib/tomcat9/webapps/hmdm.war

# Create database
sudo -u postgres createuser hmdm
sudo -u postgres createdb -O hmdm hmdm

# Access web interface
# http://your-server:8080/hmdm
```

### Default Credentials

- URL: `http://your-server:8080/hmdm`
- Username: `admin`
- Password: `admin` (change immediately!)

---

## Step 2: Configure Certificate Deployment

### 2.1 Upload CA Certificate

1. Log into Headwind MDM admin panel
2. Navigate to: **Settings → Certificates**
3. Click **Add Certificate**
4. Upload: `SafeOps-CA.crt`
5. Set **Certificate Type**: `CA Certificate`
6. Check: `Install in system store`
7. Save

### 2.2 Create Configuration Profile

1. Go to: **Configurations → Add Configuration**
2. Name: `SafeOps Network`
3. Under **Certificates** section:
   - Enable: `Install CA certificates`
   - Select: `SafeOps-CA.crt`
4. Save configuration

---

## Step 3: Create Enrollment QR Code

### 3.1 Generate QR for Device Enrollment

1. Go to: **Devices → QR Enrollment**
2. Select: `SafeOps Network` configuration
3. Click: **Generate QR Code**
4. Download/print the QR code

### 3.2 QR Code Options

| Mode             | Use Case                             |
| ---------------- | ------------------------------------ |
| **Work Profile** | BYOD - Creates separate work profile |
| **Device Owner** | Company-owned - Full control         |
| **Kiosk**        | Single-app mode                      |

---

## Step 4: Enroll Android Devices

### For New/Factory Reset Devices:

1. Power on device
2. Connect to WiFi
3. Tap screen 6 times → Opens QR scanner
4. Scan Headwind QR code
5. Device auto-configures + installs cert!

### For Existing Devices (Work Profile):

1. Download "Headwind MDM" app from Play Store
2. Open app → Scan QR code
3. Follow prompts to create work profile
4. Cert installs automatically

---

## Step 5: SafeOps Integration (API)

### Configure Headwind to Notify SafeOps

When a device enrolls, Headwind can call SafeOps API:

**In Headwind Admin:**

1. Go to: **Settings → Plugins → Webhooks**
2. Add webhook:
   - URL: `http://192.168.1.1/api/enroll`
   - Event: `device.enrolled`
   - Method: `POST`
   - Payload:
   ```json
   {
     "ip": "${device.ip}",
     "mac": "${device.mac}",
     "os": "Android",
     "method": "headwind-mdm",
     "device_id": "${device.number}"
   }
   ```

---

## Step 6: Print QR for Guest WiFi

Create a sign for your network:

```
┌─────────────────────────────────────────┐
│                                         │
│   📶 Connect to SafeOps Network         │
│                                         │
│   ┌───────────────┐                     │
│   │   [QR CODE]   │  ← Scan with phone  │
│   │               │                     │
│   └───────────────┘                     │
│                                         │
│   1. Scan QR code                       │
│   2. Follow setup prompts               │
│   3. Done! You're connected securely    │
│                                         │
└─────────────────────────────────────────┘
```

---

## API Integration Code

See: `tools/mdm_integration/headwind_client.go`

This Go client can:

- Query enrolled devices from Headwind
- Sync enrollment status with SafeOps
- Push new certificates to all devices

---

## Troubleshooting

| Issue                | Solution                                         |
| -------------------- | ------------------------------------------------ |
| QR won't scan        | Ensure device is factory reset or use app method |
| Cert not installing  | Check "Install in system store" is enabled       |
| Device not appearing | Check network connectivity to Headwind server    |
| Work profile issues  | User must complete setup wizard                  |

---

## Resources

- **Headwind MDM Docs**: https://h-mdm.com/docs/
- **Android Enterprise**: https://www.android.com/enterprise/
- **Source Code**: https://github.com/nickelyan/hmdm-server

---

## Summary

| Before (Captive Portal)   | After (Headwind MDM)  |
| ------------------------- | --------------------- |
| 5+ taps to install cert   | 1 QR scan             |
| User follows instructions | Automatic             |
| Can be skipped/ignored    | Enforced by MDM       |
| No device visibility      | Full device inventory |
