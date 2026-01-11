# SafeOps CA Certificate - Windows Group Policy Deployment

# =========================================================

# This folder contains files for automatic certificate deployment via GPO

## Quick Setup (5 minutes):

### Step 1: Copy Certificate to Network Share

```
\\domain-controller\NETLOGON\SafeOps\ca.crt
```

### Step 2: Create GPO

1. Open Group Policy Management Console (gpmc.msc)
2. Right-click your domain → Create a GPO → Name it "SafeOps Certificate"
3. Edit the GPO

### Step 3: Configure Certificate Auto-Enrollment

Navigate to:

```
Computer Configuration
  → Policies
    → Windows Settings
      → Security Settings
        → Public Key Policies
          → Trusted Root Certification Authorities
```

Right-click → Import → Select your ca.crt file

### Step 4: Alternative - Use Startup Script

Navigate to:

```
Computer Configuration
  → Policies
    → Windows Settings
      → Scripts (Startup/Shutdown)
        → Startup
```

Add: `install_cert_gpo.bat`

### Step 5: Link GPO

Link the GPO to the OU containing your computers.

### Step 6: Force Update (Optional)

On client machines, run:

```
gpupdate /force
```

## Files in this folder:

- `install_cert_gpo.bat` - Startup script for GPO
- `install_cert_gpo.ps1` - PowerShell version
- `SafeOps-CA.crt` - Copy your CA cert here

## Verification:

On a client machine, run:

```
certutil -store Root | findstr SafeOps
```
