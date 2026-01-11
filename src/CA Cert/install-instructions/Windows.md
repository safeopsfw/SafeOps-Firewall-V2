# Windows Installation Instructions

## SafeOps Root CA Certificate

### Method 1: Double-Click (Easiest)

1. **Double-click** `root_ca.der`
2. Click "**Install Certificate...**"
3. Select "**Local Machine**" (requires admin)
4. Click "**Next**"
5. Select "**Place all certificates in the following store**"
6. Click "**Browse**" > Select "**Trusted Root Certification Authorities**"
7. Click "**Next**" > "**Finish**"
8. Click "**Yes**" on security warning

### Method 2: PowerShell (As Admin)

```powershell
Import-Certificate -FilePath "D:\SafeOpsFV2\src\CA Cert\root_ca.der" -CertStoreLocation Cert:\LocalMachine\Root
```

### Verification:

1. Open `certmgr.msc` (run as admin)
2. Navigate to **Trusted Root Certification Authorities > Certificates**
3. Look for "**SafeOps Root CA**"

Or run:
```powershell
Get-ChildItem Cert:\LocalMachine\Root | Where-Object { $_.Subject -match "SafeOps" }
```
