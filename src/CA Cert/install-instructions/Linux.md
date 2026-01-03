# Linux Installation Instructions

## SafeOps Root CA Certificate

### Ubuntu/Debian:

```bash
sudo cp root_ca.crt /usr/local/share/ca-certificates/safeops-root-ca.crt
sudo update-ca-certificates
```

### Fedora/RHEL/CentOS:

```bash
sudo cp root_ca.crt /etc/pki/ca-trust/source/anchors/safeops-root-ca.crt
sudo update-ca-trust
```

### Arch Linux:

```bash
sudo cp root_ca.crt /etc/ca-certificates/trust-source/anchors/safeops-root-ca.crt
sudo trust extract-compat
```

### Firefox (all distros):

Firefox has its own certificate store:
1. Open Firefox > Settings > Privacy & Security
2. Scroll to "Certificates" > Click "View Certificates"
3. Go to "Authorities" tab
4. Click "Import" and select `root_ca.crt`
5. Check "Trust this CA to identify websites"

### Verification:

```bash
curl -v https://captive.safeops.local:8444
# Should NOT show certificate errors
```
