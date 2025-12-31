# SafeOps CA Manual Setup Script
# This creates a complete CA structure for step-ca

$ErrorActionPreference = "Stop"

$CA_DIR = "D:\SafeOpsFV2\certs\step-ca\ca"
$CERTS_DIR = "$CA_DIR\certs"
$SECRETS_DIR = "$CA_DIR\secrets"
$CONFIG_DIR = "$CA_DIR\config"
$DB_DIR = "$CA_DIR\db"

Write-Host "========================================" -ForegroundColor Cyan
Write-Host "SafeOps Certificate Authority Setup" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan
Write-Host ""

# Create directory structure
Write-Host "[1/6] Creating CA directory structure..." -ForegroundColor Yellow
New-Item -Path $CERTS_DIR -ItemType Directory -Force | Out-Null
New-Item -Path $SECRETS_DIR -ItemType Directory -Force | Out-Null
New-Item -Path $CONFIG_DIR -ItemType Directory -Force | Out-Null
New-Item -Path $DB_DIR -ItemType Directory -Force | Out-Null

# Generate random password
Write-Host "[2/6] Generating secure password..." -ForegroundColor Yellow
$password = -join ((48..57) + (65..90) + (97..122) | Get-Random -Count 32 | ForEach-Object {[char]$_})
$password | Out-File -FilePath "$SECRETS_DIR\password.txt" -NoNewline -Encoding ASCII

# Create OpenSSL config for Root CA
Write-Host "[3/6] Creating Root CA certificate..." -ForegroundColor Yellow
$rootCaConfig = @"
[req]
distinguished_name = req_distinguished_name
x509_extensions = v3_ca
prompt = no

[req_distinguished_name]
C = US
ST = SafeOps
L = Network
O = SafeOps Network
OU = Certificate Authority
CN = SafeOps Root CA

[v3_ca]
basicConstraints = critical,CA:TRUE
keyUsage = critical,keyCertSign,cRLSign
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid:always,issuer:always
"@

$rootCaConfig | Out-File -FilePath "$CONFIG_DIR\root-ca.conf" -Encoding ASCII

# Check if OpenSSL is available
try {
    $opensslPath = (Get-Command openssl -ErrorAction Stop).Source
    Write-Host "  Found OpenSSL at: $opensslPath" -ForegroundColor Green
} catch {
    Write-Host "  ERROR: OpenSSL not found in PATH!" -ForegroundColor Red
    Write-Host "  Please install OpenSSL or use Git Bash (includes OpenSSL)" -ForegroundColor Yellow
    Write-Host "  Git for Windows: https://git-scm.com/download/win" -ForegroundColor Yellow
    exit 1
}

# Generate Root CA
& openssl genrsa -out "$SECRETS_DIR\root_ca_key" 4096 2>&1 | Out-Null
& openssl req -new -x509 -days 3650 -key "$SECRETS_DIR\root_ca_key" -out "$CERTS_DIR\root_ca.crt" -config "$CONFIG_DIR\root-ca.conf" 2>&1 | Out-Null

Write-Host "[4/6] Creating Intermediate CA certificate..." -ForegroundColor Yellow

# Create OpenSSL config for Intermediate CA
$intermediateCaConfig = @"
[req]
distinguished_name = req_distinguished_name
prompt = no

[req_distinguished_name]
C = US
ST = SafeOps
L = Network
O = SafeOps Network
OU = Certificate Authority
CN = SafeOps Intermediate CA
"@

$intermediateCaConfig | Out-File -FilePath "$CONFIG_DIR\intermediate-ca.conf" -Encoding ASCII

# Generate Intermediate CA
& openssl genrsa -out "$SECRETS_DIR\intermediate_ca_key" 4096 2>&1 | Out-Null
& openssl req -new -key "$SECRETS_DIR\intermediate_ca_key" -out "$CONFIG_DIR\intermediate_ca.csr" -config "$CONFIG_DIR\intermediate-ca.conf" 2>&1 | Out-Null

# Sign Intermediate CA with Root CA
$v3Config = @"
basicConstraints = critical,CA:TRUE,pathlen:0
keyUsage = critical,keyCertSign,cRLSign
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid:always,issuer:always
"@

$v3Config | Out-File -FilePath "$CONFIG_DIR\v3.ext" -Encoding ASCII

& openssl x509 -req -in "$CONFIG_DIR\intermediate_ca.csr" -CA "$CERTS_DIR\root_ca.crt" -CAkey "$SECRETS_DIR\root_ca_key" -CAcreateserial -out "$CERTS_DIR\intermediate_ca.crt" -days 1825 -extfile "$CONFIG_DIR\v3.ext" 2>&1 | Out-Null

Write-Host "[5/6] Creating step-ca configuration..." -ForegroundColor Yellow

# Create minimal step-ca config
$stepConfig = @{
    root = "$CERTS_DIR\root_ca.crt"
    crt = "$CERTS_DIR\intermediate_ca.crt"
    key = "$SECRETS_DIR\intermediate_ca_key"
    address = "192.168.137.1:9000"
    dnsNames = @("safeops.local", "192.168.137.1", "localhost")
    logger = @{format = "text"}
    db = @{
        type = "badgerv2"
        dataSource = $DB_DIR
    }
    authority = @{
        provisioners = @(
            @{
                type = "ACME"
                name = "safeops-acme"
                forceCN = $false
                claims = @{
                    minTLSCertDuration = "5m"
                    maxTLSCertDuration = "87600h"
                    defaultTLSCertDuration = "720h"
                    disableRenewal = $false
                }
            }
        )
    }
    tls = @{
        minVersion = 1.2
        maxVersion = 1.3
        renegotiation = $false
    }
}

# Convert paths to use forward slashes for JSON
$stepConfigJson = $stepConfig | ConvertTo-Json -Depth 10
$stepConfigJson = $stepConfigJson -replace '\\\\', '/'
$stepConfigJson | Out-File -FilePath "$CONFIG_DIR\ca.json" -Encoding ASCII

# Copy Root CA to main certs directory
Copy-Item "$CERTS_DIR\root_ca.crt" "D:\SafeOpsFV2\certs\safeops-root-ca.crt" -Force

Write-Host "[6/6] Creating startup script..." -ForegroundColor Yellow

$startupScript = @"
@echo off
title SafeOps Certificate Authority
echo ========================================
echo SafeOps Certificate Authority
echo ========================================
echo.
echo Starting CA server on https://192.168.137.1:9000
echo Press Ctrl+C to stop
echo.

cd /d "D:\SafeOpsFV2\certs\step-ca"
step-ca.exe "ca\config\ca.json" --password-file "ca\secrets\password.txt"
"@

$startupScript | Out-File -FilePath "D:\SafeOpsFV2\certs\step-ca\start-safeops-ca.bat" -Encoding ASCII

# Create PowerShell startup script
$psStartup = @"
`$Host.UI.RawUI.WindowTitle = "SafeOps Certificate Authority"
Write-Host "========================================" -ForegroundColor Cyan
Write-Host "SafeOps Certificate Authority" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan
Write-Host ""
Write-Host "Starting CA server on https://192.168.137.1:9000" -ForegroundColor Green
Write-Host "Press Ctrl+C to stop" -ForegroundColor Yellow
Write-Host ""

Set-Location "D:\SafeOpsFV2\certs\step-ca"
& .\step-ca.exe "ca\config\ca.json" --password-file "ca\secrets\password.txt"
"@

$psStartup | Out-File -FilePath "D:\SafeOpsFV2\certs\step-ca\start-safeops-ca.ps1" -Encoding UTF8

Write-Host ""
Write-Host "========================================" -ForegroundColor Green
Write-Host "SafeOps CA Setup Complete!" -ForegroundColor Green
Write-Host "========================================" -ForegroundColor Green
Write-Host ""
Write-Host "CA Details:" -ForegroundColor Cyan
Write-Host "  Organization: SafeOps Network" -ForegroundColor White
Write-Host "  Root CA: SafeOps Root CA" -ForegroundColor White
Write-Host "  Intermediate CA: SafeOps Intermediate CA" -ForegroundColor White
Write-Host "  Validity: 10 years (Root), 5 years (Intermediate)" -ForegroundColor White
Write-Host "  API Address: https://192.168.137.1:9000" -ForegroundColor White
Write-Host "  ACME Provisioner: safeops-acme" -ForegroundColor White
Write-Host ""
Write-Host "Certificate Locations:" -ForegroundColor Cyan
Write-Host "  Root CA: D:\SafeOpsFV2\certs\safeops-root-ca.crt" -ForegroundColor White
Write-Host "  Full CA: $CERTS_DIR\root_ca.crt" -ForegroundColor White
Write-Host ""
Write-Host "To start the CA server:" -ForegroundColor Yellow
Write-Host "  Method 1 (Batch): D:\SafeOpsFV2\certs\step-ca\start-safeops-ca.bat" -ForegroundColor White
Write-Host "  Method 2 (PowerShell): D:\SafeOpsFV2\certs\step-ca\start-safeops-ca.ps1" -ForegroundColor White
Write-Host ""
Write-Host "To test the CA:" -ForegroundColor Yellow
Write-Host "  curl -k https://192.168.137.1:9000/health" -ForegroundColor White
Write-Host ""
