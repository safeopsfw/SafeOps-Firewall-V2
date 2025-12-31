@echo off
title SafeOps Certificate Authority
echo ========================================
echo SafeOps Certificate Authority
echo ========================================
echo.
echo Starting CA server on https://192.168.137.1:9000
echo ACME endpoint: https://192.168.137.1:9000/acme/safeops-acme/directory
echo Press Ctrl+C to stop
echo.

cd /d "D:\SafeOpsFV2\certs\step-ca"
step-ca.exe "ca\config\ca.json" --password-file "ca\secrets\password.txt"
pause
