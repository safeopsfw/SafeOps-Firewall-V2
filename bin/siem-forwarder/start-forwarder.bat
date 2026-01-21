@echo off
echo Starting SafeOps SIEM Log Forwarder...
cd /d "%~dp0"
siem-forwarder.exe -config config.yaml
