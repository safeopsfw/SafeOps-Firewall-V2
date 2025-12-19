# SafeOps Windows Sandbox Testing - README

## 📦 What's in this folder?

This folder contains automated testing tools for SafeOps shared libraries using Windows Sandbox.

### Files:
- `SafeOps-Test.wsb` - Windows Sandbox configuration
- `test-shared-libs.ps1` - Automated test script
- `test-results.txt` - Test output (created after run)

---

## 🚀 Quick Start

### Method 1: Double-Click (Easiest)
1. Double-click `SafeOps-Test.wsb`
2. Wait for sandbox to start and tests to run
3. Review results in the sandbox window

### Method 2: Command Line
```powershell
# Run from this directory
Start-Process "SafeOps-Test.wsb"
```

---

## 📋 What the test does

1. ✅ **Checks Go installation** (installs if missing)
2. ✅ **Downloads dependencies** (go mod download)
3. ✅ **Builds all packages** (13 components)
4. ✅ **Runs unit tests** (all tests with verbose output)
5. ✅ **Runs linters** (go vet)
6. ✅ **Coverage analysis** (test coverage report)

---

## 📊 Test Components

**13 Components Tested**:
1. Redis pipeline
2. PostgreSQL connection pool
3. PostgreSQL transactions
4. PostgreSQL bulk insert
5. PostgreSQL migrations
6. gRPC client wrapper
7. gRPC interceptors
8. gRPC retry logic
9. gRPC circuit breaker
10. gRPC load balancer
11. gRPC retry budget
12. gRPC service discovery
13. Module dependencies (go.mod)

**Total**: 5,000+ lines tested

---

## 🔍 Understanding Results

### Success:
```
✓ ALL TESTS PASSED!
  SafeOps shared libraries are production-ready
```

### Failure:
```
✗ TESTS FAILED
  Review test output above for details
```

Check `test-results.txt` for detailed error messages.

---

## ⚙️ Requirements

### Windows Sandbox
**Enable Windows Sandbox** (one-time setup):
```powershell
# Run as Administrator
Enable-WindowsOptionalFeature -Online -FeatureName "Containers-DisposableClientVM" -All
```

**Requirements**:
- Windows 10 Pro/Enterprise (version 1903+) OR Windows 11
- Virtualization enabled in BIOS
- At least 4GB RAM
- 1GB free disk space

---

## 🐛 Troubleshooting

### "Windows Sandbox not available"
- Enable in Windows Features
- Ensure virtualization is enabled in BIOS
- Requires Windows 10 Pro/Enterprise or Windows 11

### "Go not found"
- Script auto-installs Go
- If it fails, manually install from: https://go.dev/dl/

### Tests timeout
- Increase RAM allocation in `.wsb` file
- Run on faster machine

---

## 📝 Manual Testing

If you want to run tests manually in sandbox:

```powershell
# In sandbox, open PowerShell and run:
cd C:\SafeOps\src\shared\go

# Build
go build ./...

# Test
go test ./... -v

# Specific package
go test ./redis -v
go test ./postgres -v
go test ./grpc_client -v

# With coverage
go test ./... -cover
```

---

## 🎯 CI/CD Integration

This sandbox setup can be automated in CI/CD:

```yaml
# GitHub Actions example
- name: Test in Windows Sandbox
  run: |
    Start-Process "D:\SafeOpsFV2\sandbox\SafeOps-Test.wsb"
```

---

## 📧 Support

If tests fail, check:
1. `test-results.txt` for details
2. Run `go test ./[package] -v` manually
3. Check individual component logs

**All 13 components tested automatically in clean environment!** ✅
