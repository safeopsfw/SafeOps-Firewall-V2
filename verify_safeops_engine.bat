@echo off
echo ========================================
echo  SafeOps Engine - Verification Script
echo ========================================
echo.

echo [1/5] Checking Go installation...
go version >nul 2>&1
if %ERRORLEVEL% neq 0 (
    echo ❌ Go not found! Install Go 1.21+
    pause
    exit /b 1
)
go version
echo ✅ Go installed
echo.

echo [2/5] Checking WinpkFilter driver...
sc query ndisrd | find "RUNNING" >nul 2>&1
if %ERRORLEVEL% neq 0 (
    echo ❌ WinpkFilter driver not running!
    echo    Run: sc start ndisrd
    echo    Or install from: https://www.ntkernel.com/downloads/
    pause
    exit /b 1
)
echo ✅ WinpkFilter driver is running
echo.

echo [3/5] Checking binary...
if not exist "bin\safeops-engine.exe" (
    echo ❌ Binary not found!
    echo    Run: cd src\safeops-engine
    echo         build.bat
    pause
    exit /b 1
)
echo ✅ Binary found: bin\safeops-engine.exe
dir bin\safeops-engine.exe | find "safeops-engine.exe"
echo.

echo [4/5] Checking configuration...
if not exist "src\safeops-engine\configs\engine.yaml" (
    echo ❌ Config file not found!
    pause
    exit /b 1
)
echo ✅ Config file found
echo.

echo [5/5] Checking Administrator privileges...
net session >nul 2>&1
if %ERRORLEVEL% neq 0 (
    echo ⚠️  NOT running as Administrator!
    echo    Right-click this script → "Run as Administrator"
    echo.
    echo    SafeOps Engine MUST run as Administrator
    pause
    exit /b 1
)
echo ✅ Running as Administrator
echo.

echo ========================================
echo  ✅ ALL CHECKS PASSED!
echo ========================================
echo.
echo SafeOps Engine is ready to run:
echo.
echo   cd bin
echo   safeops-engine.exe
echo.
echo IMPORTANT:
echo   - Internet will NEVER break (failsafe mode)
echo   - ALL UDP bypassed (Discord/gaming work)
echo   - Press Ctrl+C to stop
echo.

pause
