@echo off
echo ========================================
echo SafeOps Network Logger - Build Script
echo ========================================
echo.

REM Set Npcap SDK path
set NPCAP_SDK=..\..\npcap-sdk-1.16
set CGO_ENABLED=1

REM Check if Npcap SDK exists
if not exist "%NPCAP_SDK%" (
    echo [ERROR] Npcap SDK not found at: %NPCAP_SDK%
    echo Please ensure the Npcap SDK is available.
    exit /b 1
)

echo [INFO] Using Npcap SDK: %NPCAP_SDK%
echo.

REM Create bin directory
if not exist "bin" mkdir bin

REM Build application
echo [BUILD] Compiling SafeOps Network Logger...
go build -ldflags="-s -w" -o bin\safeops-logger.exe cmd\logger\main.go

if %ERRORLEVEL% == 0 (
    echo.
    echo ========================================
    echo [SUCCESS] Build completed!
    echo ========================================
    echo.
    echo Executable: bin\safeops-logger.exe
    echo.
    echo To list interfaces:
    echo   bin\safeops-logger.exe -list-interfaces
    echo.
    echo To start capturing:
    echo   bin\safeops-logger.exe
    echo.
    echo NOTE: Requires Administrator privileges
    echo.
) else (
    echo.
    echo [ERROR] Build failed!
    exit /b 1
)
