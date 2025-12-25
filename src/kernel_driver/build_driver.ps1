# SafeOps Kernel Driver Build Script (PowerShell)

$ErrorActionPreference = "Continue"

# Set paths
$MSVC_PATH = "C:\Program Files\Microsoft Visual Studio\2022\Community\VC\Tools\MSVC\14.44.35207\bin\Hostx64\x64"
$WDK_BIN = "C:\Program Files (x86)\Windows Kits\10\bin\10.0.22621.0\x64"
$env:Path = "$MSVC_PATH;$WDK_BIN;" + $env:Path

# Navigate to kernel driver directory
Set-Location "D:\SafeOpsFV2\src\kernel_driver"

# Run nmake
Write-Host "Starting build process..."
Write-Host "MSVC Path: $MSVC_PATH"
Write-Host "WDK Bin: $WDK_BIN"
Write-Host ""

& "$MSVC_PATH\nmake.exe" BUILD=release

$exitCode = $LASTEXITCODE
Write-Host ""
if ($exitCode -eq 0) {
    Write-Host "Build completed successfully!"

    # Check for output file
    $sysFile = "D:\SafeOpsFV2\build\driver\release\x64\SafeOps.sys"
    if (Test-Path $sysFile) {
        $fileSize = (Get-Item $sysFile).Length
        Write-Host "Driver file created: $sysFile"
        Write-Host "File size: $fileSize bytes"
    }
} else {
    Write-Host "Build failed with exit code: $exitCode"
}

exit $exitCode
