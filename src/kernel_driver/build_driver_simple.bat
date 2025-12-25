@echo off
setlocal

REM Set paths
set "MSVC_PATH=C:\Program Files\Microsoft Visual Studio\2022\Community\VC\Tools\MSVC\14.44.35207\bin\Hostx64\x64"
set "WDK_BIN=C:\Program Files (x86)\Windows Kits\10\bin\10.0.22621.0\x64"
set "PATH=%MSVC_PATH%;%WDK_BIN%;%PATH%"

REM Navigate to kernel driver directory
cd /d "%~dp0"

REM Run nmake
"%MSVC_PATH%\nmake.exe" BUILD=release

exit /b %ERRORLEVEL%
