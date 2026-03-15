# Kill any SafeOps-related processes
Get-Process | Where-Object { $_.Path -and ($_.Path -like '*SafeOps*' -or $_.Path -like '*safeops*') } | ForEach-Object {
    Write-Host "Killing PID=$($_.Id) Name=$($_.Name)"
    Stop-Process -Id $_.Id -Force -ErrorAction SilentlyContinue
}
Start-Sleep 3
# Delete the locked file
$target = 'D:\SafeOpsFV2\safeops-app\build\bin\SafeOps.exe'
if (Test-Path $target) {
    Remove-Item $target -Force -ErrorAction SilentlyContinue
}
Write-Host "Ready to build"
