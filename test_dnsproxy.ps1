# DNS Proxy Test Script
# Tests if dnsproxy on 127.0.0.1:15353 is responding

Write-Host "=== DNS Proxy Diagnostic Test ===" -ForegroundColor Cyan
Write-Host ""

# Test 1: Check if dnsproxy process is running
Write-Host "[1] Checking if dnsproxy is running..." -ForegroundColor Yellow
$dnsproxy = Get-Process -Name "dnsproxy" -ErrorAction SilentlyContinue
if ($dnsproxy) {
    Write-Host "    ✓ dnsproxy process found (PID: $($dnsproxy.Id))" -ForegroundColor Green
} else {
    Write-Host "    ✗ dnsproxy process NOT running" -ForegroundColor Red
    Write-Host "    Please start SafeOps Engine first" -ForegroundColor Yellow
    exit 1
}

# Test 2: Check if port 15353 is listening
Write-Host "[2] Checking if port 15353 is listening..." -ForegroundColor Yellow
$listener = Get-NetUDPEndpoint | Where-Object { $_.LocalPort -eq 15353 -and $_.LocalAddress -eq "127.0.0.1" }
if ($listener) {
    Write-Host "    ✓ Port 15353 is listening on 127.0.0.1" -ForegroundColor Green
} else {
    Write-Host "    ✗ Port 15353 NOT listening" -ForegroundColor Red
}

# Test 3: Test DNS resolution using PowerShell
Write-Host "[3] Testing DNS resolution through dnsproxy..." -ForegroundColor Yellow
Write-Host "    Querying: google.com" -ForegroundColor Gray

try {
    # Create UDP client
    $udpClient = New-Object System.Net.Sockets.UdpClient
    $udpClient.Client.ReceiveTimeout = 5000  # 5 second timeout

    # Connect to dnsproxy
    $udpClient.Connect("127.0.0.1", 15353)

    # Build simple DNS query for google.com (A record)
    # DNS query format: [Transaction ID:2][Flags:2][Questions:2][Answers:2][Authority:2][Additional:2][Query...]
    $query = [byte[]](
        0x12, 0x34,  # Transaction ID
        0x01, 0x00,  # Flags: standard query
        0x00, 0x01,  # Questions: 1
        0x00, 0x00,  # Answers: 0
        0x00, 0x00,  # Authority: 0
        0x00, 0x00,  # Additional: 0
        # Query: google.com
        0x06, # Length of "google"
        0x67, 0x6f, 0x6f, 0x67, 0x6c, 0x65,  # "google"
        0x03, # Length of "com"
        0x63, 0x6f, 0x6d,  # "com"
        0x00,  # End of name
        0x00, 0x01,  # Type: A
        0x00, 0x01   # Class: IN
    )

    # Send query
    $udpClient.Send($query, $query.Length) | Out-Null

    # Receive response
    $remoteEP = New-Object System.Net.IPEndPoint([System.Net.IPAddress]::Any, 0)
    $response = $udpClient.Receive([ref]$remoteEP)

    if ($response.Length -gt 12) {
        Write-Host "    ✓ DNS response received ($($response.Length) bytes)" -ForegroundColor Green

        # Parse response code
        $flags = ($response[2] -shl 8) -bor $response[3]
        $rcode = $flags -band 0x0F

        if ($rcode -eq 0) {
            Write-Host "    ✓ DNS resolution successful (NOERROR)" -ForegroundColor Green
        } else {
            Write-Host "    ! DNS returned error code: $rcode" -ForegroundColor Yellow
        }
    } else {
        Write-Host "    ✗ Invalid DNS response" -ForegroundColor Red
    }

    $udpClient.Close()

} catch {
    Write-Host "    ✗ DNS query failed: $($_.Exception.Message)" -ForegroundColor Red
    Write-Host "    This likely means dnsproxy is not responding" -ForegroundColor Yellow
}

# Test 4: Check upstream connectivity
Write-Host "[4] Checking upstream DNS connectivity..." -ForegroundColor Yellow
$upstreams = @("8.8.8.8", "1.1.1.1", "208.67.222.222")
foreach ($upstream in $upstreams) {
    $result = Test-Connection -ComputerName $upstream -Count 1 -Quiet
    if ($result) {
        Write-Host "    ✓ Can reach $upstream" -ForegroundColor Green
    } else {
        Write-Host "    ✗ Cannot reach $upstream" -ForegroundColor Red
    }
}

Write-Host ""
Write-Host "=== Test Complete ===" -ForegroundColor Cyan
Write-Host ""
Write-Host "If dnsproxy is not responding, try:" -ForegroundColor Yellow
Write-Host "  1. Check firewall settings" -ForegroundColor Gray
Write-Host "  2. Restart SafeOps Engine" -ForegroundColor Gray
Write-Host "  3. Check dnsproxy logs in engine output" -ForegroundColor Gray
