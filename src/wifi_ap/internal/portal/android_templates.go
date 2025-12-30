// Package portal provides Android-specific templates.
package portal

// androidSetupTemplate is the Android-optimized setup page.
const androidSetupTemplate = `<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0, maximum-scale=1.0, user-scalable=no">
    <title>{{.Title}}</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body {
            font-family: "Roboto", -apple-system, BlinkMacSystemFont, "Segoe UI", Arial, sans-serif;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            min-height: 100vh;
            padding: 10px;
        }
        .container {
            background: white;
            border-radius: 16px;
            box-shadow: 0 20px 60px rgba(0,0,0,0.3);
            max-width: 500px;
            width: 100%;
            margin: 0 auto;
            padding: 20px;
        }
        .header {
            text-align: center;
            margin-bottom: 24px;
            padding-bottom: 20px;
            border-bottom: 2px solid #f0f0f0;
        }
        .logo {
            width: 60px;
            height: 60px;
            background: linear-gradient(135deg, #3DDC84 0%, #689F38 100%);
            border-radius: 50%;
            margin: 0 auto 12px;
            display: flex;
            align-items: center;
            justify-content: center;
            font-size: 32px;
        }
        h1 {
            color: #333;
            font-size: 22px;
            margin-bottom: 8px;
            font-weight: 500;
        }
        .subtitle {
            color: #3DDC84;
            font-size: 16px;
            font-weight: 500;
        }
        .big-button {
            background: linear-gradient(135deg, #3DDC84 0%, #689F38 100%);
            color: white;
            border: none;
            padding: 18px;
            font-size: 18px;
            font-weight: 500;
            border-radius: 12px;
            cursor: pointer;
            text-decoration: none;
            display: block;
            margin: 20px 0;
            text-align: center;
            box-shadow: 0 4px 12px rgba(61, 220, 132, 0.4);
            transition: transform 0.2s;
        }
        .big-button:active {
            transform: scale(0.98);
        }
        .qr-section {
            background: #f8f9fa;
            border-radius: 12px;
            padding: 20px;
            margin: 20px 0;
            text-align: center;
        }
        .qr-section img {
            max-width: 200px;
            width: 100%;
            border: 3px solid white;
            border-radius: 12px;
            box-shadow: 0 4px 12px rgba(0,0,0,0.1);
        }
        .steps {
            list-style: none;
            counter-reset: step;
            margin: 20px 0;
        }
        .steps li {
            counter-increment: step;
            margin-bottom: 16px;
            padding: 12px;
            padding-left: 50px;
            position: relative;
            background: #f8f9fa;
            border-radius: 8px;
            line-height: 1.5;
        }
        .steps li::before {
            content: counter(step);
            position: absolute;
            left: 12px;
            top: 50%;
            transform: translateY(-50%);
            width: 28px;
            height: 28px;
            background: #3DDC84;
            color: white;
            border-radius: 50%;
            display: flex;
            align-items: center;
            justify-content: center;
            font-weight: bold;
            font-size: 14px;
        }
        .info-box {
            background: #E3F2FD;
            border-left: 4px solid #2196F3;
            padding: 12px;
            margin: 16px 0;
            border-radius: 4px;
            font-size: 14px;
        }
        .warning-box {
            background: #FFF3E0;
            border-left: 4px solid #FF9800;
            padding: 12px;
            margin: 16px 0;
            border-radius: 4px;
            font-size: 14px;
        }
        .emoji {
            font-size: 24px;
            display: inline-block;
            margin-right: 8px;
        }
        .divider {
            text-align: center;
            margin: 24px 0;
            position: relative;
        }
        .divider::before {
            content: "";
            position: absolute;
            top: 50%;
            left: 0;
            right: 0;
            height: 1px;
            background: #e0e0e0;
        }
        .divider span {
            background: white;
            padding: 0 16px;
            position: relative;
            color: #666;
            font-weight: 500;
        }
        .method-card {
            border: 2px solid #e0e0e0;
            border-radius: 12px;
            padding: 16px;
            margin: 12px 0;
        }
        .method-card h3 {
            color: #333;
            font-size: 16px;
            margin-bottom: 8px;
            display: flex;
            align-items: center;
        }
        code {
            background: #f4f4f4;
            padding: 2px 6px;
            border-radius: 4px;
            font-family: 'Courier New', monospace;
            font-size: 13px;
        }
        strong {
            color: #333;
            font-weight: 600;
        }
        .footer {
            text-align: center;
            margin-top: 24px;
            padding-top: 16px;
            border-top: 1px solid #e0e0e0;
            color: #666;
            font-size: 13px;
        }
        .version-badge {
            display: inline-block;
            background: #e0e0e0;
            padding: 4px 12px;
            border-radius: 12px;
            font-size: 12px;
            margin-top: 8px;
        }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <div class="logo">🤖</div>
            <h1>Android Certificate Setup</h1>
            <div class="subtitle">{{.Organization}}</div>
        </div>

        <div class="info-box">
            <strong>📱 Quick Setup:</strong> This certificate allows your Android device to securely access network services.
            Installation takes less than 1 minute!
        </div>

        <!-- Method 1: One-Tap Install (Easiest) -->
        <div class="method-card">
            <h3><span class="emoji">⚡</span>Method 1: One-Tap Install</h3>
            <p style="margin: 8px 0; color: #666; font-size: 14px;">Recommended for Android 11+</p>
            <a href="/android/install" class="big-button">
                📥 Download & Install Certificate
            </a>
        </div>

        <div class="divider"><span>OR</span></div>

        <!-- Method 2: QR Code (For another device to help) -->
        <div class="qr-section">
            <h3 style="margin-bottom: 16px;"><span class="emoji">📷</span>Scan with Another Device</h3>
            <img src="{{.QRCodeURL}}" alt="QR Code">
            <p style="margin-top: 12px; color: #666; font-size: 14px;">
                Use another phone's camera to scan and send the link to this device
            </p>
        </div>

        <div class="divider"><span>OR</span></div>

        <!-- Method 3: Manual Installation -->
        <div class="method-card">
            <h3><span class="emoji">🔧</span>Method 3: Manual Installation</h3>

            <div style="margin: 16px 0;">
                <a href="{{.CACertURL}}" class="big-button" download>
                    📥 Download Certificate File
                </a>
            </div>

            <p style="font-weight: 600; margin: 16px 0;">Follow these steps:</p>
            <ol class="steps">
                <li>Download the certificate file using the button above</li>
                <li>Open <strong>Settings</strong> app</li>
                <li>Go to <strong>Security</strong> or <strong>Security & Privacy</strong></li>
                <li>Tap <strong>Encryption & credentials</strong></li>
                <li>Tap <strong>Install a certificate</strong></li>
                <li>Select <strong>CA certificate</strong></li>
                <li>Tap <strong>Install anyway</strong> if warned</li>
                <li>Navigate to <strong>Downloads</strong> folder</li>
                <li>Select <strong>SafeOps-CA.crt</strong></li>
                <li>Name it "SafeOps Network" and tap <strong>OK</strong></li>
            </ol>
        </div>

        <!-- Android Version Specific Notes -->
        <div class="warning-box">
            <strong>⚠️ Important Notes:</strong>
            <ul style="margin: 8px 0 0 20px; line-height: 1.6;">
                <li><strong>Android 11+:</strong> User certificates work for most apps</li>
                <li><strong>Android 14+:</strong> Some apps may require system-level trust</li>
                <li><strong>Chrome/Firefox:</strong> User certificates are automatically trusted</li>
            </ul>
        </div>

        <!-- Verification Section -->
        <div class="method-card" style="background: #E8F5E9; border-color: #4CAF50;">
            <h3><span class="emoji">✅</span>Verify Installation</h3>
            <p style="margin: 8px 0; color: #333;">After installing, check if it worked:</p>
            <ol style="margin: 12px 0 0 20px; line-height: 1.8;">
                <li>Go to <strong>Settings → Security → Trusted credentials</strong></li>
                <li>Tap <strong>USER</strong> tab</li>
                <li>Look for <strong>SafeOps Network</strong> or <strong>{{.Organization}}</strong></li>
            </ol>
            <a href="/android/verify" style="display: inline-block; margin-top: 12px; color: #2196F3; text-decoration: none; font-weight: 500;">
                → Test Certificate Installation
            </a>
        </div>

        <!-- Android Version Detection -->
        <div class="info-box" style="background: #F3E5F5; border-color: #9C27B0;">
            <strong>💡 Pro Tip:</strong> Save this page to your home screen for easy access later!
            <br><br>
            Chrome: Menu (⋮) → Add to Home screen
        </div>

        <div class="footer">
            Your IP: <strong>{{.ClientIP}}</strong><br>
            <div class="version-badge">Android Optimized</div>
        </div>
    </div>

    <script>
        // Detect Android version and show relevant tips
        const userAgent = navigator.userAgent;
        const androidVersion = userAgent.match(/Android (\d+)/);

        if (androidVersion && parseInt(androidVersion[1]) >= 14) {
            console.log('Android 14+ detected');
            // Could show additional warnings for Android 14+
        }

        // Track download attempts
        document.querySelectorAll('a[download]').forEach(link => {
            link.addEventListener('click', function() {
                console.log('Certificate download initiated');
                // Could send analytics event here
            });
        });
    </script>
</body>
</html>`

// androidVerifyTemplate helps users verify certificate installation.
const androidVerifyTemplate = `<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Verify Certificate - {{.Title}}</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body {
            font-family: "Roboto", -apple-system, BlinkMacSystemFont, "Segoe UI", Arial, sans-serif;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            min-height: 100vh;
            padding: 20px;
        }
        .container {
            background: white;
            border-radius: 16px;
            box-shadow: 0 20px 60px rgba(0,0,0,0.3);
            max-width: 500px;
            width: 100%;
            margin: 0 auto;
            padding: 30px;
        }
        .header {
            text-align: center;
            margin-bottom: 30px;
        }
        .status-indicator {
            width: 80px;
            height: 80px;
            border-radius: 50%;
            margin: 0 auto 20px;
            display: flex;
            align-items: center;
            justify-content: center;
            font-size: 40px;
        }
        .status-success {
            background: linear-gradient(135deg, #4CAF50 0%, #388E3C 100%);
            animation: pulse 2s infinite;
        }
        .status-pending {
            background: linear-gradient(135deg, #FF9800 0%, #F57C00 100%);
        }
        @keyframes pulse {
            0%, 100% { transform: scale(1); }
            50% { transform: scale(1.05); }
        }
        h1 {
            color: #333;
            font-size: 24px;
            margin-bottom: 10px;
        }
        .test-section {
            background: #f8f9fa;
            border-radius: 12px;
            padding: 20px;
            margin: 20px 0;
        }
        .test-button {
            background: #2196F3;
            color: white;
            border: none;
            padding: 15px;
            font-size: 16px;
            font-weight: 500;
            border-radius: 8px;
            cursor: pointer;
            width: 100%;
            margin: 10px 0;
        }
        .result {
            margin-top: 20px;
            padding: 15px;
            border-radius: 8px;
            display: none;
        }
        .result.success {
            background: #E8F5E9;
            border: 2px solid #4CAF50;
            color: #2E7D32;
        }
        .result.error {
            background: #FFEBEE;
            border: 2px solid #F44336;
            color: #C62828;
        }
        .back-link {
            text-align: center;
            margin-top: 20px;
        }
        .back-link a {
            color: #2196F3;
            text-decoration: none;
            font-weight: 500;
        }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <div class="status-indicator status-pending" id="statusIndicator">
                ⏳
            </div>
            <h1>Certificate Verification</h1>
            <p style="color: #666;">Let's check if the certificate is properly installed</p>
        </div>

        <div class="test-section">
            <h3 style="margin-bottom: 15px;">Automatic Test</h3>
            <p style="color: #666; margin-bottom: 15px;">
                This will make a secure connection to verify the certificate is trusted.
            </p>
            <button class="test-button" onclick="testCertificate()">
                🔍 Test Certificate Now
            </button>
            <div id="result" class="result"></div>
        </div>

        <div class="test-section">
            <h3 style="margin-bottom: 15px;">Manual Verification</h3>
            <ol style="margin-left: 20px; line-height: 1.8; color: #333;">
                <li>Open <strong>Settings</strong></li>
                <li>Go to <strong>Security → Trusted credentials</strong></li>
                <li>Tap <strong>USER</strong> tab</li>
                <li>Look for <strong>{{.Organization}}</strong></li>
                <li>Tap it to view details</li>
            </ol>
        </div>

        <div class="back-link">
            <a href="/android/setup">← Back to Setup</a> |
            <a href="/">Home</a>
        </div>
    </div>

    <script>
        async function testCertificate() {
            const resultDiv = document.getElementById('result');
            const statusIndicator = document.getElementById('statusIndicator');

            resultDiv.style.display = 'block';
            resultDiv.className = 'result';
            resultDiv.innerHTML = '⏳ Testing certificate...';

            try {
                // Test HTTPS connection to the network
                const response = await fetch('https://192.168.1.1/health', {
                    method: 'GET',
                    cache: 'no-cache'
                });

                if (response.ok) {
                    // Certificate is trusted!
                    resultDiv.className = 'result success';
                    resultDiv.innerHTML = '✅ <strong>Success!</strong> Certificate is properly installed and trusted.';
                    statusIndicator.className = 'status-indicator status-success';
                    statusIndicator.innerHTML = '✅';
                } else {
                    throw new Error('Connection failed');
                }
            } catch (error) {
                // Certificate not trusted or connection failed
                resultDiv.className = 'result error';
                resultDiv.innerHTML = `
                    ❌ <strong>Not Yet Installed</strong><br>
                    <small>The certificate doesn't appear to be trusted yet. Please install it following the setup guide.</small>
                `;
            }
        }

        // Auto-test on page load after 1 second
        setTimeout(testCertificate, 1000);
    </script>
</body>
</html>`
