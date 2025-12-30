// Package portal provides captive portal templates.
package portal

// indexTemplate is the main portal landing page.
const indexTemplate = `<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>{{.Title}}</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body {
            font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Arial, sans-serif;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            min-height: 100vh;
            display: flex;
            align-items: center;
            justify-content: center;
            padding: 20px;
        }
        .container {
            background: white;
            border-radius: 20px;
            box-shadow: 0 20px 60px rgba(0,0,0,0.3);
            max-width: 600px;
            width: 100%;
            padding: 40px;
            text-align: center;
        }
        .logo {
            width: 80px;
            height: 80px;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            border-radius: 50%;
            margin: 0 auto 20px;
            display: flex;
            align-items: center;
            justify-center;
            color: white;
            font-size: 36px;
            font-weight: bold;
        }
        h1 {
            color: #333;
            margin-bottom: 10px;
            font-size: 28px;
        }
        .org-name {
            color: #667eea;
            font-size: 18px;
            margin-bottom: 20px;
        }
        .message {
            color: #666;
            font-size: 16px;
            line-height: 1.6;
            margin-bottom: 30px;
        }
        .cta-button {
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            border: none;
            padding: 15px 40px;
            font-size: 18px;
            border-radius: 50px;
            cursor: pointer;
            text-decoration: none;
            display: inline-block;
            transition: transform 0.2s, box-shadow 0.2s;
        }
        .cta-button:hover {
            transform: translateY(-2px);
            box-shadow: 0 10px 20px rgba(102,126,234,0.4);
        }
        .footer {
            margin-top: 30px;
            padding-top: 20px;
            border-top: 1px solid #eee;
            color: #999;
            font-size: 14px;
        }
    </style>
</head>
<body>
    <div class="container">
        <div class="logo">🔒</div>
        <h1>{{.Title}}</h1>
        <div class="org-name">{{.Organization}}</div>
        <div class="message">{{.Message}}</div>
        <a href="{{.CASetupURL}}" class="cta-button">Get Started</a>
        <div class="footer">
            Secure network powered by SafeOps
        </div>
    </div>
</body>
</html>`

// caSetupTemplate is the CA certificate installation guide page.
const caSetupTemplate = `<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>{{.Title}}</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body {
            font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Arial, sans-serif;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            min-height: 100vh;
            padding: 20px;
        }
        .container {
            background: white;
            border-radius: 20px;
            box-shadow: 0 20px 60px rgba(0,0,0,0.3);
            max-width: 800px;
            width: 100%;
            margin: 0 auto;
            padding: 40px;
        }
        .header {
            text-align: center;
            margin-bottom: 40px;
        }
        .logo {
            width: 60px;
            height: 60px;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            border-radius: 50%;
            margin: 0 auto 15px;
            display: flex;
            align-items: center;
            justify-content: center;
            color: white;
            font-size: 28px;
        }
        h1 {
            color: #333;
            font-size: 24px;
            margin-bottom: 10px;
        }
        .org-name {
            color: #667eea;
            font-size: 16px;
        }
        .section {
            margin-bottom: 30px;
            padding: 20px;
            background: #f8f9fa;
            border-radius: 12px;
        }
        .section h2 {
            color: #333;
            font-size: 20px;
            margin-bottom: 15px;
            display: flex;
            align-items: center;
        }
        .section h2::before {
            content: "📋";
            margin-right: 10px;
            font-size: 24px;
        }
        .steps {
            list-style: none;
            counter-reset: step;
        }
        .steps li {
            counter-increment: step;
            margin-bottom: 15px;
            padding-left: 40px;
            position: relative;
            line-height: 1.6;
        }
        .steps li::before {
            content: counter(step);
            position: absolute;
            left: 0;
            top: 0;
            width: 28px;
            height: 28px;
            background: #667eea;
            color: white;
            border-radius: 50%;
            display: flex;
            align-items: center;
            justify-content: center;
            font-weight: bold;
            font-size: 14px;
        }
        .download-button {
            background: #28a745;
            color: white;
            border: none;
            padding: 12px 30px;
            font-size: 16px;
            border-radius: 8px;
            cursor: pointer;
            text-decoration: none;
            display: inline-block;
            margin: 10px 5px;
            transition: background 0.2s;
        }
        .download-button:hover {
            background: #218838;
        }
        .qr-code {
            text-align: center;
            margin: 20px 0;
        }
        .qr-code img {
            max-width: 200px;
            border: 2px solid #ddd;
            border-radius: 8px;
            padding: 10px;
            background: white;
        }
        .info-box {
            background: #e7f3ff;
            border-left: 4px solid #2196F3;
            padding: 15px;
            margin: 15px 0;
            border-radius: 4px;
        }
        .warning-box {
            background: #fff3cd;
            border-left: 4px solid #ffc107;
            padding: 15px;
            margin: 15px 0;
            border-radius: 4px;
        }
        code {
            background: #f4f4f4;
            padding: 2px 6px;
            border-radius: 4px;
            font-family: 'Courier New', monospace;
        }
        .footer {
            text-align: center;
            margin-top: 30px;
            padding-top: 20px;
            border-top: 1px solid #eee;
            color: #999;
            font-size: 14px;
        }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <div class="logo">🔐</div>
            <h1>Security Certificate Setup</h1>
            <div class="org-name">{{.Organization}}</div>
        </div>

        <div class="info-box">
            <strong>Why do I need this?</strong><br>
            To access secure services on this network, you need to trust the network's security certificate.
            This is a one-time setup that ensures your device can securely communicate with network services.
        </div>

        <!-- Quick Download Section -->
        <div class="section">
            <h2>Quick Download</h2>
            <div style="text-align: center;">
                <a href="{{.CACertURL}}" class="download-button" download>📥 Download Certificate</a>
                <a href="{{.TrustGuideURL}}" class="download-button">📖 View Guide</a>
            </div>
        </div>

        {{if .ShowiOSSteps}}
        <!-- iOS/iPadOS Steps -->
        <div class="section">
            <h2>iOS/iPadOS Setup</h2>
            <div class="qr-code">
                <p>Scan this QR code with your camera:</p>
                <img src="{{.QRCodeURL}}" alt="QR Code">
            </div>
            <p style="text-align: center; margin: 20px 0;"><strong>OR</strong></p>
            <ol class="steps">
                <li>Download the <a href="{{.MobileConfigURL}}">iOS Configuration Profile</a></li>
                <li>Open <strong>Settings</strong> → <strong>Profile Downloaded</strong></li>
                <li>Tap <strong>Install</strong> (enter passcode if prompted)</li>
                <li>Tap <strong>Install</strong> again to confirm</li>
                <li>Go to <strong>Settings</strong> → <strong>General</strong> → <strong>About</strong> → <strong>Certificate Trust Settings</strong></li>
                <li>Enable full trust for the certificate</li>
            </ol>
        </div>
        {{end}}

        {{if .ShowAndroidSteps}}
        <!-- Android Steps -->
        <div class="section">
            <h2>Android Setup</h2>
            <ol class="steps">
                <li>Download the <a href="{{.CACertURL}}">certificate file</a></li>
                <li>Open <strong>Settings</strong> → <strong>Security</strong> → <strong>Encryption & credentials</strong></li>
                <li>Tap <strong>Install a certificate</strong> → <strong>CA certificate</strong></li>
                <li>Tap <strong>Install anyway</strong> if warned</li>
                <li>Navigate to your Downloads folder and select the certificate file</li>
                <li>Give it a name like "SafeOps Network CA"</li>
            </ol>
        </div>
        {{end}}

        {{if .ShowWindowsSteps}}
        <!-- Windows Steps -->
        <div class="section">
            <h2>Windows Setup</h2>
            <div style="text-align: center; margin-bottom: 20px;">
                <a href="{{.InstallScriptURL}}" class="download-button">📥 Download PowerShell Script</a>
            </div>
            <ol class="steps">
                <li>Download the <a href="{{.CACertURL}}">certificate file</a></li>
                <li>Right-click the certificate file and select <strong>Install Certificate</strong></li>
                <li>Select <strong>Local Machine</strong> → Click <strong>Next</strong></li>
                <li>Select <strong>Place all certificates in the following store</strong></li>
                <li>Click <strong>Browse</strong> and select <strong>Trusted Root Certification Authorities</strong></li>
                <li>Click <strong>Next</strong> → <strong>Finish</strong></li>
            </ol>
            <div class="info-box">
                <strong>Alternative:</strong> Run the PowerShell script as Administrator for automatic installation
            </div>
        </div>
        {{end}}

        {{if .ShowMacSteps}}
        <!-- macOS Steps -->
        <div class="section">
            <h2>macOS Setup</h2>
            <ol class="steps">
                <li>Download the <a href="{{.CACertURL}}">certificate file</a></li>
                <li>Double-click the downloaded certificate</li>
                <li>In Keychain Access, select <strong>System</strong> keychain</li>
                <li>Click <strong>Add</strong></li>
                <li>Enter your password when prompted</li>
                <li>Find the certificate in the list and double-click it</li>
                <li>Expand <strong>Trust</strong> and set to <strong>Always Trust</strong></li>
                <li>Close the window and enter your password again</li>
            </ol>
        </div>
        {{end}}

        {{if .ShowLinuxSteps}}
        <!-- Linux Steps -->
        <div class="section">
            <h2>Linux Setup</h2>
            <div style="text-align: center; margin-bottom: 20px;">
                <a href="{{.InstallScriptURL}}" class="download-button">📥 Download Install Script</a>
            </div>
            <ol class="steps">
                <li>Download the <a href="{{.CACertURL}}">certificate file</a> or run the script above</li>
                <li>Open a terminal and run:<br>
                    <code>sudo cp ~/Downloads/safeops-root-ca.crt /usr/local/share/ca-certificates/</code>
                </li>
                <li>Update the certificate store:<br>
                    <code>sudo update-ca-certificates</code>
                </li>
                <li>Verify installation:<br>
                    <code>ls /etc/ssl/certs/ | grep safeops</code>
                </li>
            </ol>
        </div>
        {{end}}

        <div class="warning-box">
            <strong>⚠️ Important:</strong> Only install certificates from networks you trust.
            This certificate allows the network to inspect secure traffic for security purposes.
        </div>

        <div class="footer">
            Detected OS: <strong>{{.OSType}}</strong> | Your IP: <strong>{{.ClientIP}}</strong><br>
            Need help? Visit the <a href="{{.TrustGuideURL}}">complete trust guide</a>
        </div>
    </div>
</body>
</html>`
