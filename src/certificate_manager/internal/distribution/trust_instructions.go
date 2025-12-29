package distribution

import (
	"bytes"
	"fmt"
	"html/template"
	"strings"
	"time"
)

// ============================================================================
// Configuration Types
// ============================================================================

// TrustInstructionsConfig contains configuration for generating trust instructions.
type TrustInstructionsConfig struct {
	BaseURL          string // HTTP server base URL (e.g., "http://192.168.1.1")
	OrganizationName string // Organization name
	CACommonName     string // CA common name
	SupportEmail     string // Support email address
	Title            string // Page title
	ShowQRCodes      bool   // Whether to show QR codes
	PrivacyPolicyURL string // Privacy policy URL (optional)
}

// Platform represents supported platforms.
type Platform string

const (
	PlatformWindows Platform = "windows"
	PlatformMacOS   Platform = "macos"
	PlatformLinux   Platform = "linux"
	PlatformiOS     Platform = "ios"
	PlatformAndroid Platform = "android"
	PlatformFirefox Platform = "firefox"
	PlatformChrome  Platform = "chrome"
)

// ============================================================================
// Trust Guide HTML Template
// ============================================================================

const trustGuideTemplate = `<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>{{.Title}}</title>
    <style>
        :root {
            --primary: #2563eb;
            --primary-dark: #1d4ed8;
            --success: #22c55e;
            --warning: #f59e0b;
            --danger: #ef4444;
            --bg: #f8fafc;
            --card-bg: #ffffff;
            --text: #1e293b;
            --text-muted: #64748b;
            --border: #e2e8f0;
            --code-bg: #1e293b;
        }
        * { box-sizing: border-box; margin: 0; padding: 0; }
        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
            background: var(--bg);
            color: var(--text);
            line-height: 1.6;
            padding: 20px;
        }
        .container { max-width: 900px; margin: 0 auto; }
        header {
            text-align: center;
            padding: 40px 20px;
            background: linear-gradient(135deg, var(--primary), var(--primary-dark));
            color: white;
            border-radius: 16px;
            margin-bottom: 30px;
        }
        header h1 { font-size: 2em; margin-bottom: 10px; }
        header p { opacity: 0.9; }
        .warning-box {
            background: #fef3c7;
            border-left: 4px solid var(--warning);
            padding: 15px 20px;
            border-radius: 8px;
            margin-bottom: 25px;
        }
        .warning-box h3 { color: #92400e; margin-bottom: 8px; }
        .warning-box p { color: #78350f; }
        .platform-tabs {
            display: flex;
            flex-wrap: wrap;
            gap: 10px;
            margin-bottom: 25px;
            border-bottom: 2px solid var(--border);
            padding-bottom: 15px;
        }
        .tab-btn {
            padding: 10px 20px;
            background: var(--card-bg);
            border: 1px solid var(--border);
            border-radius: 8px;
            cursor: pointer;
            font-size: 14px;
            transition: all 0.2s;
        }
        .tab-btn:hover { border-color: var(--primary); }
        .tab-btn.active {
            background: var(--primary);
            color: white;
            border-color: var(--primary);
        }
        .platform-content { display: none; }
        .platform-content.active { display: block; }
        .card {
            background: var(--card-bg);
            border-radius: 12px;
            padding: 25px;
            margin-bottom: 20px;
            box-shadow: 0 1px 3px rgba(0,0,0,0.1);
        }
        .card h2 {
            font-size: 1.5em;
            margin-bottom: 20px;
            display: flex;
            align-items: center;
            gap: 10px;
        }
        .step {
            display: flex;
            gap: 15px;
            margin-bottom: 20px;
            padding-bottom: 20px;
            border-bottom: 1px solid var(--border);
        }
        .step:last-child { border-bottom: none; padding-bottom: 0; margin-bottom: 0; }
        .step-number {
            width: 32px;
            height: 32px;
            background: var(--primary);
            color: white;
            border-radius: 50%;
            display: flex;
            align-items: center;
            justify-content: center;
            font-weight: bold;
            flex-shrink: 0;
        }
        .step-content { flex: 1; }
        .step-content h4 { margin-bottom: 8px; }
        .code-block {
            background: var(--code-bg);
            color: #e2e8f0;
            padding: 15px;
            border-radius: 8px;
            font-family: 'Monaco', 'Consolas', monospace;
            font-size: 13px;
            overflow-x: auto;
            position: relative;
            margin: 10px 0;
        }
        .copy-btn {
            position: absolute;
            top: 8px;
            right: 8px;
            background: var(--primary);
            color: white;
            border: none;
            padding: 5px 12px;
            border-radius: 4px;
            cursor: pointer;
            font-size: 12px;
        }
        .copy-btn:hover { background: var(--primary-dark); }
        .download-section {
            background: #f0fdf4;
            border: 1px solid #bbf7d0;
            padding: 20px;
            border-radius: 8px;
            text-align: center;
            margin: 20px 0;
        }
        .download-btn {
            display: inline-block;
            background: var(--success);
            color: white;
            padding: 12px 30px;
            border-radius: 8px;
            text-decoration: none;
            font-weight: 600;
            margin: 5px;
        }
        .download-btn:hover { background: #16a34a; }
        .qr-code { max-width: 200px; margin: 15px auto; }
        .qr-code img { width: 100%; }
        .fingerprint {
            background: #f1f5f9;
            padding: 12px;
            border-radius: 8px;
            font-family: monospace;
            font-size: 11px;
            word-break: break-all;
            margin: 15px 0;
        }
        .troubleshooting {
            background: #fef2f2;
            border-left: 4px solid var(--danger);
            padding: 15px 20px;
            border-radius: 8px;
            margin-top: 20px;
        }
        .troubleshooting h4 { color: #991b1b; margin-bottom: 10px; }
        footer {
            text-align: center;
            padding: 30px;
            color: var(--text-muted);
            font-size: 14px;
        }
        @media (max-width: 600px) {
            .platform-tabs { justify-content: center; }
            .tab-btn { padding: 8px 15px; font-size: 12px; }
            .step { flex-direction: column; }
            header h1 { font-size: 1.5em; }
        }
    </style>
</head>
<body>
    <div class="container">
        <header>
            <h1>🔐 {{.Title}}</h1>
            <p>Install the {{.CACommonName}} certificate to enable secure network access</p>
        </header>

        <div class="warning-box">
            <h3>⚠️ Security Notice</h3>
            <p>This root CA certificate is for devices on the <strong>{{.OrganizationName}}</strong> network only. 
               Installing this certificate allows the network to inspect encrypted HTTPS traffic for security purposes.
               Remove this certificate when leaving the network.</p>
        </div>

        <div class="download-section">
            <h3>Quick Download</h3>
            <a href="{{.BaseURL}}/ca.crt" class="download-btn">📄 Download Certificate (PEM)</a>
            <a href="{{.BaseURL}}/ca.der" class="download-btn">📄 Download Certificate (DER)</a>
            {{if .ShowQRCodes}}
            <div class="qr-code">
                <img src="{{.BaseURL}}/ca-qr-code.png" alt="QR Code">
                <p style="font-size: 12px; color: #666;">Scan with your phone</p>
            </div>
            {{end}}
        </div>

        <div class="platform-tabs">
            <button class="tab-btn active" onclick="showPlatform('windows')">🪟 Windows</button>
            <button class="tab-btn" onclick="showPlatform('macos')">🍎 macOS</button>
            <button class="tab-btn" onclick="showPlatform('linux')">🐧 Linux</button>
            <button class="tab-btn" onclick="showPlatform('ios')">📱 iOS</button>
            <button class="tab-btn" onclick="showPlatform('android')">🤖 Android</button>
            <button class="tab-btn" onclick="showPlatform('firefox')">🦊 Firefox</button>
        </div>

        <!-- Windows Instructions -->
        <div id="windows" class="platform-content active">
            <div class="card">
                <h2>🪟 Windows Installation</h2>
                
                <div class="step">
                    <div class="step-number">1</div>
                    <div class="step-content">
                        <h4>Download the Certificate</h4>
                        <p>Download the CA certificate file:</p>
                        <div class="code-block">
                            <button class="copy-btn" onclick="copyCode(this)">Copy</button>
                            curl -o safeops-ca.crt {{.BaseURL}}/ca.crt
                        </div>
                        <p>Or click the download button above.</p>
                    </div>
                </div>

                <div class="step">
                    <div class="step-number">2</div>
                    <div class="step-content">
                        <h4>Install Certificate (PowerShell - Recommended)</h4>
                        <p>Run PowerShell as Administrator and execute:</p>
                        <div class="code-block">
                            <button class="copy-btn" onclick="copyCode(this)">Copy</button>
Import-Certificate -FilePath .\safeops-ca.crt -CertStoreLocation Cert:\LocalMachine\Root
                        </div>
                    </div>
                </div>

                <div class="step">
                    <div class="step-number">3</div>
                    <div class="step-content">
                        <h4>Alternative: GUI Installation</h4>
                        <p>1. Double-click the downloaded .crt file<br>
                           2. Click "Install Certificate..."<br>
                           3. Select "Local Machine" → Next<br>
                           4. Select "Place all certificates in the following store"<br>
                           5. Browse → Select "Trusted Root Certification Authorities"<br>
                           6. Click Next → Finish</p>
                    </div>
                </div>

                <div class="step">
                    <div class="step-number">4</div>
                    <div class="step-content">
                        <h4>Verify Installation</h4>
                        <div class="code-block">
                            <button class="copy-btn" onclick="copyCode(this)">Copy</button>
certutil -store root "{{.CACommonName}}"
                        </div>
                        <p>Restart your browser for changes to take effect.</p>
                    </div>
                </div>
            </div>
        </div>

        <!-- macOS Instructions -->
        <div id="macos" class="platform-content">
            <div class="card">
                <h2>🍎 macOS Installation</h2>
                
                <div class="step">
                    <div class="step-number">1</div>
                    <div class="step-content">
                        <h4>Download the Certificate</h4>
                        <div class="code-block">
                            <button class="copy-btn" onclick="copyCode(this)">Copy</button>
curl -o ~/Downloads/safeops-ca.crt {{.BaseURL}}/ca.crt
                        </div>
                    </div>
                </div>

                <div class="step">
                    <div class="step-number">2</div>
                    <div class="step-content">
                        <h4>Install to System Keychain</h4>
                        <div class="code-block">
                            <button class="copy-btn" onclick="copyCode(this)">Copy</button>
sudo security add-trusted-cert -d -r trustRoot -k /Library/Keychains/System.keychain ~/Downloads/safeops-ca.crt
                        </div>
                        <p>You will be prompted for your admin password.</p>
                    </div>
                </div>

                <div class="step">
                    <div class="step-number">3</div>
                    <div class="step-content">
                        <h4>Verify Installation</h4>
                        <div class="code-block">
                            <button class="copy-btn" onclick="copyCode(this)">Copy</button>
security find-certificate -c "{{.CACommonName}}" /Library/Keychains/System.keychain
                        </div>
                    </div>
                </div>
            </div>
        </div>

        <!-- Linux Instructions -->
        <div id="linux" class="platform-content">
            <div class="card">
                <h2>🐧 Linux Installation</h2>
                
                <h3 style="margin: 20px 0 15px;">Debian / Ubuntu</h3>
                <div class="step">
                    <div class="step-number">1</div>
                    <div class="step-content">
                        <h4>Download and Install</h4>
                        <div class="code-block">
                            <button class="copy-btn" onclick="copyCode(this)">Copy</button>
sudo mkdir -p /usr/local/share/ca-certificates/safeops
sudo curl -o /usr/local/share/ca-certificates/safeops/safeops-ca.crt {{.BaseURL}}/ca.crt
sudo update-ca-certificates
                        </div>
                    </div>
                </div>

                <h3 style="margin: 20px 0 15px;">RHEL / CentOS / Fedora</h3>
                <div class="step">
                    <div class="step-number">1</div>
                    <div class="step-content">
                        <h4>Download and Install</h4>
                        <div class="code-block">
                            <button class="copy-btn" onclick="copyCode(this)">Copy</button>
sudo curl -o /etc/pki/ca-trust/source/anchors/safeops-ca.crt {{.BaseURL}}/ca.crt
sudo update-ca-trust
                        </div>
                    </div>
                </div>

                <h3 style="margin: 20px 0 15px;">Arch Linux</h3>
                <div class="step">
                    <div class="step-number">1</div>
                    <div class="step-content">
                        <h4>Download and Install</h4>
                        <div class="code-block">
                            <button class="copy-btn" onclick="copyCode(this)">Copy</button>
sudo curl -o /tmp/safeops-ca.crt {{.BaseURL}}/ca.crt
sudo trust anchor --store /tmp/safeops-ca.crt
                        </div>
                    </div>
                </div>

                <div class="troubleshooting">
                    <h4>⚠️ Note: Firefox on Linux</h4>
                    <p>Firefox uses its own certificate store. See the Firefox tab for separate instructions.</p>
                </div>
            </div>
        </div>

        <!-- iOS Instructions -->
        <div id="ios" class="platform-content">
            <div class="card">
                <h2>📱 iOS / iPadOS Installation</h2>
                
                <div class="download-section">
                    <a href="{{.BaseURL}}/ca.mobileconfig" class="download-btn">📲 Download iOS Profile</a>
                    <p style="margin-top: 10px; font-size: 13px;">Open this link in Safari</p>
                </div>

                <div class="step">
                    <div class="step-number">1</div>
                    <div class="step-content">
                        <h4>Download Profile</h4>
                        <p>Open this page in <strong>Safari</strong> (not Chrome) and tap the download button above.</p>
                    </div>
                </div>

                <div class="step">
                    <div class="step-number">2</div>
                    <div class="step-content">
                        <h4>Install Profile</h4>
                        <p>1. When prompted, tap "Allow"<br>
                           2. Go to <strong>Settings → General → VPN & Device Management</strong><br>
                           3. Tap the downloaded profile<br>
                           4. Tap "Install" in the top right<br>
                           5. Enter your passcode<br>
                           6. Tap "Install" again to confirm</p>
                    </div>
                </div>

                <div class="step">
                    <div class="step-number">3</div>
                    <div class="step-content">
                        <h4>⚠️ CRITICAL: Enable Trust</h4>
                        <p style="color: #dc2626; font-weight: bold;">This step is required!</p>
                        <p>1. Go to <strong>Settings → General → About</strong><br>
                           2. Scroll down and tap <strong>Certificate Trust Settings</strong><br>
                           3. Find "{{.CACommonName}}"<br>
                           4. Toggle the switch <strong>ON</strong><br>
                           5. Tap "Continue" in the warning</p>
                    </div>
                </div>
            </div>
        </div>

        <!-- Android Instructions -->
        <div id="android" class="platform-content">
            <div class="card">
                <h2>🤖 Android Installation</h2>
                
                <div class="step">
                    <div class="step-number">1</div>
                    <div class="step-content">
                        <h4>Download Certificate</h4>
                        <p>Tap the download button at the top of this page, or visit:<br>
                           <a href="{{.BaseURL}}/ca.crt">{{.BaseURL}}/ca.crt</a></p>
                    </div>
                </div>

                <div class="step">
                    <div class="step-number">2</div>
                    <div class="step-content">
                        <h4>Install Certificate</h4>
                        <p>1. Go to <strong>Settings → Security → Encryption & credentials</strong><br>
                           2. Tap <strong>Install a certificate → CA certificate</strong><br>
                           3. Tap "Install Anyway" on the warning<br>
                           4. Select the downloaded file<br>
                           5. Name it "{{.CACommonName}}"</p>
                    </div>
                </div>

                <div class="step">
                    <div class="step-number">3</div>
                    <div class="step-content">
                        <h4>Verify Installation</h4>
                        <p>Go to <strong>Settings → Security → Trusted credentials → User</strong><br>
                           You should see "{{.CACommonName}}" in the list.</p>
                    </div>
                </div>

                <div class="troubleshooting">
                    <h4>📍 Settings Location Varies</h4>
                    <p>The exact path may differ by device manufacturer. Search for "certificates" in Settings.</p>
                </div>
            </div>
        </div>

        <!-- Firefox Instructions -->
        <div id="firefox" class="platform-content">
            <div class="card">
                <h2>🦊 Firefox Browser</h2>
                <p style="margin-bottom: 20px;">Firefox uses its own certificate store, separate from your operating system.</p>
                
                <div class="step">
                    <div class="step-number">1</div>
                    <div class="step-content">
                        <h4>Open Certificate Manager</h4>
                        <p>1. Click the menu ☰ → Settings<br>
                           2. Search for "certificates"<br>
                           3. Click "View Certificates..."</p>
                    </div>
                </div>

                <div class="step">
                    <div class="step-number">2</div>
                    <div class="step-content">
                        <h4>Import Certificate</h4>
                        <p>1. Go to the "Authorities" tab<br>
                           2. Click "Import..."<br>
                           3. Select the downloaded certificate file<br>
                           4. Check "Trust this CA to identify websites"<br>
                           5. Click OK</p>
                    </div>
                </div>

                <div class="step">
                    <div class="step-number">3</div>
                    <div class="step-content">
                        <h4>Verify Installation</h4>
                        <p>In the Authorities tab, you should see "{{.CACommonName}}".</p>
                    </div>
                </div>

                <h3 style="margin: 25px 0 15px;">Command Line (Linux/macOS)</h3>
                <div class="code-block">
                    <button class="copy-btn" onclick="copyCode(this)">Copy</button>
# Install NSS tools first:
# Ubuntu: sudo apt install libnss3-tools
# macOS: brew install nss

# Find Firefox profile and install
certutil -A -n "{{.CACommonName}}" -t "C,," -i safeops-ca.crt -d sql:~/.mozilla/firefox/*.default*
                </div>
            </div>
        </div>

        {{if .Fingerprint}}
        <div class="card">
            <h2>🔍 Certificate Fingerprint</h2>
            <p>Verify the certificate fingerprint matches:</p>
            <div class="fingerprint">SHA-256: {{.Fingerprint}}</div>
        </div>
        {{end}}

        <div class="card">
            <h2>❓ Troubleshooting</h2>
            
            <div class="troubleshooting" style="background: white; border-color: var(--border);">
                <h4 style="color: var(--text);">Certificate still showing as untrusted?</h4>
                <p>• Restart your browser completely (close all windows)<br>
                   • Make sure you installed to "Trusted Root" store, not "Personal"<br>
                   • On iOS, ensure you completed the trust toggle in Certificate Trust Settings</p>
            </div>
            
            <div class="troubleshooting" style="background: white; border-color: var(--border); margin-top: 15px;">
                <h4 style="color: var(--text);">Android shows "Network may be monitored"?</h4>
                <p>This is normal. Android warns about user-installed CA certificates. Your connection is still secure.</p>
            </div>

            {{if .SupportEmail}}
            <p style="margin-top: 20px;">Need help? Contact <a href="mailto:{{.SupportEmail}}">{{.SupportEmail}}</a></p>
            {{end}}
        </div>

        <footer>
            <p>{{.OrganizationName}} • Generated on {{.GeneratedAt}}</p>
            {{if .PrivacyPolicyURL}}<p><a href="{{.PrivacyPolicyURL}}">Privacy Policy</a></p>{{end}}
        </footer>
    </div>

    <script>
        function showPlatform(platform) {
            document.querySelectorAll('.platform-content').forEach(el => el.classList.remove('active'));
            document.querySelectorAll('.tab-btn').forEach(el => el.classList.remove('active'));
            document.getElementById(platform).classList.add('active');
            event.target.classList.add('active');
        }

        function copyCode(btn) {
            const code = btn.parentElement.textContent.replace('Copy', '').trim();
            navigator.clipboard.writeText(code).then(() => {
                btn.textContent = 'Copied!';
                setTimeout(() => btn.textContent = 'Copy', 2000);
            });
        }

        // Auto-detect platform
        (function() {
            const ua = navigator.userAgent.toLowerCase();
            let platform = 'windows';
            if (ua.includes('iphone') || ua.includes('ipad')) platform = 'ios';
            else if (ua.includes('android')) platform = 'android';
            else if (ua.includes('mac')) platform = 'macos';
            else if (ua.includes('linux')) platform = 'linux';
            else if (ua.includes('firefox')) platform = 'firefox';
            
            // Activate detected platform
            document.querySelectorAll('.platform-content').forEach(el => el.classList.remove('active'));
            document.querySelectorAll('.tab-btn').forEach(el => el.classList.remove('active'));
            const platformEl = document.getElementById(platform);
            if (platformEl) {
                platformEl.classList.add('active');
                document.querySelector('[onclick*="' + platform + '"]')?.classList.add('active');
            }
        })();
    </script>
</body>
</html>
`

// ============================================================================
// Template Data Structure
// ============================================================================

// trustGuideData contains all data for rendering the trust guide template.
type trustGuideData struct {
	Title            string
	BaseURL          string
	OrganizationName string
	CACommonName     string
	SupportEmail     string
	ShowQRCodes      bool
	PrivacyPolicyURL string
	Fingerprint      string
	GeneratedAt      string
}

// ============================================================================
// Trust Instructions Generator
// ============================================================================

// GenerateTrustGuide generates a complete HTML trust guide page.
func GenerateTrustGuide(config *TrustInstructionsConfig, fingerprint string) ([]byte, error) {
	if config == nil {
		return nil, fmt.Errorf("config cannot be nil")
	}

	// Set defaults
	if config.Title == "" {
		config.Title = "Certificate Installation Guide"
	}
	if config.OrganizationName == "" {
		config.OrganizationName = "SafeOps"
	}
	if config.CACommonName == "" {
		config.CACommonName = "SafeOps Root CA"
	}

	// Prepare template data
	data := &trustGuideData{
		Title:            config.Title,
		BaseURL:          strings.TrimSuffix(config.BaseURL, "/"),
		OrganizationName: config.OrganizationName,
		CACommonName:     config.CACommonName,
		SupportEmail:     config.SupportEmail,
		ShowQRCodes:      config.ShowQRCodes,
		PrivacyPolicyURL: config.PrivacyPolicyURL,
		Fingerprint:      fingerprint,
		GeneratedAt:      time.Now().Format("January 2, 2006"),
	}

	// Parse and execute template
	tmpl, err := template.New("trustguide").Parse(trustGuideTemplate)
	if err != nil {
		return nil, fmt.Errorf("template parse error: %w", err)
	}

	var buf bytes.Buffer
	if err := tmpl.Execute(&buf, data); err != nil {
		return nil, fmt.Errorf("template execute error: %w", err)
	}

	return buf.Bytes(), nil
}

// ============================================================================
// Platform-Specific Instructions
// ============================================================================

// PlatformInstructions contains platform-specific installation instructions.
type PlatformInstructions struct {
	Platform  Platform `json:"platform"`
	Title     string   `json:"title"`
	Steps     []string `json:"steps"`
	Commands  []string `json:"commands"`
	VerifyCmd string   `json:"verify_command"`
	Notes     []string `json:"notes,omitempty"`
}

// GetPlatformInstructions returns instructions for a specific platform.
func GetPlatformInstructions(platform Platform, config *TrustInstructionsConfig) *PlatformInstructions {
	baseURL := strings.TrimSuffix(config.BaseURL, "/")
	caName := config.CACommonName

	switch platform {
	case PlatformWindows:
		return &PlatformInstructions{
			Platform: PlatformWindows,
			Title:    "Windows Installation",
			Steps: []string{
				"Download the certificate from " + baseURL + "/ca.crt",
				"Run PowerShell as Administrator",
				"Execute: Import-Certificate -FilePath .\\safeops-ca.crt -CertStoreLocation Cert:\\LocalMachine\\Root",
				"Restart your browser",
			},
			Commands: []string{
				fmt.Sprintf("curl -o safeops-ca.crt %s/ca.crt", baseURL),
				"Import-Certificate -FilePath .\\safeops-ca.crt -CertStoreLocation Cert:\\LocalMachine\\Root",
			},
			VerifyCmd: fmt.Sprintf("certutil -store root \"%s\"", caName),
		}

	case PlatformMacOS:
		return &PlatformInstructions{
			Platform: PlatformMacOS,
			Title:    "macOS Installation",
			Steps: []string{
				"Download the certificate",
				"Install using security command",
				"Verify installation",
			},
			Commands: []string{
				fmt.Sprintf("curl -o ~/Downloads/safeops-ca.crt %s/ca.crt", baseURL),
				"sudo security add-trusted-cert -d -r trustRoot -k /Library/Keychains/System.keychain ~/Downloads/safeops-ca.crt",
			},
			VerifyCmd: fmt.Sprintf("security find-certificate -c \"%s\" /Library/Keychains/System.keychain", caName),
		}

	case PlatformLinux:
		return &PlatformInstructions{
			Platform: PlatformLinux,
			Title:    "Linux Installation",
			Steps: []string{
				"Download the certificate",
				"Copy to CA directory",
				"Update CA trust store",
			},
			Commands: []string{
				fmt.Sprintf("sudo curl -o /usr/local/share/ca-certificates/safeops-ca.crt %s/ca.crt", baseURL),
				"sudo update-ca-certificates",
			},
			VerifyCmd: "openssl verify -CAfile /etc/ssl/certs/ca-certificates.crt /path/to/test.pem",
			Notes:     []string{"Firefox uses its own certificate store - import separately"},
		}

	case PlatformiOS:
		return &PlatformInstructions{
			Platform: PlatformiOS,
			Title:    "iOS / iPadOS Installation",
			Steps: []string{
				"Open " + baseURL + "/ca.mobileconfig in Safari",
				"Allow download when prompted",
				"Go to Settings → General → VPN & Device Management",
				"Install the profile",
				"CRITICAL: Go to Settings → General → About → Certificate Trust Settings",
				"Enable trust for " + caName,
			},
			Commands:  []string{},
			VerifyCmd: "",
			Notes:     []string{"Must use Safari browser", "Trust toggle is required for the certificate to work"},
		}

	case PlatformAndroid:
		return &PlatformInstructions{
			Platform: PlatformAndroid,
			Title:    "Android Installation",
			Steps: []string{
				"Download certificate from " + baseURL + "/ca.crt",
				"Go to Settings → Security → Encryption & credentials",
				"Tap Install a certificate → CA certificate",
				"Select the downloaded file",
			},
			Commands:  []string{},
			VerifyCmd: "",
			Notes:     []string{"Path may vary by manufacturer", "You will see a 'Network monitored' notification"},
		}

	case PlatformFirefox:
		return &PlatformInstructions{
			Platform: PlatformFirefox,
			Title:    "Firefox Browser",
			Steps: []string{
				"Open Firefox Settings → Privacy & Security",
				"Scroll to Certificates → View Certificates",
				"Go to Authorities tab → Import",
				"Select the certificate and trust for websites",
			},
			Commands: []string{
				fmt.Sprintf("certutil -A -n \"%s\" -t \"C,,\" -i safeops-ca.crt -d sql:~/.mozilla/firefox/*.default*", caName),
			},
			VerifyCmd: "",
			Notes:     []string{"Firefox uses its own certificate store, separate from the OS"},
		}

	default:
		return nil
	}
}

// ============================================================================
// Utility Functions
// ============================================================================

// NewTrustInstructionsConfig creates a new configuration with defaults.
func NewTrustInstructionsConfig(baseURL string) *TrustInstructionsConfig {
	return &TrustInstructionsConfig{
		BaseURL:          strings.TrimSuffix(baseURL, "/"),
		OrganizationName: "SafeOps",
		CACommonName:     "SafeOps Root CA",
		Title:            "Certificate Installation Guide",
		ShowQRCodes:      true,
	}
}

// WithOrganization sets the organization name.
func (c *TrustInstructionsConfig) WithOrganization(org string) *TrustInstructionsConfig {
	c.OrganizationName = org
	return c
}

// WithCAName sets the CA common name.
func (c *TrustInstructionsConfig) WithCAName(name string) *TrustInstructionsConfig {
	c.CACommonName = name
	return c
}

// WithTitle sets the page title.
func (c *TrustInstructionsConfig) WithTitle(title string) *TrustInstructionsConfig {
	c.Title = title
	return c
}

// WithSupportEmail sets the support email.
func (c *TrustInstructionsConfig) WithSupportEmail(email string) *TrustInstructionsConfig {
	c.SupportEmail = email
	return c
}

// WithQRCodes enables or disables QR codes.
func (c *TrustInstructionsConfig) WithQRCodes(show bool) *TrustInstructionsConfig {
	c.ShowQRCodes = show
	return c
}

// TrustGuideContentType returns the content type for the trust guide.
func TrustGuideContentType() string {
	return "text/html; charset=utf-8"
}
