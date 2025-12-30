// Package distribution provides auto-install pages for Windows, iOS, and macOS.
package distribution

import (
	"fmt"
	"net/http"
)

// ============================================================================
// Windows Auto-Install Page
// ============================================================================

// HandleWindowsInstall handles Windows auto-install with PowerShell script.
func (h *Handlers) HandleWindowsInstall(w http.ResponseWriter, r *http.Request) {
	autoInstall := r.URL.Query().Get("auto") == "1"

	autoScript := ""
	if autoInstall {
		autoScript = "window.onload = function() { setTimeout(autoInstallWindows, 1000); };"
	}

	html := fmt.Sprintf(`<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>SafeOps - Install CA Certificate (Windows)</title>
    <style>
        body { font-family: 'Segoe UI', Tahoma, sans-serif; background: #0078d4; color: white; padding: 50px; }
        .container { max-width: 700px; margin: 0 auto; background: white; color: #333; padding: 40px; border-radius: 10px; box-shadow: 0 4px 20px rgba(0,0,0,0.3); }
        h1 { color: #0078d4; margin-bottom: 20px; }
        .install-btn { background: #0078d4; color: white; padding: 15px 30px; font-size: 18px; border: none; border-radius: 5px; cursor: pointer; margin: 10px 5px; }
        .install-btn:hover { background: #005a9e; }
        .command { background: #f5f5f5; padding: 15px; border-radius: 5px; font-family: 'Consolas', monospace; margin: 15px 0; overflow-x: auto; }
        .status { margin: 20px 0; padding: 15px; border-radius: 5px; }
        .success { background: #d4edda; color: #155724; }
        .warning { background: #fff3cd; color: #856404; }
    </style>
</head>
<body>
    <div class="container">
        <h1>🪟 SafeOps CA Certificate - Windows Installation</h1>
        <p><strong>Automatic installation for Windows 10/11</strong></p>

        <div id="status"></div>

        <h3>Method 1: One-Click Install (Recommended)</h3>
        <button class="install-btn" onclick="autoInstallWindows()">
            ⚡ Auto-Install Certificate
        </button>

        <h3>Method 2: Manual PowerShell</h3>
        <p>Copy and paste this command in PowerShell (Run as Administrator):</p>
        <div class="command" id="psCommand">
            Invoke-WebRequest -Uri "%s/install-ca.ps1" -UseBasicParsing | Invoke-Expression
        </div>
        <button class="install-btn" onclick="copyPSCommand()">
            📋 Copy PowerShell Command
        </button>

        <h3>Method 3: Certificate Manager</h3>
        <button class="install-btn" onclick="downloadCertificate()">
            📥 Download Certificate
        </button>
        <p style="font-size: 14px; color: #666;">
            Then: Right-click → Install Certificate → Local Machine → Trusted Root Certification Authorities
        </p>

        <div style="margin-top: 30px; padding: 15px; background: #e7f3ff; border-left: 4px solid #0078d4; border-radius: 3px;">
            <strong>Why install this certificate?</strong><br>
            This allows your device to securely access the network and internet without security warnings.
            The certificate is issued by SafeOps and is required for network access.
        </div>
    </div>

    <script>
        function autoInstallWindows() {
            const statusDiv = document.getElementById('status');
            statusDiv.className = 'status warning';
            statusDiv.textContent = '⏳ Downloading and installing certificate...';

            // Download PowerShell script
            const link = document.createElement('a');
            link.href = '%s/install-ca.ps1';
            link.download = 'install-safeops-ca.ps1';
            link.click();

            setTimeout(() => {
                statusDiv.className = 'status success';
                statusDiv.innerHTML = '✅ Installation script downloaded!<br>' +
                    'Right-click the downloaded file → Run with PowerShell (as Administrator)';

                // Report installation
                fetch('%s/api/report', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({
                        mac_address: 'unknown',
                        ip_address: 'unknown',
                        os: 'Windows',
                        installation_status: 'script_downloaded',
                        installation_method: 'auto-powershell',
                        timestamp: new Date().toISOString()
                    })
                });
            }, 1500);
        }

        function copyPSCommand() {
            const cmd = document.getElementById('psCommand').textContent.trim();
            navigator.clipboard.writeText(cmd);
            alert('PowerShell command copied! Open PowerShell as Administrator and paste it.');
        }

        function downloadCertificate() {
            window.location.href = '%s/ca.crt?download=windows';

            setTimeout(() => {
                document.getElementById('status').className = 'status success';
                document.getElementById('status').textContent = '✅ Certificate downloaded! Follow the instructions above to install it.';
            }, 1000);
        }

        %s
    </script>
</body>
</html>`, h.config.BaseURL, h.config.BaseURL, h.config.BaseURL, h.config.BaseURL, autoScript)

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	w.Write([]byte(html))
}

// ============================================================================
// macOS Auto-Install Page
// ============================================================================

// HandleMacOSInstall handles macOS auto-install with configuration profile.
func (h *Handlers) HandleMacOSInstall(w http.ResponseWriter, r *http.Request) {
	autoInstall := r.URL.Query().Get("auto") == "1"

	autoScript := ""
	if autoInstall {
		autoScript = "window.onload = function() { setTimeout(autoInstallMacOS, 1000); };"
	}

	html := fmt.Sprintf(`<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>SafeOps - Install CA Certificate (macOS)</title>
    <style>
        body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif; background: linear-gradient(135deg, #667eea 0%%, #764ba2 100%%); color: white; padding: 50px; }
        .container { max-width: 700px; margin: 0 auto; background: white; color: #333; padding: 40px; border-radius: 15px; box-shadow: 0 10px 40px rgba(0,0,0,0.3); }
        h1 { color: #667eea; margin-bottom: 20px; }
        .install-btn { background: linear-gradient(135deg, #667eea 0%%, #764ba2 100%%); color: white; padding: 15px 30px; font-size: 18px; border: none; border-radius: 8px; cursor: pointer; margin: 10px 5px; font-weight: 600; }
        .install-btn:hover { transform: translateY(-2px); box-shadow: 0 5px 15px rgba(102, 126, 234, 0.4); }
        .command { background: #f5f5f5; padding: 15px; border-radius: 8px; font-family: 'Monaco', monospace; margin: 15px 0; overflow-x: auto; }
        .status { margin: 20px 0; padding: 15px; border-radius: 8px; }
        .success { background: #d4edda; color: #155724; }
        .warning { background: #fff3cd; color: #856404; }
    </style>
</head>
<body>
    <div class="container">
        <h1>🍎 SafeOps CA Certificate - macOS Installation</h1>
        <p><strong>Automatic installation for macOS</strong></p>

        <div id="status"></div>

        <h3>Method 1: Configuration Profile (Easiest)</h3>
        <button class="install-btn" onclick="installProfile()">
            ⚡ Install Configuration Profile
        </button>
        <p style="font-size: 14px; color: #666;">
            macOS will prompt you to install the profile. Click "Install" when prompted.
        </p>

        <h3>Method 2: Terminal Command</h3>
        <p>Copy and paste this command in Terminal:</p>
        <div class="command" id="terminalCommand">
            curl -s %s/install-ca.sh | sudo bash
        </div>
        <button class="install-btn" onclick="copyTerminalCommand()">
            📋 Copy Terminal Command
        </button>

        <h3>Method 3: Keychain Access</h3>
        <button class="install-btn" onclick="downloadCertMac()">
            📥 Download Certificate
        </button>
        <p style="font-size: 14px; color: #666;">
            Then: Double-click → Keychain Access opens → Add to System → Always Trust
        </p>

        <div style="margin-top: 30px; padding: 15px; background: #e7f3ff; border-left: 4px solid #667eea; border-radius: 8px;">
            <strong>Why install this certificate?</strong><br>
            This certificate allows secure network access without warnings. It's issued by SafeOps and required for this network.
        </div>
    </div>

    <script>
        function installProfile() {
            const statusDiv = document.getElementById('status');
            statusDiv.className = 'status warning';
            statusDiv.textContent = '⏳ Downloading configuration profile...';

            window.location.href = '%s/install-ca.mobileconfig';

            setTimeout(() => {
                statusDiv.className = 'status success';
                statusDiv.innerHTML = '✅ Profile downloaded!<br>System Preferences should open automatically. Click "Install" to complete.';

                fetch('%s/api/report', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({
                        mac_address: 'unknown',
                        ip_address: 'unknown',
                        os: 'macOS',
                        installation_status: 'profile_downloaded',
                        installation_method: 'auto-profile',
                        timestamp: new Date().toISOString()
                    })
                });
            }, 1500);
        }

        function copyTerminalCommand() {
            const cmd = document.getElementById('terminalCommand').textContent.trim();
            navigator.clipboard.writeText(cmd);
            alert('Terminal command copied! Open Terminal and paste it.');
        }

        function downloadCertMac() {
            window.location.href = '%s/ca.crt?download=macos';

            setTimeout(() => {
                document.getElementById('status').className = 'status success';
                document.getElementById('status').textContent = '✅ Certificate downloaded! Double-click to install via Keychain Access.';
            }, 1000);
        }

        function autoInstallMacOS() {
            installProfile();
        }

        %s
    </script>
</body>
</html>`, h.config.BaseURL, h.config.BaseURL, h.config.BaseURL, h.config.BaseURL, autoScript)

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	w.Write([]byte(html))
}

// ============================================================================
// iOS Auto-Install Page
// ============================================================================

// HandleiOSInstall handles iOS auto-install with configuration profile.
func (h *Handlers) HandleiOSInstall(w http.ResponseWriter, r *http.Request) {
	autoInstall := r.URL.Query().Get("auto") == "1"

	autoScript := ""
	if autoInstall {
		autoScript = "window.onload = function() { setTimeout(installiOSProfile, 1000); };"
	}

	html := fmt.Sprintf(`<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>SafeOps - Install CA Certificate</title>
    <style>
        body { font-family: -apple-system, BlinkMacSystemFont, sans-serif; background: linear-gradient(135deg, #667eea 0%%, #764ba2 100%%); color: white; padding: 30px 20px; text-align: center; }
        .container { max-width: 500px; margin: 0 auto; background: white; color: #333; padding: 30px 20px; border-radius: 20px; box-shadow: 0 10px 40px rgba(0,0,0,0.3); }
        h1 { color: #667eea; font-size: 24px; margin-bottom: 15px; }
        .install-btn { background: linear-gradient(135deg, #667eea 0%%, #764ba2 100%%); color: white; padding: 18px 40px; font-size: 20px; border: none; border-radius: 12px; cursor: pointer; margin: 20px 0; width: 100%%; font-weight: 600; box-shadow: 0 4px 15px rgba(102, 126, 234, 0.4); }
        .install-btn:active { transform: scale(0.98); }
        .status { margin: 20px 0; padding: 15px; border-radius: 12px; font-size: 16px; }
        .success { background: #d4edda; color: #155724; }
        .warning { background: #fff3cd; color: #856404; }
        .steps { text-align: left; margin: 20px 0; padding: 20px; background: #f8f9fa; border-radius: 12px; }
        .step { margin: 10px 0; padding-left: 25px; position: relative; }
        .step:before { content: "✓"; position: absolute; left: 0; color: #667eea; font-weight: bold; }
    </style>
</head>
<body>
    <div class="container">
        <h1>🔐 Network Security Setup</h1>
        <p style="font-size: 16px; color: #666; margin-bottom: 20px;">
            Install the security certificate to access the internet
        </p>

        <div id="status"></div>

        <button class="install-btn" onclick="installiOSProfile()">
            📥 Install Certificate
        </button>

        <div class="steps">
            <strong style="color: #667eea;">After tapping Install:</strong>
            <div class="step">Settings will open automatically</div>
            <div class="step">Tap "Profile Downloaded"</div>
            <div class="step">Tap "Install" (top right)</div>
            <div class="step">Enter your passcode</div>
            <div class="step">Tap "Install" again to confirm</div>
            <div class="step">Tap "Done" when complete</div>
        </div>

        <p style="font-size: 13px; color: #999; margin-top: 20px;">
            This certificate is required for network access.<br>
            Safe and secure • Issued by SafeOps
        </p>
    </div>

    <script>
        function installiOSProfile() {
            const statusDiv = document.getElementById('status');
            statusDiv.className = 'status warning';
            statusDiv.textContent = '⏳ Opening Settings...';

            // iOS automatically prompts to install .mobileconfig files
            window.location.href = '%s/install-ca.mobileconfig';

            setTimeout(() => {
                statusDiv.className = 'status success';
                statusDiv.innerHTML = '✅ Settings opened!<br>Follow the steps above to complete installation.';

                fetch('%s/api/report', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({
                        mac_address: 'unknown',
                        ip_address: 'unknown',
                        os: 'iOS',
                        installation_status: 'profile_downloaded',
                        installation_method: 'auto-profile',
                        timestamp: new Date().toISOString()
                    })
                });
            }, 1500);
        }

        %s
    </script>
</body>
</html>`, h.config.BaseURL, h.config.BaseURL, autoScript)

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	w.Write([]byte(html))
}

// RegisterAllPlatformHandlers registers all platform install handlers.
func (h *Handlers) RegisterAllPlatformHandlers(mux *http.ServeMux) {
	mux.HandleFunc("/android", h.HandleAndroidInstall)
	mux.HandleFunc("/linux", h.HandleLinuxInstall)
	mux.HandleFunc("/windows", h.HandleWindowsInstall)
	mux.HandleFunc("/macos", h.HandleMacOSInstall)
	mux.HandleFunc("/ios", h.HandleiOSInstall)
}
