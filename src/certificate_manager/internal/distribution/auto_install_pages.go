// Package distribution provides auto-install pages for different platforms.
package distribution

import (
	"fmt"
	"net/http"
)

// ============================================================================
// Auto-Install Pages for Different Platforms
// ============================================================================

// HandleAndroidInstall handles Android auto-install page with auto-redirect.
func (h *Handlers) HandleAndroidInstall(w http.ResponseWriter, r *http.Request) {
	autoInstall := r.URL.Query().Get("auto") == "1"

	autoScript := ""
	if autoInstall {
		autoScript = "window.onload = function() { setTimeout(installCertificate, 1000); };"
	}

	html := fmt.Sprintf(`<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>SafeOps - Install CA Certificate</title>
    <style>
        body { font-family: Arial, sans-serif; text-align: center; padding: 50px; background: #f5f5f5; }
        .container { max-width: 500px; margin: 0 auto; background: white; padding: 30px; border-radius: 10px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }
        h1 { color: #2196F3; }
        .install-btn { background: #4CAF50; color: white; padding: 15px 30px; font-size: 18px; border: none; border-radius: 5px; cursor: pointer; margin: 10px; }
        .install-btn:hover { background: #45a049; }
        .status { margin: 20px 0; padding: 15px; border-radius: 5px; }
        .success { background: #d4edda; color: #155724; }
        .warning { background: #fff3cd; color: #856404; }
        .error { background: #f8d7da; color: #721c24; }
    </style>
</head>
<body>
    <div class="container">
        <h1>🔐 Network Security Setup</h1>
        <p>To access the internet, please install the SafeOps security certificate.</p>

        <div id="status"></div>

        <button class="install-btn" onclick="installCertificate()">
            📥 Install Certificate
        </button>

        <p style="font-size: 14px; color: #666; margin-top: 30px;">
            This certificate allows your device to securely connect to the network.<br>
            Installation takes 5 seconds. ✓ Safe ✓ Required
        </p>
    </div>

    <script>
        function installCertificate() {
            const statusDiv = document.getElementById('status');
            statusDiv.className = 'status warning';
            statusDiv.textContent = 'Downloading certificate...';

            window.location.href = '%s/ca.crt?download=android';

            setTimeout(() => {
                statusDiv.className = 'status success';
                statusDiv.textContent = '✅ Certificate downloaded! Tap "Install" when Android prompts you.';

                fetch('%s/api/report', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({
                        mac_address: 'unknown',
                        ip_address: 'unknown',
                        os: 'Android',
                        installation_status: 'initiated',
                        installation_method: 'auto-web',
                        timestamp: new Date().toISOString()
                    })
                });
            }, 2000);
        }

        %s
    </script>
</body>
</html>`, h.config.BaseURL, h.config.BaseURL, autoScript)

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	w.Write([]byte(html))
}

// HandleLinuxInstall handles Linux auto-install with bash script.
func (h *Handlers) HandleLinuxInstall(w http.ResponseWriter, r *http.Request) {
	autoInstall := r.URL.Query().Get("auto") == "1"

	autoScript := ""
	if autoInstall {
		autoScript = "window.onload = function() { setTimeout(autoInstall, 1000); };"
	}

	html := fmt.Sprintf(`<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>SafeOps - Install CA Certificate (Linux)</title>
    <style>
        body { font-family: 'Courier New', monospace; background: #1e1e1e; color: #00ff00; padding: 50px; }
        .container { max-width: 800px; margin: 0 auto; background: #2d2d2d; padding: 30px; border-radius: 10px; border: 2px solid #00ff00; }
        h1 { color: #00ff00; }
        .command { background: #000; padding: 15px; border-radius: 5px; margin: 10px 0; overflow-x: auto; }
        .install-btn { background: #00ff00; color: #000; padding: 15px 30px; font-size: 18px; border: none; border-radius: 5px; cursor: pointer; font-weight: bold; }
        .install-btn:hover { background: #00cc00; }
        pre { color: #fff; }
    </style>
</head>
<body>
    <div class="container">
        <h1>🐧 SafeOps CA Certificate - Linux Installation</h1>
        <p>Run this command in your terminal to install the certificate:</p>

        <div class="command">
            <pre id="installCmd">curl -s %s/install-ca.sh | sudo bash</pre>
        </div>

        <button class="install-btn" onclick="copyCommand()">
            📋 Copy Command
        </button>

        <button class="install-btn" onclick="autoInstallScript()" style="margin-left: 10px;">
            ⚡ Auto-Install Now
        </button>

        <div id="status" style="margin-top: 20px;"></div>

        <p style="margin-top: 30px; font-size: 14px; color: #00ff00;">
            ✓ Installs to /usr/local/share/ca-certificates/<br>
            ✓ Updates system certificate store<br>
            ✓ Works on Ubuntu, Debian, Kali, Fedora, Arch
        </p>
    </div>

    <script>
        function copyCommand() {
            const cmd = document.getElementById('installCmd').textContent;
            navigator.clipboard.writeText(cmd);
            alert('Command copied! Paste it in your terminal.');
        }

        function autoInstallScript() {
            const statusDiv = document.getElementById('status');
            statusDiv.style.color = '#ffff00';
            statusDiv.textContent = 'Downloading install script...';

            const link = document.createElement('a');
            link.href = '%s/install-ca.sh';
            link.download = 'install-ca.sh';
            link.click();

            setTimeout(() => {
                statusDiv.style.color = '#00ff00';
                statusDiv.innerHTML = '✅ Script downloaded!<br>Open terminal and run: bash ~/Downloads/install-ca.sh';

                fetch('%s/api/report', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({
                        mac_address: 'unknown',
                        ip_address: 'unknown',
                        os: 'Linux',
                        installation_status: 'script_downloaded',
                        installation_method: 'auto-bash',
                        timestamp: new Date().toISOString()
                    })
                });
            }, 1000);
        }

        %s
    </script>
</body>
</html>`, h.config.BaseURL, h.config.BaseURL, h.config.BaseURL, autoScript)

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	w.Write([]byte(html))
}

// RegisterPlatformHandlers registers platform-specific install handlers.
func (h *Handlers) RegisterPlatformHandlers(mux *http.ServeMux) {
	mux.HandleFunc("/android", h.HandleAndroidInstall)
	mux.HandleFunc("/linux", h.HandleLinuxInstall)
}
