// Package portal provides Android-specific CA installation handlers.
package portal

import (
	"fmt"
	"net/http"
)

// ============================================================================
// Android-Specific Handlers
// ============================================================================

// handleAndroidSetup provides Android-optimized CA setup page.
func (p *CaptivePortal) handleAndroidSetup(w http.ResponseWriter, r *http.Request) {
	clientIP := p.getClientIP(r)

	data := map[string]interface{}{
		"Title":           p.config.PortalTitle + " - Android Setup",
		"Organization":    p.config.Organization,
		"CertManagerURL":  p.config.CertManagerBaseURL,
		"ClientIP":        clientIP,
		"CACertURL":       p.config.CertManagerBaseURL + "/ca.crt",
		"CADerURL":        p.config.CertManagerBaseURL + "/ca.der",
		"AndroidCertURL":  p.config.CertManagerBaseURL + "/ca-android.crt",
		"QRCodeURL":       p.config.CertManagerBaseURL + "/ca-qr-android.png",
		"VideoGuideURL":   p.config.CertManagerBaseURL + "/android-guide.mp4",
	}

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := p.templates.ExecuteTemplate(w, "android_setup.html", data); err != nil {
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
	}
}

// handleAndroidDownload handles direct Android certificate download.
func (p *CaptivePortal) handleAndroidDownload(w http.ResponseWriter, r *http.Request) {
	// Set headers for Android to recognize it as a certificate
	w.Header().Set("Content-Type", "application/x-x509-ca-cert")
	w.Header().Set("Content-Disposition", `attachment; filename="SafeOps-CA.crt"`)

	// Redirect to Certificate Manager
	certURL := p.config.CertManagerBaseURL + "/ca.crt"
	http.Redirect(w, r, certURL, http.StatusTemporaryRedirect)
}

// handleAndroidIntent handles Android Intent-based installation.
func (p *CaptivePortal) handleAndroidIntent(w http.ResponseWriter, r *http.Request) {
	// Generate Android Intent URL for direct installation
	certURL := p.config.CertManagerBaseURL + "/ca.crt"

	// Android Intent format for certificate installation
	intentURL := fmt.Sprintf("intent://install?url=%s#Intent;scheme=certinstaller;package=com.android.certinstaller;end", certURL)

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	fmt.Fprintf(w, `<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Installing Certificate...</title>
    <style>
        body {
            font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Arial, sans-serif;
            background: linear-gradient(135deg, #667eea 0%%, #764ba2 100%%);
            min-height: 100vh;
            display: flex;
            align-items: center;
            justify-content: center;
            margin: 0;
            padding: 20px;
        }
        .container {
            background: white;
            border-radius: 20px;
            padding: 40px;
            text-align: center;
            max-width: 400px;
        }
        .spinner {
            border: 4px solid #f3f3f3;
            border-top: 4px solid #667eea;
            border-radius: 50%%;
            width: 50px;
            height: 50px;
            animation: spin 1s linear infinite;
            margin: 20px auto;
        }
        @keyframes spin {
            0%% { transform: rotate(0deg); }
            100%% { transform: rotate(360deg); }
        }
        .button {
            background: #667eea;
            color: white;
            border: none;
            padding: 15px 30px;
            font-size: 16px;
            border-radius: 8px;
            cursor: pointer;
            text-decoration: none;
            display: inline-block;
            margin-top: 20px;
        }
    </style>
</head>
<body>
    <div class="container">
        <h2>Installing Certificate...</h2>
        <div class="spinner"></div>
        <p>Opening Android certificate installer...</p>
        <p style="color: #666; font-size: 14px;">If nothing happens, tap the button below:</p>
        <a href="%s" class="button">Open Installer</a>
        <p style="margin-top: 30px;">
            <a href="/setup-ca">← Back to Setup Guide</a>
        </p>
    </div>
    <script>
        // Auto-redirect after 1 second
        setTimeout(function() {
            window.location.href = '%s';
        }, 1000);
    </script>
</body>
</html>`, intentURL, intentURL)
}

// handleAndroidQRCode serves QR code specifically for Android.
func (p *CaptivePortal) handleAndroidQRCode(w http.ResponseWriter, r *http.Request) {
	qrURL := p.config.CertManagerBaseURL + "/ca-qr-android.png"
	http.Redirect(w, r, qrURL, http.StatusTemporaryRedirect)
}

// handleAndroidVerify helps users verify the certificate is installed.
func (p *CaptivePortal) handleAndroidVerify(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")

	data := map[string]interface{}{
		"Title":        "Verify Installation",
		"Organization": p.config.Organization,
	}

	if err := p.templates.ExecuteTemplate(w, "android_verify.html", data); err != nil {
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
	}
}

// registerAndroidRoutes registers Android-specific routes.
func (p *CaptivePortal) registerAndroidRoutes(mux *http.ServeMux) {
	// Android-specific pages
	mux.HandleFunc("/android/setup", p.handleAndroidSetup)
	mux.HandleFunc("/android/download", p.handleAndroidDownload)
	mux.HandleFunc("/android/install", p.handleAndroidIntent)
	mux.HandleFunc("/android/qr", p.handleAndroidQRCode)
	mux.HandleFunc("/android/verify", p.handleAndroidVerify)

	// Short links for mobile typing
	mux.HandleFunc("/a", p.handleAndroidSetup)
	mux.HandleFunc("/android", p.handleAndroidSetup)
}
