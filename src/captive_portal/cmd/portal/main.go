// Package main implements the Captive Portal HTTP server.
// This server displays the certificate installation page for unenrolled devices.
package main

import (
	"context"
	"embed"
	"flag"
	"fmt"
	"html/template"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"
)

//go:embed templates/*
var templateFS embed.FS

var (
	listenAddr     = flag.String("addr", ":80", "HTTP listen address")
	certManagerURL = flag.String("cert-manager", "http://localhost:50055", "Certificate Manager URL")
	certPath       = flag.String("cert-path", "certs/ca.crt", "Path to CA certificate file")
	dnsServerURL   = flag.String("dns-server", "http://localhost:50053", "DNS Server API URL")
)

func main() {
	flag.Parse()

	log.Printf("SafeOps Captive Portal starting...")
	log.Printf("  Listen: %s", *listenAddr)
	log.Printf("  Cert Path: %s", *certPath)

	// Create server
	portal := NewPortalServer(*certPath, *certManagerURL, *dnsServerURL)

	// Setup routes
	mux := http.NewServeMux()
	mux.HandleFunc("/", portal.handleRoot)
	mux.HandleFunc("/install", portal.handleInstall)
	mux.HandleFunc("/download", portal.handleDownload)
	mux.HandleFunc("/success", portal.handleSuccess)
	mux.HandleFunc("/detect", portal.handleDetect)
	mux.HandleFunc("/api/enroll", portal.handleEnrollCallback)
	mux.HandleFunc("/health", portal.handleHealth)

	// OS-specific installer scripts
	mux.HandleFunc("/install-windows.ps1", portal.handleWindowsInstaller)
	mux.HandleFunc("/install-linux.sh", portal.handleLinuxInstaller)
	mux.HandleFunc("/install-macos.sh", portal.handleMacOSInstaller)

	// Static files
	mux.Handle("/static/", http.StripPrefix("/static/", http.FileServer(http.Dir("static"))))

	server := &http.Server{
		Addr:    *listenAddr,
		Handler: mux,
	}

	// Start server
	go func() {
		log.Printf("Captive Portal listening on %s", *listenAddr)
		if err := server.ListenAndServe(); err != http.ErrServerClosed {
			log.Fatalf("HTTP server error: %v", err)
		}
	}()

	// Wait for shutdown
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	<-sigCh

	log.Printf("Shutting down...")
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	server.Shutdown(ctx)
	log.Printf("Captive Portal stopped")
}

// ============================================================================
// Portal Server
// ============================================================================

// PortalServer handles captive portal requests
type PortalServer struct {
	certPath       string
	certManagerURL string
	dnsServerURL   string
	templates      *template.Template
}

// NewPortalServer creates a new portal server
func NewPortalServer(certPath, certManagerURL, dnsServerURL string) *PortalServer {
	// Parse templates
	tmpl, err := template.ParseFS(templateFS, "templates/*.html")
	if err != nil {
		// Fallback to inline templates
		tmpl = template.Must(template.New("install.html").Parse(installTemplate))
		template.Must(tmpl.New("success.html").Parse(successTemplate))
	}

	return &PortalServer{
		certPath:       certPath,
		certManagerURL: certManagerURL,
		dnsServerURL:   dnsServerURL,
		templates:      tmpl,
	}
}

// ============================================================================
// HTTP Handlers
// ============================================================================

func (p *PortalServer) handleRoot(w http.ResponseWriter, r *http.Request) {
	// Redirect to install page
	http.Redirect(w, r, "/install", http.StatusTemporaryRedirect)
}

func (p *PortalServer) handleInstall(w http.ResponseWriter, r *http.Request) {
	clientIP := getClientIP(r)
	userAgent := r.UserAgent()
	osType := detectOS(userAgent)

	data := PageData{
		Title:           "SafeOps Network Security",
		OSType:          osType,
		ClientIP:        clientIP,
		DownloadURL:     "/download?os=" + osType,
		InstructionsURL: getInstructionsURL(osType),
	}

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	p.renderTemplate(w, "install.html", data)
}

func (p *PortalServer) handleDownload(w http.ResponseWriter, r *http.Request) {
	clientIP := getClientIP(r)
	osType := r.URL.Query().Get("os")
	if osType == "" {
		osType = detectOS(r.UserAgent())
	}

	// Read certificate file
	certData, err := os.ReadFile(p.certPath)
	if err != nil {
		log.Printf("Failed to read cert: %v", err)
		http.Error(w, "Certificate not available", http.StatusInternalServerError)
		return
	}

	// Set appropriate content type based on OS
	filename := "SafeOps-CA.crt"
	contentType := "application/x-x509-ca-cert"

	switch osType {
	case "Windows":
		filename = "SafeOps-CA.crt"
		contentType = "application/x-x509-ca-cert"
	case "macOS", "iOS":
		filename = "SafeOps-CA.mobileconfig"
		// For Apple, we'd need to wrap in mobileconfig profile
		// For now, serve the .crt
		filename = "SafeOps-CA.crt"
	case "Android":
		filename = "SafeOps-CA.crt"
		contentType = "application/x-x509-ca-cert"
	case "Linux":
		filename = "SafeOps-CA.crt"
		contentType = "application/x-pem-file"
	}

	w.Header().Set("Content-Type", contentType)
	w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=\"%s\"", filename))
	w.Header().Set("Content-Length", fmt.Sprintf("%d", len(certData)))
	w.Write(certData)

	log.Printf("Certificate downloaded by %s (OS: %s)", clientIP, osType)

	// Notify DNS server about pending enrollment
	go p.notifyDeviceSeen(clientIP, osType, r.UserAgent())
}

func (p *PortalServer) handleSuccess(w http.ResponseWriter, r *http.Request) {
	clientIP := getClientIP(r)

	data := PageData{
		Title:    "Installation Complete",
		ClientIP: clientIP,
	}

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	p.renderTemplate(w, "success.html", data)

	// Mark device as enrolled
	go p.markDeviceEnrolled(clientIP, r.UserAgent())
}

func (p *PortalServer) handleDetect(w http.ResponseWriter, r *http.Request) {
	// Captive portal detection endpoints return simple responses
	// If we get here, the device should be redirected to /install
	http.Redirect(w, r, "/install", http.StatusTemporaryRedirect)
}

func (p *PortalServer) handleEnrollCallback(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	ipAddress := r.FormValue("ip")
	macAddress := r.FormValue("mac")
	osType := r.FormValue("os")

	if ipAddress == "" {
		ipAddress = getClientIP(r)
	}

	log.Printf("Enrollment callback: IP=%s MAC=%s OS=%s", ipAddress, macAddress, osType)

	// Mark as enrolled
	p.markDeviceEnrolled(ipAddress, r.UserAgent())

	w.Header().Set("Content-Type", "application/json")
	w.Write([]byte(`{"status":"enrolled"}`))
}

func (p *PortalServer) handleHealth(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.Write([]byte(`{"status":"healthy"}`))
}

func (p *PortalServer) handleWindowsInstaller(w http.ResponseWriter, r *http.Request) {
	script := `# SafeOps CA Certificate Installer for Windows
# Run: powershell -ExecutionPolicy Bypass -Command "iwr http://192.168.1.1/install-windows.ps1 | iex"

$CertURL = "http://192.168.1.1/download?os=Windows"
$CertPath = "$env:TEMP\SafeOps-CA.crt"

Write-Host "Downloading certificate..." -ForegroundColor Cyan
Invoke-WebRequest -Uri $CertURL -OutFile $CertPath

Write-Host "Installing certificate..." -ForegroundColor Cyan
$cert = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2($CertPath)
$store = New-Object System.Security.Cryptography.X509Certificates.X509Store("Root", "LocalMachine")
$store.Open("ReadWrite")
$store.Add($cert)
$store.Close()

Write-Host "SUCCESS! Certificate installed." -ForegroundColor Green
Remove-Item $CertPath

# Notify portal
try { Invoke-RestMethod -Uri "http://192.168.1.1/api/enroll" -Method POST -Body @{os="Windows";method="script"} -TimeoutSec 5 } catch {}
`
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.Header().Set("Content-Disposition", "attachment; filename=\"install_cert.ps1\"")
	w.Write([]byte(script))
}

func (p *PortalServer) handleLinuxInstaller(w http.ResponseWriter, r *http.Request) {
	script := `#!/bin/bash
# SafeOps CA Certificate Installer for Linux
# Run: curl -fsSL http://192.168.1.1/install-linux.sh | sudo bash

set -e
echo "Downloading certificate..."
curl -fsSL "http://192.168.1.1/download?os=Linux" -o /tmp/SafeOps-CA.crt

echo "Installing certificate..."
if [ -d /usr/local/share/ca-certificates ]; then
    sudo cp /tmp/SafeOps-CA.crt /usr/local/share/ca-certificates/
    sudo update-ca-certificates
elif [ -d /etc/pki/ca-trust/source/anchors ]; then
    sudo cp /tmp/SafeOps-CA.crt /etc/pki/ca-trust/source/anchors/
    sudo update-ca-trust extract
fi

rm -f /tmp/SafeOps-CA.crt
echo "SUCCESS! Certificate installed."
curl -s -X POST "http://192.168.1.1/api/enroll" -d "os=Linux&method=script" 2>/dev/null || true
`
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.Write([]byte(script))
}

func (p *PortalServer) handleMacOSInstaller(w http.ResponseWriter, r *http.Request) {
	script := `#!/bin/bash
# SafeOps CA Certificate Installer for macOS
# Run: curl -fsSL http://192.168.1.1/install-macos.sh | bash

set -e
echo "Downloading certificate..."
curl -fsSL "http://192.168.1.1/download?os=macOS" -o /tmp/SafeOps-CA.crt

echo "Installing certificate (you may be prompted for password)..."
sudo security add-trusted-cert -d -r trustRoot -k /Library/Keychains/System.keychain /tmp/SafeOps-CA.crt

rm -f /tmp/SafeOps-CA.crt
echo "SUCCESS! Certificate installed."
curl -s -X POST "http://192.168.1.1/api/enroll" -d "os=macOS&method=script" 2>/dev/null || true
`
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.Write([]byte(script))
}

// ============================================================================
// Helper Functions
// ============================================================================

func (p *PortalServer) renderTemplate(w http.ResponseWriter, name string, data interface{}) {
	if p.templates != nil {
		err := p.templates.ExecuteTemplate(w, name, data)
		if err != nil {
			log.Printf("Template error: %v", err)
			// Fallback to inline template
			if name == "install.html" {
				tmpl := template.Must(template.New("install.html").Parse(installTemplate))
				tmpl.Execute(w, data)
			} else if name == "success.html" {
				tmpl := template.Must(template.New("success.html").Parse(successTemplate))
				tmpl.Execute(w, data)
			}
		}
	}
}

func (p *PortalServer) notifyDeviceSeen(ip, osType, userAgent string) {
	// Call Certificate Manager API to track device
	_ = userAgent
	log.Printf("Device seen: %s (OS: %s)", ip, osType)

	// Notify Certificate Manager
	go func() {
		data := fmt.Sprintf("ip=%s&os=%s", ip, osType)
		resp, err := http.Post(p.certManagerURL+"/api/devices/track",
			"application/x-www-form-urlencoded",
			strings.NewReader(data))
		if err != nil {
			log.Printf("Failed to notify cert manager: %v", err)
			return
		}
		resp.Body.Close()
	}()
}

func (p *PortalServer) markDeviceEnrolled(ip, userAgent string) {
	// Device enrollment tracked via Certificate Manager
	_ = userAgent
	log.Printf("Device enrolled: %s", ip)
}

func getClientIP(r *http.Request) string {
	// Check forwarded headers
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		parts := strings.Split(xff, ",")
		return strings.TrimSpace(parts[0])
	}
	if xrip := r.Header.Get("X-Real-IP"); xrip != "" {
		return xrip
	}
	// Fall back to remote addr
	host, _, _ := net.SplitHostPort(r.RemoteAddr)
	return host
}

func detectOS(userAgent string) string {
	ua := strings.ToLower(userAgent)
	switch {
	case strings.Contains(ua, "windows"):
		return "Windows"
	case strings.Contains(ua, "iphone") || strings.Contains(ua, "ipad"):
		return "iOS"
	case strings.Contains(ua, "mac os") || strings.Contains(ua, "macintosh"):
		return "macOS"
	case strings.Contains(ua, "android"):
		return "Android"
	case strings.Contains(ua, "linux"):
		return "Linux"
	default:
		return "Unknown"
	}
}

func getInstructionsURL(osType string) string {
	base := "/instructions/"
	switch osType {
	case "Windows":
		return base + "windows"
	case "macOS":
		return base + "macos"
	case "iOS":
		return base + "ios"
	case "Android":
		return base + "android"
	case "Linux":
		return base + "linux"
	default:
		return base + "general"
	}
}

// ============================================================================
// Data Types
// ============================================================================

// PageData contains data for template rendering
type PageData struct {
	Title           string
	OSType          string
	ClientIP        string
	DownloadURL     string
	InstructionsURL string
}

// ============================================================================
// Inline Templates (Fallback)
// ============================================================================

var installTemplate = `<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>{{.Title}}</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
            background: linear-gradient(135deg, #1a1a2e 0%, #16213e 50%, #0f3460 100%);
            min-height: 100vh;
            display: flex;
            align-items: center;
            justify-content: center;
            color: #fff;
        }
        .container {
            background: rgba(255,255,255,0.1);
            backdrop-filter: blur(20px);
            border-radius: 24px;
            padding: 48px;
            max-width: 500px;
            width: 90%;
            text-align: center;
            box-shadow: 0 25px 50px rgba(0,0,0,0.3);
            border: 1px solid rgba(255,255,255,0.1);
        }
        .logo {
            width: 80px;
            height: 80px;
            background: linear-gradient(135deg, #00d4ff, #7c3aed);
            border-radius: 20px;
            margin: 0 auto 24px;
            display: flex;
            align-items: center;
            justify-content: center;
            font-size: 36px;
        }
        h1 { font-size: 28px; margin-bottom: 12px; }
        p { color: rgba(255,255,255,0.8); margin-bottom: 24px; line-height: 1.6; }
        .os-badge {
            display: inline-block;
            background: rgba(0,212,255,0.2);
            border: 1px solid #00d4ff;
            border-radius: 20px;
            padding: 6px 16px;
            font-size: 14px;
            margin-bottom: 24px;
        }
        .btn {
            display: inline-block;
            background: linear-gradient(135deg, #00d4ff, #7c3aed);
            color: white;
            text-decoration: none;
            padding: 16px 48px;
            border-radius: 50px;
            font-size: 18px;
            font-weight: 600;
            transition: transform 0.2s, box-shadow 0.2s;
            border: none;
            cursor: pointer;
        }
        .btn:hover {
            transform: translateY(-2px);
            box-shadow: 0 10px 30px rgba(0,212,255,0.4);
        }
        .steps {
            margin-top: 32px;
            text-align: left;
            background: rgba(0,0,0,0.2);
            border-radius: 16px;
            padding: 24px;
        }
        .steps h3 { margin-bottom: 16px; font-size: 16px; }
        .steps ol { padding-left: 20px; }
        .steps li { margin-bottom: 8px; color: rgba(255,255,255,0.8); }
        .footer { margin-top: 24px; font-size: 12px; color: rgba(255,255,255,0.5); }
    </style>
</head>
<body>
    <div class="container">
        <div class="logo">🔐</div>
        <h1>Network Security Certificate</h1>
        <p>To access the network securely, please install the SafeOps security certificate.</p>
        
        <div class="os-badge">Detected: {{.OSType}}</div>
        
        <a href="{{.DownloadURL}}" class="btn" onclick="setTimeout(function(){window.location='/success';}, 3000);">
            Download Certificate
        </a>
        
        <div class="steps">
            <h3>Installation Steps:</h3>
            <ol>
                {{if eq .OSType "Windows"}}
                <li>Click "Download Certificate"</li>
                <li>Open the downloaded file</li>
                <li>Click "Install Certificate"</li>
                <li>Select "Local Machine" → Next</li>
                <li>Select "Place all certificates in: Trusted Root Certification Authorities"</li>
                <li>Click Finish</li>
                {{else if eq .OSType "macOS"}}
                <li>Click "Download Certificate"</li>
                <li>Open the downloaded file</li>
                <li>Add to Keychain when prompted</li>
                <li>Open Keychain Access</li>
                <li>Double-click the certificate → Trust → Always Trust</li>
                {{else if eq .OSType "iOS"}}
                <li>Click "Download Certificate"</li>
                <li>Go to Settings → General → VPN & Device Management</li>
                <li>Tap on the downloaded profile</li>
                <li>Tap Install → Enter passcode</li>
                <li>Go to Settings → General → About → Certificate Trust Settings</li>
                <li>Enable trust for SafeOps CA</li>
                {{else if eq .OSType "Android"}}
                <li>Click "Download Certificate"</li>
                <li>Go to Settings → Security → Install from storage</li>
                <li>Select the downloaded certificate</li>
                <li>Name it "SafeOps CA"</li>
                <li>Select "VPN and apps" for credential use</li>
                {{else}}
                <li>Click "Download Certificate"</li>
                <li>Install the certificate according to your OS</li>
                <li>Mark it as trusted for SSL/TLS</li>
                {{end}}
            </ol>
        </div>
        
        <div class="footer">
            SafeOps Network Security • Your IP: {{.ClientIP}}
        </div>
    </div>
</body>
</html>`

var successTemplate = `<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>{{.Title}}</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
            background: linear-gradient(135deg, #0f3460 0%, #16213e 50%, #1a1a2e 100%);
            min-height: 100vh;
            display: flex;
            align-items: center;
            justify-content: center;
            color: #fff;
        }
        .container {
            background: rgba(255,255,255,0.1);
            backdrop-filter: blur(20px);
            border-radius: 24px;
            padding: 48px;
            max-width: 500px;
            width: 90%;
            text-align: center;
            box-shadow: 0 25px 50px rgba(0,0,0,0.3);
        }
        .success-icon {
            width: 100px;
            height: 100px;
            background: linear-gradient(135deg, #10b981, #059669);
            border-radius: 50%;
            margin: 0 auto 24px;
            display: flex;
            align-items: center;
            justify-content: center;
            font-size: 48px;
            animation: pulse 2s infinite;
        }
        @keyframes pulse {
            0%, 100% { transform: scale(1); }
            50% { transform: scale(1.05); }
        }
        h1 { font-size: 28px; margin-bottom: 16px; color: #10b981; }
        p { color: rgba(255,255,255,0.8); margin-bottom: 24px; line-height: 1.6; }
        .btn {
            display: inline-block;
            background: linear-gradient(135deg, #10b981, #059669);
            color: white;
            text-decoration: none;
            padding: 14px 36px;
            border-radius: 50px;
            font-size: 16px;
            font-weight: 600;
        }
    </style>
    <script>
        // Auto-redirect after 5 seconds
        setTimeout(function() {
            window.location.href = 'https://www.google.com';
        }, 5000);
    </script>
</head>
<body>
    <div class="container">
        <div class="success-icon">✓</div>
        <h1>Certificate Installed!</h1>
        <p>Your device is now secured and ready to use the network.</p>
        <p>You will be redirected automatically in 5 seconds...</p>
        <a href="https://www.google.com" class="btn">Continue to Internet</a>
    </div>
</body>
</html>`
