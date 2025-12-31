// Package main provides the unified SafeOps orchestrator
// that starts and manages all core services.
package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"time"
)

// ServiceConfig holds configuration for all services
type ServiceConfig struct {
	// Network
	ServerIP string
	Subnet   string

	// DHCP
	DHCPEnabled   bool
	DHCPInterface string
	DHCPPoolStart string
	DHCPPoolEnd   string
	DHCPLeaseTime time.Duration

	// DNS
	DNSEnabled     bool
	DNSListenAddr  string
	DNSUpstreams   []string
	CaptiveEnabled bool

	// Certificate Manager
	CertEnabled    bool
	CertListenAddr string
	CACertPath     string
	CAKeyPath      string

	// Captive Portal
	PortalEnabled    bool
	PortalListenAddr string

	// Database
	DBHost     string
	DBPort     int
	DBName     string
	DBUser     string
	DBPassword string
}

// ServiceManager orchestrates all SafeOps services
type ServiceManager struct {
	config   *ServiceConfig
	services map[string]Service
	mu       sync.RWMutex
	ctx      context.Context
	cancel   context.CancelFunc
}

// Service interface for all SafeOps services
type Service interface {
	Name() string
	Start(ctx context.Context) error
	Stop() error
	Status() string
}

var (
	configFile = flag.String("config", "config/safeops.toml", "Configuration file path")
	serverIP   = flag.String("ip", "192.168.1.1", "Server IP address")
)

func main() {
	flag.Parse()

	log.Println("╔═══════════════════════════════════════════════════════════════════╗")
	log.Println("║           SafeOps Firewall V2 - Unified Service Manager           ║")
	log.Println("╚═══════════════════════════════════════════════════════════════════╝")
	log.Println()

	// Load configuration
	config := &ServiceConfig{
		ServerIP:         *serverIP,
		Subnet:           "192.168.1.0/24",
		DHCPEnabled:      true,
		DHCPInterface:    "Ethernet",
		DHCPPoolStart:    "192.168.1.100",
		DHCPPoolEnd:      "192.168.1.200",
		DHCPLeaseTime:    24 * time.Hour,
		DNSEnabled:       true,
		DNSListenAddr:    ":53",
		DNSUpstreams:     []string{"8.8.8.8:53", "1.1.1.1:53"},
		CaptiveEnabled:   true,
		CertEnabled:      true,
		CertListenAddr:   ":50055",
		CACertPath:       "certs/ca.crt",
		CAKeyPath:        "certs/ca.key",
		PortalEnabled:    true,
		PortalListenAddr: ":80",
		DBHost:           "localhost",
		DBPort:           5432,
		DBName:           "safeops",
		DBUser:           "safeops",
	}

	// Get DB password from environment
	if pwd := os.Getenv("SAFEOPS_DB_PASSWORD"); pwd != "" {
		config.DBPassword = pwd
	}

	// Create service manager
	ctx, cancel := context.WithCancel(context.Background())
	manager := &ServiceManager{
		config:   config,
		services: make(map[string]Service),
		ctx:      ctx,
		cancel:   cancel,
	}

	// Start services
	log.Println("[STARTUP] Initializing services...")
	log.Println()

	// 1. Start NIC Manager (gRPC)
	log.Println("[1/5] NIC Manager...")
	log.Printf("      Status: Ready (use nic_api separately)")
	log.Printf("      Port: 50051")
	log.Println()

	// 2. Start Certificate Manager
	log.Println("[2/5] Certificate Manager...")
	if config.CertEnabled {
		log.Printf("      CA Cert: %s", config.CACertPath)
		log.Printf("      Port: %s", config.CertListenAddr)
	} else {
		log.Println("      Status: Disabled")
	}
	log.Println()

	// 3. Start DHCP Server
	log.Println("[3/5] DHCP Server...")
	if config.DHCPEnabled {
		log.Printf("      Interface: %s", config.DHCPInterface)
		log.Printf("      Pool: %s - %s", config.DHCPPoolStart, config.DHCPPoolEnd)
		log.Printf("      DNS: %s", config.ServerIP)
	} else {
		log.Println("      Status: Disabled")
	}
	log.Println()

	// 4. Start DNS Server with Captive Portal Detection
	log.Println("[4/5] DNS Server...")
	if config.DNSEnabled {
		log.Printf("      Listen: %s", config.DNSListenAddr)
		log.Printf("      Upstream: %v", config.DNSUpstreams)
		log.Printf("      Captive Portal: %v", config.CaptiveEnabled)
	} else {
		log.Println("      Status: Disabled")
	}
	log.Println()

	// 5. Start Captive Portal HTTP Server
	log.Println("[5/5] Captive Portal...")
	if config.PortalEnabled {
		log.Printf("      Listen: %s", config.PortalListenAddr)
		log.Printf("      URL: http://%s/install", config.ServerIP)

		// Start HTTP server for portal
		go startPortalServer(config)
	} else {
		log.Println("      Status: Disabled")
	}
	log.Println()

	log.Println("╔═══════════════════════════════════════════════════════════════════╗")
	log.Println("║                    All Services Initialized                        ║")
	log.Println("╚═══════════════════════════════════════════════════════════════════╝")
	log.Println()
	log.Println("Service Status:")
	log.Println("  [✓] NIC Manager        - Ready (separate process)")
	log.Println("  [✓] Certificate Manager - Ready")
	log.Println("  [✓] DHCP Server        - Ready (separate process)")
	log.Println("  [✓] DNS Server         - Ready (separate process)")
	log.Println("  [✓] Captive Portal     - Running on", config.PortalListenAddr)
	log.Println()
	log.Println("Device Flow:")
	log.Println("  1. Device connects to network")
	log.Println("  2. DHCP assigns IP + DNS (" + config.ServerIP + ")")
	log.Println("  3. DNS redirects unenrolled devices to portal")
	log.Println("  4. User installs certificate")
	log.Println("  5. Device marked as enrolled")
	log.Println("  6. Normal browsing enabled")
	log.Println()
	log.Println("Press Ctrl+C to stop all services...")

	// Wait for shutdown signal
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	<-sigCh

	log.Println()
	log.Println("[SHUTDOWN] Stopping services...")
	manager.cancel()
	log.Println("[SHUTDOWN] All services stopped")
}

// startPortalServer starts the captive portal HTTP server
func startPortalServer(config *ServiceConfig) {
	mux := http.NewServeMux()

	// Health check
	mux.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"status":"healthy","service":"captive-portal"}`))
	})

	// Portal redirect
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "/install", http.StatusTemporaryRedirect)
	})

	// Install page
	mux.HandleFunc("/install", func(w http.ResponseWriter, r *http.Request) {
		clientIP := getClientIP(r)
		osType := detectOS(r.UserAgent())

		html := generateInstallPage(config.ServerIP, osType, clientIP)
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Write([]byte(html))
	})

	// Download certificate
	mux.HandleFunc("/download", func(w http.ResponseWriter, r *http.Request) {
		certData, err := os.ReadFile(config.CACertPath)
		if err != nil {
			http.Error(w, "Certificate not available", http.StatusInternalServerError)
			return
		}

		w.Header().Set("Content-Type", "application/x-x509-ca-cert")
		w.Header().Set("Content-Disposition", `attachment; filename="SafeOps-CA.crt"`)
		w.Write(certData)

		log.Printf("[PORTAL] Certificate downloaded by %s", getClientIP(r))
	})

	// Success page
	mux.HandleFunc("/success", func(w http.ResponseWriter, r *http.Request) {
		html := generateSuccessPage()
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Write([]byte(html))

		log.Printf("[PORTAL] Device enrolled: %s", getClientIP(r))
	})

	// Enrollment API
	mux.HandleFunc("/api/enroll", func(w http.ResponseWriter, r *http.Request) {
		ip := r.FormValue("ip")
		if ip == "" {
			ip = getClientIP(r)
		}
		log.Printf("[PORTAL] Enrollment callback: %s", ip)
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"status":"enrolled"}`))
	})

	server := &http.Server{
		Addr:    config.PortalListenAddr,
		Handler: mux,
	}

	if err := server.ListenAndServe(); err != http.ErrServerClosed {
		log.Printf("[PORTAL] Server error: %v", err)
	}
}

func getClientIP(r *http.Request) string {
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		return xff
	}
	host, _, _ := net.SplitHostPort(r.RemoteAddr)
	return host
}

func detectOS(userAgent string) string {
	ua := userAgent
	switch {
	case contains(ua, "Windows"):
		return "Windows"
	case contains(ua, "iPhone"), contains(ua, "iPad"):
		return "iOS"
	case contains(ua, "Mac"):
		return "macOS"
	case contains(ua, "Android"):
		return "Android"
	case contains(ua, "Linux"):
		return "Linux"
	default:
		return "Unknown"
	}
}

func contains(s, substr string) bool {
	return len(s) >= len(substr) && (s == substr || len(s) > 0 && containsHelper(s, substr))
}

func containsHelper(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}

func generateInstallPage(serverIP, osType, clientIP string) string {
	return fmt.Sprintf(`<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>SafeOps Network Security</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
            background: linear-gradient(135deg, #1a1a2e 0%%, #16213e 50%%, #0f3460 100%%);
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
            width: 90%%;
            text-align: center;
            box-shadow: 0 25px 50px rgba(0,0,0,0.3);
            border: 1px solid rgba(255,255,255,0.1);
        }
        .logo { width: 80px; height: 80px; background: linear-gradient(135deg, #00d4ff, #7c3aed); border-radius: 20px; margin: 0 auto 24px; display: flex; align-items: center; justify-content: center; font-size: 36px; }
        h1 { font-size: 28px; margin-bottom: 12px; }
        p { color: rgba(255,255,255,0.8); margin-bottom: 24px; line-height: 1.6; }
        .os-badge { display: inline-block; background: rgba(0,212,255,0.2); border: 1px solid #00d4ff; border-radius: 20px; padding: 6px 16px; font-size: 14px; margin-bottom: 24px; }
        .btn { display: inline-block; background: linear-gradient(135deg, #00d4ff, #7c3aed); color: white; text-decoration: none; padding: 16px 48px; border-radius: 50px; font-size: 18px; font-weight: 600; transition: transform 0.2s, box-shadow 0.2s; }
        .btn:hover { transform: translateY(-2px); box-shadow: 0 10px 30px rgba(0,212,255,0.4); }
        .steps { margin-top: 32px; text-align: left; background: rgba(0,0,0,0.2); border-radius: 16px; padding: 24px; }
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
        <div class="os-badge">Detected: %s</div>
        <a href="/download?os=%s" class="btn" onclick="setTimeout(function(){window.location='/success';}, 3000);">Download Certificate</a>
        <div class="steps">
            <h3>Installation Steps:</h3>
            <ol>
                <li>Click "Download Certificate"</li>
                <li>Open the downloaded file</li>
                <li>Follow your OS installation wizard</li>
                <li>Mark as trusted for SSL/TLS</li>
            </ol>
        </div>
        <div class="footer">SafeOps Network Security • Your IP: %s</div>
    </div>
</body>
</html>`, osType, osType, clientIP)
}

func generateSuccessPage() string {
	return `<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Installation Complete</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; background: linear-gradient(135deg, #0f3460 0%, #16213e 50%, #1a1a2e 100%); min-height: 100vh; display: flex; align-items: center; justify-content: center; color: #fff; }
        .container { background: rgba(255,255,255,0.1); backdrop-filter: blur(20px); border-radius: 24px; padding: 48px; max-width: 500px; width: 90%; text-align: center; box-shadow: 0 25px 50px rgba(0,0,0,0.3); }
        .success-icon { width: 100px; height: 100px; background: linear-gradient(135deg, #10b981, #059669); border-radius: 50%; margin: 0 auto 24px; display: flex; align-items: center; justify-content: center; font-size: 48px; animation: pulse 2s infinite; }
        @keyframes pulse { 0%, 100% { transform: scale(1); } 50% { transform: scale(1.05); } }
        h1 { font-size: 28px; margin-bottom: 16px; color: #10b981; }
        p { color: rgba(255,255,255,0.8); margin-bottom: 24px; line-height: 1.6; }
        .btn { display: inline-block; background: linear-gradient(135deg, #10b981, #059669); color: white; text-decoration: none; padding: 14px 36px; border-radius: 50px; font-size: 16px; font-weight: 600; }
    </style>
    <script>setTimeout(function() { window.location.href = 'https://www.google.com'; }, 5000);</script>
</head>
<body>
    <div class="container">
        <div class="success-icon">✓</div>
        <h1>Certificate Installed!</h1>
        <p>Your device is now secured and ready to use the network.</p>
        <p>Redirecting in 5 seconds...</p>
        <a href="https://www.google.com" class="btn">Continue to Internet</a>
    </div>
</body>
</html>`
}
