// Package blockpage serves a block page for DNS-redirected domains.
// When a domain is blocked via DNS redirect to 127.0.0.1, the browser
// connects here and receives an HTML page explaining why access was denied.
// Serves on both HTTP (:80) and HTTPS (:443) with dynamic per-domain certificates.
package blockpage

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"math/big"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"safeops-engine/internal/logger"
)

// DeviceInfo represents a network device that accessed the CA page.
type DeviceInfo struct {
	IP        string    `json:"ip"`
	UserAgent string    `json:"user_agent"`
	FirstSeen time.Time `json:"first_seen"`
	LastSeen  time.Time `json:"last_seen"`
	Downloads int       `json:"downloads"`
}

// Server serves block pages for DNS-redirected domains.
type Server struct {
	log         *logger.Logger
	httpServer  *http.Server
	httpsServer *http.Server
	ca          *blockPageCA

	// Track devices that downloaded the CA cert
	devices sync.Map // IP string -> *DeviceInfo
}

// NewServer creates a block page server on HTTP and HTTPS.
func NewServer(log *logger.Logger, httpAddr, httpsAddr string) *Server {
	s := &Server{log: log}

	mux := http.NewServeMux()
	mux.HandleFunc("/ca", s.handleCAPage)
	mux.HandleFunc("/ca/download", s.handleCADownload)
	mux.HandleFunc("/ca/devices", s.handleCADevices)
	mux.HandleFunc("/", s.handleBlockPage)

	s.httpServer = &http.Server{
		Addr:         httpAddr,
		Handler:      mux,
		ReadTimeout:  5 * time.Second,
		WriteTimeout: 5 * time.Second,
	}

	// Generate block page CA for dynamic per-domain HTTPS certificates
	ca, err := newBlockPageCA()
	if err != nil {
		log.Warn("Failed to generate block page CA", map[string]interface{}{
			"error": err.Error(),
		})
	} else {
		s.ca = ca
		s.httpsServer = &http.Server{
			Addr:         httpsAddr,
			Handler:      mux,
			ReadTimeout:  5 * time.Second,
			WriteTimeout: 5 * time.Second,
			TLSConfig: &tls.Config{
				GetCertificate: ca.getCertificate,
			},
		}
	}

	return s
}

// Start starts both HTTP and HTTPS block page servers in the background.
func (s *Server) Start() error {
	// Install CA cert into Windows trusted root store (so Chrome accepts our block page certs)
	if s.ca != nil {
		if err := s.ca.installCAToCertStore(s.log); err != nil {
			s.log.Warn("Failed to install block page CA to cert store", map[string]interface{}{
				"error": err.Error(),
			})
			fmt.Println("  Block page CA:    NOT installed (run as admin to install)")
		} else {
			fmt.Println("  Block page CA:    installed in Windows trusted root store")
		}
	}

	// Start HTTP server (port 80)
	go func() {
		s.log.Info("Block page server starting (HTTP)", map[string]interface{}{
			"address": s.httpServer.Addr,
		})
		if err := s.httpServer.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			s.log.Warn("Block page HTTP server error", map[string]interface{}{
				"error": err.Error(),
			})
		}
	}()

	// Start HTTPS server (port 443) with dynamic SNI certs
	if s.httpsServer != nil {
		go func() {
			s.log.Info("Block page server starting (HTTPS)", map[string]interface{}{
				"address": s.httpsServer.Addr,
			})
			// ListenAndServeTLS with empty strings because TLSConfig.GetCertificate handles it
			ln, err := tls.Listen("tcp", s.httpsServer.Addr, s.httpsServer.TLSConfig)
			if err != nil {
				s.log.Warn("Block page HTTPS listen error", map[string]interface{}{
					"error": err.Error(),
				})
				return
			}
			if err := s.httpsServer.Serve(ln); err != nil && err != http.ErrServerClosed {
				s.log.Warn("Block page HTTPS server error", map[string]interface{}{
					"error": err.Error(),
				})
			}
		}()
	}

	return nil
}

// Stop gracefully shuts down both servers.
func (s *Server) Stop() {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	if s.httpServer != nil {
		s.httpServer.Shutdown(ctx)
	}
	if s.httpsServer != nil {
		s.httpsServer.Shutdown(ctx)
	}
	s.log.Info("Block page servers stopped", nil)
}

// handleBlockPage serves the HTML block page for any request.
// The Host header tells us which domain was blocked.
func (s *Server) handleBlockPage(w http.ResponseWriter, r *http.Request) {
	domain := r.Host
	if domain == "" {
		domain = "unknown"
	}

	timestamp := time.Now().Format("2006-01-02 15:04:05 MST")

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store, no-cache, must-revalidate")
	w.Header().Set("Server", "SafeOps-Engine")
	w.WriteHeader(http.StatusForbidden)

	fmt.Fprintf(w, blockPageHTML, domain, domain, timestamp)
}

// handleCAPage serves an HTML page for downloading the SafeOps CA certificate.
// Network devices visit http://127.0.0.1/ca to trust the block page HTTPS certs.
func (s *Server) handleCAPage(w http.ResponseWriter, r *http.Request) {
	if s.ca == nil {
		http.Error(w, "CA not available", http.StatusServiceUnavailable)
		return
	}

	clientIP := r.RemoteAddr
	if colon := strings.LastIndex(clientIP, ":"); colon != -1 {
		clientIP = clientIP[:colon]
	}
	clientIP = strings.Trim(clientIP, "[]")

	ua := r.UserAgent()

	// Track device visit
	s.trackDevice(clientIP, ua, false)

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Server", "SafeOps-Engine")

	fmt.Fprintf(w, caPageHTML, clientIP, ua, time.Now().Format("2006-01-02 15:04:05 MST"))
}

// handleCADownload serves the CA certificate PEM file for download.
func (s *Server) handleCADownload(w http.ResponseWriter, r *http.Request) {
	if s.ca == nil {
		http.Error(w, "CA not available", http.StatusServiceUnavailable)
		return
	}

	clientIP := r.RemoteAddr
	if colon := strings.LastIndex(clientIP, ":"); colon != -1 {
		clientIP = clientIP[:colon]
	}
	clientIP = strings.Trim(clientIP, "[]")

	// Track download
	s.trackDevice(clientIP, r.UserAgent(), true)

	pemData := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: s.ca.caCertDER,
	})

	w.Header().Set("Content-Type", "application/x-pem-file")
	w.Header().Set("Content-Disposition", "attachment; filename=safeops-ca.crt")
	w.Header().Set("Content-Length", fmt.Sprintf("%d", len(pemData)))
	w.Write(pemData)

	s.log.Info("CA cert downloaded", map[string]interface{}{
		"client_ip":  clientIP,
		"user_agent": r.UserAgent(),
	})
}

// handleCADevices returns JSON with all devices that visited the CA page.
func (s *Server) handleCADevices(w http.ResponseWriter, r *http.Request) {
	var devices []DeviceInfo
	s.devices.Range(func(_, v interface{}) bool {
		if di, ok := v.(*DeviceInfo); ok {
			devices = append(devices, *di)
		}
		return true
	})

	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"devices": devices,
		"count":   len(devices),
	})
}

// trackDevice records a device visit or download.
func (s *Server) trackDevice(ip, userAgent string, isDownload bool) {
	now := time.Now()
	if v, ok := s.devices.Load(ip); ok {
		di := v.(*DeviceInfo)
		di.LastSeen = now
		if di.UserAgent == "" {
			di.UserAgent = userAgent
		}
		if isDownload {
			di.Downloads++
		}
		return
	}

	di := &DeviceInfo{
		IP:        ip,
		UserAgent: userAgent,
		FirstSeen: now,
		LastSeen:  now,
	}
	if isDownload {
		di.Downloads = 1
	}
	s.devices.Store(ip, di)
}

// ============================================================================
// Block page CA — generates per-domain TLS certificates dynamically
// ============================================================================

// blockPageCA holds a self-signed CA that dynamically generates
// per-domain certificates when a blocked domain connects on HTTPS.
// This means the browser sees a cert that matches the domain (e.g., facebook.com)
// instead of a generic cert. The browser will still show a cert warning
// because the CA is not trusted, but it won't be a hostname mismatch error.
type blockPageCA struct {
	caCert    *x509.Certificate
	caKey     *ecdsa.PrivateKey
	caCertDER []byte

	// Cache generated certs to avoid re-generating for repeated requests
	mu    sync.RWMutex
	cache map[string]*tls.Certificate
}

// newBlockPageCA generates a self-signed CA for the block page server.
func newBlockPageCA() (*blockPageCA, error) {
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("generate CA key: %w", err)
	}

	serial, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))

	caTemplate := &x509.Certificate{
		SerialNumber: serial,
		Subject: pkix.Name{
			Organization: []string{"SafeOps Firewall"},
			CommonName:   "SafeOps Block Page CA",
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(10 * 365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLen:            0,
	}

	caCertDER, err := x509.CreateCertificate(rand.Reader, caTemplate, caTemplate, &caKey.PublicKey, caKey)
	if err != nil {
		return nil, fmt.Errorf("create CA cert: %w", err)
	}

	caCert, err := x509.ParseCertificate(caCertDER)
	if err != nil {
		return nil, fmt.Errorf("parse CA cert: %w", err)
	}

	return &blockPageCA{
		caCert:    caCert,
		caKey:     caKey,
		caCertDER: caCertDER,
		cache:     make(map[string]*tls.Certificate),
	}, nil
}

// getCertificate is called by TLS for each incoming connection.
// It generates (or returns cached) a certificate matching the requested SNI domain.
func (ca *blockPageCA) getCertificate(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
	domain := hello.ServerName
	if domain == "" {
		domain = "blocked.safeops.local"
	}

	// Check cache
	ca.mu.RLock()
	if cert, ok := ca.cache[domain]; ok {
		ca.mu.RUnlock()
		return cert, nil
	}
	ca.mu.RUnlock()

	// Generate new cert for this domain
	cert, err := ca.generateCertForDomain(domain)
	if err != nil {
		return nil, err
	}

	// Cache it (limit cache size to prevent unbounded growth)
	ca.mu.Lock()
	if len(ca.cache) > 10000 {
		// Clear cache when it gets too large
		ca.cache = make(map[string]*tls.Certificate)
	}
	ca.cache[domain] = &cert
	ca.mu.Unlock()

	return &cert, nil
}

// generateCertForDomain creates a TLS certificate valid for the given domain,
// signed by the block page CA.
func (ca *blockPageCA) generateCertForDomain(domain string) (tls.Certificate, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return tls.Certificate{}, err
	}

	serial, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))

	template := &x509.Certificate{
		SerialNumber: serial,
		Subject: pkix.Name{
			Organization: []string{"SafeOps Firewall - Blocked"},
			CommonName:   domain,
		},
		DNSNames:              []string{domain},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, ca.caCert, &key.PublicKey, ca.caKey)
	if err != nil {
		return tls.Certificate{}, err
	}

	return tls.Certificate{
		Certificate: [][]byte{certDER, ca.caCertDER},
		PrivateKey:  key,
	}, nil
}

// installCAToCertStore exports the CA cert to a PEM file and installs it
// into the Windows trusted root certificate store using certutil.
// This makes Chrome accept our dynamically generated per-domain certs
// for blocked HTTPS sites (including HSTS sites like Facebook).
func (ca *blockPageCA) installCAToCertStore(log *logger.Logger) error {
	// Export CA cert to temp PEM file
	exePath, err := os.Executable()
	if err != nil {
		return fmt.Errorf("get executable path: %w", err)
	}
	certPath := filepath.Join(filepath.Dir(exePath), "safeops-blockpage-ca.crt")

	pemData := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: ca.caCertDER,
	})

	if err := os.WriteFile(certPath, pemData, 0644); err != nil {
		return fmt.Errorf("write CA cert: %w", err)
	}

	// Check if already installed by looking for our cert in the root store
	checkCmd := exec.Command("certutil", "-store", "Root", "SafeOps Block Page CA")
	if checkOutput, checkErr := checkCmd.CombinedOutput(); checkErr == nil {
		// Found existing cert — check if it matches by looking for our serial
		if len(checkOutput) > 0 {
			log.Info("Block page CA already in cert store, replacing", nil)
			// Delete old one first
			delCmd := exec.Command("certutil", "-delstore", "Root", "SafeOps Block Page CA")
			delCmd.Run() // Ignore errors
		}
	}

	// Install into trusted root store
	cmd := exec.Command("certutil", "-addstore", "Root", certPath)
	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("certutil -addstore failed: %w (output: %s)", err, string(output))
	}

	log.Info("Block page CA installed in trusted root store", map[string]interface{}{
		"cert_path": certPath,
	})

	return nil
}

// blockPageHTML is the HTML template for the block page.
const blockPageHTML = `<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Access Blocked - %s</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body {
            font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, "Helvetica Neue", Arial, sans-serif;
            background: linear-gradient(135deg, #1a1a2e 0%%, #16213e 50%%, #0f3460 100%%);
            min-height: 100vh;
            display: flex;
            align-items: center;
            justify-content: center;
            padding: 20px;
        }
        .container {
            background: rgba(255, 255, 255, 0.95);
            border-radius: 16px;
            box-shadow: 0 20px 60px rgba(0, 0, 0, 0.5);
            max-width: 580px;
            width: 100%%;
            padding: 48px 40px;
            text-align: center;
        }
        .shield {
            width: 80px; height: 80px; margin: 0 auto 24px;
            background: linear-gradient(135deg, #e53e3e, #c53030);
            border-radius: 50%%;
            display: flex; align-items: center; justify-content: center;
            box-shadow: 0 8px 32px rgba(229, 62, 62, 0.3);
        }
        .shield svg { width: 40px; height: 40px; fill: white; }
        h1 { color: #1a202c; font-size: 28px; margin-bottom: 12px; font-weight: 700; }
        .subtitle { color: #718096; font-size: 16px; margin-bottom: 32px; line-height: 1.5; }
        .domain-box {
            background: #fff5f5; border: 2px solid #fed7d7; border-left: 4px solid #e53e3e;
            padding: 20px; margin: 24px 0; text-align: left; border-radius: 8px;
        }
        .domain-box .label {
            font-weight: 600; color: #c53030; margin-bottom: 8px;
            font-size: 12px; text-transform: uppercase; letter-spacing: 1px;
        }
        .domain-box .value {
            color: #2d3748; font-size: 18px; font-family: "Courier New", monospace;
            word-break: break-all;
        }
        .info {
            display: flex; justify-content: space-between;
            margin-top: 24px; padding: 16px; background: #f7fafc; border-radius: 8px;
        }
        .info-item { text-align: left; }
        .info-item .label {
            font-size: 11px; color: #a0aec0; text-transform: uppercase;
            letter-spacing: 0.5px; margin-bottom: 4px;
        }
        .info-item .value { font-size: 13px; color: #4a5568; font-family: "Courier New", monospace; }
        .footer {
            margin-top: 32px; padding-top: 24px; border-top: 1px solid #e2e8f0;
            color: #a0aec0; font-size: 13px;
        }
        .footer-brand { color: #4a5568; font-weight: 700; font-size: 14px; margin-bottom: 6px; }
    </style>
</head>
<body>
    <div class="container">
        <div class="shield">
            <svg viewBox="0 0 24 24"><path d="M12 1L3 5v6c0 5.55 3.84 10.74 9 12 5.16-1.26 9-6.45 9-12V5l-9-4zm-1 6h2v2h-2V7zm0 4h2v6h-2v-6z"/></svg>
        </div>
        <h1>Access Blocked</h1>
        <p class="subtitle">This website has been blocked by your network security policy.</p>

        <div class="domain-box">
            <div class="label">Blocked Domain</div>
            <div class="value">%s</div>
        </div>

        <div class="info">
            <div class="info-item">
                <div class="label">Enforced By</div>
                <div class="value">SafeOps Firewall</div>
            </div>
            <div class="info-item">
                <div class="label">Method</div>
                <div class="value">DNS Redirect</div>
            </div>
            <div class="info-item">
                <div class="label">Time</div>
                <div class="value">%s</div>
            </div>
        </div>

        <div class="footer">
            <div class="footer-brand">SafeOps Network Security</div>
            <div>If you believe this is an error, contact your network administrator.</div>
        </div>
    </div>
</body>
</html>`

// caPageHTML is the HTML template for the CA certificate download page.
// Format args: %s = client IP, %s = user agent, %s = timestamp
const caPageHTML = `<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>SafeOps - Install Network Certificate</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body {
            font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, "Helvetica Neue", Arial, sans-serif;
            background: linear-gradient(135deg, #1a1a2e 0%%, #16213e 50%%, #0f3460 100%%);
            min-height: 100vh;
            display: flex;
            align-items: center;
            justify-content: center;
            padding: 20px;
        }
        .container {
            background: rgba(255, 255, 255, 0.97);
            border-radius: 16px;
            box-shadow: 0 20px 60px rgba(0, 0, 0, 0.5);
            max-width: 640px;
            width: 100%%;
            padding: 48px 40px;
        }
        .header {
            text-align: center;
            margin-bottom: 32px;
        }
        .shield {
            width: 72px; height: 72px; margin: 0 auto 20px;
            background: linear-gradient(135deg, #38a169, #2f855a);
            border-radius: 50%%;
            display: flex; align-items: center; justify-content: center;
            box-shadow: 0 8px 32px rgba(56, 161, 105, 0.3);
        }
        .shield svg { width: 36px; height: 36px; fill: white; }
        h1 { color: #1a202c; font-size: 26px; font-weight: 700; }
        .subtitle { color: #718096; font-size: 15px; margin-top: 8px; }
        .download-btn {
            display: block; width: 100%%; padding: 16px; margin: 28px 0;
            background: linear-gradient(135deg, #38a169, #2f855a);
            color: white; font-size: 17px; font-weight: 600;
            border: none; border-radius: 10px; cursor: pointer;
            text-decoration: none; text-align: center;
            box-shadow: 0 4px 16px rgba(56, 161, 105, 0.3);
            transition: transform 0.1s;
        }
        .download-btn:hover { transform: translateY(-1px); }
        .download-btn:active { transform: translateY(1px); }
        .steps {
            background: #f7fafc; border-radius: 10px; padding: 24px;
            margin: 24px 0;
        }
        .steps h3 {
            color: #2d3748; font-size: 15px; margin-bottom: 16px;
            text-transform: uppercase; letter-spacing: 0.5px;
        }
        .step {
            display: flex; align-items: flex-start; margin-bottom: 14px;
        }
        .step:last-child { margin-bottom: 0; }
        .step-num {
            background: #38a169; color: white; width: 24px; height: 24px;
            border-radius: 50%%; display: flex; align-items: center;
            justify-content: center; font-size: 13px; font-weight: 700;
            flex-shrink: 0; margin-right: 12px; margin-top: 1px;
        }
        .step-text { color: #4a5568; font-size: 14px; line-height: 1.5; }
        .step-text strong { color: #2d3748; }
        .device-info {
            background: #edf2f7; border-radius: 8px; padding: 16px;
            margin-top: 24px;
        }
        .device-info h4 {
            color: #4a5568; font-size: 12px; text-transform: uppercase;
            letter-spacing: 1px; margin-bottom: 10px;
        }
        .info-row {
            display: flex; justify-content: space-between;
            padding: 6px 0; border-bottom: 1px solid #e2e8f0;
        }
        .info-row:last-child { border-bottom: none; }
        .info-label { color: #a0aec0; font-size: 13px; }
        .info-value { color: #2d3748; font-size: 13px; font-family: "Courier New", monospace; max-width: 340px; word-break: break-all; text-align: right; }
        .footer {
            text-align: center; margin-top: 28px; padding-top: 20px;
            border-top: 1px solid #e2e8f0; color: #a0aec0; font-size: 13px;
        }
        .footer-brand { color: #4a5568; font-weight: 700; margin-bottom: 4px; }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <div class="shield">
                <svg viewBox="0 0 24 24"><path d="M12 1L3 5v6c0 5.55 3.84 10.74 9 12 5.16-1.26 9-6.45 9-12V5l-9-4zm-1 15l-4-4 1.41-1.41L11 13.17l5.59-5.59L18 9l-7 7z"/></svg>
            </div>
            <h1>Install SafeOps Certificate</h1>
            <p class="subtitle">Trust this certificate to see proper block pages on HTTPS sites.</p>
        </div>

        <a href="/ca/download" class="download-btn">Download SafeOps CA Certificate</a>

        <div class="steps">
            <h3>Installation Steps</h3>
            <div class="step">
                <div class="step-num">1</div>
                <div class="step-text">Click <strong>Download</strong> above to save <strong>safeops-ca.crt</strong></div>
            </div>
            <div class="step">
                <div class="step-num">2</div>
                <div class="step-text"><strong>Windows:</strong> Double-click the .crt file, click <strong>Install Certificate</strong> &#8594; <strong>Local Machine</strong> &#8594; <strong>Trusted Root Certification Authorities</strong></div>
            </div>
            <div class="step">
                <div class="step-num">3</div>
                <div class="step-text"><strong>macOS:</strong> Double-click to add to Keychain, then open <strong>Keychain Access</strong> &#8594; find "SafeOps" &#8594; set to <strong>Always Trust</strong></div>
            </div>
            <div class="step">
                <div class="step-num">4</div>
                <div class="step-text"><strong>Android:</strong> Settings &#8594; Security &#8594; Install from storage &#8594; select the file</div>
            </div>
            <div class="step">
                <div class="step-num">5</div>
                <div class="step-text"><strong>iOS:</strong> Open in Safari &#8594; Install Profile &#8594; Settings &#8594; General &#8594; About &#8594; Certificate Trust Settings &#8594; enable SafeOps</div>
            </div>
        </div>

        <div class="device-info">
            <h4>Your Device</h4>
            <div class="info-row">
                <span class="info-label">IP Address</span>
                <span class="info-value">%s</span>
            </div>
            <div class="info-row">
                <span class="info-label">User Agent</span>
                <span class="info-value">%s</span>
            </div>
            <div class="info-row">
                <span class="info-label">Timestamp</span>
                <span class="info-value">%s</span>
            </div>
        </div>

        <div class="footer">
            <div class="footer-brand">SafeOps Network Security</div>
            <div>This certificate allows your device to display block pages securely over HTTPS.</div>
        </div>
    </div>
</body>
</html>`
