// Package blockpage serves a block page for DNS-redirected domains.
// When a domain is blocked via DNS redirect to 127.0.0.1, the browser
// connects here and receives an HTML page explaining why access was denied.
// Serves on both HTTP (:80) and HTTPS (:443) with a self-signed certificate.
package blockpage

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"math/big"
	"net/http"
	"time"

	"safeops-engine/internal/logger"
)

// Server serves block pages for DNS-redirected domains.
type Server struct {
	log         *logger.Logger
	httpServer  *http.Server
	httpsServer *http.Server
}

// NewServer creates a block page server on HTTP and HTTPS.
func NewServer(log *logger.Logger, httpAddr, httpsAddr string) *Server {
	s := &Server{log: log}

	mux := http.NewServeMux()
	mux.HandleFunc("/", s.handleBlockPage)

	s.httpServer = &http.Server{
		Addr:         httpAddr,
		Handler:      mux,
		ReadTimeout:  5 * time.Second,
		WriteTimeout: 5 * time.Second,
	}

	// Generate self-signed TLS certificate for HTTPS block page
	tlsCert, err := generateSelfSignedCert()
	if err != nil {
		log.Warn("Failed to generate self-signed cert for block page", map[string]interface{}{
			"error": err.Error(),
		})
	} else {
		s.httpsServer = &http.Server{
			Addr:         httpsAddr,
			Handler:      mux,
			ReadTimeout:  5 * time.Second,
			WriteTimeout: 5 * time.Second,
			TLSConfig: &tls.Config{
				Certificates: []tls.Certificate{tlsCert},
			},
		}
	}

	return s
}

// Start starts both HTTP and HTTPS block page servers in the background.
func (s *Server) Start() error {
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

	// Start HTTPS server (port 443) if cert was generated
	if s.httpsServer != nil {
		go func() {
			s.log.Info("Block page server starting (HTTPS)", map[string]interface{}{
				"address": s.httpsServer.Addr,
			})
			if err := s.httpsServer.ListenAndServeTLS("", ""); err != nil && err != http.ErrServerClosed {
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

// generateSelfSignedCert creates a self-signed TLS certificate in memory.
// The cert covers 127.0.0.1 and localhost, valid for 10 years.
func generateSelfSignedCert() (tls.Certificate, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("generate key: %w", err)
	}

	serial, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))

	template := &x509.Certificate{
		SerialNumber: serial,
		Subject: pkix.Name{
			Organization: []string{"SafeOps Firewall"},
			CommonName:   "SafeOps Block Page",
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(10 * 365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("create certificate: %w", err)
	}

	return tls.Certificate{
		Certificate: [][]byte{certDER},
		PrivateKey:  key,
	}, nil
}

// blockPageHTML is the HTML template for the block page.
const blockPageHTML = `<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Blocked - %s</title>
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
