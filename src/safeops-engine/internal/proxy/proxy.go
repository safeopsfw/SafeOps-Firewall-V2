package proxy

import (
	"fmt"
	"net/http"
	"os/exec"
	"runtime"
	"strings"
	"sync/atomic"

	"github.com/elazarl/goproxy"
)

// InlineProxy handles HTTP/HTTPS traffic inline
// HTTPS: Pass-through (no MITM, no cert needed)
// HTTP: Can inspect and log
type InlineProxy struct {
	proxy   *goproxy.ProxyHttpServer
	port    int
	running bool

	// Stats
	requests uint64
	connects uint64 // HTTPS CONNECT requests (domain visibility)
	blocked  uint64
}

// New creates a new inline proxy on the specified port
// NO HTTPS MITM - just pass-through with domain logging
func New(port int) *InlineProxy {
	proxyServer := goproxy.NewProxyHttpServer()

	p := &InlineProxy{
		proxy: proxyServer,
		port:  port,
	}

	// HTTPS: Pass-through (no MITM) but log the domain
	proxyServer.OnRequest().HandleConnectFunc(func(host string, ctx *goproxy.ProxyCtx) (*goproxy.ConnectAction, string) {
		atomic.AddUint64(&p.connects, 1)

		// Skip logging for localhost/local traffic
		if strings.HasPrefix(host, "127.") || strings.HasPrefix(host, "localhost") ||
			strings.HasPrefix(host, "[::1]") || strings.HasPrefix(host, "192.168.") ||
			strings.HasPrefix(host, "10.") || strings.HasPrefix(host, "172.") {
			return goproxy.OkConnect, host
		}

		// Skip Windows connectivity tests
		if strings.Contains(host, "msftncsi") || strings.Contains(host, "msftconnecttest") {
			return goproxy.OkConnect, host
		}

		// Print HTTPS domain being visited (real-time visibility)
		fmt.Printf("[PROXY] CONNECT %s\n", host)

		// TODO: Add domain-based blocking here
		// Example: if strings.Contains(host, "malware.com") { return goproxy.RejectConnect, host }

		return goproxy.OkConnect, host // Forward unchanged, no MITM
	})

	// HTTP: Can fully inspect (no cert needed for HTTP)
	proxyServer.OnRequest().DoFunc(func(r *http.Request, ctx *goproxy.ProxyCtx) (*http.Request, *http.Response) {
		atomic.AddUint64(&p.requests, 1)

		// Skip logging for local/test traffic
		if strings.Contains(r.Host, "msftncsi") || strings.Contains(r.Host, "msftconnecttest") ||
			strings.HasPrefix(r.Host, "127.") || strings.HasPrefix(r.Host, "localhost") ||
			strings.Contains(r.Host, "ipv6.") {
			return r, nil
		}

		// Print HTTP request (full visibility)
		fmt.Printf("[PROXY] %s %s%s\n", r.Method, r.Host, r.URL.Path)

		return r, nil // Forward unchanged
	})

	return p
}

// ConfigureSystemProxy sets up Windows system proxy to use this proxy
func ConfigureSystemProxy(port int) error {
	if runtime.GOOS != "windows" {
		return fmt.Errorf("only Windows supported")
	}

	proxyServer := fmt.Sprintf("127.0.0.1:%d", port)

	// Set ProxyServer
	cmd1 := exec.Command("reg", "add",
		`HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings`,
		"/v", "ProxyServer", "/t", "REG_SZ", "/d", proxyServer, "/f")
	if err := cmd1.Run(); err != nil {
		return fmt.Errorf("failed to set ProxyServer: %w", err)
	}

	// Enable proxy
	cmd2 := exec.Command("reg", "add",
		`HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings`,
		"/v", "ProxyEnable", "/t", "REG_DWORD", "/d", "1", "/f")
	if err := cmd2.Run(); err != nil {
		return fmt.Errorf("failed to enable proxy: %w", err)
	}

	fmt.Printf("[PROXY] System proxy configured: %s\n", proxyServer)
	return nil
}

// DisableSystemProxy disables Windows system proxy
func DisableSystemProxy() error {
	if runtime.GOOS != "windows" {
		return nil
	}

	fmt.Println("[PROXY] Disabling system proxy...")
	cmd := exec.Command("reg", "add",
		`HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings`,
		"/v", "ProxyEnable", "/t", "REG_DWORD", "/d", "0", "/f")
	return cmd.Run()
}

// Start starts the proxy server
func (p *InlineProxy) Start() error {
	p.running = true

	addr := fmt.Sprintf(":%d", p.port)
	fmt.Printf("[PROXY] Starting pass-through proxy on %s (NO HTTPS MITM)\n", addr)

	return http.ListenAndServe(addr, p.proxy)
}

// GetStats returns proxy statistics
func (p *InlineProxy) GetStats() (requests, blocked uint64) {
	return atomic.LoadUint64(&p.requests) + atomic.LoadUint64(&p.connects), atomic.LoadUint64(&p.blocked)
}

// GetDetailedStats returns all proxy stats
func (p *InlineProxy) GetDetailedStats() (http, https, blocked uint64) {
	return atomic.LoadUint64(&p.requests), atomic.LoadUint64(&p.connects), atomic.LoadUint64(&p.blocked)
}

// Block increments the blocked counter (for IDS/IPS)
func (p *InlineProxy) Block() {
	atomic.AddUint64(&p.blocked, 1)
}
