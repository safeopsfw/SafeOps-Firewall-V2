// Package metrics provides HTTP handler for metrics endpoint.
package metrics

import (
	"compress/gzip"
	"context"
	"crypto/subtle"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

// HTTPHandler creates a metrics HTTP handler
type HTTPHandler struct {
	path     string
	gatherer prometheus.Gatherer
}

// NewHTTPHandler creates a new HTTP handler
func NewHTTPHandler(path string) *HTTPHandler {
	return &HTTPHandler{
		path:     path,
		gatherer: prometheus.DefaultGatherer,
	}
}

// WithGatherer sets a custom gatherer
func (h *HTTPHandler) WithGatherer(g prometheus.Gatherer) *HTTPHandler {
	h.gatherer = g
	return h
}

// ServeHTTP implements http.Handler
func (h *HTTPHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	promhttp.HandlerFor(h.gatherer, promhttp.HandlerOpts{}).ServeHTTP(w, r)
}

// InstrumentHandler wraps an HTTP handler with metrics
func InstrumentHandler(handler http.Handler, name string) http.Handler {
	return promhttp.InstrumentHandlerDuration(
		prometheus.NewHistogramVec(
			prometheus.HistogramOpts{
				Name:    name + "_request_duration_seconds",
				Help:    "Request duration",
				Buckets: DefaultBuckets,
			},
			[]string{"code", "method"},
		),
		promhttp.InstrumentHandlerCounter(
			prometheus.NewCounterVec(
				prometheus.CounterOpts{
					Name: name + "_requests_total",
					Help: "Total requests",
				},
				[]string{"code", "method"},
			),
			handler,
		),
	)
}

// HTTPMiddleware is a metrics middleware for HTTP handlers
type HTTPMiddleware struct {
	requestsTotal   *prometheus.CounterVec
	requestDuration *prometheus.HistogramVec
	inFlight        prometheus.Gauge
}

// NewHTTPMiddleware creates a new HTTP middleware
func NewHTTPMiddleware(namespace string) *HTTPMiddleware {
	m := &HTTPMiddleware{
		requestsTotal: prometheus.NewCounterVec(
			prometheus.CounterOpts{
				Namespace: namespace,
				Name:      "http_requests_total",
				Help:      "Total HTTP requests",
			},
			[]string{"method", "path", "status"},
		),
		requestDuration: prometheus.NewHistogramVec(
			prometheus.HistogramOpts{
				Namespace: namespace,
				Name:      "http_request_duration_seconds",
				Help:      "HTTP request duration",
				Buckets:   DefaultBuckets,
			},
			[]string{"method", "path"},
		),
		inFlight: prometheus.NewGauge(
			prometheus.GaugeOpts{
				Namespace: namespace,
				Name:      "http_requests_in_flight",
				Help:      "HTTP requests currently in flight",
			},
		),
	}

	prometheus.MustRegister(m.requestsTotal)
	prometheus.MustRegister(m.requestDuration)
	prometheus.MustRegister(m.inFlight)

	return m
}

// Wrap wraps an HTTP handler
func (m *HTTPMiddleware) Wrap(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		m.inFlight.Inc()
		defer m.inFlight.Dec()

		wrapped := &responseWriter{ResponseWriter: w, statusCode: 200}

		timer := prometheus.NewTimer(m.requestDuration.WithLabelValues(r.Method, r.URL.Path))
		defer timer.ObserveDuration()

		next.ServeHTTP(wrapped, r)

		m.requestsTotal.WithLabelValues(
			r.Method,
			r.URL.Path,
			http.StatusText(wrapped.statusCode),
		).Inc()
	})
}

// responseWriter wraps http.ResponseWriter to capture status code
type responseWriter struct {
	http.ResponseWriter
	statusCode int
}

// WriteHeader captures the status code
func (w *responseWriter) WriteHeader(code int) {
	w.statusCode = code
	w.ResponseWriter.WriteHeader(code)
}

// MetricsServer runs a metrics server
type MetricsServer struct {
	addr string
	path string
}

// NewMetricsServer creates a new metrics server
func NewMetricsServer(addr, path string) *MetricsServer {
	return &MetricsServer{
		addr: addr,
		path: path,
	}
}

// ListenAndServe starts the metrics server
func (s *MetricsServer) ListenAndServe() error {
	mux := http.NewServeMux()
	mux.Handle(s.path, Handler())
	return http.ListenAndServe(s.addr, mux)
}
// ============================================================================`n// Enhanced Handler with Timeout, Compression, and Security`n// ============================================================================`n
// HandlerWithTimeout wraps handler with timeout protection
func HandlerWithTimeout(gatherer prometheus.Gatherer, timeout time.Duration) http.Handler {
handler := promhttp.HandlerFor(gatherer, promhttp.HandlerOpts{
Timeout: timeout,
})
return http.TimeoutHandler(handler, timeout, "Metrics collection timeout\n")
}

// HandlerWithCompression wraps handler with gzip compression
func HandlerWithCompression(handler http.Handler, threshold int) http.Handler {
return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
if !strings.Contains(r.Header.Get("Accept-Encoding"), "gzip") {
handler.ServeHTTP(w, r)
return
}

w.Header().Set("Content-Encoding", "gzip")
gz := gzip.NewWriter(w)
defer gz.Close()

gzw := &gzipResponseWriter{ResponseWriter: w, Writer: gz}
handler.ServeHTTP(gzw, r)
})
}

// gzipResponseWriter wraps ResponseWriter for compression
type gzipResponseWriter struct {
http.ResponseWriter
Writer io.Writer
}

func (w *gzipResponseWriter) Write(b []byte) (int, error) {
return w.Writer.Write(b)
}

// HandlerWithBasicAuth wraps handler with basic authentication
func HandlerWithBasicAuth(handler http.Handler, username, password string) http.Handler {
return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
user, pass, ok := r.BasicAuth()
if !ok || subtle.ConstantTimeCompare([]byte(user), []byte(username)) != 1 ||
subtle.ConstantTimeCompare([]byte(pass), []byte(password)) != 1 {
w.Header().Set("WWW-Authenticate", `Basic realm="metrics"`)
http.Error(w, "Unauthorized", http.StatusUnauthorized)
return
}
handler.ServeHTTP(w, r)
})
}

// HandlerWithIPWhitelist wraps handler with IP whitelist
func HandlerWithIPWhitelist(handler http.Handler, allowedIPs []string) http.Handler {
allowed := parseAllowedIPs(allowedIPs)

return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
clientIP := getClientIP(r)
if !isIPAllowed(clientIP, allowed) {
http.Error(w, "Forbidden", http.StatusForbidden)
return
}
handler.ServeHTTP(w, r)
})
}

func parseAllowedIPs(ips []string) []*net.IPNet {
var cidrs []*net.IPNet
for _, ip := range ips {
ip = strings.TrimSpace(ip)
if ip == "" {
continue
}

// Check if it's a CIDR
if strings.Contains(ip, "/") {
_, cidr, err := net.ParseCIDR(ip)
if err == nil {
cidrs = append(cidrs, cidr)
}
} else {
// Single IP - convert to /32 or /128 CIDR
parsedIP := net.ParseIP(ip)
if parsedIP != nil {
mask := 32
if parsedIP.To4() == nil {
mask = 128
}
_, cidr, _ := net.ParseCIDR(fmt.Sprintf("%s/%d", ip, mask))
cidrs = append(cidrs, cidr)
}
}
}
return cidrs
}

func getClientIP(r *http.Request) string {
// Check X-Forwarded-For header
if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
ips := strings.Split(xff, ",")
return strings.TrimSpace(ips[0])
}

// Check X-Real-IP header
if xri := r.Header.Get("X-Real-IP"); xri != "" {
return strings.TrimSpace(xri)
}

// Fall back to RemoteAddr
ip, _, _ := net.SplitHostPort(r.RemoteAddr)
return ip
}

func isIPAllowed(clientIP string, allowed []*net.IPNet) bool {
if len(allowed) == 0 {
return true // No whitelist = allow all
}

ip := net.ParseIP(clientIP)
if ip == nil {
return false
}

for _, cidr := range allowed {
if cidr.Contains(ip) {
return true
}
}
return false
}

// Enhanced MetricsServer with graceful shutdown
func (s *MetricsServer) StartWithShutdown(ctx context.Context) error {
mux := http.NewServeMux()
mux.Handle(s.path, Handler())

server := &http.Server{
Addr:         s.addr,
Handler:      mux,
ReadTimeout:  5 * time.Second,
WriteTimeout: 10 * time.Second,
}

// Start server in goroutine
errChan := make(chan error, 1)
go func() {
errChan <- server.ListenAndServe()
}()

// Wait for context cancellation or server error
select {
case <-ctx.Done():
shutdownCtx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
defer cancel()
return server.Shutdown(shutdownCtx)
case err := <-errChan:
return err
}
}

// HandlerFor creates a handler for a specific registry
func HandlerFor(registry *prometheus.Registry) http.Handler {
return promhttp.HandlerFor(registry, promhttp.HandlerOpts{})
}

// StartMetricsServer starts a basic metrics server
func StartMetricsServer(addr string) error {
mux := http.NewServeMux()
mux.Handle("/metrics", Handler())
return http.ListenAndServe(addr, mux)
}

// StartMetricsServerWithRegistry starts a metrics server with custom registry
func StartMetricsServerWithRegistry(addr string, registry *prometheus.Registry) error {
mux := http.NewServeMux()
mux.Handle("/metrics", HandlerFor(registry))
return http.ListenAndServe(addr, mux)
}

// GetConfigFromEnv reads metrics server config from environment variables
func GetConfigFromEnv() (addr, username, password, tlsCert, tlsKey string, allowedIPs []string) {
addr = os.Getenv("METRICS_HTTP_PORT")
if addr == "" {
addr = ":9090"
}

username = os.Getenv("METRICS_AUTH_USERNAME")
password = os.Getenv("METRICS_AUTH_PASSWORD")
tlsCert = os.Getenv("METRICS_TLS_CERT")
tlsKey = os.Getenv("METRICS_TLS_KEY")

if ips := os.Getenv("METRICS_ALLOWED_IPS"); ips != "" {
allowedIPs = strings.Split(ips, ",")
}

return
}
// ============================================================================
// Content Negotiation - Support for Multiple Formats
// ============================================================================

// HandlerWithContentNegotiation supports text, protobuf, and OpenMetrics formats
func HandlerWithContentNegotiation(gatherer prometheus.Gatherer) http.Handler {
return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
accept := r.Header.Get("Accept")

var opts promhttp.HandlerOpts

// Determine format based on Accept header
switch {
case strings.Contains(accept, "application/vnd.google.protobuf"):
// Protobuf format (most efficient)
w.Header().Set("Content-Type", "application/vnd.google.protobuf")
case strings.Contains(accept, "application/openmetrics-text"):
// OpenMetrics format (newer standard)
w.Header().Set("Content-Type", "application/openmetrics-text; version=1.0.0; charset=utf-8")
default:
// Prometheus text format (default)
w.Header().Set("Content-Type", "text/plain; version=0.0.4; charset=utf-8")
}

promhttp.HandlerFor(gatherer, opts).ServeHTTP(w, r)
})
}

// ============================================================================
// Health Check Integration
// ============================================================================

// HealthChecker interface for health status
type HealthChecker interface {
IsHealthy() bool
IsReady() bool
IsLive() bool
}

// AddHealthEndpoints adds health check endpoints to a mux
func AddHealthEndpoints(mux *http.ServeMux, checker HealthChecker) {
// Health endpoint
mux.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
if checker != nil && !checker.IsHealthy() {
http.Error(w, "Unhealthy", http.StatusServiceUnavailable)
return
}
w.WriteHeader(http.StatusOK)
w.Write([]byte("OK"))
})

// Readiness probe
mux.HandleFunc("/ready", func(w http.ResponseWriter, r *http.Request) {
if checker != nil && !checker.IsReady() {
http.Error(w, "Not Ready", http.StatusServiceUnavailable)
return
}
w.WriteHeader(http.StatusOK)
w.Write([]byte("Ready"))
})

// Liveness probe
mux.HandleFunc("/live", func(w http.ResponseWriter, r *http.Request) {
if checker != nil && !checker.IsLive() {
http.Error(w, "Not Live", http.StatusServiceUnavailable)
return
}
w.WriteHeader(http.StatusOK)
w.Write([]byte("Live"))
})
}

// ============================================================================
// TLS Support
// ============================================================================

// ListenAndServeTLS starts the metrics server with TLS
func (s *MetricsServer) ListenAndServeTLS(certFile, keyFile string) error {
mux := http.NewServeMux()
mux.Handle(s.path, Handler())
return http.ListenAndServeTLS(s.addr, certFile, keyFile, mux)
}

// StartWithShutdownAndHealth starts server with health checks and graceful shutdown
func (s *MetricsServer) StartWithShutdownAndHealth(ctx context.Context, checker HealthChecker) error {
mux := http.NewServeMux()
mux.Handle(s.path, Handler())

// Add health endpoints if checker provided
if checker != nil {
AddHealthEndpoints(mux, checker)
}

server := &http.Server{
Addr:         s.addr,
Handler:      mux,
ReadTimeout:  5 * time.Second,
WriteTimeout: 10 * time.Second,
}

// Start server in goroutine
errChan := make(chan error, 1)
go func() {
errChan <- server.ListenAndServe()
}()

// Wait for context cancellation or server error
select {
case <-ctx.Done():
shutdownCtx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
defer cancel()
return server.Shutdown(shutdownCtx)
case err := <-errChan:
return err
}
}

// StartWithTLSAndShutdown starts TLS server with graceful shutdown
func (s *MetricsServer) StartWithTLSAndShutdown(ctx context.Context, certFile, keyFile string, checker HealthChecker) error {
mux := http.NewServeMux()
mux.Handle(s.path, Handler())

// Add health endpoints if checker provided
if checker != nil {
AddHealthEndpoints(mux, checker)
}

server := &http.Server{
Addr:         s.addr,
Handler:      mux,
ReadTimeout:  5 * time.Second,
WriteTimeout: 10 * time.Second,
}

// Start TLS server in goroutine
errChan := make(chan error, 1)
go func() {
errChan <- server.ListenAndServeTLS(certFile, keyFile)
}()

// Wait for context cancellation or server error
select {
case <-ctx.Done():
shutdownCtx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
defer cancel()
return server.Shutdown(shutdownCtx)
case err := <-errChan:
return err
}
}

// ============================================================================
// Complete Metrics Server with All Features
// ============================================================================

// ServeMetricsWithAllFeatures starts a full-featured metrics server
func ServeMetricsWithAllFeatures(ctx context.Context) error {
addr, username, password, tlsCert, tlsKey, allowedIPs := GetConfigFromEnv()

// Create handler with all middleware
handler := Handler()

// Add timeout protection
handler = HandlerWithTimeout(prometheus.DefaultGatherer, 5*time.Second)

// Add compression
handler = HandlerWithCompression(handler, 1024)

// Add basic auth if configured
if username != "" && password != "" {
handler = HandlerWithBasicAuth(handler, username, password)
}

// Add IP whitelist if configured
if len(allowedIPs) > 0 {
handler = HandlerWithIPWhitelist(handler, allowedIPs)
}

mux := http.NewServeMux()
mux.Handle("/metrics", handler)

server := &http.Server{
Addr:         addr,
Handler:      mux,
ReadTimeout:  5 * time.Second,
WriteTimeout: 10 * time.Second,
}

// Start server
errChan := make(chan error, 1)
go func() {
if tlsCert != "" && tlsKey != "" {
errChan <- server.ListenAndServeTLS(tlsCert, tlsKey)
} else {
errChan <- server.ListenAndServe()
}
}()

// Wait for shutdown
select {
case <-ctx.Done():
shutdownCtx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
defer cancel()
return server.Shutdown(shutdownCtx)
case err := <-errChan:
return err
}
}
