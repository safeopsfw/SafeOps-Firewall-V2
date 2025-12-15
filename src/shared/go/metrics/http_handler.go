// Package metrics provides HTTP handler for metrics endpoint.
package metrics

import (
	"net/http"

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
