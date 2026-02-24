// Package api implements the Web UI Backend API for the SafeOps Firewall Engine.
// It provides a REST API and WebSocket server for the dashboard, configuration
// management, and real-time event streaming. The embedded SPA frontend is served
// directly from the Go binary.
package api

import (
	"embed"
	"encoding/json"
	"fmt"
	"io/fs"
	"net"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"firewall_engine/internal/alerting"
	"firewall_engine/internal/config"
	"firewall_engine/internal/domain"
	"firewall_engine/internal/geoip"
	"firewall_engine/internal/hotreload"
	"firewall_engine/internal/logging"
	"firewall_engine/internal/security"

	"github.com/gofiber/fiber/v2"
	"github.com/gofiber/fiber/v2/middleware/cors"
	"github.com/gofiber/fiber/v2/middleware/recover"
)

// ============================================================================
// Embedded Frontend Assets
// ============================================================================

//go:embed web/*
var webFS embed.FS

// ============================================================================
// Dependencies — all engine components the API needs access to
// ============================================================================

// Dependencies holds references to all firewall engine components.
// These are injected from main.go at startup — the API never modifies
// core engine state directly, only reads stats and updates config files.
type Dependencies struct {
	// Config holds the loaded configuration (read-only after startup)
	Config *config.AllConfig

	// SecurityMgr provides access to security detection stats and sub-systems
	SecurityMgr *security.Manager

	// DomainFilter provides domain blocking stats and management
	DomainFilter *domain.Filter

	// GeoChecker provides GeoIP blocking stats and policy management
	GeoChecker *geoip.Checker

	// AlertMgr provides access to alert statistics
	AlertMgr *alerting.Manager

	// Reloader provides hot-reload stats and current parsed blocklist
	Reloader *hotreload.Reloader

	// LiveBlocklist is the atomic pointer to the current parsed blocklist
	// Used for reading current blocklist state
	LiveBlocklist *atomic.Pointer[config.ParsedBlocklist]

	// Logger is the structured logger for API operations
	Logger logging.Logger

	// StartTime records when the engine started (for uptime calculation)
	StartTime time.Time

	// APIKey is the optional API key for authentication.
	// If empty, authentication is disabled.
	APIKey string
}

// Validate checks that all required dependencies are provided.
// Returns an error describing any missing dependencies.
func (d *Dependencies) Validate() error {
	var missing []string

	if d.Config == nil {
		missing = append(missing, "Config")
	}
	if d.SecurityMgr == nil {
		missing = append(missing, "SecurityMgr")
	}
	if d.AlertMgr == nil {
		missing = append(missing, "AlertMgr")
	}
	if d.Logger == nil {
		missing = append(missing, "Logger")
	}
	if d.LiveBlocklist == nil {
		missing = append(missing, "LiveBlocklist")
	}
	if d.StartTime.IsZero() {
		missing = append(missing, "StartTime")
	}

	if len(missing) > 0 {
		return fmt.Errorf("api: missing required dependencies: %s", strings.Join(missing, ", "))
	}
	return nil
}

// ============================================================================
// Server
// ============================================================================

// Server is the Web UI API server.
// It wraps a Fiber app and provides REST endpoints + WebSocket connections
// for the firewall dashboard frontend.
type Server struct {
	app     *fiber.App
	addr    string
	deps    Dependencies
	hub     *EventHub
	tickets *TicketStore
	triage  *TriageStore
	logger  logging.Logger

	// running tracks whether the server is currently started
	running atomic.Bool

	// listener is held so we can get the actual bound address
	listener net.Listener

	// mu protects shutdown sequence
	mu sync.Mutex
}

// NewServer creates a new API server bound to the given address.
// The address should be in the form ":port" or "host:port".
// Dependencies must be validated before calling this.
func NewServer(addr string, deps Dependencies) (*Server, error) {
	if err := deps.Validate(); err != nil {
		return nil, fmt.Errorf("api.NewServer: %w", err)
	}

	if addr == "" {
		addr = ":8443"
	}

	s := &Server{
		addr:    addr,
		deps:    deps,
		hub:     NewEventHub(),
		tickets: NewTicketStore(),
		triage:  NewTriageStore(),
		logger:  deps.Logger,
	}

	s.app = s.createApp()
	return s, nil
}

// createApp initializes the Fiber application with middleware and routes.
func (s *Server) createApp() *fiber.App {
	app := fiber.New(fiber.Config{
		AppName:               "SafeOps Firewall Web UI",
		DisableStartupMessage: true,
		ErrorHandler:          s.errorHandler,
		ReadTimeout:           30 * time.Second,
		WriteTimeout:          30 * time.Second,
		IdleTimeout:           120 * time.Second,
		BodyLimit:             10 * 1024 * 1024, // 10MB max body
		// Disable header server identification for security
		ServerHeader: "",
	})

	// ---- Middleware Stack ----

	// 1. Panic recovery — never let a panic crash the firewall engine
	app.Use(recover.New(recover.Config{
		EnableStackTrace: true,
		StackTraceHandler: func(c *fiber.Ctx, e interface{}) {
			s.logger.Error().
				Str("path", c.Path()).
				Str("method", c.Method()).
				Str("panic", fmt.Sprintf("%v", e)).
				Msg("API panic recovered")
		},
	}))

	// 2. CORS — allow all origins for local dev; can be restricted via config
	app.Use(cors.New(cors.Config{
		AllowOrigins: "*",
		AllowMethods: "GET,POST,PUT,DELETE,PATCH,OPTIONS",
		AllowHeaders: "Origin,Content-Type,Accept,Authorization,X-API-Key",
		MaxAge:       3600,
	}))

	// 3. Request logging — log every API request with method, path, status, latency
	app.Use(s.requestLogger())

	// 4. Security headers
	app.Use(s.securityHeaders())

	// ---- API Routes ----
	api := app.Group("/api/v1")

	// Optional API key authentication on all /api routes
	if s.deps.APIKey != "" {
		api.Use(s.apiKeyAuth())
	}

	// Auth routes (no auth required)
	api.Post("/auth/login", s.handleLogin)

	// Dashboard
	api.Get("/dashboard/stats", s.handleDashboardStats)
	api.Get("/dashboard/threats", s.handleDashboardThreats)

	// Alerts & Triage
	api.Get("/alerts", s.handleGetAlerts)
	api.Get("/alerts/:id", s.handleGetAlert)
	api.Post("/alerts/:id/triage", s.handleTriageAlert)

	// Rules — Domains
	api.Get("/rules/domains", s.handleGetDomains)
	api.Post("/rules/domains", s.handleAddDomain)
	api.Delete("/rules/domains/:domain", s.handleRemoveDomain)
	api.Get("/rules/domains/whitelist", s.handleGetWhitelistDomains)
	api.Post("/rules/domains/whitelist", s.handleAddWhitelistDomain)
	api.Delete("/rules/domains/whitelist/:domain", s.handleRemoveWhitelistDomain)
	api.Get("/rules/categories", s.handleGetCategories)
	api.Put("/rules/categories", s.handleUpdateCategories)
	api.Get("/rules/categories/patterns", s.handleGetCategoryPatterns)
	api.Put("/rules/categories/patterns/:category", s.handleUpdateCategoryPatterns)

	// Rules — IPs
	api.Get("/rules/ips", s.handleGetBlockedIPs)
	api.Post("/rules/ips", s.handleAddBlockedIP)
	api.Delete("/rules/ips/:ip", s.handleRemoveBlockedIP)
	api.Get("/rules/ips/whitelist", s.handleGetWhitelistIPs)
	api.Post("/rules/ips/whitelist", s.handleAddWhitelistIP)
	api.Delete("/rules/ips/whitelist/:ip", s.handleRemoveWhitelistIP)

	// Rules — GeoIP
	api.Get("/rules/geoip", s.handleGetGeoIPConfig)
	api.Put("/rules/geoip", s.handleUpdateGeoIPConfig)

	// Rules — Detection
	api.Get("/rules/detection", s.handleGetDetectionConfig)
	api.Put("/rules/detection", s.handleUpdateDetectionConfig)

	// Rules — Custom Detection Rules (rules.toml)
	api.Get("/rules/custom", s.handleGetCustomRules)
	api.Put("/rules/custom/:name/toggle", s.handleToggleCustomRule)

	// Rules — Blocklist policy
	api.Get("/rules/blocklist", s.handleGetBlocklistConfig)
	api.Put("/rules/blocklist", s.handleUpdateBlocklistConfig)

	// Security — Bans
	api.Get("/security/bans", s.handleGetBans)
	api.Post("/security/bans", s.handleCreateBan)
	api.Delete("/security/bans/:ip", s.handleDeleteBan)
	api.Get("/security/stats", s.handleSecurityStats)

	// Tickets
	api.Get("/tickets", s.handleGetTickets)
	api.Post("/tickets", s.handleCreateTicket)
	api.Get("/tickets/:id", s.handleGetTicket)
	api.Put("/tickets/:id", s.handleUpdateTicket)
	api.Delete("/tickets/:id", s.handleDeleteTicket)
	api.Post("/tickets/:id/notes", s.handleAddTicketNote)

	// Health & Status
	api.Get("/health", s.handleHealth)
	api.Get("/status", s.handleStatus)

	// Logs — Verdict viewer (Phase 11)
	api.Get("/logs/verdicts", s.handleGetVerdictLogs)

	// Real-time stats (Phase 11)
	api.Get("/stats/realtime", s.handleRealtimeStats)

	// WebSocket routes
	api.Get("/ws/events", s.handleWSEvents)
	api.Get("/ws/stats", s.handleWSStats)

	// ---- Static File Serving (SPA) ----
	s.setupStaticFiles(app)

	return app
}

// Start begins listening for HTTP connections in a background goroutine.
// It returns immediately after the listener is bound.
// Returns an error if the address is already in use or binding fails.
func (s *Server) Start() error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.running.Load() {
		return fmt.Errorf("api: server already running")
	}

	// Create listener first to detect port conflicts immediately
	ln, err := net.Listen("tcp", s.addr)
	if err != nil {
		return fmt.Errorf("api: failed to listen on %s: %w", s.addr, err)
	}
	s.listener = ln

	s.running.Store(true)

	s.logger.Info().
		Str("address", ln.Addr().String()).
		Bool("auth_enabled", s.deps.APIKey != "").
		Msg("Web UI API server starting")

	// Run Fiber in background goroutine — does not block
	go func() {
		if err := s.app.Listener(ln); err != nil {
			// Only log if we're still supposed to be running
			// (Shutdown causes a benign error)
			if s.running.Load() {
				s.logger.Error().Err(err).Msg("Web UI API server error")
			}
		}
	}()

	return nil
}

// Stop gracefully shuts down the API server.
// It waits for active connections to finish (up to 10 seconds).
func (s *Server) Stop() error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if !s.running.Load() {
		return nil
	}

	s.running.Store(false)
	s.logger.Info().Msg("Web UI API server shutting down")

	// Graceful shutdown with timeout
	if err := s.app.ShutdownWithTimeout(10 * time.Second); err != nil {
		s.logger.Error().Err(err).Msg("Web UI API server shutdown error")
		return fmt.Errorf("api: shutdown error: %w", err)
	}

	s.logger.Info().Msg("Web UI API server stopped")
	return nil
}

// Addr returns the actual bound address (useful when using port 0).
func (s *Server) Addr() string {
	if s.listener != nil {
		return s.listener.Addr().String()
	}
	return s.addr
}

// Hub returns the event hub for broadcasting events from other components.
func (s *Server) Hub() *EventHub {
	return s.hub
}

// SetReloader wires the hot-reload component into the server after startup.
// Called from main.go once the reloader is initialized (after the API server starts).
func (s *Server) SetReloader(r *hotreload.Reloader) {
	s.deps.Reloader = r
}

// ============================================================================
// Middleware
// ============================================================================

// requestLogger returns middleware that logs every request.
func (s *Server) requestLogger() fiber.Handler {
	return func(c *fiber.Ctx) error {
		start := time.Now()

		// Process request
		err := c.Next()

		// Skip logging for static files to reduce noise
		path := c.Path()
		if !strings.HasPrefix(path, "/api/") && !strings.HasPrefix(path, "/ws/") {
			return err
		}

		latency := time.Since(start)
		status := c.Response().StatusCode()

		event := s.logger.Info()
		if status >= 400 {
			event = s.logger.Warn()
		}
		if status >= 500 {
			event = s.logger.Error()
		}

		event.
			Str("method", c.Method()).
			Str("path", path).
			Int("status", status).
			Str("latency", latency.String()).
			Str("ip", c.IP()).
			Msg("API request")

		return err
	}
}

// securityHeaders adds standard security headers to all responses.
func (s *Server) securityHeaders() fiber.Handler {
	return func(c *fiber.Ctx) error {
		c.Set("X-Content-Type-Options", "nosniff")
		c.Set("X-Frame-Options", "DENY")
		c.Set("X-XSS-Protection", "1; mode=block")
		c.Set("Referrer-Policy", "strict-origin-when-cross-origin")
		return c.Next()
	}
}

// apiKeyAuth returns middleware that validates the X-API-Key header.
func (s *Server) apiKeyAuth() fiber.Handler {
	return func(c *fiber.Ctx) error {
		// Skip auth for login endpoint
		if c.Path() == "/api/v1/auth/login" {
			return c.Next()
		}

		// Check Authorization header (Bearer token) first
		auth := c.Get("Authorization")
		if auth != "" {
			parts := strings.SplitN(auth, " ", 2)
			if len(parts) == 2 && strings.EqualFold(parts[0], "Bearer") {
				if parts[1] == s.deps.APIKey {
					return c.Next()
				}
			}
		}

		// Check X-API-Key header
		apiKey := c.Get("X-API-Key")
		if apiKey == s.deps.APIKey {
			return c.Next()
		}

		return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{
			"error":   "unauthorized",
			"message": "Invalid or missing API key",
		})
	}
}

// ============================================================================
// Error Handling
// ============================================================================

// errorHandler is the global Fiber error handler.
// It converts all errors to consistent JSON responses.
func (s *Server) errorHandler(c *fiber.Ctx, err error) error {
	// Default to 500 Internal Server Error
	code := fiber.StatusInternalServerError
	message := "Internal server error"

	// Check for Fiber-specific errors (404, 405, etc.)
	if e, ok := err.(*fiber.Error); ok {
		code = e.Code
		message = e.Message
	}

	s.logger.Error().
		Err(err).
		Str("path", c.Path()).
		Str("method", c.Method()).
		Int("status", code).
		Msg("API error")

	return c.Status(code).JSON(fiber.Map{
		"error":   http.StatusText(code),
		"message": message,
		"status":  code,
	})
}

// ============================================================================
// Auth Handler (simple token-based)
// ============================================================================

// loginRequest is the request body for POST /auth/login.
type loginRequest struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

// handleLogin handles POST /api/v1/auth/login.
// For now, this is a simple check — if an API key is configured,
// the password must match. If no API key is set, any credentials work.
func (s *Server) handleLogin(c *fiber.Ctx) error {
	var req loginRequest
	if err := c.BodyParser(&req); err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"error":   "bad_request",
			"message": "Invalid request body",
		})
	}

	if req.Username == "" || req.Password == "" {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"error":   "bad_request",
			"message": "Username and password are required",
		})
	}

	// Simple auth: if API key is set, password must match
	if s.deps.APIKey != "" && req.Password != s.deps.APIKey {
		return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{
			"error":   "unauthorized",
			"message": "Invalid credentials",
		})
	}

	// Return the API key as a bearer token
	token := s.deps.APIKey
	if token == "" {
		token = "safeops-local-token"
	}

	return c.JSON(fiber.Map{
		"token":    token,
		"username": req.Username,
		"role":     "admin",
		"message":  "Login successful",
	})
}

// ============================================================================
// Static File Serving (Embedded SPA)
// ============================================================================

// setupStaticFiles configures the embedded SPA frontend to be served.
// All routes that don't match /api/* or /ws/* fall through to the SPA.
func (s *Server) setupStaticFiles(app *fiber.App) {
	// Get the web subdirectory from the embedded FS
	webContent, err := fs.Sub(webFS, "web")
	if err != nil {
		s.logger.Error().Err(err).Msg("Failed to access embedded web files")
		return
	}

	// Serve static files
	app.Use("/", func(c *fiber.Ctx) error {
		path := c.Path()

		// Skip API and WebSocket routes
		if strings.HasPrefix(path, "/api/") || strings.HasPrefix(path, "/ws/") {
			return c.Next()
		}

		// Clean the path
		filePath := strings.TrimPrefix(path, "/")
		if filePath == "" {
			filePath = "index.html"
		}

		// Try to serve the exact file
		file, err := webContent.(fs.ReadFileFS).ReadFile(filePath)
		if err == nil {
			c.Set("Content-Type", getContentType(filePath))
			c.Set("Cache-Control", getCacheControl(filePath))
			return c.Send(file)
		}

		// For SPA routing: serve index.html for any unmatched path
		// This allows the frontend hash router to handle the route
		indexFile, err := webContent.(fs.ReadFileFS).ReadFile("index.html")
		if err != nil {
			return c.Status(fiber.StatusNotFound).SendString("Frontend not found")
		}

		c.Set("Content-Type", "text/html; charset=utf-8")
		c.Set("Cache-Control", "no-cache")
		return c.Send(indexFile)
	})
}

// getContentType returns the MIME type for a file based on extension.
func getContentType(path string) string {
	switch {
	case strings.HasSuffix(path, ".html"):
		return "text/html; charset=utf-8"
	case strings.HasSuffix(path, ".css"):
		return "text/css; charset=utf-8"
	case strings.HasSuffix(path, ".js"):
		return "application/javascript; charset=utf-8"
	case strings.HasSuffix(path, ".json"):
		return "application/json; charset=utf-8"
	case strings.HasSuffix(path, ".png"):
		return "image/png"
	case strings.HasSuffix(path, ".jpg"), strings.HasSuffix(path, ".jpeg"):
		return "image/jpeg"
	case strings.HasSuffix(path, ".svg"):
		return "image/svg+xml"
	case strings.HasSuffix(path, ".ico"):
		return "image/x-icon"
	case strings.HasSuffix(path, ".woff2"):
		return "font/woff2"
	case strings.HasSuffix(path, ".woff"):
		return "font/woff"
	default:
		return "application/octet-stream"
	}
}

// getCacheControl returns the cache control header for a file.
// CSS/JS/images get long cache, HTML gets no-cache for SPA freshness.
func getCacheControl(path string) string {
	switch {
	case strings.HasSuffix(path, ".html"):
		return "no-cache"
	case strings.HasSuffix(path, ".css"), strings.HasSuffix(path, ".js"):
		return "public, max-age=3600" // 1 hour
	case strings.HasSuffix(path, ".png"), strings.HasSuffix(path, ".jpg"),
		strings.HasSuffix(path, ".svg"), strings.HasSuffix(path, ".ico"):
		return "public, max-age=86400" // 24 hours
	case strings.HasSuffix(path, ".woff2"), strings.HasSuffix(path, ".woff"):
		return "public, max-age=604800" // 7 days
	default:
		return "no-cache"
	}
}

// ============================================================================
// JSON Helpers
// ============================================================================

// respondJSON sends a JSON response with the given status code.
func respondJSON(c *fiber.Ctx, status int, data interface{}) error {
	return c.Status(status).JSON(data)
}

// respondError sends a JSON error response.
func respondError(c *fiber.Ctx, status int, errType string, message string) error {
	return c.Status(status).JSON(fiber.Map{
		"error":   errType,
		"message": message,
		"status":  status,
	})
}

// parseJSONBody parses the request body as JSON into the target.
// Returns a user-friendly error if parsing fails.
func parseJSONBody(c *fiber.Ctx, target interface{}) error {
	if err := json.Unmarshal(c.Body(), target); err != nil {
		return fmt.Errorf("invalid JSON: %w", err)
	}
	return nil
}

// ============================================================================
// Triage Store (in-memory alert triage status)
// ============================================================================

// TriageStatus represents the triage state of an alert.
type TriageStatus struct {
	AlertID      string    `json:"alert_id"`
	Status       string    `json:"status"` // new, acknowledged, escalated, dismissed, resolved
	Analyst      string    `json:"analyst,omitempty"`
	Notes        string    `json:"notes,omitempty"`
	LinkedTicket string    `json:"linked_ticket,omitempty"`
	UpdatedAt    time.Time `json:"updated_at"`
}

// TriageStore is a thread-safe in-memory store for alert triage statuses.
type TriageStore struct {
	mu      sync.RWMutex
	entries map[string]*TriageStatus
}

// NewTriageStore creates a new triage store.
func NewTriageStore() *TriageStore {
	return &TriageStore{
		entries: make(map[string]*TriageStatus),
	}
}

// Get returns the triage status for an alert.
func (ts *TriageStore) Get(alertID string) *TriageStatus {
	ts.mu.RLock()
	defer ts.mu.RUnlock()
	return ts.entries[alertID]
}

// Set updates the triage status for an alert.
func (ts *TriageStore) Set(status *TriageStatus) {
	ts.mu.Lock()
	defer ts.mu.Unlock()
	status.UpdatedAt = time.Now()
	ts.entries[status.AlertID] = status
}

// GetAll returns all triage statuses.
func (ts *TriageStore) GetAll() []*TriageStatus {
	ts.mu.RLock()
	defer ts.mu.RUnlock()
	result := make([]*TriageStatus, 0, len(ts.entries))
	for _, s := range ts.entries {
		result = append(result, s)
	}
	return result
}
