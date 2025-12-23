// Package api provides REST API route definitions
package api

import (
	"encoding/json"
	"net/http"

	"threat_intel/config"
	"threat_intel/src/storage"
)

// Server represents the API server
type Server struct {
	cfg        *config.Config
	db         *storage.DB
	handler    *Handler
	middleware *Middleware
}

// NewServer creates a new API server instance
func NewServer(cfg *config.Config, db *storage.DB) *Server {
	return &Server{
		cfg:        cfg,
		db:         db,
		handler:    NewHandler(cfg, db),
		middleware: NewMiddleware(),
	}
}

// SetupRoutes configures all API routes
func (s *Server) SetupRoutes() http.Handler {
	mux := http.NewServeMux()

	// API v1 routes
	mux.HandleFunc("GET /v1/ip/{ip}", s.handler.GetIPReputation)
	mux.HandleFunc("GET /v1/domain/{domain}", s.handler.GetDomainIntelligence)
	mux.HandleFunc("GET /v1/hash/{hash}", s.handler.GetHashReputation)
	mux.HandleFunc("GET /v1/ioc", s.handler.GetIOCs)
	mux.HandleFunc("GET /v1/feeds", s.handler.GetFeeds)
	mux.HandleFunc("GET /v1/feeds/{id}", s.handler.GetFeedByID)
	mux.HandleFunc("GET /v1/stats", s.handler.GetStats)
	mux.HandleFunc("POST /v1/search", s.handler.Search)

	// Bulk lookup endpoints
	mux.HandleFunc("POST /v1/ip/bulk", s.handler.BulkIPLookup)
	mux.HandleFunc("POST /v1/domain/bulk", s.handler.BulkDomainLookup)
	mux.HandleFunc("POST /v1/hash/bulk", s.handler.BulkHashLookup)

	// Apply middleware chain
	if s.middleware != nil {
		handler := Chain(
			mux,
			s.middleware.Recover,
			s.middleware.Logger,
			s.middleware.CORS,
			s.middleware.RateLimit,
			s.middleware.ContentType,
		)
		return handler
	}

	return mux
}

// BulkIPLookup handles POST /v1/ip/bulk
func (h *Handler) BulkIPLookup(w http.ResponseWriter, r *http.Request) {
	// Parse JSON array of IPs
	var ips []string
	if err := parseJSONBody(r, &ips); err != nil {
		h.sendError(w, http.StatusBadRequest, "Invalid request body")
		return
	}

	if len(ips) > 100 {
		h.sendError(w, http.StatusBadRequest, "Maximum 100 IPs per request")
		return
	}

	results, err := h.db.BulkGetIPReputation(r.Context(), ips)
	if err != nil {
		h.sendError(w, http.StatusInternalServerError, "Failed to query IPs")
		return
	}

	h.sendJSON(w, http.StatusOK, Response{
		Success: true,
		Data:    results,
		Meta: &MetaData{
			Total: len(results),
		},
	})
}

// BulkDomainLookup handles POST /v1/domain/bulk
func (h *Handler) BulkDomainLookup(w http.ResponseWriter, r *http.Request) {
	var domains []string
	if err := parseJSONBody(r, &domains); err != nil {
		h.sendError(w, http.StatusBadRequest, "Invalid request body")
		return
	}

	if len(domains) > 100 {
		h.sendError(w, http.StatusBadRequest, "Maximum 100 domains per request")
		return
	}

	results, err := h.db.BulkGetDomainIntelligence(r.Context(), domains)
	if err != nil {
		h.sendError(w, http.StatusInternalServerError, "Failed to query domains")
		return
	}

	h.sendJSON(w, http.StatusOK, Response{
		Success: true,
		Data:    results,
		Meta: &MetaData{
			Total: len(results),
		},
	})
}

// BulkHashLookup handles POST /v1/hash/bulk
func (h *Handler) BulkHashLookup(w http.ResponseWriter, r *http.Request) {
	var hashes []string
	if err := parseJSONBody(r, &hashes); err != nil {
		h.sendError(w, http.StatusBadRequest, "Invalid request body")
		return
	}

	if len(hashes) > 100 {
		h.sendError(w, http.StatusBadRequest, "Maximum 100 hashes per request")
		return
	}

	results, err := h.db.BulkGetHashReputation(r.Context(), hashes)
	if err != nil {
		h.sendError(w, http.StatusInternalServerError, "Failed to query hashes")
		return
	}

	h.sendJSON(w, http.StatusOK, Response{
		Success: true,
		Data:    results,
		Meta: &MetaData{
			Total: len(results),
		},
	})
}

// parseJSONBody parses JSON request body into target
func parseJSONBody(r *http.Request, target interface{}) error {
	return decodeJSON(r.Body, target)
}

// decodeJSON decodes JSON from reader
func decodeJSON(r interface{ Read([]byte) (int, error) }, target interface{}) error {
	return json.NewDecoder(r.(interface{ Read([]byte) (int, error) })).Decode(target)
}
