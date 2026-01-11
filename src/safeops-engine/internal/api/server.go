package api

import (
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"safeops-engine/internal/config"
	"safeops-engine/internal/logger"
)

// Server is the HTTP API server
type Server struct {
	cfg    config.APIConfig
	log    *logger.Logger
	server *http.Server
}

// InspectRequest from mitmproxy
type InspectRequest struct {
	URL       string            `json:"url"`
	Method    string            `json:"method"`
	Headers   map[string]string `json:"headers"`
	Body      string            `json:"body"`
	ClientIP  string            `json:"client_ip"`
}

// InspectResponse to mitmproxy
type InspectResponse struct {
	Action string `json:"action"` // ALLOW, BLOCK, MODIFY
	Reason string `json:"reason,omitempty"`
}

// NewServer creates a new API server
func NewServer(cfg config.APIConfig, log *logger.Logger) *Server {
	return &Server{
		cfg: cfg,
		log: log,
	}
}

// Start starts the HTTP server
func (s *Server) Start() error {
	mux := http.NewServeMux()

	// Health check endpoint
	mux.HandleFunc("/health", s.handleHealth)

	// Inspection endpoint (called by mitmproxy)
	mux.HandleFunc("/inspect", s.handleInspect)

	// Stats endpoint
	mux.HandleFunc("/stats", s.handleStats)

	addr := fmt.Sprintf("%s:%d", s.cfg.Address, s.cfg.Port)
	s.server = &http.Server{
		Addr:         addr,
		Handler:      mux,
		ReadTimeout:  10 * time.Second,
		WriteTimeout: 10 * time.Second,
	}

	s.log.Info("API server listening", map[string]interface{}{
		"address": addr,
	})

	return s.server.ListenAndServe()
}

// handleHealth returns server health status
func (s *Server) handleHealth(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{
		"status": "healthy",
		"time":   time.Now().UTC().Format(time.RFC3339),
	})
}

// handleInspect processes inspection requests from mitmproxy
func (s *Server) handleInspect(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req InspectRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request", http.StatusBadRequest)
		return
	}

	s.log.Debug("Inspection request", map[string]interface{}{
		"url":       req.URL,
		"method":    req.Method,
		"client_ip": req.ClientIP,
	})

	// Phase 1: Always ALLOW (no IDS/IPS/Firewall yet)
	resp := InspectResponse{
		Action: "ALLOW",
	}

	// TODO: In Phase 2+, add IDS/IPS/Firewall checks here

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(resp)
}

// handleStats returns statistics
func (s *Server) handleStats(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	stats := map[string]interface{}{
		"uptime_seconds": 0, // TODO: Calculate actual uptime
		"packets_total":  0,
		"packets_dns":    0,
		"packets_http":   0,
		"packets_https":  0,
		"packets_gaming": 0,
	}

	json.NewEncoder(w).Encode(stats)
}

// Stop stops the HTTP server
func (s *Server) Stop() error {
	if s.server != nil {
		return s.server.Close()
	}
	return nil
}
