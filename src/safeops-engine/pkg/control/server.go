// Package control provides an HTTP/JSON API for runtime rule management
package control

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"strings"

	"safeops-engine/internal/logger"
	"safeops-engine/internal/verdict"
)

// EngineController interface avoids circular dependency with engine package
type EngineController interface {
	BlockDomain(domain string)
	UnblockDomain(domain string)
	GetBlockedDomains() []string
	GetEnhancedStats() map[string]interface{}
}

// Server provides HTTP/JSON control API for runtime rule management
type Server struct {
	log           *logger.Logger
	verdictEngine *verdict.Engine
	engine        EngineController
	httpServer    *http.Server
	listenAddr    string
}

// NewServer creates a new HTTP control server
func NewServer(log *logger.Logger, ve *verdict.Engine, eng EngineController, listenAddr string) *Server {
	return &Server{
		log:           log,
		verdictEngine: ve,
		engine:        eng,
		listenAddr:    listenAddr,
	}
}

// Start starts the HTTP control server
func (s *Server) Start() error {
	mux := http.NewServeMux()

	// IP blocking
	mux.HandleFunc("/api/v1/block/ip", s.handleBlockIP)

	// Domain blocking
	mux.HandleFunc("/api/v1/block/domain", s.handleBlockDomain)

	// Port blocking
	mux.HandleFunc("/api/v1/block/port", s.handleBlockPort)

	// DNS redirect
	mux.HandleFunc("/api/v1/dns/redirect", s.handleDNSRedirect)

	// List all rules
	mux.HandleFunc("/api/v1/rules", s.handleListRules)

	// Stats
	mux.HandleFunc("/api/v1/stats", s.handleStats)

	// Clear all rules
	mux.HandleFunc("/api/v1/clear", s.handleClear)

	// Health check
	mux.HandleFunc("/api/v1/health", s.handleHealth)

	s.httpServer = &http.Server{
		Addr:    s.listenAddr,
		Handler: mux,
	}

	go func() {
		s.log.Info("Control API server starting", map[string]interface{}{
			"address": s.listenAddr,
		})
		if err := s.httpServer.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			s.log.Error("Control API server error", map[string]interface{}{
				"error": err.Error(),
			})
		}
	}()

	return nil
}

// Stop stops the HTTP control server
func (s *Server) Stop() {
	if s.httpServer != nil {
		s.httpServer.Shutdown(context.Background())
		s.log.Info("Control API server stopped", nil)
	}
}

// ============ Request/Response types ============

type apiResponse struct {
	Success bool        `json:"success"`
	Message string      `json:"message,omitempty"`
	Data    interface{} `json:"data,omitempty"`
}

type blockIPRequest struct {
	IP      string `json:"ip"`
	Verdict string `json:"verdict"` // "block" or "drop"
}

type blockDomainRequest struct {
	Domain string `json:"domain"`
}

type blockPortRequest struct {
	Port    uint16 `json:"port"`
	Verdict string `json:"verdict"` // "block" or "drop"
}

type dnsRedirectRequest struct {
	Domain     string `json:"domain"`
	RedirectIP string `json:"redirect_ip"`
}

// ============ Handlers ============

func (s *Server) handleBlockIP(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodPost:
		var req blockIPRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			s.writeJSON(w, http.StatusBadRequest, apiResponse{Success: false, Message: "invalid JSON"})
			return
		}

		ip := net.ParseIP(strings.TrimSpace(req.IP))
		if ip == nil {
			s.writeJSON(w, http.StatusBadRequest, apiResponse{Success: false, Message: "invalid IP address"})
			return
		}

		v := verdict.VerdictBlock
		if req.Verdict == "drop" {
			v = verdict.VerdictDrop
		}

		s.verdictEngine.BlockIP(ip, v)

		s.log.Info("IP blocked via control API", map[string]interface{}{
			"ip":      req.IP,
			"verdict": req.Verdict,
		})

		s.writeJSON(w, http.StatusOK, apiResponse{Success: true, Message: fmt.Sprintf("IP %s blocked", req.IP)})

	case http.MethodDelete:
		var req blockIPRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			s.writeJSON(w, http.StatusBadRequest, apiResponse{Success: false, Message: "invalid JSON"})
			return
		}

		ip := net.ParseIP(strings.TrimSpace(req.IP))
		if ip == nil {
			s.writeJSON(w, http.StatusBadRequest, apiResponse{Success: false, Message: "invalid IP address"})
			return
		}

		s.verdictEngine.UnblockIP(ip)

		s.log.Info("IP unblocked via control API", map[string]interface{}{"ip": req.IP})

		s.writeJSON(w, http.StatusOK, apiResponse{Success: true, Message: fmt.Sprintf("IP %s unblocked", req.IP)})

	default:
		s.writeJSON(w, http.StatusMethodNotAllowed, apiResponse{Success: false, Message: "method not allowed"})
	}
}

func (s *Server) handleBlockDomain(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodPost:
		var req blockDomainRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			s.writeJSON(w, http.StatusBadRequest, apiResponse{Success: false, Message: "invalid JSON"})
			return
		}

		domain := strings.ToLower(strings.TrimSpace(req.Domain))
		if domain == "" {
			s.writeJSON(w, http.StatusBadRequest, apiResponse{Success: false, Message: "domain cannot be empty"})
			return
		}

		s.engine.BlockDomain(domain)

		s.writeJSON(w, http.StatusOK, apiResponse{
			Success: true,
			Message: fmt.Sprintf("Domain %s blocked (DNS redirect + SNI/HTTP matching)", domain),
		})

	case http.MethodDelete:
		var req blockDomainRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			s.writeJSON(w, http.StatusBadRequest, apiResponse{Success: false, Message: "invalid JSON"})
			return
		}

		domain := strings.ToLower(strings.TrimSpace(req.Domain))
		if domain == "" {
			s.writeJSON(w, http.StatusBadRequest, apiResponse{Success: false, Message: "domain cannot be empty"})
			return
		}

		s.engine.UnblockDomain(domain)

		s.writeJSON(w, http.StatusOK, apiResponse{Success: true, Message: fmt.Sprintf("Domain %s unblocked", domain)})

	default:
		s.writeJSON(w, http.StatusMethodNotAllowed, apiResponse{Success: false, Message: "method not allowed"})
	}
}

func (s *Server) handleBlockPort(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodPost:
		var req blockPortRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			s.writeJSON(w, http.StatusBadRequest, apiResponse{Success: false, Message: "invalid JSON"})
			return
		}

		if req.Port == 0 {
			s.writeJSON(w, http.StatusBadRequest, apiResponse{Success: false, Message: "port cannot be 0"})
			return
		}

		v := verdict.VerdictBlock
		if req.Verdict == "drop" {
			v = verdict.VerdictDrop
		}

		s.verdictEngine.BlockPort(req.Port, v)

		s.log.Info("Port blocked via control API", map[string]interface{}{
			"port":    req.Port,
			"verdict": req.Verdict,
		})

		s.writeJSON(w, http.StatusOK, apiResponse{Success: true, Message: fmt.Sprintf("Port %d blocked", req.Port)})

	case http.MethodDelete:
		var req blockPortRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			s.writeJSON(w, http.StatusBadRequest, apiResponse{Success: false, Message: "invalid JSON"})
			return
		}

		s.verdictEngine.UnblockPort(req.Port)

		s.log.Info("Port unblocked via control API", map[string]interface{}{"port": req.Port})

		s.writeJSON(w, http.StatusOK, apiResponse{Success: true, Message: fmt.Sprintf("Port %d unblocked", req.Port)})

	default:
		s.writeJSON(w, http.StatusMethodNotAllowed, apiResponse{Success: false, Message: "method not allowed"})
	}
}

func (s *Server) handleDNSRedirect(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodPost:
		var req dnsRedirectRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			s.writeJSON(w, http.StatusBadRequest, apiResponse{Success: false, Message: "invalid JSON"})
			return
		}

		domain := strings.ToLower(strings.TrimSpace(req.Domain))
		if domain == "" {
			s.writeJSON(w, http.StatusBadRequest, apiResponse{Success: false, Message: "domain cannot be empty"})
			return
		}

		redirectIP := net.ParseIP(strings.TrimSpace(req.RedirectIP))
		if redirectIP == nil {
			s.writeJSON(w, http.StatusBadRequest, apiResponse{Success: false, Message: "invalid redirect_ip"})
			return
		}

		s.verdictEngine.AddDNSRedirect(domain, redirectIP)

		s.log.Info("DNS redirect added via control API", map[string]interface{}{
			"domain":      domain,
			"redirect_ip": req.RedirectIP,
		})

		s.writeJSON(w, http.StatusOK, apiResponse{
			Success: true,
			Message: fmt.Sprintf("DNS redirect: %s -> %s", domain, req.RedirectIP),
		})

	case http.MethodDelete:
		var req dnsRedirectRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			s.writeJSON(w, http.StatusBadRequest, apiResponse{Success: false, Message: "invalid JSON"})
			return
		}

		domain := strings.ToLower(strings.TrimSpace(req.Domain))
		if domain == "" {
			s.writeJSON(w, http.StatusBadRequest, apiResponse{Success: false, Message: "domain cannot be empty"})
			return
		}

		s.verdictEngine.RemoveDNSRedirect(domain)

		s.log.Info("DNS redirect removed via control API", map[string]interface{}{"domain": domain})

		s.writeJSON(w, http.StatusOK, apiResponse{Success: true, Message: fmt.Sprintf("DNS redirect removed: %s", domain)})

	default:
		s.writeJSON(w, http.StatusMethodNotAllowed, apiResponse{Success: false, Message: "method not allowed"})
	}
}

func (s *Server) handleListRules(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		s.writeJSON(w, http.StatusMethodNotAllowed, apiResponse{Success: false, Message: "method not allowed"})
		return
	}

	rules := map[string]interface{}{
		"blocked_ips":     s.verdictEngine.GetBlockedIPs(),
		"blocked_ip_count": s.verdictEngine.GetBlockedIPCount(),
		"blocked_domains": s.engine.GetBlockedDomains(),
	}

	s.writeJSON(w, http.StatusOK, apiResponse{Success: true, Data: rules})
}

func (s *Server) handleStats(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		s.writeJSON(w, http.StatusMethodNotAllowed, apiResponse{Success: false, Message: "method not allowed"})
		return
	}

	stats := s.engine.GetEnhancedStats()
	s.writeJSON(w, http.StatusOK, apiResponse{Success: true, Data: stats})
}

func (s *Server) handleClear(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		s.writeJSON(w, http.StatusMethodNotAllowed, apiResponse{Success: false, Message: "method not allowed"})
		return
	}

	s.verdictEngine.ClearBlocklist()
	s.verdictEngine.ClearRedirects()

	// Unblock all domains
	for _, domain := range s.engine.GetBlockedDomains() {
		s.engine.UnblockDomain(domain)
	}

	s.log.Info("All rules cleared via control API", nil)

	s.writeJSON(w, http.StatusOK, apiResponse{Success: true, Message: "All rules cleared"})
}

func (s *Server) handleHealth(w http.ResponseWriter, r *http.Request) {
	s.writeJSON(w, http.StatusOK, apiResponse{Success: true, Message: "SafeOps Engine control API is running"})
}

// writeJSON writes a JSON response
func (s *Server) writeJSON(w http.ResponseWriter, statusCode int, data interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(statusCode)
	json.NewEncoder(w).Encode(data)
}
