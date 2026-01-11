// Package api provides REST API handlers for threat intelligence queries
package api

import (
	"encoding/json"
	"net/http"
	"strconv"

	"threat_intel/config"
	"threat_intel/models"
	"threat_intel/src/storage"
)

// Handler contains dependencies for API handlers
type Handler struct {
	cfg *config.Config
	db  *storage.DB
}

// NewHandler creates a new API handler instance
func NewHandler(cfg *config.Config, db *storage.DB) *Handler {
	return &Handler{
		cfg: cfg,
		db:  db,
	}
}

// Response represents a standard API response
type Response struct {
	Success bool        `json:"success"`
	Data    interface{} `json:"data,omitempty"`
	Error   string      `json:"error,omitempty"`
	Meta    *MetaData   `json:"meta,omitempty"`
}

// MetaData contains pagination and metadata
type MetaData struct {
	Total      int `json:"total,omitempty"`
	Page       int `json:"page,omitempty"`
	PerPage    int `json:"per_page,omitempty"`
	TotalPages int `json:"total_pages,omitempty"`
}

// GetIPReputation handles GET /v1/ip/{ip}
func (h *Handler) GetIPReputation(w http.ResponseWriter, r *http.Request) {
	ip := r.PathValue("ip")
	if ip == "" {
		h.sendError(w, http.StatusBadRequest, "IP address is required")
		return
	}

	// Query IP from all tables
	result, err := h.db.GetIPReputation(r.Context(), ip)
	if err != nil {
		h.sendError(w, http.StatusInternalServerError, "Failed to query IP reputation")
		return
	}

	if result == nil {
		h.sendError(w, http.StatusNotFound, "IP not found in threat intelligence database")
		return
	}

	h.sendJSON(w, http.StatusOK, Response{
		Success: true,
		Data:    result,
	})
}

// GetDomainIntelligence handles GET /v1/domain/{domain}
func (h *Handler) GetDomainIntelligence(w http.ResponseWriter, r *http.Request) {
	domain := r.PathValue("domain")
	if domain == "" {
		h.sendError(w, http.StatusBadRequest, "Domain is required")
		return
	}

	result, err := h.db.GetDomainIntelligence(r.Context(), domain)
	if err != nil {
		h.sendError(w, http.StatusInternalServerError, "Failed to query domain intelligence")
		return
	}

	if result == nil {
		h.sendError(w, http.StatusNotFound, "Domain not found in threat intelligence database")
		return
	}

	h.sendJSON(w, http.StatusOK, Response{
		Success: true,
		Data:    result,
	})
}

// GetHashReputation handles GET /v1/hash/{hash}
func (h *Handler) GetHashReputation(w http.ResponseWriter, r *http.Request) {
	hash := r.PathValue("hash")
	if hash == "" {
		h.sendError(w, http.StatusBadRequest, "Hash is required")
		return
	}

	result, err := h.db.GetHashReputation(r.Context(), hash)
	if err != nil {
		h.sendError(w, http.StatusInternalServerError, "Failed to query hash reputation")
		return
	}

	if result == nil {
		h.sendError(w, http.StatusNotFound, "Hash not found in threat intelligence database")
		return
	}

	h.sendJSON(w, http.StatusOK, Response{
		Success: true,
		Data:    result,
	})
}

// GetIOCs handles GET /v1/ioc
func (h *Handler) GetIOCs(w http.ResponseWriter, r *http.Request) {
	// Parse query parameters
	query := r.URL.Query()
	iocType := query.Get("type")
	page, _ := strconv.Atoi(query.Get("page"))
	perPage, _ := strconv.Atoi(query.Get("per_page"))

	if page < 1 {
		page = 1
	}
	if perPage < 1 || perPage > 100 {
		perPage = 50
	}

	filter := &models.IOCFilter{
		Type:    iocType,
		Page:    page,
		PerPage: perPage,
	}

	result, total, err := h.db.GetIOCs(r.Context(), filter)
	if err != nil {
		h.sendError(w, http.StatusInternalServerError, "Failed to query IOCs")
		return
	}

	totalPages := (total + perPage - 1) / perPage

	h.sendJSON(w, http.StatusOK, Response{
		Success: true,
		Data:    result,
		Meta: &MetaData{
			Total:      total,
			Page:       page,
			PerPage:    perPage,
			TotalPages: totalPages,
		},
	})
}

// GetFeeds handles GET /v1/feeds
func (h *Handler) GetFeeds(w http.ResponseWriter, r *http.Request) {
	feeds, err := h.db.GetFeeds(r.Context())
	if err != nil {
		h.sendError(w, http.StatusInternalServerError, "Failed to query feeds")
		return
	}

	h.sendJSON(w, http.StatusOK, Response{
		Success: true,
		Data:    feeds,
	})
}

// GetFeedByID handles GET /v1/feeds/{id}
func (h *Handler) GetFeedByID(w http.ResponseWriter, r *http.Request) {
	idStr := r.PathValue("id")
	id, err := strconv.Atoi(idStr)
	if err != nil {
		h.sendError(w, http.StatusBadRequest, "Invalid feed ID")
		return
	}

	feed, err := h.db.GetFeedByID(r.Context(), id)
	if err != nil {
		h.sendError(w, http.StatusInternalServerError, "Failed to query feed")
		return
	}

	if feed == nil {
		h.sendError(w, http.StatusNotFound, "Feed not found")
		return
	}

	h.sendJSON(w, http.StatusOK, Response{
		Success: true,
		Data:    feed,
	})
}

// GetStats handles GET /v1/stats
func (h *Handler) GetStats(w http.ResponseWriter, r *http.Request) {
	stats, err := h.db.GetStats(r.Context())
	if err != nil {
		h.sendError(w, http.StatusInternalServerError, "Failed to get statistics")
		return
	}

	h.sendJSON(w, http.StatusOK, Response{
		Success: true,
		Data:    stats,
	})
}

// Search handles POST /v1/search
func (h *Handler) Search(w http.ResponseWriter, r *http.Request) {
	var req models.SearchRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.sendError(w, http.StatusBadRequest, "Invalid request body")
		return
	}

	results, err := h.db.Search(r.Context(), &req)
	if err != nil {
		h.sendError(w, http.StatusInternalServerError, "Search failed")
		return
	}

	h.sendJSON(w, http.StatusOK, Response{
		Success: true,
		Data:    results,
	})
}

// sendJSON sends a JSON response
func (h *Handler) sendJSON(w http.ResponseWriter, status int, data interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(data)
}

// sendError sends an error response
func (h *Handler) sendError(w http.ResponseWriter, status int, message string) {
	h.sendJSON(w, status, Response{
		Success: false,
		Error:   message,
	})
}
