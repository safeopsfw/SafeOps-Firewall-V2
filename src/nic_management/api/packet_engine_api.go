// Package api provides packet engine HTTP API endpoints.
package api

import (
	"encoding/json"
	"net/http"

	"safeops/nic_management/internal/subprocess"
)

// PacketEngineAPI provides REST API for packet engine status and logs.
type PacketEngineAPI struct {
	manager *subprocess.PacketEngineManager
}

// NewPacketEngineAPI creates a new packet engine API handler.
func NewPacketEngineAPI(manager *subprocess.PacketEngineManager) *PacketEngineAPI {
	return &PacketEngineAPI{manager: manager}
}

// RegisterRoutes registers packet engine routes on the given mux.
func (p *PacketEngineAPI) RegisterRoutes(mux *http.ServeMux, corsMiddleware func(http.HandlerFunc) http.HandlerFunc) {
	mux.HandleFunc("/api/packet-engine/status", corsMiddleware(p.handleStatus))
	mux.HandleFunc("/api/packet-engine/logs", corsMiddleware(p.handleLogs))
	mux.HandleFunc("/api/packet-engine/start", corsMiddleware(p.handleStart))
	mux.HandleFunc("/api/packet-engine/stop", corsMiddleware(p.handleStop))
}

// handleStatus returns packet engine running status.
func (p *PacketEngineAPI) handleStatus(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(p.manager.GetStatus())
}

// handleLogs returns recent log entries (last 50 seconds).
func (p *PacketEngineAPI) handleLogs(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	logs := p.manager.GetRecentLogs()

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"logs":  logs,
		"count": len(logs),
	})
}

// handleStart starts the packet engine.
func (p *PacketEngineAPI) handleStart(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	if err := p.manager.Start(); err != nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(map[string]interface{}{
			"success": false,
			"error":   err.Error(),
		})
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"success": true,
		"message": "Packet engine started",
	})
}

// handleStop stops the packet engine.
func (p *PacketEngineAPI) handleStop(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	if err := p.manager.Stop(); err != nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(map[string]interface{}{
			"success": false,
			"error":   err.Error(),
		})
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"success": true,
		"message": "Packet engine stopped",
	})
}
