package api

import (
	"encoding/json"
	"sync"
	"time"

	"github.com/gofiber/contrib/websocket"
	"github.com/gofiber/fiber/v2"
)

// ============================================================================
// EventHub — WebSocket broadcast server
// ============================================================================

// EventHub manages WebSocket connections and broadcasts events to all clients.
type EventHub struct {
	mu      sync.RWMutex
	clients map[*websocket.Conn]bool
}

// NewEventHub creates a new WebSocket event hub.
func NewEventHub() *EventHub {
	return &EventHub{
		clients: make(map[*websocket.Conn]bool),
	}
}

// Register adds a new WebSocket client.
func (h *EventHub) Register(c *websocket.Conn) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.clients[c] = true
}

// Unregister removes a WebSocket client.
func (h *EventHub) Unregister(c *websocket.Conn) {
	h.mu.Lock()
	defer h.mu.Unlock()
	delete(h.clients, c)
}

// BroadcastEvent sends a typed event to all connected WebSocket clients.
func (h *EventHub) BroadcastEvent(eventType string, data interface{}) {
	msg := map[string]interface{}{
		"type":      eventType,
		"data":      data,
		"timestamp": time.Now().UTC().Format(time.RFC3339),
	}

	payload, err := json.Marshal(msg)
	if err != nil {
		return
	}

	h.mu.RLock()
	defer h.mu.RUnlock()

	for conn := range h.clients {
		// Best-effort write; ignore per-client errors
		_ = conn.WriteMessage(websocket.TextMessage, payload)
	}
}

// BroadcastJSON sends raw JSON bytes to all clients.
func (h *EventHub) BroadcastJSON(payload []byte) {
	h.mu.RLock()
	defer h.mu.RUnlock()

	for conn := range h.clients {
		_ = conn.WriteMessage(websocket.TextMessage, payload)
	}
}

// ClientCount returns the number of connected WebSocket clients.
func (h *EventHub) ClientCount() int {
	h.mu.RLock()
	defer h.mu.RUnlock()
	return len(h.clients)
}

// ============================================================================
// WebSocket Handlers
// ============================================================================

// handleWSEvents handles WebSocket connections for real-time event streams.
// Clients receive ban events, alert triage updates, ticket changes, etc.
func (s *Server) handleWSEvents(c *fiber.Ctx) error {
	// Upgrade to WebSocket
	if !websocket.IsWebSocketUpgrade(c) {
		return fiber.ErrUpgradeRequired
	}

	return websocket.New(func(conn *websocket.Conn) {
		s.hub.Register(conn)
		defer s.hub.Unregister(conn)

		s.logger.Info().
			Str("remote", conn.RemoteAddr().String()).
			Msg("WebSocket client connected (events)")

		// Send welcome message
		welcome := map[string]interface{}{
			"type":    "connected",
			"message": "SafeOps Firewall Event Stream",
			"data": map[string]interface{}{
				"version": s.getEngineVersion(),
				"uptime":  time.Since(s.deps.StartTime).Truncate(time.Second).String(),
				"clients": s.hub.ClientCount(),
			},
		}
		welcomeJSON, _ := json.Marshal(welcome)
		conn.WriteMessage(websocket.TextMessage, welcomeJSON)

		// Read loop — keep connection alive, handle client messages
		for {
			_, _, err := conn.ReadMessage()
			if err != nil {
				break
			}
			// Client messages are ignored for now (event stream is one-way)
		}

		s.logger.Info().
			Str("remote", conn.RemoteAddr().String()).
			Msg("WebSocket client disconnected (events)")
	})(c)
}

// handleWSStats handles WebSocket connections for real-time statistics.
// Pushes aggregated stats to the client every 2 seconds.
func (s *Server) handleWSStats(c *fiber.Ctx) error {
	if !websocket.IsWebSocketUpgrade(c) {
		return fiber.ErrUpgradeRequired
	}

	return websocket.New(func(conn *websocket.Conn) {
		s.logger.Info().
			Str("remote", conn.RemoteAddr().String()).
			Msg("WebSocket client connected (stats)")

		ticker := time.NewTicker(2 * time.Second)
		defer ticker.Stop()

		// Done channel to coordinate cleanup
		done := make(chan struct{})

		// Read goroutine — detect client disconnect
		go func() {
			defer close(done)
			for {
				if _, _, err := conn.ReadMessage(); err != nil {
					return
				}
			}
		}()

		// Write loop — push stats at interval
		for {
			select {
			case <-done:
				s.logger.Info().
					Str("remote", conn.RemoteAddr().String()).
					Msg("WebSocket client disconnected (stats)")
				return
			case <-ticker.C:
				stats := s.collectLiveStats()
				payload, err := json.Marshal(map[string]interface{}{
					"type":      "stats_update",
					"data":      stats,
					"timestamp": time.Now().UTC().Format(time.RFC3339),
				})
				if err != nil {
					continue
				}
				if err := conn.WriteMessage(websocket.TextMessage, payload); err != nil {
					return
				}
			}
		}
	})(c)
}

// collectLiveStats gathers current stats from all engine components.
func (s *Server) collectLiveStats() map[string]interface{} {
	stats := map[string]interface{}{
		"uptime_seconds": int64(time.Since(s.deps.StartTime).Seconds()),
		"ws_clients":     s.hub.ClientCount(),
	}

	if s.deps.SecurityMgr != nil {
		stats["security"] = s.deps.SecurityMgr.Stats()
	}
	if s.deps.DomainFilter != nil {
		stats["domains"] = s.deps.DomainFilter.Stats()
	}
	if s.deps.GeoChecker != nil {
		stats["geoip"] = s.deps.GeoChecker.Stats()
	}
	if s.deps.AlertMgr != nil {
		stats["alerts"] = s.deps.AlertMgr.GetStats()
	}
	if s.deps.Reloader != nil {
		stats["reloader"] = s.deps.Reloader.Stats()
	}

	return stats
}
