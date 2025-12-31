// Package websocket provides real-time event broadcasting for the dashboard.
package websocket

import (
	"encoding/json"
	"log"
	"net/http"
	"sync"
	"time"

	"golang.org/x/net/websocket"
)

// Event types for real-time updates
const (
	EventDeviceConnected = "device_connected"
	EventDeviceEnrolled  = "device_enrolled"
	EventDHCPLease       = "dhcp_lease"
	EventDNSQuery        = "dns_query"
	EventServiceStatus   = "service_status"
)

// Event represents a real-time dashboard event
type Event struct {
	Type      string      `json:"type"`
	Timestamp time.Time   `json:"timestamp"`
	Data      interface{} `json:"data"`
}

// Hub manages WebSocket connections and broadcasts events
type Hub struct {
	clients    map[*Client]bool
	register   chan *Client
	unregister chan *Client
	broadcast  chan *Event
	mu         sync.RWMutex
}

// Client represents a WebSocket client connection
type Client struct {
	hub  *Hub
	conn *websocket.Conn
	send chan *Event
}

// NewHub creates a new WebSocket hub
func NewHub() *Hub {
	return &Hub{
		clients:    make(map[*Client]bool),
		register:   make(chan *Client),
		unregister: make(chan *Client),
		broadcast:  make(chan *Event, 100),
	}
}

// Run starts the hub event loop
func (h *Hub) Run() {
	for {
		select {
		case client := <-h.register:
			h.mu.Lock()
			h.clients[client] = true
			h.mu.Unlock()
			log.Printf("[WebSocket] Client connected (%d total)", len(h.clients))

		case client := <-h.unregister:
			h.mu.Lock()
			if _, ok := h.clients[client]; ok {
				delete(h.clients, client)
				close(client.send)
			}
			h.mu.Unlock()
			log.Printf("[WebSocket] Client disconnected (%d remaining)", len(h.clients))

		case event := <-h.broadcast:
			h.mu.RLock()
			for client := range h.clients {
				select {
				case client.send <- event:
				default:
					// Client too slow, skip
				}
			}
			h.mu.RUnlock()
		}
	}
}

// Broadcast sends an event to all connected clients
func (h *Hub) Broadcast(eventType string, data interface{}) {
	event := &Event{
		Type:      eventType,
		Timestamp: time.Now(),
		Data:      data,
	}

	select {
	case h.broadcast <- event:
	default:
		log.Printf("[WebSocket] Broadcast channel full, dropping event")
	}
}

// Handler returns the WebSocket HTTP handler
func (h *Hub) Handler() http.Handler {
	return websocket.Handler(func(conn *websocket.Conn) {
		client := &Client{
			hub:  h,
			conn: conn,
			send: make(chan *Event, 256),
		}

		h.register <- client

		// Start writer goroutine
		go client.writePump()

		// Read loop (for keepalive/close detection)
		client.readPump()
	})
}

func (c *Client) readPump() {
	defer func() {
		c.hub.unregister <- c
		c.conn.Close()
	}()

	for {
		var msg string
		if err := websocket.Message.Receive(c.conn, &msg); err != nil {
			break
		}
	}
}

func (c *Client) writePump() {
	for event := range c.send {
		data, err := json.Marshal(event)
		if err != nil {
			continue
		}
		if err := websocket.Message.Send(c.conn, string(data)); err != nil {
			break
		}
	}
}

// ============================================================================
// Event Data Types
// ============================================================================

// DeviceConnectedData represents a new device connection event
type DeviceConnectedData struct {
	IPAddress  string `json:"ip_address"`
	MACAddress string `json:"mac_address"`
	Hostname   string `json:"hostname"`
	OSType     string `json:"os_type"`
}

// DeviceEnrolledData represents a device enrollment event
type DeviceEnrolledData struct {
	IPAddress string `json:"ip_address"`
	OSType    string `json:"os_type"`
	Method    string `json:"method"` // "portal", "gpo", "mdm", etc.
}

// DHCPLeaseData represents a DHCP lease event
type DHCPLeaseData struct {
	IPAddress  string    `json:"ip_address"`
	MACAddress string    `json:"mac_address"`
	Hostname   string    `json:"hostname"`
	LeaseTime  time.Time `json:"lease_time"`
	ExpiresAt  time.Time `json:"expires_at"`
}

// DNSQueryData represents a DNS query event
type DNSQueryData struct {
	ClientIP   string `json:"client_ip"`
	Domain     string `json:"domain"`
	QueryType  string `json:"query_type"`
	Blocked    bool   `json:"blocked"`
	Cached     bool   `json:"cached"`
	ResponseMs int    `json:"response_ms"`
}

// ServiceStatusData represents a service health status
type ServiceStatusData struct {
	ServiceName string `json:"service_name"`
	Status      string `json:"status"` // "healthy", "degraded", "offline"
	Message     string `json:"message,omitempty"`
}
