// NIC WebSocket and Real-Time Monitor
// Provides WebSocket endpoint for real-time NIC change notifications
package api

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"log"
	"net"
	"net/http"
	"os/exec"
	"runtime"
	"strings"
	"sync"
	"time"
)

// ============================================================================
// WebSocket Types
// ============================================================================

// WSClient represents a connected WebSocket client
type WSClient struct {
	ID      string
	Conn    http.ResponseWriter
	Flusher http.Flusher
	Done    chan struct{}
	mu      sync.Mutex
}

// NICEvent represents a NIC change event
type NICEvent struct {
	Type      string    `json:"type"` // nic_added, nic_removed, nic_status_changed, nic_ip_changed, speed_update, full_update
	Interface *NICInfo  `json:"interface,omitempty"`
	OldValue  string    `json:"oldValue,omitempty"`
	NewValue  string    `json:"newValue,omitempty"`
	Timestamp time.Time `json:"timestamp"`
}

// SpeedUpdate contains bandwidth information
type SpeedUpdate struct {
	Type       string           `json:"type"` // speed_update
	Interfaces []InterfaceSpeed `json:"interfaces"`
	Timestamp  time.Time        `json:"timestamp"`
}

// InterfaceSpeed tracks bandwidth for one interface
type InterfaceSpeed struct {
	Index int    `json:"index"`
	RxBps uint64 `json:"rxBps"`
	TxBps uint64 `json:"txBps"`
}

// ============================================================================
// NIC Monitor
// ============================================================================

// NICMonitor watches for NIC changes
type NICMonitor struct {
	server       *NICAPIServer
	clients      map[string]*WSClient
	clientsMu    sync.RWMutex
	prevState    map[int]*NICInfo
	prevBytes    map[int]ByteCounter
	pollInterval time.Duration
	ctx          context.Context
	cancel       context.CancelFunc
}

// ByteCounter tracks bytes for speed calculation
type ByteCounter struct {
	RxBytes   uint64
	TxBytes   uint64
	Timestamp time.Time
}

// NewNICMonitor creates a new monitor
func NewNICMonitor(server *NICAPIServer) *NICMonitor {
	ctx, cancel := context.WithCancel(context.Background())
	return &NICMonitor{
		server:       server,
		clients:      make(map[string]*WSClient),
		prevState:    make(map[int]*NICInfo),
		prevBytes:    make(map[int]ByteCounter),
		pollInterval: 500 * time.Millisecond,
		ctx:          ctx,
		cancel:       cancel,
	}
}

// Start begins the monitoring loop
func (m *NICMonitor) Start() {
	go m.monitorLoop()
	log.Println("NIC Monitor started (polling every 500ms)")
}

// Stop halts the monitor
func (m *NICMonitor) Stop() {
	m.cancel()
}

// monitorLoop continuously checks for NIC changes
func (m *NICMonitor) monitorLoop() {
	ticker := time.NewTicker(m.pollInterval)
	defer ticker.Stop()

	// Initial scan
	m.scanAndUpdate()

	for {
		select {
		case <-m.ctx.Done():
			return
		case <-ticker.C:
			m.scanAndUpdate()
		}
	}
}

// scanAndUpdate checks for changes and broadcasts events
func (m *NICMonitor) scanAndUpdate() {
	nics, err := m.server.detectNICs()
	if err != nil {
		log.Printf("NIC scan error: %v", err)
		return
	}

	// Build current state map
	currentState := make(map[int]*NICInfo)
	for i := range nics {
		nic := nics[i]
		currentState[nic.Index] = &nic
	}

	// Detect primary WAN
	primaryIdx := m.detectPrimaryWAN(nics)

	// Mark primary
	for _, nic := range currentState {
		nic.IsPrimary = (nic.Index == primaryIdx)
	}

	// Compare with previous state
	var events []NICEvent

	// Check for added/changed NICs
	for idx, current := range currentState {
		prev, existed := m.prevState[idx]
		if !existed {
			// NIC added
			events = append(events, NICEvent{
				Type:      "nic_added",
				Interface: current,
				Timestamp: time.Now(),
			})
		} else {
			// Check for changes
			if prev.Status != current.Status {
				events = append(events, NICEvent{
					Type:      "nic_status_changed",
					Interface: current,
					OldValue:  prev.Status,
					NewValue:  current.Status,
					Timestamp: time.Now(),
				})
			}
			if !equalStringSlices(prev.IPv4, current.IPv4) {
				events = append(events, NICEvent{
					Type:      "nic_ip_changed",
					Interface: current,
					OldValue:  strings.Join(prev.IPv4, ","),
					NewValue:  strings.Join(current.IPv4, ","),
					Timestamp: time.Now(),
				})
			}
			if prev.IsPrimary != current.IsPrimary {
				events = append(events, NICEvent{
					Type:      "nic_primary_changed",
					Interface: current,
					Timestamp: time.Now(),
				})
			}
		}
	}

	// Check for removed NICs
	for idx, prev := range m.prevState {
		if _, exists := currentState[idx]; !exists {
			events = append(events, NICEvent{
				Type:      "nic_removed",
				Interface: prev,
				Timestamp: time.Now(),
			})
		}
	}

	// Update previous state
	m.prevState = currentState

	// Broadcast events
	for _, event := range events {
		m.broadcast(event)
	}

	// Calculate and broadcast speed updates
	m.broadcastSpeedUpdate(nics)
}

// detectPrimaryWAN finds the NIC with actual internet connectivity
// Prioritizes: 1. Wired Ethernet with gateway, 2. Any NIC with gateway, 3. First UP NIC
func (m *NICMonitor) detectPrimaryWAN(nics []NICInfo) int {
	// Try to find the NIC associated with default gateway
	gatewayIP := m.getDefaultGateway()

	var candidates []NICInfo

	if gatewayIP != "" {
		// Find all NICs on the same subnet as the gateway
		for _, nic := range nics {
			if nic.Status != "UP" {
				continue
			}
			for _, ipStr := range nic.IPv4 {
				_, ipNet, err := net.ParseCIDR(ipStr)
				if err != nil {
					continue
				}
				gw := net.ParseIP(gatewayIP)
				if ipNet.Contains(gw) {
					candidates = append(candidates, nic)
					break
				}
			}
		}
	}

	// Priority 1: Prefer physical wired Ethernet over WiFi
	// First pass: Look for physical Ethernet adapters (not virtual, not WiFi)
	for _, nic := range candidates {
		name := strings.ToLower(nic.Name)
		// Skip WiFi interfaces
		if strings.Contains(name, "wi-fi") || strings.Contains(name, "wireless") ||
			strings.Contains(name, "wlan") || strings.Contains(name, "802.11") {
			continue
		}
		// Skip virtual adapters
		if strings.Contains(name, "vethernet") || strings.Contains(name, "vmware") ||
			strings.Contains(name, "virtualbox") || strings.Contains(name, "hyper-v") ||
			strings.Contains(name, "loopback") {
			continue
		}
		// Prefer simple "Ethernet" or "Ethernet N" names (physical adapters)
		if strings.HasPrefix(name, "ethernet") {
			return nic.Index
		}
	}

	// Second pass: Any non-WiFi, non-virtual with gateway
	for _, nic := range candidates {
		name := strings.ToLower(nic.Name)
		if !strings.Contains(name, "wi-fi") && !strings.Contains(name, "wireless") &&
			!strings.Contains(name, "wlan") && !strings.Contains(name, "vethernet") &&
			!strings.Contains(name, "vmware") && !strings.Contains(name, "virtualbox") {
			return nic.Index
		}
	}

	// Priority 2: Return any candidate with gateway
	if len(candidates) > 0 {
		return candidates[0].Index
	}

	// Priority 3: Fallback - first UP wired NIC
	for _, nic := range nics {
		if nic.Status == "UP" && nic.IsPhysical && nic.Type != "LOOPBACK" {
			name := strings.ToLower(nic.Name)
			if !strings.Contains(name, "wi-fi") && !strings.Contains(name, "wireless") {
				return nic.Index
			}
		}
	}

	// Priority 4: Any UP physical NIC
	for _, nic := range nics {
		if nic.Status == "UP" && nic.IsPhysical && nic.Type != "LOOPBACK" {
			return nic.Index
		}
	}

	return -1
}

// getDefaultGateway retrieves the default gateway IP
func (m *NICMonitor) getDefaultGateway() string {
	if runtime.GOOS == "windows" {
		cmd := exec.Command("cmd", "/c", "route", "print", "0.0.0.0")
		output, err := cmd.Output()
		if err != nil {
			return ""
		}
		lines := strings.Split(string(output), "\n")
		for _, line := range lines {
			fields := strings.Fields(line)
			if len(fields) >= 3 && fields[0] == "0.0.0.0" {
				return fields[2] // Gateway column
			}
		}
	}
	return ""
}

// broadcastSpeedUpdate calculates and sends speed data
func (m *NICMonitor) broadcastSpeedUpdate(nics []NICInfo) {
	now := time.Now()
	var speeds []InterfaceSpeed

	for _, nic := range nics {
		prev, exists := m.prevBytes[nic.Index]

		if exists {
			elapsed := now.Sub(prev.Timestamp).Seconds()
			if elapsed > 0 {
				rxBps := uint64(float64(nic.RxBytes-prev.RxBytes) / elapsed)
				txBps := uint64(float64(nic.TxBytes-prev.TxBytes) / elapsed)
				speeds = append(speeds, InterfaceSpeed{
					Index: nic.Index,
					RxBps: rxBps,
					TxBps: txBps,
				})
			}
		}

		m.prevBytes[nic.Index] = ByteCounter{
			RxBytes:   nic.RxBytes,
			TxBytes:   nic.TxBytes,
			Timestamp: now,
		}
	}

	if len(speeds) > 0 {
		m.broadcast(SpeedUpdate{
			Type:       "speed_update",
			Interfaces: speeds,
			Timestamp:  now,
		})
	}
}

// broadcast sends data to all connected clients
func (m *NICMonitor) broadcast(data interface{}) {
	jsonData, err := json.Marshal(data)
	if err != nil {
		return
	}

	m.clientsMu.RLock()
	defer m.clientsMu.RUnlock()

	for _, client := range m.clients {
		go client.Send(jsonData)
	}
}

// Send writes data to a client using SSE format
func (c *WSClient) Send(data []byte) {
	c.mu.Lock()
	defer c.mu.Unlock()

	select {
	case <-c.Done:
		return
	default:
		// Write SSE format
		c.Conn.Write([]byte("data: "))
		c.Conn.Write(data)
		c.Conn.Write([]byte("\n\n"))
		if c.Flusher != nil {
			c.Flusher.Flush()
		}
	}
}

// AddClient registers a new SSE client
func (m *NICMonitor) AddClient(w http.ResponseWriter, r *http.Request) *WSClient {
	id := generateID()

	flusher, ok := w.(http.Flusher)
	if !ok {
		http.Error(w, "SSE not supported", http.StatusInternalServerError)
		return nil
	}

	client := &WSClient{
		ID:      id,
		Conn:    w,
		Flusher: flusher,
		Done:    make(chan struct{}),
	}

	m.clientsMu.Lock()
	m.clients[id] = client
	m.clientsMu.Unlock()

	log.Printf("Client connected: %s (total: %d)", id, len(m.clients))

	// Send initial full state
	nics, _ := m.server.detectNICs()
	primaryIdx := m.detectPrimaryWAN(nics)
	for i := range nics {
		nics[i].IsPrimary = (nics[i].Index == primaryIdx)
	}

	initialData, _ := json.Marshal(map[string]interface{}{
		"type":       "full_update",
		"interfaces": nics,
		"timestamp":  time.Now(),
	})
	client.Send(initialData)

	return client
}

// RemoveClient unregisters a client
func (m *NICMonitor) RemoveClient(id string) {
	m.clientsMu.Lock()
	if client, exists := m.clients[id]; exists {
		close(client.Done)
		delete(m.clients, id)
	}
	m.clientsMu.Unlock()
	log.Printf("Client disconnected: %s (remaining: %d)", id, len(m.clients))
}

// ============================================================================
// SSE Endpoint Handler
// ============================================================================

// HandleSSE handles the Server-Sent Events endpoint
func (s *NICAPIServer) HandleSSE(w http.ResponseWriter, r *http.Request) {
	// Set SSE headers
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")
	w.Header().Set("Access-Control-Allow-Origin", "*")

	client := s.monitor.AddClient(w, r)
	if client == nil {
		return
	}

	// Keep connection open
	<-r.Context().Done()
	s.monitor.RemoveClient(client.ID)
}

// ============================================================================
// Helper Functions
// ============================================================================

func generateID() string {
	bytes := make([]byte, 8)
	rand.Read(bytes)
	return hex.EncodeToString(bytes)
}

func equalStringSlices(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
