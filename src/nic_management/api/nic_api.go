// NIC Management REST API
// Provides HTTP endpoints for NIC detection, configuration, and status
package api

import (
	"encoding/json"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"gopkg.in/yaml.v3"
)

// NICInfo represents a network interface
type NICInfo struct {
	Index       int      `json:"index"`
	Name        string   `json:"name"`
	Alias       string   `json:"alias"`
	Type        string   `json:"type"` // WAN, LAN, VIRTUAL, LOOPBACK
	Status      string   `json:"status"`
	IPv4        []string `json:"ipv4"`
	IPv6        []string `json:"ipv6"`
	Gateway     string   `json:"gateway"`
	MAC         string   `json:"mac"`
	Speed       uint64   `json:"speed"`
	MTU         int      `json:"mtu"`
	IsPhysical  bool     `json:"isPhysical"`
	IsPrimary   bool     `json:"isPrimary"`
	RxBytes     uint64   `json:"rxBytes"`
	TxBytes     uint64   `json:"txBytes"`
	RxBps       uint64   `json:"rxBps"`
	TxBps       uint64   `json:"txBps"`
	LastUpdated string   `json:"lastUpdated"`
}

// NICListResponse is the API response for listing NICs
type NICListResponse struct {
	Interfaces []NICInfo `json:"interfaces"`
	Total      int       `json:"total"`
	Timestamp  string    `json:"timestamp"`
}

// UpdateNICRequest represents a NIC update request
type UpdateNICRequest struct {
	Alias string `json:"alias,omitempty"`
	Type  string `json:"type,omitempty"`
}

// NICAPIServer provides REST API for NIC management
type NICAPIServer struct {
	port       int
	configPath string
	aliases    map[int]string // index -> alias mapping
	types      map[int]string // index -> type mapping
	mu         sync.RWMutex
	server     *http.Server
	monitor    *NICMonitor
}

// NewNICAPIServer creates a new NIC API server
func NewNICAPIServer(port int, configPath string) *NICAPIServer {
	return &NICAPIServer{
		port:       port,
		configPath: configPath,
		aliases:    make(map[int]string),
		types:      make(map[int]string),
	}
}

// Start starts the HTTP server
func (s *NICAPIServer) Start() error {
	// Initialize monitor
	s.monitor = NewNICMonitor(s)
	s.monitor.Start()

	mux := http.NewServeMux()

	// API routes
	mux.HandleFunc("/api/nics", s.corsMiddleware(s.handleNICs))
	mux.HandleFunc("/api/nics/", s.corsMiddleware(s.handleNIC))
	mux.HandleFunc("/api/nics/refresh", s.corsMiddleware(s.handleRefresh))
	mux.HandleFunc("/api/nics/events", s.corsMiddleware(s.HandleSSE)) // SSE real-time updates

	// NIC Control endpoints
	mux.HandleFunc("/api/nics/control/", s.corsMiddleware(s.HandleNICControl))

	// Hotspot endpoints
	mux.HandleFunc("/api/hotspot/status", s.corsMiddleware(s.HandleHotspotStatus))
	mux.HandleFunc("/api/hotspot/start", s.corsMiddleware(s.HandleHotspotStart))
	mux.HandleFunc("/api/hotspot/stop", s.corsMiddleware(s.HandleHotspotStop))

	// Topology and System Stats
	mux.HandleFunc("/api/topology", s.corsMiddleware(s.HandleTopology))
	mux.HandleFunc("/api/system/stats", s.corsMiddleware(s.HandleSystemStats))

	// DHCP Management
	mux.HandleFunc("/api/dhcp/leases", s.corsMiddleware(s.HandleDHCPLeases))
	mux.HandleFunc("/api/dhcp/leases/search", s.corsMiddleware(s.HandleDHCPSearch))
	mux.HandleFunc("/api/dhcp/leases/", s.corsMiddleware(s.HandleDHCPRelease))
	mux.HandleFunc("/api/dhcp/stats", s.corsMiddleware(s.HandleDHCPStats))
	mux.HandleFunc("/api/dhcp/pools", s.corsMiddleware(s.HandleDHCPPools))

	mux.HandleFunc("/api/health", s.corsMiddleware(s.handleHealth))

	s.server = &http.Server{
		Addr:         fmt.Sprintf(":%d", s.port),
		Handler:      mux,
		ReadTimeout:  0, // No timeout for SSE
		WriteTimeout: 0, // No timeout for SSE
	}

	log.Printf("NIC API server starting on port %d (with real-time SSE)", s.port)
	return s.server.ListenAndServe()
}

// Stop stops the HTTP server
func (s *NICAPIServer) Stop() error {
	if s.server != nil {
		return s.server.Close()
	}
	return nil
}

// CORS middleware
func (s *NICAPIServer) corsMiddleware(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Methods", "GET, POST, PATCH, DELETE, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization")

		if r.Method == "OPTIONS" {
			w.WriteHeader(http.StatusOK)
			return
		}

		next(w, r)
	}
}

// handleNICs handles GET /api/nics - list all NICs
func (s *NICAPIServer) handleNICs(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	nics, err := s.detectNICs()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	resp := NICListResponse{
		Interfaces: nics,
		Total:      len(nics),
		Timestamp:  time.Now().Format(time.RFC3339),
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(resp)
}

// handleNIC handles GET/PATCH /api/nics/:id
func (s *NICAPIServer) handleNIC(w http.ResponseWriter, r *http.Request) {
	// Extract NIC index from URL
	parts := strings.Split(r.URL.Path, "/")
	if len(parts) < 4 {
		http.Error(w, "Invalid URL", http.StatusBadRequest)
		return
	}

	indexStr := parts[3]
	index, err := strconv.Atoi(indexStr)
	if err != nil {
		http.Error(w, "Invalid NIC index", http.StatusBadRequest)
		return
	}

	switch r.Method {
	case http.MethodGet:
		s.getNIC(w, index)
	case http.MethodPatch:
		s.updateNIC(w, r, index)
	default:
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
	}
}

// getNIC returns a specific NIC by index
func (s *NICAPIServer) getNIC(w http.ResponseWriter, index int) {
	nics, err := s.detectNICs()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	for _, nic := range nics {
		if nic.Index == index {
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(nic)
			return
		}
	}

	http.Error(w, "NIC not found", http.StatusNotFound)
}

// updateNIC updates a NIC's alias or type
func (s *NICAPIServer) updateNIC(w http.ResponseWriter, r *http.Request, index int) {
	var req UpdateNICRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	s.mu.Lock()
	if req.Alias != "" {
		s.aliases[index] = req.Alias
	}
	if req.Type != "" {
		s.types[index] = req.Type
	}
	s.mu.Unlock()

	// Update config file
	if err := s.updateConfigFile(index, req); err != nil {
		log.Printf("Warning: failed to update config file: %v", err)
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"success": true,
		"message": "NIC updated",
		"index":   index,
		"alias":   req.Alias,
		"type":    req.Type,
	})
}

// handleRefresh forces a NIC re-detection
func (s *NICAPIServer) handleRefresh(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	nics, err := s.detectNICs()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"success":    true,
		"count":      len(nics),
		"interfaces": nics,
	})
}

// handleHealth returns server health status
func (s *NICAPIServer) handleHealth(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"status":    "healthy",
		"timestamp": time.Now().Format(time.RFC3339),
	})
}

// detectNICs scans all network interfaces
func (s *NICAPIServer) detectNICs() ([]NICInfo, error) {
	interfaces, err := net.Interfaces()
	if err != nil {
		return nil, err
	}

	s.mu.RLock()
	defer s.mu.RUnlock()

	var nics []NICInfo
	for _, iface := range interfaces {
		nic := NICInfo{
			Index: iface.Index,
			Name:  iface.Name,
			MAC:   iface.HardwareAddr.String(),
			MTU:   iface.MTU,
		}

		// Apply saved alias or use name
		if alias, ok := s.aliases[iface.Index]; ok {
			nic.Alias = alias
		} else {
			nic.Alias = iface.Name
		}

		// Apply saved type or detect
		if nicType, ok := s.types[iface.Index]; ok {
			nic.Type = nicType
		} else {
			nic.Type = s.classifyInterface(iface)
		}

		// Status
		if iface.Flags&net.FlagUp != 0 {
			nic.Status = "UP"
		} else {
			nic.Status = "DOWN"
		}

		// Physical check
		nic.IsPhysical = s.isPhysicalInterface(iface)

		// Get addresses
		addrs, _ := iface.Addrs()
		for _, addr := range addrs {
			ip, _, err := net.ParseCIDR(addr.String())
			if err != nil {
				continue
			}
			if ip.To4() != nil {
				nic.IPv4 = append(nic.IPv4, addr.String())
				// Guess gateway
				ip4 := ip.To4()
				nic.Gateway = fmt.Sprintf("%d.%d.%d.1", ip4[0], ip4[1], ip4[2])
			} else {
				nic.IPv6 = append(nic.IPv6, addr.String())
			}
		}

		nic.LastUpdated = time.Now().Format(time.RFC3339)
		nics = append(nics, nic)
	}

	return nics, nil
}

// classifyInterface determines if an interface is WAN/LAN/VIRTUAL
func (s *NICAPIServer) classifyInterface(iface net.Interface) string {
	name := strings.ToLower(iface.Name)

	// Loopback
	if iface.Flags&net.FlagLoopback != 0 {
		return "LOOPBACK"
	}

	// Virtual patterns
	virtualPatterns := []string{"vmware", "vmnet", "vbox", "vethernet", "docker", "br-", "virbr", "wsl"}
	for _, p := range virtualPatterns {
		if strings.Contains(name, p) {
			return "VIRTUAL"
		}
	}

	// Check for addresses
	addrs, _ := iface.Addrs()
	hasPrivateIP := false
	for _, addr := range addrs {
		ip, _, _ := net.ParseCIDR(addr.String())
		if ip != nil && ip.To4() != nil {
			if s.isPrivateIP(ip) {
				hasPrivateIP = true
			} else {
				return "WAN" // Has public IP
			}
		}
	}

	if hasPrivateIP {
		// Check if has gateway (WAN) or no gateway (LAN)
		// For now, assume Wi-Fi/first adapter is WAN
		if strings.Contains(name, "wi-fi") || strings.Contains(name, "wireless") {
			return "WAN"
		}
		return "LAN"
	}

	return "UNKNOWN"
}

func (s *NICAPIServer) isPhysicalInterface(iface net.Interface) bool {
	name := strings.ToLower(iface.Name)
	virtualPatterns := []string{"loopback", "lo", "veth", "docker", "br-", "vmware", "vmnet", "vbox", "vethernet", "wsl"}
	for _, p := range virtualPatterns {
		if strings.Contains(name, p) {
			return false
		}
	}
	return len(iface.HardwareAddr) > 0
}

func (s *NICAPIServer) isPrivateIP(ip net.IP) bool {
	private := []string{"10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "169.254.0.0/16"}
	for _, cidr := range private {
		_, network, _ := net.ParseCIDR(cidr)
		if network.Contains(ip) {
			return true
		}
	}
	return false
}

// updateConfigFile updates the config.yaml with the new alias/type
func (s *NICAPIServer) updateConfigFile(index int, req UpdateNICRequest) error {
	if s.configPath == "" {
		return nil
	}

	// Read existing config
	data, err := os.ReadFile(s.configPath)
	if err != nil {
		return err
	}

	// Parse YAML
	var config map[string]interface{}
	if err := yaml.Unmarshal(data, &config); err != nil {
		return err
	}

	// TODO: Update the specific interface in wan_interfaces or lan_interfaces
	// For now, just log the change
	log.Printf("Config update: NIC %d -> alias=%s, type=%s", index, req.Alias, req.Type)

	return nil
}

// StartNICAPI starts the NIC API server in a goroutine
func StartNICAPI(port int, configPath string) (*NICAPIServer, error) {
	server := NewNICAPIServer(port, configPath)
	go func() {
		if err := server.Start(); err != nil && err != http.ErrServerClosed {
			log.Printf("NIC API server error: %v", err)
		}
	}()
	return server, nil
}
