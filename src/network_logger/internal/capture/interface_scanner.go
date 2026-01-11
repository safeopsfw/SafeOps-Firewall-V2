package capture

import (
	"context"
	"strings"
	"sync"
	"time"

	"github.com/google/gopacket/pcap"
)

// InterfaceInfo contains information about a network interface
type InterfaceInfo struct {
	Name        string
	Description string
	IsHotspot   bool
	IsPhysical  bool
	Addresses   []string
}

// InterfaceScanner monitors available network interfaces
type InterfaceScanner struct {
	activeInterfaces map[string]*InterfaceInfo
	mu               sync.RWMutex
	scanInterval     time.Duration
}

// NewInterfaceScanner creates a new interface scanner
func NewInterfaceScanner(interval time.Duration) *InterfaceScanner {
	return &InterfaceScanner{
		activeInterfaces: make(map[string]*InterfaceInfo),
		scanInterval:     interval,
	}
}

// Start begins scanning for interfaces
func (s *InterfaceScanner) Start(ctx context.Context) {
	// Initial scan
	s.scan()

	go func() {
		ticker := time.NewTicker(s.scanInterval)
		defer ticker.Stop()

		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				s.scan()
			}
		}
	}()
}

// scan discovers available interfaces
func (s *InterfaceScanner) scan() {
	devices, err := pcap.FindAllDevs()
	if err != nil {
		return
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	// Clear old interfaces
	s.activeInterfaces = make(map[string]*InterfaceInfo)

	for _, device := range devices {
		// Skip loopback and disconnected interfaces
		if isLoopback(device.Name, device.Description) {
			continue
		}

		// Skip if no addresses (disconnected)
		if len(device.Addresses) == 0 {
			continue
		}

		info := &InterfaceInfo{
			Name:        device.Name,
			Description: device.Description,
			IsHotspot:   isHotspotInterface(device.Description),
			IsPhysical:  isPhysicalInterface(device.Description),
			Addresses:   make([]string, 0),
		}

		for _, addr := range device.Addresses {
			info.Addresses = append(info.Addresses, addr.IP.String())
		}

		s.activeInterfaces[device.Name] = info
	}
}

// GetActiveInterfaces returns all active interface names
func (s *InterfaceScanner) GetActiveInterfaces() []string {
	s.mu.RLock()
	defer s.mu.RUnlock()

	interfaces := make([]string, 0, len(s.activeInterfaces))
	for name := range s.activeInterfaces {
		interfaces = append(interfaces, name)
	}

	return interfaces
}

// GetInterfaceInfo returns information about a specific interface
func (s *InterfaceScanner) GetInterfaceInfo(name string) *InterfaceInfo {
	s.mu.RLock()
	defer s.mu.RUnlock()

	return s.activeInterfaces[name]
}

// IsHotspotInterface checks if an interface is a Windows hotspot
func (s *InterfaceScanner) IsHotspotInterface(name string) bool {
	s.mu.RLock()
	defer s.mu.RUnlock()

	if info, ok := s.activeInterfaces[name]; ok {
		return info.IsHotspot
	}
	return false
}

// isLoopback checks if an interface is loopback
func isLoopback(name, desc string) bool {
	nameL := strings.ToLower(name)
	descL := strings.ToLower(desc)

	return strings.Contains(nameL, "loopback") ||
		strings.Contains(descL, "loopback") ||
		strings.Contains(nameL, "127.0.0.1")
}

// isHotspotInterface identifies Windows Mobile Hotspot interface
func isHotspotInterface(desc string) bool {
	descL := strings.ToLower(desc)

	// Windows Mobile Hotspot indicators
	return strings.Contains(descL, "microsoft wi-fi direct virtual adapter") ||
		strings.Contains(descL, "hosted network") ||
		strings.Contains(descL, "softap")
}

// isPhysicalInterface checks if this is a physical adapter
func isPhysicalInterface(desc string) bool {
	descL := strings.ToLower(desc)

	physical := []string{
		"ethernet",
		"wi-fi",
		"wireless",
		"802.11",
		"wlan",
		"lan",
	}

	for _, keyword := range physical {
		if strings.Contains(descL, keyword) {
			return true
		}
	}

	return false
}
