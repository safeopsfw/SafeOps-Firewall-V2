// Package poller provides periodic monitoring of Windows DHCP Server
package poller

import (
	"context"
	"dhcp_monitor/internal/windows_dhcp"
	"fmt"
	"sync"
	"time"
)

// Poller periodically checks Windows DHCP for changes
type Poller struct {
	client   windows_dhcp.Client
	interval time.Duration
	eventCh  chan windows_dhcp.MonitorEvent
	stopCh   chan struct{}
	wg       sync.WaitGroup

	// Track known leases to detect changes
	mu           sync.RWMutex
	knownLeases  map[string]*windows_dhcp.Lease // key: IP address
	lastPollTime time.Time

	// Track DHCP availability to avoid error spam
	dhcpAvailable bool
	errorLogged   bool
}

// Config holds poller configuration
type Config struct {
	Client       windows_dhcp.Client
	PollInterval time.Duration
}

// New creates a new DHCP poller
func New(cfg Config) *Poller {
	if cfg.PollInterval == 0 {
		cfg.PollInterval = 30 * time.Second
	}

	return &Poller{
		client:      cfg.Client,
		interval:    cfg.PollInterval,
		eventCh:     make(chan windows_dhcp.MonitorEvent, 100),
		stopCh:      make(chan struct{}),
		knownLeases: make(map[string]*windows_dhcp.Lease),
	}
}

// Start begins polling Windows DHCP Server
func (p *Poller) Start(ctx context.Context) error {
	// Initial poll to populate known leases (non-fatal if fails)
	if err := p.poll(); err != nil {
		// Log warning but don't fail - Windows DHCP Server may not be installed
		fmt.Printf("[WARN] Initial DHCP poll failed (Windows DHCP Server may not be available): %v\n", err)
		fmt.Println("[WARN] DHCP Monitor will continue running - captive portal and DNS hijacking are still active")
		fmt.Println("[WARN] DHCP poller will check periodically for Windows DHCP Server availability")
		p.dhcpAvailable = false
		p.errorLogged = true
	} else {
		p.dhcpAvailable = true
		p.errorLogged = false
	}

	p.wg.Add(1)
	go p.runPollLoop(ctx)

	return nil
}

// Stop stops the poller
func (p *Poller) Stop() error {
	close(p.stopCh)
	p.wg.Wait()
	close(p.eventCh)
	return nil
}

// Events returns the event channel
func (p *Poller) Events() <-chan windows_dhcp.MonitorEvent {
	return p.eventCh
}

// runPollLoop runs the periodic polling loop
func (p *Poller) runPollLoop(ctx context.Context) {
	defer p.wg.Done()

	ticker := time.NewTicker(p.interval)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			// Skip polling if we know Windows DHCP is not available
			if p.errorLogged && !p.dhcpAvailable {
				continue // Silently skip - error was already logged
			}

			if err := p.poll(); err != nil {
				// Only log once when DHCP becomes unavailable
				if !p.errorLogged {
					p.errorLogged = true
					p.dhcpAvailable = false
					// Error already logged in Start(), just mark as unavailable
				}
				continue
			}

			// DHCP is available
			if !p.dhcpAvailable {
				p.dhcpAvailable = true
				p.errorLogged = false
				fmt.Println("[INFO] Windows DHCP Server is now available")
			}

		case <-p.stopCh:
			return

		case <-ctx.Done():
			return
		}
	}
}

// poll checks Windows DHCP for changes
func (p *Poller) poll() error {
	// Get all current leases from Windows DHCP
	currentLeases, err := p.client.GetAllLeases()
	if err != nil {
		return fmt.Errorf("failed to get leases: %w", err)
	}

	p.mu.Lock()
	defer p.mu.Unlock()

	// Track current lease IPs
	currentIPs := make(map[string]bool)

	// Check for new or updated leases
	for i := range currentLeases {
		lease := &currentLeases[i]
		currentIPs[lease.IPAddress] = true

		known, exists := p.knownLeases[lease.IPAddress]

		if !exists {
			// New lease detected
			p.emitEvent(windows_dhcp.MonitorEvent{
				Type:      windows_dhcp.EventTypeLeaseCreated,
				Lease:     lease,
				Timestamp: time.Now(),
			})
			p.knownLeases[lease.IPAddress] = lease
		} else {
			// Check if lease was renewed (MAC changed or expiry changed)
			if known.MACAddress != lease.MACAddress {
				// IP reassigned to different device
				p.emitEvent(windows_dhcp.MonitorEvent{
					Type:      windows_dhcp.EventTypeLeaseCreated,
					Lease:     lease,
					Timestamp: time.Now(),
				})
				p.knownLeases[lease.IPAddress] = lease
			} else if !known.LeaseExpiry.Equal(lease.LeaseExpiry) {
				// Lease renewed
				p.emitEvent(windows_dhcp.MonitorEvent{
					Type:      windows_dhcp.EventTypeLeaseRenewed,
					Lease:     lease,
					Timestamp: time.Now(),
				})
				p.knownLeases[lease.IPAddress] = lease
			}
		}
	}

	// Check for expired/released leases
	for ip, lease := range p.knownLeases {
		if !currentIPs[ip] {
			// Lease no longer exists
			p.emitEvent(windows_dhcp.MonitorEvent{
				Type:      windows_dhcp.EventTypeLeaseExpired,
				Lease:     lease,
				Timestamp: time.Now(),
			})
			delete(p.knownLeases, ip)
		}
	}

	p.lastPollTime = time.Now()
	return nil
}

// emitEvent sends an event to the event channel (non-blocking)
func (p *Poller) emitEvent(event windows_dhcp.MonitorEvent) {
	select {
	case p.eventCh <- event:
		// Event sent successfully
	default:
		// Channel full, log warning
		fmt.Printf("[WARN] Event channel full, dropping event: %v\n", event.Type)
	}
}

// GetKnownLeases returns all currently known leases
func (p *Poller) GetKnownLeases() []windows_dhcp.Lease {
	p.mu.RLock()
	defer p.mu.RUnlock()

	leases := make([]windows_dhcp.Lease, 0, len(p.knownLeases))
	for _, lease := range p.knownLeases {
		leases = append(leases, *lease)
	}
	return leases
}

// GetLeaseByIP returns a known lease by IP address
func (p *Poller) GetLeaseByIP(ip string) (*windows_dhcp.Lease, bool) {
	p.mu.RLock()
	defer p.mu.RUnlock()

	lease, exists := p.knownLeases[ip]
	if !exists {
		return nil, false
	}
	return lease, true
}

// GetLeaseByMAC returns a known lease by MAC address
func (p *Poller) GetLeaseByMAC(mac string) (*windows_dhcp.Lease, bool) {
	p.mu.RLock()
	defer p.mu.RUnlock()

	for _, lease := range p.knownLeases {
		if lease.MACAddress == mac {
			return lease, true
		}
	}
	return nil, false
}

// GetLastPollTime returns the timestamp of the last successful poll
func (p *Poller) GetLastPollTime() time.Time {
	p.mu.RLock()
	defer p.mu.RUnlock()
	return p.lastPollTime
}

// GetStats returns poller statistics
func (p *Poller) GetStats() Stats {
	p.mu.RLock()
	defer p.mu.RUnlock()

	return Stats{
		KnownLeaseCount: len(p.knownLeases),
		LastPollTime:    p.lastPollTime,
		PollInterval:    p.interval,
	}
}

// Stats holds poller statistics
type Stats struct {
	KnownLeaseCount int
	LastPollTime    time.Time
	PollInterval    time.Duration
}
