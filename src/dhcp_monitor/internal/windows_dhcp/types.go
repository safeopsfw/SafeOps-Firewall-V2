// Package windows_dhcp provides Windows DHCP Server monitoring via WMI, PowerShell, and netsh.
package windows_dhcp

import "time"

// Lease represents a DHCP lease from Windows DHCP Server
type Lease struct {
	IPAddress      string
	MACAddress     string
	Hostname       string
	LeaseExpiry    time.Time
	State          LeaseState
	AddressState   string
	ClientType     string
	SubnetMask     string
	ScopeID        string
	ServerIP       string
	LeaseGrantTime time.Time
}

// LeaseState represents the state of a DHCP lease
type LeaseState string

const (
	LeaseStateActive   LeaseState = "Active"
	LeaseStateInactive LeaseState = "Inactive"
	LeaseStateReserved LeaseState = "Reserved"
	LeaseStateExpired  LeaseState = "Expired"
)

// Scope represents a DHCP scope (IP pool) on Windows DHCP Server
type Scope struct {
	ScopeID       string
	SubnetMask    string
	Name          string
	StartRange    string
	EndRange      string
	LeaseDuration time.Duration
	State         string
	Description   string
}

// Client is an interface for Windows DHCP monitoring
type Client interface {
	// GetAllLeases retrieves all DHCP leases from Windows DHCP Server
	GetAllLeases() ([]Lease, error)

	// GetLeaseByIP retrieves a specific lease by IP address
	GetLeaseByIP(ip string) (*Lease, error)

	// GetLeaseByMAC retrieves a specific lease by MAC address
	GetLeaseByMAC(mac string) (*Lease, error)

	// GetScopes retrieves all DHCP scopes
	GetScopes() ([]Scope, error)

	// GetScopeByID retrieves a specific scope by ID
	GetScopeByID(scopeID string) (*Scope, error)

	// ConfigureDNSOption sets DNS server option for a scope
	ConfigureDNSOption(scopeID string, dnsServers []string) error

	// ConfigureRouterOption sets gateway/router option for a scope
	ConfigureRouterOption(scopeID string, router string) error

	// Close cleans up any resources
	Close() error
}

// MonitorEvent represents a DHCP event detected by the monitor
type MonitorEvent struct {
	Type      EventType
	Lease     *Lease
	Timestamp time.Time
}

// EventType represents the type of DHCP event
type EventType string

const (
	EventTypeLeaseCreated  EventType = "LeaseCreated"
	EventTypeLeaseRenewed  EventType = "LeaseRenewed"
	EventTypeLeaseExpired  EventType = "LeaseExpired"
	EventTypeLeaseReleased EventType = "LeaseReleased"
)
