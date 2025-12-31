package windows_dhcp

import (
	"encoding/json"
	"fmt"
	"os/exec"
	"strings"
	"time"
)

// PowerShellClient implements Client using PowerShell DHCP cmdlets
type PowerShellClient struct {
	serverName string
}

// NewPowerShellClient creates a new PowerShell-based DHCP client
func NewPowerShellClient(serverName string) (*PowerShellClient, error) {
	if serverName == "" {
		serverName = "localhost"
	}

	// Test if PowerShell DHCP module is available
	cmd := exec.Command("powershell", "-Command", "Get-Module -ListAvailable -Name DhcpServer")
	if err := cmd.Run(); err != nil {
		return nil, fmt.Errorf("DHCP PowerShell module not available: %w", err)
	}

	return &PowerShellClient{
		serverName: serverName,
	}, nil
}

// GetAllLeases retrieves all DHCP leases using PowerShell
func (c *PowerShellClient) GetAllLeases() ([]Lease, error) {
	// PowerShell command to get all leases in JSON format
	psCmd := fmt.Sprintf(`
		Get-DhcpServerv4Lease -ComputerName %s |
		Select-Object IPAddress, ClientId, HostName, LeaseExpiryTime, AddressState, ScopeId |
		ConvertTo-Json -Compress
	`, c.serverName)

	cmd := exec.Command("powershell", "-Command", psCmd)
	output, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("failed to get DHCP leases: %w", err)
	}

	// Parse JSON output
	var rawLeases []map[string]interface{}
	if err := json.Unmarshal(output, &rawLeases); err != nil {
		// Handle single lease case (PowerShell returns object instead of array)
		var singleLease map[string]interface{}
		if err := json.Unmarshal(output, &singleLease); err != nil {
			return nil, fmt.Errorf("failed to parse lease data: %w", err)
		}
		rawLeases = []map[string]interface{}{singleLease}
	}

	// Convert to Lease structs
	leases := make([]Lease, 0, len(rawLeases))
	for _, raw := range rawLeases {
		lease := Lease{
			IPAddress:  getStringField(raw, "IPAddress"),
			MACAddress: formatMAC(getStringField(raw, "ClientId")),
			Hostname:   getStringField(raw, "HostName"),
			ScopeID:    getStringField(raw, "ScopeId"),
			State:      parseLeaseState(getStringField(raw, "AddressState")),
		}

		// Parse expiry time
		if expiryStr := getStringField(raw, "LeaseExpiryTime"); expiryStr != "" {
			if expiry, err := time.Parse(time.RFC3339, expiryStr); err == nil {
				lease.LeaseExpiry = expiry
			}
		}

		leases = append(leases, lease)
	}

	return leases, nil
}

// GetLeaseByIP retrieves a specific lease by IP address
func (c *PowerShellClient) GetLeaseByIP(ip string) (*Lease, error) {
	psCmd := fmt.Sprintf(`
		Get-DhcpServerv4Lease -ComputerName %s -IPAddress %s |
		Select-Object IPAddress, ClientId, HostName, LeaseExpiryTime, AddressState, ScopeId |
		ConvertTo-Json -Compress
	`, c.serverName, ip)

	cmd := exec.Command("powershell", "-Command", psCmd)
	output, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("failed to get lease for IP %s: %w", ip, err)
	}

	var raw map[string]interface{}
	if err := json.Unmarshal(output, &raw); err != nil {
		return nil, fmt.Errorf("failed to parse lease data: %w", err)
	}

	lease := &Lease{
		IPAddress:  getStringField(raw, "IPAddress"),
		MACAddress: formatMAC(getStringField(raw, "ClientId")),
		Hostname:   getStringField(raw, "HostName"),
		ScopeID:    getStringField(raw, "ScopeId"),
		State:      parseLeaseState(getStringField(raw, "AddressState")),
	}

	if expiryStr := getStringField(raw, "LeaseExpiryTime"); expiryStr != "" {
		if expiry, err := time.Parse(time.RFC3339, expiryStr); err == nil {
			lease.LeaseExpiry = expiry
		}
	}

	return lease, nil
}

// GetLeaseByMAC retrieves a specific lease by MAC address
func (c *PowerShellClient) GetLeaseByMAC(mac string) (*Lease, error) {
	// Get all leases and filter by MAC
	leases, err := c.GetAllLeases()
	if err != nil {
		return nil, err
	}

	normalizedMAC := formatMAC(mac)
	for _, lease := range leases {
		if lease.MACAddress == normalizedMAC {
			return &lease, nil
		}
	}

	return nil, fmt.Errorf("lease not found for MAC %s", mac)
}

// GetScopes retrieves all DHCP scopes
func (c *PowerShellClient) GetScopes() ([]Scope, error) {
	psCmd := fmt.Sprintf(`
		Get-DhcpServerv4Scope -ComputerName %s |
		Select-Object ScopeId, SubnetMask, Name, StartRange, EndRange, LeaseDuration, State, Description |
		ConvertTo-Json -Compress
	`, c.serverName)

	cmd := exec.Command("powershell", "-Command", psCmd)
	output, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("failed to get DHCP scopes: %w", err)
	}

	var rawScopes []map[string]interface{}
	if err := json.Unmarshal(output, &rawScopes); err != nil {
		// Handle single scope case
		var singleScope map[string]interface{}
		if err := json.Unmarshal(output, &singleScope); err != nil {
			return nil, fmt.Errorf("failed to parse scope data: %w", err)
		}
		rawScopes = []map[string]interface{}{singleScope}
	}

	scopes := make([]Scope, 0, len(rawScopes))
	for _, raw := range rawScopes {
		scope := Scope{
			ScopeID:     getStringField(raw, "ScopeId"),
			SubnetMask:  getStringField(raw, "SubnetMask"),
			Name:        getStringField(raw, "Name"),
			StartRange:  getStringField(raw, "StartRange"),
			EndRange:    getStringField(raw, "EndRange"),
			State:       getStringField(raw, "State"),
			Description: getStringField(raw, "Description"),
		}

		// Parse lease duration (format: "8.00:00:00" = 8 days)
		if durationStr := getStringField(raw, "LeaseDuration"); durationStr != "" {
			if duration, err := parseDuration(durationStr); err == nil {
				scope.LeaseDuration = duration
			}
		}

		scopes = append(scopes, scope)
	}

	return scopes, nil
}

// GetScopeByID retrieves a specific scope by ID
func (c *PowerShellClient) GetScopeByID(scopeID string) (*Scope, error) {
	psCmd := fmt.Sprintf(`
		Get-DhcpServerv4Scope -ComputerName %s -ScopeId %s |
		Select-Object ScopeId, SubnetMask, Name, StartRange, EndRange, LeaseDuration, State, Description |
		ConvertTo-Json -Compress
	`, c.serverName, scopeID)

	cmd := exec.Command("powershell", "-Command", psCmd)
	output, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("failed to get scope %s: %w", scopeID, err)
	}

	var raw map[string]interface{}
	if err := json.Unmarshal(output, &raw); err != nil {
		return nil, fmt.Errorf("failed to parse scope data: %w", err)
	}

	scope := &Scope{
		ScopeID:     getStringField(raw, "ScopeId"),
		SubnetMask:  getStringField(raw, "SubnetMask"),
		Name:        getStringField(raw, "Name"),
		StartRange:  getStringField(raw, "StartRange"),
		EndRange:    getStringField(raw, "EndRange"),
		State:       getStringField(raw, "State"),
		Description: getStringField(raw, "Description"),
	}

	if durationStr := getStringField(raw, "LeaseDuration"); durationStr != "" {
		if duration, err := parseDuration(durationStr); err == nil {
			scope.LeaseDuration = duration
		}
	}

	return scope, nil
}

// ConfigureDNSOption sets DNS server option (Option 6) for a scope
func (c *PowerShellClient) ConfigureDNSOption(scopeID string, dnsServers []string) error {
	dnsServerList := strings.Join(dnsServers, ",")
	psCmd := fmt.Sprintf(`
		Set-DhcpServerv4OptionValue -ComputerName %s -ScopeId %s -OptionId 6 -Value %s
	`, c.serverName, scopeID, dnsServerList)

	cmd := exec.Command("powershell", "-Command", psCmd)
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("failed to set DNS option for scope %s: %w", scopeID, err)
	}

	return nil
}

// ConfigureRouterOption sets router/gateway option (Option 3) for a scope
func (c *PowerShellClient) ConfigureRouterOption(scopeID string, router string) error {
	psCmd := fmt.Sprintf(`
		Set-DhcpServerv4OptionValue -ComputerName %s -ScopeId %s -OptionId 3 -Value %s
	`, c.serverName, scopeID, router)

	cmd := exec.Command("powershell", "-Command", psCmd)
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("failed to set router option for scope %s: %w", scopeID, err)
	}

	return nil
}

// Close cleans up resources
func (c *PowerShellClient) Close() error {
	// No cleanup needed for PowerShell client
	return nil
}

// Helper functions

func getStringField(m map[string]interface{}, key string) string {
	if val, ok := m[key]; ok {
		if str, ok := val.(string); ok {
			return str
		}
	}
	return ""
}

// formatMAC normalizes MAC address format to XX:XX:XX:XX:XX:XX
func formatMAC(mac string) string {
	// Remove common separators
	mac = strings.ReplaceAll(mac, "-", "")
	mac = strings.ReplaceAll(mac, ":", "")
	mac = strings.ToUpper(mac)

	if len(mac) != 12 {
		return mac
	}

	// Insert colons
	return fmt.Sprintf("%s:%s:%s:%s:%s:%s",
		mac[0:2], mac[2:4], mac[4:6], mac[6:8], mac[8:10], mac[10:12])
}

// parseLeaseState converts Windows DHCP AddressState to LeaseState
func parseLeaseState(state string) LeaseState {
	switch strings.ToLower(state) {
	case "active":
		return LeaseStateActive
	case "inactive":
		return LeaseStateInactive
	case "reserved":
		return LeaseStateReserved
	case "expired":
		return LeaseStateExpired
	default:
		return LeaseStateActive
	}
}

// parseDuration parses PowerShell duration format "8.00:00:00" (8 days)
func parseDuration(s string) (time.Duration, error) {
	parts := strings.Split(s, ".")
	if len(parts) != 2 {
		return 0, fmt.Errorf("invalid duration format: %s", s)
	}

	days := 0
	fmt.Sscanf(parts[0], "%d", &days)

	timeParts := strings.Split(parts[1], ":")
	if len(timeParts) != 3 {
		return 0, fmt.Errorf("invalid time format: %s", parts[1])
	}

	hours, minutes, seconds := 0, 0, 0
	fmt.Sscanf(timeParts[0], "%d", &hours)
	fmt.Sscanf(timeParts[1], "%d", &minutes)
	fmt.Sscanf(timeParts[2], "%d", &seconds)

	totalDuration := time.Duration(days)*24*time.Hour +
		time.Duration(hours)*time.Hour +
		time.Duration(minutes)*time.Minute +
		time.Duration(seconds)*time.Second

	return totalDuration, nil
}
