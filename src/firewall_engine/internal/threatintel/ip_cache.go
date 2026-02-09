package threatintel

import (
	"context"
	"database/sql"
	"fmt"
	"sync"
	"sync/atomic"
	"time"
)

// IPThreat holds threat data for a single malicious IP
type IPThreat struct {
	ThreatScore int
	AbuseType   string
	Confidence  int
}

// VPNInfo holds anonymizer/VPN data for a single IP
type VPNInfo struct {
	Provider    string
	ServiceType string // commercial_vpn, free_vpn, tor_exit, proxy
	RiskScore   int
	CountryCode string
}

// IPCache holds in-memory copies of ip_blacklist and vpn_ips tables
// for O(1) lookups on the packet-processing hot path. No DB queries per packet.
type IPCache struct {
	ips         sync.Map // ip_string -> *IPThreat
	vpnIPs      sync.Map // ip_string -> *VPNInfo
	count       atomic.Int64
	vpnCount    atomic.Int64
	lastRefresh atomic.Value // stores time.Time
}

// NewIPCache creates an empty IP cache
func NewIPCache() *IPCache {
	c := &IPCache{}
	c.lastRefresh.Store(time.Time{})
	return c
}

// Load bulk-loads malicious IPs from ip_blacklist table
func (c *IPCache) Load(ctx context.Context, db *sql.DB) error {
	query := `SELECT ip_address::text, threat_score, abuse_type, confidence
		FROM ip_blacklist
		WHERE is_malicious = true
		AND (expires_at IS NULL OR expires_at > NOW())`

	rows, err := db.QueryContext(ctx, query)
	if err != nil {
		return fmt.Errorf("ip_blacklist query failed: %w", err)
	}
	defer rows.Close()

	// Clear existing entries
	c.ips.Range(func(key, _ interface{}) bool {
		c.ips.Delete(key)
		return true
	})

	var loaded int64
	for rows.Next() {
		var ip, abuseType string
		var score, confidence int

		if err := rows.Scan(&ip, &score, &abuseType, &confidence); err != nil {
			continue
		}

		c.ips.Store(ip, &IPThreat{
			ThreatScore: score,
			AbuseType:   abuseType,
			Confidence:  confidence,
		})
		loaded++
	}

	if err := rows.Err(); err != nil {
		return fmt.Errorf("ip_blacklist scan error: %w", err)
	}

	c.count.Store(loaded)
	c.lastRefresh.Store(time.Now())
	return nil
}

// LoadVPNIPs bulk-loads VPN/anonymizer IPs from vpn_ips table
func (c *IPCache) LoadVPNIPs(ctx context.Context, db *sql.DB) error {
	query := `SELECT ip_address::text, vpn_provider, service_type, risk_score, COALESCE(country_code, '')
		FROM vpn_ips
		WHERE is_active = true`

	rows, err := db.QueryContext(ctx, query)
	if err != nil {
		return fmt.Errorf("vpn_ips query failed: %w", err)
	}
	defer rows.Close()

	c.vpnIPs.Range(func(key, _ interface{}) bool {
		c.vpnIPs.Delete(key)
		return true
	})

	var loaded int64
	for rows.Next() {
		var ip, provider, serviceType, country string
		var riskScore int

		if err := rows.Scan(&ip, &provider, &serviceType, &riskScore, &country); err != nil {
			continue
		}

		c.vpnIPs.Store(ip, &VPNInfo{
			Provider:    provider,
			ServiceType: serviceType,
			RiskScore:   riskScore,
			CountryCode: country,
		})
		loaded++
	}

	if err := rows.Err(); err != nil {
		return fmt.Errorf("vpn_ips scan error: %w", err)
	}

	c.vpnCount.Store(loaded)
	return nil
}

// CheckIP looks up an IP in the malicious IP cache. O(1) via sync.Map.
func (c *IPCache) CheckIP(ip string) (*IPThreat, bool) {
	val, ok := c.ips.Load(ip)
	if !ok {
		return nil, false
	}
	return val.(*IPThreat), true
}

// CheckVPN looks up an IP in the VPN/anonymizer cache. O(1) via sync.Map.
func (c *IPCache) CheckVPN(ip string) (*VPNInfo, bool) {
	val, ok := c.vpnIPs.Load(ip)
	if !ok {
		return nil, false
	}
	return val.(*VPNInfo), true
}

// IsAnonymizer returns true if the IP is a VPN, Tor, or proxy exit
func (c *IPCache) IsAnonymizer(ip string) bool {
	_, ok := c.vpnIPs.Load(ip)
	return ok
}

// Count returns the number of loaded malicious IPs
func (c *IPCache) Count() int64 {
	return c.count.Load()
}

// VPNCount returns the number of loaded VPN/anonymizer IPs
func (c *IPCache) VPNCount() int64 {
	return c.vpnCount.Load()
}

// LastRefresh returns when the cache was last refreshed
func (c *IPCache) LastRefresh() time.Time {
	return c.lastRefresh.Load().(time.Time)
}
