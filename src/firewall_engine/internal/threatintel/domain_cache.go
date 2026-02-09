package threatintel

import (
	"context"
	"database/sql"
	"fmt"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// DomainThreat holds threat data for a single malicious domain
type DomainThreat struct {
	ThreatScore int
	Category    string // phishing, malware, c2, spam, exploit_kit, scam, ransomware
	Confidence  int
	RootDomain  string
}

// DomainCache holds in-memory copy of the domains table
// for O(1) lookups on the packet-processing hot path.
type DomainCache struct {
	domains     sync.Map // domain_string -> *DomainThreat (exact match)
	rootDomains sync.Map // root_domain -> *DomainThreat (subdomain matching)
	count       atomic.Int64
	lastRefresh atomic.Value // stores time.Time
}

// NewDomainCache creates an empty domain cache
func NewDomainCache() *DomainCache {
	c := &DomainCache{}
	c.lastRefresh.Store(time.Time{})
	return c
}

// Load bulk-loads malicious domains from the domains table
func (c *DomainCache) Load(ctx context.Context, db *sql.DB) error {
	query := `SELECT domain, COALESCE(root_domain, ''), threat_score, COALESCE(category, 'unknown'), confidence
		FROM domains
		WHERE is_malicious = true
		AND status = 'active'
		AND (expires_at IS NULL OR expires_at > NOW())`

	rows, err := db.QueryContext(ctx, query)
	if err != nil {
		return fmt.Errorf("domains query failed: %w", err)
	}
	defer rows.Close()

	// Clear existing
	c.domains.Range(func(key, _ interface{}) bool {
		c.domains.Delete(key)
		return true
	})
	c.rootDomains.Range(func(key, _ interface{}) bool {
		c.rootDomains.Delete(key)
		return true
	})

	var loaded int64
	for rows.Next() {
		var domain, rootDomain, category string
		var score, confidence int

		if err := rows.Scan(&domain, &rootDomain, &score, &category, &confidence); err != nil {
			continue
		}

		threat := &DomainThreat{
			ThreatScore: score,
			Category:    category,
			Confidence:  confidence,
			RootDomain:  rootDomain,
		}

		// Store exact domain match
		c.domains.Store(strings.ToLower(domain), threat)

		// Store root domain for subdomain matching
		if rootDomain != "" {
			c.rootDomains.Store(strings.ToLower(rootDomain), threat)
		}

		loaded++
	}

	if err := rows.Err(); err != nil {
		return fmt.Errorf("domains scan error: %w", err)
	}

	c.count.Store(loaded)
	c.lastRefresh.Store(time.Now())
	return nil
}

// CheckDomain checks if a domain (or its root) is malicious. O(1) per check.
// Checks exact match first, then root domain match for subdomain blocking.
func (c *DomainCache) CheckDomain(domain string) (*DomainThreat, bool) {
	lower := strings.ToLower(domain)

	// Exact match
	if val, ok := c.domains.Load(lower); ok {
		return val.(*DomainThreat), true
	}

	// Root domain match (subdomain blocking)
	// e.g., "cdn.malware.com" → check "malware.com"
	if val, ok := c.rootDomains.Load(lower); ok {
		return val.(*DomainThreat), true
	}

	// Walk up the domain hierarchy
	parts := strings.SplitN(lower, ".", 2)
	for len(parts) == 2 && strings.Contains(parts[1], ".") {
		parent := parts[1]
		if val, ok := c.domains.Load(parent); ok {
			return val.(*DomainThreat), true
		}
		if val, ok := c.rootDomains.Load(parent); ok {
			return val.(*DomainThreat), true
		}
		parts = strings.SplitN(parent, ".", 2)
	}

	return nil, false
}

// Count returns the number of loaded malicious domains
func (c *DomainCache) Count() int64 {
	return c.count.Load()
}

// LastRefresh returns when the cache was last refreshed
func (c *DomainCache) LastRefresh() time.Time {
	return c.lastRefresh.Load().(time.Time)
}
