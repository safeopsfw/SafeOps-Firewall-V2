// Package filtering implements domain blocking and allowlisting.
package filtering

import (
	"context"
	"database/sql"
	"log"
	"strings"
	"sync"
	"time"
)

// ============================================================================
// Domain Filter
// ============================================================================

// Filter manages domain blocking and allowlisting
type Filter struct {
	db        *sql.DB
	blocklist map[string]*BlockEntry
	allowlist map[string]bool
	mu        sync.RWMutex
	enabled   bool
}

// BlockEntry represents a blocked domain
type BlockEntry struct {
	Domain   string
	Reason   string
	Category string
	Source   string
	AddedAt  time.Time
}

// NewFilter creates a new domain filter
func NewFilter(db *sql.DB) *Filter {
	f := &Filter{
		db:        db,
		blocklist: make(map[string]*BlockEntry),
		allowlist: make(map[string]bool),
		enabled:   true,
	}
	return f
}

// ============================================================================
// Filtering Operations
// ============================================================================

// IsBlocked checks if a domain is blocked
func (f *Filter) IsBlocked(domain string) (bool, string) {
	if !f.enabled {
		return false, ""
	}

	domain = strings.ToLower(strings.TrimSuffix(domain, "."))

	f.mu.RLock()
	defer f.mu.RUnlock()

	// Check exact match
	if entry, ok := f.blocklist[domain]; ok {
		return true, entry.Reason
	}

	// Check wildcard matches (parent domains)
	parts := strings.Split(domain, ".")
	for i := 1; i < len(parts); i++ {
		parent := strings.Join(parts[i:], ".")
		if entry, ok := f.blocklist[parent]; ok {
			return true, entry.Reason
		}
	}

	return false, ""
}

// IsAllowed checks if a domain is explicitly allowed
func (f *Filter) IsAllowed(domain string) bool {
	domain = strings.ToLower(strings.TrimSuffix(domain, "."))

	f.mu.RLock()
	defer f.mu.RUnlock()

	// Check exact match
	if f.allowlist[domain] {
		return true
	}

	// Check parent domains
	parts := strings.Split(domain, ".")
	for i := 1; i < len(parts); i++ {
		parent := strings.Join(parts[i:], ".")
		if f.allowlist[parent] {
			return true
		}
	}

	return false
}

// ============================================================================
// List Management
// ============================================================================

// AddBlock adds a domain to the blocklist
func (f *Filter) AddBlock(domain, reason, category, source string) {
	domain = strings.ToLower(strings.TrimSuffix(domain, "."))

	f.mu.Lock()
	f.blocklist[domain] = &BlockEntry{
		Domain:   domain,
		Reason:   reason,
		Category: category,
		Source:   source,
		AddedAt:  time.Now(),
	}
	f.mu.Unlock()

	// Persist to database
	if f.db != nil {
		ctx := context.Background()
		_, err := f.db.ExecContext(ctx,
			`INSERT INTO dns_blocklist (domain, reason, category, source)
			 VALUES ($1, $2, $3, $4)
			 ON CONFLICT (domain) DO UPDATE SET reason=$2, category=$3, source=$4`,
			domain, reason, category, source,
		)
		if err != nil {
			log.Printf("Failed to persist block: %v", err)
		}
	}
}

// RemoveBlock removes a domain from the blocklist
func (f *Filter) RemoveBlock(domain string) {
	domain = strings.ToLower(strings.TrimSuffix(domain, "."))

	f.mu.Lock()
	delete(f.blocklist, domain)
	f.mu.Unlock()

	// Remove from database
	if f.db != nil {
		ctx := context.Background()
		f.db.ExecContext(ctx, `DELETE FROM dns_blocklist WHERE domain = $1`, domain)
	}
}

// AddAllow adds a domain to the allowlist
func (f *Filter) AddAllow(domain string) {
	domain = strings.ToLower(strings.TrimSuffix(domain, "."))

	f.mu.Lock()
	f.allowlist[domain] = true
	f.mu.Unlock()

	// Persist to database
	if f.db != nil {
		ctx := context.Background()
		f.db.ExecContext(ctx,
			`INSERT INTO dns_allowlist (domain) VALUES ($1) ON CONFLICT DO NOTHING`,
			domain,
		)
	}
}

// RemoveAllow removes a domain from the allowlist
func (f *Filter) RemoveAllow(domain string) {
	domain = strings.ToLower(strings.TrimSuffix(domain, "."))

	f.mu.Lock()
	delete(f.allowlist, domain)
	f.mu.Unlock()

	if f.db != nil {
		ctx := context.Background()
		f.db.ExecContext(ctx, `DELETE FROM dns_allowlist WHERE domain = $1`, domain)
	}
}

// ============================================================================
// Database Loading
// ============================================================================

// LoadFromDatabase loads blocklist and allowlist from database
func (f *Filter) LoadFromDatabase(ctx context.Context) error {
	if f.db == nil {
		return nil
	}

	// Load blocklist
	rows, err := f.db.QueryContext(ctx,
		`SELECT domain, reason, category, source FROM dns_blocklist WHERE is_active = true`,
	)
	if err != nil {
		return err
	}
	defer rows.Close()

	f.mu.Lock()
	for rows.Next() {
		var domain, reason, category, source string
		if err := rows.Scan(&domain, &reason, &category, &source); err != nil {
			continue
		}
		f.blocklist[domain] = &BlockEntry{
			Domain:   domain,
			Reason:   reason,
			Category: category,
			Source:   source,
		}
	}
	f.mu.Unlock()

	// Load allowlist
	rows2, err := f.db.QueryContext(ctx,
		`SELECT domain FROM dns_allowlist WHERE is_active = true`,
	)
	if err != nil {
		return err
	}
	defer rows2.Close()

	f.mu.Lock()
	for rows2.Next() {
		var domain string
		if err := rows2.Scan(&domain); err != nil {
			continue
		}
		f.allowlist[domain] = true
	}
	f.mu.Unlock()

	log.Printf("Loaded %d blocked domains, %d allowed domains",
		len(f.blocklist), len(f.allowlist))
	return nil
}

// ============================================================================
// Statistics
// ============================================================================

// GetStats returns filter statistics
func (f *Filter) GetStats() (int, int) {
	f.mu.RLock()
	defer f.mu.RUnlock()
	return len(f.blocklist), len(f.allowlist)
}

// SetEnabled enables or disables filtering
func (f *Filter) SetEnabled(enabled bool) {
	f.enabled = enabled
}

// IsEnabled returns whether filtering is enabled
func (f *Filter) IsEnabled() bool {
	return f.enabled
}
