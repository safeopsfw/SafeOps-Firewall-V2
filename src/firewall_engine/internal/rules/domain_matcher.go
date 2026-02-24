// Package rules provides rule matching and management for the firewall engine.
package rules

import (
	"os"
	"strings"
	"sync"

	"github.com/BurntSushi/toml"
)

// ============================================================================
// Domain Matcher - Wildcard Domain Matching
// ============================================================================

// MatchDomain checks if a domain matches a pattern.
// Supports:
// - Exact match: facebook.com matches facebook.com
// - Wildcard prefix: *.facebook.com matches www.facebook.com, api.facebook.com
// - Wildcard at root: facebook.com also matches as *.facebook.com
func MatchDomain(pattern, domain string) bool {
	if pattern == "" {
		return true // Empty pattern matches any
	}
	if domain == "" {
		return false // Empty domain doesn't match non-empty pattern
	}

	pattern = strings.ToLower(strings.TrimSpace(pattern))
	domain = strings.ToLower(strings.TrimSpace(domain))

	// Exact match
	if pattern == domain {
		return true
	}

	// Wildcard prefix: *.example.com
	if strings.HasPrefix(pattern, "*.") {
		suffix := strings.TrimPrefix(pattern, "*")
		baseDomain := strings.TrimPrefix(suffix, ".")

		// Check if domain ends with the suffix
		if strings.HasSuffix(domain, suffix) {
			return true
		}

		// Also match the base domain itself
		if domain == baseDomain {
			return true
		}
	}

	// Wildcard suffix: example.*
	if strings.HasSuffix(pattern, ".*") {
		prefix := strings.TrimSuffix(pattern, "*")
		if strings.HasPrefix(domain, prefix) {
			return true
		}
	}

	return false
}

// MatchDomainList checks if a domain matches any pattern in a list.
func MatchDomainList(patterns []string, domain string) bool {
	for _, pattern := range patterns {
		if MatchDomain(pattern, domain) {
			return true
		}
	}
	return false
}

// ============================================================================
// Domain Pattern Helpers
// ============================================================================

// IsWildcardPattern checks if a pattern contains wildcards.
func IsWildcardPattern(pattern string) bool {
	return strings.Contains(pattern, "*")
}

// GetDomainSuffix extracts the suffix from a wildcard pattern.
// e.g., *.facebook.com -> .facebook.com
func GetDomainSuffix(pattern string) string {
	if strings.HasPrefix(pattern, "*.") {
		return strings.TrimPrefix(pattern, "*")
	}
	return ""
}

// GetBaseDomain extracts the base domain from a pattern.
// e.g., *.facebook.com -> facebook.com
func GetBaseDomain(pattern string) string {
	if strings.HasPrefix(pattern, "*.") {
		return strings.TrimPrefix(pattern, "*.")
	}
	return pattern
}

// NormalizeDomain normalizes a domain for matching.
func NormalizeDomain(domain string) string {
	domain = strings.ToLower(strings.TrimSpace(domain))
	// Remove trailing dot if present
	domain = strings.TrimSuffix(domain, ".")
	return domain
}

// ============================================================================
// Domain Categories — loaded from categories.toml at runtime
// ============================================================================

// categoryEntry is used for TOML parsing of each category section.
type categoryEntry struct {
	Patterns []string `toml:"patterns"`
}

// categoryStore holds the loaded category patterns, protected by RWMutex.
var (
	categoryPatterns   = make(map[string][]string)
	categoryMu         sync.RWMutex
	categoriesFilePath string // set by LoadCategoriesFromFile
)

// builtinCategories is the minimal fallback used ONLY if no categories.toml exists.
var builtinCategories = map[string][]string{
	"social_media": {"*.facebook.com", "*.twitter.com", "*.x.com", "*.instagram.com", "*.tiktok.com", "*.linkedin.com", "*.snapchat.com", "*.pinterest.com"},
	"streaming":    {"*.netflix.com", "*.youtube.com", "*.twitch.tv", "*.hulu.com", "*.disneyplus.com", "*.primevideo.com", "*.spotify.com"},
	"gaming":       {"*.steampowered.com", "*.epicgames.com", "*.ea.com", "*.riotgames.com", "*.blizzard.com"},
	"ads":          {"*.doubleclick.net", "*.googlesyndication.com", "*.googleadservices.com", "*.facebook.net", "*.adnxs.com", "*.adsrvr.org"},
	"trackers":     {"*.google-analytics.com", "*.analytics.google.com", "*.mixpanel.com", "*.segment.io", "*.hotjar.com"},
}

// LoadCategoriesFromFile loads category patterns from a TOML file.
// Call this at startup from main.go. If the file doesn't exist, builtin
// fallback patterns are used. Hot-reload calls ReloadCategories().
func LoadCategoriesFromFile(path string) error {
	categoriesFilePath = path
	return loadCategoriesFile(path)
}

// ReloadCategories reloads category patterns from the previously configured file.
// Called by hot-reload watcher when categories.toml changes.
func ReloadCategories() error {
	if categoriesFilePath == "" {
		return nil
	}
	return loadCategoriesFile(categoriesFilePath)
}

// loadCategoriesFile parses a TOML file into the category store.
func loadCategoriesFile(path string) error {
	if _, err := os.Stat(path); os.IsNotExist(err) {
		// File doesn't exist — use builtin fallback
		categoryMu.Lock()
		categoryPatterns = builtinCategories
		categoryMu.Unlock()
		return nil
	}

	// Parse TOML: each top-level key is a category name with a "patterns" array
	var raw map[string]categoryEntry
	if _, err := toml.DecodeFile(path, &raw); err != nil {
		return err
	}

	newPatterns := make(map[string][]string, len(raw))
	for cat, entry := range raw {
		cat = strings.ToLower(strings.TrimSpace(cat))
		if len(entry.Patterns) > 0 {
			newPatterns[cat] = entry.Patterns
		}
	}

	categoryMu.Lock()
	categoryPatterns = newPatterns
	categoryMu.Unlock()
	return nil
}

// GetCategoryPatterns returns patterns for a domain category.
// Thread-safe: reads from the dynamically loaded category store.
func GetCategoryPatterns(category string) []string {
	categoryMu.RLock()
	defer categoryMu.RUnlock()
	if patterns, ok := categoryPatterns[strings.ToLower(category)]; ok {
		return patterns
	}
	return nil
}

// GetAllCategories returns all loaded category names.
func GetAllCategories() []string {
	categoryMu.RLock()
	defer categoryMu.RUnlock()
	cats := make([]string, 0, len(categoryPatterns))
	for cat := range categoryPatterns {
		cats = append(cats, cat)
	}
	return cats
}

// MatchCategory checks if a domain matches any pattern in a category.
func MatchCategory(category, domain string) bool {
	patterns := GetCategoryPatterns(category)
	return MatchDomainList(patterns, domain)
}

// ============================================================================
// Advanced Domain Matching
// ============================================================================

// DomainMatcher provides optimized domain matching with caching.
type DomainMatcher struct {
	// Exact domain lookup
	exactDomains map[string]bool

	// Wildcard suffixes for fast suffix matching
	wildcardSuffixes []string

	// Patterns for fallback
	patterns []string
}

// NewDomainMatcher creates a new domain matcher from patterns.
func NewDomainMatcher(patterns []string) *DomainMatcher {
	dm := &DomainMatcher{
		exactDomains:     make(map[string]bool),
		wildcardSuffixes: make([]string, 0),
		patterns:         patterns,
	}

	for _, pattern := range patterns {
		pattern = strings.ToLower(strings.TrimSpace(pattern))
		if pattern == "" {
			continue
		}

		if strings.HasPrefix(pattern, "*.") {
			// Wildcard pattern - extract suffix
			suffix := strings.TrimPrefix(pattern, "*")
			dm.wildcardSuffixes = append(dm.wildcardSuffixes, suffix)
			// Also add base domain for exact match
			baseDomain := strings.TrimPrefix(suffix, ".")
			dm.exactDomains[baseDomain] = true
		} else {
			// Exact pattern
			dm.exactDomains[pattern] = true
		}
	}

	return dm
}

// Match checks if a domain matches any pattern.
func (dm *DomainMatcher) Match(domain string) bool {
	domain = NormalizeDomain(domain)
	if domain == "" {
		return false
	}

	// Check exact match first (O(1))
	if dm.exactDomains[domain] {
		return true
	}

	// Check wildcard suffixes
	for _, suffix := range dm.wildcardSuffixes {
		if strings.HasSuffix(domain, suffix) {
			return true
		}
	}

	return false
}

// AddPattern adds a new pattern to the matcher.
func (dm *DomainMatcher) AddPattern(pattern string) {
	pattern = strings.ToLower(strings.TrimSpace(pattern))
	if pattern == "" {
		return
	}

	dm.patterns = append(dm.patterns, pattern)

	if strings.HasPrefix(pattern, "*.") {
		suffix := strings.TrimPrefix(pattern, "*")
		dm.wildcardSuffixes = append(dm.wildcardSuffixes, suffix)
		baseDomain := strings.TrimPrefix(suffix, ".")
		dm.exactDomains[baseDomain] = true
	} else {
		dm.exactDomains[pattern] = true
	}
}

// Count returns the number of patterns.
func (dm *DomainMatcher) Count() int {
	return len(dm.patterns)
}

// GetExactDomains returns all exact domain entries (no wildcards).
// Used by BlocklistSync to push domains to SafeOps Engine.
func (dm *DomainMatcher) GetExactDomains() []string {
	domains := make([]string, 0, len(dm.exactDomains))
	for d := range dm.exactDomains {
		domains = append(domains, d)
	}
	return domains
}
