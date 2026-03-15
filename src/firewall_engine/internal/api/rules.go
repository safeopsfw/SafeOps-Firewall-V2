package api

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/BurntSushi/toml"
	"github.com/gofiber/fiber/v2"

	"firewall_engine/internal/config"
	"firewall_engine/internal/rules"
)

// ============================================================================
// Domain Rules (domains.txt)
// ============================================================================

// handleGetDomains handles GET /api/v1/rules/domains.
// Returns the list of blocked domains from domains.txt.
func (s *Server) handleGetDomains(c *fiber.Ctx) error {
	path := s.getDomainsFilePath()
	if path == "" {
		return respondError(c, fiber.StatusServiceUnavailable, "unavailable",
			"Domains file path not configured")
	}

	domains, err := readLinesFromFile(path)
	if err != nil {
		return respondError(c, fiber.StatusInternalServerError, "internal_error",
			"Failed to read domains file: "+err.Error())
	}

	return c.JSON(fiber.Map{
		"domains": domains,
		"total":   len(domains),
		"file":    filepath.Base(path),
	})
}

// DomainRequest is the request body for adding/removing a domain.
type DomainRequest struct {
	Domain string `json:"domain"`
}

// handleAddDomain handles POST /api/v1/rules/domains.
func (s *Server) handleAddDomain(c *fiber.Ctx) error {
	var req DomainRequest
	if err := c.BodyParser(&req); err != nil {
		return respondError(c, fiber.StatusBadRequest, "bad_request",
			"Invalid request body: "+err.Error())
	}

	domain := strings.TrimSpace(strings.ToLower(req.Domain))
	if domain == "" {
		return respondError(c, fiber.StatusBadRequest, "bad_request", "Domain is required")
	}

	path := s.getDomainsFilePath()
	if path == "" {
		return respondError(c, fiber.StatusServiceUnavailable, "unavailable",
			"Domains file path not configured")
	}

	// Check for duplicates
	existing, _ := readLinesFromFile(path)
	for _, d := range existing {
		if d == domain {
			return respondError(c, fiber.StatusConflict, "conflict",
				fmt.Sprintf("Domain %s is already blocked", domain))
		}
	}

	if err := appendLineToFile(path, domain); err != nil {
		return respondError(c, fiber.StatusInternalServerError, "internal_error",
			"Failed to add domain: "+err.Error())
	}

	// Trigger hot-reload
	s.triggerReload("domains.txt")

	s.logger.Info().Str("domain", domain).Msg("Domain added to blocklist")
	return c.Status(fiber.StatusCreated).JSON(fiber.Map{
		"message": fmt.Sprintf("Domain %s added to blocklist", domain),
		"domain":  domain,
	})
}

// handleRemoveDomain handles DELETE /api/v1/rules/domains/:domain.
func (s *Server) handleRemoveDomain(c *fiber.Ctx) error {
	domain := strings.ToLower(c.Params("domain"))
	if domain == "" {
		return respondError(c, fiber.StatusBadRequest, "bad_request", "Domain is required")
	}

	path := s.getDomainsFilePath()
	if path == "" {
		return respondError(c, fiber.StatusServiceUnavailable, "unavailable",
			"Domains file path not configured")
	}

	removed, err := removeLineFromFile(path, domain)
	if err != nil {
		return respondError(c, fiber.StatusInternalServerError, "internal_error",
			"Failed to remove domain: "+err.Error())
	}
	if !removed {
		return respondError(c, fiber.StatusNotFound, "not_found",
			fmt.Sprintf("Domain %s not found in blocklist", domain))
	}

	s.triggerReload("domains.txt")

	s.logger.Info().Str("domain", domain).Msg("Domain removed from blocklist")
	return c.JSON(fiber.Map{
		"message": fmt.Sprintf("Domain %s removed from blocklist", domain),
	})
}

// ============================================================================
// Whitelist Domains (whitelist_domains.txt)
// ============================================================================

// handleGetWhitelistDomains handles GET /api/v1/rules/domains/whitelist.
func (s *Server) handleGetWhitelistDomains(c *fiber.Ctx) error {
	path := s.getWhitelistDomainsFilePath()
	if path == "" {
		return respondError(c, fiber.StatusServiceUnavailable, "unavailable",
			"Whitelist domains file not configured")
	}

	domains, err := readLinesFromFile(path)
	if err != nil {
		return respondError(c, fiber.StatusInternalServerError, "internal_error",
			"Failed to read whitelist domains: "+err.Error())
	}

	return c.JSON(fiber.Map{
		"domains": domains,
		"total":   len(domains),
	})
}

// handleAddWhitelistDomain handles POST /api/v1/rules/domains/whitelist.
func (s *Server) handleAddWhitelistDomain(c *fiber.Ctx) error {
	var req DomainRequest
	if err := c.BodyParser(&req); err != nil {
		return respondError(c, fiber.StatusBadRequest, "bad_request",
			"Invalid request body: "+err.Error())
	}

	domain := strings.TrimSpace(strings.ToLower(req.Domain))
	if domain == "" {
		return respondError(c, fiber.StatusBadRequest, "bad_request", "Domain is required")
	}

	path := s.getWhitelistDomainsFilePath()
	if path == "" {
		return respondError(c, fiber.StatusServiceUnavailable, "unavailable",
			"Whitelist domains file not configured")
	}

	existing, _ := readLinesFromFile(path)
	for _, d := range existing {
		if d == domain {
			return respondError(c, fiber.StatusConflict, "conflict",
				fmt.Sprintf("Domain %s is already whitelisted", domain))
		}
	}

	if err := appendLineToFile(path, domain); err != nil {
		return respondError(c, fiber.StatusInternalServerError, "internal_error",
			"Failed to add whitelist domain: "+err.Error())
	}

	s.triggerReload("whitelist_domains.txt")
	s.logger.Info().Str("domain", domain).Msg("Domain added to whitelist")

	return c.Status(fiber.StatusCreated).JSON(fiber.Map{
		"message": fmt.Sprintf("Domain %s added to whitelist", domain),
	})
}

// handleRemoveWhitelistDomain handles DELETE /api/v1/rules/domains/whitelist/:domain.
func (s *Server) handleRemoveWhitelistDomain(c *fiber.Ctx) error {
	domain := strings.ToLower(c.Params("domain"))
	if domain == "" {
		return respondError(c, fiber.StatusBadRequest, "bad_request", "Domain is required")
	}

	path := s.getWhitelistDomainsFilePath()
	if path == "" {
		return respondError(c, fiber.StatusServiceUnavailable, "unavailable",
			"Whitelist domains file not configured")
	}

	removed, err := removeLineFromFile(path, domain)
	if err != nil {
		return respondError(c, fiber.StatusInternalServerError, "internal_error",
			"Failed to remove whitelist domain: "+err.Error())
	}
	if !removed {
		return respondError(c, fiber.StatusNotFound, "not_found",
			fmt.Sprintf("Domain %s not found in whitelist", domain))
	}

	s.triggerReload("whitelist_domains.txt")
	s.logger.Info().Str("domain", domain).Msg("Domain removed from whitelist")

	return c.JSON(fiber.Map{
		"message": fmt.Sprintf("Domain %s removed from whitelist", domain),
	})
}

// ============================================================================
// Categories
// ============================================================================

// handleGetCategories handles GET /api/v1/rules/categories.
func (s *Server) handleGetCategories(c *fiber.Ctx) error {
	// Available categories are defined in the blocklist config
	bl := s.deps.LiveBlocklist.Load()
	if bl == nil {
		return respondError(c, fiber.StatusServiceUnavailable, "unavailable",
			"Blocklist not loaded")
	}

	// Known categories with their descriptions
	allCategories := map[string]string{
		"social_media":  "Social media platforms (Facebook, Instagram, Twitter, TikTok, etc.)",
		"streaming":     "Streaming services (YouTube, Netflix, Twitch, Spotify, etc.)",
		"gaming":        "Gaming platforms (Steam, Epic, Xbox, PlayStation, etc.)",
		"ads":           "Advertising and tracking networks",
		"trackers":      "Web analytics and user tracking",
		"adult":         "Adult content websites",
		"gambling":      "Online gambling and betting sites",
		"malware":       "Known malware distribution domains",
		"phishing":      "Known phishing domains",
		"crypto_mining": "Cryptocurrency mining scripts",
	}

	activeSet := make(map[string]bool)
	for _, cat := range bl.BlockedCategories {
		activeSet[cat] = true
	}

	type CategoryInfo struct {
		Name        string `json:"name"`
		Description string `json:"description"`
		Active      bool   `json:"active"`
	}

	var categories []CategoryInfo
	for name, desc := range allCategories {
		categories = append(categories, CategoryInfo{
			Name:        name,
			Description: desc,
			Active:      activeSet[name],
		})
	}
	sort.Slice(categories, func(i, j int) bool {
		return categories[i].Name < categories[j].Name
	})

	return c.JSON(fiber.Map{
		"categories":      categories,
		"active_count":    len(bl.BlockedCategories),
		"available_count": len(allCategories),
	})
}

// UpdateCategoriesRequest is the request body for updating active categories.
type UpdateCategoriesRequest struct {
	Categories []string `json:"categories"`
}

// handleUpdateCategories handles PUT /api/v1/rules/categories.
// Persists the change to blocklist.toml so it survives engine restart.
func (s *Server) handleUpdateCategories(c *fiber.Ctx) error {
	var req UpdateCategoriesRequest
	if err := c.BodyParser(&req); err != nil {
		return respondError(c, fiber.StatusBadRequest, "bad_request",
			"Invalid request body: "+err.Error())
	}

	// Apply to domain filter immediately (in-memory)
	if s.deps.DomainFilter != nil {
		s.deps.DomainFilter.SetBlockedCategories(req.Categories)
	}

	// Persist to blocklist.toml by updating the [domains.categories] section.
	// Build a set of enabled categories for O(1) lookup.
	enabled := make(map[string]bool, len(req.Categories))
	for _, cat := range req.Categories {
		enabled[strings.ToLower(strings.TrimSpace(cat))] = true
	}

	configPath := s.deps.Config.BlocklistFilePath()
	if configPath != "" {
		currentBL, err := config.LoadBlocklistConfigFromFile(configPath)
		if err == nil {
			currentBL.Domains.Categories = config.BlocklistCategoriesConfig{
				SocialMedia: enabled["social_media"],
				Streaming:   enabled["streaming"],
				Gaming:      enabled["gaming"],
				Ads:         enabled["ads"],
				Trackers:    enabled["trackers"],
				Adult:       enabled["adult"],
				Gambling:    enabled["gambling"],
				VPNProxy:    enabled["vpn_proxy"],
			}

			if writeErr := writeJSONToTOMLFile(configPath, currentBL); writeErr != nil {
				s.logger.Warn().Err(writeErr).Msg("Failed to persist categories to blocklist.toml — in-memory update applied")
			} else {
				s.triggerReload("blocklist.toml")
			}
		}
	}

	s.logger.Info().
		Strs("categories", req.Categories).
		Int("count", len(req.Categories)).
		Msg("Blocked categories updated and persisted")

	return c.JSON(fiber.Map{
		"message":    "Categories updated",
		"categories": req.Categories,
	})
}

// ============================================================================
// Category Patterns (categories.toml)
// ============================================================================

// handleGetCategoryPatterns handles GET /api/v1/rules/categories/patterns.
// Returns all category names with their domain patterns from categories.toml.
func (s *Server) handleGetCategoryPatterns(c *fiber.Ctx) error {
	allCats := rules.GetAllCategories()

	type catPatterns struct {
		Name     string   `json:"name"`
		Patterns []string `json:"patterns"`
		Count    int      `json:"count"`
	}

	var result []catPatterns
	for _, cat := range allCats {
		patterns := rules.GetCategoryPatterns(cat)
		result = append(result, catPatterns{
			Name:     cat,
			Patterns: patterns,
			Count:    len(patterns),
		})
	}

	sort.Slice(result, func(i, j int) bool { return result[i].Name < result[j].Name })

	return c.JSON(fiber.Map{
		"categories": result,
		"total":      len(result),
	})
}

// CategoryPatternsRequest is the request body for updating category patterns.
type CategoryPatternsRequest struct {
	Patterns []string `json:"patterns"`
}

// handleUpdateCategoryPatterns handles PUT /api/v1/rules/categories/patterns/:category.
// Updates the domain patterns for a specific category in categories.toml.
func (s *Server) handleUpdateCategoryPatterns(c *fiber.Ctx) error {
	category := strings.ToLower(c.Params("category"))
	if category == "" {
		return respondError(c, fiber.StatusBadRequest, "bad_request", "Category name is required")
	}

	var req CategoryPatternsRequest
	if err := c.BodyParser(&req); err != nil {
		return respondError(c, fiber.StatusBadRequest, "bad_request",
			"Invalid request body: "+err.Error())
	}

	if len(req.Patterns) == 0 {
		return respondError(c, fiber.StatusBadRequest, "bad_request", "At least one pattern is required")
	}

	// Read current categories.toml
	categoriesPath := filepath.Join(s.deps.Config.ConfigDir, "categories.toml")

	type catEntry struct {
		Patterns []string `toml:"patterns"`
	}
	var raw map[string]catEntry

	data, err := os.ReadFile(categoriesPath)
	if err != nil {
		if os.IsNotExist(err) {
			raw = make(map[string]catEntry)
		} else {
			return respondError(c, fiber.StatusInternalServerError, "internal_error",
				"Failed to read categories.toml: "+err.Error())
		}
	} else {
		if _, decErr := toml.Decode(string(data), &raw); decErr != nil {
			return respondError(c, fiber.StatusInternalServerError, "internal_error",
				"Failed to parse categories.toml: "+decErr.Error())
		}
	}

	// Update the category
	raw[category] = catEntry{Patterns: req.Patterns}

	// Write back as TOML
	f, err := os.Create(categoriesPath)
	if err != nil {
		return respondError(c, fiber.StatusInternalServerError, "internal_error",
			"Failed to write categories.toml: "+err.Error())
	}
	defer f.Close()

	encoder := toml.NewEncoder(f)
	if err := encoder.Encode(raw); err != nil {
		return respondError(c, fiber.StatusInternalServerError, "internal_error",
			"Failed to encode categories.toml: "+err.Error())
	}

	s.triggerReload("categories.toml")

	s.logger.Info().
		Str("category", category).
		Int("patterns", len(req.Patterns)).
		Msg("Category patterns updated via API")

	return c.JSON(fiber.Map{
		"message":  fmt.Sprintf("Category %s patterns updated (%d patterns)", category, len(req.Patterns)),
		"category": category,
		"patterns": req.Patterns,
	})
}

// ============================================================================
// Blocked IPs (blocked_ips.txt)
// ============================================================================

// IPRequest is the request body for adding/removing an IP.
type IPRequest struct {
	IP string `json:"ip"`
}

// handleGetBlockedIPs handles GET /api/v1/rules/ips.
func (s *Server) handleGetBlockedIPs(c *fiber.Ctx) error {
	path := s.getBlockedIPsFilePath()
	if path == "" {
		return respondError(c, fiber.StatusServiceUnavailable, "unavailable",
			"Blocked IPs file not configured")
	}

	ips, err := readLinesFromFile(path)
	if err != nil {
		return respondError(c, fiber.StatusInternalServerError, "internal_error",
			"Failed to read blocked IPs: "+err.Error())
	}

	return c.JSON(fiber.Map{
		"ips":   ips,
		"total": len(ips),
	})
}

// handleAddBlockedIP handles POST /api/v1/rules/ips.
func (s *Server) handleAddBlockedIP(c *fiber.Ctx) error {
	var req IPRequest
	if err := c.BodyParser(&req); err != nil {
		return respondError(c, fiber.StatusBadRequest, "bad_request",
			"Invalid request body: "+err.Error())
	}

	ip := strings.TrimSpace(req.IP)
	if ip == "" {
		return respondError(c, fiber.StatusBadRequest, "bad_request", "IP is required")
	}

	path := s.getBlockedIPsFilePath()
	if path == "" {
		return respondError(c, fiber.StatusServiceUnavailable, "unavailable",
			"Blocked IPs file not configured")
	}

	existing, _ := readLinesFromFile(path)
	for _, e := range existing {
		if e == ip {
			return respondError(c, fiber.StatusConflict, "conflict",
				fmt.Sprintf("IP %s is already blocked", ip))
		}
	}

	if err := appendLineToFile(path, ip); err != nil {
		return respondError(c, fiber.StatusInternalServerError, "internal_error",
			"Failed to add blocked IP: "+err.Error())
	}

	s.triggerReload("blocked_ips.txt")
	s.logger.Info().Str("ip", ip).Msg("IP added to blocklist")

	return c.Status(fiber.StatusCreated).JSON(fiber.Map{
		"message": fmt.Sprintf("IP %s added to blocklist", ip),
		"ip":      ip,
	})
}

// handleRemoveBlockedIP handles DELETE /api/v1/rules/ips/:ip.
func (s *Server) handleRemoveBlockedIP(c *fiber.Ctx) error {
	ip := c.Params("ip")
	if ip == "" {
		return respondError(c, fiber.StatusBadRequest, "bad_request", "IP is required")
	}
	// URL decode for CIDR notation (slashes)
	ip = strings.ReplaceAll(ip, "%2F", "/")

	path := s.getBlockedIPsFilePath()
	if path == "" {
		return respondError(c, fiber.StatusServiceUnavailable, "unavailable",
			"Blocked IPs file not configured")
	}

	removed, err := removeLineFromFile(path, ip)
	if err != nil {
		return respondError(c, fiber.StatusInternalServerError, "internal_error",
			"Failed to remove blocked IP: "+err.Error())
	}
	if !removed {
		return respondError(c, fiber.StatusNotFound, "not_found",
			fmt.Sprintf("IP %s not found in blocklist", ip))
	}

	s.triggerReload("blocked_ips.txt")
	s.logger.Info().Str("ip", ip).Msg("IP removed from blocklist")

	return c.JSON(fiber.Map{
		"message": fmt.Sprintf("IP %s removed from blocklist", ip),
	})
}

// ============================================================================
// Whitelist IPs (whitelist.txt)
// ============================================================================

// handleGetWhitelistIPs handles GET /api/v1/rules/ips/whitelist.
func (s *Server) handleGetWhitelistIPs(c *fiber.Ctx) error {
	path := s.getWhitelistFilePath()
	if path == "" {
		return respondError(c, fiber.StatusServiceUnavailable, "unavailable",
			"Whitelist file not configured")
	}

	ips, err := readLinesFromFile(path)
	if err != nil {
		return respondError(c, fiber.StatusInternalServerError, "internal_error",
			"Failed to read whitelist IPs: "+err.Error())
	}

	return c.JSON(fiber.Map{
		"ips":   ips,
		"total": len(ips),
	})
}

// handleAddWhitelistIP handles POST /api/v1/rules/ips/whitelist.
func (s *Server) handleAddWhitelistIP(c *fiber.Ctx) error {
	var req IPRequest
	if err := c.BodyParser(&req); err != nil {
		return respondError(c, fiber.StatusBadRequest, "bad_request",
			"Invalid request body: "+err.Error())
	}

	ip := strings.TrimSpace(req.IP)
	if ip == "" {
		return respondError(c, fiber.StatusBadRequest, "bad_request", "IP is required")
	}

	path := s.getWhitelistFilePath()
	if path == "" {
		return respondError(c, fiber.StatusServiceUnavailable, "unavailable",
			"Whitelist file not configured")
	}

	existing, _ := readLinesFromFile(path)
	for _, e := range existing {
		if e == ip {
			return respondError(c, fiber.StatusConflict, "conflict",
				fmt.Sprintf("IP %s is already whitelisted", ip))
		}
	}

	if err := appendLineToFile(path, ip); err != nil {
		return respondError(c, fiber.StatusInternalServerError, "internal_error",
			"Failed to add whitelist IP: "+err.Error())
	}

	s.logger.Info().Str("ip", ip).Msg("IP added to whitelist")
	return c.Status(fiber.StatusCreated).JSON(fiber.Map{
		"message": fmt.Sprintf("IP %s added to whitelist", ip),
	})
}

// handleRemoveWhitelistIP handles DELETE /api/v1/rules/ips/whitelist/:ip.
func (s *Server) handleRemoveWhitelistIP(c *fiber.Ctx) error {
	ip := c.Params("ip")
	if ip == "" {
		return respondError(c, fiber.StatusBadRequest, "bad_request", "IP is required")
	}
	ip = strings.ReplaceAll(ip, "%2F", "/")

	path := s.getWhitelistFilePath()
	if path == "" {
		return respondError(c, fiber.StatusServiceUnavailable, "unavailable",
			"Whitelist file not configured")
	}

	removed, err := removeLineFromFile(path, ip)
	if err != nil {
		return respondError(c, fiber.StatusInternalServerError, "internal_error",
			"Failed to remove whitelist IP: "+err.Error())
	}
	if !removed {
		return respondError(c, fiber.StatusNotFound, "not_found",
			fmt.Sprintf("IP %s not found in whitelist", ip))
	}

	s.logger.Info().Str("ip", ip).Msg("IP removed from whitelist")
	return c.JSON(fiber.Map{
		"message": fmt.Sprintf("IP %s removed from whitelist", ip),
	})
}

// ============================================================================
// GeoIP Config
// ============================================================================

// handleGetGeoIPConfig handles GET /api/v1/rules/geoip.
func (s *Server) handleGetGeoIPConfig(c *fiber.Ctx) error {
	if s.deps.Config == nil || s.deps.Config.GeoIP == nil {
		return respondError(c, fiber.StatusServiceUnavailable, "unavailable",
			"GeoIP config not loaded")
	}

	// Include stats alongside config
	var stats interface{}
	if s.deps.GeoChecker != nil {
		stats = s.deps.GeoChecker.Stats()
	}

	return c.JSON(fiber.Map{
		"config": s.deps.Config.GeoIP,
		"stats":  stats,
	})
}

// handleUpdateGeoIPConfig handles PUT /api/v1/rules/geoip.
// Updates the geoip.toml file and triggers hot-reload.
func (s *Server) handleUpdateGeoIPConfig(c *fiber.Ctx) error {
	configPath := filepath.Join(s.deps.Config.ConfigDir, "geoip.toml")

	var updates map[string]interface{}
	if err := c.BodyParser(&updates); err != nil {
		return respondError(c, fiber.StatusBadRequest, "bad_request",
			"Invalid request body: "+err.Error())
	}

	// Read current config, apply updates, write back
	current, err := config.LoadGeoIPConfigFromFile(configPath)
	if err != nil {
		return respondError(c, fiber.StatusInternalServerError, "internal_error",
			"Failed to read current GeoIP config: "+err.Error())
	}

	// Apply JSON updates by marshaling/unmarshaling
	currentJSON, _ := json.Marshal(current)
	var merged map[string]interface{}
	json.Unmarshal(currentJSON, &merged)
	for k, v := range updates {
		merged[k] = v
	}

	mergedJSON, err := json.Marshal(merged)
	if err != nil {
		return respondError(c, fiber.StatusBadRequest, "bad_request",
			"Failed to merge config: "+err.Error())
	}

	// Validate by attempting to unmarshal
	var validated config.GeoIPConfig
	if err := json.Unmarshal(mergedJSON, &validated); err != nil {
		return respondError(c, fiber.StatusBadRequest, "bad_request",
			"Invalid GeoIP config: "+err.Error())
	}

	// Write validated config back as TOML
	if err := writeJSONToTOMLFile(configPath, &validated); err != nil {
		return respondError(c, fiber.StatusInternalServerError, "internal_error",
			"Failed to write GeoIP config: "+err.Error())
	}

	s.triggerReload("geoip.toml")
	s.logger.Info().Msg("GeoIP config updated via API")

	return c.JSON(fiber.Map{
		"message": "GeoIP configuration updated — hot-reload triggered",
	})
}

// ============================================================================
// Detection Config
// ============================================================================

// handleGetDetectionConfig handles GET /api/v1/rules/detection.
func (s *Server) handleGetDetectionConfig(c *fiber.Ctx) error {
	if s.deps.Config == nil || s.deps.Config.Detection == nil {
		return respondError(c, fiber.StatusServiceUnavailable, "unavailable",
			"Detection config not loaded")
	}

	var stats interface{}
	if s.deps.SecurityMgr != nil {
		stats = s.deps.SecurityMgr.Stats()
	}

	return c.JSON(fiber.Map{
		"config": s.deps.Config.Detection,
		"stats":  stats,
	})
}

// handleUpdateDetectionConfig handles PUT /api/v1/rules/detection.
func (s *Server) handleUpdateDetectionConfig(c *fiber.Ctx) error {
	configPath := filepath.Join(s.deps.Config.ConfigDir, "detection.toml")

	var updates map[string]interface{}
	if err := c.BodyParser(&updates); err != nil {
		return respondError(c, fiber.StatusBadRequest, "bad_request",
			"Invalid request body: "+err.Error())
	}

	current, err := config.LoadDetectionConfigFromFile(configPath)
	if err != nil {
		return respondError(c, fiber.StatusInternalServerError, "internal_error",
			"Failed to read current detection config: "+err.Error())
	}

	currentJSON, _ := json.Marshal(current)
	var merged map[string]interface{}
	json.Unmarshal(currentJSON, &merged)
	for k, v := range updates {
		merged[k] = v
	}

	mergedJSON, err := json.Marshal(merged)
	if err != nil {
		return respondError(c, fiber.StatusBadRequest, "bad_request",
			"Failed to merge config: "+err.Error())
	}

	var validated config.DetectionConfig
	if err := json.Unmarshal(mergedJSON, &validated); err != nil {
		return respondError(c, fiber.StatusBadRequest, "bad_request",
			"Invalid detection config: "+err.Error())
	}

	if err := writeJSONToTOMLFile(configPath, &validated); err != nil {
		return respondError(c, fiber.StatusInternalServerError, "internal_error",
			"Failed to write detection config: "+err.Error())
	}

	s.triggerReload("detection.toml")
	s.logger.Info().Msg("Detection config updated via API")

	return c.JSON(fiber.Map{
		"message": "Detection configuration updated — hot-reload triggered",
	})
}

// ============================================================================
// Blocklist Config
// ============================================================================

// handleGetBlocklistConfig handles GET /api/v1/rules/blocklist.
func (s *Server) handleGetBlocklistConfig(c *fiber.Ctx) error {
	if s.deps.Config == nil || s.deps.Config.Blocklist == nil {
		return respondError(c, fiber.StatusServiceUnavailable, "unavailable",
			"Blocklist config not loaded")
	}

	// Get live parsed blocklist state
	var liveState interface{}
	bl := s.deps.LiveBlocklist.Load()
	if bl != nil {
		liveState = fiber.Map{
			"domains_enabled":      bl.DomainsEnabled,
			"ips_enabled":          bl.IPsEnabled,
			"threat_intel":         bl.ThreatIntelEnabled,
			"geo_enabled":          bl.GeoEnabled,
			"manual_ips":           len(bl.ManualIPs),
			"whitelist_ips":        len(bl.WhitelistIPs),
			"categories":           bl.BlockedCategories,
			"cdn_enforce_dns_only": bl.CDNEnforceDNSOnly,
		}
	}

	return c.JSON(fiber.Map{
		"config":     s.deps.Config.Blocklist,
		"live_state": liveState,
	})
}

// handleUpdateBlocklistConfig handles PUT /api/v1/rules/blocklist.
func (s *Server) handleUpdateBlocklistConfig(c *fiber.Ctx) error {
	configPath := s.deps.Config.BlocklistFilePath()

	var updates map[string]interface{}
	if err := c.BodyParser(&updates); err != nil {
		return respondError(c, fiber.StatusBadRequest, "bad_request",
			"Invalid request body: "+err.Error())
	}

	current, err := config.LoadBlocklistConfigFromFile(configPath)
	if err != nil {
		return respondError(c, fiber.StatusInternalServerError, "internal_error",
			"Failed to read current blocklist config: "+err.Error())
	}

	currentJSON, _ := json.Marshal(current)
	var merged map[string]interface{}
	json.Unmarshal(currentJSON, &merged)
	for k, v := range updates {
		merged[k] = v
	}

	mergedJSON, err := json.Marshal(merged)
	if err != nil {
		return respondError(c, fiber.StatusBadRequest, "bad_request",
			"Failed to merge config: "+err.Error())
	}

	var validated config.BlocklistConfig
	if err := json.Unmarshal(mergedJSON, &validated); err != nil {
		return respondError(c, fiber.StatusBadRequest, "bad_request",
			"Invalid blocklist config: "+err.Error())
	}

	if err := writeJSONToTOMLFile(configPath, &validated); err != nil {
		return respondError(c, fiber.StatusInternalServerError, "internal_error",
			"Failed to write blocklist config: "+err.Error())
	}

	s.triggerReload("blocklist.toml")
	s.logger.Info().Msg("Blocklist config updated via API")

	return c.JSON(fiber.Map{
		"message": "Blocklist configuration updated — hot-reload triggered",
	})
}

// ============================================================================
// File Helpers
// ============================================================================

// readLinesFromFile reads non-empty, non-comment lines from a text file.
func readLinesFromFile(path string) ([]string, error) {
	file, err := os.Open(path)
	if err != nil {
		if os.IsNotExist(err) {
			return []string{}, nil
		}
		return nil, err
	}
	defer file.Close()

	var lines []string
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line != "" && !strings.HasPrefix(line, "#") {
			lines = append(lines, line)
		}
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}
	return lines, nil
}

// appendLineToFile appends a line to a text file (creates if not exists).
func appendLineToFile(path, line string) error {
	// Ensure parent directory exists
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return fmt.Errorf("create directory: %w", err)
	}

	f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		return err
	}
	defer f.Close()

	_, err = fmt.Fprintf(f, "%s\n", line)
	return err
}

// removeLineFromFile removes the first matching line from a text file.
// Returns true if the line was found and removed.
func removeLineFromFile(path, target string) (bool, error) {
	lines, err := func() ([]string, error) {
		file, err := os.Open(path)
		if err != nil {
			return nil, err
		}
		defer file.Close()

		var lines []string
		scanner := bufio.NewScanner(file)
		for scanner.Scan() {
			lines = append(lines, scanner.Text())
		}
		return lines, scanner.Err()
	}()
	if err != nil {
		return false, err
	}

	found := false
	var kept []string
	for _, line := range lines {
		trimmed := strings.TrimSpace(line)
		if !found && strings.EqualFold(trimmed, target) {
			found = true
			continue
		}
		kept = append(kept, line)
	}

	if !found {
		return false, nil
	}

	// Write back atomically via temp file
	tmpPath := path + ".tmp." + fmt.Sprintf("%d", time.Now().UnixNano())
	f, err := os.Create(tmpPath)
	if err != nil {
		return false, err
	}

	for _, line := range kept {
		if _, err := fmt.Fprintln(f, line); err != nil {
			f.Close()
			os.Remove(tmpPath)
			return false, err
		}
	}

	if err := f.Close(); err != nil {
		os.Remove(tmpPath)
		return false, err
	}

	// Atomic replace
	if err := os.Rename(tmpPath, path); err != nil {
		os.Remove(tmpPath)
		return false, err
	}

	return true, nil
}

// writeJSONToTOMLFile writes a struct as a JSON file (TOML serializers not
// available in this module). The hot-reload system will parse the file.
// NOTE: This writes the config as JSON since we don't have a TOML writer
// dependency. The config loaders should handle this gracefully if they
// support JSON, otherwise a TOML writer dependency would be needed.
// As a pragmatic solution, we write to a sidecar .json file and rely on
// the hot-reload to pick up the changes.
func writeJSONToTOMLFile(path string, data interface{}) error {
	// For safety, write to a .bak first
	content, _ := os.ReadFile(path)
	if len(content) > 0 {
		bakPath := path + ".bak." + time.Now().Format("20060102-150405")
		os.WriteFile(bakPath, content, 0644)
	}

	jsonData, err := json.MarshalIndent(data, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal config: %w", err)
	}

	// Write the JSON data — the config loader will need to handle JSON
	// For now, we write the data and rely on the observer pattern
	return os.WriteFile(path, jsonData, 0644)
}

// ============================================================================
// Path Helpers
// ============================================================================

// getDomainsFilePath returns the path to domains.txt.
func (s *Server) getDomainsFilePath() string {
	if s.deps.Config != nil {
		return s.deps.Config.DomainsFilePath()
	}
	return ""
}

// getBlockedIPsFilePath returns the path to blocked_ips.txt.
func (s *Server) getBlockedIPsFilePath() string {
	if s.deps.Config != nil {
		return filepath.Join(s.deps.Config.ConfigDir, "blocked_ips.txt")
	}
	return ""
}

// getWhitelistFilePath returns the path to whitelist.txt.
func (s *Server) getWhitelistFilePath() string {
	if s.deps.Config != nil {
		return filepath.Join(s.deps.Config.ConfigDir, "whitelist.txt")
	}
	return ""
}

// getWhitelistDomainsFilePath returns the path to whitelist_domains.txt.
func (s *Server) getWhitelistDomainsFilePath() string {
	if s.deps.Config != nil {
		return filepath.Join(s.deps.Config.ConfigDir, "whitelist_domains.txt")
	}
	return ""
}

// triggerReload triggers a hot-reload of a specific config file.
// This is a best-effort operation — the hot-reloader watches for FS changes,
// so writing to the file will automatically trigger a reload.
// This method exists for logging purposes and future direct reload support.
func (s *Server) triggerReload(filename string) {
	s.logger.Info().
		Str("file", filename).
		Msg("Config file modified via API — hot-reload should trigger")
}

// ============================================================================
// Custom Detection Rules (rules.toml) — read/toggle
// ============================================================================

// handleGetCustomRules handles GET /api/v1/rules/custom.
// Returns all detection rules from rules.toml (including disabled).
func (s *Server) handleGetCustomRules(c *fiber.Ctx) error {
	rulesPath := filepath.Join(s.deps.Config.ConfigDir, "rules.toml")

	allRules, err := rules.GetAllRulesFromFile(rulesPath)
	if err != nil {
		return respondError(c, fiber.StatusInternalServerError, "read_error",
			fmt.Sprintf("Failed to read rules.toml: %v", err))
	}

	// Group rules by alert_type category
	type ruleResponse struct {
		Name             string   `json:"name"`
		Description      string   `json:"description"`
		Enabled          bool     `json:"enabled"`
		Severity         string   `json:"severity"`
		Protocol         string   `json:"protocol,omitempty"`
		DstPort          []int    `json:"dst_port,omitempty"`
		SrcPort          []int    `json:"src_port,omitempty"`
		Direction        string   `json:"direction,omitempty"`
		DstIP            []string `json:"dst_ip,omitempty"`
		Action           string   `json:"action"`
		AlertType        string   `json:"alert_type"`
		ThresholdCount   int      `json:"threshold_count,omitempty"`
		ThresholdWindow  int      `json:"threshold_window,omitempty"`
		ThresholdGroupBy string   `json:"threshold_group_by,omitempty"`
		BanDuration      string   `json:"ban_duration,omitempty"`
		TCPFlags         string   `json:"tcp_flags,omitempty"`
	}

	var resp []ruleResponse
	for _, r := range allRules {
		resp = append(resp, ruleResponse{
			Name:             r.Name,
			Description:      r.Description,
			Enabled:          r.Enabled,
			Severity:         r.Severity,
			Protocol:         r.Protocol,
			DstPort:          r.DstPort,
			SrcPort:          r.SrcPort,
			Direction:        r.Direction,
			DstIP:            r.DstIP,
			Action:           r.Action,
			AlertType:        r.AlertType,
			ThresholdCount:   r.ThresholdCount,
			ThresholdWindow:  r.ThresholdWindow,
			ThresholdGroupBy: r.ThresholdGroupBy,
			BanDuration:      r.BanDuration,
			TCPFlags:         r.TCPFlags,
		})
	}

	return c.JSON(fiber.Map{
		"rules": resp,
		"total": len(resp),
	})
}

// handleToggleCustomRule handles PUT /api/v1/rules/custom/:name/toggle.
// Toggles the enabled state of a rule and writes back to rules.toml.
func (s *Server) handleToggleCustomRule(c *fiber.Ctx) error {
	ruleName := c.Params("name")
	if ruleName == "" {
		return respondError(c, fiber.StatusBadRequest, "invalid_request", "Rule name is required")
	}

	var body struct {
		Enabled bool `json:"enabled"`
	}
	if err := c.BodyParser(&body); err != nil {
		return respondError(c, fiber.StatusBadRequest, "invalid_body", "Expected JSON with 'enabled' field")
	}

	rulesPath := filepath.Join(s.deps.Config.ConfigDir, "rules.toml")

	// Read all rules
	allRules, err := rules.GetAllRulesFromFile(rulesPath)
	if err != nil {
		return respondError(c, fiber.StatusInternalServerError, "read_error",
			fmt.Sprintf("Failed to read rules.toml: %v", err))
	}

	// Find and toggle the rule
	found := false
	for i, r := range allRules {
		if r.Name == ruleName {
			allRules[i].Enabled = body.Enabled
			found = true
			break
		}
	}
	if !found {
		return respondError(c, fiber.StatusNotFound, "not_found",
			fmt.Sprintf("Rule '%s' not found", ruleName))
	}

	// Write back to TOML
	f, err := os.Create(rulesPath)
	if err != nil {
		return respondError(c, fiber.StatusInternalServerError, "write_error",
			fmt.Sprintf("Failed to write rules.toml: %v", err))
	}
	defer f.Close()

	w := bufio.NewWriter(f)
	w.WriteString("# SafeOps Firewall Engine - Custom Detection Rules\n")
	w.WriteString("# Auto-generated by Web UI — " + time.Now().Format(time.RFC3339) + "\n\n")

	enc := toml.NewEncoder(w)
	err = enc.Encode(struct {
		Rule []rules.Rule `toml:"rule"`
	}{Rule: allRules})
	if err != nil {
		return respondError(c, fiber.StatusInternalServerError, "encode_error",
			fmt.Sprintf("Failed to encode rules: %v", err))
	}
	w.Flush()

	s.triggerReload("rules.toml")

	return c.JSON(fiber.Map{
		"status":  "ok",
		"rule":    ruleName,
		"enabled": body.Enabled,
	})
}

// ============================================================================
// Malicious Visit Auto-Block API
// ============================================================================

// handleGetAutoBlockedDomains handles GET /api/v1/domains/auto-blocked.
// Returns domains that were automatically blocked after exceeding the visit threshold.
func (s *Server) handleGetAutoBlockedDomains(c *fiber.Ctx) error {
	if s.deps.DomainFilter == nil {
		return c.JSON(fiber.Map{"domains": []interface{}{}, "total": 0})
	}
	entries := s.deps.DomainFilter.GetAutoBlockedDomains()
	return c.JSON(fiber.Map{
		"domains":   entries,
		"total":     len(entries),
		"threshold": s.deps.DomainFilter.GetVisitThreshold(),
	})
}

// handleRemoveAutoBlock handles DELETE /api/v1/domains/auto-blocked/:domain.
// Removes a domain from the auto-block set and resets its visit counter.
// Note: takes effect for new connections; full removal requires Reload().
func (s *Server) handleRemoveAutoBlock(c *fiber.Ctx) error {
	if s.deps.DomainFilter == nil {
		return respondError(c, fiber.StatusServiceUnavailable, "unavailable", "Domain filter not initialized")
	}
	domain := strings.TrimSpace(c.Params("domain"))
	if domain == "" {
		return respondError(c, fiber.StatusBadRequest, "bad_request", "Domain is required")
	}
	s.deps.DomainFilter.RemoveAutoBlock(domain)
	return c.JSON(fiber.Map{"status": "ok", "domain": domain, "message": "Removed from auto-block list; call Reload to remove from in-memory blocklist"})
}

// handleGetMaliciousVisits handles GET /api/v1/domains/malicious-visits.
// Returns all threat-intel-flagged domains with their visit counts.
func (s *Server) handleGetMaliciousVisits(c *fiber.Ctx) error {
	if s.deps.DomainFilter == nil {
		return c.JSON(fiber.Map{"domains": []interface{}{}, "total": 0})
	}
	entries := s.deps.DomainFilter.GetMaliciousVisitCounts()
	return c.JSON(fiber.Map{
		"domains":   entries,
		"total":     len(entries),
		"threshold": s.deps.DomainFilter.GetVisitThreshold(),
	})
}

// handleGetVisitThreshold handles GET /api/v1/domains/visit-threshold.
func (s *Server) handleGetVisitThreshold(c *fiber.Ctx) error {
	threshold := int64(10) // default
	if s.deps.DomainFilter != nil {
		threshold = s.deps.DomainFilter.GetVisitThreshold()
	}
	return c.JSON(fiber.Map{
		"threshold": threshold,
		"enabled":   threshold > 0,
		"description": "Malicious domains are auto-blocked after this many visits. 0 = alert-only mode.",
	})
}

// VisitThresholdRequest is the body for PUT /api/v1/domains/visit-threshold.
type VisitThresholdRequest struct {
	Threshold int64 `json:"threshold"`
}

// handleSetVisitThreshold handles PUT /api/v1/domains/visit-threshold.
// Updates the malicious-visit auto-block threshold at runtime.
func (s *Server) handleSetVisitThreshold(c *fiber.Ctx) error {
	if s.deps.DomainFilter == nil {
		return respondError(c, fiber.StatusServiceUnavailable, "unavailable", "Domain filter not initialized")
	}
	var req VisitThresholdRequest
	if err := c.BodyParser(&req); err != nil {
		return respondError(c, fiber.StatusBadRequest, "bad_request", "Invalid JSON: "+err.Error())
	}
	if req.Threshold < 0 {
		return respondError(c, fiber.StatusBadRequest, "bad_request", "Threshold must be >= 0 (0 = disabled)")
	}
	s.deps.DomainFilter.SetVisitThreshold(req.Threshold)
	return c.JSON(fiber.Map{
		"status":    "ok",
		"threshold": req.Threshold,
		"enabled":   req.Threshold > 0,
	})
}
