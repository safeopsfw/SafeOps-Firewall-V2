package api

import (
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/gofiber/fiber/v2"
)

// ============================================================================
// Ban Management
// ============================================================================

// BanResponse is the JSON representation of a ban entry for the API.
type BanResponse struct {
	IP        string `json:"ip"`
	Reason    string `json:"reason"`
	BannedAt  string `json:"banned_at"`
	ExpiresAt string `json:"expires_at,omitempty"`
	Duration  string `json:"duration"`
	Level     int    `json:"level"`
	Permanent bool   `json:"permanent"`
	TimeLeft  string `json:"time_left,omitempty"`
}

// handleGetBans handles GET /api/v1/security/bans.
// Returns all active bans with optional IP filter.
func (s *Server) handleGetBans(c *fiber.Ctx) error {
	if s.deps.SecurityMgr == nil || s.deps.SecurityMgr.BanMgr == nil {
		return respondError(c, fiber.StatusServiceUnavailable, "unavailable",
			"Security manager not initialized")
	}

	bans := s.deps.SecurityMgr.BanMgr.GetActiveBans()
	ipFilter := c.Query("ip", "")

	var response []BanResponse
	for _, ban := range bans {
		// Apply IP filter if provided
		if ipFilter != "" && !strings.Contains(ban.IP, ipFilter) {
			continue
		}

		entry := BanResponse{
			IP:        ban.IP,
			Reason:    ban.Reason,
			BannedAt:  ban.BannedAt.Format(time.RFC3339),
			Duration:  ban.Duration.String(),
			Level:     ban.Level,
			Permanent: ban.Permanent,
		}

		if !ban.ExpiresAt.IsZero() {
			entry.ExpiresAt = ban.ExpiresAt.Format(time.RFC3339)
			remaining := time.Until(ban.ExpiresAt)
			if remaining > 0 {
				entry.TimeLeft = remaining.Truncate(time.Second).String()
			} else {
				entry.TimeLeft = "expired"
			}
		}

		response = append(response, entry)
	}

	if response == nil {
		response = []BanResponse{}
	}

	return c.JSON(fiber.Map{
		"bans":  response,
		"total": len(response),
	})
}

// CreateBanRequest is the request body for POST /api/v1/security/bans.
type CreateBanRequest struct {
	IP       string `json:"ip"`
	Reason   string `json:"reason"`
	Duration string `json:"duration,omitempty"` // e.g. "30m", "2h", "24h". Empty = auto-escalate
}

// handleCreateBan handles POST /api/v1/security/bans.
// Manually bans an IP address.
func (s *Server) handleCreateBan(c *fiber.Ctx) error {
	if s.deps.SecurityMgr == nil || s.deps.SecurityMgr.BanMgr == nil {
		return respondError(c, fiber.StatusServiceUnavailable, "unavailable",
			"Security manager not initialized")
	}

	var req CreateBanRequest
	if err := c.BodyParser(&req); err != nil {
		return respondError(c, fiber.StatusBadRequest, "bad_request",
			"Invalid request body: "+err.Error())
	}

	// Validate IP
	if req.IP == "" {
		return respondError(c, fiber.StatusBadRequest, "bad_request", "IP address is required")
	}
	if ip := net.ParseIP(req.IP); ip == nil {
		// Try CIDR
		if _, _, err := net.ParseCIDR(req.IP); err != nil {
			return respondError(c, fiber.StatusBadRequest, "bad_request",
				fmt.Sprintf("Invalid IP address or CIDR: %s", req.IP))
		}
	}

	// Default reason
	if req.Reason == "" {
		req.Reason = "Manual ban from Web UI"
	}

	// Apply ban
	var entry interface{}
	if req.Duration != "" {
		dur, err := time.ParseDuration(req.Duration)
		if err != nil {
			return respondError(c, fiber.StatusBadRequest, "bad_request",
				fmt.Sprintf("Invalid duration %q: %v", req.Duration, err))
		}
		entry = s.deps.SecurityMgr.BanMgr.BanWithDuration(req.IP, req.Reason, dur)
	} else {
		entry = s.deps.SecurityMgr.BanMgr.Ban(req.IP, req.Reason)
	}

	// Broadcast ban event
	s.hub.BroadcastEvent("ban_created", map[string]interface{}{
		"ip":     req.IP,
		"reason": req.Reason,
	})

	s.logger.Info().
		Str("ip", req.IP).
		Str("reason", req.Reason).
		Str("duration", req.Duration).
		Msg("IP banned via Web UI")

	return c.Status(fiber.StatusCreated).JSON(fiber.Map{
		"message": fmt.Sprintf("IP %s banned successfully", req.IP),
		"ban":     entry,
	})
}

// handleDeleteBan handles DELETE /api/v1/security/bans/:ip.
// Unbans an IP address.
func (s *Server) handleDeleteBan(c *fiber.Ctx) error {
	if s.deps.SecurityMgr == nil || s.deps.SecurityMgr.BanMgr == nil {
		return respondError(c, fiber.StatusServiceUnavailable, "unavailable",
			"Security manager not initialized")
	}

	ip := c.Params("ip")
	if ip == "" {
		return respondError(c, fiber.StatusBadRequest, "bad_request", "IP address is required")
	}

	// URL decode the IP (in case it contains encoded characters)
	ip = strings.ReplaceAll(ip, "%2F", "/")

	unbanned := s.deps.SecurityMgr.BanMgr.Unban(ip)
	if !unbanned {
		return respondError(c, fiber.StatusNotFound, "not_found",
			fmt.Sprintf("IP %s is not currently banned", ip))
	}

	// Also reset escalation history
	s.deps.SecurityMgr.BanMgr.ResetHistory(ip)

	// Broadcast unban event
	s.hub.BroadcastEvent("ban_removed", map[string]interface{}{
		"ip": ip,
	})

	s.logger.Info().
		Str("ip", ip).
		Msg("IP unbanned via Web UI")

	return c.JSON(fiber.Map{
		"message": fmt.Sprintf("IP %s unbanned and escalation history cleared", ip),
	})
}

// ============================================================================
// Security Stats
// ============================================================================

// handleSecurityStats handles GET /api/v1/security/stats.
// Returns full security sub-system statistics.
func (s *Server) handleSecurityStats(c *fiber.Ctx) error {
	if s.deps.SecurityMgr == nil {
		return respondError(c, fiber.StatusServiceUnavailable, "unavailable",
			"Security manager not initialized")
	}

	stats := s.deps.SecurityMgr.Stats()
	return c.JSON(stats)
}
