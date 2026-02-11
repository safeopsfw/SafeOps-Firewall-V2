package api

import (
	"runtime"
	"time"

	"github.com/gofiber/fiber/v2"
)

// handleHealth handles GET /api/v1/health.
// Returns a lightweight health check response (no auth required for monitoring).
func (s *Server) handleHealth(c *fiber.Ctx) error {
	return c.JSON(fiber.Map{
		"status": "ok",
		"uptime": time.Since(s.deps.StartTime).Truncate(time.Second).String(),
	})
}

// handleStatus handles GET /api/v1/status.
// Returns a comprehensive status overview of the engine.
func (s *Server) handleStatus(c *fiber.Ctx) error {
	var memStats runtime.MemStats
	runtime.ReadMemStats(&memStats)

	status := fiber.Map{
		"status":         "running",
		"version":        s.getEngineVersion(),
		"uptime":         time.Since(s.deps.StartTime).Truncate(time.Second).String(),
		"uptime_seconds": int64(time.Since(s.deps.StartTime).Seconds()),
		"ws_clients":     s.hub.ClientCount(),
		"memory": fiber.Map{
			"alloc_mb":       float64(memStats.Alloc) / 1024 / 1024,
			"total_alloc_mb": float64(memStats.TotalAlloc) / 1024 / 1024,
			"sys_mb":         float64(memStats.Sys) / 1024 / 1024,
			"gc_cycles":      memStats.NumGC,
			"goroutines":     runtime.NumGoroutine(),
		},
	}

	// Component status
	components := fiber.Map{}

	if s.deps.SecurityMgr != nil {
		ss := s.deps.SecurityMgr.Stats()
		components["security"] = fiber.Map{
			"status":      "active",
			"active_bans": ss.Bans.ActiveBans,
		}
	} else {
		components["security"] = fiber.Map{"status": "not_available"}
	}

	if s.deps.DomainFilter != nil {
		ds := s.deps.DomainFilter.Stats()
		components["domain_filter"] = fiber.Map{
			"status":          "active",
			"blocked_domains": ds.ConfigDomains,
			"total_checks":    ds.TotalChecks,
		}
	} else {
		components["domain_filter"] = fiber.Map{"status": "not_available"}
	}

	if s.deps.GeoChecker != nil {
		gs := s.deps.GeoChecker.Stats()
		components["geoip"] = fiber.Map{
			"status":  "active",
			"enabled": gs.Enabled,
			"mode":    gs.Mode,
		}
	} else {
		components["geoip"] = fiber.Map{"status": "not_available"}
	}

	if s.deps.AlertMgr != nil {
		as := s.deps.AlertMgr.GetStats()
		components["alerting"] = fiber.Map{
			"status":       "active",
			"total_alerts": as.TotalAlerts,
		}
	} else {
		components["alerting"] = fiber.Map{"status": "not_available"}
	}

	if s.deps.Reloader != nil {
		rs := s.deps.Reloader.Stats()
		components["hot_reload"] = fiber.Map{
			"status":    "active",
			"successes": rs.Successes,
			"failures":  rs.Failures,
		}
	} else {
		components["hot_reload"] = fiber.Map{"status": "not_available"}
	}

	status["components"] = components

	return c.JSON(status)
}
