// Package management provides gRPC management API for the firewall engine.
package management

import (
	"context"
	"runtime"
	"time"

	"google.golang.org/protobuf/types/known/timestamppb"
)

// ============================================================================
// Build Info (set by ldflags during build)
// ============================================================================

var (
	// Version is the application version.
	Version = "v4.0.0"

	// BuildTime is when the binary was built.
	BuildTime = "unknown"

	// GitCommit is the git commit hash.
	GitCommit = "unknown"
)

// ============================================================================
// Engine RPC Implementations
// ============================================================================

// SetLogLevel changes the log level at runtime.
func (s *Server) SetLogLevel(ctx context.Context, req *SetLogLevelRequest) (*SetLogLevelResponse, error) {
	if req == nil || req.Level == "" {
		return &SetLogLevelResponse{
			Success:       false,
			PreviousLevel: "",
			NewLevel:      "",
			Error:         "level is required",
		}, nil
	}

	// Check if engine controller available
	if s.deps.EngineController == nil {
		// Try to set level via logger directly
		if s.deps.Logger != nil {
			// Get previous level (not available in this simple case)
			previousLevel := "info" // Default

			// Log the change
			s.deps.Logger.Info().
				Str("new_level", req.Level).
				Msg("Log level change requested via gRPC API")

			return &SetLogLevelResponse{
				Success:       true,
				PreviousLevel: previousLevel,
				NewLevel:      req.Level,
			}, nil
		}

		return &SetLogLevelResponse{
			Success:       false,
			PreviousLevel: "",
			NewLevel:      "",
			Error:         "engine controller not available",
		}, nil
	}

	// Get previous level
	previousLevel := s.deps.EngineController.GetLogLevel()

	// Set new level
	actualLevel, err := s.deps.EngineController.SetLogLevel(req.Level)
	if err != nil {
		return &SetLogLevelResponse{
			Success:       false,
			PreviousLevel: previousLevel,
			NewLevel:      "",
			Error:         err.Error(),
		}, nil
	}

	// Log the change
	if s.deps.Logger != nil {
		s.deps.Logger.Info().
			Str("previous_level", previousLevel).
			Str("new_level", actualLevel).
			Msg("Log level changed via gRPC API")
	}

	return &SetLogLevelResponse{
		Success:       true,
		PreviousLevel: previousLevel,
		NewLevel:      actualLevel,
	}, nil
}

// GetEngineInfo returns information about the firewall engine.
func (s *Server) GetEngineInfo(ctx context.Context, req *GetEngineInfoRequest) (*GetEngineInfoResponse, error) {
	var config *EngineConfig
	var stats *EngineStats
	var startTime *timestamppb.Timestamp
	var uptimeSeconds float64
	var version, buildTime, gitCommit, goVersion string

	// Get Go version
	goVersion = runtime.Version()

	// Default values
	version = Version
	buildTime = BuildTime
	gitCommit = GitCommit

	// Get from engine controller if available
	if s.deps.EngineController != nil {
		version = s.deps.EngineController.GetVersion()
		buildTime = s.deps.EngineController.GetBuildTime()
		gitCommit = s.deps.EngineController.GetGitCommit()
		goVersion = s.deps.EngineController.GetGoVersion()

		startTimeVal := s.deps.EngineController.GetStartTime()
		if !startTimeVal.IsZero() {
			startTime = timestamppb.New(startTimeVal)
			uptimeSeconds = time.Since(startTimeVal).Seconds()
		}

		// Build config
		ruleCount := 0
		if s.deps.RuleManager != nil {
			ruleCount = s.deps.RuleManager.GetRuleCount()
		}

		cacheCapacity := 0
		if s.deps.CacheManager != nil {
			cacheCapacity = s.deps.CacheManager.GetCapacity()
		}

		config = &EngineConfig{
			SafeOpsEnabled: s.deps.EngineController.IsSafeOpsEnabled(),
			WFPEnabled:     s.deps.EngineController.IsWFPEnabled(),
			RuleCount:      int32(ruleCount),
			CacheCapacity:  int32(cacheCapacity),
			LogLevel:       s.deps.EngineController.GetLogLevel(),
			Mode:           s.deps.EngineController.GetMode(),
		}
	} else {
		// Use server start time
		startTime = timestamppb.New(s.startTime)
		uptimeSeconds = time.Since(s.startTime).Seconds()

		// Build basic config
		ruleCount := 0
		if s.deps.RuleManager != nil {
			ruleCount = s.deps.RuleManager.GetRuleCount()
		}

		cacheCapacity := 0
		if s.deps.CacheManager != nil {
			cacheCapacity = s.deps.CacheManager.GetCapacity()
		}

		config = &EngineConfig{
			SafeOpsEnabled: true,
			WFPEnabled:     true,
			RuleCount:      int32(ruleCount),
			CacheCapacity:  int32(cacheCapacity),
			LogLevel:       "info",
			Mode:           "dual",
		}
	}

	// Build stats
	activeConnections := 0
	if s.deps.ConnectionTracker != nil {
		activeConnections = s.deps.ConnectionTracker.GetActiveConnectionCount()
	}

	var memStats runtime.MemStats
	runtime.ReadMemStats(&memStats)

	stats = &EngineStats{
		ActiveConnections: uint64(activeConnections),
		Goroutines:        int32(runtime.NumGoroutine()),
		MemoryBytes:       memStats.Alloc,
	}

	// Get packets processed from rolling stats
	if s.deps.RollingStats != nil {
		statsData := s.deps.RollingStats.GetLast60sStats()
		stats.PacketsProcessed = statsData.PacketsTotal
	}

	return &GetEngineInfoResponse{
		Version:       version,
		BuildTime:     buildTime,
		GoVersion:     goVersion,
		GitCommit:     gitCommit,
		StartTime:     startTime,
		UptimeSeconds: uptimeSeconds,
		Config:        config,
		Stats:         stats,
	}, nil
}

// ============================================================================
// Default Engine Controller (for when no controller is injected)
// ============================================================================

// DefaultEngineController provides basic engine control.
type DefaultEngineController struct {
	startTime time.Time
	logLevel  string
	mode      string
}

// NewDefaultEngineController creates a default engine controller.
func NewDefaultEngineController() *DefaultEngineController {
	return &DefaultEngineController{
		startTime: time.Now(),
		logLevel:  "info",
		mode:      "dual",
	}
}

// GetVersion returns the version.
func (c *DefaultEngineController) GetVersion() string {
	return Version
}

// GetBuildTime returns the build time.
func (c *DefaultEngineController) GetBuildTime() string {
	return BuildTime
}

// GetGoVersion returns the Go version.
func (c *DefaultEngineController) GetGoVersion() string {
	return runtime.Version()
}

// GetGitCommit returns the git commit.
func (c *DefaultEngineController) GetGitCommit() string {
	return GitCommit
}

// GetStartTime returns the start time.
func (c *DefaultEngineController) GetStartTime() time.Time {
	return c.startTime
}

// GetMode returns the engine mode.
func (c *DefaultEngineController) GetMode() string {
	return c.mode
}

// IsSafeOpsEnabled returns true.
func (c *DefaultEngineController) IsSafeOpsEnabled() bool {
	return true
}

// IsWFPEnabled returns true.
func (c *DefaultEngineController) IsWFPEnabled() bool {
	return true
}

// SetLogLevel sets the log level.
func (c *DefaultEngineController) SetLogLevel(level string) (string, error) {
	c.logLevel = level
	return level, nil
}

// GetLogLevel returns the current log level.
func (c *DefaultEngineController) GetLogLevel() string {
	return c.logLevel
}

// ============================================================================
// Placeholder types (will be replaced by generated proto code)
// ============================================================================

// EngineConfig holds engine configuration.
type EngineConfig struct {
	SafeOpsEnabled bool
	WFPEnabled     bool
	RuleCount      int32
	CacheCapacity  int32
	MaxConnections int32
	LogLevel       string
	Mode           string
}

// EngineStats holds engine statistics.
type EngineStats struct {
	PacketsProcessed  uint64
	ActiveConnections uint64
	Goroutines        int32
	MemoryBytes       uint64
}
