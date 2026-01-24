// Package logging provides structured logging for the firewall engine.
package logging

import (
	"sync/atomic"
)

// ============================================================================
// Sampler Configuration
// ============================================================================

// SamplerConfig configures log sampling behavior.
type SamplerConfig struct {
	// Enabled turns sampling on/off.
	Enabled bool `json:"enabled" toml:"enabled"`

	// Initial is the number of logs to write before sampling starts.
	// This allows burst logging at startup.
	Initial int `json:"initial" toml:"initial"`

	// Rate is the sampling rate. 1 in N logs will be written.
	// For example, Rate=10 means 10% of logs are written.
	Rate int `json:"rate" toml:"rate"`

	// SampleAllows determines whether ALLOW verdicts should be sampled.
	// Default is true (sample ALLOW to reduce volume).
	SampleAllows bool `json:"sample_allows" toml:"sample_allows"`

	// SampleDenies determines whether DENY verdicts should be sampled.
	// Default is false (log all DENY for security).
	SampleDenies bool `json:"sample_denies" toml:"sample_denies"`

	// AllowRate is the sampling rate for ALLOW verdicts.
	// Default is 10 (10% of ALLOW verdicts logged).
	AllowRate int `json:"allow_rate" toml:"allow_rate"`

	// DenyRate is the sampling rate for DENY verdicts.
	// Default is 1 (100% of DENY verdicts logged).
	DenyRate int `json:"deny_rate" toml:"deny_rate"`
}

// DefaultSamplerConfig returns a sampler config with sensible defaults.
func DefaultSamplerConfig() SamplerConfig {
	return SamplerConfig{
		Enabled:      true,
		Initial:      100,
		Rate:         10,
		SampleAllows: true,
		SampleDenies: false,
		AllowRate:    10,
		DenyRate:     1,
	}
}

// ApplyDefaults fills in default values for unset fields.
func (c *SamplerConfig) ApplyDefaults() {
	if c.Initial == 0 {
		c.Initial = 100
	}
	if c.Rate == 0 {
		c.Rate = 10
	}
	if c.AllowRate == 0 {
		c.AllowRate = 10
	}
	if c.DenyRate == 0 {
		c.DenyRate = 1
	}
}

// ============================================================================
// Sampler Interface
// ============================================================================

// Sampler decides whether a log entry should be written.
type Sampler interface {
	// Sample returns true if this log should be written.
	Sample() bool

	// SampleAction returns true if this action-type log should be written.
	// It uses action-specific rates for ALLOW vs DENY.
	SampleAction(action string) bool

	// GetStats returns sampling statistics.
	GetStats() SamplerStats

	// Reset resets the sampler counters.
	Reset()
}

// SamplerStats contains sampling statistics.
type SamplerStats struct {
	TotalLogs   uint64  `json:"total_logs"`
	SampledLogs uint64  `json:"sampled_logs"`
	DroppedLogs uint64  `json:"dropped_logs"`
	SampleRate  float64 `json:"sample_rate"`
}

// ============================================================================
// Basic Sampler
// ============================================================================

// basicSampler implements simple rate-based sampling.
type basicSampler struct {
	config  SamplerConfig
	counter atomic.Uint64
	initial atomic.Uint64
	sampled atomic.Uint64
	dropped atomic.Uint64
}

// Ensure basicSampler implements Sampler.
var _ Sampler = (*basicSampler)(nil)

// NewSampler creates a new sampler with the given configuration.
func NewSampler(config SamplerConfig) Sampler {
	config.ApplyDefaults()
	return &basicSampler{
		config: config,
	}
}

// Sample returns true if this log should be written.
func (s *basicSampler) Sample() bool {
	if !s.config.Enabled {
		s.sampled.Add(1)
		return true // No sampling, log everything
	}

	// Always log the first N entries (burst allowance)
	initial := s.initial.Add(1)
	if initial <= uint64(s.config.Initial) {
		s.sampled.Add(1)
		return true
	}

	// Sample 1 in N
	count := s.counter.Add(1)
	if count%uint64(s.config.Rate) == 0 {
		s.sampled.Add(1)
		return true
	}

	s.dropped.Add(1)
	return false
}

// SampleAction returns true if this action should be logged.
func (s *basicSampler) SampleAction(action string) bool {
	if !s.config.Enabled {
		s.sampled.Add(1)
		return true
	}

	// Always log first N entries
	initial := s.initial.Add(1)
	if initial <= uint64(s.config.Initial) {
		s.sampled.Add(1)
		return true
	}

	count := s.counter.Add(1)

	switch action {
	case ActionDeny, ActionDrop, ActionReject:
		// Security events: use deny rate (default: log all)
		if !s.config.SampleDenies || s.config.DenyRate <= 1 {
			s.sampled.Add(1)
			return true
		}
		if count%uint64(s.config.DenyRate) == 0 {
			s.sampled.Add(1)
			return true
		}

	case ActionAllow:
		// Normal traffic: use allow rate (default: 10%)
		if !s.config.SampleAllows {
			s.sampled.Add(1)
			return true
		}
		if count%uint64(s.config.AllowRate) == 0 {
			s.sampled.Add(1)
			return true
		}

	default:
		// Unknown action: use general sampling
		if count%uint64(s.config.Rate) == 0 {
			s.sampled.Add(1)
			return true
		}
	}

	s.dropped.Add(1)
	return false
}

// GetStats returns sampling statistics.
func (s *basicSampler) GetStats() SamplerStats {
	sampled := s.sampled.Load()
	dropped := s.dropped.Load()
	total := sampled + dropped

	var rate float64
	if total > 0 {
		rate = float64(sampled) / float64(total)
	}

	return SamplerStats{
		TotalLogs:   total,
		SampledLogs: sampled,
		DroppedLogs: dropped,
		SampleRate:  rate,
	}
}

// Reset resets the sampler counters.
func (s *basicSampler) Reset() {
	s.counter.Store(0)
	s.initial.Store(0)
	s.sampled.Store(0)
	s.dropped.Store(0)
}

// ============================================================================
// No-op Sampler
// ============================================================================

// noopSampler always returns true (no sampling).
type noopSampler struct {
	counter atomic.Uint64
}

// NewNoopSampler creates a sampler that doesn't sample (logs everything).
func NewNoopSampler() Sampler {
	return &noopSampler{}
}

func (s *noopSampler) Sample() bool {
	s.counter.Add(1)
	return true
}

func (s *noopSampler) SampleAction(action string) bool {
	s.counter.Add(1)
	return true
}

func (s *noopSampler) GetStats() SamplerStats {
	count := s.counter.Load()
	return SamplerStats{
		TotalLogs:   count,
		SampledLogs: count,
		DroppedLogs: 0,
		SampleRate:  1.0,
	}
}

func (s *noopSampler) Reset() {
	s.counter.Store(0)
}

// ============================================================================
// Sampled Logger
// ============================================================================

// SampledLogger wraps a Logger with a Sampler.
type SampledLogger struct {
	logger  Logger
	sampler Sampler
}

// NewSampledLogger creates a logger that applies sampling.
func NewSampledLogger(logger Logger, sampler Sampler) *SampledLogger {
	if sampler == nil {
		sampler = NewNoopSampler()
	}
	return &SampledLogger{
		logger:  logger,
		sampler: sampler,
	}
}

// Log checks sampling before logging.
func (sl *SampledLogger) Log(fn func(Logger)) {
	if sl.sampler.Sample() {
		fn(sl.logger)
	}
}

// LogAction checks action-based sampling before logging.
func (sl *SampledLogger) LogAction(action string, fn func(Logger)) {
	if sl.sampler.SampleAction(action) {
		fn(sl.logger)
	}
}

// LogVerdict logs a verdict with sampling.
func (sl *SampledLogger) LogVerdict(pkt PacketContext, verdict VerdictContext, msg string) {
	if sl.sampler.SampleAction(verdict.Action) {
		LogVerdict(sl.logger, pkt, verdict, msg)
	}
}

// GetSampler returns the underlying sampler.
func (sl *SampledLogger) GetSampler() Sampler {
	return sl.sampler
}

// GetLogger returns the underlying logger.
func (sl *SampledLogger) GetLogger() Logger {
	return sl.logger
}

// ============================================================================
// Level-Based Sampling
// ============================================================================

// LevelSamplerConfig configures per-level sampling.
type LevelSamplerConfig struct {
	TraceSampleRate int `json:"trace_sample_rate" toml:"trace_sample_rate"` // Default: 100 (1%)
	DebugSampleRate int `json:"debug_sample_rate" toml:"debug_sample_rate"` // Default: 10 (10%)
	InfoSampleRate  int `json:"info_sample_rate" toml:"info_sample_rate"`   // Default: 1 (100%)
	WarnSampleRate  int `json:"warn_sample_rate" toml:"warn_sample_rate"`   // Default: 1 (100%)
	ErrorSampleRate int `json:"error_sample_rate" toml:"error_sample_rate"` // Default: 1 (100%)
}

// DefaultLevelSamplerConfig returns sensible defaults.
func DefaultLevelSamplerConfig() LevelSamplerConfig {
	return LevelSamplerConfig{
		TraceSampleRate: 100, // 1% of trace logs
		DebugSampleRate: 10,  // 10% of debug logs
		InfoSampleRate:  1,   // 100% of info logs
		WarnSampleRate:  1,   // 100% of warn logs
		ErrorSampleRate: 1,   // 100% of error logs
	}
}

// levelSampler samples based on log level.
type levelSampler struct {
	config  LevelSamplerConfig
	counter atomic.Uint64
	sampled atomic.Uint64
	dropped atomic.Uint64
}

// NewLevelSampler creates a level-based sampler.
func NewLevelSampler(config LevelSamplerConfig) *levelSampler {
	return &levelSampler{config: config}
}

// SampleLevel returns true if a log at this level should be written.
func (s *levelSampler) SampleLevel(level LogLevel) bool {
	count := s.counter.Add(1)

	var rate int
	switch level {
	case LevelTrace:
		rate = s.config.TraceSampleRate
	case LevelDebug:
		rate = s.config.DebugSampleRate
	case LevelInfo:
		rate = s.config.InfoSampleRate
	case LevelWarn:
		rate = s.config.WarnSampleRate
	case LevelError, LevelFatal:
		rate = s.config.ErrorSampleRate
	default:
		rate = 1
	}

	if rate <= 0 {
		rate = 1
	}

	if count%uint64(rate) == 0 {
		s.sampled.Add(1)
		return true
	}

	s.dropped.Add(1)
	return false
}

func (s *levelSampler) Sample() bool {
	return s.SampleLevel(LevelInfo)
}

func (s *levelSampler) SampleAction(action string) bool {
	// For level sampler, treat deny as error level (always log)
	switch action {
	case ActionDeny, ActionDrop:
		return s.SampleLevel(LevelError)
	default:
		return s.SampleLevel(LevelInfo)
	}
}

func (s *levelSampler) GetStats() SamplerStats {
	sampled := s.sampled.Load()
	dropped := s.dropped.Load()
	total := sampled + dropped

	var rate float64
	if total > 0 {
		rate = float64(sampled) / float64(total)
	}

	return SamplerStats{
		TotalLogs:   total,
		SampledLogs: sampled,
		DroppedLogs: dropped,
		SampleRate:  rate,
	}
}

func (s *levelSampler) Reset() {
	s.counter.Store(0)
	s.sampled.Store(0)
	s.dropped.Store(0)
}
