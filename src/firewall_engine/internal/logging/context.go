// Package logging provides structured logging for the firewall engine.
package logging

import (
	"time"
)

// ============================================================================
// Packet Context
// ============================================================================

// PacketContext holds packet-related logging context.
// It contains all the fields needed to identify a network connection.
type PacketContext struct {
	FlowID   string `json:"flow_id"`
	SrcIP    string `json:"src_ip"`
	SrcPort  int    `json:"src_port"`
	DstIP    string `json:"dst_ip"`
	DstPort  int    `json:"dst_port"`
	Protocol string `json:"protocol"`
}

// NewPacketContext creates a new PacketContext.
func NewPacketContext(flowID, srcIP, dstIP, protocol string, srcPort, dstPort int) PacketContext {
	return PacketContext{
		FlowID:   flowID,
		SrcIP:    srcIP,
		DstIP:    dstIP,
		SrcPort:  srcPort,
		DstPort:  dstPort,
		Protocol: protocol,
	}
}

// NewPacketLogger creates a logger with packet context attached.
// All logs from this logger will include the packet context fields.
func NewPacketLogger(base Logger, ctx PacketContext) Logger {
	if base == nil {
		return &noopLogger{}
	}

	return base.With().
		Str(FieldFlowID, ctx.FlowID).
		Str(FieldSrcIP, ctx.SrcIP).
		Int(FieldSrcPort, ctx.SrcPort).
		Str(FieldDstIP, ctx.DstIP).
		Int(FieldDstPort, ctx.DstPort).
		Str(FieldProtocol, ctx.Protocol).
		Logger()
}

// LogPacket logs a packet event with full context.
func LogPacket(logger Logger, ctx PacketContext, msg string) {
	if logger == nil {
		return
	}

	logger.Info().
		Str(FieldFlowID, ctx.FlowID).
		Str(FieldSrcIP, ctx.SrcIP).
		Int(FieldSrcPort, ctx.SrcPort).
		Str(FieldDstIP, ctx.DstIP).
		Int(FieldDstPort, ctx.DstPort).
		Str(FieldProtocol, ctx.Protocol).
		Msg(msg)
}

// ============================================================================
// Verdict Context
// ============================================================================

// VerdictContext holds verdict-related logging context.
type VerdictContext struct {
	Action   string        `json:"action"`
	Rule     string        `json:"rule"`
	RuleID   string        `json:"rule_id"`
	Engine   string        `json:"engine"`
	Reason   string        `json:"reason"`
	Latency  time.Duration `json:"latency"`
	CacheHit bool          `json:"cache_hit"`
}

// NewVerdictContext creates a new VerdictContext.
func NewVerdictContext(action, rule, ruleID, engine, reason string) VerdictContext {
	return VerdictContext{
		Action: action,
		Rule:   rule,
		RuleID: ruleID,
		Engine: engine,
		Reason: reason,
	}
}

// WithLatency adds latency to the context.
func (v VerdictContext) WithLatency(d time.Duration) VerdictContext {
	v.Latency = d
	return v
}

// WithCacheHit marks the verdict as a cache hit.
func (v VerdictContext) WithCacheHit(hit bool) VerdictContext {
	v.CacheHit = hit
	return v
}

// LogVerdict logs a verdict with full packet and verdict context.
func LogVerdict(logger Logger, pkt PacketContext, verdict VerdictContext, msg string) {
	if logger == nil {
		return
	}

	event := logger.Info()

	// Packet context
	event.Str(FieldFlowID, pkt.FlowID).
		Str(FieldSrcIP, pkt.SrcIP).
		Int(FieldSrcPort, pkt.SrcPort).
		Str(FieldDstIP, pkt.DstIP).
		Int(FieldDstPort, pkt.DstPort).
		Str(FieldProtocol, pkt.Protocol)

	// Verdict context
	event.Str(FieldAction, verdict.Action).
		Str(FieldRule, verdict.Rule).
		Str(FieldEngine, verdict.Engine).
		Str(FieldReason, verdict.Reason).
		Bool(FieldCacheHit, verdict.CacheHit)

	// Add rule ID if present
	if verdict.RuleID != "" {
		event.Str(FieldRuleID, verdict.RuleID)
	}

	// Add latency
	if verdict.Latency > 0 {
		event.Int64(FieldLatencyUS, verdict.Latency.Microseconds())
	}

	event.Msg(msg)
}

// LogVerdictWithLevel logs a verdict at the specified level.
func LogVerdictWithLevel(logger Logger, level LogLevel, pkt PacketContext, verdict VerdictContext, msg string) {
	if logger == nil {
		return
	}

	var event Event
	switch level {
	case LevelTrace:
		event = logger.Trace()
	case LevelDebug:
		event = logger.Debug()
	case LevelInfo:
		event = logger.Info()
	case LevelWarn:
		event = logger.Warn()
	case LevelError:
		event = logger.Error()
	default:
		event = logger.Info()
	}

	// Packet context
	event.Str(FieldFlowID, pkt.FlowID).
		Str(FieldSrcIP, pkt.SrcIP).
		Int(FieldSrcPort, pkt.SrcPort).
		Str(FieldDstIP, pkt.DstIP).
		Int(FieldDstPort, pkt.DstPort).
		Str(FieldProtocol, pkt.Protocol)

	// Verdict context
	event.Str(FieldAction, verdict.Action).
		Str(FieldRule, verdict.Rule).
		Str(FieldEngine, verdict.Engine).
		Str(FieldReason, verdict.Reason).
		Bool(FieldCacheHit, verdict.CacheHit).
		Int64(FieldLatencyUS, verdict.Latency.Microseconds())

	event.Msg(msg)
}

// ============================================================================
// Component Logger
// ============================================================================

// ComponentLogger creates a logger with a component name attached.
// All logs from this logger will include the component field.
func ComponentLogger(base Logger, component string) Logger {
	if base == nil {
		return &noopLogger{}
	}
	return base.WithComponent(component)
}

// CreateComponentLoggers creates loggers for all standard components.
func CreateComponentLoggers(base Logger) map[string]Logger {
	if base == nil {
		base = &noopLogger{}
	}

	return map[string]Logger{
		ComponentMain:            base.WithComponent(ComponentMain),
		ComponentRuleManager:     base.WithComponent(ComponentRuleManager),
		ComponentSafeOpsClient:   base.WithComponent(ComponentSafeOpsClient),
		ComponentWFPEngine:       base.WithComponent(ComponentWFPEngine),
		ComponentVerdictCache:    base.WithComponent(ComponentVerdictCache),
		ComponentConnTracker:     base.WithComponent(ComponentConnTracker),
		ComponentPacketInspector: base.WithComponent(ComponentPacketInspector),
		ComponentEnforcement:     base.WithComponent(ComponentEnforcement),
		ComponentDualEngine:      base.WithComponent(ComponentDualEngine),
		ComponentMetrics:         base.WithComponent(ComponentMetrics),
		ComponentHealth:          base.WithComponent(ComponentHealth),
		ComponentAPI:             base.WithComponent(ComponentAPI),
		ComponentConfig:          base.WithComponent(ComponentConfig),
	}
}

// ============================================================================
// Request Context
// ============================================================================

// RequestContext holds request-related logging context.
// Used for gRPC request tracing.
type RequestContext struct {
	RequestID string `json:"request_id"`
	Method    string `json:"method"`
	User      string `json:"user,omitempty"`
	TraceID   string `json:"trace_id,omitempty"`
	SpanID    string `json:"span_id,omitempty"`
}

// NewRequestContext creates a new RequestContext.
func NewRequestContext(requestID, method string) RequestContext {
	return RequestContext{
		RequestID: requestID,
		Method:    method,
	}
}

// WithUser adds user info to the context.
func (r RequestContext) WithUser(user string) RequestContext {
	r.User = user
	return r
}

// WithTrace adds trace info to the context.
func (r RequestContext) WithTrace(traceID, spanID string) RequestContext {
	r.TraceID = traceID
	r.SpanID = spanID
	return r
}

// NewRequestLogger creates a logger with request context attached.
func NewRequestLogger(base Logger, ctx RequestContext) Logger {
	if base == nil {
		return &noopLogger{}
	}

	c := base.With().
		Str(FieldRequestID, ctx.RequestID).
		Str("method", ctx.Method)

	if ctx.User != "" {
		c = c.Str("user", ctx.User)
	}
	if ctx.TraceID != "" {
		c = c.Str(FieldTraceID, ctx.TraceID)
	}
	if ctx.SpanID != "" {
		c = c.Str(FieldSpanID, ctx.SpanID)
	}

	return c.Logger()
}

// ============================================================================
// Error Context
// ============================================================================

// ErrorContext holds error-related logging context.
type ErrorContext struct {
	Error      error  `json:"-"`
	ErrorCode  string `json:"error_code,omitempty"`
	ErrorType  string `json:"error_type,omitempty"`
	RetryCount int    `json:"retry_count,omitempty"`
}

// NewErrorContext creates a new ErrorContext.
func NewErrorContext(err error) ErrorContext {
	return ErrorContext{Error: err}
}

// WithCode adds an error code.
func (e ErrorContext) WithCode(code string) ErrorContext {
	e.ErrorCode = code
	return e
}

// WithType adds an error type.
func (e ErrorContext) WithType(errType string) ErrorContext {
	e.ErrorType = errType
	return e
}

// WithRetry adds retry count.
func (e ErrorContext) WithRetry(count int) ErrorContext {
	e.RetryCount = count
	return e
}

// LogError logs an error with context.
func LogError(logger Logger, ctx ErrorContext, msg string) {
	if logger == nil {
		return
	}

	event := logger.Error()

	if ctx.Error != nil {
		event.Err(ctx.Error)
	}
	if ctx.ErrorCode != "" {
		event.Str(FieldErrorCode, ctx.ErrorCode)
	}
	if ctx.ErrorType != "" {
		event.Str(FieldErrorType, ctx.ErrorType)
	}
	if ctx.RetryCount > 0 {
		event.Int(FieldRetryCount, ctx.RetryCount)
	}

	event.Msg(msg)
}

// ============================================================================
// Performance Context
// ============================================================================

// PerformanceContext holds performance-related logging context.
type PerformanceContext struct {
	StartTime    time.Time     `json:"-"`
	Duration     time.Duration `json:"duration"`
	Throughput   float64       `json:"throughput,omitempty"`
	CacheHitRate float64       `json:"cache_hit_rate,omitempty"`
}

// NewPerformanceContext creates a new PerformanceContext.
func NewPerformanceContext() PerformanceContext {
	return PerformanceContext{
		StartTime: time.Now(),
	}
}

// End marks the end of the operation and calculates duration.
func (p *PerformanceContext) End() {
	p.Duration = time.Since(p.StartTime)
}

// LogPerformance logs performance metrics.
func LogPerformance(logger Logger, ctx PerformanceContext, msg string) {
	if logger == nil {
		return
	}

	event := logger.Info()
	event.Int64(FieldLatencyUS, ctx.Duration.Microseconds())

	if ctx.Throughput > 0 {
		event.Float64(FieldThroughput, ctx.Throughput)
	}
	if ctx.CacheHitRate > 0 {
		event.Float64(FieldCacheHitRate, ctx.CacheHitRate)
	}

	event.Msg(msg)
}

// ============================================================================
// Timing Helper
// ============================================================================

// Timer is a helper for timing operations.
type Timer struct {
	logger    Logger
	startTime time.Time
	message   string
	fields    map[string]interface{}
}

// NewTimer creates a new timer that will log when Done is called.
func NewTimer(logger Logger, message string) *Timer {
	return &Timer{
		logger:    logger,
		startTime: time.Now(),
		message:   message,
		fields:    make(map[string]interface{}),
	}
}

// WithField adds a field to be logged.
func (t *Timer) WithField(key string, value interface{}) *Timer {
	t.fields[key] = value
	return t
}

// Done logs the elapsed time.
func (t *Timer) Done() time.Duration {
	elapsed := time.Since(t.startTime)

	if t.logger != nil {
		event := t.logger.Debug()
		event.Int64(FieldLatencyUS, elapsed.Microseconds())
		for k, v := range t.fields {
			event.Interface(k, v)
		}
		event.Msg(t.message)
	}

	return elapsed
}

// DoneInfo logs at info level.
func (t *Timer) DoneInfo() time.Duration {
	elapsed := time.Since(t.startTime)

	if t.logger != nil {
		event := t.logger.Info()
		event.Int64(FieldLatencyUS, elapsed.Microseconds())
		for k, v := range t.fields {
			event.Interface(k, v)
		}
		event.Msg(t.message)
	}

	return elapsed
}
