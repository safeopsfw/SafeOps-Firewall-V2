// Package logging provides structured logging for the firewall engine.
package logging

// ============================================================================
// Standard Field Names - Connection
// ============================================================================

// Connection fields are used for every packet log entry.
const (
	// FieldSrcIP is the source IP address.
	FieldSrcIP = "src_ip"

	// FieldSrcPort is the source port number.
	FieldSrcPort = "src_port"

	// FieldDstIP is the destination IP address.
	FieldDstIP = "dst_ip"

	// FieldDstPort is the destination port number.
	FieldDstPort = "dst_port"

	// FieldProtocol is the network protocol (TCP, UDP, ICMP).
	FieldProtocol = "protocol"

	// FieldFlowID is the unique identifier for a connection flow.
	FieldFlowID = "flow_id"

	// FieldDirection is the packet direction (inbound, outbound).
	FieldDirection = "direction"

	// FieldInterface is the network interface name.
	FieldInterface = "interface"

	// FieldPacketSize is the packet size in bytes.
	FieldPacketSize = "packet_size"

	// FieldTTL is the IP time-to-live value.
	FieldTTL = "ttl"
)

// ============================================================================
// Standard Field Names - Verdict
// ============================================================================

// Verdict fields are used when logging firewall decisions.
const (
	// FieldAction is the firewall action (allow, deny, drop).
	FieldAction = "action"

	// FieldVerdict is the verdict result.
	FieldVerdict = "verdict"

	// FieldRule is the matched rule name.
	FieldRule = "rule"

	// FieldRuleID is the matched rule ID.
	FieldRuleID = "rule_id"

	// FieldRulePriority is the rule priority.
	FieldRulePriority = "rule_priority"

	// FieldEngine is the enforcement engine (safeops, wfp, dual).
	FieldEngine = "engine"

	// FieldReason is the reason for the verdict.
	FieldReason = "reason"

	// FieldMatchType is the type of rule match.
	FieldMatchType = "match_type"

	// FieldZone is the firewall zone.
	FieldZone = "zone"

	// FieldCategory is the rule category.
	FieldCategory = "category"
)

// ============================================================================
// Standard Field Names - Performance
// ============================================================================

// Performance fields are used for latency and timing information.
const (
	// FieldLatencyUS is the processing latency in microseconds.
	FieldLatencyUS = "latency_us"

	// FieldLatencyMS is the processing latency in milliseconds.
	FieldLatencyMS = "latency_ms"

	// FieldLatencyNS is the processing latency in nanoseconds.
	FieldLatencyNS = "latency_ns"

	// FieldCacheHit indicates whether the result was from cache.
	FieldCacheHit = "cache_hit"

	// FieldCacheTTL is the cache entry TTL.
	FieldCacheTTL = "cache_ttl"

	// FieldRuleEvalTimeUS is the rule evaluation time in microseconds.
	FieldRuleEvalTimeUS = "rule_eval_time_us"

	// FieldQueueTime is the time spent in queue.
	FieldQueueTime = "queue_time_us"

	// FieldProcessingTime is the total processing time.
	FieldProcessingTime = "processing_time_us"

	// FieldThroughput is the throughput in packets/second.
	FieldThroughput = "throughput_pps"
)

// ============================================================================
// Standard Field Names - Application (WFP)
// ============================================================================

// Application fields are used for application-aware filtering.
const (
	// FieldAppName is the application name (e.g., chrome.exe).
	FieldAppName = "app_name"

	// FieldAppPath is the full path to the application.
	FieldAppPath = "app_path"

	// FieldPID is the process ID.
	FieldPID = "pid"

	// FieldParentPID is the parent process ID.
	FieldParentPID = "parent_pid"

	// FieldUserName is the username running the process.
	FieldUserName = "user_name"

	// FieldUserSID is the Windows Security ID.
	FieldUserSID = "user_sid"
)

// ============================================================================
// Standard Field Names - Domain
// ============================================================================

// Domain fields are used for DNS-related information.
const (
	// FieldDomain is the domain name.
	FieldDomain = "domain"

	// FieldDstDomain is the destination domain name.
	FieldDstDomain = "dst_domain"

	// FieldDNSTTL is the DNS TTL value.
	FieldDNSTTL = "dns_ttl"

	// FieldDNSResolvedAt is the timestamp when DNS was resolved.
	FieldDNSResolvedAt = "dns_resolved_at"

	// FieldDNSQueryType is the DNS query type (A, AAAA, CNAME).
	FieldDNSQueryType = "dns_query_type"

	// FieldDNSServer is the DNS server that resolved the query.
	FieldDNSServer = "dns_server"

	// FieldSNI is the TLS Server Name Indication.
	FieldSNI = "sni"

	// FieldHostHeader is the HTTP Host header.
	FieldHostHeader = "host_header"
)

// ============================================================================
// Standard Field Names - System
// ============================================================================

// System fields are used for component and request tracking.
const (
	// FieldComponent is the component name.
	FieldComponent = "component"

	// FieldRequestID is the unique request identifier.
	FieldRequestID = "request_id"

	// FieldTraceID is the distributed trace ID.
	FieldTraceID = "trace_id"

	// FieldSpanID is the span ID within a trace.
	FieldSpanID = "span_id"

	// FieldVersion is the application version.
	FieldVersion = "version"

	// FieldEnvironment is the deployment environment.
	FieldEnvironment = "environment"

	// FieldInstance is the instance identifier.
	FieldInstance = "instance"

	// FieldHostname is the hostname.
	FieldHostname = "hostname"
)

// ============================================================================
// Standard Field Names - Error
// ============================================================================

// Error fields are used for error reporting.
const (
	// FieldError is the error message.
	FieldError = "error"

	// FieldErrorCode is the error code.
	FieldErrorCode = "error_code"

	// FieldErrorType is the error type.
	FieldErrorType = "error_type"

	// FieldStackTrace is the stack trace.
	FieldStackTrace = "stack_trace"

	// FieldRetryCount is the retry attempt count.
	FieldRetryCount = "retry_count"
)

// ============================================================================
// Standard Field Names - Statistics
// ============================================================================

// Statistics fields are used for counters and metrics.
const (
	// FieldCount is a generic count field.
	FieldCount = "count"

	// FieldTotal is a total count.
	FieldTotal = "total"

	// FieldPacketsAllowed is the number of allowed packets.
	FieldPacketsAllowed = "packets_allowed"

	// FieldPacketsDenied is the number of denied packets.
	FieldPacketsDenied = "packets_denied"

	// FieldBytesIn is incoming bytes.
	FieldBytesIn = "bytes_in"

	// FieldBytesOut is outgoing bytes.
	FieldBytesOut = "bytes_out"

	// FieldActiveConnections is the number of active connections.
	FieldActiveConnections = "active_connections"

	// FieldCacheSize is the cache size.
	FieldCacheSize = "cache_size"

	// FieldCacheHitRate is the cache hit rate.
	FieldCacheHitRate = "cache_hit_rate"

	// FieldRuleCount is the number of rules.
	FieldRuleCount = "rule_count"

	// FieldFilterCount is the number of WFP filters.
	FieldFilterCount = "filter_count"
)

// ============================================================================
// Standard Field Values - Actions
// ============================================================================

// Action values for FieldAction.
const (
	// ActionAllow indicates the packet was allowed.
	ActionAllow = "allow"

	// ActionDeny indicates the packet was denied.
	ActionDeny = "deny"

	// ActionDrop indicates the packet was dropped silently.
	ActionDrop = "drop"

	// ActionReject indicates the packet was rejected with response.
	ActionReject = "reject"

	// ActionRedirect indicates the packet was redirected.
	ActionRedirect = "redirect"

	// ActionLog indicates the packet was logged only.
	ActionLog = "log"

	// ActionQueue indicates the packet was queued for inspection.
	ActionQueue = "queue"
)

// ============================================================================
// Standard Field Values - Engines
// ============================================================================

// Engine values for FieldEngine.
const (
	// EngineSafeOps indicates the SafeOps kernel engine.
	EngineSafeOps = "safeops"

	// EngineWFP indicates the Windows Filtering Platform.
	EngineWFP = "wfp"

	// EngineDual indicates both engines were used.
	EngineDual = "dual"

	// EngineNone indicates no engine was used.
	EngineNone = "none"
)

// ============================================================================
// Standard Field Values - Reasons
// ============================================================================

// Reason values for FieldReason.
const (
	// ReasonCacheHit indicates the verdict came from cache.
	ReasonCacheHit = "cache_hit"

	// ReasonRuleMatch indicates a rule was matched.
	ReasonRuleMatch = "rule_match"

	// ReasonDefaultPolicy indicates the default policy was applied.
	ReasonDefaultPolicy = "default_policy"

	// ReasonWhitelist indicates the target was whitelisted.
	ReasonWhitelist = "whitelist"

	// ReasonBlocklist indicates the target was blocklisted.
	ReasonBlocklist = "blocklist"

	// ReasonThreatIntel indicates threat intelligence matched.
	ReasonThreatIntel = "threat_intel"

	// ReasonRateLimit indicates rate limiting was applied.
	ReasonRateLimit = "rate_limit"

	// ReasonGeoIP indicates GeoIP filtering was applied.
	ReasonGeoIP = "geoip"

	// ReasonApplication indicates app-based filtering was applied.
	ReasonApplication = "application"

	// ReasonTimeout indicates a timeout occurred.
	ReasonTimeout = "timeout"
)

// ============================================================================
// Standard Field Values - Components
// ============================================================================

// Component values for FieldComponent.
const (
	// ComponentMain is the main application component.
	ComponentMain = "main"

	// ComponentRuleManager is the rule manager component.
	ComponentRuleManager = "rule_manager"

	// ComponentSafeOpsClient is the SafeOps gRPC client.
	ComponentSafeOpsClient = "safeops_client"

	// ComponentWFPEngine is the WFP engine.
	ComponentWFPEngine = "wfp_engine"

	// ComponentVerdictCache is the verdict cache.
	ComponentVerdictCache = "verdict_cache"

	// ComponentConnTracker is the connection tracker.
	ComponentConnTracker = "conn_tracker"

	// ComponentPacketInspector is the packet inspector.
	ComponentPacketInspector = "packet_inspector"

	// ComponentEnforcement is the enforcement handler.
	ComponentEnforcement = "enforcement"

	// ComponentDualEngine is the dual engine coordinator.
	ComponentDualEngine = "dual_engine"

	// ComponentMetrics is the metrics collector.
	ComponentMetrics = "metrics"

	// ComponentHealth is the health monitor.
	ComponentHealth = "health"

	// ComponentAPI is the management API.
	ComponentAPI = "api"

	// ComponentConfig is the configuration loader.
	ComponentConfig = "config"
)

// ============================================================================
// Standard Field Values - Protocols
// ============================================================================

// Protocol values for FieldProtocol.
const (
	// ProtocolTCP is TCP protocol.
	ProtocolTCP = "TCP"

	// ProtocolUDP is UDP protocol.
	ProtocolUDP = "UDP"

	// ProtocolICMP is ICMP protocol.
	ProtocolICMP = "ICMP"

	// ProtocolICMPv6 is ICMPv6 protocol.
	ProtocolICMPv6 = "ICMPv6"

	// ProtocolUnknown is unknown protocol.
	ProtocolUnknown = "UNKNOWN"
)

// ============================================================================
// Standard Field Values - Directions
// ============================================================================

// Direction values for FieldDirection.
const (
	// DirectionInbound is inbound traffic.
	DirectionInbound = "inbound"

	// DirectionOutbound is outbound traffic.
	DirectionOutbound = "outbound"

	// DirectionForward is forwarded traffic.
	DirectionForward = "forward"
)

// ============================================================================
// Standard Field Values - Match Types
// ============================================================================

// MatchType values for FieldMatchType.
const (
	// MatchTypeIP indicates IP address match.
	MatchTypeIP = "ip"

	// MatchTypeDomain indicates domain match.
	MatchTypeDomain = "domain"

	// MatchTypePort indicates port match.
	MatchTypePort = "port"

	// MatchTypeProtocol indicates protocol match.
	MatchTypeProtocol = "protocol"

	// MatchTypeApplication indicates application match.
	MatchTypeApplication = "application"

	// MatchTypeZone indicates zone match.
	MatchTypeZone = "zone"

	// MatchTypeGeoIP indicates GeoIP match.
	MatchTypeGeoIP = "geoip"

	// MatchTypeAll indicates all conditions matched.
	MatchTypeAll = "all"
)
