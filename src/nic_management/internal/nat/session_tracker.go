// Package nat provides NAT/NAPT translation functionality for the NIC Management service.
package nat

import (
	"context"
	"errors"
	"sync"
	"time"
)

// =============================================================================
// Error Types
// =============================================================================

var (
	// ErrSessionNotFound indicates the session was not found.
	ErrSessionNotFound = errors.New("session not found")
	// ErrSessionExists indicates the session already exists.
	ErrSessionExists = errors.New("session already exists")
	// ErrInvalidProtocol indicates an unsupported protocol.
	ErrInvalidProtocol = errors.New("invalid protocol")
	// ErrInvalidState indicates an invalid state transition.
	ErrInvalidState = errors.New("invalid state transition")
)

// =============================================================================
// Connection State
// =============================================================================

// ConnectionState represents TCP connection states.
type ConnectionState int

const (
	// StateNew indicates SYN sent, waiting for SYN-ACK.
	StateNew ConnectionState = iota
	// StateEstablished indicates connection established.
	StateEstablished
	// StateClosing indicates FIN sent, waiting for FIN-ACK.
	StateClosing
	// StateClosed indicates connection terminated.
	StateClosed
)

// String returns the string representation of the state.
func (s ConnectionState) String() string {
	switch s {
	case StateNew:
		return "NEW"
	case StateEstablished:
		return "ESTABLISHED"
	case StateClosing:
		return "CLOSING"
	case StateClosed:
		return "CLOSED"
	default:
		return "UNKNOWN"
	}
}

// =============================================================================
// Session Structure
// =============================================================================

// Session represents an active NAT session.
type Session struct {
	// MappingID is the associated NAT mapping ID.
	MappingID string `json:"mapping_id"`
	// Protocol is the protocol ("TCP", "UDP", "ICMP").
	Protocol string `json:"protocol"`
	// State is the current TCP connection state.
	State ConnectionState `json:"state"`
	// CreatedAt is the session creation timestamp.
	CreatedAt time.Time `json:"created_at"`
	// LastActivity is the last packet timestamp.
	LastActivity time.Time `json:"last_activity"`
	// ExpiresAt is the session expiration time.
	ExpiresAt time.Time `json:"expires_at"`
	// Timeout is the session timeout duration.
	Timeout time.Duration `json:"timeout"`
	// PacketCount is the total packets in session.
	PacketCount uint64 `json:"packet_count"`
	// ByteCount is the total bytes in session.
	ByteCount uint64 `json:"byte_count"`
	// IsKeepalive indicates keepalive is enabled.
	IsKeepalive bool `json:"is_keepalive"`
}

// =============================================================================
// Session Filters
// =============================================================================

// SessionFilters contains query filters for sessions.
type SessionFilters struct {
	// Protocol filters by protocol.
	Protocol string
	// State filters by TCP state.
	State *ConnectionState
	// ActiveOnly excludes expired sessions.
	ActiveOnly bool
}

// =============================================================================
// Session Statistics
// =============================================================================

// SessionStatistics contains aggregate session statistics.
type SessionStatistics struct {
	// TotalSessions is the total active sessions.
	TotalSessions int `json:"total_sessions"`
	// TCPSessions is the TCP session count.
	TCPSessions int `json:"tcp_sessions"`
	// UDPSessions is the UDP session count.
	UDPSessions int `json:"udp_sessions"`
	// ICMPSessions is the ICMP session count.
	ICMPSessions int `json:"icmp_sessions"`
	// NewConnections is the TCP StateNew count.
	NewConnections int `json:"new_connections"`
	// EstablishedConnections is the TCP StateEstablished count.
	EstablishedConnections int `json:"established_connections"`
	// ClosingConnections is the TCP StateClosing count.
	ClosingConnections int `json:"closing_connections"`
	// ClosedConnections is the TCP StateClosed count.
	ClosedConnections int `json:"closed_connections"`
	// TotalPackets is the aggregate packet count.
	TotalPackets uint64 `json:"total_packets"`
	// TotalBytes is the aggregate byte count.
	TotalBytes uint64 `json:"total_bytes"`
}

// =============================================================================
// Session Tracker Configuration
// =============================================================================

// SessionTrackerConfig contains configuration for the session tracker.
type SessionTrackerConfig struct {
	// TCPTimeout is the TCP session timeout.
	TCPTimeout time.Duration `json:"tcp_timeout"`
	// UDPTimeout is the UDP session timeout.
	UDPTimeout time.Duration `json:"udp_timeout"`
	// ICMPTimeout is the ICMP session timeout.
	ICMPTimeout time.Duration `json:"icmp_timeout"`
	// EstablishedTCPTimeout is the established TCP timeout.
	EstablishedTCPTimeout time.Duration `json:"established_tcp_timeout"`
	// CheckInterval is the timeout check interval.
	CheckInterval time.Duration `json:"check_interval"`
	// EnableKeepalive enables session keepalive.
	EnableKeepalive bool `json:"enable_keepalive"`
	// KeepaliveInterval is the keepalive packet interval.
	KeepaliveInterval time.Duration `json:"keepalive_interval"`
	// EnableActivityTracking tracks packet/byte counts.
	EnableActivityTracking bool `json:"enable_activity_tracking"`
}

// DefaultSessionTrackerConfig returns the default configuration.
func DefaultSessionTrackerConfig() *SessionTrackerConfig {
	return &SessionTrackerConfig{
		TCPTimeout:             5 * time.Minute,
		UDPTimeout:             3 * time.Minute,
		ICMPTimeout:            30 * time.Second,
		EstablishedTCPTimeout:  2 * time.Hour,
		CheckInterval:          30 * time.Second,
		EnableKeepalive:        false,
		KeepaliveInterval:      60 * time.Second,
		EnableActivityTracking: true,
	}
}

// =============================================================================
// Session Tracker
// =============================================================================

// SessionTracker manages NAT session lifecycle tracking.
type SessionTracker struct {
	// Active sessions map.
	sessions map[string]*Session
	// Read-write mutex.
	mu sync.RWMutex
	// Configuration.
	config *SessionTrackerConfig
	// Control channels.
	stopChan  chan struct{}
	wg        sync.WaitGroup
	running   bool
	runningMu sync.Mutex
	// Callback for expired session cleanup.
	onSessionExpired func(mappingID string)
}

// NewSessionTracker creates a new session tracker.
func NewSessionTracker(config *SessionTrackerConfig) *SessionTracker {
	if config == nil {
		config = DefaultSessionTrackerConfig()
	}

	return &SessionTracker{
		sessions: make(map[string]*Session),
		config:   config,
		stopChan: make(chan struct{}),
	}
}

// SetOnSessionExpired sets the callback for expired sessions.
func (st *SessionTracker) SetOnSessionExpired(callback func(mappingID string)) {
	st.onSessionExpired = callback
}

// =============================================================================
// Lifecycle Management
// =============================================================================

// Start starts the background timeout checker.
func (st *SessionTracker) Start(ctx context.Context) error {
	st.runningMu.Lock()
	defer st.runningMu.Unlock()

	if st.running {
		return nil
	}

	st.wg.Add(1)
	go st.timeoutLoop()

	st.running = true
	return nil
}

// Stop stops the background tasks.
func (st *SessionTracker) Stop() error {
	st.runningMu.Lock()
	if !st.running {
		st.runningMu.Unlock()
		return nil
	}
	st.running = false
	st.runningMu.Unlock()

	close(st.stopChan)
	st.wg.Wait()

	return nil
}

// timeoutLoop runs the periodic timeout checker.
func (st *SessionTracker) timeoutLoop() {
	defer st.wg.Done()

	ticker := time.NewTicker(st.config.CheckInterval)
	defer ticker.Stop()

	for {
		select {
		case <-st.stopChan:
			return
		case <-ticker.C:
			st.checkTimeouts()
		}
	}
}

// =============================================================================
// Session Management
// =============================================================================

// AddSession creates a new session for a NAT mapping.
func (st *SessionTracker) AddSession(ctx context.Context, mappingID string, protocol string) error {
	if mappingID == "" {
		return ErrSessionNotFound
	}

	if protocol != "TCP" && protocol != "UDP" && protocol != "ICMP" {
		return ErrInvalidProtocol
	}

	st.mu.Lock()
	defer st.mu.Unlock()

	if _, exists := st.sessions[mappingID]; exists {
		return ErrSessionExists
	}

	now := time.Now()
	timeout := st.calculateTimeout(protocol, StateNew)

	session := &Session{
		MappingID:    mappingID,
		Protocol:     protocol,
		State:        StateNew,
		CreatedAt:    now,
		LastActivity: now,
		ExpiresAt:    now.Add(timeout),
		Timeout:      timeout,
		PacketCount:  0,
		ByteCount:    0,
		IsKeepalive:  false,
	}

	st.sessions[mappingID] = session
	return nil
}

// RemoveSession removes a session.
func (st *SessionTracker) RemoveSession(ctx context.Context, mappingID string) error {
	st.mu.Lock()
	defer st.mu.Unlock()

	if _, exists := st.sessions[mappingID]; !exists {
		return ErrSessionNotFound
	}

	delete(st.sessions, mappingID)
	return nil
}

// UpdateActivity updates session activity and extends timeout.
func (st *SessionTracker) UpdateActivity(ctx context.Context, mappingID string, packetSize uint64) error {
	st.mu.Lock()
	defer st.mu.Unlock()

	session, exists := st.sessions[mappingID]
	if !exists {
		return ErrSessionNotFound
	}

	now := time.Now()
	session.LastActivity = now
	session.ExpiresAt = now.Add(session.Timeout)

	if st.config.EnableActivityTracking {
		session.PacketCount++
		session.ByteCount += packetSize
	}

	return nil
}

// UpdateTCPState updates TCP connection state based on packet flags.
func (st *SessionTracker) UpdateTCPState(ctx context.Context, mappingID string, tcpFlags uint8) error {
	const (
		tcpFIN = 0x01
		tcpSYN = 0x02
		tcpRST = 0x04
		tcpACK = 0x10
	)

	st.mu.Lock()
	defer st.mu.Unlock()

	session, exists := st.sessions[mappingID]
	if !exists {
		return ErrSessionNotFound
	}

	if session.Protocol != "TCP" {
		return ErrInvalidProtocol
	}

	now := time.Now()
	var newState ConnectionState

	if tcpFlags&tcpRST != 0 {
		// RST - immediate close.
		newState = StateClosed
		session.ExpiresAt = now // Immediate expiration.
	} else if tcpFlags&tcpFIN != 0 {
		// FIN - closing.
		newState = StateClosing
		session.Timeout = 30 * time.Second
		session.ExpiresAt = now.Add(session.Timeout)
	} else if tcpFlags&tcpSYN != 0 && tcpFlags&tcpACK != 0 {
		// SYN-ACK - established.
		newState = StateEstablished
		session.Timeout = st.config.EstablishedTCPTimeout
		session.ExpiresAt = now.Add(session.Timeout)
	} else if tcpFlags&tcpSYN != 0 {
		// SYN - new.
		newState = StateNew
	} else {
		// No state change for other flags.
		newState = session.State
	}

	session.State = newState
	session.LastActivity = now

	return nil
}

// =============================================================================
// Timeout Management
// =============================================================================

// checkTimeouts checks for and removes expired sessions.
func (st *SessionTracker) checkTimeouts() {
	st.mu.Lock()
	defer st.mu.Unlock()

	now := time.Now()
	var expired []string

	for id, session := range st.sessions {
		if st.shouldExpire(session, now) {
			expired = append(expired, id)
		}
	}

	for _, id := range expired {
		delete(st.sessions, id)

		// Call callback if set.
		if st.onSessionExpired != nil {
			go st.onSessionExpired(id)
		}
	}
}

// shouldExpire checks if a session should expire.
func (st *SessionTracker) shouldExpire(session *Session, now time.Time) bool {
	// Always expire closed TCP connections.
	if session.Protocol == "TCP" && session.State == StateClosed {
		return true
	}

	// Check expiration time.
	return now.After(session.ExpiresAt)
}

// calculateTimeout returns timeout based on protocol and state.
func (st *SessionTracker) calculateTimeout(protocol string, state ConnectionState) time.Duration {
	switch protocol {
	case "TCP":
		switch state {
		case StateNew:
			return st.config.TCPTimeout
		case StateEstablished:
			return st.config.EstablishedTCPTimeout
		case StateClosing:
			return 30 * time.Second
		case StateClosed:
			return 0
		default:
			return st.config.TCPTimeout
		}
	case "UDP":
		return st.config.UDPTimeout
	case "ICMP":
		return st.config.ICMPTimeout
	default:
		return st.config.UDPTimeout
	}
}

// ExtendTimeout manually extends session timeout.
func (st *SessionTracker) ExtendTimeout(ctx context.Context, mappingID string, extension time.Duration) error {
	st.mu.Lock()
	defer st.mu.Unlock()

	session, exists := st.sessions[mappingID]
	if !exists {
		return ErrSessionNotFound
	}

	session.ExpiresAt = session.ExpiresAt.Add(extension)
	return nil
}

// ForceExpire immediately expires a session.
func (st *SessionTracker) ForceExpire(ctx context.Context, mappingID string) error {
	st.mu.Lock()
	defer st.mu.Unlock()

	session, exists := st.sessions[mappingID]
	if !exists {
		return ErrSessionNotFound
	}

	session.ExpiresAt = time.Now().Add(-1 * time.Second)
	return nil
}

// =============================================================================
// Query Operations
// =============================================================================

// GetSession retrieves a session by mapping ID.
func (st *SessionTracker) GetSession(ctx context.Context, mappingID string) (*Session, error) {
	st.mu.RLock()
	defer st.mu.RUnlock()

	session, exists := st.sessions[mappingID]
	if !exists {
		return nil, ErrSessionNotFound
	}

	// Return a copy.
	copy := *session
	return &copy, nil
}

// ListSessions retrieves all sessions with optional filtering.
func (st *SessionTracker) ListSessions(ctx context.Context, filters *SessionFilters) ([]*Session, error) {
	st.mu.RLock()
	defer st.mu.RUnlock()

	now := time.Now()
	result := make([]*Session, 0, len(st.sessions))

	for _, session := range st.sessions {
		if st.matchesFilters(session, filters, now) {
			copy := *session
			result = append(result, &copy)
		}
	}

	return result, nil
}

// matchesFilters checks if a session matches the filters.
func (st *SessionTracker) matchesFilters(session *Session, filters *SessionFilters, now time.Time) bool {
	if filters == nil {
		return true
	}

	if filters.Protocol != "" && session.Protocol != filters.Protocol {
		return false
	}

	if filters.State != nil && session.State != *filters.State {
		return false
	}

	if filters.ActiveOnly && now.After(session.ExpiresAt) {
		return false
	}

	return true
}

// GetSessionCount returns the count of active sessions.
func (st *SessionTracker) GetSessionCount() int {
	st.mu.RLock()
	defer st.mu.RUnlock()
	return len(st.sessions)
}

// GetSessionStatistics returns aggregate session statistics.
func (st *SessionTracker) GetSessionStatistics() *SessionStatistics {
	st.mu.RLock()
	defer st.mu.RUnlock()

	stats := &SessionStatistics{}

	for _, session := range st.sessions {
		stats.TotalSessions++
		stats.TotalPackets += session.PacketCount
		stats.TotalBytes += session.ByteCount

		switch session.Protocol {
		case "TCP":
			stats.TCPSessions++
			switch session.State {
			case StateNew:
				stats.NewConnections++
			case StateEstablished:
				stats.EstablishedConnections++
			case StateClosing:
				stats.ClosingConnections++
			case StateClosed:
				stats.ClosedConnections++
			}
		case "UDP":
			stats.UDPSessions++
		case "ICMP":
			stats.ICMPSessions++
		}
	}

	return stats
}

// GetInactiveSessions finds sessions with no recent activity.
func (st *SessionTracker) GetInactiveSessions(ctx context.Context, inactivityThreshold time.Duration) ([]*Session, error) {
	st.mu.RLock()
	defer st.mu.RUnlock()

	now := time.Now()
	result := make([]*Session, 0)

	for _, session := range st.sessions {
		if now.Sub(session.LastActivity) > inactivityThreshold {
			copy := *session
			result = append(result, &copy)
		}
	}

	return result, nil
}

// =============================================================================
// Keepalive Management
// =============================================================================

// EnableKeepalive enables keepalive for a session.
func (st *SessionTracker) EnableKeepalive(ctx context.Context, mappingID string) error {
	st.mu.Lock()
	defer st.mu.Unlock()

	session, exists := st.sessions[mappingID]
	if !exists {
		return ErrSessionNotFound
	}

	session.IsKeepalive = true
	return nil
}

// DisableKeepalive disables keepalive for a session.
func (st *SessionTracker) DisableKeepalive(ctx context.Context, mappingID string) error {
	st.mu.Lock()
	defer st.mu.Unlock()

	session, exists := st.sessions[mappingID]
	if !exists {
		return ErrSessionNotFound
	}

	session.IsKeepalive = false
	return nil
}

// GetKeepaliveSessions returns sessions with keepalive enabled.
func (st *SessionTracker) GetKeepaliveSessions() []*Session {
	st.mu.RLock()
	defer st.mu.RUnlock()

	result := make([]*Session, 0)
	for _, session := range st.sessions {
		if session.IsKeepalive {
			copy := *session
			result = append(result, &copy)
		}
	}

	return result
}

// =============================================================================
// Utility Functions
// =============================================================================

// GetConfig returns the current configuration.
func (st *SessionTracker) GetConfig() *SessionTrackerConfig {
	return st.config
}

// IsRunning returns whether the tracker is running.
func (st *SessionTracker) IsRunning() bool {
	st.runningMu.Lock()
	defer st.runningMu.Unlock()
	return st.running
}

// Clear removes all sessions.
func (st *SessionTracker) Clear() {
	st.mu.Lock()
	defer st.mu.Unlock()
	st.sessions = make(map[string]*Session)
}
