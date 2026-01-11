package nat

import (
	"net"
	"sync"
	"time"
)

// ConnectionState tracks TCP connection lifecycle
type ConnectionState int

const (
	StateNew ConnectionState = iota
	StateSynSent
	StateEstablished
	StateFinWait
	StateClosed
)

func (s ConnectionState) String() string {
	switch s {
	case StateNew:
		return "NEW"
	case StateSynSent:
		return "SYN_SENT"
	case StateEstablished:
		return "ESTABLISHED"
	case StateFinWait:
		return "FIN_WAIT"
	case StateClosed:
		return "CLOSED"
	default:
		return "UNKNOWN"
	}
}

// Connection represents a tracked network connection
type Connection struct {
	FlowID      string
	SrcIP       net.IP
	SrcPort     uint16
	DstIP       net.IP
	DstPort     uint16
	Protocol    uint8
	State       ConnectionState
	CreatedAt   time.Time
	LastSeenAt  time.Time
	BytesSent   uint64
	BytesRecv   uint64
	PacketsSent uint64
	PacketsRecv uint64
}

// Engine tracks NAT connections for statistics and state management
type Engine struct {
	connections map[string]*Connection
	mu          sync.RWMutex
}

// NewEngine creates a new NAT engine
func NewEngine() *Engine {
	e := &Engine{
		connections: make(map[string]*Connection),
	}

	// Start cleanup worker
	go e.cleanupWorker()

	return e
}

// TrackOutbound tracks an outbound packet and returns connection info
func (e *Engine) TrackOutbound(flowID string, srcIP net.IP, srcPort uint16, dstIP net.IP, dstPort uint16, protocol uint8, size int) *Connection {
	e.mu.Lock()
	defer e.mu.Unlock()

	conn, exists := e.connections[flowID]
	if !exists {
		conn = &Connection{
			FlowID:     flowID,
			SrcIP:      srcIP,
			SrcPort:    srcPort,
			DstIP:      dstIP,
			DstPort:    dstPort,
			Protocol:   protocol,
			State:      StateNew,
			CreatedAt:  time.Now(),
			LastSeenAt: time.Now(),
		}
		e.connections[flowID] = conn
	}

	conn.BytesSent += uint64(size)
	conn.PacketsSent++
	conn.LastSeenAt = time.Now()

	return conn
}

// TrackInbound tracks an inbound packet
func (e *Engine) TrackInbound(flowID string, size int) *Connection {
	e.mu.RLock()
	conn, exists := e.connections[flowID]
	e.mu.RUnlock()

	if !exists {
		return nil
	}

	e.mu.Lock()
	conn.BytesRecv += uint64(size)
	conn.PacketsRecv++
	conn.LastSeenAt = time.Now()
	e.mu.Unlock()

	return conn
}

// UpdateState updates connection state (useful for TCP handshake tracking)
func (e *Engine) UpdateState(flowID string, newState ConnectionState) {
	e.mu.Lock()
	defer e.mu.Unlock()

	if conn, exists := e.connections[flowID]; exists {
		conn.State = newState
		conn.LastSeenAt = time.Now()
	}
}

// GetConnection retrieves connection info
func (e *Engine) GetConnection(flowID string) *Connection {
	e.mu.RLock()
	defer e.mu.RUnlock()

	return e.connections[flowID]
}

// GetStats returns NAT engine statistics
func (e *Engine) GetStats() (total, established, closed int) {
	e.mu.RLock()
	defer e.mu.RUnlock()

	total = len(e.connections)
	for _, conn := range e.connections {
		if conn.State == StateEstablished {
			established++
		} else if conn.State == StateClosed {
			closed++
		}
	}

	return
}

// cleanupWorker removes idle connections every minute
func (e *Engine) cleanupWorker() {
	ticker := time.NewTicker(1 * time.Minute)
	defer ticker.Stop()

	for range ticker.C {
		e.mu.Lock()

		now := time.Now()
		removed := 0

		for flowID, conn := range e.connections {
			// Remove connections idle for >5 minutes
			if now.Sub(conn.LastSeenAt) > 5*time.Minute {
				delete(e.connections, flowID)
				removed++
			}
		}

		e.mu.Unlock()

		// Log cleanup stats periodically
		if removed > 0 {
			// Note: We don't have logger here, so this is silent
			// Can add logging if needed later
		}
	}
}

// Close stops the NAT engine
func (e *Engine) Close() {
	// Cleanup is handled by cleanupWorker goroutine
	// It will stop when program exits
}
