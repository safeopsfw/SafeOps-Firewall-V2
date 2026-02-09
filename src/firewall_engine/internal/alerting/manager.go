package alerting

import (
	"context"
	"fmt"
	"sync"
	"sync/atomic"
	"time"

	"github.com/google/uuid"
)

// ManagerStats holds alert pipeline statistics
type ManagerStats struct {
	TotalAlerts     int64            `json:"total_alerts"`
	Throttled       int64            `json:"throttled"`
	Written         int64            `json:"written"`
	DBLogged        int64            `json:"db_logged"`
	Errors          int64            `json:"errors"`
	BySeverity      map[string]int64 `json:"by_severity"`
	ByType          map[string]int64 `json:"by_type"`
}

// Manager is the central alert dispatcher.
// Alert() → throttle check → format → write to file + DB
type Manager struct {
	writer    *Writer
	throttle  *Throttle
	dbLogger  *DBLogger
	alertChan chan *Alert

	// Stats (atomic for lock-free reads)
	totalAlerts atomic.Int64
	throttled   atomic.Int64
	written     atomic.Int64
	dbLogged    atomic.Int64
	errors      atomic.Int64

	// Per-severity and per-type counters (mutex-protected)
	mu         sync.Mutex
	bySeverity map[Severity]int64
	byType     map[AlertType]int64

	cancel context.CancelFunc
	wg     sync.WaitGroup
}

// NewManager creates a new alert manager
func NewManager(alertDir string, maxFileSizeMB int, throttleWindowSeconds int, dbLogger *DBLogger) (*Manager, error) {
	writer, err := NewWriter(alertDir, maxFileSizeMB)
	if err != nil {
		return nil, fmt.Errorf("failed to create alert writer: %w", err)
	}

	m := &Manager{
		writer:     writer,
		throttle:   NewThrottle(throttleWindowSeconds),
		dbLogger:   dbLogger,
		alertChan:  make(chan *Alert, 10000),
		bySeverity: make(map[Severity]int64),
		byType:     make(map[AlertType]int64),
	}

	return m, nil
}

// Start begins the background alert processing goroutines
func (m *Manager) Start(ctx context.Context) {
	ctx, m.cancel = context.WithCancel(ctx)

	// Alert processing goroutine
	m.wg.Add(1)
	go func() {
		defer m.wg.Done()
		m.processLoop(ctx)
	}()

	// Periodic flush goroutine
	m.wg.Add(1)
	go func() {
		defer m.wg.Done()
		m.flushLoop(ctx)
	}()

	// Throttle cleanup goroutine
	m.wg.Add(1)
	go func() {
		defer m.wg.Done()
		m.cleanupLoop(ctx)
	}()
}

// Alert submits an alert for processing. Non-blocking — drops if buffer full.
func (m *Manager) Alert(alert *Alert) {
	if alert.ID == "" {
		alert.ID = uuid.New().String()
	}
	m.totalAlerts.Add(1)

	m.mu.Lock()
	m.bySeverity[alert.Severity]++
	m.byType[alert.Type]++
	m.mu.Unlock()

	select {
	case m.alertChan <- alert:
	default:
		// Channel full — drop to avoid blocking the packet pipeline
		m.errors.Add(1)
	}
}

// Stop gracefully shuts down the alert manager
func (m *Manager) Stop() {
	if m.cancel != nil {
		m.cancel()
	}
	m.wg.Wait()

	// Flush any remaining throttled alerts
	remaining := m.throttle.FlushAll()
	for _, alert := range remaining {
		m.writeAlert(alert)
	}

	// Drain remaining alerts in channel
	close(m.alertChan)
	for alert := range m.alertChan {
		emit, aggregated := m.throttle.Check(alert)
		if emit && aggregated != nil {
			m.writeAlert(aggregated)
		}
	}

	// Final flush
	m.writer.Flush()
	m.writer.Close()

	if m.dbLogger != nil {
		m.dbLogger.Flush()
		m.dbLogger.Close()
	}
}

// GetStats returns a snapshot of alert statistics
func (m *Manager) GetStats() ManagerStats {
	m.mu.Lock()
	bySev := make(map[string]int64, len(m.bySeverity))
	for k, v := range m.bySeverity {
		bySev[k.String()] = v
	}
	byType := make(map[string]int64, len(m.byType))
	for k, v := range m.byType {
		byType[string(k)] = v
	}
	m.mu.Unlock()

	return ManagerStats{
		TotalAlerts: m.totalAlerts.Load(),
		Throttled:   m.throttled.Load(),
		Written:     m.written.Load(),
		DBLogged:    m.dbLogged.Load(),
		Errors:      m.errors.Load(),
		BySeverity:  bySev,
		ByType:      byType,
	}
}

func (m *Manager) processLoop(ctx context.Context) {
	for {
		select {
		case <-ctx.Done():
			return
		case alert, ok := <-m.alertChan:
			if !ok {
				return
			}
			emit, aggregated := m.throttle.Check(alert)
			if !emit {
				m.throttled.Add(1)
				continue
			}
			if aggregated != nil {
				m.writeAlert(aggregated)
			}
		}
	}
}

func (m *Manager) flushLoop(ctx context.Context) {
	ticker := time.NewTicker(1 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			m.writer.Flush()
			if m.dbLogger != nil {
				m.dbLogger.Flush()
			}
		}
	}
}

func (m *Manager) cleanupLoop(ctx context.Context) {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			m.throttle.Cleanup()
		}
	}
}

func (m *Manager) writeAlert(alert *Alert) {
	// Write JSON line to file
	data, err := FormatJSON(alert)
	if err != nil {
		m.errors.Add(1)
		return
	}

	if err := m.writer.Write(data); err != nil {
		m.errors.Add(1)
		return
	}
	m.written.Add(1)

	// Write to DB if available
	if m.dbLogger != nil {
		m.dbLogger.Log(alert)
		m.dbLogged.Add(1)
	}
}
