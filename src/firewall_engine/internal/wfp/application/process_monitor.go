// Package application provides real-time process monitoring capabilities.
// The ProcessMonitor observes process lifecycle events (start/stop) and
// notifies subscribers for dynamic application-aware filtering.
package application

import (
	"fmt"
	"strings"
	"sync"
	"syscall"
	"time"
	"unsafe"
)

// ============================================================================
// Process Event Types
// ============================================================================

// ProcessEventType indicates the type of process lifecycle event.
type ProcessEventType int

const (
	// ProcessStart indicates a new process has started.
	ProcessStart ProcessEventType = iota

	// ProcessStop indicates a process has terminated.
	ProcessStop
)

// String returns the string representation of the event type.
func (t ProcessEventType) String() string {
	switch t {
	case ProcessStart:
		return "START"
	case ProcessStop:
		return "STOP"
	default:
		return "UNKNOWN"
	}
}

// ============================================================================
// Process Event
// ============================================================================

// ProcessEvent represents a process lifecycle event.
type ProcessEvent struct {
	// Type is the event type (start or stop).
	Type ProcessEventType

	// PID is the process ID.
	PID uint32

	// PPID is the parent process ID.
	PPID uint32

	// Name is the process executable name (e.g., "chrome.exe").
	Name string

	// Path is the full path to the executable.
	Path string

	// CommandLine is the command line used to start the process.
	// Only available for ProcessStart events and may be empty.
	CommandLine string

	// Timestamp is when the event was detected.
	Timestamp time.Time
}

// String returns a human-readable representation.
func (e *ProcessEvent) String() string {
	return fmt.Sprintf("ProcessEvent[%s, PID=%d, name=%s]",
		e.Type, e.PID, e.Name)
}

// ============================================================================
// Process Snapshot
// ============================================================================

// ProcessSnapshot captures the state of all running processes at a point in time.
type ProcessSnapshot struct {
	// Processes maps PID to ProcessInfo.
	Processes map[uint32]*ProcessSnapshotInfo

	// Timestamp is when the snapshot was taken.
	Timestamp time.Time

	// Count is the number of processes.
	Count int
}

// ProcessSnapshotInfo contains information about a process in a snapshot.
type ProcessSnapshotInfo struct {
	PID         uint32
	PPID        uint32
	Name        string
	Path        string
	ThreadCount uint32
}

// NewProcessSnapshot creates an empty snapshot.
func NewProcessSnapshot() *ProcessSnapshot {
	return &ProcessSnapshot{
		Processes: make(map[uint32]*ProcessSnapshotInfo),
		Timestamp: time.Now(),
	}
}

// Add adds a process to the snapshot.
func (s *ProcessSnapshot) Add(info *ProcessSnapshotInfo) {
	s.Processes[info.PID] = info
	s.Count = len(s.Processes)
}

// Get returns the process info for a PID.
func (s *ProcessSnapshot) Get(pid uint32) (*ProcessSnapshotInfo, bool) {
	info, found := s.Processes[pid]
	return info, found
}

// Contains checks if a PID is in the snapshot.
func (s *ProcessSnapshot) Contains(pid uint32) bool {
	_, found := s.Processes[pid]
	return found
}

// FindByName finds all processes with the given name.
func (s *ProcessSnapshot) FindByName(name string) []*ProcessSnapshotInfo {
	name = strings.ToLower(name)
	results := make([]*ProcessSnapshotInfo, 0)
	for _, info := range s.Processes {
		if strings.ToLower(info.Name) == name {
			results = append(results, info)
		}
	}
	return results
}

// ============================================================================
// Process Monitor
// ============================================================================

// ProcessMonitor monitors process lifecycle events using polling.
// It detects new and terminated processes by comparing snapshots.
type ProcessMonitor struct {
	mu sync.RWMutex

	// State
	running  bool
	stopChan chan struct{}
	doneChan chan struct{}

	// Configuration
	pollInterval time.Duration
	bufferSize   int

	// Subscribers
	subscribers []chan<- ProcessEvent

	// Current state
	lastSnapshot *ProcessSnapshot
	resolver     *Resolver

	// Statistics
	stats MonitorStats
}

// MonitorStats contains monitoring statistics.
type MonitorStats struct {
	StartTime           time.Time
	PollCount           uint64
	EventsEmitted       uint64
	ProcessStarts       uint64
	ProcessStops        uint64
	LastPollTime        time.Time
	LastEventTime       time.Time
	SubscriberCount     int
	CurrentProcessCount int
}

// MonitorConfig configures the process monitor.
type MonitorConfig struct {
	// PollInterval is how often to check for process changes.
	// Default: 1 second. Minimum: 100ms.
	PollInterval time.Duration

	// BufferSize is the size of the event buffer for subscribers.
	// Default: 100 events.
	BufferSize int

	// Resolver is an optional custom resolver for path resolution.
	Resolver *Resolver
}

// DefaultMonitorConfig returns the default monitor configuration.
func DefaultMonitorConfig() *MonitorConfig {
	return &MonitorConfig{
		PollInterval: time.Second,
		BufferSize:   100,
		Resolver:     nil,
	}
}

// NewProcessMonitor creates a new process monitor with default settings.
func NewProcessMonitor(pollInterval time.Duration) *ProcessMonitor {
	cfg := DefaultMonitorConfig()
	if pollInterval > 0 {
		cfg.PollInterval = pollInterval
	}
	return NewProcessMonitorWithConfig(cfg)
}

// NewProcessMonitorWithConfig creates a monitor with custom configuration.
func NewProcessMonitorWithConfig(cfg *MonitorConfig) *ProcessMonitor {
	if cfg == nil {
		cfg = DefaultMonitorConfig()
	}

	// Enforce minimum poll interval
	if cfg.PollInterval < 100*time.Millisecond {
		cfg.PollInterval = 100 * time.Millisecond
	}

	if cfg.BufferSize <= 0 {
		cfg.BufferSize = 100
	}

	resolver := cfg.Resolver
	if resolver == nil {
		resolver = NewResolver()
	}

	return &ProcessMonitor{
		pollInterval: cfg.PollInterval,
		bufferSize:   cfg.BufferSize,
		subscribers:  make([]chan<- ProcessEvent, 0),
		resolver:     resolver,
		stats: MonitorStats{
			StartTime: time.Time{},
		},
	}
}

// ============================================================================
// Lifecycle Methods
// ============================================================================

// Start begins process monitoring.
func (m *ProcessMonitor) Start() error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.running {
		return fmt.Errorf("monitor is already running")
	}

	// Take initial snapshot
	snapshot, err := m.takeSnapshot()
	if err != nil {
		return fmt.Errorf("take initial snapshot: %w", err)
	}
	m.lastSnapshot = snapshot

	// Initialize channels
	m.stopChan = make(chan struct{})
	m.doneChan = make(chan struct{})

	// Start monitoring goroutine
	m.running = true
	m.stats.StartTime = time.Now()
	m.stats.CurrentProcessCount = snapshot.Count

	go m.monitorLoop()

	return nil
}

// Stop stops process monitoring.
func (m *ProcessMonitor) Stop() {
	m.mu.Lock()
	if !m.running {
		m.mu.Unlock()
		return
	}
	m.running = false
	m.mu.Unlock()

	// Signal stop
	close(m.stopChan)

	// Wait for goroutine to finish (with timeout)
	select {
	case <-m.doneChan:
		// Clean exit
	case <-time.After(5 * time.Second):
		// Timeout - goroutine may be stuck
	}

	// Close all subscriber channels
	m.mu.Lock()
	for _, ch := range m.subscribers {
		close(ch)
	}
	m.subscribers = make([]chan<- ProcessEvent, 0)
	m.mu.Unlock()
}

// IsRunning returns true if the monitor is running.
func (m *ProcessMonitor) IsRunning() bool {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.running
}

// ============================================================================
// Subscription Methods
// ============================================================================

// Subscribe creates a new subscription channel for process events.
func (m *ProcessMonitor) Subscribe() <-chan ProcessEvent {
	m.mu.Lock()
	defer m.mu.Unlock()

	ch := make(chan ProcessEvent, m.bufferSize)
	m.subscribers = append(m.subscribers, ch)
	m.stats.SubscriberCount = len(m.subscribers)

	return ch
}

// Unsubscribe removes a subscription channel.
func (m *ProcessMonitor) Unsubscribe(ch <-chan ProcessEvent) {
	m.mu.Lock()
	defer m.mu.Unlock()

	for i, sub := range m.subscribers {
		// Compare channel receivers
		if fmt.Sprintf("%p", sub) == fmt.Sprintf("%p", ch) {
			// Remove from slice
			m.subscribers = append(m.subscribers[:i], m.subscribers[i+1:]...)
			close(sub)
			break
		}
	}
	m.stats.SubscriberCount = len(m.subscribers)
}

// ============================================================================
// Monitor Loop
// ============================================================================

// monitorLoop is the main polling loop.
func (m *ProcessMonitor) monitorLoop() {
	defer close(m.doneChan)

	ticker := time.NewTicker(m.pollInterval)
	defer ticker.Stop()

	for {
		select {
		case <-m.stopChan:
			return
		case <-ticker.C:
			m.poll()
		}
	}
}

// poll takes a snapshot and compares with previous.
func (m *ProcessMonitor) poll() {
	snapshot, err := m.takeSnapshot()
	if err != nil {
		// Log error but continue
		return
	}

	m.mu.Lock()
	lastSnapshot := m.lastSnapshot
	m.lastSnapshot = snapshot
	m.stats.PollCount++
	m.stats.LastPollTime = time.Now()
	m.stats.CurrentProcessCount = snapshot.Count
	m.mu.Unlock()

	if lastSnapshot == nil {
		return
	}

	// Find new processes (in current but not in last)
	for pid, info := range snapshot.Processes {
		if !lastSnapshot.Contains(pid) {
			m.emitEvent(ProcessEvent{
				Type:      ProcessStart,
				PID:       pid,
				PPID:      info.PPID,
				Name:      info.Name,
				Path:      info.Path,
				Timestamp: time.Now(),
			})
		}
	}

	// Find terminated processes (in last but not in current)
	for pid, info := range lastSnapshot.Processes {
		if !snapshot.Contains(pid) {
			m.emitEvent(ProcessEvent{
				Type:      ProcessStop,
				PID:       pid,
				PPID:      info.PPID,
				Name:      info.Name,
				Path:      info.Path,
				Timestamp: time.Now(),
			})
		}
	}
}

// emitEvent sends an event to all subscribers.
func (m *ProcessMonitor) emitEvent(event ProcessEvent) {
	m.mu.Lock()
	subscribers := make([]chan<- ProcessEvent, len(m.subscribers))
	copy(subscribers, m.subscribers)
	m.stats.EventsEmitted++
	m.stats.LastEventTime = event.Timestamp
	if event.Type == ProcessStart {
		m.stats.ProcessStarts++
	} else {
		m.stats.ProcessStops++
	}
	m.mu.Unlock()

	for _, ch := range subscribers {
		select {
		case ch <- event:
			// Sent successfully
		default:
			// Channel full, drop event
		}
	}
}

// ============================================================================
// Snapshot Methods
// ============================================================================

// takeSnapshot captures the current process state.
func (m *ProcessMonitor) takeSnapshot() (*ProcessSnapshot, error) {
	snapshot := NewProcessSnapshot()

	// Create process snapshot
	handle, _, err := procCreateToolhelp.Call(
		uintptr(TH32CS_SNAPPROCESS),
		0,
	)
	if handle == INVALID_HANDLE_VALUE {
		return nil, fmt.Errorf("CreateToolhelp32Snapshot failed: %w", err)
	}
	defer procCloseHandle.Call(handle)

	var pe PROCESSENTRY32W
	pe.dwSize = uint32(unsafe.Sizeof(pe))

	ret, _, _ := procProcess32First.Call(
		handle,
		uintptr(unsafe.Pointer(&pe)),
	)
	if ret == 0 {
		return nil, fmt.Errorf("Process32First failed")
	}

	for {
		name := syscall.UTF16ToString(pe.szExeFile[:])
		path, _ := m.resolver.getProcessPathByPID(pe.th32ProcessID)

		snapshot.Add(&ProcessSnapshotInfo{
			PID:         pe.th32ProcessID,
			PPID:        pe.th32ParentProcessID,
			Name:        name,
			Path:        path,
			ThreadCount: pe.cntThreads,
		})

		ret, _, _ = procProcess32Next.Call(
			handle,
			uintptr(unsafe.Pointer(&pe)),
		)
		if ret == 0 {
			break
		}
	}

	return snapshot, nil
}

// GetSnapshot returns a snapshot of currently running processes.
func (m *ProcessMonitor) GetSnapshot() (*ProcessSnapshot, error) {
	return m.takeSnapshot()
}

// ============================================================================
// Query Methods
// ============================================================================

// IsProcessRunning checks if a process with the given name is running.
func (m *ProcessMonitor) IsProcessRunning(name string) (bool, uint32) {
	return m.resolver.IsProcessRunning(name)
}

// GetProcessPath returns the path for a running process by PID.
func (m *ProcessMonitor) GetProcessPath(pid uint32) (string, error) {
	return m.resolver.getProcessPathByPID(pid)
}

// GetCurrentProcessCount returns the current number of processes.
func (m *ProcessMonitor) GetCurrentProcessCount() int {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.stats.CurrentProcessCount
}

// GetStats returns the current monitoring statistics.
func (m *ProcessMonitor) GetStats() MonitorStats {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.stats
}

// ============================================================================
// Convenience Functions
// ============================================================================

// WaitForProcess waits for a process with the given name to start.
// Returns the PID when found, or error if timeout.
func (m *ProcessMonitor) WaitForProcess(name string, timeout time.Duration) (uint32, error) {
	name = strings.ToLower(name)
	if !strings.HasSuffix(name, ".exe") {
		name += ".exe"
	}

	// Check if already running
	if running, pid := m.IsProcessRunning(name); running {
		return pid, nil
	}

	// Subscribe and wait
	events := m.Subscribe()
	defer m.Unsubscribe(events)

	timer := time.NewTimer(timeout)
	defer timer.Stop()

	for {
		select {
		case event := <-events:
			if event.Type == ProcessStart {
				if strings.ToLower(event.Name) == name {
					return event.PID, nil
				}
			}
		case <-timer.C:
			return 0, fmt.Errorf("timeout waiting for process %s", name)
		}
	}
}

// WaitForProcessTermination waits for a specific PID to terminate.
func (m *ProcessMonitor) WaitForProcessTermination(pid uint32, timeout time.Duration) error {
	// Check if already terminated
	snapshot, err := m.GetSnapshot()
	if err != nil {
		return fmt.Errorf("get snapshot: %w", err)
	}
	if !snapshot.Contains(pid) {
		return nil // Already terminated
	}

	// Subscribe and wait
	events := m.Subscribe()
	defer m.Unsubscribe(events)

	timer := time.NewTimer(timeout)
	defer timer.Stop()

	for {
		select {
		case event := <-events:
			if event.Type == ProcessStop && event.PID == pid {
				return nil
			}
		case <-timer.C:
			return fmt.Errorf("timeout waiting for PID %d to terminate", pid)
		}
	}
}

// OnProcessStart registers a callback for process start events.
// Returns a stop function to unregister the callback.
func (m *ProcessMonitor) OnProcessStart(callback func(ProcessEvent)) func() {
	events := m.Subscribe()
	stopChan := make(chan struct{})

	go func() {
		for {
			select {
			case event, ok := <-events:
				if !ok {
					return
				}
				if event.Type == ProcessStart {
					callback(event)
				}
			case <-stopChan:
				return
			}
		}
	}()

	return func() {
		close(stopChan)
		m.Unsubscribe(events)
	}
}

// OnProcessStop registers a callback for process stop events.
// Returns a stop function to unregister the callback.
func (m *ProcessMonitor) OnProcessStop(callback func(ProcessEvent)) func() {
	events := m.Subscribe()
	stopChan := make(chan struct{})

	go func() {
		for {
			select {
			case event, ok := <-events:
				if !ok {
					return
				}
				if event.Type == ProcessStop {
					callback(event)
				}
			case <-stopChan:
				return
			}
		}
	}()

	return func() {
		close(stopChan)
		m.Unsubscribe(events)
	}
}

// ============================================================================
// Filtered Monitoring
// ============================================================================

// ProcessFilter defines criteria for filtering process events.
type ProcessFilter struct {
	// Names is a list of process names to match (case-insensitive).
	Names []string

	// EventTypes is a list of event types to include.
	EventTypes []ProcessEventType

	// IncludeChildren includes child processes of matching processes.
	IncludeChildren bool
}

// SubscribeFiltered creates a filtered subscription.
func (m *ProcessMonitor) SubscribeFiltered(filter *ProcessFilter) <-chan ProcessEvent {
	rawEvents := m.Subscribe()
	filteredEvents := make(chan ProcessEvent, m.bufferSize)

	go func() {
		defer close(filteredEvents)

		// Normalize filter names
		names := make(map[string]bool)
		for _, name := range filter.Names {
			names[strings.ToLower(name)] = true
		}

		eventTypes := make(map[ProcessEventType]bool)
		for _, t := range filter.EventTypes {
			eventTypes[t] = true
		}

		for event := range rawEvents {
			// Check event type
			if len(eventTypes) > 0 && !eventTypes[event.Type] {
				continue
			}

			// Check name
			if len(names) > 0 {
				eventName := strings.ToLower(event.Name)
				if !names[eventName] {
					continue
				}
			}

			// Send filtered event
			select {
			case filteredEvents <- event:
			default:
				// Channel full, drop event
			}
		}
	}()

	return filteredEvents
}
