// Package subprocess manages the packet_engine Rust subprocess.
package subprocess

import (
	"bufio"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"sync"
	"time"
)

// LogEntry represents a single line of stdout from packet_engine.
type LogEntry struct {
	Timestamp time.Time `json:"timestamp"`
	Message   string    `json:"message"`
}

// PacketEngineManager manages the packet_engine subprocess lifecycle.
type PacketEngineManager struct {
	mu        sync.RWMutex
	cmd       *exec.Cmd
	running   bool
	exePath   string
	logs      []LogEntry
	maxLogAge time.Duration
	stopChan  chan struct{}
	stoppedWg sync.WaitGroup
}

// NewPacketEngineManager creates a new manager instance.
func NewPacketEngineManager() *PacketEngineManager {
	// Find packet_engine.exe in same directory as this executable
	execPath, _ := os.Executable()
	dir := filepath.Dir(execPath)
	exePath := filepath.Join(dir, "packet_engine.exe")

	return &PacketEngineManager{
		exePath:   exePath,
		logs:      make([]LogEntry, 0, 1000),
		maxLogAge: 60 * time.Minute, // Last 60 minutes of logs
		stopChan:  make(chan struct{}),
	}
}

// Start launches the packet_engine subprocess.
func (m *PacketEngineManager) Start() error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.running {
		return fmt.Errorf("packet_engine already running")
	}

	// Check if executable exists
	if _, err := os.Stat(m.exePath); os.IsNotExist(err) {
		return fmt.Errorf("packet_engine.exe not found at %s", m.exePath)
	}

	// Create command
	m.cmd = exec.Command(m.exePath)
	m.cmd.Dir = filepath.Dir(m.exePath)

	// Capture stdout and stderr
	stdout, err := m.cmd.StdoutPipe()
	if err != nil {
		return fmt.Errorf("failed to create stdout pipe: %w", err)
	}

	stderr, err := m.cmd.StderrPipe()
	if err != nil {
		return fmt.Errorf("failed to create stderr pipe: %w", err)
	}

	// Start the process
	if err := m.cmd.Start(); err != nil {
		return fmt.Errorf("failed to start packet_engine: %w", err)
	}

	m.running = true
	m.stopChan = make(chan struct{})

	// Capture output in background
	m.stoppedWg.Add(2)
	go m.captureOutput(stdout)
	go m.captureOutput(stderr)

	// Monitor process in background
	go m.monitorProcess()

	return nil
}

// captureOutput reads from a pipe and stores lines in the log buffer.
func (m *PacketEngineManager) captureOutput(r io.ReadCloser) {
	defer m.stoppedWg.Done()
	scanner := bufio.NewScanner(r)

	for scanner.Scan() {
		line := scanner.Text()
		m.addLogEntry(line)
	}
}

// addLogEntry adds a log entry and prunes old entries.
func (m *PacketEngineManager) addLogEntry(message string) {
	m.mu.Lock()
	defer m.mu.Unlock()

	entry := LogEntry{
		Timestamp: time.Now(),
		Message:   message,
	}
	m.logs = append(m.logs, entry)

	// Prune entries older than maxLogAge
	cutoff := time.Now().Add(-m.maxLogAge)
	newStart := 0
	for i, e := range m.logs {
		if e.Timestamp.After(cutoff) {
			newStart = i
			break
		}
	}
	if newStart > 0 {
		m.logs = m.logs[newStart:]
	}

	// Also limit to max 500 entries
	if len(m.logs) > 500 {
		m.logs = m.logs[len(m.logs)-500:]
	}
}

// monitorProcess watches for process exit and handles restart.
func (m *PacketEngineManager) monitorProcess() {
	if m.cmd == nil || m.cmd.Process == nil {
		return
	}

	// Wait for process to exit
	err := m.cmd.Wait()

	m.mu.Lock()
	m.running = false
	m.mu.Unlock()

	if err != nil {
		m.addLogEntry(fmt.Sprintf("[MANAGER] packet_engine exited with error: %v", err))
	} else {
		m.addLogEntry("[MANAGER] packet_engine exited normally")
	}
}

// Stop terminates the packet_engine subprocess.
func (m *PacketEngineManager) Stop() error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if !m.running || m.cmd == nil || m.cmd.Process == nil {
		return nil
	}

	// Signal stop
	close(m.stopChan)

	// Kill the process
	if err := m.cmd.Process.Kill(); err != nil {
		return fmt.Errorf("failed to kill packet_engine: %w", err)
	}

	m.running = false
	return nil
}

// IsRunning returns whether packet_engine is currently running.
func (m *PacketEngineManager) IsRunning() bool {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.running
}

// GetRecentLogs returns log entries from the last 50 seconds.
func (m *PacketEngineManager) GetRecentLogs() []LogEntry {
	m.mu.RLock()
	defer m.mu.RUnlock()

	// Return a copy to avoid race conditions
	result := make([]LogEntry, len(m.logs))
	copy(result, m.logs)
	return result
}

// GetStatus returns current status information.
func (m *PacketEngineManager) GetStatus() map[string]interface{} {
	m.mu.RLock()
	defer m.mu.RUnlock()

	pid := 0
	if m.cmd != nil && m.cmd.Process != nil {
		pid = m.cmd.Process.Pid
	}

	return map[string]interface{}{
		"running":   m.running,
		"pid":       pid,
		"log_count": len(m.logs),
		"exe_path":  m.exePath,
	}
}
