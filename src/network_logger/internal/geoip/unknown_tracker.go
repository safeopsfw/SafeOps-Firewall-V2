package geoip

import (
	"bufio"
	"encoding/csv"
	"fmt"
	"os"
	"strconv"
	"sync"
	"time"
)

// UnknownIPTracker tracks IPs that weren't found in the GeoIP database
type UnknownIPTracker struct {
	filePath  string
	counts    map[string]int
	mu        sync.Mutex
	lastFlush time.Time
}

// NewUnknownIPTracker creates a new tracker
func NewUnknownIPTracker(filePath string) *UnknownIPTracker {
	tracker := &UnknownIPTracker{
		filePath:  filePath,
		counts:    make(map[string]int),
		lastFlush: time.Now(),
	}

	// Load existing data
	tracker.load()

	// Start background flush goroutine
	go tracker.flushLoop()

	return tracker
}

// Track records an unknown IP
func (t *UnknownIPTracker) Track(ip string) {
	// Skip private IPs
	if isInternalIP(ip) {
		return
	}

	t.mu.Lock()
	t.counts[ip]++
	t.mu.Unlock()
}

// load reads existing CSV file
func (t *UnknownIPTracker) load() {
	file, err := os.Open(t.filePath)
	if err != nil {
		return // File doesn't exist yet
	}
	defer file.Close()

	reader := csv.NewReader(file)
	records, err := reader.ReadAll()
	if err != nil {
		return
	}

	for i, record := range records {
		if i == 0 { // Skip header
			continue
		}
		if len(record) >= 2 {
			count, _ := strconv.Atoi(record[1])
			t.counts[record[0]] = count
		}
	}
}

// flushLoop periodically saves to disk
func (t *UnknownIPTracker) flushLoop() {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()

	for range ticker.C {
		t.Flush()
	}
}

// Flush writes the current counts to the CSV file
func (t *UnknownIPTracker) Flush() {
	t.mu.Lock()
	defer t.mu.Unlock()

	if len(t.counts) == 0 {
		return
	}

	// Create temp file
	tmpPath := t.filePath + ".tmp"
	file, err := os.Create(tmpPath)
	if err != nil {
		return
	}

	writer := bufio.NewWriter(file)

	// Write header
	writer.WriteString("ip_address,count,last_updated\n")

	now := time.Now().Format(time.RFC3339)

	// Sort by count (highest first) - simple bubble for now
	type ipCount struct {
		ip    string
		count int
	}
	sorted := make([]ipCount, 0, len(t.counts))
	for ip, count := range t.counts {
		sorted = append(sorted, ipCount{ip, count})
	}
	// Simple sort by count descending
	for i := 0; i < len(sorted)-1; i++ {
		for j := i + 1; j < len(sorted); j++ {
			if sorted[j].count > sorted[i].count {
				sorted[i], sorted[j] = sorted[j], sorted[i]
			}
		}
	}

	// Write rows
	for _, item := range sorted {
		writer.WriteString(fmt.Sprintf("%s,%d,%s\n", item.ip, item.count, now))
	}

	writer.Flush()
	file.Close()

	// Atomic rename
	os.Rename(tmpPath, t.filePath)

	t.lastFlush = time.Now()
}

// GetStats returns tracker statistics
func (t *UnknownIPTracker) GetStats() (total int, unique int) {
	t.mu.Lock()
	defer t.mu.Unlock()

	unique = len(t.counts)
	for _, count := range t.counts {
		total += count
	}
	return
}

// Close flushes and stops the tracker
func (t *UnknownIPTracker) Close() {
	t.Flush()
}
