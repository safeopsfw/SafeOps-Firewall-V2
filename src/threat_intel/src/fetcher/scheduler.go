package fetcher

import (
	"context"
	"fmt"
	"log"
	"sync"
	"time"
)

// ==========================================================================
// Scheduler Struct - Manages Time-Based Fetch Scheduling
// ==========================================================================

// Scheduler manages periodic fetch operations for threat intelligence sources
type Scheduler struct {
	fetcher   *Fetcher
	sources   map[string]*Source
	schedules map[string]*ScheduleEntry
	tickers   map[string]*time.Ticker
	running   bool
	mutex     sync.RWMutex
	stopChan  chan bool
	ctx       context.Context
	cancel    context.CancelFunc
}

// ScheduleEntry represents a scheduled fetch job
type ScheduleEntry struct {
	SourceName string
	NextRun    time.Time
	Interval   time.Duration
	LastRun    time.Time
	LastStatus string // success, failed, skipped
	Enabled    bool
}

// ==========================================================================
// Constructor
// ==========================================================================

// NewScheduler creates and initializes a new scheduler
func NewScheduler(fetcher *Fetcher, sources []Source) *Scheduler {
	ctx, cancel := context.WithCancel(context.Background())

	// Create source map for quick lookup
	sourceMap := make(map[string]*Source)
	for i := range sources {
		sourceMap[sources[i].Name] = &sources[i]
	}

	scheduler := &Scheduler{
		fetcher:   fetcher,
		sources:   sourceMap,
		schedules: make(map[string]*ScheduleEntry),
		tickers:   make(map[string]*time.Ticker),
		stopChan:  make(chan bool),
		ctx:       ctx,
		cancel:    cancel,
	}

	// Initialize schedule entries
	for _, source := range sources {
		if source.Enabled {
			entry := &ScheduleEntry{
				SourceName: source.Name,
				NextRun:    time.Now(), // Fetch immediately on first start
				Interval:   GetUpdateDuration(&source),
				Enabled:    true,
				LastStatus: "pending",
			}
			scheduler.schedules[source.Name] = entry
		}
	}

	log.Printf("Scheduler initialized with %d sources", len(scheduler.schedules))

	return scheduler
}

// ==========================================================================
// Main Public Methods
// ==========================================================================

// Start begins the scheduling process
func (s *Scheduler) Start() error {
	s.mutex.Lock()
	if s.running {
		s.mutex.Unlock()
		return fmt.Errorf("scheduler already running")
	}
	s.running = true
	s.mutex.Unlock()

	log.Println("Starting scheduler...")

	// Start scheduler for each enabled source
	for name, entry := range s.schedules {
		if entry.Enabled {
			go s.scheduleSource(name, entry)
		}
	}

	log.Printf("Scheduler started with %d active schedules", len(s.schedules))

	// Wait for stop signal
	<-s.stopChan
	return nil
}

// Stop gracefully stops the scheduler
func (s *Scheduler) Stop() error {
	log.Println("Stopping scheduler...")

	s.mutex.Lock()
	if !s.running {
		s.mutex.Unlock()
		return fmt.Errorf("scheduler not running")
	}
	s.running = false
	s.mutex.Unlock()

	// Cancel context to stop all goroutines
	s.cancel()

	// Stop all tickers
	s.mutex.Lock()
	for _, ticker := range s.tickers {
		ticker.Stop()
	}
	s.mutex.Unlock()

	// Send stop signal
	close(s.stopChan)

	log.Println("Scheduler stopped")
	return nil
}

// ==========================================================================
// Internal Scheduling Methods
// ==========================================================================

// scheduleSource sets up scheduling for a single source
func (s *Scheduler) scheduleSource(sourceName string, entry *ScheduleEntry) {
	// Create ticker with source's interval
	ticker := time.NewTicker(entry.Interval)

	// Store ticker
	s.mutex.Lock()
	s.tickers[sourceName] = ticker
	s.mutex.Unlock()

	// Fetch immediately on first start if scheduled for now
	if entry.NextRun.Before(time.Now()) || entry.NextRun.Equal(time.Now()) {
		go s.checkAndFetch(sourceName)
	}

	// Listen for ticker events
	for {
		select {
		case <-ticker.C:
			// Time to fetch this source
			go s.checkAndFetch(sourceName)

		case <-s.ctx.Done():
			// Scheduler stopped
			ticker.Stop()
			return
		}
	}
}

// checkAndFetch checks if source should be fetched and executes if needed
func (s *Scheduler) checkAndFetch(sourceName string) {
	s.mutex.RLock()
	entry, exists := s.schedules[sourceName]
	source, sourceExists := s.sources[sourceName]
	s.mutex.RUnlock()

	if !exists || !sourceExists {
		log.Printf("Source %s not found in schedules", sourceName)
		return
	}

	// Check if it's time to fetch
	now := time.Now()
	if now.Before(entry.NextRun) {
		log.Printf("Skipping %s - not yet time to fetch (next: %s)", sourceName, entry.NextRun.Format(time.RFC3339))
		return
	}

	// Check for duplicate fetch (prevent concurrent fetches of same source)
	if s.isDuplicateFetch(sourceName) {
		log.Printf("Skipping %s - duplicate fetch detected", sourceName)
		s.updateScheduleEntry(sourceName, "skipped")
		return
	}

	log.Printf("Triggering scheduled fetch for: %s", sourceName)

	// Execute fetch
	startTime := time.Now()
	err := s.fetcher.FetchSource(source)
	duration := time.Since(startTime)

	// Update schedule entry based on result
	if err != nil {
		log.Printf("Scheduled fetch failed for %s: %v (took %v)", sourceName, err, duration)
		s.updateScheduleEntry(sourceName, "failed")
	} else {
		log.Printf("Scheduled fetch succeeded for %s (took %v)", sourceName, duration)
		s.updateScheduleEntry(sourceName, "success")
	}
}

// updateScheduleEntry updates the schedule after a fetch attempt
func (s *Scheduler) updateScheduleEntry(sourceName, status string) {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	entry, exists := s.schedules[sourceName]
	if !exists {
		return
	}

	now := time.Now()
	entry.LastRun = now
	entry.LastStatus = status
	entry.NextRun = now.Add(entry.Interval)

	log.Printf("Updated schedule for %s: next run at %s", sourceName, entry.NextRun.Format(time.RFC3339))
}

// isDuplicateFetch prevents fetching same source multiple times concurrently
func (s *Scheduler) isDuplicateFetch(sourceName string) bool {
	// Check if source is in fetcher's active jobs
	activeJobs := s.fetcher.GetActiveJobs()
	for _, job := range activeJobs {
		if job.Source.Name == sourceName {
			return true
		}
	}

	return false
}

// ==========================================================================
// Schedule Management Methods
// ==========================================================================

// RescheduleSource adjusts schedule for a source
func (s *Scheduler) RescheduleSource(sourceName string, newInterval time.Duration) error {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	entry, exists := s.schedules[sourceName]
	if !exists {
		return fmt.Errorf("source %s not found in schedules", sourceName)
	}

	// Stop existing ticker
	if ticker, exists := s.tickers[sourceName]; exists {
		ticker.Stop()
		delete(s.tickers, sourceName)
	}

	// Update interval
	entry.Interval = newInterval
	entry.NextRun = time.Now().Add(newInterval)

	// Create new ticker if scheduler is running
	if s.running {
		ticker := time.NewTicker(newInterval)
		s.tickers[sourceName] = ticker
		go s.scheduleSource(sourceName, entry)
	}

	log.Printf("Rescheduled %s with new interval: %v", sourceName, newInterval)
	return nil
}

// EnableSource enables scheduling for a source
func (s *Scheduler) EnableSource(sourceName string) error {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	entry, exists := s.schedules[sourceName]
	if !exists {
		return fmt.Errorf("source %s not found in schedules", sourceName)
	}

	if entry.Enabled {
		return nil // Already enabled
	}

	entry.Enabled = true
	entry.NextRun = time.Now() // Fetch immediately

	// Start ticker if scheduler is running
	if s.running {
		ticker := time.NewTicker(entry.Interval)
		s.tickers[sourceName] = ticker
		go s.scheduleSource(sourceName, entry)
	}

	log.Printf("Enabled schedule for %s", sourceName)
	return nil
}

// DisableSource disables scheduling for a source
func (s *Scheduler) DisableSource(sourceName string) error {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	entry, exists := s.schedules[sourceName]
	if !exists {
		return fmt.Errorf("source %s not found in schedules", sourceName)
	}

	if !entry.Enabled {
		return nil // Already disabled
	}

	entry.Enabled = false

	// Stop ticker
	if ticker, exists := s.tickers[sourceName]; exists {
		ticker.Stop()
		delete(s.tickers, sourceName)
	}

	log.Printf("Disabled schedule for %s", sourceName)
	return nil
}

// ==========================================================================
// Query Methods
// ==========================================================================

// GetSchedules returns current schedule status for all sources
func (s *Scheduler) GetSchedules() map[string]*ScheduleEntry {
	s.mutex.RLock()
	defer s.mutex.RUnlock()

	// Create copy to avoid race conditions
	schedulesCopy := make(map[string]*ScheduleEntry)
	for name, entry := range s.schedules {
		entryCopy := *entry
		schedulesCopy[name] = &entryCopy
	}

	return schedulesCopy
}

// GetNextRuns returns upcoming fetch jobs sorted by time
func (s *Scheduler) GetNextRuns(limit int) []*ScheduleEntry {
	s.mutex.RLock()
	defer s.mutex.RUnlock()

	// Collect all enabled schedule entries
	var entries []*ScheduleEntry
	for _, entry := range s.schedules {
		if entry.Enabled {
			entryCopy := *entry
			entries = append(entries, &entryCopy)
		}
	}

	// Simple bubble sort by next run time
	for i := 0; i < len(entries)-1; i++ {
		for j := 0; j < len(entries)-i-1; j++ {
			if entries[j].NextRun.After(entries[j+1].NextRun) {
				entries[j], entries[j+1] = entries[j+1], entries[j]
			}
		}
	}

	// Limit results
	if limit > 0 && len(entries) > limit {
		entries = entries[:limit]
	}

	return entries
}

// GetScheduleStatus returns the status of a specific source's schedule
func (s *Scheduler) GetScheduleStatus(sourceName string) (*ScheduleEntry, error) {
	s.mutex.RLock()
	defer s.mutex.RUnlock()

	entry, exists := s.schedules[sourceName]
	if !exists {
		return nil, fmt.Errorf("source %s not found in schedules", sourceName)
	}

	entryCopy := *entry
	return &entryCopy, nil
}

// IsRunning returns true if scheduler is currently running
func (s *Scheduler) IsRunning() bool {
	s.mutex.RLock()
	defer s.mutex.RUnlock()
	return s.running
}
