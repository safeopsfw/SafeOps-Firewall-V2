package fetcher

import (
	"context"
	"fmt"
	"log"
	"sort"
	"sync"
	"time"
)

// ==========================================================================
// Scheduler Struct Definition
// ==========================================================================

// Scheduler manages fetch scheduling based on update frequencies
type Scheduler struct {
	fetcher   *Fetcher
	sources   map[string]*Source
	schedules map[string]*ScheduleEntry
	tickers   map[string]*time.Ticker
	running   bool
	mutex     sync.RWMutex
	stopChan  chan struct{}
	logger    *log.Logger
	ctx       context.Context
	cancel    context.CancelFunc
}

// ==========================================================================
// ScheduleEntry Struct Definition
// ==========================================================================

// ScheduleEntry represents a scheduled fetch job
type ScheduleEntry struct {
	SourceName string
	NextRun    time.Time
	Interval   time.Duration
	LastRun    time.Time
	LastStatus string // success, failed, running
	Enabled    bool
}

// ==========================================================================
// NewScheduler Constructor
// ==========================================================================

// NewScheduler creates and initializes scheduler
func NewScheduler(fetcher *Fetcher, sources []Source) *Scheduler {
	ctx, cancel := context.WithCancel(context.Background())

	scheduler := &Scheduler{
		fetcher:   fetcher,
		sources:   make(map[string]*Source),
		schedules: make(map[string]*ScheduleEntry),
		tickers:   make(map[string]*time.Ticker),
		running:   false,
		stopChan:  make(chan struct{}),
		logger:    log.New(fetcher.logger.Writer(), "[SCHEDULER] ", log.LstdFlags),
		ctx:       ctx,
		cancel:    cancel,
	}

	// Index sources by name
	for i := range sources {
		scheduler.sources[sources[i].Name] = &sources[i]
	}

	// Calculate initial schedules
	for _, source := range sources {
		if source.Enabled {
			scheduler.calculateSchedule(&source)
		}
	}

	scheduler.logger.Printf("Scheduler initialized with %d sources\n", len(sources))

	return scheduler
}

// ==========================================================================
// Main Scheduling Methods
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

	enabledCount := 0

	// Start scheduling for each enabled source
	for name, source := range s.sources {
		if source.Enabled {
			s.scheduleSource(name, source)
			enabledCount++
		}
	}

	s.logger.Printf("Scheduler started for %d enabled sources\n", enabledCount)

	// Wait for stop signal
	<-s.stopChan

	return nil
}

// Stop gracefully stops the scheduler
func (s *Scheduler) Stop() {
	s.logger.Println("Stopping scheduler...")

	s.mutex.Lock()
	s.running = false

	// Stop all tickers
	for name, ticker := range s.tickers {
		ticker.Stop()
		s.logger.Printf("Stopped ticker for: %s\n", name)
	}

	s.mutex.Unlock()

	// Signal stop
	s.cancel()
	close(s.stopChan)

	s.logger.Println("Scheduler stopped")
}

// ==========================================================================
// Source Scheduling
// ==========================================================================

// scheduleSource sets up scheduling for a single source
func (s *Scheduler) scheduleSource(name string, source *Source) {
	interval := source.GetUpdateDuration()
	nextRun := s.getNextRunTime(source)

	s.mutex.Lock()
	s.schedules[name] = &ScheduleEntry{
		SourceName: name,
		NextRun:    nextRun,
		Interval:   interval,
		LastRun:    source.LastFetched,
		LastStatus: "",
		Enabled:    true,
	}
	s.mutex.Unlock()

	// Create ticker
	ticker := time.NewTicker(interval)
	s.tickers[name] = ticker

	s.logger.Printf("Scheduled: %s (interval: %s, next run: %s)\n",
		name, interval, nextRun.Format("15:04:05"))

	// Start goroutine to watch ticker
	go s.watchTicker(name, ticker)

	// If should run immediately, trigger now
	if time.Now().After(nextRun) || time.Now().Equal(nextRun) {
		go s.checkAndFetch(name, source)
	}
}

// watchTicker listens for ticker events and triggers fetches
func (s *Scheduler) watchTicker(name string, ticker *time.Ticker) {
	for {
		select {
		case <-s.ctx.Done():
			return
		case <-ticker.C:
			s.mutex.RLock()
			source, exists := s.sources[name]
			s.mutex.RUnlock()

			if !exists {
				continue
			}

			go s.checkAndFetch(name, source)
		}
	}
}

// checkAndFetch checks if source should be fetched and executes if needed
func (s *Scheduler) checkAndFetch(name string, source *Source) {
	s.mutex.Lock()
	schedule, exists := s.schedules[name]
	if !exists || !schedule.Enabled {
		s.mutex.Unlock()
		return
	}

	// Check if it's time to fetch
	now := time.Now()
	if now.Before(schedule.NextRun) {
		s.mutex.Unlock()
		return
	}

	// Check for duplicate fetch
	if schedule.LastStatus == "running" {
		s.mutex.Unlock()
		s.logger.Printf("Skipping %s - already running\n", name)
		return
	}

	// Mark as running
	schedule.LastStatus = "running"
	schedule.LastRun = now
	s.mutex.Unlock()

	s.logger.Printf("Triggering fetch: %s\n", name)

	// Execute fetch
	err := s.fetcher.FetchSource(source)

	// Update schedule
	s.mutex.Lock()
	if err != nil {
		schedule.LastStatus = "failed"
		s.logger.Printf("Fetch failed: %s - %s\n", name, err.Error())
	} else {
		schedule.LastStatus = "success"
		s.logger.Printf("Fetch successful: %s\n", name)
	}

	// Calculate next run time
	schedule.NextRun = now.Add(schedule.Interval)
	s.mutex.Unlock()
}

// ==========================================================================
// Schedule Management
// ==========================================================================

// rescheduleSource adjusts schedule for a source
func (s *Scheduler) rescheduleSource(name string) error {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	// Get source
	source, exists := s.sources[name]
	if !exists {
		return fmt.Errorf("source not found: %s", name)
	}

	// Stop existing ticker
	if ticker, exists := s.tickers[name]; exists {
		ticker.Stop()
		delete(s.tickers, name)
	}

	// Remove old schedule
	delete(s.schedules, name)

	// Create new schedule if enabled
	if source.Enabled {
		s.mutex.Unlock() // Unlock before calling scheduleSource
		s.scheduleSource(name, source)
		s.mutex.Lock()
	}

	return nil
}

// calculateSchedule calculates initial schedule for a source
func (s *Scheduler) calculateSchedule(source *Source) {
	nextRun := s.getNextRunTime(source)
	interval := source.GetUpdateDuration()

	s.schedules[source.Name] = &ScheduleEntry{
		SourceName: source.Name,
		NextRun:    nextRun,
		Interval:   interval,
		LastRun:    source.LastFetched,
		Enabled:    source.Enabled,
	}
}

// getNextRunTime calculates when a source should next be fetched
func (s *Scheduler) getNextRunTime(source *Source) time.Time {
	interval := source.GetUpdateDuration()

	// If never fetched, run immediately
	if source.LastFetched.IsZero() {
		return time.Now()
	}

	// Calculate next run based on last fetch
	nextRun := source.LastFetched.Add(interval)

	// If next run is in the past, run immediately
	if nextRun.Before(time.Now()) {
		return time.Now()
	}

	return nextRun
}

// isDuplicateFetch checks if source is currently being fetched
func (s *Scheduler) isDuplicateFetch(name string) bool {
	s.mutex.RLock()
	defer s.mutex.RUnlock()

	schedule, exists := s.schedules[name]
	if !exists {
		return false
	}

	// Check if currently running
	if schedule.LastStatus == "running" {
		// Check if it's been running for too long (stuck)
		if time.Since(schedule.LastRun) > 10*time.Minute {
			// Consider it stuck, allow re-fetch
			return false
		}
		return true
	}

	// Check if fetched very recently (within last minute)
	if time.Since(schedule.LastRun) < 60*time.Second {
		return true
	}

	return false
}

// ==========================================================================
// Status and Monitoring
// ==========================================================================

// GetSchedules returns current schedule status for all sources
func (s *Scheduler) GetSchedules() map[string]*ScheduleEntry {
	s.mutex.RLock()
	defer s.mutex.RUnlock()

	// Return copy
	schedules := make(map[string]*ScheduleEntry)
	for name, entry := range s.schedules {
		entryCopy := *entry
		schedules[name] = &entryCopy
	}

	return schedules
}

// GetNextRuns returns list of upcoming fetch jobs sorted by time
func (s *Scheduler) GetNextRuns() []*ScheduleEntry {
	s.mutex.RLock()
	defer s.mutex.RUnlock()

	var entries []*ScheduleEntry
	for _, entry := range s.schedules {
		if entry.Enabled {
			entryCopy := *entry
			entries = append(entries, &entryCopy)
		}
	}

	// Sort by next run time
	sort.Slice(entries, func(i, j int) bool {
		return entries[i].NextRun.Before(entries[j].NextRun)
	})

	return entries
}

// GetScheduleBySource returns schedule for a specific source
func (s *Scheduler) GetScheduleBySource(name string) (*ScheduleEntry, error) {
	s.mutex.RLock()
	defer s.mutex.RUnlock()

	entry, exists := s.schedules[name]
	if !exists {
		return nil, fmt.Errorf("schedule not found for source: %s", name)
	}

	entryCopy := *entry
	return &entryCopy, nil
}

// GetDueSources returns sources that need to be fetched now
func (s *Scheduler) GetDueSources() []string {
	s.mutex.RLock()
	defer s.mutex.RUnlock()

	var due []string
	now := time.Now()

	for name, entry := range s.schedules {
		if entry.Enabled && entry.LastStatus != "running" {
			if now.After(entry.NextRun) || now.Equal(entry.NextRun) {
				due = append(due, name)
			}
		}
	}

	return due
}

// ==========================================================================
// Scheduler Statistics
// ==========================================================================

// SchedulerStats holds statistics about scheduler state
type SchedulerStats struct {
	TotalSources   int
	EnabledSources int
	RunningJobs    int
	DueForUpdate   int
	NextUpdate     time.Time
	UptimeDuration time.Duration
}

// GetStats returns scheduler statistics
func (s *Scheduler) GetStats() *SchedulerStats {
	s.mutex.RLock()
	defer s.mutex.RUnlock()

	stats := &SchedulerStats{
		TotalSources: len(s.sources),
	}

	var earliestNext time.Time

	for _, entry := range s.schedules {
		if entry.Enabled {
			stats.EnabledSources++

			if entry.LastStatus == "running" {
				stats.RunningJobs++
			}

			now := time.Now()
			if now.After(entry.NextRun) || now.Equal(entry.NextRun) {
				stats.DueForUpdate++
			}

			if earliestNext.IsZero() || entry.NextRun.Before(earliestNext) {
				earliestNext = entry.NextRun
			}
		}
	}

	stats.NextUpdate = earliestNext

	return stats
}
