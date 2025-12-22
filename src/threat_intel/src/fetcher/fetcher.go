package fetcher

import (
	"context"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"sync"
	"time"

	"threat_intel/config"
)

// ==========================================================================
// Fetcher Struct - Main Orchestrator
// ==========================================================================

// Fetcher coordinates all feed downloading operations
type Fetcher struct {
	config     *config.Config
	sources    []Source
	downloader *HTTPDownloader
	jobQueue   chan *FetchJob
	activeJobs map[string]*FetchJob
	jobMutex   sync.RWMutex
	stats      *FetchStats
	statsMutex sync.RWMutex
	ctx        context.Context
	cancel     context.CancelFunc
	wg         sync.WaitGroup
}

// ==========================================================================
// FetchJob Struct - Represents Single Fetch Operation
// ==========================================================================

// FetchJob represents a single feed fetch operation
type FetchJob struct {
	Source      *Source
	ScheduledAt time.Time
	StartedAt   time.Time
	CompletedAt time.Time
	Status      string // queued, running, success, failed, retrying
	Attempt     int
	Error       error
	FilePath    string
	FileSize    int64
	Duration    time.Duration
}

// ==========================================================================
// FetchStats Struct - Aggregated Statistics
// ==========================================================================

// FetchStats holds aggregated statistics for monitoring
type FetchStats struct {
	TotalJobs            int64
	SuccessfulJobs       int64
	FailedJobs           int64
	TotalBytesDownloaded int64
	AverageDuration      time.Duration
	LastFetchTime        time.Time
}

// ==========================================================================
// Constructor
// ==========================================================================

// NewFetcher creates and initializes a new Fetcher instance
func NewFetcher(cfg *config.Config, sources []Source) (*Fetcher, error) {
	// Validate all sources
	if errs := ValidateSources(sources); len(errs) > 0 {
		return nil, fmt.Errorf("source validation failed: %v", errs)
	}

	// Create context for cancellation
	ctx, cancel := context.WithCancel(context.Background())

	// Initialize fetcher
	fetcher := &Fetcher{
		config:     cfg,
		sources:    sources,
		downloader: NewHTTPDownloader(cfg),
		jobQueue:   make(chan *FetchJob, 100), // Buffered channel
		activeJobs: make(map[string]*FetchJob),
		stats:      &FetchStats{},
		ctx:        ctx,
		cancel:     cancel,
	}

	// Create storage directories for each category
	if err := fetcher.createStorageDirectories(); err != nil {
		return nil, fmt.Errorf("failed to create storage directories: %w", err)
	}

	// Start background job processors
	for i := 0; i < cfg.Worker.ConcurrentJobs; i++ {
		fetcher.wg.Add(1)
		go fetcher.jobProcessor()
	}

	log.Printf("Fetcher initialized with %d sources (%d enabled)",
		len(sources), len(GetEnabledSources(sources)))

	return fetcher, nil
}

// ==========================================================================
// Main Public Methods
// ==========================================================================

// Start begins the fetching process for all enabled sources
func (f *Fetcher) Start() error {
	enabledSources := GetEnabledSources(f.sources)
	if len(enabledSources) == 0 {
		return fmt.Errorf("no enabled sources to fetch")
	}

	log.Printf("Starting fetcher with %d enabled sources", len(enabledSources))

	// Sort by priority
	sortedSources := GetSourcesByPriority(enabledSources)

	// Queue all fetch jobs
	for _, source := range sortedSources {
		sourceCopy := source // Avoid loop variable capture
		job := &FetchJob{
			Source:      &sourceCopy,
			ScheduledAt: time.Now(),
			Status:      "queued",
			Attempt:     1,
		}

		select {
		case f.jobQueue <- job:
			log.Printf("Queued fetch job for: %s", source.Name)
		case <-f.ctx.Done():
			return fmt.Errorf("fetcher stopped before all jobs queued")
		}
	}

	return nil
}

// FetchAll performs parallel fetch of all enabled sources
func (f *Fetcher) FetchAll() (*FetchStats, error) {
	enabledSources := GetEnabledSources(f.sources)
	if len(enabledSources) == 0 {
		return nil, fmt.Errorf("no enabled sources to fetch")
	}

	log.Printf("Starting parallel fetch of %d enabled sources (10 concurrent)", len(enabledSources))

	// Create job channel and result channel
	jobs := make(chan Source, len(enabledSources))
	results := make(chan bool, len(enabledSources))

	// Start 10 worker goroutines
	numWorkers := 10
	for w := 0; w < numWorkers; w++ {
		go func(workerID int) {
			for source := range jobs {
				sourceCopy := source

				// Try up to 2 times
				var lastErr error
				for attempt := 1; attempt <= 2; attempt++ {
					startTime := time.Now()
					err := f.FetchSource(&sourceCopy)
					duration := time.Since(startTime)

					if err == nil {
						// Success!
						f.updateStats(true, 0, duration)
						break
					}

					lastErr = err
					log.Printf("Fetch failed for %s (attempt %d/2): %v", sourceCopy.Name, attempt, err)

					if attempt < 2 {
						time.Sleep(2 * time.Second)
					}
				}

				if lastErr != nil {
					log.Printf("⏭️ Skipping %s after 2 failed attempts", sourceCopy.Name)
					f.updateStats(false, 0, 0)
				}

				results <- lastErr == nil
			}
		}(w)
	}

	// Send all jobs
	for _, source := range enabledSources {
		jobs <- source
	}
	close(jobs)

	// Wait for all results
	for i := 0; i < len(enabledSources); i++ {
		<-results
	}

	log.Printf("Fetch complete: %d success, %d failed", f.stats.SuccessfulJobs, f.stats.FailedJobs)
	return f.GetStats(), nil
}

// FetchSource fetches a single source
func (f *Fetcher) FetchSource(source *Source) error {
	log.Printf("Fetching source: %s (%s)", source.Name, source.URL)

	// Determine output path
	outputPath, err := f.getOutputPath(source)
	if err != nil {
		return fmt.Errorf("failed to determine output path: %w", err)
	}

	// Download file
	startTime := time.Now()
	fileSize, err := f.downloader.Download(source.URL, outputPath)
	duration := time.Since(startTime)

	if err != nil {
		return fmt.Errorf("download failed: %w", err)
	}

	log.Printf("Downloaded %s: %d bytes in %v", source.Name, fileSize, duration)

	// Validate downloaded file
	if err := f.validateDownloadedFile(outputPath, source); err != nil {
		return fmt.Errorf("file validation failed: %w", err)
	}

	// Update statistics
	f.updateStats(true, fileSize, duration)

	// NOTE: Parser will read this file later for database insertion
	log.Printf("Saved %s to %s (ready for parsing)", source.Name, outputPath)

	return nil
}

// Stop gracefully shuts down the fetcher
func (f *Fetcher) Stop() error {
	log.Println("Stopping fetcher...")

	// Stop accepting new jobs
	f.cancel()
	close(f.jobQueue)

	// Wait for active jobs to complete (with timeout)
	done := make(chan bool)
	go func() {
		f.wg.Wait()
		done <- true
	}()

	select {
	case <-done:
		log.Println("Fetcher stopped gracefully")
	case <-time.After(30 * time.Second):
		log.Println("Fetcher stop timeout - some jobs may be incomplete")
	}

	return nil
}

// GetStats returns current fetch statistics
func (f *Fetcher) GetStats() *FetchStats {
	f.statsMutex.RLock()
	defer f.statsMutex.RUnlock()

	// Create copy to avoid race conditions
	stats := &FetchStats{
		TotalJobs:            f.stats.TotalJobs,
		SuccessfulJobs:       f.stats.SuccessfulJobs,
		FailedJobs:           f.stats.FailedJobs,
		TotalBytesDownloaded: f.stats.TotalBytesDownloaded,
		AverageDuration:      f.stats.AverageDuration,
		LastFetchTime:        f.stats.LastFetchTime,
	}

	return stats
}

// ==========================================================================
// Internal Methods
// ==========================================================================

// jobProcessor processes jobs from the queue
func (f *Fetcher) jobProcessor() {
	defer f.wg.Done()

	for {
		select {
		case job, ok := <-f.jobQueue:
			if !ok {
				// Channel closed, stop processing
				return
			}

			// Process the job
			f.processFetchJob(job)

		case <-f.ctx.Done():
			return
		}
	}
}

// processFetchJob handles a single fetch job
func (f *Fetcher) processFetchJob(job *FetchJob) {
	// Mark job as running
	job.Status = "running"
	job.StartedAt = time.Now()

	// Add to active jobs
	f.jobMutex.Lock()
	f.activeJobs[job.Source.Name] = job
	f.jobMutex.Unlock()

	// Perform fetch
	err := f.FetchSource(job.Source)

	// Update job status
	job.CompletedAt = time.Now()
	job.Duration = job.CompletedAt.Sub(job.StartedAt)

	if err != nil {
		job.Status = "failed"
		job.Error = err
		log.Printf("Fetch failed for %s (attempt %d/2): %v",
			job.Source.Name, job.Attempt, err)

		// Retry only once (max 2 attempts total), then skip
		if job.Attempt < 2 {
			f.retryJob(job)
		} else {
			log.Printf("⏭️ Skipping %s after 2 failed attempts - moving to next source",
				job.Source.Name)
			// Update stats for failure
			f.updateStats(false, 0, job.Duration)
		}
	} else {
		job.Status = "success"
		log.Printf("Fetch succeeded for %s", job.Source.Name)
	}

	// Remove from active jobs
	f.jobMutex.Lock()
	delete(f.activeJobs, job.Source.Name)
	f.jobMutex.Unlock()
}

// retryJob handles retry logic for failed jobs
func (f *Fetcher) retryJob(job *FetchJob) {
	job.Attempt++
	job.Status = "retrying"

	// Use very short fixed delay (2 seconds) - don't wait long on retries
	delay := 2 * time.Second
	log.Printf("Retrying %s in %v (attempt %d/2)",
		job.Source.Name, delay, job.Attempt)

	// Schedule retry
	go func() {
		time.Sleep(delay)
		select {
		case f.jobQueue <- job:
		case <-f.ctx.Done():
		}
	}()
}

// getOutputPath determines where to save downloaded file
func (f *Fetcher) getOutputPath(source *Source) (string, error) {
	// Base storage path from config
	basePath := f.config.Storage.BasePath

	// Create category subdirectory path
	categoryPath := filepath.Join(basePath, source.Category)

	// Ensure directory exists
	if err := os.MkdirAll(categoryPath, 0755); err != nil {
		return "", fmt.Errorf("failed to create directory %s: %w", categoryPath, err)
	}

	// Generate filename with timestamp
	timestamp := time.Now().Format("20060102_150405")
	extension := GetFileExtension(source.Format)
	filename := fmt.Sprintf("%s_%s%s", source.Name, timestamp, extension)

	// Replace spaces and special characters in filename
	filename = filepath.Base(filename)

	// Full path
	fullPath := filepath.Join(categoryPath, filename)

	return fullPath, nil
}

// validateDownloadedFile checks if downloaded file is valid
func (f *Fetcher) validateDownloadedFile(filePath string, source *Source) error {
	// Check if file exists
	info, err := os.Stat(filePath)
	if err != nil {
		return fmt.Errorf("file not found: %w", err)
	}

	// Check file size > 0
	if info.Size() == 0 {
		return fmt.Errorf("downloaded file is empty")
	}

	// Check file size < max limit
	maxSizeBytes := int64(f.config.Storage.MaxFileSize) * 1024 * 1024 // Convert MB to bytes
	if info.Size() > maxSizeBytes {
		return fmt.Errorf("file size (%d bytes) exceeds maximum (%d MB)",
			info.Size(), f.config.Storage.MaxFileSize)
	}

	// Check file extension matches expected format
	expectedExt := GetFileExtension(source.Format)
	actualExt := filepath.Ext(filePath)
	if actualExt != expectedExt {
		log.Printf("Warning: expected extension %s, got %s for %s",
			expectedExt, actualExt, source.Name)
	}

	return nil
}

// updateStats updates fetch statistics
func (f *Fetcher) updateStats(success bool, bytesDownloaded int64, duration time.Duration) {
	f.statsMutex.Lock()
	defer f.statsMutex.Unlock()

	f.stats.TotalJobs++
	if success {
		f.stats.SuccessfulJobs++
	} else {
		f.stats.FailedJobs++
	}

	f.stats.TotalBytesDownloaded += bytesDownloaded
	f.stats.LastFetchTime = time.Now()

	// Update average duration
	if f.stats.TotalJobs > 0 {
		totalDuration := f.stats.AverageDuration*time.Duration(f.stats.TotalJobs-1) + duration
		f.stats.AverageDuration = totalDuration / time.Duration(f.stats.TotalJobs)
	}
}

// createStorageDirectories creates necessary storage directories
func (f *Fetcher) createStorageDirectories() error {
	basePath := f.config.Storage.BasePath

	// Create base directory
	if err := os.MkdirAll(basePath, 0755); err != nil {
		return fmt.Errorf("failed to create base directory: %w", err)
	}

	// Create category subdirectories if enabled
	if f.config.Storage.CreateSubdirs {
		categories := []string{
			CategoryIPGeo,
			CategoryIPBlacklist,
			CategoryIPAnonymization,
			CategoryDomain,
			CategoryHash,
			CategoryIOC,
			CategoryASN,
			CategoryMixed,
		}

		for _, category := range categories {
			categoryPath := filepath.Join(basePath, category)
			if err := os.MkdirAll(categoryPath, 0755); err != nil {
				return fmt.Errorf("failed to create directory %s: %w", categoryPath, err)
			}
		}

		log.Printf("Created storage directories under %s", basePath)
	}

	return nil
}

// ==========================================================================
// Helper Methods
// ==========================================================================

// GetActiveJobs returns currently running jobs
func (f *Fetcher) GetActiveJobs() []*FetchJob {
	f.jobMutex.RLock()
	defer f.jobMutex.RUnlock()

	jobs := make([]*FetchJob, 0, len(f.activeJobs))
	for _, job := range f.activeJobs {
		jobs = append(jobs, job)
	}

	return jobs
}

// GetSourceByName finds a source by name
func (f *Fetcher) GetSourceByName(name string) (*Source, error) {
	for _, source := range f.sources {
		if source.Name == name {
			return &source, nil
		}
	}
	return nil, fmt.Errorf("source not found: %s", name)
}
