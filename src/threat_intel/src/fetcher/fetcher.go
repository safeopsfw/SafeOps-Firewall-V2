package fetcher

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

// ==========================================================================
// Fetcher Struct Definition
// ==========================================================================

// Fetcher orchestrates the entire download process for threat intelligence feeds
type Fetcher struct {
	config       *Config
	sources      []Source
	httpClient   *HTTPDownloader
	githubClient *GitHubDownloader
	jobQueue     chan *FetchJob
	activeJobs   map[string]*FetchJob
	jobMutex     sync.RWMutex
	stats        *FetchStats
	statsMutex   sync.Mutex
	logger       *log.Logger
	ctx          context.Context
	cancel       context.CancelFunc
	startTime    time.Time
}

// Config holds fetcher-specific configuration
type Config struct {
	StoragePath   string
	MaxConcurrent int
	RetryAttempts int
	RetryDelay    int // seconds
	MaxFileSize   int // MB
	JobTimeout    int // seconds
	CreateSubdirs bool
}

// ==========================================================================
// FetchJob Struct Definition
// ==========================================================================

// FetchJob represents a single fetch operation
type FetchJob struct {
	Source      Source
	ScheduledAt time.Time
	StartedAt   time.Time
	CompletedAt time.Time
	Status      string // queued, running, success, failed, retrying
	Attempt     int
	Error       string
	FilePath    string
	FileSize    int64
	Duration    time.Duration
}

// ==========================================================================
// FetchStats Struct Definition
// ==========================================================================

// FetchStats holds aggregated statistics for monitoring
type FetchStats struct {
	TotalJobs            int
	SuccessfulJobs       int
	FailedJobs           int
	TotalBytesDownloaded int64
	AverageDuration      time.Duration
	LastFetchTime        time.Time
}

// ==========================================================================
// FetcherReport JSON Output (FETCHER'S ONLY FINAL OUTPUT)
// ==========================================================================

// FetcherReport is the JSON output report - fetcher's final deliverable
type FetcherReport struct {
	JobStarted           time.Time `json:"job_started"`
	JobCompleted         time.Time `json:"job_completed"`
	DurationSeconds      float64   `json:"duration_seconds"`
	TotalSources         int       `json:"total_sources"`
	EnabledSources       int       `json:"enabled_sources"`
	SuccessfulDownloads  int       `json:"successful_downloads"`
	FailedDownloads      int       `json:"failed_downloads"`
	TotalBytesDownloaded int64     `json:"total_bytes_downloaded"`
	TotalMBDownloaded    float64   `json:"total_mb_downloaded"`
	DownloadedFiles      []string  `json:"downloaded_files"`
	OutputDirectory      string    `json:"output_directory"`
	Status               string    `json:"status"` // "completed", "partial", "failed"
}

// ==========================================================================
// NewFetcher Constructor
// ==========================================================================

// NewFetcher initializes and returns a Fetcher instance
func NewFetcher(config *Config, sources []Source) (*Fetcher, error) {
	// Validate config
	if config.StoragePath == "" {
		return nil, fmt.Errorf("storage path is required")
	}

	// Create storage directories
	if err := os.MkdirAll(config.StoragePath, 0755); err != nil {
		return nil, fmt.Errorf("failed to create storage directory: %w", err)
	}

	// Create category subdirectories using simplified structure (domain/ip/hash)
	if config.CreateSubdirs {
		if err := CreateOutputDirectories(config.StoragePath); err != nil {
			return nil, fmt.Errorf("failed to create output directories: %w", err)
		}
	}

	// Validate sources
	if errs := ValidateSources(sources); len(errs) > 0 {
		return nil, fmt.Errorf("source validation failed: %v", errs[0])
	}

	// Create context for graceful shutdown
	ctx, cancel := context.WithCancel(context.Background())

	// Initialize fetcher
	fetcher := &Fetcher{
		config:       config,
		sources:      sources,
		httpClient:   NewHTTPDownloader(config.MaxFileSize, time.Duration(config.JobTimeout)*time.Second),
		githubClient: NewGitHubDownloader(),
		jobQueue:     make(chan *FetchJob, 100), // Buffered channel
		activeJobs:   make(map[string]*FetchJob),
		stats:        &FetchStats{},
		logger:       log.New(os.Stdout, "[FETCHER] ", log.LstdFlags),
		ctx:          ctx,
		cancel:       cancel,
		startTime:    time.Now(),
	}

	// Start job processors
	for i := 0; i < config.MaxConcurrent; i++ {
		go fetcher.jobProcessor(i)
	}

	fetcher.logger.Printf("Fetcher initialized with %d sources, max %d concurrent downloads\n",
		len(sources), config.MaxConcurrent)

	return fetcher, nil
}

// ==========================================================================
// Main Fetching Methods
// ==========================================================================

// Start begins the fetching process for all enabled sources
func (f *Fetcher) Start() error {
	f.startTime = time.Now()
	enabledSources := GetEnabledSources(f.sources)
	f.logger.Printf("Starting fetch for %d enabled sources\n", len(enabledSources))

	// Sort by priority
	prioritized := GetSourcesByPriority(enabledSources)

	// Queue all sources
	for _, source := range prioritized {
		job := &FetchJob{
			Source:      source,
			ScheduledAt: time.Now(),
			Status:      "queued",
			Attempt:     1,
		}

		f.jobQueue <- job
		f.logger.Printf("Queued fetch job for: %s\n", source.Name)
	}

	return nil
}

// FetchAll performs one-time fetch of all enabled sources (no scheduling)
func (f *Fetcher) FetchAll() (*FetchStats, error) {
	if err := f.Start(); err != nil {
		return nil, err
	}

	// Wait for all jobs to complete
	timeout := time.After(time.Duration(f.config.JobTimeout) * time.Second * time.Duration(len(f.sources)))
	ticker := time.NewTicker(1 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-timeout:
			return f.GetStats(), fmt.Errorf("fetch timeout exceeded")
		case <-ticker.C:
			if f.allJobsComplete() {
				return f.GetStats(), nil
			}
		}
	}
}

// FetchSource fetches a single source
func (f *Fetcher) FetchSource(source *Source) error {
	// Validate source
	if err := ValidateSource(source); err != nil {
		return fmt.Errorf("source validation failed: %w", err)
	}

	// Check if recently fetched (avoid duplicates)
	if !source.ShouldFetch() {
		f.logger.Printf("Skipping %s - recently fetched at %s\n",
			source.Name, source.LastFetched.Format(time.RFC3339))
		return nil
	}

	// Determine output path based on category
	// IOC/Mixed feeds go to 'pending' folder for content analysis
	// Other feeds go directly to domain/ip/hash folders
	outputPath := f.getOutputPath(source)

	// Ensure directory exists
	if err := os.MkdirAll(filepath.Dir(outputPath), 0755); err != nil {
		return fmt.Errorf("failed to create output directory: %w", err)
	}

	// Download file
	if NeedsContentAnalysis(source.Category) {
		f.logger.Printf("Downloading IOC feed %s (will require content analysis) from %s\n", source.Name, source.URL)
	} else {
		f.logger.Printf("Downloading %s to %s folder from %s\n", source.Name, GetOutputFolder(source.Category), source.URL)
	}
	startTime := time.Now()

	var err error
	if isGitHubURL(source.URL) {
		err = f.githubClient.DownloadFromGitHub(source.URL, outputPath)
	} else {
		var authConfig *AuthConfig
		if source.AuthRequired {
			authConfig = &AuthConfig{
				Type: source.AuthType,
				// Auth values loaded from environment in http.go
			}
		}
		err = f.httpClient.Download(source.URL, outputPath, authConfig)
	}

	duration := time.Since(startTime)

	if err != nil {
		return fmt.Errorf("download failed: %w", err)
	}

	// Validate downloaded file
	fileInfo, err := f.validateDownloadedFile(outputPath, source.Format)
	if err != nil {
		os.Remove(outputPath) // Clean up invalid file
		return fmt.Errorf("file validation failed: %w", err)
	}

	// Update source metadata
	source.LastFetched = time.Now()
	source.FetchCount++

	// Log where the file was saved
	if NeedsContentAnalysis(source.Category) {
		f.logger.Printf("Downloaded IOC feed %s (%d bytes) in %s - PENDING content analysis\n",
			source.Name, fileInfo.Size(), duration)
	} else {
		f.logger.Printf("Successfully downloaded %s (%d bytes) to %s/ in %s\n",
			source.Name, fileInfo.Size(), GetOutputFolder(source.Category), duration)
	}

	// NOTE: Files saved in data/fetch/{domain|ip|hash}/ folders
	// IOC feeds saved in data/fetch/pending/ need parser to analyze and split content
	// Fetcher ONLY downloads - parser handles content analysis and database insertion

	return nil
}

// ==========================================================================
// Job Processing
// ==========================================================================

// jobProcessor processes jobs from the queue
func (f *Fetcher) jobProcessor(workerID int) {
	for {
		select {
		case <-f.ctx.Done():
			return
		case job := <-f.jobQueue:
			f.processFetchJob(workerID, job)
		}
	}
}

// processFetchJob processes a single fetch job
func (f *Fetcher) processFetchJob(workerID int, job *FetchJob) {
	// Mark job as running
	job.Status = "running"
	job.StartedAt = time.Now()

	f.jobMutex.Lock()
	f.activeJobs[job.Source.Name] = job
	f.jobMutex.Unlock()

	f.logger.Printf("[Worker %d] Processing: %s (attempt %d)\n",
		workerID, job.Source.Name, job.Attempt)

	// Execute fetch
	err := f.FetchSource(&job.Source)

	job.CompletedAt = time.Now()
	job.Duration = job.CompletedAt.Sub(job.StartedAt)

	// Handle result
	if err != nil {
		job.Status = "failed"
		job.Error = err.Error()
		f.logger.Printf("[Worker %d] Failed: %s - %s\n", workerID, job.Source.Name, err.Error())

		// Check if should retry
		if job.Attempt < f.config.RetryAttempts {
			f.retryJob(job)
		} else {
			f.updateStats(job, false)
		}
	} else {
		job.Status = "success"
		f.logger.Printf("[Worker %d] Success: %s in %s\n",
			workerID, job.Source.Name, job.Duration)
		f.updateStats(job, true)
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

	// Calculate exponential backoff
	delay := time.Duration(f.config.RetryDelay) * time.Second * time.Duration(job.Attempt)

	f.logger.Printf("Retrying %s in %s (attempt %d/%d)\n",
		job.Source.Name, delay, job.Attempt, f.config.RetryAttempts)

	// Re-queue after delay
	go func() {
		time.Sleep(delay)
		f.jobQueue <- job
	}()
}

// ==========================================================================
// Helper Methods
// ==========================================================================

// getOutputPath determines where to save downloaded file
func (f *Fetcher) getOutputPath(source *Source) string {
	// Base path from config
	basePath := f.config.StoragePath

	// Get output folder based on source category
	// IOC/Mixed feeds go to 'pending' folder for content analysis
	// Regular feeds go to domain/ip/hash folders
	outputFolder := GetOutputFolder(source.Category)
	if outputFolder == "" {
		// IOC/Mixed feeds need content analysis - save to pending folder
		outputFolder = "pending"
	}
	folderPath := filepath.Join(basePath, outputFolder)

	// Generate filename: {source_name}_{timestamp}.{extension}
	timestamp := time.Now().Format("20060102_150405")
	extension := getFileExtension(source.Format)
	filename := fmt.Sprintf("%s_%s.%s",
		sanitizeFilename(source.Name), timestamp, extension)

	return filepath.Join(folderPath, filename)
}

// validateDownloadedFile checks if downloaded file is valid
func (f *Fetcher) validateDownloadedFile(filePath string, format string) (os.FileInfo, error) {
	// Check file exists
	fileInfo, err := os.Stat(filePath)
	if err != nil {
		return nil, fmt.Errorf("file not found: %w", err)
	}

	// Check file size > 0
	if fileInfo.Size() == 0 {
		return nil, fmt.Errorf("file is empty")
	}

	// Check file size < max
	maxSizeBytes := int64(f.config.MaxFileSize) * 1024 * 1024
	if fileInfo.Size() > maxSizeBytes {
		return nil, fmt.Errorf("file exceeds max size (%d MB)", f.config.MaxFileSize)
	}

	// Check file extension matches format
	expectedExt := getFileExtension(format)
	actualExt := filepath.Ext(filePath)
	if actualExt != "."+expectedExt {
		return nil, fmt.Errorf("file extension mismatch: expected .%s, got %s",
			expectedExt, actualExt)
	}

	// NOTE: Parser will do deeper content validation later

	return fileInfo, nil
}

// updateStats updates fetch statistics
func (f *Fetcher) updateStats(job *FetchJob, success bool) {
	f.statsMutex.Lock()
	defer f.statsMutex.Unlock()

	f.stats.TotalJobs++
	if success {
		f.stats.SuccessfulJobs++
		if job.FileSize > 0 {
			f.stats.TotalBytesDownloaded += job.FileSize
		}
	} else {
		f.stats.FailedJobs++
	}

	// Update average duration
	if f.stats.TotalJobs > 0 {
		totalDuration := f.stats.AverageDuration * time.Duration(f.stats.TotalJobs-1)
		f.stats.AverageDuration = (totalDuration + job.Duration) / time.Duration(f.stats.TotalJobs)
	}

	f.stats.LastFetchTime = time.Now()
}

// allJobsComplete checks if all jobs are finished
func (f *Fetcher) allJobsComplete() bool {
	f.jobMutex.RLock()
	defer f.jobMutex.RUnlock()

	return len(f.activeJobs) == 0 && len(f.jobQueue) == 0
}

// ==========================================================================
// JSON Report Generation (FETCHER'S FINAL OUTPUT)
// ==========================================================================

// SaveReport generates and saves JSON report - THIS IS FETCHER'S ONLY JOB OUTPUT
func (f *Fetcher) SaveReport(reportPath string) error {
	stats := f.GetStats()
	endTime := time.Now()
	duration := endTime.Sub(f.startTime)

	// Scan downloaded files
	downloadedFiles := f.scanDownloadedFiles()

	// Create report
	report := &FetcherReport{
		JobStarted:           f.startTime,
		JobCompleted:         endTime,
		DurationSeconds:      duration.Seconds(),
		TotalSources:         len(f.sources),
		EnabledSources:       len(GetEnabledSources(f.sources)),
		SuccessfulDownloads:  stats.SuccessfulJobs,
		FailedDownloads:      stats.FailedJobs,
		TotalBytesDownloaded: stats.TotalBytesDownloaded,
		TotalMBDownloaded:    float64(stats.TotalBytesDownloaded) / (1024 * 1024),
		DownloadedFiles:      downloadedFiles,
		OutputDirectory:      f.config.StoragePath,
	}

	// Determine status
	if stats.FailedJobs == 0 {
		report.Status = "completed"
	} else if stats.SuccessfulJobs > 0 {
		report.Status = "partial"
	} else {
		report.Status = "failed"
	}

	// Marshal to JSON with indentation
	data, err := json.MarshalIndent(report, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal report: %w", err)
	}

	// Ensure report directory exists
	reportDir := filepath.Dir(reportPath)
	if reportDir != "." && reportDir != "" {
		if err := os.MkdirAll(reportDir, 0755); err != nil {
			return fmt.Errorf("failed to create report directory: %w", err)
		}
	}

	// Write to file
	if err := os.WriteFile(reportPath, data, 0644); err != nil {
		return fmt.Errorf("failed to write report: %w", err)
	}

	f.logger.Println("===========================================")
	f.logger.Printf("FETCHER JOB COMPLETE\n")
	f.logger.Printf("Status: %s\n", report.Status)
	f.logger.Printf("Downloaded: %d files (%.2f MB)\n", report.SuccessfulDownloads, report.TotalMBDownloaded)
	f.logger.Printf("Failed: %d\n", report.FailedDownloads)
	f.logger.Printf("Output directory: %s\n", f.config.StoragePath)
	f.logger.Printf("Report saved: %s\n", reportPath)
	f.logger.Println("===========================================")

	return nil
}

// scanDownloadedFiles scans output directory for all downloaded files
func (f *Fetcher) scanDownloadedFiles() []string {
	var files []string

	// Use the new simplified folder structure: domain, ip, hash, pending
	folders := GetAllOutputFolders()

	for _, folder := range folders {
		folderPath := filepath.Join(f.config.StoragePath, folder)

		if _, err := os.Stat(folderPath); os.IsNotExist(err) {
			continue
		}

		filepath.Walk(folderPath, func(path string, info os.FileInfo, err error) error {
			if err != nil || info.IsDir() {
				return nil
			}

			// Store relative path
			relPath, _ := filepath.Rel(f.config.StoragePath, path)
			files = append(files, relPath)
			return nil
		})
	}

	return files
}

// ==========================================================================
// Public Methods
// ==========================================================================

// GetStats returns current fetch statistics
func (f *Fetcher) GetStats() *FetchStats {
	f.statsMutex.Lock()
	defer f.statsMutex.Unlock()

	// Return copy
	stats := *f.stats
	return &stats
}

// Stop gracefully shuts down the fetcher
func (f *Fetcher) Stop() {
	f.logger.Println("Shutting down fetcher...")

	// Signal shutdown
	f.cancel()

	// Wait for active jobs to complete (with timeout)
	timeout := time.After(30 * time.Second)
	ticker := time.NewTicker(1 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-timeout:
			f.logger.Println("Shutdown timeout - forcing stop")
			return
		case <-ticker.C:
			if f.allJobsComplete() {
				f.logger.Println("All jobs complete - shutdown successful")
				return
			}
		}
	}
}

// ==========================================================================
// Utility Functions
// ==========================================================================

// getFileExtension returns file extension for format
func getFileExtension(format string) string {
	switch format {
	case FormatCSV:
		return "csv"
	case FormatJSON:
		return "json"
	case FormatTXT:
		return "txt"
	case FormatXML:
		return "xml"
	case FormatMMDB:
		return "mmdb"
	case FormatTSV:
		return "tsv"
	default:
		return "dat"
	}
}

// sanitizeFilename removes unsafe characters from filename
func sanitizeFilename(name string) string {
	// Replace spaces and special characters
	safe := ""
	for _, r := range name {
		if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') ||
			(r >= '0' && r <= '9') || r == '-' || r == '_' {
			safe += string(r)
		} else if r == ' ' {
			safe += "_"
		}
	}
	return safe
}

// isGitHubURL checks if URL is a GitHub URL
func isGitHubURL(urlStr string) bool {
	return strings.HasPrefix(urlStr, "https://github.com/") ||
		strings.HasPrefix(urlStr, "https://raw.githubusercontent.com/")
}
