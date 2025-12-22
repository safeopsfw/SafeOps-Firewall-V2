package fetcher

import (
	"compress/gzip"
	"context"
	"encoding/base64"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"threat_intel/config"
)

// ==========================================================================
// HTTPDownloader Struct
// ==========================================================================

// HTTPDownloader handles HTTP/HTTPS file downloads
type HTTPDownloader struct {
	client        *http.Client
	userAgent     string
	timeout       time.Duration
	maxFileSize   int64
	retryAttempts int
}

// ProgressCallback is called during download to report progress
type ProgressCallback func(bytesDownloaded int64, totalBytes int64, percentage float64)

// ==========================================================================
// Constructor
// ==========================================================================

// NewHTTPDownloader creates and configures an HTTP downloader
func NewHTTPDownloader(cfg *config.Config) *HTTPDownloader {
	// Create HTTP client with reasonable timeout for varied file sizes
	client := &http.Client{
		Timeout: 45 * time.Second, // 45s timeout - balance between speed and reliability
		Transport: &http.Transport{
			MaxIdleConns:          10,
			IdleConnTimeout:       15 * time.Second,
			DisableCompression:    false,
			DisableKeepAlives:     false,
			MaxIdleConnsPerHost:   5,
			ResponseHeaderTimeout: 15 * time.Second,
			DialContext: (&net.Dialer{
				Timeout:   10 * time.Second,
				KeepAlive: 15 * time.Second,
			}).DialContext,
		},
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) >= 5 {
				return fmt.Errorf("too many redirects")
			}
			return nil
		},
	}

	return &HTTPDownloader{
		client:        client,
		userAgent:     "SafeOps-ThreatIntel/2.0",
		timeout:       45 * time.Second, // 45 second timeout
		maxFileSize:   int64(cfg.Storage.MaxFileSize) * 1024 * 1024,
		retryAttempts: 2, // Max 2 retries then skip
	}
}

// ==========================================================================
// Main Download Method
// ==========================================================================

// Download downloads a file from URL and saves it to outputPath
func (d *HTTPDownloader) Download(url, outputPath string) (int64, error) {
	return d.DownloadWithAuth(url, outputPath, nil)
}

// DownloadWithAuth downloads a file with optional authentication
func (d *HTTPDownloader) DownloadWithAuth(url, outputPath string, auth *AuthConfig) (int64, error) {
	// Create request with context for timeout
	ctx, cancel := context.WithTimeout(context.Background(), d.timeout)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return 0, fmt.Errorf("failed to create request: %w", err)
	}

	// Set headers
	req.Header.Set("User-Agent", d.userAgent)
	req.Header.Set("Accept", "*/*") // Accept any content type

	// Add authentication headers if provided
	if auth != nil {
		if err := d.addAuthHeaders(req, auth); err != nil {
			return 0, fmt.Errorf("failed to add auth headers: %w", err)
		}
	}

	// Execute request
	resp, err := d.client.Do(req)
	if err != nil {
		if isRetryableError(err) {
			return 0, &RetryableError{err}
		}
		return 0, fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close()

	// Validate response
	if err := d.validateResponse(resp); err != nil {
		return 0, err
	}

	// Check Content-Length against max file size
	if resp.ContentLength > 0 {
		if resp.ContentLength > d.maxFileSize {
			return 0, fmt.Errorf("file size (%d bytes) exceeds maximum (%d bytes)",
				resp.ContentLength, d.maxFileSize)
		}
	}

	// Create output directory if needed
	if err := os.MkdirAll(filepath.Dir(outputPath), 0755); err != nil {
		return 0, fmt.Errorf("failed to create output directory: %w", err)
	}

	// Check if URL is gzip compressed (ends with .gz)
	isGzip := strings.HasSuffix(strings.ToLower(url), ".gz")

	// Adjust output path - remove .gz extension if decompressing
	finalOutputPath := outputPath
	if isGzip && strings.HasSuffix(outputPath, ".gz") {
		finalOutputPath = strings.TrimSuffix(outputPath, ".gz")
	}

	// Create output file
	outFile, err := os.Create(finalOutputPath)
	if err != nil {
		return 0, fmt.Errorf("failed to create output file: %w", err)
	}
	defer outFile.Close()

	// Handle gzip decompression if needed
	var reader io.Reader = resp.Body
	if isGzip {
		gzReader, err := gzip.NewReader(resp.Body)
		if err != nil {
			os.Remove(finalOutputPath)
			return 0, fmt.Errorf("failed to create gzip reader: %w", err)
		}
		defer gzReader.Close()
		reader = gzReader
	}

	// Stream response body to file (efficient for large files)
	bytesWritten, err := io.Copy(outFile, reader)
	if err != nil {
		// Clean up partial download
		os.Remove(finalOutputPath)
		return 0, fmt.Errorf("failed to write file: %w", err)
	}

	// Skip size verification for gzip (compressed vs uncompressed size differs)
	if !isGzip && resp.ContentLength > 0 && bytesWritten != resp.ContentLength {
		os.Remove(finalOutputPath)
		return 0, fmt.Errorf("size mismatch: expected %d bytes, got %d bytes",
			resp.ContentLength, bytesWritten)
	}

	// File successfully downloaded and saved to feeds/{category}/ directory
	// Parser will read this file in the next pipeline stage
	return bytesWritten, nil
}

// ==========================================================================
// Download with Progress Tracking
// ==========================================================================

// DownloadWithProgress downloads a file with progress callback
func (d *HTTPDownloader) DownloadWithProgress(url, outputPath string, auth *AuthConfig, callback ProgressCallback) (int64, error) {
	// Create request
	ctx, cancel := context.WithTimeout(context.Background(), d.timeout)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return 0, fmt.Errorf("failed to create request: %w", err)
	}

	// Set headers
	req.Header.Set("User-Agent", d.userAgent)
	req.Header.Set("Accept", "*/*")

	if auth != nil {
		if err := d.addAuthHeaders(req, auth); err != nil {
			return 0, fmt.Errorf("failed to add auth headers: %w", err)
		}
	}

	// Execute request
	resp, err := d.client.Do(req)
	if err != nil {
		return 0, fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close()

	// Validate response
	if err := d.validateResponse(resp); err != nil {
		return 0, err
	}

	// Create output file
	if err := os.MkdirAll(filepath.Dir(outputPath), 0755); err != nil {
		return 0, fmt.Errorf("failed to create output directory: %w", err)
	}

	outFile, err := os.Create(outputPath)
	if err != nil {
		return 0, fmt.Errorf("failed to create output file: %w", err)
	}
	defer outFile.Close()

	// Wrap reader with progress tracker
	progressReader := &progressReader{
		reader:   resp.Body,
		total:    resp.ContentLength,
		callback: callback,
	}

	// Stream with progress tracking
	bytesWritten, err := io.Copy(outFile, progressReader)
	if err != nil {
		os.Remove(outputPath)
		return 0, fmt.Errorf("failed to write file: %w", err)
	}

	return bytesWritten, nil
}

// ==========================================================================
// Authentication Methods
// ==========================================================================

// addAuthHeaders adds authentication headers based on config
func (d *HTTPDownloader) addAuthHeaders(req *http.Request, auth *AuthConfig) error {
	switch strings.ToLower(auth.Type) {
	case "api_key":
		// API Key authentication
		headerName := auth.HeaderName
		if headerName == "" {
			headerName = "X-API-Key"
		}
		req.Header.Set(headerName, auth.APIKey)

	case "bearer":
		// Bearer token authentication
		if auth.Token == "" {
			return fmt.Errorf("bearer token is empty")
		}
		req.Header.Set("Authorization", "Bearer "+auth.Token)

	case "basic":
		// Basic authentication
		if auth.Username == "" || auth.Password == "" {
			return fmt.Errorf("username and password required for basic auth")
		}
		credentials := auth.Username + ":" + auth.Password
		encoded := base64.StdEncoding.EncodeToString([]byte(credentials))
		req.Header.Set("Authorization", "Basic "+encoded)

	case "oauth":
		// OAuth token (similar to bearer)
		if auth.Token == "" {
			return fmt.Errorf("oauth token is empty")
		}
		req.Header.Set("Authorization", "Bearer "+auth.Token)

	default:
		return fmt.Errorf("unsupported auth type: %s", auth.Type)
	}

	return nil
}

// ==========================================================================
// Response Validation
// ==========================================================================

// validateResponse checks if HTTP response is valid
func (d *HTTPDownloader) validateResponse(resp *http.Response) error {
	// Check status code
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return d.handleHTTPError(resp)
	}

	// Check Content-Length exists (warning only)
	if resp.ContentLength <= 0 {
		// Some servers don't provide Content-Length, that's OK
		// We'll just stream until EOF
	}

	return nil
}

// handleHTTPError converts HTTP errors to actionable error messages
func (d *HTTPDownloader) handleHTTPError(resp *http.Response) error {
	switch resp.StatusCode {
	case 401, 403:
		return &AuthError{
			StatusCode: resp.StatusCode,
			Message:    "Authentication failed - check API key or credentials",
		}

	case 404:
		return fmt.Errorf("source URL not found (HTTP 404) - check configuration")

	case 429:
		return &RetryableError{
			err: fmt.Errorf("rate limited (HTTP 429) - will retry later"),
		}

	case 408, 500, 502, 503, 504:
		return &RetryableError{
			err: fmt.Errorf("server error (HTTP %d) - will retry", resp.StatusCode),
		}

	default:
		// Try to read error details from response body
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 1024))
		return fmt.Errorf("HTTP error %d: %s", resp.StatusCode, string(body))
	}
}

// ==========================================================================
// Error Classification
// ==========================================================================

// isRetryableError determines if an error should trigger retry
func isRetryableError(err error) bool {
	if err == nil {
		return false
	}

	errMsg := err.Error()

	// Network errors that should be retried
	retryablePatterns := []string{
		"connection refused",
		"connection timeout",
		"connection reset",
		"temporary failure",
		"i/o timeout",
		"deadline exceeded",
		"no route to host",
	}

	for _, pattern := range retryablePatterns {
		if strings.Contains(strings.ToLower(errMsg), pattern) {
			return true
		}
	}

	return false
}

// RetryableError indicates an error that should be retried
type RetryableError struct {
	err error
}

func (e *RetryableError) Error() string {
	return e.err.Error()
}

func (e *RetryableError) Unwrap() error {
	return e.err
}

// AuthError indicates an authentication failure (not retryable)
type AuthError struct {
	StatusCode int
	Message    string
}

func (e *AuthError) Error() string {
	return fmt.Sprintf("auth error (HTTP %d): %s", e.StatusCode, e.Message)
}

// ==========================================================================
// Progress Reader
// ==========================================================================

// progressReader wraps an io.Reader to track download progress
type progressReader struct {
	reader   io.Reader
	total    int64
	current  int64
	callback ProgressCallback
}

func (pr *progressReader) Read(p []byte) (int, error) {
	n, err := pr.reader.Read(p)
	pr.current += int64(n)

	if pr.callback != nil && pr.total > 0 {
		percentage := float64(pr.current) / float64(pr.total) * 100
		pr.callback(pr.current, pr.total, percentage)
	}

	return n, err
}

// ==========================================================================
// Helper Methods
// ==========================================================================

// SetUserAgent updates the User-Agent header
func (d *HTTPDownloader) SetUserAgent(userAgent string) {
	d.userAgent = userAgent
}

// SetTimeout updates the request timeout
func (d *HTTPDownloader) SetTimeout(timeout time.Duration) {
	d.timeout = timeout
	d.client.Timeout = timeout
}

// IsRetryable checks if an error is retryable
func IsRetryable(err error) bool {
	if err == nil {
		return false
	}

	// Check if it's a RetryableError
	if _, ok := err.(*RetryableError); ok {
		return true
	}

	// Check error message patterns
	return isRetryableError(err)
}
