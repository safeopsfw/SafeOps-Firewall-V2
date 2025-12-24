package fetcher

import (
	"compress/gzip"
	"context"
	"encoding/base64"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"
)

// ==========================================================================
// HTTPDownloader Struct Definition
// ==========================================================================

// HTTPDownloader handles HTTP/HTTPS downloading of threat intelligence feeds
type HTTPDownloader struct {
	client      *http.Client
	userAgent   string
	timeout     time.Duration
	maxFileSize int64 // bytes
	logger      interface{}
}

// ==========================================================================
// NewHTTPDownloader Constructor
// ==========================================================================

// NewHTTPDownloader creates and configures HTTP client
func NewHTTPDownloader(maxFileSizeMB int, timeout time.Duration) *HTTPDownloader {
	// Create HTTP client with custom transport
	transport := &http.Transport{
		MaxIdleConns:       10,
		IdleConnTimeout:    30 * time.Second,
		DisableCompression: false,
		DisableKeepAlives:  false,
	}

	client := &http.Client{
		Transport: transport,
		Timeout:   timeout,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			// Limit redirects to prevent loops
			if len(via) >= 10 {
				return fmt.Errorf("too many redirects")
			}
			return nil
		},
	}

	return &HTTPDownloader{
		client:      client,
		userAgent:   "SafeOps-ThreatIntel-Fetcher/2.0",
		timeout:     timeout,
		maxFileSize: int64(maxFileSizeMB) * 1024 * 1024,
	}
}

// ==========================================================================
// Main Download Methods
// ==========================================================================

// Download downloads a file from URL to disk
func (d *HTTPDownloader) Download(url string, outputPath string, authConfig *AuthConfig) error {
	// Create request with context for timeout
	ctx, cancel := context.WithTimeout(context.Background(), d.timeout)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return fmt.Errorf("failed to create request: %w", err)
	}

	// Set headers
	req.Header.Set("User-Agent", d.userAgent)
	req.Header.Set("Accept", "*/*")

	// Add authentication if provided
	if authConfig != nil {
		if err := d.addAuthHeaders(req, authConfig); err != nil {
			return fmt.Errorf("failed to add auth headers: %w", err)
		}
	}

	// Execute request
	resp, err := d.client.Do(req)
	if err != nil {
		return fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close()

	// Check response status
	if err := d.handleHTTPError(resp); err != nil {
		return err
	}

	// Validate response
	if err := d.validateResponse(resp); err != nil {
		return err
	}

	// Create output file
	out, err := os.Create(outputPath)
	if err != nil {
		return fmt.Errorf("failed to create output file: %w", err)
	}
	defer out.Close()

	// Handle gzip decompression
	var reader io.Reader = resp.Body
	if strings.HasSuffix(url, ".gz") || resp.Header.Get("Content-Encoding") == "gzip" {
		gzReader, err := gzip.NewReader(resp.Body)
		if err != nil {
			return fmt.Errorf("gzip decode failed: %w", err)
		}
		defer gzReader.Close()
		reader = gzReader
	}

	// Stream response body to file (efficient for large files)
	written, err := io.Copy(out, reader)
	if err != nil {
		os.Remove(outputPath) // Clean up partial file
		return fmt.Errorf("failed to write file: %w", err)
	}

	// Verify size if Content-Length was provided (skip for gzip)
	if !strings.HasSuffix(url, ".gz") && resp.ContentLength > 0 && written != resp.ContentLength {
		os.Remove(outputPath)
		return fmt.Errorf("size mismatch: expected %d bytes, got %d bytes",
			resp.ContentLength, written)
	}

	return nil
}

// DownloadWithProgress downloads file with progress tracking
func (d *HTTPDownloader) DownloadWithProgress(url string, outputPath string,
	authConfig *AuthConfig, progressChan chan<- int64) error {

	// Create request
	ctx, cancel := context.WithTimeout(context.Background(), d.timeout)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return fmt.Errorf("failed to create request: %w", err)
	}

	// Set headers
	req.Header.Set("User-Agent", d.userAgent)
	req.Header.Set("Accept", "*/*")

	if authConfig != nil {
		if err := d.addAuthHeaders(req, authConfig); err != nil {
			return err
		}
	}

	// Execute request
	resp, err := d.client.Do(req)
	if err != nil {
		return fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close()

	if err := d.handleHTTPError(resp); err != nil {
		return err
	}

	// Create output file
	out, err := os.Create(outputPath)
	if err != nil {
		return fmt.Errorf("failed to create output file: %w", err)
	}
	defer out.Close()

	// Progress reader
	reader := &progressReader{
		reader:       resp.Body,
		progressChan: progressChan,
	}

	// Copy with progress
	_, err = io.Copy(out, reader)
	if err != nil {
		os.Remove(outputPath)
		return fmt.Errorf("failed to write file: %w", err)
	}

	close(progressChan)
	return nil
}

// ==========================================================================
// Authentication Methods
// ==========================================================================

// addAuthHeaders adds authentication headers to HTTP request
func (d *HTTPDownloader) addAuthHeaders(req *http.Request, config *AuthConfig) error {
	switch config.Type {
	case AuthTypeAPIKey:
		// Default header name is X-API-Key, but can be customized
		headerName := "X-API-Key"
		if config.HeaderName != "" {
			headerName = config.HeaderName
		}

		// Get API key from environment
		apiKey := os.Getenv("FEED_API_KEY")
		if apiKey == "" {
			return fmt.Errorf("FEED_API_KEY environment variable not set")
		}

		req.Header.Set(headerName, apiKey)

	case AuthTypeBearer:
		// Get bearer token from environment
		token := os.Getenv("FEED_BEARER_TOKEN")
		if token == "" {
			return fmt.Errorf("FEED_BEARER_TOKEN environment variable not set")
		}

		req.Header.Set("Authorization", "Bearer "+token)

	case AuthTypeBasic:
		// Get username and password from environment
		username := os.Getenv("FEED_USERNAME")
		password := os.Getenv("FEED_PASSWORD")

		if username == "" || password == "" {
			return fmt.Errorf("FEED_USERNAME and FEED_PASSWORD environment variables required")
		}

		// Encode credentials
		credentials := base64.StdEncoding.EncodeToString([]byte(username + ":" + password))
		req.Header.Set("Authorization", "Basic "+credentials)

	case AuthTypeOAuth:
		// Get OAuth token from environment
		token := os.Getenv("FEED_OAUTH_TOKEN")
		if token == "" {
			return fmt.Errorf("FEED_OAUTH_TOKEN environment variable not set")
		}

		req.Header.Set("Authorization", "Bearer "+token)

	case AuthTypeNone:
		// No authentication needed

	default:
		return fmt.Errorf("unsupported auth type: %s", config.Type)
	}

	return nil
}

// ==========================================================================
// Validation and Error Handling
// ==========================================================================

// validateResponse checks if HTTP response is valid
func (d *HTTPDownloader) validateResponse(resp *http.Response) error {
	// Check Content-Length if provided
	if resp.ContentLength > 0 {
		if resp.ContentLength > d.maxFileSize {
			return fmt.Errorf("file too large: %d bytes (max %d bytes)",
				resp.ContentLength, d.maxFileSize)
		}
	}

	// Content-Type check (optional, some feeds don't set it correctly)
	contentType := resp.Header.Get("Content-Type")
	if contentType != "" {
		// Just log warning if unexpected, don't fail
		_ = contentType
	}

	return nil
}

// handleHTTPError converts HTTP errors to actionable error messages
func (d *HTTPDownloader) handleHTTPError(resp *http.Response) error {
	if resp.StatusCode >= 200 && resp.StatusCode < 300 {
		return nil // Success
	}

	// Read error response body (limited)
	bodyBytes := make([]byte, 1024)
	n, _ := resp.Body.Read(bodyBytes)
	responseBody := string(bodyBytes[:n])

	switch resp.StatusCode {
	case 400:
		return fmt.Errorf("bad request (400): %s", responseBody)
	case 401:
		return fmt.Errorf("authentication failed (401) - check API key or credentials")
	case 403:
		return fmt.Errorf("access forbidden (403) - insufficient permissions")
	case 404:
		return fmt.Errorf("source URL not found (404) - check configuration")
	case 429:
		// Rate limited - should retry later
		retryAfter := resp.Header.Get("Retry-After")
		if retryAfter != "" {
			return &RetryableError{
				Message:    fmt.Sprintf("rate limited (429) - retry after %s seconds", retryAfter),
				RetryAfter: retryAfter,
			}
		}
		return &RetryableError{Message: "rate limited (429) - will retry later"}

	case 500, 502, 503, 504:
		// Server errors - retryable
		return &RetryableError{
			Message: fmt.Sprintf("server error (%d) - will retry", resp.StatusCode),
		}

	default:
		return fmt.Errorf("HTTP error %d: %s", resp.StatusCode, responseBody)
	}
}

// ==========================================================================
// Error Types
// ==========================================================================

// RetryableError indicates an error that should trigger a retry
type RetryableError struct {
	Message    string
	RetryAfter string
}

func (e *RetryableError) Error() string {
	return e.Message
}

// IsRetryable checks if error should trigger retry
func IsRetryable(err error) bool {
	if err == nil {
		return false
	}

	// Check if it's a RetryableError
	if _, ok := err.(*RetryableError); ok {
		return true
	}

	// Check error message for common retryable patterns
	errMsg := strings.ToLower(err.Error())
	retryablePatterns := []string{
		"connection refused",
		"connection timeout",
		"timeout",
		"temporary failure",
		"rate limit",
		"server error",
		"502", "503", "504",
	}

	for _, pattern := range retryablePatterns {
		if strings.Contains(errMsg, pattern) {
			return true
		}
	}

	return false
}

// ==========================================================================
// Progress Reader
// ==========================================================================

// progressReader wraps io.Reader to emit progress events
type progressReader struct {
	reader       io.Reader
	total        int64
	progressChan chan<- int64
}

func (r *progressReader) Read(p []byte) (int, error) {
	n, err := r.reader.Read(p)
	r.total += int64(n)

	// Send progress update
	if r.progressChan != nil {
		select {
		case r.progressChan <- r.total:
		default:
			// Don't block if channel is full
		}
	}

	return n, err
}
