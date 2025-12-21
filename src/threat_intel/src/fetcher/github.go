package fetcher

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"
)

// ==========================================================================
// GitHubDownloader Struct
// ==========================================================================

// GitHubDownloader handles GitHub-specific file downloads
type GitHubDownloader struct {
	client             *http.Client
	apiBaseURL         string
	rawBaseURL         string
	token              string
	rateLimitRemaining int
	rateLimitReset     time.Time
	userAgent          string
}

// GitHubRepo represents parsed GitHub repository information
type GitHubRepo struct {
	Owner  string
	Repo   string
	Branch string
	Path   string
}

// GitHubRateLimit represents GitHub API rate limit response
type GitHubRateLimit struct {
	Resources struct {
		Core struct {
			Limit     int   `json:"limit"`
			Remaining int   `json:"remaining"`
			Reset     int64 `json:"reset"`
		} `json:"core"`
	} `json:"resources"`
}

// GitHubRelease represents a GitHub release
type GitHubRelease struct {
	TagName string `json:"tag_name"`
	Assets  []struct {
		Name               string `json:"name"`
		BrowserDownloadURL string `json:"browser_download_url"`
		Size               int64  `json:"size"`
	} `json:"assets"`
}

// GitHubError represents a GitHub API error response
type GitHubError struct {
	Message          string `json:"message"`
	DocumentationURL string `json:"documentation_url"`
}

// ==========================================================================
// Constructor
// ==========================================================================

// NewGitHubDownloader creates a GitHub-specific downloader
func NewGitHubDownloader() *GitHubDownloader {
	// Create HTTP client with GitHub requirements
	client := &http.Client{
		Timeout: 2 * time.Minute,
		Transport: &http.Transport{
			MaxIdleConns:       10,
			IdleConnTimeout:    30 * time.Second,
			DisableCompression: false,
		},
	}

	// Load GitHub token from environment (optional but recommended)
	token := os.Getenv("GITHUB_TOKEN")

	return &GitHubDownloader{
		client:             client,
		apiBaseURL:         "https://api.github.com",
		rawBaseURL:         "https://raw.githubusercontent.com",
		token:              token,
		userAgent:          "SafeOps-ThreatIntel/2.0",
		rateLimitRemaining: -1, // Unknown until first API call
	}
}

// ==========================================================================
// Main Download Methods
// ==========================================================================

// DownloadFromGitHub downloads a file from a GitHub repository
func (g *GitHubDownloader) DownloadFromGitHub(url, outputPath string) (int64, error) {
	// Parse GitHub URL
	repo, err := g.parseGitHubURL(url)
	if err != nil {
		return 0, fmt.Errorf("failed to parse GitHub URL: %w", err)
	}

	// Build raw URL (faster, no API limits for public repos)
	rawURL := g.buildRawURL(repo)

	// Create request
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, "GET", rawURL, nil)
	if err != nil {
		return 0, fmt.Errorf("failed to create request: %w", err)
	}

	// Set headers
	req.Header.Set("User-Agent", g.userAgent)

	// Add authentication if token available (improves rate limits)
	if g.token != "" {
		req.Header.Set("Authorization", "token "+g.token)
	}

	// Execute request
	resp, err := g.client.Do(req)
	if err != nil {
		return 0, fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close()

	// Handle errors
	if resp.StatusCode != 200 {
		return 0, g.handleGitHubError(resp)
	}

	// Create output directory
	if err := os.MkdirAll(filepath.Dir(outputPath), 0755); err != nil {
		return 0, fmt.Errorf("failed to create output directory: %w", err)
	}

	// Create output file
	outFile, err := os.Create(outputPath)
	if err != nil {
		return 0, fmt.Errorf("failed to create output file: %w", err)
	}
	defer outFile.Close()

	// Stream response to file
	bytesWritten, err := io.Copy(outFile, resp.Body)
	if err != nil {
		os.Remove(outputPath)
		return 0, fmt.Errorf("failed to write file: %w", err)
	}

	// File successfully downloaded and saved to feeds/{category}/ directory
	// Parser will read this file in the next pipeline stage
	return bytesWritten, nil
}

// DownloadLatestRelease downloads the latest release asset from a GitHub repository
func (g *GitHubDownloader) DownloadLatestRelease(owner, repo, assetPattern, outputPath string) (int64, error) {
	// Check rate limit before API call
	if err := g.checkRateLimit(); err != nil {
		return 0, err
	}

	// Build API URL for latest release
	apiURL := fmt.Sprintf("%s/repos/%s/%s/releases/latest", g.apiBaseURL, owner, repo)

	// Create request
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, "GET", apiURL, nil)
	if err != nil {
		return 0, fmt.Errorf("failed to create request: %w", err)
	}

	// Set headers
	req.Header.Set("User-Agent", g.userAgent)
	req.Header.Set("Accept", "application/vnd.github.v3+json")

	// Add authentication
	if g.token != "" {
		req.Header.Set("Authorization", "token "+g.token)
	}

	// Execute request
	resp, err := g.client.Do(req)
	if err != nil {
		return 0, fmt.Errorf("API request failed: %w", err)
	}
	defer resp.Body.Close()

	// Update rate limit from response headers
	g.updateRateLimitFromHeaders(resp)

	// Handle errors
	if resp.StatusCode != 200 {
		return 0, g.handleGitHubError(resp)
	}

	// Parse release response
	var release GitHubRelease
	if err := json.NewDecoder(resp.Body).Decode(&release); err != nil {
		return 0, fmt.Errorf("failed to parse release response: %w", err)
	}

	// Find matching asset
	var downloadURL string
	pattern := regexp.MustCompile(assetPattern)

	for _, asset := range release.Assets {
		if pattern.MatchString(asset.Name) {
			downloadURL = asset.BrowserDownloadURL
			break
		}
	}

	if downloadURL == "" {
		return 0, fmt.Errorf("no asset matching pattern '%s' found in release %s", assetPattern, release.TagName)
	}

	// Download the asset (using standard HTTP, not API)
	return g.downloadFile(downloadURL, outputPath)
}

// ==========================================================================
// URL Parsing Methods
// ==========================================================================

// parseGitHubURL extracts components from various GitHub URL formats
func (g *GitHubDownloader) parseGitHubURL(url string) (*GitHubRepo, error) {
	// Remove trailing slash
	url = strings.TrimSuffix(url, "/")

	// Pattern 1: https://github.com/{owner}/{repo}/blob/{branch}/{path}
	blobPattern := regexp.MustCompile(`github\.com/([^/]+)/([^/]+)/blob/([^/]+)/(.+)`)
	if matches := blobPattern.FindStringSubmatch(url); len(matches) == 5 {
		return &GitHubRepo{
			Owner:  matches[1],
			Repo:   matches[2],
			Branch: matches[3],
			Path:   matches[4],
		}, nil
	}

	// Pattern 2: https://github.com/{owner}/{repo}/raw/{branch}/{path}
	rawPattern := regexp.MustCompile(`github\.com/([^/]+)/([^/]+)/raw/([^/]+)/(.+)`)
	if matches := rawPattern.FindStringSubmatch(url); len(matches) == 5 {
		return &GitHubRepo{
			Owner:  matches[1],
			Repo:   matches[2],
			Branch: matches[3],
			Path:   matches[4],
		}, nil
	}

	// Pattern 3: https://raw.githubusercontent.com/{owner}/{repo}/{branch}/{path}
	rawGitPattern := regexp.MustCompile(`raw\.githubusercontent\.com/([^/]+)/([^/]+)/([^/]+)/(.+)`)
	if matches := rawGitPattern.FindStringSubmatch(url); len(matches) == 5 {
		return &GitHubRepo{
			Owner:  matches[1],
			Repo:   matches[2],
			Branch: matches[3],
			Path:   matches[4],
		}, nil
	}

	// Pattern 4: https://github.com/{owner}/{repo}/releases/download/{tag}/{file}
	releasePattern := regexp.MustCompile(`github\.com/([^/]+)/([^/]+)/releases/download/([^/]+)/(.+)`)
	if matches := releasePattern.FindStringSubmatch(url); len(matches) == 5 {
		// For releases, use the download URL directly
		return &GitHubRepo{
			Owner:  matches[1],
			Repo:   matches[2],
			Branch: matches[3], // This is actually the tag, but we'll use it as branch
			Path:   matches[4],
		}, nil
	}

	return nil, fmt.Errorf("unsupported GitHub URL format: %s", url)
}

// buildRawURL constructs raw content URL for direct download
func (g *GitHubDownloader) buildRawURL(repo *GitHubRepo) string {
	// Format: https://raw.githubusercontent.com/{owner}/{repo}/{branch}/{path}
	return fmt.Sprintf("%s/%s/%s/%s/%s",
		g.rawBaseURL,
		repo.Owner,
		repo.Repo,
		repo.Branch,
		repo.Path,
	)
}

// buildAPIURL constructs GitHub API URL for authenticated downloads
func (g *GitHubDownloader) buildAPIURL(repo *GitHubRepo) string {
	// Format: https://api.github.com/repos/{owner}/{repo}/contents/{path}?ref={branch}
	return fmt.Sprintf("%s/repos/%s/%s/contents/%s?ref=%s",
		g.apiBaseURL,
		repo.Owner,
		repo.Repo,
		repo.Path,
		repo.Branch,
	)
}

// ==========================================================================
// Rate Limit Methods
// ==========================================================================

// checkRateLimit checks GitHub API rate limit before making requests
func (g *GitHubDownloader) checkRateLimit() error {
	// If we have cached rate limit info and it's still valid
	if g.rateLimitRemaining > 0 && time.Now().Before(g.rateLimitReset) {
		return nil
	}

	// If rate limit is exceeded, wait
	if g.rateLimitRemaining == 0 && time.Now().Before(g.rateLimitReset) {
		return g.waitForRateLimit()
	}

	// Fetch current rate limit from API
	req, err := http.NewRequest("GET", g.apiBaseURL+"/rate_limit", nil)
	if err != nil {
		return fmt.Errorf("failed to create rate limit request: %w", err)
	}

	req.Header.Set("User-Agent", g.userAgent)
	if g.token != "" {
		req.Header.Set("Authorization", "token "+g.token)
	}

	resp, err := g.client.Do(req)
	if err != nil {
		// If we can't check rate limit, proceed anyway
		return nil
	}
	defer resp.Body.Close()

	var rateLimit GitHubRateLimit
	if err := json.NewDecoder(resp.Body).Decode(&rateLimit); err != nil {
		return nil // Proceed if we can't parse
	}

	g.rateLimitRemaining = rateLimit.Resources.Core.Remaining
	g.rateLimitReset = time.Unix(rateLimit.Resources.Core.Reset, 0)

	if g.rateLimitRemaining == 0 {
		return g.waitForRateLimit()
	}

	return nil
}

// updateRateLimitFromHeaders updates rate limit from response headers
func (g *GitHubDownloader) updateRateLimitFromHeaders(resp *http.Response) {
	if remaining := resp.Header.Get("X-RateLimit-Remaining"); remaining != "" {
		fmt.Sscanf(remaining, "%d", &g.rateLimitRemaining)
	}
	if reset := resp.Header.Get("X-RateLimit-Reset"); reset != "" {
		var resetTimestamp int64
		fmt.Sscanf(reset, "%d", &resetTimestamp)
		g.rateLimitReset = time.Unix(resetTimestamp, 0)
	}
}

// waitForRateLimit waits for rate limit reset if exceeded
func (g *GitHubDownloader) waitForRateLimit() error {
	waitDuration := time.Until(g.rateLimitReset)
	if waitDuration <= 0 {
		return nil
	}

	return fmt.Errorf("GitHub rate limit exceeded, resets in %v", waitDuration)
}

// ==========================================================================
// Error Handling
// ==========================================================================

// handleGitHubError handles GitHub-specific error responses
func (g *GitHubDownloader) handleGitHubError(resp *http.Response) error {
	// Try to parse GitHub error response
	var ghErr GitHubError
	if err := json.NewDecoder(resp.Body).Decode(&ghErr); err == nil && ghErr.Message != "" {
		return fmt.Errorf("GitHub error (HTTP %d): %s", resp.StatusCode, ghErr.Message)
	}

	// Fall back to generic error messages
	switch resp.StatusCode {
	case 401:
		return fmt.Errorf("GitHub authentication failed (HTTP 401) - check GITHUB_TOKEN")
	case 403:
		g.updateRateLimitFromHeaders(resp)
		if g.rateLimitRemaining == 0 {
			return fmt.Errorf("GitHub rate limit exceeded (HTTP 403) - resets at %s", g.rateLimitReset.Format(time.RFC3339))
		}
		return fmt.Errorf("GitHub access forbidden (HTTP 403)")
	case 404:
		return fmt.Errorf("GitHub repository or file not found (HTTP 404)")
	case 422:
		return fmt.Errorf("GitHub request unprocessable (HTTP 422) - invalid parameters")
	default:
		return fmt.Errorf("GitHub error: HTTP %d", resp.StatusCode)
	}
}

// ==========================================================================
// Helper Methods
// ==========================================================================

// downloadFile downloads a file from a URL (generic, not GitHub-specific)
func (g *GitHubDownloader) downloadFile(url, outputPath string) (int64, error) {
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return 0, err
	}

	req.Header.Set("User-Agent", g.userAgent)

	resp, err := g.client.Do(req)
	if err != nil {
		return 0, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		return 0, fmt.Errorf("download failed: HTTP %d", resp.StatusCode)
	}

	if err := os.MkdirAll(filepath.Dir(outputPath), 0755); err != nil {
		return 0, err
	}

	outFile, err := os.Create(outputPath)
	if err != nil {
		return 0, err
	}
	defer outFile.Close()

	bytesWritten, err := io.Copy(outFile, resp.Body)
	if err != nil {
		os.Remove(outputPath)
		return 0, err
	}

	return bytesWritten, nil
}

// HasGitHubToken returns true if GitHub token is configured
func (g *GitHubDownloader) HasGitHubToken() bool {
	return g.token != ""
}
