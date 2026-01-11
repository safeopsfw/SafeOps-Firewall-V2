package fetcher

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"
)

// ==========================================================================
// GitHubDownloader Struct Definition
// ==========================================================================

// GitHubDownloader handles downloading threat intelligence feeds from GitHub
type GitHubDownloader struct {
	client             *http.Client
	apiBaseURL         string
	rawBaseURL         string
	token              string
	rateLimitRemaining int
	rateLimitReset     time.Time
}

// GitHubRelease represents a GitHub release
type GitHubRelease struct {
	TagName string `json:"tag_name"`
	Assets  []struct {
		Name        string `json:"name"`
		DownloadURL string `json:"browser_download_url"`
		Size        int64  `json:"size"`
	} `json:"assets"`
}

// GitHubContents represents GitHub API contents response
type GitHubContents struct {
	DownloadURL string `json:"download_url"`
	Size        int64  `json:"size"`
}

// ==========================================================================
// NewGitHubDownloader Constructor
// ==========================================================================

// NewGitHubDownloader creates GitHub-specific downloader
func NewGitHubDownloader() *GitHubDownloader {
	// Load GitHub token from environment if available
	token := os.Getenv("GITHUB_TOKEN")

	client := &http.Client{
		Timeout: 2 * time.Minute,
	}

	return &GitHubDownloader{
		client:     client,
		apiBaseURL: "https://api.github.com",
		rawBaseURL: "https://raw.githubusercontent.com",
		token:      token,
	}
}

// ==========================================================================
// Main Download Methods
// ==========================================================================

// DownloadFromGitHub downloads a file from GitHub repository
func (d *GitHubDownloader) DownloadFromGitHub(url string, outputPath string) error {
	// Parse GitHub URL
	owner, repo, branch, path, err := d.parseGitHubURL(url)
	if err != nil {
		return fmt.Errorf("invalid GitHub URL: %w", err)
	}

	// Check rate limit before making API calls
	if d.token != "" {
		if err := d.checkRateLimit(); err != nil {
			return err
		}
	}

	// Prefer raw URL (no API limit) for public repos
	if d.token == "" {
		rawURL := d.buildRawURL(owner, repo, branch, path)
		return d.downloadRawFile(rawURL, outputPath)
	}

	// Use API for authenticated access
	apiURL := d.buildAPIURL(owner, repo, branch, path)
	return d.downloadViaAPI(apiURL, outputPath)
}

// DownloadLatestRelease downloads the latest release asset from a repository
func (d *GitHubDownloader) DownloadLatestRelease(owner, repo, assetPattern string, outputPath string) error {
	// Check rate limit
	if err := d.checkRateLimit(); err != nil {
		return err
	}

	// Get latest release
	releaseURL := fmt.Sprintf("%s/repos/%s/%s/releases/latest", d.apiBaseURL, owner, repo)

	req, err := http.NewRequest("GET", releaseURL, nil)
	if err != nil {
		return fmt.Errorf("failed to create request: %w", err)
	}

	d.addGitHubAuth(req)

	resp, err := d.client.Do(req)
	if err != nil {
		return fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		return d.handleGitHubError(resp)
	}

	// Parse release
	var release GitHubRelease
	if err := json.NewDecoder(resp.Body).Decode(&release); err != nil {
		return fmt.Errorf("failed to parse release: %w", err)
	}

	// Find matching asset
	var assetURL string
	for _, asset := range release.Assets {
		if strings.Contains(asset.Name, assetPattern) {
			assetURL = asset.DownloadURL
			break
		}
	}

	if assetURL == "" {
		return fmt.Errorf("no asset matching pattern '%s' found in release", assetPattern)
	}

	// Download asset
	return d.downloadRawFile(assetURL, outputPath)
}

// ==========================================================================
// URL Parsing and Building
// ==========================================================================

// parseGitHubURL extracts components from various GitHub URL formats
func (d *GitHubDownloader) parseGitHubURL(url string) (owner, repo, branch, path string, err error) {
	url = strings.TrimSpace(url)

	// Handle different URL formats
	if strings.HasPrefix(url, "https://raw.githubusercontent.com/") {
		// https://raw.githubusercontent.com/{owner}/{repo}/{branch}/{path}
		parts := strings.Split(strings.TrimPrefix(url, "https://raw.githubusercontent.com/"), "/")
		if len(parts) < 4 {
			return "", "", "", "", fmt.Errorf("invalid raw GitHub URL format")
		}
		owner = parts[0]
		repo = parts[1]
		branch = parts[2]
		path = strings.Join(parts[3:], "/")

	} else if strings.HasPrefix(url, "https://github.com/") {
		// https://github.com/{owner}/{repo}/blob/{branch}/{path}
		// https://github.com/{owner}/{repo}/raw/{branch}/{path}
		parts := strings.Split(strings.TrimPrefix(url, "https://github.com/"), "/")
		if len(parts) < 5 {
			return "", "", "", "", fmt.Errorf("invalid GitHub URL format")
		}
		owner = parts[0]
		repo = parts[1]
		// parts[2] is "blob" or "raw"
		branch = parts[3]
		path = strings.Join(parts[4:], "/")

	} else {
		return "", "", "", "", fmt.Errorf("unsupported GitHub URL format")
	}

	// Default branch if empty
	if branch == "" {
		branch = "main"
	}

	return owner, repo, branch, path, nil
}

// buildRawURL constructs raw content URL for direct download
func (d *GitHubDownloader) buildRawURL(owner, repo, branch, path string) string {
	return fmt.Sprintf("%s/%s/%s/%s/%s", d.rawBaseURL, owner, repo, branch, path)
}

// buildAPIURL constructs GitHub API URL for authenticated downloads
func (d *GitHubDownloader) buildAPIURL(owner, repo, branch, path string) string {
	return fmt.Sprintf("%s/repos/%s/%s/contents/%s?ref=%s",
		d.apiBaseURL, owner, repo, path, branch)
}

// ==========================================================================
// Download Helpers
// ==========================================================================

// downloadRawFile downloads from raw.githubusercontent.com (no API limit)
func (d *GitHubDownloader) downloadRawFile(url string, outputPath string) error {
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("User-Agent", "SafeOps-ThreatIntel-Fetcher/2.0")

	resp, err := d.client.Do(req)
	if err != nil {
		return fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		return fmt.Errorf("download failed with status %d", resp.StatusCode)
	}

	// Create output file
	out, err := os.Create(outputPath)
	if err != nil {
		return fmt.Errorf("failed to create output file: %w", err)
	}
	defer out.Close()

	// Stream to file
	_, err = io.Copy(out, resp.Body)
	if err != nil {
		os.Remove(outputPath)
		return fmt.Errorf("failed to write file: %w", err)
	}

	return nil
}

// downloadViaAPI downloads using GitHub API (for authenticated access)
func (d *GitHubDownloader) downloadViaAPI(apiURL string, outputPath string) error {
	// Get file metadata from API
	req, err := http.NewRequest("GET", apiURL, nil)
	if err != nil {
		return fmt.Errorf("failed to create request: %w", err)
	}

	d.addGitHubAuth(req)

	resp, err := d.client.Do(req)
	if err != nil {
		return fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close()

	d.updateRateLimitFromHeaders(resp)

	if resp.StatusCode != 200 {
		return d.handleGitHubError(resp)
	}

	// Parse API response
	var contents GitHubContents
	if err := json.NewDecoder(resp.Body).Decode(&contents); err != nil {
		return fmt.Errorf("failed to parse API response: %w", err)
	}

	// Download from download_url
	if contents.DownloadURL == "" {
		return fmt.Errorf("no download URL in API response")
	}

	return d.downloadRawFile(contents.DownloadURL, outputPath)
}

// ==========================================================================
// Authentication and Rate Limiting
// ==========================================================================

// addGitHubAuth adds authentication to GitHub API requests
func (d *GitHubDownloader) addGitHubAuth(req *http.Request) {
	req.Header.Set("User-Agent", "SafeOps-ThreatIntel-Fetcher/2.0")
	req.Header.Set("Accept", "application/vnd.github.v3+json")

	if d.token != "" {
		req.Header.Set("Authorization", "token "+d.token)
	}
}

// checkRateLimit checks GitHub API rate limit before making requests
func (d *GitHubDownloader) checkRateLimit() error {
	// If we have cached rate limit info and it's still valid
	if d.rateLimitRemaining > 0 && time.Now().Before(d.rateLimitReset) {
		return nil
	}

	// Query rate limit endpoint
	req, err := http.NewRequest("GET", d.apiBaseURL+"/rate_limit", nil)
	if err != nil {
		return err
	}

	d.addGitHubAuth(req)

	resp, err := d.client.Do(req)
	if err != nil {
		return fmt.Errorf("failed to check rate limit: %w", err)
	}
	defer resp.Body.Close()

	d.updateRateLimitFromHeaders(resp)

	// Check if we're rate limited
	if d.rateLimitRemaining <= 0 {
		waitTime := time.Until(d.rateLimitReset)
		if waitTime > 0 {
			return fmt.Errorf("GitHub API rate limit exceeded, resets in %s", waitTime)
		}
	}

	return nil
}

// updateRateLimitFromHeaders updates rate limit info from response headers
func (d *GitHubDownloader) updateRateLimitFromHeaders(resp *http.Response) {
	if remaining := resp.Header.Get("X-RateLimit-Remaining"); remaining != "" {
		fmt.Sscanf(remaining, "%d", &d.rateLimitRemaining)
	}

	if reset := resp.Header.Get("X-RateLimit-Reset"); reset != "" {
		var resetTimestamp int64
		fmt.Sscanf(reset, "%d", &resetTimestamp)
		d.rateLimitReset = time.Unix(resetTimestamp, 0)
	}
}

// ==========================================================================
// Error Handling
// ==========================================================================

// handleGitHubError handles GitHub-specific error responses
func (d *GitHubDownloader) handleGitHubError(resp *http.Response) error {
	bodyBytes, _ := io.ReadAll(resp.Body)

	var apiError struct {
		Message string `json:"message"`
		DocURL  string `json:"documentation_url"`
	}
	json.Unmarshal(bodyBytes, &apiError)

	switch resp.StatusCode {
	case 401:
		return fmt.Errorf("GitHub authentication failed (401) - check GITHUB_TOKEN: %s", apiError.Message)
	case 403:
		// Could be rate limit or permissions
		if strings.Contains(apiError.Message, "rate limit") {
			waitTime := time.Until(d.rateLimitReset)
			return fmt.Errorf("GitHub API rate limit exceeded - resets in %s", waitTime)
		}
		return fmt.Errorf("GitHub access forbidden (403): %s", apiError.Message)
	case 404:
		return fmt.Errorf("GitHub repository or file not found (404): %s", apiError.Message)
	case 422:
		return fmt.Errorf("GitHub API error (422): %s", apiError.Message)
	default:
		return fmt.Errorf("GitHub API error %d: %s", resp.StatusCode, apiError.Message)
	}
}
