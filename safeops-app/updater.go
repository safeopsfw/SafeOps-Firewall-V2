package main

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	wailsruntime "github.com/wailsapp/wails/v2/pkg/runtime"
)

// ─── Version & repo ──────────────────────────────────────────────────────────

const (
	AppVersion = "1.0.0"
	GitHubRepo = "safeopsfw/SafeOps"
)

// ─── Types ───────────────────────────────────────────────────────────────────

type UpdateInfo struct {
	Available    bool   `json:"available"`
	Version      string `json:"version"`
	CurrentVer   string `json:"currentVersion"`
	DownloadURL  string `json:"downloadURL"`
	ReleaseNotes string `json:"releaseNotes"`
	Size         int64  `json:"size"`
	Error        string `json:"error"`
}

type UpdateProgress struct {
	Percent  int    `json:"percent"`
	Message  string `json:"message"`
	Done     bool   `json:"done"`
	FilePath string `json:"filePath"`
	Error    string `json:"error"`
}

// GitHub API response types
type ghRelease struct {
	TagName string    `json:"tag_name"`
	Name    string    `json:"name"`
	Body    string    `json:"body"`
	Assets  []ghAsset `json:"assets"`
}

type ghAsset struct {
	Name               string `json:"name"`
	BrowserDownloadURL string `json:"browser_download_url"`
	Size               int64  `json:"size"`
}

// ─── Public methods (Wails bindings) ─────────────────────────────────────────

func (a *App) GetCurrentVersion() string {
	return AppVersion
}

// CheckForUpdates queries GitHub Releases API for the latest release.
func (a *App) CheckForUpdates() UpdateInfo {
	info := UpdateInfo{CurrentVer: AppVersion}

	url := fmt.Sprintf("https://api.github.com/repos/%s/releases/latest", GitHubRepo)
	client := &http.Client{Timeout: 15 * time.Second}
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		info.Error = err.Error()
		return info
	}
	req.Header.Set("Accept", "application/vnd.github.v3+json")
	req.Header.Set("User-Agent", "SafeOps-Updater/"+AppVersion)

	resp, err := client.Do(req)
	if err != nil {
		info.Error = "Cannot reach GitHub: " + err.Error()
		return info
	}
	defer resp.Body.Close()

	if resp.StatusCode == 404 {
		// No releases yet
		info.Error = ""
		return info
	}
	if resp.StatusCode != 200 {
		info.Error = fmt.Sprintf("GitHub API returned %d", resp.StatusCode)
		return info
	}

	var release ghRelease
	if err := json.NewDecoder(resp.Body).Decode(&release); err != nil {
		info.Error = "Failed to parse release info"
		return info
	}

	remoteVer := strings.TrimPrefix(release.TagName, "v")
	if !isNewer(remoteVer, AppVersion) {
		return info
	}

	// Find the installer .exe asset
	var dlURL string
	var dlSize int64
	for _, asset := range release.Assets {
		if strings.HasSuffix(strings.ToLower(asset.Name), ".exe") {
			dlURL = asset.BrowserDownloadURL
			dlSize = asset.Size
			break
		}
	}

	if dlURL == "" {
		info.Error = "Release found but no installer (.exe) attached"
		return info
	}

	info.Available = true
	info.Version = remoteVer
	info.DownloadURL = dlURL
	info.Size = dlSize
	info.ReleaseNotes = release.Body
	if len(info.ReleaseNotes) > 500 {
		info.ReleaseNotes = info.ReleaseNotes[:500] + "..."
	}

	return info
}

// DownloadUpdate downloads the installer to a temp directory and reports progress.
func (a *App) DownloadUpdate(url string) UpdateProgress {
	prog := UpdateProgress{Message: "Starting download..."}

	if url == "" {
		prog.Error = "No download URL"
		return prog
	}

	client := &http.Client{Timeout: 10 * time.Minute}
	resp, err := client.Get(url)
	if err != nil {
		prog.Error = "Download failed: " + err.Error()
		return prog
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		prog.Error = fmt.Sprintf("Download returned HTTP %d", resp.StatusCode)
		return prog
	}

	totalSize := resp.ContentLength
	tmpDir := os.TempDir()
	outPath := filepath.Join(tmpDir, "SafeOps-Update.exe")

	out, err := os.Create(outPath)
	if err != nil {
		prog.Error = "Cannot create temp file: " + err.Error()
		return prog
	}
	defer out.Close()

	// Stream download with progress updates
	var downloaded int64
	buf := make([]byte, 128*1024) // 128KB chunks
	lastEmit := time.Now()

	for {
		n, readErr := resp.Body.Read(buf)
		if n > 0 {
			if _, err := out.Write(buf[:n]); err != nil {
				prog.Error = "Write failed: " + err.Error()
				return prog
			}
			downloaded += int64(n)

			// Emit progress every 250ms
			if time.Since(lastEmit) > 250*time.Millisecond {
				pct := 0
				if totalSize > 0 {
					pct = int(downloaded * 100 / totalSize)
				}
				a.emitUpdateProgress(pct, fmt.Sprintf("Downloading... %s / %s",
					formatBytes(downloaded), formatBytes(totalSize)))
				lastEmit = time.Now()
			}
		}
		if readErr == io.EOF {
			break
		}
		if readErr != nil {
			prog.Error = "Download interrupted: " + readErr.Error()
			return prog
		}
	}

	prog.Percent = 100
	prog.Done = true
	prog.FilePath = outPath
	prog.Message = "Download complete"
	a.emitUpdateProgress(100, "Download complete. Ready to install.")
	return prog
}

// ApplyUpdate launches the downloaded installer and quits the app.
func (a *App) ApplyUpdate() string {
	installerPath := filepath.Join(os.TempDir(), "SafeOps-Update.exe")
	if _, err := os.Stat(installerPath); os.IsNotExist(err) {
		return "Installer not found. Please download the update first."
	}

	// Stop all services before updating
	a.StopAll()

	// Launch installer (non-blocking)
	cmd := cmdStart(installerPath)
	if err := cmd.Start(); err != nil {
		return "Failed to launch installer: " + err.Error()
	}

	// Quit the app so the installer can replace files
	go func() {
		time.Sleep(500 * time.Millisecond)
		wailsruntime.Quit(a.ctx)
	}()

	return ""
}

// ─── Background startup check ────────────────────────────────────────────────

func (a *App) checkUpdateOnStartup() {
	time.Sleep(8 * time.Second) // Don't slow down startup
	info := a.CheckForUpdates()
	if info.Available && a.ctx != nil {
		wailsruntime.EventsEmit(a.ctx, "update:available", info)
	}
}

// ─── Helpers ─────────────────────────────────────────────────────────────────

func (a *App) emitUpdateProgress(pct int, msg string) {
	if a.ctx != nil {
		wailsruntime.EventsEmit(a.ctx, "update:progress", UpdateProgress{
			Percent: pct,
			Message: msg,
		})
	}
}

// isNewer returns true if remote > local (semver comparison).
func isNewer(remote, local string) bool {
	rParts := splitVersion(remote)
	lParts := splitVersion(local)
	for i := 0; i < 3; i++ {
		r, l := 0, 0
		if i < len(rParts) {
			r, _ = strconv.Atoi(rParts[i])
		}
		if i < len(lParts) {
			l, _ = strconv.Atoi(lParts[i])
		}
		if r > l {
			return true
		}
		if r < l {
			return false
		}
	}
	return false
}

func splitVersion(v string) []string {
	v = strings.TrimPrefix(v, "v")
	// Strip any pre-release suffix (e.g. "1.0.0-beta")
	if idx := strings.IndexAny(v, "-+"); idx >= 0 {
		v = v[:idx]
	}
	return strings.Split(v, ".")
}

func formatBytes(b int64) string {
	if b < 0 {
		return "?"
	}
	const mb = 1024 * 1024
	if b >= mb {
		return fmt.Sprintf("%.1f MB", float64(b)/float64(mb))
	}
	return fmt.Sprintf("%.0f KB", float64(b)/1024)
}
