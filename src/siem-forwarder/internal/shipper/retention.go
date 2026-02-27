package shipper

import (
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"strings"
	"time"
)

// RetentionManager handles automatic deletion of old Elasticsearch indices
type RetentionManager struct {
	hosts         []string
	username      string
	password      string
	maxDays       int
	checkInterval time.Duration
	client        *http.Client
	stop          chan struct{}
	stopped       chan struct{}
}

// RetentionConfig holds retention configuration
type RetentionConfig struct {
	Hosts         []string
	Username      string
	Password      string
	MaxDays       int
	CheckInterval time.Duration
}

// NewRetentionManager creates a new retention manager
func NewRetentionManager(cfg RetentionConfig) *RetentionManager {
	return &RetentionManager{
		hosts:         cfg.Hosts,
		username:      cfg.Username,
		password:      cfg.Password,
		maxDays:       cfg.MaxDays,
		checkInterval: cfg.CheckInterval,
		client:        &http.Client{Timeout: 30 * time.Second},
		stop:          make(chan struct{}),
		stopped:       make(chan struct{}),
	}
}

// Start begins the retention cleanup loop
func (r *RetentionManager) Start() {
	go r.run()
}

// Stop stops the retention manager
func (r *RetentionManager) Stop() {
	close(r.stop)
	<-r.stopped
}

func (r *RetentionManager) run() {
	defer close(r.stopped)

	// Run immediately on startup
	r.cleanup()

	ticker := time.NewTicker(r.checkInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			r.cleanup()
		case <-r.stop:
			return
		}
	}
}

// cleanup finds and deletes safeops-* indices older than maxDays
func (r *RetentionManager) cleanup() {
	cutoff := time.Now().AddDate(0, 0, -r.maxDays)
	log.Printf("[RETENTION] Checking for indices older than %d days (before %s)",
		r.maxDays, cutoff.Format("2006.01.02"))

	for _, host := range r.hosts {
		indices, err := r.listSafeopsIndices(host)
		if err != nil {
			log.Printf("[RETENTION] Failed to list indices from %s: %v", host, err)
			continue
		}

		var toDelete []string
		for _, idx := range indices {
			indexDate, ok := extractDateFromIndex(idx)
			if !ok {
				continue
			}
			if indexDate.Before(cutoff) {
				toDelete = append(toDelete, idx)
			}
		}

		if len(toDelete) == 0 {
			log.Printf("[RETENTION] No expired indices found")
			return
		}

		log.Printf("[RETENTION] Deleting %d expired indices", len(toDelete))
		for _, idx := range toDelete {
			if err := r.deleteIndex(host, idx); err != nil {
				log.Printf("[RETENTION] Failed to delete %s: %v", idx, err)
			} else {
				log.Printf("[RETENTION] Deleted: %s", idx)
			}
		}
		return // Only need to clean up from one host
	}
}

// listSafeopsIndices returns all safeops-* index names
func (r *RetentionManager) listSafeopsIndices(host string) ([]string, error) {
	url := strings.TrimSuffix(host, "/") + "/_cat/indices/safeops-*?format=json&h=index"

	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil, err
	}
	if r.username != "" {
		req.SetBasicAuth(r.username, r.password)
	}

	resp, err := r.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("HTTP %d: %s", resp.StatusCode, string(body))
	}

	var indices []struct {
		Index string `json:"index"`
	}
	if err := json.Unmarshal(body, &indices); err != nil {
		return nil, err
	}

	var names []string
	for _, idx := range indices {
		names = append(names, idx.Index)
	}
	return names, nil
}

// deleteIndex deletes a single Elasticsearch index
func (r *RetentionManager) deleteIndex(host, indexName string) error {
	url := strings.TrimSuffix(host, "/") + "/" + indexName

	req, err := http.NewRequest("DELETE", url, nil)
	if err != nil {
		return err
	}
	if r.username != "" {
		req.SetBasicAuth(r.username, r.password)
	}

	resp, err := r.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 200 && resp.StatusCode < 300 {
		return nil
	}

	body, _ := io.ReadAll(resp.Body)
	return fmt.Errorf("HTTP %d: %s", resp.StatusCode, string(body))
}

// extractDateFromIndex parses the date suffix from index names like "safeops-firewall-2026.02.25"
func extractDateFromIndex(indexName string) (time.Time, bool) {
	// Find the last date-like segment (YYYY.MM.DD)
	parts := strings.Split(indexName, "-")
	if len(parts) < 2 {
		return time.Time{}, false
	}

	datePart := parts[len(parts)-1]
	t, err := time.Parse("2006.01.02", datePart)
	if err != nil {
		return time.Time{}, false
	}
	return t, true
}
