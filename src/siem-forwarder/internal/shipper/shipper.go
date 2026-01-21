package shipper

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/safeops/siem-forwarder/internal/tailer"
)

// Shipper sends log entries to Elasticsearch
type Shipper struct {
	hosts         []string
	username      string
	password      string
	bulkSize      int
	flushInterval time.Duration

	client   *http.Client
	input    <-chan tailer.LogEntry
	buffer   []tailer.LogEntry
	bufferMu sync.Mutex

	stop    chan struct{}
	stopped chan struct{}

	// Stats
	docsSent   int64
	docsErrors int64
}

// Config holds shipper configuration
type Config struct {
	Hosts         []string
	Username      string
	Password      string
	BulkSize      int
	FlushInterval time.Duration
	Input         <-chan tailer.LogEntry
}

// New creates a new Elasticsearch shipper
func New(cfg Config) *Shipper {
	return &Shipper{
		hosts:         cfg.Hosts,
		username:      cfg.Username,
		password:      cfg.Password,
		bulkSize:      cfg.BulkSize,
		flushInterval: cfg.FlushInterval,
		input:         cfg.Input,
		buffer:        make([]tailer.LogEntry, 0, cfg.BulkSize),
		client: &http.Client{
			Timeout: 30 * time.Second,
		},
		stop:    make(chan struct{}),
		stopped: make(chan struct{}),
	}
}

// Start begins the shipper
func (s *Shipper) Start() {
	go s.run()
}

// Stop stops the shipper gracefully
func (s *Shipper) Stop() {
	close(s.stop)
	<-s.stopped
}

// Stats returns current statistics
func (s *Shipper) Stats() (sent, errors int64) {
	return s.docsSent, s.docsErrors
}

func (s *Shipper) run() {
	defer close(s.stopped)

	flushTicker := time.NewTicker(s.flushInterval)
	defer flushTicker.Stop()

	for {
		select {
		case entry, ok := <-s.input:
			if !ok {
				// Channel closed, flush remaining
				s.flush()
				return
			}
			s.addToBuffer(entry)

		case <-flushTicker.C:
			s.flush()

		case <-s.stop:
			// Drain input channel and flush
			for {
				select {
				case entry, ok := <-s.input:
					if !ok {
						s.flush()
						return
					}
					s.addToBuffer(entry)
				default:
					s.flush()
					return
				}
			}
		}
	}
}

func (s *Shipper) addToBuffer(entry tailer.LogEntry) {
	s.bufferMu.Lock()
	s.buffer = append(s.buffer, entry)
	shouldFlush := len(s.buffer) >= s.bulkSize
	s.bufferMu.Unlock()

	if shouldFlush {
		s.flush()
	}
}

func (s *Shipper) flush() {
	s.bufferMu.Lock()
	if len(s.buffer) == 0 {
		s.bufferMu.Unlock()
		return
	}
	entries := s.buffer
	s.buffer = make([]tailer.LogEntry, 0, s.bulkSize)
	s.bufferMu.Unlock()

	if err := s.bulkIndex(entries); err != nil {
		log.Printf("Bulk index error: %v", err)
		s.docsErrors += int64(len(entries))
	} else {
		s.docsSent += int64(len(entries))
		log.Printf("Shipped %d documents to Elasticsearch", len(entries))
	}
}

// bulkIndex sends entries using Elasticsearch Bulk API
func (s *Shipper) bulkIndex(entries []tailer.LogEntry) error {
	if len(entries) == 0 {
		return nil
	}

	var body bytes.Buffer
	today := time.Now().Format("2006.01.02")

	for _, entry := range entries {
		// Generate index name with date suffix
		indexName := fmt.Sprintf("%s-%s", entry.IndexPrefix, today)

		// Create bulk action line
		action := map[string]interface{}{
			"index": map[string]interface{}{
				"_index": indexName,
			},
		}
		actionJSON, err := json.Marshal(action)
		if err != nil {
			log.Printf("Error marshaling action: %v", err)
			continue
		}
		body.Write(actionJSON)
		body.WriteByte('\n')

		// Parse the log line as JSON and add metadata
		var doc map[string]interface{}
		if err := json.Unmarshal([]byte(entry.Line), &doc); err != nil {
			// If not valid JSON, wrap in a message field
			doc = map[string]interface{}{
				"message": entry.Line,
			}
		}

		// Extract original timestamp from log based on log type
		timestamp := extractTimestamp(doc, entry.LogType)
		if timestamp == "" {
			// Fallback to current time if no timestamp found
			timestamp = entry.Timestamp.Format(time.RFC3339Nano)
		}

		// Add metadata fields
		doc["@timestamp"] = timestamp
		doc["log_type"] = entry.LogType
		doc["source_file"] = entry.FilePath
		doc["forwarded_at"] = entry.Timestamp.Format(time.RFC3339Nano)

		docJSON, err := json.Marshal(doc)
		if err != nil {
			log.Printf("Error marshaling document: %v", err)
			continue
		}
		body.Write(docJSON)
		body.WriteByte('\n')
	}

	// Send to Elasticsearch
	for _, host := range s.hosts {
		url := strings.TrimSuffix(host, "/") + "/_bulk"
		req, err := http.NewRequest("POST", url, &body)
		if err != nil {
			return err
		}

		req.Header.Set("Content-Type", "application/x-ndjson")
		if s.username != "" {
			req.SetBasicAuth(s.username, s.password)
		}

		resp, err := s.client.Do(req)
		if err != nil {
			log.Printf("Error connecting to %s: %v", host, err)
			continue
		}

		respBody, _ := io.ReadAll(resp.Body)
		resp.Body.Close()

		if resp.StatusCode >= 200 && resp.StatusCode < 300 {
			// Check for individual errors in response
			var bulkResp struct {
				Errors bool `json:"errors"`
				Items  []struct {
					Index struct {
						Error interface{} `json:"error"`
					} `json:"index"`
				} `json:"items"`
			}
			if err := json.Unmarshal(respBody, &bulkResp); err == nil && bulkResp.Errors {
				errorCount := 0
				for _, item := range bulkResp.Items {
					if item.Index.Error != nil {
						errorCount++
					}
				}
				if errorCount > 0 {
					log.Printf("Bulk request had %d errors", errorCount)
				}
			}
			return nil
		}

		log.Printf("Elasticsearch returned status %d: %s", resp.StatusCode, string(respBody))
	}

	return fmt.Errorf("failed to ship to any Elasticsearch host")
}

// extractTimestamp extracts the original timestamp from a log document based on log type
// Returns empty string if no timestamp found
func extractTimestamp(doc map[string]interface{}, logType string) string {
	// Map of log types to their timestamp field names
	timestampFields := map[string][]string{
		"firewall":           {"timestamp_ist", "timestamp"},
		"ids":                {"timestamp_ist", "timestamp"},
		"devices":            {"generated_at", "first_seen", "device.first_seen"},
		"netflow_eastwest":   {"timestamp", "flow_end", "@timestamp"},
		"netflow_northsouth": {"timestamp", "flow_end", "@timestamp"},
		"netflow_unknown":    {"timestamp", "flow_end", "@timestamp"},
	}

	// Get the fields to check for this log type
	fields, ok := timestampFields[logType]
	if !ok {
		// Unknown log type, try common timestamp fields
		fields = []string{"timestamp", "timestamp_ist", "@timestamp", "time", "datetime"}
	}

	// Try each field in order
	for _, field := range fields {
		if val, exists := doc[field]; exists {
			if ts, ok := val.(string); ok && ts != "" {
				return ts
			}
		}

		// Check nested fields (e.g., device.first_seen)
		if strings.Contains(field, ".") {
			parts := strings.SplitN(field, ".", 2)
			if nested, exists := doc[parts[0]]; exists {
				if nestedMap, ok := nested.(map[string]interface{}); ok {
					if val, exists := nestedMap[parts[1]]; exists {
						if ts, ok := val.(string); ok && ts != "" {
							return ts
						}
					}
				}
			}
		}
	}

	return ""
}
