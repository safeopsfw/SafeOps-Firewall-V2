// Package logging provides structured logging for the firewall engine.
// VerdictLogger writes per-packet firewall decisions to JSONL files
// in a format suitable for SOC analysis / SIEM ingestion.
//
// Log format (one JSON object per line):
//
//	{"ts":"2026-02-18T12:01:03.456Z","src":"192.168.1.5","sp":49231,"dst":"93.184.216.34","dp":443,
//	 "proto":"TCP","action":"DROP","detector":"domain_filter","domain":"example.com",
//	 "reason":"Domain blocked: example.com (matched: exact, source: DNS)","size":64,"flags":"S","ttl":60}
//
// Storage optimization:
//   - Only BLOCK/DROP/REDIRECT verdicts logged by default
//   - ALLOW verdicts sampled at 1/1000 rate
//   - Short field names to minimize storage (src, dst, sp, dp, proto)
//   - 5-minute time-based rotation with gzip compression
//   - Max 20 rotated archives (~200MB compressed typical)
//   - Buffered writes (64KB) — flushes every 2 seconds or on buffer full
package logging

import (
	"bufio"
	"compress/gzip"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"time"
)

// VerdictEntry is a single firewall decision log line.
// Field names are short for storage efficiency (SOC tools map them on ingest).
type VerdictEntry struct {
	Timestamp string `json:"ts"`               // ISO 8601 with ms
	SrcIP     string `json:"src"`              // source IP
	SrcPort   uint32 `json:"sp"`               // source port
	DstIP     string `json:"dst"`              // destination IP
	DstPort   uint32 `json:"dp"`               // destination port
	Proto     string `json:"proto"`            // TCP/UDP/ICMP
	Action    string `json:"action"`           // ALLOW/DROP/BLOCK/REDIRECT
	Detector  string `json:"detector"`         // which module decided
	Domain    string `json:"domain,omitempty"` // domain if available
	Reason    string `json:"reason"`           // human-readable reason
	Size      uint32 `json:"size,omitempty"`   // packet size
	Flags     string `json:"flags,omitempty"`  // TCP flags (S/A/F/R/P/U)
	CacheTTL  uint32 `json:"ttl,omitempty"`    // verdict cache TTL seconds
}

// VerdictLoggerConfig controls what gets logged and storage limits.
type VerdictLoggerConfig struct {
	Dir            string        // directory for verdict log files (e.g. bin/logs)
	RotateInterval time.Duration // time-based rotation interval (default 5 min)
	MaxBackups     int           // max rotated archives to keep (default 20)
	LogAllows      bool          // log ALLOW verdicts (default false — too noisy)
	AllowSampleN   int           // if LogAllows, sample 1 in N (default 1000)
	FlushInterval  time.Duration // buffer flush interval (default 2s)
}

// DefaultVerdictLoggerConfig returns production defaults.
func DefaultVerdictLoggerConfig() VerdictLoggerConfig {
	return VerdictLoggerConfig{
		RotateInterval: 5 * time.Minute,
		MaxBackups:     20,
		LogAllows:      false,
		AllowSampleN:   1000,
		FlushInterval:  2 * time.Second,
	}
}

// VerdictFileLogger writes verdict entries to JSONL files with time-based rotation.
type VerdictFileLogger struct {
	mu       sync.Mutex
	cfg      VerdictLoggerConfig
	writer   *bufio.Writer
	file     *os.File
	curSize  int64
	stopCh   chan struct{}
	stopped  atomic.Bool
	openedAt time.Time // when current file was opened

	// Stats
	written  atomic.Int64
	dropped  atomic.Int64
	rotated  atomic.Int64
	allowCtr atomic.Int64
}

const verdictActiveFile = "firewall-verdicts.jsonl"

// NewVerdictFileLogger creates a verdict logger writing to cfg.Dir.
func NewVerdictFileLogger(cfg VerdictLoggerConfig) (*VerdictFileLogger, error) {
	if cfg.Dir == "" {
		return nil, fmt.Errorf("verdict logger: dir is required")
	}
	if cfg.RotateInterval <= 0 {
		cfg.RotateInterval = 5 * time.Minute
	}
	if cfg.MaxBackups <= 0 {
		cfg.MaxBackups = 20
	}
	if cfg.AllowSampleN <= 0 {
		cfg.AllowSampleN = 1000
	}
	if cfg.FlushInterval <= 0 {
		cfg.FlushInterval = 2 * time.Second
	}

	if err := os.MkdirAll(cfg.Dir, 0755); err != nil {
		return nil, fmt.Errorf("verdict logger: create dir %s: %w", cfg.Dir, err)
	}

	vl := &VerdictFileLogger{
		cfg:    cfg,
		stopCh: make(chan struct{}),
	}

	if err := vl.openActive(); err != nil {
		return nil, err
	}

	// Background ticker: flush buffer + check time-based rotation
	go vl.backgroundLoop()

	return vl, nil
}

// Log writes a verdict entry. Non-blocking: drops on error.
func (vl *VerdictFileLogger) Log(entry VerdictEntry) {
	if vl.stopped.Load() {
		return
	}

	// Filter: skip ALLOWs unless sampling says yes
	if entry.Action == "ALLOW" {
		if !vl.cfg.LogAllows {
			return
		}
		if vl.allowCtr.Add(1)%int64(vl.cfg.AllowSampleN) != 0 {
			return
		}
	}

	if entry.Timestamp == "" {
		entry.Timestamp = time.Now().UTC().Format("2006-01-02T15:04:05.000Z")
	}

	data, err := json.Marshal(entry)
	if err != nil {
		vl.dropped.Add(1)
		return
	}

	vl.mu.Lock()
	defer vl.mu.Unlock()

	n, err := vl.writer.Write(data)
	if err != nil {
		vl.dropped.Add(1)
		return
	}
	vl.curSize += int64(n)

	if err := vl.writer.WriteByte('\n'); err != nil {
		vl.dropped.Add(1)
		return
	}
	vl.curSize++

	vl.written.Add(1)
}

// Stop flushes and closes the logger.
func (vl *VerdictFileLogger) Stop() error {
	if vl.stopped.Swap(true) {
		return nil
	}
	close(vl.stopCh)

	vl.mu.Lock()
	defer vl.mu.Unlock()
	return vl.closeFile()
}

// Stats returns logger statistics.
func (vl *VerdictFileLogger) Stats() VerdictLoggerStats {
	return VerdictLoggerStats{
		Written: vl.written.Load(),
		Dropped: vl.dropped.Load(),
		Rotated: vl.rotated.Load(),
	}
}

// VerdictLoggerStats holds logger statistics.
type VerdictLoggerStats struct {
	Written int64 `json:"written"`
	Dropped int64 `json:"dropped"`
	Rotated int64 `json:"rotated"`
}

// --- internal ---

func (vl *VerdictFileLogger) openActive() error {
	path := filepath.Join(vl.cfg.Dir, verdictActiveFile)
	f, err := os.OpenFile(path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0644)
	if err != nil {
		return fmt.Errorf("verdict logger: open %s: %w", path, err)
	}

	info, err := f.Stat()
	if err != nil {
		f.Close()
		return err
	}

	vl.file = f
	vl.writer = bufio.NewWriterSize(f, 64*1024)
	vl.curSize = info.Size()
	vl.openedAt = time.Now()
	return nil
}

func (vl *VerdictFileLogger) rotate() error {
	if err := vl.closeFile(); err != nil {
		return err
	}

	activePath := filepath.Join(vl.cfg.Dir, verdictActiveFile)

	// Skip rotation if file is empty
	info, err := os.Stat(activePath)
	if err == nil && info.Size() == 0 {
		return vl.openActive()
	}

	ts := time.Now().Format("2006-01-02T150405")
	archiveName := fmt.Sprintf("firewall-verdicts-%s.jsonl.gz", ts)
	archivePath := filepath.Join(vl.cfg.Dir, archiveName)

	if err := verdictCompressFile(activePath, archivePath); err != nil {
		fallback := filepath.Join(vl.cfg.Dir, fmt.Sprintf("firewall-verdicts-%s.jsonl", ts))
		os.Rename(activePath, fallback)
	} else {
		os.Remove(activePath)
	}

	vl.pruneOldArchives()
	vl.rotated.Add(1)
	return vl.openActive()
}

func (vl *VerdictFileLogger) pruneOldArchives() {
	pattern := filepath.Join(vl.cfg.Dir, "firewall-verdicts-*.jsonl.gz")
	matches, _ := filepath.Glob(pattern)
	if len(matches) <= vl.cfg.MaxBackups {
		return
	}
	toRemove := len(matches) - vl.cfg.MaxBackups
	for i := 0; i < toRemove; i++ {
		os.Remove(matches[i])
	}
}

func (vl *VerdictFileLogger) closeFile() error {
	if vl.writer != nil {
		if err := vl.writer.Flush(); err != nil {
			return err
		}
	}
	if vl.file != nil {
		if err := vl.file.Close(); err != nil {
			return err
		}
		vl.file = nil
		vl.writer = nil
	}
	return nil
}

// backgroundLoop handles periodic flushing and time-based rotation.
func (vl *VerdictFileLogger) backgroundLoop() {
	flushTicker := time.NewTicker(vl.cfg.FlushInterval)
	rotateTicker := time.NewTicker(vl.cfg.RotateInterval)
	defer flushTicker.Stop()
	defer rotateTicker.Stop()

	for {
		select {
		case <-vl.stopCh:
			return
		case <-flushTicker.C:
			vl.mu.Lock()
			if vl.writer != nil {
				vl.writer.Flush()
			}
			vl.mu.Unlock()
		case <-rotateTicker.C:
			vl.mu.Lock()
			vl.rotate()
			vl.mu.Unlock()
		}
	}
}

func verdictCompressFile(src, dst string) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()

	out, err := os.Create(dst)
	if err != nil {
		return err
	}
	defer out.Close()

	gz, err := gzip.NewWriterLevel(out, gzip.BestSpeed)
	if err != nil {
		return err
	}
	gz.Name = filepath.Base(src)
	gz.ModTime = time.Now()

	if _, err := io.Copy(gz, in); err != nil {
		gz.Close()
		return err
	}
	return gz.Close()
}

// TCPFlagsToString converts TCP flags bitmask to readable string.
// e.g., 0x02 = "S", 0x12 = "SA", 0x04 = "R"
func TCPFlagsToString(flags uint32) string {
	if flags == 0 {
		return ""
	}
	var s []byte
	if flags&0x20 != 0 {
		s = append(s, 'U')
	}
	if flags&0x10 != 0 {
		s = append(s, 'A')
	}
	if flags&0x08 != 0 {
		s = append(s, 'P')
	}
	if flags&0x04 != 0 {
		s = append(s, 'R')
	}
	if flags&0x02 != 0 {
		s = append(s, 'S')
	}
	if flags&0x01 != 0 {
		s = append(s, 'F')
	}
	return string(s)
}
