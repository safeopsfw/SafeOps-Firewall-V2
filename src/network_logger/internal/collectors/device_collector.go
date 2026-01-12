package collectors

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"
)

// DeviceCollector analyzes packet logs and generates device inventory in JSONL
type DeviceCollector struct {
	masterLogPath string
	outputPath    string
	analyzer      *LogAnalyzer
	interval      time.Duration
	mu            sync.Mutex
}

// NewDeviceCollector creates a new device collector
func NewDeviceCollector(masterLogPath, outputPath string, interval time.Duration) *DeviceCollector {
	return &DeviceCollector{
		masterLogPath: masterLogPath,
		outputPath:    outputPath,
		analyzer:      NewLogAnalyzer(masterLogPath),
		interval:      interval,
	}
}

// Start begins the collector loop
func (c *DeviceCollector) Start(ctx context.Context) {
	go c.loop(ctx)
}

func (c *DeviceCollector) loop(ctx context.Context) {
	// Wait a bit for logs to accumulate before first analysis
	time.Sleep(5 * time.Second)
	c.analyzeAndWrite()

	ticker := time.NewTicker(c.interval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			c.analyzeAndWrite() // Final write
			return
		case <-ticker.C:
			c.analyzeAndWrite()
		}
	}
}

func (c *DeviceCollector) analyzeAndWrite() {
	c.mu.Lock()
	defer c.mu.Unlock()

	// Analyze the master log
	if err := c.analyzer.Analyze(); err != nil {
		fmt.Printf("⚠️  Device Collector: Failed to analyze logs: %v\n", err)
		return
	}

	devices := c.analyzer.GetDevices()
	if len(devices) == 0 {
		return
	}

	// Ensure output directory exists
	dir := filepath.Dir(c.outputPath)
	os.MkdirAll(dir, 0755)

	// APPEND mode - devices are persistent across restarts
	file, err := os.OpenFile(c.outputPath, os.O_WRONLY|os.O_CREATE|os.O_APPEND, 0644)
	if err != nil {
		fmt.Printf("⚠️  Device Collector: Failed to open output file: %v\n", err)
		return
	}
	defer file.Close()

	writer := bufio.NewWriter(file)

	// Write report header as first line
	header := DeviceReportHeader{
		Type:        "report_header",
		GeneratedAt: time.Now().Format(time.RFC3339),
		LogAnalyzed: c.masterLogPath,
		DeviceCount: len(devices),
		Summary:     c.generateSummary(devices),
	}
	headerJSON, _ := json.Marshal(header)
	writer.Write(headerJSON)
	writer.WriteByte('\n')

	// Write each device as a separate line
	for _, device := range devices {
		entry := DeviceEntry{
			Type:   "device",
			Device: device,
		}
		deviceJSON, err := json.Marshal(entry)
		if err != nil {
			continue
		}
		writer.Write(deviceJSON)
		writer.WriteByte('\n')
	}

	writer.Flush()

	fmt.Printf("📱 Device Collector: %d devices appended to %s\n", len(devices), c.outputPath)
}

func (c *DeviceCollector) generateSummary(devices []*AnalyzedDevice) DeviceSummary {
	summary := DeviceSummary{
		ByType:     make(map[string]int),
		ByCategory: make(map[string]int),
	}

	for _, device := range devices {
		summary.TotalDevices++
		summary.TotalPackets += device.Traffic.PacketsSent + device.Traffic.PacketsRecv
		summary.TotalBytes += device.Traffic.BytesSent + device.Traffic.BytesRecv
		summary.TotalSessions += device.Sessions

		if device.DeviceType != "" {
			summary.ByType[device.DeviceType]++
		}
		if device.Category != "" {
			summary.ByCategory[device.Category]++
		}
	}

	return summary
}

// DeviceReportHeader is the first line in the JSONL output
type DeviceReportHeader struct {
	Type        string        `json:"type"`
	GeneratedAt string        `json:"generated_at"`
	LogAnalyzed string        `json:"log_analyzed"`
	DeviceCount int           `json:"device_count"`
	Summary     DeviceSummary `json:"summary"`
}

// DeviceSummary contains aggregate statistics
type DeviceSummary struct {
	TotalDevices  int            `json:"total_devices"`
	TotalPackets  int64          `json:"total_packets"`
	TotalBytes    int64          `json:"total_bytes"`
	TotalSessions int            `json:"total_sessions"`
	ByType        map[string]int `json:"by_type"`
	ByCategory    map[string]int `json:"by_category"`
}

// DeviceEntry is a single device line in JSONL
type DeviceEntry struct {
	Type   string          `json:"type"`
	Device *AnalyzedDevice `json:"device"`
}
