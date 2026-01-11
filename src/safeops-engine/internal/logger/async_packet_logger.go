package logger

import (
	"encoding/json"
	"fmt"
	"os"
	"sync"
	"time"
)

// PacketLog represents a single packet log entry
type PacketLog struct {
	Timestamp time.Time `json:"timestamp"`
	Action    string    `json:"action"`
	NIC       string    `json:"nic"`
	Protocol  uint8     `json:"proto"`
	SrcIP     string    `json:"src_ip"`
	SrcPort   uint16    `json:"src_port"`
	DstIP     string    `json:"dst_ip"`
	DstPort   uint16    `json:"dst_port"`
}

// AsyncPacketLogger is a non-blocking logger for packet data
// It uses a buffered channel so logging never blocks packet processing
type AsyncPacketLogger struct {
	logChan  chan PacketLog
	file     *os.File
	filePath string
	wg       sync.WaitGroup
	done     chan struct{}

	// Stats
	logsWritten uint64
	logsDropped uint64
}

// NewAsyncPacketLogger creates a new async logger
// bufferSize controls how many logs can queue before drops occur
func NewAsyncPacketLogger(filePath string, bufferSize int) (*AsyncPacketLogger, error) {
	file, err := os.OpenFile(filePath, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0644)
	if err != nil {
		return nil, fmt.Errorf("failed to open packet log file: %w", err)
	}

	l := &AsyncPacketLogger{
		logChan:  make(chan PacketLog, bufferSize),
		file:     file,
		filePath: filePath,
		done:     make(chan struct{}),
	}

	// Start background writer
	l.wg.Add(1)
	go l.backgroundWriter()

	return l, nil
}

// Log queues a packet log entry (non-blocking)
// If buffer is full, the log is dropped (never blocks)
func (l *AsyncPacketLogger) Log(entry PacketLog) {
	entry.Timestamp = time.Now()

	select {
	case l.logChan <- entry:
		// Logged successfully
	default:
		// Buffer full, drop this log (preserve performance)
		l.logsDropped++
	}
}

// LogPacket is a convenience method
func (l *AsyncPacketLogger) LogPacket(action, nic, srcIP, dstIP string, srcPort, dstPort uint16, proto uint8) {
	l.Log(PacketLog{
		Action:   action,
		NIC:      nic,
		Protocol: proto,
		SrcIP:    srcIP,
		SrcPort:  srcPort,
		DstIP:    dstIP,
		DstPort:  dstPort,
	})
}

// backgroundWriter runs in a goroutine and writes logs to file
func (l *AsyncPacketLogger) backgroundWriter() {
	defer l.wg.Done()

	encoder := json.NewEncoder(l.file)

	for {
		select {
		case entry := <-l.logChan:
			if err := encoder.Encode(entry); err == nil {
				l.logsWritten++
			}
		case <-l.done:
			// Drain remaining logs before exit
			for {
				select {
				case entry := <-l.logChan:
					encoder.Encode(entry)
					l.logsWritten++
				default:
					return
				}
			}
		}
	}
}

// GetStats returns logging statistics
func (l *AsyncPacketLogger) GetStats() (written, dropped uint64) {
	return l.logsWritten, l.logsDropped
}

// Close stops the logger and flushes remaining logs
func (l *AsyncPacketLogger) Close() error {
	close(l.done)
	l.wg.Wait()
	return l.file.Close()
}
