package stats

import (
	"fmt"
	"sync"
	"time"

	"github.com/fatih/color"
	"github.com/safeops/network_logger/internal/writer"
)

// Collector collects and displays runtime statistics
type Collector struct {
	PacketsCaptured     int64
	PacketsLogged       int64
	PacketsExcluded     int64
	PacketsDeduplicated int64
	BytesTotal          int64
	StartTime           time.Time
	mu                  sync.RWMutex
}

// NewCollector creates a new stats collector
func NewCollector() *Collector {
	return &Collector{
		StartTime: time.Now(),
	}
}

// IncrementCaptured increments captured packet counter
func (c *Collector) IncrementCaptured() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.PacketsCaptured++
}

// IncrementLogged increments logged packet counter
func (c *Collector) IncrementLogged() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.PacketsLogged++
}

// IncrementExcluded increments excluded packet counter
func (c *Collector) IncrementExcluded() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.PacketsExcluded++
}

// IncrementDeduplicated increments deduplicated packet counter
func (c *Collector) IncrementDeduplicated() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.PacketsDeduplicated++
}

// AddBytes adds to total bytes counter
func (c *Collector) AddBytes(n int64) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.BytesTotal += n
}

// GetSnapshot returns a snapshot of current statistics
func (c *Collector) GetSnapshot() StatsSnapshot {
	c.mu.RLock()
	defer c.mu.RUnlock()

	return StatsSnapshot{
		PacketsCaptured:     c.PacketsCaptured,
		PacketsLogged:       c.PacketsLogged,
		PacketsExcluded:     c.PacketsExcluded,
		PacketsDeduplicated: c.PacketsDeduplicated,
		BytesTotal:          c.BytesTotal,
		Runtime:             time.Since(c.StartTime),
	}
}

// StatsSnapshot represents a statistics snapshot
type StatsSnapshot struct {
	PacketsCaptured     int64
	PacketsLogged       int64
	PacketsExcluded     int64
	PacketsDeduplicated int64
	BytesTotal          int64
	Runtime             time.Duration
}

// DisplayStats displays formatted statistics
func (c *Collector) DisplayStats(writerStats writer.WriterStats, dedupStats map[string]int64, tlsStats TLSStats) {
	snapshot := c.GetSnapshot()

	// Calculate rates
	runtimeSecs := snapshot.Runtime.Seconds()
	if runtimeSecs == 0 {
		runtimeSecs = 1
	}

	captureRate := float64(snapshot.PacketsCaptured) / runtimeSecs
	bandwidth := (float64(snapshot.BytesTotal) * 8) / runtimeSecs / 1_000_000 // Mbps

	// Colors
	cyan := color.New(color.FgCyan).SprintFunc()
	yellow := color.New(color.FgYellow).SprintFunc()
	green := color.New(color.FgGreen).SprintFunc()
	red := color.New(color.FgRed).SprintFunc()
	white := color.New(color.FgWhite, color.Bold).SprintFunc()

	// Clear screen and display
	fmt.Print("\033[H\033[2J")

	fmt.Println(cyan("┌──────────────────────────────────────────────────────────────────────────────┐"))
	fmt.Println(cyan("│") + white("            SAFEOPS NETWORK LOGGER - LIVE STATISTICS                         ") + cyan("│"))
	fmt.Println(cyan("├──────────────────────────────────────────────────────────────────────────────┤"))

	// Capture stats
	fmt.Printf(cyan("│")+" 📡 Packets Captured: %-12s    ⚡ Capture Rate: %s pkt/s     "+cyan("│")+"\n",
		yellow(formatNumber(snapshot.PacketsCaptured)),
		green(fmt.Sprintf("%.1f", captureRate)))

	fmt.Printf(cyan("│")+" 🌐 Bandwidth:       %-12s    ⏱️  Runtime:     %s         "+cyan("│")+"\n",
		yellow(fmt.Sprintf("%.2f Mbps", bandwidth)),
		green(formatDuration(snapshot.Runtime)))

	fmt.Println(cyan("├──────────────────────────────────────────────────────────────────────────────┤"))

	// Logging stats
	fmt.Printf(cyan("│")+" ✅ Logged:          %-12s    🚫 Excluded:     %-12s"+cyan("│")+"\n",
		green(formatNumber(snapshot.PacketsLogged)),
		red(formatNumber(snapshot.PacketsExcluded)))

	fmt.Printf(cyan("│")+" 🔄 Deduplicated:    %-12s    📊 Total Bytes:  %-12s"+cyan("│")+"\n",
		yellow(formatNumber(snapshot.PacketsDeduplicated)),
		green(formatBytes(snapshot.BytesTotal)))

	fmt.Println(cyan("├──────────────────────────────────────────────────────────────────────────────┤"))

	// Dedup breakdown
	if len(dedupStats) > 0 {
		fmt.Printf(cyan("│")+" 🎯 Dedup: DNS=%s HTTP=%s TLS=%s Unique=%s"+cyan("│")+"\n",
			yellow(formatNumber(dedupStats["dns_protocol"])),
			yellow(formatNumber(dedupStats["http_protocol"])),
			yellow(formatNumber(dedupStats["tls_protocol"])),
			green(formatNumber(dedupStats["unique"])))
	}

	// TLS stats
	if tlsStats.TotalKeys > 0 {
		fmt.Printf(cyan("│")+" 🔐 TLS Keys: %-8d               🕐 Recent Keys: %-8d         "+cyan("│")+"\n",
			tlsStats.TotalKeys,
			tlsStats.RecentKeys)
	}

	// File stats
	fmt.Printf(cyan("│")+" 💾 Log File Size:   %-12s    📝 Queue Size:   %-12s"+cyan("│")+"\n",
		yellow(formatBytes(writerStats.FileSize)),
		green(fmt.Sprintf("%d", writerStats.QueueSize)))

	fmt.Println(cyan("└──────────────────────────────────────────────────────────────────────────────┘"))
	fmt.Println()
}

// TLSStats represents TLS statistics
type TLSStats struct {
	TotalKeys  int
	RecentKeys int
}

// formatNumber formats large numbers with commas
func formatNumber(n int64) string {
	if n < 1000 {
		return fmt.Sprintf("%d", n)
	}
	if n < 1_000_000 {
		return fmt.Sprintf("%.1fK", float64(n)/1000)
	}
	if n < 1_000_000_000 {
		return fmt.Sprintf("%.1fM", float64(n)/1_000_000)
	}
	return fmt.Sprintf("%.1fB", float64(n)/1_000_000_000)
}

// formatBytes formats byte counts
func formatBytes(n int64) string {
	if n < 1024 {
		return fmt.Sprintf("%d B", n)
	}
	if n < 1024*1024 {
		return fmt.Sprintf("%.1f KB", float64(n)/1024)
	}
	if n < 1024*1024*1024 {
		return fmt.Sprintf("%.1f MB", float64(n)/1024/1024)
	}
	return fmt.Sprintf("%.1f GB", float64(n)/1024/1024/1024)
}

// formatDuration formats time duration
func formatDuration(d time.Duration) string {
	if d < time.Minute {
		return fmt.Sprintf("%.0fs", d.Seconds())
	}
	if d < time.Hour {
		return fmt.Sprintf("%.1fmin", d.Minutes())
	}
	return fmt.Sprintf("%.1fh", d.Hours())
}

// PrintBanner prints the startup banner
func PrintBanner() {
	cyan := color.New(color.FgCyan, color.Bold).SprintFunc()
	yellow := color.New(color.FgYellow).SprintFunc()

	fmt.Println()
	fmt.Println(cyan("╔══════════════════════════════════════════════════════════════════════╗"))
	fmt.Println(cyan("║") + yellow("              SAFEOPS NETWORK LOGGER v1.0                            ") + cyan("║"))
	fmt.Println(cyan("║") + "                High-Performance Packet Capture                      " + cyan("║"))
	fmt.Println(cyan("╚══════════════════════════════════════════════════════════════════════╝"))
	fmt.Println()
}

// PrintShutdownStats prints final statistics on shutdown
func (c *Collector) PrintShutdownStats(writerStats writer.WriterStats) {
	snapshot := c.GetSnapshot()

	cyan := color.New(color.FgCyan, color.Bold).SprintFunc()
	green := color.New(color.FgGreen).SprintFunc()
	yellow := color.New(color.FgYellow).SprintFunc()

	fmt.Println()
	fmt.Println(cyan("═══════════════════════════════════════════════════════════════"))
	fmt.Println(cyan("                    FINAL STATISTICS"))
	fmt.Println(cyan("═══════════════════════════════════════════════════════════════"))
	fmt.Printf("📦 Total Packets Captured:     %s\n", green(formatNumber(snapshot.PacketsCaptured)))
	fmt.Printf("✅ Total Packets Logged:       %s\n", green(formatNumber(snapshot.PacketsLogged)))
	fmt.Printf("🚫 Total Packets Excluded:     %s\n", yellow(formatNumber(snapshot.PacketsExcluded)))
	fmt.Printf("🔄 Total Packets Deduplicated: %s\n", yellow(formatNumber(snapshot.PacketsDeduplicated)))
	fmt.Printf("💾 Total Bytes Processed:      %s\n", green(formatBytes(snapshot.BytesTotal)))
	fmt.Printf("⏱️  Total Runtime:              %s\n", green(formatDuration(snapshot.Runtime)))
	fmt.Printf("💾 Final Log File Size:        %s\n", green(formatBytes(writerStats.FileSize)))
	fmt.Println(cyan("═══════════════════════════════════════════════════════════════"))
	fmt.Println()
}
