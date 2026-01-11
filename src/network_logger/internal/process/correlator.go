package process

import (
	"fmt"
	"sync"
	"time"

	"github.com/safeops/network_logger/pkg/models"
	"github.com/shirou/gopsutil/v3/net"
	"github.com/shirou/gopsutil/v3/process"
)

// Correlator maps network connections to Windows processes
type Correlator struct{
	cache    map[string]*CachedProcessInfo
	mu       sync.RWMutex
	cacheTTL time.Duration
}

// CachedProcessInfo represents a cached process lookup
type CachedProcessInfo struct {
	Info      *models.ProcessInfo
	Timestamp time.Time
}

// NewCorrelator creates a new process correlator
func NewCorrelator(cacheTTL time.Duration) *Correlator {
	return &Correlator{
		cache:    make(map[string]*CachedProcessInfo),
		cacheTTL: cacheTTL,
	}
}

// GetProcessInfo retrieves process information for a connection
func (c *Correlator) GetProcessInfo(srcIP string, srcPort uint16, dstIP string, dstPort uint16, proto string) *models.ProcessInfo {
	// Generate cache key
	key := fmt.Sprintf("%s:%d-%s:%d/%s", srcIP, srcPort, dstIP, dstPort, proto)

	// Check cache
	if info := c.getFromCache(key); info != nil {
		return info
	}

	// Query system for process info
	info := c.querySystemConnections(srcIP, srcPort, dstIP, dstPort, proto)
	if info != nil {
		c.addToCache(key, info)
	}

	return info
}

// getFromCache retrieves cached process info
func (c *Correlator) getFromCache(key string) *models.ProcessInfo {
	c.mu.RLock()
	defer c.mu.RUnlock()

	cached, exists := c.cache[key]
	if !exists {
		return nil
	}

	// Check if expired
	if time.Since(cached.Timestamp) > c.cacheTTL {
		return nil
	}

	return cached.Info
}

// addToCache stores process info in cache
func (c *Correlator) addToCache(key string, info *models.ProcessInfo) {
	c.mu.Lock()
	defer c.mu.Unlock()

	c.cache[key] = &CachedProcessInfo{
		Info:      info,
		Timestamp: time.Now(),
	}

	// Cleanup old entries if cache is large
	if len(c.cache) > 10000 {
		c.cleanupOldEntries()
	}
}

// cleanupOldEntries removes expired cache entries
func (c *Correlator) cleanupOldEntries() {
	now := time.Now()

	for key, cached := range c.cache {
		if now.Sub(cached.Timestamp) > c.cacheTTL {
			delete(c.cache, key)
		}
	}
}

// querySystemConnections queries Windows for network connections
func (c *Correlator) querySystemConnections(srcIP string, srcPort uint16, dstIP string, dstPort uint16, proto string) *models.ProcessInfo {
	// Get all network connections
	connections, err := net.Connections("all")
	if err != nil {
		return nil
	}

	// Find matching connection
	for _, conn := range connections {
		// Match local address and port
		if conn.Laddr.IP == srcIP && uint16(conn.Laddr.Port) == srcPort {
			// Get process details
			if conn.Pid == 0 {
				continue
			}

			proc, err := process.NewProcess(int32(conn.Pid))
			if err != nil {
				continue
			}

			name, _ := proc.Name()
			exe, _ := proc.Exe()
			cmdline, _ := proc.Cmdline()

			return &models.ProcessInfo{
				PID:     int32(conn.Pid),
				Name:    name,
				Exe:     exe,
				Cmdline: cmdline,
			}
		}
	}

	return nil
}

// GetCacheStats returns cache statistics
func (c *Correlator) GetCacheStats() map[string]interface{} {
	c.mu.RLock()
	defer c.mu.RUnlock()

	return map[string]interface{}{
		"cache_size": len(c.cache),
		"ttl_seconds": c.cacheTTL.Seconds(),
	}
}

// ClearCache clears the cache
func (c *Correlator) ClearCache() {
	c.mu.Lock()
	defer c.mu.Unlock()

	c.cache = make(map[string]*CachedProcessInfo)
}
