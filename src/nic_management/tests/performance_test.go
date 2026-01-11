// Package tests provides performance tests and benchmarks for the NIC Management service.
package tests

import (
	"context"
	"fmt"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// =============================================================================
// Performance Test Configuration
// =============================================================================

// PerfTestConfig contains performance test configuration.
type PerfTestConfig struct {
	Duration       time.Duration
	Warmup         time.Duration
	Concurrency    int
	TargetOps      int
	ReportInterval time.Duration
}

// DefaultPerfConfig returns default performance test configuration.
func DefaultPerfConfig() *PerfTestConfig {
	return &PerfTestConfig{
		Duration:       10 * time.Second,
		Warmup:         1 * time.Second,
		Concurrency:    8,
		TargetOps:      100000,
		ReportInterval: 1 * time.Second,
	}
}

// PerfResult contains performance test results.
type PerfResult struct {
	TotalOps     uint64
	Duration     time.Duration
	OpsPerSecond float64
	AvgLatencyNs int64
	P50LatencyNs int64
	P95LatencyNs int64
	P99LatencyNs int64
	MaxLatencyNs int64
	Errors       uint64
}

// =============================================================================
// NAT Translation Benchmarks
// =============================================================================

func BenchmarkNATTranslation(b *testing.B) {
	lanIP := net.ParseIP("192.168.1.100")
	wanIP := net.ParseIP("203.0.113.5")
	extIP := net.ParseIP("8.8.8.8")

	b.Run("outbound translation", func(b *testing.B) {
		packet := createBenchPacket(lanIP, extIP, 50000, 80, 6)

		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			_ = simulateBenchNAT(packet, wanIP, 60000)
		}
	})

	b.Run("inbound translation", func(b *testing.B) {
		packet := createBenchPacket(extIP, wanIP, 80, 60000, 6)

		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			_ = simulateBenchReverseNAT(packet, lanIP, 50000)
		}
	})

	b.Run("checksum recalculation", func(b *testing.B) {
		packet := createBenchPacket(lanIP, extIP, 50000, 80, 6)

		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			_ = calculateBenchIPChecksum(packet[:20])
		}
	})
}

func BenchmarkNATParallel(b *testing.B) {
	lanIP := net.ParseIP("192.168.1.100")
	wanIP := net.ParseIP("203.0.113.5")
	extIP := net.ParseIP("8.8.8.8")

	b.RunParallel(func(pb *testing.PB) {
		packet := createBenchPacket(lanIP, extIP, 50000, 80, 6)
		for pb.Next() {
			_ = simulateBenchNAT(packet, wanIP, 60000)
		}
	})
}

// =============================================================================
// Connection Tracking Benchmarks
// =============================================================================

func BenchmarkConnectionTracking(b *testing.B) {
	b.Run("connection lookup", func(b *testing.B) {
		connections := make(map[string]bool)
		for i := 0; i < 100000; i++ {
			key := fmt.Sprintf("192.168.1.%d:%d->8.8.8.8:80/6", i%256, 50000+i)
			connections[key] = true
		}

		lookupKey := "192.168.1.100:55000->8.8.8.8:80/6"

		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			_ = connections[lookupKey]
		}
	})

	b.Run("connection creation", func(b *testing.B) {
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			_ = fmt.Sprintf("192.168.1.%d:%d->8.8.8.8:80/6", i%256, 50000+i%10000)
		}
	})

	b.Run("state transition", func(b *testing.B) {
		states := []int{0, 1, 2, 3, 4, 5}
		stateIdx := 0

		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			stateIdx = (stateIdx + 1) % len(states)
			_ = states[stateIdx]
		}
	})
}

func BenchmarkConnectionTrackingParallel(b *testing.B) {
	var connCounter uint64

	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			id := atomic.AddUint64(&connCounter, 1)
			_ = fmt.Sprintf("conn-%d", id)
		}
	})
}

// =============================================================================
// Routing Engine Benchmarks
// =============================================================================

func BenchmarkRoutingLookup(b *testing.B) {
	routes := make(map[string]string)
	for i := 0; i < 10000; i++ {
		key := fmt.Sprintf("192.168.%d.%d", i/256, i%256)
		routes[key] = fmt.Sprintf("wan%d", (i%3)+1)
	}

	b.Run("exact match", func(b *testing.B) {
		key := "192.168.50.100"

		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			_ = routes[key]
		}
	})

	b.Run("miss lookup", func(b *testing.B) {
		key := "10.0.0.1" // Not in table

		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			_ = routes[key]
		}
	})
}

func BenchmarkWANSelection(b *testing.B) {
	wans := []string{"wan1", "wan2", "wan3"}
	counter := 0

	b.Run("round-robin", func(b *testing.B) {
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			_ = wans[counter%len(wans)]
			counter++
		}
	})

	b.Run("weighted", func(b *testing.B) {
		weights := []int{50, 30, 20}
		totalWeight := 100

		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			r := i % totalWeight
			cumulative := 0
			for j, w := range weights {
				cumulative += w
				if r < cumulative {
					_ = wans[j]
					break
				}
			}
		}
	})
}

// =============================================================================
// Packet Processing Benchmarks
// =============================================================================

func BenchmarkPacketParsing(b *testing.B) {
	packet := createBenchPacket(net.ParseIP("192.168.1.100"), net.ParseIP("8.8.8.8"), 50000, 80, 6)

	b.Run("extract 5-tuple", func(b *testing.B) {
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			_ = extractBench5Tuple(packet)
		}
	})

	b.Run("validate checksum", func(b *testing.B) {
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			_ = validateBenchChecksum(packet[:20])
		}
	})

	b.Run("protocol detection", func(b *testing.B) {
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			_ = packet[9] // Protocol field
		}
	})
}

func BenchmarkPacketCopy(b *testing.B) {
	sizes := []int{64, 512, 1500, 9000}

	for _, size := range sizes {
		b.Run(fmt.Sprintf("size-%d", size), func(b *testing.B) {
			src := make([]byte, size)
			dst := make([]byte, size)

			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				copy(dst, src)
			}
		})
	}
}

// =============================================================================
// Memory Allocation Benchmarks
// =============================================================================

func BenchmarkMemoryAllocation(b *testing.B) {
	b.Run("packet buffer small", func(b *testing.B) {
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			_ = make([]byte, 64)
		}
	})

	b.Run("packet buffer MTU", func(b *testing.B) {
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			_ = make([]byte, 1500)
		}
	})

	b.Run("packet buffer jumbo", func(b *testing.B) {
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			_ = make([]byte, 9000)
		}
	})

	b.Run("connection entry", func(b *testing.B) {
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			_ = &struct {
				key       [13]byte
				state     int
				createdAt int64
				lastSeen  int64
				expiresAt int64
				packets   uint64
				bytes     uint64
			}{}
		}
	})
}

func BenchmarkPooledAllocation(b *testing.B) {
	pool := sync.Pool{
		New: func() interface{} {
			return make([]byte, 1500)
		},
	}

	b.Run("pool get/put", func(b *testing.B) {
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			buf := pool.Get().([]byte)
			pool.Put(buf)
		}
	})

	b.Run("direct allocation", func(b *testing.B) {
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			_ = make([]byte, 1500)
		}
	})
}

// =============================================================================
// Concurrency Benchmarks
// =============================================================================

func BenchmarkMutexVsRWMutex(b *testing.B) {
	b.Run("Mutex read", func(b *testing.B) {
		var mu sync.Mutex
		value := 0

		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			mu.Lock()
			_ = value
			mu.Unlock()
		}
	})

	b.Run("RWMutex read", func(b *testing.B) {
		var mu sync.RWMutex
		value := 0

		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			mu.RLock()
			_ = value
			mu.RUnlock()
		}
	})

	b.Run("RWMutex parallel read", func(b *testing.B) {
		var mu sync.RWMutex
		value := 0

		b.RunParallel(func(pb *testing.PB) {
			for pb.Next() {
				mu.RLock()
				_ = value
				mu.RUnlock()
			}
		})
	})
}

func BenchmarkAtomicOps(b *testing.B) {
	b.Run("atomic add", func(b *testing.B) {
		var counter uint64

		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			atomic.AddUint64(&counter, 1)
		}
	})

	b.Run("atomic load", func(b *testing.B) {
		var counter uint64 = 12345

		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			_ = atomic.LoadUint64(&counter)
		}
	})

	b.Run("atomic CAS", func(b *testing.B) {
		var counter uint64

		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			for !atomic.CompareAndSwapUint64(&counter, uint64(i), uint64(i+1)) {
			}
		}
	})
}

func BenchmarkChannelOperations(b *testing.B) {
	b.Run("unbuffered channel", func(b *testing.B) {
		ch := make(chan int)

		go func() {
			for i := 0; i < b.N; i++ {
				ch <- i
			}
			close(ch)
		}()

		b.ResetTimer()
		for range ch {
		}
	})

	b.Run("buffered channel", func(b *testing.B) {
		ch := make(chan int, 1000)

		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			ch <- i
			<-ch
		}
	})
}

// =============================================================================
// Cache Benchmarks
// =============================================================================

func BenchmarkCacheLookup(b *testing.B) {
	cache := make(map[string]interface{})
	for i := 0; i < 50000; i++ {
		key := fmt.Sprintf("key-%d", i)
		cache[key] = struct{ value int }{value: i}
	}

	b.Run("cache hit", func(b *testing.B) {
		key := "key-25000"

		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			_ = cache[key]
		}
	})

	b.Run("cache miss", func(b *testing.B) {
		key := "nonexistent"

		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			_ = cache[key]
		}
	})
}

// =============================================================================
// Throughput Tests
// =============================================================================

func TestPacketThroughput(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping throughput test in short mode")
	}

	duration := 5 * time.Second
	var packetCount uint64
	var byteCount uint64

	ctx, cancel := context.WithTimeout(context.Background(), duration)
	defer cancel()

	var wg sync.WaitGroup
	workers := 8

	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			packet := make([]byte, 1500)

			for {
				select {
				case <-ctx.Done():
					return
				default:
					atomic.AddUint64(&packetCount, 1)
					atomic.AddUint64(&byteCount, uint64(len(packet)))
				}
			}
		}()
	}

	wg.Wait()

	pps := float64(packetCount) / duration.Seconds()
	bps := float64(byteCount*8) / duration.Seconds() / 1e9

	t.Logf("Throughput: %.2f Mpps, %.2f Gbps", pps/1e6, bps)
}

func TestConnectionThroughput(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping throughput test in short mode")
	}

	duration := 5 * time.Second
	var connCount uint64

	ctx, cancel := context.WithTimeout(context.Background(), duration)
	defer cancel()

	var wg sync.WaitGroup
	workers := 8

	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			localCount := 0

			for {
				select {
				case <-ctx.Done():
					atomic.AddUint64(&connCount, uint64(localCount))
					return
				default:
					localCount++
				}
			}
		}(i)
	}

	wg.Wait()

	cps := float64(connCount) / duration.Seconds()
	t.Logf("Connection rate: %.2f K connections/sec", cps/1e3)
}

// =============================================================================
// Latency Tests
// =============================================================================

func TestPacketLatency(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping latency test in short mode")
	}

	iterations := 10000
	latencies := make([]time.Duration, iterations)

	for i := 0; i < iterations; i++ {
		start := time.Now()
		// Simulate packet processing
		_ = make([]byte, 1500)
		latencies[i] = time.Since(start)
	}

	// Calculate statistics
	var total time.Duration
	var max time.Duration
	for _, l := range latencies {
		total += l
		if l > max {
			max = l
		}
	}

	avg := total / time.Duration(iterations)
	t.Logf("Latency - Avg: %v, Max: %v", avg, max)
}

// =============================================================================
// Benchmark Helpers
// =============================================================================

func createBenchPacket(srcIP, dstIP net.IP, srcPort, dstPort uint16, protocol uint8) []byte {
	packet := make([]byte, 60)
	packet[0] = 0x45
	packet[9] = protocol
	copy(packet[12:16], srcIP.To4())
	copy(packet[16:20], dstIP.To4())
	packet[20] = byte(srcPort >> 8)
	packet[21] = byte(srcPort)
	packet[22] = byte(dstPort >> 8)
	packet[23] = byte(dstPort)
	return packet
}

func simulateBenchNAT(packet []byte, wanIP net.IP, wanPort uint16) []byte {
	copy(packet[12:16], wanIP.To4())
	packet[20] = byte(wanPort >> 8)
	packet[21] = byte(wanPort)
	return packet
}

func simulateBenchReverseNAT(packet []byte, lanIP net.IP, lanPort uint16) []byte {
	copy(packet[16:20], lanIP.To4())
	packet[22] = byte(lanPort >> 8)
	packet[23] = byte(lanPort)
	return packet
}

func calculateBenchIPChecksum(header []byte) uint16 {
	var sum uint32
	for i := 0; i < len(header); i += 2 {
		if i == 10 {
			continue
		}
		sum += uint32(header[i])<<8 | uint32(header[i+1])
	}
	for sum>>16 != 0 {
		sum = (sum & 0xFFFF) + (sum >> 16)
	}
	return ^uint16(sum)
}

func extractBench5Tuple(packet []byte) [13]byte {
	var tuple [13]byte
	copy(tuple[0:4], packet[12:16]) // src IP
	copy(tuple[4:8], packet[16:20]) // dst IP
	tuple[8] = packet[20]           // src port high
	tuple[9] = packet[21]           // src port low
	tuple[10] = packet[22]          // dst port high
	tuple[11] = packet[23]          // dst port low
	tuple[12] = packet[9]           // protocol
	return tuple
}

func validateBenchChecksum(header []byte) bool {
	var sum uint32
	for i := 0; i < len(header); i += 2 {
		sum += uint32(header[i])<<8 | uint32(header[i+1])
	}
	for sum>>16 != 0 {
		sum = (sum & 0xFFFF) + (sum >> 16)
	}
	return uint16(sum) == 0xFFFF
}
