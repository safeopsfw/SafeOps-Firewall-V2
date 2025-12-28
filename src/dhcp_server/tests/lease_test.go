// Package tests contains tests for DHCP lease management.
// This file implements comprehensive lease lifecycle tests.
package tests

import (
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// ============================================================================
// Test Fixtures
// ============================================================================

type testPool struct {
	Name       string
	Subnet     string
	RangeStart string
	RangeEnd   string
	Gateway    string
	LeaseTime  time.Duration
}

type testLease struct {
	MAC        string
	IP         string
	Hostname   string
	LeaseStart time.Time
	LeaseEnd   time.Time
	State      string
	PoolName   string
}

type testReservation struct {
	MAC      string
	IP       string
	Hostname string
	PoolName string
}

// ============================================================================
// Mock Lease Manager
// ============================================================================

type mockLeaseManager struct {
	mu           sync.RWMutex
	leases       map[string]*testLease // keyed by MAC
	reservations map[string]*testReservation
	pools        map[string]*testPool
	nextIP       map[string]net.IP // next IP per pool
	conflicts    map[string]time.Time
}

func newMockLeaseManager() *mockLeaseManager {
	return &mockLeaseManager{
		leases:       make(map[string]*testLease),
		reservations: make(map[string]*testReservation),
		pools:        make(map[string]*testPool),
		nextIP:       make(map[string]net.IP),
		conflicts:    make(map[string]time.Time),
	}
}

func (m *mockLeaseManager) addPool(pool *testPool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.pools[pool.Name] = pool
	m.nextIP[pool.Name] = net.ParseIP(pool.RangeStart).To4()
}

func (m *mockLeaseManager) allocateLease(mac, poolName string) (*testLease, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	// Check for existing lease
	if lease, exists := m.leases[mac]; exists {
		return lease, nil
	}

	// Check for reservation
	if res, exists := m.reservations[mac]; exists {
		lease := &testLease{
			MAC:        mac,
			IP:         res.IP,
			Hostname:   res.Hostname,
			LeaseStart: time.Now(),
			LeaseEnd:   time.Now().Add(24 * time.Hour),
			State:      "ACTIVE",
			PoolName:   poolName,
		}
		m.leases[mac] = lease
		return lease, nil
	}

	pool, exists := m.pools[poolName]
	if !exists {
		return nil, errPoolNotFound
	}

	// Check pool exhaustion
	nextIP := m.nextIP[poolName]
	rangeEnd := net.ParseIP(pool.RangeEnd).To4()
	if compareIP(nextIP, rangeEnd) > 0 {
		return nil, errPoolExhausted
	}

	// Skip reserved IPs
	for m.isReserved(nextIP.String()) {
		nextIP = incrementIP(nextIP)
		if compareIP(nextIP, rangeEnd) > 0 {
			return nil, errPoolExhausted
		}
	}

	// Skip conflicted IPs
	for m.isConflicted(nextIP.String()) {
		nextIP = incrementIP(nextIP)
		if compareIP(nextIP, rangeEnd) > 0 {
			return nil, errPoolExhausted
		}
	}

	lease := &testLease{
		MAC:        mac,
		IP:         nextIP.String(),
		LeaseStart: time.Now(),
		LeaseEnd:   time.Now().Add(pool.LeaseTime),
		State:      "ACTIVE",
		PoolName:   poolName,
	}

	m.leases[mac] = lease
	m.nextIP[poolName] = incrementIP(nextIP)

	return lease, nil
}

func (m *mockLeaseManager) renewLease(mac string) (*testLease, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	lease, exists := m.leases[mac]
	if !exists {
		return nil, errLeaseNotFound
	}

	// Check if expired
	if time.Now().After(lease.LeaseEnd) {
		return nil, errLeaseExpired
	}

	pool := m.pools[lease.PoolName]
	lease.LeaseEnd = time.Now().Add(pool.LeaseTime)

	return lease, nil
}

func (m *mockLeaseManager) releaseLease(mac string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	delete(m.leases, mac)
	return nil
}

func (m *mockLeaseManager) getLease(mac string) (*testLease, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	lease, exists := m.leases[mac]
	if !exists {
		return nil, errLeaseNotFound
	}

	return lease, nil
}

// Ensure getLease is used
var _ = (*mockLeaseManager).getLease

func (m *mockLeaseManager) addReservation(res *testReservation) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.reservations[res.MAC] = res
}

func (m *mockLeaseManager) isReserved(ip string) bool {
	for _, res := range m.reservations {
		if res.IP == ip {
			return true
		}
	}
	return false
}

func (m *mockLeaseManager) markConflict(ip string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.conflicts[ip] = time.Now().Add(24 * time.Hour)
}

func (m *mockLeaseManager) isConflicted(ip string) bool {
	expiry, exists := m.conflicts[ip]
	if !exists {
		return false
	}
	return time.Now().Before(expiry)
}

func (m *mockLeaseManager) cleanupExpired() int {
	m.mu.Lock()
	defer m.mu.Unlock()

	count := 0
	for mac, lease := range m.leases {
		if time.Now().After(lease.LeaseEnd) {
			delete(m.leases, mac)
			count++
		}
	}
	return count
}

func (m *mockLeaseManager) getActiveLeaseCount() int {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return len(m.leases)
}

func (m *mockLeaseManager) getPoolUtilization(poolName string) float64 {
	m.mu.RLock()
	defer m.mu.RUnlock()

	pool, exists := m.pools[poolName]
	if !exists {
		return 0.0
	}

	rangeStart := net.ParseIP(pool.RangeStart).To4()
	rangeEnd := net.ParseIP(pool.RangeEnd).To4()
	totalIPs := ipCount(rangeStart, rangeEnd)

	allocatedCount := 0
	for _, lease := range m.leases {
		if lease.PoolName == poolName {
			allocatedCount++
		}
	}

	return float64(allocatedCount) / float64(totalIPs) * 100.0
}

// ============================================================================
// Lease Allocation Tests
// ============================================================================

func TestAllocateFirstLease(t *testing.T) {
	t.Run("FirstIPAllocated", func(t *testing.T) {
		lm := newMockLeaseManager()
		lm.addPool(&testPool{
			Name:       "test-pool",
			Subnet:     "192.168.1.0/24",
			RangeStart: "192.168.1.100",
			RangeEnd:   "192.168.1.200",
			Gateway:    "192.168.1.1",
			LeaseTime:  24 * time.Hour,
		})

		lease, err := lm.allocateLease("AA:BB:CC:DD:EE:FF", "test-pool")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		if lease.IP != "192.168.1.100" {
			t.Errorf("expected first IP 192.168.1.100, got %s", lease.IP)
		}
		if lease.State != "ACTIVE" {
			t.Errorf("expected ACTIVE state, got %s", lease.State)
		}
	})
}

func TestAllocateSequentialLeases(t *testing.T) {
	t.Run("SequentialAllocation", func(t *testing.T) {
		lm := newMockLeaseManager()
		lm.addPool(&testPool{
			Name:       "test-pool",
			Subnet:     "192.168.1.0/24",
			RangeStart: "192.168.1.100",
			RangeEnd:   "192.168.1.105",
			Gateway:    "192.168.1.1",
			LeaseTime:  24 * time.Hour,
		})

		macs := []string{
			"AA:BB:CC:DD:EE:01",
			"AA:BB:CC:DD:EE:02",
			"AA:BB:CC:DD:EE:03",
			"AA:BB:CC:DD:EE:04",
			"AA:BB:CC:DD:EE:05",
		}

		expectedIPs := []string{
			"192.168.1.100",
			"192.168.1.101",
			"192.168.1.102",
			"192.168.1.103",
			"192.168.1.104",
		}

		for i, mac := range macs {
			lease, err := lm.allocateLease(mac, "test-pool")
			if err != nil {
				t.Fatalf("allocation %d failed: %v", i, err)
			}
			if lease.IP != expectedIPs[i] {
				t.Errorf("expected %s, got %s", expectedIPs[i], lease.IP)
			}
		}
	})
}

func TestAllocateExhaustedPool(t *testing.T) {
	t.Run("PoolExhausted", func(t *testing.T) {
		lm := newMockLeaseManager()
		lm.addPool(&testPool{
			Name:       "small-pool",
			Subnet:     "192.168.1.0/24",
			RangeStart: "192.168.1.100",
			RangeEnd:   "192.168.1.102", // Only 3 IPs
			Gateway:    "192.168.1.1",
			LeaseTime:  24 * time.Hour,
		})

		// Allocate all 3 IPs
		for i := 0; i < 3; i++ {
			mac := "AA:BB:CC:DD:EE:" + string(rune('0'+i))
			_, err := lm.allocateLease(mac, "small-pool")
			if err != nil {
				t.Fatalf("allocation %d failed: %v", i, err)
			}
		}

		// 4th allocation should fail
		_, err := lm.allocateLease("AA:BB:CC:DD:EE:FF", "small-pool")
		if err != errPoolExhausted {
			t.Errorf("expected pool exhausted error, got %v", err)
		}
	})
}

// ============================================================================
// Static Reservation Tests
// ============================================================================

func TestAllocateReservedIP(t *testing.T) {
	t.Run("ReservedIPForMatchingMAC", func(t *testing.T) {
		lm := newMockLeaseManager()
		lm.addPool(&testPool{
			Name:       "test-pool",
			Subnet:     "192.168.1.0/24",
			RangeStart: "192.168.1.100",
			RangeEnd:   "192.168.1.200",
			Gateway:    "192.168.1.1",
			LeaseTime:  24 * time.Hour,
		})

		lm.addReservation(&testReservation{
			MAC:      "AA:BB:CC:DD:EE:FF",
			IP:       "192.168.1.50",
			Hostname: "reserved-host",
			PoolName: "test-pool",
		})

		lease, err := lm.allocateLease("AA:BB:CC:DD:EE:FF", "test-pool")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		if lease.IP != "192.168.1.50" {
			t.Errorf("expected reserved IP 192.168.1.50, got %s", lease.IP)
		}
	})
}

func TestReservedIPNotAllocatedToOthers(t *testing.T) {
	t.Run("SkipsReservedIP", func(t *testing.T) {
		lm := newMockLeaseManager()
		lm.addPool(&testPool{
			Name:       "test-pool",
			Subnet:     "192.168.1.0/24",
			RangeStart: "192.168.1.100",
			RangeEnd:   "192.168.1.102",
			Gateway:    "192.168.1.1",
			LeaseTime:  24 * time.Hour,
		})

		// Reserve the first IP in range
		lm.addReservation(&testReservation{
			MAC:      "11:22:33:44:55:66",
			IP:       "192.168.1.100",
			PoolName: "test-pool",
		})

		// Different MAC should skip reserved IP
		lease, err := lm.allocateLease("AA:BB:CC:DD:EE:FF", "test-pool")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		if lease.IP == "192.168.1.100" {
			t.Error("reserved IP should not be allocated to different MAC")
		}
		if lease.IP != "192.168.1.101" {
			t.Errorf("expected 192.168.1.101, got %s", lease.IP)
		}
	})
}

// ============================================================================
// Lease Renewal Tests
// ============================================================================

func TestRenewActiveLease(t *testing.T) {
	t.Run("RenewalExtendsExpiration", func(t *testing.T) {
		lm := newMockLeaseManager()
		lm.addPool(&testPool{
			Name:       "test-pool",
			Subnet:     "192.168.1.0/24",
			RangeStart: "192.168.1.100",
			RangeEnd:   "192.168.1.200",
			Gateway:    "192.168.1.1",
			LeaseTime:  24 * time.Hour,
		})

		// Allocate initial lease
		mac := "AA:BB:CC:DD:EE:FF"
		originalLease, _ := lm.allocateLease(mac, "test-pool")
		originalEnd := originalLease.LeaseEnd

		// Simulate time passing
		time.Sleep(10 * time.Millisecond)

		// Renew lease
		renewedLease, err := lm.renewLease(mac)
		if err != nil {
			t.Fatalf("renewal failed: %v", err)
		}

		// Verify same IP
		if renewedLease.IP != originalLease.IP {
			t.Errorf("IP changed during renewal: %s -> %s", originalLease.IP, renewedLease.IP)
		}

		// Verify expiration extended
		if !renewedLease.LeaseEnd.After(originalEnd) {
			t.Error("expiration not extended after renewal")
		}
	})
}

func TestRenewExpiredLease(t *testing.T) {
	t.Run("CannotRenewExpired", func(t *testing.T) {
		lm := newMockLeaseManager()
		lm.addPool(&testPool{
			Name:       "test-pool",
			Subnet:     "192.168.1.0/24",
			RangeStart: "192.168.1.100",
			RangeEnd:   "192.168.1.200",
			Gateway:    "192.168.1.1",
			LeaseTime:  1 * time.Millisecond, // Very short lease
		})

		// Allocate lease
		mac := "AA:BB:CC:DD:EE:FF"
		lm.allocateLease(mac, "test-pool")

		// Wait for expiration
		time.Sleep(10 * time.Millisecond)

		// Attempt renewal should fail
		_, err := lm.renewLease(mac)
		if err != errLeaseExpired {
			t.Errorf("expected lease expired error, got %v", err)
		}
	})
}

// ============================================================================
// Lease Release Tests
// ============================================================================

func TestReleaseActiveLease(t *testing.T) {
	t.Run("ReleaseFreesIP", func(t *testing.T) {
		lm := newMockLeaseManager()
		lm.addPool(&testPool{
			Name:       "test-pool",
			Subnet:     "192.168.1.0/24",
			RangeStart: "192.168.1.100",
			RangeEnd:   "192.168.1.200",
			Gateway:    "192.168.1.1",
			LeaseTime:  24 * time.Hour,
		})

		mac := "AA:BB:CC:DD:EE:FF"
		lm.allocateLease(mac, "test-pool")

		// Verify lease exists
		if lm.getActiveLeaseCount() != 1 {
			t.Error("expected 1 active lease before release")
		}

		// Release
		err := lm.releaseLease(mac)
		if err != nil {
			t.Fatalf("release failed: %v", err)
		}

		// Verify lease removed
		if lm.getActiveLeaseCount() != 0 {
			t.Error("expected 0 active leases after release")
		}
	})
}

func TestReleaseNonexistentLease(t *testing.T) {
	t.Run("ReleaseIdempotent", func(t *testing.T) {
		lm := newMockLeaseManager()

		// Release non-existent lease should not error
		err := lm.releaseLease("AA:BB:CC:DD:EE:FF")
		if err != nil {
			t.Errorf("release of non-existent lease should be idempotent, got %v", err)
		}
	})
}

// ============================================================================
// Lease Expiration Tests
// ============================================================================

func TestExpireLease(t *testing.T) {
	t.Run("ExpiredLeaseCleanedUp", func(t *testing.T) {
		lm := newMockLeaseManager()
		lm.addPool(&testPool{
			Name:       "test-pool",
			Subnet:     "192.168.1.0/24",
			RangeStart: "192.168.1.100",
			RangeEnd:   "192.168.1.200",
			Gateway:    "192.168.1.1",
			LeaseTime:  1 * time.Millisecond,
		})

		// Allocate lease with short duration
		lm.allocateLease("AA:BB:CC:DD:EE:FF", "test-pool")

		// Wait for expiration
		time.Sleep(10 * time.Millisecond)

		// Run cleanup
		cleaned := lm.cleanupExpired()
		if cleaned != 1 {
			t.Errorf("expected 1 lease cleaned, got %d", cleaned)
		}

		if lm.getActiveLeaseCount() != 0 {
			t.Error("expected 0 active leases after cleanup")
		}
	})
}

func TestExpirationCleanupBatch(t *testing.T) {
	t.Run("BatchCleanup", func(t *testing.T) {
		lm := newMockLeaseManager()
		lm.addPool(&testPool{
			Name:       "test-pool",
			Subnet:     "10.0.0.0/16",
			RangeStart: "10.0.0.1",
			RangeEnd:   "10.0.255.254",
			Gateway:    "10.0.0.1",
			LeaseTime:  1 * time.Millisecond,
		})

		// Allocate 100 leases
		for i := 0; i < 100; i++ {
			mac := "AA:BB:CC:DD:" + string(rune(i/256)) + string(rune(i%256))
			lm.allocateLease(mac, "test-pool")
		}

		// Wait for expiration
		time.Sleep(10 * time.Millisecond)

		// Run cleanup
		start := time.Now()
		cleaned := lm.cleanupExpired()
		duration := time.Since(start)

		if cleaned != 100 {
			t.Errorf("expected 100 leases cleaned, got %d", cleaned)
		}

		if duration > 5*time.Second {
			t.Errorf("cleanup took too long: %v", duration)
		}
	})
}

// ============================================================================
// IP Conflict Detection Tests
// ============================================================================

func TestDeclineMarksConflict(t *testing.T) {
	t.Run("ConflictQuarantine", func(t *testing.T) {
		lm := newMockLeaseManager()
		lm.addPool(&testPool{
			Name:       "test-pool",
			Subnet:     "192.168.1.0/24",
			RangeStart: "192.168.1.100",
			RangeEnd:   "192.168.1.102",
			Gateway:    "192.168.1.1",
			LeaseTime:  24 * time.Hour,
		})

		// Mark first IP as conflicted (simulating DECLINE)
		lm.markConflict("192.168.1.100")

		// Allocation should skip conflicted IP
		lease, err := lm.allocateLease("AA:BB:CC:DD:EE:FF", "test-pool")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		if lease.IP == "192.168.1.100" {
			t.Error("conflicted IP should not be allocated")
		}
		if lease.IP != "192.168.1.101" {
			t.Errorf("expected 192.168.1.101, got %s", lease.IP)
		}
	})
}

// ============================================================================
// Pool Utilization Tests
// ============================================================================

func TestPoolUtilizationCalculation(t *testing.T) {
	t.Run("CorrectUtilization", func(t *testing.T) {
		lm := newMockLeaseManager()
		lm.addPool(&testPool{
			Name:       "test-pool",
			Subnet:     "192.168.1.0/24",
			RangeStart: "192.168.1.100",
			RangeEnd:   "192.168.1.109", // 10 IPs
			Gateway:    "192.168.1.1",
			LeaseTime:  24 * time.Hour,
		})

		// Allocate 8 leases (80%)
		for i := 0; i < 8; i++ {
			mac := "AA:BB:CC:DD:EE:" + string(rune('0'+i))
			lm.allocateLease(mac, "test-pool")
		}

		utilization := lm.getPoolUtilization("test-pool")
		if utilization != 80.0 {
			t.Errorf("expected 80%% utilization, got %.1f%%", utilization)
		}
	})
}

func TestPoolUtilizationAfterRelease(t *testing.T) {
	t.Run("UtilizationDecreases", func(t *testing.T) {
		lm := newMockLeaseManager()
		lm.addPool(&testPool{
			Name:       "test-pool",
			Subnet:     "192.168.1.0/24",
			RangeStart: "192.168.1.100",
			RangeEnd:   "192.168.1.109", // 10 IPs
			Gateway:    "192.168.1.1",
			LeaseTime:  24 * time.Hour,
		})

		// Allocate 8 leases
		macs := make([]string, 8)
		for i := 0; i < 8; i++ {
			macs[i] = "AA:BB:CC:DD:EE:" + string(rune('0'+i))
			lm.allocateLease(macs[i], "test-pool")
		}

		// Release one lease
		lm.releaseLease(macs[0])

		utilization := lm.getPoolUtilization("test-pool")
		if utilization != 70.0 {
			t.Errorf("expected 70%% utilization after release, got %.1f%%", utilization)
		}
	})
}

// ============================================================================
// Concurrent Access Tests
// ============================================================================

func TestConcurrentAllocations(t *testing.T) {
	t.Run("ThreadSafeAllocation", func(t *testing.T) {
		lm := newMockLeaseManager()
		lm.addPool(&testPool{
			Name:       "test-pool",
			Subnet:     "10.0.0.0/16",
			RangeStart: "10.0.0.1",
			RangeEnd:   "10.0.255.254",
			Gateway:    "10.0.0.1",
			LeaseTime:  24 * time.Hour,
		})

		var wg sync.WaitGroup
		var successCount int64

		for i := 0; i < 100; i++ {
			wg.Add(1)
			go func(id int) {
				defer wg.Done()
				mac := "AA:BB:CC:" + string(rune(id/256/256)) + string(rune(id/256%256)) + string(rune(id%256))
				_, err := lm.allocateLease(mac, "test-pool")
				if err == nil {
					atomic.AddInt64(&successCount, 1)
				}
			}(i)
		}

		wg.Wait()

		if successCount != 100 {
			t.Errorf("expected 100 successful allocations, got %d", successCount)
		}
	})
}

// ============================================================================
// Helper Functions
// ============================================================================

func incrementIP(ip net.IP) net.IP {
	result := make(net.IP, len(ip))
	copy(result, ip)

	for i := len(result) - 1; i >= 0; i-- {
		result[i]++
		if result[i] != 0 {
			break
		}
	}
	return result
}

func compareIP(a, b net.IP) int {
	for i := 0; i < 4; i++ {
		if a[i] < b[i] {
			return -1
		}
		if a[i] > b[i] {
			return 1
		}
	}
	return 0
}

func ipCount(start, end net.IP) int {
	count := 0
	current := make(net.IP, 4)
	copy(current, start)

	for compareIP(current, end) <= 0 {
		count++
		current = incrementIP(current)
	}
	return count
}

// ============================================================================
// Errors
// ============================================================================

// ============================================================================
// Errors
// ============================================================================

var (
	errPoolNotFound  = &testError{"pool not found"}
	errPoolExhausted = &testError{"pool exhausted"}
	errLeaseNotFound = &testError{"lease not found"}
	errLeaseExpired  = &testError{"lease expired"}
)
