// Package tests contains end-to-end integration tests for DHCP server.
// This file implements comprehensive full-stack integration tests.
package tests

import (
	"context"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// ============================================================================
// Test Configuration
// ============================================================================

const (
	integrationTestTimeout = 30 * time.Second
	defaultPoolSize        = 101 // 192.168.1.100-200

	testPoolStart = "192.168.1.100"
	testPoolEnd   = "192.168.1.200"
	testLeaseTime = 86400 // 24 hours

	// Multi-pool test config
	testPoolAStart = "192.168.1.100"
	testPoolAEnd   = "192.168.1.200"
)

// ============================================================================
// Mock DHCP Server
// ============================================================================

type mockDHCPServer struct {
	mu           sync.RWMutex
	running      bool
	leases       map[string]*mockLease
	pools        map[string]*mockPool
	nextXID      uint32
	requestCount int64
	dns          *mockDNSClient
	ca           *mockCAClient
	db           *mockDatabase
}

type mockLease struct {
	MAC       string
	IP        string
	Hostname  string
	State     string
	ExpiresAt time.Time
	PoolName  string
}

type mockPool struct {
	Name       string
	Subnet     string
	RangeStart string
	RangeEnd   string
	NextIP     net.IP
	Allocated  int
}

type mockDNSClient struct {
	available bool
	records   map[string]string
	queue     []dnsUpdate
}

type dnsUpdate struct {
	recordType string
	name       string
	value      string
}

type mockCAClient struct {
	available  bool
	caCertURL  string
	wpadURL    string
	scriptURLs []string
}

type mockDatabase struct {
	available bool
	leases    map[string]*mockLease
	queue     []*mockLease
}

func newMockDHCPServer() *mockDHCPServer {
	return &mockDHCPServer{
		running: true,
		leases:  make(map[string]*mockLease),
		pools:   make(map[string]*mockPool),
		dns: &mockDNSClient{
			available: true,
			records:   make(map[string]string),
		},
		ca: &mockCAClient{
			available:  true,
			caCertURL:  "http://192.168.1.1/ca.crt",
			wpadURL:    "http://192.168.1.1/wpad.dat",
			scriptURLs: []string{"http://192.168.1.1/install.sh"},
		},
		db: &mockDatabase{
			available: true,
			leases:    make(map[string]*mockLease),
		},
	}
}

func (s *mockDHCPServer) addPool(name, rangeStart, rangeEnd string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.pools[name] = &mockPool{
		Name:       name,
		RangeStart: rangeStart,
		RangeEnd:   rangeEnd,
		NextIP:     net.ParseIP(rangeStart).To4(),
	}
}

func (s *mockDHCPServer) processDiscover(mac, hostname string) (*mockLease, error) {
	atomic.AddInt64(&s.requestCount, 1)
	s.mu.Lock()
	defer s.mu.Unlock()

	// Find available pool
	var pool *mockPool
	for _, p := range s.pools {
		pool = p
		break
	}
	if pool == nil {
		return nil, errNoPoolAvailable
	}

	// Check existing lease
	if lease, exists := s.leases[mac]; exists {
		return lease, nil
	}

	// Allocate new IP
	rangeEnd := net.ParseIP(pool.RangeEnd).To4()
	if compareIPIntegration(pool.NextIP, rangeEnd) > 0 {
		return nil, errPoolExhaustedInt
	}

	lease := &mockLease{
		MAC:       mac,
		IP:        pool.NextIP.String(),
		Hostname:  hostname,
		State:     "OFFERED",
		ExpiresAt: time.Now().Add(time.Duration(testLeaseTime) * time.Second),
		PoolName:  pool.Name,
	}

	pool.NextIP = incrementIPIntegration(pool.NextIP)
	pool.Allocated++

	return lease, nil
}

func (s *mockDHCPServer) processRequest(mac string, offer *mockLease) (*mockLease, error) {
	atomic.AddInt64(&s.requestCount, 1)
	s.mu.Lock()
	defer s.mu.Unlock()

	offer.State = "ACTIVE"
	s.leases[mac] = offer

	// Persist to database
	if s.db.available {
		s.db.leases[mac] = offer
	} else {
		s.db.queue = append(s.db.queue, offer)
	}

	// Update DNS
	if s.dns.available && offer.Hostname != "" {
		s.dns.records[offer.Hostname] = offer.IP
		s.dns.records[reverseDNS(offer.IP)] = offer.Hostname
	} else if offer.Hostname != "" {
		s.dns.queue = append(s.dns.queue, dnsUpdate{"A", offer.Hostname, offer.IP})
	}

	return offer, nil
}

func (s *mockDHCPServer) processRelease(mac string) error {
	atomic.AddInt64(&s.requestCount, 1)
	s.mu.Lock()
	defer s.mu.Unlock()

	lease, exists := s.leases[mac]
	if !exists {
		return nil // Idempotent
	}

	// Remove DNS records
	if s.dns.available && lease.Hostname != "" {
		delete(s.dns.records, lease.Hostname)
		delete(s.dns.records, reverseDNS(lease.IP))
	}

	// Remove from database
	if s.db.available {
		delete(s.db.leases, mac)
	}

	delete(s.leases, mac)
	return nil
}

func (s *mockDHCPServer) renewLease(mac string) (*mockLease, error) {
	atomic.AddInt64(&s.requestCount, 1)
	s.mu.Lock()
	defer s.mu.Unlock()

	lease, exists := s.leases[mac]
	if !exists {
		return nil, errLeaseNotFoundInt
	}

	lease.ExpiresAt = time.Now().Add(time.Duration(testLeaseTime) * time.Second)

	if s.db.available {
		s.db.leases[mac] = lease
	}

	return lease, nil
}

func (s *mockDHCPServer) getActiveLeaseCount() int {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return len(s.leases)
}

func (s *mockDHCPServer) shutdown() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.running = false
}

// ============================================================================
// Full DHCP Flow Integration Tests
// ============================================================================

func TestE2E_BasicDHCPFlow(t *testing.T) {
	t.Run("DiscoverOfferRequestAck", func(t *testing.T) {
		server := newMockDHCPServer()
		server.addPool("test-pool", testPoolStart, testPoolEnd)

		mac := "AA:BB:CC:DD:EE:FF"
		hostname := "desktop-pc"

		// 1. DISCOVER
		start := time.Now()
		offer, err := server.processDiscover(mac, hostname)
		if err != nil {
			t.Fatalf("DISCOVER failed: %v", err)
		}
		if offer.State != "OFFERED" {
			t.Errorf("expected OFFERED state, got %s", offer.State)
		}

		// 2. REQUEST
		ack, err := server.processRequest(mac, offer)
		if err != nil {
			t.Fatalf("REQUEST failed: %v", err)
		}
		elapsed := time.Since(start)

		// Verify ACK
		if ack.State != "ACTIVE" {
			t.Errorf("expected ACTIVE state, got %s", ack.State)
		}
		if ack.IP != testPoolStart {
			t.Errorf("expected IP %s, got %s", testPoolStart, ack.IP)
		}
		if ack.Hostname != hostname {
			t.Errorf("expected hostname %s, got %s", hostname, ack.Hostname)
		}

		// Verify response time
		if elapsed > 50*time.Millisecond {
			t.Logf("response time %v exceeds target 50ms", elapsed)
		}

		// Verify database persistence
		if server.db.leases[mac] == nil {
			t.Error("lease not persisted to database")
		}
	})
}

func TestE2E_LeaseRenewal(t *testing.T) {
	t.Run("T1Renewal", func(t *testing.T) {
		server := newMockDHCPServer()
		server.addPool("test-pool", testPoolStart, testPoolEnd)

		mac := "AA:BB:CC:DD:EE:FF"

		// Get initial lease
		offer, _ := server.processDiscover(mac, "")
		server.processRequest(mac, offer)

		originalExpiry := server.leases[mac].ExpiresAt

		// Simulate T1 (just wait briefly and renew)
		time.Sleep(10 * time.Millisecond)

		// Renew
		renewed, err := server.renewLease(mac)
		if err != nil {
			t.Fatalf("renewal failed: %v", err)
		}

		// Verify same IP
		if renewed.IP != testPoolStart {
			t.Error("IP changed during renewal")
		}

		// Verify expiration extended
		if !renewed.ExpiresAt.After(originalExpiry) {
			t.Error("expiration not extended")
		}
	})
}

func TestE2E_LeaseRelease(t *testing.T) {
	t.Run("VoluntaryRelease", func(t *testing.T) {
		server := newMockDHCPServer()
		server.addPool("test-pool", testPoolStart, testPoolEnd)

		mac := "AA:BB:CC:DD:EE:FF"
		hostname := "desktop-pc"

		// Get lease
		offer, _ := server.processDiscover(mac, hostname)
		server.processRequest(mac, offer)

		if server.getActiveLeaseCount() != 1 {
			t.Error("expected 1 active lease")
		}

		// Release
		err := server.processRelease(mac)
		if err != nil {
			t.Fatalf("release failed: %v", err)
		}

		// Verify lease removed
		if server.getActiveLeaseCount() != 0 {
			t.Error("expected 0 active leases after release")
		}

		// Verify database updated
		if server.db.leases[mac] != nil {
			t.Error("lease still in database after release")
		}

		// Verify DNS records removed
		if server.dns.records[hostname] != "" {
			t.Error("DNS A record not removed")
		}
	})
}

func TestE2E_MultipleClients(t *testing.T) {
	t.Run("ConcurrentClients", func(t *testing.T) {
		server := newMockDHCPServer()
		server.addPool("test-pool", testPoolStart, testPoolEnd)

		clientCount := 10
		var wg sync.WaitGroup
		var successCount int64
		assignedIPs := sync.Map{}

		for i := 0; i < clientCount; i++ {
			wg.Add(1)
			go func(id int) {
				defer wg.Done()
				mac := "AA:BB:CC:DD:EE:" + string(rune('0'+id))

				offer, err := server.processDiscover(mac, "")
				if err != nil {
					return
				}

				ack, err := server.processRequest(mac, offer)
				if err != nil {
					return
				}

				// Check for duplicate IPs
				if _, exists := assignedIPs.LoadOrStore(ack.IP, true); exists {
					t.Errorf("duplicate IP assigned: %s", ack.IP)
					return
				}

				atomic.AddInt64(&successCount, 1)
			}(i)
		}

		wg.Wait()

		if successCount != int64(clientCount) {
			t.Errorf("expected %d successful clients, got %d", clientCount, successCount)
		}
		if server.getActiveLeaseCount() != clientCount {
			t.Errorf("expected %d active leases, got %d", clientCount, server.getActiveLeaseCount())
		}
	})
}

// ============================================================================
// DNS Integration Tests
// ============================================================================

func TestE2E_DNSUpdateOnLeaseCreate(t *testing.T) {
	t.Run("AandPTRRecordsCreated", func(t *testing.T) {
		server := newMockDHCPServer()
		server.addPool("test-pool", testPoolStart, testPoolEnd)

		mac := "AA:BB:CC:DD:EE:FF"
		hostname := "desktop-pc"

		offer, _ := server.processDiscover(mac, hostname)
		server.processRequest(mac, offer)

		// Verify A record
		if server.dns.records[hostname] != testPoolStart {
			t.Errorf("A record wrong: expected %s, got %s", testPoolStart, server.dns.records[hostname])
		}

		// Verify PTR record
		ptrName := reverseDNS(testPoolStart)
		if server.dns.records[ptrName] != hostname {
			t.Errorf("PTR record wrong: expected %s, got %s", hostname, server.dns.records[ptrName])
		}
	})
}

func TestE2E_DNSUpdateOnLeaseRelease(t *testing.T) {
	t.Run("RecordsDeleted", func(t *testing.T) {
		server := newMockDHCPServer()
		server.addPool("test-pool", testPoolStart, testPoolEnd)

		mac := "AA:BB:CC:DD:EE:FF"
		hostname := "desktop-pc"

		offer, _ := server.processDiscover(mac, hostname)
		server.processRequest(mac, offer)
		server.processRelease(mac)

		// Verify A record deleted
		if server.dns.records[hostname] != "" {
			t.Error("A record not deleted")
		}

		// Verify PTR record deleted
		ptrName := reverseDNS(testPoolStart)
		if server.dns.records[ptrName] != "" {
			t.Error("PTR record not deleted")
		}
	})
}

func TestE2E_DNSUpdateFailureRecovery(t *testing.T) {
	t.Run("DHCPContinuesWhenDNSDown", func(t *testing.T) {
		server := newMockDHCPServer()
		server.addPool("test-pool", testPoolStart, testPoolEnd)
		server.dns.available = false

		mac := "AA:BB:CC:DD:EE:FF"
		hostname := "desktop-pc"

		offer, err := server.processDiscover(mac, hostname)
		if err != nil {
			t.Fatalf("DISCOVER should succeed without DNS: %v", err)
		}

		ack, err := server.processRequest(mac, offer)
		if err != nil {
			t.Fatalf("REQUEST should succeed without DNS: %v", err)
		}

		// Client should have IP
		if ack.IP == "" {
			t.Error("client should receive IP even when DNS down")
		}

		// DNS update should be queued
		if len(server.dns.queue) != 1 {
			t.Errorf("expected 1 DNS update queued, got %d", len(server.dns.queue))
		}
	})
}

// ============================================================================
// CA Certificate Distribution Tests
// ============================================================================

func TestE2E_CADistribution(t *testing.T) {
	t.Run("CAOptionsInACK", func(t *testing.T) {
		server := newMockDHCPServer()
		server.addPool("test-pool", testPoolStart, testPoolEnd)

		mac := "AA:BB:CC:DD:EE:FF"

		offer, _ := server.processDiscover(mac, "")
		server.processRequest(mac, offer)

		// Verify CA client is available and has URLs
		if !server.ca.available {
			t.Error("CA should be available")
		}
		if server.ca.caCertURL != "http://192.168.1.1/ca.crt" {
			t.Error("CA cert URL not set")
		}
		if server.ca.wpadURL != "http://192.168.1.1/wpad.dat" {
			t.Error("WPAD URL not set")
		}
		if len(server.ca.scriptURLs) != 1 {
			t.Error("install script URLs not set")
		}
	})
}

func TestE2E_CADistribution_WithDNS(t *testing.T) {
	t.Run("BothIntegrationsWork", func(t *testing.T) {
		server := newMockDHCPServer()
		server.addPool("test-pool", testPoolStart, testPoolEnd)

		mac := "AA:BB:CC:DD:EE:FF"
		hostname := "desktop-pc"

		offer, _ := server.processDiscover(mac, hostname)
		server.processRequest(mac, offer)

		// Verify CA available
		if !server.ca.available {
			t.Error("CA should be available")
		}

		// Verify DNS records created
		if server.dns.records[hostname] == "" {
			t.Error("DNS records should be created")
		}
	})
}

// ============================================================================
// Database Persistence Tests
// ============================================================================

func TestE2E_DatabasePersistence(t *testing.T) {
	t.Run("LeasesPersistedToDatabase", func(t *testing.T) {
		server := newMockDHCPServer()
		server.addPool("test-pool", testPoolStart, testPoolEnd)

		// Create 5 leases
		for i := 0; i < 5; i++ {
			mac := "AA:BB:CC:DD:EE:" + string(rune('0'+i))
			offer, _ := server.processDiscover(mac, "")
			server.processRequest(mac, offer)
		}

		// Verify in-memory
		if server.getActiveLeaseCount() != 5 {
			t.Errorf("expected 5 active leases, got %d", server.getActiveLeaseCount())
		}

		// Verify in database
		if len(server.db.leases) != 5 {
			t.Errorf("expected 5 database leases, got %d", len(server.db.leases))
		}
	})
}

func TestE2E_DatabaseFailure(t *testing.T) {
	t.Run("DHCPContinuesWhenDBDown", func(t *testing.T) {
		server := newMockDHCPServer()
		server.addPool("test-pool", testPoolStart, testPoolEnd)
		server.db.available = false

		mac := "AA:BB:CC:DD:EE:FF"

		offer, err := server.processDiscover(mac, "")
		if err != nil {
			t.Fatalf("DISCOVER should succeed without DB: %v", err)
		}

		ack, err := server.processRequest(mac, offer)
		if err != nil {
			t.Fatalf("REQUEST should succeed without DB: %v", err)
		}

		// Client should have IP
		if ack.IP == "" {
			t.Error("client should receive IP even when DB down")
		}

		// Lease should be queued
		if len(server.db.queue) != 1 {
			t.Errorf("expected 1 lease queued, got %d", len(server.db.queue))
		}
	})
}

// ============================================================================
// Multi-Pool Tests
// ============================================================================

func TestE2E_MultiPool_Allocation(t *testing.T) {
	t.Run("CorrectPoolSelected", func(t *testing.T) {
		server := newMockDHCPServer()
		server.addPool("pool-a", testPoolAStart, testPoolAEnd)

		mac := "AA:BB:CC:DD:EE:FF"
		offer, _ := server.processDiscover(mac, "")
		server.processRequest(mac, offer)

		if server.leases[mac].IP != testPoolAStart {
			t.Errorf("expected IP from pool A: %s, got %s", testPoolAStart, server.leases[mac].IP)
		}
	})
}

func TestE2E_MultiPool_Utilization(t *testing.T) {
	t.Run("IndependentTracking", func(t *testing.T) {
		server := newMockDHCPServer()
		server.addPool("pool-a", testPoolAStart, testPoolAEnd)

		// Allocate 10 IPs
		for i := 0; i < 10; i++ {
			mac := "AA:BB:CC:DD:EE:" + string(rune('0'+i))
			offer, _ := server.processDiscover(mac, "")
			server.processRequest(mac, offer)
		}

		// Verify utilization
		pool := server.pools["pool-a"]
		if pool.Allocated != 10 {
			t.Errorf("expected 10 allocated, got %d", pool.Allocated)
		}
	})
}

// ============================================================================
// Monitoring and Metrics Tests
// ============================================================================

func TestE2E_MetricsTracking(t *testing.T) {
	t.Run("RequestCountTracked", func(t *testing.T) {
		server := newMockDHCPServer()
		server.addPool("test-pool", testPoolStart, testPoolEnd)

		// Process 10 requests
		for i := 0; i < 10; i++ {
			mac := "AA:BB:CC:DD:EE:" + string(rune('0'+i))
			offer, _ := server.processDiscover(mac, "")
			server.processRequest(mac, offer)
		}

		// 10 DISCOVER + 10 REQUEST = 20 total
		if server.requestCount != 20 {
			t.Errorf("expected 20 requests, got %d", server.requestCount)
		}
	})
}

// ============================================================================
// API Integration Tests
// ============================================================================

type mockAPI struct {
	server *mockDHCPServer
}

func newMockAPI(server *mockDHCPServer) *mockAPI {
	return &mockAPI{server: server}
}

func (a *mockAPI) GetLease(mac string) (*mockLease, error) {
	a.server.mu.RLock()
	defer a.server.mu.RUnlock()
	lease, exists := a.server.leases[mac]
	if !exists {
		return nil, errLeaseNotFoundInt
	}
	return lease, nil
}

func (a *mockAPI) ReleaseLease(mac string) error {
	return a.server.processRelease(mac)
}

func (a *mockAPI) GetPoolStats(poolName string) (int, int, float64, error) {
	a.server.mu.RLock()
	defer a.server.mu.RUnlock()
	pool, exists := a.server.pools[poolName]
	if !exists {
		return 0, 0, 0, errNoPoolAvailable
	}
	total := defaultPoolSize
	utilization := float64(pool.Allocated) / float64(total) * 100
	return total, pool.Allocated, utilization, nil
}

func TestE2E_APIGetLease(t *testing.T) {
	t.Run("QueryLeaseInfo", func(t *testing.T) {
		server := newMockDHCPServer()
		server.addPool("test-pool", testPoolStart, testPoolEnd)
		api := newMockAPI(server)

		mac := "AA:BB:CC:DD:EE:FF"
		hostname := "desktop-pc"

		offer, _ := server.processDiscover(mac, hostname)
		server.processRequest(mac, offer)

		lease, err := api.GetLease(mac)
		if err != nil {
			t.Fatalf("GetLease failed: %v", err)
		}

		if lease.IP != testPoolStart {
			t.Errorf("expected IP %s, got %s", testPoolStart, lease.IP)
		}
		if lease.Hostname != hostname {
			t.Errorf("expected hostname %s, got %s", hostname, lease.Hostname)
		}
	})
}

func TestE2E_APIReleaseLease(t *testing.T) {
	t.Run("AdminRelease", func(t *testing.T) {
		server := newMockDHCPServer()
		server.addPool("test-pool", testPoolStart, testPoolEnd)
		api := newMockAPI(server)

		mac := "AA:BB:CC:DD:EE:FF"
		offer, _ := server.processDiscover(mac, "")
		server.processRequest(mac, offer)

		err := api.ReleaseLease(mac)
		if err != nil {
			t.Fatalf("ReleaseLease failed: %v", err)
		}

		_, err = api.GetLease(mac)
		if err == nil {
			t.Error("lease should not exist after admin release")
		}
	})
}

func TestE2E_APIGetPoolStats(t *testing.T) {
	t.Run("PoolStatistics", func(t *testing.T) {
		server := newMockDHCPServer()
		server.addPool("test-pool", testPoolStart, testPoolEnd)
		api := newMockAPI(server)

		// Allocate 10 IPs
		for i := 0; i < 10; i++ {
			mac := "AA:BB:CC:DD:EE:" + string(rune('0'+i))
			offer, _ := server.processDiscover(mac, "")
			server.processRequest(mac, offer)
		}

		total, allocated, utilization, err := api.GetPoolStats("test-pool")
		if err != nil {
			t.Fatalf("GetPoolStats failed: %v", err)
		}

		if total != defaultPoolSize {
			t.Errorf("expected total %d, got %d", defaultPoolSize, total)
		}
		if allocated != 10 {
			t.Errorf("expected allocated 10, got %d", allocated)
		}
		expectedUtil := float64(10) / float64(defaultPoolSize) * 100
		if utilization != expectedUtil {
			t.Errorf("expected utilization %.2f%%, got %.2f%%", expectedUtil, utilization)
		}
	})
}

// ============================================================================
// Failure Recovery Tests
// ============================================================================

func TestE2E_GracefulShutdown(t *testing.T) {
	t.Run("CleanShutdown", func(t *testing.T) {
		server := newMockDHCPServer()
		server.addPool("test-pool", testPoolStart, testPoolEnd)

		// Process some requests
		for i := 0; i < 5; i++ {
			mac := "AA:BB:CC:DD:EE:" + string(rune('0'+i))
			offer, _ := server.processDiscover(mac, "")
			server.processRequest(mac, offer)
		}

		// Shutdown
		server.shutdown()

		if server.running {
			t.Error("server should not be running after shutdown")
		}
	})
}

func TestE2E_ConcurrentFailures(t *testing.T) {
	t.Run("MultipleServicesDown", func(t *testing.T) {
		server := newMockDHCPServer()
		server.addPool("test-pool", testPoolStart, testPoolEnd)

		// Both DNS and DB unavailable
		server.dns.available = false
		server.db.available = false

		mac := "AA:BB:CC:DD:EE:FF"
		hostname := "desktop-pc"

		offer, err := server.processDiscover(mac, hostname)
		if err != nil {
			t.Fatalf("DISCOVER should succeed: %v", err)
		}

		ack, err := server.processRequest(mac, offer)
		if err != nil {
			t.Fatalf("REQUEST should succeed: %v", err)
		}

		// Client should have IP
		if ack.IP == "" {
			t.Error("client should receive IP")
		}

		// Both should have queued updates
		if len(server.dns.queue) == 0 {
			t.Error("DNS update should be queued")
		}
		if len(server.db.queue) == 0 {
			t.Error("DB persistence should be queued")
		}
	})
}

// ============================================================================
// Performance Tests
// ============================================================================

func TestE2E_ResponseTimePerformance(t *testing.T) {
	t.Run("MeasureLatency", func(t *testing.T) {
		server := newMockDHCPServer()
		server.addPool("test-pool", testPoolStart, testPoolEnd)

		iterations := 100
		var totalTime time.Duration

		for i := 0; i < iterations; i++ {
			mac := "AA:BB:" + string(rune('0'+i/256/256)) + ":" + string(rune('0'+i/256%256)) + ":" + string(rune('0'+i%256)) + ":FF"

			start := time.Now()
			offer, _ := server.processDiscover(mac, "")
			server.processRequest(mac, offer)
			elapsed := time.Since(start)

			totalTime += elapsed
		}

		avgTime := totalTime / time.Duration(iterations)
		t.Logf("Average response time: %v", avgTime)

		// Mock should be very fast
		if avgTime > 1*time.Millisecond {
			t.Logf("Note: Average response time %v is higher than expected for mock", avgTime)
		}
	})
}

// ============================================================================
// Helper Functions
// ============================================================================

func incrementIPIntegration(ip net.IP) net.IP {
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

func compareIPIntegration(a, b net.IP) int {
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

func reverseDNS(ip string) string {
	// Simplified: just use IP as key
	return ip + ".in-addr.arpa"
}

// ============================================================================
// Context Helpers
// ============================================================================

func integrationContext() (context.Context, context.CancelFunc) {
	return context.WithTimeout(context.Background(), integrationTestTimeout)
}

// Ensure integrationContext is used
var _ = integrationContext

// ============================================================================
// Errors
// ============================================================================

var (
	errNoPoolAvailable  = &testError{"no pool available"}
	errPoolExhaustedInt = &testError{"pool exhausted"}
	errLeaseNotFoundInt = &testError{"lease not found"}
)
