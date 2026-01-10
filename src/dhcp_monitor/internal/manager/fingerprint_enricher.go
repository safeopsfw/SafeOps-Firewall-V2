// Package manager provides business logic for device fingerprint enrichment
package manager

import (
	"context"
	"log"
	"sync"
	"time"

	"dhcp_monitor/internal/database"
	"dhcp_monitor/internal/platform"
)

// =============================================================================
// FINGERPRINT ENRICHER
// =============================================================================

// FingerprintEnricher handles background device fingerprint collection
type FingerprintEnricher struct {
	db        *database.DatabaseClient
	collector *platform.DeviceInfoCollector
	ctx       context.Context
	cancel    context.CancelFunc
	wg        sync.WaitGroup
	running   bool
	mu        sync.RWMutex

	// Configuration
	interval     time.Duration // How often to check for devices needing fingerprinting
	batchSize    int           // How many devices to process per cycle
	workerCount  int           // Concurrent fingerprint collectors
	deviceQueue  chan *database.Device
	statsCounter struct {
		Processed int64
		Errors    int64
		LastRun   time.Time
	}
}

// NewFingerprintEnricher creates a new background fingerprint enricher
func NewFingerprintEnricher(db *database.DatabaseClient) *FingerprintEnricher {
	return &FingerprintEnricher{
		db:          db,
		collector:   platform.NewDeviceInfoCollector(),
		interval:    30 * time.Second, // Check every 30 seconds
		batchSize:   10,               // Process 10 devices at a time
		workerCount: 3,                // 3 concurrent collectors
		deviceQueue: make(chan *database.Device, 50),
	}
}

// Start begins the background fingerprint collection
func (e *FingerprintEnricher) Start(ctx context.Context) error {
	e.mu.Lock()
	if e.running {
		e.mu.Unlock()
		return nil
	}
	e.running = true
	e.ctx, e.cancel = context.WithCancel(ctx)
	e.mu.Unlock()

	log.Println("[FINGERPRINT] Starting background fingerprint enricher")

	// Start workers
	for i := 0; i < e.workerCount; i++ {
		e.wg.Add(1)
		go e.worker(i)
	}

	// Start scheduler
	e.wg.Add(1)
	go e.scheduler()

	return nil
}

// Stop gracefully shuts down the enricher
func (e *FingerprintEnricher) Stop() error {
	e.mu.Lock()
	if !e.running {
		e.mu.Unlock()
		return nil
	}
	e.running = false
	e.cancel()
	e.mu.Unlock()

	// Wait for workers with timeout
	done := make(chan struct{})
	go func() {
		e.wg.Wait()
		close(done)
	}()

	select {
	case <-done:
		log.Println("[FINGERPRINT] Enricher stopped gracefully")
	case <-time.After(5 * time.Second):
		log.Println("[FINGERPRINT] Enricher stop timeout - forcing shutdown")
	}

	return nil
}

// EnrichDevice immediately fingerprints a specific device
func (e *FingerprintEnricher) EnrichDevice(device *database.Device) {
	e.mu.RLock()
	running := e.running
	e.mu.RUnlock()

	if !running {
		return
	}

	select {
	case e.deviceQueue <- device:
		log.Printf("[FINGERPRINT] Queued device %s for fingerprinting", device.MACAddress)
	default:
		log.Printf("[FINGERPRINT] Queue full, skipping device %s", device.MACAddress)
	}
}

// scheduler periodically fetches devices needing fingerprinting
func (e *FingerprintEnricher) scheduler() {
	defer e.wg.Done()

	ticker := time.NewTicker(e.interval)
	defer ticker.Stop()

	// Initial run
	e.fetchAndQueueDevices()

	for {
		select {
		case <-e.ctx.Done():
			return
		case <-ticker.C:
			e.fetchAndQueueDevices()
		}
	}
}

// fetchAndQueueDevices gets devices that need fingerprinting
func (e *FingerprintEnricher) fetchAndQueueDevices() {
	devices, err := e.db.GetDevicesNeedingFingerprint(e.ctx, e.batchSize)
	if err != nil {
		log.Printf("[FINGERPRINT] Error fetching devices: %v", err)
		return
	}

	for _, device := range devices {
		select {
		case e.deviceQueue <- device:
			// Queued successfully
		case <-e.ctx.Done():
			return
		default:
			// Queue full, skip
		}
	}

	if len(devices) > 0 {
		log.Printf("[FINGERPRINT] Queued %d devices for fingerprinting", len(devices))
	}

	e.mu.Lock()
	e.statsCounter.LastRun = time.Now()
	e.mu.Unlock()
}

// worker processes devices from the queue
func (e *FingerprintEnricher) worker(_ int) {
	defer e.wg.Done()

	for {
		select {
		case <-e.ctx.Done():
			return
		case device := <-e.deviceQueue:
			e.processDevice(device)
		}
	}
}

// processDevice collects and stores fingerprint for a device
func (e *FingerprintEnricher) processDevice(device *database.Device) {
	if device.CurrentIP == nil {
		return
	}

	log.Printf("[FINGERPRINT] Collecting info for device %s (%s)", device.MACAddress, device.CurrentIP)

	// Collect fingerprint
	fp := e.collector.CollectAll(device.CurrentIP.String(), device.MACAddress)

	// Store in database
	err := e.db.UpdateDeviceFingerprint(e.ctx, device.DeviceID,
		fp.NetBIOSName, fp.NetBIOSDomain, fp.ResolvedHostname,
		fp.OSType, fp.OSVersion, fp.OSFingerprint,
		fp.InitialTTL, fp.DHCPVendorClass, fp.DeviceClass, fp.Manufacturer,
	)

	e.mu.Lock()
	if err != nil {
		e.statsCounter.Errors++
		log.Printf("[FINGERPRINT] Error saving fingerprint for %s: %v", device.MACAddress, err)
	} else {
		e.statsCounter.Processed++
		log.Printf("[FINGERPRINT] Saved fingerprint for %s: OS=%s, Class=%s, Manufacturer=%s",
			device.MACAddress, fp.OSType, fp.DeviceClass, fp.Manufacturer)
	}
	e.mu.Unlock()
}

// GetStats returns enricher statistics
func (e *FingerprintEnricher) GetStats() (processed, errors int64, lastRun time.Time) {
	e.mu.RLock()
	defer e.mu.RUnlock()
	return e.statsCounter.Processed, e.statsCounter.Errors, e.statsCounter.LastRun
}
