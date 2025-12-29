package revocation

import (
	"context"
	"errors"
	"fmt"
	"log"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// ============================================================================
// Errors
// ============================================================================

var (
	ErrRevocationNotFound      = errors.New("revocation entry not found")
	ErrInvalidSerialNumber     = errors.New("invalid serial number format")
	ErrInvalidRevocationReason = errors.New("invalid revocation reason")
	ErrAlreadyRevoked          = errors.New("certificate already revoked")
	ErrUnrevokeNotAllowed      = errors.New("unrevocation is not allowed")
)

// ============================================================================
// Revocation Reasons (RFC 5280)
// ============================================================================

// RevocationReason represents standard revocation reasons.
type RevocationReason string

const (
	ReasonUnspecified          RevocationReason = "unspecified"
	ReasonKeyCompromise        RevocationReason = "keyCompromise"
	ReasonCACompromise         RevocationReason = "cACompromise"
	ReasonAffiliationChanged   RevocationReason = "affiliationChanged"
	ReasonSuperseded           RevocationReason = "superseded"
	ReasonCessationOfOperation RevocationReason = "cessationOfOperation"
	ReasonCertificateHold      RevocationReason = "certificateHold"
	ReasonRemoveFromCRL        RevocationReason = "removeFromCRL"
	ReasonPrivilegeWithdrawn   RevocationReason = "privilegeWithdrawn"
	ReasonAACompromise         RevocationReason = "aACompromise"
)

// validReasons is the list of valid revocation reasons.
var validReasons = map[RevocationReason]bool{
	ReasonUnspecified:          true,
	ReasonKeyCompromise:        true,
	ReasonCACompromise:         true,
	ReasonAffiliationChanged:   true,
	ReasonSuperseded:           true,
	ReasonCessationOfOperation: true,
	ReasonCertificateHold:      true,
	ReasonRemoveFromCRL:        true,
	ReasonPrivilegeWithdrawn:   true,
	ReasonAACompromise:         true,
}

// ValidateRevocationReason checks if a reason is valid.
func ValidateRevocationReason(reason string) error {
	if !validReasons[RevocationReason(reason)] {
		return fmt.Errorf("%w: %s", ErrInvalidRevocationReason, reason)
	}
	return nil
}

// ============================================================================
// Revocation Entry
// ============================================================================

// RevocationEntry represents a revoked certificate.
type RevocationEntry struct {
	SerialNumber   string           `json:"serial_number"`
	RevokedAt      time.Time        `json:"revoked_at"`
	Reason         RevocationReason `json:"reason"`
	CommonName     string           `json:"common_name"`
	RevokedBy      string           `json:"revoked_by"`
	InvalidityDate *time.Time       `json:"invalidity_date,omitempty"`
}

// ============================================================================
// Revocation Stats
// ============================================================================

// RevocationStats contains revocation statistics.
type RevocationStats struct {
	TotalRevoked     int64     `json:"total_revoked"`
	LastUpdate       time.Time `json:"last_update"`
	CacheHits        int64     `json:"cache_hits"`
	CacheMisses      int64     `json:"cache_misses"`
	HitRate          float64   `json:"hit_rate"`
	SyncedToDatabase bool      `json:"synced_to_database"`
}

// ============================================================================
// Configuration
// ============================================================================

// StorageConfig configures the revocation storage.
type StorageConfig struct {
	CacheEnabled     bool          // Enable in-memory caching
	SyncStrategy     string        // "write_through", "periodic", "hybrid"
	SyncInterval     time.Duration // Interval for periodic sync
	PreloadOnStartup bool          // Load revocations at startup
	MaxCacheSize     int           // Maximum cached entries
	AllowUnrevoke    bool          // Allow certificate unrevocation
}

// DefaultStorageConfig returns default configuration.
func DefaultStorageConfig() *StorageConfig {
	return &StorageConfig{
		CacheEnabled:     true,
		SyncStrategy:     "write_through",
		SyncInterval:     5 * time.Minute,
		PreloadOnStartup: true,
		MaxCacheSize:     100000,
		AllowUnrevoke:    false,
	}
}

// ============================================================================
// Revocation Repository Interface
// ============================================================================

// RevocationRepository defines database operations.
type RevocationRepository interface {
	GetAll(ctx context.Context) ([]*RevocationEntry, error)
	Get(ctx context.Context, serialNumber string) (*RevocationEntry, error)
	Add(ctx context.Context, entry *RevocationEntry) error
	Remove(ctx context.Context, serialNumber string) error
	BulkAdd(ctx context.Context, entries []*RevocationEntry) error
	Count(ctx context.Context) (int64, error)
}

// ============================================================================
// Revocation Storage
// ============================================================================

// RevocationStorage provides dual-layer revocation storage.
type RevocationStorage struct {
	config *StorageConfig
	repo   RevocationRepository

	// In-memory cache
	mu         sync.RWMutex
	cache      map[string]*RevocationEntry
	lastUpdate time.Time

	// Statistics
	cacheHits   int64
	cacheMisses int64

	// Background sync
	stopCh chan struct{}
	wg     sync.WaitGroup
}

// NewRevocationStorage creates a new revocation storage.
func NewRevocationStorage(config *StorageConfig, repo RevocationRepository) *RevocationStorage {
	if config == nil {
		config = DefaultStorageConfig()
	}

	return &RevocationStorage{
		config: config,
		repo:   repo,
		cache:  make(map[string]*RevocationEntry),
		stopCh: make(chan struct{}),
	}
}

// ============================================================================
// Initialization
// ============================================================================

// Initialize loads revocations from database and starts sync worker.
func (s *RevocationStorage) Initialize(ctx context.Context) error {
	if s.config.PreloadOnStartup && s.repo != nil {
		if err := s.LoadFromDatabase(ctx); err != nil {
			log.Printf("[revocation] Warning: failed to preload revocations: %v", err)
		}
	}

	// Start periodic sync if configured
	if s.config.SyncStrategy == "periodic" || s.config.SyncStrategy == "hybrid" {
		s.startSyncWorker()
	}

	return nil
}

// LoadFromDatabase loads all revocations from database into cache.
func (s *RevocationStorage) LoadFromDatabase(ctx context.Context) error {
	if s.repo == nil {
		return nil
	}

	entries, err := s.repo.GetAll(ctx)
	if err != nil {
		return fmt.Errorf("failed to load revocations: %w", err)
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	s.cache = make(map[string]*RevocationEntry, len(entries))
	for _, entry := range entries {
		s.cache[normalizeSerialNumber(entry.SerialNumber)] = entry
	}

	s.lastUpdate = time.Now()
	log.Printf("[revocation] Loaded %d revoked certificates into memory", len(entries))

	return nil
}

// ============================================================================
// Core Operations
// ============================================================================

// IsRevoked checks if a certificate is revoked.
func (s *RevocationStorage) IsRevoked(serialNumber string) (bool, *RevocationEntry) {
	normalized := normalizeSerialNumber(serialNumber)

	s.mu.RLock()
	entry, exists := s.cache[normalized]
	s.mu.RUnlock()

	if exists {
		atomic.AddInt64(&s.cacheHits, 1)
		return true, entry
	}

	atomic.AddInt64(&s.cacheMisses, 1)
	return false, nil
}

// AddRevocation adds a certificate to the revocation list.
func (s *RevocationStorage) AddRevocation(serialNumber, reason, commonName, revokedBy string) error {
	// Validate serial number
	if err := validateSerialNumber(serialNumber); err != nil {
		return err
	}

	// Validate reason
	if err := ValidateRevocationReason(reason); err != nil {
		return err
	}

	normalized := normalizeSerialNumber(serialNumber)

	// Check if already revoked
	s.mu.RLock()
	_, exists := s.cache[normalized]
	s.mu.RUnlock()

	if exists {
		return ErrAlreadyRevoked
	}

	entry := &RevocationEntry{
		SerialNumber: normalized,
		RevokedAt:    time.Now(),
		Reason:       RevocationReason(reason),
		CommonName:   commonName,
		RevokedBy:    revokedBy,
	}

	// Add to cache
	s.mu.Lock()
	s.cache[normalized] = entry
	s.lastUpdate = time.Now()
	s.mu.Unlock()

	// Persist to database (write-through)
	if s.repo != nil && (s.config.SyncStrategy == "write_through" || s.config.SyncStrategy == "hybrid") {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()

		if err := s.repo.Add(ctx, entry); err != nil {
			log.Printf("[revocation] Warning: failed to persist revocation: %v", err)
			// Don't fail - cache is still updated
		}
	}

	log.Printf("[revocation] Revoked certificate: serial=%s, reason=%s, by=%s",
		normalized, reason, revokedBy)

	return nil
}

// RemoveRevocation removes a certificate from the revocation list.
func (s *RevocationStorage) RemoveRevocation(serialNumber string) error {
	if !s.config.AllowUnrevoke {
		return ErrUnrevokeNotAllowed
	}

	normalized := normalizeSerialNumber(serialNumber)

	s.mu.Lock()
	_, exists := s.cache[normalized]
	if !exists {
		s.mu.Unlock()
		return ErrRevocationNotFound
	}
	delete(s.cache, normalized)
	s.lastUpdate = time.Now()
	s.mu.Unlock()

	// Remove from database
	if s.repo != nil && (s.config.SyncStrategy == "write_through" || s.config.SyncStrategy == "hybrid") {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()

		if err := s.repo.Remove(ctx, normalized); err != nil {
			log.Printf("[revocation] Warning: failed to remove revocation from database: %v", err)
		}
	}

	log.Printf("[revocation] Unrevoked certificate: serial=%s (AUDIT EVENT)", normalized)

	return nil
}

// GetRevocation retrieves a revocation entry.
func (s *RevocationStorage) GetRevocation(serialNumber string) (*RevocationEntry, error) {
	normalized := normalizeSerialNumber(serialNumber)

	s.mu.RLock()
	entry, exists := s.cache[normalized]
	s.mu.RUnlock()

	if !exists {
		return nil, ErrRevocationNotFound
	}

	return entry, nil
}

// ============================================================================
// Bulk Operations
// ============================================================================

// GetAllRevocations returns all revoked certificates.
func (s *RevocationStorage) GetAllRevocations() []*RevocationEntry {
	s.mu.RLock()
	defer s.mu.RUnlock()

	entries := make([]*RevocationEntry, 0, len(s.cache))
	for _, entry := range s.cache {
		entries = append(entries, entry)
	}
	return entries
}

// BulkAddRevocations adds multiple revocations at once.
func (s *RevocationStorage) BulkAddRevocations(entries []*RevocationEntry) error {
	if len(entries) == 0 {
		return nil
	}

	s.mu.Lock()
	for _, entry := range entries {
		normalized := normalizeSerialNumber(entry.SerialNumber)
		entry.SerialNumber = normalized
		s.cache[normalized] = entry
	}
	s.lastUpdate = time.Now()
	s.mu.Unlock()

	// Persist to database
	if s.repo != nil && (s.config.SyncStrategy == "write_through" || s.config.SyncStrategy == "hybrid") {
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()

		if err := s.repo.BulkAdd(ctx, entries); err != nil {
			log.Printf("[revocation] Warning: failed to bulk persist revocations: %v", err)
		}
	}

	log.Printf("[revocation] Bulk added %d revocations", len(entries))
	return nil
}

// ============================================================================
// Synchronization
// ============================================================================

// startSyncWorker starts the periodic sync worker.
func (s *RevocationStorage) startSyncWorker() {
	s.wg.Add(1)
	go func() {
		defer s.wg.Done()

		ticker := time.NewTicker(s.config.SyncInterval)
		defer ticker.Stop()

		for {
			select {
			case <-s.stopCh:
				return
			case <-ticker.C:
				s.syncToDatabase()
			}
		}
	}()
}

// syncToDatabase syncs in-memory cache to database.
func (s *RevocationStorage) syncToDatabase() {
	if s.repo == nil {
		return
	}

	s.mu.RLock()
	entries := make([]*RevocationEntry, 0, len(s.cache))
	for _, entry := range s.cache {
		entries = append(entries, entry)
	}
	s.mu.RUnlock()

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	if err := s.repo.BulkAdd(ctx, entries); err != nil {
		log.Printf("[revocation] Sync to database failed: %v", err)
		return
	}

	log.Printf("[revocation] Synced %d revocations to database", len(entries))
}

// ============================================================================
// Statistics
// ============================================================================

// GetStats returns revocation statistics.
func (s *RevocationStorage) GetStats() *RevocationStats {
	s.mu.RLock()
	totalRevoked := int64(len(s.cache))
	lastUpdate := s.lastUpdate
	s.mu.RUnlock()

	hits := atomic.LoadInt64(&s.cacheHits)
	misses := atomic.LoadInt64(&s.cacheMisses)
	total := hits + misses

	var hitRate float64
	if total > 0 {
		hitRate = float64(hits) / float64(total) * 100
	}

	return &RevocationStats{
		TotalRevoked:     totalRevoked,
		LastUpdate:       lastUpdate,
		CacheHits:        hits,
		CacheMisses:      misses,
		HitRate:          hitRate,
		SyncedToDatabase: s.repo != nil,
	}
}

// Count returns the number of revoked certificates.
func (s *RevocationStorage) Count() int {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return len(s.cache)
}

// ============================================================================
// Lifecycle
// ============================================================================

// Stop stops the storage and syncs to database.
func (s *RevocationStorage) Stop() {
	close(s.stopCh)
	s.wg.Wait()

	// Final sync
	if s.config.SyncStrategy == "periodic" {
		s.syncToDatabase()
	}
}

// Clear clears all revocations from cache.
func (s *RevocationStorage) Clear() {
	s.mu.Lock()
	s.cache = make(map[string]*RevocationEntry)
	s.lastUpdate = time.Now()
	s.mu.Unlock()
}

// ============================================================================
// Helper Functions
// ============================================================================

// normalizeSerialNumber normalizes a serial number to uppercase hex.
func normalizeSerialNumber(serial string) string {
	// Remove colons and convert to uppercase
	serial = strings.ReplaceAll(serial, ":", "")
	serial = strings.ReplaceAll(serial, " ", "")
	return strings.ToUpper(strings.TrimSpace(serial))
}

// validateSerialNumber validates a serial number format.
func validateSerialNumber(serial string) error {
	if serial == "" {
		return fmt.Errorf("%w: empty serial number", ErrInvalidSerialNumber)
	}

	// Remove formatting
	normalized := normalizeSerialNumber(serial)

	// Check it's valid hex
	for _, c := range normalized {
		if !((c >= '0' && c <= '9') || (c >= 'A' && c <= 'F')) {
			return fmt.Errorf("%w: invalid character in serial number", ErrInvalidSerialNumber)
		}
	}

	return nil
}
