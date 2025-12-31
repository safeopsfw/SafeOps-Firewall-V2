// Package storage provides zone and record data access for the DNS server.
package storage

import (
	"context"
	"database/sql"
	"fmt"
	"log"
	"sync"
	"time"
)

// ============================================================================
// Zone Store
// ============================================================================

// ZoneStore manages DNS zone data persistence and caching
type ZoneStore struct {
	db         *Database
	zoneCache  map[string]*CachedZone
	cacheMutex sync.RWMutex
}

// CachedZone holds zone data with cache metadata
type CachedZone struct {
	Zone         *Zone
	LoadedAt     time.Time
	LastAccessed time.Time
	RecordCount  int
}

// Zone represents a DNS zone with SOA and records
type Zone struct {
	ID          string
	Name        string
	Type        string // "primary" or "secondary"
	Description string
	SOA         *SOARecord
	Records     []*Record
	CreatedAt   time.Time
	UpdatedAt   time.Time
}

// SOARecord represents Start of Authority data
type SOARecord struct {
	ID         string
	ZoneID     string
	PrimaryNS  string
	AdminEmail string
	Serial     uint32
	Refresh    uint32
	Retry      uint32
	Expire     uint32
	MinimumTTL uint32
}

// Record represents a DNS resource record in database format
type Record struct {
	ID        string
	ZoneID    string
	Name      string
	Type      string
	TTL       uint32
	Value     string
	Priority  *uint32 // For MX, SRV
	Weight    *uint32 // For SRV
	Port      *uint32 // For SRV
	IsDynamic bool    // Created by DHCP
	CreatedAt time.Time
	UpdatedAt time.Time
}

// NewZoneStore creates a new zone store
func NewZoneStore(db *Database) *ZoneStore {
	return &ZoneStore{
		db:        db,
		zoneCache: make(map[string]*CachedZone),
	}
}

// ============================================================================
// Zone Operations
// ============================================================================

// LoadZone retrieves a complete zone from database
func (zs *ZoneStore) LoadZone(ctx context.Context, zoneName string) (*Zone, error) {
	// Check cache first
	zs.cacheMutex.RLock()
	if cached, ok := zs.zoneCache[zoneName]; ok {
		cached.LastAccessed = time.Now()
		zs.cacheMutex.RUnlock()
		return cached.Zone, nil
	}
	zs.cacheMutex.RUnlock()

	// Query zone from database
	zone := &Zone{}
	err := zs.db.QueryRow(ctx,
		`SELECT id, name, type, COALESCE(description, ''), created_at, updated_at 
		 FROM dns_zones WHERE name = $1`,
		zoneName,
	).Scan(&zone.ID, &zone.Name, &zone.Type, &zone.Description, &zone.CreatedAt, &zone.UpdatedAt)

	if err == sql.ErrNoRows {
		return nil, fmt.Errorf("zone not found: %s", zoneName)
	}
	if err != nil {
		return nil, fmt.Errorf("failed to load zone %s: %w", zoneName, err)
	}

	// Load SOA
	soa, err := zs.loadSOA(ctx, zone.ID)
	if err != nil {
		return nil, err
	}
	zone.SOA = soa

	// Load records
	records, err := zs.loadRecords(ctx, zone.ID)
	if err != nil {
		return nil, err
	}
	zone.Records = records

	// Update cache
	zs.cacheMutex.Lock()
	zs.zoneCache[zoneName] = &CachedZone{
		Zone:         zone,
		LoadedAt:     time.Now(),
		LastAccessed: time.Now(),
		RecordCount:  len(records),
	}
	zs.cacheMutex.Unlock()

	return zone, nil
}

// SaveZone creates a new zone with SOA record
func (zs *ZoneStore) SaveZone(ctx context.Context, zone *Zone) error {
	tx, err := zs.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("failed to begin transaction: %w", err)
	}
	defer tx.Rollback()

	// Insert zone
	err = tx.QueryRowContext(ctx,
		`INSERT INTO dns_zones (name, type, description) VALUES ($1, $2, $3) RETURNING id`,
		zone.Name, zone.Type, zone.Description,
	).Scan(&zone.ID)
	if err != nil {
		return fmt.Errorf("failed to create zone %s: %w", zone.Name, err)
	}

	// Insert SOA if provided
	if zone.SOA != nil {
		_, err = tx.ExecContext(ctx,
			`INSERT INTO dns_soa (zone_id, primary_ns, admin_email, serial, refresh, retry, expire, minimum_ttl)
			 VALUES ($1, $2, $3, $4, $5, $6, $7, $8)`,
			zone.ID, zone.SOA.PrimaryNS, zone.SOA.AdminEmail, zone.SOA.Serial,
			zone.SOA.Refresh, zone.SOA.Retry, zone.SOA.Expire, zone.SOA.MinimumTTL,
		)
		if err != nil {
			return fmt.Errorf("failed to create SOA for zone %s: %w", zone.Name, err)
		}
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("failed to commit zone %s: %w", zone.Name, err)
	}

	zs.invalidateCache(zone.Name)
	log.Printf("Zone created: %s", zone.Name)
	return nil
}

// DeleteZone removes a zone and all associated records
func (zs *ZoneStore) DeleteZone(ctx context.Context, zoneName string) error {
	result, err := zs.db.Exec(ctx, `DELETE FROM dns_zones WHERE name = $1`, zoneName)
	if err != nil {
		return fmt.Errorf("failed to delete zone %s: %w", zoneName, err)
	}

	rowsAffected, _ := result.RowsAffected()
	if rowsAffected == 0 {
		return fmt.Errorf("zone not found: %s", zoneName)
	}

	zs.invalidateCache(zoneName)
	log.Printf("Zone deleted: %s", zoneName)
	return nil
}

// ListZones returns all zones with metadata
func (zs *ZoneStore) ListZones(ctx context.Context) ([]*Zone, error) {
	rows, err := zs.db.Query(ctx,
		`SELECT z.id, z.name, z.type, COALESCE(z.description, ''), z.created_at, z.updated_at,
		        (SELECT COUNT(*) FROM dns_records WHERE zone_id = z.id) as record_count
		 FROM dns_zones z ORDER BY z.name`,
	)
	if err != nil {
		return nil, fmt.Errorf("failed to list zones: %w", err)
	}
	defer rows.Close()

	var zones []*Zone
	for rows.Next() {
		zone := &Zone{}
		var recordCount int
		if err := rows.Scan(&zone.ID, &zone.Name, &zone.Type, &zone.Description,
			&zone.CreatedAt, &zone.UpdatedAt, &recordCount); err != nil {
			return nil, fmt.Errorf("failed to scan zone: %w", err)
		}
		zones = append(zones, zone)
	}
	return zones, nil
}

// UpdateSOA modifies the SOA record for a zone
func (zs *ZoneStore) UpdateSOA(ctx context.Context, zoneName string, soa *SOARecord) error {
	result, err := zs.db.Exec(ctx,
		`UPDATE dns_soa SET primary_ns=$1, admin_email=$2, serial=$3, 
		 refresh=$4, retry=$5, expire=$6, minimum_ttl=$7
		 WHERE zone_id = (SELECT id FROM dns_zones WHERE name = $8)`,
		soa.PrimaryNS, soa.AdminEmail, soa.Serial,
		soa.Refresh, soa.Retry, soa.Expire, soa.MinimumTTL, zoneName,
	)
	if err != nil {
		return fmt.Errorf("failed to update SOA for %s: %w", zoneName, err)
	}

	rowsAffected, _ := result.RowsAffected()
	if rowsAffected == 0 {
		return fmt.Errorf("SOA not found for zone: %s", zoneName)
	}

	zs.invalidateCache(zoneName)
	return nil
}

// ============================================================================
// Record Operations
// ============================================================================

// AddRecord inserts a new DNS record
func (zs *ZoneStore) AddRecord(ctx context.Context, zoneName string, record *Record) (string, error) {
	// Get zone ID
	zoneID, err := zs.getZoneID(ctx, zoneName)
	if err != nil {
		return "", err
	}

	var recordID string
	err = zs.db.QueryRow(ctx,
		`INSERT INTO dns_records (zone_id, name, type, ttl, value, priority, weight, port, is_dynamic)
		 VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9) RETURNING id`,
		zoneID, record.Name, record.Type, record.TTL, record.Value,
		record.Priority, record.Weight, record.Port, record.IsDynamic,
	).Scan(&recordID)
	if err != nil {
		return "", fmt.Errorf("failed to add record: %w", err)
	}

	zs.invalidateCache(zoneName)
	log.Printf("Record added: %s %s in zone %s", record.Name, record.Type, zoneName)
	return recordID, nil
}

// DeleteRecord removes a record by ID
func (zs *ZoneStore) DeleteRecord(ctx context.Context, recordID string) error {
	// Get zone name for cache invalidation
	var zoneName string
	err := zs.db.QueryRow(ctx,
		`SELECT z.name FROM dns_zones z 
		 JOIN dns_records r ON r.zone_id = z.id 
		 WHERE r.id = $1`,
		recordID,
	).Scan(&zoneName)
	if err != nil {
		return fmt.Errorf("record not found: %s", recordID)
	}

	_, err = zs.db.Exec(ctx, `DELETE FROM dns_records WHERE id = $1`, recordID)
	if err != nil {
		return fmt.Errorf("failed to delete record: %w", err)
	}

	zs.invalidateCache(zoneName)
	return nil
}

// UpdateRecord modifies an existing record
func (zs *ZoneStore) UpdateRecord(ctx context.Context, recordID string, record *Record) error {
	// Get zone name for cache invalidation
	var zoneName string
	err := zs.db.QueryRow(ctx,
		`SELECT z.name FROM dns_zones z 
		 JOIN dns_records r ON r.zone_id = z.id 
		 WHERE r.id = $1`,
		recordID,
	).Scan(&zoneName)
	if err != nil {
		return fmt.Errorf("record not found: %s", recordID)
	}

	_, err = zs.db.Exec(ctx,
		`UPDATE dns_records SET ttl=$1, value=$2, priority=$3, weight=$4, port=$5, updated_at=NOW()
		 WHERE id=$6`,
		record.TTL, record.Value, record.Priority, record.Weight, record.Port, recordID,
	)
	if err != nil {
		return fmt.Errorf("failed to update record: %w", err)
	}

	zs.invalidateCache(zoneName)
	return nil
}

// ListRecords returns records by zone and optional type filter
func (zs *ZoneStore) ListRecords(ctx context.Context, zoneName string, recordType *string) ([]*Record, error) {
	var rows *sql.Rows
	var err error

	if recordType != nil {
		rows, err = zs.db.Query(ctx,
			`SELECT r.id, r.zone_id, r.name, r.type, r.ttl, r.value, r.priority, r.weight, r.port, 
			        COALESCE(r.is_dynamic, false), r.created_at, r.updated_at
			 FROM dns_records r
			 JOIN dns_zones z ON r.zone_id = z.id
			 WHERE z.name = $1 AND r.type = $2
			 ORDER BY r.name`,
			zoneName, *recordType,
		)
	} else {
		rows, err = zs.db.Query(ctx,
			`SELECT r.id, r.zone_id, r.name, r.type, r.ttl, r.value, r.priority, r.weight, r.port,
			        COALESCE(r.is_dynamic, false), r.created_at, r.updated_at
			 FROM dns_records r
			 JOIN dns_zones z ON r.zone_id = z.id
			 WHERE z.name = $1
			 ORDER BY r.name`,
			zoneName,
		)
	}
	if err != nil {
		return nil, fmt.Errorf("failed to list records: %w", err)
	}
	defer rows.Close()

	return zs.scanRecords(rows)
}

// GetRecord retrieves a specific record for query answering
func (zs *ZoneStore) GetRecord(ctx context.Context, zoneName, name, recordType string) (*Record, error) {
	record := &Record{}
	err := zs.db.QueryRow(ctx,
		`SELECT r.id, r.zone_id, r.name, r.type, r.ttl, r.value, r.priority, r.weight, r.port,
		        COALESCE(r.is_dynamic, false), r.created_at, r.updated_at
		 FROM dns_records r
		 JOIN dns_zones z ON r.zone_id = z.id
		 WHERE z.name = $1 AND r.name = $2 AND r.type = $3
		 LIMIT 1`,
		zoneName, name, recordType,
	).Scan(&record.ID, &record.ZoneID, &record.Name, &record.Type, &record.TTL,
		&record.Value, &record.Priority, &record.Weight, &record.Port,
		&record.IsDynamic, &record.CreatedAt, &record.UpdatedAt)

	if err == sql.ErrNoRows {
		return nil, nil // Not found, not an error
	}
	if err != nil {
		return nil, fmt.Errorf("failed to get record: %w", err)
	}
	return record, nil
}

// GetRecordsByName returns all records for a given name (for round-robin, etc.)
func (zs *ZoneStore) GetRecordsByName(ctx context.Context, zoneName, name, recordType string) ([]*Record, error) {
	rows, err := zs.db.Query(ctx,
		`SELECT r.id, r.zone_id, r.name, r.type, r.ttl, r.value, r.priority, r.weight, r.port,
		        COALESCE(r.is_dynamic, false), r.created_at, r.updated_at
		 FROM dns_records r
		 JOIN dns_zones z ON r.zone_id = z.id
		 WHERE z.name = $1 AND r.name = $2 AND r.type = $3`,
		zoneName, name, recordType,
	)
	if err != nil {
		return nil, fmt.Errorf("failed to get records: %w", err)
	}
	defer rows.Close()

	return zs.scanRecords(rows)
}

// ============================================================================
// Cache Management
// ============================================================================

func (zs *ZoneStore) invalidateCache(zoneName string) {
	zs.cacheMutex.Lock()
	delete(zs.zoneCache, zoneName)
	zs.cacheMutex.Unlock()
}

// LoadAllZones pre-loads all zones into cache
func (zs *ZoneStore) LoadAllZones(ctx context.Context) error {
	zones, err := zs.ListZones(ctx)
	if err != nil {
		return err
	}

	for _, zone := range zones {
		if _, err := zs.LoadZone(ctx, zone.Name); err != nil {
			log.Printf("Warning: failed to pre-load zone %s: %v", zone.Name, err)
		}
	}

	log.Printf("Pre-loaded %d zones into cache", len(zones))
	return nil
}

// FlushCache clears the entire zone cache
func (zs *ZoneStore) FlushCache() {
	zs.cacheMutex.Lock()
	zs.zoneCache = make(map[string]*CachedZone)
	zs.cacheMutex.Unlock()
	log.Printf("Zone cache flushed")
}

// GetCacheStats returns cache statistics
func (zs *ZoneStore) GetCacheStats() (int, int) {
	zs.cacheMutex.RLock()
	defer zs.cacheMutex.RUnlock()

	totalRecords := 0
	for _, cached := range zs.zoneCache {
		totalRecords += cached.RecordCount
	}
	return len(zs.zoneCache), totalRecords
}

// ============================================================================
// Helper Methods
// ============================================================================

func (zs *ZoneStore) loadSOA(ctx context.Context, zoneID string) (*SOARecord, error) {
	soa := &SOARecord{}
	err := zs.db.QueryRow(ctx,
		`SELECT id, zone_id, primary_ns, admin_email, serial, refresh, retry, expire, minimum_ttl
		 FROM dns_soa WHERE zone_id = $1`,
		zoneID,
	).Scan(&soa.ID, &soa.ZoneID, &soa.PrimaryNS, &soa.AdminEmail, &soa.Serial,
		&soa.Refresh, &soa.Retry, &soa.Expire, &soa.MinimumTTL)

	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("failed to load SOA: %w", err)
	}
	return soa, nil
}

func (zs *ZoneStore) loadRecords(ctx context.Context, zoneID string) ([]*Record, error) {
	rows, err := zs.db.Query(ctx,
		`SELECT id, zone_id, name, type, ttl, value, priority, weight, port, 
		        COALESCE(is_dynamic, false), created_at, updated_at
		 FROM dns_records WHERE zone_id = $1 ORDER BY name`,
		zoneID,
	)
	if err != nil {
		return nil, fmt.Errorf("failed to load records: %w", err)
	}
	defer rows.Close()

	return zs.scanRecords(rows)
}

func (zs *ZoneStore) scanRecords(rows *sql.Rows) ([]*Record, error) {
	var records []*Record
	for rows.Next() {
		record := &Record{}
		if err := rows.Scan(&record.ID, &record.ZoneID, &record.Name, &record.Type,
			&record.TTL, &record.Value, &record.Priority, &record.Weight, &record.Port,
			&record.IsDynamic, &record.CreatedAt, &record.UpdatedAt); err != nil {
			return nil, fmt.Errorf("failed to scan record: %w", err)
		}
		records = append(records, record)
	}
	return records, nil
}

func (zs *ZoneStore) getZoneID(ctx context.Context, zoneName string) (string, error) {
	var zoneID string
	err := zs.db.QueryRow(ctx, `SELECT id FROM dns_zones WHERE name = $1`, zoneName).Scan(&zoneID)
	if err == sql.ErrNoRows {
		return "", fmt.Errorf("zone not found: %s", zoneName)
	}
	if err != nil {
		return "", fmt.Errorf("failed to get zone ID: %w", err)
	}
	return zoneID, nil
}
