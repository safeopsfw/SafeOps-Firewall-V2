// Package storage provides database operations for the DHCP server.
// This file implements the data access layer for DHCP lease management.
package storage

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"net"
	"time"
)

// ============================================================================
// Lease State
// ============================================================================

// LeaseState represents the state of a DHCP lease.
type LeaseState string

const (
	LeaseStateOffered  LeaseState = "OFFERED"
	LeaseStateActive   LeaseState = "ACTIVE"
	LeaseStateExpired  LeaseState = "EXPIRED"
	LeaseStateReleased LeaseState = "RELEASED"
)

// ============================================================================
// Lease Model
// ============================================================================

// DBLease represents a database lease record.
type DBLease struct {
	ID            int64
	PoolID        int64
	IPAddress     net.IP
	MACAddress    net.HardwareAddr
	Hostname      string
	ClientID      string
	State         LeaseState
	LeaseStart    time.Time
	LeaseEnd      time.Time
	LastSeen      *time.Time
	TransactionID uint32
	RenewalCount  int
	LastRenewed   *time.Time
	CreatedAt     time.Time
	UpdatedAt     time.Time
}

// ============================================================================
// Repository Definition
// ============================================================================

// LeaseRepository provides data access for DHCP leases.
type LeaseRepository struct {
	db      *Database
	timeout time.Duration
}

// NewLeaseRepository creates a new lease repository.
func NewLeaseRepository(db *Database) *LeaseRepository {
	return &LeaseRepository{
		db:      db,
		timeout: 5 * time.Second,
	}
}

// ============================================================================
// CRUD Operations
// ============================================================================

// CreateLease creates a new lease record.
func (r *LeaseRepository) CreateLease(ctx context.Context, lease *DBLease) error {
	ctx, cancel := context.WithTimeout(ctx, r.timeout)
	defer cancel()

	query := `
		INSERT INTO dhcp_leases (
			pool_id, ip_address, mac_address, hostname, client_id,
			state, lease_start, lease_end, transaction_id
		) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
		RETURNING id, created_at, updated_at
	`

	err := r.db.QueryRow(ctx, query,
		lease.PoolID,
		lease.IPAddress.String(),
		lease.MACAddress.String(),
		lease.Hostname,
		lease.ClientID,
		lease.State,
		lease.LeaseStart,
		lease.LeaseEnd,
		lease.TransactionID,
	).Scan(&lease.ID, &lease.CreatedAt, &lease.UpdatedAt)

	if err != nil {
		if IsConstraintViolation(err) {
			return ErrLeaseAlreadyExists
		}
		return fmt.Errorf("failed to create lease: %w", err)
	}

	return nil
}

// GetLeaseByID retrieves a lease by ID.
func (r *LeaseRepository) GetLeaseByID(ctx context.Context, id int64) (*DBLease, error) {
	ctx, cancel := context.WithTimeout(ctx, r.timeout)
	defer cancel()

	query := `
		SELECT id, pool_id, ip_address, mac_address, hostname, client_id,
			   state, lease_start, lease_end, last_seen, transaction_id,
			   renewal_count, last_renewed, created_at, updated_at
		FROM dhcp_leases
		WHERE id = $1
	`

	return r.scanLease(r.db.QueryRow(ctx, query, id))
}

// GetLeaseByMAC retrieves an active lease by MAC address.
func (r *LeaseRepository) GetLeaseByMAC(ctx context.Context, mac net.HardwareAddr) (*DBLease, error) {
	ctx, cancel := context.WithTimeout(ctx, r.timeout)
	defer cancel()

	query := `
		SELECT id, pool_id, ip_address, mac_address, hostname, client_id,
			   state, lease_start, lease_end, last_seen, transaction_id,
			   renewal_count, last_renewed, created_at, updated_at
		FROM dhcp_leases
		WHERE mac_address = $1
		  AND state NOT IN ('EXPIRED', 'RELEASED')
		ORDER BY created_at DESC
		LIMIT 1
	`

	return r.scanLease(r.db.QueryRow(ctx, query, mac.String()))
}

// GetLeaseByIP retrieves an active lease by IP address.
func (r *LeaseRepository) GetLeaseByIP(ctx context.Context, ip net.IP) (*DBLease, error) {
	ctx, cancel := context.WithTimeout(ctx, r.timeout)
	defer cancel()

	query := `
		SELECT id, pool_id, ip_address, mac_address, hostname, client_id,
			   state, lease_start, lease_end, last_seen, transaction_id,
			   renewal_count, last_renewed, created_at, updated_at
		FROM dhcp_leases
		WHERE ip_address = $1
		  AND state = 'ACTIVE'
	`

	return r.scanLease(r.db.QueryRow(ctx, query, ip.String()))
}

// UpdateLease updates an existing lease.
func (r *LeaseRepository) UpdateLease(ctx context.Context, lease *DBLease) error {
	ctx, cancel := context.WithTimeout(ctx, r.timeout)
	defer cancel()

	query := `
		UPDATE dhcp_leases
		SET ip_address = $2,
			hostname = $3,
			state = $4,
			lease_end = $5,
			last_seen = $6,
			renewal_count = $7,
			last_renewed = $8,
			updated_at = NOW()
		WHERE id = $1
	`

	result, err := r.db.Exec(ctx, query,
		lease.ID,
		lease.IPAddress.String(),
		lease.Hostname,
		lease.State,
		lease.LeaseEnd,
		lease.LastSeen,
		lease.RenewalCount,
		lease.LastRenewed,
	)
	if err != nil {
		return fmt.Errorf("failed to update lease: %w", err)
	}

	rows, _ := result.RowsAffected()
	if rows == 0 {
		return ErrLeaseNotFound
	}

	return nil
}

// DeleteLease deletes a lease by ID.
func (r *LeaseRepository) DeleteLease(ctx context.Context, id int64) error {
	ctx, cancel := context.WithTimeout(ctx, r.timeout)
	defer cancel()

	query := `DELETE FROM dhcp_leases WHERE id = $1`
	result, err := r.db.Exec(ctx, query, id)
	if err != nil {
		return fmt.Errorf("failed to delete lease: %w", err)
	}

	rows, _ := result.RowsAffected()
	if rows == 0 {
		return ErrLeaseNotFound
	}

	return nil
}

// ============================================================================
// Query Methods
// ============================================================================

// GetActiveLeases retrieves all active leases.
func (r *LeaseRepository) GetActiveLeases(ctx context.Context) ([]*DBLease, error) {
	ctx, cancel := context.WithTimeout(ctx, r.timeout)
	defer cancel()

	query := `
		SELECT id, pool_id, ip_address, mac_address, hostname, client_id,
			   state, lease_start, lease_end, last_seen, transaction_id,
			   renewal_count, last_renewed, created_at, updated_at
		FROM dhcp_leases
		WHERE state = 'ACTIVE'
		  AND lease_end > NOW()
		ORDER BY lease_start DESC
	`

	return r.queryLeases(ctx, query)
}

// GetLeasesByPool retrieves all leases for a pool.
func (r *LeaseRepository) GetLeasesByPool(ctx context.Context, poolID int64) ([]*DBLease, error) {
	ctx, cancel := context.WithTimeout(ctx, r.timeout)
	defer cancel()

	query := `
		SELECT id, pool_id, ip_address, mac_address, hostname, client_id,
			   state, lease_start, lease_end, last_seen, transaction_id,
			   renewal_count, last_renewed, created_at, updated_at
		FROM dhcp_leases
		WHERE pool_id = $1
		  AND state IN ('OFFERED', 'ACTIVE')
		ORDER BY ip_address
	`

	return r.queryLeases(ctx, query, poolID)
}

// GetExpiredLeases retrieves leases that have expired.
func (r *LeaseRepository) GetExpiredLeases(ctx context.Context) ([]*DBLease, error) {
	ctx, cancel := context.WithTimeout(ctx, r.timeout)
	defer cancel()

	query := `
		SELECT id, pool_id, ip_address, mac_address, hostname, client_id,
			   state, lease_start, lease_end, last_seen, transaction_id,
			   renewal_count, last_renewed, created_at, updated_at
		FROM dhcp_leases
		WHERE state = 'ACTIVE'
		  AND lease_end < NOW()
	`

	return r.queryLeases(ctx, query)
}

// GetLeaseCountByPool returns the count of active leases in a pool.
func (r *LeaseRepository) GetLeaseCountByPool(ctx context.Context, poolID int64) (int, error) {
	ctx, cancel := context.WithTimeout(ctx, r.timeout)
	defer cancel()

	query := `
		SELECT COUNT(*)
		FROM dhcp_leases
		WHERE pool_id = $1
		  AND state IN ('OFFERED', 'ACTIVE')
	`

	var count int
	row := r.db.QueryRow(ctx, query, poolID)
	if row == nil {
		return 0, ErrNotConnected
	}
	if err := row.Scan(&count); err != nil {
		return 0, err
	}
	return count, nil
}

// ============================================================================
// State Transition Methods
// ============================================================================

// ActivateLease transitions lease from OFFERED to ACTIVE.
func (r *LeaseRepository) ActivateLease(ctx context.Context, id int64) error {
	ctx, cancel := context.WithTimeout(ctx, r.timeout)
	defer cancel()

	query := `
		UPDATE dhcp_leases
		SET state = 'ACTIVE',
			last_seen = NOW(),
			updated_at = NOW()
		WHERE id = $1
		  AND state = 'OFFERED'
	`

	result, err := r.db.Exec(ctx, query, id)
	if err != nil {
		return err
	}

	rows, _ := result.RowsAffected()
	if rows == 0 {
		return ErrLeaseNotFound
	}

	return nil
}

// ReleaseLeaseByMAC releases a lease by MAC address.
func (r *LeaseRepository) ReleaseLeaseByMAC(ctx context.Context, mac net.HardwareAddr) error {
	ctx, cancel := context.WithTimeout(ctx, r.timeout)
	defer cancel()

	query := `
		UPDATE dhcp_leases
		SET state = 'RELEASED',
			updated_at = NOW()
		WHERE mac_address = $1
		  AND state = 'ACTIVE'
	`

	_, err := r.db.Exec(ctx, query, mac.String())
	return err
}

// ExpireLeases marks expired leases as EXPIRED.
func (r *LeaseRepository) ExpireLeases(ctx context.Context) (int64, error) {
	ctx, cancel := context.WithTimeout(ctx, r.timeout)
	defer cancel()

	query := `
		UPDATE dhcp_leases
		SET state = 'EXPIRED',
			updated_at = NOW()
		WHERE state = 'ACTIVE'
		  AND lease_end < NOW()
	`

	result, err := r.db.Exec(ctx, query)
	if err != nil {
		return 0, err
	}

	return result.RowsAffected()
}

// RenewLease extends a lease expiration time.
func (r *LeaseRepository) RenewLease(ctx context.Context, id int64, newExpiry time.Time) error {
	ctx, cancel := context.WithTimeout(ctx, r.timeout)
	defer cancel()

	query := `
		UPDATE dhcp_leases
		SET lease_end = $2,
			last_seen = NOW(),
			renewal_count = renewal_count + 1,
			last_renewed = NOW(),
			updated_at = NOW()
		WHERE id = $1
		  AND state = 'ACTIVE'
	`

	result, err := r.db.Exec(ctx, query, id, newExpiry)
	if err != nil {
		return err
	}

	rows, _ := result.RowsAffected()
	if rows == 0 {
		return ErrLeaseNotFound
	}

	return nil
}

// ============================================================================
// Helper Functions
// ============================================================================

func (r *LeaseRepository) scanLease(row *sql.Row) (*DBLease, error) {
	if row == nil {
		return nil, ErrNotConnected
	}

	var lease DBLease
	var ipStr, macStr string
	var lastSeen, lastRenewed sql.NullTime

	err := row.Scan(
		&lease.ID,
		&lease.PoolID,
		&ipStr,
		&macStr,
		&lease.Hostname,
		&lease.ClientID,
		&lease.State,
		&lease.LeaseStart,
		&lease.LeaseEnd,
		&lastSeen,
		&lease.TransactionID,
		&lease.RenewalCount,
		&lastRenewed,
		&lease.CreatedAt,
		&lease.UpdatedAt,
	)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, nil
		}
		return nil, err
	}

	lease.IPAddress = net.ParseIP(ipStr)
	lease.MACAddress, _ = net.ParseMAC(macStr)
	if lastSeen.Valid {
		lease.LastSeen = &lastSeen.Time
	}
	if lastRenewed.Valid {
		lease.LastRenewed = &lastRenewed.Time
	}

	return &lease, nil
}

func (r *LeaseRepository) queryLeases(ctx context.Context, query string, args ...interface{}) ([]*DBLease, error) {
	rows, err := r.db.Query(ctx, query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	leases := make([]*DBLease, 0)
	for rows.Next() {
		var lease DBLease
		var ipStr, macStr string
		var lastSeen, lastRenewed sql.NullTime

		err := rows.Scan(
			&lease.ID,
			&lease.PoolID,
			&ipStr,
			&macStr,
			&lease.Hostname,
			&lease.ClientID,
			&lease.State,
			&lease.LeaseStart,
			&lease.LeaseEnd,
			&lastSeen,
			&lease.TransactionID,
			&lease.RenewalCount,
			&lastRenewed,
			&lease.CreatedAt,
			&lease.UpdatedAt,
		)
		if err != nil {
			return nil, err
		}

		lease.IPAddress = net.ParseIP(ipStr)
		lease.MACAddress, _ = net.ParseMAC(macStr)
		if lastSeen.Valid {
			lease.LastSeen = &lastSeen.Time
		}
		if lastRenewed.Valid {
			lease.LastRenewed = &lastRenewed.Time
		}

		leases = append(leases, &lease)
	}

	return leases, nil
}

// ============================================================================
// Errors
// ============================================================================

var (
	// ErrLeaseNotFound is returned when lease doesn't exist
	ErrLeaseNotFound = errors.New("lease not found")

	// ErrLeaseAlreadyExists is returned for duplicate MAC/IP
	ErrLeaseAlreadyExists = errors.New("lease already exists")
)
