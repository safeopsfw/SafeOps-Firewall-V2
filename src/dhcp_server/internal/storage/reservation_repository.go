// Package storage provides database operations for the DHCP server.
// This file implements the data access layer for static IP reservations.
package storage

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"net"
	"regexp"
	"strings"
	"time"
)

// ============================================================================
// Reservation Database Model
// ============================================================================

// DBReservation represents a database reservation record.
type DBReservation struct {
	ID          int64
	PoolID      int64
	MACAddress  net.HardwareAddr
	IPAddress   net.IP
	Hostname    string
	Description string
	Enabled     bool
	ExpiresAt   *time.Time
	CreatedAt   time.Time
	UpdatedAt   time.Time
}

// ============================================================================
// Repository Definition
// ============================================================================

// ReservationRepository provides data access for DHCP reservations.
type ReservationRepository struct {
	db      *Database
	timeout time.Duration
}

// NewReservationRepository creates a new reservation repository.
func NewReservationRepository(db *Database) *ReservationRepository {
	return &ReservationRepository{
		db:      db,
		timeout: 5 * time.Second,
	}
}

// ============================================================================
// CRUD Operations
// ============================================================================

// CreateReservation creates a new static IP reservation.
func (r *ReservationRepository) CreateReservation(ctx context.Context, res *DBReservation) error {
	ctx, cancel := context.WithTimeout(ctx, r.timeout)
	defer cancel()

	// Validate MAC format
	if err := validateMACFormat(res.MACAddress.String()); err != nil {
		return err
	}

	// Check IP in pool range
	inRange, err := r.CheckIPInPoolRange(ctx, res.PoolID, res.IPAddress)
	if err != nil {
		return err
	}
	if !inRange {
		return ErrIPOutsidePoolRange
	}

	query := `
		INSERT INTO dhcp_reservations (
			pool_id, mac_address, ip_address, hostname, 
			description, enabled, expires_at
		) VALUES ($1, $2, $3, $4, $5, $6, $7)
		RETURNING id, created_at, updated_at
	`

	macStr := normalizeMACAddress(res.MACAddress.String())

	err = r.db.QueryRow(ctx, query,
		res.PoolID,
		macStr,
		res.IPAddress.String(),
		res.Hostname,
		res.Description,
		res.Enabled,
		res.ExpiresAt,
	).Scan(&res.ID, &res.CreatedAt, &res.UpdatedAt)

	if err != nil {
		if IsConstraintViolation(err) {
			if strings.Contains(err.Error(), "mac_address") {
				return ErrMACAlreadyReserved
			}
			if strings.Contains(err.Error(), "ip_address") {
				return ErrIPAlreadyReserved
			}
			return ErrReservationConflict
		}
		return fmt.Errorf("failed to create reservation: %w", err)
	}

	return nil
}

// GetReservationByID retrieves a reservation by ID.
func (r *ReservationRepository) GetReservationByID(ctx context.Context, id int64) (*DBReservation, error) {
	ctx, cancel := context.WithTimeout(ctx, r.timeout)
	defer cancel()

	query := `
		SELECT id, pool_id, mac_address, ip_address, hostname,
			   description, enabled, expires_at, created_at, updated_at
		FROM dhcp_reservations
		WHERE id = $1
	`

	return r.scanReservation(r.db.QueryRow(ctx, query, id))
}

// GetReservationByMAC retrieves an enabled reservation by MAC address.
func (r *ReservationRepository) GetReservationByMAC(ctx context.Context, mac net.HardwareAddr) (*DBReservation, error) {
	ctx, cancel := context.WithTimeout(ctx, r.timeout)
	defer cancel()

	macStr := normalizeMACAddress(mac.String())

	query := `
		SELECT id, pool_id, mac_address, ip_address, hostname,
			   description, enabled, expires_at, created_at, updated_at
		FROM dhcp_reservations
		WHERE mac_address = $1
		  AND enabled = TRUE
	`

	return r.scanReservation(r.db.QueryRow(ctx, query, macStr))
}

// GetReservationByIP retrieves an enabled reservation by IP address.
func (r *ReservationRepository) GetReservationByIP(ctx context.Context, ip net.IP) (*DBReservation, error) {
	ctx, cancel := context.WithTimeout(ctx, r.timeout)
	defer cancel()

	query := `
		SELECT id, pool_id, mac_address, ip_address, hostname,
			   description, enabled, expires_at, created_at, updated_at
		FROM dhcp_reservations
		WHERE ip_address = $1
		  AND enabled = TRUE
	`

	return r.scanReservation(r.db.QueryRow(ctx, query, ip.String()))
}

// ListReservations retrieves all enabled reservations.
func (r *ReservationRepository) ListReservations(ctx context.Context) ([]*DBReservation, error) {
	ctx, cancel := context.WithTimeout(ctx, r.timeout)
	defer cancel()

	query := `
		SELECT id, pool_id, mac_address, ip_address, hostname,
			   description, enabled, expires_at, created_at, updated_at
		FROM dhcp_reservations
		WHERE enabled = TRUE
		ORDER BY ip_address ASC
	`

	return r.queryReservations(ctx, query)
}

// GetReservationsByPool retrieves all reservations for a pool.
func (r *ReservationRepository) GetReservationsByPool(ctx context.Context, poolID int64) ([]*DBReservation, error) {
	ctx, cancel := context.WithTimeout(ctx, r.timeout)
	defer cancel()

	query := `
		SELECT id, pool_id, mac_address, ip_address, hostname,
			   description, enabled, expires_at, created_at, updated_at
		FROM dhcp_reservations
		WHERE pool_id = $1
		  AND enabled = TRUE
		ORDER BY ip_address ASC
	`

	return r.queryReservations(ctx, query, poolID)
}

// UpdateReservation updates an existing reservation.
func (r *ReservationRepository) UpdateReservation(ctx context.Context, res *DBReservation) error {
	ctx, cancel := context.WithTimeout(ctx, r.timeout)
	defer cancel()

	// Validate MAC format
	if err := validateMACFormat(res.MACAddress.String()); err != nil {
		return err
	}

	// Check IP in pool range
	inRange, err := r.CheckIPInPoolRange(ctx, res.PoolID, res.IPAddress)
	if err != nil {
		return err
	}
	if !inRange {
		return ErrIPOutsidePoolRange
	}

	query := `
		UPDATE dhcp_reservations
		SET mac_address = $2,
			ip_address = $3,
			hostname = $4,
			description = $5,
			enabled = $6,
			expires_at = $7,
			updated_at = NOW()
		WHERE id = $1
	`

	macStr := normalizeMACAddress(res.MACAddress.String())

	result, err := r.db.Exec(ctx, query,
		res.ID,
		macStr,
		res.IPAddress.String(),
		res.Hostname,
		res.Description,
		res.Enabled,
		res.ExpiresAt,
	)
	if err != nil {
		if IsConstraintViolation(err) {
			return ErrReservationConflict
		}
		return fmt.Errorf("failed to update reservation: %w", err)
	}

	rows, _ := result.RowsAffected()
	if rows == 0 {
		return ErrReservationNotFound
	}

	return nil
}

// DeleteReservation deletes a reservation by ID.
func (r *ReservationRepository) DeleteReservation(ctx context.Context, id int64) error {
	ctx, cancel := context.WithTimeout(ctx, r.timeout)
	defer cancel()

	query := `DELETE FROM dhcp_reservations WHERE id = $1`
	result, err := r.db.Exec(ctx, query, id)
	if err != nil {
		return fmt.Errorf("failed to delete reservation: %w", err)
	}

	rows, _ := result.RowsAffected()
	if rows == 0 {
		return ErrReservationNotFound
	}

	return nil
}

// EnableReservation enables a reservation.
func (r *ReservationRepository) EnableReservation(ctx context.Context, id int64) error {
	return r.setReservationEnabled(ctx, id, true)
}

// DisableReservation disables a reservation.
func (r *ReservationRepository) DisableReservation(ctx context.Context, id int64) error {
	return r.setReservationEnabled(ctx, id, false)
}

func (r *ReservationRepository) setReservationEnabled(ctx context.Context, id int64, enabled bool) error {
	ctx, cancel := context.WithTimeout(ctx, r.timeout)
	defer cancel()

	query := `UPDATE dhcp_reservations SET enabled = $2, updated_at = NOW() WHERE id = $1`
	result, err := r.db.Exec(ctx, query, id, enabled)
	if err != nil {
		return err
	}

	rows, _ := result.RowsAffected()
	if rows == 0 {
		return ErrReservationNotFound
	}

	return nil
}

// ============================================================================
// Lookup Methods
// ============================================================================

// IsIPReserved checks if an IP has an active reservation.
func (r *ReservationRepository) IsIPReserved(ctx context.Context, ip net.IP) (bool, error) {
	ctx, cancel := context.WithTimeout(ctx, r.timeout)
	defer cancel()

	query := `
		SELECT EXISTS(
			SELECT 1 FROM dhcp_reservations
			WHERE ip_address = $1 AND enabled = TRUE
		)
	`

	var exists bool
	row := r.db.QueryRow(ctx, query, ip.String())
	if row == nil {
		return false, ErrNotConnected
	}
	if err := row.Scan(&exists); err != nil {
		return false, err
	}
	return exists, nil
}

// IsMACReserved checks if a MAC has an active reservation.
func (r *ReservationRepository) IsMACReserved(ctx context.Context, mac net.HardwareAddr) (bool, error) {
	ctx, cancel := context.WithTimeout(ctx, r.timeout)
	defer cancel()

	macStr := normalizeMACAddress(mac.String())

	query := `
		SELECT EXISTS(
			SELECT 1 FROM dhcp_reservations
			WHERE mac_address = $1 AND enabled = TRUE
		)
	`

	var exists bool
	row := r.db.QueryRow(ctx, query, macStr)
	if row == nil {
		return false, ErrNotConnected
	}
	if err := row.Scan(&exists); err != nil {
		return false, err
	}
	return exists, nil
}

// GetReservedIPForMAC returns the reserved IP for a MAC, or nil if none.
func (r *ReservationRepository) GetReservedIPForMAC(ctx context.Context, mac net.HardwareAddr) (net.IP, error) {
	res, err := r.GetReservationByMAC(ctx, mac)
	if err != nil {
		return nil, err
	}
	if res == nil {
		return nil, nil
	}
	return res.IPAddress, nil
}

// ============================================================================
// Validation Methods
// ============================================================================

// CheckIPInPoolRange verifies IP is within pool's range.
func (r *ReservationRepository) CheckIPInPoolRange(ctx context.Context, poolID int64, ip net.IP) (bool, error) {
	ctx, cancel := context.WithTimeout(ctx, r.timeout)
	defer cancel()

	// Get pool subnet
	var subnetCIDR string
	row := r.db.QueryRow(ctx, `SELECT subnet_cidr FROM dhcp_pools WHERE id = $1`, poolID)
	if row == nil {
		return false, ErrNotConnected
	}
	if err := row.Scan(&subnetCIDR); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return false, ErrPoolNotFound
		}
		return false, err
	}

	_, subnet, err := net.ParseCIDR(subnetCIDR)
	if err != nil {
		return false, err
	}

	return subnet.Contains(ip), nil
}

// CountReservationsByPool returns the count of reservations in a pool.
func (r *ReservationRepository) CountReservationsByPool(ctx context.Context, poolID int64) (int, error) {
	ctx, cancel := context.WithTimeout(ctx, r.timeout)
	defer cancel()

	query := `
		SELECT COUNT(*) FROM dhcp_reservations
		WHERE pool_id = $1 AND enabled = TRUE
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
// Helper Functions
// ============================================================================

func (r *ReservationRepository) scanReservation(row *sql.Row) (*DBReservation, error) {
	if row == nil {
		return nil, ErrNotConnected
	}

	var res DBReservation
	var macStr, ipStr string
	var expiresAt sql.NullTime

	err := row.Scan(
		&res.ID,
		&res.PoolID,
		&macStr,
		&ipStr,
		&res.Hostname,
		&res.Description,
		&res.Enabled,
		&expiresAt,
		&res.CreatedAt,
		&res.UpdatedAt,
	)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, nil
		}
		return nil, err
	}

	res.MACAddress, _ = net.ParseMAC(macStr)
	res.IPAddress = net.ParseIP(ipStr)
	if expiresAt.Valid {
		res.ExpiresAt = &expiresAt.Time
	}

	return &res, nil
}

func (r *ReservationRepository) queryReservations(ctx context.Context, query string, args ...interface{}) ([]*DBReservation, error) {
	rows, err := r.db.Query(ctx, query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	reservations := make([]*DBReservation, 0)
	for rows.Next() {
		var res DBReservation
		var macStr, ipStr string
		var expiresAt sql.NullTime

		err := rows.Scan(
			&res.ID,
			&res.PoolID,
			&macStr,
			&ipStr,
			&res.Hostname,
			&res.Description,
			&res.Enabled,
			&expiresAt,
			&res.CreatedAt,
			&res.UpdatedAt,
		)
		if err != nil {
			return nil, err
		}

		res.MACAddress, _ = net.ParseMAC(macStr)
		res.IPAddress = net.ParseIP(ipStr)
		if expiresAt.Valid {
			res.ExpiresAt = &expiresAt.Time
		}

		reservations = append(reservations, &res)
	}

	return reservations, nil
}

// MAC address regex pattern
var macRegex = regexp.MustCompile(`^([0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}$`)

func validateMACFormat(mac string) error {
	normalized := normalizeMACAddress(mac)
	if !macRegex.MatchString(normalized) {
		return ErrInvalidMACFormat
	}
	return nil
}

func normalizeMACAddress(mac string) string {
	// Convert dash-separated to colon-separated
	mac = strings.ReplaceAll(mac, "-", ":")
	// Convert to lowercase
	return strings.ToLower(mac)
}

// ipToUint32 is available in pool_repository.go if needed

// ============================================================================
// Errors
// ============================================================================

var (
	// ErrReservationNotFound is returned when reservation doesn't exist
	ErrReservationNotFound = errors.New("reservation not found")

	// ErrMACAlreadyReserved is returned for duplicate MAC
	ErrMACAlreadyReserved = errors.New("MAC address already reserved")

	// ErrIPAlreadyReserved is returned for duplicate IP
	ErrIPAlreadyReserved = errors.New("IP address already reserved")

	// ErrReservationConflict is returned for general conflicts
	ErrReservationConflict = errors.New("reservation conflict")

	// ErrIPOutsidePoolRange is returned when IP not in pool
	ErrIPOutsidePoolRange = errors.New("IP address is outside pool range")

	// ErrInvalidMACFormat is returned for malformed MAC
	ErrInvalidMACFormat = errors.New("invalid MAC address format")
)
