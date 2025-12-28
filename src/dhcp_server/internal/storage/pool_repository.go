// Package storage provides database operations for the DHCP server.
// This file implements the data access layer for DHCP pool management.
package storage

import (
	"context"
	"database/sql"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"time"
)

// ============================================================================
// Pool Database Model
// ============================================================================

// DBPool represents a database pool record.
type DBPool struct {
	ID               int64
	Name             string
	Description      string
	SubnetCIDR       string
	RangeStart       net.IP
	RangeEnd         net.IP
	Gateway          net.IP
	DNSServers       []net.IP
	DomainName       string
	NTPServers       []net.IP
	DefaultLeaseTime time.Duration
	MinLeaseTime     time.Duration
	MaxLeaseTime     time.Duration
	VLANID           int
	Enabled          bool
	CreatedAt        time.Time
	UpdatedAt        time.Time
}

// PoolStats holds pool utilization statistics.
type PoolStats struct {
	PoolID       int64
	TotalIPs     int
	ActiveLeases int
	ReservedIPs  int
	AvailableIPs int
	Utilization  float64
}

// ============================================================================
// Repository Definition
// ============================================================================

// PoolRepository provides data access for DHCP pools.
type PoolRepository struct {
	db      *Database
	timeout time.Duration
}

// NewPoolRepository creates a new pool repository.
func NewPoolRepository(db *Database) *PoolRepository {
	return &PoolRepository{
		db:      db,
		timeout: 5 * time.Second,
	}
}

// ============================================================================
// CRUD Operations
// ============================================================================

// CreatePool creates a new pool record.
func (r *PoolRepository) CreatePool(ctx context.Context, pool *DBPool) error {
	ctx, cancel := context.WithTimeout(ctx, r.timeout)
	defer cancel()

	// Validate configuration
	if err := r.ValidatePoolConfig(pool); err != nil {
		return err
	}

	// Check for overlap
	overlap, err := r.CheckPoolOverlap(ctx, pool.RangeStart, pool.RangeEnd, 0)
	if err != nil {
		return err
	}
	if overlap {
		return ErrPoolOverlap
	}

	query := `
		INSERT INTO dhcp_pools (
			name, description, subnet_cidr, gateway, 
			dns_servers, domain_name, ntp_servers,
			default_lease_time, min_lease_time, max_lease_time,
			vlan_id, enabled
		) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12)
		RETURNING id, created_at, updated_at
	`

	dnsArray := ipListToStringArray(pool.DNSServers)
	ntpArray := ipListToStringArray(pool.NTPServers)

	var gatewayStr interface{}
	if pool.Gateway != nil {
		gatewayStr = pool.Gateway.String()
	}

	err = r.db.QueryRow(ctx, query,
		pool.Name,
		pool.Description,
		pool.SubnetCIDR,
		gatewayStr,
		dnsArray,
		pool.DomainName,
		ntpArray,
		int(pool.DefaultLeaseTime.Seconds()),
		int(pool.MinLeaseTime.Seconds()),
		int(pool.MaxLeaseTime.Seconds()),
		pool.VLANID,
		pool.Enabled,
	).Scan(&pool.ID, &pool.CreatedAt, &pool.UpdatedAt)

	if err != nil {
		if IsConstraintViolation(err) {
			return ErrPoolNameExists
		}
		return fmt.Errorf("failed to create pool: %w", err)
	}

	return nil
}

// GetPoolByID retrieves a pool by ID.
func (r *PoolRepository) GetPoolByID(ctx context.Context, id int64) (*DBPool, error) {
	ctx, cancel := context.WithTimeout(ctx, r.timeout)
	defer cancel()

	query := `
		SELECT id, name, description, subnet_cidr, gateway,
			   dns_servers, domain_name, ntp_servers,
			   default_lease_time, min_lease_time, max_lease_time,
			   vlan_id, enabled, created_at, updated_at
		FROM dhcp_pools
		WHERE id = $1
	`

	return r.scanPool(r.db.QueryRow(ctx, query, id))
}

// GetPoolByName retrieves a pool by name.
func (r *PoolRepository) GetPoolByName(ctx context.Context, name string) (*DBPool, error) {
	ctx, cancel := context.WithTimeout(ctx, r.timeout)
	defer cancel()

	query := `
		SELECT id, name, description, subnet_cidr, gateway,
			   dns_servers, domain_name, ntp_servers,
			   default_lease_time, min_lease_time, max_lease_time,
			   vlan_id, enabled, created_at, updated_at
		FROM dhcp_pools
		WHERE name = $1
	`

	return r.scanPool(r.db.QueryRow(ctx, query, name))
}

// ListPools retrieves all enabled pools.
func (r *PoolRepository) ListPools(ctx context.Context) ([]*DBPool, error) {
	ctx, cancel := context.WithTimeout(ctx, r.timeout)
	defer cancel()

	query := `
		SELECT id, name, description, subnet_cidr, gateway,
			   dns_servers, domain_name, ntp_servers,
			   default_lease_time, min_lease_time, max_lease_time,
			   vlan_id, enabled, created_at, updated_at
		FROM dhcp_pools
		WHERE enabled = TRUE
		ORDER BY name ASC
	`

	return r.queryPools(ctx, query)
}

// ListAllPools retrieves all pools including disabled.
func (r *PoolRepository) ListAllPools(ctx context.Context) ([]*DBPool, error) {
	ctx, cancel := context.WithTimeout(ctx, r.timeout)
	defer cancel()

	query := `
		SELECT id, name, description, subnet_cidr, gateway,
			   dns_servers, domain_name, ntp_servers,
			   default_lease_time, min_lease_time, max_lease_time,
			   vlan_id, enabled, created_at, updated_at
		FROM dhcp_pools
		ORDER BY name ASC
	`

	return r.queryPools(ctx, query)
}

// UpdatePool updates an existing pool.
func (r *PoolRepository) UpdatePool(ctx context.Context, pool *DBPool) error {
	ctx, cancel := context.WithTimeout(ctx, r.timeout)
	defer cancel()

	// Validate configuration
	if err := r.ValidatePoolConfig(pool); err != nil {
		return err
	}

	// Check for overlap (exclude self)
	overlap, err := r.CheckPoolOverlap(ctx, pool.RangeStart, pool.RangeEnd, pool.ID)
	if err != nil {
		return err
	}
	if overlap {
		return ErrPoolOverlap
	}

	query := `
		UPDATE dhcp_pools
		SET name = $2,
			description = $3,
			subnet_cidr = $4,
			gateway = $5,
			dns_servers = $6,
			domain_name = $7,
			ntp_servers = $8,
			default_lease_time = $9,
			min_lease_time = $10,
			max_lease_time = $11,
			vlan_id = $12,
			enabled = $13,
			updated_at = NOW()
		WHERE id = $1
	`

	dnsArray := ipListToStringArray(pool.DNSServers)
	ntpArray := ipListToStringArray(pool.NTPServers)

	var gatewayStr interface{}
	if pool.Gateway != nil {
		gatewayStr = pool.Gateway.String()
	}

	result, err := r.db.Exec(ctx, query,
		pool.ID,
		pool.Name,
		pool.Description,
		pool.SubnetCIDR,
		gatewayStr,
		dnsArray,
		pool.DomainName,
		ntpArray,
		int(pool.DefaultLeaseTime.Seconds()),
		int(pool.MinLeaseTime.Seconds()),
		int(pool.MaxLeaseTime.Seconds()),
		pool.VLANID,
		pool.Enabled,
	)
	if err != nil {
		return fmt.Errorf("failed to update pool: %w", err)
	}

	rows, _ := result.RowsAffected()
	if rows == 0 {
		return ErrPoolNotFound
	}

	return nil
}

// DeletePool deletes a pool if no active leases exist.
func (r *PoolRepository) DeletePool(ctx context.Context, id int64) error {
	ctx, cancel := context.WithTimeout(ctx, r.timeout)
	defer cancel()

	// Check for active leases
	var leaseCount int
	err := r.db.QueryRow(ctx, `
		SELECT COUNT(*) FROM dhcp_leases
		WHERE pool_id = $1 AND state = 'ACTIVE'
	`, id).Scan(&leaseCount)
	if err != nil {
		return err
	}

	if leaseCount > 0 {
		return ErrPoolHasActiveLeases
	}

	query := `DELETE FROM dhcp_pools WHERE id = $1`
	result, err := r.db.Exec(ctx, query, id)
	if err != nil {
		return fmt.Errorf("failed to delete pool: %w", err)
	}

	rows, _ := result.RowsAffected()
	if rows == 0 {
		return ErrPoolNotFound
	}

	return nil
}

// EnablePool enables a pool.
func (r *PoolRepository) EnablePool(ctx context.Context, id int64) error {
	return r.setPoolEnabled(ctx, id, true)
}

// DisablePool disables a pool.
func (r *PoolRepository) DisablePool(ctx context.Context, id int64) error {
	return r.setPoolEnabled(ctx, id, false)
}

func (r *PoolRepository) setPoolEnabled(ctx context.Context, id int64, enabled bool) error {
	ctx, cancel := context.WithTimeout(ctx, r.timeout)
	defer cancel()

	query := `UPDATE dhcp_pools SET enabled = $2, updated_at = NOW() WHERE id = $1`
	result, err := r.db.Exec(ctx, query, id, enabled)
	if err != nil {
		return err
	}

	rows, _ := result.RowsAffected()
	if rows == 0 {
		return ErrPoolNotFound
	}

	return nil
}

// ============================================================================
// Validation Methods
// ============================================================================

// ValidatePoolConfig validates pool configuration.
func (r *PoolRepository) ValidatePoolConfig(pool *DBPool) error {
	if pool.Name == "" {
		return errors.New("pool name is required")
	}

	if pool.SubnetCIDR == "" {
		return errors.New("subnet CIDR is required")
	}

	// Validate CIDR
	_, subnet, err := net.ParseCIDR(pool.SubnetCIDR)
	if err != nil {
		return ErrInvalidSubnetCIDR
	}

	// Validate range within subnet
	if pool.RangeStart != nil && !subnet.Contains(pool.RangeStart) {
		return ErrRangeOutsideSubnet
	}
	if pool.RangeEnd != nil && !subnet.Contains(pool.RangeEnd) {
		return ErrRangeOutsideSubnet
	}

	// Validate range order
	if pool.RangeStart != nil && pool.RangeEnd != nil {
		if ipToUint32(pool.RangeStart) >= ipToUint32(pool.RangeEnd) {
			return ErrInvalidIPRange
		}
	}

	// Validate gateway
	if pool.Gateway != nil {
		if !subnet.Contains(pool.Gateway) {
			return errors.New("gateway must be within subnet")
		}
	}

	// Validate lease times
	if pool.DefaultLeaseTime < time.Hour {
		return errors.New("default lease time must be at least 1 hour")
	}
	if pool.MaxLeaseTime > 365*24*time.Hour {
		return errors.New("max lease time cannot exceed 365 days")
	}

	return nil
}

// CheckPoolOverlap checks if a range overlaps with existing pools.
func (r *PoolRepository) CheckPoolOverlap(ctx context.Context, start, end net.IP, excludeID int64) (bool, error) {
	if start == nil || end == nil {
		return false, nil
	}

	// Get all enabled pools
	pools, err := r.ListAllPools(ctx)
	if err != nil {
		return false, err
	}

	startVal := ipToUint32(start)
	endVal := ipToUint32(end)

	for _, pool := range pools {
		if pool.ID == excludeID {
			continue
		}
		if pool.RangeStart == nil || pool.RangeEnd == nil {
			continue
		}

		pStart := ipToUint32(pool.RangeStart)
		pEnd := ipToUint32(pool.RangeEnd)

		// Check overlap: ranges overlap if start1 <= end2 AND start2 <= end1
		if startVal <= pEnd && pStart <= endVal {
			return true, nil
		}
	}

	return false, nil
}

// ============================================================================
// Statistics Methods
// ============================================================================

// GetPoolStats returns utilization statistics for a pool.
func (r *PoolRepository) GetPoolStats(ctx context.Context, poolID int64) (*PoolStats, error) {
	ctx, cancel := context.WithTimeout(ctx, r.timeout)
	defer cancel()

	pool, err := r.GetPoolByID(ctx, poolID)
	if err != nil {
		return nil, err
	}
	if pool == nil {
		return nil, ErrPoolNotFound
	}

	// Calculate total IPs
	totalIPs := 0
	if pool.RangeStart != nil && pool.RangeEnd != nil {
		totalIPs = int(ipToUint32(pool.RangeEnd) - ipToUint32(pool.RangeStart) + 1)
	}

	// Count active leases
	var activeLeases int
	err = r.db.QueryRow(ctx, `
		SELECT COUNT(*) FROM dhcp_leases
		WHERE pool_id = $1 AND state = 'ACTIVE'
	`, poolID).Scan(&activeLeases)
	if err != nil {
		return nil, err
	}

	// Count reserved IPs
	var reservedIPs int
	err = r.db.QueryRow(ctx, `
		SELECT COUNT(*) FROM dhcp_reservations
		WHERE pool_id = $1 AND enabled = TRUE
	`, poolID).Scan(&reservedIPs)
	if err != nil {
		return nil, err
	}

	stats := &PoolStats{
		PoolID:       poolID,
		TotalIPs:     totalIPs,
		ActiveLeases: activeLeases,
		ReservedIPs:  reservedIPs,
	}

	if totalIPs > 0 {
		stats.AvailableIPs = totalIPs - activeLeases - reservedIPs
		stats.Utilization = float64(activeLeases) / float64(totalIPs) * 100
	}

	return stats, nil
}

// ============================================================================
// Helper Functions
// ============================================================================

func (r *PoolRepository) scanPool(row *sql.Row) (*DBPool, error) {
	if row == nil {
		return nil, ErrNotConnected
	}

	var pool DBPool
	var gateway sql.NullString
	var dnsServers, ntpServers []string
	var defaultLease, minLease, maxLease int

	err := row.Scan(
		&pool.ID,
		&pool.Name,
		&pool.Description,
		&pool.SubnetCIDR,
		&gateway,
		&dnsServers,
		&pool.DomainName,
		&ntpServers,
		&defaultLease,
		&minLease,
		&maxLease,
		&pool.VLANID,
		&pool.Enabled,
		&pool.CreatedAt,
		&pool.UpdatedAt,
	)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, nil
		}
		return nil, err
	}

	if gateway.Valid {
		pool.Gateway = net.ParseIP(gateway.String)
	}
	pool.DNSServers = stringArrayToIPList(dnsServers)
	pool.NTPServers = stringArrayToIPList(ntpServers)
	pool.DefaultLeaseTime = time.Duration(defaultLease) * time.Second
	pool.MinLeaseTime = time.Duration(minLease) * time.Second
	pool.MaxLeaseTime = time.Duration(maxLease) * time.Second

	return &pool, nil
}

func (r *PoolRepository) queryPools(ctx context.Context, query string, args ...interface{}) ([]*DBPool, error) {
	rows, err := r.db.Query(ctx, query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	pools := make([]*DBPool, 0)
	for rows.Next() {
		var pool DBPool
		var gateway sql.NullString
		var dnsServers, ntpServers []string
		var defaultLease, minLease, maxLease int

		err := rows.Scan(
			&pool.ID,
			&pool.Name,
			&pool.Description,
			&pool.SubnetCIDR,
			&gateway,
			&dnsServers,
			&pool.DomainName,
			&ntpServers,
			&defaultLease,
			&minLease,
			&maxLease,
			&pool.VLANID,
			&pool.Enabled,
			&pool.CreatedAt,
			&pool.UpdatedAt,
		)
		if err != nil {
			return nil, err
		}

		if gateway.Valid {
			pool.Gateway = net.ParseIP(gateway.String)
		}
		pool.DNSServers = stringArrayToIPList(dnsServers)
		pool.NTPServers = stringArrayToIPList(ntpServers)
		pool.DefaultLeaseTime = time.Duration(defaultLease) * time.Second
		pool.MinLeaseTime = time.Duration(minLease) * time.Second
		pool.MaxLeaseTime = time.Duration(maxLease) * time.Second

		pools = append(pools, &pool)
	}

	return pools, nil
}

func ipToUint32(ip net.IP) uint32 {
	ip4 := ip.To4()
	if ip4 == nil {
		return 0
	}
	return binary.BigEndian.Uint32(ip4)
}

func ipListToStringArray(ips []net.IP) []string {
	if ips == nil {
		return nil
	}
	result := make([]string, len(ips))
	for i, ip := range ips {
		result[i] = ip.String()
	}
	return result
}

func stringArrayToIPList(strs []string) []net.IP {
	if strs == nil {
		return nil
	}
	result := make([]net.IP, 0, len(strs))
	for _, s := range strs {
		if ip := net.ParseIP(s); ip != nil {
			result = append(result, ip)
		}
	}
	return result
}

// ============================================================================
// Errors
// ============================================================================

var (
	// ErrPoolNotFound is returned when pool doesn't exist
	ErrPoolNotFound = errors.New("pool not found")

	// ErrPoolNameExists is returned for duplicate pool name
	ErrPoolNameExists = errors.New("pool name already exists")

	// ErrPoolOverlap is returned when ranges overlap
	ErrPoolOverlap = errors.New("pool range overlaps with existing pool")

	// ErrPoolHasActiveLeases is returned when deleting pool with leases
	ErrPoolHasActiveLeases = errors.New("pool has active leases")

	// ErrInvalidSubnetCIDR is returned for bad CIDR notation
	ErrInvalidSubnetCIDR = errors.New("invalid subnet CIDR notation")

	// ErrRangeOutsideSubnet is returned when range is not in subnet
	ErrRangeOutsideSubnet = errors.New("range is outside subnet boundaries")

	// ErrInvalidIPRange is returned when start >= end
	ErrInvalidIPRange = errors.New("invalid IP range: start must be less than end")
)
