// Package database provides PostgreSQL connection management
package database

import (
	"context"
	"database/sql"
	"fmt"
	"log"
	"time"

	_ "github.com/lib/pq" // PostgreSQL driver
)

// DatabaseConfig holds PostgreSQL connection configuration
type DatabaseConfig struct {
	Host              string        `yaml:"host"`
	Port              int           `yaml:"port"`
	Name              string        `yaml:"name"`
	User              string        `yaml:"user"`
	Password          string        `yaml:"password"`
	SSLMode           string        `yaml:"sslmode"`
	MinConnections    int           `yaml:"min_connections"`
	MaxConnections    int           `yaml:"max_connections"`
	ConnectionTimeout time.Duration `yaml:"connection_timeout"`
	IdleTimeout       time.Duration `yaml:"idle_timeout"`
	MaxLifetime       time.Duration `yaml:"max_lifetime"`
}

// DatabaseClient wraps the SQL connection pool with configuration
type DatabaseClient struct {
	DB        *sql.DB
	Config    *DatabaseConfig
	Connected bool
}

// NewDatabaseClient creates a new PostgreSQL connection pool
func NewDatabaseClient(cfg *DatabaseConfig) (*DatabaseClient, error) {
	connStr := buildConnectionString(cfg)

	db, err := sql.Open("postgres", connStr)
	if err != nil {
		return nil, fmt.Errorf("failed to open database: %w", err)
	}

	// Configure connection pool
	db.SetMaxOpenConns(cfg.MaxConnections)
	db.SetMaxIdleConns(cfg.MinConnections)
	db.SetConnMaxLifetime(cfg.MaxLifetime)
	db.SetConnMaxIdleTime(cfg.IdleTimeout)

	client := &DatabaseClient{
		DB:        db,
		Config:    cfg,
		Connected: false,
	}

	// Validate connection
	ctx, cancel := context.WithTimeout(context.Background(), cfg.ConnectionTimeout)
	defer cancel()

	if err := client.Ping(ctx); err != nil {
		db.Close()
		return nil, fmt.Errorf("failed to connect to database: %w", err)
	}

	client.Connected = true
	log.Printf("[DATABASE] Connected to PostgreSQL %s:%d/%s", cfg.Host, cfg.Port, cfg.Name)

	return client, nil
}

// buildConnectionString constructs PostgreSQL DSN
func buildConnectionString(cfg *DatabaseConfig) string {
	return fmt.Sprintf(
		"host=%s port=%d dbname=%s user=%s password=%s sslmode=%s application_name=dhcp_monitor connect_timeout=10",
		cfg.Host, cfg.Port, cfg.Name, cfg.User, cfg.Password, cfg.SSLMode,
	)
}

// Ping validates database connectivity
func (c *DatabaseClient) Ping(ctx context.Context) error {
	return c.DB.PingContext(ctx)
}

// Close gracefully closes the connection pool
func (c *DatabaseClient) Close() error {
	if c.DB != nil {
		c.Connected = false
		log.Println("[DATABASE] Closing PostgreSQL connection pool")
		return c.DB.Close()
	}
	return nil
}

// BeginTx starts a new transaction with context
func (c *DatabaseClient) BeginTx(ctx context.Context, opts *sql.TxOptions) (*sql.Tx, error) {
	return c.DB.BeginTx(ctx, opts)
}

// ConnectWithRetry attempts connection with exponential backoff
func (c *DatabaseClient) ConnectWithRetry(maxRetries int, initialDelay time.Duration) error {
	delay := initialDelay

	for attempt := 1; attempt <= maxRetries; attempt++ {
		ctx, cancel := context.WithTimeout(context.Background(), c.Config.ConnectionTimeout)
		err := c.Ping(ctx)
		cancel()

		if err == nil {
			c.Connected = true
			return nil
		}

		log.Printf("[DATABASE] Connection attempt %d/%d failed: %v", attempt, maxRetries, err)

		if attempt < maxRetries {
			time.Sleep(delay)
			delay *= 2 // Exponential backoff
			if delay > 30*time.Second {
				delay = 30 * time.Second // Cap at 30 seconds
			}
		}
	}

	return fmt.Errorf("failed to connect after %d attempts", maxRetries)
}

// IsConnected returns current connection status
func (c *DatabaseClient) IsConnected() bool {
	if !c.Connected {
		return false
	}

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	return c.Ping(ctx) == nil
}

// GetStats returns connection pool statistics
func (c *DatabaseClient) GetStats() sql.DBStats {
	return c.DB.Stats()
}
