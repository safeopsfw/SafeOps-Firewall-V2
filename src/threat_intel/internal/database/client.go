// Package database provides PostgreSQL database client for threat intelligence
package database

import (
	"context"

	"github.com/safeops/shared/go/postgres"
	"github.com/safeops/threat-intel/internal/config"
)

// Client wraps the PostgreSQL client with threat-specific functionality
type Client struct {
	*postgres.Client
}

// NewClient creates a new database client from configuration
func NewClient(cfg config.DatabaseConfig) (*Client, error) {
	pgConfig := postgres.Config{
		Host:     cfg.Host,
		Port:     cfg.Port,
		Database: cfg.Database,
		User:     cfg.User,
		Password: cfg.Password,
		SSLMode:  cfg.SSLMode,
	}

	pgClient, err := postgres.NewClient(pgConfig)
	if err != nil {
		return nil, err
	}

	return &Client{
		Client: pgClient,
	}, nil
}

// HealthCheck verifies database connectivity
func (c *Client) HealthCheck(ctx context.Context) error {
	return c.Client.HealthCheck(ctx)
}
