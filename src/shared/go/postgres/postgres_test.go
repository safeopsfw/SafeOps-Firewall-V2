package postgres

import (
	"context"
	"os"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ============================================================================
// Configuration Tests
// ============================================================================

func TestDefaultConfig(t *testing.T) {
	cfg := DefaultConfig()

	assert.Equal(t, "localhost", cfg.Host)
	assert.Equal(t, 5432, cfg.Port)
	assert.Equal(t, "safeops", cfg.Database)
	assert.Equal(t, "postgres", cfg.User)
	assert.Equal(t, "require", cfg.SSLMode)
	assert.Equal(t, int32(25), cfg.MaxOpenConns)
	assert.Equal(t, int32(5), cfg.MaxIdleConns)
	assert.Equal(t, time.Hour, cfg.MaxConnLifetime)
	assert.Equal(t, 15*time.Minute, cfg.MaxConnIdleTime)
	assert.Equal(t, 10*time.Second, cfg.ConnectTimeout)
	assert.Equal(t, 30*time.Second, cfg.StatementTimeout)
}

func TestConfigDSN(t *testing.T) {
	cfg := Config{
		Host:             "localhost",
		Port:             5432,
		Database:         "testdb",
		User:             "testuser",
		Password:         "testpass",
		SSLMode:          "require",
		ConnectTimeout:   5 * time.Second,
		StatementTimeout: 10 * time.Second,
	}

	dsn := cfg.DSN()

	assert.Contains(t, dsn, "host=localhost")
	assert.Contains(t, dsn, "port=5432")
	assert.Contains(t, dsn, "user=testuser")
	assert.Contains(t, dsn, "password=testpass")
	assert.Contains(t, dsn, "dbname=testdb")
	assert.Contains(t, dsn, "sslmode=require")
	assert.Contains(t, dsn, "connect_timeout=5")
	assert.Contains(t, dsn, "statement_timeout=10000")
}

func TestConfigDSN_WithSSLCerts(t *testing.T) {
	cfg := Config{
		Host:        "localhost",
		Port:        5432,
		Database:    "testdb",
		User:        "testuser",
		Password:    "testpass",
		SSLMode:     "verify-full",
		SSLCert:     "/path/to/client.crt",
		SSLKey:      "/path/to/client.key",
		SSLRootCert: "/path/to/ca.crt",
	}

	dsn := cfg.DSN()

	assert.Contains(t, dsn, "sslmode=verify-full")
	assert.Contains(t, dsn, "sslcert=/path/to/client.crt")
	assert.Contains(t, dsn, "sslkey=/path/to/client.key")
	assert.Contains(t, dsn, "sslrootcert=/path/to/ca.crt")
}

func TestConfigSanitizeDSN(t *testing.T) {
	cfg := Config{
		Host:     "localhost",
		Port:     5432,
		Database: "testdb",
		User:     "testuser",
		Password: "supersecret",
		SSLMode:  "require",
	}

	sanitized := cfg.SanitizeDSN()

	assert.NotContains(t, sanitized, "supersecret")
	assert.Contains(t, sanitized, "password=***")
	assert.Contains(t, sanitized, "user=testuser")
}

func TestNewConfigFromEnv(t *testing.T) {
	// Set environment variables
	os.Setenv("POSTGRES_HOST", "dbserver")
	os.Setenv("POSTGRES_PORT", "5433")
	os.Setenv("POSTGRES_DATABASE", "mydb")
	os.Setenv("POSTGRES_USER", "myuser")
	os.Setenv("POSTGRES_PASSWORD", "mypass")
	os.Setenv("POSTGRES_SSLMODE", "verify-full")
	os.Setenv("POSTGRES_MAX_OPEN_CONNS", "50")
	os.Setenv("POSTGRES_MAX_IDLE_CONNS", "10")

	defer func() {
		os.Unsetenv("POSTGRES_HOST")
		os.Unsetenv("POSTGRES_PORT")
		os.Unsetenv("POSTGRES_DATABASE")
		os.Unsetenv("POSTGRES_USER")
		os.Unsetenv("POSTGRES_PASSWORD")
		os.Unsetenv("POSTGRES_SSLMODE")
		os.Unsetenv("POSTGRES_MAX_OPEN_CONNS")
		os.Unsetenv("POSTGRES_MAX_IDLE_CONNS")
	}()

	cfg, err := NewConfigFromEnv()
	require.NoError(t, err)

	assert.Equal(t, "dbserver", cfg.Host)
	assert.Equal(t, 5433, cfg.Port)
	assert.Equal(t, "mydb", cfg.Database)
	assert.Equal(t, "myuser", cfg.User)
	assert.Equal(t, "mypass", cfg.Password)
	assert.Equal(t, "verify-full", cfg.SSLMode)
	assert.Equal(t, int32(50), cfg.MaxOpenConns)
	assert.Equal(t, int32(10), cfg.MaxIdleConns)
}

func TestNewConfigFromEnv_Defaults(t *testing.T) {
	// Clear all env vars
	os.Unsetenv("POSTGRES_HOST")
	os.Unsetenv("POSTGRES_PORT")

	cfg, err := NewConfigFromEnv()
	require.NoError(t, err)

	// Should use defaults
	assert.Equal(t, "localhost", cfg.Host)
	assert.Equal(t, 5432, cfg.Port)
	assert.Equal(t, "safeops", cfg.Database)
}

// ============================================================================
// Error Classification Tests
// ============================================================================

func TestIsRetryable(t *testing.T) {
	tests := []struct {
		name     string
		err      error
		expected bool
	}{
		{
			name:     "nil error",
			err:      nil,
			expected: false,
		},
		{
			name:     "context canceled",
			err:      context.Canceled,
			expected: false,
		},
		{
			name:     "context deadline exceeded",
			err:      context.DeadlineExceeded,
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := IsRetryable(tt.err)
			assert.Equal(t, tt.expected, result)
		})
	}
}

// ============================================================================
// Integration Tests (Skipped without live database)
// ============================================================================

func TestClientCreation_Integration(t *testing.T) {
	t.Skip("Integration test - requires PostgreSQL instance")

	cfg := Config{
		Host:     "localhost",
		Port:     5432,
		Database: "postgres",
		User:     "postgres",
		Password: "postgres",
		SSLMode:  "disable",
	}

	client, err := NewClient(cfg)
	require.NoError(t, err)
	defer client.Close()

	assert.NotNil(t, client)
	assert.NotNil(t, client.pool)
}

func TestClientPing_Integration(t *testing.T) {
	t.Skip("Integration test - requires PostgreSQL instance")

	cfg := Config{
		Host:     "localhost",
		Port:     5432,
		Database: "postgres",
		User:     "postgres",
		Password: "postgres",
		SSLMode:  "disable",
	}

	client, err := NewClient(cfg)
	require.NoError(t, err)
	defer client.Close()

	ctx := context.Background()
	err = client.Ping(ctx)
	assert.NoError(t, err)
}

func TestClientHealthCheck_Integration(t *testing.T) {
	t.Skip("Integration test - requires PostgreSQL instance")

	cfg := Config{
		Host:     "localhost",
		Port:     5432,
		Database: "postgres",
		User:     "postgres",
		Password: "postgres",
		SSLMode:  "disable",
	}

	client, err := NewClient(cfg)
	require.NoError(t, err)
	defer client.Close()

	ctx := context.Background()
	err = client.HealthCheck(ctx)
	assert.NoError(t, err)
}

func TestClientQuery_Integration(t *testing.T) {
	t.Skip("Integration test - requires PostgreSQL instance")

	cfg := Config{
		Host:     "localhost",
		Port:     5432,
		Database: "postgres",
		User:     "postgres",
		Password: "postgres",
		SSLMode:  "disable",
	}

	client, err := NewClient(cfg)
	require.NoError(t, err)
	defer client.Close()

	ctx := context.Background()

	// Test simple query
	rows, err := client.Query(ctx, "SELECT 1 as num")
	require.NoError(t, err)
	defer rows.Close()

	assert.True(t, rows.Next())

	var num int
	err = rows.Scan(&num)
	require.NoError(t, err)
	assert.Equal(t, 1, num)
}

func TestClientQueryRow_Integration(t *testing.T) {
	t.Skip("Integration test - requires PostgreSQL instance")

	cfg := Config{
		Host:     "localhost",
		Port:     5432,
		Database: "postgres",
		User:     "postgres",
		Password: "postgres",
		SSLMode:  "disable",
	}

	client, err := NewClient(cfg)
	require.NoError(t, err)
	defer client.Close()

	ctx := context.Background()

	var version string
	row := client.QueryRow(ctx, "SELECT version()")
	err = row.Scan(&version)
	require.NoError(t, err)
	assert.NotEmpty(t, version)
	assert.Contains(t, version, "PostgreSQL")
}

func TestClientExec_Integration(t *testing.T) {
	t.Skip("Integration test - requires PostgreSQL instance")

	cfg := Config{
		Host:     "localhost",
		Port:     5432,
		Database: "postgres",
		User:     "postgres",
		Password: "postgres",
		SSLMode:  "disable",
	}

	client, err := NewClient(cfg)
	require.NoError(t, err)
	defer client.Close()

	ctx := context.Background()

	// Create test table
	_, err = client.Exec(ctx, `
		CREATE TEMP TABLE test_table (
			id SERIAL PRIMARY KEY,
			name TEXT NOT NULL
		)
	`)
	require.NoError(t, err)

	// Insert data
	tag, err := client.Exec(ctx, "INSERT INTO test_table (name) VALUES ($1), ($2)", "Alice", "Bob")
	require.NoError(t, err)
	assert.Equal(t, int64(2), tag.RowsAffected())

	// Query data
	rows, err := client.Query(ctx, "SELECT name FROM test_table ORDER BY id")
	require.NoError(t, err)
	defer rows.Close()

	names := []string{}
	for rows.Next() {
		var name string
		err := rows.Scan(&name)
		require.NoError(t, err)
		names = append(names, name)
	}

	assert.Equal(t, []string{"Alice", "Bob"}, names)
}

func TestClientPoolStats_Integration(t *testing.T) {
	t.Skip("Integration test - requires PostgreSQL instance")

	cfg := Config{
		Host:     "localhost",
		Port:     5432,
		Database: "postgres",
		User:     "postgres",
		Password: "postgres",
		SSLMode:  "disable",
	}

	client, err := NewClient(cfg)
	require.NoError(t, err)
	defer client.Close()

	stats := client.Stats()
	assert.NotNil(t, stats)
	assert.GreaterOrEqual(t, stats.MaxConns(), int32(0))
	assert.GreaterOrEqual(t, stats.TotalConns(), int32(0))
}

func TestClientUtilityMethods_Integration(t *testing.T) {
	t.Skip("Integration test - requires PostgreSQL instance")

	cfg := Config{
		Host:     "localhost",
		Port:     5432,
		Database: "postgres",
		User:     "postgres",
		Password: "postgres",
		SSLMode:  "disable",
	}

	client, err := NewClient(cfg)
	require.NoError(t, err)
	defer client.Close()

	ctx := context.Background()

	// Test CurrentDatabase
	dbName, err := client.CurrentDatabase(ctx)
	require.NoError(t, err)
	assert.Equal(t, "postgres", dbName)

	// Test ServerVersion
	version, err := client.ServerVersion(ctx)
	require.NoError(t, err)
	assert.NotEmpty(t, version)
	assert.Contains(t, version, "PostgreSQL")

	// Test TableExists (should not exist)
	exists, err := client.TableExists(ctx, "nonexistent_table")
	require.NoError(t, err)
	assert.False(t, exists)
}

func TestContextTimeout_Integration(t *testing.T) {
	t.Skip("Integration test - requires PostgreSQL instance")

	cfg := Config{
		Host:     "localhost",
		Port:     5432,
		Database: "postgres",
		User:     "postgres",
		Password: "postgres",
		SSLMode:  "disable",
	}

	client, err := NewClient(cfg)
	require.NoError(t, err)
	defer client.Close()

	// Create context with very short timeout
	ctx, cancel := context.WithTimeout(context.Background(), 1*time.Millisecond)
	defer cancel()

	// Wait for context to expire
	time.Sleep(5 * time.Millisecond)

	// This should fail due to timeout
	_, err = client.Query(ctx, "SELECT pg_sleep(10)")
	assert.Error(t, err)
}

// ============================================================================
// Benchmarks
// ============================================================================

func BenchmarkConfigDSN(b *testing.B) {
	cfg := DefaultConfig()
	cfg.Password = "testpassword"

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = cfg.DSN()
	}
}

func BenchmarkSanitizeDSN(b *testing.B) {
	cfg := DefaultConfig()
	cfg.Password = "supersecretpassword"

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = cfg.SanitizeDSN()
	}
}
