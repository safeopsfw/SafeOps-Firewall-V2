package postgres

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ============================================================================
// Transaction Utility Tests
// ============================================================================

func TestTransactionAge(t *testing.T) {
	t.Skip("Integration test - requires PostgreSQL instance")

	client, err := NewClient(Config{
		Host:     "localhost",
		Port:     5432,
		Database: "postgres",
		User:     "postgres",
		Password: "postgres",
		SSLMode:  "disable",
	})
	require.NoError(t, err)
	defer client.Close()

	ctx := context.Background()

	tx, err := client.BeginTx(ctx)
	require.NoError(t, err)
	defer tx.Rollback(ctx)

	// Wait a bit
	time.Sleep(100 * time.Millisecond)

	age := tx.Age()
	assert.Greater(t, age, 100*time.Millisecond)
	assert.Less(t, age, 200*time.Millisecond)
}

func TestTransactionStartTime(t *testing.T) {
	t.Skip("Integration test - requires PostgreSQL instance")

	client, err := NewClient(Config{
		Host:     "localhost",
		Port:     5432,
		Database: "postgres",
		User:     "postgres",
		Password: "postgres",
		SSLMode:  "disable",
	})
	require.NoError(t, err)
	defer client.Close()

	ctx := context.Background()

	before := time.Now()
	tx, err := client.BeginTx(ctx)
	require.NoError(t, err)
	defer tx.Rollback(ctx)
	after := time.Now()

	startTime := tx.StartTime()
	assert.True(t, startTime.After(before) || startTime.Equal(before))
	assert.True(t, startTime.Before(after) || startTime.Equal(after))
}

// ============================================================================
// BeginFunc Pattern Tests
// ============================================================================

func TestBeginFunc_Success(t *testing.T) {
	t.Skip("Integration test - requires PostgreSQL instance")

	client, err := NewClient(Config{
		Host:     "localhost",
		Port:     5432,
		Database: "postgres",
		User:     "postgres",
		Password: "postgres",
		SSLMode:  "disable",
	})
	require.NoError(t, err)
	defer client.Close()

	ctx := context.Background()

	// Create test table
	client.Exec(ctx, "CREATE TEMP TABLE test_users (id SERIAL PRIMARY KEY, name TEXT)")

	// Test BeginFunc with automatic commit
	err = client.BeginFunc(ctx, func(tx *Tx) error {
		_, err := tx.Exec(ctx, "INSERT INTO test_users (name) VALUES ($1)", "Alice")
		return err
	})
	require.NoError(t, err)

	// Verify data was committed
	var count int
	client.QueryRow(ctx, "SELECT COUNT(*) FROM test_users").Scan(&count)
	assert.Equal(t, 1, count)
}

func TestBeginFunc_Rollback(t *testing.T) {
	t.Skip("Integration test - requires PostgreSQL instance")

	client, err := NewClient(Config{
		Host:     "localhost",
		Port:     5432,
		Database: "postgres",
		User:     "postgres",
		Password: "postgres",
		SSLMode:  "disable",
	})
	require.NoError(t, err)
	defer client.Close()

	ctx := context.Background()

	// Create test table
	client.Exec(ctx, "CREATE TEMP TABLE test_users (id SERIAL PRIMARY KEY, name TEXT)")

	// Test BeginFunc with automatic rollback on error
	err = client.BeginFunc(ctx, func(tx *Tx) error {
		tx.Exec(ctx, "INSERT INTO test_users (name) VALUES ($1)", "Bob")
		return assert.AnError // Force error to trigger rollback
	})
	assert.Error(t, err)

	// Verify data was rolled back
	var count int
	client.QueryRow(ctx, "SELECT COUNT(*) FROM test_users").Scan(&count)
	assert.Equal(t, 0, count)
}

// ============================================================================
// Isolation Level Tests
// ============================================================================

func TestReadOnlyTransaction(t *testing.T) {
	t.Skip("Integration test - requires PostgreSQL instance")

	client, err := NewClient(Config{
		Host:     "localhost",
		Port:     5432,
		Database: "postgres",
		User:     "postgres",
		Password: "postgres",
		SSLMode:  "disable",
	})
	require.NoError(t, err)
	defer client.Close()

	ctx := context.Background()

	tx, err := client.ReadOnly(ctx)
	require.NoError(t, err)
	defer tx.Rollback(ctx)

	// Should be able to read
	var result int
	err = tx.QueryRow(ctx, "SELECT 1").Scan(&result)
	assert.NoError(t, err)
	assert.Equal(t, 1, result)

	tx.Rollback(ctx)
}

func TestSerializableTransaction(t *testing.T) {
	t.Skip("Integration test - requires PostgreSQL instance")

	client, err := NewClient(Config{
		Host:     "localhost",
		Port:     5432,
		Database: "postgres",
		User:     "postgres",
		Password: "postgres",
		SSLMode:  "disable",
	})
	require.NoError(t, err)
	defer client.Close()

	ctx := context.Background()

	tx, err := client.Serializable(ctx)
	require.NoError(t, err)
	defer tx.Rollback(ctx)

	assert.NotNil(t, tx)
	tx.Rollback(ctx)
}

// ============================================================================
// Savepoint Tests
// ============================================================================

func TestSavepoints(t *testing.T) {
	t.Skip("Integration test - requires PostgreSQL instance")

	client, err := NewClient(Config{
		Host:     "localhost",
		Port:     5432,
		Database: "postgres",
		User:     "postgres",
		Password: "postgres",
		SSLMode:  "disable",
	})
	require.NoError(t, err)
	defer client.Close()

	ctx := context.Background()

	// Create test table
	client.Exec(ctx, "CREATE TEMP TABLE test_savepoints (id SERIAL PRIMARY KEY, value INT)")

	tx, err := client.BeginTx(ctx)
	require.NoError(t, err)
	defer tx.Rollback(ctx)

	// Insert first value
	tx.Exec(ctx, "INSERT INTO test_savepoints (value) VALUES (1)")

	// Create savepoint
	err = tx.Savepoint(ctx, "sp1")
	require.NoError(t, err)
	assert.Equal(t, 1, tx.SavepointCount())

	// Insert second value
	tx.Exec(ctx, "INSERT INTO test_savepoints (value) VALUES (2)")

	// Rollback to savepoint
	err = tx.RollbackTo(ctx, "sp1")
	require.NoError(t, err)

	// Commit transaction
	err = tx.Commit(ctx)
	require.NoError(t, err)

	// Should only have first value
	var count int
	client.QueryRow(ctx, "SELECT COUNT(*) FROM test_savepoints WHERE value = 1").Scan(&count)
	assert.Equal(t, 1, count)

	client.QueryRow(ctx, "SELECT COUNT(*) FROM test_savepoints WHERE value = 2").Scan(&count)
	assert.Equal(t, 0, count)
}

func TestWithSavepoint_Success(t *testing.T) {
	t.Skip("Integration test - requires PostgreSQL instance")

	client, err := NewClient(Config{
		Host:     "localhost",
		Port:     5432,
		Database: "postgres",
		User:     "postgres",
		Password: "postgres",
		SSLMode:  "disable",
	})
	require.NoError(t, err)
	defer client.Close()

	ctx := context.Background()

	client.Exec(ctx, "CREATE TEMP TABLE test_sp (id SERIAL PRIMARY KEY, value INT)")

	tx, err := client.BeginTx(ctx)
	require.NoError(t, err)
	defer tx.Rollback(ctx)

	// Use WithSavepoint
	err = tx.WithSavepoint(ctx, "sp1", func() error {
		_, err := tx.Exec(ctx, "INSERT INTO test_sp (value) VALUES (1)")
		return err
	})
	require.NoError(t, err)

	tx.Commit(ctx)

	var count int
	client.QueryRow(ctx, "SELECT COUNT(*) FROM test_sp").Scan(&count)
	assert.Equal(t, 1, count)
}

func TestWithSavepoint_Rollback(t *testing.T) {
	t.Skip("Integration test - requires PostgreSQL instance")

	client, err := NewClient(Config{
		Host:     "localhost",
		Port:     5432,
		Database: "postgres",
		User:     "postgres",
		Password: "postgres",
		SSLMode:  "disable",
	})
	require.NoError(t, err)
	defer client.Close()

	ctx := context.Background()

	client.Exec(ctx, "CREATE TEMP TABLE test_sp (id SERIAL PRIMARY KEY, value INT)")

	tx, err := client.BeginTx(ctx)
	require.NoError(t, err)
	defer tx.Rollback(ctx)

	// Insert before savepoint
	tx.Exec(ctx, "INSERT INTO test_sp (value) VALUES (1)")

	// Use WithSavepoint that fails
	err = tx.WithSavepoint(ctx, "sp1", func() error {
		tx.Exec(ctx, "INSERT INTO test_sp (value) VALUES (2)")
		return assert.AnError // Force error
	})
	assert.Error(t, err)

	tx.Commit(ctx)

	// Should only have first insert
	var count int
	client.QueryRow(ctx, "SELECT COUNT(*) FROM test_sp").Scan(&count)
	assert.Equal(t, 1, count)
}

// ============================================================================
// WithTx Tests
// ============================================================================

func TestWithTx_Success(t *testing.T) {
	t.Skip("Integration test - requires PostgreSQL instance")

	client, err := NewClient(Config{
		Host:     "localhost",
		Port:     5432,
		Database: "postgres",
		User:     "postgres",
		Password: "postgres",
		SSLMode:  "disable",
	})
	require.NoError(t, err)
	defer client.Close()

	ctx := context.Background()

	result, err := WithTx(ctx, client, func(tx *Tx) (int, error) {
		var one int
		tx.QueryRow(ctx, "SELECT 1").Scan(&one)
		return one * 2, nil
	})

	require.NoError(t, err)
	assert.Equal(t, 2, result)
}

func TestWithTx_Rollback(t *testing.T) {
	t.Skip("Integration test - requires PostgreSQL instance")

	client, err := NewClient(Config{
		Host:     "localhost",
		Port:     5432,
		Database: "postgres",
		User:     "postgres",
		Password: "postgres",
		SSLMode:  "disable",
	})
	require.NoError(t, err)
	defer client.Close()

	ctx := context.Background()

	client.Exec(ctx, "CREATE TEMP TABLE test_withtx (id INT)")

	_, err = WithTx(ctx, client, func(tx *Tx) (int, error) {
		tx.Exec(ctx, "INSERT INTO test_withtx VALUES (1)")
		return 0, assert.AnError // Force rollback
	})

	assert.Error(t, err)

	// Verify rollback
	var count int
	client.QueryRow(ctx, "SELECT COUNT(*) FROM test_withtx").Scan(&count)
	assert.Equal(t, 0, count)
}

// ============================================================================
// Retry Logic Tests
// ============================================================================

func TestIsTransactionRetryable(t *testing.T) {
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
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := isTransactionRetryable(tt.err)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestWithRetry_Success(t *testing.T) {
	t.Skip("Integration test - requires PostgreSQL instance")

	client, err := NewClient(Config{
		Host:     "localhost",
		Port:     5432,
		Database: "postgres",
		User:     "postgres",
		Password: "postgres",
		SSLMode:  "disable",
	})
	require.NoError(t, err)
	defer client.Close()

	ctx := context.Background()

	result, err := WithRetry(ctx, client, 3, func(tx *Tx) (int, error) {
		var one int
		tx.QueryRow(ctx, "SELECT 1").Scan(&one)
		return one, nil
	})

	require.NoError(t, err)
	assert.Equal(t, 1, result)
}

func TestWithRetryVoid_Success(t *testing.T) {
	t.Skip("Integration test - requires PostgreSQL instance")

	client, err := NewClient(Config{
		Host:     "localhost",
		Port:     5432,
		Database: "postgres",
		User:     "postgres",
		Password: "postgres",
		SSLMode:  "disable",
	})
	require.NoError(t, err)
	defer client.Close()

	ctx := context.Background()

	err = WithRetryVoid(ctx, client, 3, func(tx *Tx) error {
		var one int
		return tx.QueryRow(ctx, "SELECT 1").Scan(&one)
	})

	require.NoError(t, err)
}

// ============================================================================
// Context Timeout Tests
// ============================================================================

func TestTransactionTimeout(t *testing.T) {
	t.Skip("Integration test - requires PostgreSQL instance")

	client, err := NewClient(Config{
		Host:     "localhost",
		Port:     5432,
		Database: "postgres",
		User:     "postgres",
		Password: "postgres",
		SSLMode:  "disable",
	})
	require.NoError(t, err)
	defer client.Close()

	// Create context with short timeout
	ctx, cancel := context.WithTimeout(context.Background(), 1*time.Millisecond)
	defer cancel()

	// Wait for context to expire
	time.Sleep(5 * time.Millisecond)

	err = client.BeginFunc(ctx, func(tx *Tx) error {
		_, err := tx.Exec(ctx, "SELECT pg_sleep(10)")
		return err
	})

	assert.Error(t, err)
}

// ============================================================================
// Panic Recovery Tests
// ============================================================================

func TestPanicRecovery(t *testing.T) {
	t.Skip("Integration test - requires PostgreSQL instance")

	client, err := NewClient(Config{
		Host:     "localhost",
		Port:     5432,
		Database: "postgres",
		User:     "postgres",
		Password: "postgres",
		SSLMode:  "disable",
	})
	require.NoError(t, err)
	defer client.Close()

	ctx := context.Background()

	client.Exec(ctx, "CREATE TEMP TABLE test_panic (id INT)")

	// Test panic recovery with automatic rollback
	assert.Panics(t, func() {
		client.BeginFunc(ctx, func(tx *Tx) error {
			tx.Exec(ctx, "INSERT INTO test_panic VALUES (1)")
			panic("test panic")
		})
	})

	// Verify rollback occurred
	var count int
	client.QueryRow(ctx, "SELECT COUNT(*) FROM test_panic").Scan(&count)
	assert.Equal(t, 0, count)
}
