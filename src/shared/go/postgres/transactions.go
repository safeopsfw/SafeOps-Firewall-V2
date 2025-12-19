// Package postgres provides transaction management utilities.
package postgres

import (
	"context"
	"fmt"
	"time"

	goerrors "errors"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/safeops/shared/go/errors"
)

// ============================================================================
// Transaction Wrapper
// ============================================================================

// Tx wraps pgx.Tx with additional functionality for savepoints
type Tx struct {
	pgx.Tx
	savepoints []string
	startTime  time.Time
}

// ============================================================================
// Transaction Initialization
// ============================================================================

// BeginTx starts a new transaction with default settings
func (c *Client) BeginTx(ctx context.Context) (*Tx, error) {
	tx, err := c.pool.Begin(ctx)
	if err != nil {
		return nil, errors.Wrap(err, "POSTGRES_BEGIN_TX_FAILED", "Failed to begin transaction")
	}
	return &Tx{
		Tx:        tx,
		startTime: time.Now(),
	}, nil
}

// BeginTxWithOptions starts a transaction with custom options
func (c *Client) BeginTxWithOptions(ctx context.Context, opts pgx.TxOptions) (*Tx, error) {
	tx, err := c.pool.BeginTx(ctx, opts)
	if err != nil {
		return nil, errors.Wrap(err, "POSTGRES_BEGIN_TX_FAILED", "Failed to begin transaction with options")
	}
	return &Tx{
		Tx:        tx,
		startTime: time.Now(),
	}, nil
}

// ============================================================================
// Transaction Isolation Levels
// ============================================================================

// ReadOnly starts a read-only transaction
// Read-only transactions can be optimized by the database and may read from replicas
func (c *Client) ReadOnly(ctx context.Context) (*Tx, error) {
	return c.BeginTxWithOptions(ctx, pgx.TxOptions{
		AccessMode: pgx.ReadOnly,
	})
}

// Serializable starts a serializable transaction (highest isolation level)
// Prevents all concurrency anomalies but may cause more serialization failures
func (c *Client) Serializable(ctx context.Context) (*Tx, error) {
	return c.BeginTxWithOptions(ctx, pgx.TxOptions{
		IsoLevel: pgx.Serializable,
	})
}

// RepeatableRead starts a repeatable read transaction
// Prevents non-repeatable reads and phantom reads
func (c *Client) RepeatableRead(ctx context.Context) (*Tx, error) {
	return c.BeginTxWithOptions(ctx, pgx.TxOptions{
		IsoLevel: pgx.RepeatableRead,
	})
}

// ReadCommitted starts a read committed transaction (PostgreSQL default)
// Prevents dirty reads but allows non-repeatable reads
func (c *Client) ReadCommitted(ctx context.Context) (*Tx, error) {
	return c.BeginTxWithOptions(ctx, pgx.TxOptions{
		IsoLevel: pgx.ReadCommitted,
	})
}

// ============================================================================
// Automatic Transaction Management (BeginFunc Pattern)
// ============================================================================

// BeginFunc executes a function within a transaction with automatic commit/rollback
// The transaction is automatically committed if the function returns nil
// The transaction is automatically rolled back if the function returns an error or panics
//
// Example:
//
//	err := client.BeginFunc(ctx, func(tx *Tx) error {
//	    _, err := tx.Exec(ctx, "INSERT INTO users ...")
//	    if err != nil {
//	        return err  // Automatic rollback
//	    }
//	    return nil  // Automatic commit
//	})
func (c *Client) BeginFunc(ctx context.Context, fn func(tx *Tx) error) error {
	tx, err := c.BeginTx(ctx)
	if err != nil {
		return err
	}

	defer func() {
		if p := recover(); p != nil {
			tx.Rollback(ctx)
			panic(p) // Re-panic after rollback
		}
	}()

	if err = fn(tx); err != nil {
		tx.Rollback(ctx)
		return err
	}

	return tx.Commit(ctx)
}

// BeginFuncWithOptions executes a function within a transaction with custom options
func (c *Client) BeginFuncWithOptions(ctx context.Context, opts pgx.TxOptions, fn func(tx *Tx) error) error {
	tx, err := c.BeginTxWithOptions(ctx, opts)
	if err != nil {
		return err
	}

	defer func() {
		if p := recover(); p != nil {
			tx.Rollback(ctx)
			panic(p)
		}
	}()

	if err = fn(tx); err != nil {
		tx.Rollback(ctx)
		return err
	}

	return tx.Commit(ctx)
}

// ============================================================================
// Savepoint Management (Nested Transactions)
// ============================================================================

// Savepoint creates a savepoint within the transaction
// Savepoints allow partial rollback within a transaction
func (tx *Tx) Savepoint(ctx context.Context, name string) error {
	_, err := tx.Exec(ctx, fmt.Sprintf("SAVEPOINT %s", name))
	if err != nil {
		return errors.Wrap(err, "POSTGRES_SAVEPOINT_FAILED", "Failed to create savepoint").
			WithField("savepoint", name)
	}
	tx.savepoints = append(tx.savepoints, name)
	return nil
}

// RollbackTo rolls back to a savepoint
func (tx *Tx) RollbackTo(ctx context.Context, name string) error {
	_, err := tx.Exec(ctx, fmt.Sprintf("ROLLBACK TO SAVEPOINT %s", name))
	if err != nil {
		return errors.Wrap(err, "POSTGRES_ROLLBACK_TO_SAVEPOINT_FAILED", "Failed to rollback to savepoint").
			WithField("savepoint", name)
	}
	return nil
}

// ReleaseSavepoint releases a savepoint
func (tx *Tx) ReleaseSavepoint(ctx context.Context, name string) error {
	_, err := tx.Exec(ctx, fmt.Sprintf("RELEASE SAVEPOINT %s", name))
	if err != nil {
		return errors.Wrap(err, "POSTGRES_RELEASE_SAVEPOINT_FAILED", "Failed to release savepoint").
			WithField("savepoint", name)
	}
	return nil
}

// WithSavepoint executes a function within a savepoint
// If the function returns an error, the savepoint is rolled back
// If the function succeeds, the savepoint is released
//
// Example:
//
//	err := tx.WithSavepoint(ctx, "sp1", func() error {
//	    _, err := tx.Exec(ctx, "INSERT INTO risky_table ...")
//	    return err  // Rollback to savepoint on error
//	})
func (tx *Tx) WithSavepoint(ctx context.Context, name string, fn func() error) error {
	if err := tx.Savepoint(ctx, name); err != nil {
		return err
	}

	if err := fn(); err != nil {
		tx.RollbackTo(ctx, name)
		return err
	}

	return tx.ReleaseSavepoint(ctx, name)
}

// ============================================================================
// Transaction Helpers with Generics
// ============================================================================

// WithTx executes a function within a transaction and returns a result
// Automatically commits on success, rolls back on error or panic
func WithTx[T any](ctx context.Context, c *Client, fn func(tx *Tx) (T, error)) (T, error) {
	var result T

	tx, err := c.BeginTx(ctx)
	if err != nil {
		return result, err
	}

	defer func() {
		if p := recover(); p != nil {
			tx.Rollback(ctx)
			panic(p)
		}
	}()

	result, err = fn(tx)
	if err != nil {
		tx.Rollback(ctx)
		return result, err
	}

	if err = tx.Commit(ctx); err != nil {
		return result, err
	}

	return result, nil
}

// WithTxVoid executes a function within a transaction (no return value)
// Automatically commits on success, rolls back on error or panic
func WithTxVoid(ctx context.Context, c *Client, fn func(tx *Tx) error) error {
	tx, err := c.BeginTx(ctx)
	if err != nil {
		return err
	}

	defer func() {
		if p := recover(); p != nil {
			tx.Rollback(ctx)
			panic(p)
		}
	}()

	if err = fn(tx); err != nil {
		tx.Rollback(ctx)
		return err
	}

	return tx.Commit(ctx)
}

// ============================================================================
// Retry Logic with Exponential Backoff
// ============================================================================

// WithRetry executes a transaction with retry on serialization failures
// Uses exponential backoff between retries
//
// Example:
//
//	result, err := WithRetry(ctx, client, 3, func(tx *Tx) (int, error) {
//	    // Transaction may be retried on serialization failure
//	    return 42, nil
//	})
func WithRetry[T any](ctx context.Context, c *Client, maxRetries int, fn func(tx *Tx) (T, error)) (T, error) {
	var result T
	var lastErr error

	for attempt := 0; attempt < maxRetries; attempt++ {
		result, lastErr = WithTx(ctx, c, fn)
		if lastErr == nil {
			return result, nil
		}

		// Check if error is retryable
		if !isTransactionRetryable(lastErr) {
			return result, lastErr
		}

		// Exponential backoff: 100ms, 200ms, 400ms, etc.
		if attempt < maxRetries-1 {
			backoff := time.Duration(100*(1<<uint(attempt))) * time.Millisecond
			select {
			case <-time.After(backoff):
				// Continue to next retry
			case <-ctx.Done():
				return result, ctx.Err()
			}
		}
	}

	return result, lastErr
}

// WithRetryVoid executes a transaction with retry (no return value)
func WithRetryVoid(ctx context.Context, c *Client, maxRetries int, fn func(tx *Tx) error) error {
	var lastErr error

	for attempt := 0; attempt < maxRetries; attempt++ {
		lastErr = WithTxVoid(ctx, c, fn)
		if lastErr == nil {
			return nil
		}

		// Check if error is retryable
		if !isTransactionRetryable(lastErr) {
			return lastErr
		}

		// Exponential backoff
		if attempt < maxRetries-1 {
			backoff := time.Duration(100*(1<<uint(attempt))) * time.Millisecond
			select {
			case <-time.After(backoff):
				// Continue to next retry
			case <-ctx.Done():
				return ctx.Err()
			}
		}
	}

	return lastErr
}

// isTransactionRetryable checks if a transaction error is retryable
func isTransactionRetryable(err error) bool {
	if err == nil {
		return false
	}

	// Check for PostgreSQL error codes
	var pgErr *pgconn.PgError
	if goerrors.As(err, &pgErr) {
		switch pgErr.Code {
		case "40001": // serialization_failure
			return true
		case "40P01": // deadlock_detected
			return true
		default:
			return false
		}
	}

	// Check for SafeOps error codes
	code := errors.GetCode(err)
	switch code {
	case "POSTGRES_SERIALIZATION_FAILURE", "POSTGRES_DEADLOCK":
		return true
	default:
		return false
	}
}

// ============================================================================
// Transaction Utility Methods
// ============================================================================

// Age returns how long the transaction has been open
func (tx *Tx) Age() time.Duration {
	return time.Since(tx.startTime)
}

// StartTime returns when the transaction was started
func (tx *Tx) StartTime() time.Time {
	return tx.startTime
}

// SavepointCount returns the number of active savepoints
func (tx *Tx) SavepointCount() int {
	return len(tx.savepoints)
}

// ============================================================================
// Legacy Compatibility (Deprecated)
// ============================================================================

// The following functions are kept for backward compatibility but are deprecated
// Use BeginFunc, WithTx, or WithRetry instead

// isRetryableError checks if error is retryable (legacy, use isTransactionRetryable)
func isRetryableError(err error) bool {
	return isTransactionRetryable(err)
}
