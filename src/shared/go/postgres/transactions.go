// Package postgres provides transaction helpers.
package postgres

import (
	"context"
	"fmt"

	"github.com/jackc/pgx/v5"
)

// Tx wraps pgx.Tx with additional functionality
type Tx struct {
	pgx.Tx
	savepoints []string
}

// BeginTx starts a new transaction
func (p *Pool) BeginTx(ctx context.Context) (*Tx, error) {
	tx, err := p.Pool.Begin(ctx)
	if err != nil {
		return nil, err
	}
	return &Tx{Tx: tx}, nil
}

// BeginTxWithOptions starts a transaction with options
func (p *Pool) BeginTxWithOptions(ctx context.Context, opts pgx.TxOptions) (*Tx, error) {
	tx, err := p.Pool.BeginTx(ctx, opts)
	if err != nil {
		return nil, err
	}
	return &Tx{Tx: tx}, nil
}

// ReadOnly starts a read-only transaction
func (p *Pool) ReadOnly(ctx context.Context) (*Tx, error) {
	return p.BeginTxWithOptions(ctx, pgx.TxOptions{
		AccessMode: pgx.ReadOnly,
	})
}

// Serializable starts a serializable transaction
func (p *Pool) Serializable(ctx context.Context) (*Tx, error) {
	return p.BeginTxWithOptions(ctx, pgx.TxOptions{
		IsoLevel: pgx.Serializable,
	})
}

// Savepoint creates a savepoint
func (tx *Tx) Savepoint(ctx context.Context, name string) error {
	_, err := tx.Exec(ctx, fmt.Sprintf("SAVEPOINT %s", name))
	if err != nil {
		return err
	}
	tx.savepoints = append(tx.savepoints, name)
	return nil
}

// RollbackTo rolls back to a savepoint
func (tx *Tx) RollbackTo(ctx context.Context, name string) error {
	_, err := tx.Exec(ctx, fmt.Sprintf("ROLLBACK TO SAVEPOINT %s", name))
	return err
}

// ReleaseSavepoint releases a savepoint
func (tx *Tx) ReleaseSavepoint(ctx context.Context, name string) error {
	_, err := tx.Exec(ctx, fmt.Sprintf("RELEASE SAVEPOINT %s", name))
	return err
}

// WithTx executes a function within a transaction
func WithTx[T any](ctx context.Context, p *Pool, fn func(tx *Tx) (T, error)) (T, error) {
	var result T

	tx, err := p.BeginTx(ctx)
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
func WithTxVoid(ctx context.Context, p *Pool, fn func(tx *Tx) error) error {
	tx, err := p.BeginTx(ctx)
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

// WithRetry executes with retry on serialization errors
func WithRetry[T any](ctx context.Context, p *Pool, maxRetries int, fn func(tx *Tx) (T, error)) (T, error) {
	var result T
	var lastErr error

	for i := 0; i < maxRetries; i++ {
		result, lastErr = WithTx(ctx, p, fn)
		if lastErr == nil {
			return result, nil
		}

		// Check if it's a serialization error
		if !isRetryableError(lastErr) {
			return result, lastErr
		}
	}

	return result, lastErr
}

// isRetryableError checks if error is retryable
func isRetryableError(err error) bool {
	// PostgreSQL serialization failure code: 40001
	errStr := err.Error()
	return contains(errStr, "40001") || contains(errStr, "serialization failure")
}

func contains(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}
