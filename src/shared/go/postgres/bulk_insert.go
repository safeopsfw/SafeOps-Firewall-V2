// Package postgres provides bulk insert utilities.
package postgres

import (
	"context"
	"fmt"
	"strings"

	"github.com/jackc/pgx/v5"
)

// BulkInserter provides bulk insert functionality
type BulkInserter struct {
	pool      *Pool
	tableName string
	columns   []string
	batchSize int
}

// NewBulkInserter creates a new bulk inserter
func NewBulkInserter(pool *Pool, tableName string, columns []string) *BulkInserter {
	return &BulkInserter{
		pool:      pool,
		tableName: tableName,
		columns:   columns,
		batchSize: 1000,
	}
}

// WithBatchSize sets the batch size
func (b *BulkInserter) WithBatchSize(size int) *BulkInserter {
	b.batchSize = size
	return b
}

// Insert inserts rows using COPY protocol
func (b *BulkInserter) Insert(ctx context.Context, rows [][]interface{}) (int64, error) {
	if len(rows) == 0 {
		return 0, nil
	}

	conn, err := b.pool.Pool.Acquire(ctx)
	if err != nil {
		return 0, err
	}
	defer conn.Release()

	copyCount, err := conn.Conn().CopyFrom(
		ctx,
		pgx.Identifier{b.tableName},
		b.columns,
		pgx.CopyFromRows(rows),
	)

	return copyCount, err
}

// InsertBatched inserts rows in batches
func (b *BulkInserter) InsertBatched(ctx context.Context, rows [][]interface{}) (int64, error) {
	var total int64

	for i := 0; i < len(rows); i += b.batchSize {
		end := i + b.batchSize
		if end > len(rows) {
			end = len(rows)
		}

		batch := rows[i:end]
		count, err := b.Insert(ctx, batch)
		if err != nil {
			return total, err
		}
		total += count
	}

	return total, nil
}

// Upsert performs an upsert operation
func (b *BulkInserter) Upsert(ctx context.Context, rows [][]interface{}, conflictColumns []string, updateColumns []string) (int64, error) {
	if len(rows) == 0 {
		return 0, nil
	}

	// Build INSERT ... ON CONFLICT ... DO UPDATE query
	placeholders := make([]string, 0, len(rows))
	args := make([]interface{}, 0, len(rows)*len(b.columns))

	for i, row := range rows {
		rowPlaceholders := make([]string, len(b.columns))
		for j := range b.columns {
			rowPlaceholders[j] = fmt.Sprintf("$%d", i*len(b.columns)+j+1)
			args = append(args, row[j])
		}
		placeholders = append(placeholders, fmt.Sprintf("(%s)", strings.Join(rowPlaceholders, ", ")))
	}

	// Build UPDATE SET clause
	updateClauses := make([]string, len(updateColumns))
	for i, col := range updateColumns {
		updateClauses[i] = fmt.Sprintf("%s = EXCLUDED.%s", col, col)
	}

	query := fmt.Sprintf(
		"INSERT INTO %s (%s) VALUES %s ON CONFLICT (%s) DO UPDATE SET %s",
		b.tableName,
		strings.Join(b.columns, ", "),
		strings.Join(placeholders, ", "),
		strings.Join(conflictColumns, ", "),
		strings.Join(updateClauses, ", "),
	)

	result, err := b.pool.Pool.Exec(ctx, query, args...)
	if err != nil {
		return 0, err
	}

	return result.RowsAffected(), nil
}

// BatchBuilder builds batch insert queries
type BatchBuilder struct {
	tableName string
	columns   []string
	rows      [][]interface{}
}

// NewBatchBuilder creates a new batch builder
func NewBatchBuilder(tableName string, columns ...string) *BatchBuilder {
	return &BatchBuilder{
		tableName: tableName,
		columns:   columns,
		rows:      make([][]interface{}, 0),
	}
}

// Add adds a row
func (b *BatchBuilder) Add(values ...interface{}) *BatchBuilder {
	if len(values) != len(b.columns) {
		panic("column count mismatch")
	}
	b.rows = append(b.rows, values)
	return b
}

// Build builds the INSERT query
func (b *BatchBuilder) Build() (string, []interface{}) {
	if len(b.rows) == 0 {
		return "", nil
	}

	placeholders := make([]string, 0, len(b.rows))
	args := make([]interface{}, 0, len(b.rows)*len(b.columns))

	for i, row := range b.rows {
		rowPlaceholders := make([]string, len(b.columns))
		for j := range b.columns {
			rowPlaceholders[j] = fmt.Sprintf("$%d", i*len(b.columns)+j+1)
			args = append(args, row[j])
		}
		placeholders = append(placeholders, fmt.Sprintf("(%s)", strings.Join(rowPlaceholders, ", ")))
	}

	query := fmt.Sprintf(
		"INSERT INTO %s (%s) VALUES %s",
		b.tableName,
		strings.Join(b.columns, ", "),
		strings.Join(placeholders, ", "),
	)

	return query, args
}

// Execute executes the batch insert
func (b *BatchBuilder) Execute(ctx context.Context, p *Pool) (int64, error) {
	query, args := b.Build()
	if query == "" {
		return 0, nil
	}

	result, err := p.Pool.Exec(ctx, query, args...)
	if err != nil {
		return 0, err
	}

	return result.RowsAffected(), nil
}

// Clear clears the builder
func (b *BatchBuilder) Clear() {
	b.rows = b.rows[:0]
}

// Size returns the number of rows
func (b *BatchBuilder) Size() int {
	return len(b.rows)
}
