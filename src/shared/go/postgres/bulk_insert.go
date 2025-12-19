// Package postgres provides high-performance bulk insert utilities using COPY protocol.
package postgres

import (
	"context"
	"encoding/csv"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/safeops/shared/go/errors"
)

// ============================================================================
// Bulk Inserter (COPY Protocol)
// ============================================================================

// BulkInserter provides high-performance bulk insert functionality using COPY protocol
// Achieves 100-1000× performance improvement over individual INSERT statements
type BulkInserter struct {
	client    *Client
	tableName string
	columns   []string
	batchSize int
}

// NewBulkInserter creates a new bulk inserter for a specific table
func NewBulkInserter(client *Client, tableName string, columns []string) *BulkInserter {
	return &BulkInserter{
		client:    client,
		tableName: tableName,
		columns:   columns,
		batchSize: 10000, // Default batch size
	}
}

// WithBatchSize sets the batch size for batched operations
func (b *BulkInserter) WithBatchSize(size int) *BulkInserter {
	b.batchSize = size
	return b
}

// Insert inserts rows using COPY protocol
// This is 100-1000× faster than individual INSERT statements
//
// Example:
//
//	rows := [][]interface{}{
//	    {"192.168.1.1", "malicious", time.Now()},
//	    {"10.0.0.1", "suspicious", time.Now()},
//	}
//	count, err := inserter.Insert(ctx, rows)
func (b *BulkInserter) Insert(ctx context.Context, rows [][]interface{}) (int64, error) {
	if len(rows) == 0 {
		return 0, nil
	}

	startTime := time.Now()

	copyCount, err := b.client.CopyFrom(
		ctx,
		pgx.Identifier{b.tableName},
		b.columns,
		pgx.CopyFromRows(rows),
	)

	duration := time.Since(startTime)

	if b.client.logger != nil {
		if err != nil {
			b.client.logger.Error("Bulk insert failed",
				"table", b.tableName,
				"rows", len(rows),
				"duration_ms", duration.Milliseconds(),
				"error", err.Error(),
			)
		} else {
			throughput := float64(copyCount) / duration.Seconds()
			b.client.logger.Info("Bulk insert completed",
				"table", b.tableName,
				"rows_inserted", copyCount,
				"duration_ms", duration.Milliseconds(),
				"rows_per_sec", int64(throughput),
			)
		}
	}

	if err != nil {
		return copyCount, errors.Wrap(err, "POSTGRES_BULK_INSERT_FAILED", "Bulk insert failed").
			WithField("table", b.tableName).
			WithField("rows", len(rows))
	}

	return copyCount, nil
}

// InsertBatched inserts rows in batches for extremely large datasets
// This prevents memory issues and allows for partial success
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
			return total, errors.Wrap(err, "POSTGRES_BATCH_INSERT_FAILED", "Batch insert failed").
				WithField("batch_start", i).
				WithField("batch_end", end)
		}
		total += count
	}

	return total, nil
}

// ============================================================================
// Streaming Bulk Insert (Channel-based)
// ============================================================================

// InsertFromChannel inserts rows from a channel using streaming COPY
// This allows processing data as it arrives without loading everything into memory
//
// Example:
//
//	rowChan := make(chan []interface{}, 1000)
//	go func() {
//	    defer close(rowChan)
//	    for _, item := range largeDataset {
//	        rowChan <- []interface{}{item.ID, item.Name}
//	    }
//	}()
//	count, err := inserter.InsertFromChannel(ctx, rowChan)
func (b *BulkInserter) InsertFromChannel(ctx context.Context, rowChan <-chan []interface{}) (int64, error) {
	startTime := time.Now()

	source := &channelSource{ch: rowChan}

	copyCount, err := b.client.CopyFrom(
		ctx,
		pgx.Identifier{b.tableName},
		b.columns,
		source,
	)

	duration := time.Since(startTime)

	if b.client.logger != nil {
		if err != nil {
			b.client.logger.Error("Streaming bulk insert failed",
				"table", b.tableName,
				"duration_ms", duration.Milliseconds(),
				"error", err.Error(),
			)
		} else {
			throughput := float64(copyCount) / duration.Seconds()
			b.client.logger.Info("Streaming bulk insert completed",
				"table", b.tableName,
				"rows_inserted", copyCount,
				"duration_ms", duration.Milliseconds(),
				"rows_per_sec", int64(throughput),
			)
		}
	}

	if err != nil {
		return copyCount, errors.Wrap(err, "POSTGRES_STREAM_INSERT_FAILED", "Streaming insert failed").
			WithField("table", b.tableName)
	}

	return copyCount, nil
}

// channelSource implements pgx.CopyFromSource for channel-based streaming
type channelSource struct {
	ch      <-chan []interface{}
	current []interface{}
}

func (s *channelSource) Next() bool {
	row, ok := <-s.ch
	if !ok {
		return false
	}
	s.current = row
	return true
}

func (s *channelSource) Values() ([]interface{}, error) {
	return s.current, nil
}

func (s *channelSource) Err() error {
	return nil
}

// ============================================================================
// CSV Import
// ============================================================================

// ImportCSV imports data from a CSV file using COPY protocol
// The CSV file must have the same column order as specified in the inserter
//
// Example:
//
//	inserter := NewBulkInserter(client, "users", []string{"id", "name", "email"})
//	count, err := inserter.ImportCSV(ctx, "/path/to/users.csv", true)
func (b *BulkInserter) ImportCSV(ctx context.Context, csvPath string, hasHeader bool) (int64, error) {
	file, err := os.Open(csvPath)
	if err != nil {
		return 0, errors.Wrap(err, "POSTGRES_CSV_OPEN_FAILED", "Failed to open CSV file").
			WithField("path", csvPath)
	}
	defer file.Close()

	return b.ImportCSVFromReader(ctx, file, hasHeader)
}

// ImportCSVFromReader imports data from a CSV reader
func (b *BulkInserter) ImportCSVFromReader(ctx context.Context, reader io.Reader, hasHeader bool) (int64, error) {
	startTime := time.Now()

	csvReader := csv.NewReader(reader)
	source := &csvSource{
		reader:      csvReader,
		hasHeader:   hasHeader,
		columnCount: len(b.columns),
	}

	// Skip header if present
	if hasHeader {
		_, err := csvReader.Read()
		if err != nil {
			return 0, errors.Wrap(err, "POSTGRES_CSV_HEADER_FAILED", "Failed to read CSV header")
		}
	}

	copyCount, err := b.client.CopyFrom(
		ctx,
		pgx.Identifier{b.tableName},
		b.columns,
		source,
	)

	duration := time.Since(startTime)

	if b.client.logger != nil {
		if err != nil {
			b.client.logger.Error("CSV import failed",
				"table", b.tableName,
				"duration_ms", duration.Milliseconds(),
				"error", err.Error(),
			)
		} else {
			throughput := float64(copyCount) / duration.Seconds()
			b.client.logger.Info("CSV import completed",
				"table", b.tableName,
				"rows_imported", copyCount,
				"duration_ms", duration.Milliseconds(),
				"rows_per_sec", int64(throughput),
			)
		}
	}

	if err != nil {
		return copyCount, errors.Wrap(err, "POSTGRES_CSV_IMPORT_FAILED", "CSV import failed").
			WithField("table", b.tableName)
	}

	return copyCount, nil
}

// csvSource implements pgx.CopyFromSource for CSV files
type csvSource struct {
	reader      *csv.Reader
	hasHeader   bool
	columnCount int
	current     []interface{}
	err         error
}

func (s *csvSource) Next() bool {
	record, err := s.reader.Read()
	if err != nil {
		if err != io.EOF {
			s.err = err
		}
		return false
	}

	// Convert strings to interface{} slice
	s.current = make([]interface{}, len(record))
	for i, val := range record {
		s.current[i] = val
	}

	return true
}

func (s *csvSource) Values() ([]interface{}, error) {
	return s.current, nil
}

func (s *csvSource) Err() error {
	return s.err
}

// ============================================================================
// Bulk Upsert (Using Temporary Tables)
// ============================================================================

// BulkUpsert performs bulk insert with conflict resolution using temporary tables
// This is much more efficient than INSERT...ON CONFLICT for large datasets (1000+ rows)
//
// Example:
//
//	err := inserter.BulkUpsert(ctx, rows,
//	    []string{"ip_address"},           // conflict columns (unique constraint)
//	    []string{"reputation", "updated"}) // columns to update on conflict
func (b *BulkInserter) BulkUpsert(ctx context.Context, rows [][]interface{}, conflictColumns []string, updateColumns []string) (int64, error) {
	if len(rows) == 0 {
		return 0, nil
	}

	startTime := time.Now()
	tempTable := fmt.Sprintf("temp_%s_%d", b.tableName, time.Now().UnixNano())

	var totalAffected int64

	// Use transaction for atomicity
	err := b.client.BeginFunc(ctx, func(tx *Tx) error {
		// Create temporary table
		createTempSQL := fmt.Sprintf("CREATE TEMP custom ON COMMIT DROP AS SELECT * FROM %s LIMIT 0", b.tableName)
		_, err := tx.Exec(ctx, createTempSQL)
		if err != nil {
			return errors.Wrap(err, "POSTGRES_TEMP_TABLE_CREATE_FAILED", "Failed to create temporary table").
				WithField("temp_table", tempTable)
		}

		// Bulk insert into temp table using COPY
		// Acquire a connection for the COPY operation within the transaction
		conn, err := b.client.pool.Acquire(ctx)
		if err != nil {
			return errors.Wrap(err, "POSTGRES_ACQUIRE_CONN_FAILED", "Failed to acquire connection")
		}
		defer conn.Release()

		copyCount, err := conn.Conn().CopyFrom(
			ctx,
			pgx.Identifier{tempTable},
			b.columns,
			pgx.CopyFromRows(rows),
		)
		if err != nil {
			return errors.Wrap(err, "POSTGRES_TEMP_INSERT_FAILED", "Failed to insert into temporary table").
				WithField("temp_table", tempTable)
		}

		// Build upsert SQL
		upsertSQL := buildBulkUpsertSQL(b.tableName, tempTable, b.columns, conflictColumns, updateColumns)

		// Execute upsert
		result, err := tx.Exec(ctx, upsertSQL)
		if err != nil {
			return errors.Wrap(err, "POSTGRES_UPSERT_FAILED", "Failed to execute upsert").
				WithField("rows_in_temp", copyCount)
		}

		totalAffected = result.RowsAffected()
		return nil
	})

	duration := time.Since(startTime)

	if b.client.logger != nil {
		if err != nil {
			b.client.logger.Error("Bulk upsert failed",
				"table", b.tableName,
				"rows", len(rows),
				"duration_ms", duration.Milliseconds(),
				"error", err.Error(),
			)
		} else {
			b.client.logger.Info("Bulk upsert completed",
				"table", b.tableName,
				"rows_affected", totalAffected,
				"duration_ms", duration.Milliseconds(),
			)
		}
	}

	return totalAffected, err
}

// buildBulkUpsertSQL builds the SQL for bulk upsert using temp table
func buildBulkUpsertSQL(mainTable, tempTable string, columns, conflictColumns, updateColumns []string) string {
	// Build column list
	colList := strings.Join(columns, ", ")

	// Build UPDATE SET clause
	setClauses := make([]string, len(updateColumns))
	for i, col := range updateColumns {
		setClauses[i] = fmt.Sprintf("%s = EXCLUDED.%s", col, col)
	}
	setClause := strings.Join(setClauses, ", ")

	// Build conflict clause
	conflictClause := strings.Join(conflictColumns, ", ")

	return fmt.Sprintf(
		"INSERT INTO %s (%s) SELECT %s FROM %s ON CONFLICT (%s) DO UPDATE SET %s",
		mainTable, colList, colList, tempTable, conflictClause, setClause,
	)
}

// ============================================================================
// Legacy Batch Builder (for backward compatibility)
// ============================================================================

// BatchBuilder builds batch INSERT queries (less efficient than COPY)
// Use BulkInserter with COPY protocol for better performance
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

// Add adds a row to the batch
func (b *BatchBuilder) Add(values ...interface{}) *BatchBuilder {
	if len(values) != len(b.columns) {
		panic(fmt.Sprintf("column count mismatch: expected %d, got %d", len(b.columns), len(values)))
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
func (b *BatchBuilder) Execute(ctx context.Context, c *Client) (int64, error) {
	query, args := b.Build()
	if query == "" {
		return 0, nil
	}

	result, err := c.pool.Exec(ctx, query, args...)
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
