package alerting

import (
	"context"
	"database/sql"
	"fmt"
	"sync"
	"time"
)

const (
	dbBatchSize    = 100
	dbFlushTimeout = 5 * time.Second
)

// DBLogger batches alert inserts into the packet_logs table.
// Batch of 100 or flush every 5 seconds — whichever comes first.
type DBLogger struct {
	db        *sql.DB
	mu        sync.Mutex
	batch     []*Alert
	ctx       context.Context
	cancel    context.CancelFunc
	wg        sync.WaitGroup
}

// NewDBLogger creates a new database alert logger
// db must be an open *sql.DB connection to the safeops_network database
func NewDBLogger(db *sql.DB) *DBLogger {
	ctx, cancel := context.WithCancel(context.Background())
	d := &DBLogger{
		db:     db,
		batch:  make([]*Alert, 0, dbBatchSize),
		ctx:    ctx,
		cancel: cancel,
	}

	d.wg.Add(1)
	go func() {
		defer d.wg.Done()
		d.timerLoop()
	}()

	return d
}

// Log adds an alert to the batch. Thread-safe.
func (d *DBLogger) Log(alert *Alert) {
	d.mu.Lock()
	d.batch = append(d.batch, alert)
	shouldFlush := len(d.batch) >= dbBatchSize
	d.mu.Unlock()

	if shouldFlush {
		d.Flush()
	}
}

// Flush writes all buffered alerts to the database
func (d *DBLogger) Flush() {
	d.mu.Lock()
	if len(d.batch) == 0 {
		d.mu.Unlock()
		return
	}
	batch := d.batch
	d.batch = make([]*Alert, 0, dbBatchSize)
	d.mu.Unlock()

	d.writeBatch(batch)
}

// Close stops the timer and flushes remaining alerts
func (d *DBLogger) Close() {
	d.cancel()
	d.wg.Wait()
	d.Flush()
}

func (d *DBLogger) timerLoop() {
	ticker := time.NewTicker(dbFlushTimeout)
	defer ticker.Stop()

	for {
		select {
		case <-d.ctx.Done():
			return
		case <-ticker.C:
			d.Flush()
		}
	}
}

func (d *DBLogger) writeBatch(alerts []*Alert) {
	if len(alerts) == 0 || d.db == nil {
		return
	}

	ctx, cancel := context.WithTimeout(d.ctx, 10*time.Second)
	defer cancel()

	tx, err := d.db.BeginTx(ctx, nil)
	if err != nil {
		return // Silently fail — file log is the primary record
	}

	stmt, err := tx.PrepareContext(ctx,
		`INSERT INTO packet_logs (timestamp, src_ip, dst_ip, src_port, dst_port, protocol, action, rule_name, packet_size)
		 VALUES ($1, $2::inet, $3::inet, $4, $5, $6, $7, $8, $9)`)
	if err != nil {
		tx.Rollback()
		return
	}
	defer stmt.Close()

	for _, a := range alerts {
		dstIP := a.DstIP
		if dstIP == "" {
			dstIP = "0.0.0.0"
		}

		action := string(a.ActionTaken)
		if action == "" {
			action = "LOGGED"
		}

		// rule_name carries the alert type + details for searchability
		ruleName := fmt.Sprintf("[%s] %s", string(a.Type), a.Details)
		if len(ruleName) > 255 {
			ruleName = ruleName[:255]
		}

		_, err := stmt.ExecContext(ctx,
			a.Timestamp,
			a.SrcIP,
			dstIP,
			nilIfZero(a.SrcPort),
			nilIfZero(a.DstPort),
			coalesce(a.Protocol, "TCP"),
			action,
			ruleName,
			nil, // packet_size not tracked in alerts
		)
		if err != nil {
			// Skip individual failures, continue batch
			continue
		}
	}

	tx.Commit()
}

func nilIfZero(v uint16) interface{} {
	if v == 0 {
		return nil
	}
	return int(v)
}

func coalesce(a, b string) string {
	if a != "" {
		return a
	}
	return b
}
