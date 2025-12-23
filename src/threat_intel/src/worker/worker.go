package worker

import (
	"context"
	"log"
	"threat_intel/config"
	"threat_intel/src/storage"
)

// Worker represents the background worker
type Worker struct {
	cfg *config.Config
	db  *storage.DB
}

// NewWorker creates a new Worker instance
func NewWorker(cfg *config.Config, db *storage.DB) *Worker {
	return &Worker{
		cfg: cfg,
		db:  db,
	}
}

// Start starts the worker
func (w *Worker) Start(ctx context.Context) {
	log.Println("Worker started (stub)")
	<-ctx.Done()
	log.Println("Worker stopped")
}
