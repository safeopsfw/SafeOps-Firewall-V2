package worker

import (
	"log"
	"sync"
	"threat_intel/config"
)

type WorkerPool struct {
	cfg      *config.Config
	workerWg sync.WaitGroup
	stopCh   chan struct{}
	jobQueue chan Job
}

type Job struct {
	Name string
	Func func() error
}

func NewWorkerPool(cfg *config.Config) *WorkerPool {
	return &WorkerPool{
		cfg:      cfg,
		stopCh:   make(chan struct{}),
		jobQueue: make(chan Job, 100),
	}
}

// Start begins the worker pool
func (wp *WorkerPool) Start() {
	log.Printf("Starting worker pool with %d workers", wp.cfg.Worker.ConcurrentJobs)

	for i := 0; i < wp.cfg.Worker.ConcurrentJobs; i++ {
		wp.workerWg.Add(1)
		go wp.worker(i)
	}

	wp.workerWg.Wait()
}

// Stop shuts down the worker pool
func (wp *WorkerPool) Stop() {
	log.Println("Stopping worker pool...")
	close(wp.stopCh)
}

func (wp *WorkerPool) worker(id int) {
	defer wp.workerWg.Done()

	for {
		select {
		case job := <-wp.jobQueue:
			log.Printf("Worker %d processing job: %s", id, job.Name)
			if err := job.Func(); err != nil {
				log.Printf("Worker %d job failed: %v", id, err)
			}
		case <-wp.stopCh:
			log.Printf("Worker %d shutting down", id)
			return
		}
	}
}

// SubmitJob adds a job to the queue
func (wp *WorkerPool) SubmitJob(job Job) {
	wp.jobQueue <- job
}
