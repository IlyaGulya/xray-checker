package worker

import (
	"context"
	"fmt"
	"go.uber.org/zap"
	"sync"
	"time"
	"xray-checker/internal/checker"
	"xray-checker/internal/config"
	"xray-checker/internal/domain"
	"xray-checker/internal/xray"
)

type Pool struct {
	workers    []Worker
	scheduler  Scheduler
	jobs       chan domain.ParsedLink
	logger     *zap.Logger
	wg         sync.WaitGroup
	cancel     context.CancelFunc
	mu         sync.Mutex
	metrics    domain.MetricsCollector
	isStarted  bool
	maxRetries int
}

type PoolConfig struct {
	WorkerCount     int
	JobBufferSize   int
	ShutdownTimeout time.Duration
	MaxRetries      int
	HealthCheckFreq time.Duration
}

func NewPool(
	cfg *config.Config,
	checker checker.IPChecker,
	xrayService *xray.Service,
	exporters map[domain.LinkName][]domain.Exporter,
	scheduler Scheduler,
	metrics domain.MetricsCollector,
	logger *zap.Logger,
) (*Pool, error) {
	poolConfig := PoolConfig{
		WorkerCount:     cfg.Workers.Count,
		JobBufferSize:   len(cfg.Links) * 2, // Buffer twice the number of links
		ShutdownTimeout: 30 * time.Second,
		MaxRetries:      3,
		HealthCheckFreq: 1 * time.Minute,
	}

	jobs := make(chan domain.ParsedLink, poolConfig.JobBufferSize)
	workers := make([]Worker, poolConfig.WorkerCount)

	for i := 0; i < poolConfig.WorkerCount; i++ {
		workers[i] = NewWorker(
			i,
			jobs,
			checker,
			xrayService,
			exporters,
			metrics,
			logger,
		)
	}

	return &Pool{
		workers:    workers,
		scheduler:  scheduler,
		jobs:       jobs,
		logger:     logger,
		metrics:    metrics,
		maxRetries: poolConfig.MaxRetries,
	}, nil
}

func (p *Pool) Start(ctx context.Context) error {
	p.mu.Lock()
	if p.isStarted {
		p.mu.Unlock()
		return fmt.Errorf("worker pool already started")
	}
	p.isStarted = true
	p.mu.Unlock()

	p.logger.Debug("starting worker pool")

	// Create pool context
	poolCtx, cancel := context.WithCancel(context.Background())
	p.cancel = cancel

	// Start scheduler
	p.wg.Add(1)
	go func() {
		defer p.wg.Done()
		p.scheduler.Start(poolCtx, p.jobs)
	}()

	// Start workers
	for _, w := range p.workers {
		p.wg.Add(1)
		go func(worker Worker) {
			defer p.wg.Done()
			defer p.handleWorkerPanic(worker)
			worker.Start(poolCtx)
		}(w)
	}

	p.logger.Info("worker pool started",
		zap.Int("worker_count", len(p.workers)),
		zap.Int("job_buffer_size", cap(p.jobs)))

	// Monitor parent context
	go func() {
		select {
		case <-ctx.Done():
			p.logger.Debug("parent context cancelled, stopping pool")
			p.Stop()
		case <-poolCtx.Done():
			return
		}
	}()

	return nil
}

func (p *Pool) Stop() error {
	p.mu.Lock()
	if !p.isStarted {
		p.mu.Unlock()
		return nil
	}
	p.isStarted = false
	p.mu.Unlock()

	p.logger.Debug("stopping worker pool")

	if p.cancel != nil {
		p.cancel()
		p.cancel = nil
	}

	// Wait for all goroutines with timeout
	done := make(chan struct{})
	go func() {
		p.wg.Wait()
		close(done)
	}()

	select {
	case <-done:
		p.logger.Debug("worker pool stopped gracefully")
	case <-time.After(30 * time.Second):
		return fmt.Errorf("worker pool shutdown timed out")
	}

	close(p.jobs)
	return nil
}

func (p *Pool) handleWorkerPanic(w Worker) {
	if r := recover(); r != nil {
		p.logger.Error("worker panic recovered",
			zap.Any("panic", r),
			zap.Stack("stack"))

		// Attempt to restart the worker
		go func() {
			p.mu.Lock()
			defer p.mu.Unlock()

			if p.isStarted {
				poolCtx, _ := context.WithCancel(context.Background())
				w.Start(poolCtx)
				p.logger.Info("worker restarted after panic")
			}
		}()
	}
}
