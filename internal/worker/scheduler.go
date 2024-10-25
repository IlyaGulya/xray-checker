package worker

import (
	"context"
	"fmt"
	"go.uber.org/zap"
	"sync"
	"time"
	"xray-checker/internal/domain"
)

type Scheduler interface {
	Start(context.Context, chan<- domain.ParsedLink)
	Stop() error
	IsHealthy() bool
}

type schedulerConfig struct {
	interval   time.Duration
	retryDelay time.Duration
	maxRetries int
	batchSize  int
}

type defaultScheduler struct {
	interval time.Duration
	links    []domain.ParsedLink
	logger   *zap.Logger
	metrics  domain.MetricsCollector
	config   schedulerConfig
	mu       sync.RWMutex
	stopping bool
}

func NewScheduler(
	interval time.Duration,
	links []domain.ParsedLink,
	metrics domain.MetricsCollector,
	logger *zap.Logger,
) Scheduler {
	return &defaultScheduler{
		interval: interval,
		links:    links,
		logger:   logger.With(zap.String("component", "scheduler")),
		metrics:  metrics,
		config: schedulerConfig{
			interval:   interval,
			retryDelay: 5 * time.Second,
			maxRetries: 3,
			batchSize:  10,
		},
	}
}

func (s *defaultScheduler) Start(ctx context.Context, jobs chan<- domain.ParsedLink) {
	ticker := time.NewTicker(s.interval)
	defer ticker.Stop()

	// Send initial batch of jobs
	if err := s.sendJobs(ctx, jobs); err != nil {
		s.logger.Error("failed to send initial jobs", zap.Error(err))
	}

	for {
		select {
		case <-ticker.C:
			if err := s.sendJobs(ctx, jobs); err != nil {
				s.logger.Error("failed to send jobs", zap.Error(err))
				continue
			}
		case <-ctx.Done():
			s.logger.Debug("scheduler stopped", zap.Error(ctx.Err()))
			return
		}
	}
}

func (s *defaultScheduler) sendJobs(ctx context.Context, jobs chan<- domain.ParsedLink) error {
	s.mu.RLock()
	if s.stopping {
		s.mu.RUnlock()
		return fmt.Errorf("scheduler is stopping")
	}
	s.mu.RUnlock()

	for _, link := range s.links {
		select {
		case jobs <- link:
			s.logger.Debug("sent job",
				zap.String("link", string(link.LinkName)))
			s.metrics.RecordSchedulerJob(string(link.LinkName))
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(5 * time.Second):
			return fmt.Errorf("timed out sending job for link %s", link.LinkName)
		}
	}
	return nil
}

func (s *defaultScheduler) Stop() error {
	s.mu.Lock()
	s.stopping = true
	s.mu.Unlock()
	return nil
}

func (s *defaultScheduler) IsHealthy() bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return !s.stopping
}
