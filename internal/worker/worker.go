package worker

import (
	"context"
	"fmt"
	"go.uber.org/zap"
	"sync"
	"time"
	"xray-checker/internal/checker"
	"xray-checker/internal/domain"
	"xray-checker/internal/xray"
)

// Worker represents a single worker that processes VPN checks
type Worker interface {
	Start(context.Context)
	Stop()
}

type workerConfig struct {
	checkTimeout time.Duration
	retryCount   int
	retryDelay   time.Duration
}

type worker struct {
	id          int
	jobs        <-chan domain.ParsedLink
	checker     checker.IPChecker
	xrayService *xray.Service
	exporters   map[domain.LinkName][]domain.Exporter
	logger      *zap.Logger
	stopOnce    sync.Once
	stopChan    chan struct{}
	config      workerConfig
	metrics     domain.MetricsCollector
}

func NewWorker(
	id int,
	jobs <-chan domain.ParsedLink,
	checker checker.IPChecker,
	xrayService *xray.Service,
	exporters map[domain.LinkName][]domain.Exporter,
	metrics domain.MetricsCollector,
	logger *zap.Logger,
) Worker {
	return &worker{
		id:          id,
		jobs:        jobs,
		checker:     checker,
		xrayService: xrayService,
		exporters:   exporters,
		logger:      logger.With(zap.Int("worker_id", id)),
		stopChan:    make(chan struct{}),
		config: workerConfig{
			checkTimeout: 30 * time.Second,
			retryCount:   3,
			retryDelay:   5 * time.Second,
		},
		metrics: metrics,
	}
}

func (w *worker) Start(ctx context.Context) {
	w.logger.Debug("worker started")
	defer w.logger.Debug("worker stopped")

	for {
		select {
		case link, ok := <-w.jobs:
			if !ok {
				w.logger.Info("jobs channel closed")
				return
			}
			if err := w.processCheck(link); err != nil {
				w.logger.Error("check processing failed",
					zap.String("link", string(link.LinkName)),
					zap.Error(err))
			}
		case <-ctx.Done():
			w.logger.Info("context cancelled",
				zap.Error(ctx.Err()))
			return
		case <-w.stopChan:
			w.logger.Info("received stop signal")
			return
		}
	}
}

func (w *worker) Stop() {
	w.stopOnce.Do(func() {
		close(w.stopChan)
	})
}

func (w *worker) processCheck(link domain.ParsedLink) error {
	result := w.newCheckResult(link)
	start := time.Now()

	defer func() {
		result.Check.TimeStamp = start
		w.exportResult(result)
		w.metrics.RecordCheck(result)
	}()

	// Create context with timeout
	ctx, cancel := context.WithTimeout(context.Background(), w.config.checkTimeout)
	defer cancel()

	// Get source IP with retry mechanism
	var sourceIP string
	var err error
	for attempt := 0; attempt < w.config.retryCount; attempt++ {
		if attempt > 0 {
			time.Sleep(w.config.retryDelay)
			w.logger.Debug("retrying source IP check",
				zap.String("link", string(link.LinkName)),
				zap.Int("attempt", attempt+1))
		}

		sourceIP, err = w.checker.GetDirectIP()
		if err == nil {
			break
		}
	}
	if err != nil {
		result.Check.Status = "Error"
		result.Check.Error = fmt.Errorf("failed to get source IP after %d attempts: %w",
			w.config.retryCount, err)
		return result.Check.Error
	}
	result.Check.SourceIP = sourceIP

	// Get proxy configuration with timeout
	proxyAddr, port, err := w.getProxyConfigWithTimeout(ctx, link.LinkName)
	if err != nil {
		result.Check.Status = "Error"
		result.Check.Error = fmt.Errorf("failed to get proxy configuration: %w", err)
		return result.Check.Error
	}

	// Check VPN IP with retry mechanism
	proxyURL := fmt.Sprintf("socks5://%s:%d", proxyAddr, port)
	var vpnIP string
	for attempt := 0; attempt < w.config.retryCount; attempt++ {
		if attempt > 0 {
			time.Sleep(w.config.retryDelay)
			w.logger.Debug("retrying VPN IP check",
				zap.String("link", string(link.LinkName)),
				zap.Int("attempt", attempt+1))
		}

		vpnIP, err = w.checker.GetProxiedIP(proxyURL)
		if err == nil {
			break
		}
	}
	if err != nil {
		result.Check.Status = "Error"
		result.Check.Error = fmt.Errorf("failed to get VPN IP after %d attempts: %w",
			w.config.retryCount, err)
		return result.Check.Error
	}
	result.Check.VPNIP = vpnIP

	if result.Check.VPNIP != result.Check.SourceIP {
		result.Check.Status = "Success"
	} else {
		result.Check.Status = "Failed"
	}

	result.Duration = time.Since(start)
	result.Completed = time.Now()

	return nil
}

func (w *worker) getProxyConfigWithTimeout(ctx context.Context, linkName domain.LinkName) (string, int, error) {
	type proxyConfigResult struct {
		addr string
		port int
		err  error
	}

	ch := make(chan proxyConfigResult, 1)
	go func() {
		addr, port, err := w.xrayService.GetProxyConfig(linkName)
		ch <- proxyConfigResult{addr, port, err}
	}()

	select {
	case <-ctx.Done():
		return "", 0, ctx.Err()
	case result := <-ch:
		return result.addr, result.port, result.err
	}
}

func (w *worker) newCheckResult(link domain.ParsedLink) domain.CheckResult {
	return domain.CheckResult{
		Check: domain.Check{
			Link:   link,
			Status: "Error", // Default status
		},
	}
}

func (w *worker) exportResult(result domain.CheckResult) {
	for _, exporter := range w.exporters[result.Check.Link.LinkName] {
		if err := exporter.Export(result.Check); err != nil {
			w.logger.Error("failed to export result",
				zap.String("link", string(result.Check.Link.LinkName)),
				zap.Error(err),
			)
		}
	}
}
