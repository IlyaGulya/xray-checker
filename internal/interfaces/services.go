package interfaces

import (
	"context"
	"xray-checker/internal/domain"
)

// XrayService defines the interface for Xray functionality
type XrayService interface {
	GetProxyConfig(linkName domain.LinkName) (string, int, error)
	IsHealthy() bool
	WaitForInitialization(ctx context.Context) error
}

// WorkerPool defines the interface for worker pool management
type WorkerPool interface {
	Start(context.Context) error
	Stop() error
}

// Scheduler defines the interface for job scheduling
type Scheduler interface {
	Start(context.Context, chan<- domain.ParsedLink)
	Stop() error
	IsHealthy() bool
}

// IPChecker defines the interface for IP checking operations
type IPChecker interface {
	GetDirectIP() (string, error)
	GetProxiedIP(proxyAddr string) (string, error)
}

// MetricsCollector defines the interface for metrics collection
type MetricsCollector interface {
	RecordCheck(domain.CheckResult)
	RecordWorkerStart(workerID string)
	RecordWorkerStop(workerID string)
	RecordSchedulerJob(linkName string)
	RecordCheckRetry(linkName string)
	RecordXrayRestart()
}
