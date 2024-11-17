package common

import (
	"go.uber.org/zap"
	"xray-checker/internal/config"
	"xray-checker/internal/domain"
	"xray-checker/internal/interfaces"
)

// ServiceOptions defines common options for service constructors
type ServiceOptions struct {
	Logger      *zap.Logger
	Metrics     domain.MetricsCollector
	Config      *config.Config
	Links       []domain.ParsedLink
	Env         string
	WorkerPool  interfaces.WorkerPool
	Scheduler   interfaces.Scheduler
	XrayService interfaces.XrayService
}

// Option defines a service option modifier
type Option func(*ServiceOptions)

func WithLogger(logger *zap.Logger) Option {
	return func(o *ServiceOptions) {
		o.Logger = logger
	}
}

func WithMetrics(metrics domain.MetricsCollector) Option {
	return func(o *ServiceOptions) {
		o.Metrics = metrics
	}
}

func WithConfig(cfg *config.Config) Option {
	return func(o *ServiceOptions) {
		o.Config = cfg
	}
}

func WithLinks(links []domain.ParsedLink) Option {
	return func(o *ServiceOptions) {
		o.Links = links
	}
}

func WithEnv(env string) Option {
	return func(o *ServiceOptions) {
		o.Env = env
	}
}
