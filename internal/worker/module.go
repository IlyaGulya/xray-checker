package worker

import (
	"context"
	"go.uber.org/zap"
	"time"

	"go.uber.org/fx"
	"xray-checker/internal/config"
	"xray-checker/internal/domain"
)

var Module = fx.Options(
	fx.Provide(NewPool),
	fx.Provide(func(cfg *config.Config, links []domain.ParsedLink, metrics domain.MetricsCollector, logger *zap.Logger) Scheduler {
		return NewScheduler(
			time.Duration(cfg.Workers.CheckInterval)*time.Second,
			links,
			metrics,
			logger,
		)
	}),
	fx.Invoke(registerHooks),
)

func registerHooks(lc fx.Lifecycle, pool *Pool) {
	lc.Append(fx.Hook{
		OnStart: func(ctx context.Context) error {
			return pool.Start(ctx)
		},
		OnStop: func(ctx context.Context) error {
			return pool.Stop()
		},
	})
}
