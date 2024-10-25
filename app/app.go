package app

import (
	"go.uber.org/fx"
	"go.uber.org/fx/fxevent"
	"xray-checker/internal/link"

	"xray-checker/internal/checker"
	"xray-checker/internal/config"
	"xray-checker/internal/exporter"
	"xray-checker/internal/metrics"
	"xray-checker/internal/worker"
	"xray-checker/internal/xray"
)

func New(opts Options) *fx.App {
	return fx.New(
		// Provide application-wide dependencies
		fx.Supply(opts.Logger),
		fx.Supply(opts.Env),

		// Register all modules
		config.Module,
		metrics.Module,
		worker.Module,
		xray.Module,
		checker.Module,
		exporter.Module,
		link.Module,

		// Register lifecycle hooks
		fx.Invoke(registerHooks),

		// Configure fx logging
		fx.WithLogger(func() fxevent.Logger {
			return &fxevent.ZapLogger{Logger: opts.Logger}
		}),
	)
}
