package app

import (
	"context"
	"go.uber.org/fx"
	"go.uber.org/fx/fxevent"
	"go.uber.org/zap"
	"time"
	"xray-checker/internal/common"
	"xray-checker/internal/config"
	"xray-checker/internal/exporter"
	"xray-checker/internal/ipchecker"
	"xray-checker/internal/link"
	"xray-checker/internal/metrics"
	"xray-checker/internal/worker"
	"xray-checker/internal/xray"
)

type Application struct {
	app    *fx.App
	logger *zap.Logger
}

func NewApplication(opts ...common.Option) *Application {
	options := &common.ServiceOptions{}
	for _, opt := range opts {
		opt(options)
	}

	// Ensure required options are set
	if options.Logger == nil {
		options.Logger = zap.NewNop()
	}

	app := &Application{
		logger: options.Logger,
	}

	// Build fx application
	app.app = fx.New(
		// Core modules
		config.Module,
		link.Module,
		metrics.Module,
		worker.Module,
		xray.Module,
		ipchecker.Module,
		exporter.Module,

		// Provide base dependencies
		fx.Provide(
			func() *zap.Logger { return options.Logger },
			func() string { return options.Env },
		),

		// Configure fx
		fx.WithLogger(func(logger *zap.Logger) fxevent.Logger {
			return &fxevent.ZapLogger{Logger: logger}
		}),

		// Set timeouts
		fx.StopTimeout(30*time.Second),
		fx.StartTimeout(30*time.Second),

		// Register lifecycle hooks
		fx.Invoke(app.registerHooks),
	)

	return app
}

func (a *Application) Start(ctx context.Context) error {
	return a.app.Start(ctx)
}

func (a *Application) Stop(ctx context.Context) error {
	return a.app.Stop(ctx)
}

func (a *Application) registerHooks(lc fx.Lifecycle) {
	lc.Append(fx.Hook{
		OnStart: func(ctx context.Context) error {
			a.logger.Info("starting application")
			return nil
		},
		OnStop: func(ctx context.Context) error {
			a.logger.Info("stopping application")
			return nil
		},
	})
}
