package app

import (
	"context"
	"go.uber.org/fx"
	"go.uber.org/zap"
)

type hookParams struct {
	fx.In

	Logger     *zap.Logger
	Lifecycle  fx.Lifecycle
	Shutdowner fx.Shutdowner
}

func registerHooks(p hookParams) {
	p.Lifecycle.Append(fx.Hook{
		OnStart: func(ctx context.Context) error {
			p.Logger.Info("starting application")
			return nil
		},
		OnStop: func(ctx context.Context) error {
			p.Logger.Info("stopping application")
			return nil
		},
	})
}
