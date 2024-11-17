package app

import (
	"context"
	"testing"
	"time"

	"go.uber.org/fx"
	"go.uber.org/fx/fxtest"
	"go.uber.org/zap"
	"xray-checker/internal/common"
)

// TestApplication provides testing functionality for the application
type TestApplication struct {
	tb      testing.TB
	mocks   map[string]interface{}
	testApp *fxtest.App
	options []fx.Option
	logger  *zap.Logger
}

func NewTestApplication(tb testing.TB, opts ...common.Option) *TestApplication {
	logger := zap.NewNop()

	options := &common.ServiceOptions{
		Logger: logger,
	}
	for _, opt := range opts {
		opt(options)
	}

	return &TestApplication{
		tb:      tb,
		mocks:   make(map[string]interface{}),
		logger:  logger,
		options: []fx.Option{},
	}
}

func (ta *TestApplication) WithMock(name string, mock interface{}) *TestApplication {
	ta.mocks[name] = mock
	return ta
}

func (ta *TestApplication) WithOption(opt fx.Option) *TestApplication {
	ta.options = append(ta.options, opt)
	return ta
}

func (ta *TestApplication) Start(ctx context.Context) error {
	var testOptions []fx.Option

	// Add base options
	testOptions = append(testOptions,
		fx.Provide(func() *zap.Logger { return ta.logger }),
		fx.Supply(ta.mocks),
	)

	// Add mock providers
	for name, mock := range ta.mocks {
		testOptions = append(testOptions, fx.Provide(
			fx.Annotated{
				Name:   name,
				Target: func() interface{} { return mock },
			},
		))
	}

	// Add user-provided options
	testOptions = append(testOptions, ta.options...)

	// Configure test app
	testOptions = append(testOptions,
		fx.StartTimeout(10*time.Second),
		fx.StopTimeout(10*time.Second),
	)

	// Create test app
	ta.testApp = fxtest.New(
		ta.tb,
		testOptions...,
	)

	return ta.testApp.Start(ctx)
}

func (ta *TestApplication) Stop(ctx context.Context) error {
	if ta.testApp != nil {
		return ta.testApp.Stop(ctx)
	}
	return nil
}
