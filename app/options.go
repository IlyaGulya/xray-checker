package app

import (
	"go.uber.org/zap"
)

// Options defines the configuration options for the application
type Options struct {
	Logger *zap.Logger
	Env    string
}

// DefaultOptions returns default application options
func DefaultOptions() Options {
	logger, _ := zap.NewDevelopment()
	return Options{
		Logger: logger,
		Env:    "development",
	}
}
