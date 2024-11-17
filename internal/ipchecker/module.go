package ipchecker

import (
	"go.uber.org/fx"
	"xray-checker/internal/config"
)

// Module exports the checker module
var Module = fx.Options(
	fx.Provide(New),
)

// IPChecker defines the interface for IP checking operations
type IPChecker interface {
	GetDirectIP() (string, error)
	GetProxiedIP(proxyAddr string) (string, error)
}

// New creates a new IPChecker instance
func New(cfg *config.Config) (IPChecker, error) {
	return &defaultIPChecker{
		checkURL: cfg.Workers.CheckIPService,
		client:   createDefaultHTTPClient(),
	}, nil
}
