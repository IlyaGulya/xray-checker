package checker

import (
	"go.uber.org/fx"
	"xray-checker/internal/config"
)

// Module exports the checker module
var Module = fx.Options(
	fx.Provide(NewIPChecker),
)

// IPChecker defines the interface for IP checking operations
type IPChecker interface {
	GetDirectIP() (string, error)
	GetProxiedIP(proxyAddr string) (string, error)
}

// NewIPChecker creates a new IPChecker instance
func NewIPChecker(cfg *config.Config) (IPChecker, error) {
	return &defaultIPChecker{
		checkURL: cfg.Workers.CheckIPService,
		client:   createDefaultHTTPClient(),
	}, nil
}
