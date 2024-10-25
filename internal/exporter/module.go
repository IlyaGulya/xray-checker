package exporter

import (
	"fmt"
	"go.uber.org/fx"
	"go.uber.org/zap"
	"xray-checker/internal/config"
	"xray-checker/internal/domain"
	"xray-checker/internal/exporter/uptimekuma"
)

// Module exports the exporter module
var Module = fx.Options(
	fx.Provide(NewManager),
	fx.Provide(func(m *Manager) map[domain.LinkName][]domain.Exporter {
		return m.Exporters()
	}),
)

type Manager struct {
	exporters map[domain.LinkName][]domain.Exporter
	logger    *zap.Logger
}

func NewManager(cfg *config.Config, logger *zap.Logger) (*Manager, error) {
	manager := &Manager{
		exporters: make(map[domain.LinkName][]domain.Exporter),
		logger:    logger,
	}

	for _, expCfg := range cfg.Exporters {
		exporter, err := createExporter(&expCfg)
		if err != nil {
			return nil, fmt.Errorf("failed to create exporter %s: %w", expCfg.Type, err)
		}

		for _, watch := range expCfg.Watches {
			manager.exporters[watch] = append(
				manager.exporters[watch],
				exporter,
			)
		}
	}

	return manager, nil
}

func (m *Manager) Exporters() map[domain.LinkName][]domain.Exporter {
	return m.exporters
}

func (m *Manager) Export(check domain.Check) {
	exporters := m.exporters[check.Link.LinkName]
	for _, exporter := range exporters {
		if err := exporter.Export(check); err != nil {
			m.logger.Error("failed to export check",
				zap.String("link", string(check.Link.LinkName)),
				zap.String("status", check.Status),
				zap.Error(err),
			)
		}
	}
}

func createExporter(cfg *config.ExporterConfig) (domain.Exporter, error) {
	switch cfg.Type {
	case config.ExporterTypeUptimeKuma:
		return uptimekuma.New(cfg.Raw)
	default:
		return nil, fmt.Errorf("unknown exporter type: %s", cfg.Type)
	}
}
