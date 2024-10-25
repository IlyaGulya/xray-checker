package uptimekuma

import (
	"encoding/json"
	"fmt"
	"net/http"
	. "xray-checker/internal/domain"
)

type Config struct {
	MonitorURL string `json:"monitor_url" validate:"required,url"`
}

type UptimeKuma struct {
	monitorURL string
}

func New(rawConfig json.RawMessage) (Exporter, error) {
	var cfg Config
	if err := json.Unmarshal(rawConfig, &cfg); err != nil {
		return nil, fmt.Errorf("invalid uptime kuma config: %w", err)
	}

	return NewWithURL(cfg.MonitorURL), nil
}

func NewWithURL(monitorURL string) Exporter {
	return &UptimeKuma{
		monitorURL: monitorURL,
	}
}

func (u *UptimeKuma) Export(check Check) error {
	if check.VPNIP == check.SourceIP {
		return nil
	}

	_, err := http.Get(u.monitorURL)
	return err
}
